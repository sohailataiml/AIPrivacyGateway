"""The audit service: a bounded queue between a request and the audit table.

Architecture.md section 9.9 requires that audit writes never delay a response
indefinitely, and that the buffer between the two be bounded with safe fallback
counters. This module is that buffer.

Saturation policy
-----------------
When the queue is full this service **never applies backpressure**. It refuses
or drops, immediately, and counts what it did.

Backpressure was the alternative: ``await queue.put(...)`` would hold the
request until the writer drained. That couples every request's latency to
PostgreSQL's, which is precisely the coupling the queue exists to remove -- a
slow audit database would stall worker tasks, exhaust the connection pool, and
turn a degraded dependency into a full outage. A bounded queue whose overflow
behaviour is "wait" is an unbounded queue wearing a hat.

So overflow resolves by configuration instead:

* ``fail_closed=True`` (production default): ``submit`` raises
  :class:`~app.domain.errors.AuditUnavailableError`, the request fails with 503,
  and nothing is served that could not be audited.
* ``fail_closed=False``: the event is dropped, ``sgw_audit_events_total{outcome="dropped"}``
  and ``sgw_audit_failures_total{reason="queue_full"}`` increment, and the
  request proceeds. Availability is preserved at the cost of a gap in the trail.

Fail-open versus fail-closed
----------------------------
**Recommendation: run production with** ``AUDIT_FAIL_CLOSED=true`` (the default
in :class:`~app.config.settings.Settings`). ADR-0008 makes failure closed the
house rule, and a privacy gateway that cannot record what it did has lost the
property it is sold on. Fail-open belongs in local development, load tests, and
a declared incident where an operator has consciously chosen availability over
the audit trail.

One honest limitation: because writes are asynchronous, a request whose event
fails *after* the response was returned cannot be retroactively failed. The
strongest achievable guarantee is to refuse what comes next. A write failure
puts a fail-closed service into a degraded state, and every subsequent
``submit`` raises until a write succeeds -- while still queueing the record, so
the writer keeps retrying and storage coming back clears the state without a
restart. The request that failed is lost to the trail; the ones that follow are
refused rather than served unaudited.

Nothing in this module logs an event payload. Failure logs carry a fixed reason
string and a request id -- never counts, digests, aliases, or anything derived
from message text.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from datetime import UTC, datetime
from types import TracebackType
from typing import Final, Protocol, Self

from app.audit import metrics
from app.audit.models import AuditRecord
from app.config.settings import Settings, get_settings
from app.domain.errors import AuditUnavailableError
from app.observability.logging import get_logger
from app.repositories.audit_events import AuditEventDraft

logger = get_logger(__name__)

DEFAULT_MAX_QUEUE_SIZE: Final = 1_000
"""Roughly one second of peak throughput. Large enough to absorb a database
hiccup, small enough that a sustained outage is noticed rather than buffered."""

DEFAULT_DRAIN_TIMEOUT_SECONDS: Final = 5.0
"""Shutdown budget. A slow writer must not hold the process open forever."""


class AuditSink(Protocol):
    """Append-only audit storage, from this service's point of view.

    A ``Protocol`` rather than an import of the concrete repository: the audit
    package must stay testable without a database session, and the repository
    package owns its own implementation.
    """

    async def record(self, draft: AuditEventDraft) -> object:
        """Append one event. The return value is ignored by this service."""
        ...


def to_draft(record: AuditRecord) -> AuditEventDraft:
    """Project the domain record onto the repository's insert shape.

    Field-by-field and explicit. A ``**asdict(record)`` splat would silently
    forward any field a future edit added, which is the failure mode the
    prohibited-field list exists to prevent.
    """
    return AuditEventDraft(
        tenant_id=record.tenant_id,
        request_id=record.request_id,
        status_code=record.status_code,
        occurred_at=record.occurred_at,
        api_key_id=record.api_key_id,
        session_id_hash=record.session_id_hash,
        policy_id=record.policy_id,
        policy_version=record.policy_version,
        provider_alias=record.provider_alias,
        model_alias=record.model_alias,
        input_character_count=record.input_character_count,
        output_character_count=record.output_character_count,
        entity_counts=dict(record.entity_counts),
        actions=dict(record.actions),
        blocked=record.blocked,
        block_reason_code=record.block_reason_code,
        provider_latency_ms=record.provider_latency_ms,
        pipeline_latency_ms=record.pipeline_latency_ms,
        error_code=record.error_code,
        prompt_hmac=record.prompt_hmac,
        response_hmac=record.response_hmac,
    )


class AuditService:
    """Accepts audit records on the request path, writes them off it."""

    __slots__ = (
        "_degraded",
        "_drain_timeout_seconds",
        "_fail_closed",
        "_queue",
        "_sink",
        "_stopped",
        "_worker",
    )

    def __init__(
        self,
        sink: AuditSink,
        *,
        fail_closed: bool = True,
        max_queue_size: int = DEFAULT_MAX_QUEUE_SIZE,
        drain_timeout_seconds: float = DEFAULT_DRAIN_TIMEOUT_SECONDS,
    ) -> None:
        if max_queue_size < 1:
            raise ValueError("max_queue_size must be at least 1")
        self._sink = sink
        self._fail_closed = fail_closed
        self._drain_timeout_seconds = drain_timeout_seconds
        self._queue: asyncio.Queue[AuditRecord] = asyncio.Queue(maxsize=max_queue_size)
        self._worker: asyncio.Task[None] | None = None
        self._degraded = False
        self._stopped = False
        metrics.set_queue_capacity(max_queue_size)
        metrics.set_queue_depth(0)

    @classmethod
    def from_settings(
        cls,
        sink: AuditSink,
        settings: Settings | None = None,
        *,
        max_queue_size: int = DEFAULT_MAX_QUEUE_SIZE,
    ) -> AuditService:
        """Build a service whose failure mode comes from configuration."""
        resolved = settings if settings is not None else get_settings()
        return cls(sink, fail_closed=resolved.audit_fail_closed, max_queue_size=max_queue_size)

    # -- Introspection ----------------------------------------------------
    @property
    def fail_closed(self) -> bool:
        return self._fail_closed

    @property
    def degraded(self) -> bool:
        """True when a write has failed and no write has succeeded since."""
        return self._degraded

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    # -- Lifecycle --------------------------------------------------------
    async def start(self) -> None:
        """Start the background writer. Idempotent."""
        if self._worker is not None:
            return
        self._stopped = False
        self._worker = asyncio.create_task(self._run(), name="audit-writer")

    async def stop(self, *, drain: bool = True) -> None:
        """Stop accepting work, optionally draining what is queued.

        A drain that exceeds the timeout is counted, not waited out: shutdown
        must complete even when the audit database is the thing that is broken.
        """
        self._stopped = True
        worker = self._worker
        if worker is None:
            return

        if drain and not self._queue.empty():
            try:
                await asyncio.wait_for(self._queue.join(), timeout=self._drain_timeout_seconds)
            except TimeoutError:
                metrics.record_failure(metrics.REASON_DRAIN_TIMEOUT)
                logger.warning("audit_drain_timeout", stage="audit", reason="drain_timeout")

        worker.cancel()
        try:
            await worker
        except asyncio.CancelledError:
            pass
        finally:
            self._worker = None

        undelivered = self._queue.qsize()
        if undelivered:
            metrics.record_failure(metrics.REASON_SHUTDOWN)
            metrics.record_event(metrics.OUTCOME_DROPPED, count=undelivered)
            logger.warning("audit_events_undelivered", stage="audit", reason="shutdown")

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.stop()

    # -- Request path -----------------------------------------------------
    async def submit(self, record: AuditRecord) -> None:
        """Enqueue one record. Returns as soon as the queue accepts it.

        Raises:
            AuditUnavailableError: when fail-closed and the event cannot be
                accepted -- the queue is saturated, a previous write failed, or
                the service is shutting down.
        """
        stamped = (
            record
            if record.occurred_at is not None
            else replace_occurred_at(record, datetime.now(UTC))
        )

        if self._stopped:
            self._refuse(metrics.REASON_SHUTDOWN, "audit_service_stopped")
            return

        try:
            self._queue.put_nowait(stamped)
        except asyncio.QueueFull:
            self._refuse(metrics.REASON_QUEUE_FULL, "audit_queue_full")
            return

        metrics.record_event(metrics.OUTCOME_ENQUEUED)
        metrics.set_queue_depth(self._queue.qsize())

        if self._degraded and self._fail_closed:
            # The record stays queued deliberately. The writer retries it, and a
            # success clears the degraded flag, so storage coming back restores
            # service without a restart -- while this request still fails, since
            # nothing may be served that could not be audited.
            metrics.record_failure(metrics.REASON_DEGRADED)
            metrics.record_event(metrics.OUTCOME_REJECTED)
            raise AuditUnavailableError(
                log_context={"stage": "audit", "reason": metrics.REASON_DEGRADED}
            )

    async def flush(self, *, wait_seconds: float | None = None) -> bool:
        """Wait until every queued record has been handled. Returns success.

        Test and shutdown support only. The request path never calls this: that
        would reintroduce exactly the coupling the queue removes.
        """
        if self._worker is None:
            return self._queue.empty()
        budget = wait_seconds if wait_seconds is not None else self._drain_timeout_seconds
        try:
            async with asyncio.timeout(budget):
                await self._queue.join()
        except TimeoutError:
            return False
        return True

    # -- Writer -----------------------------------------------------------
    async def _run(self) -> None:
        while True:
            record = await self._queue.get()
            try:
                await self._write(record)
            finally:
                self._queue.task_done()
                metrics.set_queue_depth(self._queue.qsize())

    async def _write(self, record: AuditRecord) -> None:
        started = time.perf_counter()
        try:
            await self._sink.record(to_draft(record))
        except asyncio.CancelledError:
            raise
        except Exception:
            # Contained on purpose: an audit failure must not kill the writer,
            # and the payload is never logged -- only a fixed reason and the
            # request id an operator needs to correlate.
            self._degraded = True
            metrics.record_failure(metrics.REASON_WRITE_ERROR)
            metrics.record_event(metrics.OUTCOME_FAILED)
            logger.error(
                "audit_write_failed",
                stage="audit",
                reason="write_failed",
                request_id=str(record.request_id),
            )
        else:
            self._degraded = False
            metrics.record_event(metrics.OUTCOME_WRITTEN)
        finally:
            metrics.observe_write(time.perf_counter() - started)

    # -- Internals --------------------------------------------------------
    def _refuse(self, reason: str, event: str) -> None:
        """Reject or drop one record according to the configured failure mode."""
        metrics.record_failure(reason)
        if self._fail_closed:
            metrics.record_event(metrics.OUTCOME_REJECTED)
            raise AuditUnavailableError(log_context={"stage": "audit", "reason": reason})
        metrics.record_event(metrics.OUTCOME_DROPPED)
        logger.warning(event, stage="audit", reason=reason)

    def __repr__(self) -> str:
        return (
            f"AuditService(fail_closed={self._fail_closed}, depth={self._queue.qsize()}, "
            f"degraded={self._degraded}, running={self._worker is not None})"
        )


def replace_occurred_at(record: AuditRecord, occurred_at: datetime) -> AuditRecord:
    """Return a copy stamped with ``occurred_at``. The input is not mutated.

    The stamp is taken when the request hands the record over, not when the
    writer gets to it, so queue lag never distorts the timeline.
    """
    return replace(record, occurred_at=occurred_at)
