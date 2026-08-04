"""Per-request identity, budgets, and the privacy-safe audit projection.

Two immutable carriers live here.

``PipelineAttempt`` is what is known *before* the policy resolves: the request
id, the principal, the one session id, and the clock this request runs against.
``RequestContext`` -- the canonical domain type -- is derived from it once the
policy version is known, and is what the stages after policy share.

Both are frozen. The request id and the session id are therefore fixed at the
moment the request is admitted and cannot be reassigned by a later stage, which
is what makes them stable from detection through to the audit row.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID, uuid4

from app.config.settings import Settings
from app.domain.models import ChatRequest, Principal, PrivacySummary, RequestContext
from app.llm.base import overall_deadline_seconds
from app.policy.models import PolicySnapshot

DEFAULT_MAX_CONCURRENT_PROVIDER_CALLS: Final[int] = 16
"""In-flight provider calls allowed per process.

A bound is required, not optional. Provider calls are the longest-lived and
most memory-hungry operation in the request path, and an unbounded fan-out
converts one traffic spike into exhausted sockets, a rate-limit ban, and an
unbounded bill. Sixteen is a starting point for a single instance; a deployment
that has measured its provider concurrency should pass its own.
"""

PIPELINE_OVERHEAD_BUDGET_SECONDS: Final[float] = 15.0
"""Time allowed for everything that is not the provider call.

Detection, tokenization, every vault round trip, restoration, and the audit
write together. Generous relative to the performance targets (p95 gateway
overhead under 250 ms) because this is a safety net against a wedged
dependency, not a latency objective.
"""

DEFAULT_LANGUAGE: Final[str] = "en"
"""The only language v1 detection supports. Not caller-controlled: an
unsupported language must fail closed rather than skip detection."""


def default_timeout_seconds(settings: Settings) -> float:
    """Derive the pipeline deadline from the provider's own worst case.

    The provider adapter already bounds itself, including retries and backoff.
    The pipeline's bound is that number plus the gateway's own budget, so the
    outer deadline normally fires *after* the adapter's -- the request then
    fails with the accurate upstream error instead of a generic timeout -- while
    still capping an adapter that fails to honour its deadline at all.
    """
    provider_budget = overall_deadline_seconds(
        connect_timeout_seconds=settings.provider_connect_timeout_seconds,
        read_timeout_seconds=settings.provider_read_timeout_seconds,
        max_retries=settings.provider_max_retries,
    )
    return provider_budget + PIPELINE_OVERHEAD_BUDGET_SECONDS


@dataclass(frozen=True, slots=True)
class PipelineConfig:
    """Request-path budgets. Built once at startup and shared by every request."""

    timeout_seconds: float
    max_concurrent_provider_calls: int = DEFAULT_MAX_CONCURRENT_PROVIDER_CALLS

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_concurrent_provider_calls < 1:
            raise ValueError("max_concurrent_provider_calls must be at least 1")

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        max_concurrent_provider_calls: int = DEFAULT_MAX_CONCURRENT_PROVIDER_CALLS,
    ) -> PipelineConfig:
        """Build the config a deployment's settings call for."""
        return cls(
            timeout_seconds=default_timeout_seconds(settings),
            max_concurrent_provider_calls=max_concurrent_provider_calls,
        )


@dataclass(frozen=True, slots=True)
class PipelineAttempt:
    """Identity and clock for one request, fixed before the policy resolves."""

    request_id: UUID
    principal: Principal
    session_id: UUID
    provider_alias: str
    model_alias: str
    started_at: datetime
    started_clock: float
    """Event-loop time at admission. Monotonic, so it survives a clock change."""

    deadline: float
    """Absolute event-loop time the whole request must complete by."""

    @classmethod
    def begin(
        cls,
        *,
        request: ChatRequest,
        principal: Principal,
        session_id: UUID,
        clock_now: float,
        timeout_seconds: float,
    ) -> PipelineAttempt:
        """Admit a request: mint its id and start its clock."""
        return cls(
            request_id=uuid4(),
            principal=principal,
            session_id=session_id,
            provider_alias=request.provider,
            model_alias=request.model,
            started_at=datetime.now(UTC),
            started_clock=clock_now,
            deadline=clock_now + timeout_seconds,
        )

    @property
    def tenant_id(self) -> UUID:
        return self.principal.tenant_id

    def elapsed_ms(self, clock_now: float) -> int:
        return max(int((clock_now - self.started_clock) * 1000), 0)

    def with_policy(self, snapshot: PolicySnapshot) -> RequestContext:
        """Derive the canonical context now that the policy version is known."""
        return RequestContext(
            request_id=self.request_id,
            principal=self.principal,
            session_id=self.session_id,
            started_at=self.started_at,
            policy_version=snapshot.version,
        )


@dataclass(frozen=True, slots=True)
class RequestOutcome:
    """How one request ended, in counts and codes only.

    There is no field here for message content, response content, an original
    value, or a token. The audit projection is built from this type alone, so a
    prohibited field cannot reach an audit row by way of the pipeline.
    """

    status_code: int
    summary: PrivacySummary
    input_character_count: int = 0
    output_character_count: int = 0
    provider_latency_ms: int | None = None
    pipeline_latency_ms: int | None = None
    error_code: str | None = None
    blocked: bool = False


def audit_payload(
    *,
    attempt: PipelineAttempt,
    snapshot: PolicySnapshot | None,
    outcome: RequestOutcome,
) -> Mapping[str, Any]:
    """Project one finished request onto the audit service's field names.

    ``session_id`` is passed raw and hashed by the audit service, which owns the
    keyed digest. Everything else is an identifier, a count, or a code.
    """
    return {
        "request_id": attempt.request_id,
        "tenant_id": attempt.tenant_id,
        "api_key_id": attempt.principal.api_key_id,
        "session_id": attempt.session_id,
        "policy_id": snapshot.policy_id if snapshot is not None else None,
        "policy_version": snapshot.version if snapshot is not None else None,
        "provider_alias": attempt.provider_alias,
        "model_alias": attempt.model_alias,
        "status_code": outcome.status_code,
        "error_code": outcome.error_code,
        "blocked": outcome.blocked,
        "input_character_count": outcome.input_character_count,
        "output_character_count": outcome.output_character_count,
        "entity_counts": dict(outcome.summary.entity_types),
        "actions": _action_counts(outcome.summary),
        "provider_latency_ms": outcome.provider_latency_ms,
        "pipeline_latency_ms": outcome.pipeline_latency_ms,
        "occurred_at": attempt.started_at,
    }


def _action_counts(summary: PrivacySummary) -> dict[str, int]:
    """Counts per action. Names and integers, never a value."""
    return {
        "detected": summary.detected,
        "tokenized": summary.tokenized,
        "redacted": summary.redacted,
        "pseudonymized": summary.pseudonymized,
        "allowed": summary.allowed,
        "blocked": summary.blocked,
        "restored": summary.restored,
        "unknown_tokens": summary.unknown_tokens,
    }
