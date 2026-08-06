"""Detection over a stored document, end to end.

Opens and decrypts (Phase 1), extracts and segments (Phase 2), then runs the
detector over every segment, merges what comes back into one set of labeled
global spans, and refuses the document if the policy says so. The result is an
:class:`~app.documents.analysis.models.AnalyzedDocument`, which exists only for
the life of the call — nothing here writes anything down (ADR-0030).

Three things this module is careful about.

**Detection is not narrowed to the policy's entity types.** Defect 7 in
``PROGRESS.md`` was two fail-safes cancelling out: the policy defaults an
unconfigured type to ``TOKENIZE``, and the pipeline asked the detector only for
policy-listed types, so an unlisted sensitive type was never detected and the
protective default could never fire. ``requested_entities=None``, deliberately,
exactly as ``SecurePipeline._detect`` does.

**Diagnostics are off, always.** Not configurable. A recognizer name is
diagnostic output for a privileged caller inspecting one prompt; there is no
privileged document path that wants it, and a flag that could turn it on is a
flag someone can turn on.

**Concurrency is bounded and the bound is shared.** Presidio runs on a worker
thread per call. A 300-segment document with no bound would ask for 300 threads,
and two such documents would ask for 600 — CPU-bound work that starves the
request path rather than going faster. The semaphore lives on the analyzer, not
on the call, so the bound holds across concurrent documents rather than per
document.

A failed segment cancels the rest. ``asyncio.TaskGroup`` rather than
``gather``: with ``gather`` the first failure propagates while its siblings keep
running, so a document that is already refused goes on paying for detection over
every remaining segment.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Protocol

from app.documents.analysis.models import AnalyzedDocument
from app.documents.analysis.spans import (
    blocked_entity_type,
    coalesce,
    label,
    resolve,
    select_confident,
    to_global,
)
from app.domain.errors import (
    DetectorUnavailableError,
    EntityLimitExceededError,
    GatewayError,
    PolicyViolationError,
)
from app.observability.logging import get_logger
from app.pipeline.context import DEFAULT_LANGUAGE

if TYPE_CHECKING:
    from collections.abc import Iterator
    from uuid import UUID

    from app.detection.base import Detector
    from app.documents.analysis.spans import GlobalDetection
    from app.documents.segmentation import SegmentedDocument
    from app.domain.models import DetectedEntity
    from app.policy.models import PolicySnapshot

logger = get_logger(__name__)

DEFAULT_MAX_ENTITIES = 10_000
"""Ceiling on labeled spans in one document.

Not the policy's ``max_entities``, which is sized for a chat request: 500 spans
is generous for a prompt and refuses an ordinary clinical document. This bound
exists to stop one upload from becoming an unbounded batch of vault writes in
the phase that protects it, and 10,000 matches ``MAX_POLICY_ENTITY_BUDGET`` --
the most a policy is allowed to ask for at all.
"""

DEFAULT_CONCURRENCY = 4
"""Segments detected at once, across every document in flight."""


class SegmentSource(Protocol):
    """The narrow slice of document processing this module needs.

    Deliberately not ``DocumentProcessor``: analysis needs segments and nothing
    else, and depending on the concrete class would let it grow a dependency on
    how extraction is isolated.
    """

    async def segment(
        self, *, tenant_id: UUID, user_id: UUID, document_id: UUID
    ) -> SegmentedDocument:
        """Open, decrypt, extract, and segment one document."""
        ...


class PolicySource(Protocol):
    """Resolution of the active policy snapshot for a tenant.

    ``snapshot_for`` rather than ``resolve``: analysing a document names no
    provider and no model, so there is no route to authorize. Requiring one
    would mean inventing a provider argument that means nothing.
    """

    async def snapshot_for(self, tenant_id: UUID) -> PolicySnapshot:
        """Return the tenant's active policy."""
        ...


class DocumentAnalyzer:
    """Turns a stored document into labeled, policy-decided global spans."""

    __slots__ = ("_detector", "_max_entities", "_policies", "_semaphore", "_source")

    def __init__(
        self,
        *,
        source: SegmentSource,
        detector: Detector,
        policies: PolicySource,
        max_entities: int = DEFAULT_MAX_ENTITIES,
        concurrency: int = DEFAULT_CONCURRENCY,
    ) -> None:
        if max_entities < 1:
            raise ValueError("max_entities must be at least 1")
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        self._source = source
        self._detector = detector
        self._policies = policies
        self._max_entities = max_entities
        self._semaphore = asyncio.Semaphore(concurrency)

    @property
    def detector(self) -> Detector:
        """The detector this analyzer runs, so wiring can be asserted.

        Exposed for the same reason ``PresidioDetector.config`` is: whether
        documents and prompts share one configured engine is a property of the
        composition, and a test that has to reach into a private attribute to
        check it will be deleted the first time the attribute is renamed.
        """
        return self._detector

    async def analyze(
        self, *, tenant_id: UUID, user_id: UUID, document_id: UUID
    ) -> AnalyzedDocument:
        """Detect over one document and return its labeled spans.

        Args:
            tenant_id: The authenticated principal's tenant.
            user_id: The principal the document belongs to. Scoping is enforced
                by the storage service underneath, not here.
            document_id: The document to analyze.

        Returns:
            An :class:`AnalyzedDocument`. Its existence means the policy has
            been applied and nothing in the document was blocked.

        Raises:
            DocumentNotFoundError: no such document for this principal.
            DocumentEncryptionError: the stored bytes failed authentication.
            DocumentExtractionError: unparseable, or no extractable text.
            DocumentExtractionTimeoutError: extraction overran its budget.
            PolicyNotFoundError: the tenant has no usable active policy.
            DetectorUnavailableError: the detector could not run.
            EntityLimitExceededError: more spans than the document budget.
            PolicyViolationError: the policy blocks an entity type present in
                the document. Raised before any span is labeled.
        """
        # Resolved first: a tenant with no usable policy is refused before the
        # expensive work, and the snapshot is then fixed for the whole document
        # so a policy edit mid-analysis cannot apply to half of it.
        policy = await self._policies.snapshot_for(tenant_id)

        segmented = await self._source.segment(
            tenant_id=tenant_id, user_id=user_id, document_id=document_id
        )
        detections = await self._detect(segmented)

        merged = coalesce(detections)
        confident = select_confident(merged, policy=policy)
        resolved = resolve(confident)

        self._enforce_budget(resolved, tenant_id=tenant_id, document_id=document_id)
        self._reject_blocked(resolved, policy=policy, tenant_id=tenant_id, document_id=document_id)

        analyzed = AnalyzedDocument(
            tenant_id=tenant_id,
            document_id=document_id,
            segmented=segmented,
            spans=label(resolved, document=segmented.document, policy=policy),
            policy=policy,
        )

        # Identifiers, a version, and counts. Never a value and never an
        # offset -- an offset plus the stored ciphertext is a map of where the
        # sensitive values are.
        #
        # Never the per-type breakdown either. "This document holds two social
        # security numbers" is not a value, and it is still a description of the
        # contents; it belongs in an audit record, which is access-controlled,
        # rather than on stdout, which is not. The breakdown is available on the
        # returned object for the phase that writes that record.
        #
        # ``detected`` rather than a new key name: it is the existing counter
        # vocabulary in ``ALLOWED_EVENT_KEYS``, and a log field invented per
        # call site is a field nobody has reviewed.
        logger.info(
            "document_analyzed",
            tenant_id=str(tenant_id),
            document_id=str(document_id),
            policy_version=policy.version,
            segment_count=analyzed.segment_count,
            detected=analyzed.span_count,
        )
        return analyzed

    # -- Internals --------------------------------------------------------
    async def _detect(self, segmented: SegmentedDocument) -> list[GlobalDetection]:
        """Run the detector over every segment and promote the offsets.

        Segment order is preserved, so two runs over the same document produce
        the same detections in the same order regardless of which segment
        happened to finish first.
        """
        try:
            async with asyncio.TaskGroup() as group:
                tasks = [
                    group.create_task(self._detect_segment(segmented, index))
                    for index in range(segmented.segment_count)
                ]
        except BaseExceptionGroup as failures:
            # A cancellation from outside is re-raised by TaskGroup as a bare
            # CancelledError rather than a group, so it passes through here
            # untouched and is never reported as a detector fault.
            raise _first_failure(failures) from failures

        promoted: list[GlobalDetection] = []
        for segment, task in zip(segmented.segments, tasks, strict=True):
            promoted.extend(to_global(segment, task.result()))
        return promoted

    async def _detect_segment(
        self, segmented: SegmentedDocument, index: int
    ) -> list[DetectedEntity]:
        async with self._semaphore:
            return await self._detector.detect(
                segmented.text_of(segmented.segments[index]),
                language=DEFAULT_LANGUAGE,
                requested_entities=None,
                diagnostic=False,
            )

    def _enforce_budget(
        self, detections: list[GlobalDetection], *, tenant_id: UUID, document_id: UUID
    ) -> None:
        if len(detections) > self._max_entities:
            raise EntityLimitExceededError(
                log_context={
                    "tenant_id": str(tenant_id),
                    "document_id": str(document_id),
                    "entity_count": len(detections),
                    "limit": self._max_entities,
                    "reason": "document_entity_budget_exceeded",
                }
            )

    def _reject_blocked(
        self,
        detections: list[GlobalDetection],
        *,
        policy: PolicySnapshot,
        tenant_id: UUID,
        document_id: UUID,
    ) -> None:
        blocked = blocked_entity_type(detections, policy=policy)
        if blocked is not None:
            raise PolicyViolationError(
                log_context={
                    "tenant_id": str(tenant_id),
                    "document_id": str(document_id),
                    "entity_type": blocked,
                    "reason": "policy_blocked_entity",
                }
            )

    def __repr__(self) -> str:
        return f"DocumentAnalyzer(max_entities={self._max_entities})"


def _first_failure(failures: BaseExceptionGroup[BaseException]) -> GatewayError:
    """The domain error to report for a group of failed segments.

    ``TaskGroup`` reports every failure at once, and segments are independent,
    so several can fail the same way. The caller needs one error: the first
    ``GatewayError`` in segment order, which keeps the answer stable across
    runs and keeps "the vault is down" from being reported as "the detector is
    down".

    Anything that is not already a domain error becomes
    ``DetectorUnavailableError`` and loses its message. A third-party exception
    string can carry the text the detector was analyzing, so it is never
    propagated and never logged.
    """
    for failure in _flatten(failures):
        if isinstance(failure, GatewayError):
            return failure
    return DetectorUnavailableError(
        log_context={"stage": "document_detection", "reason": "stage_failed"}
    )


def _flatten(failures: BaseExceptionGroup[BaseException]) -> Iterator[BaseException]:
    """Yield the leaf exceptions of a possibly nested group, in order."""
    for failure in failures.exceptions:
        if isinstance(failure, BaseExceptionGroup):
            yield from _flatten(failure)
        else:
            yield failure


__all__ = [
    "DEFAULT_CONCURRENCY",
    "DEFAULT_MAX_ENTITIES",
    "DocumentAnalyzer",
    "PolicySource",
    "SegmentSource",
]
