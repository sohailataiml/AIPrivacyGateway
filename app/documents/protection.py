"""Applying a document's labeled spans: tokens in, originals in the vault.

The last stage before a document can be sent anywhere. Given an
:class:`~app.documents.analysis.models.AnalyzedDocument`, every span is replaced
according to the action already attached to it, every reversible replacement is
backed by a durable vault mapping, and what comes out is a
:class:`ProtectedDocument` — text safe to hand to a provider.

**This module writes almost none of that itself.** The splice and the batched
mint are `app/tokenization/tokenizer.py`, unchanged. Reimplementing them for
documents would duplicate the two pieces of code in the system where a mistake
is both silent and unrecoverable: replacement runs right to left because every
offset indexes the *original* string, and mappings are minted in one call
because a round trip per span is arithmetically fatal on a document (ADR-0022).
A second copy of either would be a second place for them to drift.

Three things this stage must get right, and they are the whole module.

**The policy must be the one analysis used.** `AnalyzedDocument` carries its
snapshot rather than a version number for exactly this reason: policy is cached
for 30 seconds and an operator can edit it mid-flight, so resolving it again
here could apply actions the labels never agreed to — both stages correct in
isolation, every count reporting success, and the wrong text sent. The snapshot
travels with the analysis.

**The entity budget must be the document's.** The tokenizer enforces
`policy.max_entities`, which is sized for a chat request — 500 by default.
Analysis has already enforced `MAX_DOCUMENT_ENTITIES` against the same spans, so
re-applying the prompt ceiling here would refuse documents that analysis
accepted, at the very end of the most expensive path in the system.
:class:`_DocumentEntityBudget` is a read-through view of the snapshot that
reports the document ceiling and changes nothing else.

**The session is the caller's.** The vault is session-scoped by design
(ADR-0003, ADR-0023): a token minted in one session does not resolve in another,
and logging out destroys them. A document's tokens are only useful in the
conversation that will quote them, so the session id is a parameter rather than
something invented here. Inventing one would mint mappings that nothing can
resolve and that nothing but a TTL will ever clean up.

Nothing here logs anything derived from content, and the module makes no log
call carrying a value — same reasoning as the tokenizer: the cheapest guarantee
that a value is never logged is having nowhere for it to go.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from app.domain.errors import ErrorCode, GatewayError
from app.domain.models import DetectedEntity
from app.observability.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Sequence
    from uuid import UUID

    from app.documents.analysis.models import AnalyzedDocument
    from app.domain.models import EntityAction, PrivacySummary, TransformedText
    from app.policy.models import PolicySnapshot

logger = get_logger(__name__)


class DocumentAnalysis(Protocol):
    """The narrow slice of detection this module needs."""

    async def analyze(
        self, *, tenant_id: UUID, user_id: UUID, document_id: UUID
    ) -> AnalyzedDocument:
        """Return the document's labeled spans and the policy that decided them."""
        ...


class TextProtector(Protocol):
    """The tokenizer, from this module's point of view.

    A Protocol so protection can be tested without a Redis instance, and so the
    tokenizer stays a dependency rather than a base class.
    """

    async def transform(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        text: str,
        entities: Sequence[DetectedEntity],
        policy: PolicyLike,
    ) -> TransformedText:
        """Replace every span per policy and persist the mappings it creates."""
        ...


class PolicyLike(Protocol):
    """Repeated from ``app.tokenization.protocols`` to keep the import one-way."""

    @property
    def max_entities(self) -> int: ...
    @property
    def session_ttl_seconds(self) -> int: ...
    def action_for(self, entity_type: str) -> EntityAction: ...
    def min_score_for(self, entity_type: str) -> float: ...


@dataclass(frozen=True, slots=True)
class _DocumentEntityBudget:
    """The analysis policy, with the document's entity ceiling substituted.

    Every other question is answered by the snapshot itself, so an action or a
    threshold cannot differ between the stage that decided it and the stage that
    applies it. Only ``max_entities`` is overridden, and only because the
    tokenizer's ceiling is the per-request one.

    This is not a way to loosen a policy. The ceiling it reports is a deployment
    setting that analysis has *already* enforced against the same spans; by the
    time the tokenizer re-checks it, the answer is known to pass.
    """

    snapshot: PolicySnapshot
    document_max_entities: int

    @property
    def max_entities(self) -> int:
        return self.document_max_entities

    @property
    def session_ttl_seconds(self) -> int:
        return self.snapshot.session_ttl_seconds

    def action_for(self, entity_type: str) -> EntityAction:
        return self.snapshot.action_for(entity_type)

    def min_score_for(self, entity_type: str) -> float:
        return self.snapshot.min_score_for(entity_type)


@dataclass(frozen=True, slots=True)
class ProtectedDocument:
    """A document with every detected span replaced. Safe to send to a provider.

    The document-shaped counterpart of ``ProtectedChatRequest``, and the same
    checkpoint: it exists only where protection has completed and every mapping
    it needed is durably in the vault. A provider adapter that accepted a
    ``SegmentedDocument`` or an ``AnalyzedDocument`` would be a type error, not a
    review miss.

    **Confidential, not Restricted** — `docs/data-classification.md` classes a
    protected prompt that way. It is not persisted, it is never logged, and
    ``__repr__`` reports counts. The distinction from Restricted is real but
    thin: the text contains no *detected* original, and detection is
    probabilistic, so what it contains is "everything the recognizers found,
    replaced".

    ``mappings`` is deliberately absent. The originals are in the vault, which is
    where the next stage resolves them from; carrying them alongside the text
    would put a Restricted value on the object that gets passed to a provider
    adapter.
    """

    tenant_id: UUID
    session_id: UUID
    document_id: UUID
    text: str
    summary: PrivacySummary
    policy_version: int

    def __post_init__(self) -> None:
        if not self.text:
            # Analysis refuses a document with no extractable text, so an empty
            # protected text means the splice consumed everything -- a bug here,
            # not a property of the document.
            raise ValueError("a protected document must carry text")

    @property
    def character_count(self) -> int:
        return len(self.text)

    def __repr__(self) -> str:
        # Defensive: a stray repr() in a traceback must not spill the document.
        return (
            f"ProtectedDocument(document_id={self.document_id!r}, "
            f"characters={self.character_count}, protected={self.summary.detected})"
        )


class DocumentProtector:
    """Turns a stored document into text a provider may see."""

    __slots__ = ("_analysis", "_max_entities", "_tokenizer")

    def __init__(
        self,
        *,
        analysis: DocumentAnalysis,
        tokenizer: TextProtector,
        max_entities: int,
    ) -> None:
        if max_entities < 1:
            raise ValueError("max_entities must be at least 1")
        self._analysis = analysis
        self._tokenizer = tokenizer
        self._max_entities = max_entities

    async def protect(
        self,
        *,
        tenant_id: UUID,
        user_id: UUID,
        session_id: UUID,
        document_id: UUID,
    ) -> ProtectedDocument:
        """Analyze one document and replace every span the policy acts on.

        Args:
            tenant_id: The authenticated principal's tenant.
            user_id: The principal the document belongs to.
            session_id: The session the mappings are scoped to. Tokens minted
                here resolve only within it, so it must be the session of the
                conversation that will quote them.
            document_id: The document to protect.

        Returns:
            A :class:`ProtectedDocument`. Its existence means every mapping the
            document needed is durably in the vault.

        Raises:
            DocumentNotFoundError: no such document for this principal.
            DocumentExtractionError: unparseable, or no extractable text.
            PolicyViolationError: the policy blocks an entity type present in
                the document. Raised by analysis, before any vault write.
            EntityLimitExceededError: more spans than the document budget.
            DetectorUnavailableError: the detector could not run.
            VaultUnavailableError: the mappings could not be persisted. Nothing
                is returned, so no partially protected text can be sent.
        """
        analyzed = await self._analysis.analyze(
            tenant_id=tenant_id, user_id=user_id, document_id=document_id
        )

        transformed = await self._tokenizer.transform(
            tenant_id=tenant_id,
            session_id=session_id,
            text=analyzed.segmented.document.text,
            entities=_as_detections(analyzed),
            policy=_DocumentEntityBudget(
                snapshot=analyzed.policy, document_max_entities=self._max_entities
            ),
        )
        _verify_every_span_was_acted_on(analyzed, transformed)

        # Identifiers, a version, and counts. The counts come from the summary,
        # which is the tokenizer's account of what it actually did rather than
        # this module's account of what it asked for.
        logger.info(
            "document_protected",
            tenant_id=str(tenant_id),
            session_id=str(session_id),
            document_id=str(document_id),
            policy_version=analyzed.policy_version,
            detected=transformed.summary.detected,
            tokenized=transformed.summary.tokenized,
            redacted=transformed.summary.redacted,
            pseudonymized=transformed.summary.pseudonymized,
            allowed=transformed.summary.allowed,
        )
        return ProtectedDocument(
            tenant_id=tenant_id,
            session_id=session_id,
            document_id=document_id,
            text=transformed.text,
            summary=transformed.summary,
            policy_version=analyzed.policy_version,
        )

    def __repr__(self) -> str:
        return f"DocumentProtector(max_entities={self._max_entities})"


def _as_detections(analyzed: AnalyzedDocument) -> tuple[DetectedEntity, ...]:
    """The labeled spans as the plain detections the tokenizer expects.

    A narrowing, not a translation: the tokenizer takes spans and a policy and
    derives the action itself. Because the policy it is given is the one that
    produced these labels, that derivation reproduces them exactly -- which
    :func:`_verify_every_span_was_acted_on` then checks rather than assumes.
    """
    return tuple(
        DetectedEntity(
            entity_type=span.entity_type,
            start=span.start,
            end=span.end,
            score=span.score,
        )
        for span in analyzed.spans
    )


def _verify_every_span_was_acted_on(
    analyzed: AnalyzedDocument, transformed: TransformedText
) -> None:
    """Refuse a result that acted on a different set of spans than were labeled.

    The tokenizer re-selects: it re-validates bounds, re-applies the policy's
    confidence thresholds, and re-resolves overlaps with its own simpler rule.
    On spans that analysis has already made non-overlapping and confident, all
    three are no-ops -- but "should be a no-op" is exactly the kind of claim that
    stops being true when one of the two rules is edited and the other is not.

    A mismatch means a span was silently dropped between the decision and the
    splice, so the document is refused rather than sent with an original still
    in it. This is the assertion that makes reusing the prompt tokenizer safe
    instead of merely convenient.
    """
    if transformed.summary.detected == analyzed.span_count:
        return
    raise GatewayError(
        # An internal inconsistency, not a caller error: the caller supplied a
        # document id and everything else came from this process.
        code=ErrorCode.INTERNAL_ERROR,
        log_context={
            "reason": "protection_dropped_labeled_spans",
            "labeled": analyzed.span_count,
            "protected": transformed.summary.detected,
        },
    )


__all__ = [
    "DocumentAnalysis",
    "DocumentProtector",
    "PolicyLike",
    "ProtectedDocument",
    "TextProtector",
]
