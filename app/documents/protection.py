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

**The instruction is protected too, and by the same everything.** A caller who
writes "summarise Marguerite Okonkwo-Vasquez's referral" has put an original
into the payload, and a gateway that protects the document while sending that
verbatim has not protected the request. So the instruction is detected and
spliced here rather than at the route: same tenant, same session, same policy
snapshot, same tokenizer, same vault.

That sameness buys the property that matters. A value appearing in *both* the
document and the instruction produces the same fingerprint — tenant, session,
entity type, normalized value — so the vault returns the same token for both,
and the model sees one identifier for one person rather than two.

**The instruction is checked for blocked types before the document is
protected.** The tokenizer would refuse it anyway, but by then the document's
mappings are already in the vault: a request destined to fail would leave
records behind, which is exactly the outcome `app/pipeline/guards.py` orders its
stages to avoid.

Nothing here logs anything derived from content, and the module makes no log
call carrying a value — same reasoning as the tokenizer: the cheapest guarantee
that a value is never logged is having nowhere for it to go.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from app.domain.errors import ErrorCode, GatewayError, PolicyViolationError
from app.domain.models import DetectedEntity, EntityAction
from app.observability.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Sequence
    from uuid import UUID

    from app.detection.base import Detector
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
    instruction: str
    """The caller's instruction, protected under the same session as the text.

    Empty when none was supplied. It stays a separate field rather than being
    folded into ``text`` because the two travel as different messages: splicing
    a caller's instruction into the document's own turn would let it be read as
    part of the content.
    """

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

    __slots__ = ("_analysis", "_detector", "_language", "_max_entities", "_tokenizer")

    def __init__(
        self,
        *,
        analysis: DocumentAnalysis,
        tokenizer: TextProtector,
        detector: Detector,
        max_entities: int,
        language: str = "en",
    ) -> None:
        if max_entities < 1:
            raise ValueError("max_entities must be at least 1")
        self._analysis = analysis
        self._tokenizer = tokenizer
        self._detector = detector
        self._max_entities = max_entities
        self._language = language

    async def _detect_instruction(self, instruction: str) -> tuple[DetectedEntity, ...]:
        """Detect over the caller's instruction, or nothing for an empty one.

        Not narrowed to the policy's configured entity types, for the same
        reason the document is not: the policy's protective default for an
        unconfigured type cannot fire if no such entity is ever detected
        (defect 7). Diagnostics are off here too.
        """
        if not instruction.strip():
            return ()
        return tuple(
            await self._detector.detect(
                instruction,
                language=self._language,
                requested_entities=None,
                diagnostic=False,
            )
        )

    async def protect(
        self,
        *,
        tenant_id: UUID,
        user_id: UUID,
        session_id: UUID,
        document_id: UUID,
        instruction: str = "",
    ) -> ProtectedDocument:
        """Analyze one document and replace every span the policy acts on.

        Args:
            tenant_id: The authenticated principal's tenant.
            user_id: The principal the document belongs to.
            session_id: The session the mappings are scoped to. Tokens minted
                here resolve only within it, so it must be the session of the
                conversation that will quote them.
            document_id: The document to protect.
            instruction: The caller's own text about the document. Detected and
                protected under the same policy and session, so a value it
                shares with the document collapses onto one token.

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

        # Before the document's vault write, so a request the policy will refuse
        # leaves no mappings behind.
        instruction_entities = await self._detect_instruction(instruction)
        _reject_blocked_instruction(instruction_entities, policy=analyzed.policy)

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

        # A second call, same tenant and same session, so a value shared with
        # the document resolves to the token the document already minted. Two
        # round trips rather than one: ADR-0022 is about never paying a round
        # trip *per token*, and these are two batches, not two hundred.
        protected_instruction = (
            await self._tokenizer.transform(
                tenant_id=tenant_id,
                session_id=session_id,
                text=instruction,
                entities=instruction_entities,
                policy=analyzed.policy,
            )
            if instruction_entities
            else None
        )
        summary = transformed.summary
        if protected_instruction is not None:
            summary = summary.merged_with(protected_instruction.summary)

        # Identifiers, a version, and counts. The counts come from the summary,
        # which is the tokenizer's account of what it actually did rather than
        # this module's account of what it asked for.
        logger.info(
            "document_protected",
            tenant_id=str(tenant_id),
            session_id=str(session_id),
            document_id=str(document_id),
            policy_version=analyzed.policy_version,
            detected=summary.detected,
            tokenized=summary.tokenized,
            redacted=summary.redacted,
            pseudonymized=summary.pseudonymized,
            allowed=summary.allowed,
        )
        return ProtectedDocument(
            tenant_id=tenant_id,
            session_id=session_id,
            document_id=document_id,
            text=transformed.text,
            instruction=(
                protected_instruction.text if protected_instruction is not None else instruction
            ),
            summary=summary,
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


def _reject_blocked_instruction(
    entities: Sequence[DetectedEntity], *, policy: PolicySnapshot
) -> None:
    """Refuse the request if the instruction holds a blocked entity type.

    Runs before the document's vault write, so a request the policy will refuse
    leaves no mappings behind — the same ordering rule
    ``app/pipeline/guards.py`` applies across a chat request's messages.

    The entity type is safe to record; the value it stood for is deliberately
    absent from both the message and the log context.
    """
    for entity in entities:
        if policy.action_for(entity.entity_type) is EntityAction.BLOCK:
            raise PolicyViolationError(
                log_context={
                    "entity_type": entity.entity_type,
                    "reason": "policy_blocked_instruction_entity",
                }
            )
