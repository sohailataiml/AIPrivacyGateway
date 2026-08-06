"""The document request, end to end, in the order the guarantees require.

```text
protect → serialize → scan → transmit → restore → attest
```

The order is the whole design, and each step is placed where it is because
moving it would break something specific.

**Protection comes first**, and it finishes before anything is serialised. A
payload assembled from half-protected text is a payload that could be sent, and
the type system is what stops that: ``DocumentProtector`` returns a
``ProtectedDocument`` or it raises.

**Serialisation happens before the scan and before transmission**, and the same
bytes are used for all three. If the scan ran over one rendering and the adapter
sent another, the attestation would prove something nobody checked and the scan
would have checked something nobody sent. There is one byte string per request
and it is produced once.

**The scan runs before the provider call.** After it, the leak has happened; a
check that runs afterwards is a report, not a control (ADR-0008, ADR-0024).

**Restoration runs after the provider call and fails closed.** A vault outage on
the way back means the caller gets nothing rather than half-restored text, which
would be indistinguishable from a successful answer with fewer entities.

**The attestation is written on every path that reached serialisation**,
including the blocked one. ADR-0024 is explicit that a request stopped by the
scan is the case most worth auditing: a row proving the check ran and refused is
the evidence the whole mechanism exists to produce.

What this module does *not* do is decide anything about privacy. Detection,
policy, and the splice happened upstream; the provider adapter enforces its own
allowlist and deadline; restoration owns the token grammar. This is the file
that puts them in an order and refuses to let one of them be skipped.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from app.audit.models import AuditRecord, counts_from_summary
from app.documents.outbound import ScanVerdict, scan_outbound, serialize_outbound
from app.domain.errors import PolicyViolationError, RequestTooLargeError
from app.domain.models import ChatMessage, PrivacySummary, ProtectedChatRequest
from app.observability.logging import get_logger

if TYPE_CHECKING:
    from uuid import UUID

    from app.audit.correlation import CorrelationHasher
    from app.detection.base import Detector
    from app.documents.protection import ProtectedDocument
    from app.domain.models import Principal, ProviderResponse
    from app.llm.base import LLMProvider
    from app.llm.registry import ProviderRegistry
    from app.policy.models import PolicySnapshot
    from app.restoration.protocols import PolicyLike as RestorationPolicyLike
    from app.restoration.results import RestoredOutput

logger = get_logger(__name__)

DEFAULT_INSTRUCTION_MAX_CHARS = 4_000
"""Ceiling on the caller's instruction.

The document is bounded by ``MAX_DOCUMENT_BYTES``; the instruction is ordinary
request text and gets a much smaller bound, because it is the one part of this
payload a caller writes directly.
"""


class DocumentProtection(Protocol):
    """The narrow slice of protection this module needs."""

    async def protect(
        self, *, tenant_id: UUID, user_id: UUID, session_id: UUID, document_id: UUID
    ) -> ProtectedDocument:
        """Return provider-safe text with every mapping durably stored."""
        ...


class PolicySource(Protocol):
    """Resolution and route authorization for one request."""

    async def resolve(self, *, tenant_id: UUID, provider: str, model: str) -> PolicySnapshot:
        """Return the active policy, refusing an unpermitted destination."""
        ...


class OutputRestorer(Protocol):
    """Restoration, from this module's point of view.

    ``policy`` is typed as the restoration package's own ``PolicyLike`` rather
    than something looser: a Protocol method is contravariant in its parameters,
    so widening it here would make the real ``OutputPipeline`` fail to satisfy
    this seam for a reason that has nothing to do with behaviour.
    """

    async def restore(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        response: ProviderResponse,
        policy: RestorationPolicyLike,
    ) -> RestoredOutput:
        """Replace this session's tokens with their originals."""
        ...


class AuditSink(Protocol):
    """Where the attestation goes."""

    async def submit(self, record: AuditRecord) -> None:
        """Accept one record. Never raises for a full queue on the request path."""
        ...


@dataclass(frozen=True, slots=True)
class DocumentAnswer:
    """What the caller gets back. Restored, and only for the request principal.

    Restricted: ``text`` holds originals again. Never log one, and never place
    one anywhere but the response to the principal that asked.
    """

    request_id: UUID
    session_id: UUID
    document_id: UUID
    provider: str
    model: str
    text: str
    privacy: PrivacySummary
    outbound_hmac: str
    """The attestation for this request, echoed so a caller can retain it.

    A digest, never the payload. It lets a caller who kept the payload prove
    later what was transmitted, without the gateway having stored it.
    """

    def __repr__(self) -> str:
        return (
            f"DocumentAnswer(request_id={self.request_id!r}, "
            f"document_id={self.document_id!r}, characters={len(self.text)})"
        )


class DocumentPipeline:
    """Runs one document through protection, transmission, and restoration."""

    __slots__ = (
        "_audit",
        "_detector",
        "_hasher",
        "_instruction_max_chars",
        "_policies",
        "_protection",
        "_providers",
        "_restorer",
    )

    def __init__(
        self,
        *,
        protection: DocumentProtection,
        policies: PolicySource,
        detector: Detector,
        providers: ProviderRegistry,
        restorer: OutputRestorer,
        audit: AuditSink,
        hasher: CorrelationHasher,
        instruction_max_chars: int = DEFAULT_INSTRUCTION_MAX_CHARS,
    ) -> None:
        if instruction_max_chars < 1:
            raise ValueError("instruction_max_chars must be at least 1")
        self._protection = protection
        self._policies = policies
        self._detector = detector
        self._providers = providers
        self._restorer = restorer
        self._audit = audit
        self._hasher = hasher
        self._instruction_max_chars = instruction_max_chars

    async def run(
        self,
        *,
        principal: Principal,
        request_id: UUID,
        session_id: UUID,
        user_id: UUID,
        document_id: UUID,
        provider: str,
        model: str,
        instruction: str,
    ) -> DocumentAnswer:
        """Send one protected document to a model and restore the answer.

        Args:
            principal: The verified API key record. The tenant comes from here
                and never from the request body.
            request_id: Correlation id for this request.
            session_id: The session the vault mappings belong to.
            user_id: The principal the document belongs to.
            document_id: The document to send.
            provider: Provider alias. Authorized against the policy allowlist
                before any work happens.
            model: Model alias, likewise.
            instruction: What the caller wants done with the document.

        Raises:
            RequestTooLargeError: the instruction exceeds its bound.
            ProviderNotAllowedError, ModelNotAllowedError: destination refused.
            DocumentNotFoundError: no such document for this principal.
            PolicyViolationError: an entity type the policy blocks is present,
                or the outbound scan found one that survived protection.
            DetectorUnavailableError, VaultUnavailableError: fail closed.
            ProviderTimeoutError, ProviderUnavailableError: upstream failed.
            RestorationError: the answer could not be safely restored.
        """
        started = time.perf_counter()
        _enforce_instruction_size(instruction, limit=self._instruction_max_chars)

        # Destination first. An unpermitted provider costs nothing to refuse and
        # must not be able to buy a decrypt-extract-detect pass.
        policy = await self._policies.resolve(
            tenant_id=principal.tenant_id, provider=provider, model=model
        )
        adapter = self._providers.get(provider)

        protected = await self._protection.protect(
            tenant_id=principal.tenant_id,
            user_id=user_id,
            session_id=session_id,
            document_id=document_id,
        )

        request = _protected_request(
            principal=principal,
            request_id=request_id,
            session_id=session_id,
            protected=protected,
            provider=provider,
            model=model,
            instruction=instruction,
        )

        # One byte string, produced once, used for the scan, the transmission,
        # and the attestation. Three renderings would be three chances to check
        # one thing and send another.
        payload = serialize_outbound(request)
        attestation = self._hasher.outbound_digest(tenant_id=principal.tenant_id, payload=payload)

        scan = await scan_outbound(request, detector=self._detector, policy=policy)
        if not scan.is_clean:
            await self._attest(
                principal=principal,
                request_id=request_id,
                session_id=session_id,
                policy=policy,
                provider=provider,
                model=model,
                summary=protected.summary,
                attestation=attestation,
                verdict=scan.verdict,
                blocked=True,
                elapsed=started,
                request_characters=len(request.messages[-1].content),
            )
            # Entity *type* names, never a value and never an offset. The
            # caller learns the request was refused and nothing more.
            logger.warning(
                "document_outbound_blocked",
                tenant_id=str(principal.tenant_id),
                document_id=str(document_id),
                request_id=str(request_id),
                reason="outbound_scan_found_entities",
            )
            raise PolicyViolationError(
                log_context={
                    "reason": "outbound_scan_found_entities",
                    "entity_type": ",".join(scan.findings),
                }
            )

        response = await _complete(adapter, request)
        restored = await self._restorer.restore(
            tenant_id=principal.tenant_id,
            session_id=session_id,
            response=response,
            policy=policy,
        )

        summary = protected.summary.merged_with(restored.summary)
        await self._attest(
            principal=principal,
            request_id=request_id,
            session_id=session_id,
            policy=policy,
            provider=provider,
            model=model,
            summary=summary,
            attestation=attestation,
            verdict=scan.verdict,
            blocked=False,
            elapsed=started,
            request_characters=len(request.messages[-1].content),
            response_characters=len(restored.text),
            response_text=restored.text,
        )
        logger.info(
            "document_completed",
            tenant_id=str(principal.tenant_id),
            document_id=str(document_id),
            request_id=str(request_id),
            policy_version=policy.version,
            provider_alias=provider,
            model_alias=model,
            detected=summary.detected,
            restored=summary.restored,
        )
        return DocumentAnswer(
            request_id=request_id,
            session_id=session_id,
            document_id=document_id,
            provider=provider,
            model=restored.model,
            text=restored.text,
            privacy=summary,
            outbound_hmac=attestation,
        )

    # -- Internals --------------------------------------------------------
    async def _attest(
        self,
        *,
        principal: Principal,
        request_id: UUID,
        session_id: UUID,
        policy: PolicySnapshot,
        provider: str,
        model: str,
        summary: PrivacySummary,
        attestation: str,
        verdict: ScanVerdict,
        blocked: bool,
        elapsed: float,
        request_characters: int,
        response_characters: int = 0,
        response_text: str | None = None,
    ) -> None:
        """Write the audit row. Counts, digests, and codes only.

        The correlation digests are populated here rather than left null.
        ADR-0024 is explicit that a column which is always null is worse than an
        absent one, and this is the path that has the material to fill them.
        """
        entity_counts, actions = counts_from_summary(summary)
        tenant_id = principal.tenant_id
        await self._audit.submit(
            AuditRecord(
                tenant_id=tenant_id,
                request_id=request_id,
                status_code=422 if blocked else 200,
                api_key_id=principal.api_key_id,
                session_id_hash=self._hasher.session_digest(
                    tenant_id=tenant_id, session_id=session_id
                ),
                policy_id=policy.policy_id,
                policy_version=policy.version,
                provider_alias=provider,
                model_alias=model,
                input_character_count=request_characters,
                output_character_count=response_characters,
                entity_counts=entity_counts,
                actions=actions,
                blocked=blocked,
                block_reason_code="outbound_scan" if blocked else None,
                pipeline_latency_ms=int((time.perf_counter() - elapsed) * 1000),
                outbound_hmac=attestation,
                outbound_scan=verdict.value,
                response_hmac=(
                    self._hasher.response_digest(tenant_id=tenant_id, text=response_text)
                    if response_text is not None
                    else None
                ),
            )
        )

    def __repr__(self) -> str:
        return f"DocumentPipeline(instruction_max_chars={self._instruction_max_chars})"


def _protected_request(
    *,
    principal: Principal,
    request_id: UUID,
    session_id: UUID,
    protected: ProtectedDocument,
    provider: str,
    model: str,
    instruction: str,
) -> ProtectedChatRequest:
    """Assemble the provider request from an already-protected document.

    The instruction is a **system** message and the document is a **user**
    message, kept apart rather than concatenated. Splicing a caller's
    instruction into the same turn as the document would let it be read as part
    of the content, which is the shape of a prompt-injection foothold the
    gateway should not hand out for free.

    The instruction is not tokenized. It is the caller's own text about their
    own document, it never contains a value the gateway protected, and running
    it through the vault would mint mappings for text nobody needs restored.
    That is a deliberate limit, not an oversight: an instruction that quotes a
    patient's name reaches the provider as written, and the outbound scan is
    what catches it.
    """
    return ProtectedChatRequest(
        request_id=request_id,
        tenant_id=principal.tenant_id,
        session_id=session_id,
        provider_alias=provider,
        model_alias=model,
        messages=(
            ChatMessage(role="system", content=instruction),
            ChatMessage(role="user", content=protected.text),
        ),
        policy_version=protected.policy_version,
    )


async def _complete(adapter: LLMProvider, request: ProtectedChatRequest) -> ProviderResponse:
    """Call the provider, letting its own domain errors through untouched."""
    return await adapter.complete(request)


def _enforce_instruction_size(instruction: str, *, limit: int) -> None:
    if len(instruction) > limit:
        raise RequestTooLargeError(log_context={"reason": "instruction_too_long", "limit": limit})


__all__ = [
    "DEFAULT_INSTRUCTION_MAX_CHARS",
    "AuditSink",
    "DocumentAnswer",
    "DocumentPipeline",
    "DocumentProtection",
    "OutputRestorer",
    "PolicySource",
]
