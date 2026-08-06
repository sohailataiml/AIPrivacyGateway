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

**Serialisation, the scan, the digest, and the transmission are not here at
all.** They live in :class:`~app.outbound.gateway.OutboundGateway`, which
`/v1/chat` uses too. That is deliberate: a control implemented once on one route
is a control that can be forgotten on the other, and forgetting it is precisely
the failure ADR-0024 was written about.

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
from app.domain.errors import RequestTooLargeError
from app.domain.models import ChatMessage, PrivacySummary, ProtectedChatRequest
from app.observability.logging import get_logger
from app.outbound.gateway import OutboundBlockedError

if TYPE_CHECKING:
    from uuid import UUID

    from app.documents.protection import ProtectedDocument
    from app.domain.models import Principal, ProviderResponse
    from app.outbound.gateway import Attestation, OutboundGateway
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
        self,
        *,
        tenant_id: UUID,
        user_id: UUID,
        session_id: UUID,
        document_id: UUID,
        instruction: str = "",
    ) -> ProtectedDocument:
        """Return provider-safe text and instruction, mappings durably stored."""
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
        "_instruction_max_chars",
        "_outbound",
        "_policies",
        "_protection",
        "_restorer",
    )

    def __init__(
        self,
        *,
        protection: DocumentProtection,
        policies: PolicySource,
        outbound: OutboundGateway,
        restorer: OutputRestorer,
        audit: AuditSink,
        instruction_max_chars: int = DEFAULT_INSTRUCTION_MAX_CHARS,
    ) -> None:
        if instruction_max_chars < 1:
            raise ValueError("instruction_max_chars must be at least 1")
        self._protection = protection
        self._policies = policies
        self._outbound = outbound
        self._restorer = restorer
        self._audit = audit
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
        # Policy allows the alias; the registry has to have it too. Both checks
        # are cheap and both come before the document is opened.
        self._outbound.authorize(provider)

        # One call, so the document and the instruction share a tenant, a
        # session, a policy snapshot, a tokenizer, and a vault -- which is what
        # makes a value appearing in both collapse onto one token.
        protected = await self._protection.protect(
            tenant_id=principal.tenant_id,
            user_id=user_id,
            session_id=session_id,
            document_id=document_id,
            instruction=instruction,
        )

        request = _protected_request(
            principal=principal,
            request_id=request_id,
            session_id=session_id,
            protected=protected,
            provider=provider,
            model=model,
        )

        try:
            transmission = await self._outbound.send(request, policy=policy)
        except OutboundBlockedError as blocked:
            await self._attest(
                principal=principal,
                request_id=request_id,
                session_id=session_id,
                policy=policy,
                provider=provider,
                model=model,
                summary=protected.summary,
                attestation=blocked.attestation,
                is_blocked=True,
                elapsed=started,
                request_characters=len(protected.text),
            )
            # Entity *type* names only, and only in the error the caller never
            # sees the context of. No value and no offset.
            logger.warning(
                "document_outbound_blocked",
                tenant_id=str(principal.tenant_id),
                document_id=str(document_id),
                request_id=str(request_id),
                reason="outbound_scan_found_entities",
            )
            raise

        restored = await self._restorer.restore(
            tenant_id=principal.tenant_id,
            session_id=session_id,
            response=transmission.response,
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
            attestation=transmission.attestation,
            is_blocked=False,
            elapsed=started,
            request_characters=len(protected.text),
            response_characters=len(restored.text),
            response_text=restored.text,
            provider_latency_ms=transmission.provider_latency_ms,
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
            outbound_hmac=transmission.attestation.payload_hmac,
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
        attestation: Attestation,
        is_blocked: bool,
        elapsed: float,
        request_characters: int,
        response_characters: int = 0,
        response_text: str | None = None,
        provider_latency_ms: int | None = None,
    ) -> None:
        """Write the audit row. Counts, digests, and codes only.

        The correlation digests are populated rather than left null: ADR-0024
        is explicit that a column which is always null is worse than an absent
        one, and this is the path that has the material to fill them.
        """
        entity_counts, actions = counts_from_summary(summary)
        tenant_id = principal.tenant_id
        await self._audit.submit(
            AuditRecord(
                tenant_id=tenant_id,
                request_id=request_id,
                status_code=422 if is_blocked else 200,
                api_key_id=principal.api_key_id,
                session_id_hash=self._outbound.session_digest(
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
                blocked=is_blocked,
                block_reason_code="outbound_scan" if is_blocked else None,
                provider_latency_ms=provider_latency_ms,
                pipeline_latency_ms=int((time.perf_counter() - elapsed) * 1000),
                outbound_hmac=attestation.payload_hmac,
                outbound_scan=attestation.verdict,
                prompt_hmac=attestation.prompt_hmac,
                response_hmac=(
                    self._outbound.response_digest(tenant_id=tenant_id, text=response_text)
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
) -> ProtectedChatRequest:
    """Assemble the provider request from an already-protected document.

    The instruction is a **system** message and the document is a **user**
    message, kept apart rather than concatenated. Splicing a caller's
    instruction into the same turn as the document would let it be read as part
    of the content, which is the shape of a prompt-injection foothold the
    gateway should not hand out for free.

    Both halves arrive already protected. ``DocumentProtector`` splices the
    instruction under the same session as the document, so an original a caller
    wrote into their instruction is a token by the time it reaches here.
    """
    return ProtectedChatRequest(
        request_id=request_id,
        tenant_id=principal.tenant_id,
        session_id=session_id,
        provider_alias=provider,
        model_alias=model,
        messages=(
            ChatMessage(role="system", content=protected.instruction),
            ChatMessage(role="user", content=protected.text),
        ),
        policy_version=protected.policy_version,
    )


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
