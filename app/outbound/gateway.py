"""The one door to a provider, and the only place a payload is checked.

Everything the gateway sends upstream goes through :meth:`OutboundGateway.send`
— `/v1/chat` and `/v1/documents/{id}/process` alike. That is the point of the
module. Two routes with two copies of "serialize, scan, digest, transmit" is two
places for the scan to be skipped, two definitions of what was attested, and two
things to remember when either is fixed.

The order inside is fixed and each step is where it is because moving it breaks
something specific:

1. **Serialize.** One canonical byte string, produced once. It is what gets
   scanned, what gets transmitted, and what gets attested — if those were three
   renderings there would be three chances to check one thing and send another.
2. **Digest.** The payload attestation and the prompt correlation digest, both
   computed before anything is transmitted, so a refused request still has them.
3. **Scan.** Detection over the payload. A finding refuses the request, because
   after transmission a check is a report rather than a control (ADR-0008).
4. **Transmit.** Only a payload that passed step 3 reaches an adapter.

**A blocked payload still produces an attestation.** ADR-0024 is explicit that a
request stopped by the scan is the case most worth auditing, so
:class:`OutboundBlockedError` carries the attestation rather than discarding it
— the caller writes the same audit row it would have written on success, with
`blocked` set.

**Invocation is injectable, the decision to invoke is not.** The chat pipeline
wraps its provider call in a request deadline and a concurrency semaphore; the
document path does not need either. So a caller may supply *how* the adapter is
awaited, while *whether* it is awaited at all stays here, after the scan. A
caller cannot reach an adapter without passing through this method.

Nothing here logs. The payload is Confidential; findings are entity type names,
which the caller places in its own log context.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.domain.errors import PolicyViolationError
from app.outbound.scan import OutboundScan, ScanVerdict, scan_outbound
from app.outbound.serialization import outbound_segments, serialize_outbound

if TYPE_CHECKING:
    from uuid import UUID

    from app.audit.correlation import CorrelationHasher
    from app.detection.base import Detector
    from app.domain.models import ProtectedChatRequest, ProviderResponse
    from app.llm.base import LLMProvider
    from app.llm.registry import ProviderRegistry
    from app.policy.models import PolicySnapshot

Invoker = Callable[["LLMProvider", "ProtectedChatRequest"], Awaitable["ProviderResponse"]]
"""How the adapter is awaited. Supplied by callers that need a deadline or a
concurrency bound around the call; never a way to bypass the scan."""


@dataclass(frozen=True, slots=True)
class Attestation:
    """Evidence that one payload was assembled, checked, and what came of it.

    Digests only. There is no field here that can hold the payload, and none
    that can hold a detected value — ``scan`` carries entity *type* names.
    """

    payload_hmac: str
    """Keyed digest of the exact transmitted bytes (ADR-0024)."""

    prompt_hmac: str
    """Keyed digest of the outbound conversation, for correlation (ADR-0015)."""

    scan: OutboundScan

    @property
    def verdict(self) -> str:
        """``clean`` or ``blocked``, as written to ``audit_events``."""
        return self.scan.verdict.value

    def __repr__(self) -> str:
        return f"Attestation(verdict={self.verdict!r}, findings={len(self.scan.findings)})"


@dataclass(frozen=True, slots=True)
class Transmission:
    """A completed provider call and the evidence that it was allowed."""

    response: ProviderResponse
    attestation: Attestation
    provider_latency_ms: int

    def __repr__(self) -> str:
        return f"Transmission(latency_ms={self.provider_latency_ms}, {self.attestation!r})"


class OutboundBlockedError(PolicyViolationError):
    """The scan found an actionable entity in a payload about to be sent.

    A ``PolicyViolationError``, so the API layer renders it as the same 422 a
    blocked entity type produces — a caller learns the request was refused and
    nothing about what was found.

    Carries the attestation so the caller can audit the refusal. Discarding it
    would leave the one case ADR-0024 calls most worth auditing with no row.
    """

    def __init__(self, attestation: Attestation) -> None:
        super().__init__(
            log_context={
                "reason": "outbound_scan_found_entities",
                # Type names only. The values they stood for are absent from the
                # message, the context, and this object.
                "entity_type": ",".join(attestation.scan.findings),
            }
        )
        self.attestation = attestation


class OutboundGateway:
    """Serializes, attests, scans, and transmits one protected request."""

    __slots__ = ("_detector", "_hasher", "_language", "_providers")

    def __init__(
        self,
        *,
        detector: Detector,
        providers: ProviderRegistry,
        hasher: CorrelationHasher,
        language: str = "en",
    ) -> None:
        self._detector = detector
        self._providers = providers
        self._hasher = hasher
        self._language = language

    async def send(
        self,
        request: ProtectedChatRequest,
        *,
        policy: PolicySnapshot,
        invoke: Invoker | None = None,
    ) -> Transmission:
        """Check one protected payload and, if it passes, transmit it.

        Args:
            request: The protected request. Constructing one is already the
                assertion that detection, policy, and tokenization have run.
            policy: The snapshot those stages used. The scan applies the same
                thresholds and actions, so it cannot be stricter than the
                protection it is checking.
            invoke: How to await the adapter. Defaults to calling it directly.

        Returns:
            The provider's response, the attestation, and the call latency.

        Raises:
            OutboundBlockedError: the scan found an actionable entity. Nothing
                was transmitted, and the error carries the attestation.
            DetectorUnavailableError: the scan could not run. Fail closed --
                an outbound check that cannot run must not pass by default.
            ProviderNotAllowedError: the alias is not registered.
            GatewayError: whatever the adapter raises, unchanged.
        """
        attestation = await self.attest(request, policy=policy)
        if not attestation.scan.is_clean:
            raise OutboundBlockedError(attestation)

        adapter = self._providers.get(request.provider_alias)
        started = time.perf_counter()
        response = await (invoke(adapter, request) if invoke else adapter.complete(request))
        latency_ms = max(int((time.perf_counter() - started) * 1000), 0)
        return Transmission(
            response=response, attestation=attestation, provider_latency_ms=latency_ms
        )

    def authorize(self, provider_alias: str) -> None:
        """Refuse an unregistered alias before any expensive stage runs.

        The registry lookup happens inside :meth:`send` too, but by then a
        document has been decrypted, extracted, detected over, and tokenized.
        An unpermitted destination must cost nothing, so callers check here
        first -- and this method calls no adapter, so checking is free.

        Raises:
            ProviderNotAllowedError: nothing is registered under that alias.
        """
        self._providers.get(provider_alias)

    async def attest(self, request: ProtectedChatRequest, *, policy: PolicySnapshot) -> Attestation:
        """Serialize, digest, and scan, without transmitting anything.

        Separated from :meth:`send` so the digests exist before the verdict does
        — a refused payload has to be attestable, and computing the digest after
        deciding to send would leave the blocked path with nothing to record.
        """
        payload = serialize_outbound(request)
        scan = await scan_outbound(
            request, detector=self._detector, policy=policy, language=self._language
        )
        return Attestation(
            payload_hmac=self._hasher.outbound_digest(tenant_id=request.tenant_id, payload=payload),
            prompt_hmac=self._hasher.prompt_digest(
                tenant_id=request.tenant_id, segments=outbound_segments(request)
            ),
            scan=scan,
        )

    def session_digest(self, *, tenant_id: UUID, session_id: UUID) -> str:
        """Keyed digest of a session id, for ``audit_events.session_id_hash``."""
        return self._hasher.session_digest(tenant_id=tenant_id, session_id=session_id)

    def response_digest(self, *, tenant_id: UUID, text: str) -> str:
        """Keyed digest of one restored answer, for ``audit_events``.

        Exposed here rather than making every caller reach for the hasher, so
        the correlation key has exactly one holder on the outbound path.
        """
        return self._hasher.response_digest(tenant_id=tenant_id, text=text)

    def __repr__(self) -> str:
        return f"OutboundGateway(language={self._language!r})"


__all__ = [
    "Attestation",
    "Invoker",
    "OutboundBlockedError",
    "OutboundGateway",
    "ScanVerdict",
    "Transmission",
]
