"""The bytes that actually leave, and the check that runs over them.

ADR-0024 states the problem this module exists for: the gateway's central claim
is that originals do not reach the provider, and until now that claim rested on
the pipeline being correct and on a test asserting the property. Neither
produces evidence after the fact, and neither is a control.

Two things here, and they are deliberately separate.

**Serialization** produces one canonical byte string for a protected request.
That string is what gets attested, so it has to be exact and it has to be
stable: the same request must always produce the same bytes, on any machine, in
any Python version, whatever a provider adapter later does with it.

It is *not* the provider's wire format. An OpenAI JSON body is that adapter's
business and would change with its SDK; attesting it would tie the audit trail
to a vendor and make an adapter upgrade silently invalidate old attestations.
What is attested is the content the gateway decided to send — roles, texts,
routing aliases, policy version — in the gateway's own framing.

**Scanning** runs the detector over that payload one more time, immediately
before transmission. This is the control ADR-0008 requires and ADR-0024 makes
audit-worthy: if protection missed a span, this is the last place to find out,
and the answer is to refuse rather than to warn.

The scan has one subtlety worth stating. The payload is *full of things that
look like sensitive values* — that is what a token is. `⟦SGW:PERSON:01J8Z…⟧`
carries a 26-character identifier that a recognizer can and does read as an
account number. So every detection landing inside a token or a redaction
placeholder is discarded before the verdict, using the same strict parser
restoration uses. Without that, the scan would block every document it was
given and the control would be removed within a day for being useless.

Nothing here logs. The payload is Confidential and the findings are entity type
names, which the caller places in its own log context.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from app.domain.models import EntityAction
from app.tokenization.grammar import find_tokens

if TYPE_CHECKING:
    from collections.abc import Sequence

    from app.detection.base import Detector
    from app.domain.models import DetectedEntity, ProtectedChatRequest
    from app.policy.models import PolicySnapshot

SERIALIZATION_VERSION: Final = b"sgw:outbound:v1"
"""Framing version, mixed into every payload.

An attestation is only meaningful against a known framing. Changing how a
payload is assembled without changing this label would make old digests
unverifiable while still looking verifiable.
"""

_LENGTH_PREFIX_BYTES: Final = 4

REDACTION_PREFIX: Final = "⟦SGW:REDACTED:"
"""Redactions share the token delimiters and are not tokens -- they carry no
identifier, because there is nothing to resolve. The scan has to skip them too."""


class ScanVerdict(StrEnum):
    """What the outbound check concluded. Recorded on the audit row."""

    CLEAN = "clean"
    """No actionable entity survived into the payload."""

    BLOCKED = "blocked"
    """At least one did. The request was refused; nothing was transmitted."""


@dataclass(frozen=True, slots=True)
class OutboundScan:
    """The result of scanning one payload.

    ``findings`` holds **entity type names only**. The span offsets are
    deliberately absent: an offset plus the payload is a map of what the scan
    caught, and this object is built to be summarised into an audit record.
    """

    verdict: ScanVerdict
    findings: tuple[str, ...]

    @property
    def is_clean(self) -> bool:
        return self.verdict is ScanVerdict.CLEAN

    def __repr__(self) -> str:
        return f"OutboundScan(verdict={self.verdict.value!r}, findings={len(self.findings)})"


def serialize_outbound(request: ProtectedChatRequest) -> bytes:
    """Return the canonical bytes for one protected request.

    Every field is length-prefixed before concatenation, so no regrouping of
    the same bytes yields the same result -- two messages ``("AB", "C")``
    cannot collide with ``("A", "BC")``. The same reasoning, and the same
    framing, as ``app.audit.correlation``.

    Routing aliases and the policy version are inside the frame on purpose. The
    attestation should distinguish "this text, to this model, under this policy"
    from the same text sent somewhere else; a digest over the message bodies
    alone would call those identical.
    """
    parts: list[bytes] = [
        SERIALIZATION_VERSION,
        request.provider_alias.encode("utf-8"),
        request.model_alias.encode("utf-8"),
        str(request.policy_version).encode("ascii"),
        str(len(request.messages)).encode("ascii"),
    ]
    for message in request.messages:
        parts.append(message.role.encode("utf-8"))
        parts.append(message.content.encode("utf-8"))
    return _frame(*parts)


def outbound_text(request: ProtectedChatRequest) -> str:
    """The message content the scan runs over, in order.

    Separated from :func:`serialize_outbound` because the two want different
    things: the digest needs unambiguous framing, and the scanner needs text
    with offsets it can address. Joining with a newline keeps every message's
    content whole rather than letting two messages form a value across the
    join.
    """
    return "\n".join(message.content for message in request.messages)


async def scan_outbound(
    request: ProtectedChatRequest,
    *,
    detector: Detector,
    policy: PolicySnapshot,
    language: str = "en",
) -> OutboundScan:
    """Detect over the payload and report whether anything actionable survived.

    A finding is a detection the policy would *act* on. A span the policy allows
    is not a finding: allowing a type means the payload is permitted to carry it,
    and treating it as a leak would refuse documents the operator deliberately
    configured to pass.

    Detections falling inside a gateway token or a redaction placeholder are
    discarded first. A token's identifier is a 26-character alphanumeric run and
    recognizers read it as an account number; without this, the scan would flag
    the very substitutions protection just made.

    Raises:
        DetectorUnavailableError: the detector could not run. Fail closed --
            an outbound check that cannot run must not pass by default.
    """
    text = outbound_text(request)
    if not text.strip():
        return OutboundScan(verdict=ScanVerdict.CLEAN, findings=())

    detected = await detector.detect(text, language=language, requested_entities=None)
    surviving = _outside_placeholders(text, detected)

    findings = tuple(
        sorted(
            {
                entity.entity_type
                for entity in surviving
                if entity.score >= policy.min_score_for(entity.entity_type)
                and policy.action_for(entity.entity_type) is not EntityAction.ALLOW
            }
        )
    )
    verdict = ScanVerdict.BLOCKED if findings else ScanVerdict.CLEAN
    return OutboundScan(verdict=verdict, findings=findings)


def _outside_placeholders(text: str, detected: Sequence[DetectedEntity]) -> list[DetectedEntity]:
    """Drop detections that overlap a gateway token or a redaction.

    Token ranges come from ``find_tokens``, the same strict parser restoration
    uses, so the scan and the restorer agree on what a token is. Redactions are
    located by their reserved prefix, which by construction cannot parse as a
    token.
    """
    reserved: list[tuple[int, int]] = [(match.start, match.end) for match in find_tokens(text)]

    cursor = text.find(REDACTION_PREFIX)
    while cursor != -1:
        closing = text.find("⟧", cursor)
        if closing == -1:
            break
        reserved.append((cursor, closing + 1))
        cursor = text.find(REDACTION_PREFIX, closing)

    if not reserved:
        return list(detected)
    return [
        entity
        for entity in detected
        if not any(entity.start < end and start < entity.end for start, end in reserved)
    ]


def _frame(*parts: bytes) -> bytes:
    return b"".join(len(part).to_bytes(_LENGTH_PREFIX_BYTES, "big") + part for part in parts)


__all__ = [
    "REDACTION_PREFIX",
    "SERIALIZATION_VERSION",
    "OutboundScan",
    "ScanVerdict",
    "outbound_text",
    "scan_outbound",
    "serialize_outbound",
]
