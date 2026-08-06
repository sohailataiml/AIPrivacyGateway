"""The last look at a payload before it leaves.

ADR-0024 states the problem: the gateway's central claim is that originals do
not reach the provider, and for a long time that claim rested on the pipeline
being correct and on a test asserting the property. Neither produces evidence
after the fact, and neither is a control.

This module is the control. It runs the detector over the payload one more
time, immediately before transmission. If protection missed a span, this is the
last place to find out, and the answer is to refuse rather than to warn
(ADR-0008).

Shared by every outbound path. `/v1/chat` and `/v1/documents/{id}/process` both
reach a provider, so both are scanned by this function -- one implementation, so
a fix to either path is a fix to both and neither can drift into being the lax
one.

**Each message is scanned on its own, not the concatenation.** That is a
deliberate choice and it cost a green test to find. Presidio's NER is
context-sensitive: `"An unremarkable week, clinically."` yields nothing on its
own, and the same sentence preceded by another one yields `DATE_TIME` on
`"week"` at 0.85. Scanning the joined text therefore reports entities that no
protection pass could have seen, because protection ran over each message
separately -- so an ordinary document, protected exactly as the policy asked,
gets refused for a value that only exists at the seam between two messages.

Scanning per message makes the check see each message the way protection saw it,
which is the only way its verdict can mean "protection missed something" rather
than "the concatenation reads differently". The cost is that an entity formed
*across* a message boundary is not reported, and that is the right trade: no
real value spans two messages, while the artifacts demonstrably do.

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


async def scan_outbound(
    request: ProtectedChatRequest,
    *,
    detector: Detector,
    policy: PolicySnapshot,
    language: str = "en",
) -> OutboundScan:
    """Detect over every message of the payload and report what survived.

    A finding is a detection the policy would *act* on. A span the policy allows
    is not a finding: allowing a type means the payload is permitted to carry it,
    and treating it as a leak would refuse traffic the operator deliberately
    configured to pass.

    Detections falling inside a gateway token or a redaction placeholder are
    discarded first. A token's identifier is a 26-character alphanumeric run and
    recognizers read it as an account number; without this, the scan would flag
    the very substitutions protection just made.

    Every message is covered, each scanned as its own text. See the module
    docstring for why the concatenation is not what gets scanned.

    Raises:
        DetectorUnavailableError: the detector could not run. Fail closed --
            an outbound check that cannot run must not pass by default.
    """
    findings: set[str] = set()
    for message in request.messages:
        findings.update(
            await _findings_in(message.content, detector=detector, policy=policy, language=language)
        )

    ordered = tuple(sorted(findings))
    verdict = ScanVerdict.BLOCKED if ordered else ScanVerdict.CLEAN
    return OutboundScan(verdict=verdict, findings=ordered)


async def _findings_in(
    text: str, *, detector: Detector, policy: PolicySnapshot, language: str
) -> set[str]:
    """Entity type names the policy would act on, for one message."""
    if not text.strip():
        return set()

    detected = await detector.detect(text, language=language, requested_entities=None)
    return {
        entity.entity_type
        for entity in _outside_placeholders(text, detected)
        if entity.score >= policy.min_score_for(entity.entity_type)
        and policy.action_for(entity.entity_type) is not EntityAction.ALLOW
    }


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


__all__ = [
    "REDACTION_PREFIX",
    "OutboundScan",
    "ScanVerdict",
    "scan_outbound",
]
