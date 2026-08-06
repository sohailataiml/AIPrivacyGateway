"""Serialization and the pre-transmission scan.

Both are the evidence side of ADR-0024, and they fail in opposite directions.

**Serialization** fails by being unstable. An attestation is a digest of these
bytes; if the same request can produce two byte strings, or two different
requests can produce one, the digest proves nothing and the audit row is
decoration. So the tests here are mostly about what must and must not collide.

**The scan** fails by being useless. A payload is full of things that look like
sensitive values — a gateway token carries a 26-character identifier that a
recognizer reads as an account number — so a scan that flagged those would block
every document it saw and be switched off within a day. The tests establish both
halves: it catches an original that survived, and it does not catch the
substitutions protection just made.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.detection.config import DetectionConfig
from app.detection.entities import EMAIL_ADDRESS, PERSON, PHONE_NUMBER, US_SSN
from app.detection.fakes import FakeDetector
from app.documents.outbound import (
    SERIALIZATION_VERSION,
    OutboundScan,
    ScanVerdict,
    outbound_text,
    scan_outbound,
    serialize_outbound,
)
from app.domain.errors import DetectorUnavailableError
from app.domain.models import ChatMessage, EntityAction, ProtectedChatRequest
from app.policy.models import EntityRule, PolicySnapshot
from tests.fixtures.documents import CANARIES, TENANT
from tests.fixtures.policies import snapshot

PROTECT_EVERYTHING = {
    PERSON: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    EMAIL_ADDRESS: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    US_SSN: EntityRule(action=EntityAction.BLOCK, min_score=0.5),
}

TOKEN = "⟦SGW:PERSON:01J8Z6J4M7Y9Q2K3T4V5W6X7Y8⟧"
REDACTION = "⟦SGW:REDACTED:MEDICAL_RECORD_NUMBER⟧"


def policy(entities: dict[str, EntityRule] | None = None) -> PolicySnapshot:
    return snapshot(entities or PROTECT_EVERYTHING, tenant_id=TENANT)


def request_of(
    *contents: str, provider: str = "mock", model: str = "general-chat", version: int = 7
) -> ProtectedChatRequest:
    return ProtectedChatRequest(
        request_id=uuid4(),
        tenant_id=TENANT,
        session_id=uuid4(),
        provider_alias=provider,
        model_alias=model,
        messages=tuple(ChatMessage(role="user", content=content) for content in contents),
        policy_version=version,
    )


def detector() -> FakeDetector:
    return FakeDetector(config=DetectionConfig(), person_names=(CANARIES["person_name"],))


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------
class TestSerialization:
    def test_the_same_request_always_produces_the_same_bytes(self) -> None:
        request = request_of("hello", "world")

        assert serialize_outbound(request) == serialize_outbound(request)

    def test_the_framing_version_is_present(self) -> None:
        # An attestation is only meaningful against a known framing. The label
        # is what lets a future change be recognised rather than silently
        # invalidating every old digest.
        assert SERIALIZATION_VERSION in serialize_outbound(request_of("hello"))

    def test_regrouping_the_same_text_does_not_collide(self) -> None:
        # Length-prefixing, stated as the property it exists for. Without it,
        # two messages ("AB", "C") and ("A", "BC") serialise identically and a
        # different conversation attests as the same one.
        assert serialize_outbound(request_of("AB", "C")) != serialize_outbound(
            request_of("A", "BC")
        )

    def test_the_destination_is_inside_the_frame(self) -> None:
        # The same text sent to a different model is a different outbound
        # event, and the attestation should say so.
        assert serialize_outbound(request_of("hello", model="general-chat")) != serialize_outbound(
            request_of("hello", model="other-model")
        )

    def test_the_policy_version_is_inside_the_frame(self) -> None:
        assert serialize_outbound(request_of("hello", version=7)) != serialize_outbound(
            request_of("hello", version=8)
        )

    def test_the_request_id_is_not_inside_the_frame(self) -> None:
        # Two identical payloads must attest identically. Mixing in a per-request
        # id would make every digest unique and remove the only property that
        # makes an attestation checkable: that it can be recomputed.
        first = request_of("hello")
        second = ProtectedChatRequest(
            request_id=uuid4(),
            tenant_id=first.tenant_id,
            session_id=first.session_id,
            provider_alias=first.provider_alias,
            model_alias=first.model_alias,
            messages=first.messages,
            policy_version=first.policy_version,
        )

        assert serialize_outbound(first) == serialize_outbound(second)

    def test_the_scanned_text_is_the_message_content_in_order(self) -> None:
        assert outbound_text(request_of("first", "second")) == "first\nsecond"


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------
class TestScan:
    async def test_a_surviving_original_is_caught(self) -> None:
        # The control, stated plainly. If protection missed a span, this is the
        # last place to find out, and the answer is to refuse.
        request = request_of(f"Contact {CANARIES['email']} about the referral.")

        scan = await scan_outbound(request, detector=detector(), policy=policy())

        assert scan.verdict is ScanVerdict.BLOCKED
        assert scan.findings == (EMAIL_ADDRESS,)

    async def test_a_protected_payload_is_clean(self) -> None:
        request = request_of(f"Contact {TOKEN} about the referral. Record {REDACTION}.")

        scan = await scan_outbound(request, detector=detector(), policy=policy())

        assert scan.verdict is ScanVerdict.CLEAN
        assert scan.findings == ()

    async def test_a_token_identifier_is_not_read_as_an_entity(self) -> None:
        # The subtlety the module exists to handle. A token's 26-character
        # identifier is exactly the shape of an account number, so without the
        # placeholder exclusion the scan would block every protected document.
        many_tokens = " ".join(TOKEN for _ in range(20))
        request = request_of(many_tokens)

        scan = await scan_outbound(request, detector=detector(), policy=policy())

        assert scan.is_clean

    async def test_an_allowed_type_is_not_a_finding(self) -> None:
        # Allowing a type means the payload is permitted to carry it. Treating
        # that as a leak would refuse documents an operator configured to pass.
        permissive = policy({EMAIL_ADDRESS: EntityRule(action=EntityAction.ALLOW, min_score=0.5)})
        request = request_of(f"Contact {CANARIES['email']}.")

        scan = await scan_outbound(request, detector=detector(), policy=permissive)

        assert scan.is_clean

    async def test_a_sub_threshold_detection_is_not_a_finding(self) -> None:
        # The scan applies the same confidence rule the rest of the pipeline
        # does. A span the policy considers too weak to act on is not a leak the
        # scan should refuse over -- otherwise the outbound check would be
        # stricter than the protection it is checking.
        #
        # The fake scores a phone number at 0.75; the threshold here is above it
        # and below the email's 1.0, so exactly one of the two survives.
        request = request_of(f"Reach {CANARIES['email']} or {CANARIES['phone']} today.")
        strict = policy(
            {
                EMAIL_ADDRESS: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
                PHONE_NUMBER: EntityRule(action=EntityAction.TOKENIZE, min_score=0.9),
            }
        )

        scan = await scan_outbound(request, detector=detector(), policy=strict)

        assert scan.findings == (EMAIL_ADDRESS,), "the phone number was below its threshold"

    async def test_findings_are_type_names_and_never_values(self) -> None:
        request = request_of(f"{CANARIES['person_name']} at {CANARIES['email']}.")

        scan = await scan_outbound(request, detector=detector(), policy=policy())

        assert scan.findings, "non-vacuity: something must have been found"
        rendered = f"{scan.findings}{scan!r}"
        for name in ("person_name", "email"):
            assert CANARIES[name] not in rendered

    async def test_an_empty_payload_is_clean_without_calling_the_detector(self) -> None:
        # Not an optimisation -- a detector that cannot run must not be reached
        # by a payload that has nothing to scan, or an empty instruction turns
        # into a 503.
        engine = detector()
        request = request_of("   ")

        scan = await scan_outbound(request, detector=engine, policy=policy())

        assert scan.is_clean
        assert engine.call_count == 0

    async def test_a_detector_outage_fails_closed(self) -> None:
        # An outbound check that cannot run must not pass by default.
        class DeadDetector:
            async def detect(self, text: str, **_kwargs: object) -> list[object]:
                raise DetectorUnavailableError(log_context={"stage": "outbound"})

        with pytest.raises(DetectorUnavailableError):
            await scan_outbound(
                request_of("anything at all"),
                detector=DeadDetector(),  # type: ignore[arg-type]
                policy=policy(),
            )

    async def test_an_unterminated_redaction_marker_does_not_hang_the_scan(self) -> None:
        # A caller can put anything in an instruction, including the redaction
        # prefix with no closing delimiter. The placeholder walk has to stop
        # rather than loop, and the text after it still has to be scanned --
        # otherwise an unclosed marker would be a way to switch the scan off.
        request = request_of(f"⟦SGW:REDACTED:PERSON and then {CANARIES['email']}")

        scan = await scan_outbound(request, detector=detector(), policy=policy())

        assert scan.findings == (EMAIL_ADDRESS,)

    def test_the_repr_reports_a_count_not_the_findings(self) -> None:
        scan = OutboundScan(verdict=ScanVerdict.BLOCKED, findings=(US_SSN, EMAIL_ADDRESS))

        assert repr(scan) == "OutboundScan(verdict='blocked', findings=2)"
        assert not scan.is_clean
