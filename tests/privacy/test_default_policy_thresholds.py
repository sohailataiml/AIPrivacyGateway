"""The shipped default policy, measured against the real detector.

Unit tests define their own policies with thresholds chosen to exercise a code
path, and the detector tests assert scores without reference to any policy.
Neither combination catches a default whose threshold sits above what the
detector actually produces -- the policy simply discards the detection and the
value travels onward in the clear.

That is how PHONE_NUMBER shipped at min_score 0.65 while Presidio scores a US
phone number at 0.40 unless the literal word "phone" is nearby. These tests
pair the two real components so a future threshold change cannot reopen it.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.detection.config import DetectionConfig
from app.detection.engine import PresidioDetector
from app.domain.models import EntityAction
from app.policy.defaults import DEFAULT_POLICY
from app.policy.models import PolicySnapshot

pytestmark = pytest.mark.privacy

# Phrasings a real user would write. None contains the word "phone", which is
# exactly why they defeated the original threshold.
PHONE_PHRASINGS = [
    "Call 415-555-0142 with questions.",
    "Reach me at 415-555-0142 any time.",
    "Follow up on 415-555-0142 tomorrow.",
    "415-555-0142 is the best number for the patient.",
]


@pytest.fixture(scope="module")
def detector() -> PresidioDetector:
    return PresidioDetector(config=DetectionConfig())


@pytest.fixture(scope="module")
def policy() -> PolicySnapshot:
    return PolicySnapshot.from_document(
        DEFAULT_POLICY, policy_id=uuid4(), tenant_id=uuid4(), version=1
    )


def surviving(entities: list, policy: PolicySnapshot, entity_type: str) -> list:
    """Detections of one type that clear the policy's own threshold."""
    return [
        entity
        for entity in entities
        if entity.entity_type == entity_type and entity.score >= policy.min_score_for(entity_type)
    ]


class TestDefaultPolicyActuallyCatchesWhatItClaims:
    @pytest.mark.parametrize("text", PHONE_PHRASINGS)
    async def test_phone_numbers_survive_the_default_threshold(
        self, detector: PresidioDetector, policy: PolicySnapshot, text: str
    ) -> None:
        # Arrange / Act
        entities = await detector.detect(text, language="en")

        # Assert
        kept = surviving(entities, policy, "PHONE_NUMBER")
        assert kept, (
            f"the default policy discards the phone number in {text!r}, "
            f"so it would reach the provider in the clear"
        )

    async def test_email_survives_the_default_threshold(
        self, detector: PresidioDetector, policy: PolicySnapshot
    ) -> None:
        entities = await detector.detect(
            "Send it to jordan.rivera@example.com today.", language="en"
        )

        assert surviving(entities, policy, "EMAIL_ADDRESS")

    async def test_every_tokenizing_default_has_a_reachable_threshold(
        self, policy: PolicySnapshot
    ) -> None:
        # A reversible action should not carry a high bar: a false positive is
        # recoverable for the caller, a miss is not. 0.8 is the LOCATION rule,
        # which is deliberately conservative and documented as such.
        for entity_type in policy.entity_types:
            if policy.action_for(entity_type) is not EntityAction.TOKENIZE:
                continue
            assert policy.min_score_for(entity_type) <= 0.8, (
                f"{entity_type} tokenizes but requires an unusually high score; "
                f"confirm the detector actually reaches it"
            )


class TestBlockingRulesStillFire:
    async def test_credit_card_clears_its_block_threshold(
        self, detector: PresidioDetector, policy: PolicySnapshot
    ) -> None:
        # 4111111111111111 is the standard Luhn-valid test card.
        entities = await detector.detect("card 4111 1111 1111 1111", language="en")

        kept = surviving(entities, policy, "CREDIT_CARD")
        assert kept
        assert policy.action_for("CREDIT_CARD") is EntityAction.BLOCK

    async def test_ssn_clears_its_block_threshold(
        self, detector: PresidioDetector, policy: PolicySnapshot
    ) -> None:
        # Not 123-45-6789: Presidio hard-rejects published placeholders, so a
        # test built on one asserts nothing.
        entities = await detector.detect("ssn 412-88-3719", language="en")

        kept = surviving(entities, policy, "US_SSN")
        assert kept
        assert policy.action_for("US_SSN") is EntityAction.BLOCK


# Every one of these was verified missing against the running stack before
# InternalEmailRecognizer existed: Presidio validates each match with
# tldextract against the Public Suffix List and silently drops anything whose
# TLD is not on it. ``.internal`` is the load-bearing case -- ICANN reserved it
# in 2024 as the recommended private-network TLD, so it is precisely what an
# enterprise deploying this gateway internally would be using.
PRIVATE_TLD_EMAILS = [
    "mail jordan.rivera@acme.internal about the outage",
    "mail jordan.rivera@acme.lan about the outage",
    "mail jordan.rivera@acme.corp about the outage",
    "mail jordan.rivera@example.test about the outage",
    "mail jordan.rivera@example.invalid about the outage",
]

PUBLIC_TLD_EMAILS = [
    "mail jordan.rivera@example.com about the outage",
    "mail jordan.rivera@example.org about the outage",
    "mail jordan.rivera@example.io about the outage",
]


class TestEmailDetectionDoesNotDependOnATldList:
    """A privacy control must not fail open on TLDs nobody remembered.

    These are regression tests for a leak found by running the stack, not by
    the unit suite -- which never caught it because its fixtures use a fake
    detector, and whose own sample addresses are ``@example.test``: one of the
    TLDs that silently failed to detect.
    """

    @pytest.mark.parametrize("text", PRIVATE_TLD_EMAILS)
    async def test_private_and_reserved_tlds_are_detected(
        self, detector: PresidioDetector, policy: PolicySnapshot, text: str
    ) -> None:
        entities = await detector.detect(text, language="en")

        kept = surviving(entities, policy, "EMAIL_ADDRESS")
        assert kept, (
            f"no EMAIL_ADDRESS survives the default policy for {text!r}; "
            f"an address on a private TLD would reach the provider in clear text"
        )

    @pytest.mark.parametrize("text", PUBLIC_TLD_EMAILS)
    async def test_public_tlds_still_detected_exactly_once(
        self, detector: PresidioDetector, policy: PolicySnapshot, text: str
    ) -> None:
        """Presidio and the custom recognizer both fire on a public address;
        overlap resolution must collapse them to a single span rather than
        tokenizing the same value twice."""
        entities = await detector.detect(text, language="en")

        kept = surviving(entities, policy, "EMAIL_ADDRESS")
        assert len(kept) == 1, f"expected exactly one EMAIL_ADDRESS span, got {kept}"

    async def test_the_address_is_tokenized_not_merely_detected(
        self, detector: PresidioDetector, policy: PolicySnapshot
    ) -> None:
        entities = await detector.detect(
            "mail jordan.rivera@acme.internal about the outage", language="en"
        )

        kept = surviving(entities, policy, "EMAIL_ADDRESS")
        assert kept
        assert policy.action_for("EMAIL_ADDRESS") is EntityAction.TOKENIZE
