"""Privacy regression: canary values must never leave the gateway.

Implementation.md sections 17 and 20 ask for one test that runs synthetic
sensitive values through the pipeline and then searches *everything* the process
produced for them. This is that test.

What is wired together
----------------------
Real components, not mocks, for every stage that exists today:

* ``FakeDetector`` (:mod:`app.detection.fakes`) -- see "Why the fake detector".
* ``Tokenizer`` (:mod:`app.tokenization.tokenizer`) with the real
  ``Fingerprinter``.
* ``RedisTokenVault`` over ``fakeredis`` with the real ``EnvelopeCipher``.
  Deliberately *not* ``InMemoryTokenVault``: that fake stores originals as
  plaintext strings by design, so "the vault's stored bytes contain no
  plaintext canary" would be either vacuous or false against it. Only the
  encrypting implementation can make that assertion mean something.
* ``MockProvider`` (:mod:`app.llm.mock_provider`), wrapped in a recorder that
  keeps the exact ``ProtectedChatRequest`` it received and the literal outbound
  body ``OpenAIProvider`` would have serialized for the same request.
* Restoration by hand -- ``app/restoration`` is not implemented yet, so this
  test resolves tokens through the vault the way that package will.
* ``AuditService`` with a list-backed repository and the real
  ``CorrelationHasher``.

Why the fake detector
---------------------
The three canary strings from implementation.md section 20 are *not shaped like
the values their names suggest*, and the real detector finds none of them.
``TestRealDetectorCoverage`` proves that rather than asserting it: Presidio
returns zero entities for all three. The reasons differ per canary --
``123-45-6789`` is a published placeholder Presidio hard-rejects (see
``tests/fixtures/detection_corpus.py``), and ``SENSITIVE_CANARY_NAME_Avery
Example`` is not a name any NER model will accept -- but the effect is the same.

Rather than weaken the canaries or the assertions, this file does both things
the brief allows:

1. ``FakeDetector`` is given rules that mark each canary span in full, so the
   canary flow exercises detection -> tokenization -> vault -> provider ->
   restoration -> audit end to end.
2. ``TestRealDetectorCoverage`` runs the same pipeline with the real
   ``PresidioDetector`` over realistic values from the detection corpus, so the
   privacy property is also proven against the detector that ships.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import AsyncIterator, Sequence
from dataclasses import asdict, dataclass
from typing import Final
from uuid import UUID, uuid4

import fakeredis.aioredis
import pytest
import structlog
from prometheus_client import REGISTRY, generate_latest
from redis.asyncio import Redis

from app.audit.correlation import CorrelationHasher, derive_correlation_key
from app.audit.models import AuditRecord, counts_from_summary
from app.audit.service import AuditService
from app.detection.engine import PresidioDetector
from app.detection.entities import EMAIL_ADDRESS, PERSON, US_SSN
from app.detection.fakes import DEFAULT_FAKE_RULES, FakeDetector, FakeRule
from app.domain.errors import PolicyViolationError
from app.domain.models import (
    ChatMessage,
    EntityAction,
    PrivacySummary,
    ProtectedChatRequest,
    ProviderResponse,
)
from app.llm.mock_provider import MockProvider
from app.llm.openai_provider import _build_input
from app.policy.models import (
    POLICY_SCHEMA_VERSION,
    EntityRule,
    PolicyDocument,
    PolicySnapshot,
    ProviderRule,
)
from app.repositories.audit_events import AuditEventDraft
from app.tokenization.fingerprint import Fingerprinter, derive_fingerprint_key
from app.tokenization.grammar import find_token_strings
from app.tokenization.tokenizer import Tokenizer
from app.vault.crypto import EnvelopeCipher
from app.vault.keys import StaticKeyRing
from app.vault.redis_vault import RedisTokenVault

pytestmark = pytest.mark.privacy

# -- Canaries from implementation.md section 20 -------------------------------
CANARY_EMAIL: Final = "SENSITIVE_CANARY_EMAIL_7f91@example.test"
CANARY_SSN: Final = "SENSITIVE_CANARY_SSN_123-45-6789"
CANARY_NAME: Final = "SENSITIVE_CANARY_NAME_Avery Example"
CANARIES: Final[tuple[str, ...]] = (CANARY_EMAIL, CANARY_SSN, CANARY_NAME)

# Realistic values, for the run against the real detector. Every one is
# synthetic; see tests/fixtures/detection_corpus.py for the provenance rules.
REALISTIC_EMAIL: Final = "jordan.rivera@example.com"
REALISTIC_SSN: Final = "412-88-3719"

TENANT_ID: Final = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
API_KEY_ID: Final = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
POLICY_ID: Final = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
POLICY_VERSION: Final = 7

PRODUCTION_LOG_LEVEL: Final = logging.INFO
"""``Settings.log_level`` defaults to INFO, so this is what a deployment emits."""

VAULT_KEY: Final = bytes(range(32))
AUDIT_ROOT_SECRET: Final = b"privacy-regression-root-secret-0123456789"

# Rules that mark each canary span in full. The email canary is already covered
# by the default email rule; the other two need help for the reasons in the
# module docstring.
CANARY_RULES: Final[tuple[FakeRule, ...]] = (
    FakeRule(US_SSN, re.compile(r"SENSITIVE_CANARY_SSN_\d{3}-\d{2}-\d{4}"), 0.95),
    *DEFAULT_FAKE_RULES,
)


@dataclass(frozen=True, slots=True)
class CapturedRun:
    """Every surface one request produced, ready to be searched."""

    protected_prompt: str
    provider_payload: str
    restored_response: str
    audit_rows: str
    logs: str
    metrics: str
    vault_bytes: bytes
    summary: PrivacySummary
    drafts: tuple[AuditEventDraft, ...]

    def surfaces(self) -> dict[str, str]:
        """Named text surfaces a canary must never appear on."""
        return {
            "protected prompt": self.protected_prompt,
            "provider payload": self.provider_payload,
            "audit rows": self.audit_rows,
            "logs": self.logs,
            "metrics": self.metrics,
            "vault storage": self.vault_bytes.decode("utf-8", errors="replace"),
        }


class RecordingProvider:
    """``MockProvider`` plus a record of exactly what it was handed."""

    def __init__(self) -> None:
        self._inner = MockProvider()
        self.alias = self._inner.alias
        self.requests: list[ProtectedChatRequest] = []

    async def complete(self, request: ProtectedChatRequest) -> ProviderResponse:
        self.requests.append(request)
        return await self._inner.complete(request)

    def payload(self) -> str:
        """The outbound body, rendered as the wire would carry it.

        ``_build_input`` is the same projection ``OpenAIProvider`` sends
        upstream, so this is the literal payload, not a paraphrase of it.
        """
        return json.dumps(
            [_build_input(request) for request in self.requests],
            ensure_ascii=False,
        )


class FakeAuditRepository:
    """An ``AuditSink`` that keeps its rows in a list."""

    def __init__(self) -> None:
        self.drafts: list[AuditEventDraft] = []

    async def record(self, draft: AuditEventDraft) -> object:
        self.drafts.append(draft)
        return draft


def policy_snapshot(*, ssn_action: EntityAction = EntityAction.TOKENIZE) -> PolicySnapshot:
    """A policy that tokenizes what the canaries are typed as.

    The shipped default policy *blocks* ``US_SSN``. That is the right production
    choice and it is exercised by ``TestBlockedRequest`` below, but a blocked
    request never reaches a provider, so it cannot prove the restoration half of
    the property. This snapshot tokenizes instead.
    """
    document = PolicyDocument(
        schema_version=POLICY_SCHEMA_VERSION,
        name="privacy-regression",
        session_ttl_seconds=1800,
        max_entities=50,
        providers={"mock": ProviderRule(models=("mock-echo-1",))},
        entities={
            EMAIL_ADDRESS: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
            US_SSN: EntityRule(action=ssn_action, min_score=0.4),
            PERSON: EntityRule(action=EntityAction.TOKENIZE, min_score=0.6),
        },
    )
    return PolicySnapshot.from_document(
        document, policy_id=POLICY_ID, tenant_id=TENANT_ID, version=POLICY_VERSION
    )


@pytest.fixture
async def redis_client() -> AsyncIterator[Redis]:
    client = fakeredis.aioredis.FakeRedis(decode_responses=False)
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def vault(redis_client: Redis) -> RedisTokenVault:
    cipher = EnvelopeCipher(StaticKeyRing({"test1": VAULT_KEY}, active_key_id="test1"))
    return RedisTokenVault(redis_client, cipher)


@pytest.fixture
def tokenizer(vault: RedisTokenVault) -> Tokenizer:
    return Tokenizer(
        vault=vault,
        fingerprinter=Fingerprinter(derive_fingerprint_key(AUDIT_ROOT_SECRET)),
    )


async def dump_vault(redis_client: Redis) -> bytes:
    """Every key and value currently in the vault, concatenated.

    Types are branched rather than assumed: the vault keeps envelopes and index
    entries as strings and the session manifest as a set, and a canary hiding in
    the one structure this helper skipped would be exactly the bug worth
    catching.
    """
    chunks: list[bytes] = []
    for key in await redis_client.keys(b"*"):
        chunks.append(bytes(key))
        key_type = _as_bytes(await redis_client.type(key))
        if key_type == b"set":
            chunks.extend(_as_bytes(member) for member in await redis_client.smembers(key))
        elif key_type == b"hash":  # pragma: no cover - not used by the vault today
            entries = await redis_client.hgetall(key)
            chunks.extend(_as_bytes(part) for pair in entries.items() for part in pair)
        else:
            value = await redis_client.get(key)
            if value is not None:
                chunks.append(_as_bytes(value))
    return b"\x00".join(chunks)


def _as_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


async def restore(
    text: str, *, vault: RedisTokenVault, tenant_id: UUID, session_id: UUID
) -> tuple[str, int]:
    """Resolve gateway tokens back to originals, as app/restoration will."""
    tokens = set(find_token_strings(text))
    if not tokens:
        return text, 0
    resolved = await vault.resolve_many(tenant_id=tenant_id, session_id=session_id, tokens=tokens)
    restored = text
    for token, original in resolved.items():
        restored = restored.replace(token, original)
    return restored, len(resolved)


async def run_pipeline(
    *,
    detector: FakeDetector | PresidioDetector,
    tokenizer: Tokenizer,
    vault: RedisTokenVault,
    redis_client: Redis,
    prompt: str,
    policy: PolicySnapshot,
    caplog: pytest.LogCaptureFixture,
    log_level: int = logging.DEBUG,
) -> CapturedRun:
    """Run one request end to end and capture every surface it touched.

    ``log_level`` is the level the stdlib capture runs at. It defaults to DEBUG,
    which is stricter than production; the real-detector run lowers it to the
    configured production level for the reason documented at
    ``TestRealDetectorCoverage.test_presidio_debug_logging_echoes_analyzed_text``.
    """
    session_id = uuid4()
    request_id = uuid4()
    provider = RecordingProvider()
    repository = FakeAuditRepository()
    audit = AuditService(repository, fail_closed=True, max_queue_size=16)
    hasher = CorrelationHasher(derive_correlation_key(AUDIT_ROOT_SECRET))

    with caplog.at_level(log_level), structlog.testing.capture_logs() as captured:
        entities = await detector.detect(prompt)
        transformed = await tokenizer.transform(
            tenant_id=TENANT_ID,
            session_id=session_id,
            text=prompt,
            entities=entities,
            policy=policy,
        )
        protected = ProtectedChatRequest(
            request_id=request_id,
            tenant_id=TENANT_ID,
            session_id=session_id,
            provider_alias="mock",
            model_alias="mock-echo-1",
            messages=(ChatMessage(role="user", content=transformed.text),),
            policy_version=policy.version,
        )
        raw = await provider.complete(protected)
        restored, restored_count = await restore(
            raw.content, vault=vault, tenant_id=TENANT_ID, session_id=session_id
        )

        summary = transformed.summary.merged_with(PrivacySummary(restored=restored_count))
        entity_counts, actions = counts_from_summary(summary)
        async with audit:
            await audit.submit(
                AuditRecord(
                    tenant_id=TENANT_ID,
                    request_id=request_id,
                    status_code=200,
                    api_key_id=API_KEY_ID,
                    session_id_hash=hasher.session_digest(
                        tenant_id=TENANT_ID, session_id=session_id
                    ),
                    policy_id=POLICY_ID,
                    policy_version=policy.version,
                    provider_alias="mock",
                    model_alias=raw.model,
                    input_character_count=len(prompt),
                    output_character_count=len(restored),
                    entity_counts=entity_counts,
                    actions=actions,
                    prompt_hmac=hasher.prompt_digest(
                        tenant_id=TENANT_ID, segments=[transformed.text]
                    ),
                    response_hmac=hasher.response_digest(tenant_id=TENANT_ID, text=raw.content),
                )
            )
            assert await audit.flush(wait_seconds=2.0)

    logs = "\n".join([*(str(entry) for entry in captured), caplog.text])
    audit_rows = "\n".join(str(asdict(draft)) for draft in repository.drafts)

    return CapturedRun(
        protected_prompt=transformed.text,
        provider_payload=provider.payload(),
        restored_response=restored,
        audit_rows=audit_rows,
        logs=logs,
        metrics=generate_latest(REGISTRY).decode("utf-8"),
        vault_bytes=await dump_vault(redis_client),
        summary=summary,
        drafts=tuple(repository.drafts),
    )


# ---------------------------------------------------------------------------
# The canary run
# ---------------------------------------------------------------------------
class TestCanariesNeverLeaveTheGateway:
    @pytest.fixture
    def detector(self) -> FakeDetector:
        return FakeDetector(rules=CANARY_RULES, person_names={CANARY_NAME})

    @pytest.fixture
    async def run(
        self,
        detector: FakeDetector,
        tokenizer: Tokenizer,
        vault: RedisTokenVault,
        redis_client: Redis,
        caplog: pytest.LogCaptureFixture,
    ) -> CapturedRun:
        prompt = (
            f"Please email {CANARY_EMAIL} and tell {CANARY_NAME} "
            f"that the record {CANARY_SSN} was updated."
        )
        return await run_pipeline(
            detector=detector,
            tokenizer=tokenizer,
            vault=vault,
            redis_client=redis_client,
            prompt=prompt,
            policy=policy_snapshot(),
            caplog=caplog,
        )

    def test_every_canary_was_detected_and_tokenized(self, run: CapturedRun) -> None:
        # Arrange / Act / Assert -- the positive control. Without this, the
        # absence assertions below could pass on an empty pipeline.
        assert run.summary.detected == len(CANARIES)
        assert run.summary.tokenized == len(CANARIES)
        assert len(find_token_strings(run.protected_prompt)) == len(CANARIES)

    @pytest.mark.parametrize("canary", CANARIES)
    def test_canary_is_absent_from_every_surface(self, run: CapturedRun, canary: str) -> None:
        # Arrange / Act
        offenders = [name for name, text in run.surfaces().items() if canary in text]

        # Assert
        assert offenders == [], f"canary leaked into: {', '.join(offenders)}"

    @pytest.mark.parametrize("canary", CANARIES)
    def test_canary_is_present_only_in_the_restored_response(
        self, run: CapturedRun, canary: str
    ) -> None:
        # Assert -- the authorized caller still gets the real value back.
        assert canary in run.restored_response

    @pytest.mark.parametrize("canary", CANARIES)
    def test_vault_stores_no_plaintext_canary(self, run: CapturedRun, canary: str) -> None:
        # Assert -- searched as bytes, so no decoding choice can hide a match.
        assert canary.encode("utf-8") not in run.vault_bytes

    def test_provider_payload_carries_tokens_instead(self, run: CapturedRun) -> None:
        # Arrange / Act
        tokens = find_token_strings(run.protected_prompt)

        # Assert -- what left the gateway was opaque, and it was not nothing.
        assert tokens
        for token in tokens:
            assert token in run.provider_payload

    def test_audit_row_records_counts_policy_and_correlation_only(self, run: CapturedRun) -> None:
        # Arrange
        assert len(run.drafts) == 1
        draft = run.drafts[0]

        # Assert
        assert draft.policy_version == POLICY_VERSION
        assert draft.provider_alias == "mock"
        assert draft.entity_counts == {EMAIL_ADDRESS: 1, PERSON: 1, US_SSN: 1}
        assert draft.actions["tokenized"] == len(CANARIES)
        assert draft.actions["restored"] == len(CANARIES)
        assert draft.prompt_hmac is not None
        assert draft.prompt_hmac != draft.response_hmac

    def test_audit_row_holds_no_gateway_token(self, run: CapturedRun) -> None:
        # Arrange / Act / Assert -- complete tokens are prohibited in audit too.
        for token in find_token_strings(run.protected_prompt):
            assert token not in run.audit_rows

    def test_logs_carry_no_protected_text_either(self, run: CapturedRun) -> None:
        # Assert -- not just the canaries: no message text at all.
        assert "Please email" not in run.logs
        assert run.protected_prompt not in run.logs


# ---------------------------------------------------------------------------
# The blocked path -- the exception surface
# ---------------------------------------------------------------------------
class TestBlockedRequest:
    async def test_a_block_reveals_nothing_in_the_error(
        self, tokenizer: Tokenizer, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Arrange -- the shipped default policy blocks US_SSN.
        detector = FakeDetector(rules=CANARY_RULES, person_names={CANARY_NAME})
        prompt = f"The record {CANARY_SSN} was updated."
        policy = policy_snapshot(ssn_action=EntityAction.BLOCK)

        # Act
        with caplog.at_level(logging.DEBUG), structlog.testing.capture_logs() as captured:
            entities = await detector.detect(prompt)
            with pytest.raises(PolicyViolationError) as raised:
                await tokenizer.transform(
                    tenant_id=TENANT_ID,
                    session_id=uuid4(),
                    text=prompt,
                    entities=entities,
                    policy=policy,
                )

        # Assert
        error = raised.value
        rendered = f"{error!s}{error.public_message}{error.log_context}"
        assert CANARY_SSN not in rendered
        assert "123-45-6789" not in rendered
        assert error.log_context == {"entity_type": US_SSN}
        assert CANARY_SSN not in "\n".join([*(str(e) for e in captured), caplog.text])

    async def test_a_blocked_request_leaves_nothing_in_the_vault(
        self, tokenizer: Tokenizer, redis_client: Redis
    ) -> None:
        # Arrange
        detector = FakeDetector(rules=CANARY_RULES, person_names={CANARY_NAME})
        prompt = f"Email {CANARY_EMAIL} about record {CANARY_SSN}."

        # Act
        entities = await detector.detect(prompt)
        with pytest.raises(PolicyViolationError):
            await tokenizer.transform(
                tenant_id=TENANT_ID,
                session_id=uuid4(),
                text=prompt,
                entities=entities,
                policy=policy_snapshot(ssn_action=EntityAction.BLOCK),
            )

        # Assert -- the email was never written either: the block happens first.
        assert await dump_vault(redis_client) == b""


# ---------------------------------------------------------------------------
# The real detector
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def presidio() -> PresidioDetector:
    """One detector for the module: constructing it loads a spaCy model."""
    return PresidioDetector()


class TestRealDetectorCoverage:
    """What the shipped detector can and cannot see, asserted rather than assumed."""

    @pytest.mark.parametrize("canary", CANARIES)
    async def test_presidio_does_not_recognize_the_canary(
        self, presidio: PresidioDetector, canary: str
    ) -> None:
        """Documents the gap that justifies ``FakeDetector`` above.

        If a future detector upgrade starts recognizing one of these, this test
        fails and the canary run should switch to the real engine for it.
        """
        # Arrange
        prompt = f"Reference {canary} in the file."

        # Act
        found = await presidio.detect(prompt)

        # Assert
        covered = [prompt[entity.start : entity.end] for entity in found]
        assert not any(part in canary for part in covered), (
            f"the real detector now sees {covered!r}; move this canary to the real engine"
        )

    async def test_realistic_values_never_leave_the_gateway(
        self,
        presidio: PresidioDetector,
        tokenizer: Tokenizer,
        vault: RedisTokenVault,
        redis_client: Redis,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # Arrange -- values the shipped detector genuinely recognizes. Logs are
        # captured at the configured production level here, not DEBUG; see the
        # test below for why that distinction is a finding rather than a fudge.
        prompt = f"My email is {REALISTIC_EMAIL} and my SSN is {REALISTIC_SSN}."

        # Act
        run = await run_pipeline(
            detector=presidio,
            tokenizer=tokenizer,
            vault=vault,
            redis_client=redis_client,
            prompt=prompt,
            policy=policy_snapshot(),
            caplog=caplog,
            log_level=PRODUCTION_LOG_LEVEL,
        )

        # Assert
        assert run.summary.tokenized >= 2
        for original in (REALISTIC_EMAIL, REALISTIC_SSN):
            offenders = [name for name, text in run.surfaces().items() if original in text]
            assert offenders == [], f"{original} leaked into: {', '.join(offenders)}"
            assert original.encode("utf-8") not in run.vault_bytes
            assert original in run.restored_response

    async def test_debug_log_level_does_not_echo_analyzed_text(
        self,
        presidio: PresidioDetector,
        tokenizer: Tokenizer,
        vault: RedisTokenVault,
        redis_client: Redis,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # Arrange
        prompt = f"My email is {REALISTIC_EMAIL} and my SSN is {REALISTIC_SSN}."

        # Act
        run = await run_pipeline(
            detector=presidio,
            tokenizer=tokenizer,
            vault=vault,
            redis_client=redis_client,
            prompt=prompt,
            policy=policy_snapshot(),
            caplog=caplog,
            log_level=logging.DEBUG,
        )

        # Assert -- the property must hold at any log level. presidio-analyzer
        # logs the context around each match at DEBUG; app.detection.analyzer
        # raises its logger floor to INFO before the first analyze() call.
        assert REALISTIC_EMAIL not in run.logs
        assert REALISTIC_SSN not in run.logs


# ---------------------------------------------------------------------------
# The canaries themselves
# ---------------------------------------------------------------------------
def test_canaries_match_the_implementation_plan() -> None:
    """Guards the constants: a typo here would silently weaken every test above."""
    # Arrange
    expected: Sequence[str] = (
        "SENSITIVE_CANARY_EMAIL_7f91@example.test",
        "SENSITIVE_CANARY_SSN_123-45-6789",
        "SENSITIVE_CANARY_NAME_Avery Example",
    )

    # Assert
    assert tuple(expected) == CANARIES
