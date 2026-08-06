"""Tests for the secure pipeline.

The properties asserted here are ordering properties, and ordering is the whole
point of this module: mappings are durable before the provider is reachable, a
blocked request creates nothing anywhere, one session id covers every message,
and every dependency failure stops the request instead of degrading it.

Everything is an in-memory fake except the two pieces whose behaviour the
ordering depends on -- the real ``Tokenizer`` and the real ``ProviderRegistry``.
Stubbing those would let a test pass while the production wiring wrote nothing
to the vault. The vault fake records call order, and the provider fake asserts,
from inside the provider call, that the mappings are already there.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final
from uuid import UUID

import pytest
from pydantic import SecretStr

from app.audit.correlation import CorrelationHasher
from app.config.settings import AppEnv, Settings
from app.detection import Detector, FakeDetector
from app.domain.errors import (
    AuditUnavailableError,
    DetectorUnavailableError,
    EntityLimitExceededError,
    ErrorCode,
    GatewayError,
    InvalidRequestError,
    PolicyNotFoundError,
    PolicyViolationError,
    ProviderNotAllowedError,
    ProviderResponseInvalidError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    RequestTooLargeError,
    RestorationError,
    VaultUnavailableError,
)
from app.domain.models import (
    ChatMessage,
    ChatRequest,
    DetectedEntity,
    EntityAction,
    Principal,
    PrivacySummary,
    ProtectedChatRequest,
    ProviderResponse,
    ProviderUsage,
    Scope,
    VaultWriteRequest,
)
from app.llm import ProviderRegistry
from app.outbound.gateway import OutboundGateway
from app.pipeline import (
    DetectorLike,
    OutputPipelineLike,
    PipelineConfig,
    PipelineStage,
    RequestOutcome,
    SecurePipeline,
    TokenizerLike,
    audit_payload,
    default_timeout_seconds,
    entity_budget,
    resolve_session_id,
    run_stage,
    stage_failure,
)
from app.pipeline.context import PipelineAttempt
from app.policy.models import (
    POLICY_SCHEMA_VERSION,
    EntityRule,
    PolicyDocument,
    PolicySnapshot,
    ProviderRule,
)
from app.tokenization import Fingerprinter, Tokenizer, find_token_strings
from app.vault.fakes import InMemoryTokenVault

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TENANT: Final = UUID("11111111-1111-1111-1111-111111111111")
API_KEY_ID: Final = UUID("22222222-2222-2222-2222-222222222222")
POLICY_ID: Final = UUID("33333333-3333-3333-3333-333333333333")
FIXED_SESSION: Final = UUID("44444444-4444-4444-4444-444444444444")
POLICY_VERSION: Final = 7

PROVIDER_ALIAS: Final = "mock"
MODEL_ALIAS: Final = "test-model"

EMAIL: Final = "jordan.rivera@example.com"
OTHER_EMAIL: Final = "dana.whitfield@example.org"
SSN: Final = "123-45-6789"

VAULT_WRITE: Final = "vault.get_or_create_many"
VAULT_READ: Final = "vault.resolve_many"
PROVIDER_CALL: Final = "provider.complete"
RESTORE_CALL: Final = "output.restore"

FINGERPRINT_KEY: Final = b"pipeline-unit-test-fingerprint-key-0123456789"

TEST_ENTITY_RULES: Final = {
    "EMAIL_ADDRESS": EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    "PHONE_NUMBER": EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    "PERSON": EntityRule(action=EntityAction.TOKENIZE, min_score=0.7),
    "US_SSN": EntityRule(action=EntityAction.BLOCK, min_score=0.5),
}


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------
def build_settings(**overrides: Any) -> Settings:
    """Test settings that never read a developer's ``.env``."""
    defaults: dict[str, Any] = {
        "_env_file": None,
        "app_env": AppEnv.TEST,
        "audit_hmac_key": SecretStr("a" * 44),
    }
    return Settings(**{**defaults, **overrides})


def build_snapshot(
    *,
    max_entities: int = 100,
    entities: dict[str, EntityRule] | None = None,
    session_ttl_seconds: int = 900,
) -> PolicySnapshot:
    document = PolicyDocument(
        schema_version=POLICY_SCHEMA_VERSION,
        name="pipeline-test",
        session_ttl_seconds=session_ttl_seconds,
        max_entities=max_entities,
        providers={PROVIDER_ALIAS: ProviderRule(models=(MODEL_ALIAS,))},
        entities=entities if entities is not None else dict(TEST_ENTITY_RULES),
    )
    return PolicySnapshot.from_document(
        document, policy_id=POLICY_ID, tenant_id=TENANT, version=POLICY_VERSION
    )


def build_principal() -> Principal:
    return Principal(
        tenant_id=TENANT,
        api_key_id=API_KEY_ID,
        api_key_prefix="sgw_test_abcd",
        scopes=frozenset({Scope.CHAT_INVOKE}),
    )


def build_request(
    *contents: str,
    roles: tuple[str, ...] | None = None,
    session_id: UUID | None = None,
) -> ChatRequest:
    chosen = roles if roles is not None else ("user",) * len(contents)
    return ChatRequest(
        session_id=session_id,
        provider=PROVIDER_ALIAS,
        model=MODEL_ALIAS,
        messages=[
            ChatMessage(role=role, content=content)  # type: ignore[arg-type]
            for role, content in zip(chosen, contents, strict=True)
        ],
    )


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
@dataclass
class FakePolicyResolver:
    """Returns a prepared snapshot, or fails the way ``PolicyService`` would."""

    snapshot: PolicySnapshot
    error: GatewayError | None = None
    calls: list[tuple[UUID, str, str]] = field(default_factory=list)

    async def resolve(self, *, tenant_id: UUID, provider: str, model: str) -> PolicySnapshot:
        self.calls.append((tenant_id, provider, model))
        if self.error is not None:
            raise self.error
        return self.snapshot


class RecordingVault:
    """``TokenVault`` that appends every call to a shared ordering log."""

    def __init__(self, log: list[str]) -> None:
        self._log = log
        self._inner = InMemoryTokenVault()

    def simulate_failure(self, error: GatewayError | None) -> None:
        self._inner.simulate_failure(error)

    def stored_original_values(self) -> list[str]:
        return self._inner.stored_original_values()

    async def get_or_create_many(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        entries: Sequence[VaultWriteRequest],
        ttl_seconds: int,
    ) -> tuple[str, ...]:
        tokens = await self._inner.get_or_create_many(
            tenant_id=tenant_id,
            session_id=session_id,
            entries=entries,
            ttl_seconds=ttl_seconds,
        )
        # Appended *after* the write returns, so the log records durability,
        # not intent. One entry per batch, whatever the entity count -- which
        # is what makes the ordering assertions also assert ADR-0022.
        self._log.append(VAULT_WRITE)
        return tokens

    async def resolve_many(
        self, *, tenant_id: UUID, session_id: UUID, tokens: set[str]
    ) -> dict[str, str]:
        self._log.append(VAULT_READ)
        return await self._inner.resolve_many(
            tenant_id=tenant_id, session_id=session_id, tokens=tokens
        )

    async def delete_session(self, *, tenant_id: UUID, session_id: UUID) -> int:
        return await self._inner.delete_session(tenant_id=tenant_id, session_id=session_id)


class RecordingProvider:
    """Echoes tokens back, and refuses to answer before the vault is written.

    ``expect_persisted`` is the enforcement point for the phase's central
    guarantee: if the pipeline ever reached a provider before the tokenizer's
    vault writes completed, this raises from inside the provider call.
    """

    alias: str = PROVIDER_ALIAS

    def __init__(self, log: list[str], vault: RecordingVault) -> None:
        self._log = log
        self._vault = vault
        self.requests: list[ProtectedChatRequest] = []
        self.expect_persisted: tuple[str, ...] = ()
        self.error: BaseException | None = None
        self.delay_seconds: float = 0.0
        self.response: ProviderResponse | None = None
        self.in_flight = 0
        self.max_in_flight = 0

    async def complete(self, request: ProtectedChatRequest) -> ProviderResponse:
        self._log.append(PROVIDER_CALL)
        self.requests.append(request)

        stored = set(self._vault.stored_original_values())
        missing = [value for value in self.expect_persisted if value not in stored]
        if missing:
            raise AssertionError(f"provider reached with {len(missing)} mapping(s) unpersisted")

        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.delay_seconds:
                await asyncio.sleep(self.delay_seconds)
            if self.error is not None:
                raise self.error
            return self.response if self.response is not None else _echo(request)
        finally:
            self.in_flight -= 1


def _echo(request: ProtectedChatRequest) -> ProviderResponse:
    tokens: list[str] = []
    for message in request.messages:
        tokens.extend(token for token in find_token_strings(message.content) if token not in tokens)
    return ProviderResponse(
        content="Reply. " + " ".join(tokens),
        model="fake-model-1",
        usage=ProviderUsage(input_tokens=10, output_tokens=5, total_tokens=15),
        finish_reason="completed",
    )


@dataclass(frozen=True, slots=True)
class FakeRestored:
    """Satisfies ``RestoredOutputLike`` structurally."""

    text: str
    summary: PrivacySummary
    usage: ProviderUsage | None


class FakeOutputPipeline:
    """Resolves this session's tokens through the vault, like the real one."""

    def __init__(self, log: list[str], vault: RecordingVault) -> None:
        self._log = log
        self._vault = vault
        self.calls: list[tuple[UUID, UUID]] = []
        self.error: BaseException | None = None

    async def restore(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        response: ProviderResponse,
        policy: Any,
    ) -> FakeRestored:
        self._log.append(RESTORE_CALL)
        self.calls.append((tenant_id, session_id))
        if self.error is not None:
            raise self.error

        tokens = find_token_strings(response.content)
        resolved = await self._vault.resolve_many(
            tenant_id=tenant_id, session_id=session_id, tokens=set(tokens)
        )
        text = response.content
        for token, original in resolved.items():
            text = text.replace(token, original)
        return FakeRestored(
            text=text,
            summary=PrivacySummary(
                restored=len(resolved), unknown_tokens=len(tokens) - len(resolved)
            ),
            usage=response.usage,
        )


class FakeAudit:
    """Captures audit payloads so tests can assert what would be persisted."""

    def __init__(self) -> None:
        self.payloads: list[dict[str, Any]] = []
        self.error: BaseException | None = None

    async def record(self, **fields: Any) -> None:
        if self.error is not None:
            raise self.error
        self.payloads.append(dict(fields))


class ScriptedDetector:
    """Fails, stalls, or returns fixed spans. Never analyses anything."""

    def __init__(
        self,
        *,
        error: BaseException | None = None,
        delay_seconds: float = 0.0,
        entities: list[DetectedEntity] | None = None,
    ) -> None:
        self._error = error
        self._delay_seconds = delay_seconds
        self._entities = entities if entities is not None else []
        self.call_count = 0

    async def detect(
        self,
        text: str,
        *,
        language: str = "en",
        requested_entities: set[str] | None = None,
        diagnostic: bool = False,
    ) -> list[DetectedEntity]:
        self.call_count += 1
        if self._delay_seconds:
            await asyncio.sleep(self._delay_seconds)
        if self._error is not None:
            raise self._error
        return list(self._entities)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
@dataclass
class Harness:
    """One assembled pipeline plus every fake it was built from."""

    pipeline: SecurePipeline
    log: list[str]
    policy: FakePolicyResolver
    detector: Any
    vault: RecordingVault
    provider: RecordingProvider
    output: FakeOutputPipeline
    audit: FakeAudit

    @property
    def protected(self) -> ProtectedChatRequest:
        """The single request the provider received."""
        assert len(self.provider.requests) == 1
        return self.provider.requests[0]


def build_harness(
    *,
    snapshot: PolicySnapshot | None = None,
    detector: Any | None = None,
    settings: Settings | None = None,
    config: PipelineConfig | None = None,
    registry: ProviderRegistry | None = None,
) -> Harness:
    log: list[str] = []
    vault = RecordingVault(log)
    provider = RecordingProvider(log, vault)
    policy = FakePolicyResolver(snapshot=snapshot if snapshot is not None else build_snapshot())
    output = FakeOutputPipeline(log, vault)
    audit = FakeAudit()
    resolved_settings = settings if settings is not None else build_settings()
    resolved_detector = detector if detector is not None else FakeDetector()

    resolved_registry = (
        registry if registry is not None else ProviderRegistry.from_providers(provider)
    )
    pipeline = SecurePipeline(
        policy_service=policy,
        detector=resolved_detector,
        tokenizer=Tokenizer(vault=vault, fingerprinter=Fingerprinter(FINGERPRINT_KEY)),
        provider_registry=resolved_registry,
        # The real shared boundary, not a stub. The outbound scan is a control
        # on this path now, and a harness that stubbed it out would let every
        # test below pass against a pipeline that never checked anything.
        outbound=OutboundGateway(
            detector=resolved_detector,
            providers=resolved_registry,
            hasher=CorrelationHasher(key=bytes(range(32))),
        ),
        output_pipeline=output,
        audit_service=audit,
        settings=resolved_settings,
        config=config if config is not None else PipelineConfig(timeout_seconds=30.0),
    )
    return Harness(
        pipeline=pipeline,
        log=log,
        policy=policy,
        detector=resolved_detector,
        vault=vault,
        provider=provider,
        output=output,
        audit=audit,
    )


# ---------------------------------------------------------------------------
# Happy path and identity stability
# ---------------------------------------------------------------------------
async def test_invoke_returns_a_restored_response() -> None:
    # Arrange
    harness = build_harness()
    request = build_request(f"Email {EMAIL} today.")

    # Act
    response = await harness.pipeline.invoke(request, build_principal())

    # Assert
    assert response.message.role == "assistant"
    assert EMAIL in response.message.content
    assert response.privacy.tokenized == 1
    assert response.privacy.restored == 1
    assert response.usage is not None


async def test_request_and_session_ids_are_stable_through_every_stage() -> None:
    # Arrange
    harness = build_harness()
    request = build_request(f"Email {EMAIL}.", session_id=FIXED_SESSION)

    # Act
    response = await harness.pipeline.invoke(request, build_principal())

    # Assert
    protected = harness.protected
    audit_row = harness.audit.payloads[0]
    assert protected.session_id == FIXED_SESSION
    assert response.session_id == FIXED_SESSION
    assert harness.output.calls == [(TENANT, FIXED_SESSION)]
    assert audit_row["session_id"] == FIXED_SESSION
    assert protected.request_id == response.request_id == audit_row["request_id"]


async def test_policy_version_is_carried_to_the_provider_and_the_audit_row() -> None:
    # Arrange
    harness = build_harness()

    # Act
    await harness.pipeline.invoke(build_request("nothing sensitive"), build_principal())

    # Assert
    assert harness.protected.policy_version == POLICY_VERSION
    assert harness.audit.payloads[0]["policy_version"] == POLICY_VERSION
    assert harness.audit.payloads[0]["policy_id"] == POLICY_ID


async def test_provider_and_model_aliases_are_echoed_not_provider_model_ids() -> None:
    # Arrange
    harness = build_harness()

    # Act
    response = await harness.pipeline.invoke(build_request("hello"), build_principal())

    # Assert
    assert (response.provider, response.model) == (PROVIDER_ALIAS, MODEL_ALIAS)


# ---------------------------------------------------------------------------
# Ordering: the vault is written before the provider is reachable
# ---------------------------------------------------------------------------
async def test_mappings_are_persisted_before_the_provider_is_called() -> None:
    # Arrange
    harness = build_harness()
    harness.provider.expect_persisted = (EMAIL, OTHER_EMAIL)
    request = build_request(f"Write to {EMAIL}.", f"And copy {OTHER_EMAIL}.")

    # Act
    await harness.pipeline.invoke(request, build_principal())

    # Assert: every vault write precedes the single provider call.
    provider_index = harness.log.index(PROVIDER_CALL)
    writes = [index for index, event in enumerate(harness.log) if event == VAULT_WRITE]
    assert len(writes) == 2
    assert max(writes) < provider_index


async def test_provider_never_receives_a_raw_detected_value() -> None:
    # Arrange
    harness = build_harness()
    request = build_request(f"Contact {EMAIL} or Jordan Rivera.")

    # Act
    await harness.pipeline.invoke(request, build_principal())

    # Assert
    outbound = " ".join(message.content for message in harness.protected.messages)
    assert EMAIL not in outbound
    assert "Jordan Rivera" not in outbound
    assert len(find_token_strings(outbound)) == 2


async def test_no_vault_write_and_no_provider_call_when_nothing_is_detected() -> None:
    # Arrange
    harness = build_harness()

    # Act
    await harness.pipeline.invoke(build_request("The weather is fine."), build_principal())

    # Assert
    assert VAULT_WRITE not in harness.log
    assert harness.log.index(PROVIDER_CALL) < harness.log.index(RESTORE_CALL)


# ---------------------------------------------------------------------------
# Blocking stops before the vault and before the provider
# ---------------------------------------------------------------------------
async def test_blocked_entity_stops_before_the_vault_and_the_provider() -> None:
    # Arrange
    harness = build_harness()
    request = build_request(f"My SSN is {SSN}.")

    # Act
    with pytest.raises(PolicyViolationError) as caught:
        await harness.pipeline.invoke(request, build_principal())

    # Assert
    assert caught.value.code is ErrorCode.POLICY_VIOLATION
    assert harness.log == []
    assert harness.vault.stored_original_values() == []
    assert harness.provider.requests == []


async def test_a_block_in_a_later_message_leaves_no_mapping_from_an_earlier_one() -> None:
    # Arrange: the email would tokenize cleanly on its own.
    harness = build_harness()
    request = build_request(f"Email {EMAIL}.", "Filler.", f"SSN {SSN}.")

    # Act
    with pytest.raises(PolicyViolationError):
        await harness.pipeline.invoke(request, build_principal())

    # Assert: the whole request is refused before any message is tokenized.
    assert harness.vault.stored_original_values() == []
    assert VAULT_WRITE not in harness.log
    assert harness.provider.requests == []


async def test_a_blocked_request_never_leaks_the_blocked_value() -> None:
    # Arrange
    harness = build_harness()

    # Act
    with pytest.raises(PolicyViolationError) as caught:
        await harness.pipeline.invoke(build_request(f"SSN {SSN}."), build_principal())

    # Assert
    rendered = f"{caught.value.public_message} {caught.value.log_context}"
    assert SSN not in rendered
    assert caught.value.log_context["entity_type"] == "US_SSN"


# ---------------------------------------------------------------------------
# Every role, one session
# ---------------------------------------------------------------------------
async def test_every_message_role_is_processed() -> None:
    # Arrange
    harness = build_harness()
    request = build_request(
        f"System note: {EMAIL}",
        f"User note: {OTHER_EMAIL}",
        "Assistant note: Jordan Rivera",
        roles=("system", "user", "assistant"),
    )

    # Act
    await harness.pipeline.invoke(request, build_principal())

    # Assert
    protected = harness.protected
    assert [message.role for message in protected.messages] == ["system", "user", "assistant"]
    for message in protected.messages:
        assert len(find_token_strings(message.content)) == 1
    assert EMAIL not in protected.messages[0].content
    assert OTHER_EMAIL not in protected.messages[1].content
    assert "Jordan Rivera" not in protected.messages[2].content


async def test_one_session_id_makes_a_repeated_value_tokenize_identically() -> None:
    # Arrange
    harness = build_harness()
    request = build_request(
        f"System: {EMAIL}",
        "Unrelated turn.",
        f"Assistant: {EMAIL}",
        roles=("system", "user", "assistant"),
    )

    # Act
    await harness.pipeline.invoke(request, build_principal())

    # Assert: one mapping, one token, two occurrences.
    messages = harness.protected.messages
    first = find_token_strings(messages[0].content)
    third = find_token_strings(messages[2].content)
    assert first == third
    assert harness.vault.stored_original_values() == [EMAIL]


async def test_absent_session_id_is_minted_and_shared_by_every_message() -> None:
    # Arrange
    harness = build_harness()

    # Act
    response = await harness.pipeline.invoke(
        build_request(f"a {EMAIL}", f"b {EMAIL}"), build_principal()
    )

    # Assert
    assert response.session_id == harness.protected.session_id
    assert harness.vault.stored_original_values() == [EMAIL]


def test_resolve_session_id_mints_a_fresh_id_when_absent() -> None:
    # Arrange / Act
    first = resolve_session_id(None)
    second = resolve_session_id(None)

    # Assert
    assert first != second
    assert resolve_session_id(FIXED_SESSION) == FIXED_SESSION


def test_resolve_session_id_refuses_the_nil_uuid() -> None:
    # Arrange / Act / Assert
    with pytest.raises(InvalidRequestError):
        resolve_session_id(UUID(int=0))


# ---------------------------------------------------------------------------
# Fail closed: every dependency, in turn
# ---------------------------------------------------------------------------
async def test_missing_policy_fails_closed_before_detection() -> None:
    # Arrange
    detector = ScriptedDetector()
    harness = build_harness(detector=detector)
    harness.policy.error = PolicyNotFoundError()

    # Act
    with pytest.raises(PolicyNotFoundError):
        await harness.pipeline.invoke(build_request(f"Email {EMAIL}."), build_principal())

    # Assert
    assert detector.call_count == 0
    assert harness.provider.requests == []
    assert harness.log == []


async def test_disallowed_provider_fails_closed_before_detection() -> None:
    # Arrange
    detector = ScriptedDetector()
    harness = build_harness(detector=detector)
    harness.policy.error = ProviderNotAllowedError()

    # Act
    with pytest.raises(ProviderNotAllowedError):
        await harness.pipeline.invoke(build_request("hello"), build_principal())

    # Assert
    assert detector.call_count == 0
    assert harness.provider.requests == []


async def test_unregistered_provider_alias_fails_before_the_vault() -> None:
    # Arrange: policy permits the alias, but no adapter is registered for it.
    harness = build_harness(registry=ProviderRegistry.from_providers())

    # Act
    with pytest.raises(ProviderNotAllowedError):
        await harness.pipeline.invoke(build_request(f"Email {EMAIL}."), build_principal())

    # Assert
    assert harness.vault.stored_original_values() == []
    assert VAULT_WRITE not in harness.log


async def test_detector_down_fails_closed_and_never_reaches_the_provider() -> None:
    # Arrange
    harness = build_harness(detector=ScriptedDetector(error=DetectorUnavailableError()))

    # Act
    with pytest.raises(DetectorUnavailableError):
        await harness.pipeline.invoke(build_request(f"Email {EMAIL}."), build_principal())

    # Assert
    assert harness.provider.requests == []
    assert VAULT_WRITE not in harness.log


async def test_an_unexpected_detector_error_becomes_a_domain_error() -> None:
    # Arrange
    harness = build_harness(detector=ScriptedDetector(error=RuntimeError("spaCy exploded")))

    # Act
    with pytest.raises(DetectorUnavailableError) as caught:
        await harness.pipeline.invoke(build_request("hello"), build_principal())

    # Assert: the third-party message never becomes the public message.
    assert "spaCy" not in caught.value.public_message
    assert caught.value.log_context["stage"] == str(PipelineStage.DETECTION)
    assert harness.provider.requests == []


async def test_vault_down_fails_closed_and_never_reaches_the_provider() -> None:
    # Arrange
    harness = build_harness()
    harness.vault.simulate_failure(VaultUnavailableError())

    # Act
    with pytest.raises(VaultUnavailableError):
        await harness.pipeline.invoke(build_request(f"Email {EMAIL}."), build_principal())

    # Assert
    assert harness.provider.requests == []
    assert PROVIDER_CALL not in harness.log


async def test_provider_down_fails_closed() -> None:
    # Arrange
    harness = build_harness()
    harness.provider.error = ProviderUnavailableError()

    # Act
    with pytest.raises(ProviderUnavailableError):
        await harness.pipeline.invoke(build_request(f"Email {EMAIL}."), build_principal())

    # Assert: mappings survive their normal TTL, and nothing was restored.
    assert harness.vault.stored_original_values() == [EMAIL]
    assert harness.output.calls == []


async def test_an_unexpected_provider_error_becomes_a_domain_error() -> None:
    # Arrange
    harness = build_harness()
    harness.provider.error = RuntimeError("socket reset")

    # Act
    with pytest.raises(ProviderUnavailableError) as caught:
        await harness.pipeline.invoke(build_request("hello"), build_principal())

    # Assert
    assert "socket" not in caught.value.public_message


async def test_malformed_provider_content_is_rejected() -> None:
    # Arrange
    harness = build_harness()
    harness.provider.response = ProviderResponse(content=None, model="fake")  # type: ignore[arg-type]

    # Act
    with pytest.raises(ProviderResponseInvalidError):
        await harness.pipeline.invoke(build_request("hello"), build_principal())

    # Assert
    assert harness.output.calls == []


async def test_restoration_failure_fails_closed() -> None:
    # Arrange
    harness = build_harness()
    harness.output.error = RestorationError()

    # Act / Assert
    with pytest.raises(RestorationError):
        await harness.pipeline.invoke(build_request(f"Email {EMAIL}."), build_principal())


async def test_an_unexpected_restoration_error_becomes_a_domain_error() -> None:
    # Arrange
    harness = build_harness()
    harness.output.error = RuntimeError("token table corrupt")

    # Act
    with pytest.raises(RestorationError) as caught:
        await harness.pipeline.invoke(build_request("hello"), build_principal())

    # Assert
    assert caught.value.log_context["stage"] == str(PipelineStage.RESTORATION)


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
async def test_entity_budget_is_enforced_across_the_whole_request() -> None:
    # Arrange: one entity per message passes per message, three exceeds the cap.
    harness = build_harness(snapshot=build_snapshot(max_entities=2))
    request = build_request(f"a {EMAIL}", f"b {OTHER_EMAIL}", "c Jordan Rivera")

    # Act
    with pytest.raises(EntityLimitExceededError) as caught:
        await harness.pipeline.invoke(request, build_principal())

    # Assert
    assert caught.value.log_context["entity_count"] == 3
    assert harness.vault.stored_original_values() == []
    assert harness.provider.requests == []


async def test_the_deployment_ceiling_overrides_a_looser_policy() -> None:
    # Arrange
    harness = build_harness(
        snapshot=build_snapshot(max_entities=500),
        settings=build_settings(max_entities_per_request=1),
    )

    # Act / Assert
    with pytest.raises(EntityLimitExceededError):
        await harness.pipeline.invoke(
            build_request(f"a {EMAIL}", f"b {OTHER_EMAIL}"), build_principal()
        )


def test_entity_budget_takes_the_stricter_of_the_two_bounds() -> None:
    # Arrange
    snapshot = build_snapshot(max_entities=10)

    # Act / Assert
    assert entity_budget(policy=snapshot, deployment_max_entities=500) == 10
    assert entity_budget(policy=snapshot, deployment_max_entities=3) == 3


async def test_an_oversized_message_is_refused_before_detection() -> None:
    # Arrange
    detector = ScriptedDetector()
    harness = build_harness(detector=detector, settings=build_settings(max_message_chars=16))

    # Act
    with pytest.raises(RequestTooLargeError):
        await harness.pipeline.invoke(build_request("x" * 17), build_principal())

    # Assert
    assert detector.call_count == 0
    assert harness.policy.calls == []


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
async def test_privacy_counters_aggregate_across_every_message() -> None:
    # Arrange
    harness = build_harness()
    request = build_request(f"a {EMAIL}", f"b {OTHER_EMAIL}", "c Jordan Rivera")

    # Act
    response = await harness.pipeline.invoke(request, build_principal())

    # Assert
    assert response.privacy.detected == 3
    assert response.privacy.tokenized == 3
    assert response.privacy.entity_types == {"EMAIL_ADDRESS": 2, "PERSON": 1}
    assert response.privacy.restored == 3
    assert response.privacy.unknown_tokens == 0


async def test_a_repeated_value_counts_twice_but_stores_once() -> None:
    # Arrange
    harness = build_harness()

    # Act
    response = await harness.pipeline.invoke(
        build_request(f"a {EMAIL}", f"b {EMAIL}"), build_principal()
    )

    # Assert
    assert response.privacy.tokenized == 2
    assert harness.vault.stored_original_values() == [EMAIL]


# ---------------------------------------------------------------------------
# Deadline and concurrency
# ---------------------------------------------------------------------------
async def test_the_pipeline_deadline_stops_a_stalled_provider() -> None:
    # Arrange
    harness = build_harness(config=PipelineConfig(timeout_seconds=0.05))
    harness.provider.delay_seconds = 30.0

    # Act / Assert
    with pytest.raises(ProviderTimeoutError):
        await harness.pipeline.invoke(build_request(f"Email {EMAIL}."), build_principal())


async def test_the_pipeline_deadline_stops_a_stalled_detector() -> None:
    # Arrange
    harness = build_harness(
        detector=ScriptedDetector(delay_seconds=30.0),
        config=PipelineConfig(timeout_seconds=0.05),
    )

    # Act
    with pytest.raises(DetectorUnavailableError) as caught:
        await harness.pipeline.invoke(build_request("hello"), build_principal())

    # Assert
    assert caught.value.log_context["reason"] == "deadline_exceeded"
    assert harness.provider.requests == []


async def test_provider_concurrency_is_bounded() -> None:
    # Arrange
    harness = build_harness(
        config=PipelineConfig(timeout_seconds=30.0, max_concurrent_provider_calls=2)
    )
    harness.provider.delay_seconds = 0.02
    principal = build_principal()

    # Act
    await asyncio.gather(
        *(harness.pipeline.invoke(build_request(f"call {index}"), principal) for index in range(6))
    )

    # Assert
    assert len(harness.provider.requests) == 6
    assert harness.provider.max_in_flight <= 2


def test_pipeline_config_refuses_useless_bounds() -> None:
    # Arrange / Act / Assert
    with pytest.raises(ValueError, match="timeout_seconds"):
        PipelineConfig(timeout_seconds=0.0)
    with pytest.raises(ValueError, match="max_concurrent_provider_calls"):
        PipelineConfig(timeout_seconds=1.0, max_concurrent_provider_calls=0)


def test_the_default_deadline_exceeds_the_providers_own_budget() -> None:
    # Arrange
    settings = build_settings(
        provider_connect_timeout_seconds=5.0,
        provider_read_timeout_seconds=60.0,
        provider_max_retries=2,
    )

    # Act
    timeout = default_timeout_seconds(settings)

    # Assert: three attempts of 65s plus backoff, plus the gateway's own budget.
    assert timeout > 3 * 65.0


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
async def test_the_audit_row_carries_counts_and_identifiers_only() -> None:
    # Arrange
    harness = build_harness()

    # Act
    await harness.pipeline.invoke(build_request(f"Email {EMAIL}."), build_principal())

    # Assert
    payload = harness.audit.payloads[0]
    rendered = repr(payload)
    assert EMAIL not in rendered
    assert "⟦SGW:" not in rendered
    assert payload["status_code"] == 200
    assert payload["entity_counts"] == {"EMAIL_ADDRESS": 1}
    assert payload["actions"]["tokenized"] == 1
    assert payload["tenant_id"] == TENANT
    assert payload["api_key_id"] == API_KEY_ID


async def test_a_refused_request_is_audited_with_its_error_code() -> None:
    # Arrange
    harness = build_harness(detector=ScriptedDetector(error=DetectorUnavailableError()))

    # Act
    with pytest.raises(DetectorUnavailableError):
        await harness.pipeline.invoke(build_request("hello"), build_principal())

    # Assert
    payload = harness.audit.payloads[0]
    assert payload["error_code"] == str(ErrorCode.PRIVACY_DETECTOR_UNAVAILABLE)
    assert payload["status_code"] == 503
    assert payload["policy_version"] == POLICY_VERSION


async def test_a_blocked_request_is_audited_as_blocked() -> None:
    # Arrange
    harness = build_harness()

    # Act
    with pytest.raises(PolicyViolationError):
        await harness.pipeline.invoke(build_request(f"SSN {SSN}."), build_principal())

    # Assert
    assert harness.audit.payloads[0]["blocked"] is True


async def test_audit_failure_fails_the_request_when_configured_closed() -> None:
    # Arrange
    harness = build_harness(settings=build_settings(audit_fail_closed=True))
    harness.audit.error = AuditUnavailableError()

    # Act / Assert
    with pytest.raises(AuditUnavailableError):
        await harness.pipeline.invoke(build_request(f"Email {EMAIL}."), build_principal())


async def test_audit_failure_can_be_configured_open() -> None:
    # Arrange
    harness = build_harness(settings=build_settings(audit_fail_closed=False))
    harness.audit.error = AuditUnavailableError()

    # Act
    response = await harness.pipeline.invoke(build_request(f"Email {EMAIL}."), build_principal())

    # Assert
    assert EMAIL in response.message.content


async def test_audit_failure_never_masks_the_reason_a_request_was_refused() -> None:
    # Arrange
    harness = build_harness(detector=ScriptedDetector(error=DetectorUnavailableError()))
    harness.audit.error = AuditUnavailableError()

    # Act / Assert
    with pytest.raises(DetectorUnavailableError):
        await harness.pipeline.invoke(build_request("hello"), build_principal())


def test_audit_payload_has_no_field_that_could_hold_content() -> None:
    # Arrange
    attempt = PipelineAttempt.begin(
        request=build_request("hello"),
        principal=build_principal(),
        session_id=FIXED_SESSION,
        clock_now=0.0,
        timeout_seconds=1.0,
    )
    outcome = RequestOutcome(status_code=200, summary=PrivacySummary(detected=2, tokenized=2))

    # Act
    payload = audit_payload(attempt=attempt, snapshot=build_snapshot(), outcome=outcome)

    # Assert
    prohibited = {"content", "text", "messages", "message", "mappings", "tokens", "prompt"}
    assert prohibited.isdisjoint(payload)
    assert payload["actions"]["tokenized"] == 2


# ---------------------------------------------------------------------------
# Stage helper
# ---------------------------------------------------------------------------
async def _succeed() -> str:
    return "done"


async def _fail(error: BaseException) -> str:
    raise error


async def _stall() -> str:
    await asyncio.sleep(30.0)
    return "never"


async def test_run_stage_returns_the_stage_result() -> None:
    # Arrange
    deadline = asyncio.get_running_loop().time() + 5.0

    # Act
    result = await run_stage(
        _succeed(),
        stage=PipelineStage.POLICY,
        deadline=deadline,
        failure=stage_failure(GatewayError),
    )

    # Assert
    assert result == "done"


async def test_run_stage_passes_domain_errors_through_unchanged() -> None:
    # Arrange
    original = VaultUnavailableError(log_context={"reason": "redis_down"})
    deadline = asyncio.get_running_loop().time() + 5.0

    # Act
    with pytest.raises(VaultUnavailableError) as caught:
        await run_stage(
            _fail(original),
            stage=PipelineStage.TOKENIZATION,
            deadline=deadline,
            failure=stage_failure(DetectorUnavailableError),
        )

    # Assert
    assert caught.value is original


async def test_run_stage_uses_the_timeout_type_only_for_the_deadline() -> None:
    # Arrange
    failure = stage_failure(ProviderUnavailableError, timeout_type=ProviderTimeoutError)
    past = asyncio.get_running_loop().time() - 1.0
    future = asyncio.get_running_loop().time() + 5.0

    # Act / Assert
    with pytest.raises(ProviderTimeoutError):
        await run_stage(_stall(), stage=PipelineStage.PROVIDER, deadline=past, failure=failure)
    with pytest.raises(ProviderUnavailableError):
        await run_stage(
            _fail(RuntimeError("boom")),
            stage=PipelineStage.PROVIDER,
            deadline=future,
            failure=failure,
        )


async def test_run_stage_lets_a_real_cancellation_propagate() -> None:
    # Arrange
    deadline = asyncio.get_running_loop().time() + 30.0
    task = asyncio.create_task(
        run_stage(
            _stall(),
            stage=PipelineStage.PROVIDER,
            deadline=deadline,
            failure=stage_failure(ProviderUnavailableError),
        )
    )
    await asyncio.sleep(0)

    # Act
    task.cancel()

    # Assert
    with pytest.raises(asyncio.CancelledError):
        await task


# ---------------------------------------------------------------------------
# Seams
# ---------------------------------------------------------------------------
def test_the_pipelines_detector_seam_matches_the_detection_package() -> None:
    # Arrange
    detector = FakeDetector()

    # Act / Assert
    assert isinstance(detector, Detector)
    assert isinstance(detector, DetectorLike)


def test_the_real_tokenizer_satisfies_the_pipeline_seam() -> None:
    # Arrange
    tokenizer = Tokenizer(vault=InMemoryTokenVault(), fingerprinter=Fingerprinter(FINGERPRINT_KEY))

    # Act / Assert
    assert isinstance(tokenizer, TokenizerLike)


def test_the_output_pipeline_fake_satisfies_the_pipeline_seam() -> None:
    # Arrange
    output = FakeOutputPipeline([], RecordingVault([]))

    # Act / Assert
    assert isinstance(output, OutputPipelineLike)
