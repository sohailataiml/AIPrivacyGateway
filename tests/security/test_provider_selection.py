"""Provider choice must change who answers and nothing else.

The risk this file exists for is a second code path. A "real provider" feature
implemented as a branch -- mock through the pipeline, real through something
quicker -- would pass every functional test while sending unprotected text
upstream. So these tests do not check that protection *happened*; they check
that it happened **for both adapters, through the same gateway**, and that a
refusal fires before either adapter is reachable.

The external adapter is a stub. CI must never depend on a live external call: a
test that spends money is a test people disable, and a test that needs network
is a test that fails for reasons unrelated to the code. What matters here is not
how the real adapter speaks HTTP -- that is ``OpenAIProvider``'s own concern --
but *what text arrives at an adapter*, and that is identical for both because
``OutboundGateway`` hands each the same ``ProtectedChatRequest``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr

from app.audit.correlation import CorrelationHasher
from app.config.settings import Settings
from app.detection.config import DetectionConfig
from app.detection.fakes import FakeDetector
from app.domain.errors import ProviderNotAllowedError
from app.domain.models import (
    ChatMessage,
    EntityAction,
    ProtectedChatRequest,
    ProviderResponse,
    ProviderUsage,
    UnknownTokenAction,
)
from app.llm.mock_provider import MOCK_PROVIDER_ALIAS, MockProvider
from app.llm.openai_provider import OPENAI_PROVIDER_ALIAS
from app.llm.registry import ProviderRegistry, build_default_registry
from app.outbound.gateway import OutboundBlockedError, OutboundGateway
from app.policy.models import (
    POLICY_SCHEMA_VERSION,
    EntityRule,
    PolicyDocument,
    PolicySnapshot,
    ProviderRule,
)

pytestmark = pytest.mark.security

EXTERNAL_ALIAS = OPENAI_PROVIDER_ALIAS
TENANT = UUID("11111111-1111-4111-8111-111111111111")
POLICY_ID = UUID("22222222-2222-4222-8222-222222222222")

PERSON = "Dana Whitfield"
"""Synthetic. The outbound scan is configured to find this name, which is how a
'the scan refuses' case is produced without depending on Presidio."""

CLEAN_TEXT = "Please summarise the attached report."
LEAKED_TEXT = f"Please contact {PERSON} about the report."


def make_settings(**overrides: object) -> Settings:
    defaults: dict[str, object] = {
        "app_env": "test",
        "api_key_pepper": SecretStr("provider-selection-test-pepper-not-a-secret"),
        "vault_active_key_id": "k1",
        "vault_keys": {"k1": SecretStr("A" * 43 + "=")},
        "openai_api_key": SecretStr("sk-test-not-a-real-key-0000000000"),
    }
    return Settings(**{**defaults, **overrides})  # type: ignore[arg-type]


def make_snapshot() -> PolicySnapshot:
    document = PolicyDocument(
        schema_version=POLICY_SCHEMA_VERSION,
        name="provider-selection-test",
        session_ttl_seconds=900,
        max_entities=50,
        providers={
            MOCK_PROVIDER_ALIAS: ProviderRule(models=("general-chat",)),
            EXTERNAL_ALIAS: ProviderRule(models=("fast",)),
        },
        entities={"PERSON": EntityRule(action=EntityAction.TOKENIZE, min_score=0.5)},
        unknown_output_token_action=UnknownTokenAction.PRESERVE,
    )
    return PolicySnapshot.from_document(document, policy_id=POLICY_ID, tenant_id=TENANT, version=1)


def make_gateway(registry: ProviderRegistry) -> OutboundGateway:
    """A gateway whose scan finds ``PERSON`` -- the same one for every adapter."""
    return OutboundGateway(
        detector=FakeDetector(config=DetectionConfig(), person_names=(PERSON,)),
        providers=registry,
        hasher=CorrelationHasher(key=bytes(range(32))),
    )


def make_request(alias: str, text: str) -> ProtectedChatRequest:
    return ProtectedChatRequest(
        request_id=uuid4(),
        tenant_id=TENANT,
        session_id=uuid4(),
        provider_alias=alias,
        model_alias="fast" if alias == EXTERNAL_ALIAS else "general-chat",
        messages=(ChatMessage(role="user", content=text),),
        policy_version=1,
    )


@dataclass
class RecordingProvider:
    """Stands in for a real adapter and records exactly what it was handed."""

    alias: str = EXTERNAL_ALIAS
    seen: list[ProtectedChatRequest] = field(default_factory=list)

    async def complete(self, request: ProtectedChatRequest) -> ProviderResponse:
        self.seen.append(request)
        return ProviderResponse(
            content="Acknowledged.",
            model="stub-model",
            usage=ProviderUsage(input_tokens=1, output_tokens=1, total_tokens=2),
            finish_reason="completed",
        )

    async def aclose(self) -> None:
        """Match the adapter lifecycle."""

    def text(self) -> str:
        return "\n".join(m.content for call in self.seen for m in call.messages)


class TestRegistryGating:
    """Registration is the credential gate, and it fails closed."""

    def test_the_external_provider_is_absent_without_a_credential(self) -> None:
        registry = build_default_registry(make_settings(openai_api_key=None))

        assert MOCK_PROVIDER_ALIAS in registry
        assert EXTERNAL_ALIAS not in registry

    def test_selecting_it_anyway_is_refused_rather_than_downgraded(self) -> None:
        """No silent fallback.

        A demo that answered from the mock while the operator believed a real
        model had replied would be worse than an error: it would demonstrate
        something that did not happen.
        """
        registry = build_default_registry(make_settings(openai_api_key=None))

        with pytest.raises(ProviderNotAllowedError):
            registry.get(EXTERNAL_ALIAS)

    def test_a_credential_registers_the_adapter(self) -> None:
        registry = build_default_registry(make_settings())

        assert EXTERNAL_ALIAS in registry
        assert MOCK_PROVIDER_ALIAS in registry

    def test_the_mock_is_always_present(self) -> None:
        # Offline development, deterministic demos, and this test suite all
        # depend on it, so it is never conditional on configuration.
        assert MOCK_PROVIDER_ALIAS in build_default_registry(make_settings(openai_api_key=None))


class TestTheScanGatesBothAdapters:
    async def test_a_refused_scan_reaches_neither_adapter(self) -> None:
        recorder = RecordingProvider()
        registry = ProviderRegistry.from_providers(
            MockProvider(alias=MOCK_PROVIDER_ALIAS), recorder
        )
        gateway = make_gateway(registry)
        snapshot = make_snapshot()

        for alias in (MOCK_PROVIDER_ALIAS, EXTERNAL_ALIAS):
            with pytest.raises(OutboundBlockedError):
                await gateway.send(make_request(alias, LEAKED_TEXT), policy=snapshot)

        # The mock cannot record, so the external adapter carries the assertion:
        # if the scan were bypassed for the "real" path, this would be non-empty.
        assert recorder.seen == []

    async def test_a_clean_payload_reaches_the_external_adapter(self) -> None:
        recorder = RecordingProvider()
        gateway = make_gateway(ProviderRegistry.from_providers(recorder))

        await gateway.send(make_request(EXTERNAL_ALIAS, CLEAN_TEXT), policy=make_snapshot())

        assert recorder.text() == CLEAN_TEXT

    async def test_the_external_adapter_never_receives_a_detected_original(self) -> None:
        recorder = RecordingProvider()
        gateway = make_gateway(ProviderRegistry.from_providers(recorder))

        with pytest.raises(OutboundBlockedError):
            await gateway.send(make_request(EXTERNAL_ALIAS, LEAKED_TEXT), policy=make_snapshot())

        assert PERSON not in recorder.text()

    async def test_the_transmission_reports_the_adapter_that_ran(self) -> None:
        # Provider identity is execution metadata, not the echoed request.
        recorder = RecordingProvider()
        gateway = make_gateway(ProviderRegistry.from_providers(recorder))

        transmission = await gateway.send(
            make_request(EXTERNAL_ALIAS, CLEAN_TEXT), policy=make_snapshot()
        )

        assert transmission.provider_alias == EXTERNAL_ALIAS

    async def test_an_unregistered_alias_is_refused_after_the_scan(self) -> None:
        """Ordering: the scan is not skipped for an alias that will be refused.

        The adapter lookup happens after attestation, so a caller cannot use an
        unknown alias to find out whether their payload would have passed.
        """
        gateway = make_gateway(ProviderRegistry.from_providers(MockProvider()))

        with pytest.raises(OutboundBlockedError):
            await gateway.send(make_request(EXTERNAL_ALIAS, LEAKED_TEXT), policy=make_snapshot())


class TestCredentialsNeverTravel:
    def test_the_key_is_absent_from_adapter_and_registry_reprs(self) -> None:
        settings = make_settings()
        registry = build_default_registry(settings)

        assert settings.openai_api_key is not None
        secret = settings.openai_api_key.get_secret_value()
        # repr is what lands in a traceback, a log line, and an error report.
        assert secret not in repr(registry.get(EXTERNAL_ALIAS))
        assert secret not in repr(registry)
