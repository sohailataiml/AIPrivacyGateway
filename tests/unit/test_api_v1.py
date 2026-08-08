"""``/v1`` router tests.

The application is assembled the way production assembles it -- ``create_app``,
the real lifespan, the real middleware stack, the real pipeline -- over a
``fakeredis`` vault, an in-memory SQLite database, the mock provider, and
``FakeDetector`` in place of Presidio. Nothing here loads spaCy or opens a
socket, and nothing in the request path is stubbed out, so what these tests
assert about headers, statuses, and bodies is what a deployment does.

Three properties get the most attention, because they are the ones a router is
most likely to lose: every protected route refuses an unauthenticated caller and
a caller holding the wrong scope; ``/v1/detect`` never echoes matched text; and
``DELETE /v1/sessions/{id}`` is idempotent and cannot reach across tenants.
"""

from __future__ import annotations

import base64
import re
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

import fakeredis.aioredis
import httpx
import pytest
import structlog.testing
from asgi_lifespan import LifespanManager
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.api import composition
from app.api.composition import Services, build_services, stop_services
from app.config.settings import Settings
from app.db.base import Base
from app.db.models import API_KEY_STATUS_ACTIVE, ApiKey, AuditEvent, Policy, Tenant
from app.db.session import build_session_factory
from app.detection.fakes import FakeDetector
from app.domain.models import (
    EntityAction,
    ProtectedChatRequest,
    ProviderResponse,
    Scope,
    UnknownTokenAction,
)
from app.llm.mock_provider import MockProvider
from app.main import create_app
from app.pipeline.preview import MASK
from app.policy.models import POLICY_SCHEMA_VERSION, EntityRule, PolicyDocument, ProviderRule
from app.repositories.api_keys import generate_api_key, prefix_of, verify_api_key
from app.tokenization.grammar import LEFT_DELIMITER, TOKEN_PATTERN

TENANT_A = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
TENANT_B = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")

PEPPER = SecretStr("api-v1-router-test-pepper-not-a-real-secret")
VAULT_KEY = base64.b64encode(bytes(range(1, 33))).decode()

PROVIDER = "mock"
MODEL = "general-chat"

# Every value below is invented. None of it belongs to a real person.
EMAIL = "jordan.rivera@example.test"
PERSON = "Jordan Rivera"
PHONE = "415-555-0142"
SSN = "123-45-6789"
IP = "203.0.113.7"

PROMPT = f"Email {PERSON} at {EMAIL} or call {PHONE}."
SENSITIVE_TEXT = f"{PROMPT} SSN {SSN}, host {IP}."

TEST_POLICY = PolicyDocument(
    schema_version=POLICY_SCHEMA_VERSION,
    name="router-test",
    session_ttl_seconds=1800,
    max_entities=50,
    providers={PROVIDER: ProviderRule(models=(MODEL,))},
    entities={
        "EMAIL_ADDRESS": EntityRule(action=EntityAction.TOKENIZE, min_score=0.7),
        "PHONE_NUMBER": EntityRule(action=EntityAction.TOKENIZE, min_score=0.4),
        "PERSON": EntityRule(action=EntityAction.TOKENIZE, min_score=0.75),
        "US_SSN": EntityRule(action=EntityAction.BLOCK, min_score=0.5),
        # Deliberately above the 0.6 the fake detector scores an address at, so
        # one detection in every response is a sub-threshold one.
        "IP_ADDRESS": EntityRule(action=EntityAction.REDACT, min_score=0.9),
    },
    unknown_output_token_action=UnknownTokenAction.PRESERVE,
)


# ---------------------------------------------------------------------------
# Fakes and builders
# ---------------------------------------------------------------------------
class FakeApiKeyAuthenticator:
    """An ``ApiKeyAuthenticator`` over a fixed list of key records."""

    def __init__(self, records: Sequence[ApiKey] = ()) -> None:
        self.records = list(records)

    async def authenticate(self, raw_key: str, *, pepper: SecretStr) -> ApiKey | None:
        prefix = prefix_of(raw_key)
        record = next((row for row in self.records if row.prefix == prefix), None)
        if record is None or not verify_api_key(raw_key, record.key_hash, pepper):
            return None
        return record

    async def touch_last_used(self, tenant_id: UUID, api_key_id: UUID, *, when: datetime) -> None:
        """Accepted and discarded; last-used tracking is not under test here."""


@dataclass(frozen=True, slots=True)
class Keys:
    """One raw API key per scope combination the tests need."""

    full_a: str
    chat_only_a: str
    detect_only_a: str
    delete_b: str
    records: tuple[ApiKey, ...]


@dataclass(frozen=True, slots=True)
class Api:
    """A client bound to the running application, plus the keys to drive it.

    One request helper per route, so a test reads as the call it is making and
    the assertion it cares about, and an omitted ``key`` means "send no
    credential at all" rather than "send an empty one".
    """

    client: httpx.AsyncClient
    keys: Keys

    async def chat(self, key: str | None = None, **overrides: object) -> httpx.Response:
        body: dict[str, object] = {
            "provider": PROVIDER,
            "model": MODEL,
            "messages": [{"role": "user", "content": PROMPT}],
        }
        body.update(overrides)
        return await self.client.post("/v1/chat", json=body, headers=_auth(key))

    async def detect(self, key: str | None = None, **overrides: object) -> httpx.Response:
        body: dict[str, object] = {"text": SENSITIVE_TEXT}
        body.update(overrides)
        return await self.client.post("/v1/detect", json=body, headers=_auth(key))

    async def delete(self, key: str | None, session: object) -> httpx.Response:
        return await self.client.delete(f"/v1/sessions/{session}", headers=_auth(key))


def _auth(raw_key: str | None) -> dict[str, str]:
    return {} if raw_key is None else {"Authorization": f"Bearer {raw_key}"}


def make_settings(**overrides: object) -> Settings:
    """Settings for the router suite, pinned against the ambient environment.

    ``openai_api_key`` is forced to ``None`` unless a test asks otherwise.
    ``Settings`` reads the process environment, so a developer with a real
    ``OPENAI_API_KEY`` exported would otherwise register the external adapter
    and change what ``GET /v1/providers`` returns -- a suite that passes or
    fails depending on whose machine it runs on. It also keeps a real
    credential out of a test process entirely.
    """
    defaults: dict[str, object] = {
        "app_env": "test",
        "api_key_pepper": PEPPER,
        "vault_active_key_id": "local1",
        "vault_keys": {"local1": SecretStr(VAULT_KEY)},
        "openai_api_key": None,
    }
    return Settings(**{**defaults, **overrides})  # type: ignore[arg-type]


def make_key(*, tenant_id: UUID, scopes: Sequence[Scope]) -> tuple[ApiKey, str]:
    generated = generate_api_key(PEPPER)
    record = ApiKey(
        id=uuid4(),
        tenant_id=tenant_id,
        name="router-test-key",
        prefix=generated.prefix,
        key_hash=generated.key_hash,
        scopes=[scope.value for scope in scopes],
        status=API_KEY_STATUS_ACTIVE,
    )
    return record, generated.raw_key


def views_of(response: httpx.Response) -> list[dict[str, object]]:
    entities: list[dict[str, object]] = response.json()["entities"]
    return entities


def view_named(response: httpx.Response, entity_type: str) -> dict[str, object]:
    return next(view for view in views_of(response) if view["entity_type"] == entity_type)


def span_of(view: dict[str, object]) -> str:
    return SENSITIVE_TEXT[int(str(view["start"])) : int(str(view["end"]))]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def settings() -> Settings:
    return make_settings()


AUDIT_FLUSH_SECONDS = 5.0
"""Bound on draining the audit queue before reading the table.

Long enough that a loaded CI box does not report an empty table as a clean
result, short enough that a genuinely stuck writer fails the test.
"""

STARTUP_TIMEOUT_SECONDS = 60.0
"""Generous on purpose.

``asgi_lifespan`` defaults to five seconds, and startup warms the spaCy
pipeline. Under ``pytest --cov`` that instrumented load overruns the default
and every test in the file errors at setup -- a red suite that says nothing
about the code. Still bounded, so a genuinely hung startup fails rather than
blocking the run forever.
"""


@pytest.fixture
def keys() -> Keys:
    full, full_raw = make_key(tenant_id=TENANT_A, scopes=tuple(Scope))
    chat, chat_raw = make_key(tenant_id=TENANT_A, scopes=(Scope.CHAT_INVOKE,))
    detect, detect_raw = make_key(tenant_id=TENANT_A, scopes=(Scope.DETECT_INVOKE,))
    delete, delete_raw = make_key(tenant_id=TENANT_B, scopes=(Scope.SESSIONS_DELETE,))
    return Keys(
        full_a=full_raw,
        chat_only_a=chat_raw,
        detect_only_a=detect_raw,
        delete_b=delete_raw,
        records=(full, chat, detect, delete),
    )


@pytest.fixture
def policy() -> PolicyDocument:
    """The document seeded as the tenant's active policy.

    A fixture rather than a constant so a class can seed a different allowlist
    -- which is the only way to test "registered but not permitted" separately
    from "permitted but not registered".
    """
    return TEST_POLICY


@pytest.fixture
async def engine(policy: PolicyDocument) -> AsyncIterator[AsyncEngine]:
    built = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with built.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with build_session_factory(built)() as session:
        session.add(Tenant(id=TENANT_A, name="Tenant A", slug="tenant-a"))
        session.add(Tenant(id=TENANT_B, name="Tenant B", slug="tenant-b"))
        session.add(
            Policy(
                tenant_id=TENANT_A,
                name=policy.name,
                version=1,
                document=policy.model_dump(mode="json"),
                is_active=True,
            )
        )
        await session.commit()

    yield built
    await built.dispose()


@pytest.fixture
async def services(
    settings: Settings, engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Services]:
    # Swapped at the composition root so the pipeline and /v1/detect share one
    # detector, exactly as they do in production.
    monkeypatch.setattr(composition, "PresidioDetector", FakeDetector)
    built = await build_services(
        settings,
        redis=fakeredis.aioredis.FakeRedis(decode_responses=False),
        engine=engine,
    )
    yield built
    await stop_services(built)


@pytest.fixture
async def api(settings: Settings, services: Services, keys: Keys) -> AsyncIterator[Api]:
    app = create_app(settings)
    app.state.services = services
    app.state.api_key_authenticator = FakeApiKeyAuthenticator(keys.records)
    async with LifespanManager(app, startup_timeout=STARTUP_TIMEOUT_SECONDS):
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as client:
            yield Api(client=client, keys=keys)


# ---------------------------------------------------------------------------
# POST /v1/chat
# ---------------------------------------------------------------------------
class TestChat:
    async def test_rejects_a_request_with_no_credential(self, api: Api) -> None:
        response = await api.chat()

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"

    async def test_rejects_a_key_without_the_chat_scope(self, api: Api) -> None:
        response = await api.chat(api.keys.detect_only_a)

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "AUTHORIZATION_FAILED"

    async def test_returns_the_restored_reply_and_a_privacy_summary(self, api: Api) -> None:
        response = await api.chat(api.keys.chat_only_a)

        assert response.status_code == 200
        body = response.json()
        # The provider only ever saw tokens; the caller gets the values back.
        assert EMAIL in body["message"]["content"]
        assert body["privacy"]["tokenized"] >= 2
        assert body["privacy"]["restored"] >= 2
        assert set(body["privacy"]["entity_types"]) <= {"EMAIL_ADDRESS", "PERSON", "PHONE_NUMBER"}

    async def test_no_protected_preview_unless_the_deployment_enables_it(self, api: Api) -> None:
        # architecture.md 22.6 forbids the provider request body in the
        # inspector. The preview is a narrowed exception a deployment opts into,
        # so the default must be its absence.
        response = await api.chat(api.keys.chat_only_a)

        assert response.json()["protected_preview"] is None

    async def test_the_privacy_summary_carries_counts_and_no_values(self, api: Api) -> None:
        response = await api.chat(api.keys.full_a)

        privacy = str(response.json()["privacy"])
        assert not any(value in privacy for value in (EMAIL, PERSON, PHONE))

    async def test_sends_request_id_and_forbids_caching(self, api: Api) -> None:
        response = await api.chat(api.keys.full_a)

        assert response.headers["Cache-Control"] == "no-store"
        assert UUID(response.headers["X-Request-ID"])
        assert response.headers["X-Content-Type-Options"] == "nosniff"

    async def test_a_provider_outside_the_policy_is_refused(self, api: Api) -> None:
        # The domain error reaches the registered handler unwrapped, so the
        # caller gets the precise code rather than a flattened 500.
        response = await api.chat(api.keys.full_a, provider="openai-primary")

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "PROVIDER_NOT_ALLOWED"

    async def test_a_malformed_body_is_refused_without_echoing_it(self, api: Api) -> None:
        response = await api.chat(api.keys.full_a, messages=[])

        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_REQUEST"


class TestProtectedPreview:
    """The preview when a deployment has opted in.

    Overriding the ``settings`` fixture rather than mutating ``services.settings``
    matters here: the pipeline captures settings when it is built, so a later
    assignment reaches the routes and not the pipeline, and a test written that
    way would exercise the default while appearing to exercise the flag.
    """

    @pytest.fixture
    def settings(self) -> Settings:
        return make_settings(protected_preview_enabled=True)

    @pytest.fixture
    def provider_calls(self, monkeypatch: pytest.MonkeyPatch) -> list[ProtectedChatRequest]:
        """Every request the provider actually received, in order.

        Patched on the class rather than on an instance because the registry
        builds its own; wrapping the real method rather than replacing it keeps
        the reply -- and therefore restoration -- working.
        """
        seen: list[ProtectedChatRequest] = []
        original = MockProvider.complete

        async def recording(self: MockProvider, request: ProtectedChatRequest) -> ProviderResponse:
            seen.append(request)
            return await original(self, request)

        monkeypatch.setattr(MockProvider, "complete", recording)
        return seen

    async def test_it_shows_what_the_provider_saw_with_values_replaced(self, api: Api) -> None:
        response = await api.chat(api.keys.chat_only_a)

        preview = response.json()["protected_preview"]
        assert preview is not None
        assert "⟦EMAIL_ADDRESS:" in preview["text"]
        # The prose around the values survives; only the values are gone.
        assert "Email" in preview["text"]

    async def test_the_preview_contains_no_original_value(self, api: Api) -> None:
        response = await api.chat(api.keys.chat_only_a)

        preview = str(response.json()["protected_preview"])
        assert not any(value in preview for value in (EMAIL, PERSON, PHONE, SSN, IP))

    async def test_the_preview_contains_no_resolvable_token(self, api: Api) -> None:
        # The single property that makes this safe to send to a browser. A full
        # token names a vault key; a masked one names nothing.
        response = await api.chat(api.keys.chat_only_a)

        text = response.json()["protected_preview"]["text"]
        assert "SGW:" not in text
        assert TOKEN_PATTERN.search(text) is None

    async def test_the_entity_summary_reports_what_was_applied(self, api: Api) -> None:
        response = await api.chat(api.keys.chat_only_a)

        summary = response.json()["protected_preview"]["entity_summary"]
        by_type = {item["entity_type"]: item for item in summary}
        assert by_type["EMAIL_ADDRESS"]["action"] == "tokenize"
        assert by_type["EMAIL_ADDRESS"]["count"] >= 1

    async def test_it_reports_the_outbound_scan(self, api: Api) -> None:
        response = await api.chat(api.keys.chat_only_a)

        assert response.json()["protected_preview"]["outbound_scan"] == "passed"

    async def test_the_restored_answer_is_unaffected(self, api: Api) -> None:
        # Non-regression: the preview is additive and must not change what the
        # caller actually receives.
        response = await api.chat(api.keys.chat_only_a)

        body = response.json()
        assert EMAIL in body["message"]["content"]
        assert body["privacy"]["restored"] >= 2

    async def test_the_preview_is_the_masked_form_of_what_the_provider_received(
        self, api: Api, provider_calls: list[ProtectedChatRequest]
    ) -> None:
        """The derivation, proved rather than asserted in a docstring.

        The expectation is rebuilt here with a local substitution rather than by
        calling ``preview_of``. That distinction is the whole test: comparing the
        endpoint against the same helper it calls is a tautology that both sides
        satisfy together, and it passes unchanged even when the implementation is
        mutated to reconstruct the text from entity counts.

        Rebuilding it independently means a reconstruction fails here, because no
        amount of count data can reproduce the caller's prose between the masks.
        """
        response = await api.chat(api.keys.chat_only_a)

        assert len(provider_calls) == 1
        sent = "\n\n".join(message.content for message in provider_calls[0].messages).strip()
        expected = re.sub(r"⟦SGW:([A-Z0-9_]{1,64}):[0-9A-HJKMNP-TV-Z]{26}⟧", rf"⟦\1:{MASK}⟧", sent)

        assert response.json()["protected_preview"]["text"] == expected
        # Guards the guard: a prompt that produced no token would make the
        # substitution a no-op and the comparison meaningless.
        assert MASK in expected

    async def test_the_provider_still_receives_full_resolvable_tokens(
        self, api: Api, provider_calls: list[ProtectedChatRequest]
    ) -> None:
        """The masking is for the browser only; upstream is untouched.

        Restoration resolves the tokens the provider echoes back, so a mask that
        leaked into the outbound payload would break the round trip rather than
        merely look wrong -- and the response assertion below would not catch it,
        since the mock echoes whatever it is given.
        """
        response = await api.chat(api.keys.chat_only_a)

        outbound = "\n".join(message.content for message in provider_calls[0].messages)
        assert "SGW:" in outbound
        assert TOKEN_PATTERN.search(outbound) is not None
        # Full tokens upstream, no originals: the gateway's whole promise.
        assert not any(value in outbound for value in (EMAIL, PERSON, PHONE))
        assert EMAIL in response.json()["message"]["content"]

    async def test_the_preview_is_never_logged(
        self, api: Api, provider_calls: list[ProtectedChatRequest]
    ) -> None:
        """Ephemeral means it exists in the response and nowhere else.

        The logging allowlist is deny-by-default, so no preview key can reach a
        log line today. This asserts the property rather than the mechanism: a
        later change that adds ``protected_preview`` to the allowlist would be
        caught here instead of shipping.
        """
        with structlog.testing.capture_logs() as captured:
            response = await api.chat(api.keys.chat_only_a)

        text = response.json()["protected_preview"]["text"]
        assert text  # a vacuous pass if the preview were empty
        logged = str(captured)
        assert text not in logged
        assert MASK not in logged

    async def test_the_preview_is_never_persisted_or_audited(
        self, api: Api, services: Services, engine: AsyncEngine
    ) -> None:
        """The audit row is built from ``RequestOutcome``, which has no preview.

        Flushed rather than sampled: the audit service writes from a background
        queue, so reading the table without draining it first would find nothing
        and pass for the wrong reason.
        """
        response = await api.chat(api.keys.chat_only_a)
        text = response.json()["protected_preview"]["text"]
        assert text

        await services.audit.flush(wait_seconds=AUDIT_FLUSH_SECONDS)
        async with build_session_factory(engine)() as session:
            rows = (await session.execute(select(AuditEvent))).scalars().all()

        assert rows, "no audit row written, so this would pass vacuously"
        stored = str([row.__dict__ for row in rows])
        assert text not in stored
        assert MASK not in stored


class TestProviders:
    """``GET /v1/providers`` -- the selector's source of truth."""

    async def test_rejects_a_request_with_no_credential(self, api: Api) -> None:
        response = await api.client.get("/v1/providers")

        assert response.status_code == 401

    async def test_rejects_a_key_without_chat_scope(self, api: Api) -> None:
        response = await api.client.get("/v1/providers", headers=_auth(api.keys.detect_only_a))

        assert response.status_code == 403

    async def test_lists_the_mock_and_preselects_it(self, api: Api) -> None:
        # Default matters: a demo that opens pointed at a paid service is a demo
        # that costs money to open.
        response = await api.client.get("/v1/providers", headers=_auth(api.keys.chat_only_a))

        body = response.json()
        assert body["default"] == PROVIDER
        assert [row["alias"] for row in body["providers"]] == [PROVIDER]
        assert body["providers"][0]["kind"] == "mock"
        assert body["providers"][0]["available"] is True

    async def test_omits_a_provider_this_deployment_cannot_call(self, api: Api) -> None:
        """No credential, no adapter, no entry -- rather than a broken option.

        The test settings configure no OpenAI key, so the registry never builds
        that adapter and the selector never offers it.
        """
        response = await api.client.get("/v1/providers", headers=_auth(api.keys.chat_only_a))

        assert "openai" not in [row["alias"] for row in response.json()["providers"]]

    async def test_reports_only_the_model_aliases_the_policy_permits(self, api: Api) -> None:
        response = await api.client.get("/v1/providers", headers=_auth(api.keys.chat_only_a))

        assert response.json()["providers"][0]["models"] == [MODEL]

    async def test_discloses_no_configuration_detail(self, api: Api) -> None:
        # Availability is a boolean. Why it is false is a fact about a credential
        # and stays on the server.
        response = await api.client.get("/v1/providers", headers=_auth(api.keys.chat_only_a))

        body = response.text.lower()
        for leak in ("api_key", "sk-", "secret", "endpoint", "base_url", "openai_api_key"):
            assert leak not in body


OPENAI_ALIAS = "openai"
FAKE_OPENAI_KEY = SecretStr("sk-test-not-a-real-key-0000000000000000")
"""Structurally plausible, functionally worthless, and never sent anywhere: the
registry builds an adapter from it but no test in this file makes a call."""


class TestProviderAvailabilityGates:
    """Availability is a conjunction, and each gate is tested on its own.

    The bug this guards against is the two gates being conflated -- a build that
    reported availability from the registry alone would offer a provider the
    policy refuses, and the selector's only outcome would be a 403.
    """

    @pytest.fixture
    def settings(self) -> Settings:
        return make_settings(openai_api_key=FAKE_OPENAI_KEY)

    async def test_a_registered_provider_the_policy_forbids_is_unavailable(self, api: Api) -> None:
        # The credential is configured, so the adapter exists. The default test
        # policy allows only the mock, so it must not be offered.
        response = await api.client.get("/v1/providers", headers=_auth(api.keys.chat_only_a))

        rows = {row["alias"]: row for row in response.json()["providers"]}
        assert rows[OPENAI_ALIAS]["available"] is False
        assert rows[OPENAI_ALIAS]["models"] == []
        assert rows[PROVIDER]["available"] is True

    async def test_choosing_it_anyway_is_refused_by_policy(self, api: Api) -> None:
        response = await api.chat(api.keys.chat_only_a, provider=OPENAI_ALIAS, model="fast")

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "PROVIDER_NOT_ALLOWED"

    async def test_no_part_of_the_credential_appears_in_the_response(self, api: Api) -> None:
        response = await api.client.get("/v1/providers", headers=_auth(api.keys.chat_only_a))

        assert FAKE_OPENAI_KEY.get_secret_value() not in response.text
        assert "sk-" not in response.text


class TestProviderAvailableWhenPolicyAllowsAndKeyPresent:
    """Both gates open: the provider is offered."""

    @pytest.fixture
    def settings(self) -> Settings:
        return make_settings(openai_api_key=FAKE_OPENAI_KEY)

    @pytest.fixture
    def policy(self) -> PolicyDocument:
        return TEST_POLICY.model_copy(
            update={
                "providers": {
                    **TEST_POLICY.providers,
                    OPENAI_ALIAS: ProviderRule(models=("fast",)),
                }
            }
        )

    async def test_it_is_offered_with_the_models_the_policy_permits(self, api: Api) -> None:
        response = await api.client.get("/v1/providers", headers=_auth(api.keys.chat_only_a))

        rows = {row["alias"]: row for row in response.json()["providers"]}
        assert rows[OPENAI_ALIAS]["available"] is True
        assert rows[OPENAI_ALIAS]["kind"] == "external"
        assert rows[OPENAI_ALIAS]["models"] == ["fast"]

    async def test_the_mock_is_still_the_default(self, api: Api) -> None:
        # Adding a real provider must not change what a demo opens pointed at.
        response = await api.client.get("/v1/providers", headers=_auth(api.keys.chat_only_a))

        assert response.json()["default"] == PROVIDER


class TestProviderIdentity:
    async def test_the_response_names_the_provider_that_answered(self, api: Api) -> None:
        """Sourced from the adapter the gateway invoked.

        At this level the executed alias and the requested alias agree, so this
        cannot by itself distinguish "reported" from "echoed" -- that separation
        is proved in ``tests/security/test_provider_selection.py``, which asserts
        ``Transmission.provider_alias`` comes from ``adapter.alias``. What this
        pins is the contract the UI reads.
        """
        response = await api.chat(api.keys.chat_only_a)

        assert response.json()["provider"] == PROVIDER

    async def test_a_provider_the_policy_rejects_never_answers(self, api: Api) -> None:
        # Case included: the policy allowlist is exact, and refuses before the
        # registry's own normalization is ever reached.
        response = await api.chat(api.keys.chat_only_a, provider="MoCk")

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "PROVIDER_NOT_ALLOWED"


# ---------------------------------------------------------------------------
# POST /v1/detect
# ---------------------------------------------------------------------------
class TestDetect:
    async def test_rejects_a_request_with_no_credential(self, api: Api) -> None:
        response = await api.detect()

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"

    async def test_rejects_a_key_without_the_detect_scope(self, api: Api) -> None:
        response = await api.detect(api.keys.chat_only_a)

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "AUTHORIZATION_FAILED"

    async def test_reports_offsets_types_scores_and_actions(self, api: Api) -> None:
        response = await api.detect(api.keys.detect_only_a)

        assert response.status_code == 200
        actions = {view["entity_type"]: view["action"] for view in views_of(response)}
        assert actions["EMAIL_ADDRESS"] == "tokenize"
        assert actions["US_SSN"] == "block"
        # Offsets index the submitted text, so a caller can locate a span itself.
        email = view_named(response, "EMAIL_ADDRESS")
        assert span_of(email) == EMAIL
        assert 0.0 <= float(str(email["score"])) <= 1.0

    async def test_returns_no_substring_of_the_submitted_text(self, api: Api) -> None:
        # The property this endpoint exists to keep: spans and types leave the
        # gateway, matched values do not.
        response = await api.detect(api.keys.detect_only_a)

        views = views_of(response)
        assert views
        assert all(view["text"] is None for view in views)
        assert not any(span_of(view) in response.text for view in views)
        assert not any(value in response.text for value in (EMAIL, PERSON, PHONE, SSN, IP))

    async def test_matched_text_appears_only_when_diagnostics_are_allowed(
        self, api: Api, services: Services
    ) -> None:
        # diagnostics_allowed is a derived property that is false in production
        # whatever the flag says, so the endpoint keys off it, not off the flag.
        services.settings = make_settings(diagnostics_return_matched_text=True)
        assert services.settings.diagnostics_allowed is True

        response = await api.detect(api.keys.detect_only_a)

        assert EMAIL in {view["text"] for view in views_of(response)}

    async def test_a_span_below_its_threshold_is_reported_as_allow(self, api: Api) -> None:
        # The policy redacts IP_ADDRESS above 0.9 and the detector scores this
        # one at 0.6, so the pipeline would leave it alone. Reporting "redact"
        # would advertise protection that will not happen.
        response = await api.detect(api.keys.detect_only_a)

        assert view_named(response, "IP_ADDRESS")["action"] == "allow"

    async def test_narrows_to_the_requested_entity_types(self, api: Api) -> None:
        response = await api.detect(api.keys.detect_only_a, entity_types=["EMAIL_ADDRESS"])

        assert {view["entity_type"] for view in views_of(response)} == {"EMAIL_ADDRESS"}

    async def test_summarizes_counts_by_type(self, api: Api) -> None:
        response = await api.detect(api.keys.detect_only_a)

        body = response.json()
        assert body["summary"]["detected"] == len(body["entities"])
        assert body["summary"]["entity_types"]["EMAIL_ADDRESS"] == 1

    async def test_an_unsupported_language_is_refused(self, api: Api) -> None:
        response = await api.detect(api.keys.detect_only_a, language="zz")

        assert response.status_code == 400

    async def test_sends_request_id_and_forbids_caching(self, api: Api) -> None:
        response = await api.detect(api.keys.detect_only_a)

        assert response.headers["Cache-Control"] == "no-store"
        # The body's request id is the one the header advertises.
        assert response.json()["request_id"] == response.headers["X-Request-ID"]


# ---------------------------------------------------------------------------
# DELETE /v1/sessions/{session_id}
# ---------------------------------------------------------------------------
class TestDeleteSession:
    async def test_rejects_a_request_with_no_credential(self, api: Api) -> None:
        response = await api.delete(None, uuid4())

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"

    async def test_rejects_a_key_without_the_delete_scope(self, api: Api) -> None:
        response = await api.delete(api.keys.detect_only_a, uuid4())

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "AUTHORIZATION_FAILED"

    async def test_deleting_an_absent_session_still_succeeds(self, api: Api) -> None:
        # 404 here would be an oracle for which session ids exist, and would
        # punish a client retrying after a timeout.
        response = await api.delete(api.keys.full_a, uuid4())

        assert response.status_code == 204
        assert not response.content

    async def test_repeating_the_delete_is_idempotent(self, api: Api, services: Services) -> None:
        session_id = uuid4()
        await api.chat(api.keys.full_a, session_id=str(session_id))

        first = await api.delete(api.keys.full_a, session_id)
        second = await api.delete(api.keys.full_a, session_id)

        assert (first.status_code, second.status_code) == (204, 204)
        assert await services.vault.delete_session(tenant_id=TENANT_A, session_id=session_id) == 0

    async def test_one_tenant_cannot_delete_another_tenants_session(
        self, api: Api, services: Services
    ) -> None:
        session_id = uuid4()
        await api.chat(api.keys.full_a, session_id=str(session_id))

        response = await api.delete(api.keys.delete_b, session_id)

        assert response.status_code == 204
        # Tenant B's delete found nothing, and tenant A's mappings survived it.
        surviving = await services.vault.delete_session(tenant_id=TENANT_A, session_id=session_id)
        assert surviving > 0

    async def test_a_path_that_is_not_a_uuid_is_refused(self, api: Api) -> None:
        response = await api.delete(api.keys.full_a, "not-a-uuid")

        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_REQUEST"

    async def test_sends_request_id_and_forbids_caching(self, api: Api) -> None:
        response = await api.delete(api.keys.full_a, uuid4())

        assert response.headers["Cache-Control"] == "no-store"
        assert UUID(response.headers["X-Request-ID"])


# ---------------------------------------------------------------------------
# GET /metrics
# ---------------------------------------------------------------------------
@pytest.mark.security
class TestMetricsExposure:
    """What a scrape reveals after real traffic has moved through the gateway.

    The unit tests in ``test_observability.py`` prove each recorder folds its
    labels. This proves the composition: a request carrying an email, a name, a
    phone number, an SSN, and an IP goes through the whole stack, and then the
    entire exposition payload is searched for any of it. The endpoint is the one
    place every instrument's output is concatenated, so it is the right place to
    check that none of them leaked.
    """

    async def test_a_real_request_leaves_no_sensitive_value_in_the_payload(self, api: Api) -> None:
        chat = await api.chat(api.keys.full_a)
        assert chat.status_code == 200
        session_id = chat.json()["session_id"]

        payload = (await api.client.get("/metrics")).text

        # The values themselves.
        for value in (EMAIL, PERSON, PHONE, SSN, IP):
            assert value not in payload, value
        # The identifiers that would let a reader correlate series to a caller.
        for identifier in (str(TENANT_A), str(TENANT_B), session_id):
            assert identifier not in payload, identifier
        # And any token minted for the values above.
        assert LEFT_DELIMITER not in payload

    async def test_a_real_request_is_actually_reflected_in_the_payload(self, api: Api) -> None:
        """The counterpart to the test above: absence proves nothing if the
        instruments never fired."""
        await api.chat(api.keys.full_a)

        payload = (await api.client.get("/metrics")).text

        assert 'sgw_http_requests_total{method="POST",route="/v1/chat",status="200"}' in payload
        assert 'sgw_entities_detected_total{action="tokenize",entity_type="EMAIL_ADDRESS"}' in (
            payload
        )
        assert 'sgw_provider_requests_total{provider="mock",result="success"}' in payload
        assert 'sgw_pipeline_stage_total{outcome="success",stage="detection"}' in payload

    async def test_a_blocked_request_is_counted_as_a_policy_block(self, api: Api) -> None:
        """``US_SSN`` is a BLOCK rule in the test policy, so this request dies
        before the vault. The refusal must still be visible."""
        response = await api.chat(
            api.keys.full_a, messages=[{"role": "user", "content": f"SSN {SSN}"}]
        )
        assert response.json()["error"]["code"] == "POLICY_VIOLATION"

        payload = (await api.client.get("/metrics")).text

        assert 'sgw_policy_blocks_total{reason="blocked_entity"}' in payload
        assert SSN not in payload

    async def test_the_route_label_is_the_template_not_the_session_id(self, api: Api) -> None:
        """A session id in a label would be a new time series per delete, for
        the life of the process, keyed by an identifier from the request path."""
        session_id = uuid4()
        assert (await api.delete(api.keys.delete_b, session_id)).status_code == 204

        payload = (await api.client.get("/metrics")).text

        assert 'route="/v1/sessions/{session_id}"' in payload
        assert str(session_id) not in payload


# ---------------------------------------------------------------------------
# OpenAPI
# ---------------------------------------------------------------------------
class TestOpenApi:
    def test_every_v1_route_is_published(self, settings: Settings) -> None:
        schema = create_app(settings).openapi()

        assert {"/v1/chat", "/v1/detect", "/v1/sessions/{session_id}"} <= set(schema["paths"])

    def test_error_statuses_are_documented_on_every_route(self, settings: Settings) -> None:
        paths = create_app(settings).openapi()["paths"]

        for path, method in (
            ("/v1/chat", "post"),
            ("/v1/detect", "post"),
            ("/v1/sessions/{session_id}", "delete"),
        ):
            documented = paths[path][method]["responses"]
            assert {"401", "403", "429"} <= set(documented), path
            assert "AUTHORIZATION_FAILED" in documented["403"]["description"], path

    def test_request_examples_use_synthetic_values_only(self, settings: Settings) -> None:
        schema = create_app(settings).openapi()
        published = str(schema["paths"]["/v1/chat"]) + str(schema["paths"]["/v1/detect"])

        assert "example.test" in published
        assert "example.com" not in published
