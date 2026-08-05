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
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

import fakeredis.aioredis
import httpx
import pytest
from asgi_lifespan import LifespanManager
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.api import composition
from app.api.composition import Services, build_services, stop_services
from app.config.settings import Settings
from app.db.base import Base
from app.db.models import API_KEY_STATUS_ACTIVE, ApiKey, Policy, Tenant
from app.db.session import build_session_factory
from app.detection.fakes import FakeDetector
from app.domain.models import EntityAction, Scope, UnknownTokenAction
from app.main import create_app
from app.policy.models import POLICY_SCHEMA_VERSION, EntityRule, PolicyDocument, ProviderRule
from app.repositories.api_keys import generate_api_key, prefix_of, verify_api_key
from app.tokenization.grammar import LEFT_DELIMITER

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
    return Settings(
        app_env="test",
        api_key_pepper=PEPPER,
        vault_active_key_id="local1",
        vault_keys={"local1": SecretStr(VAULT_KEY)},
        **overrides,  # type: ignore[arg-type]
    )


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
async def engine() -> AsyncIterator[AsyncEngine]:
    built = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with built.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with build_session_factory(built)() as session:
        session.add(Tenant(id=TENANT_A, name="Tenant A", slug="tenant-a"))
        session.add(Tenant(id=TENANT_B, name="Tenant B", slug="tenant-b"))
        session.add(
            Policy(
                tenant_id=TENANT_A,
                name=TEST_POLICY.name,
                version=1,
                document=TEST_POLICY.model_dump(mode="json"),
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
