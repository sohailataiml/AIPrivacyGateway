"""Router tests for the policy management endpoints.

Drives the real application through ASGI: real middleware, real auth
dependencies, real detector. Redis, the database, and the API-key lookup are
fakes, because those are the pieces that would otherwise need a network.

The assertions worth reading are the negative ones. The playground accepts
caller-supplied text, so the tests that matter prove what it does *not* do:
no vault write, no provider call, no matched substring in the response, and no
submitted text in a log record. Those are properties of code that is never
called, and a test is how they stay that way.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

import fakeredis.aioredis
import httpx
import pytest
from asgi_lifespan import LifespanManager
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import create_async_engine

from app.api.composition import Services, build_services, stop_services
from app.config.settings import Settings
from app.db.base import Base
from app.db.models import ApiKey, Tenant
from app.db.session import build_session_factory
from app.domain.models import Scope
from app.main import create_app
from app.policy.defaults import DEFAULT_POLICY
from app.repositories.api_keys import generate_api_key
from app.repositories.policies import SqlAlchemyPolicyRepository
from app.vault import DEFAULT_KEY_PREFIX
from tests.unit.test_api_v1 import PEPPER, VAULT_KEY, FakeApiKeyAuthenticator

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from sqlalchemy.ext.asyncio import AsyncEngine

TENANT_A = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
TENANT_B = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
POLICY = "default"
STARTUP_TIMEOUT_SECONDS = 60.0

# Synthetic throughout. A real-looking value in a test fixture is a real value
# in a log if a test ever fails the wrong way.
CANARY_EMAIL = "avery.example@example.test"
TEST_TEXT = f"Contact {CANARY_EMAIL} about invoice 4471."


def _auth(raw_key: str | None) -> dict[str, str]:
    return {} if raw_key is None else {"Authorization": f"Bearer {raw_key}"}


def make_key(*, tenant_id: UUID, scopes: Sequence[Scope]) -> tuple[ApiKey, str]:
    generated = generate_api_key(PEPPER)
    record = ApiKey(
        id=uuid4(),
        tenant_id=tenant_id,
        name="policy-test-key",
        prefix=generated.prefix,
        key_hash=generated.key_hash,
        scopes=[scope.value for scope in scopes],
        status="active",
    )
    return record, generated.raw_key


class Keys:
    def __init__(self) -> None:
        self.admin_record, self.admin = make_key(tenant_id=TENANT_A, scopes=tuple(Scope))
        self.viewer_record, self.viewer = make_key(
            tenant_id=TENANT_A, scopes=(Scope.POLICIES_READ, Scope.POLICIES_TEST)
        )
        self.chat_only_record, self.chat_only = make_key(
            tenant_id=TENANT_A, scopes=(Scope.CHAT_INVOKE,)
        )
        self.other_tenant_record, self.other_tenant = make_key(
            tenant_id=TENANT_B, scopes=tuple(Scope)
        )

    @property
    def records(self) -> tuple[ApiKey, ...]:
        return (
            self.admin_record,
            self.viewer_record,
            self.chat_only_record,
            self.other_tenant_record,
        )


def document(**overrides: Any) -> dict[str, Any]:
    base = DEFAULT_POLICY.model_dump(mode="json")
    base.update(overrides)
    return base


@pytest.fixture
def settings() -> Settings:
    return Settings(
        app_env="test",
        api_key_pepper=PEPPER,
        vault_active_key_id="local1",
        vault_keys={"local1": SecretStr(VAULT_KEY)},
        documents_enabled=False,
    )


@pytest.fixture
def keys() -> Keys:
    return Keys()


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    built = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with built.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with build_session_factory(built)() as session:
        session.add(Tenant(id=TENANT_A, name="Tenant A", slug="tenant-a"))
        session.add(Tenant(id=TENANT_B, name="Tenant B", slug="tenant-b"))
        await session.flush()
        repository = SqlAlchemyPolicyRepository(session)
        for tenant in (TENANT_A, TENANT_B):
            await repository.create_version(
                tenant, name=POLICY, version=1, document=document(), is_active=True
            )
        await session.commit()
    yield built
    await built.dispose()


@pytest.fixture
async def services(settings: Settings, engine: AsyncEngine) -> AsyncIterator[Services]:
    built = await build_services(
        settings,
        redis=fakeredis.aioredis.FakeRedis(decode_responses=False),
        engine=engine,
    )
    yield built
    await stop_services(built)


@pytest.fixture
async def client(
    settings: Settings, services: Services, keys: Keys
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings)
    app.state.services = services
    app.state.api_key_authenticator = FakeApiKeyAuthenticator(keys.records)
    async with LifespanManager(app, startup_timeout=STARTUP_TIMEOUT_SECONDS):
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as http:
            yield http


class TestReads:
    async def test_listing_reports_the_active_version_and_counts(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        response = await client.get("/v1/policies", headers=_auth(keys.viewer))

        assert response.status_code == 200
        [summary] = response.json()
        assert summary["policy_name"] == POLICY
        assert summary["active_version"] == 1
        assert summary["draft_version"] is None
        assert summary["entity_count"] == len(DEFAULT_POLICY.entities)
        assert summary["enabled_entity_count"] == len(DEFAULT_POLICY.entities)

    async def test_getting_a_policy_returns_its_entity_rules(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        response = await client.get(f"/v1/policies/{POLICY}", headers=_auth(keys.viewer))

        assert response.status_code == 200
        rules = {rule["entity_type"]: rule for rule in response.json()["entity_rules"]}
        # The real threshold, from the stored document. Not 0.65.
        assert rules["PHONE_NUMBER"]["confidence_threshold"] == 0.4
        assert rules["US_SSN"]["action"] == "block"

    async def test_another_tenants_policy_is_not_reachable(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        # Both tenants have a policy called "default"; the name must not be a
        # way into someone else's.
        response = await client.get("/v1/policies", headers=_auth(keys.other_tenant))

        assert response.status_code == 200
        assert all(item["policy_name"] == POLICY for item in response.json())
        detail = await client.get(f"/v1/policies/{POLICY}", headers=_auth(keys.other_tenant))
        assert detail.json()["version"] == 1

    async def test_an_unknown_policy_is_refused(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        response = await client.get("/v1/policies/nonexistent", headers=_auth(keys.viewer))

        assert response.status_code == 409
        assert response.json()["error"]["code"] == "POLICY_NOT_FOUND"

    async def test_the_detector_catalog_is_available(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        response = await client.get("/v1/detectors/entities", headers=_auth(keys.viewer))

        assert response.status_code == 200
        catalog = response.json()
        by_type = {entry["entity_type"]: entry for entry in catalog}
        assert by_type["PHONE_NUMBER"]["default_threshold"] == 0.4
        assert set(by_type["US_SSN"]["supported_actions"]) == {
            "allow",
            "tokenize",
            "redact",
            "pseudonymize",
            "block",
        }

    async def test_the_catalog_exposes_no_patterns(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        response = await client.get("/v1/detectors/entities", headers=_auth(keys.viewer))

        body = response.text
        assert "\\d" not in body
        assert "(?" not in body


class TestAuthorization:
    async def test_reading_requires_a_credential(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/v1/policies", headers=_auth(None))

        assert response.status_code == 401

    async def test_a_key_without_policy_scopes_is_refused(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        response = await client.get("/v1/policies", headers=_auth(keys.chat_only))

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "AUTHORIZATION_FAILED"

    async def test_a_viewer_cannot_create_a_draft(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        # The authorization model in one assertion: an analyst reviews what is
        # enforced, an administrator changes it.
        response = await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.viewer))

        assert response.status_code == 403

    async def test_a_viewer_cannot_publish(self, client: httpx.AsyncClient, keys: Keys) -> None:
        response = await client.post(f"/v1/policies/{POLICY}/publish", headers=_auth(keys.viewer))

        assert response.status_code == 403

    async def test_a_viewer_may_validate_and_test(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        # Non-vacuity for the two refusals above: the viewer key works for the
        # operations it is meant to reach.
        await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))

        validated = await client.post(f"/v1/policies/{POLICY}/validate", headers=_auth(keys.viewer))
        assert validated.status_code == 200


class TestDraftLifecycle:
    async def test_a_draft_is_seeded_from_the_active_version(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        response = await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))

        assert response.status_code == 201
        body = response.json()
        assert body["version"] == 2
        assert body["status"] == "draft"
        assert body["is_active"] is False
        assert body["entity_count"] == len(DEFAULT_POLICY.entities)

    async def test_a_second_draft_is_refused(self, client: httpx.AsyncClient, keys: Keys) -> None:
        await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))

        second = await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))

        assert second.status_code == 400
        assert second.json()["error"]["code"] == "INVALID_REQUEST"

    async def test_editing_a_draft_stores_the_new_document(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))
        edited = document()
        edited["entities"]["PHONE_NUMBER"]["min_score"] = 0.55

        response = await client.patch(
            f"/v1/policies/{POLICY}/draft",
            headers=_auth(keys.admin),
            json={"document": edited},
        )

        assert response.status_code == 200
        rules = {r["entity_type"]: r for r in response.json()["entity_rules"]}
        assert rules["PHONE_NUMBER"]["confidence_threshold"] == 0.55

    async def test_an_invalid_edit_is_refused_before_it_is_stored(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))
        broken = document()
        broken["entities"]["PERSON"]["min_score"] = 4.2

        response = await client.patch(
            f"/v1/policies/{POLICY}/draft",
            headers=_auth(keys.admin),
            json={"document": broken},
        )

        assert response.status_code == 400

    async def test_editing_the_active_version_is_impossible(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        # There is no route that writes a published row. Editing without an open
        # draft is a 404, not a silent in-place mutation.
        response = await client.patch(
            f"/v1/policies/{POLICY}/draft",
            headers=_auth(keys.admin),
            json={"document": document(max_entities=1)},
        )

        assert response.status_code == 409
        active = await client.get(f"/v1/policies/{POLICY}", headers=_auth(keys.admin))
        assert active.json()["max_entities"] == 500

    async def test_discarding_leaves_history_intact(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))

        discarded = await client.delete(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))

        assert discarded.status_code == 204
        versions = await client.get(f"/v1/policies/{POLICY}/versions", headers=_auth(keys.admin))
        assert [v["version"] for v in versions.json()] == [1]


class TestPublishing:
    async def test_publishing_creates_a_new_active_version(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))
        edited = document(max_entities=250)
        await client.patch(
            f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin), json={"document": edited}
        )

        response = await client.post(f"/v1/policies/{POLICY}/publish", headers=_auth(keys.admin))

        assert response.status_code == 200
        body = response.json()
        assert body["version"] == 2
        assert body["status"] == "published"
        assert body["is_active"] is True
        assert body["published_at"] is not None

    async def test_the_previous_version_is_unchanged(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        before = await client.get(f"/v1/policies/{POLICY}/versions/1", headers=_auth(keys.admin))
        await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))
        await client.patch(
            f"/v1/policies/{POLICY}/draft",
            headers=_auth(keys.admin),
            json={"document": document(max_entities=7)},
        )
        await client.post(f"/v1/policies/{POLICY}/publish", headers=_auth(keys.admin))

        after = await client.get(f"/v1/policies/{POLICY}/versions/1", headers=_auth(keys.admin))

        # Only is_active may move. Everything an operator reads must be identical.
        original, current = before.json(), after.json()
        for field in ("version", "max_entities", "entity_rules", "created_at", "published_at"):
            assert current[field] == original[field]
        assert current["is_active"] is False

    async def test_publishing_an_invalid_draft_is_refused(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))
        # Bypass the edit endpoint's validation to store something publishable-
        # looking but wrong, proving publish re-checks rather than trusting it.
        broken = document()
        broken["entities"]["FAVOURITE_COLOUR"] = {"action": "tokenize", "min_score": 0.5}
        await client.patch(
            f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin), json={"document": broken}
        )

        response = await client.post(f"/v1/policies/{POLICY}/publish", headers=_auth(keys.admin))

        assert response.status_code == 400

    async def test_publishing_without_a_draft_is_refused(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        response = await client.post(f"/v1/policies/{POLICY}/publish", headers=_auth(keys.admin))

        assert response.status_code == 409

    async def test_history_accumulates(self, client: httpx.AsyncClient, keys: Keys) -> None:
        for entities in (100, 200):
            await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))
            await client.patch(
                f"/v1/policies/{POLICY}/draft",
                headers=_auth(keys.admin),
                json={"document": document(max_entities=entities)},
            )
            await client.post(f"/v1/policies/{POLICY}/publish", headers=_auth(keys.admin))

        versions = await client.get(f"/v1/policies/{POLICY}/versions", headers=_auth(keys.admin))
        body = versions.json()
        assert [v["version"] for v in body] == [1, 2, 3]
        assert [v["max_entities"] for v in body] == [500, 100, 200]
        assert sum(1 for v in body if v["is_active"]) == 1


class TestValidationAndDiff:
    async def test_validation_reports_a_high_risk_warning_without_blocking(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))
        risky = document()
        risky["entities"]["US_SSN"]["action"] = "allow"
        await client.patch(
            f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin), json={"document": risky}
        )

        response = await client.post(f"/v1/policies/{POLICY}/validate", headers=_auth(keys.admin))

        body = response.json()
        assert body["valid"] is True
        assert any(w["code"] == "high_risk_allowed" for w in body["warnings"])

    async def test_validation_requires_a_draft_rather_than_checking_the_live_version(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        # The playground falls back to the active version; validate must not.
        # Reporting "valid" about a published policy when the operator asked
        # about their draft answers a question nobody posed, reassuringly.
        response = await client.post(f"/v1/policies/{POLICY}/validate", headers=_auth(keys.admin))

        assert response.status_code == 409

    async def test_the_diff_reports_a_threshold_change_between_stored_versions(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))
        edited = document()
        edited["entities"]["PHONE_NUMBER"]["min_score"] = 0.6
        await client.patch(
            f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin), json={"document": edited}
        )
        await client.post(f"/v1/policies/{POLICY}/publish", headers=_auth(keys.admin))

        response = await client.get(
            f"/v1/policies/{POLICY}/diff",
            headers=_auth(keys.viewer),
            params={"from_version": 1, "to_version": 2},
        )

        assert response.status_code == 200
        body = response.json()
        change = next(c for c in body["entity_changes"] if c["path"] == "PHONE_NUMBER.min_score")
        assert (change["before"], change["after"]) == ("0.4", "0.6")
        assert body["total_changes"] >= 1


class TestPlayground:
    async def test_it_reports_spans_and_actions_for_the_active_version(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        response = await client.post(
            "/v1/policies/test",
            headers=_auth(keys.viewer),
            json={"text": TEST_TEXT, "policy_name": POLICY, "version": 1},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["version"] == 1
        assert body["detected"] >= 1
        assert any(span["entity_type"] == "EMAIL_ADDRESS" for span in body["spans"])

    async def test_it_returns_offsets_and_never_the_matched_text(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        # The whole point. This endpoint is run against realistic input while
        # designing a policy, which is exactly when a response gets pasted into
        # a ticket.
        response = await client.post(
            "/v1/policies/test",
            headers=_auth(keys.viewer),
            json={"text": TEST_TEXT, "policy_name": POLICY, "version": 1},
        )

        assert CANARY_EMAIL not in response.text
        span = next(s for s in response.json()["spans"] if s["entity_type"] == "EMAIL_ADDRESS")
        assert span["start"] < span["end"]
        assert "text" not in span

    async def test_a_blocking_action_says_the_provider_would_not_be_called(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        response = await client.post(
            "/v1/policies/test",
            headers=_auth(keys.viewer),
            json={
                "text": "Card 4111 1111 1111 1111 on file.",
                "policy_name": POLICY,
                "version": 1,
            },
        )

        body = response.json()
        assert body["would_block"] is True

    async def test_it_falls_back_to_the_active_version_when_no_draft_is_open(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        # Omitting the version asks "what does this policy do", and for a policy
        # nobody is editing that means the live one. The first version of this
        # endpoint looked only for a draft and answered POLICY_NOT_FOUND for
        # every policy that was not mid-edit.
        response = await client.post(
            "/v1/policies/test",
            headers=_auth(keys.viewer),
            json={"text": TEST_TEXT, "policy_name": POLICY},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["version"] == 1
        assert body["policy_status"] == "published"

    async def test_it_can_test_an_unpublished_draft(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        await client.post(f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin))
        allowed = document()
        allowed["entities"]["EMAIL_ADDRESS"]["action"] = "allow"
        await client.patch(
            f"/v1/policies/{POLICY}/draft", headers=_auth(keys.admin), json={"document": allowed}
        )

        response = await client.post(
            "/v1/policies/test",
            headers=_auth(keys.viewer),
            json={"text": TEST_TEXT, "policy_name": POLICY},
        )

        body = response.json()
        assert body["policy_status"] == "draft"
        span = next(s for s in body["spans"] if s["entity_type"] == "EMAIL_ADDRESS")
        assert span["action"] == "allow"

    async def test_it_never_writes_a_vault_mapping(
        self, client: httpx.AsyncClient, keys: Keys, services: Services
    ) -> None:
        # Tokenizing would create session mappings. The playground resolves a
        # policy and detects; it never reaches the tokenizer.
        # Filtered to the vault prefix. Rate-limit counters legitimately appear
        # on every request, and counting all keys would make this pass or fail
        # for reasons unrelated to what it claims to check.
        async def vault_keys() -> list[bytes]:
            return list(await services.redis.keys(f"{DEFAULT_KEY_PREFIX}*"))

        assert await vault_keys() == []

        await client.post(
            "/v1/policies/test",
            headers=_auth(keys.viewer),
            json={"text": TEST_TEXT, "policy_name": POLICY, "version": 1},
        )

        assert await vault_keys() == []

    async def test_it_never_calls_a_provider(self, client: httpx.AsyncClient, keys: Keys) -> None:
        # No session id is minted and no message is returned, because no
        # conversation happened.
        response = await client.post(
            "/v1/policies/test",
            headers=_auth(keys.viewer),
            json={"text": TEST_TEXT, "policy_name": POLICY, "version": 1},
        )

        body = response.json()
        assert "message" not in body
        assert "session_id" not in body
        assert "usage" not in body

    async def test_the_submitted_text_never_reaches_a_log_record(
        self, client: httpx.AsyncClient, keys: Keys, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.DEBUG):
            await client.post(
                "/v1/policies/test",
                headers=_auth(keys.viewer),
                json={"text": TEST_TEXT, "policy_name": POLICY, "version": 1},
            )

        rendered = "\n".join(record.getMessage() for record in caplog.records)
        assert CANARY_EMAIL not in rendered
        assert "invoice 4471" not in rendered

    async def test_results_are_not_cached(self, client: httpx.AsyncClient, keys: Keys) -> None:
        # A result describes one draft at one moment.
        response = await client.post(
            "/v1/policies/test",
            headers=_auth(keys.viewer),
            json={"text": TEST_TEXT, "policy_name": POLICY, "version": 1},
        )

        assert response.headers["cache-control"] == "no-store"

    async def test_oversized_input_is_refused(self, client: httpx.AsyncClient, keys: Keys) -> None:
        response = await client.post(
            "/v1/policies/test",
            headers=_auth(keys.viewer),
            json={"text": "x" * 20_001, "policy_name": POLICY, "version": 1},
        )

        assert response.status_code in {400, 413}

    async def test_it_requires_the_test_scope(self, client: httpx.AsyncClient, keys: Keys) -> None:
        response = await client.post(
            "/v1/policies/test",
            headers=_auth(keys.chat_only),
            json={"text": TEST_TEXT, "policy_name": POLICY, "version": 1},
        )

        assert response.status_code == 403
