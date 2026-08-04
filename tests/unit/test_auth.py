"""Authentication, authorization, and rate-limiting tests.

Nothing here needs PostgreSQL or a real Redis. The ``ApiKeyAuthenticator``
Protocol is faked, rate limiting runs against ``fakeredis``, and the one test
that must exercise the *real* authenticator -- the digest-parity check that
proves an unknown key costs the same work as a wrong secret -- uses in-memory
SQLite.

The security block at the bottom is the point of the file: identical failure
responses, no credential in logs or exceptions or metric labels, no raw key in a
Redis key or value, and fail-closed behaviour when the limiter's backing store
is gone.
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import AsyncIterator, Iterator, Sequence
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID, uuid4

import fakeredis.aioredis
import httpx
import pytest
from fastapi import Depends, FastAPI
from prometheus_client import REGISTRY
from pydantic import SecretStr
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.api.errors import register_exception_handlers
from app.auth import metrics
from app.auth.dependencies import (
    CurrentPrincipal,
    get_principal,
    get_rate_limiter,
    require_scope,
)
from app.auth.last_used import LastUsedTracker
from app.auth.principal import (
    MAX_CREDENTIAL_CHARS,
    BearerCredential,
    authenticate_bearer,
    build_principal,
    parse_bearer_credential,
    parse_scopes,
    resolve_principal,
)
from app.auth.rate_limit import (
    DEFAULT_KEY_PREFIX,
    FAIL_OPEN_ON_BACKEND_ERROR,
    InMemoryRateLimiter,
    RateLimiter,
    RateLimitRule,
    RedisRateLimiter,
    enforce,
)
from app.config.settings import AppEnv, Settings
from app.db.base import Base
from app.db.models import API_KEY_STATUS_ACTIVE, API_KEY_STATUS_REVOKED, ApiKey, Tenant
from app.db.session import build_session_factory
from app.domain.errors import (
    AuthenticationError,
    AuthorizationError,
    ErrorCode,
    RateLimitExceededError,
)
from app.domain.models import Principal, Scope
from app.repositories import api_keys as api_keys_module
from app.repositories.api_keys import (
    GeneratedApiKey,
    SqlAlchemyApiKeyRepository,
    generate_api_key,
    hash_api_key,
)

PEPPER = SecretStr("unit-test-pepper-not-a-real-secret-value")

TENANT_A = UUID("11111111-1111-1111-1111-111111111111")
TENANT_B = UUID("22222222-2222-2222-2222-222222222222")

ALL_SCOPES = [Scope.CHAT_INVOKE.value, Scope.DETECT_INVOKE.value, Scope.SESSIONS_DELETE.value]


# ---------------------------------------------------------------------------
# Fakes and builders
# ---------------------------------------------------------------------------
def make_key(
    *,
    tenant_id: UUID = TENANT_A,
    scopes: Sequence[str] = tuple(ALL_SCOPES),
    status: str = API_KEY_STATUS_ACTIVE,
    expires_at: datetime | None = None,
    name: str = "test-key",
) -> tuple[ApiKey, str]:
    """Return a persisted-shaped key record and the raw credential for it."""
    generated: GeneratedApiKey = generate_api_key(PEPPER)
    record = ApiKey(
        id=uuid4(),
        tenant_id=tenant_id,
        name=name,
        prefix=generated.prefix,
        key_hash=generated.key_hash,
        scopes=list(scopes),
        status=status,
        expires_at=expires_at,
    )
    return record, generated.raw_key


class FakeApiKeyAuthenticator:
    """An ``ApiKeyAuthenticator`` over a list of records.

    It reproduces the real implementation's contract exactly, including the
    digest burned on a prefix miss, so tests that assert timing parity through
    ``resolve_principal`` are not measuring a shortcut this fake took.
    """

    def __init__(self, records: Sequence[ApiKey] = ()) -> None:
        self.records = list(records)
        self.calls: list[str] = []
        self.failure: Exception | None = None
        self.touched: list[tuple[UUID, UUID, datetime]] = []

    async def authenticate(self, raw_key: str, *, pepper: SecretStr) -> ApiKey | None:
        self.calls.append(raw_key)
        if self.failure is not None:
            raise self.failure

        prefix = api_keys_module.prefix_of(raw_key)
        record = next((row for row in self.records if row.prefix == prefix), None)
        if record is None:
            api_keys_module.hash_api_key(raw_key, pepper)
            return None
        if not api_keys_module.verify_api_key(raw_key, record.key_hash, pepper):
            return None
        return record

    async def touch_last_used(self, tenant_id: UUID, api_key_id: UUID, *, when: datetime) -> None:
        self.touched.append((tenant_id, api_key_id, when))


class FailingWriter:
    """A ``LastUsedWriter`` whose backing store is down."""

    def __init__(self) -> None:
        self.calls = 0

    async def touch_last_used(self, tenant_id: UUID, api_key_id: UUID, *, when: datetime) -> None:
        self.calls += 1
        raise OperationalError("SELECT 1", {}, Exception("connection refused"))


class StubClock:
    """A monotonic clock a test can move by hand."""

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_settings() -> Settings:
    return Settings(app_env=AppEnv.TEST, api_key_pepper=PEPPER)


def make_principal(
    *,
    tenant_id: UUID = TENANT_A,
    api_key_id: UUID | None = None,
    scopes: frozenset[Scope] = frozenset(Scope),
) -> Principal:
    return Principal(
        tenant_id=tenant_id,
        api_key_id=api_key_id or uuid4(),
        api_key_prefix="sgw_live_abcd1234",
        scopes=scopes,
    )


def build_app(
    *,
    authenticator: object | None = None,
    limiter: RateLimiter | None = None,
    tracker: LastUsedTracker | None = None,
    repository: object | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    """A minimal application wired exactly the way a router would wire it."""
    application = FastAPI()
    register_exception_handlers(application)
    application.state.settings = settings or make_settings()
    if authenticator is not None:
        application.state.api_key_authenticator = authenticator
    if limiter is not None:
        application.state.rate_limiter = limiter
    if tracker is not None:
        application.state.last_used_tracker = tracker
    if repository is not None:
        application.state.api_key_repository = repository

    @application.get("/chat")
    async def chat(
        principal: Annotated[Principal, Depends(require_scope(Scope.CHAT_INVOKE))],
    ) -> dict[str, str]:
        return {"tenant_id": str(principal.tenant_id), "api_key_id": str(principal.api_key_id)}

    @application.get("/any")
    async def any_scope(principal: CurrentPrincipal) -> dict[str, str]:
        return {"tenant_id": str(principal.tenant_id)}

    return application


@pytest.fixture
def limiter() -> InMemoryRateLimiter:
    """A permissive limiter, so authentication tests are not rate limited."""
    return InMemoryRateLimiter(
        tenant_rule=RateLimitRule(limit=1_000, window_seconds=60),
        api_key_rule=RateLimitRule(limit=1_000, window_seconds=60),
    )


@pytest.fixture
async def client_factory(
    limiter: InMemoryRateLimiter,
) -> AsyncIterator[Any]:
    """Build an ``AsyncClient`` over an app wired with the given collaborators."""
    clients: list[httpx.AsyncClient] = []

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        kwargs.setdefault("limiter", limiter)
        application = build_app(**kwargs)
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application), base_url="http://gateway"
        )
        clients.append(client)
        return client

    yield factory
    for client in clients:
        await client.aclose()


@pytest.fixture
async def redis_client() -> AsyncIterator[fakeredis.aioredis.FakeRedis]:
    client = fakeredis.aioredis.FakeRedis(decode_responses=False)
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
async def sqlite_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """A session factory over a fresh in-memory schema. No PostgreSQL involved."""
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        yield build_session_factory(engine)
    finally:
        await engine.dispose()


async def seed_key(
    factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: UUID = TENANT_A,
    scopes: Sequence[str] = tuple(ALL_SCOPES),
) -> tuple[UUID, str, str]:
    """Persist a tenant and a key. Returns (api key id, prefix, raw key)."""
    async with factory() as session:
        session.add(Tenant(id=tenant_id, name="acme", slug=f"acme-{tenant_id}"))
        issued = await SqlAlchemyApiKeyRepository(session).create(
            tenant_id, name="seeded", scopes=list(scopes), pepper=PEPPER
        )
        await session.commit()
        return issued.record.id, issued.record.prefix, issued.raw_key


def metric_value(name: str, **labels: str) -> float:
    """Current counter value, or zero before the series exists."""
    value = REGISTRY.get_sample_value(name, labels)
    return 0.0 if value is None else value


def emitted(caplog: pytest.LogCaptureFixture) -> str:
    """Everything a log record could conceivably carry, as one string."""
    return "\n".join(record.getMessage() + repr(record.__dict__) for record in caplog.records)


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------
class TestBearerParsing:
    def test_missing_header_is_rejected_as_authentication_required(self) -> None:
        # Arrange / Act
        with pytest.raises(AuthenticationError) as caught:
            parse_bearer_credential(None)

        # Assert
        assert caught.value.code is ErrorCode.AUTHENTICATION_REQUIRED
        assert caught.value.status_code == 401

    def test_blank_header_is_treated_as_a_missing_header(self) -> None:
        # Arrange / Act
        with pytest.raises(AuthenticationError) as caught:
            parse_bearer_credential("   ")

        # Assert
        assert caught.value.code is ErrorCode.AUTHENTICATION_REQUIRED

    @pytest.mark.parametrize(
        "header",
        ["Basic c2VjcmV0", "Token sgw_live_abc", "ApiKey sgw_live_abc"],
    )
    def test_a_non_bearer_scheme_is_rejected(self, header: str) -> None:
        # Arrange / Act
        with pytest.raises(AuthenticationError) as caught:
            parse_bearer_credential(header)

        # Assert
        assert caught.value.code is ErrorCode.AUTHENTICATION_FAILED

    @pytest.mark.parametrize("header", ["Bearer", "sgw_live_abcdef", "Bearerx sgw_live_abc"])
    def test_a_header_without_a_scheme_and_a_token_is_rejected(self, header: str) -> None:
        # Arrange / Act
        with pytest.raises(AuthenticationError) as caught:
            parse_bearer_credential(header)

        # Assert
        assert caught.value.status_code == 401

    @pytest.mark.parametrize(
        "header",
        [
            "Bearer ",
            "Bearer sgw_live_abc def",
            "Bearer sgw_live_ééé",
            "Bearer sgw_live_abc\tdef",
        ],
    )
    def test_a_malformed_credential_is_rejected(self, header: str) -> None:
        # Arrange / Act
        with pytest.raises(AuthenticationError) as caught:
            parse_bearer_credential(header)

        # Assert
        assert caught.value.code is ErrorCode.AUTHENTICATION_FAILED

    def test_an_overlong_credential_is_rejected_before_any_digest_work(self) -> None:
        # Arrange
        header = "Bearer " + "a" * (MAX_CREDENTIAL_CHARS + 1)

        # Act
        with pytest.raises(AuthenticationError) as caught:
            parse_bearer_credential(header)

        # Assert
        assert caught.value.code is ErrorCode.AUTHENTICATION_FAILED

    @pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER", "BeArEr"])
    def test_the_scheme_is_matched_case_insensitively(self, scheme: str) -> None:
        # Arrange
        _, raw_key = make_key()

        # Act
        credential = parse_bearer_credential(f"{scheme} {raw_key}")

        # Assert
        assert credential.reveal() == raw_key

    def test_surrounding_whitespace_does_not_change_the_credential(self) -> None:
        # Arrange
        _, raw_key = make_key()

        # Act
        credential = parse_bearer_credential(f"  Bearer   {raw_key}  ")

        # Assert
        assert credential.reveal() == raw_key

    def test_the_credential_wrapper_never_renders_its_value(self) -> None:
        # Arrange
        _, raw_key = make_key()

        # Act
        credential = BearerCredential(raw_key)

        # Assert
        assert raw_key not in repr(credential)
        assert raw_key not in str(credential)
        assert raw_key not in f"{credential}"

    def test_the_credential_wrapper_is_immutable(self) -> None:
        # Arrange
        credential = BearerCredential("sgw_live_abcdefgh")

        # Act / Assert
        with pytest.raises(dataclasses.FrozenInstanceError):
            credential._value = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Principal resolution
# ---------------------------------------------------------------------------
class TestPrincipalResolution:
    async def test_a_valid_key_produces_an_immutable_principal(self) -> None:
        # Arrange
        record, raw_key = make_key(scopes=[Scope.CHAT_INVOKE.value])
        authenticator = FakeApiKeyAuthenticator([record])

        # Act
        principal = await authenticate_bearer(
            f"Bearer {raw_key}", authenticator=authenticator, pepper=PEPPER
        )

        # Assert
        assert principal.tenant_id == TENANT_A
        assert principal.api_key_id == record.id
        assert principal.api_key_prefix == record.prefix
        assert principal.scopes == frozenset({Scope.CHAT_INVOKE})
        with pytest.raises(dataclasses.FrozenInstanceError):
            principal.tenant_id = TENANT_B  # type: ignore[misc]

    async def test_an_unknown_key_is_rejected(self) -> None:
        # Arrange -- a well-formed key the store has never seen.
        authenticator = FakeApiKeyAuthenticator([])
        _, raw_key = make_key()

        # Act
        with pytest.raises(AuthenticationError) as caught:
            await authenticate_bearer(
                f"Bearer {raw_key}", authenticator=authenticator, pepper=PEPPER
            )

        # Assert
        assert caught.value.code is ErrorCode.AUTHENTICATION_FAILED

    async def test_a_valid_prefix_with_an_incorrect_secret_is_rejected(self) -> None:
        # Arrange -- same prefix, different body.
        record, raw_key = make_key()
        forged = raw_key[: len(record.prefix)] + "X" * (len(raw_key) - len(record.prefix))
        authenticator = FakeApiKeyAuthenticator([record])

        # Act
        with pytest.raises(AuthenticationError) as caught:
            await authenticate_bearer(
                f"Bearer {forged}", authenticator=authenticator, pepper=PEPPER
            )

        # Assert
        assert api_keys_module.prefix_of(forged) == record.prefix
        assert caught.value.code is ErrorCode.AUTHENTICATION_FAILED

    async def test_an_expired_key_is_rejected(self) -> None:
        # Arrange
        yesterday = datetime.now(UTC) - timedelta(days=1)
        record, raw_key = make_key(expires_at=yesterday)
        authenticator = FakeApiKeyAuthenticator([record])

        # Act
        with pytest.raises(AuthenticationError) as caught:
            await authenticate_bearer(
                f"Bearer {raw_key}", authenticator=authenticator, pepper=PEPPER
            )

        # Assert
        assert caught.value.code is ErrorCode.AUTHENTICATION_FAILED

    async def test_a_key_expiring_in_the_future_still_authenticates(self) -> None:
        # Arrange
        record, raw_key = make_key(expires_at=datetime.now(UTC) + timedelta(minutes=1))
        authenticator = FakeApiKeyAuthenticator([record])

        # Act
        principal = await authenticate_bearer(
            f"Bearer {raw_key}", authenticator=authenticator, pepper=PEPPER
        )

        # Assert
        assert principal.api_key_id == record.id

    async def test_a_revoked_key_is_rejected(self) -> None:
        # Arrange
        record, raw_key = make_key(status=API_KEY_STATUS_REVOKED)
        authenticator = FakeApiKeyAuthenticator([record])

        # Act
        with pytest.raises(AuthenticationError) as caught:
            await authenticate_bearer(
                f"Bearer {raw_key}", authenticator=authenticator, pepper=PEPPER
            )

        # Assert
        assert caught.value.code is ErrorCode.AUTHENTICATION_FAILED

    async def test_a_key_store_outage_fails_closed_with_the_same_public_error(self) -> None:
        # Arrange
        record, raw_key = make_key()
        authenticator = FakeApiKeyAuthenticator([record])
        authenticator.failure = OperationalError("SELECT 1", {}, Exception("no route to host"))

        # Act
        with pytest.raises(AuthenticationError) as caught:
            await authenticate_bearer(
                f"Bearer {raw_key}", authenticator=authenticator, pepper=PEPPER
            )

        # Assert
        assert caught.value.code is ErrorCode.AUTHENTICATION_FAILED
        assert "no route to host" not in caught.value.public_message

    async def test_the_credential_reaches_the_authenticator_intact(self) -> None:
        # Arrange
        record, raw_key = make_key()
        authenticator = FakeApiKeyAuthenticator([record])

        # Act
        await authenticate_bearer(f"Bearer {raw_key}", authenticator=authenticator, pepper=PEPPER)

        # Assert -- the whole key is verified, not just the prefix.
        assert authenticator.calls == [raw_key]

    async def test_resolve_principal_accepts_an_injected_clock(self) -> None:
        # Arrange -- valid now, expired at the supplied moment.
        record, raw_key = make_key(expires_at=datetime.now(UTC) + timedelta(hours=1))
        authenticator = FakeApiKeyAuthenticator([record])
        credential = parse_bearer_credential(f"Bearer {raw_key}")

        # Act
        with pytest.raises(AuthenticationError):
            await resolve_principal(
                credential,
                authenticator=authenticator,
                pepper=PEPPER,
                now=datetime.now(UTC) + timedelta(hours=2),
            )

    def test_unknown_scope_strings_are_dropped_rather_than_granted(self) -> None:
        # Arrange / Act
        scopes = parse_scopes(["chat:invoke", "admin:manage", "not-a-scope", ""])

        # Assert
        assert scopes == frozenset({Scope.CHAT_INVOKE})

    def test_building_a_principal_copies_nothing_secret(self) -> None:
        # Arrange
        record, raw_key = make_key()

        # Act
        principal = build_principal(record)

        # Assert
        assert raw_key not in repr(principal)
        assert record.key_hash not in repr(principal)


# ---------------------------------------------------------------------------
# Scope authorization
# ---------------------------------------------------------------------------
class TestScopeAuthorization:
    async def test_a_key_without_the_required_scope_is_forbidden(self, client_factory: Any) -> None:
        # Arrange
        record, raw_key = make_key(scopes=[Scope.DETECT_INVOKE.value])
        client = client_factory(authenticator=FakeApiKeyAuthenticator([record]))

        # Act
        response = await client.get("/chat", headers={"Authorization": f"Bearer {raw_key}"})

        # Assert
        assert response.status_code == 403
        assert response.json()["error"]["code"] == ErrorCode.AUTHORIZATION_FAILED.value

    async def test_a_key_with_the_required_scope_is_admitted(self, client_factory: Any) -> None:
        # Arrange
        record, raw_key = make_key(scopes=[Scope.CHAT_INVOKE.value])
        client = client_factory(authenticator=FakeApiKeyAuthenticator([record]))

        # Act
        response = await client.get("/chat", headers={"Authorization": f"Bearer {raw_key}"})

        # Assert
        assert response.status_code == 200
        assert response.json()["tenant_id"] == str(TENANT_A)

    async def test_the_denial_message_names_neither_the_scope_nor_the_granted_scopes(
        self, client_factory: Any
    ) -> None:
        # Arrange
        record, raw_key = make_key(scopes=[Scope.SESSIONS_DELETE.value])
        client = client_factory(authenticator=FakeApiKeyAuthenticator([record]))

        # Act
        response = await client.get("/chat", headers={"Authorization": f"Bearer {raw_key}"})

        # Assert
        body = response.text
        assert Scope.CHAT_INVOKE.value not in body
        assert Scope.SESSIONS_DELETE.value not in body

    async def test_an_endpoint_without_a_scope_requirement_still_authenticates(
        self, client_factory: Any
    ) -> None:
        # Arrange
        record, raw_key = make_key(scopes=[])
        client = client_factory(authenticator=FakeApiKeyAuthenticator([record]))

        # Act
        authorized = await client.get("/any", headers={"Authorization": f"Bearer {raw_key}"})
        anonymous = await client.get("/any")

        # Assert
        assert authorized.status_code == 200
        assert anonymous.status_code == 401

    def test_require_scope_rejects_a_bare_string(self) -> None:
        # Arrange / Act / Assert
        with pytest.raises(TypeError):
            require_scope("chat:invoke")  # type: ignore[arg-type]

    async def test_a_scope_denial_records_a_bounded_metric(self, client_factory: Any) -> None:
        # Arrange
        record, raw_key = make_key(scopes=[Scope.DETECT_INVOKE.value])
        client = client_factory(authenticator=FakeApiKeyAuthenticator([record]))
        before = metric_value(
            "sgw_authz_decisions_total",
            scope=Scope.CHAT_INVOKE.value,
            outcome=metrics.AUTHZ_OUTCOME_DENIED,
        )

        # Act
        await client.get("/chat", headers={"Authorization": f"Bearer {raw_key}"})

        # Assert
        after = metric_value(
            "sgw_authz_decisions_total",
            scope=Scope.CHAT_INVOKE.value,
            outcome=metrics.AUTHZ_OUTCOME_DENIED,
        )
        assert after == before + 1


# ---------------------------------------------------------------------------
# End-to-end through the dependencies
# ---------------------------------------------------------------------------
class TestProtectedEndpointBehaviour:
    async def test_a_missing_header_is_rejected(self, client_factory: Any) -> None:
        # Arrange
        client = client_factory(authenticator=FakeApiKeyAuthenticator([]))

        # Act
        response = await client.get("/chat")

        # Assert
        assert response.status_code == 401
        assert response.json()["error"]["code"] == ErrorCode.AUTHENTICATION_REQUIRED.value

    async def test_a_wrong_scheme_is_rejected(self, client_factory: Any) -> None:
        # Arrange
        client = client_factory(authenticator=FakeApiKeyAuthenticator([]))

        # Act
        response = await client.get("/chat", headers={"Authorization": "Basic dXNlcjpwYXNz"})

        # Assert
        assert response.status_code == 401
        assert response.json()["error"]["code"] == ErrorCode.AUTHENTICATION_FAILED.value

    async def test_an_unknown_key_is_rejected(self, client_factory: Any) -> None:
        # Arrange
        _, raw_key = make_key()
        client = client_factory(authenticator=FakeApiKeyAuthenticator([]))

        # Act
        response = await client.get("/chat", headers={"Authorization": f"Bearer {raw_key}"})

        # Assert
        assert response.status_code == 401

    async def test_an_expired_key_is_rejected(self, client_factory: Any) -> None:
        # Arrange
        record, raw_key = make_key(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        client = client_factory(authenticator=FakeApiKeyAuthenticator([record]))

        # Act
        response = await client.get("/chat", headers={"Authorization": f"Bearer {raw_key}"})

        # Assert
        assert response.status_code == 401

    async def test_a_disabled_key_is_rejected(self, client_factory: Any) -> None:
        # Arrange
        record, raw_key = make_key(status=API_KEY_STATUS_REVOKED)
        client = client_factory(authenticator=FakeApiKeyAuthenticator([record]))

        # Act
        response = await client.get("/chat", headers={"Authorization": f"Bearer {raw_key}"})

        # Assert
        assert response.status_code == 401

    async def test_an_unwired_authenticator_rejects_rather_than_admits(
        self, client_factory: Any
    ) -> None:
        # Arrange -- nothing on app.state at all.
        _, raw_key = make_key()
        client = client_factory()

        # Act
        response = await client.get("/chat", headers={"Authorization": f"Bearer {raw_key}"})

        # Assert
        assert response.status_code == 401

    async def test_an_unwired_rate_limiter_rejects_rather_than_admits(self) -> None:
        # Arrange -- authentication is wired, rate limiting is not.
        record, raw_key = make_key()
        application = build_app(authenticator=FakeApiKeyAuthenticator([record]))
        transport = httpx.ASGITransport(app=application)

        # Act
        async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as client:
            response = await client.get("/chat", headers={"Authorization": f"Bearer {raw_key}"})

        # Assert
        assert response.status_code == 429
        assert response.json()["error"]["code"] == ErrorCode.RATE_LIMIT_EXCEEDED.value

    async def test_the_rate_limit_is_enforced_on_a_protected_endpoint(self) -> None:
        # Arrange
        record, raw_key = make_key()
        limiter = InMemoryRateLimiter(
            tenant_rule=RateLimitRule(limit=10, window_seconds=60),
            api_key_rule=RateLimitRule(limit=2, window_seconds=60),
        )
        application = build_app(authenticator=FakeApiKeyAuthenticator([record]), limiter=limiter)
        transport = httpx.ASGITransport(app=application)
        headers = {"Authorization": f"Bearer {raw_key}"}

        # Act
        async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as client:
            statuses = [(await client.get("/chat", headers=headers)).status_code for _ in range(4)]

        # Assert
        assert statuses == [200, 200, 429, 429]

    async def test_a_caller_cannot_choose_its_own_tenant(self, client_factory: Any) -> None:
        # Arrange -- tenant B's key, plus headers claiming to be tenant A.
        record, raw_key = make_key(tenant_id=TENANT_B)
        client = client_factory(authenticator=FakeApiKeyAuthenticator([record]))

        # Act
        response = await client.get(
            "/chat",
            headers={
                "Authorization": f"Bearer {raw_key}",
                "X-Tenant-ID": str(TENANT_A),
                "X-Tenant-Id": str(TENANT_A),
            },
        )

        # Assert -- identity comes from the key record, never from a header.
        assert response.status_code == 200
        assert response.json()["tenant_id"] == str(TENANT_B)

    async def test_a_key_from_one_tenant_never_resolves_to_another_tenants_record(
        self, client_factory: Any
    ) -> None:
        # Arrange -- two tenants, two keys, one store.
        record_a, raw_a = make_key(tenant_id=TENANT_A, name="a")
        record_b, raw_b = make_key(tenant_id=TENANT_B, name="b")
        client = client_factory(authenticator=FakeApiKeyAuthenticator([record_a, record_b]))
        headers_a = {"Authorization": f"Bearer {raw_a}"}
        headers_b = {"Authorization": f"Bearer {raw_b}"}

        # Act
        response_a = await client.get("/chat", headers=headers_a)
        response_b = await client.get("/chat", headers=headers_b)

        # Assert
        assert response_a.json()["tenant_id"] == str(TENANT_A)
        assert response_a.json()["api_key_id"] == str(record_a.id)
        assert response_b.json()["tenant_id"] == str(TENANT_B)
        assert response_b.json()["api_key_id"] == str(record_b.id)

    async def test_a_forged_credential_built_from_another_tenants_prefix_is_rejected(
        self, client_factory: Any
    ) -> None:
        # Arrange -- tenant A holds a key and knows tenant B's prefix.
        record_a, raw_a = make_key(tenant_id=TENANT_A, name="a")
        record_b, _ = make_key(tenant_id=TENANT_B, name="b")
        forged = record_b.prefix + raw_a[len(record_a.prefix) :]
        client = client_factory(authenticator=FakeApiKeyAuthenticator([record_a, record_b]))

        # Act
        response = await client.get("/chat", headers={"Authorization": f"Bearer {forged}"})

        # Assert
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
class TestRedisRateLimiter:
    async def test_requests_under_the_limit_are_admitted(
        self, redis_client: fakeredis.aioredis.FakeRedis
    ) -> None:
        # Arrange
        limiter = RedisRateLimiter(
            redis_client,
            tenant_rule=RateLimitRule(limit=10, window_seconds=60),
            api_key_rule=RateLimitRule(limit=3, window_seconds=60),
        )
        principal = make_principal()

        # Act
        decisions = [await limiter.acquire(principal) for _ in range(3)]

        # Assert
        assert [decision.allowed for decision in decisions] == [True, True, True]
        assert [decision.remaining for decision in decisions] == [2, 1, 0]

    async def test_the_request_after_the_limit_is_denied(
        self, redis_client: fakeredis.aioredis.FakeRedis
    ) -> None:
        # Arrange
        limiter = RedisRateLimiter(
            redis_client,
            tenant_rule=RateLimitRule(limit=10, window_seconds=60),
            api_key_rule=RateLimitRule(limit=2, window_seconds=60),
        )
        principal = make_principal()
        for _ in range(2):
            await limiter.acquire(principal)

        # Act
        decision = await limiter.acquire(principal)

        # Assert
        assert decision.allowed is False
        assert decision.bucket == metrics.BUCKET_API_KEY
        assert 1 <= decision.retry_after_seconds <= 60

    async def test_the_tenant_bucket_is_shared_across_that_tenants_keys(
        self, redis_client: fakeredis.aioredis.FakeRedis
    ) -> None:
        # Arrange -- two keys, one tenant, a tenant limit of two.
        limiter = RedisRateLimiter(
            redis_client,
            tenant_rule=RateLimitRule(limit=2, window_seconds=60),
            api_key_rule=RateLimitRule(limit=100, window_seconds=60),
        )
        first = make_principal(tenant_id=TENANT_A)
        second = make_principal(tenant_id=TENANT_A)

        # Act
        allowed_first = await limiter.acquire(first)
        allowed_second = await limiter.acquire(second)
        denied = await limiter.acquire(second)

        # Assert
        assert allowed_first.allowed and allowed_second.allowed
        assert denied.allowed is False
        assert denied.bucket == metrics.BUCKET_TENANT

    async def test_one_tenants_traffic_does_not_throttle_another(
        self, redis_client: fakeredis.aioredis.FakeRedis
    ) -> None:
        # Arrange
        limiter = RedisRateLimiter(
            redis_client,
            tenant_rule=RateLimitRule(limit=1, window_seconds=60),
            api_key_rule=RateLimitRule(limit=100, window_seconds=60),
        )
        noisy = make_principal(tenant_id=TENANT_A)
        quiet = make_principal(tenant_id=TENANT_B)
        await limiter.acquire(noisy)
        await limiter.acquire(noisy)

        # Act
        decision = await limiter.acquire(quiet)

        # Assert
        assert decision.allowed is True

    async def test_budget_returns_once_the_window_slides_past(
        self, redis_client: fakeredis.aioredis.FakeRedis
    ) -> None:
        # Arrange
        clock = StubClock(start=1_000.0)
        limiter = RedisRateLimiter(
            redis_client,
            tenant_rule=RateLimitRule(limit=10, window_seconds=60),
            api_key_rule=RateLimitRule(limit=1, window_seconds=60),
            clock=clock,
        )
        principal = make_principal()
        await limiter.acquire(principal)
        assert (await limiter.acquire(principal)).allowed is False

        # Act
        clock.advance(61)
        decision = await limiter.acquire(principal)

        # Assert
        assert decision.allowed is True

    async def test_a_denied_request_does_not_extend_the_window(
        self, redis_client: fakeredis.aioredis.FakeRedis
    ) -> None:
        # Arrange -- one slot, consumed at t=0, then hammered for a minute.
        clock = StubClock(start=1_000.0)
        limiter = RedisRateLimiter(
            redis_client,
            tenant_rule=RateLimitRule(limit=10, window_seconds=60),
            api_key_rule=RateLimitRule(limit=1, window_seconds=60),
            clock=clock,
        )
        principal = make_principal()
        await limiter.acquire(principal)
        for _ in range(5):
            clock.advance(10)
            await limiter.acquire(principal)

        # Act -- 61 seconds after the one admitted request.
        clock.advance(11)
        decision = await limiter.acquire(principal)

        # Assert
        assert decision.allowed is True

    async def test_a_bucket_never_holds_more_members_than_its_limit(
        self, redis_client: fakeredis.aioredis.FakeRedis
    ) -> None:
        # Arrange
        limiter = RedisRateLimiter(
            redis_client,
            tenant_rule=RateLimitRule(limit=50, window_seconds=60),
            api_key_rule=RateLimitRule(limit=3, window_seconds=60),
        )
        principal = make_principal()

        # Act
        for _ in range(20):
            await limiter.acquire(principal)

        # Assert
        key = limiter.api_key_key(principal.api_key_id)
        assert await redis_client.zcard(key) == 3

    async def test_bucket_keys_expire_so_idle_tenants_cost_nothing(
        self, redis_client: fakeredis.aioredis.FakeRedis
    ) -> None:
        # Arrange
        limiter = RedisRateLimiter(
            redis_client, api_key_rule=RateLimitRule(limit=5, window_seconds=30)
        )
        principal = make_principal()

        # Act
        await limiter.acquire(principal)

        # Assert
        ttl = await redis_client.pttl(limiter.api_key_key(principal.api_key_id))
        assert 0 < ttl <= 30_000

    async def test_bucket_keys_are_derived_from_record_ids(self) -> None:
        # Arrange
        limiter = RedisRateLimiter(fakeredis.aioredis.FakeRedis())
        principal = make_principal()

        # Act
        tenant_key = limiter.tenant_key(principal.tenant_id)
        api_key_key = limiter.api_key_key(principal.api_key_id)

        # Assert
        assert tenant_key == f"{DEFAULT_KEY_PREFIX}:tenant:{principal.tenant_id}"
        assert api_key_key == f"{DEFAULT_KEY_PREFIX}:key:{principal.api_key_id}"

    async def test_the_backing_store_being_down_denies_by_default(self) -> None:
        # Arrange
        limiter = RedisRateLimiter(_BrokenRedis())

        # Act
        decision = await limiter.acquire(make_principal())

        # Assert
        assert FAIL_OPEN_ON_BACKEND_ERROR is False
        assert decision.allowed is False
        assert decision.reason == "rate_limit_backend_unavailable"

    async def test_enforce_turns_a_backend_outage_into_a_public_429(self) -> None:
        # Arrange
        limiter = RedisRateLimiter(_BrokenRedis())

        # Act
        with pytest.raises(RateLimitExceededError) as caught:
            await enforce(limiter, make_principal())

        # Assert
        assert caught.value.status_code == 429
        assert "redis" not in caught.value.public_message.lower()

    async def test_the_deliberate_opt_out_admits_when_the_backing_store_is_down(self) -> None:
        # Arrange -- an operator who prefers an unmetered burst to an outage.
        limiter = RedisRateLimiter(_BrokenRedis(), fail_open_on_backend_error=True)

        # Act
        decision = await limiter.acquire(make_principal())

        # Assert
        assert decision.allowed is True
        assert decision.reason == "rate_limit_backend_unavailable"

    async def test_the_two_failure_modes_are_counted_separately(self) -> None:
        # Arrange
        closed_before = metric_value(
            "sgw_rate_limit_decisions_total",
            bucket=metrics.BUCKET_TENANT,
            outcome=metrics.RATE_LIMIT_OUTCOME_FAILED_CLOSED,
        )
        open_before = metric_value(
            "sgw_rate_limit_decisions_total",
            bucket=metrics.BUCKET_TENANT,
            outcome=metrics.RATE_LIMIT_OUTCOME_FAILED_OPEN,
        )

        # Act
        await RedisRateLimiter(_BrokenRedis()).acquire(make_principal())
        await RedisRateLimiter(_BrokenRedis(), fail_open_on_backend_error=True).acquire(
            make_principal()
        )

        # Assert
        assert (
            metric_value(
                "sgw_rate_limit_decisions_total",
                bucket=metrics.BUCKET_TENANT,
                outcome=metrics.RATE_LIMIT_OUTCOME_FAILED_CLOSED,
            )
            == closed_before + 1
        )
        assert (
            metric_value(
                "sgw_rate_limit_decisions_total",
                bucket=metrics.BUCKET_TENANT,
                outcome=metrics.RATE_LIMIT_OUTCOME_FAILED_OPEN,
            )
            == open_before + 1
        )

    async def test_enforce_returns_the_decision_when_the_request_is_admitted(
        self, redis_client: fakeredis.aioredis.FakeRedis
    ) -> None:
        # Arrange
        limiter = RedisRateLimiter(redis_client)

        # Act
        decision = await enforce(limiter, make_principal())

        # Assert
        assert decision.allowed is True
        assert decision.reason == "within_limit"

    def test_a_rule_must_describe_a_real_window(self) -> None:
        # Arrange / Act / Assert
        with pytest.raises(ValueError, match="limit"):
            RateLimitRule(limit=0, window_seconds=60)
        with pytest.raises(ValueError, match="window_seconds"):
            RateLimitRule(limit=1, window_seconds=0)


class _BrokenRedis:
    """A Redis client whose every call fails, for fail-closed assertions."""

    async def transaction(self, *args: object, **kwargs: object) -> object:
        raise RedisConnectionError("connection refused")


class TestInMemoryRateLimiter:
    async def test_it_denies_once_the_api_key_limit_is_reached(self) -> None:
        # Arrange
        limiter = InMemoryRateLimiter(
            tenant_rule=RateLimitRule(limit=10, window_seconds=60),
            api_key_rule=RateLimitRule(limit=2, window_seconds=60),
        )
        principal = make_principal()

        # Act
        decisions = [await limiter.acquire(principal) for _ in range(3)]

        # Assert
        assert [decision.allowed for decision in decisions] == [True, True, False]

    async def test_it_denies_once_the_tenant_limit_is_reached(self) -> None:
        # Arrange
        limiter = InMemoryRateLimiter(
            tenant_rule=RateLimitRule(limit=1, window_seconds=60),
            api_key_rule=RateLimitRule(limit=100, window_seconds=60),
        )

        # Act
        first = await limiter.acquire(make_principal(tenant_id=TENANT_A))
        second = await limiter.acquire(make_principal(tenant_id=TENANT_A))

        # Assert
        assert first.allowed is True
        assert second.allowed is False
        assert second.bucket == metrics.BUCKET_TENANT

    async def test_its_window_slides_with_the_injected_clock(self) -> None:
        # Arrange
        clock = StubClock()
        limiter = InMemoryRateLimiter(
            tenant_rule=RateLimitRule(limit=10, window_seconds=60),
            api_key_rule=RateLimitRule(limit=1, window_seconds=60),
            clock=clock,
        )
        principal = make_principal()
        await limiter.acquire(principal)

        # Act
        clock.advance(61)
        decision = await limiter.acquire(principal)

        # Assert
        assert decision.allowed is True

    async def test_simulated_failure_denies_by_default(self) -> None:
        # Arrange
        limiter = InMemoryRateLimiter()
        limiter.simulate_failure()

        # Act / Assert
        with pytest.raises(RateLimitExceededError):
            await enforce(limiter, make_principal())

    async def test_simulated_failure_admits_only_with_the_explicit_opt_out(self) -> None:
        # Arrange
        limiter = InMemoryRateLimiter(fail_open_on_backend_error=True)
        limiter.simulate_failure()

        # Act
        decision = await limiter.acquire(make_principal())

        # Assert
        assert decision.allowed is True


# ---------------------------------------------------------------------------
# last_used_at maintenance
# ---------------------------------------------------------------------------
class TestLastUsedTracker:
    async def test_the_first_use_of_a_key_is_written(self) -> None:
        # Arrange
        tracker = LastUsedTracker(interval_seconds=300, clock=StubClock())
        writer = FakeApiKeyAuthenticator()
        principal = make_principal()

        # Act
        written = await tracker.record_use(writer, principal)

        # Assert
        assert written is True
        assert len(writer.touched) == 1

    async def test_subsequent_uses_inside_the_interval_are_not_written(self) -> None:
        # Arrange
        clock = StubClock()
        tracker = LastUsedTracker(interval_seconds=300, clock=clock)
        writer = FakeApiKeyAuthenticator()
        principal = make_principal()

        # Act
        for _ in range(50):
            clock.advance(1)
            await tracker.record_use(writer, principal)

        # Assert -- fifty requests, one write.
        assert len(writer.touched) == 1

    async def test_a_use_after_the_interval_is_written_again(self) -> None:
        # Arrange
        clock = StubClock()
        tracker = LastUsedTracker(interval_seconds=300, clock=clock)
        writer = FakeApiKeyAuthenticator()
        principal = make_principal()
        await tracker.record_use(writer, principal)

        # Act
        clock.advance(301)
        await tracker.record_use(writer, principal)

        # Assert
        assert len(writer.touched) == 2

    async def test_each_key_gets_its_own_budget(self) -> None:
        # Arrange
        tracker = LastUsedTracker(interval_seconds=300, clock=StubClock())
        writer = FakeApiKeyAuthenticator()

        # Act
        await tracker.record_use(writer, make_principal())
        await tracker.record_use(writer, make_principal())

        # Assert
        assert len(writer.touched) == 2

    def test_the_tracked_set_is_bounded(self) -> None:
        # Arrange
        tracker = LastUsedTracker(interval_seconds=300, max_tracked_keys=4, clock=StubClock())

        # Act
        for _ in range(50):
            tracker.should_update(uuid4())

        # Assert
        assert len(tracker._seen) == 4

    async def test_a_write_failure_does_not_fail_the_request(self) -> None:
        # Arrange
        tracker = LastUsedTracker(interval_seconds=300, clock=StubClock())
        writer = FailingWriter()

        # Act
        written = await tracker.record_use(writer, make_principal())

        # Assert
        assert written is False
        assert writer.calls == 1

    async def test_no_writer_means_no_write_and_no_error(self) -> None:
        # Arrange
        tracker = LastUsedTracker(clock=StubClock())

        # Act
        written = await tracker.record_use(None, make_principal())

        # Assert
        assert written is False

    async def test_a_burst_of_requests_produces_one_write(self, client_factory: Any) -> None:
        # Arrange
        record, raw_key = make_key()
        authenticator = FakeApiKeyAuthenticator([record])
        tracker = LastUsedTracker(interval_seconds=300, clock=StubClock())
        client = client_factory(authenticator=authenticator, tracker=tracker)
        headers = {"Authorization": f"Bearer {raw_key}"}

        # Act
        for _ in range(10):
            await client.get("/chat", headers=headers)

        # Assert
        assert len(authenticator.touched) == 1
        assert authenticator.touched[0][0] == record.tenant_id

    def test_a_tracker_rejects_a_nonsensical_configuration(self) -> None:
        # Arrange / Act / Assert
        with pytest.raises(ValueError, match="interval_seconds"):
            LastUsedTracker(interval_seconds=0)
        with pytest.raises(ValueError, match="max_tracked_keys"):
            LastUsedTracker(max_tracked_keys=0)


# ---------------------------------------------------------------------------
# Security properties
# ---------------------------------------------------------------------------
@pytest.mark.security
class TestSecurityProperties:
    async def test_every_credential_failure_returns_the_same_status_and_message(
        self, client_factory: Any
    ) -> None:
        # Arrange -- one store holding a valid, an expired, and a revoked key.
        valid, valid_raw = make_key(name="valid")
        expired, expired_raw = make_key(
            name="expired", expires_at=datetime.now(UTC) - timedelta(days=1)
        )
        revoked, revoked_raw = make_key(name="revoked", status=API_KEY_STATUS_REVOKED)
        _, unknown_raw = make_key(name="unknown")
        forged = valid.prefix + "Z" * (len(valid_raw) - len(valid.prefix))
        client = client_factory(authenticator=FakeApiKeyAuthenticator([valid, expired, revoked]))

        # Act
        bodies = []
        statuses = []
        for header in (
            "Basic dXNlcjpwYXNz",
            "Bearer not-a-key",
            f"Bearer {unknown_raw}",
            f"Bearer {forged}",
            f"Bearer {expired_raw}",
            f"Bearer {revoked_raw}",
        ):
            response = await client.get("/chat", headers={"Authorization": header})
            statuses.append(response.status_code)
            bodies.append(response.json()["error"])

        # Assert -- byte-identical bodies, so nothing can be inferred.
        assert statuses == [401] * 6
        assert all(body == bodies[0] for body in bodies)
        assert bodies[0]["code"] == ErrorCode.AUTHENTICATION_FAILED.value

    async def test_a_missing_header_is_also_401_and_says_nothing_about_keys(
        self, client_factory: Any
    ) -> None:
        # Arrange
        valid, _ = make_key()
        client = client_factory(authenticator=FakeApiKeyAuthenticator([valid]))

        # Act
        response = await client.get("/chat")

        # Assert -- a different code (the caller sent no credential), but the
        # message reveals nothing about which keys exist.
        assert response.status_code == 401
        assert valid.prefix not in response.text

    async def test_an_unknown_key_costs_the_same_digest_work_as_a_wrong_secret(
        self,
        sqlite_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Arrange -- the *real* authenticator over a real (SQLite) row, with the
        # digest function counted. The unknown-prefix path must still spend one.
        _, real_prefix, raw_key = await seed_key(sqlite_factory)
        _, unknown_raw = make_key()
        forged = real_prefix + "Z" * (len(raw_key) - len(real_prefix))

        digests: list[str] = []

        def counting_hash(value: str, pepper: SecretStr) -> str:
            digests.append("spent")
            return hash_api_key(value, pepper)

        monkeypatch.setattr(api_keys_module, "hash_api_key", counting_hash)

        async with sqlite_factory() as session:
            repository = SqlAlchemyApiKeyRepository(session)

            # Act -- unknown prefix.
            digests.clear()
            with pytest.raises(AuthenticationError):
                await authenticate_bearer(
                    f"Bearer {unknown_raw}", authenticator=repository, pepper=PEPPER
                )
            unknown_cost = len(digests)

            # Act -- known prefix, wrong secret.
            digests.clear()
            with pytest.raises(AuthenticationError):
                await authenticate_bearer(
                    f"Bearer {forged}", authenticator=repository, pepper=PEPPER
                )
            wrong_secret_cost = len(digests)

            # Act -- the correct key, for reference.
            digests.clear()
            principal = await authenticate_bearer(
                f"Bearer {raw_key}", authenticator=repository, pepper=PEPPER
            )
            success_cost = len(digests)

        # Assert -- one digest on every path, so this layer adds no oracle.
        assert unknown_cost == wrong_secret_cost == success_cost == 1
        assert principal.tenant_id == TENANT_A

    async def test_the_supplied_credential_never_reaches_a_log_record(
        self, client_factory: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Arrange
        record, raw_key = make_key(scopes=[Scope.DETECT_INVOKE.value])
        _, unknown_raw = make_key()
        client = client_factory(authenticator=FakeApiKeyAuthenticator([record]))
        caplog.set_level(logging.DEBUG)

        # Act -- success, scope denial, unknown key, malformed value.
        await client.get("/any", headers={"Authorization": f"Bearer {raw_key}"})
        await client.get("/chat", headers={"Authorization": f"Bearer {raw_key}"})
        await client.get("/chat", headers={"Authorization": f"Bearer {unknown_raw}"})
        await client.get("/chat", headers={"Authorization": "Bearer sgw_live_deadbeefcafe"})

        # Assert
        assert caplog.records
        text = emitted(caplog)
        assert raw_key not in text
        assert unknown_raw not in text
        assert "sgw_live_deadbeefcafe" not in text
        assert record.key_hash not in text
        # Stronger: no run of twelve characters from the credential -- not even
        # the non-secret prefix -- is quoted anywhere in a record.
        windows = {raw_key[index : index + 12] for index in range(len(raw_key) - 12)}
        assert not any(window in text for window in windows)

    async def test_no_authentication_error_carries_the_credential(self) -> None:
        # Arrange
        record, raw_key = make_key()
        authenticator = FakeApiKeyAuthenticator([record])
        forged = record.prefix + "Q" * (len(raw_key) - len(record.prefix))

        # Act
        errors: list[AuthenticationError] = []
        for header in ("Basic abc", f"Bearer {forged}", "Bearer x y"):
            with pytest.raises(AuthenticationError) as caught:
                await authenticate_bearer(header, authenticator=authenticator, pepper=PEPPER)
            errors.append(caught.value)

        # Assert
        for error in errors:
            rendered = f"{error!r}{error!s}{error.public_message}{error.log_context}"
            assert forged not in rendered
            assert raw_key not in rendered
            assert "abc" not in rendered

    async def test_an_authorization_error_carries_no_caller_data(self) -> None:
        # Arrange
        error = AuthorizationError(log_context={"reason": "missing_scope"})

        # Assert
        assert error.status_code == 403
        assert Scope.CHAT_INVOKE.value not in repr(error)
        assert error.public_message == "The credentials do not grant access to this operation."

    async def test_no_redis_key_or_value_contains_the_raw_credential(
        self, redis_client: fakeredis.aioredis.FakeRedis
    ) -> None:
        # Arrange -- a real key, and a principal built from its record.
        record, raw_key = make_key()
        principal = build_principal(record)
        limiter = RedisRateLimiter(
            redis_client, api_key_rule=RateLimitRule(limit=5, window_seconds=60)
        )

        # Act
        for _ in range(3):
            await limiter.acquire(principal)

        # Assert
        keys = await redis_client.keys("*")
        assert keys
        for key in keys:
            name = key.decode()
            assert raw_key not in name
            assert record.prefix not in name
            assert record.key_hash not in name
            for member, _score in await redis_client.zrange(key, 0, -1, withscores=True):
                value = member.decode()
                assert raw_key not in value
                assert record.prefix not in value
                assert record.key_hash not in value

    async def test_rate_limit_keys_are_built_from_identifiers_not_secrets(
        self, redis_client: fakeredis.aioredis.FakeRedis
    ) -> None:
        # Arrange
        record, _ = make_key()
        principal = build_principal(record)
        limiter = RedisRateLimiter(redis_client)

        # Act
        await limiter.acquire(principal)

        # Assert
        names = {key.decode() for key in await redis_client.keys("*")}
        assert names == {
            f"{DEFAULT_KEY_PREFIX}:tenant:{principal.tenant_id}",
            f"{DEFAULT_KEY_PREFIX}:key:{principal.api_key_id}",
        }

    async def test_no_metric_label_carries_an_identifier_or_a_credential(
        self, client_factory: Any, redis_client: fakeredis.aioredis.FakeRedis
    ) -> None:
        # Arrange
        record, raw_key = make_key(scopes=[Scope.DETECT_INVOKE.value])
        client = client_factory(authenticator=FakeApiKeyAuthenticator([record]))

        # Act -- exercise every counter this package owns.
        await client.get("/chat", headers={"Authorization": f"Bearer {raw_key}"})
        await client.get("/chat", headers={"Authorization": "Bearer sgw_live_unknownkey"})
        await client.get("/chat")
        await RedisRateLimiter(redis_client).acquire(build_principal(record))

        # Assert
        forbidden = {
            str(record.id),
            str(record.tenant_id),
            record.prefix,
            record.key_hash,
            raw_key,
            "/chat",
        }
        for family in REGISTRY.collect():
            if not family.name.startswith(
                ("sgw_auth", "sgw_authz", "sgw_rate_limit", "sgw_api_key")
            ):
                continue
            for sample in family.samples:
                for label_value in sample.labels.values():
                    assert label_value not in forbidden

    def test_metric_label_sets_are_closed(self) -> None:
        # Arrange / Act / Assert -- a dynamic string cannot become a label.
        with pytest.raises(ValueError, match="authentication outcome"):
            metrics.record_authentication("tenant-11111111")
        with pytest.raises(ValueError, match="rate-limit bucket"):
            metrics.record_rate_limit(bucket="/v1/chat", outcome=metrics.RATE_LIMIT_OUTCOME_ALLOWED)
        with pytest.raises(ValueError, match="rate-limit outcome"):
            metrics.record_rate_limit(bucket=metrics.BUCKET_TENANT, outcome="sgw_live_abc")
        with pytest.raises(ValueError, match="last_used outcome"):
            metrics.record_last_used("sgw_live_abc")
        with pytest.raises(TypeError):
            metrics.record_authorization(scope="chat:invoke", outcome="granted")  # type: ignore[arg-type]

    def test_the_declared_label_names_exclude_high_cardinality_dimensions(self) -> None:
        # Arrange
        banned = {"tenant", "tenant_id", "api_key", "api_key_id", "prefix", "key", "path", "route"}
        collectors = (
            metrics.AUTHENTICATION_ATTEMPTS_TOTAL,
            metrics.AUTHORIZATION_DECISIONS_TOTAL,
            metrics.RATE_LIMIT_DECISIONS_TOTAL,
            metrics.API_KEY_LAST_USED_UPDATES_TOTAL,
        )

        # Act / Assert
        for collector in collectors:
            assert set(collector._labelnames).isdisjoint(banned)

    async def test_an_authentication_failure_is_counted_without_identifying_the_key(
        self, client_factory: Any
    ) -> None:
        # Arrange
        _, raw_key = make_key()
        client = client_factory(authenticator=FakeApiKeyAuthenticator([]))
        before = metric_value(
            "sgw_auth_attempts_total", outcome=metrics.AUTH_OUTCOME_INVALID_CREDENTIAL
        )

        # Act
        await client.get("/chat", headers={"Authorization": f"Bearer {raw_key}"})

        # Assert
        after = metric_value(
            "sgw_auth_attempts_total", outcome=metrics.AUTH_OUTCOME_INVALID_CREDENTIAL
        )
        assert after == before + 1


# ---------------------------------------------------------------------------
# Dependency wiring
# ---------------------------------------------------------------------------
class TestDependencyWiring:
    async def test_an_unwired_application_yields_a_denying_rate_limiter(self) -> None:
        # Arrange
        application = FastAPI()
        request = _fake_request(application)

        # Act
        limiter = await get_rate_limiter(request)
        decision = await limiter.acquire(make_principal())

        # Assert
        assert decision.allowed is False
        assert decision.reason == "rate_limiter_not_configured"

    async def test_a_redis_client_on_state_produces_a_redis_limiter(
        self, redis_client: fakeredis.aioredis.FakeRedis
    ) -> None:
        # Arrange
        application = FastAPI()
        application.state.redis = redis_client
        request = _fake_request(application)

        # Act
        limiter = await get_rate_limiter(request)

        # Assert
        assert isinstance(limiter, RedisRateLimiter)

    async def test_the_session_factory_fallback_builds_the_real_authenticator(
        self, sqlite_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        # Arrange -- no authenticator on state, only a session factory.
        api_key_id, _, raw_key = await seed_key(sqlite_factory, scopes=[Scope.CHAT_INVOKE.value])
        application = build_app(limiter=InMemoryRateLimiter())
        application.state.db_session_factory = sqlite_factory
        transport = httpx.ASGITransport(app=application)

        # Act
        async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as client:
            response = await client.get("/chat", headers={"Authorization": f"Bearer {raw_key}"})

        # Assert
        assert response.status_code == 200
        assert response.json()["tenant_id"] == str(TENANT_A)
        assert response.json()["api_key_id"] == str(api_key_id)

    async def test_the_principal_is_published_on_request_state(self, client_factory: Any) -> None:
        # Arrange
        record, raw_key = make_key()
        application = build_app(
            authenticator=FakeApiKeyAuthenticator([record]), limiter=InMemoryRateLimiter()
        )
        seen: list[Principal] = []

        @application.get("/state")
        async def read_state(
            principal: Annotated[Principal, Depends(get_principal)],
        ) -> dict[str, bool]:
            seen.append(principal)
            return {"ok": True}

        transport = httpx.ASGITransport(app=application)

        # Act
        async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as client:
            await client.get("/state", headers={"Authorization": f"Bearer {raw_key}"})

        # Assert
        assert seen and seen[0].api_key_id == record.id


class _FakeApp:
    def __init__(self, application: FastAPI) -> None:
        self.state = application.state


class _FakeRequest:
    def __init__(self, application: FastAPI) -> None:
        self.app = _FakeApp(application)


def _fake_request(application: FastAPI) -> Any:
    """A stand-in carrying only what the dependencies read: ``app.state``."""
    return _FakeRequest(application)


@pytest.fixture(autouse=True)
def _quiet_loggers() -> Iterator[None]:
    """Keep the auth logger at DEBUG so leak assertions see everything."""
    logger = logging.getLogger("app.auth")
    previous = logger.level
    logger.setLevel(logging.DEBUG)
    yield
    logger.setLevel(previous)
