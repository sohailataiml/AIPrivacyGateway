"""Unit tests for the database layer and the tenant-scoped repositories.

These run against in-memory SQLite via ``aiosqlite`` -- no live PostgreSQL. The
schema is built from the same ``Base.metadata`` the migration mirrors, so the
tenant-scoping, uniqueness, and API-key assertions here exercise the real
mappings. Anything genuinely PostgreSQL-specific (JSONB behaviour, migration
upgrade/downgrade) lives in ``tests/integration/test_migrations.py``.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import sqlalchemy as sa
from pydantic import SecretStr
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db.base import Base, utc_now
from app.db.models import ApiKey, Tenant
from app.db.session import build_session_factory, transaction
from app.repositories.api_keys import (
    KEY_LABEL,
    KEY_RANDOM_BYTES,
    SqlAlchemyApiKeyRepository,
    generate_api_key,
    hash_api_key,
    prefix_of,
    verify_api_key,
)
from app.repositories.audit_events import AuditEventDraft, SqlAlchemyAuditEventRepository
from app.repositories.policies import SqlAlchemyPolicyRepository
from app.repositories.provider_configs import SqlAlchemyProviderConfigRepository
from app.repositories.tenants import SqlAlchemyTenantRepository

PEPPER = SecretStr("unit-test-pepper-not-a-real-secret-value")
POLICY_DOC = {"schema_version": 1, "entities": {}}

FORBIDDEN_AUDIT_FIELDS = frozenset(
    {"content", "message", "messages", "prompt", "response", "original_value", "token", "api_key"}
)


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    """A session over a fresh in-memory schema, discarded after each test."""
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    factory = build_session_factory(engine)
    async with factory() as open_session:
        yield open_session
    await engine.dispose()


@pytest.fixture
async def tenants(session: AsyncSession) -> tuple[Tenant, Tenant]:
    """Two tenants. Every cross-tenant assertion below uses this pair."""
    repository = SqlAlchemyTenantRepository(session)
    first = await repository.create(name="Acme", slug="acme")
    second = await repository.create(name="Globex", slug="globex")
    await session.commit()
    return first, second


# ---------------------------------------------------------------------------
# Session, transactions, timestamps
# ---------------------------------------------------------------------------
async def test_transaction_commits_on_success(session: AsyncSession) -> None:
    # Arrange
    repository = SqlAlchemyTenantRepository(session)

    # Act
    async with transaction(session):
        created = await repository.create(name="Initech", slug="initech")

    # Assert
    assert await repository.get_by_slug("initech") is not None
    assert created.id is not None


async def test_transaction_rolls_back_on_error(session: AsyncSession) -> None:
    # Arrange
    repository = SqlAlchemyTenantRepository(session)

    # Act
    with pytest.raises(RuntimeError):
        async with transaction(session):
            await repository.create(name="Umbrella", slug="umbrella")
            raise RuntimeError("failure inside the unit of work")

    # Assert
    assert await repository.get_by_slug("umbrella") is None


async def test_stored_timestamps_are_timezone_aware(session: AsyncSession) -> None:
    # Arrange
    repository = SqlAlchemyTenantRepository(session)

    # Act
    async with transaction(session):
        tenant = await repository.create(name="Hooli", slug="hooli")
    session.expunge_all()
    reloaded = await repository.get(tenant.id)

    # Assert
    assert reloaded is not None
    assert reloaded.created_at.tzinfo is not None
    assert reloaded.created_at.utcoffset() == timedelta(0)
    assert reloaded.updated_at.tzinfo is not None


async def test_naive_timestamp_is_rejected(session: AsyncSession) -> None:
    # Arrange
    repository = SqlAlchemyApiKeyRepository(session)

    # Act / Assert
    with pytest.raises(ValueError, match="timezone-aware"):
        await repository.create(
            uuid4(),
            name="naive",
            scopes=[],
            pepper=PEPPER,
            expires_at=datetime(2030, 1, 1),  # noqa: DTZ001 -- deliberately naive
        )


# ---------------------------------------------------------------------------
# Tenants
# ---------------------------------------------------------------------------
async def test_tenant_lookup_is_identity_scoped(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, globex = tenants
    repository = SqlAlchemyTenantRepository(session)

    # Act
    found = await repository.get(acme.id)
    missing = await repository.get(uuid4())

    # Assert
    assert found is not None and found.id == acme.id
    assert found.id != globex.id
    assert missing is None


# ---------------------------------------------------------------------------
# API keys: format, hashing, storage
# ---------------------------------------------------------------------------
def test_generated_key_carries_at_least_32_random_bytes() -> None:
    # Arrange / Act
    generated = generate_api_key(PEPPER)
    body = generated.raw_key.removeprefix(KEY_LABEL)

    # Assert -- base64url without padding: 4 chars per 3 bytes.
    assert generated.raw_key.startswith(KEY_LABEL)
    assert len(body) >= (KEY_RANDOM_BYTES * 4) // 3
    assert generated.prefix == prefix_of(generated.raw_key)
    assert generated.key_hash == hash_api_key(generated.raw_key, PEPPER)


def test_generated_keys_are_unique() -> None:
    # Arrange / Act
    keys = {generate_api_key(PEPPER).raw_key for _ in range(50)}

    # Assert
    assert len(keys) == 50


def test_verification_rejects_a_wrong_key() -> None:
    # Arrange
    generated = generate_api_key(PEPPER)
    other = generate_api_key(PEPPER)

    # Act / Assert
    assert verify_api_key(generated.raw_key, generated.key_hash, PEPPER) is True
    assert verify_api_key(other.raw_key, generated.key_hash, PEPPER) is False
    assert verify_api_key(generated.raw_key, generated.key_hash, SecretStr("other-pepper")) is False


def test_generated_key_repr_masks_the_raw_value() -> None:
    # Arrange
    generated = generate_api_key(PEPPER)

    # Act
    rendered = repr(generated)

    # Assert
    assert generated.raw_key not in rendered
    assert "raw_key=***" in rendered


async def test_raw_key_is_absent_from_every_stored_column(
    session: AsyncSession, tenants: tuple[Tenant, Tenant], caplog: pytest.LogCaptureFixture
) -> None:
    # Arrange
    acme, _ = tenants
    repository = SqlAlchemyApiKeyRepository(session)

    # Act
    with caplog.at_level(logging.DEBUG):
        async with transaction(session):
            issued = await repository.create(
                acme.id, name="primary", scopes=["chat:invoke"], pepper=PEPPER
            )
        row = (await session.execute(sa.select(ApiKey.__table__))).mappings().one()

    # Assert -- no column, and no emitted log line, holds the raw credential.
    raw = issued.raw_key
    assert raw not in {str(value) for value in row.values()}
    for column, value in row.items():
        assert raw not in str(value), f"raw key leaked into column {column!r}"
    assert row["key_hash"] == hash_api_key(raw, PEPPER)
    assert row["prefix"] == prefix_of(raw)
    assert raw not in caplog.text
    assert repr(issued).count(raw) == 0


async def test_authenticate_accepts_only_the_real_key(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, _ = tenants
    repository = SqlAlchemyApiKeyRepository(session)
    async with transaction(session):
        issued = await repository.create(
            acme.id, name="primary", scopes=["chat:invoke"], pepper=PEPPER
        )

    # A correct prefix with a wrong secret: the case a prefix-only lookup misses.
    forgery = prefix_of(issued.raw_key) + "A" * 34

    # Act
    good = await repository.authenticate(issued.raw_key, pepper=PEPPER)
    forged = await repository.authenticate(forgery, pepper=PEPPER)
    unknown = await repository.authenticate(generate_api_key(PEPPER).raw_key, pepper=PEPPER)

    # Assert
    assert good is not None and good.id == issued.record.id
    assert forged is None
    assert unknown is None


async def test_authenticate_rejects_revoked_and_expired_keys(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, _ = tenants
    repository = SqlAlchemyApiKeyRepository(session)
    async with transaction(session):
        revoked = await repository.create(acme.id, name="revoked", scopes=[], pepper=PEPPER)
        expired = await repository.create(
            acme.id,
            name="expired",
            scopes=[],
            pepper=PEPPER,
            expires_at=utc_now() - timedelta(seconds=1),
        )
        await repository.revoke(acme.id, revoked.record.id)

    # Act / Assert
    assert await repository.authenticate(revoked.raw_key, pepper=PEPPER) is None
    assert await repository.authenticate(expired.raw_key, pepper=PEPPER) is None


async def test_cross_tenant_api_key_lookup_returns_nothing(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, globex = tenants
    repository = SqlAlchemyApiKeyRepository(session)
    async with transaction(session):
        issued = await repository.create(acme.id, name="primary", scopes=[], pepper=PEPPER)

    # Act -- Globex asks for a key it does not own, by its exact id.
    stolen = await repository.get(globex.id, issued.record.id)
    listed = await repository.list_for_tenant(globex.id)
    revoked = await repository.revoke(globex.id, issued.record.id)

    # Assert
    assert stolen is None
    assert listed == []
    assert revoked is None


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------
async def test_duplicate_policy_version_is_rejected(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, _ = tenants
    repository = SqlAlchemyPolicyRepository(session)
    async with transaction(session):
        await repository.create_version(acme.id, name="default", version=1, document=POLICY_DOC)

    # Act / Assert
    with pytest.raises(IntegrityError):
        async with transaction(session):
            await repository.create_version(acme.id, name="default", version=1, document=POLICY_DOC)


async def test_same_version_is_allowed_for_a_different_tenant(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, globex = tenants
    repository = SqlAlchemyPolicyRepository(session)

    # Act
    async with transaction(session):
        first = await repository.create_version(
            acme.id, name="default", version=1, document=POLICY_DOC
        )
        second = await repository.create_version(
            globex.id, name="default", version=1, document=POLICY_DOC
        )

    # Assert
    assert first.id != second.id


async def test_activate_deactivates_the_other_versions(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, _ = tenants
    repository = SqlAlchemyPolicyRepository(session)
    async with transaction(session):
        v1 = await repository.create_version(
            acme.id, name="default", version=1, document=POLICY_DOC, is_active=True
        )
        v2 = await repository.create_version(
            acme.id, name="default", version=2, document=POLICY_DOC
        )

    # Act
    async with transaction(session):
        await repository.activate(acme.id, v2.id)
    active = await repository.get_active(acme.id)

    # Assert
    assert active is not None and active.id == v2.id
    await session.refresh(v1)
    assert v1.is_active is False


async def test_cross_tenant_policy_lookup_returns_nothing(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, globex = tenants
    repository = SqlAlchemyPolicyRepository(session)
    async with transaction(session):
        await repository.create_version(
            acme.id, name="default", version=1, document=POLICY_DOC, is_active=True
        )

    # Act
    assert await repository.get_active(globex.id) is None
    assert await repository.get_version(globex.id, name="default", version=1) is None
    assert await repository.list_versions(globex.id, name="default") == []
    # The default-policy accessor must never surface a tenant-owned row either.
    assert await repository.get_default() is None


# ---------------------------------------------------------------------------
# Provider configs
# ---------------------------------------------------------------------------
async def test_provider_config_stores_a_reference_not_a_secret(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, _ = tenants
    repository = SqlAlchemyProviderConfigRepository(session)

    # Act
    async with transaction(session):
        config = await repository.upsert(
            acme.id,
            alias="openai-primary",
            provider_type="openai",
            secret_ref="OPENAI_API_KEY",
            allowed_models=["general-chat"],
        )

    # Assert
    assert config.secret_ref == "OPENAI_API_KEY"
    assert not hasattr(config, "secret")
    assert not hasattr(config, "api_key")


@pytest.mark.parametrize(
    "candidate",
    ["sk-live-abc123def456", "lowercase_name", "HAS SPACE", "", "Bearer sk-abc"],
)
async def test_secret_values_are_rejected_as_secret_refs(
    session: AsyncSession, tenants: tuple[Tenant, Tenant], candidate: str
) -> None:
    # Arrange
    acme, _ = tenants
    repository = SqlAlchemyProviderConfigRepository(session)

    # Act / Assert
    with pytest.raises(ValueError, match="environment variable name"):
        await repository.upsert(
            acme.id,
            alias="openai-primary",
            provider_type="openai",
            secret_ref=candidate,
            allowed_models=[],
        )


async def test_cross_tenant_provider_config_lookup_returns_nothing(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, globex = tenants
    repository = SqlAlchemyProviderConfigRepository(session)
    async with transaction(session):
        await repository.upsert(
            acme.id,
            alias="openai-primary",
            provider_type="openai",
            secret_ref="OPENAI_API_KEY",
            allowed_models=[],
        )

    # Act / Assert
    assert await repository.get_by_alias(globex.id, "openai-primary") is None
    assert await repository.list_for_tenant(globex.id) == []
    assert await repository.disable(globex.id, "openai-primary") is None


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------
def test_audit_draft_has_no_field_that_could_hold_content() -> None:
    # Arrange / Act
    fields = {field.name for field in AuditEventDraft.__dataclass_fields__.values()}

    # Assert -- hmac fields are keyed digests, so they are named explicitly.
    assert fields & FORBIDDEN_AUDIT_FIELDS == set()
    assert "prompt_hmac" in fields
    assert "response_hmac" in fields


async def test_audit_event_persists_an_aware_timestamp(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, _ = tenants
    repository = SqlAlchemyAuditEventRepository(session)

    # Act
    async with transaction(session):
        await repository.record(
            AuditEventDraft(tenant_id=acme.id, request_id=uuid4(), status_code=200)
        )
    session.expunge_all()
    events = await repository.list_for_tenant(acme.id)

    # Assert
    assert len(events) == 1
    assert events[0].occurred_at.tzinfo is not None
    assert events[0].occurred_at.utcoffset() == timedelta(0)


async def test_cross_tenant_audit_lookup_returns_nothing(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, globex = tenants
    repository = SqlAlchemyAuditEventRepository(session)
    async with transaction(session):
        event = await repository.record(
            AuditEventDraft(tenant_id=acme.id, request_id=uuid4(), status_code=200)
        )

    # Act / Assert
    assert await repository.get(globex.id, event.id) is None
    assert await repository.list_for_tenant(globex.id) == []


async def test_audit_reads_are_bounded(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, _ = tenants
    repository = SqlAlchemyAuditEventRepository(session)

    # Act / Assert
    with pytest.raises(ValueError, match="limit must be between"):
        await repository.list_for_tenant(acme.id, limit=10_000)
    with pytest.raises(ValueError, match="offset"):
        await repository.list_for_tenant(acme.id, offset=-1)


async def test_audit_window_filters_by_occurred_at(
    session: AsyncSession, tenants: tuple[Tenant, Tenant]
) -> None:
    # Arrange
    acme, _ = tenants
    repository = SqlAlchemyAuditEventRepository(session)
    old = datetime(2020, 1, 1, tzinfo=UTC)
    async with transaction(session):
        await repository.record(
            AuditEventDraft(tenant_id=acme.id, request_id=uuid4(), status_code=200, occurred_at=old)
        )
        await repository.record(
            AuditEventDraft(tenant_id=acme.id, request_id=uuid4(), status_code=500)
        )

    # Act
    recent = await repository.list_for_tenant(acme.id, since=datetime(2025, 1, 1, tzinfo=UTC))

    # Assert
    assert len(recent) == 1
    assert recent[0].status_code == 500
