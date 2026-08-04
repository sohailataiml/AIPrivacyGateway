"""Migration integration tests. Require a disposable PostgreSQL database.

Marked ``integration`` and skipped when ``TEST_DATABASE_URL`` is unset, so the
default unit run collects them without failing. Point them at a throwaway
database -- ``upgrade head`` followed by ``downgrade base`` runs against it and
the assertions destroy schema state::

    TEST_DATABASE_URL=postgresql+asyncpg://gateway:gateway@localhost:5432/gateway_test \\
        pytest tests/integration/test_migrations.py -m integration

These assertions are the ones SQLite cannot make: real ``JSONB`` columns,
``TIMESTAMP WITH TIME ZONE`` storage, and a downgrade that leaves no tables
behind.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_TABLES = frozenset({"tenants", "api_keys", "policies", "provider_configs", "audit_events"})

DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
requires_postgres = pytest.mark.skipif(
    not DATABASE_URL,
    reason="set TEST_DATABASE_URL to a disposable PostgreSQL database to run these",
)


def _alembic_config() -> Config:
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    return config


def _upgrade(connection: Connection, revision: str = "head") -> None:
    config = _alembic_config()
    config.attributes["connection"] = connection
    command.upgrade(config, revision)


def _downgrade(connection: Connection, revision: str = "base") -> None:
    config = _alembic_config()
    config.attributes["connection"] = connection
    command.downgrade(config, revision)


def _table_names(connection: Connection) -> set[str]:
    return set(sa.inspect(connection).get_table_names())


@pytest.fixture(scope="module")
def _clean_environment() -> Iterator[None]:
    """Point env.py at the disposable database for the duration of the module."""
    previous = os.environ.get("ALEMBIC_DATABASE_URL")
    if DATABASE_URL:
        os.environ["ALEMBIC_DATABASE_URL"] = DATABASE_URL
    yield
    if previous is None:
        os.environ.pop("ALEMBIC_DATABASE_URL", None)
    else:
        os.environ["ALEMBIC_DATABASE_URL"] = previous


@pytest.fixture
async def engine(_clean_environment: None) -> AsyncIterator[AsyncEngine]:
    assert DATABASE_URL is not None
    created = create_async_engine(DATABASE_URL, future=True)
    async with created.begin() as connection:
        await connection.run_sync(_downgrade)
    yield created
    async with created.begin() as connection:
        await connection.run_sync(_downgrade)
    await created.dispose()


@requires_postgres
async def test_upgrade_creates_every_table(engine: AsyncEngine) -> None:
    # Arrange / Act
    async with engine.begin() as connection:
        await connection.run_sync(_upgrade)
        tables = await connection.run_sync(_table_names)

    # Assert
    assert tables >= EXPECTED_TABLES


@requires_postgres
async def test_downgrade_removes_every_table(engine: AsyncEngine) -> None:
    # Arrange
    async with engine.begin() as connection:
        await connection.run_sync(_upgrade)

    # Act
    async with engine.begin() as connection:
        await connection.run_sync(_downgrade)
        tables = await connection.run_sync(_table_names)

    # Assert
    assert EXPECTED_TABLES & tables == set()


@requires_postgres
async def test_upgrade_downgrade_upgrade_is_repeatable(engine: AsyncEngine) -> None:
    # Arrange / Act
    async with engine.begin() as connection:
        await connection.run_sync(_upgrade)
        await connection.run_sync(_downgrade)
        await connection.run_sync(_upgrade)
        tables = await connection.run_sync(_table_names)

    # Assert
    assert tables >= EXPECTED_TABLES


@requires_postgres
async def test_json_columns_are_jsonb(engine: AsyncEngine) -> None:
    # Arrange
    async with engine.begin() as connection:
        await connection.run_sync(_upgrade)

    # Act
    async with engine.connect() as connection:
        result = await connection.execute(
            sa.text(
                "SELECT table_name, column_name, udt_name FROM information_schema.columns "
                "WHERE table_schema = 'public' "
                "AND column_name IN ('document', 'scopes', 'allowed_models', "
                "'entity_counts', 'actions')"
            )
        )
        rows = result.fetchall()

    # Assert
    assert rows
    assert {row.udt_name for row in rows} == {"jsonb"}


@requires_postgres
async def test_timestamp_columns_are_timezone_aware(engine: AsyncEngine) -> None:
    # Arrange
    async with engine.begin() as connection:
        await connection.run_sync(_upgrade)

    # Act
    async with engine.connect() as connection:
        result = await connection.execute(
            sa.text(
                "SELECT table_name, column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = 'public' AND data_type LIKE 'timestamp%'"
            )
        )
        rows = result.fetchall()

    # Assert
    assert rows
    assert {row.data_type for row in rows} == {"timestamp with time zone"}


@requires_postgres
async def test_duplicate_policy_version_violates_the_unique_constraint(
    engine: AsyncEngine,
) -> None:
    # Arrange
    async with engine.begin() as connection:
        await connection.run_sync(_upgrade)
    tenant_id = uuid4()
    now = datetime.now(UTC)

    # Act / Assert
    async with engine.begin() as connection:
        await connection.execute(
            sa.text(
                "INSERT INTO tenants (id, name, slug, status, created_at, updated_at) "
                "VALUES (:id, :name, :slug, 'active', :now, :now)"
            ),
            {"id": tenant_id, "name": "Acme", "slug": "acme", "now": now},
        )
        insert_policy = sa.text(
            "INSERT INTO policies "
            "(id, tenant_id, name, version, document, is_active, created_at, updated_at) "
            "VALUES (:id, :tenant_id, 'default', 1, '{}'::jsonb, false, :now, :now)"
        )
        await connection.execute(insert_policy, {"id": uuid4(), "tenant_id": tenant_id, "now": now})
        with pytest.raises(sa.exc.IntegrityError):
            await connection.execute(
                insert_policy, {"id": uuid4(), "tenant_id": tenant_id, "now": now}
            )


@requires_postgres
async def test_audit_events_primary_key_supports_monthly_partitioning(
    engine: AsyncEngine,
) -> None:
    # Arrange
    async with engine.begin() as connection:
        await connection.run_sync(_upgrade)

    # Act -- a RANGE-partitioned table requires the partition key in the PK.
    async with engine.connect() as connection:
        result = await connection.execute(
            sa.text(
                "SELECT a.attname FROM pg_index i "
                "JOIN pg_attribute a ON a.attrelid = i.indrelid "
                "AND a.attnum = ANY(i.indkey) "
                "WHERE i.indrelid = 'audit_events'::regclass AND i.indisprimary"
            )
        )
        key_columns = {row.attname for row in result.fetchall()}

    # Assert
    assert key_columns == {"id", "occurred_at"}
