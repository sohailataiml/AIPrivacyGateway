"""Alembic environment, wired for the async engine.

The database URL never appears in ``alembic.ini``. It is read here from
``Settings`` (which itself reads the environment), which keeps the password out
of version control and out of Alembic's own logging.

``ALEMBIC_DATABASE_URL`` overrides it, which is how the integration test points
migrations at a disposable database without mutating process settings.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.config.settings import Settings
from app.db.base import Base
from app.db.models import (  # noqa: F401  -- imported so Base.metadata is populated
    ApiKey,
    AuditEvent,
    Policy,
    ProviderConfig,
    Tenant,
)

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    override = os.environ.get("ALEMBIC_DATABASE_URL")
    if override:
        return override
    return Settings().database_url.get_secret_value()


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        render_as_batch=connection.dialect.name == "sqlite",
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online_async() -> None:
    """Connect with the async engine and run migrations in one transaction."""
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()

    engine = async_engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_run_migrations)
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    """Entry point used when Alembic runs with a live database."""
    connectable = config.attributes.get("connection")
    if connectable is not None:
        # A caller (the integration test) supplied its own sync connection.
        _run_migrations(connectable)
        return
    asyncio.run(run_migrations_online_async())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
