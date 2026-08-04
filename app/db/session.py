"""Async engine, session factory, and the transaction boundary helper.

Nothing in this module ever logs or repr's the connection URL: it carries the
database password. ``build_engine`` takes a ``SecretStr`` precisely so a stray
f-string cannot leak it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from pydantic import SecretStr
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config.settings import Settings

DEFAULT_POOL_SIZE = 10
DEFAULT_MAX_OVERFLOW = 5
DEFAULT_POOL_TIMEOUT_SECONDS = 10
DEFAULT_POOL_RECYCLE_SECONDS = 1_800


def build_engine(
    database_url: SecretStr,
    *,
    echo: bool = False,
    pool_size: int = DEFAULT_POOL_SIZE,
    max_overflow: int = DEFAULT_MAX_OVERFLOW,
) -> AsyncEngine:
    """Create an async engine.

    ``echo`` is exposed for local debugging only. It must stay ``False`` in any
    deployed environment: SQLAlchemy echo prints bound parameters, which for
    this schema includes API key hashes and audit correlation HMACs.
    """
    url = database_url.get_secret_value()
    if url.startswith("sqlite"):
        # SQLite ignores server-side pooling knobs and rejects them outright.
        return create_async_engine(url, echo=echo, future=True)

    return create_async_engine(
        url,
        echo=echo,
        future=True,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=DEFAULT_POOL_TIMEOUT_SECONDS,
        pool_recycle=DEFAULT_POOL_RECYCLE_SECONDS,
    )


def build_engine_from_settings(settings: Settings) -> AsyncEngine:
    """Create the application engine from typed settings."""
    return build_engine(settings.database_url)


def build_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create the process-wide session factory.

    ``expire_on_commit`` is off so a caller can still read attributes of an
    object after the transaction closes without triggering lazy IO on a
    connection that no longer exists.
    """
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


async def dispose_engine(engine: AsyncEngine) -> None:
    """Close every pooled connection. Call during application shutdown."""
    await engine.dispose()


@asynccontextmanager
async def transaction(session: AsyncSession) -> AsyncIterator[AsyncSession]:
    """Run a unit of work, committing on success and rolling back on any error.

    ``BaseException`` is caught rather than ``Exception`` so that cancellation
    -- an ordinary event in an async server under load -- also rolls back
    instead of leaving a half-applied transaction on a pooled connection. The
    exception is always re-raised; nothing is swallowed.
    """
    try:
        yield session
    except BaseException:
        await session.rollback()
        raise
    else:
        await session.commit()
