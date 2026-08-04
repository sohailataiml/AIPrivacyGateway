"""Provider configuration repository.

Every method takes a tenant id because a provider alias is tenant-local: two
tenants may both call an alias ``openai-primary`` and they must resolve to
different rows with different secret references.

This repository stores ``secret_ref`` -- the *name* of an environment variable.
``resolve_secret`` is the only place the value is read, it is read from the
process environment, and it is never written back.
"""

from __future__ import annotations

import os
from typing import Protocol
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import SECRET_REF_PATTERN, ProviderConfig


def resolve_secret(secret_ref: str) -> SecretStr | None:
    """Read the credential named by ``secret_ref`` from the environment.

    Returns ``None`` when the variable is unset so callers fail closed with a
    configuration error rather than sending an empty credential upstream.
    """
    if not SECRET_REF_PATTERN.match(secret_ref):
        raise ValueError("secret_ref is not a valid environment variable name")
    raw = os.environ.get(secret_ref)
    return SecretStr(raw) if raw else None


class ProviderConfigRepository(Protocol):
    """Tenant-scoped access to provider aliases and their non-secret settings."""

    async def get_by_alias(self, tenant_id: UUID, alias: str) -> ProviderConfig | None: ...

    async def list_for_tenant(self, tenant_id: UUID) -> list[ProviderConfig]: ...

    async def upsert(
        self,
        tenant_id: UUID,
        *,
        alias: str,
        provider_type: str,
        secret_ref: str,
        allowed_models: list[str],
        connect_timeout_seconds: int = 5,
        read_timeout_seconds: int = 60,
        max_retries: int = 2,
        is_enabled: bool = True,
    ) -> ProviderConfig:
        """Create or update the alias. ``secret_ref`` must name an env var."""
        ...

    async def disable(self, tenant_id: UUID, alias: str) -> ProviderConfig | None: ...


class SqlAlchemyProviderConfigRepository:
    """``ProviderConfigRepository`` backed by an async SQLAlchemy session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_alias(self, tenant_id: UUID, alias: str) -> ProviderConfig | None:
        result = await self._session.execute(
            select(ProviderConfig).where(
                ProviderConfig.tenant_id == tenant_id,
                ProviderConfig.alias == alias,
            )
        )
        return result.scalar_one_or_none()

    async def list_for_tenant(self, tenant_id: UUID) -> list[ProviderConfig]:
        result = await self._session.execute(
            select(ProviderConfig)
            .where(ProviderConfig.tenant_id == tenant_id)
            .order_by(ProviderConfig.alias)
        )
        return list(result.scalars().all())

    async def upsert(
        self,
        tenant_id: UUID,
        *,
        alias: str,
        provider_type: str,
        secret_ref: str,
        allowed_models: list[str],
        connect_timeout_seconds: int = 5,
        read_timeout_seconds: int = 60,
        max_retries: int = 2,
        is_enabled: bool = True,
    ) -> ProviderConfig:
        existing = await self.get_by_alias(tenant_id, alias)
        if existing is None:
            existing = ProviderConfig(tenant_id=tenant_id, alias=alias)
            self._session.add(existing)

        # Assigning secret_ref runs the model validator, which rejects anything
        # that does not look like an environment variable name.
        existing.provider_type = provider_type
        existing.secret_ref = secret_ref
        existing.allowed_models = list(allowed_models)
        existing.connect_timeout_seconds = connect_timeout_seconds
        existing.read_timeout_seconds = read_timeout_seconds
        existing.max_retries = max_retries
        existing.is_enabled = is_enabled
        await self._session.flush()
        return existing

    async def disable(self, tenant_id: UUID, alias: str) -> ProviderConfig | None:
        config = await self.get_by_alias(tenant_id, alias)
        if config is None:
            return None
        config.is_enabled = False
        await self._session.flush()
        return config
