"""Tenant repository.

The tenant aggregate is the root of every ownership chain, so "tenant-scoped"
here means the tenant's own identity is always the lookup key. There is no
``list_all`` and no way to page through other people's tenants.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import TENANT_STATUS_ACTIVE, TENANT_STATUSES, Tenant


class TenantRepository(Protocol):
    """Read and write access to tenant records."""

    async def get(self, tenant_id: UUID) -> Tenant | None:
        """Return the tenant with this id, or ``None``."""
        ...

    async def get_by_slug(self, slug: str) -> Tenant | None:
        """Resolve a tenant by its stable slug.

        Bootstrap and administration only -- the slug *is* a tenant identifier,
        so this is identity resolution rather than a cross-tenant read.
        """
        ...

    async def create(self, *, name: str, slug: str, status: str = TENANT_STATUS_ACTIVE) -> Tenant:
        """Insert a tenant. Raises on a duplicate slug."""
        ...

    async def set_status(self, tenant_id: UUID, status: str) -> Tenant | None:
        """Change a tenant's status. Returns ``None`` if the tenant is unknown."""
        ...


class SqlAlchemyTenantRepository:
    """``TenantRepository`` backed by an async SQLAlchemy session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, tenant_id: UUID) -> Tenant | None:
        result = await self._session.execute(select(Tenant).where(Tenant.id == tenant_id))
        return result.scalar_one_or_none()

    async def get_by_slug(self, slug: str) -> Tenant | None:
        result = await self._session.execute(select(Tenant).where(Tenant.slug == slug))
        return result.scalar_one_or_none()

    async def create(self, *, name: str, slug: str, status: str = TENANT_STATUS_ACTIVE) -> Tenant:
        if status not in TENANT_STATUSES:
            raise ValueError(f"unknown tenant status; expected one of {TENANT_STATUSES}")
        tenant = Tenant(name=name, slug=slug, status=status)
        self._session.add(tenant)
        await self._session.flush()
        return tenant

    async def set_status(self, tenant_id: UUID, status: str) -> Tenant | None:
        if status not in TENANT_STATUSES:
            raise ValueError(f"unknown tenant status; expected one of {TENANT_STATUSES}")
        tenant = await self.get(tenant_id)
        if tenant is None:
            return None
        tenant.status = status
        await self._session.flush()
        return tenant
