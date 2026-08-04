"""Policy repository.

Policy documents are opaque JSON at this layer. Validating their shape belongs
to the policy engine; persisting them belongs here, and mixing the two would
couple the storage layer to a schema that is expected to version independently.

The built-in default policy is stored with ``tenant_id IS NULL``. Tenant-scoped
reads never see it -- ``get_default`` is a separate, explicitly named method, so
a tenant read cannot silently fall through to a row it does not own.
"""

from __future__ import annotations

from typing import Any, Protocol
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Policy

DEFAULT_POLICY_NAME = "default"


class PolicyRepository(Protocol):
    """Tenant-scoped access to versioned policy documents."""

    async def get_active(self, tenant_id: UUID) -> Policy | None:
        """Return the tenant's active policy, or ``None`` if it has none."""
        ...

    async def get_version(self, tenant_id: UUID, *, name: str, version: int) -> Policy | None: ...

    async def list_versions(self, tenant_id: UUID, *, name: str) -> list[Policy]: ...

    async def create_version(
        self,
        tenant_id: UUID,
        *,
        name: str,
        version: int,
        document: dict[str, Any],
        is_active: bool = False,
    ) -> Policy:
        """Insert a new version. Violating ``(tenant_id, name, version)`` raises."""
        ...

    async def activate(self, tenant_id: UUID, policy_id: UUID) -> Policy | None:
        """Make one version active and deactivate the tenant's other versions."""
        ...

    async def get_default(self) -> Policy | None:
        """Return the built-in default policy (``tenant_id IS NULL``).

        Deliberately not tenant-scoped because it belongs to no tenant. It can
        never return a tenant-owned row.
        """
        ...


class SqlAlchemyPolicyRepository:
    """``PolicyRepository`` backed by an async SQLAlchemy session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_active(self, tenant_id: UUID) -> Policy | None:
        result = await self._session.execute(
            select(Policy)
            .where(
                Policy.tenant_id == tenant_id,
                Policy.is_active.is_(True),
            )
            .order_by(Policy.version.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def get_version(self, tenant_id: UUID, *, name: str, version: int) -> Policy | None:
        result = await self._session.execute(
            select(Policy).where(
                Policy.tenant_id == tenant_id,
                Policy.name == name,
                Policy.version == version,
            )
        )
        return result.scalar_one_or_none()

    async def list_versions(self, tenant_id: UUID, *, name: str) -> list[Policy]:
        result = await self._session.execute(
            select(Policy)
            .where(Policy.tenant_id == tenant_id, Policy.name == name)
            .order_by(Policy.version)
        )
        return list(result.scalars().all())

    async def create_version(
        self,
        tenant_id: UUID,
        *,
        name: str,
        version: int,
        document: dict[str, Any],
        is_active: bool = False,
    ) -> Policy:
        if version < 1:
            raise ValueError("policy version must be a positive integer")
        policy = Policy(
            tenant_id=tenant_id,
            name=name,
            version=version,
            document=dict(document),
            is_active=is_active,
        )
        self._session.add(policy)
        await self._session.flush()
        return policy

    async def activate(self, tenant_id: UUID, policy_id: UUID) -> Policy | None:
        result = await self._session.execute(
            select(Policy).where(Policy.tenant_id == tenant_id, Policy.id == policy_id)
        )
        policy = result.scalar_one_or_none()
        if policy is None:
            return None

        await self._session.execute(
            update(Policy)
            .where(
                Policy.tenant_id == tenant_id,
                Policy.name == policy.name,
                Policy.id != policy_id,
            )
            .values(is_active=False)
        )
        policy.is_active = True
        await self._session.flush()
        return policy

    async def get_default(self) -> Policy | None:
        result = await self._session.execute(
            select(Policy)
            .where(
                Policy.tenant_id.is_(None),
                Policy.name == DEFAULT_POLICY_NAME,
                Policy.is_active.is_(True),
            )
            .order_by(Policy.version.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()
