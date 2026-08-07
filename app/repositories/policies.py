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

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utc_now
from app.db.models import POLICY_STATUS_DRAFT, POLICY_STATUS_PUBLISHED, Policy

DEFAULT_POLICY_NAME = "default"


class PublishedPolicyImmutableError(RuntimeError):
    """Raised when something tries to edit a version that is already published.

    A programming error rather than a caller error, which is why it is a
    ``RuntimeError`` and not a domain error with a public message: the API layer
    routes edits to drafts, so reaching this means a code path skipped that
    routing. Enforced here, at the last layer before the database, because
    "published versions are immutable" is worth less as a convention than as
    something a repository refuses to do.
    """


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

    async def list_names(self, tenant_id: UUID) -> list[str]:
        """Distinct policy names this tenant has any version of."""
        ...

    async def get_draft(self, tenant_id: UUID, *, name: str) -> Policy | None:
        """Return the open draft for ``name``, or ``None``."""
        ...

    async def next_version(self, tenant_id: UUID, *, name: str) -> int:
        """The version number a new draft for ``name`` would take."""
        ...

    async def create_draft(
        self, tenant_id: UUID, *, name: str, document: dict[str, Any]
    ) -> Policy: ...

    async def update_draft(
        self, tenant_id: UUID, *, name: str, document: dict[str, Any]
    ) -> Policy | None:
        """Replace a draft's document.

        Raises:
            PublishedPolicyImmutableError: if the row found is not a draft.
        """
        ...

    async def discard_draft(self, tenant_id: UUID, *, name: str) -> bool:
        """Delete the open draft. Returns whether one was there."""
        ...

    async def publish_draft(self, tenant_id: UUID, *, name: str) -> Policy | None:
        """Mark the draft published and active, deactivating earlier versions."""
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
        # Published on creation. This path is for callers that mint a finished
        # version directly -- the seed script, tests, the default policy -- and
        # a row created this way was never a draft. Drafts come from
        # `create_draft`, which is the only writer of `status='draft'`.
        policy = Policy(
            tenant_id=tenant_id,
            name=name,
            version=version,
            document=dict(document),
            is_active=is_active,
            status=POLICY_STATUS_PUBLISHED,
            published_at=utc_now(),
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

    # -- Draft lifecycle (ADR-0037) ---------------------------------------
    async def list_names(self, tenant_id: UUID) -> list[str]:
        result = await self._session.execute(
            select(Policy.name)
            .where(Policy.tenant_id == tenant_id)
            .distinct()
            .order_by(Policy.name)
        )
        return list(result.scalars().all())

    async def get_draft(self, tenant_id: UUID, *, name: str) -> Policy | None:
        result = await self._session.execute(
            select(Policy).where(
                Policy.tenant_id == tenant_id,
                Policy.name == name,
                Policy.status == POLICY_STATUS_DRAFT,
            )
        )
        return result.scalar_one_or_none()

    async def next_version(self, tenant_id: UUID, *, name: str) -> int:
        # Highest version of any status, so a draft already holding version N
        # does not hand the same number to a second draft.
        result = await self._session.execute(
            select(func.max(Policy.version)).where(
                Policy.tenant_id == tenant_id, Policy.name == name
            )
        )
        highest = result.scalar_one_or_none()
        return 1 if highest is None else int(highest) + 1

    async def create_draft(self, tenant_id: UUID, *, name: str, document: dict[str, Any]) -> Policy:
        """Open a draft at the next version number.

        A second concurrent call violates ``uq_policies_one_draft_per_name`` and
        raises ``IntegrityError``, which is the intended outcome: the database
        decides who won rather than a read-then-write race in the service.
        """
        policy = Policy(
            tenant_id=tenant_id,
            name=name,
            version=await self.next_version(tenant_id, name=name),
            document=dict(document),
            is_active=False,
            status=POLICY_STATUS_DRAFT,
            published_at=None,
        )
        self._session.add(policy)
        await self._session.flush()
        return policy

    async def update_draft(
        self, tenant_id: UUID, *, name: str, document: dict[str, Any]
    ) -> Policy | None:
        draft = await self.get_draft(tenant_id, name=name)
        if draft is None:
            return None
        if draft.status != POLICY_STATUS_DRAFT:  # pragma: no cover - guarded by the query
            raise PublishedPolicyImmutableError(f"policy {name!r} v{draft.version} is published")
        draft.document = dict(document)
        await self._session.flush()
        return draft

    async def discard_draft(self, tenant_id: UUID, *, name: str) -> bool:
        draft = await self.get_draft(tenant_id, name=name)
        if draft is None:
            return False
        await self._session.delete(draft)
        await self._session.flush()
        return True

    async def publish_draft(self, tenant_id: UUID, *, name: str) -> Policy | None:
        """Promote the draft to the active published version.

        The previous versions are deactivated but otherwise untouched: their
        documents, versions, and timestamps are exactly what they were, which is
        what makes "previous versions remain unchanged" true rather than
        aspirational. Only ``is_active`` moves, and only on rows that are not
        this one.
        """
        draft = await self.get_draft(tenant_id, name=name)
        if draft is None:
            return None

        await self._session.execute(
            update(Policy)
            .where(
                Policy.tenant_id == tenant_id,
                Policy.name == name,
                Policy.id != draft.id,
            )
            .values(is_active=False)
        )
        draft.status = POLICY_STATUS_PUBLISHED
        draft.is_active = True
        draft.published_at = utc_now()
        await self._session.flush()
        return draft
