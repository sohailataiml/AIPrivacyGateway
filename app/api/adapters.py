"""Adapters across the seams between independently-built packages.

Each package here was built against a ``Protocol`` describing what it needed,
not against the concrete class that would eventually supply it. That kept them
independently testable, and it means the shapes do not line up exactly at the
composition root. Three joins need translating:

- ``PolicyService`` wants ``get_active_policy() -> StoredPolicy``; the
  repository offers ``get_active() -> Policy`` (a SQLAlchemy row).
- ``AuditService`` writes through an ``AuditSink`` and runs on a background
  queue, so it needs a database session of its own per write rather than the
  request-scoped one.
- The pipeline hands the audit service a loose field bag; that translation lives
  in :mod:`app.audit.pipeline_adapter`, which the audit package owns.

Keeping the translations here rather than bending either side means neither
package grows a dependency on the other, and the seams stay visible in one file
instead of being spread across the modules they join.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import TYPE_CHECKING
from uuid import UUID

from app.audit.service import AuditSink
from app.policy.models import StoredPolicy
from app.repositories.audit_events import AuditEventDraft, SqlAlchemyAuditEventRepository
from app.repositories.policies import SqlAlchemyPolicyRepository

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.ext.asyncio import AsyncSession

SessionScope = Callable[[], AbstractAsyncContextManager["AsyncSession"]]
"""Opens a short-lived session. Each call must yield a fresh one."""


class PolicyRepositoryAdapter:
    """Presents the repository as the ``PolicyRepository`` the policy service wants.

    A session is opened per lookup rather than held: policy resolution happens
    once per request and the result is cached, so a long-lived session would
    pin a connection for no benefit.
    """

    __slots__ = ("_session_scope",)

    def __init__(self, session_scope: SessionScope) -> None:
        self._session_scope = session_scope

    async def get_active_policy(self, tenant_id: UUID) -> StoredPolicy | None:
        async with self._session_scope() as session:
            row = await SqlAlchemyPolicyRepository(session).get_active(tenant_id)
            if row is None:
                return None
            # Read every attribute inside the session: the row is detached once
            # the scope closes, and a lazy load would then raise.
            return StoredPolicy(
                policy_id=row.id,
                tenant_id=row.tenant_id,
                version=row.version,
                document=dict(row.document),
            )


class AuditSinkAdapter(AuditSink):
    """Persists audit drafts from the background writer.

    The audit queue drains outside any request, so it cannot borrow a
    request-scoped session. It opens its own per write, which also means a slow
    or failing audit write cannot hold a connection that a live request needs.
    """

    __slots__ = ("_session_scope",)

    def __init__(self, session_scope: SessionScope) -> None:
        self._session_scope = session_scope

    async def record(self, draft: AuditEventDraft) -> object:
        async with self._session_scope() as session:
            event = await SqlAlchemyAuditEventRepository(session).record(draft)
            await session.commit()
            return event


__all__ = ["AuditSinkAdapter", "PolicyRepositoryAdapter", "SessionScope"]
