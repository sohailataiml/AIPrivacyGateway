"""Audit event repository.

``AuditEventDraft`` is the only way to construct a row. It is the enforcement
point for the prohibited-field list in architecture.md section 9.9: there is no
field on it for message content, response content, original values, decrypted
mappings, complete gateway tokens, or credentials, so a future caller cannot
pass one in by mistake. ``prompt_hmac`` and ``response_hmac`` are keyed digests
computed elsewhere and are useful only for correlation.

Reads are tenant-scoped and always bounded by a limit. An unbounded audit query
is both a performance hazard and, in a multi-tenant system, the kind of endpoint
that turns one bug into a full-table disclosure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utc_now
from app.db.models import AuditEvent

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1_000


@dataclass(frozen=True, slots=True)
class AuditEventDraft:
    """Privacy-safe description of one completed request."""

    tenant_id: UUID
    request_id: UUID
    status_code: int
    occurred_at: datetime | None = None
    api_key_id: UUID | None = None
    session_id_hash: str | None = None
    policy_id: UUID | None = None
    policy_version: int | None = None
    provider_alias: str | None = None
    model_alias: str | None = None
    input_character_count: int = 0
    output_character_count: int = 0
    entity_counts: dict[str, Any] = field(default_factory=dict)
    actions: dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    block_reason_code: str | None = None
    provider_latency_ms: int | None = None
    pipeline_latency_ms: int | None = None
    error_code: str | None = None
    prompt_hmac: str | None = None
    response_hmac: str | None = None


class AuditEventRepository(Protocol):
    """Append-only, tenant-scoped audit storage."""

    async def record(self, draft: AuditEventDraft) -> AuditEvent:
        """Append one event. Audit rows are never updated or deleted in place."""
        ...

    async def list_for_tenant(
        self,
        tenant_id: UUID,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> list[AuditEvent]:
        """Return the tenant's events, newest first, bounded by ``limit``."""
        ...

    async def get(self, tenant_id: UUID, event_id: UUID) -> AuditEvent | None: ...


class SqlAlchemyAuditEventRepository:
    """``AuditEventRepository`` backed by an async SQLAlchemy session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record(self, draft: AuditEventDraft) -> AuditEvent:
        occurred_at = draft.occurred_at or utc_now()
        if occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")

        event = AuditEvent(
            id=uuid4(),
            occurred_at=occurred_at,
            tenant_id=draft.tenant_id,
            request_id=draft.request_id,
            api_key_id=draft.api_key_id,
            session_id_hash=draft.session_id_hash,
            policy_id=draft.policy_id,
            policy_version=draft.policy_version,
            provider_alias=draft.provider_alias,
            model_alias=draft.model_alias,
            input_character_count=draft.input_character_count,
            output_character_count=draft.output_character_count,
            entity_counts=dict(draft.entity_counts),
            actions=dict(draft.actions),
            blocked=draft.blocked,
            block_reason_code=draft.block_reason_code,
            provider_latency_ms=draft.provider_latency_ms,
            pipeline_latency_ms=draft.pipeline_latency_ms,
            status_code=draft.status_code,
            error_code=draft.error_code,
            prompt_hmac=draft.prompt_hmac,
            response_hmac=draft.response_hmac,
        )
        self._session.add(event)
        await self._session.flush()
        return event

    async def list_for_tenant(
        self,
        tenant_id: UUID,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> list[AuditEvent]:
        if limit < 1 or limit > MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
        if offset < 0:
            raise ValueError("offset must not be negative")

        statement = select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
        if since is not None:
            statement = statement.where(AuditEvent.occurred_at >= since)
        if until is not None:
            statement = statement.where(AuditEvent.occurred_at < until)

        result = await self._session.execute(
            statement.order_by(AuditEvent.occurred_at.desc()).limit(limit).offset(offset)
        )
        return list(result.scalars().all())

    async def get(self, tenant_id: UUID, event_id: UUID) -> AuditEvent | None:
        result = await self._session.execute(
            select(AuditEvent).where(
                AuditEvent.tenant_id == tenant_id,
                AuditEvent.id == event_id,
            )
        )
        return result.scalar_one_or_none()
