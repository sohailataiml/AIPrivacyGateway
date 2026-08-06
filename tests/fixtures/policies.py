"""Policy snapshots and a policy source, for suites that need one of each.

The document analysis suites and the privacy sweep all need the same two
things: a snapshot built from an entity table stated inline, and something
satisfying ``PolicySource``. Building them per file is how one copy quietly
stops matching the real ``PolicyDocument`` schema.

Snapshots go through ``PolicyDocument`` rather than being constructed directly,
so a test policy that would be rejected in production is rejected here too.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final
from uuid import UUID

from app.policy.models import (
    POLICY_SCHEMA_VERSION,
    EntityRule,
    PolicyDocument,
    PolicySnapshot,
    ProviderRule,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

POLICY_ID: Final = UUID("77777777-7777-7777-7777-777777777777")


def snapshot(
    entities: Mapping[str, EntityRule],
    *,
    tenant_id: UUID,
    version: int = 7,
    max_entities: int = 500,
) -> PolicySnapshot:
    """A validated snapshot carrying exactly ``entities``.

    The default version is deliberately not 1: a test asserting that the
    version travels onto the result would pass against a hard-coded 1.
    """
    document = PolicyDocument(
        schema_version=POLICY_SCHEMA_VERSION,
        name="test",
        session_ttl_seconds=1800,
        max_entities=max_entities,
        providers={"mock": ProviderRule(models=("general-chat",))},
        entities=dict(entities),
    )
    return PolicySnapshot.from_document(
        document, policy_id=POLICY_ID, tenant_id=tenant_id, version=version
    )


class FakePolicySource:
    """A ``PolicySource`` that returns one snapshot and counts its calls."""

    def __init__(self, resolved: PolicySnapshot) -> None:
        self._snapshot = resolved
        self.call_count = 0
        self.tenants: list[UUID] = []

    async def snapshot_for(self, tenant_id: UUID) -> PolicySnapshot:
        self.call_count += 1
        self.tenants.append(tenant_id)
        return self._snapshot


class FailingPolicySource:
    """A ``PolicySource`` that always raises ``error``."""

    def __init__(self, error: Exception) -> None:
        self._error = error
        self.call_count = 0

    async def snapshot_for(self, tenant_id: UUID) -> PolicySnapshot:
        self.call_count += 1
        raise self._error


__all__ = ["POLICY_ID", "FailingPolicySource", "FakePolicySource", "snapshot"]
