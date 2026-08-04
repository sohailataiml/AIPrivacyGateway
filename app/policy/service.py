"""Resolution of the active policy snapshot for a request.

:meth:`PolicyService.resolve` is the first thing the pipeline calls and the
first place a request can be refused. The provider and model allowlist checks
live here, before detection runs and long before any provider client is
constructed, so a request for an unpermitted destination costs nothing and
leaks nothing.

The service depends on a ``Protocol``, not on a concrete repository. That keeps
this package testable against an in-memory fake and keeps the persistence layer
free to change.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol
from uuid import UUID

from app.domain.errors import (
    InvalidRequestError,
    ModelNotAllowedError,
    PolicyNotFoundError,
    ProviderNotAllowedError,
)
from app.policy.models import PolicyDocument, PolicySnapshot, StoredPolicy
from app.policy.validation import validate_policy_document

POLICY_CACHE_TTL_SECONDS: Final[float] = 30.0
"""How long a resolved snapshot is reused before the repository is asked again.

Short on purpose. A policy change is a security control, so the window in which
a revoked provider or a loosened threshold is still honoured has to be measured
in seconds, not minutes. Long enough to spare the database one query per
request under load; short enough that an operator sees the effect of an edit
within one health-check interval.
"""


class PolicyRepository(Protocol):
    """The persistence surface this package needs.

    Deliberately narrow: one read. The policy engine never writes, so it cannot
    be the thing that activates an unvalidated document.
    """

    async def get_active_policy(self, tenant_id: UUID) -> StoredPolicy | None:
        """Return the tenant's active policy row, or ``None`` if it has none."""
        ...


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    """One cached snapshot and the moment it stops being trustworthy."""

    key: tuple[UUID, int]
    """The snapshot's identity: ``(tenant_id, policy version)``."""

    snapshot: PolicySnapshot
    expires_at: float


class PolicyService:
    """Resolves and briefly caches the active policy snapshot per tenant.

    Only policy documents are cached. Nothing here holds a credential, a
    provider secret, a session mapping, or a detected value -- the cache
    contains exactly the configuration an operator could read from the
    ``policies`` table.
    """

    def __init__(
        self,
        repository: PolicyRepository,
        *,
        cache_ttl_seconds: float = POLICY_CACHE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._repository = repository
        self._cache_ttl_seconds = cache_ttl_seconds
        self._clock = clock
        # Indexed by tenant so a lookup is possible before the version is
        # known; each entry carries its own ``(tenant_id, version)`` identity.
        self._entries: dict[UUID, _CacheEntry] = {}

    async def resolve(self, *, tenant_id: UUID, provider: str, model: str) -> PolicySnapshot:
        """Resolve the active policy and authorize the requested destination.

        Args:
            tenant_id: The authenticated principal's tenant.
            provider: The requested provider alias.
            model: The requested model alias.

        Returns:
            The immutable, versioned snapshot for this request.

        Raises:
            PolicyNotFoundError: the tenant has no active policy, or the stored
                document no longer satisfies the policy schema.
            ProviderNotAllowedError: the provider is outside the allowlist.
            ModelNotAllowedError: the model is outside the provider's allowlist.
        """
        snapshot = await self._active_snapshot(tenant_id)

        # Aliases are caller-supplied routing labels, not secrets, so they are
        # safe to record for operators debugging a rejection.
        if not snapshot.allows_provider(provider):
            raise ProviderNotAllowedError(
                log_context={
                    "tenant_id": str(tenant_id),
                    "policy_version": snapshot.version,
                    "provider": provider,
                }
            )

        if not snapshot.allows_model(provider, model):
            raise ModelNotAllowedError(
                log_context={
                    "tenant_id": str(tenant_id),
                    "policy_version": snapshot.version,
                    "provider": provider,
                    "model": model,
                }
            )

        return snapshot

    def invalidate(self, tenant_id: UUID) -> None:
        """Drop one tenant's cached snapshot. Safe to call when absent."""
        self._entries.pop(tenant_id, None)

    def clear(self) -> None:
        """Drop every cached snapshot."""
        self._entries.clear()

    async def snapshot_for(self, tenant_id: UUID) -> PolicySnapshot:
        """Resolve the tenant's active policy without authorizing a route.

        ``resolve`` is the request path: it also checks a provider and model
        against the allowlist. Callers that genuinely have no route to authorize
        -- ``POST /v1/detect`` inspects text and names no provider -- need the
        snapshot alone, and forcing a provider argument on them would put a
        meaningless required field in a public API contract.

        This is deliberately not a way around the allowlist. It returns a policy
        for reading entity actions and thresholds; it grants nothing. Anything
        that will call a provider must go through ``resolve``.
        """
        return await self._active_snapshot(tenant_id)

    async def _active_snapshot(self, tenant_id: UUID) -> PolicySnapshot:
        now = self._clock()
        cached = self._entries.get(tenant_id)
        if cached is not None and cached.expires_at > now:
            return cached.snapshot

        stored = await self._repository.get_active_policy(tenant_id)
        if stored is None:
            # A stale entry must not outlive the row it was built from.
            self._entries.pop(tenant_id, None)
            raise PolicyNotFoundError(
                log_context={"tenant_id": str(tenant_id), "reason": "no_active_policy"}
            )

        snapshot = PolicySnapshot.from_document(
            self._validated_document(stored, tenant_id),
            policy_id=stored.policy_id,
            tenant_id=tenant_id,
            version=stored.version,
        )
        self._entries[tenant_id] = _CacheEntry(
            key=(tenant_id, stored.version),
            snapshot=snapshot,
            expires_at=now + self._cache_ttl_seconds,
        )
        return snapshot

    @staticmethod
    def _validated_document(stored: StoredPolicy, tenant_id: UUID) -> PolicyDocument:
        try:
            return validate_policy_document(stored.document)
        except InvalidRequestError as exc:
            # A row that fails validation is treated as no policy at all. The
            # alternative -- running on a partially understood document -- is
            # the one outcome this engine must never produce.
            raise PolicyNotFoundError(
                log_context={
                    "tenant_id": str(tenant_id),
                    "policy_id": str(stored.policy_id),
                    "policy_version": stored.version,
                    "reason": "stored_document_invalid",
                    "problems": exc.log_context.get("problems", ()),
                }
            ) from exc
