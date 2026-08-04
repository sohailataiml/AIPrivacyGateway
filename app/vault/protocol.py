"""The vault seam.

Every consumer -- the pipeline, restoration, the session API -- depends on this
Protocol and never on ``RedisTokenVault``. Two properties are contractual:

1. Every method is scoped by both ``tenant_id`` and ``session_id``. There is no
   global lookup by token id, so possessing a token is not sufficient to
   resolve it.
2. Failure is closed. An implementation that cannot reach its backing store
   raises ``VaultUnavailableError``; it never returns an empty or partial
   result that a caller could read as "nothing to restore".
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable
from uuid import UUID


@runtime_checkable
class TokenVault(Protocol):
    """Stores and resolves short-lived encrypted token mappings."""

    async def get_or_create(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        entity_type: str,
        normalized_hmac: str,
        original_value: str,
        ttl_seconds: int,
    ) -> str:
        """Return the token for ``original_value`` within this session.

        Repeated calls with the same ``normalized_hmac`` return the same token,
        including under concurrency. Returns the full token string, e.g.
        ``⟦SGW:EMAIL_ADDRESS:01J8Z6J4M7Y9Q2K3T4V5W6X7Y8⟧``.

        Raises:
            VaultUnavailableError: the backing store could not be reached.
            VaultEncryptionError: the record could not be sealed.
        """
        ...

    async def resolve_many(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        tokens: set[str],
    ) -> dict[str, str]:
        """Map tokens to their original values in one round trip.

        Tokens that do not belong to this tenant and session -- including
        expired ones and ones minted for another session -- are absent from the
        result. Absence is the only signal; no distinction is made between
        "never existed", "expired", and "belongs to someone else".

        Raises:
            VaultUnavailableError: the backing store could not be reached.
            VaultEncryptionError: a stored record failed authentication.
        """
        ...

    async def delete_session(self, *, tenant_id: UUID, session_id: UUID) -> int:
        """Remove every mapping for one session. Returns records removed."""
        ...
