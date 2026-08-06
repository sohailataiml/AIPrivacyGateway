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

from typing import TYPE_CHECKING, Protocol, runtime_checkable
from uuid import UUID

if TYPE_CHECKING:
    from collections.abc import Sequence

    from app.domain.models import VaultWriteRequest


@runtime_checkable
class TokenVault(Protocol):
    """Stores and resolves short-lived encrypted token mappings.

    Both directions are batched, per ADR-0022: the number of round trips an
    implementation makes does not vary with the number of tokens. There is
    deliberately no single-token write method, because the only way to use one
    for a request carrying many entities is a loop.
    """

    async def get_or_create_many(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        entries: Sequence[VaultWriteRequest],
        ttl_seconds: int,
    ) -> tuple[str, ...]:
        """Return one token per entry, minting what does not already exist.

        The result is positionally aligned with ``entries``. Each token is the
        full token string, e.g.
        ``⟦SGW:EMAIL_ADDRESS:01J8Z6J4M7Y9Q2K3T4V5W6X7Y8⟧``.

        Entries repeating the same ``entity_type`` and ``normalized_hmac``
        receive the same token, and so do repeated calls -- including when two
        requests race. That is what makes a value appearing twice in one prompt
        collapse onto one token.

        The batch is all-or-nothing from the caller's point of view: either
        every returned token has a stored, resolvable mapping, or the call
        raises. A partial result is never returned as success.

        Raises:
            VaultUnavailableError: the backing store could not be reached.
            VaultEncryptionError: a record could not be sealed.
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
