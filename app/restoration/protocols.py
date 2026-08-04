"""The two seams the output pipeline depends on.

Both are structural. Restoration must not import ``app.policy`` or
``app.vault``: it needs one field from a policy snapshot and one method from a
vault, and depending on those packages would drag their settings, database, and
Redis machinery into a stage that runs after the provider has already replied.

``VaultLike`` deliberately exposes *only* ``resolve_many``. Restoration can
therefore neither mint a mapping nor delete a session, and -- because every
parameter is tenant- and session-scoped -- there is no shape of call it can make
that looks up a token by identifier alone.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable
from uuid import UUID

from app.domain.models import UnknownTokenAction


@runtime_checkable
class VaultLike(Protocol):
    """The one vault operation restoration is allowed to perform."""

    async def resolve_many(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        tokens: set[str],
    ) -> dict[str, str]:
        """Map tokens to their original values for this tenant and session.

        Tokens belonging to another tenant or session, expired tokens, and
        tokens that never existed are all simply absent from the result. The
        caller cannot tell those cases apart, and must not try.

        Raises:
            VaultUnavailableError: the backing store could not be reached.
        """
        ...


@runtime_checkable
class PolicyLike(Protocol):
    """The one policy field restoration reads.

    Declared as a read-only property so that a frozen dataclass -- which is what
    ``PolicySnapshot`` is -- satisfies it, while restoration itself is statically
    prevented from writing to policy.
    """

    @property
    def unknown_output_token_action(self) -> UnknownTokenAction:
        """What to do with a token-shaped string that does not resolve."""
        ...
