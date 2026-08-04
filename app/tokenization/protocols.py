"""Structural contracts the tokenizer depends on.

These are ``Protocol`` classes on purpose. The tokenizer must not import the
policy or vault packages: doing so would couple three independently built
modules and make this one impossible to test without a Redis instance and a
policy loader. Structural typing means the real implementations satisfy these
contracts without inheriting from anything, and an in-memory fake satisfies them
just as well.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from app.domain.models import EntityAction


class PolicyLike(Protocol):
    """The resolved, active privacy policy for one request.

    The two values are declared as read-only properties rather than mutable
    attributes on purpose: a policy is immutable for the life of a request, and
    a read-only member is satisfied by a plain attribute, a property, a frozen
    dataclass field, and a frozen pydantic model alike. Declaring them mutable
    would reject exactly the immutable implementations this codebase prefers.
    """

    @property
    def max_entities(self) -> int:
        """Upper bound on entities in a single transformation."""
        ...

    @property
    def session_ttl_seconds(self) -> int:
        """Lifetime applied to every vault mapping created for this session."""
        ...

    def action_for(self, entity_type: str) -> EntityAction:
        """Return the action to apply to spans of ``entity_type``."""
        ...

    def min_score_for(self, entity_type: str) -> float:
        """Return the confidence below which a detection of this type is ignored."""
        ...


class VaultLike(Protocol):
    """The session vault, from the tokenizer's point of view.

    ``get_or_create`` is expected to be atomic: concurrent calls with the same
    fingerprint must return the same token, which is what makes repeated values
    collapse onto one token within a session.
    """

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
        """Return the existing token for this fingerprint, or mint and store one."""
        ...
