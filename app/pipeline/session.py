"""Session identity for one request.

Exactly one session id is resolved per request and every message is processed
under it. That is what makes a value repeated across a system prompt and a user
turn collapse onto a single token: the tokenizer's fingerprint is scoped by
``(tenant_id, session_id, entity_type, normalized_value)``, so two messages only
agree if they were handed the same session.

Resolution is deliberately dumb. A caller-supplied id is used as given -- the
vault is tenant-scoped, so an id borrowed from another tenant resolves nothing
-- and an absent id mints a fresh random one.
"""

from __future__ import annotations

from typing import Final
from uuid import UUID, uuid4

from app.domain.errors import InvalidRequestError

NIL_SESSION_ID: Final[UUID] = UUID(int=0)
"""The all-zero UUID. Refused: it is the value a broken client sends when it
means "I have no session", and accepting it would merge unrelated conversations
inside one tenant into a single mapping namespace."""


def resolve_session_id(requested: UUID | None) -> UUID:
    """Return the one session id this request will use for every message.

    Args:
        requested: The caller's session id, or ``None`` to start a new session.

    Returns:
        The session id. Stable for the life of the request.

    Raises:
        InvalidRequestError: if the caller supplied the nil UUID.
    """
    if requested is None:
        return uuid4()
    if requested == NIL_SESSION_ID:
        raise InvalidRequestError(log_context={"reason": "session_id_must_not_be_nil"})
    return requested
