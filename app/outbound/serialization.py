"""The exact bytes that leave, in one canonical framing.

ADR-0024 attests *the payload*, so there has to be one and it has to be stable:
the same request must always produce the same bytes, on any machine, in any
Python version, whatever a provider adapter later does with them.

It is deliberately **not** the provider's wire format. An OpenAI JSON body is
that adapter's business and would change with its SDK; attesting it would tie
the audit trail to a vendor and make an adapter upgrade silently invalidate
every old attestation. What is attested is the content the gateway decided to
send — roles, texts, routing aliases, policy version — in the gateway's own
framing.

Shared by every outbound path. `/v1/chat` and `/v1/documents/{id}/process` are
the same kind of event once protection has run, and two serializers would be
two things to keep in step.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from app.domain.models import ProtectedChatRequest

SERIALIZATION_VERSION: Final = b"sgw:outbound:v1"
"""Framing version, mixed into every payload.

An attestation is only meaningful against a known framing. Changing how a
payload is assembled without changing this label would make old digests
unverifiable while still looking verifiable.
"""

_LENGTH_PREFIX_BYTES: Final = 4


def serialize_outbound(request: ProtectedChatRequest) -> bytes:
    """Return the canonical bytes for one protected request.

    Every field is length-prefixed before concatenation, so no regrouping of
    the same bytes yields the same result -- two messages ``("AB", "C")``
    cannot collide with ``("A", "BC")``. The same reasoning, and the same
    framing, as ``app.audit.correlation``.

    Routing aliases and the policy version are inside the frame on purpose. The
    attestation should distinguish "this text, to this model, under this policy"
    from the same text sent somewhere else; a digest over the message bodies
    alone would call those identical.

    The request id is deliberately **outside** it. Two identical payloads must
    attest identically or the digest cannot be recomputed, and a digest nobody
    can recompute proves nothing.
    """
    parts: list[bytes] = [
        SERIALIZATION_VERSION,
        request.provider_alias.encode("utf-8"),
        request.model_alias.encode("utf-8"),
        str(request.policy_version).encode("ascii"),
        str(len(request.messages)).encode("ascii"),
    ]
    for message in request.messages:
        parts.append(message.role.encode("utf-8"))
        parts.append(message.content.encode("utf-8"))
    return _frame(*parts)


def outbound_text(request: ProtectedChatRequest) -> str:
    """The message content the scan runs over, in order.

    Separated from :func:`serialize_outbound` because the two want different
    things: the digest needs unambiguous framing, and the scanner needs text
    with offsets it can address. Joining with a newline keeps every message's
    content whole rather than letting two messages form a value across the
    join.
    """
    return "\n".join(message.content for message in request.messages)


def outbound_segments(request: ProtectedChatRequest) -> tuple[str, ...]:
    """The message texts, for the prompt correlation digest."""
    return tuple(message.content for message in request.messages)


def _frame(*parts: bytes) -> bytes:
    return b"".join(len(part).to_bytes(_LENGTH_PREFIX_BYTES, "big") + part for part in parts)


__all__ = [
    "SERIALIZATION_VERSION",
    "outbound_segments",
    "outbound_text",
    "serialize_outbound",
]
