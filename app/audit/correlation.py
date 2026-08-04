"""Keyed correlation digests for audit records.

ADR-0015 permits correlation of prompts and responses, but only through keyed
HMACs: a plain SHA-256 of a short prompt is a dictionary attack waiting to
happen, and audit rows are the one place in this system that outlive a session.

Three properties are load-bearing here.

**Independence from tokenization.** :mod:`app.tokenization.fingerprint` derives
its subkey from the same root secret using the label
``sgw:tokenization:fingerprint:v1``. This module uses
:data:`AUDIT_CORRELATION_LABEL`, a different label, so the audit chain and the
vault index are cryptographically unrelated: recovering one subkey reveals
nothing about the other, and neither ever produces the other's digest for the
same input.

**Domain separation between prompt and response.** The prompt and response
digests are computed under distinct domain constants, so a prompt digest can
never equal the response digest of the same text. Without that, an attacker who
learned one side of a conversation could recognize it on the other, and an
operator reading the table could not tell which direction a digest came from.

**Unambiguous framing.** Every input is length-prefixed before hashing, so no
regrouping of the same bytes produces the same digest -- two messages
``("AB", "C")`` cannot collide with ``("A", "BC")``.

Digests are internal metadata. They are never returned to a client, and they are
never logged: the logging allowlist in :mod:`app.observability.logging` has no
key that could carry one.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from typing import Final
from uuid import UUID

from pydantic import SecretStr

from app.config.settings import Settings, get_settings

AUDIT_CORRELATION_LABEL: Final = b"sgw:audit:correlation:v1"
"""Domain-separation label for the audit subkey. Must differ from every other
label derived from the same root secret."""

PROMPT_DOMAIN: Final = b"sgw:audit:prompt:v1"
RESPONSE_DOMAIN: Final = b"sgw:audit:response:v1"
SESSION_DOMAIN: Final = b"sgw:audit:session:v1"

MIN_KEY_BYTES: Final = 16
_LENGTH_PREFIX_BYTES: Final = 4


def derive_correlation_key(root_secret: bytes) -> bytes:
    """Derive the audit subkey from the configured root secret."""
    if len(root_secret) < MIN_KEY_BYTES:
        raise ValueError(f"the audit root secret must be at least {MIN_KEY_BYTES} bytes")
    return hmac.new(root_secret, AUDIT_CORRELATION_LABEL, hashlib.sha256).digest()


def _root_secret(settings: Settings) -> bytes:
    secret: SecretStr = settings.audit_hmac_key
    return secret.get_secret_value().encode("utf-8")


def _frame(*parts: bytes) -> bytes:
    """Length-prefix each part so the concatenation cannot be re-parsed."""
    return b"".join(len(part).to_bytes(_LENGTH_PREFIX_BYTES, "big") + part for part in parts)


class CorrelationHasher:
    """Computes the keyed digests that appear on an audit record.

    Holds key material, so it never reprs its state and never logs.

    Digests are scoped to a tenant. That is deliberate: an operator can see the
    same prompt recur within one tenant, which is the point of correlation,
    while the same text under two tenants produces two unrelated digests. The
    session id is *not* mixed in for prompt and response digests -- correlating
    a repeated prompt across the sessions of one tenant is exactly the signal
    this field exists to provide.
    """

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        if len(key) < MIN_KEY_BYTES:
            raise ValueError(f"the audit correlation key must be at least {MIN_KEY_BYTES} bytes")
        self._key = key

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> CorrelationHasher:
        """Build a hasher from application settings."""
        resolved = settings if settings is not None else get_settings()
        return cls(derive_correlation_key(_root_secret(resolved)))

    def prompt_digest(self, *, tenant_id: UUID, segments: Sequence[str]) -> str:
        """Digest the outbound conversation.

        ``segments`` is the message texts in order. Each is framed separately,
        so a conversation cannot be re-cut into a different one with the same
        digest.
        """
        return self._digest(
            PROMPT_DOMAIN,
            tenant_id,
            tuple(segment.encode("utf-8") for segment in segments),
        )

    def response_digest(self, *, tenant_id: UUID, text: str) -> str:
        """Digest one provider response."""
        return self._digest(RESPONSE_DOMAIN, tenant_id, (text.encode("utf-8"),))

    def session_digest(self, *, tenant_id: UUID, session_id: UUID) -> str:
        """Digest a session id for the ``session_id_hash`` column.

        The raw session id is an opaque handle, not a secret, but hashing it
        keeps the audit table free of a value that also addresses live vault
        records.
        """
        return self._digest(SESSION_DOMAIN, tenant_id, (session_id.bytes,))

    def _digest(self, domain: bytes, tenant_id: UUID, parts: tuple[bytes, ...]) -> str:
        message = _frame(domain, tenant_id.bytes, *parts)
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def __repr__(self) -> str:
        # A stray repr() in a traceback must not print key material.
        return "CorrelationHasher(key=<redacted>)"
