"""Keyed fingerprints that make repeated values reuse one token.

The fingerprint is an HMAC-SHA256 over::

    tenant_id || session_id || entity_type || normalized_value

It is an internal lookup index only. It never leaves the gateway, is never
logged, and is never sent to a provider. Keying it means an attacker holding
vault ciphertext cannot confirm a guessed value by recomputing the digest, and
scoping it by tenant and session means the same value in two sessions produces
two unrelated indexes.

Fields are length-prefixed before hashing, so no combination of inputs can be
re-parsed as a different combination -- ``("AB", "C")`` and ``("A", "BC")``
hash differently by construction.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final
from uuid import UUID

from pydantic import SecretStr

from app.config.settings import Settings, get_settings

FINGERPRINT_LABEL: Final = b"sgw:tokenization:fingerprint:v1"
"""Domain-separation label for the derived subkey."""

MIN_KEY_BYTES: Final = 16
_LENGTH_PREFIX_BYTES: Final = 4


def derive_fingerprint_key(root_secret: bytes) -> bytes:
    """Derive the tokenization subkey from a root secret.

    Deriving rather than using the root directly keeps this use cryptographically
    independent of whatever else that secret protects: recovering a fingerprint
    key would not recover the root, and the two never produce the same digest
    for the same message.
    """
    if len(root_secret) < MIN_KEY_BYTES:
        raise ValueError(f"the fingerprint root secret must be at least {MIN_KEY_BYTES} bytes")
    return hmac.new(root_secret, FINGERPRINT_LABEL, hashlib.sha256).digest()


def _root_secret(settings: Settings) -> bytes:
    """Resolve the root secret for fingerprinting.

    A dedicated ``tokenization_hmac_key`` setting is preferred and used
    automatically once it exists. Until then the audit HMAC key is the root; the
    label-based derivation above keeps the two uses independent.
    """
    dedicated = getattr(settings, "tokenization_hmac_key", None)
    if isinstance(dedicated, SecretStr):
        return dedicated.get_secret_value().encode("utf-8")
    return settings.audit_hmac_key.get_secret_value().encode("utf-8")


def _frame(*parts: bytes) -> bytes:
    """Length-prefix each part so the concatenation is unambiguous."""
    return b"".join(len(part).to_bytes(_LENGTH_PREFIX_BYTES, "big") + part for part in parts)


class Fingerprinter:
    """Computes keyed fingerprints. Holds a secret, so it never reprs its state."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        if len(key) < MIN_KEY_BYTES:
            raise ValueError(f"the fingerprint key must be at least {MIN_KEY_BYTES} bytes")
        self._key = key

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> Fingerprinter:
        """Build a fingerprinter from application settings."""
        resolved = settings if settings is not None else get_settings()
        return cls(derive_fingerprint_key(_root_secret(resolved)))

    def fingerprint(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        entity_type: str,
        normalized_value: str,
    ) -> str:
        """Return the hex fingerprint for one normalized value in one session."""
        message = _frame(
            tenant_id.bytes,
            session_id.bytes,
            entity_type.encode("utf-8"),
            normalized_value.encode("utf-8"),
        )
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def __repr__(self) -> str:
        # A stray repr() in a traceback must not print key material.
        return "Fingerprinter(key=<redacted>)"
