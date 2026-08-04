"""AES-256-GCM envelope encryption for vault records.

This module is deliberately standalone: it knows nothing about Redis, sessions,
or the pipeline. Given a key ring and some associated data it produces opaque
bytes, and given those bytes back it either returns the exact plaintext or
raises. There is no third outcome.

Envelope wire format (version 1), big-endian, no padding::

    offset  size  field
    0       4     magic  b"SGWV"
    4       1     version (1)
    5       1     key id length in bytes (1..255)
    6       n     key id, UTF-8
    6+n     12    GCM nonce, fresh random bytes per record
    18+n    ..    ciphertext with the 16-byte GCM tag appended

The key id travels *with* the record, which is what lets a rotated key ring
still open records sealed before the rotation.

Associated data binds each record to the tenant, session, entity type, and
token id it was created for. AES-GCM authenticates -- but does not encrypt --
the AAD, so a record moved to another tenant, another session, another entity
type, or another token id fails authentication instead of decrypting. This is
the cross-tenant defence; do not weaken it by dropping a field.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.domain.errors import VaultEncryptionError

if TYPE_CHECKING:
    from app.vault.keys import VaultKeyRing

ENVELOPE_MAGIC: Final = b"SGWV"
ENVELOPE_VERSION: Final = 1
NONCE_BYTES: Final = 12
"""96-bit nonce -- the size AES-GCM is specified for. Never reused."""

GCM_TAG_BYTES: Final = 16
MAX_KEY_ID_BYTES: Final = 255

_HEADER = struct.Struct("!4sBB")
_AAD_DOMAIN: Final = b"sgw.vault.aad.v1"


@dataclass(frozen=True, slots=True)
class VaultAad:
    """The identity a record is cryptographically bound to."""

    tenant_id: UUID
    session_id: UUID
    entity_type: str
    token_id: str

    def to_bytes(self) -> bytes:
        """Serialize unambiguously.

        Every field is length-prefixed so no combination of values can produce
        the same byte string as a different combination.
        """
        fields = (
            _AAD_DOMAIN,
            bytes((ENVELOPE_VERSION,)),
            str(self.tenant_id).encode("utf-8"),
            str(self.session_id).encode("utf-8"),
            self.entity_type.encode("utf-8"),
            self.token_id.encode("utf-8"),
        )
        return b"".join(len(field).to_bytes(2, "big") + field for field in fields)


@dataclass(frozen=True, slots=True)
class Envelope:
    """A parsed stored record. ``ciphertext`` includes the GCM tag."""

    version: int
    key_id: str
    nonce: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        key_id = self.key_id.encode("utf-8")
        if not 0 < len(key_id) <= MAX_KEY_ID_BYTES:
            raise VaultEncryptionError(log_context={"reason": "key_id_length_invalid"})
        header = _HEADER.pack(ENVELOPE_MAGIC, self.version, len(key_id))
        return header + key_id + self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, raw: bytes) -> Envelope:
        """Parse a stored record.

        Raises:
            VaultEncryptionError: for any malformed or truncated input. The
                error carries a reason code only -- never a byte of the record.
        """
        if len(raw) < _HEADER.size:
            raise VaultEncryptionError(log_context={"reason": "envelope_truncated"})

        magic, version, key_id_length = _HEADER.unpack_from(raw)
        if magic != ENVELOPE_MAGIC:
            raise VaultEncryptionError(log_context={"reason": "envelope_magic_mismatch"})
        if version != ENVELOPE_VERSION:
            raise VaultEncryptionError(
                log_context={"reason": "envelope_version_unsupported", "version": version}
            )
        if key_id_length == 0:
            raise VaultEncryptionError(log_context={"reason": "envelope_key_id_missing"})

        key_id_end = _HEADER.size + key_id_length
        nonce_end = key_id_end + NONCE_BYTES
        if len(raw) < nonce_end + GCM_TAG_BYTES:
            raise VaultEncryptionError(log_context={"reason": "envelope_truncated"})

        try:
            key_id = raw[_HEADER.size : key_id_end].decode("utf-8")
        except UnicodeDecodeError:
            raise VaultEncryptionError(log_context={"reason": "envelope_key_id_invalid"}) from None

        return cls(
            version=version,
            key_id=key_id,
            nonce=raw[key_id_end:nonce_end],
            ciphertext=raw[nonce_end:],
        )

    def __repr__(self) -> str:
        # Never render ciphertext or nonce material into a traceback.
        return (
            f"Envelope(version={self.version}, key_id={self.key_id!r}, size={len(self.ciphertext)})"
        )


class EnvelopeCipher:
    """Seals and unseals vault records under a rotating key ring."""

    __slots__ = ("_key_ring",)

    def __init__(self, key_ring: VaultKeyRing) -> None:
        self._key_ring = key_ring

    def seal(self, *, plaintext: bytes, aad: VaultAad) -> bytes:
        """Encrypt under the active key and return the serialized envelope."""
        key_id = self._key_ring.active_key_id
        key = self._key_ring.key(key_id)
        nonce = os.urandom(NONCE_BYTES)
        try:
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad.to_bytes())
        except Exception as exc:  # pragma: no cover - defensive
            raise VaultEncryptionError(log_context={"reason": "seal_failed"}) from exc
        return Envelope(
            version=ENVELOPE_VERSION,
            key_id=key_id,
            nonce=nonce,
            ciphertext=ciphertext,
        ).to_bytes()

    def unseal(self, *, raw: bytes, aad: VaultAad) -> bytes:
        """Authenticate and decrypt a stored envelope.

        Raises:
            VaultEncryptionError: if the envelope is malformed, its key id is
                not on the ring, the ciphertext was modified, or the associated
                data does not match. All four cases are indistinguishable to a
                caller by design.
        """
        envelope = Envelope.from_bytes(raw)
        key = self._key_ring.key(envelope.key_id)
        try:
            return AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext, aad.to_bytes())
        except InvalidTag:
            raise VaultEncryptionError(log_context={"reason": "authentication_failed"}) from None
        except ValueError as exc:
            raise VaultEncryptionError(log_context={"reason": "unseal_failed"}) from exc
