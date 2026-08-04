"""Encrypted session vault.

Public surface:

* ``TokenVault`` -- the Protocol every consumer depends on.
* ``RedisTokenVault`` -- the production implementation.
* ``InMemoryTokenVault`` -- a fake for other packages' tests.
* ``EnvelopeCipher`` / ``VaultAad`` -- standalone AES-256-GCM envelopes.
* ``StaticKeyRing`` / ``SettingsKeyRing`` -- rotation-capable key rings.
"""

from __future__ import annotations

from app.tokenization.grammar import format_token, parse_token
from app.tokenization.ids import new_token_id
from app.vault.crypto import (
    ENVELOPE_VERSION,
    NONCE_BYTES,
    Envelope,
    EnvelopeCipher,
    VaultAad,
)
from app.vault.fakes import InMemoryTokenVault
from app.vault.keys import SettingsKeyRing, StaticKeyRing, VaultKeyRing
from app.vault.protocol import TokenVault
from app.vault.records import RECORD_SCHEMA_VERSION, VaultRecord
from app.vault.redis_vault import DEFAULT_KEY_PREFIX, RedisTokenVault

__all__ = [
    "DEFAULT_KEY_PREFIX",
    "ENVELOPE_VERSION",
    "NONCE_BYTES",
    "RECORD_SCHEMA_VERSION",
    "Envelope",
    "EnvelopeCipher",
    "InMemoryTokenVault",
    "RedisTokenVault",
    "SettingsKeyRing",
    "StaticKeyRing",
    "TokenVault",
    "VaultAad",
    "VaultKeyRing",
    "VaultRecord",
    "format_token",
    "new_token_id",
    "parse_token",
]
