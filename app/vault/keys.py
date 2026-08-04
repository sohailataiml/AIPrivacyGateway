"""Vault encryption key ring.

The vault never holds a single key. It holds a *ring*: one active key used for
every new write, plus every retired key id that might still appear in a stored
envelope. That is what makes rotation a configuration change rather than a
migration -- records written before a rotation keep decrypting under the key id
recorded inside their own envelope.

Nothing in this module logs, formats, or reprs a key. ``StaticKeyRing`` is a
plain container whose ``__repr__`` is overridden for the same reason.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from app.domain.errors import VaultEncryptionError

if TYPE_CHECKING:
    from app.config.settings import Settings

VAULT_KEY_BYTES = 32
"""AES-256-GCM key length."""


@runtime_checkable
class VaultKeyRing(Protocol):
    """Supplies the active encryption key and resolves historical key ids."""

    @property
    def active_key_id(self) -> str:
        """Id of the key every new record is sealed under."""
        ...

    def key(self, key_id: str) -> bytes:
        """Return the raw 32-byte key for ``key_id``.

        Raises:
            VaultEncryptionError: if the id is unknown or the key is malformed.
        """
        ...


def _validated(key: bytes) -> bytes:
    if len(key) != VAULT_KEY_BYTES:
        # The length is a property of the configuration, not of any secret.
        raise VaultEncryptionError(log_context={"reason": "key_length_invalid"})
    return key


class StaticKeyRing:
    """An explicit in-memory ring. Used by tests and by direct construction."""

    __slots__ = ("_active_key_id", "_keys")

    def __init__(self, keys: dict[str, bytes], *, active_key_id: str) -> None:
        if active_key_id not in keys:
            raise ValueError("active_key_id must be present in the key ring")
        self._keys = {key_id: _validated(value) for key_id, value in keys.items()}
        self._active_key_id = active_key_id

    @property
    def active_key_id(self) -> str:
        return self._active_key_id

    def key(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise VaultEncryptionError(log_context={"reason": "unknown_key_id"}) from None

    def __repr__(self) -> str:
        return f"StaticKeyRing(active_key_id={self._active_key_id!r}, size={len(self._keys)})"


class SettingsKeyRing:
    """Ring backed by ``Settings``. The only ring a running gateway uses."""

    __slots__ = ("_settings",)

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def active_key_id(self) -> str:
        return self._settings.vault_active_key_id.lower()

    def key(self, key_id: str) -> bytes:
        try:
            raw = self._settings.vault_key(key_id)
        except ValueError:
            raise VaultEncryptionError(log_context={"reason": "unknown_key_id"}) from None
        return _validated(raw)

    def __repr__(self) -> str:
        return f"SettingsKeyRing(active_key_id={self.active_key_id!r})"
