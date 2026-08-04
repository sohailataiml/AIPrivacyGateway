"""The plaintext payload that goes inside an envelope.

This is the only place in the vault where an original value exists as a
structured object. ``VaultRecord.__repr__`` is overridden so a traceback,
a ``logger.exception`` call, or a debugger frame dump cannot spill it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID

import orjson

from app.domain.errors import VaultEncryptionError

RECORD_SCHEMA_VERSION: Final = 1


@dataclass(frozen=True, slots=True)
class VaultRecord:
    """One token-to-original mapping, before encryption or after decryption."""

    tenant_id: UUID
    session_id: UUID
    token: str
    entity_type: str
    original_value: str
    created_at: datetime
    expires_at: datetime
    schema_version: int = RECORD_SCHEMA_VERSION

    def to_bytes(self) -> bytes:
        """Serialize to canonical JSON for encryption."""
        return orjson.dumps(
            {
                "schema_version": self.schema_version,
                "tenant_id": str(self.tenant_id),
                "session_id": str(self.session_id),
                "token": self.token,
                "entity_type": self.entity_type,
                "original_value": self.original_value,
                "created_at": self.created_at.astimezone(UTC).isoformat(),
                "expires_at": self.expires_at.astimezone(UTC).isoformat(),
            },
            option=orjson.OPT_SORT_KEYS,
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> VaultRecord:
        """Parse decrypted plaintext.

        Raises:
            VaultEncryptionError: if the payload is not a record this version
                understands. The error never carries the payload.
        """
        try:
            payload: Any = orjson.loads(raw)
        except orjson.JSONDecodeError:
            raise VaultEncryptionError(log_context={"reason": "record_not_json"}) from None

        if not isinstance(payload, dict):
            raise VaultEncryptionError(log_context={"reason": "record_not_object"})

        schema_version = payload.get("schema_version")
        if schema_version != RECORD_SCHEMA_VERSION:
            raise VaultEncryptionError(
                log_context={
                    "reason": "record_schema_unsupported",
                    "schema_version": schema_version,
                }
            )

        try:
            return cls(
                schema_version=RECORD_SCHEMA_VERSION,
                tenant_id=UUID(payload["tenant_id"]),
                session_id=UUID(payload["session_id"]),
                token=str(payload["token"]),
                entity_type=str(payload["entity_type"]),
                original_value=str(payload["original_value"]),
                created_at=datetime.fromisoformat(payload["created_at"]),
                expires_at=datetime.fromisoformat(payload["expires_at"]),
            )
        except (KeyError, TypeError, ValueError):
            raise VaultEncryptionError(log_context={"reason": "record_fields_invalid"}) from None

    def __repr__(self) -> str:
        # Deliberately omits original_value and token.
        return (
            f"VaultRecord(entity_type={self.entity_type!r}, schema_version={self.schema_version})"
        )
