"""API key generation, storage, and verification.

The security model in one paragraph: a raw key is 32 bytes from ``secrets``,
rendered as ``sgw_live_<base64url>``. It is returned to the caller of
``generate_api_key`` exactly once and is never written to the database, a log,
or a metric. What persists is a non-secret ``prefix`` for operator
identification and an HMAC-SHA256 digest of the *whole* raw key keyed by a
pepper held outside the database. An attacker with a full database dump has no
offline attack worth running: they lack the pepper, and even with it the key
space is 256 bits.

Verification recomputes the digest and compares with ``hmac.compare_digest`` so
a timing side channel cannot reveal a prefix of the correct digest.

Two protocols live here on purpose. ``ApiKeyRepository`` is tenant-scoped:
every method demands a tenant id, so no call can surface another tenant's row.
``ApiKeyAuthenticator`` is the one pre-tenant entry point -- authentication has
to establish the tenant, so it cannot already know it. It is narrow by design:
it accepts the raw credential and returns a record only when the supplied
secret verifies, so possession of the key is the price of the lookup.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utc_now
from app.db.models import API_KEY_STATUS_ACTIVE, API_KEY_STATUS_REVOKED, ApiKey

KEY_LABEL = "sgw_live_"
"""Human-readable environment marker. Part of the raw key and of the prefix."""

KEY_RANDOM_BYTES = 32
"""256 bits of entropy. The floor required by implementation.md, not a target."""

PREFIX_BODY_CHARS = 8
"""How much of the random body is retained as the non-secret prefix.

Eight base64url characters carry 48 bits: enough that operators never see a
collision, far too little to brute-force the remaining 208 bits.
"""


def _encode_body(raw_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")


@dataclass(frozen=True, slots=True)
class GeneratedApiKey:
    """A freshly minted key. ``raw_key`` exists only in memory, only once."""

    raw_key: str
    prefix: str
    key_hash: str

    def __repr__(self) -> str:
        # Defensive: a traceback or a debugger repr must not print the secret.
        return f"GeneratedApiKey(prefix={self.prefix!r}, raw_key=***)"


@dataclass(frozen=True, slots=True)
class IssuedApiKey:
    """The persisted record paired with its one-time raw credential."""

    record: ApiKey
    raw_key: str

    def __repr__(self) -> str:
        return f"IssuedApiKey(id={self.record.id!r}, raw_key=***)"


def hash_api_key(raw_key: str, pepper: SecretStr) -> str:
    """Return the stored representation of ``raw_key``.

    HMAC-SHA256 rather than a password hash: the input is 256 bits of uniform
    randomness, so there is nothing to slow an attacker down about. The pepper
    lives in the environment, which keeps the digest useless on its own.
    """
    return hmac.new(
        pepper.get_secret_value().encode("utf-8"),
        raw_key.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_api_key(raw_key: str, stored_hash: str, pepper: SecretStr) -> bool:
    """Constant-time check of a presented key against its stored digest."""
    return hmac.compare_digest(hash_api_key(raw_key, pepper), stored_hash)


def generate_api_key(pepper: SecretStr) -> GeneratedApiKey:
    """Mint a new key. The caller is responsible for showing ``raw_key`` once."""
    body = _encode_body(secrets.token_bytes(KEY_RANDOM_BYTES))
    raw_key = f"{KEY_LABEL}{body}"
    return GeneratedApiKey(
        raw_key=raw_key,
        prefix=f"{KEY_LABEL}{body[:PREFIX_BODY_CHARS]}",
        key_hash=hash_api_key(raw_key, pepper),
    )


def prefix_of(raw_key: str) -> str:
    """Derive the stored prefix from a presented raw key."""
    return raw_key[: len(KEY_LABEL) + PREFIX_BODY_CHARS]


class ApiKeyRepository(Protocol):
    """Tenant-scoped management of API key records."""

    async def get(self, tenant_id: UUID, api_key_id: UUID) -> ApiKey | None: ...

    async def list_for_tenant(self, tenant_id: UUID) -> list[ApiKey]: ...

    async def create(
        self,
        tenant_id: UUID,
        *,
        name: str,
        scopes: list[str],
        pepper: SecretStr,
        expires_at: datetime | None = None,
    ) -> IssuedApiKey:
        """Mint and persist a key, returning the raw value exactly once."""
        ...

    async def revoke(self, tenant_id: UUID, api_key_id: UUID) -> ApiKey | None: ...

    async def touch_last_used(
        self, tenant_id: UUID, api_key_id: UUID, *, when: datetime
    ) -> None: ...


class ApiKeyAuthenticator(Protocol):
    """The single pre-tenant lookup: resolve a raw credential to its record."""

    async def authenticate(self, raw_key: str, *, pepper: SecretStr) -> ApiKey | None:
        """Return the key record when ``raw_key`` verifies, otherwise ``None``.

        Returns ``None`` identically for an unknown prefix, a bad secret, a
        revoked key, and an expired key, so a caller cannot probe for which
        prefixes exist.
        """
        ...


class SqlAlchemyApiKeyRepository:
    """``ApiKeyRepository`` and ``ApiKeyAuthenticator`` over one async session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, tenant_id: UUID, api_key_id: UUID) -> ApiKey | None:
        result = await self._session.execute(
            select(ApiKey).where(ApiKey.tenant_id == tenant_id, ApiKey.id == api_key_id)
        )
        return result.scalar_one_or_none()

    async def list_for_tenant(self, tenant_id: UUID) -> list[ApiKey]:
        result = await self._session.execute(
            select(ApiKey).where(ApiKey.tenant_id == tenant_id).order_by(ApiKey.created_at)
        )
        return list(result.scalars().all())

    async def create(
        self,
        tenant_id: UUID,
        *,
        name: str,
        scopes: list[str],
        pepper: SecretStr,
        expires_at: datetime | None = None,
    ) -> IssuedApiKey:
        if expires_at is not None and expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")

        generated = generate_api_key(pepper)
        record = ApiKey(
            tenant_id=tenant_id,
            name=name,
            prefix=generated.prefix,
            key_hash=generated.key_hash,
            scopes=list(scopes),
            status=API_KEY_STATUS_ACTIVE,
            expires_at=expires_at,
        )
        self._session.add(record)
        await self._session.flush()
        return IssuedApiKey(record=record, raw_key=generated.raw_key)

    async def revoke(self, tenant_id: UUID, api_key_id: UUID) -> ApiKey | None:
        record = await self.get(tenant_id, api_key_id)
        if record is None:
            return None
        record.status = API_KEY_STATUS_REVOKED
        await self._session.flush()
        return record

    async def touch_last_used(self, tenant_id: UUID, api_key_id: UUID, *, when: datetime) -> None:
        if when.tzinfo is None:
            raise ValueError("last_used_at must be timezone-aware")
        record = await self.get(tenant_id, api_key_id)
        if record is None:
            return
        record.last_used_at = when
        await self._session.flush()

    async def authenticate(self, raw_key: str, *, pepper: SecretStr) -> ApiKey | None:
        result = await self._session.execute(
            select(ApiKey).where(ApiKey.prefix == prefix_of(raw_key))
        )
        record = result.scalar_one_or_none()
        if record is None:
            # Still spend the digest so an unknown prefix is not measurably
            # faster than a wrong secret.
            hash_api_key(raw_key, pepper)
            return None
        if not verify_api_key(raw_key, record.key_hash, pepper):
            return None
        if not record.is_usable(now=utc_now()):
            return None
        return record
