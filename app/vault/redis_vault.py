"""Redis-backed encrypted token vault.

Key families, all namespaced by tenant *and* session::

    sgw:v1:{tenant_id}:{session_id}:token:{token_id}
    sgw:v1:{tenant_id}:{session_id}:fingerprint:{entity_type}:{digest}
    sgw:v1:{tenant_id}:{session_id}:meta

``digest`` is ``sha256(normalized_hmac)`` in hex. Hashing an already-hashed
value buys two things: the key name is guaranteed to be alphanumeric, so a
crafted fingerprint cannot inject ``:`` and escape its namespace; and the key
name is not the fingerprint preimage even for someone who obtains the HMAC key.
No key name contains an original value.

``meta`` is a set of every key belonging to the session. It exists so
``delete_session`` is an exact, tenant-scoped operation rather than a ``SCAN``
across the keyspace.

This vault requires a client with ``decode_responses=False``: envelopes are
binary and would be corrupted by UTF-8 decoding.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, cast
from uuid import UUID

from redis.exceptions import RedisError

from app.domain.errors import VaultEncryptionError, VaultUnavailableError
from app.tokenization.grammar import format_token, parse_token
from app.tokenization.ids import new_token_id
from app.vault.crypto import EnvelopeCipher, VaultAad
from app.vault.metrics import (
    OPERATION_DELETE_SESSION,
    OPERATION_GET_OR_CREATE,
    OPERATION_RESOLVE_MANY,
    OUTCOME_ENCRYPTION_ERROR,
    OUTCOME_UNAVAILABLE,
    RESULT_CREATED,
    RESULT_REUSED,
    observe,
    record_outcome,
    token_lookups,
)
from app.vault.records import VaultRecord
from app.vault.tokens import validate_entity_type

if TYPE_CHECKING:
    from redis.asyncio import Redis
    from redis.asyncio.client import Pipeline

logger = logging.getLogger("app.vault")

DEFAULT_KEY_PREFIX: Final = "sgw:v1"
MIN_TTL_SECONDS: Final = 1
MAX_TTL_SECONDS: Final = 7_200
"""Two hours -- the top of the configurable policy range."""

# A key-name segment, not a credential; S105 fires on the constant's name.
_TOKEN_SEGMENT: Final = ":token:"  # noqa: S105

_METRIC_OUTCOMES: Final[dict[type[BaseException], str]] = {
    VaultUnavailableError: OUTCOME_UNAVAILABLE,
    VaultEncryptionError: OUTCOME_ENCRYPTION_ERROR,
}


@contextmanager
def _store_failures_fail_closed(operation: str) -> Iterator[None]:
    """Translate any backing-store failure into a closed failure.

    A caller must never be able to mistake an outage for "no mappings found",
    so every ``RedisError`` and socket error becomes ``VaultUnavailableError``.
    """
    try:
        yield
    except (RedisError, OSError) as exc:
        logger.warning(
            "vault backing store unavailable",
            extra={"vault_operation": operation, "failure_type": type(exc).__name__},
        )
        raise VaultUnavailableError(log_context={"operation": operation}) from exc


def _as_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value)


def _as_binary(value: object) -> bytes:
    """Return a stored envelope as bytes.

    A client configured with ``decode_responses=True`` has already mangled the
    envelope beyond recovery, so that configuration is rejected rather than
    guessed at.
    """
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value)
    raise VaultEncryptionError(log_context={"reason": "client_decodes_responses"})


class RedisTokenVault:
    """``TokenVault`` backed by Redis with AES-256-GCM envelope encryption."""

    __slots__ = ("_cipher", "_prefix", "_redis")

    def __init__(
        self,
        redis: Redis,
        cipher: EnvelopeCipher,
        *,
        key_prefix: str = DEFAULT_KEY_PREFIX,
    ) -> None:
        self._redis = redis
        self._cipher = cipher
        self._prefix = key_prefix

    # -- Key construction -------------------------------------------------
    def _session_prefix(self, tenant_id: UUID, session_id: UUID) -> str:
        return f"{self._prefix}:{tenant_id}:{session_id}"

    @staticmethod
    def _token_key(session_prefix: str, token_id: str) -> str:
        return f"{session_prefix}{_TOKEN_SEGMENT}{token_id}"

    @staticmethod
    def _fingerprint_key(session_prefix: str, entity_type: str, normalized_hmac: str) -> str:
        digest = hashlib.sha256(normalized_hmac.encode("utf-8")).hexdigest()
        return f"{session_prefix}:fingerprint:{entity_type}:{digest}"

    @staticmethod
    def _meta_key(session_prefix: str) -> str:
        return f"{session_prefix}:meta"

    # -- TokenVault -------------------------------------------------------
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
        validate_entity_type(entity_type)
        ttl = _validated_ttl(ttl_seconds)
        if not normalized_hmac:
            raise ValueError("normalized_hmac must not be empty")

        with observe(OPERATION_GET_OR_CREATE, outcomes=_METRIC_OUTCOMES):
            session_prefix = self._session_prefix(tenant_id, session_id)
            fingerprint_key = self._fingerprint_key(session_prefix, entity_type, normalized_hmac)
            meta_key = self._meta_key(session_prefix)

            # Seal before opening the transaction: a WATCH retry must not
            # re-encrypt, and an encryption failure must not leave a half-open
            # transaction behind.
            candidate_id = new_token_id()
            candidate_token = format_token(entity_type, candidate_id)
            candidate_key = self._token_key(session_prefix, candidate_id)
            envelope = self._seal(
                tenant_id=tenant_id,
                session_id=session_id,
                entity_type=entity_type,
                token=candidate_token,
                token_id=candidate_id,
                original_value=original_value,
                ttl_seconds=ttl,
            )

            async def apply(pipe: Pipeline) -> tuple[str, bool]:
                existing = await pipe.get(fingerprint_key)
                if existing is not None:
                    reused = _as_text(existing)
                    parsed = parse_token(reused)
                    if parsed is not None:
                        reused_key = self._token_key(session_prefix, parsed.token_id)
                        if await pipe.exists(reused_key):
                            # redis-py leaves multi() unannotated.
                            pipe.multi()  # type: ignore[no-untyped-call]
                            pipe.expire(fingerprint_key, ttl)
                            pipe.expire(reused_key, ttl)
                            pipe.expire(meta_key, ttl)
                            return reused, False
                    # Index entry is unparseable or its record is gone: fall
                    # through and mint a replacement rather than hand back a
                    # token that cannot resolve.

                pipe.multi()  # type: ignore[no-untyped-call]
                pipe.set(candidate_key, envelope, ex=ttl)
                pipe.set(fingerprint_key, candidate_token, ex=ttl)
                pipe.sadd(meta_key, candidate_key, fingerprint_key)
                pipe.expire(meta_key, ttl)
                return candidate_token, True

            with _store_failures_fail_closed(OPERATION_GET_OR_CREATE):
                token, created = cast(
                    tuple[str, bool],
                    await self._redis.transaction(apply, fingerprint_key, value_from_callable=True),
                )

        record_outcome(result=RESULT_CREATED if created else RESULT_REUSED)
        return token

    async def resolve_many(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        tokens: set[str],
    ) -> dict[str, str]:
        with observe(OPERATION_RESOLVE_MANY, outcomes=_METRIC_OUTCOMES):
            session_prefix = self._session_prefix(tenant_id, session_id)

            # Sorted for a deterministic MGET argument order.
            wanted: list[tuple[str, str, str]] = []
            for token in sorted(tokens):
                parsed = parse_token(token)
                if parsed is None:
                    continue
                entity_type, token_id = parsed.entity_type, parsed.token_id
                wanted.append((token, entity_type, token_id))

            if not wanted:
                token_lookups(resolved=0, missing=len(tokens))
                return {}

            keys = [self._token_key(session_prefix, token_id) for _, _, token_id in wanted]
            with _store_failures_fail_closed(OPERATION_RESOLVE_MANY):
                raw_values = await self._redis.mget(keys)

            resolved: dict[str, str] = {}
            for (token, entity_type, token_id), raw in zip(wanted, raw_values, strict=True):
                if raw is None:
                    continue
                record = self._unseal(
                    raw=_as_binary(raw),
                    tenant_id=tenant_id,
                    session_id=session_id,
                    entity_type=entity_type,
                    token_id=token_id,
                )
                if record.token != token:
                    logger.warning(
                        "vault record token mismatch",
                        extra={"vault_operation": OPERATION_RESOLVE_MANY},
                    )
                    raise VaultEncryptionError(log_context={"reason": "record_token_mismatch"})
                resolved[token] = record.original_value

        token_lookups(resolved=len(resolved), missing=len(tokens) - len(resolved))
        return resolved

    async def delete_session(self, *, tenant_id: UUID, session_id: UUID) -> int:
        with observe(OPERATION_DELETE_SESSION, outcomes=_METRIC_OUTCOMES):
            session_prefix = self._session_prefix(tenant_id, session_id)
            meta_key = self._meta_key(session_prefix)

            with _store_failures_fail_closed(OPERATION_DELETE_SESSION):
                members = await self._redis.smembers(meta_key)
                member_keys = [_as_text(member) for member in members]
                # Belt and braces: the meta set is authoritative, but a member
                # outside this session's namespace is never deleted.
                owned = [key for key in member_keys if key.startswith(f"{session_prefix}:")]
                record_keys = [key for key in owned if _TOKEN_SEGMENT in key]
                index_keys = [key for key in owned if _TOKEN_SEGMENT not in key]

                pipe = self._redis.pipeline(transaction=True)
                if record_keys:
                    pipe.delete(*record_keys)
                if index_keys:
                    pipe.delete(*index_keys)
                pipe.delete(meta_key)
                results = await pipe.execute()

            deleted = int(results[0]) if record_keys else 0

        return deleted

    # -- Internals --------------------------------------------------------
    def _seal(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        entity_type: str,
        token: str,
        token_id: str,
        original_value: str,
        ttl_seconds: int,
    ) -> bytes:
        now = datetime.now(UTC)
        record = VaultRecord(
            tenant_id=tenant_id,
            session_id=session_id,
            token=token,
            entity_type=entity_type,
            original_value=original_value,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        aad = VaultAad(
            tenant_id=tenant_id,
            session_id=session_id,
            entity_type=entity_type,
            token_id=token_id,
        )
        try:
            return self._cipher.seal(plaintext=record.to_bytes(), aad=aad)
        except VaultEncryptionError:
            # Reason codes and entity type only. Never the record, never the
            # original value, never the token.
            logger.error(
                "vault record could not be sealed",
                extra={
                    "vault_operation": OPERATION_GET_OR_CREATE,
                    "entity_type": entity_type,
                },
            )
            raise

    def _unseal(
        self,
        *,
        raw: bytes,
        tenant_id: UUID,
        session_id: UUID,
        entity_type: str,
        token_id: str,
    ) -> VaultRecord:
        aad = VaultAad(
            tenant_id=tenant_id,
            session_id=session_id,
            entity_type=entity_type,
            token_id=token_id,
        )
        try:
            plaintext = self._cipher.unseal(raw=raw, aad=aad)
            return VaultRecord.from_bytes(plaintext)
        except VaultEncryptionError:
            logger.error(
                "vault record could not be opened",
                extra={
                    "vault_operation": OPERATION_RESOLVE_MANY,
                    "entity_type": entity_type,
                },
            )
            raise


def _validated_ttl(ttl_seconds: int) -> int:
    if not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError(f"ttl_seconds must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS}")
    return ttl_seconds
