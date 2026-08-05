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

A fingerprint key stores the bare 26-character *token id*, not the full token
string. The entity type is already part of the fingerprint key's own name, so
the token can be reassembled on read, and storing the id alone is what lets the
batch script derive a record key from an index entry without parsing the token
grammar inside Lua.

``meta`` is a set of every key belonging to the session. It exists so
``delete_session`` is an exact, tenant-scoped operation rather than a ``SCAN``
across the keyspace.

Writes are batched and atomic (ADR-0022): one ``EVALSHA`` per request, whatever
the entity count. Lua is what makes that possible -- a ``WATCH``/``MULTI``
transaction over N fingerprint keys would abort the entire batch whenever any
one of them changed, so contention would grow with batch size rather than stay
where it was per token.

This vault requires a client with ``decode_responses=False``: envelopes are
binary and would be corrupted by UTF-8 decoding.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, cast
from uuid import UUID

from redis.exceptions import RedisError

from app.domain.errors import VaultEncryptionError, VaultUnavailableError
from app.domain.models import VaultWriteRequest
from app.tokenization.grammar import format_token, is_valid_token_id, parse_token
from app.tokenization.ids import new_token_id
from app.vault.crypto import EnvelopeCipher, VaultAad
from app.vault.metrics import (
    OPERATION_DELETE_SESSION,
    OPERATION_GET_OR_CREATE_MANY,
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
    from redis.commands.core import AsyncScript

logger = logging.getLogger("app.vault")

DEFAULT_KEY_PREFIX: Final = "sgw:v1"
MIN_TTL_SECONDS: Final = 1
MAX_TTL_SECONDS: Final = 7_200
"""Two hours -- the top of the configurable policy range."""

MAX_BATCH_ENTRIES: Final = 10_000
"""Mirrors ``MAX_POLICY_ENTITY_BUDGET``.

The pipeline's entity budget already bounds a request long before this, so
reaching this ceiling means a caller bypassed it. Refusing here keeps a single
script invocation bounded regardless.
"""

_BATCH_WRITE_SCRIPT: Final = """
-- Atomic batch get-or-create. Redis runs this to completion with nothing
-- interleaved, so every entry gets the same create-or-reuse semantics the
-- single-token version had, without a WATCH retry loop whose abort rate would
-- climb with batch size.
--
-- KEYS[1]                meta set
-- KEYS[2 .. 1+n]         fingerprint (index) keys
-- KEYS[2+n .. 1+2n]      candidate record keys
-- ARGV[1]                ttl seconds
-- ARGV[2]                n
-- ARGV[3]                record-key prefix, for rebuilding an existing key
-- ARGV[4 .. 3+n]         candidate token ids
-- ARGV[4+n .. 3+2n]      candidate envelopes (binary)
--
-- Returns a flat array of (token_id, created) pairs, in entry order.
local meta_key = KEYS[1]
local ttl = tonumber(ARGV[1])
local n = tonumber(ARGV[2])
local record_prefix = ARGV[3]
local result = {}

for i = 1, n do
  local fingerprint_key = KEYS[1 + i]
  local candidate_key = KEYS[1 + n + i]
  local candidate_id = ARGV[3 + i]
  local envelope = ARGV[3 + n + i]
  local reused = false

  local existing_id = redis.call('GET', fingerprint_key)
  if existing_id then
    local existing_key = record_prefix .. existing_id
    if redis.call('EXISTS', existing_key) == 1 then
      -- Reuse extends the record's life, so a value repeated late in a
      -- session does not expire mid-conversation.
      redis.call('EXPIRE', fingerprint_key, ttl)
      redis.call('EXPIRE', existing_key, ttl)
      result[#result + 1] = existing_id
      result[#result + 1] = 0
      reused = true
    end
    -- An index entry whose record is gone falls through and is replaced,
    -- rather than handing back a token that cannot resolve.
  end

  if not reused then
    redis.call('SET', candidate_key, envelope, 'EX', ttl)
    redis.call('SET', fingerprint_key, candidate_id, 'EX', ttl)
    -- One member per call: `unpack` is absent from some Lua versions and this
    -- costs nothing across the network, being inside the same invocation.
    redis.call('SADD', meta_key, candidate_key)
    redis.call('SADD', meta_key, fingerprint_key)
    result[#result + 1] = candidate_id
    result[#result + 1] = 1
  end
end

redis.call('EXPIRE', meta_key, ttl)
return result
"""

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

    __slots__ = ("_batch_write", "_cipher", "_prefix", "_redis")

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
        # Registered once. redis-py sends EVALSHA and falls back to EVAL on
        # NOSCRIPT, so a restarted or flushed Redis recovers by itself.
        self._batch_write: AsyncScript = redis.register_script(_BATCH_WRITE_SCRIPT)

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
    async def get_or_create_many(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        entries: Sequence[VaultWriteRequest],
        ttl_seconds: int,
    ) -> tuple[str, ...]:
        ttl = _validated_ttl(ttl_seconds)
        for entry in entries:
            validate_entity_type(entry.entity_type)
            if not entry.normalized_hmac:
                raise ValueError("normalized_hmac must not be empty")
        if len(entries) > MAX_BATCH_ENTRIES:
            raise ValueError(f"batch of {len(entries)} exceeds the {MAX_BATCH_ENTRIES} ceiling")
        if not entries:
            return ()

        # Repeats collapse before the vault is touched, so a value appearing
        # twenty times in one message costs one entry, not twenty.
        unique, positions = _deduplicate(entries)

        with observe(OPERATION_GET_OR_CREATE_MANY, outcomes=_METRIC_OUTCOMES):
            session_prefix = self._session_prefix(tenant_id, session_id)
            meta_key = self._meta_key(session_prefix)

            # Seal everything before the script runs. An encryption failure
            # must fail the whole batch with nothing written, rather than
            # abandoning a partly applied one.
            fingerprint_keys: list[str] = []
            candidate_keys: list[str] = []
            candidate_ids: list[str] = []
            envelopes: list[bytes] = []
            for entry in unique:
                candidate_id = new_token_id()
                fingerprint_keys.append(
                    self._fingerprint_key(session_prefix, entry.entity_type, entry.normalized_hmac)
                )
                candidate_keys.append(self._token_key(session_prefix, candidate_id))
                candidate_ids.append(candidate_id)
                envelopes.append(
                    self._seal(
                        tenant_id=tenant_id,
                        session_id=session_id,
                        entity_type=entry.entity_type,
                        token=format_token(entry.entity_type, candidate_id),
                        token_id=candidate_id,
                        original_value=entry.original_value,
                        ttl_seconds=ttl,
                    )
                )

            with _store_failures_fail_closed(OPERATION_GET_OR_CREATE_MANY):
                raw = cast(
                    "list[object]",
                    await self._batch_write(
                        keys=[meta_key, *fingerprint_keys, *candidate_keys],
                        args=[
                            ttl,
                            len(unique),
                            f"{session_prefix}{_TOKEN_SEGMENT}",
                            *candidate_ids,
                            *envelopes,
                        ],
                    ),
                )

            tokens, created = self._read_batch_result(raw, unique)

        record_outcome(result=RESULT_CREATED, count=created)
        record_outcome(result=RESULT_REUSED, count=len(unique) - created)
        return tuple(tokens[index] for index in positions)

    @staticmethod
    def _read_batch_result(
        raw: Sequence[object],
        unique: Sequence[VaultWriteRequest],
    ) -> tuple[list[str], int]:
        """Turn the script's flat ``id, created`` pairs into tokens.

        A malformed reply means this module and its script disagree, which is
        an internal fault. It fails closed rather than handing back a token
        that may not resolve.
        """
        if len(raw) != 2 * len(unique):
            logger.error(
                "vault batch write returned an unexpected reply length",
                extra={"vault_operation": OPERATION_GET_OR_CREATE_MANY},
            )
            raise VaultEncryptionError(log_context={"reason": "batch_reply_length_mismatch"})

        tokens: list[str] = []
        created = 0
        for index, entry in enumerate(unique):
            token_id = _as_text(raw[2 * index])
            if not is_valid_token_id(token_id):
                logger.error(
                    "vault index entry is not a valid token id",
                    extra={
                        "vault_operation": OPERATION_GET_OR_CREATE_MANY,
                        "entity_type": entry.entity_type,
                    },
                )
                raise VaultEncryptionError(log_context={"reason": "malformed_index_entry"})
            tokens.append(format_token(entry.entity_type, token_id))
            created += int(cast("int", raw[2 * index + 1]))
        return tokens, created

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
                    "vault_operation": OPERATION_GET_OR_CREATE_MANY,
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


def _deduplicate(
    entries: Sequence[VaultWriteRequest],
) -> tuple[tuple[VaultWriteRequest, ...], tuple[int, ...]]:
    """Collapse repeats, returning the unique entries and each entry's index.

    Identity is ``(entity_type, normalized_hmac)`` -- the same pair that names
    a fingerprint key, so two entries that would contend for one key become
    one entry instead.
    """
    seen: dict[tuple[str, str], int] = {}
    unique: list[VaultWriteRequest] = []
    positions: list[int] = []
    for entry in entries:
        identity = (entry.entity_type, entry.normalized_hmac)
        index = seen.get(identity)
        if index is None:
            index = len(unique)
            seen[identity] = index
            unique.append(entry)
        positions.append(index)
    return tuple(unique), tuple(positions)


def _validated_ttl(ttl_seconds: int) -> int:
    if not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError(f"ttl_seconds must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS}")
    return ttl_seconds
