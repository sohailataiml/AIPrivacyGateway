"""In-memory ``TokenVault`` for tests in other packages.

This fake exists so the pipeline, restoration, and API test suites do not need
Redis. It reproduces the parts of the contract that those tests can get wrong:

* tenant and session scoping -- a token minted in one session is invisible in
  another, exactly as in Redis;
* TTL expiry, via an injectable clock so a test can move time without sleeping;
* fail-closed behaviour, via ``simulate_failure`` -- assert that your code
  refuses to call a provider when the vault is down.

It does **not** encrypt. Do not use it in an application wiring path; use
``RedisTokenVault``.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from threading import Lock
from typing import TYPE_CHECKING
from uuid import UUID

from app.domain.errors import GatewayError
from app.domain.models import VaultWriteRequest
from app.tokenization.grammar import format_token, parse_token
from app.tokenization.ids import new_token_id
from app.vault.tokens import validate_entity_type

if TYPE_CHECKING:
    from collections.abc import Sequence

    from app.domain.errors import GatewayError as _GatewayError


@dataclass(slots=True)
class _Entry:
    token: str
    entity_type: str
    original_value: str
    expires_at: float

    def __repr__(self) -> str:
        return f"_Entry(entity_type={self.entity_type!r})"


@dataclass(slots=True)
class _Session:
    """One tenant+session namespace. Nothing crosses between instances."""

    records: dict[str, _Entry] = field(default_factory=dict)
    index: dict[tuple[str, str], str] = field(default_factory=dict)


class InMemoryTokenVault:
    """A ``TokenVault`` backed by dictionaries."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._sessions: dict[tuple[UUID, UUID], _Session] = {}
        self._failure: _GatewayError | None = None
        self._lock = Lock()

    # -- Test controls ----------------------------------------------------
    def simulate_failure(self, error: GatewayError | None) -> None:
        """Make every subsequent call raise ``error``. Pass ``None`` to clear."""
        self._failure = error

    def stored_original_values(self) -> list[str]:
        """Every unexpired original value. For assertions only."""
        now = self._clock()
        return [
            entry.original_value
            for session in self._sessions.values()
            for entry in session.records.values()
            if entry.expires_at > now
        ]

    # -- TokenVault -------------------------------------------------------
    async def get_or_create_many(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        entries: Sequence[VaultWriteRequest],
        ttl_seconds: int,
    ) -> tuple[str, ...]:
        self._guard()
        for entry in entries:
            validate_entity_type(entry.entity_type)
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be at least 1")
        if not entries:
            return ()

        now = self._clock()
        expires_at = now + ttl_seconds
        # One lock for the whole batch, mirroring the single Lua invocation in
        # ``RedisTokenVault``: a concurrent caller sees all of it or none.
        with self._lock:
            session = self._sessions.setdefault((tenant_id, session_id), _Session())
            self._purge(session, now)
            return tuple(
                self._get_or_create_locked(session, entry, expires_at) for entry in entries
            )

    def _get_or_create_locked(
        self,
        session: _Session,
        entry: VaultWriteRequest,
        expires_at: float,
    ) -> str:
        """Mint or reuse one mapping. The caller holds the lock.

        Repeats within a batch land here twice and take the reuse path the
        second time, so duplicates collapse whether or not the caller
        deduplicated first.
        """
        existing = session.index.get((entry.entity_type, entry.normalized_hmac))
        if existing is not None:
            parsed = parse_token(existing)
            if parsed is not None and parsed.token_id in session.records:
                session.records[parsed.token_id].expires_at = expires_at
                return existing

        token_id = new_token_id()
        token = format_token(entry.entity_type, token_id)
        session.records[token_id] = _Entry(
            token=token,
            entity_type=entry.entity_type,
            original_value=entry.original_value,
            expires_at=expires_at,
        )
        session.index[(entry.entity_type, entry.normalized_hmac)] = token
        return token

    async def resolve_many(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        tokens: set[str],
    ) -> dict[str, str]:
        self._guard()
        now = self._clock()
        with self._lock:
            session = self._sessions.get((tenant_id, session_id))
            if session is None:
                return {}
            self._purge(session, now)

            resolved: dict[str, str] = {}
            for token in tokens:
                parsed = parse_token(token)
                if parsed is None:
                    continue
                entry = session.records.get(parsed.token_id)
                if entry is None or entry.token != token:
                    continue
                resolved[token] = entry.original_value
            return resolved

    async def delete_session(self, *, tenant_id: UUID, session_id: UUID) -> int:
        self._guard()
        with self._lock:
            session = self._sessions.pop((tenant_id, session_id), None)
            if session is None:
                return 0
            return len(session.records)

    # -- Internals --------------------------------------------------------
    def _guard(self) -> None:
        if self._failure is not None:
            raise self._failure

    @staticmethod
    def _purge(session: _Session, now: float) -> None:
        expired = [
            token_id for token_id, entry in session.records.items() if entry.expires_at <= now
        ]
        for token_id in expired:
            session.records.pop(token_id, None)
        if expired:
            live = {entry.token for entry in session.records.values()}
            for key in [key for key, token in session.index.items() if token not in live]:
                session.index.pop(key, None)

    def __repr__(self) -> str:
        return f"InMemoryTokenVault(sessions={len(self._sessions)})"
