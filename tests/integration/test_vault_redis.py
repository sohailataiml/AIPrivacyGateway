"""Vault integration tests. Require a disposable Redis.

Marked ``integration`` and skipped when ``TEST_REDIS_URL`` is unset, so the
default unit run collects them without failing. Point them at a throwaway
instance -- these tests write and delete keys under their own prefix::

    TEST_REDIS_URL=redis://localhost:6379/15 \\
        pytest tests/integration/test_vault_redis.py -m integration

These assertions are the ones ``fakeredis`` cannot make. The batch write of
ADR-0022 is a Lua script, and fakeredis executes Lua through ``lupa`` rather
than through Redis's own interpreter. That is close enough for logic and not
close enough for the things that actually break in production: ``EVALSHA``
caching and its ``NOSCRIPT`` recovery, real script atomicity against real
concurrent clients, and binary-safe argument handling for envelopes.

Defects 9 and 10 in the project's history were both "passed every test, failed
in the real artifact". A Lua script verified only against a Lua emulator is the
same shape of risk.
"""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import pytest
import redis.asyncio as redis_asyncio

from app.domain.errors import VaultUnavailableError
from app.domain.models import VaultWriteRequest
from app.vault.crypto import EnvelopeCipher
from app.vault.keys import StaticKeyRing
from app.vault.redis_vault import RedisTokenVault

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from redis.asyncio import Redis

pytestmark = pytest.mark.integration

REDIS_URL = os.environ.get("TEST_REDIS_URL")
requires_redis = pytest.mark.skipif(
    not REDIS_URL,
    reason="set TEST_REDIS_URL to a disposable Redis instance to run these",
)

TENANT = UUID("11111111-1111-1111-1111-111111111111")
TTL = 300
KEY_ID = "integration"
KEY = bytes(range(32))


@pytest.fixture
async def redis_client() -> AsyncIterator[Redis]:
    client = redis_asyncio.from_url(str(REDIS_URL), decode_responses=False)
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def prefix() -> str:
    """A per-test namespace, so a failure never strands another test's keys."""
    return f"sgwtest:{uuid4().hex}"


@pytest.fixture
async def vault(redis_client: Redis, prefix: str) -> AsyncIterator[RedisTokenVault]:
    cipher = EnvelopeCipher(StaticKeyRing({KEY_ID: KEY}, active_key_id=KEY_ID))
    yield RedisTokenVault(redis_client, cipher, key_prefix=prefix)
    keys = await redis_client.keys(f"{prefix}:*")
    if keys:
        await redis_client.delete(*keys)


def write_request(index: int) -> VaultWriteRequest:
    return VaultWriteRequest(
        entity_type="EMAIL_ADDRESS",
        normalized_hmac=f"{index:064d}",
        original_value=f"user{index}@example.com",
    )


@requires_redis
class TestBatchWriteAgainstRealRedis:
    async def test_a_batch_round_trips_through_real_redis(self, vault: RedisTokenVault) -> None:
        # Arrange
        session = uuid4()
        entries = tuple(write_request(index) for index in range(25))

        # Act
        tokens = await vault.get_or_create_many(
            tenant_id=TENANT, session_id=session, entries=entries, ttl_seconds=TTL
        )
        resolved = await vault.resolve_many(
            tenant_id=TENANT, session_id=session, tokens=set(tokens)
        )

        # Assert -- binary envelopes survive the trip through Lua and back.
        assert len(set(tokens)) == 25
        for entry, token in zip(entries, tokens, strict=True):
            assert resolved[token] == entry.original_value

    async def test_the_script_survives_a_script_flush(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange -- a flushed script cache is what a Redis restart looks like
        # to a long-lived client. redis-py should recover via NOSCRIPT.
        session = uuid4()
        await vault.get_or_create_many(
            tenant_id=TENANT, session_id=session, entries=(write_request(1),), ttl_seconds=TTL
        )
        await redis_client.script_flush()

        # Act
        tokens = await vault.get_or_create_many(
            tenant_id=TENANT, session_id=session, entries=(write_request(2),), ttl_seconds=TTL
        )

        # Assert
        assert len(tokens) == 1
        assert await vault.resolve_many(
            tenant_id=TENANT, session_id=session, tokens=set(tokens)
        ) == {tokens[0]: "user2@example.com"}

    async def test_concurrent_clients_agree_on_every_token(
        self, redis_client: Redis, prefix: str
    ) -> None:
        # Arrange -- separate vault instances, as separate workers would be.
        # Each registers the script independently.
        cipher = EnvelopeCipher(StaticKeyRing({KEY_ID: KEY}, active_key_id=KEY_ID))
        vaults = [RedisTokenVault(redis_client, cipher, key_prefix=prefix) for _ in range(6)]
        session = uuid4()
        entries = tuple(write_request(index) for index in range(10))

        # Act
        results = await asyncio.gather(
            *[
                instance.get_or_create_many(
                    tenant_id=TENANT, session_id=session, entries=entries, ttl_seconds=TTL
                )
                for instance in vaults
            ]
        )

        # Assert -- real Redis runs each script to completion, so no two
        # clients can interleave and mint competing tokens.
        assert len({tuple(result) for result in results}) == 1
        record_keys = await redis_client.keys(f"{prefix}:{TENANT}:{session}:token:*")
        assert len(record_keys) == 10

    async def test_every_key_written_carries_a_ttl(
        self, vault: RedisTokenVault, redis_client: Redis, prefix: str
    ) -> None:
        # Arrange
        session = uuid4()

        # Act
        await vault.get_or_create_many(
            tenant_id=TENANT,
            session_id=session,
            entries=tuple(write_request(index) for index in range(5)),
            ttl_seconds=TTL,
        )

        # Assert -- a key without a TTL outlives the session it belongs to.
        keys = await redis_client.keys(f"{prefix}:{TENANT}:{session}:*")
        assert keys
        for key in keys:
            assert 0 < await redis_client.ttl(key) <= TTL

    async def test_deleting_a_session_removes_the_whole_batch(
        self, vault: RedisTokenVault, redis_client: Redis, prefix: str
    ) -> None:
        # Arrange
        session = uuid4()
        tokens = await vault.get_or_create_many(
            tenant_id=TENANT,
            session_id=session,
            entries=tuple(write_request(index) for index in range(8)),
            ttl_seconds=TTL,
        )

        # Act
        removed = await vault.delete_session(tenant_id=TENANT, session_id=session)

        # Assert -- records, indexes, and meta alike (ADR-0023).
        assert removed == 8
        assert await redis_client.keys(f"{prefix}:{TENANT}:{session}:*") == []
        assert (
            await vault.resolve_many(tenant_id=TENANT, session_id=session, tokens=set(tokens)) == {}
        )

    async def test_an_unreachable_redis_fails_closed(self, prefix: str) -> None:
        # Arrange -- a port nothing listens on.
        client = redis_asyncio.from_url("redis://127.0.0.1:1/0", decode_responses=False)
        cipher = EnvelopeCipher(StaticKeyRing({KEY_ID: KEY}, active_key_id=KEY_ID))
        unreachable = RedisTokenVault(client, cipher, key_prefix=prefix)

        # Act / Assert -- never a partial tuple a caller could read as success.
        try:
            with pytest.raises(VaultUnavailableError):
                await unreachable.get_or_create_many(
                    tenant_id=TENANT,
                    session_id=uuid4(),
                    entries=(write_request(1),),
                    ttl_seconds=TTL,
                )
        finally:
            await client.aclose()
