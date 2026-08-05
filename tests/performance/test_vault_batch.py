"""Benchmarks for the batch vault write (ADR-0022).

Marked ``performance`` and excluded from the default CI gate, because a timing
assertion on shared CI hardware is a flaky test wearing a benchmark's clothes::

    pytest tests/performance -m performance -s

Two different things live here, and only one of them is a timing measurement:

* **Round-trip counts** are exact and deterministic. They are the property
  ADR-0022 actually specifies, they hold on any hardware, and they are what
  makes the target in ``docs/performance.md`` reachable at all.
* **Elapsed timings** are reported against the targets in
  ``docs/performance.md``, and asserted only against a ceiling loose enough to
  catch a return to per-token round trips rather than to police milliseconds.

These run against ``fakeredis``, so the absolute numbers describe this code and
not a network. That is deliberate: the shape being measured is how the cost
scales with entity count, and a real Redis makes the per-token version look
worse, never better.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import fakeredis.aioredis
import pytest

from app.domain.models import VaultWriteRequest
from app.vault.crypto import EnvelopeCipher
from app.vault.keys import StaticKeyRing
from app.vault.redis_vault import RedisTokenVault

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from redis.asyncio import Redis

pytestmark = pytest.mark.performance

TENANT = UUID("11111111-1111-1111-1111-111111111111")
TTL = 300
KEY_ID = "bench"
KEY = bytes(range(32))

DOCUMENT_ENTITY_COUNT = 200
"""Roughly what a 2,000-word document yields. See ``docs/performance.md``."""

PER_TOKEN_CEILING_MS = 5.0
"""``docs/performance.md``: effective batch vault work per token, under 5 ms."""


@pytest.fixture
async def redis_client() -> AsyncIterator[Redis]:
    client = fakeredis.aioredis.FakeRedis(decode_responses=False)
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def vault(redis_client: Redis) -> RedisTokenVault:
    cipher = EnvelopeCipher(StaticKeyRing({KEY_ID: KEY}, active_key_id=KEY_ID))
    return RedisTokenVault(redis_client, cipher)


def entries(count: int) -> tuple[VaultWriteRequest, ...]:
    return tuple(
        VaultWriteRequest(
            entity_type="EMAIL_ADDRESS",
            normalized_hmac=f"{index:064d}",
            original_value=f"user{index}@example.com",
        )
        for index in range(count)
    )


class RoundTripCounter:
    """Counts script invocations, which is what a round trip is for a write."""

    def __init__(self, client: Redis, monkeypatch: pytest.MonkeyPatch) -> None:
        self.count = 0
        original = client.evalsha

        async def counting(*args: object, **kwargs: object) -> object:
            self.count += 1
            return await original(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(client, "evalsha", counting)

    def reset(self) -> None:
        self.count = 0


async def warm_up(vault: RedisTokenVault) -> None:
    """Pay the one-off NOSCRIPT reload before anything is measured."""
    await vault.get_or_create_many(
        tenant_id=TENANT, session_id=uuid4(), entries=entries(1), ttl_seconds=TTL
    )


@pytest.mark.parametrize("count", [1, 10, 50, 200])
async def test_round_trips_stay_flat_as_entity_count_grows(
    vault: RedisTokenVault,
    redis_client: Redis,
    monkeypatch: pytest.MonkeyPatch,
    count: int,
) -> None:
    # Arrange
    await warm_up(vault)
    counter = RoundTripCounter(redis_client, monkeypatch)
    await warm_up(vault)
    counter.reset()

    # Act
    await vault.get_or_create_many(
        tenant_id=TENANT, session_id=uuid4(), entries=entries(count), ttl_seconds=TTL
    )

    # Assert -- the exact, hardware-independent form of the ADR-0022 claim.
    # The per-token implementation scored `count` here.
    assert counter.count == 1


async def test_a_document_sized_batch_reports_its_per_token_cost(
    vault: RedisTokenVault,
) -> None:
    # Arrange
    await warm_up(vault)
    batch = entries(DOCUMENT_ENTITY_COUNT)

    # Act
    started = time.perf_counter()
    tokens = await vault.get_or_create_many(
        tenant_id=TENANT, session_id=uuid4(), entries=batch, ttl_seconds=TTL
    )
    elapsed_ms = (time.perf_counter() - started) * 1000

    # Assert
    per_token_ms = elapsed_ms / DOCUMENT_ENTITY_COUNT
    print(
        f"\nbatch of {DOCUMENT_ENTITY_COUNT}: {elapsed_ms:.1f} ms total, "
        f"{per_token_ms:.3f} ms per token (target < {PER_TOKEN_CEILING_MS} ms)"
    )
    assert len(tokens) == DOCUMENT_ENTITY_COUNT
    assert per_token_ms < PER_TOKEN_CEILING_MS


async def test_resolving_a_document_sized_response_is_one_round_trip(
    vault: RedisTokenVault,
) -> None:
    # Arrange -- the read half of ADR-0022, which was always batched.
    await warm_up(vault)
    session = uuid4()
    tokens = await vault.get_or_create_many(
        tenant_id=TENANT,
        session_id=session,
        entries=entries(DOCUMENT_ENTITY_COUNT),
        ttl_seconds=TTL,
    )

    # Act
    started = time.perf_counter()
    resolved = await vault.resolve_many(
        tenant_id=TENANT, session_id=session, tokens=set(tokens)
    )
    elapsed_ms = (time.perf_counter() - started) * 1000

    # Assert
    print(f"\nresolve of {len(tokens)}: {elapsed_ms:.1f} ms total")
    assert len(resolved) == DOCUMENT_ENTITY_COUNT


async def test_repeated_values_cost_nothing_extra(vault: RedisTokenVault) -> None:
    # Arrange -- 200 spans of one value, as a name repeated through a document
    # produces.
    await warm_up(vault)
    one = entries(1)[0]
    batch = tuple(one for _ in range(DOCUMENT_ENTITY_COUNT))

    # Act
    started = time.perf_counter()
    tokens = await vault.get_or_create_many(
        tenant_id=TENANT, session_id=uuid4(), entries=batch, ttl_seconds=TTL
    )
    elapsed_ms = (time.perf_counter() - started) * 1000

    # Assert -- deduplication happens before the vault is touched, so this is
    # a batch of one wearing a batch of 200's clothes.
    print(f"\n{DOCUMENT_ENTITY_COUNT} repeats of one value: {elapsed_ms:.1f} ms")
    assert len(set(tokens)) == 1
    assert len(tokens) == DOCUMENT_ENTITY_COUNT
