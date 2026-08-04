"""Redis-backed rate limiting, per tenant and per API key.

**Algorithm: sliding window log, one Redis sorted set per bucket.** Each admitted
request adds a member scored with its arrival time in milliseconds; every check
first drops members older than the window, then counts what remains. Two
alternatives were considered and rejected:

* A *fixed window counter* (``INCR`` + ``EXPIRE``) is cheaper, but it admits up
  to twice the limit across a window boundary. For a gateway whose limits exist
  to bound spend at an upstream provider and to blunt credential-stuffing, a
  documented 2x overshoot is a real hole, not a rounding error.
* A *token bucket* smooths bursts nicely but needs a read-modify-write of two
  fields plus a Lua script to stay atomic; Lua is exactly the dependency this
  project avoids in its Redis paths.

The log's cost is bounded by construction: a bucket holds at most ``limit``
members, and the key carries a TTL of one window, so an idle tenant occupies
nothing. Atomicity comes from ``WATCH``/``MULTI`` over both bucket keys, the
same mechanism the vault uses -- concurrent requests either see each other's
members or retry.

**Key names never contain the credential.** Buckets are keyed by ``tenant_id``
and ``api_key_id``: identifiers of records, not secrets. Not even the key prefix
appears, since a prefix is a substring of the raw key. Members are
``<milliseconds>:<random hex>`` and carry nothing about the caller.

**Fail closed.** ``FAIL_OPEN_ON_BACKEND_ERROR`` is ``False`` and is a code
constant, not a setting: a deployment must not be able to disable a security
control by editing an environment variable. When Redis is unavailable the
limiter returns a *denied* decision and protected endpoints reject the request.
A deliberate opt-out exists per limiter instance
(``fail_open_on_backend_error=True``) for operators who would rather absorb an
unmetered burst than an outage; it is an explicit constructor argument at a
wiring site, and it is counted separately in the metrics.
"""

from __future__ import annotations

import logging
import math
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol
from uuid import UUID

from redis.exceptions import RedisError

from app.auth import metrics
from app.domain.errors import RateLimitExceededError
from app.domain.models import Principal

if TYPE_CHECKING:
    from redis.asyncio import Redis
    from redis.asyncio.client import Pipeline

logger = logging.getLogger("app.auth")

DEFAULT_KEY_PREFIX: Final = "sgw:rl:v1"

FAIL_OPEN_ON_BACKEND_ERROR: Final = False
"""The default, in code, on purpose. See the module docstring."""

BACKEND_ERROR_RETRY_AFTER_SECONDS: Final = 5
"""What a caller is told to wait when the limiter itself is down."""

REASON_WITHIN_LIMIT: Final = "within_limit"
REASON_LIMIT_EXCEEDED: Final = "rate_limit_exceeded"
REASON_BACKEND_UNAVAILABLE: Final = "rate_limit_backend_unavailable"
REASON_NOT_CONFIGURED: Final = "rate_limiter_not_configured"


@dataclass(frozen=True, slots=True)
class RateLimitRule:
    """``limit`` requests per ``window_seconds``."""

    limit: int
    window_seconds: int

    def __post_init__(self) -> None:
        if self.limit < 1:
            raise ValueError("limit must be at least 1")
        if self.window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")

    @property
    def window_ms(self) -> int:
        return self.window_seconds * 1000


DEFAULT_TENANT_RULE: Final = RateLimitRule(limit=600, window_seconds=60)
"""Aggregate ceiling for one tenant across all of its keys."""

DEFAULT_API_KEY_RULE: Final = RateLimitRule(limit=120, window_seconds=60)
"""Per-credential ceiling, so one leaked key cannot consume a tenant's budget."""


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """The outcome of one admission check. Immutable and free of caller data."""

    allowed: bool
    bucket: str
    limit: int
    remaining: int
    retry_after_seconds: int
    reason: str


class RateLimiter(Protocol):
    """Consumes one unit of budget against every bucket for a principal."""

    async def acquire(self, principal: Principal) -> RateLimitDecision:
        """Return the admission decision. Implementations do not raise on
        backend failure; they return a fail-closed decision instead."""
        ...


async def enforce(limiter: RateLimiter, principal: Principal) -> RateLimitDecision:
    """Apply the limiter, raising the public error when the request is denied."""
    decision = await limiter.acquire(principal)
    if not decision.allowed:
        raise RateLimitExceededError(
            log_context={
                "reason": decision.reason,
                "retry_after": decision.retry_after_seconds,
            }
        )
    return decision


def backend_failure_decision(
    *, fail_open: bool, bucket: str = metrics.BUCKET_TENANT
) -> RateLimitDecision:
    """The decision taken when the limiter's backing store cannot be reached."""
    outcome = (
        metrics.RATE_LIMIT_OUTCOME_FAILED_OPEN
        if fail_open
        else metrics.RATE_LIMIT_OUTCOME_FAILED_CLOSED
    )
    metrics.record_rate_limit(bucket=bucket, outcome=outcome)
    return RateLimitDecision(
        allowed=fail_open,
        bucket=bucket,
        limit=0,
        remaining=0,
        retry_after_seconds=BACKEND_ERROR_RETRY_AFTER_SECONDS,
        reason=REASON_BACKEND_UNAVAILABLE,
    )


def not_configured_decision() -> RateLimitDecision:
    """No limiter is wired: reject rather than serve an unmetered endpoint."""
    metrics.record_rate_limit(
        bucket=metrics.BUCKET_TENANT, outcome=metrics.RATE_LIMIT_OUTCOME_NOT_CONFIGURED
    )
    return RateLimitDecision(
        allowed=False,
        bucket=metrics.BUCKET_TENANT,
        limit=0,
        remaining=0,
        retry_after_seconds=BACKEND_ERROR_RETRY_AFTER_SECONDS,
        reason=REASON_NOT_CONFIGURED,
    )


@dataclass(frozen=True, slots=True)
class _Bucket:
    name: str
    key: str
    rule: RateLimitRule


def _new_member(now_ms: int) -> str:
    """A unique, meaningless member name. Never derived from the credential."""
    return f"{now_ms}:{secrets.token_hex(8)}"


def _retry_after(oldest_ms: int | None, now_ms: int, rule: RateLimitRule) -> int:
    """Seconds until the oldest member leaves the window, at least one."""
    if oldest_ms is None:
        return rule.window_seconds
    return max(1, math.ceil((oldest_ms + rule.window_ms - now_ms) / 1000))


class RedisRateLimiter:
    """``RateLimiter`` over Redis sorted sets."""

    __slots__ = ("_api_key_rule", "_clock", "_fail_open", "_prefix", "_redis", "_tenant_rule")

    def __init__(
        self,
        redis: Redis,
        *,
        tenant_rule: RateLimitRule = DEFAULT_TENANT_RULE,
        api_key_rule: RateLimitRule = DEFAULT_API_KEY_RULE,
        key_prefix: str = DEFAULT_KEY_PREFIX,
        fail_open_on_backend_error: bool = FAIL_OPEN_ON_BACKEND_ERROR,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._redis = redis
        self._tenant_rule = tenant_rule
        self._api_key_rule = api_key_rule
        self._prefix = key_prefix
        self._fail_open = fail_open_on_backend_error
        self._clock = clock

    # -- Key construction -------------------------------------------------
    def tenant_key(self, tenant_id: UUID) -> str:
        return f"{self._prefix}:tenant:{tenant_id}"

    def api_key_key(self, api_key_id: UUID) -> str:
        return f"{self._prefix}:key:{api_key_id}"

    # -- RateLimiter ------------------------------------------------------
    async def acquire(self, principal: Principal) -> RateLimitDecision:
        buckets = (
            _Bucket(
                metrics.BUCKET_API_KEY, self.api_key_key(principal.api_key_id), self._api_key_rule
            ),
            _Bucket(metrics.BUCKET_TENANT, self.tenant_key(principal.tenant_id), self._tenant_rule),
        )

        async def apply(pipe: Pipeline) -> RateLimitDecision:
            return await self._evaluate(pipe, buckets)

        try:
            decision: RateLimitDecision = await self._redis.transaction(
                apply, *[bucket.key for bucket in buckets], value_from_callable=True
            )
        except (RedisError, OSError) as exc:
            logger.warning(
                "rate_limit_backend_unavailable",
                extra={"reason": REASON_BACKEND_UNAVAILABLE, "failure_type": type(exc).__name__},
            )
            return backend_failure_decision(fail_open=self._fail_open)

        self._record(buckets, decision)
        return decision

    # -- Internals --------------------------------------------------------
    async def _evaluate(self, pipe: Pipeline, buckets: tuple[_Bucket, ...]) -> RateLimitDecision:
        """Read every bucket, then either admit into all or deny without writing.

        Denying without writing matters: a client that keeps hammering a full
        bucket must not push its own window forward and extend the block.
        """
        now_ms = int(self._clock() * 1000)
        counts: list[int] = []
        denied: RateLimitDecision | None = None

        for bucket in buckets:
            await pipe.zremrangebyscore(bucket.key, 0, now_ms - bucket.rule.window_ms)
            count = int(await pipe.zcard(bucket.key))
            counts.append(count)
            if denied is None and count >= bucket.rule.limit:
                oldest = await pipe.zrange(bucket.key, 0, 0, withscores=True)
                oldest_ms = int(oldest[0][1]) if oldest else None
                denied = RateLimitDecision(
                    allowed=False,
                    bucket=bucket.name,
                    limit=bucket.rule.limit,
                    remaining=0,
                    retry_after_seconds=_retry_after(oldest_ms, now_ms, bucket.rule),
                    reason=REASON_LIMIT_EXCEEDED,
                )

        # redis-py leaves multi() unannotated.
        pipe.multi()  # type: ignore[no-untyped-call]
        if denied is not None:
            return denied

        member = _new_member(now_ms)
        for bucket in buckets:
            pipe.zadd(bucket.key, {member: now_ms})
            pipe.pexpire(bucket.key, bucket.rule.window_ms)

        tightest = min(
            zip(buckets, counts, strict=True),
            key=lambda pair: pair[0].rule.limit - pair[1],
        )
        bucket, count = tightest
        return RateLimitDecision(
            allowed=True,
            bucket=bucket.name,
            limit=bucket.rule.limit,
            remaining=max(0, bucket.rule.limit - count - 1),
            retry_after_seconds=0,
            reason=REASON_WITHIN_LIMIT,
        )

    @staticmethod
    def _record(buckets: tuple[_Bucket, ...], decision: RateLimitDecision) -> None:
        """Count one outcome per bucket, outside the retryable transaction."""
        for bucket in buckets:
            if decision.allowed:
                metrics.record_rate_limit(
                    bucket=bucket.name, outcome=metrics.RATE_LIMIT_OUTCOME_ALLOWED
                )
            elif bucket.name == decision.bucket:
                metrics.record_rate_limit(
                    bucket=bucket.name, outcome=metrics.RATE_LIMIT_OUTCOME_THROTTLED
                )
            # A bucket that was read but not consumed has no outcome to count.

    def __repr__(self) -> str:
        return (
            f"RedisRateLimiter(tenant={self._tenant_rule}, api_key={self._api_key_rule}, "
            f"fail_open={self._fail_open})"
        )


class InMemoryRateLimiter:
    """A ``RateLimiter`` backed by dictionaries, for tests in other packages.

    It reproduces the properties those tests can get wrong: per-tenant and
    per-key buckets, window expiry through an injectable clock, and fail-closed
    behaviour via ``simulate_failure``. It is not safe across processes and must
    never be wired into an application.
    """

    __slots__ = ("_api_key_rule", "_clock", "_fail_open", "_failing", "_hits", "_tenant_rule")

    def __init__(
        self,
        *,
        tenant_rule: RateLimitRule = DEFAULT_TENANT_RULE,
        api_key_rule: RateLimitRule = DEFAULT_API_KEY_RULE,
        fail_open_on_backend_error: bool = FAIL_OPEN_ON_BACKEND_ERROR,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._tenant_rule = tenant_rule
        self._api_key_rule = api_key_rule
        self._fail_open = fail_open_on_backend_error
        self._clock = clock
        self._hits: dict[tuple[str, UUID], list[float]] = {}
        self._failing = False

    def simulate_failure(self, failing: bool = True) -> None:
        """Make subsequent calls behave as if the backing store were down."""
        self._failing = failing

    async def acquire(self, principal: Principal) -> RateLimitDecision:
        if self._failing:
            return backend_failure_decision(fail_open=self._fail_open)

        now = self._clock()
        buckets = (
            (metrics.BUCKET_API_KEY, principal.api_key_id, self._api_key_rule),
            (metrics.BUCKET_TENANT, principal.tenant_id, self._tenant_rule),
        )

        live: list[tuple[str, tuple[str, UUID], RateLimitRule, list[float]]] = []
        for name, identifier, rule in buckets:
            slot = (name, identifier)
            hits = [hit for hit in self._hits.get(slot, []) if hit > now - rule.window_seconds]
            self._hits[slot] = hits
            if len(hits) >= rule.limit:
                metrics.record_rate_limit(bucket=name, outcome=metrics.RATE_LIMIT_OUTCOME_THROTTLED)
                return RateLimitDecision(
                    allowed=False,
                    bucket=name,
                    limit=rule.limit,
                    remaining=0,
                    retry_after_seconds=_retry_after(int(min(hits) * 1000), int(now * 1000), rule),
                    reason=REASON_LIMIT_EXCEEDED,
                )
            live.append((name, slot, rule, hits))

        for name, slot, _rule, hits in live:
            hits.append(now)
            self._hits[slot] = hits
            metrics.record_rate_limit(bucket=name, outcome=metrics.RATE_LIMIT_OUTCOME_ALLOWED)

        name, _, rule, hits = min(live, key=lambda entry: entry[2].limit - len(entry[3]))
        return RateLimitDecision(
            allowed=True,
            bucket=name,
            limit=rule.limit,
            remaining=max(0, rule.limit - len(hits)),
            retry_after_seconds=0,
            reason=REASON_WITHIN_LIMIT,
        )

    def __repr__(self) -> str:
        return f"InMemoryRateLimiter(buckets={len(self._hits)}, failing={self._failing})"
