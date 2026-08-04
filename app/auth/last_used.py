"""Bounded-frequency maintenance of ``api_keys.last_used_at``.

Writing ``last_used_at`` on every request would turn authentication -- the
hottest read path in the gateway -- into a write against the single hottest row
per key, with the row lock, WAL volume, and index churn that implies. The signal
is not worth that: operators use ``last_used_at`` to answer "is this key still
in use, and can I revoke it?", a question whose useful resolution is minutes.

**The bound is one write per key per ``LAST_USED_UPDATE_INTERVAL_SECONDS``
(300s / 5 minutes) per process.** Five minutes keeps the answer accurate enough
for revocation review while cutting the write rate on a key doing 100 rps by a
factor of 30,000. The tracker is per-process, so a deployment of N workers
writes at most N times per interval per key -- still bounded, and no coordination
is needed.

The write is best effort. A failure is logged and counted but never raised:
``last_used_at`` is telemetry, and failing a request the caller is authorized to
make because a bookkeeping write failed would be an availability bug, not a
security control.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime
from typing import Final, Protocol, runtime_checkable
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from app.auth import metrics
from app.db.base import utc_now
from app.domain.models import Principal

logger = logging.getLogger("app.auth")

LAST_USED_UPDATE_INTERVAL_SECONDS: Final = 300
"""Minimum seconds between two ``last_used_at`` writes for the same key."""

MAX_TRACKED_KEYS: Final = 10_000
"""Cap on remembered keys. Bounds memory; eviction only costs an extra write."""


@runtime_checkable
class LastUsedWriter(Protocol):
    """The one repository method this module needs.

    ``SqlAlchemyApiKeyRepository`` satisfies it structurally, so wiring can pass
    the repository straight through without an adapter.
    """

    async def touch_last_used(self, tenant_id: UUID, api_key_id: UUID, *, when: datetime) -> None:
        """Record that the key was used at ``when``."""
        ...


class LastUsedTracker:
    """Decides, per key, whether this request should pay for a write.

    Instances hold process-local state and are safe to share across requests on
    one event loop. ``should_update`` is not merely a predicate: it claims the
    interval, so two concurrent requests for one key produce one write.
    """

    __slots__ = ("_clock", "_interval", "_max_tracked", "_seen")

    def __init__(
        self,
        *,
        interval_seconds: float = LAST_USED_UPDATE_INTERVAL_SECONDS,
        max_tracked_keys: int = MAX_TRACKED_KEYS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        if max_tracked_keys < 1:
            raise ValueError("max_tracked_keys must be at least 1")
        self._interval = interval_seconds
        self._max_tracked = max_tracked_keys
        self._clock = clock
        self._seen: OrderedDict[UUID, float] = OrderedDict()

    def should_update(self, api_key_id: UUID) -> bool:
        """Whether ``api_key_id`` is due a write, claiming the interval if so."""
        now = self._clock()
        previous = self._seen.get(api_key_id)
        if previous is not None and now - previous < self._interval:
            return False

        self._seen[api_key_id] = now
        self._seen.move_to_end(api_key_id)
        while len(self._seen) > self._max_tracked:
            # Least recently written key falls out first. The only consequence
            # of an eviction is one extra write next time that key appears.
            self._seen.popitem(last=False)
        return True

    async def record_use(
        self,
        writer: LastUsedWriter | None,
        principal: Principal,
        *,
        when: datetime | None = None,
    ) -> bool:
        """Write ``last_used_at`` if due. Returns whether a write happened.

        Never raises: see the module docstring.
        """
        if writer is None or not self.should_update(principal.api_key_id):
            metrics.record_last_used(metrics.LAST_USED_OUTCOME_SKIPPED)
            return False

        try:
            await writer.touch_last_used(
                principal.tenant_id, principal.api_key_id, when=when or utc_now()
            )
        except (SQLAlchemyError, OSError):
            # Narrow, and converted rather than swallowed: the outcome is
            # counted and logged with a reason code, and the request proceeds.
            logger.warning(
                "last_used_write_failed",
                extra={
                    "reason": "last_used_write_failed",
                    "api_key_id": str(principal.api_key_id),
                },
            )
            metrics.record_last_used(metrics.LAST_USED_OUTCOME_FAILED)
            return False

        metrics.record_last_used(metrics.LAST_USED_OUTCOME_WRITTEN)
        return True

    def __repr__(self) -> str:
        return f"LastUsedTracker(tracked={len(self._seen)}, interval={self._interval})"
