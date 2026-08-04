"""Audit Prometheus metrics.

Same cardinality rule as :mod:`app.vault.metrics`, and for the same reason: a
label value must come from a closed set fixed at import time. No tenant id,
request id, entity type, error message, or digest ever becomes a label. The
functions below reject an unknown label value rather than quietly creating a new
time series, so a typo at a call site fails loudly instead of growing the
registry without bound.

Metrics are an output surface like any other. Nothing here accepts a value that
could carry request content -- only fixed outcome names and numbers.
"""

from __future__ import annotations

from typing import Final

from prometheus_client import Counter, Gauge, Histogram

# -- Closed label sets --------------------------------------------------------
OUTCOME_ENQUEUED: Final = "enqueued"
OUTCOME_WRITTEN: Final = "written"
OUTCOME_DROPPED: Final = "dropped"
OUTCOME_REJECTED: Final = "rejected"
OUTCOME_FAILED: Final = "failed"

EVENT_OUTCOMES: Final[frozenset[str]] = frozenset(
    {OUTCOME_ENQUEUED, OUTCOME_WRITTEN, OUTCOME_DROPPED, OUTCOME_REJECTED, OUTCOME_FAILED}
)

REASON_QUEUE_FULL: Final = "queue_full"
REASON_WRITE_ERROR: Final = "write_error"
REASON_DEGRADED: Final = "degraded"
REASON_DRAIN_TIMEOUT: Final = "drain_timeout"
REASON_SHUTDOWN: Final = "shutdown"

FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {
        REASON_QUEUE_FULL,
        REASON_WRITE_ERROR,
        REASON_DEGRADED,
        REASON_DRAIN_TIMEOUT,
        REASON_SHUTDOWN,
    }
)

# -- Instruments --------------------------------------------------------------
AUDIT_EVENTS_TOTAL: Final = Counter(
    "sgw_audit_events_total",
    "Audit events by what happened to them.",
    labelnames=("outcome",),
)

AUDIT_FAILURES_TOTAL: Final = Counter(
    "sgw_audit_failures_total",
    "Audit failures by reason.",
    labelnames=("reason",),
)

AUDIT_QUEUE_DEPTH: Final = Gauge(
    "sgw_audit_queue_depth",
    "Audit events waiting to be written. Unlabelled: there is one queue per process.",
)

AUDIT_QUEUE_CAPACITY: Final = Gauge(
    "sgw_audit_queue_capacity",
    "Configured bound on the audit queue, so depth can be read as a ratio.",
)

AUDIT_WRITE_SECONDS: Final = Histogram(
    "sgw_audit_write_duration_seconds",
    "Time to persist one audit event.",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)


def record_event(outcome: str, *, count: int = 1) -> None:
    """Count one audit event outcome.

    Raises:
        ValueError: if ``outcome`` is outside :data:`EVENT_OUTCOMES`.
    """
    if outcome not in EVENT_OUTCOMES:
        raise ValueError(f"unknown audit outcome: {outcome!r}")
    if count:
        AUDIT_EVENTS_TOTAL.labels(outcome=outcome).inc(count)


def record_failure(reason: str, *, count: int = 1) -> None:
    """Count one audit failure.

    Raises:
        ValueError: if ``reason`` is outside :data:`FAILURE_REASONS`.
    """
    if reason not in FAILURE_REASONS:
        raise ValueError(f"unknown audit failure reason: {reason!r}")
    if count:
        AUDIT_FAILURES_TOTAL.labels(reason=reason).inc(count)


def set_queue_depth(depth: int) -> None:
    """Publish the current queue depth."""
    AUDIT_QUEUE_DEPTH.set(depth)


def set_queue_capacity(capacity: int) -> None:
    """Publish the configured queue bound."""
    AUDIT_QUEUE_CAPACITY.set(capacity)


def observe_write(seconds: float) -> None:
    """Record how long one persistence attempt took, successful or not."""
    AUDIT_WRITE_SECONDS.observe(seconds)
