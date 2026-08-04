"""Vault Prometheus metrics.

Cardinality rule for this module, without exception: a label value must come
from a closed set that is fixed at import time. No tenant id, session id,
token, token id, entity value, key id, or Redis key ever becomes a label. The
entity *type* is not a label either -- it is caller-supplied and therefore
unbounded from this module's point of view.

That leaves three operations and a handful of outcomes, which is the whole
label space.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

from prometheus_client import Counter, Histogram

OPERATION_GET_OR_CREATE: Final = "get_or_create"
OPERATION_RESOLVE_MANY: Final = "resolve_many"
OPERATION_DELETE_SESSION: Final = "delete_session"

OUTCOME_SUCCESS: Final = "success"
OUTCOME_UNAVAILABLE: Final = "unavailable"
OUTCOME_ENCRYPTION_ERROR: Final = "encryption_error"
OUTCOME_ERROR: Final = "error"

RESULT_CREATED: Final = "created"
RESULT_REUSED: Final = "reused"
RESULT_RESOLVED: Final = "resolved"
RESULT_MISSING: Final = "missing"

VAULT_OPERATION_SECONDS: Final = Histogram(
    "sgw_vault_operation_duration_seconds",
    "Vault operation latency.",
    labelnames=("operation",),
    buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)

VAULT_OPERATIONS_TOTAL: Final = Counter(
    "sgw_vault_operations_total",
    "Vault operations by outcome.",
    labelnames=("operation", "outcome"),
)

VAULT_RECORDS_TOTAL: Final = Counter(
    "sgw_vault_records_total",
    "Token records by whether a new record was created or an existing one reused.",
    labelnames=("result",),
)

VAULT_TOKEN_LOOKUPS_TOTAL: Final = Counter(
    "sgw_vault_token_lookups_total",
    "Individual token lookups performed by resolve_many.",
    labelnames=("result",),
)


def record_outcome(*, result: str, count: int = 1) -> None:
    """Count created versus reused token records."""
    if count:
        VAULT_RECORDS_TOTAL.labels(result=result).inc(count)


def token_lookups(*, resolved: int, missing: int) -> None:
    """Count resolved versus missing tokens for one batch retrieval."""
    if resolved:
        VAULT_TOKEN_LOOKUPS_TOTAL.labels(result=RESULT_RESOLVED).inc(resolved)
    if missing:
        VAULT_TOKEN_LOOKUPS_TOTAL.labels(result=RESULT_MISSING).inc(missing)


@contextmanager
def observe(operation: str, *, outcomes: dict[type[BaseException], str]) -> Iterator[None]:
    """Time an operation and classify its outcome.

    ``outcomes`` maps exception types to a fixed outcome label so the caller
    never passes a dynamic string into the metric.
    """
    started = time.perf_counter()
    outcome = OUTCOME_SUCCESS
    try:
        yield
    except BaseException as exc:
        outcome = OUTCOME_ERROR
        for exc_type, label in outcomes.items():
            if isinstance(exc, exc_type):
                outcome = label
                break
        raise
    finally:
        VAULT_OPERATION_SECONDS.labels(operation=operation).observe(time.perf_counter() - started)
        VAULT_OPERATIONS_TOTAL.labels(operation=operation, outcome=outcome).inc()
