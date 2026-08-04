"""Authentication, authorization, and rate-limit counters.

Cardinality rule for this module, without exception: every label value comes
from a closed set fixed at import time. No tenant id, api key id, key prefix,
request path, method, or credential fragment ever becomes a label. Those are
caller- or deployment-controlled and would let one noisy tenant multiply the
series count until the scrape falls over -- and, worse, would publish the
identity of every key that ever authenticated to anyone who can read /metrics.

The recorder functions validate their argument against the closed set and raise
``ValueError`` on anything else. That turns "someone passed a dynamic string
into a label" from a slow production leak into an immediate test failure.

``scope`` is a label on the authorization counter because ``Scope`` is a
three-member enum defined in this repository; it is closed in the same sense
the outcome sets are.
"""

from __future__ import annotations

from typing import Final

from prometheus_client import Counter

from app.domain.models import Scope

# -- Authentication outcomes ------------------------------------------------
AUTH_OUTCOME_SUCCESS: Final = "success"
AUTH_OUTCOME_MISSING_CREDENTIAL: Final = "missing_credential"
AUTH_OUTCOME_UNSUPPORTED_SCHEME: Final = "unsupported_scheme"
AUTH_OUTCOME_MALFORMED_CREDENTIAL: Final = "malformed_credential"
AUTH_OUTCOME_INVALID_CREDENTIAL: Final = "invalid_credential"
AUTH_OUTCOME_EXPIRED_CREDENTIAL: Final = "expired_credential"
AUTH_OUTCOME_REVOKED_CREDENTIAL: Final = "revoked_credential"
AUTH_OUTCOME_BACKEND_UNAVAILABLE: Final = "backend_unavailable"
AUTH_OUTCOME_NOT_CONFIGURED: Final = "not_configured"

AUTH_OUTCOMES: Final[frozenset[str]] = frozenset(
    {
        AUTH_OUTCOME_SUCCESS,
        AUTH_OUTCOME_MISSING_CREDENTIAL,
        AUTH_OUTCOME_UNSUPPORTED_SCHEME,
        AUTH_OUTCOME_MALFORMED_CREDENTIAL,
        AUTH_OUTCOME_INVALID_CREDENTIAL,
        AUTH_OUTCOME_EXPIRED_CREDENTIAL,
        AUTH_OUTCOME_REVOKED_CREDENTIAL,
        AUTH_OUTCOME_BACKEND_UNAVAILABLE,
        AUTH_OUTCOME_NOT_CONFIGURED,
    }
)

# -- Authorization outcomes -------------------------------------------------
AUTHZ_OUTCOME_GRANTED: Final = "granted"
AUTHZ_OUTCOME_DENIED: Final = "denied"

AUTHZ_OUTCOMES: Final[frozenset[str]] = frozenset({AUTHZ_OUTCOME_GRANTED, AUTHZ_OUTCOME_DENIED})

# -- Rate-limit buckets and outcomes ----------------------------------------
BUCKET_TENANT: Final = "tenant"
BUCKET_API_KEY: Final = "api_key"

BUCKETS: Final[frozenset[str]] = frozenset({BUCKET_TENANT, BUCKET_API_KEY})

RATE_LIMIT_OUTCOME_ALLOWED: Final = "allowed"
RATE_LIMIT_OUTCOME_THROTTLED: Final = "throttled"
RATE_LIMIT_OUTCOME_FAILED_CLOSED: Final = "backend_error_failed_closed"
RATE_LIMIT_OUTCOME_FAILED_OPEN: Final = "backend_error_failed_open"
RATE_LIMIT_OUTCOME_NOT_CONFIGURED: Final = "not_configured"

RATE_LIMIT_OUTCOMES: Final[frozenset[str]] = frozenset(
    {
        RATE_LIMIT_OUTCOME_ALLOWED,
        RATE_LIMIT_OUTCOME_THROTTLED,
        RATE_LIMIT_OUTCOME_FAILED_CLOSED,
        RATE_LIMIT_OUTCOME_FAILED_OPEN,
        RATE_LIMIT_OUTCOME_NOT_CONFIGURED,
    }
)

# -- last_used_at write outcomes --------------------------------------------
LAST_USED_OUTCOME_WRITTEN: Final = "written"
LAST_USED_OUTCOME_SKIPPED: Final = "skipped"
LAST_USED_OUTCOME_FAILED: Final = "failed"

LAST_USED_OUTCOMES: Final[frozenset[str]] = frozenset(
    {LAST_USED_OUTCOME_WRITTEN, LAST_USED_OUTCOME_SKIPPED, LAST_USED_OUTCOME_FAILED}
)


AUTHENTICATION_ATTEMPTS_TOTAL: Final = Counter(
    "sgw_auth_attempts_total",
    "Authentication attempts by outcome.",
    labelnames=("outcome",),
)

AUTHORIZATION_DECISIONS_TOTAL: Final = Counter(
    "sgw_authz_decisions_total",
    "Scope checks by required scope and outcome.",
    labelnames=("scope", "outcome"),
)

RATE_LIMIT_DECISIONS_TOTAL: Final = Counter(
    "sgw_rate_limit_decisions_total",
    "Rate-limit decisions by bucket and outcome.",
    labelnames=("bucket", "outcome"),
)

API_KEY_LAST_USED_UPDATES_TOTAL: Final = Counter(
    "sgw_api_key_last_used_updates_total",
    "Bounded-frequency last_used_at writes by outcome.",
    labelnames=("outcome",),
)


def _checked(value: str, allowed: frozenset[str], what: str) -> str:
    if value not in allowed:
        raise ValueError(f"{what} label must be one of {sorted(allowed)}")
    return value


def record_authentication(outcome: str) -> None:
    """Count one authentication attempt."""
    AUTHENTICATION_ATTEMPTS_TOTAL.labels(
        outcome=_checked(outcome, AUTH_OUTCOMES, "authentication outcome")
    ).inc()


def record_authorization(*, scope: Scope, outcome: str) -> None:
    """Count one scope check. ``scope`` must be a ``Scope`` member, not a string."""
    if not isinstance(scope, Scope):
        raise TypeError("scope must be a Scope member so the label set stays closed")
    AUTHORIZATION_DECISIONS_TOTAL.labels(
        scope=scope.value,
        outcome=_checked(outcome, AUTHZ_OUTCOMES, "authorization outcome"),
    ).inc()


def record_rate_limit(*, bucket: str, outcome: str) -> None:
    """Count one rate-limit decision for one bucket."""
    RATE_LIMIT_DECISIONS_TOTAL.labels(
        bucket=_checked(bucket, BUCKETS, "rate-limit bucket"),
        outcome=_checked(outcome, RATE_LIMIT_OUTCOMES, "rate-limit outcome"),
    ).inc()


def record_last_used(outcome: str) -> None:
    """Count one ``last_used_at`` maintenance decision."""
    API_KEY_LAST_USED_UPDATES_TOTAL.labels(
        outcome=_checked(outcome, LAST_USED_OUTCOMES, "last_used outcome")
    ).inc()
