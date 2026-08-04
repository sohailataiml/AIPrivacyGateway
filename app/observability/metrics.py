"""HTTP metrics and the single export surface for everything else.

Two jobs live here.

**The HTTP instruments.** Request counts, latency, and in-flight depth for the
whole application, labelled by method, route, and status.

**The export surface.** :func:`render` is the only place in the application that
serialises the registry. Every other module -- vault, auth, audit, pipeline,
tokenization -- defines its instruments against the same default registry, so
they appear in the scrape without any of them knowing this module exists.

Cardinality rule, the same one every ``metrics.py`` in this repository obeys: a
label value must come from a set that is closed at import time. Two of the three
HTTP labels are attacker-controlled at first glance, so both are folded onto a
closed set before they are ever used:

* ``route`` is the Starlette *route template* (``/v1/sessions/{session_id}``),
  never the request path. Requests that match no route -- which is every URL a
  scanner invents -- collapse onto :data:`ROUTE_UNMATCHED`. Without that,
  anyone on the internet could mint an unbounded number of time series by
  requesting an unbounded number of 404s.
* ``method`` is folded onto :data:`KNOWN_METHODS`; anything else is
  :data:`METHOD_OTHER`. A method is a token in the request line, so it is just
  as caller-controlled as a path.

Status is the numeric code. The set of codes this application can produce is
small and fixed by its own error catalog, so it needs no folding.

Single process assumed. The gateway runs one worker per container, so the
default in-process registry is the whole story; a multi-worker deployment would
need ``prometheus_client``'s multiprocess collector and a shared directory.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, Counter, Gauge, Histogram
from prometheus_client import generate_latest as _generate_latest

ROUTE_UNMATCHED: Final = "unmatched"
"""Label used for any request that did not match a declared route."""

METHOD_OTHER: Final = "other"
"""Label used for any method outside :data:`KNOWN_METHODS`."""

KNOWN_METHODS: Final[frozenset[str]] = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
)

HTTP_REQUESTS_TOTAL: Final = Counter(
    "sgw_http_requests_total",
    "HTTP requests by method, route template, and status code.",
    labelnames=("method", "route", "status"),
)

HTTP_REQUEST_DURATION_SECONDS: Final = Histogram(
    "sgw_http_request_duration_seconds",
    "End-to-end request latency, measured at the outermost middleware.",
    labelnames=("method", "route"),
    # Reaches 30s because the ceiling that matters is the provider deadline, not
    # the p99 of a healthy gateway. A bucket set that tops out at 1s reports
    # every slow request as "+Inf" and hides the difference between 2s and 60s.
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)

HTTP_ACTIVE_REQUESTS: Final = Gauge(
    "sgw_active_requests",
    "Requests currently in flight. Unlabelled: one number per process.",
)


def normalize_method(method: str) -> str:
    """Fold an HTTP method onto the closed label set."""
    upper = method.upper()
    return upper if upper in KNOWN_METHODS else METHOD_OTHER


def normalize_route(route_path: str | None) -> str:
    """Fold a matched route template onto a label, or report it unmatched.

    Args:
        route_path: The template Starlette matched, or ``None`` when nothing
            matched. Pass the template, never ``request.url.path``.
    """
    return route_path if route_path else ROUTE_UNMATCHED


def observe_request(
    *, method: str, route: str | None, status: int, duration_seconds: float
) -> None:
    """Record one finished HTTP request.

    Both label values are folded here rather than at the call site, so a caller
    that forgets to normalise cannot widen the label space.
    """
    safe_method = normalize_method(method)
    safe_route = normalize_route(route)
    HTTP_REQUESTS_TOTAL.labels(method=safe_method, route=safe_route, status=str(status)).inc()
    HTTP_REQUEST_DURATION_SECONDS.labels(method=safe_method, route=safe_route).observe(
        duration_seconds
    )


@contextmanager
def track_in_flight() -> Iterator[None]:
    """Hold the in-flight gauge up for the duration of one request.

    Decremented in a ``finally`` so a request that raises, times out, or is
    cancelled still releases its slot. A gauge that only counts up is worse than
    no gauge: it reads as a permanent saturation alert.
    """
    HTTP_ACTIVE_REQUESTS.inc()
    try:
        yield
    finally:
        HTTP_ACTIVE_REQUESTS.dec()


def elapsed_since(started: float) -> float:
    """Seconds since a ``time.perf_counter()`` reading, never negative."""
    return max(time.perf_counter() - started, 0.0)


def render() -> tuple[bytes, str]:
    """Serialise the registry for a scrape.

    Returns:
        The exposition payload and the content type to send with it.
    """
    return _generate_latest(REGISTRY), CONTENT_TYPE_LATEST
