"""``GET /metrics`` -- the Prometheus scrape endpoint.

Guarded by a dedicated bearer token rather than by the API-key machinery every
other route uses, for one reason: a scrape must keep working during the outage
it is meant to explain. ``require_scope`` reaches PostgreSQL to verify a key, so
using it here would blank the dashboards at exactly the moment the database goes
down -- and the metrics that say *why* it went down are the ones already in
memory, waiting to be read.

So the check is a constant-time comparison against ``METRICS_TOKEN`` and touches
nothing. It is a shared secret for one machine consumer, not a user credential:
there is no tenant, no scope, and no rate limit behind it.

An unset token leaves the endpoint open, which is deliberate for local work and
impossible in production -- ``Settings`` refuses to build without one when
metrics are enabled. Mounting is likewise conditional: ``METRICS_ENABLED=false``
means the route does not exist rather than existing and refusing.

What the payload discloses is worth stating plainly, because it is why the token
exists. Nothing here carries a tenant id, a session id, a token, or a detected
value -- every ``metrics.py`` in this repository enforces closed label sets for
that reason. But request rates, error rates, provider failures, and audit queue
depth together describe the health and shape of the deployment, and that is
reconnaissance worth denying to an anonymous reader.
"""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Request, Response, status

from app.api.errors import ErrorEnvelope
from app.auth.principal import AUTHORIZATION_HEADER, BEARER_SCHEME
from app.config.settings import Settings
from app.domain.errors import AuthenticationError
from app.observability import metrics
from app.observability.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["observability"])

METRICS_PATH = "/metrics"


def _configured_token(request: Request) -> str | None:
    """Return the expected scrape credential, or ``None`` if none is set."""
    settings = getattr(request.app.state, "settings", None)
    if not isinstance(settings, Settings) or settings.metrics_token is None:
        return None
    return settings.metrics_token.get_secret_value()


def _presented_token(request: Request) -> str | None:
    """Extract the bearer credential from the request, if it is well formed."""
    header = request.headers.get(AUTHORIZATION_HEADER)
    if not header:
        return None
    scheme, separator, credential = header.partition(" ")
    if not separator or scheme.lower() != BEARER_SCHEME:
        return None
    return credential.strip() or None


def authorize_scrape(request: Request) -> None:
    """Admit the scraper, or refuse without saying why.

    ``hmac.compare_digest`` rather than ``==``: the comparison is against a
    static secret that an attacker can probe as often as they like, which is the
    setting where a byte-at-a-time timing difference is actually exploitable.

    Raises:
        AuthenticationError: if a token is configured and the request does not
            present exactly it.
    """
    expected = _configured_token(request)
    if expected is None:
        # No token configured. Production cannot reach this branch; a local
        # stack scrapes without ceremony.
        return

    presented = _presented_token(request)
    if presented is None or not hmac.compare_digest(presented, expected):
        # The reason is withheld from the caller and kept coarse in the log:
        # "wrong token" and "no token" are the same event to an operator, and
        # distinguishing them for the caller is a probing aid.
        logger.warning("metrics_scrape_denied")
        raise AuthenticationError(log_context={"reason": "metrics_token_invalid"})


@router.get(
    METRICS_PATH,
    summary="Prometheus exposition",
    response_description="Prometheus text exposition format.",
    responses={
        status.HTTP_200_OK: {
            "content": {"text/plain": {}},
            "description": "Current values of every registered instrument.",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorEnvelope,
            "description": "`AUTHENTICATION_FAILED` -- absent or incorrect scrape token",
        },
    },
)
async def scrape(request: Request) -> Response:
    """Serialise every registered instrument for a scrape."""
    authorize_scrape(request)
    payload, content_type = metrics.render()
    return Response(content=payload, media_type=content_type)
