"""FastAPI dependencies routers depend on to get an authenticated principal.

A router asks for exactly one thing::

    @router.post("/v1/chat")
    async def chat(principal: Annotated[Principal, Depends(require_scope(Scope.CHAT_INVOKE))]):
        ...

``require_scope`` authenticates, rate limits, and then checks the scope, in that
order, so there is no way to write an endpoint that checks a scope but forgets
to authenticate, or that authenticates but escapes the rate limiter. Endpoints
that genuinely need no scope can depend on ``get_principal`` directly; they are
still authenticated and still limited.

Collaborators are read from ``app.state`` so this package does not have to
import, or care about, the application's wiring:

``api_key_authenticator``
    An ``ApiKeyAuthenticator``. Falls back to constructing
    ``SqlAlchemyApiKeyRepository`` over ``app.state.db_session_factory``.
``rate_limiter``
    A ``RateLimiter``. Falls back to a ``RedisRateLimiter`` over
    ``app.state.redis``.
``api_key_repository``
    Optional ``LastUsedWriter``; the authenticator is used when it already
    satisfies that protocol.

Every fallback is fail-closed. With nothing wired, authentication returns 401
and the rate limiter denies -- a half-configured deployment serves nobody rather
than serving everybody unmetered.

One limit of the design worth stating: buckets are keyed by the *authenticated*
principal, so an unauthenticated flood is bounded by the body-size middleware
and by the single HMAC an attempt costs, not by these counters. Limiting
unauthenticated traffic belongs at the edge, where the client address is
trustworthy.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import TYPE_CHECKING, Annotated, Final, cast

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.auth import metrics
from app.auth.last_used import LastUsedTracker, LastUsedWriter
from app.auth.principal import AUTHORIZATION_HEADER, authenticate_bearer
from app.auth.rate_limit import (
    RateLimitDecision,
    RateLimiter,
    RedisRateLimiter,
    enforce,
    not_configured_decision,
)
from app.config.settings import Settings, get_settings
from app.domain.errors import AuthenticationError, AuthorizationError
from app.domain.models import Principal, Scope
from app.repositories.api_keys import ApiKeyAuthenticator, SqlAlchemyApiKeyRepository

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = logging.getLogger("app.auth")

STATE_AUTHENTICATOR: Final = "api_key_authenticator"
STATE_SESSION_FACTORY: Final = "db_session_factory"
STATE_RATE_LIMITER: Final = "rate_limiter"
STATE_REDIS: Final = "redis"
STATE_API_KEY_REPOSITORY: Final = "api_key_repository"
STATE_LAST_USED_TRACKER: Final = "last_used_tracker"

_PROCESS_LAST_USED_TRACKER: Final = LastUsedTracker()
"""One tracker per process, so the write bound holds across requests."""


class _UnconfiguredRateLimiter:
    """Stands in when no limiter is wired. Denies everything, loudly."""

    async def acquire(self, principal: Principal) -> RateLimitDecision:
        logger.error("rate_limiter_not_configured", extra={"reason": "rate_limiter_not_configured"})
        return not_configured_decision()


def _from_state(request: Request, name: str) -> object | None:
    return getattr(request.app.state, name, None)


async def get_settings_for_request(request: Request) -> Settings:
    """Settings attached at application startup, or the process singleton."""
    configured = _from_state(request, "settings")
    if isinstance(configured, Settings):
        return configured
    return get_settings()


async def get_api_key_authenticator(request: Request) -> AsyncIterator[ApiKeyAuthenticator]:
    """Yield the pre-tenant key lookup for this request.

    Raises:
        AuthenticationError: nothing is wired, so no caller can be identified.
    """
    configured = _from_state(request, STATE_AUTHENTICATOR)
    if configured is not None:
        yield cast(ApiKeyAuthenticator, configured)
        return

    factory = _from_state(request, STATE_SESSION_FACTORY)
    if isinstance(factory, async_sessionmaker):
        session_factory = cast("async_sessionmaker[AsyncSession]", factory)
        async with session_factory() as session:
            yield SqlAlchemyApiKeyRepository(session)
        return

    logger.error("authenticator_not_configured", extra={"reason": "authenticator_not_configured"})
    metrics.record_authentication(metrics.AUTH_OUTCOME_NOT_CONFIGURED)
    raise AuthenticationError(log_context={"reason": "authenticator_not_configured"})


async def get_rate_limiter(request: Request) -> RateLimiter:
    """Return the configured limiter, or one that denies every request."""
    configured = _from_state(request, STATE_RATE_LIMITER)
    if configured is not None:
        return cast(RateLimiter, configured)

    redis = _from_state(request, STATE_REDIS)
    if redis is not None:
        return RedisRateLimiter(cast("Redis", redis))

    return _UnconfiguredRateLimiter()


async def get_last_used_tracker(request: Request) -> LastUsedTracker:
    """Return the process tracker unless a test or wiring supplied one."""
    configured = _from_state(request, STATE_LAST_USED_TRACKER)
    if isinstance(configured, LastUsedTracker):
        return configured
    return _PROCESS_LAST_USED_TRACKER


def _last_used_writer(
    request: Request, authenticator: ApiKeyAuthenticator
) -> LastUsedWriter | None:
    """Prefer an explicit repository; otherwise reuse the authenticator."""
    repository = _from_state(request, STATE_API_KEY_REPOSITORY)
    if isinstance(repository, LastUsedWriter):
        return repository
    if isinstance(authenticator, LastUsedWriter):
        return authenticator
    return None


async def get_principal(
    request: Request,
    authenticator: Annotated[ApiKeyAuthenticator, Depends(get_api_key_authenticator)],
    settings: Annotated[Settings, Depends(get_settings_for_request)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    tracker: Annotated[LastUsedTracker, Depends(get_last_used_tracker)],
) -> Principal:
    """Authenticate the caller, charge the rate limit, and return the principal.

    The tenant comes from the verified key record and nowhere else: a header or
    body field naming a tenant is data, not identity, and is ignored here.
    """
    principal = await authenticate_bearer(
        request.headers.get(AUTHORIZATION_HEADER),
        authenticator=authenticator,
        pepper=settings.api_key_pepper,
    )
    await enforce(limiter, principal)

    # Downstream stages read the principal from request state rather than
    # re-authenticating; it is frozen, so nothing can widen it in flight.
    request.state.principal = principal

    await tracker.record_use(_last_used_writer(request, authenticator), principal)
    return principal


ScopeDependency = Callable[..., Awaitable[Principal]]


def require_scope(scope: Scope) -> ScopeDependency:
    """Build a dependency that admits only principals holding ``scope``.

    Raises:
        AuthorizationError: 403, with a message that names neither the scope nor
            the scopes the principal does hold.
    """
    if not isinstance(scope, Scope):
        raise TypeError("require_scope takes a Scope member, not a string")

    async def dependency(
        principal: Annotated[Principal, Depends(get_principal)],
    ) -> Principal:
        if not principal.has_scope(scope):
            metrics.record_authorization(scope=scope, outcome=metrics.AUTHZ_OUTCOME_DENIED)
            logger.info(
                "authorization_denied",
                extra={
                    "reason": "missing_scope",
                    "tenant_id": str(principal.tenant_id),
                    "api_key_id": str(principal.api_key_id),
                },
            )
            raise AuthorizationError(log_context={"reason": "missing_scope"})

        metrics.record_authorization(scope=scope, outcome=metrics.AUTHZ_OUTCOME_GRANTED)
        return principal

    dependency.__name__ = f"require_scope_{scope.name.lower()}"
    return dependency


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
"""Convenience alias for endpoints that need authentication but no scope."""
