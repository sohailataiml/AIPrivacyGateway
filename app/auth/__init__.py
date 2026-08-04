"""Authentication, authorization, and rate limiting.

Routers import from ``app.auth.dependencies``; nothing else in the application
needs to know how a credential becomes a ``Principal``.
"""

from __future__ import annotations

from app.auth.dependencies import (
    CurrentPrincipal,
    get_principal,
    get_rate_limiter,
    require_scope,
)
from app.auth.last_used import LastUsedTracker, LastUsedWriter
from app.auth.principal import BearerCredential, authenticate_bearer, parse_bearer_credential
from app.auth.rate_limit import (
    InMemoryRateLimiter,
    RateLimitDecision,
    RateLimiter,
    RateLimitRule,
    RedisRateLimiter,
    enforce,
)

__all__ = [
    "BearerCredential",
    "CurrentPrincipal",
    "InMemoryRateLimiter",
    "LastUsedTracker",
    "LastUsedWriter",
    "RateLimitDecision",
    "RateLimitRule",
    "RateLimiter",
    "RedisRateLimiter",
    "authenticate_bearer",
    "enforce",
    "get_principal",
    "get_rate_limiter",
    "parse_bearer_credential",
    "require_scope",
]
