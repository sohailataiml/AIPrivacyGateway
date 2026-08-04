"""Policy engine.

The public surface other packages code against:

- :class:`PolicyDocument` -- the validated stored form.
- :class:`PolicySnapshot` -- the immutable, versioned runtime form.
- :class:`PolicyService` -- resolution, allowlist enforcement, short-TTL cache.
- :class:`PolicyRepository` -- the one read this package needs from persistence.
- :func:`validate_policy_document` -- the only door raw JSON comes through.
- :data:`DEFAULT_POLICY` -- the system default document.
"""

from __future__ import annotations

from app.policy.defaults import (
    DEFAULT_MODEL_ALIAS,
    DEFAULT_POLICY,
    DEFAULT_POLICY_NAME,
    DEFAULT_PROVIDER_ALIAS,
)
from app.policy.models import (
    MAX_POLICY_ENTITY_BUDGET,
    MAX_SESSION_TTL_SECONDS,
    POLICY_SCHEMA_VERSION,
    UNKNOWN_ENTITY_ACTION,
    UNKNOWN_ENTITY_MIN_SCORE,
    EntityRule,
    PolicyDocument,
    PolicySnapshot,
    ProviderRule,
    StoredPolicy,
)
from app.policy.service import POLICY_CACHE_TTL_SECONDS, PolicyRepository, PolicyService
from app.policy.validation import validate_policy_document, validate_policy_file

__all__ = [
    "DEFAULT_MODEL_ALIAS",
    "DEFAULT_POLICY",
    "DEFAULT_POLICY_NAME",
    "DEFAULT_PROVIDER_ALIAS",
    "MAX_POLICY_ENTITY_BUDGET",
    "MAX_SESSION_TTL_SECONDS",
    "POLICY_CACHE_TTL_SECONDS",
    "POLICY_SCHEMA_VERSION",
    "UNKNOWN_ENTITY_ACTION",
    "UNKNOWN_ENTITY_MIN_SCORE",
    "EntityRule",
    "PolicyDocument",
    "PolicyRepository",
    "PolicyService",
    "PolicySnapshot",
    "ProviderRule",
    "StoredPolicy",
    "validate_policy_document",
    "validate_policy_file",
]
