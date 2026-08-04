"""Tenant-scoped data access.

Every repository here is defined behind a ``typing.Protocol`` so services depend
on the interface rather than on SQLAlchemy, and so tests can substitute fakes
without a database.

The invariant that matters: with the single documented exception of
``ApiKeyAuthenticator`` -- which must run before a tenant is known, and which
demands the raw credential in exchange -- every method takes a tenant id as a
required argument. Tenant scoping is a parameter, not a filter a caller might
forget to apply.
"""

from __future__ import annotations

from app.repositories.api_keys import (
    ApiKeyAuthenticator,
    ApiKeyRepository,
    GeneratedApiKey,
    IssuedApiKey,
    SqlAlchemyApiKeyRepository,
    generate_api_key,
    hash_api_key,
    prefix_of,
    verify_api_key,
)
from app.repositories.audit_events import (
    AuditEventDraft,
    AuditEventRepository,
    SqlAlchemyAuditEventRepository,
)
from app.repositories.policies import (
    DEFAULT_POLICY_NAME,
    PolicyRepository,
    SqlAlchemyPolicyRepository,
)
from app.repositories.provider_configs import (
    ProviderConfigRepository,
    SqlAlchemyProviderConfigRepository,
    resolve_secret,
)
from app.repositories.tenants import SqlAlchemyTenantRepository, TenantRepository

__all__ = [
    "DEFAULT_POLICY_NAME",
    "ApiKeyAuthenticator",
    "ApiKeyRepository",
    "AuditEventDraft",
    "AuditEventRepository",
    "GeneratedApiKey",
    "IssuedApiKey",
    "PolicyRepository",
    "ProviderConfigRepository",
    "SqlAlchemyApiKeyRepository",
    "SqlAlchemyAuditEventRepository",
    "SqlAlchemyPolicyRepository",
    "SqlAlchemyProviderConfigRepository",
    "SqlAlchemyTenantRepository",
    "TenantRepository",
    "generate_api_key",
    "hash_api_key",
    "prefix_of",
    "resolve_secret",
    "verify_api_key",
]
