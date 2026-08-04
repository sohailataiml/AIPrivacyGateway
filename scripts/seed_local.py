"""Seed a local development tenant, default policy, and API key.

Idempotent by construction: the tenant is keyed on its slug, the policy on
``(tenant_id, name, version)``, and the API key on ``(tenant_id, name)``. Run it
as many times as you like -- the second run reports what already exists and
changes nothing.

This script is the one place in the repository that legitimately writes a raw
API key to stdout. It is printed exactly once, at creation; a second run cannot
reprint it because the raw value was never stored. Refuses to run against a
production environment.

Usage::

    python -m scripts.seed_local
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any
from uuid import UUID

from app.config.settings import AppEnv, Settings
from app.db.session import build_engine_from_settings, build_session_factory, transaction
from app.domain.models import Scope
from app.policy.defaults import DEFAULT_MODEL_ALIAS, DEFAULT_POLICY
from app.repositories.api_keys import SqlAlchemyApiKeyRepository
from app.repositories.policies import DEFAULT_POLICY_NAME, SqlAlchemyPolicyRepository
from app.repositories.provider_configs import SqlAlchemyProviderConfigRepository
from app.repositories.tenants import SqlAlchemyTenantRepository

LOCAL_TENANT_SLUG = "local"
LOCAL_TENANT_NAME = "Local Development"
LOCAL_API_KEY_NAME = "local-development"
LOCAL_PROVIDER_ALIAS = "mock"
LOCAL_MODEL_ALIAS = DEFAULT_MODEL_ALIAS
# The suppression below is justified: this is the *name* of an environment
# variable, the only thing provider_configs.secret_ref ever holds. Not a secret.
LOCAL_PROVIDER_SECRET_REF = "OPENAI_API_KEY"  # noqa: S105
DEFAULT_POLICY_VERSION = 1


def _default_policy_document() -> dict[str, Any]:
    """Serialize the shipped default policy for storage.

    Derived from ``app.policy.defaults.DEFAULT_POLICY`` rather than restated
    here. An earlier version of this file kept its own copy of the document,
    and when the PHONE_NUMBER threshold was lowered in ``defaults.py`` to stop
    phone numbers leaking, this copy silently kept the old value -- so a freshly
    seeded database was still running the unsafe policy while every test passed.

    One definition, serialized. The only local substitution is the provider
    alias, because the shipped default names a provider this machine has no
    credentials for.
    """
    document: dict[str, Any] = DEFAULT_POLICY.model_dump(mode="json")
    document["providers"] = {LOCAL_PROVIDER_ALIAS: {"models": [LOCAL_MODEL_ALIAS]}}
    return document


def _write(line: str) -> None:
    """Emit an operator-facing line. ``print`` is banned by lint in this repo."""
    sys.stdout.write(f"{line}\n")


async def _seed_policy(policies: SqlAlchemyPolicyRepository, tenant_id: UUID) -> tuple[UUID, bool]:
    existing = await policies.get_version(
        tenant_id, name=DEFAULT_POLICY_NAME, version=DEFAULT_POLICY_VERSION
    )
    if existing is not None:
        return existing.id, False

    policy = await policies.create_version(
        tenant_id,
        name=DEFAULT_POLICY_NAME,
        version=DEFAULT_POLICY_VERSION,
        document=_default_policy_document(),
        is_active=True,
    )
    return policy.id, True


async def seed(settings: Settings) -> None:
    """Create the local tenant, policy, provider alias, and API key."""
    if settings.app_env is AppEnv.PRODUCTION:
        raise SystemExit("refusing to seed a production environment")

    engine = build_engine_from_settings(settings)
    session_factory = build_session_factory(engine)

    try:
        async with session_factory() as session, transaction(session):
            tenants = SqlAlchemyTenantRepository(session)
            policies = SqlAlchemyPolicyRepository(session)
            providers = SqlAlchemyProviderConfigRepository(session)
            api_keys = SqlAlchemyApiKeyRepository(session)

            tenant = await tenants.get_by_slug(LOCAL_TENANT_SLUG)
            if tenant is None:
                tenant = await tenants.create(name=LOCAL_TENANT_NAME, slug=LOCAL_TENANT_SLUG)
                _write(f"created tenant {tenant.id} ({LOCAL_TENANT_SLUG})")
            else:
                _write(f"tenant {tenant.id} ({LOCAL_TENANT_SLUG}) already exists")

            policy_id, policy_created = await _seed_policy(policies, tenant.id)
            verb = "created" if policy_created else "already exists:"
            _write(f"policy {verb} {policy_id} ({DEFAULT_POLICY_NAME} v{DEFAULT_POLICY_VERSION})")

            # upsert is idempotent; it stores the env var name, not its value.
            await providers.upsert(
                tenant.id,
                alias=LOCAL_PROVIDER_ALIAS,
                provider_type=LOCAL_PROVIDER_ALIAS,
                secret_ref=LOCAL_PROVIDER_SECRET_REF,
                allowed_models=["general-chat"],
            )
            _write(
                f"provider alias {LOCAL_PROVIDER_ALIAS!r} references "
                f"${LOCAL_PROVIDER_SECRET_REF} (no secret stored)"
            )

            existing_keys = await api_keys.list_for_tenant(tenant.id)
            if any(key.name == LOCAL_API_KEY_NAME for key in existing_keys):
                _write(
                    f"api key {LOCAL_API_KEY_NAME!r} already exists; "
                    "the raw value was shown only at creation and cannot be recovered"
                )
                return

            issued = await api_keys.create(
                tenant.id,
                name=LOCAL_API_KEY_NAME,
                scopes=[scope.value for scope in Scope],
                pepper=settings.api_key_pepper,
            )
            _write(f"created api key {issued.record.id} (prefix {issued.record.prefix})")
            _write("")
            _write("Copy this now. It is shown once and is not stored anywhere:")
            _write(f"  {issued.raw_key}")
            _write("")
    finally:
        await engine.dispose()


def main() -> None:
    asyncio.run(seed(Settings()))


if __name__ == "__main__":
    main()
