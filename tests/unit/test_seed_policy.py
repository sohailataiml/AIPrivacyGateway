"""The seed script must write the policy the gateway actually ships.

An earlier version of ``scripts/seed_local.py`` restated the default policy
document instead of deriving it. When the PHONE_NUMBER threshold was lowered in
``app/policy/defaults.py`` to stop phone numbers reaching the provider in the
clear, that copy kept the old value -- so a freshly seeded database ran the
unsafe policy while the entire test suite stayed green. It surfaced only by
POSTing a real request to a real server.

These tests pin the seeded document to the shipped one so the two cannot drift
apart again.
"""

from __future__ import annotations

from typing import Any

from app.llm.openai_provider import OPENAI_PROVIDER_ALIAS
from app.policy.defaults import DEFAULT_POLICY
from app.policy.models import PolicyDocument
from scripts.seed_local import (
    DEMO_OPENAI_MODELS,
    LOCAL_MODEL_ALIAS,
    LOCAL_PROVIDER_ALIAS,
    _default_policy_document,
)

# Substituted deliberately: the shipped default names a provider a local machine
# has no credentials for.
LOCALLY_SUBSTITUTED_KEYS = frozenset({"providers"})


def test_seeded_document_matches_the_shipped_default() -> None:
    # Arrange
    shipped: dict[str, Any] = DEFAULT_POLICY.model_dump(mode="json")

    # Act
    seeded = _default_policy_document()

    # Assert
    for key, value in shipped.items():
        if key in LOCALLY_SUBSTITUTED_KEYS:
            continue
        assert seeded[key] == value, f"seeded {key} drifted from the shipped default"


def test_seeded_thresholds_are_identical_to_the_shipped_ones() -> None:
    # The specific failure that reached a running server: a threshold that
    # differed between the shipped policy and the seeded one.
    shipped = DEFAULT_POLICY.model_dump(mode="json")["entities"]

    seeded = _default_policy_document()["entities"]

    assert seeded == shipped


def test_only_the_provider_allowlist_is_substituted() -> None:
    """The demo policy permits the mock and the external provider, and nothing else.

    Permitting is not enabling: the registry adds the external adapter only when
    a credential is configured, so on a credential-free machine the alias is
    absent from ``GET /v1/providers`` and unreachable from chat. Listing it here
    means adding the credential is the only step needed to demonstrate the same
    pipeline against a real model.
    """
    seeded = _default_policy_document()

    assert set(seeded["providers"]) == {LOCAL_PROVIDER_ALIAS, OPENAI_PROVIDER_ALIAS}
    assert seeded["providers"][LOCAL_PROVIDER_ALIAS]["models"] == [LOCAL_MODEL_ALIAS]
    assert seeded["providers"][OPENAI_PROVIDER_ALIAS]["models"] == list(DEMO_OPENAI_MODELS)


def test_the_mock_remains_the_local_default_provider() -> None:
    # A demo that opens pointed at a paid service is a demo that costs money to
    # open, so the extra allowlist entry must not change which one is default.
    assert LOCAL_PROVIDER_ALIAS == "mock"


def test_the_seeded_document_is_valid() -> None:
    # A document that cannot be validated can never become an active policy, so
    # seeding one would leave the tenant with no policy at all.
    document = PolicyDocument.model_validate(_default_policy_document())

    assert document.name == DEFAULT_POLICY.name


def test_seeding_does_not_mutate_the_shipped_default() -> None:
    before = DEFAULT_POLICY.model_dump(mode="json")

    _default_policy_document()

    assert DEFAULT_POLICY.model_dump(mode="json") == before
