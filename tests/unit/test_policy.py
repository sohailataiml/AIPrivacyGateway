"""Tests for the policy engine.

Four properties are load-bearing and each has its own section below:

1. An invalid document cannot become an active policy.
2. A provider or model outside the allowlist is refused during resolution --
   before detection runs and before any provider client exists.
3. Resolution always yields a versioned, immutable object.
4. The resolution cache is short-lived, tenant-scoped, and holds configuration
   only.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

from app.domain.errors import (
    ErrorCode,
    InvalidRequestError,
    ModelNotAllowedError,
    PolicyNotFoundError,
    ProviderNotAllowedError,
)
from app.domain.models import EntityAction, UnknownTokenAction
from app.policy import (
    DEFAULT_MODEL_ALIAS,
    DEFAULT_POLICY,
    DEFAULT_PROVIDER_ALIAS,
    POLICY_CACHE_TTL_SECONDS,
    POLICY_SCHEMA_VERSION,
    UNKNOWN_ENTITY_ACTION,
    UNKNOWN_ENTITY_MIN_SCORE,
    EntityRule,
    PolicyDocument,
    PolicyRepository,
    PolicyService,
    PolicySnapshot,
    ProviderRule,
    StoredPolicy,
    validate_policy_document,
    validate_policy_file,
)
from app.policy.validation import main as validate_main

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
TENANT = UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = UUID("22222222-2222-2222-2222-222222222222")


def document_dict(**overrides: Any) -> dict[str, Any]:
    """A valid raw document that a test can break one field at a time."""
    raw: dict[str, Any] = DEFAULT_POLICY.model_dump(mode="json")
    raw.update(overrides)
    return raw


def stored(document: dict[str, Any] | None = None, *, version: int = 7) -> StoredPolicy:
    return StoredPolicy(
        policy_id=uuid4(),
        tenant_id=TENANT,
        version=version,
        document=document if document is not None else document_dict(),
    )


class FakePolicyRepository:
    """In-memory stand-in for the persistence layer, with a read counter."""

    def __init__(self) -> None:
        self.rows: dict[UUID, StoredPolicy] = {}
        self.reads = 0

    def put(self, tenant_id: UUID, policy: StoredPolicy) -> None:
        self.rows[tenant_id] = policy

    def drop(self, tenant_id: UUID) -> None:
        self.rows.pop(tenant_id, None)

    async def get_active_policy(self, tenant_id: UUID) -> StoredPolicy | None:
        self.reads += 1
        return self.rows.get(tenant_id)


class ManualClock:
    """A clock a test drives, so TTL expiry needs no sleeping."""

    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class DownstreamSpy:
    """Stands in for detection and the provider call, which must never run."""

    def __init__(self) -> None:
        self.detect_calls = 0
        self.provider_calls = 0

    def detect(self) -> None:
        self.detect_calls += 1

    def call_provider(self) -> None:
        self.provider_calls += 1


@pytest.fixture
def repository() -> FakePolicyRepository:
    repo = FakePolicyRepository()
    repo.put(TENANT, stored())
    return repo


@pytest.fixture
def clock() -> ManualClock:
    return ManualClock()


@pytest.fixture
def service(repository: FakePolicyRepository, clock: ManualClock) -> PolicyService:
    return PolicyService(repository, clock=clock)


def snapshot_of(document: PolicyDocument, *, version: int = 1) -> PolicySnapshot:
    return PolicySnapshot.from_document(
        document, policy_id=uuid4(), tenant_id=TENANT, version=version
    )


# ---------------------------------------------------------------------------
# The default policy
# ---------------------------------------------------------------------------
def test_default_policy_matches_the_documented_example() -> None:
    # Arrange
    expected = {
        "schema_version": 1,
        "name": "default",
        "session_ttl_seconds": 1800,
        "max_entities": 500,
        "providers": {"openai-primary": {"models": ["general-chat"]}},
        "entities": {
            "EMAIL_ADDRESS": {"action": "tokenize", "min_score": 0.7},
            "PHONE_NUMBER": {"action": "tokenize", "min_score": 0.4},
            "US_SSN": {"action": "block", "min_score": 0.5},
            "CREDIT_CARD": {"action": "block", "min_score": 0.5},
            "PERSON": {"action": "tokenize", "min_score": 0.75},
            "LOCATION": {"action": "tokenize", "min_score": 0.8},
        },
        "unknown_output_token_action": "preserve",
    }

    # Act
    actual = DEFAULT_POLICY.model_dump(mode="json")

    # Assert
    assert actual == expected


def test_default_policy_passes_the_validator_it_ships_with() -> None:
    # Arrange / Act
    validated = validate_policy_document(DEFAULT_POLICY.model_dump(mode="json"))

    # Assert
    assert validated == DEFAULT_POLICY


# ---------------------------------------------------------------------------
# Property 1: an invalid document cannot become an active policy
# ---------------------------------------------------------------------------
INVALID_DOCUMENTS: list[tuple[str, dict[str, Any]]] = [
    ("unknown_top_level_field", document_dict(streaming_allowed=True)),
    ("misspelled_field_name", document_dict(unknown_token_action="redact")),
    ("missing_required_field", {k: v for k, v in document_dict().items() if k != "max_entities"}),
    ("schema_version_ahead", document_dict(schema_version=POLICY_SCHEMA_VERSION + 1)),
    ("schema_version_behind", document_dict(schema_version=POLICY_SCHEMA_VERSION - 1)),
    ("schema_version_not_an_integer", document_dict(schema_version="one")),
    ("empty_policy_name", document_dict(name="")),
    ("zero_session_ttl", document_dict(session_ttl_seconds=0)),
    ("negative_session_ttl", document_dict(session_ttl_seconds=-1)),
    ("session_ttl_beyond_one_day", document_dict(session_ttl_seconds=86_401)),
    ("zero_max_entities", document_dict(max_entities=0)),
    ("negative_max_entities", document_dict(max_entities=-5)),
    ("max_entities_beyond_budget", document_dict(max_entities=10_001)),
    ("no_providers", document_dict(providers={})),
    ("provider_with_no_models", document_dict(providers={"openai-primary": {"models": []}})),
    ("provider_with_empty_alias", document_dict(providers={"": {"models": ["general-chat"]}})),
    ("provider_with_empty_model_alias", document_dict(providers={"p": {"models": [""]}})),
    ("unknown_field_in_provider_rule", document_dict(providers={"p": {"models": ["m"], "x": 1}})),
    ("no_entities", document_dict(entities={})),
    ("unknown_entity_action", document_dict(entities={"EMAIL_ADDRESS": {"action": "encrypt"}})),
    (
        "entity_action_with_wrong_case",
        document_dict(entities={"EMAIL_ADDRESS": {"action": "TOKENIZE", "min_score": 0.7}}),
    ),
    (
        "entity_missing_min_score",
        document_dict(entities={"EMAIL_ADDRESS": {"action": "tokenize"}}),
    ),
    (
        "min_score_above_one",
        document_dict(entities={"EMAIL_ADDRESS": {"action": "tokenize", "min_score": 1.01}}),
    ),
    (
        "min_score_below_zero",
        document_dict(entities={"EMAIL_ADDRESS": {"action": "tokenize", "min_score": -0.1}}),
    ),
    (
        "min_score_not_a_number",
        document_dict(entities={"EMAIL_ADDRESS": {"action": "tokenize", "min_score": "high"}}),
    ),
    (
        "unknown_field_in_entity_rule",
        document_dict(
            entities={"EMAIL_ADDRESS": {"action": "tokenize", "min_score": 0.7, "hint": "x"}}
        ),
    ),
    (
        "empty_entity_type_name",
        document_dict(entities={"": {"action": "tokenize", "min_score": 0.7}}),
    ),
    (
        "oversized_entity_type_name",
        document_dict(entities={"E" * 65: {"action": "tokenize", "min_score": 0.7}}),
    ),
    ("unknown_output_token_action", document_dict(unknown_output_token_action="ignore")),
]


@pytest.mark.parametrize(
    "raw",
    [case[1] for case in INVALID_DOCUMENTS],
    ids=[case[0] for case in INVALID_DOCUMENTS],
)
def test_validation_rejects_an_invalid_document(raw: dict[str, Any]) -> None:
    # Arrange / Act
    with pytest.raises(InvalidRequestError) as caught:
        validate_policy_document(raw)

    # Assert
    assert caught.value.code is ErrorCode.INVALID_REQUEST
    assert caught.value.log_context["problems"]


def test_validation_reports_field_paths_without_echoing_the_input() -> None:
    # Arrange
    marker = "a-value-that-must-not-be-logged"
    raw = document_dict(entities={"EMAIL_ADDRESS": {"action": marker, "min_score": 0.7}})

    # Act
    with pytest.raises(InvalidRequestError) as caught:
        validate_policy_document(raw)

    # Assert
    context = str(caught.value.log_context)
    assert "entities.EMAIL_ADDRESS.action" in context
    assert marker not in context
    assert marker not in caught.value.public_message


def test_validation_does_not_mutate_the_document_it_is_given() -> None:
    # Arrange
    raw = document_dict()
    before = json.dumps(raw, sort_keys=True)

    # Act
    validate_policy_document(raw)

    # Assert
    assert json.dumps(raw, sort_keys=True) == before


def test_validate_policy_file_accepts_a_valid_document(tmp_path: Path) -> None:
    # Arrange
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document_dict()), encoding="utf-8")

    # Act
    document = validate_policy_file(path)

    # Assert
    assert document == DEFAULT_POLICY


def test_validate_policy_file_rejects_malformed_json(tmp_path: Path) -> None:
    # Arrange
    path = tmp_path / "policy.json"
    path.write_text("{not json", encoding="utf-8")

    # Act / Assert
    with pytest.raises(InvalidRequestError) as caught:
        validate_policy_file(path)
    assert caught.value.log_context["reason"] == "malformed_json"


def test_validate_policy_file_rejects_a_json_document_that_is_not_an_object(
    tmp_path: Path,
) -> None:
    # Arrange
    path = tmp_path / "policy.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")

    # Act / Assert
    with pytest.raises(InvalidRequestError) as caught:
        validate_policy_file(path)
    assert caught.value.log_context["problems"] == ("root:not_an_object",)


def test_validate_policy_file_rejects_a_missing_file(tmp_path: Path) -> None:
    # Arrange / Act / Assert
    with pytest.raises(InvalidRequestError) as caught:
        validate_policy_file(tmp_path / "absent.json")
    assert caught.value.log_context["reason"] == "unreadable"


def test_validation_command_succeeds_for_a_valid_file(tmp_path: Path) -> None:
    # Arrange
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document_dict()), encoding="utf-8")

    # Act
    exit_code = validate_main([str(path)])

    # Assert
    assert exit_code == 0


def test_validation_command_fails_for_an_invalid_file(tmp_path: Path) -> None:
    # Arrange
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document_dict(max_entities=0)), encoding="utf-8")

    # Act
    exit_code = validate_main([str(path)])

    # Assert
    assert exit_code == 1


async def test_a_stored_document_that_fails_validation_never_becomes_active(
    repository: FakePolicyRepository, service: PolicyService
) -> None:
    # Arrange -- a row edited by hand into an unsupported schema version
    repository.put(TENANT, stored(document_dict(schema_version=99)))

    # Act / Assert -- fails closed, and stays failed on the next attempt
    for _ in range(2):
        with pytest.raises(PolicyNotFoundError) as caught:
            await service.resolve(
                tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
            )
        assert caught.value.log_context["reason"] == "stored_document_invalid"


async def test_resolution_fails_closed_when_the_tenant_has_no_active_policy(
    repository: FakePolicyRepository, service: PolicyService
) -> None:
    # Arrange
    repository.drop(TENANT)

    # Act / Assert
    with pytest.raises(PolicyNotFoundError) as caught:
        await service.resolve(
            tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
        )
    assert caught.value.code is ErrorCode.POLICY_NOT_FOUND


# ---------------------------------------------------------------------------
# Property 2: allowlist enforcement happens during resolution
# ---------------------------------------------------------------------------
async def test_a_provider_outside_the_allowlist_is_rejected(service: PolicyService) -> None:
    # Arrange / Act / Assert
    with pytest.raises(ProviderNotAllowedError) as caught:
        await service.resolve(
            tenant_id=TENANT, provider="anthropic-shadow", model=DEFAULT_MODEL_ALIAS
        )
    assert caught.value.code is ErrorCode.PROVIDER_NOT_ALLOWED
    assert caught.value.status_code == 403


async def test_a_model_outside_the_provider_allowlist_is_rejected(service: PolicyService) -> None:
    # Arrange / Act / Assert
    with pytest.raises(ModelNotAllowedError) as caught:
        await service.resolve(
            tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model="unlisted-model"
        )
    assert caught.value.code is ErrorCode.MODEL_NOT_ALLOWED


async def test_an_unknown_provider_is_reported_as_a_provider_failure_not_a_model_one(
    service: PolicyService,
) -> None:
    # Arrange / Act / Assert -- ordering matters: the coarser refusal wins
    with pytest.raises(ProviderNotAllowedError):
        await service.resolve(tenant_id=TENANT, provider="unknown", model="unlisted-model")


@pytest.mark.parametrize(
    ("provider", "model"),
    [("anthropic-shadow", DEFAULT_MODEL_ALIAS), (DEFAULT_PROVIDER_ALIAS, "unlisted-model")],
    ids=["provider_not_allowed", "model_not_allowed"],
)
async def test_allowlist_rejection_happens_before_detection_and_the_provider_call(
    service: PolicyService, provider: str, model: str
) -> None:
    # Arrange
    spy = DownstreamSpy()

    async def pipeline() -> None:
        await service.resolve(tenant_id=TENANT, provider=provider, model=model)
        # Everything downstream of resolution, which must stay unreached.
        spy.detect()
        spy.call_provider()

    # Act
    with pytest.raises((ProviderNotAllowedError, ModelNotAllowedError)):
        await pipeline()

    # Assert
    assert spy.detect_calls == 0
    assert spy.provider_calls == 0


def test_the_policy_service_has_no_detector_or_provider_dependency() -> None:
    # Arrange / Act -- constructible from a repository alone
    service = PolicyService(FakePolicyRepository())

    # Assert
    assert isinstance(service, PolicyService)


def test_the_fake_repository_satisfies_the_declared_protocol() -> None:
    # Arrange / Act
    repo: PolicyRepository = FakePolicyRepository()

    # Assert
    assert hasattr(repo, "get_active_policy")


# ---------------------------------------------------------------------------
# Property 3: resolution yields a versioned, immutable snapshot
# ---------------------------------------------------------------------------
async def test_resolution_yields_the_stored_policy_version(
    repository: FakePolicyRepository, service: PolicyService
) -> None:
    # Arrange
    repository.put(TENANT, stored(version=42))

    # Act
    snapshot = await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )

    # Assert
    assert snapshot.version == 42
    assert snapshot.tenant_id == TENANT
    assert snapshot.name == DEFAULT_POLICY.name


async def test_a_resolved_snapshot_cannot_be_modified(service: PolicyService) -> None:
    # Arrange
    snapshot = await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )

    # Act / Assert
    with pytest.raises(dataclasses.FrozenInstanceError):
        snapshot.version = 1  # type: ignore[misc]


def test_a_snapshot_is_hashable_and_compares_by_value() -> None:
    # Arrange
    policy_id = uuid4()
    first = PolicySnapshot.from_document(
        DEFAULT_POLICY, policy_id=policy_id, tenant_id=TENANT, version=3
    )
    second = PolicySnapshot.from_document(
        DEFAULT_POLICY, policy_id=policy_id, tenant_id=TENANT, version=3
    )

    # Act / Assert
    assert first == second
    assert len({first, second}) == 1


def test_a_snapshot_does_not_observe_later_edits_to_its_source_document() -> None:
    # Arrange
    document = validate_policy_document(document_dict())
    snapshot = snapshot_of(document)

    # Act -- pydantic's frozen config guards attributes, not dict contents
    document.entities["INJECTED"] = EntityRule(action=EntityAction.ALLOW, min_score=0.1)

    # Assert
    assert "INJECTED" not in snapshot.entity_types
    assert snapshot.action_for("INJECTED") is UNKNOWN_ENTITY_ACTION


def test_a_snapshot_entity_index_is_read_only() -> None:
    # Arrange
    snapshot = snapshot_of(DEFAULT_POLICY)

    # Act / Assert
    with pytest.raises(TypeError):
        snapshot._entity_index["EMAIL_ADDRESS"] = EntityRule(  # type: ignore[index]
            action=EntityAction.ALLOW, min_score=0.1
        )


def test_a_snapshot_carries_only_policy_configuration_fields() -> None:
    """A guard against a future field smuggling a credential into the cache."""
    # Arrange / Act
    names = {field.name for field in dataclasses.fields(PolicySnapshot)}

    # Assert
    assert names == {
        "policy_id",
        "tenant_id",
        "version",
        "name",
        "session_ttl_seconds",
        "max_entities",
        "unknown_output_token_action",
        "entities",
        "providers",
        "_entity_index",
        "_provider_index",
    }


def test_entity_types_reports_every_configured_type() -> None:
    # Arrange
    snapshot = snapshot_of(DEFAULT_POLICY)

    # Act / Assert
    assert snapshot.entity_types == frozenset(DEFAULT_POLICY.entities)


@pytest.mark.parametrize("action", list(EntityAction), ids=[a.value for a in EntityAction])
def test_every_entity_action_resolves_through_a_snapshot(action: EntityAction) -> None:
    # Arrange
    document = validate_policy_document(
        document_dict(entities={"SUBJECT": {"action": action.value, "min_score": 0.42}})
    )
    snapshot = snapshot_of(document)

    # Act / Assert
    assert snapshot.action_for("SUBJECT") is action
    assert snapshot.min_score_for("SUBJECT") == pytest.approx(0.42)
    assert snapshot.entity_types == frozenset({"SUBJECT"})


def test_an_unconfigured_entity_type_falls_back_to_tokenize() -> None:
    # Arrange
    snapshot = snapshot_of(DEFAULT_POLICY)

    # Act / Assert -- fail safe, never fail open
    assert UNKNOWN_ENTITY_ACTION is EntityAction.TOKENIZE
    assert snapshot.action_for("IBAN_CODE") is EntityAction.TOKENIZE
    assert snapshot.min_score_for("IBAN_CODE") == UNKNOWN_ENTITY_MIN_SCORE


def test_entity_lookups_are_case_sensitive() -> None:
    # Arrange
    snapshot = snapshot_of(DEFAULT_POLICY)

    # Act / Assert -- a lowercase name is a different, unconfigured type
    assert snapshot.action_for("us_ssn") is UNKNOWN_ENTITY_ACTION
    assert snapshot.action_for("US_SSN") is EntityAction.BLOCK


def test_snapshot_allowlist_predicates() -> None:
    # Arrange
    document = validate_policy_document(
        document_dict(providers={"openai-primary": {"models": ["general-chat", "summaries"]}})
    )
    snapshot = snapshot_of(document)

    # Act / Assert
    assert snapshot.allows_provider("openai-primary")
    assert not snapshot.allows_provider("openai-secondary")
    assert snapshot.allows_model("openai-primary", "summaries")
    assert not snapshot.allows_model("openai-primary", "vision")
    assert not snapshot.allows_model("openai-secondary", "general-chat")


def test_snapshot_carries_the_unknown_output_token_action() -> None:
    # Arrange
    document = validate_policy_document(document_dict(unknown_output_token_action="fail"))

    # Act
    snapshot = snapshot_of(document)

    # Assert
    assert snapshot.unknown_output_token_action is UnknownTokenAction.FAIL


def test_unknown_output_token_action_defaults_to_preserve() -> None:
    # Arrange
    raw = document_dict()
    del raw["unknown_output_token_action"]

    # Act
    document = validate_policy_document(raw)

    # Assert
    assert document.unknown_output_token_action is UnknownTokenAction.PRESERVE


def test_provider_rule_and_entity_rule_are_frozen() -> None:
    # Arrange
    rule = ProviderRule(models=("general-chat",))
    entity_rule = EntityRule(action=EntityAction.REDACT, min_score=0.5)

    # Act / Assert
    with pytest.raises(ValueError, match="frozen"):
        rule.models = ("other",)  # type: ignore[misc]
    with pytest.raises(ValueError, match="frozen"):
        entity_rule.min_score = 0.9  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Property 4: the resolution cache
# ---------------------------------------------------------------------------
async def test_the_cache_returns_the_same_snapshot_instance_within_its_ttl(
    repository: FakePolicyRepository, service: PolicyService, clock: ManualClock
) -> None:
    # Arrange
    first = await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )

    # Act
    clock.advance(POLICY_CACHE_TTL_SECONDS - 0.01)
    second = await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )

    # Assert
    assert second is first
    assert repository.reads == 1


async def test_the_cache_re_resolves_once_the_ttl_expires(
    repository: FakePolicyRepository, service: PolicyService, clock: ManualClock
) -> None:
    # Arrange
    first = await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )
    repository.put(TENANT, stored(version=99))

    # Act
    clock.advance(POLICY_CACHE_TTL_SECONDS + 0.01)
    second = await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )

    # Assert
    assert second is not first
    assert second.version == 99
    assert repository.reads == 2


async def test_a_cached_entry_is_keyed_by_tenant_and_policy_version(
    repository: FakePolicyRepository, service: PolicyService
) -> None:
    # Arrange
    repository.put(TENANT, stored(version=13))

    # Act
    await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )

    # Assert
    assert service._entries[TENANT].key == (TENANT, 13)


async def test_the_cache_does_not_serve_one_tenants_policy_to_another(
    repository: FakePolicyRepository, service: PolicyService
) -> None:
    # Arrange
    repository.put(
        OTHER_TENANT,
        StoredPolicy(
            policy_id=uuid4(),
            tenant_id=OTHER_TENANT,
            version=5,
            document=document_dict(providers={"openai-primary": {"models": ["summaries"]}}),
        ),
    )
    await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )

    # Act
    other = await service.resolve(
        tenant_id=OTHER_TENANT, provider=DEFAULT_PROVIDER_ALIAS, model="summaries"
    )

    # Assert
    assert other.tenant_id == OTHER_TENANT
    assert not other.allows_model(DEFAULT_PROVIDER_ALIAS, DEFAULT_MODEL_ALIAS)


async def test_invalidate_forces_the_next_resolution_to_re_read(
    repository: FakePolicyRepository, service: PolicyService
) -> None:
    # Arrange
    await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )

    # Act
    service.invalidate(TENANT)
    await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )

    # Assert
    assert repository.reads == 2


async def test_clear_drops_every_cached_snapshot(
    repository: FakePolicyRepository, service: PolicyService
) -> None:
    # Arrange
    await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )

    # Act
    service.clear()
    await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )

    # Assert
    assert repository.reads == 2


async def test_a_deleted_policy_evicts_its_cached_snapshot(
    repository: FakePolicyRepository, service: PolicyService, clock: ManualClock
) -> None:
    # Arrange
    await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )
    repository.drop(TENANT)
    clock.advance(POLICY_CACHE_TTL_SECONDS + 1)

    # Act
    with pytest.raises(PolicyNotFoundError):
        await service.resolve(
            tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
        )

    # Assert
    assert TENANT not in service._entries


async def test_a_failed_resolution_is_not_cached_as_a_failure(
    repository: FakePolicyRepository, service: PolicyService
) -> None:
    # Arrange
    repository.drop(TENANT)
    with pytest.raises(PolicyNotFoundError):
        await service.resolve(
            tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
        )

    # Act -- the policy is created moments later
    repository.put(TENANT, stored(version=2))
    snapshot = await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )

    # Assert
    assert snapshot.version == 2


async def test_a_rejected_provider_still_leaves_the_snapshot_cached(
    repository: FakePolicyRepository, service: PolicyService
) -> None:
    # Arrange
    with pytest.raises(ProviderNotAllowedError):
        await service.resolve(tenant_id=TENANT, provider="nope", model=DEFAULT_MODEL_ALIAS)

    # Act -- a legitimate request must not pay for the rejected one
    await service.resolve(
        tenant_id=TENANT, provider=DEFAULT_PROVIDER_ALIAS, model=DEFAULT_MODEL_ALIAS
    )

    # Assert
    assert repository.reads == 1


def test_the_cache_ttl_is_short_enough_to_bound_a_policy_change() -> None:
    # Arrange / Act / Assert -- a policy edit takes effect within a minute
    assert 0 < POLICY_CACHE_TTL_SECONDS <= 60
