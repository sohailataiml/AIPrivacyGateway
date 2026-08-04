"""Policy documents and the immutable snapshot resolved for every request.

Two shapes live here and they are deliberately different.

``PolicyDocument`` is the *stored* form: a pydantic model that validates the
JSON persisted in ``policies.document``. It is permissive about lookup
ergonomics and strict about correctness -- unknown fields, bad actions,
out-of-range scores, and non-positive limits are all rejected at parse time so
an invalid document can never become an active policy.

``PolicySnapshot`` is the *runtime* form: a frozen dataclass carrying the
version, built once per resolution and shared by every stage of the request.
It answers the four questions the pipeline actually asks -- what do I do with
this entity type, what score do I trust, is this provider allowed, is this
model allowed -- in constant time, and it cannot be edited by any stage that
receives it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Annotated, Any, Final, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.domain.models import EntityAction, UnknownTokenAction

POLICY_SCHEMA_VERSION: Final[int] = 1
"""The only ``schema_version`` this build understands.

A document written for a future schema is rejected rather than best-effort
parsed: silently ignoring a field an operator added is how a policy stops
meaning what its author thinks it means.
"""

UNKNOWN_ENTITY_ACTION: Final[EntityAction] = EntityAction.TOKENIZE
"""Action applied to an entity type the active policy does not mention.

Fail safe, not fail open. A detector can begin emitting a new entity type well
before an operator updates the policy -- a model upgrade, a new recognizer, a
newly enabled language pack. Defaulting to ``ALLOW`` would ship that new class
of sensitive value straight to the provider, which is exactly the failure this
gateway exists to prevent. Defaulting to ``BLOCK`` would take a tenant's
traffic down on a detector upgrade, which turns a privacy improvement into an
outage. ``TOKENIZE`` protects the value, keeps the request serviceable, and
stays reversible on the way back out.
"""

UNKNOWN_ENTITY_MIN_SCORE: Final[float] = 0.0
"""Score threshold for an entity type the active policy does not mention.

Zero, for the same reason: if the detector was confident enough to report an
unconfigured type at all, the safe response is to act on it.
"""

MAX_ENTITY_TYPE_CHARS: Final[int] = 64
MAX_PROVIDER_ALIAS_CHARS: Final[int] = 64
MAX_MODEL_ALIAS_CHARS: Final[int] = 128
MAX_POLICY_NAME_CHARS: Final[int] = 64

MAX_SESSION_TTL_SECONDS: Final[int] = 86_400
"""One day. A mapping that outlives its conversation is a liability, not a feature."""

MAX_POLICY_ENTITY_BUDGET: Final[int] = 10_000
"""Ceiling on ``max_entities``. Mirrors ``Settings.max_entities_per_request``."""

EntityTypeName = Annotated[
    str, StringConstraints(strip_whitespace=False, min_length=1, max_length=MAX_ENTITY_TYPE_CHARS)
]
ProviderAlias = Annotated[
    str,
    StringConstraints(strip_whitespace=False, min_length=1, max_length=MAX_PROVIDER_ALIAS_CHARS),
]
ModelAlias = Annotated[
    str, StringConstraints(strip_whitespace=False, min_length=1, max_length=MAX_MODEL_ALIAS_CHARS)
]


class EntityRule(BaseModel):
    """What the policy does with one entity type, and how sure it must be."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: EntityAction
    min_score: float = Field(ge=0.0, le=1.0)
    """Required, not defaulted. A silent threshold is a threshold nobody reviews."""


class ProviderRule(BaseModel):
    """The models a tenant may reach through one provider alias."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    models: tuple[ModelAlias, ...] = Field(min_length=1)
    """A provider entry with no models permits nothing; say so by omitting it."""


class PolicyDocument(BaseModel):
    """The validated JSON stored in ``policies.document``.

    ``extra="forbid"`` is load-bearing. A typo in a key name -- ``entites``,
    ``unknown_token_action`` -- would otherwise parse cleanly and leave the
    intended rule silently absent.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int
    name: str = Field(min_length=1, max_length=MAX_POLICY_NAME_CHARS)
    session_ttl_seconds: int = Field(gt=0, le=MAX_SESSION_TTL_SECONDS)
    max_entities: int = Field(gt=0, le=MAX_POLICY_ENTITY_BUDGET)
    providers: dict[ProviderAlias, ProviderRule] = Field(min_length=1)
    entities: dict[EntityTypeName, EntityRule] = Field(min_length=1)
    unknown_output_token_action: UnknownTokenAction = UnknownTokenAction.PRESERVE

    @field_validator("schema_version")
    @classmethod
    def _supported_schema_version(cls, value: int) -> int:
        if value != POLICY_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {POLICY_SCHEMA_VERSION}")
        return value


@dataclass(frozen=True, slots=True)
class StoredPolicy:
    """One row of ``policies`` as a repository hands it back.

    ``document`` is the raw JSONB. It is deliberately *not* a
    ``PolicyDocument``: validation belongs to this package, so a repository
    cannot hand the pipeline a document that has never been checked.
    """

    policy_id: UUID
    tenant_id: UUID | None
    version: int
    document: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """One tenant's active policy, frozen at a version, for one request.

    Every stage of the pipeline reads from the same instance, so a policy
    cannot change underneath a half-processed request. The public fields are
    all hashable, which keeps ``hash(snapshot)`` and ``a == b`` safe; the two
    lookup indexes are read-only views excluded from equality.
    """

    policy_id: UUID
    tenant_id: UUID
    version: int
    name: str
    session_ttl_seconds: int
    max_entities: int
    unknown_output_token_action: UnknownTokenAction
    entities: tuple[tuple[str, EntityRule], ...]
    """Entity rules as a sorted, hashable pair sequence."""

    providers: tuple[tuple[str, tuple[str, ...]], ...]
    """Provider alias to its permitted model aliases, sorted and hashable."""

    _entity_index: Mapping[str, EntityRule] = field(init=False, repr=False, compare=False)
    _provider_index: Mapping[str, frozenset[str]] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        # MappingProxyType, not dict: a stage that receives the snapshot cannot
        # edit the policy for the stages behind it.
        object.__setattr__(self, "_entity_index", MappingProxyType(dict(self.entities)))
        object.__setattr__(
            self,
            "_provider_index",
            MappingProxyType({alias: frozenset(models) for alias, models in self.providers}),
        )

    @classmethod
    def from_document(
        cls,
        document: PolicyDocument,
        *,
        policy_id: UUID,
        tenant_id: UUID,
        version: int,
    ) -> Self:
        """Build a snapshot from an already-validated document."""
        return cls(
            policy_id=policy_id,
            tenant_id=tenant_id,
            version=version,
            name=document.name,
            session_ttl_seconds=document.session_ttl_seconds,
            max_entities=document.max_entities,
            unknown_output_token_action=document.unknown_output_token_action,
            entities=tuple(sorted(document.entities.items(), key=lambda item: item[0])),
            providers=tuple(
                sorted(
                    ((alias, tuple(rule.models)) for alias, rule in document.providers.items()),
                    key=lambda item: item[0],
                )
            ),
        )

    @property
    def entity_types(self) -> frozenset[str]:
        """The entity types this policy configures.

        This is what the detector is asked to look for. Types outside it can
        still surface, and ``action_for`` covers them.
        """
        return frozenset(self._entity_index)

    def action_for(self, entity_type: str) -> EntityAction:
        """Return the action for ``entity_type``.

        An unconfigured type resolves to :data:`UNKNOWN_ENTITY_ACTION`.
        """
        rule = self._entity_index.get(entity_type)
        return rule.action if rule is not None else UNKNOWN_ENTITY_ACTION

    def min_score_for(self, entity_type: str) -> float:
        """Return the score threshold for ``entity_type``.

        An unconfigured type resolves to :data:`UNKNOWN_ENTITY_MIN_SCORE`.
        """
        rule = self._entity_index.get(entity_type)
        return rule.min_score if rule is not None else UNKNOWN_ENTITY_MIN_SCORE

    def allows_provider(self, provider_alias: str) -> bool:
        return provider_alias in self._provider_index

    def allows_model(self, provider_alias: str, model_alias: str) -> bool:
        """True only when the provider is allowed *and* lists this model."""
        return model_alias in self._provider_index.get(provider_alias, frozenset())
