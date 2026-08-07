"""Policy management: versions, the draft lifecycle, the catalog, and the playground.

**A policy is identified by its name.** Every version row has its own uuid, so
no single id is stable across the history an operator is managing; the name is.
Paths therefore read ``/v1/policies/{policy_name}``, and a version is addressed
by ``(name, version)`` -- the same pair the repository and the unique constraint
already use.

**Authorization is two-tier and enforced here, not in the browser.** Reads need
``policies:read``; anything that creates, edits, or publishes needs
``policies:write``; the playground needs ``policies:test``. A frontend that hides
a button is a convenience, and this is the control.

**The playground is `/v1/detect` pointed at a chosen version.** It resolves the
version the caller names -- including an unpublished draft -- builds a snapshot
from it, and reports what that policy *would* do. It does not tokenize, does not
write a vault mapping, does not call a provider, does not persist the submitted
text, and does not log it. Those are properties of what this module does not
call, not of a flag it sets.
"""

from __future__ import annotations

from collections import Counter

# Imported at runtime, not under TYPE_CHECKING: pydantic resolves the
# annotations on the response models below when it builds their schemas, and a
# name that exists only for the type checker is not there when it looks.
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any, Final
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Path, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from app.api.errors import ErrorEnvelope
from app.auth.dependencies import require_scope
from app.db.models import POLICY_STATUS_DRAFT
from app.db.session import transaction
from app.domain.errors import InvalidRequestError, PolicyNotFoundError
from app.domain.models import EntityAction, Principal, Scope
from app.observability.logging import get_logger
from app.policy.authoring import FieldChange, ValidationProblem, diff_documents, validate_draft
from app.policy.catalog import detector_catalog
from app.policy.models import PolicyDocument, PolicySnapshot
from app.policy.validation import validate_policy_document
from app.repositories.policies import SqlAlchemyPolicyRepository

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.api.composition import Services
    from app.db.models import Policy

logger = get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["policies"])

MAX_TEST_INPUT_CHARS: Final[int] = 20_000
"""Ceiling on playground input. Detection is CPU-bound; an unbounded body is a
denial-of-service vector on a shared worker pool."""

POLICY_ERRORS: dict[int | str, dict[str, Any]] = {
    status.HTTP_401_UNAUTHORIZED: {"model": ErrorEnvelope, "description": "`AUTHENTICATION_*`"},
    status.HTTP_403_FORBIDDEN: {"model": ErrorEnvelope, "description": "`AUTHORIZATION_FAILED`"},
    status.HTTP_400_BAD_REQUEST: {"model": ErrorEnvelope, "description": "`INVALID_REQUEST`"},
    # 409, not 404: the gateway reports a policy it cannot resolve as a conflict
    # with the caller state, matching how /v1/chat already reports it.
    status.HTTP_409_CONFLICT: {"model": ErrorEnvelope, "description": "`POLICY_NOT_FOUND`"},
}

PolicyName = Annotated[str, Path(min_length=1, max_length=64, description="The policy's name.")]


# -- Response schemas ---------------------------------------------------------
class EntityRuleView(BaseModel):
    """One entity rule, flattened so the entity type travels with it."""

    model_config = ConfigDict(frozen=True)

    entity_type: str
    enabled: bool
    confidence_threshold: float
    action: EntityAction
    priority: int | None
    recognizer: str | None
    description: str | None


class PolicyVersionView(BaseModel):
    """A single stored version. View-only; nothing here can be written back."""

    model_config = ConfigDict(frozen=True)

    policy_name: str
    version: int
    status: str
    is_active: bool
    created_at: datetime
    published_at: datetime | None
    name: str
    session_ttl_seconds: int
    max_entities: int
    unknown_output_token_action: str
    providers: dict[str, list[str]]
    entity_rules: list[EntityRuleView]
    entity_count: int
    enabled_entity_count: int


class PolicySummaryView(BaseModel):
    model_config = ConfigDict(frozen=True)

    policy_name: str
    active_version: int | None
    draft_version: int | None
    status: str
    last_published_at: datetime | None
    version_count: int
    entity_count: int
    enabled_entity_count: int


class ValidationProblemView(BaseModel):
    model_config = ConfigDict(frozen=True)

    field: str
    code: str
    message: str


class ValidationResultView(BaseModel):
    model_config = ConfigDict(frozen=True)

    valid: bool
    problems: list[ValidationProblemView]
    warnings: list[ValidationProblemView]


class FieldChangeView(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    before: str | None
    after: str | None
    kind: str


class PolicyDiffView(BaseModel):
    model_config = ConfigDict(frozen=True)

    policy_name: str
    from_version: int
    to_version: int
    entity_changes: list[FieldChangeView]
    setting_changes: list[FieldChangeView]
    total_changes: int


class DetectorCatalogEntryView(BaseModel):
    model_config = ConfigDict(frozen=True)

    entity_type: str
    recognizer_type: str
    default_threshold: float
    severity: int
    supported_actions: list[str]
    description: str | None


class DraftBody(BaseModel):
    """A whole policy document. Drafts are replaced, never patched field-by-field.

    Partial updates would need a merge, and a merge over a document whose
    ``extra="forbid"`` schema rejects unknown keys is a good way to drop a rule
    an operator thought they had kept. The editor holds the document and sends
    all of it.
    """

    model_config = ConfigDict(frozen=True)

    document: dict[str, Any]


class PolicyTestRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    text: str = Field(min_length=1, max_length=MAX_TEST_INPUT_CHARS)
    policy_name: str = Field(min_length=1, max_length=64)
    version: int | None = Field(default=None, ge=1)
    """Omit to test the open draft; supply a number to test a published version."""

    language: str = Field(default="en", min_length=2, max_length=8)


class PolicyTestSpan(BaseModel):
    """One detection, as offsets and metadata. Never the matched text.

    ``/v1/detect`` returns matched text when privileged diagnostics are on. This
    endpoint does not offer that even then: its whole purpose is to be run
    against realistic input while designing a policy, which is exactly the
    circumstance in which a response ends up pasted into a ticket.
    """

    model_config = ConfigDict(frozen=True)

    entity_type: str
    start: int
    end: int
    confidence: float
    action: EntityAction
    recognizer: str | None


class PolicyTestResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    policy_name: str
    version: int
    policy_status: str
    spans: list[PolicyTestSpan]
    detected: int
    entity_types: dict[str, int]
    would_block: bool
    """True when any span resolves to ``BLOCK``: the provider would not be called."""


# -- Helpers ------------------------------------------------------------------
def _rules_of(document: PolicyDocument) -> list[EntityRuleView]:
    return [
        EntityRuleView(
            entity_type=name,
            enabled=rule.enabled,
            confidence_threshold=rule.min_score,
            action=rule.action,
            priority=rule.priority,
            recognizer=rule.recognizer,
            description=rule.description,
        )
        for name, rule in sorted(document.entities.items())
    ]


def _version_view(row: Policy) -> PolicyVersionView:
    document = validate_policy_document(row.document)
    rules = _rules_of(document)
    return PolicyVersionView(
        policy_name=row.name,
        version=row.version,
        status=row.status,
        is_active=row.is_active,
        created_at=row.created_at,
        published_at=row.published_at,
        name=document.name,
        session_ttl_seconds=document.session_ttl_seconds,
        max_entities=document.max_entities,
        unknown_output_token_action=document.unknown_output_token_action.value,
        providers={alias: sorted(rule.models) for alias, rule in document.providers.items()},
        entity_rules=rules,
        entity_count=len(rules),
        enabled_entity_count=sum(1 for rule in rules if rule.enabled),
    )


def _problem_view(problem: ValidationProblem) -> ValidationProblemView:
    # Field-by-field rather than ``vars()``: these are ``slots=True``
    # dataclasses, so they have no ``__dict__`` for ``vars()`` to read. The
    # first version of this used ``vars()`` and returned a 500 from every
    # validate and diff call -- a shape mypy and ruff both accepted.
    return ValidationProblemView(field=problem.field, code=problem.code, message=problem.message)


def _change_view(change: FieldChange) -> FieldChangeView:
    return FieldChangeView(
        path=change.path, before=change.before, after=change.after, kind=change.kind
    )


def _not_found(name: str) -> PolicyNotFoundError:
    # The same refusal for "no such policy" and "not yours": distinguishing them
    # would make this endpoint an oracle for other tenants' policy names.
    return PolicyNotFoundError(log_context={"policy_name": name})


async def _load_version(
    services: Services, tenant_id: UUID, *, name: str, version: int | None
) -> Policy:
    """Resolve a named version, or the working version when ``version`` is omitted.

    The working version is the open draft if there is one, and the active
    published version otherwise. Falling back matters: an operator opening the
    playground on a policy with no draft is asking what the *live* policy does,
    and refusing would make the page useless in the common case. The first
    version of this returned the draft or nothing, which reported
    POLICY_NOT_FOUND for every policy that was not mid-edit.

    Callers that must have a draft -- validate, publish -- look it up directly
    rather than through here, so this fallback cannot make them operate on a
    published version by accident.
    """
    async with services.session_scope() as session:
        repository = SqlAlchemyPolicyRepository(session)
        if version is not None:
            row = await repository.get_version(tenant_id, name=name, version=version)
        else:
            row = await repository.get_draft(tenant_id, name=name)
            if row is None:
                versions = await repository.list_versions(tenant_id, name=name)
                row = next((candidate for candidate in versions if candidate.is_active), None)
        if row is None:
            raise _not_found(name)
        return row


# -- Read endpoints -----------------------------------------------------------
@router.get(
    "/policies",
    response_model=list[PolicySummaryView],
    summary="List this tenant's policies",
    responses=POLICY_ERRORS,
)
async def list_policies(
    http_request: Request,
    principal: Annotated[Principal, Depends(require_scope(Scope.POLICIES_READ))],
) -> list[PolicySummaryView]:
    services: Services = http_request.app.state.services
    summaries: list[PolicySummaryView] = []

    async with services.session_scope() as session:
        repository = SqlAlchemyPolicyRepository(session)
        for name in await repository.list_names(principal.tenant_id):
            versions = await repository.list_versions(principal.tenant_id, name=name)
            summaries.append(_summary_of(name, versions))
    return summaries


def _summary_of(name: str, versions: list[Policy]) -> PolicySummaryView:
    published = [row for row in versions if row.status != POLICY_STATUS_DRAFT]
    draft = next((row for row in versions if row.status == POLICY_STATUS_DRAFT), None)
    active = next((row for row in versions if row.is_active), None)

    # Counts describe the *active* version, because that is what traffic is
    # being protected by. A draft's counts belong to the draft.
    rules = _rules_of(validate_policy_document(active.document)) if active is not None else []

    return PolicySummaryView(
        policy_name=name,
        active_version=None if active is None else active.version,
        draft_version=None if draft is None else draft.version,
        status=POLICY_STATUS_DRAFT if draft is not None else "published",
        last_published_at=max(
            (row.published_at for row in published if row.published_at is not None),
            default=None,
        ),
        version_count=len(published),
        entity_count=len(rules),
        enabled_entity_count=sum(1 for rule in rules if rule.enabled),
    )


@router.get(
    "/policies/{policy_name}",
    response_model=PolicyVersionView,
    summary="The active version of one policy",
    responses=POLICY_ERRORS,
)
async def get_policy(
    http_request: Request,
    policy_name: PolicyName,
    principal: Annotated[Principal, Depends(require_scope(Scope.POLICIES_READ))],
) -> PolicyVersionView:
    services: Services = http_request.app.state.services
    async with services.session_scope() as session:
        repository = SqlAlchemyPolicyRepository(session)
        versions = await repository.list_versions(principal.tenant_id, name=policy_name)
        active = next((row for row in versions if row.is_active), None)
        if active is None:
            raise _not_found(policy_name)
        return _version_view(active)


@router.get(
    "/policies/{policy_name}/versions",
    response_model=list[PolicyVersionView],
    summary="Every version of one policy, oldest first",
    responses=POLICY_ERRORS,
)
async def list_policy_versions(
    http_request: Request,
    policy_name: PolicyName,
    principal: Annotated[Principal, Depends(require_scope(Scope.POLICIES_READ))],
) -> list[PolicyVersionView]:
    services: Services = http_request.app.state.services
    async with services.session_scope() as session:
        repository = SqlAlchemyPolicyRepository(session)
        versions = await repository.list_versions(principal.tenant_id, name=policy_name)
        if not versions:
            raise _not_found(policy_name)
        return [_version_view(row) for row in versions]


@router.get(
    "/policies/{policy_name}/versions/{version}",
    response_model=PolicyVersionView,
    summary="One stored version, view-only",
    responses=POLICY_ERRORS,
)
async def get_policy_version(
    http_request: Request,
    policy_name: PolicyName,
    version: Annotated[int, Path(ge=1)],
    principal: Annotated[Principal, Depends(require_scope(Scope.POLICIES_READ))],
) -> PolicyVersionView:
    services: Services = http_request.app.state.services
    return _version_view(
        await _load_version(services, principal.tenant_id, name=policy_name, version=version)
    )


@router.get(
    "/policies/{policy_name}/diff",
    response_model=PolicyDiffView,
    summary="Compare two stored versions",
    responses=POLICY_ERRORS,
)
async def diff_policy_versions(
    http_request: Request,
    policy_name: PolicyName,
    principal: Annotated[Principal, Depends(require_scope(Scope.POLICIES_READ))],
    from_version: Annotated[int, Query(ge=1)],
    to_version: Annotated[int, Query(ge=1)],
) -> PolicyDiffView:
    """Diff computed from two stored rows, never reconstructed by a caller."""
    services: Services = http_request.app.state.services
    before_row = await _load_version(
        services, principal.tenant_id, name=policy_name, version=from_version
    )
    after_row = await _load_version(
        services, principal.tenant_id, name=policy_name, version=to_version
    )

    diff = diff_documents(
        validate_policy_document(before_row.document),
        validate_policy_document(after_row.document),
        from_version=from_version,
        to_version=to_version,
    )
    return PolicyDiffView(
        policy_name=policy_name,
        from_version=diff.from_version,
        to_version=diff.to_version,
        entity_changes=[_change_view(change) for change in diff.entity_changes],
        setting_changes=[_change_view(change) for change in diff.setting_changes],
        total_changes=diff.total,
    )


@router.get(
    "/detectors/entities",
    response_model=list[DetectorCatalogEntryView],
    summary="Entity types the detector can emit",
    responses=POLICY_ERRORS,
)
async def list_detector_entities(
    principal: Annotated[Principal, Depends(require_scope(Scope.POLICIES_READ))],
) -> list[DetectorCatalogEntryView]:
    """The catalog, read from the detector rather than from a second list.

    Not tenant-scoped: what the detector can find is a property of the build,
    identical for everyone, and carries no tenant data.
    """
    del principal  # authorization only
    return [
        DetectorCatalogEntryView(
            entity_type=entry.entity_type,
            recognizer_type=entry.recognizer_type,
            default_threshold=entry.default_threshold,
            severity=entry.severity,
            supported_actions=list(entry.supported_actions),
            description=entry.description,
        )
        for entry in detector_catalog()
    ]


# -- Draft lifecycle ----------------------------------------------------------
def _validation_view(raw: dict[str, Any]) -> ValidationResultView:
    result = validate_draft(raw)
    return ValidationResultView(
        valid=result.valid,
        problems=[_problem_view(problem) for problem in result.problems],
        warnings=[_problem_view(warning) for warning in result.warnings],
    )


@router.post(
    "/policies/{policy_name}/draft",
    response_model=PolicyVersionView,
    status_code=status.HTTP_201_CREATED,
    summary="Open a draft from the active version",
    responses=POLICY_ERRORS,
)
async def create_policy_draft(
    http_request: Request,
    policy_name: PolicyName,
    principal: Annotated[Principal, Depends(require_scope(Scope.POLICIES_WRITE))],
) -> PolicyVersionView:
    """Copy the active version into a new draft at the next version number.

    Seeded from the active version rather than started empty: an operator edits
    what is running, and an empty draft would make every unedited rule look like
    a deliberate removal.
    """
    services: Services = http_request.app.state.services
    async with services.session_scope() as session, transaction(session):
        repository = SqlAlchemyPolicyRepository(session)
        if await repository.get_draft(principal.tenant_id, name=policy_name) is not None:
            raise InvalidRequestError(
                "A draft is already open for this policy.",
                log_context={"policy_name": policy_name, "reason": "draft_exists"},
            )
        versions = await repository.list_versions(principal.tenant_id, name=policy_name)
        active = next((row for row in versions if row.is_active), None)
        if active is None:
            raise _not_found(policy_name)

        draft = await repository.create_draft(
            principal.tenant_id, name=policy_name, document=dict(active.document)
        )
        logger.info(
            "policy_draft_created",
            policy_name=policy_name,
            from_version=active.version,
            to_version=draft.version,
            tenant_id=str(principal.tenant_id),
            api_key_id=str(principal.api_key_id),
        )
        return _version_view(draft)


@router.patch(
    "/policies/{policy_name}/draft",
    response_model=PolicyVersionView,
    summary="Replace the draft's document",
    responses=POLICY_ERRORS,
)
async def update_policy_draft(
    http_request: Request,
    policy_name: PolicyName,
    payload: Annotated[DraftBody, Body()],
    principal: Annotated[Principal, Depends(require_scope(Scope.POLICIES_WRITE))],
) -> PolicyVersionView:
    """Save edits. The document is checked before it is stored.

    Storing an invalid draft would be harmless for traffic -- a draft is never
    resolved -- but it would let an operator accumulate edits that cannot be
    published and discover it only at the end.
    """
    services: Services = http_request.app.state.services
    validate_policy_document(payload.document)

    async with services.session_scope() as session, transaction(session):
        repository = SqlAlchemyPolicyRepository(session)
        updated = await repository.update_draft(
            principal.tenant_id, name=policy_name, document=dict(payload.document)
        )
        if updated is None:
            raise _not_found(policy_name)
        logger.info(
            "policy_draft_updated",
            policy_name=policy_name,
            to_version=updated.version,
            tenant_id=str(principal.tenant_id),
            api_key_id=str(principal.api_key_id),
        )
        return _version_view(updated)


@router.delete(
    "/policies/{policy_name}/draft",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Discard the open draft",
    responses=POLICY_ERRORS,
)
async def discard_policy_draft(
    http_request: Request,
    policy_name: PolicyName,
    principal: Annotated[Principal, Depends(require_scope(Scope.POLICIES_WRITE))],
) -> Response:
    services: Services = http_request.app.state.services
    async with services.session_scope() as session, transaction(session):
        repository = SqlAlchemyPolicyRepository(session)
        if not await repository.discard_draft(principal.tenant_id, name=policy_name):
            raise _not_found(policy_name)
        logger.info(
            "policy_draft_discarded",
            policy_name=policy_name,
            tenant_id=str(principal.tenant_id),
            api_key_id=str(principal.api_key_id),
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/policies/{policy_name}/validate",
    response_model=ValidationResultView,
    summary="Check the open draft without publishing it",
    responses=POLICY_ERRORS,
)
async def validate_policy_draft(
    http_request: Request,
    policy_name: PolicyName,
    principal: Annotated[Principal, Depends(require_scope(Scope.POLICIES_READ))],
) -> ValidationResultView:
    """Read-scoped: validating changes nothing, so an analyst may check a draft."""
    services: Services = http_request.app.state.services
    # The draft directly, not through `_load_version`: that helper falls back to
    # the active version for the playground, and validating a published version
    # when the operator asked about their draft would answer a question nobody
    # asked -- and answer it reassuringly.
    async with services.session_scope() as session:
        draft = await SqlAlchemyPolicyRepository(session).get_draft(
            principal.tenant_id, name=policy_name
        )
        if draft is None:
            raise _not_found(policy_name)
        document = dict(draft.document)
        draft_version = draft.version
    result = _validation_view(document)
    logger.info(
        "policy_draft_validated",
        policy_name=policy_name,
        to_version=draft_version,
        valid=result.valid,
        problem_count=len(result.problems),
        warning_count=len(result.warnings),
        tenant_id=str(principal.tenant_id),
    )
    return result


@router.post(
    "/policies/{policy_name}/publish",
    response_model=PolicyVersionView,
    summary="Publish the draft as a new immutable version",
    responses=POLICY_ERRORS,
)
async def publish_policy_draft(
    http_request: Request,
    policy_name: PolicyName,
    principal: Annotated[Principal, Depends(require_scope(Scope.POLICIES_WRITE))],
) -> PolicyVersionView:
    """Promote the draft, leaving every earlier version byte-identical.

    Requests already holding a ``PolicySnapshot`` are unaffected: a snapshot is
    a frozen value built at resolution time, not a view onto a row, so nothing
    published here can reach one that is already in flight.
    """
    services: Services = http_request.app.state.services

    async with services.session_scope() as session, transaction(session):
        repository = SqlAlchemyPolicyRepository(session)
        draft = await repository.get_draft(principal.tenant_id, name=policy_name)
        if draft is None:
            raise _not_found(policy_name)

        # Validated at the last moment rather than trusted from the last save:
        # the detector's vocabulary can change between editing and publishing.
        result = validate_draft(dict(draft.document))
        if not result.valid:
            raise InvalidRequestError(
                "The draft cannot be published until its problems are fixed.",
                log_context={
                    "policy_name": policy_name,
                    "problem_count": len(result.problems),
                    "reason": "draft_invalid",
                },
            )

        versions = await repository.list_versions(principal.tenant_id, name=policy_name)
        previous = next((row for row in versions if row.is_active), None)
        change_count = 0
        if previous is not None:
            change_count = diff_documents(
                validate_policy_document(previous.document),
                validate_policy_document(draft.document),
                from_version=previous.version,
                to_version=draft.version,
            ).total

        published = await repository.publish_draft(principal.tenant_id, name=policy_name)
        if published is None:  # pragma: no cover - the draft was read above
            raise _not_found(policy_name)

        logger.info(
            "policy_published",
            policy_name=policy_name,
            from_version=None if previous is None else previous.version,
            to_version=published.version,
            change_count=change_count,
            warning_count=len(result.warnings),
            tenant_id=str(principal.tenant_id),
            api_key_id=str(principal.api_key_id),
        )
        return _version_view(published)


# -- Playground ---------------------------------------------------------------
@router.post(
    "/policies/test",
    response_model=PolicyTestResult,
    summary="What would this policy do with this text?",
    responses=POLICY_ERRORS,
)
async def test_policy(
    http_request: Request,
    response: Response,
    payload: Annotated[PolicyTestRequest, Body()],
    principal: Annotated[Principal, Depends(require_scope(Scope.POLICIES_TEST))],
) -> PolicyTestResult:
    """Detect against a chosen version and report intended actions.

    The submitted text calls the detector and is then discarded with the
    request. It is not stored, not audited, and not logged -- the log line below
    carries the policy and a count, and the response carries offsets rather than
    matched substrings, so neither is a route by which draft input escapes.
    """
    services: Services = http_request.app.state.services
    row = await _load_version(
        services, principal.tenant_id, name=payload.policy_name, version=payload.version
    )
    snapshot = PolicySnapshot.from_document(
        validate_policy_document(row.document),
        policy_id=row.id,
        tenant_id=principal.tenant_id,
        version=row.version,
    )

    entities = await services.detector.detect(payload.text, language=payload.language)

    spans = [
        PolicyTestSpan(
            entity_type=entity.entity_type,
            start=entity.start,
            end=entity.end,
            confidence=entity.score,
            # Below the type threshold the policy acts on nothing, and "allow"
            # is precisely that outcome.
            action=(
                snapshot.action_for(entity.entity_type)
                if entity.score >= snapshot.min_score_for(entity.entity_type)
                else EntityAction.ALLOW
            ),
            recognizer=None,
        )
        for entity in entities
    ]

    # A result reflects one draft at one moment; a cache would serve a stale
    # answer for a policy that has since been edited.
    response.headers["Cache-Control"] = "no-store"

    logger.info(
        "policy_tested",
        policy_name=payload.policy_name,
        to_version=row.version,
        policy_status=row.status,
        detected=len(spans),
        tenant_id=str(principal.tenant_id),
    )

    return PolicyTestResult(
        policy_name=payload.policy_name,
        version=row.version,
        policy_status=row.status,
        spans=spans,
        detected=len(spans),
        entity_types=dict(Counter(span.entity_type for span in spans)),
        would_block=any(span.action is EntityAction.BLOCK for span in spans),
    )
