"""``POST /v1/detect`` -- a dry run of the privacy pipeline's first stage.

The endpoint answers one question: *if this text were sent through* ``/v1/chat``
*, what would the tenant's policy do with it?* It detects, resolves the policy,
and reports the span, the type, the score, and the action -- then stops. Nothing
is tokenized, nothing is written to the vault, and no provider is called.

The single property that matters here is what the response leaves out. A caller
already holds the text it submitted, so echoing the matched substrings back
would be harmless in isolation -- but this response is exactly the shape that
ends up in a log aggregator, a support ticket, or a screenshot, which is how
matched values escape. Matched text is therefore returned only when
``Settings.diagnostics_allowed`` is true, and that property is false in
production by construction, not by configuration discipline.

Actions reflect the policy's thresholds as well as its rules. A span scoring
below its type's ``min_score`` is one the pipeline would leave in place, so it
is reported as ``allow`` rather than as the type's configured action: an
overstated action here would read as protection that will not happen.
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Annotated, Any, Final
from uuid import UUID, uuid4

from fastapi import APIRouter, Body, Depends, Request, status

from app.api.adapters import PolicyRepositoryAdapter
from app.api.errors import ErrorEnvelope
from app.auth.dependencies import require_scope
from app.domain.models import (
    DetectedEntity,
    DetectedEntityView,
    DetectRequest,
    DetectResponse,
    EntityAction,
    Principal,
    PrivacySummary,
    Scope,
)
from app.policy.models import PolicySnapshot
from app.policy.service import PolicyService

if TYPE_CHECKING:  # pragma: no cover - import cycle-free typing only
    from app.api.composition import Services

router = APIRouter(prefix="/v1", tags=["detect"])

STATE_POLICY_SERVICE: Final = "policy_service"
"""Where the lazily built policy service is cached on application state."""

DETECT_REQUEST_EXAMPLES: dict[str, dict[str, Any]] = {
    "synthetic_support_note": {
        "summary": "A support note carrying synthetic identifiers",
        "value": {
            "text": (
                "Jordan Rivera called from 415-555-0142 about the invoice sent "
                "to jordan.rivera@example.test."
            ),
            "language": "en",
        },
    },
    "narrowed_to_one_type": {
        "summary": "Narrowed to a single entity type",
        "description": "Only the listed types are reported, whatever else is present.",
        "value": {
            "text": "Reach the on-call engineer at oncall@example.test.",
            "language": "en",
            "entity_types": ["EMAIL_ADDRESS"],
        },
    },
}
"""Request examples for the OpenAPI schema. Every value here is invented."""

DETECT_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_400_BAD_REQUEST: {
        "model": ErrorEnvelope,
        "description": "`INVALID_REQUEST`, `UNSUPPORTED_LANGUAGE`",
    },
    status.HTTP_401_UNAUTHORIZED: {
        "model": ErrorEnvelope,
        "description": "`AUTHENTICATION_REQUIRED`, `AUTHENTICATION_FAILED`",
    },
    status.HTTP_403_FORBIDDEN: {
        "model": ErrorEnvelope,
        "description": "`AUTHORIZATION_FAILED`",
    },
    status.HTTP_409_CONFLICT: {
        "model": ErrorEnvelope,
        "description": "`POLICY_NOT_FOUND`",
    },
    status.HTTP_413_CONTENT_TOO_LARGE: {
        "model": ErrorEnvelope,
        "description": "`REQUEST_TOO_LARGE`",
    },
    status.HTTP_422_UNPROCESSABLE_CONTENT: {
        "model": ErrorEnvelope,
        "description": "`INVALID_REQUEST`",
    },
    status.HTTP_429_TOO_MANY_REQUESTS: {
        "model": ErrorEnvelope,
        "description": "`RATE_LIMIT_EXCEEDED`",
    },
    status.HTTP_500_INTERNAL_SERVER_ERROR: {
        "model": ErrorEnvelope,
        "description": "`INTERNAL_ERROR`",
    },
    status.HTTP_503_SERVICE_UNAVAILABLE: {
        "model": ErrorEnvelope,
        "description": "`PRIVACY_DETECTOR_UNAVAILABLE`",
    },
}


@router.post(
    "/detect",
    response_model=DetectResponse,
    status_code=status.HTTP_200_OK,
    summary="Report what the tenant's policy would do with this text",
    response_description=(
        "One entry per detection: span, type, score, and the action the policy "
        "would apply. Matched text is omitted unless privileged diagnostics are on."
    ),
    responses=DETECT_ERROR_RESPONSES,
)
async def detect(
    http_request: Request,
    payload: Annotated[DetectRequest, Body(openapi_examples=DETECT_REQUEST_EXAMPLES)],
    principal: Annotated[Principal, Depends(require_scope(Scope.DETECT_INVOKE))],
) -> DetectResponse:
    """Detect sensitive spans and report the policy action for each.

    The tenant whose policy applies is the authenticated principal's, so this
    endpoint cannot be used to inspect another tenant's rules.
    """
    services: Services = http_request.app.state.services
    snapshot = await _tenant_snapshot(_policy_service(http_request, services), principal.tenant_id)

    entities = await services.detector.detect(
        payload.text,
        language=payload.language,
        requested_entities=set(payload.entity_types) if payload.entity_types else None,
    )

    include_text = services.settings.diagnostics_allowed
    views = [
        _view_of(entity, policy=snapshot, text=payload.text, include_text=include_text)
        for entity in entities
    ]
    return DetectResponse(
        request_id=_request_id(http_request),
        entities=views,
        summary=_summary_of(views),
    )


def _view_of(
    entity: DetectedEntity,
    *,
    policy: PolicySnapshot,
    text: str,
    include_text: bool,
) -> DetectedEntityView:
    """Project one detection, carrying the matched value only when permitted."""
    confident = entity.score >= policy.min_score_for(entity.entity_type)
    return DetectedEntityView(
        entity_type=entity.entity_type,
        start=entity.start,
        end=entity.end,
        score=entity.score,
        # Below the type's threshold the policy acts on nothing, and "allow" is
        # precisely that outcome. ``recognizer`` is never projected at all.
        action=policy.action_for(entity.entity_type) if confident else EntityAction.ALLOW,
        text=text[entity.start : entity.end] if include_text else None,
    )


def _summary_of(views: list[DetectedEntityView]) -> PrivacySummary:
    """Count what was found, by type.

    The per-action counters stay zero on purpose: they record work the gateway
    performed, and ``/v1/detect`` performs none. The prospective action for each
    span is on the span itself.
    """
    counts = Counter(view.entity_type for view in views)
    return PrivacySummary(detected=len(views), entity_types=dict(counts))


def _policy_service(request: Request, services: Services) -> PolicyService:
    """Return the application's policy service, building it once on demand.

    ``Services`` does not carry one: the composition root gives its instance to
    the pipeline directly. Caching the service on application state rather than
    constructing one per request keeps its short snapshot cache useful, and
    gives a test a single seam to inject a fake through.
    """
    existing = getattr(request.app.state, STATE_POLICY_SERVICE, None)
    if isinstance(existing, PolicyService):
        return existing

    built = PolicyService(PolicyRepositoryAdapter(services.session_scope))
    setattr(request.app.state, STATE_POLICY_SERVICE, built)
    return built


async def _tenant_snapshot(policy: PolicyService, tenant_id: UUID) -> PolicySnapshot:
    """Resolve the tenant's active policy without naming a destination.

    ``PolicyService.resolve`` is the public entry point, but it also authorizes
    a provider and model pair, and a detection request names neither -- there is
    no destination to authorize when nothing is sent anywhere. The private
    accessor is the same call ``resolve`` makes before its allowlist checks, and
    it fails closed the same way: a tenant with no active policy, or with a
    stored document that no longer validates, raises ``PolicyNotFoundError``.

    ``snapshot_for`` rather than ``resolve``: this endpoint inspects text and
    names no provider or model, so there is no route to authorize. Anything
    that will actually call a provider must go through ``resolve``.
    """
    return await policy.snapshot_for(tenant_id)


def _request_id(request: Request) -> UUID:
    """The correlation id the middleware assigned, echoed in the body.

    A response whose body disagrees with its ``X-Request-ID`` header is a
    debugging trap, so both come from the same value whenever one exists.
    """
    assigned = getattr(request.state, "request_id", None)
    return assigned if isinstance(assigned, UUID) else uuid4()
