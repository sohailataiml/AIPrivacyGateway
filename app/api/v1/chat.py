"""``POST /v1/chat`` -- the only route that reaches a model provider.

This module is deliberately the thinnest file in the request path. Every privacy
control -- detection, policy, tokenization, the vault write, restoration, and
audit -- lives in :class:`~app.pipeline.service.SecurePipeline`, and the ordering
between those stages is the security property the whole service exists to
provide. A router that "helped" by pre-processing text, resolving a policy, or
retrying a stage would be a second, unreviewed path to a provider.

So the handler does three things: authorize the caller, hand the validated
request to the pipeline, and return what comes back. Domain failures propagate
untouched; :mod:`app.api.errors` renders each one into the standard envelope,
and catching them here would only risk replacing a precise code with a vaguer
one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Body, Depends, Request, status

from app.api.errors import ErrorEnvelope
from app.auth.dependencies import require_scope
from app.domain.models import ChatRequest, ChatResponse, Principal, Scope

if TYPE_CHECKING:  # pragma: no cover - import cycle-free typing only
    from app.api.composition import Services

router = APIRouter(prefix="/v1", tags=["chat"])

CHAT_REQUEST_EXAMPLES: dict[str, dict[str, Any]] = {
    "synthetic_contact_details": {
        "summary": "A prompt carrying synthetic contact details",
        "description": (
            "The email address and phone number are tokenized before the "
            "provider sees them, and restored in the reply."
        ),
        "value": {
            "provider": "mock",
            "model": "general-chat",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "Confirm the follow-up with Jordan Rivera at "
                        "jordan.rivera@example.test or 415-555-0142."
                    ),
                }
            ],
            "temperature": 0.2,
            "max_output_tokens": 400,
        },
    },
    "existing_session": {
        "summary": "Continuing an existing session",
        "description": (
            "Reusing a session id lets the gateway reuse the tokens minted for "
            "the same values earlier in the conversation."
        ),
        "value": {
            "session_id": "3f1d2c64-9c4a-4f2e-8f2a-7d5c9b0e1a33",
            "provider": "mock",
            "model": "general-chat",
            "messages": [{"role": "user", "content": "What was the agreed follow-up date?"}],
        },
    },
}
"""Request examples for the OpenAPI schema. Every value here is invented."""

CHAT_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_400_BAD_REQUEST: {
        "model": ErrorEnvelope,
        "description": "`INVALID_REQUEST`",
    },
    status.HTTP_401_UNAUTHORIZED: {
        "model": ErrorEnvelope,
        "description": "`AUTHENTICATION_REQUIRED`, `AUTHENTICATION_FAILED`",
    },
    status.HTTP_403_FORBIDDEN: {
        "model": ErrorEnvelope,
        "description": "`AUTHORIZATION_FAILED`, `PROVIDER_NOT_ALLOWED`, `MODEL_NOT_ALLOWED`",
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
        "description": "`POLICY_VIOLATION`, `ENTITY_LIMIT_EXCEEDED`, `INVALID_REQUEST`",
    },
    status.HTTP_429_TOO_MANY_REQUESTS: {
        "model": ErrorEnvelope,
        "description": "`RATE_LIMIT_EXCEEDED`",
    },
    status.HTTP_500_INTERNAL_SERVER_ERROR: {
        "model": ErrorEnvelope,
        "description": "`RESTORATION_FAILED`, `INTERNAL_ERROR`",
    },
    status.HTTP_502_BAD_GATEWAY: {
        "model": ErrorEnvelope,
        "description": "`PROVIDER_UNAVAILABLE`, `PROVIDER_RESPONSE_INVALID`",
    },
    status.HTTP_503_SERVICE_UNAVAILABLE: {
        "model": ErrorEnvelope,
        "description": (
            "`PRIVACY_DETECTOR_UNAVAILABLE`, `VAULT_UNAVAILABLE`, "
            "`VAULT_ENCRYPTION_FAILED`, `AUDIT_UNAVAILABLE`"
        ),
    },
    status.HTTP_504_GATEWAY_TIMEOUT: {
        "model": ErrorEnvelope,
        "description": "`PROVIDER_TIMEOUT`",
    },
}


@router.post(
    "/chat",
    response_model=ChatResponse,
    status_code=status.HTTP_200_OK,
    summary="Send a chat request through the privacy pipeline",
    response_description=("The restored assistant message plus a privacy summary of counts only."),
    responses=CHAT_ERROR_RESPONSES,
)
async def chat(
    http_request: Request,
    payload: Annotated[ChatRequest, Body(openapi_examples=CHAT_REQUEST_EXAMPLES)],
    principal: Annotated[Principal, Depends(require_scope(Scope.CHAT_INVOKE))],
) -> ChatResponse:
    """Run one chat request end to end.

    The tenant comes from ``principal`` -- the verified API key record -- and
    never from the request body, so a caller cannot address another tenant's
    sessions, policy, or vault mappings by asking nicely.

    The response carries a :class:`~app.domain.models.PrivacySummary` of counts
    per action and per entity *type*. No detected value, token, or mapping is
    ever part of it.
    """
    services: Services = http_request.app.state.services
    return await services.pipeline.invoke(payload, principal)
