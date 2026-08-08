"""``GET /v1/providers`` -- which providers this deployment can actually call.

The chat UI needs to offer a provider choice, and the alternative to this
endpoint is a hardcoded list in the frontend. That list would be wrong in two
directions at once: it would offer a provider whose credential is absent (a
selector that produces a guaranteed error), and it would hide one a deployment
added. The registry already knows the answer, so it is the thing that should be
asked.

**What this discloses, and what it deliberately does not.** A caller learns the
alias, whether it is the deterministic mock or an external service, whether it
is callable, and which model aliases their policy permits. A caller learns
nothing about *why* something is unavailable -- not the variable name, not
whether a key was malformed rather than missing, not the endpoint or the
account. "Not configured" is the whole story, because the difference between
"absent" and "rejected" is a fact about the credential and belongs on the
server.

Availability is the conjunction of two independent gates, and both are reported
as one boolean because a caller can act on neither separately:

* **Registered.** ``build_default_registry`` adds the OpenAI adapter only when a
  credential is configured, so an unregistered alias is a deployment that cannot
  call it.
* **Permitted by policy.** The active ``PolicySnapshot`` lists provider aliases
  and their models. A registered provider the policy omits is still refused at
  request time, and offering it here would produce a selector whose only
  outcome is ``PROVIDER_NOT_ALLOWED``.

This is read-only and adds no capability: everything it reports is already
discoverable by attempting a request and reading the error.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, ConfigDict

from app.api.errors import ErrorEnvelope
from app.auth.dependencies import require_scope
from app.domain.models import Principal, Scope
from app.llm.mock_provider import MOCK_PROVIDER_ALIAS

if TYPE_CHECKING:  # pragma: no cover - import cycle-free typing only
    from app.api.composition import Services

router = APIRouter(prefix="/v1", tags=["providers"])

PROVIDER_KIND_MOCK = "mock"
PROVIDER_KIND_EXTERNAL = "external"


class ProviderView(BaseModel):
    """One selectable provider, described without any configuration detail."""

    model_config = ConfigDict(extra="forbid")

    alias: str
    kind: str
    """``mock`` or ``external``. Drives the UI's "external provider" notice.

    Derived from the alias of the deterministic adapter rather than from a flag
    on the adapter itself: an adapter that could declare itself deterministic
    could also declare it wrongly.
    """

    available: bool
    """Callable right now: registered in this deployment *and* allowed by the
    caller's active policy. Never explains which gate failed."""

    models: tuple[str, ...]
    """Model aliases the policy permits for this provider. Empty when the policy
    does not list it."""


class ProvidersResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    providers: tuple[ProviderView, ...]
    default: str
    """The alias a client should preselect. Always the mock provider: a demo that
    silently opens by pointing at a paid external service is a demo that costs
    money to open."""


PROVIDER_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_401_UNAUTHORIZED: {
        "model": ErrorEnvelope,
        "description": "`AUTHENTICATION_REQUIRED`, `AUTHENTICATION_FAILED`",
    },
    status.HTTP_403_FORBIDDEN: {
        "model": ErrorEnvelope,
        "description": "`AUTHORIZATION_FAILED`",
    },
    status.HTTP_429_TOO_MANY_REQUESTS: {
        "model": ErrorEnvelope,
        "description": "`RATE_LIMIT_EXCEEDED`",
    },
    status.HTTP_500_INTERNAL_SERVER_ERROR: {
        "model": ErrorEnvelope,
        "description": "`INTERNAL_ERROR`",
    },
}


@router.get(
    "/providers",
    response_model=ProvidersResponse,
    summary="List the providers this deployment can call",
    response_description="Aliases, availability, and permitted model aliases.",
    responses=PROVIDER_ERROR_RESPONSES,
)
async def list_providers(
    http_request: Request,
    principal: Annotated[Principal, Depends(require_scope(Scope.CHAT_INVOKE))],
) -> ProvidersResponse:
    """Report the selectable providers for the caller's active policy.

    Guarded by ``chat:invoke`` rather than a new scope. The information is a
    strict subset of what invoking chat already reveals, and a new scope value
    would not be granted to any existing API key row -- so every current key
    would receive a 403 from an endpoint the UI needs on load.
    """
    services: Services = http_request.app.state.services
    snapshot = await services.policy.active_snapshot(principal.tenant_id)
    permitted = dict(snapshot.providers)

    views = tuple(
        ProviderView(
            alias=alias,
            kind=PROVIDER_KIND_MOCK if alias == MOCK_PROVIDER_ALIAS else PROVIDER_KIND_EXTERNAL,
            available=alias in permitted,
            models=tuple(sorted(permitted.get(alias, ()))),
        )
        for alias in services.providers.aliases()
    )
    return ProvidersResponse(providers=views, default=MOCK_PROVIDER_ALIAS)
