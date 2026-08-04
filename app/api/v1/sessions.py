"""``DELETE /v1/sessions/{session_id}`` -- forget one conversation's mappings.

This is the erasure control behind a data-subject request, and it is the reason
the vault stores mappings under a session namespace at all: deleting the session
key set destroys every token-to-value mapping made for that conversation, after
which no restoration can recover the originals. There is no soft delete.

Two properties are load-bearing:

**Tenant scoping.** The tenant comes from the verified API key record, never
from the path or a header, so ``DELETE /v1/sessions/<someone-else's-uuid>``
addresses this tenant's namespace and finds nothing there.

**Idempotence.** An absent session answers ``204``, not ``404``. Distinguishing
the two would turn this endpoint into an oracle for which session ids exist, and
a caller retrying a delete after a timeout deserves the same answer as the
caller who succeeded the first time. "The mappings are gone" is true either way.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Request, status

from app.api.errors import ErrorEnvelope
from app.auth.dependencies import require_scope
from app.domain.models import Principal, Scope
from app.observability.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - import cycle-free typing only
    from app.api.composition import Services

logger = get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["sessions"])

SESSION_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_401_UNAUTHORIZED: {
        "model": ErrorEnvelope,
        "description": "`AUTHENTICATION_REQUIRED`, `AUTHENTICATION_FAILED`",
    },
    status.HTTP_403_FORBIDDEN: {
        "model": ErrorEnvelope,
        "description": "`AUTHORIZATION_FAILED`",
    },
    status.HTTP_422_UNPROCESSABLE_CONTENT: {
        "model": ErrorEnvelope,
        "description": "`INVALID_REQUEST` -- the path segment is not a UUID",
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
        "description": "`VAULT_UNAVAILABLE`",
    },
}


@router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete every vault mapping for one session",
    response_description="The session holds no mappings, whether or not it ever did.",
    responses=SESSION_ERROR_RESPONSES,
)
async def delete_session(
    http_request: Request,
    session_id: Annotated[
        UUID,
        Path(
            description="The session whose mappings are destroyed.",
            examples=["3f1d2c64-9c4a-4f2e-8f2a-7d5c9b0e1a33"],
        ),
    ],
    principal: Annotated[Principal, Depends(require_scope(Scope.SESSIONS_DELETE))],
) -> None:
    """Destroy the caller tenant's mappings for ``session_id``.

    Returns ``204`` whether the session existed or not. A vault failure is a
    ``VaultUnavailableError`` and propagates: reporting success for a delete
    that did not happen is the one wrong answer here.
    """
    services: Services = http_request.app.state.services
    deleted = await services.vault.delete_session(
        tenant_id=principal.tenant_id, session_id=session_id
    )
    # Counts and identifiers only. A mapping, a token, or an original value in
    # this line would defeat the deletion it is reporting.
    logger.info(
        "session_deleted",
        tenant_id=str(principal.tenant_id),
        session_id=str(session_id),
        mapping_count=deleted,
    )
