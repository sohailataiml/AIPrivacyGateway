"""What leaves the pipeline: the caller's response, the audit row, the log line.

All three exits are here rather than spread through the service so that the
privacy question -- *can this path emit an original value?* -- is answered by
reading one short module.

The answers are: the response carries restored text and goes only to the
authenticated principal; the audit row carries identifiers, counts, and codes,
built from :class:`~app.pipeline.context.RequestOutcome`, which has no field
capable of holding content; the log line carries allowlisted keys only.
"""

from __future__ import annotations

import asyncio
from typing import Final

from app.domain.errors import ErrorCode, GatewayError
from app.domain.models import (
    ChatMessage,
    ChatResponse,
    MessageRole,
    PrivacySummary,
    ProtectedPreview,
)
from app.observability.logging import get_logger
from app.pipeline.context import PipelineAttempt, RequestOutcome, audit_payload
from app.pipeline.protocols import AuditServiceLike, RestoredOutputLike
from app.pipeline.stages import PipelineStage, run_stage, stage_failure
from app.policy.models import PolicySnapshot

_LOGGER = get_logger(__name__)

ASSISTANT_ROLE: Final[MessageRole] = "assistant"
"""The role the gateway always returns. A provider's own role label is ignored:
the response is the gateway's, and its shape must not be provider-controlled."""

_AUDIT_FAILURE = stage_failure(GatewayError)


def build_response(
    attempt: PipelineAttempt,
    restored: RestoredOutputLike,
    summary: PrivacySummary,
    protected_preview: ProtectedPreview | None = None,
) -> ChatResponse:
    """Assemble the caller's response. The only place restored text is exposed.

    ``provider`` and ``model`` are echoed as the *aliases* the caller asked for,
    never as the provider's internal model id: which model an alias resolves to
    is deployment configuration, not part of the API.

    ``protected_preview`` arrives already masked. This function does not build
    it, so there is no path here that could hand an unmasked token to a caller.
    """
    return ChatResponse(
        request_id=attempt.request_id,
        session_id=attempt.session_id,
        provider=attempt.provider_alias,
        model=attempt.model_alias,
        message=ChatMessage(role=ASSISTANT_ROLE, content=restored.text),
        privacy=summary,
        usage=restored.usage,
        protected_preview=protected_preview,
    )


async def record_outcome(
    audit: AuditServiceLike,
    *,
    attempt: PipelineAttempt,
    snapshot: PolicySnapshot | None,
    outcome: RequestOutcome,
    fail_closed: bool,
) -> None:
    """Append one audit event, honouring the configured failure policy.

    Args:
        audit: The audit service.
        attempt: Identity and clock for this request.
        snapshot: The active policy, or ``None`` if resolution never succeeded.
        outcome: Counts and codes. Cannot carry content by construction.
        fail_closed: When true, an audit failure fails the request.

    Raises:
        GatewayError: if the write failed and ``fail_closed`` is set.
    """
    try:
        await run_stage(
            audit.record(**audit_payload(attempt=attempt, snapshot=snapshot, outcome=outcome)),
            stage=PipelineStage.AUDIT,
            deadline=attempt.deadline,
            failure=_AUDIT_FAILURE,
        )
    except GatewayError:
        if fail_closed:
            raise
        # Fail-open is a deliberate configuration, not an excuse for silence:
        # this is the high-priority signal that a request completed unaudited.
        _LOGGER.error(
            "pipeline.audit_write_failed",
            request_id=str(attempt.request_id),
            tenant_id=str(attempt.tenant_id),
            stage=str(PipelineStage.AUDIT),
            reason="audit_write_failed",
        )


async def record_failure(
    audit: AuditServiceLike,
    *,
    attempt: PipelineAttempt,
    snapshot: PolicySnapshot | None,
    error: GatewayError,
) -> None:
    """Log and record a refused request, then let the original error surface.

    Never fails closed. Replacing the reason a request was refused with "the
    audit service is unavailable" would hide the privacy decision that actually
    stopped it, and a refused request has already protected the caller's data.
    """
    outcome = RequestOutcome(
        status_code=error.status_code,
        summary=PrivacySummary(),
        error_code=str(error.code),
        # ``blocked`` means the privacy policy refused the content, not that the
        # request failed. A vault outage is a failure; it is not a block.
        blocked=error.code is ErrorCode.POLICY_VIOLATION,
        pipeline_latency_ms=attempt.elapsed_ms(asyncio.get_running_loop().time()),
    )
    _LOGGER.warning(
        "pipeline.failed",
        request_id=str(attempt.request_id),
        session_id=str(attempt.session_id),
        tenant_id=str(attempt.tenant_id),
        provider_alias=attempt.provider_alias,
        model_alias=attempt.model_alias,
        error_code=str(error.code),
    )
    await record_outcome(
        audit, attempt=attempt, snapshot=snapshot, outcome=outcome, fail_closed=False
    )


def log_completion(
    attempt: PipelineAttempt,
    snapshot: PolicySnapshot | None,
    outcome: RequestOutcome,
) -> None:
    """One privacy-safe line per successful request: identifiers and counts."""
    _LOGGER.info(
        "pipeline.completed",
        request_id=str(attempt.request_id),
        session_id=str(attempt.session_id),
        tenant_id=str(attempt.tenant_id),
        provider_alias=attempt.provider_alias,
        model_alias=attempt.model_alias,
        policy_version=snapshot.version if snapshot is not None else None,
        detected=outcome.summary.detected,
        tokenized=outcome.summary.tokenized,
        restored=outcome.summary.restored,
        unknown_tokens=outcome.summary.unknown_tokens,
        duration_ms=outcome.pipeline_latency_ms,
    )
