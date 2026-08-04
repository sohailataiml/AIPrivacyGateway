"""Secure pipeline orchestration.

:class:`~app.pipeline.service.SecurePipeline` is the only supported way to turn
a ``ChatRequest`` into a ``ChatResponse``. A router must not call a detector, a
tokenizer, or a provider adapter directly: the ordering guarantees this package
enforces -- mappings persisted before the provider is reached, a block refused
before the vault is touched, one session id shared by every message -- exist
nowhere else.
"""

from __future__ import annotations

from app.pipeline.context import (
    DEFAULT_LANGUAGE,
    DEFAULT_MAX_CONCURRENT_PROVIDER_CALLS,
    PIPELINE_OVERHEAD_BUDGET_SECONDS,
    PipelineAttempt,
    PipelineConfig,
    RequestOutcome,
    audit_payload,
    default_timeout_seconds,
)
from app.pipeline.guards import (
    enforce_entity_budget,
    enforce_message_sizes,
    entity_budget,
    reject_blocked_entities,
    select_request_entities,
)
from app.pipeline.protocols import (
    AuditServiceLike,
    DetectorLike,
    OutputPipelineLike,
    PolicyResolverLike,
    RestoredOutputLike,
    TokenizerLike,
)
from app.pipeline.service import SecurePipeline
from app.pipeline.session import NIL_SESSION_ID, resolve_session_id
from app.pipeline.stages import PipelineStage, run_stage, stage_failure

__all__ = [
    "DEFAULT_LANGUAGE",
    "DEFAULT_MAX_CONCURRENT_PROVIDER_CALLS",
    "NIL_SESSION_ID",
    "PIPELINE_OVERHEAD_BUDGET_SECONDS",
    "AuditServiceLike",
    "DetectorLike",
    "OutputPipelineLike",
    "PipelineAttempt",
    "PipelineConfig",
    "PipelineStage",
    "PolicyResolverLike",
    "RequestOutcome",
    "RestoredOutputLike",
    "SecurePipeline",
    "TokenizerLike",
    "audit_payload",
    "default_timeout_seconds",
    "enforce_entity_budget",
    "enforce_message_sizes",
    "entity_budget",
    "reject_blocked_entities",
    "resolve_session_id",
    "run_stage",
    "select_request_entities",
    "stage_failure",
]
