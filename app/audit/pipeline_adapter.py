"""Adapter between the pipeline's audit call and :class:`AuditService`.

The pipeline and the audit package were built independently against each
other's shape, and they did not meet: the pipeline calls
``record(**fields)`` with a raw ``session_id``, while :class:`AuditService`
exposes ``submit(record: AuditRecord)`` and stores only a ``session_id_hash``.
Wiring the two together directly raises ``AttributeError`` on every request --
and because the production default is ``AUDIT_FAIL_CLOSED=true``, that is a
total outage rather than a missing log line.

Rather than reach into either package and bend it toward the other, this
adapter owns the translation. It lives in ``app.audit`` deliberately: the audit
package owns the record shape and the prohibited-field rules, so it is the side
that should decide how a loose field bag becomes a validated record. The
pipeline stays free of audit internals, and the enforcement in
``app.audit.models`` still runs on everything written.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.audit.correlation import CorrelationHasher
from app.audit.models import AuditRecord
from app.audit.service import AuditService

# Fields the pipeline sends that map straight through, unchanged.
_PASSTHROUGH_FIELDS: tuple[str, ...] = (
    "tenant_id",
    "request_id",
    "status_code",
    "occurred_at",
    "api_key_id",
    "policy_id",
    "policy_version",
    "provider_alias",
    "model_alias",
    "input_character_count",
    "output_character_count",
    "entity_counts",
    "actions",
    "blocked",
    "block_reason_code",
    "provider_latency_ms",
    "pipeline_latency_ms",
    "error_code",
    "prompt_hmac",
    "response_hmac",
    "outbound_hmac",
    "outbound_scan",
)

DEFAULT_STATUS_CODE = 500
"""Used only when the pipeline omits a status. A missing status means something
went wrong before one was assigned, so the safe assumption is failure."""


class PipelineAuditAdapter:
    """Satisfies the pipeline's ``AuditServiceLike`` over a real AuditService."""

    __slots__ = ("_hasher", "_service")

    def __init__(self, service: AuditService, *, hasher: CorrelationHasher | None = None) -> None:
        self._service = service
        self._hasher = hasher or CorrelationHasher.from_settings()

    async def record(self, **fields: Any) -> None:
        """Translate the pipeline's field bag into a validated AuditRecord.

        Unknown fields are dropped rather than passed through: ``AuditRecord``
        would reject them anyway, and a hard failure here would fail the request
        under the fail-closed policy. Dropping is safe because the drop is
        toward *less* data being written, never more.
        """
        tenant_id = fields["tenant_id"]
        payload: dict[str, Any] = {
            name: fields[name] for name in _PASSTHROUGH_FIELDS if name in fields
        }
        payload.setdefault("status_code", DEFAULT_STATUS_CODE)

        # The pipeline passes the raw session id so that the audit package --
        # which owns the correlation key -- decides how it is hashed.
        session_id = fields.get("session_id")
        if isinstance(session_id, UUID):
            payload["session_id_hash"] = self._hasher.session_digest(
                tenant_id=tenant_id, session_id=session_id
            )

        await self._service.submit(AuditRecord(**payload))


def build_pipeline_audit_adapter(
    service: AuditService, *, hasher: CorrelationHasher | None = None
) -> PipelineAuditAdapter:
    """Convenience factory for the composition root."""
    return PipelineAuditAdapter(service, hasher=hasher)


__all__ = [
    "DEFAULT_STATUS_CODE",
    "PipelineAuditAdapter",
    "build_pipeline_audit_adapter",
]
