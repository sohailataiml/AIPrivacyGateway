"""Privacy-safe audit logging.

Public surface:

* ``AuditRecord`` -- the only shape the service accepts, with the prohibited
  field list enforced at import time.
* ``AuditService`` -- a bounded asynchronous queue in front of the audit table.
* ``AuditSink`` -- the storage Protocol the service depends on.
* ``CorrelationHasher`` -- keyed prompt, response, and session digests.
* ``metrics`` -- audit failure and queue-depth instruments.
"""

from __future__ import annotations

from app.audit import metrics
from app.audit.correlation import (
    AUDIT_CORRELATION_LABEL,
    PROMPT_DOMAIN,
    RESPONSE_DOMAIN,
    SESSION_DOMAIN,
    CorrelationHasher,
    derive_correlation_key,
)
from app.audit.models import (
    ALLOWED_FIELD_NAMES,
    PROHIBITED_FIELD_SUBSTRINGS,
    AuditRecord,
    counts_from_summary,
    enforce_field_policy,
)
from app.audit.service import (
    DEFAULT_MAX_QUEUE_SIZE,
    AuditService,
    AuditSink,
    to_draft,
)

__all__ = [
    "ALLOWED_FIELD_NAMES",
    "AUDIT_CORRELATION_LABEL",
    "DEFAULT_MAX_QUEUE_SIZE",
    "PROHIBITED_FIELD_SUBSTRINGS",
    "PROMPT_DOMAIN",
    "RESPONSE_DOMAIN",
    "SESSION_DOMAIN",
    "AuditRecord",
    "AuditService",
    "AuditSink",
    "CorrelationHasher",
    "counts_from_summary",
    "derive_correlation_key",
    "enforce_field_policy",
    "metrics",
    "to_draft",
]
