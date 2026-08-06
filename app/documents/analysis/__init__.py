"""Detection over stored documents: labeled global spans, decided by policy.

The stage between segmentation (Phase 2) and protection. Given a stored
document, it decrypts, extracts, segments, detects over every segment, merges
the duplicates segmentation deliberately created, applies the tenant's policy,
and returns one :class:`~app.documents.analysis.models.AnalyzedDocument`.

Nothing is persisted. The result exists for the life of one call (ADR-0030),
and its construction is the checkpoint the next phase relies on.
"""

from app.documents.analysis.analyzer import (
    DEFAULT_CONCURRENCY,
    DEFAULT_MAX_ENTITIES,
    DocumentAnalyzer,
    PolicySource,
    SegmentSource,
)
from app.documents.analysis.models import AnalyzedDocument, LabeledSpan
from app.documents.analysis.spans import (
    GlobalDetection,
    blocked_entity_type,
    coalesce,
    label,
    resolve,
    select_confident,
    to_global,
)

__all__ = [
    "DEFAULT_CONCURRENCY",
    "DEFAULT_MAX_ENTITIES",
    "AnalyzedDocument",
    "DocumentAnalyzer",
    "GlobalDetection",
    "LabeledSpan",
    "PolicySource",
    "SegmentSource",
    "blocked_entity_type",
    "coalesce",
    "label",
    "resolve",
    "select_confident",
    "to_global",
]
