"""The shared path from raw recognizer hits to the detector's public result.

Every :class:`~app.detection.base.Detector` implementation funnels through
:func:`finalize`, so the fake and the Presidio-backed engine cannot drift on the
guarantees that matter: allowlist suppression, thresholds, checksum validation,
overlap resolution, the entity cap, and diagnostic-only recognizer names.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import NamedTuple

from app.detection.checksums import VALUE_VALIDATORS
from app.detection.config import DetectionConfig
from app.detection.overlap import resolve_overlaps
from app.domain.errors import EntityLimitExceededError
from app.domain.models import DetectedEntity


class Candidate(NamedTuple):
    """An unvalidated recognizer hit.

    Deliberately not a :class:`~app.domain.models.DetectedEntity`: a candidate
    may carry an out-of-range span or a score outside ``[0, 1]``, and the domain
    model refuses to hold either. :func:`finalize` is where the two meet.
    """

    entity_type: str
    start: int
    end: int
    score: float
    recognizer: str | None = None


def _span_is_valid(candidate: Candidate, text_length: int) -> bool:
    """Reject spans that do not address real characters of the analyzed text."""
    return 0 <= candidate.start < candidate.end <= text_length


def _score_is_reportable(candidate: Candidate, config: DetectionConfig) -> bool:
    return candidate.score >= config.threshold_for(candidate.entity_type)


def _value_is_valid(candidate: Candidate, value: str) -> bool:
    validator = VALUE_VALIDATORS.get(candidate.entity_type)
    return validator is None or validator(value)


def finalize(
    candidates: Iterable[Candidate],
    *,
    text: str,
    config: DetectionConfig,
    requested_entities: frozenset[str] | None = None,
    diagnostic: bool = False,
) -> list[DetectedEntity]:
    """Turn raw candidates into the detector's sorted, non-overlapping result.

    Applied in order: span validity, entity type filtering, value validation
    (Luhn for cards), allowlist suppression, confidence thresholds, overlap
    resolution, then the entity cap.

    Args:
        candidates: Raw hits in any order.
        text: The exact text the offsets index into.
        config: Thresholds, allowlist, and limits.
        requested_entities: Restrict output to these types. ``None`` means all
            enabled types.
        diagnostic: When ``True``, keep the recognizer name on each result.
            Off by default so no operational path can leak it.

    Returns:
        Entities ascending by ``(start, end)``, none overlapping.

    Raises:
        EntityLimitExceededError: More surviving entities than ``max_entities``.
    """
    allowed_types = config.enabled_entities
    if requested_entities is not None:
        allowed_types = allowed_types & requested_entities

    text_length = len(text)
    kept: list[DetectedEntity] = []

    for candidate in candidates:
        if candidate.entity_type not in allowed_types:
            continue
        if not _span_is_valid(candidate, text_length):
            continue

        value = text[candidate.start : candidate.end]
        if not _value_is_valid(candidate, value):
            continue
        if config.is_allowlisted(value):
            continue
        if not _score_is_reportable(candidate, config):
            continue

        kept.append(
            DetectedEntity(
                entity_type=candidate.entity_type,
                start=candidate.start,
                end=candidate.end,
                score=min(max(candidate.score, 0.0), 1.0),
                recognizer=candidate.recognizer,
            )
        )

    # Resolve with recognizer names intact so the tie-break is available, then
    # strip them: diagnostic mode changes what is reported, never what is kept.
    resolved = resolve_overlaps(kept, priority=config.entity_priority)

    if len(resolved) > config.max_entities:
        # Counts only. The log context never carries a span or a value.
        raise EntityLimitExceededError(
            log_context={"limit": config.max_entities, "detected": len(resolved)}
        )

    if diagnostic:
        return resolved
    return [
        DetectedEntity(
            entity_type=entity.entity_type,
            start=entity.start,
            end=entity.end,
            score=entity.score,
        )
        for entity in resolved
    ]
