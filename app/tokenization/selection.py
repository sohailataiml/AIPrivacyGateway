"""Choosing which detected spans the tokenizer will actually act on.

Detection may hand over spans that overlap, that score below the policy's
threshold for their type, or -- if a caller ever wires the wrong text to the
wrong detections -- that fall outside the string. Splicing any of those would
silently corrupt the message, so they are resolved here, before a single vault
call is made.

Selection is deterministic: the same detections and the same policy always yield
the same kept set, in the same order.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.domain.errors import InvalidRequestError
from app.domain.models import DetectedEntity
from app.tokenization.protocols import PolicyLike


def _ordering_key(entity: DetectedEntity) -> tuple[int, int, float, str]:
    """Earliest span first; then longest, then most confident, then type name.

    The tie-breakers exist so the outcome never depends on the order detection
    happened to return, which keeps the whole pipeline reproducible.
    """
    return (entity.start, -entity.length, -entity.score, entity.entity_type)


def validate_spans(*, text: str, entities: Sequence[DetectedEntity]) -> None:
    """Reject any span that does not lie inside ``text``.

    Raises:
        InvalidRequestError: if a span extends past the end of the text.
    """
    limit = len(text)
    for entity in entities:
        if entity.end > limit:
            raise InvalidRequestError(
                log_context={
                    "reason": "entity span outside text bounds",
                    "entity_type": entity.entity_type,
                    "span_end": entity.end,
                    "text_length": limit,
                }
            )


def resolve_overlaps(entities: Sequence[DetectedEntity]) -> tuple[DetectedEntity, ...]:
    """Return a non-overlapping subset, preferring longer then higher-scoring spans."""
    kept: list[DetectedEntity] = []
    boundary = 0
    for entity in sorted(entities, key=_ordering_key):
        if entity.start < boundary:
            continue
        kept.append(entity)
        boundary = entity.end
    return tuple(kept)


def select_entities(
    *,
    text: str,
    entities: Sequence[DetectedEntity],
    policy: PolicyLike,
) -> tuple[DetectedEntity, ...]:
    """Return the spans to act on, ascending by start offset.

    Spans scoring below their type's minimum are dropped: the policy considers
    them too weak to be detections at all, so they are not counted anywhere.
    """
    validate_spans(text=text, entities=entities)
    confident = [
        entity for entity in entities if entity.score >= policy.min_score_for(entity.entity_type)
    ]
    return resolve_overlaps(confident)
