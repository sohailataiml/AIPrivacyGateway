"""Deterministic overlap resolution.

Recognizers disagree. A card number is also a date; an email address is also a
URL; a nine digit run is also an account number. Whatever the pipeline does
next -- tokenize, redact, block -- it must act on exactly one interpretation of
each character, and it must pick the same one every run, on every machine, for
any input ordering.

:func:`resolve_overlaps` is therefore a pure function of its arguments: no
clock, no randomness, no policy lookup, no I/O. Feed it the same spans in any
order and it returns the same list.

Ordering rule
-------------
Candidates compete under a *total* order on five keys, compared in sequence
until one differs:

1. **Higher severity wins.** Severity comes from ``priority`` (default
   :data:`~app.detection.entities.ENTITY_PRIORITY`); a type with no entry
   scores :data:`~app.detection.entities.SEVERITY_UNKNOWN` and loses. This is
   first because misclassifying an SSN as a date is a disclosure, while the
   reverse is only noise -- see ``architecture.md`` section 9.4.
2. **Higher confidence wins.**
3. **Longer span wins.** Preferring the wider span avoids leaving a fragment of
   a sensitive value in the text.
4. **Lower start offset wins.**
5. **Lexicographically smaller entity type wins**, then lexicographically
   smaller recognizer name (``None`` sorts as the empty string).

Two candidates that tie on all five keys are equal in every field of
:class:`~app.domain.models.DetectedEntity`, so the order is total and the
outcome cannot depend on input order.

Selection is greedy under that order: walk candidates best-first and keep one
when it overlaps nothing already kept. Greedy is intentional. It is O(n*k), it
never splits a span, and its result is explainable from the ordering rule
alone -- unlike a maximum-coverage search, whose answer changes with unrelated
spans elsewhere in the text.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from app.detection.entities import ENTITY_PRIORITY, SEVERITY_UNKNOWN
from app.domain.models import DetectedEntity

DominanceKey = tuple[int, float, int, int, str, str]


def dominance_key(
    entity: DetectedEntity,
    priority: Mapping[str, int] = ENTITY_PRIORITY,
) -> DominanceKey:
    """Return the sort key implementing the documented ordering.

    Smaller is better, so descending keys are negated. Exposed for tests and
    for callers that need to explain why one span beat another.
    """
    severity = priority.get(entity.entity_type, SEVERITY_UNKNOWN)
    return (
        -severity,
        -entity.score,
        -entity.length,
        entity.start,
        entity.entity_type,
        entity.recognizer or "",
    )


def resolve_overlaps(
    entities: Iterable[DetectedEntity],
    *,
    priority: Mapping[str, int] = ENTITY_PRIORITY,
) -> list[DetectedEntity]:
    """Return a non-overlapping subset, sorted by ``(start, end)``.

    Identical duplicate spans collapse to one entry as a side effect: the second
    copy overlaps the first and is dropped.

    Args:
        entities: Candidate spans. Order is irrelevant to the result.
        priority: Entity type to severity rank. Missing types rank lowest.

    Returns:
        The kept spans, ascending by start then end. Never mutates the input.
    """
    ordered = sorted(entities, key=lambda entity: dominance_key(entity, priority))

    kept: list[DetectedEntity] = []
    for candidate in ordered:
        if any(candidate.overlaps(existing) for existing in kept):
            continue
        kept.append(candidate)

    return sorted(kept, key=lambda entity: (entity.start, entity.end, entity.entity_type))
