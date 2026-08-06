"""From per-segment detections to one labeled span per value.

Every function here is **pure**: no clock, no randomness, no I/O, no policy
lookup beyond the immutable snapshot it is handed. The same detections and the
same policy always produce the same spans in the same order, which is what makes
a document's protection reproducible and a disagreement between two runs a bug
rather than a coin toss.

The stages, in the order they must run:

1. :func:`to_global` — promote segment-local offsets to document offsets. This
   is the only arithmetic in the phase, and it is delegated to
   ``Segment.to_global`` so it exists in one place (ADR-0029).
2. :func:`coalesce` — collapse the duplicates segmentation deliberately created.
3. :func:`select_confident` — drop what the policy is not sure enough about.
4. :func:`resolve` — one interpretation per character.
5. :func:`label` — attach the policy's action and the pages.

**Why coalesce before resolving.** Segments overlap, so an entity in an overlap
region is detected twice at *identical* global offsets. Feeding both to overlap
resolution would work — the second copy overlaps the first and loses — but the
survivor would carry one segment's score and one segment's provenance, silently
discarding the other. Coalescing first keeps the higher score (Presidio scores
the same value differently depending on the context words around it, and after a
cut the context is genuinely different) and records both segments. Only then
does resolution decide between spans that are actually *different*.

**Why confidence is filtered before overlap resolution, not after.** The reverse
order loses values. A sub-threshold ``US_SSN`` and an above-threshold
``DATE_TIME`` over the same digits: resolving first lets the SSN win on severity
and then be dropped for confidence, leaving nothing protecting those characters.
Filtering first lets the ``DATE_TIME`` survive and be acted on. Filtering first
is never worse and is sometimes the difference between a protected value and a
leaked one — and it is the order ``app/tokenization/selection.py`` already uses
for prompts, so documents and prompts cannot drift apart.

**Why the severity-aware resolver.** ``app.detection.overlap.resolve_overlaps``
implements the ordering rule in ``architecture.md`` §9.4 — severity first,
because misclassifying an SSN as a date is a disclosure while the reverse is
only noise. It already ran inside each segment; running it again over the merged
set is what extends that guarantee from "within a segment" to "across the
document".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.detection.overlap import resolve_overlaps
from app.documents.analysis.models import LabeledSpan
from app.domain.models import DetectedEntity, EntityAction

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from app.documents.extraction.models import ExtractedDocument
    from app.documents.segmentation import Segment
    from app.policy.models import PolicySnapshot

SpanKey = tuple[str, int, int]
"""Identity of a span: entity type and its global range. Unique after coalescing."""


@dataclass(frozen=True, slots=True)
class GlobalDetection:
    """One detection, moved onto the document's coordinate system.

    Carries the segments it came from alongside the entity, because
    ``DetectedEntity`` has nowhere to put provenance and inventing a parallel
    list indexed by position is how provenance stops matching its spans.
    """

    entity: DetectedEntity
    segments: tuple[int, ...]

    @property
    def key(self) -> SpanKey:
        return (self.entity.entity_type, self.entity.start, self.entity.end)


def to_global(segment: Segment, entities: Iterable[DetectedEntity]) -> list[GlobalDetection]:
    """Rewrite segment-local detections as document-global ones.

    Args:
        segment: The segment the detector ran over.
        entities: Its detections, with offsets into that segment's text.

    Returns:
        The same detections addressed against the document's text buffer.

    Raises:
        DocumentExtractionError: an offset lies outside the segment. The
            detector's own post-processing already refuses those, so this is a
            backstop against a detector implementation that does not.
    """
    promoted: list[GlobalDetection] = []
    for entity in entities:
        promoted.append(
            GlobalDetection(
                entity=DetectedEntity(
                    entity_type=entity.entity_type,
                    start=segment.to_global(entity.start),
                    end=segment.to_global(entity.end),
                    score=entity.score,
                    # Dropped deliberately: the recognizer name is diagnostic
                    # output and never travels with a document's spans.
                    recognizer=None,
                ),
                segments=(segment.index,),
            )
        )
    return promoted


def coalesce(detections: Iterable[GlobalDetection]) -> list[GlobalDetection]:
    """Collapse detections of the same value at the same place into one.

    Two segments overlapping by design means the same entity is reported twice
    at identical global offsets. This is where those become one span again.

    The surviving score is the **highest** of the copies. Segmentation cuts
    context, and Presidio's score depends on the words around a match, so the
    segment that saw the value with its context intact is the one that scored it
    correctly. Taking the maximum is also the fail-closed direction: it can only
    move a span over a policy threshold, never under one.

    Returns:
        One entry per distinct ``(entity_type, start, end)``, ordered by
        ``(start, end, entity_type)``.
    """
    merged: dict[SpanKey, GlobalDetection] = {}
    for detection in detections:
        existing = merged.get(detection.key)
        if existing is None:
            merged[detection.key] = detection
            continue
        merged[detection.key] = GlobalDetection(
            entity=DetectedEntity(
                entity_type=detection.entity.entity_type,
                start=detection.entity.start,
                end=detection.entity.end,
                score=max(existing.entity.score, detection.entity.score),
            ),
            segments=tuple(sorted(set(existing.segments) | set(detection.segments))),
        )
    return sorted(
        merged.values(),
        key=lambda item: (item.entity.start, item.entity.end, item.entity.entity_type),
    )


def select_confident(
    detections: Iterable[GlobalDetection], *, policy: PolicySnapshot
) -> list[GlobalDetection]:
    """Drop spans scoring below their type's policy threshold.

    A span below the threshold is not a weak detection the policy tolerates; it
    is one the policy has decided is not a detection at all. It is dropped
    rather than labeled ``ALLOW``, so it appears in no count and no summary
    claims it was considered and permitted.
    """
    return [
        detection
        for detection in detections
        if detection.entity.score >= policy.min_score_for(detection.entity.entity_type)
    ]


def resolve(detections: Sequence[GlobalDetection]) -> list[GlobalDetection]:
    """Return a non-overlapping subset, ordered by offset.

    Delegates the ordering rule to :func:`app.detection.overlap.resolve_overlaps`
    so documents and prompts resolve contention identically. Provenance is
    re-attached by span identity, which is unique because :func:`coalesce` has
    already run.
    """
    provenance = {detection.key: detection.segments for detection in detections}
    kept = resolve_overlaps(detection.entity for detection in detections)
    return [
        GlobalDetection(
            entity=entity,
            segments=provenance[(entity.entity_type, entity.start, entity.end)],
        )
        for entity in kept
    ]


def blocked_entity_type(
    detections: Iterable[GlobalDetection], *, policy: PolicySnapshot
) -> str | None:
    """Return the first entity type the policy blocks, or ``None``.

    Reported as a type rather than raised here so the caller owns the error and
    its log context. The type is safe to record; the value it stood for is not,
    and no caller is given the chance to include it.
    """
    for detection in detections:
        if policy.action_for(detection.entity.entity_type) is EntityAction.BLOCK:
            return detection.entity.entity_type
    return None


def label(
    detections: Iterable[GlobalDetection],
    *,
    document: ExtractedDocument,
    policy: PolicySnapshot,
) -> tuple[LabeledSpan, ...]:
    """Attach the policy action and the page references to each span.

    Raises:
        ValueError: a detection resolves to ``BLOCK``. Callers must refuse the
            document via :func:`blocked_entity_type` first; reaching this is a
            programming error, and :class:`LabeledSpan` refuses to represent it.
    """
    return tuple(
        LabeledSpan(
            entity_type=detection.entity.entity_type,
            start=detection.entity.start,
            end=detection.entity.end,
            score=detection.entity.score,
            action=policy.action_for(detection.entity.entity_type),
            pages=document.pages_covering(detection.entity.start, detection.entity.end),
            segments=detection.segments,
        )
        for detection in detections
    )


__all__ = [
    "GlobalDetection",
    "SpanKey",
    "blocked_entity_type",
    "coalesce",
    "label",
    "resolve",
    "select_confident",
    "to_global",
]
