"""What detection over a document produces, and the checkpoint it represents.

Two types, and the relationship between them is the same one
``app/domain/models.py`` draws between ``ChatRequest`` and
``ProtectedChatRequest``: **construction is the safety check**.

A :class:`LabeledSpan` cannot hold ``BLOCK``, and an :class:`AnalyzedDocument`
cannot hold spans that overlap, run backwards, or point outside the buffer they
index. So the phase that protects a document does not need to re-establish any
of that — if it has an ``AnalyzedDocument`` at all, the policy has already been
consulted, nothing in it was blocked, and a right-to-left splice over
``spans`` is provably safe. That is what "ready for the next phase" means here,
and it is a type rather than a status because **nothing about this is
persisted** (ADR-0030). A status column describing state that dies with the
request would be a lie told to whoever polls for it.

**Counts are derived, never stored.** ``counts_by_action`` and
``counts_by_entity_type`` are computed from ``spans`` on each call, for the same
reason a page owns no text in ``extraction/models.py``: a stored summary can
disagree with the thing it summarises, and a derived one cannot. It also means a
summary reported to an operator is necessarily the summary of what will actually
be protected.

An ``AnalyzedDocument`` holds a ``SegmentedDocument``, which holds the extracted
text. It is therefore **Restricted** — never log one, never place one in an
error, and never put a span's text anywhere. Both types report counts from
``__repr__`` for that reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.domain.models import EntityAction

if TYPE_CHECKING:
    from uuid import UUID

    from app.documents.segmentation import SegmentedDocument
    from app.policy.models import PolicySnapshot


@dataclass(frozen=True, slots=True)
class LabeledSpan:
    """One sensitive value found in a document, with the policy's decision.

    ``start`` and ``end`` are **global** offsets into the document's text
    buffer, never offsets within a segment. A span found in two overlapping
    segments is one instance of this type, not two, and ``segments`` records
    every segment it was seen in.

    The span itself is Internal — a type name and a pair of integers disclose
    nothing on their own. The *text* it points at is Restricted, which is why
    reading it requires the buffer and therefore an
    :class:`AnalyzedDocument`.
    """

    entity_type: str
    start: int
    end: int
    score: float
    action: EntityAction
    pages: tuple[int, ...]
    """1-based page numbers this span touches. Ordered, and never empty."""

    segments: tuple[int, ...]
    """Segment indexes this span was detected in. Ordered, and never empty.

    More than one means the span sat in an overlap region and two detections
    collapsed onto it — the deduplication ADR-0029 exists to make possible.
    """

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError("a labeled span must be a non-empty forward range")
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("a labeled span's score must be within [0.0, 1.0]")
        if self.action is EntityAction.BLOCK:
            # A blocked value stops the document; it never becomes a label.
            # Refusing it here means "an AnalyzedDocument exists" implies
            # "nothing in it was blocked" without anyone re-checking.
            raise ValueError("a blocked entity cannot be labeled; the document is refused instead")
        if not self.pages:
            raise ValueError("a labeled span must name at least one page")
        if not self.segments:
            raise ValueError("a labeled span must name at least one segment")

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(frozen=True, slots=True)
class AnalyzedDocument:
    """A segmented document plus every labeled span found in it.

    Restricted, because ``segmented`` carries the extracted text. Never log an
    instance and never serialize one.

    The invariants asserted at construction are the ones the protection phase
    would otherwise have to trust: spans are ordered by offset, no two overlap,
    and every one lies inside the buffer. A splice that walks them in reverse
    therefore cannot corrupt an offset it has not reached yet.
    """

    tenant_id: UUID
    document_id: UUID
    segmented: SegmentedDocument
    spans: tuple[LabeledSpan, ...]
    policy: PolicySnapshot
    """The exact snapshot that produced the actions, not just its version.

    The snapshot rather than the number because the phase that protects a
    document must apply *these* decisions. Policy is cached for 30 seconds and
    an operator can edit it at any moment, so a protector that resolved the
    policy again could get a different one and splice actions the labels never
    agreed to — with both stages individually correct and every count reporting
    success. Carrying the snapshot makes that divergence unrepresentable rather
    than unlikely.
    """

    def __post_init__(self) -> None:
        limit = len(self.segmented.document.text)
        previous_end = 0
        for index, span in enumerate(self.spans):
            if span.start < previous_end:
                # Covers both "out of order" and "overlapping" in one check.
                raise ValueError(f"span {index} overlaps or precedes the span before it")
            if span.end > limit:
                raise ValueError(f"span {index} extends past the end of the document text")
            previous_end = span.end

    @property
    def policy_version(self) -> int:
        """Derived, so it cannot name a version other than the policy's own."""
        return self.policy.version

    @property
    def span_count(self) -> int:
        return len(self.spans)

    @property
    def segment_count(self) -> int:
        return self.segmented.segment_count

    def text_of(self, span: LabeledSpan) -> str:
        """The original value a span covers. Restricted — handle accordingly.

        Derived by slicing the one canonical buffer (ADR-0029), so it cannot
        disagree with the offsets the protection phase will splice at.
        """
        return self.segmented.document.text[span.start : span.end]

    def counts_by_action(self) -> dict[EntityAction, int]:
        """How many spans resolved to each action. Derived, so it cannot drift."""
        counts: dict[EntityAction, int] = {}
        for span in self.spans:
            counts[span.action] = counts.get(span.action, 0) + 1
        return counts

    def counts_by_entity_type(self) -> dict[str, int]:
        """How many spans of each entity type. Type names only, never values."""
        counts: dict[str, int] = {}
        for span in self.spans:
            counts[span.entity_type] = counts.get(span.entity_type, 0) + 1
        return counts

    def __repr__(self) -> str:
        # Defensive: a stray repr() in a traceback must not spill a document.
        return (
            f"AnalyzedDocument(document_id={self.document_id!r}, "
            f"segments={self.segment_count}, spans={self.span_count})"
        )


__all__ = ["AnalyzedDocument", "LabeledSpan"]
