"""Cutting an extracted document into pieces a detector can handle.

Segmentation exists because documents exceed model context windows and because
detection quality degrades on very long inputs. It is also the stage most able
to cause a silent leak, and ``docs/document-processing.md`` names the failure
directly: "Segments must not split entities across boundaries in a way that
hides them from the detector -- a boundary falling mid-value is a fail-open
condition."

Two mechanisms answer that, and both are needed.

**Break at whitespace.** A boundary is searched backwards from the size limit
for a paragraph break, then a line break, then a sentence end, then any
whitespace. So a boundary never lands inside `jane.doe@example.com` or
`451-88-7396`, which have no internal whitespace and would otherwise be cut into
two halves that no recognizer matches.

**Overlap.** Whitespace breaks are not enough on their own, because plenty of
entities *contain* whitespace -- `Marguerite Okonkwo-Vasquez` splits cleanly at a
space into two fragments, neither of which is a person's full name. Consecutive
segments therefore overlap, so any entity shorter than the overlap appears whole
in at least one segment.

Overlap means the same entity can be detected twice, at two different segment
offsets. That is deliberate and it is the safe direction: every segment carries
its **global** offsets, so duplicates collapse on identity later, whereas a
missed entity is unrecoverable.

**One buffer, still.** A segment is a range, not a copy. Same reasoning as
``extraction/models.py``: two copies of the text can disagree, and a range
cannot disagree with the buffer it indexes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from app.domain.errors import DocumentExtractionError

if TYPE_CHECKING:
    from app.documents.extraction.models import ExtractedDocument

DEFAULT_MAX_CHARACTERS: Final = 12_000
"""Segment ceiling. Comfortably inside every current model's context window,
and short enough that detection accuracy does not degrade with length."""

DEFAULT_OVERLAP_CHARACTERS: Final = 256
"""How much of the previous segment each segment repeats.

Sized against the longest thing a recognizer needs to see whole -- a full
postal address or a long personal name with titles, not a paragraph. Raising it
costs duplicate detection work; lowering it risks a name straddling a boundary
and being seen only in fragments.
"""

_BOUNDARY_SEARCH_FRACTION: Final = 0.25
"""How far back from the limit a break may be sought, as a fraction of the
segment size. Beyond this the segments become too uneven to be worth it, and the
hard cut is taken instead."""

# Ordered by preference: a paragraph break is a better place to divide a
# document than a space in the middle of a sentence.
_BREAK_PATTERNS: Final = ("\n\n", "\n", ". ", " ")


@dataclass(frozen=True, slots=True)
class Segment:
    """One piece of a document, as a half-open range into its text buffer.

    ``start`` and ``end`` are **global** offsets into
    ``ExtractedDocument.text``, not offsets within the segment. That is what
    lets a detection made against one segment be mapped back to the document,
    and what lets the same entity found in two overlapping segments be
    recognised as one entity.
    """

    index: int
    start: int
    end: int
    pages: tuple[int, ...]

    def __post_init__(self) -> None:
        if self.index < 0:
            raise DocumentExtractionError(log_context={"reason": "segment_index_invalid"})
        if self.start < 0 or self.end <= self.start:
            raise DocumentExtractionError(log_context={"reason": "segment_range_invalid"})

    @property
    def length(self) -> int:
        return self.end - self.start

    def to_global(self, offset: int) -> int:
        """Map an offset within this segment's text to a document offset.

        The one piece of arithmetic every caller would otherwise write for
        itself, which is how an off-by-one gets into three places at once.
        """
        if offset < 0 or offset > self.length:
            raise DocumentExtractionError(log_context={"reason": "offset_out_of_segment"})
        return self.start + offset


@dataclass(frozen=True, slots=True)
class SegmentedDocument:
    """An extracted document and the segments cut from it.

    Restricted, because it holds the document. Never log one.
    """

    document: ExtractedDocument
    segments: tuple[Segment, ...]

    def text_of(self, segment: Segment) -> str:
        """The text of one segment. Derived, so it cannot drift."""
        return self.document.text[segment.start : segment.end]

    @property
    def segment_count(self) -> int:
        return len(self.segments)

    def __repr__(self) -> str:
        return f"SegmentedDocument(segments={self.segment_count})"


class Segmenter:
    """Cuts a document into overlapping, whitespace-aligned segments."""

    __slots__ = ("_max_characters", "_overlap")

    def __init__(
        self,
        *,
        max_characters: int = DEFAULT_MAX_CHARACTERS,
        overlap_characters: int = DEFAULT_OVERLAP_CHARACTERS,
    ) -> None:
        if max_characters < 1:
            raise ValueError("max_characters must be at least 1")
        if overlap_characters < 0:
            raise ValueError("overlap_characters cannot be negative")
        if overlap_characters >= max_characters:
            # An overlap at or above the segment size means each segment
            # repeats all of the last one, and the loop makes no progress.
            raise ValueError("overlap_characters must be smaller than max_characters")
        self._max_characters = max_characters
        self._overlap = overlap_characters

    def segment(self, document: ExtractedDocument) -> SegmentedDocument:
        """Cut ``document`` into ordered, overlapping segments.

        Guarantees, all asserted in ``tests/unit/test_document_segmentation.py``:
        every character appears in at least one segment; segments are ordered
        and each begins after the last one did; and no segment is empty.

        Raises:
            DocumentExtractionError: the document holds no text to segment.
        """
        text = document.text
        if not text:
            # A PDF of scanned images extracts to nothing. Returning zero
            # segments would look like success and send an empty prompt
            # onward; saying so is the honest answer.
            raise DocumentExtractionError(log_context={"reason": "no_extractable_text"})

        segments: list[Segment] = []
        start = 0
        previous_end = 0
        length = len(text)

        while start < length:
            end = self._end_of_segment(text, start, length, minimum_end=previous_end)
            segments.append(
                Segment(
                    index=len(segments),
                    start=start,
                    end=end,
                    pages=document.pages_covering(start, end),
                )
            )
            if end >= length:
                break
            # Step back by the overlap, but never far enough to stall: the
            # next segment must start strictly after this one did.
            start = max(end - self._overlap, start + 1)
            previous_end = end

        return SegmentedDocument(document=document, segments=tuple(segments))

    # -- Internals --------------------------------------------------------
    def _end_of_segment(self, text: str, start: int, length: int, *, minimum_end: int) -> int:
        """Where this segment ends: at a break if there is a usable one.

        ``minimum_end`` is the previous segment's end. A candidate at or before
        it would produce a segment wholly contained in the last one -- no new
        characters covered, so no progress in the only sense that matters. On
        adversarial input (a break every few characters, with an overlap close
        to the segment size) that turns into a long run of near-identical
        segments and a pile of duplicate detection work. Hypothesis found it
        with ``text='0000000 00', max_characters=8, overlap=7``.

        Falling back to ``limit`` is always safe: ``limit`` is
        ``start + max_characters``, ``start`` is at least
        ``minimum_end - overlap``, and ``overlap < max_characters``, so
        ``limit`` is strictly greater than ``minimum_end``.
        """
        limit = start + self._max_characters
        if limit >= length:
            return length

        floor = start + max(1, int(self._max_characters * (1 - _BOUNDARY_SEARCH_FRACTION)))
        for pattern in _BREAK_PATTERNS:
            found = text.rfind(pattern, floor, limit)
            if found == -1:
                continue
            # Cut *after* the break, so the whitespace stays with the segment
            # that precedes it and no segment begins mid-gap.
            candidate = found + len(pattern)
            if candidate > minimum_end:
                return candidate
            # This pattern's last occurrence is inside the previous segment.
            # A less-preferred break may still fall later, so keep looking
            # rather than giving up on breaking cleanly.

        # No usable break in the window: a long run of non-whitespace, such as
        # an embedded base64 blob. It has to be cut somewhere, and the overlap
        # is what keeps anything straddling the cut recoverable.
        return limit


__all__ = [
    "DEFAULT_MAX_CHARACTERS",
    "DEFAULT_OVERLAP_CHARACTERS",
    "Segment",
    "SegmentedDocument",
    "Segmenter",
]
