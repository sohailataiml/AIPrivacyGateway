"""What extraction produces.

**One buffer, and every reference is a view into it.** ``ExtractedDocument``
holds the whole extracted text once; a page is a ``(number, start, end)`` range
and owns no text of its own. That is not a memory optimisation — it is what
makes offset drift unrepresentable. A design where a page carried its own copy
of the text would let the copy and the range disagree, and
``docs/document-processing.md`` is explicit about what that costs: "An offset
that drifts by one protects the wrong text."

So the invariant is enforced in the constructor rather than trusted: pages are
ordered, non-overlapping, contiguous, and together cover exactly the whole
buffer. A malformed set of ranges raises rather than being quietly accepted.

Extracted text is **Restricted** data (``docs/data-classification.md``). It is
the original values in bulk, minus the file format. Nothing here is logged,
and both types hide their contents from ``repr`` so a traceback cannot spill a
document into a log line.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.domain.errors import DocumentExtractionError

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


@dataclass(frozen=True, slots=True)
class PageRef:
    """One page, as a half-open range into the document's text buffer.

    ``number`` is 1-based, matching how a reader refers to a page. It is not an
    index into ``pages``: a page that extracted no text still occupies a
    (possibly empty) range, so numbering stays aligned with the source file.
    """

    number: int
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.number < 1:
            raise DocumentExtractionError(log_context={"reason": "page_number_invalid"})
        if self.start < 0 or self.end < self.start:
            raise DocumentExtractionError(log_context={"reason": "page_range_invalid"})

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(frozen=True, slots=True)
class ExtractedDocument:
    """The text of one document, plus where its pages fall within it.

    Restricted. Never log an instance, and never put ``text`` in an error
    message or a metric label.
    """

    text: str
    pages: tuple[PageRef, ...]

    def __post_init__(self) -> None:
        if not self.pages:
            # A document with no pages has no way to answer "where did this
            # come from", which the protection stage needs.
            raise DocumentExtractionError(log_context={"reason": "no_pages"})

        expected = 0
        for index, page in enumerate(self.pages):
            if page.start != expected:
                # Catches both gaps and overlaps in one check: any deviation
                # from "starts exactly where the last one ended" is a break in
                # the offset chain.
                raise DocumentExtractionError(
                    log_context={"reason": "pages_not_contiguous", "page_index": index}
                )
            expected = page.end
        if expected != len(self.text):
            raise DocumentExtractionError(log_context={"reason": "pages_do_not_cover_text"})

    @property
    def character_count(self) -> int:
        return len(self.text)

    @property
    def page_count(self) -> int:
        return len(self.pages)

    def page_text(self, page: PageRef) -> str:
        """The text of one page. Derived, so it cannot disagree with the range."""
        return self.text[page.start : page.end]

    def pages_covering(self, start: int, end: int) -> tuple[int, ...]:
        """Page numbers touched by a half-open span of the buffer.

        Used to answer "which page did this entity come from" without the
        caller doing arithmetic on ranges it does not own.
        """
        if start < 0 or end < start:
            raise DocumentExtractionError(log_context={"reason": "span_invalid"})
        if start == end:
            # An insertion point sits on the page that contains that position,
            # rather than on none of them.
            return tuple(page.number for page in self.pages if page.start <= start < page.end)
        return tuple(page.number for page in self.pages if page.start < end and start < page.end)

    def __repr__(self) -> str:
        # Defensive: a stray repr() in a traceback must not spill the document.
        return f"ExtractedDocument(characters={self.character_count}, pages={self.page_count})"


def build_extracted_document(
    *, page_texts: Sequence[str], separator: str = "\n"
) -> ExtractedDocument:
    """Join per-page text into one buffer and record where each page landed.

    The separator belongs to the page that precedes it, so pages stay
    contiguous and the invariant above holds by construction rather than by
    the caller remembering to account for it.
    """
    if not page_texts:
        raise DocumentExtractionError(log_context={"reason": "no_pages"})

    parts: list[str] = []
    pages: list[PageRef] = []
    cursor = 0
    last = len(page_texts) - 1

    for index, page_text in enumerate(page_texts):
        piece = page_text if index == last else page_text + separator
        parts.append(piece)
        pages.append(PageRef(number=index + 1, start=cursor, end=cursor + len(piece)))
        cursor += len(piece)

    return ExtractedDocument(text="".join(parts), pages=tuple(pages))


def total_characters(page_texts: Iterable[str]) -> int:
    """Character count without building the joined buffer.

    Lets a size limit be enforced before allocating the whole document.
    """
    return sum(len(page_text) for page_text in page_texts)


__all__ = [
    "ExtractedDocument",
    "PageRef",
    "build_extracted_document",
    "total_characters",
]
