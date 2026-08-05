# ADR-0029: Represent Extracted Documents as One Buffer with Page-Range Offsets

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

[document-processing.md](../document-processing.md) states the requirement and
the cost of getting it wrong: global offsets and page references must survive
extraction and segmentation, because "a detected span must map back to the exact
bytes it came from. An offset that drifts by one protects the wrong text."

That is not a rounding error. Detection returns spans as Python string indices
into the exact text it was handed (`DetectedEntity.start`, `.end`). If the
mapping from a segment offset back to a document offset is wrong by one, the
protection stage replaces the wrong characters — leaving part of the original
value in the outbound payload while reporting that the entity was protected. A
fail-open outcome that every count and every audit record calls a success.

The obvious design is for each page to carry its own text and for segments to
carry copies of theirs. That design permits the copy and the offset to disagree,
and nothing detects the disagreement until a span lands in the wrong place.

## Decision

An extracted document is **one canonical text buffer**. Everything that refers
to part of it is a range into that buffer and owns no text of its own:

- `ExtractedDocument.text` is the single authoritative string.
- A page is `PageRef(number, start, end)` — a half-open range. `page_text()`
  is derived by slicing, never stored.
- Pages are **ordered, non-overlapping, contiguous, and cover the buffer
  exactly**. Any gap or overlap is invalid and is refused at construction.
- A `Segment` is likewise `(index, start, end, pages)` with **global** offsets,
  and `SegmentedDocument.text_of()` derives its text from the same buffer.

`Segment.to_global(offset)` is the one place segment-local arithmetic is
written, so the mapping exists once rather than at every call site.

## Consequences

### Positive

- Offset drift is unrepresentable rather than merely tested for. A page's text
  cannot disagree with its range, because there is no second copy to disagree.
- The invariant is enforced in `__post_init__`, so a construction error is
  raised where the mistake is, not where the wrong span eventually lands.
- Segments carry global offsets, which is what lets the same entity found in two
  overlapping segments be recognised as one entity in Phase 3 rather than
  protected twice or, worse, protected inconsistently.
- Page references survive to the segment level, so a protected span can be
  traced to the page it came from without the caller doing range arithmetic.
- Memory is bounded: one buffer plus ranges, rather than a copy per page.

### Negative

- Every consumer needs the document alongside a segment to read its text.
  `SegmentedDocument` carries both, which makes the pair the unit that gets
  passed around rather than a bare list of strings.
- Pages that extract no text still occupy a range, so page-empty documents look
  slightly odd — a deliberate trade, see below.

## Alternatives Considered

- **Each page carries its own text.** The intuitive design, and it permits the
  text and the offset to diverge. Rejected.
- **Segments carry copies of their text.** Convenient for a detector that wants
  a plain string, and reintroduces exactly the divergence this ADR removes.
  Rejected; `text_of()` costs one slice.
- **Byte offsets rather than character offsets.** Detection reports Python
  string indices, so byte offsets would require a conversion at every boundary —
  a second place for an off-by-one to live. Rejected.
- **Drop pages that extracted no text.** Tidier output, and it renumbers every
  page after the empty one, so a citation of "page 7" points at page 6 of the
  original. Rejected.

## Implementation Constraints

- `build_extracted_document` assembles the buffer and the ranges together, so
  the invariant holds by construction rather than by each caller remembering to
  account for the separator. The page separator belongs to the page that
  precedes it.
- Page numbers are 1-based and track the source file, not the index in the
  `pages` tuple.
- `ExtractedDocument` and `SegmentedDocument` have a `__repr__` that reports
  counts and never content: extracted text is Restricted, and a stray `repr()`
  in a traceback must not spill a document into a log line.
- A document that extracted to zero characters is refused with
  `no_extractable_text` rather than producing zero segments. A scanned PDF with
  no text layer is a real case, and returning nothing would look like success
  and send an empty prompt onward.

## As Built (Phase 2)

`app/documents/extraction/models.py` and `app/documents/segmentation.py`.

The invariant has its own tests in
`tests/unit/test_document_extraction.py::TestExtractedDocument`, which assert
that a gap, an overlap, short coverage, and an empty page tuple are each
unconstructable. `tests/unit/test_document_segmentation.py` asserts the
segment-level properties with Hypothesis, because "offsets are preserved" is a
universal claim and a handful of examples would confirm only the cases someone
thought of.
