"""Turning bytes into text, one supported type at a time.

Every function here is **pure, top-level, and picklable**, because these are the
functions that run inside the isolation subprocess (ADR-0028). A closure or a
bound method could not cross that boundary; a module-level function taking bytes
and returning plain data can.

**These parse hostile input.** A stored document arrived from a caller, and
Phase 1 only checked its first eight bytes -- a valid header over deliberate
nonsense is stored, because deciding whether a PDF really parses means parsing
it, which is this module's job. So the guards here come before the parser, not
after it:

* the extracted character count is bounded, checked while accumulating rather
  than once at the end, so a file that expands without limit is stopped part-way
  instead of after it has already been allocated;
* a DOCX is a ZIP, and its declared uncompressed size is checked against a
  ratio *before* anything is decompressed -- the classic decompression bomb is a
  few kilobytes that expand to gigabytes;
* an encrypted PDF is refused rather than guessed at.

Nothing here logs. Extracted text is Restricted, and the cheapest way to
guarantee it is never logged is to have no logging statements at all -- the same
rule ``app/documents/validation.py`` follows.
"""

from __future__ import annotations

import io
import logging
import zipfile
from typing import TYPE_CHECKING, Final

from app.documents.models import CONTENT_TYPE_DOCX, CONTENT_TYPE_PDF, CONTENT_TYPE_TXT
from app.domain.errors import DocumentExtractionError

if TYPE_CHECKING:
    from collections.abc import Callable

PARSER_LOGGER_NAMES: Final[tuple[str, ...]] = ("pypdf", "docx", "lxml")
MIN_PARSER_LOG_LEVEL: Final[int] = logging.INFO


def silence_parser_logging() -> None:
    """Stop the parsers from emitting the document they are parsing.

    The third recurrence of a leak class this project has already been bitten by
    twice: ``presidio-analyzer`` logged the context around each match at DEBUG,
    and the OpenAI SDK logged full request bodies. Both were fixed the same way.

    pypdf logs structural complaints at DEBUG and WARNING while walking a file
    -- and those messages quote object contents. An operator raising LOG_LEVEL
    to DEBUG to diagnose something unrelated should not thereby start writing
    fragments of Restricted documents to stdout.

    Raising the floor to ``INFO`` leaves genuine warnings visible. Loggers
    already at ``INFO`` or stricter are left alone. Mirrors
    :func:`app.detection.analyzer.silence_analyzer_logging` and
    :func:`app.llm.base.silence_transport_logging`.
    """
    for name in PARSER_LOGGER_NAMES:
        logger = logging.getLogger(name)
        if logger.level == logging.NOTSET or logger.level < MIN_PARSER_LOG_LEVEL:
            logger.setLevel(MIN_PARSER_LOG_LEVEL)


MAX_ZIP_EXPANSION_RATIO: Final = 200
"""Uncompressed-to-compressed ratio a DOCX may not exceed.

An ordinary DOCX compresses its XML around 5-20x. 200x leaves generous headroom
for a legitimately text-heavy document while refusing the shapes that only a
bomb has -- a 10 KB archive claiming 4 GB is a ratio of 400,000.
"""

MAX_ZIP_ENTRIES: Final = 2_048
"""A DOCX with more members than this is not a document anyone authored."""

PDF_PAGE_SEPARATOR: Final = "\n"
DOCX_PARAGRAPH_SEPARATOR: Final = "\n"


def extract_text(*, data: bytes, content_type: str, max_characters: int) -> list[str]:
    """Extract one document into per-page text.

    Returns a list rather than an ``ExtractedDocument`` because this runs in a
    subprocess: plain builtins cross that boundary without the child needing to
    import a dataclass, and the parent assembles the real type where the
    invariants are enforced.

    Raises:
        DocumentExtractionError: unsupported type, unparseable file, or output
            over ``max_characters``.
    """
    # Applied here rather than only at startup, because this also runs inside a
    # freshly spawned subprocess whose interpreter has none of the parent's
    # logging configuration.
    silence_parser_logging()

    extractor = _EXTRACTORS.get(content_type)
    if extractor is None:
        raise DocumentExtractionError(log_context={"reason": "content_type_not_extractable"})
    if max_characters <= 0:
        raise DocumentExtractionError(log_context={"reason": "character_limit_invalid"})
    return extractor(data, max_characters)


# ---------------------------------------------------------------------------
# Plain text
# ---------------------------------------------------------------------------
def extract_txt(data: bytes, max_characters: int) -> list[str]:
    """Decode a text file. One page, because a text file has no pages.

    Strict decoding: a file that is not valid UTF-8 is refused rather than
    decoded with replacement characters. Replacement would silently corrupt the
    very bytes detection is about to run over, and a mangled identifier is one
    the detector cannot recognise -- a fail-open outcome.
    """
    _guard_length(len(data), max_characters)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise DocumentExtractionError(log_context={"reason": "text_not_utf8"}) from None
    _guard_length(len(text), max_characters)
    return [text]


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
def extract_pdf(data: bytes, max_characters: int) -> list[str]:
    """Extract per-page text from a PDF.

    Page structure is preserved because it is the only source reference a PDF
    offers, and ``docs/document-processing.md`` requires page references to
    survive extraction.
    """
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError

    try:
        reader = PdfReader(io.BytesIO(data))
    except PdfReadError:
        raise DocumentExtractionError(log_context={"reason": "pdf_unreadable"}) from None
    except Exception:
        # pypdf raises a wide range of types on malformed input, including bare
        # ValueError and KeyError from deep inside its object model. Anything
        # that is not a clean parse is the same answer to the caller.
        raise DocumentExtractionError(log_context={"reason": "pdf_malformed"}) from None

    if reader.is_encrypted:
        # Refuse rather than attempt the empty-password unlock pypdf offers.
        # Succeeding would mean silently processing a document whose author
        # chose to restrict it.
        raise DocumentExtractionError(log_context={"reason": "pdf_encrypted"})

    pages: list[str] = []
    running = 0
    for page in reader.pages:
        try:
            text = page.extract_text() or ""
        except Exception:
            raise DocumentExtractionError(
                log_context={"reason": "pdf_page_unreadable", "page": len(pages) + 1}
            ) from None
        running += len(text)
        _guard_length(running, max_characters)
        pages.append(text)

    if not pages:
        raise DocumentExtractionError(log_context={"reason": "pdf_no_pages"})
    return pages


# ---------------------------------------------------------------------------
# DOCX
# ---------------------------------------------------------------------------
def extract_docx(data: bytes, max_characters: int) -> list[str]:
    """Extract text from a DOCX. One page, because a DOCX has none.

    Pagination in a Word document is a rendering decision made by the reader,
    not a property stored in the file, so there is no honest way to report page
    numbers without laying the document out. Reporting a single page is the
    truthful answer; inventing page breaks would put fabricated references into
    an audit trail.

    Paragraphs and table cells are both collected, in document order. Tables are
    where forms put names and identifiers, so skipping them would be a
    detection gap disguised as an extraction detail.
    """
    _guard_zip(data)

    from docx import Document as DocxDocument
    from docx.table import Table
    from docx.text.paragraph import Paragraph

    try:
        document = DocxDocument(io.BytesIO(data))
    except Exception:
        raise DocumentExtractionError(log_context={"reason": "docx_unreadable"}) from None

    blocks: list[str] = []
    running = 0
    try:
        for child in document.element.body.iterchildren():
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "p":
                text = Paragraph(child, document).text
            elif tag == "tbl":
                text = _table_text(Table(child, document))
            else:
                continue
            if not text:
                continue
            running += len(text) + len(DOCX_PARAGRAPH_SEPARATOR)
            _guard_length(running, max_characters)
            blocks.append(text)
    except DocumentExtractionError:
        raise
    except Exception:
        raise DocumentExtractionError(log_context={"reason": "docx_malformed"}) from None

    return [DOCX_PARAGRAPH_SEPARATOR.join(blocks)]


def _table_text(table: object) -> str:
    """Flatten a table to text, row by row.

    Cells are tab-separated and rows newline-separated so that adjacent cells do
    not run together into a single word -- `Jane` and `Doe` in neighbouring
    cells must not become `JaneDoe`, which no recognizer would match.
    """
    rows: list[str] = []
    for row in table.rows:  # type: ignore[attr-defined]
        cells = [cell.text.strip() for cell in row.cells]
        if any(cells):
            rows.append("\t".join(cells))
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------
def _guard_length(count: int, limit: int) -> None:
    if count > limit:
        raise DocumentExtractionError(
            log_context={"reason": "extracted_text_over_limit", "limit": limit}
        )


def _guard_zip(data: bytes) -> None:
    """Refuse a DOCX whose archive is shaped like a bomb, before decompressing.

    The sizes come from the central directory, which is metadata: reading them
    costs nothing and expands nothing. A file that lies about them fails later
    in the parser anyway, and a file that tells the truth about being enormous
    is refused here for the cost of a directory read.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ZIP_ENTRIES:
                raise DocumentExtractionError(log_context={"reason": "docx_too_many_entries"})
            uncompressed = sum(entry.file_size for entry in entries)
            compressed = sum(entry.compress_size for entry in entries)
    except DocumentExtractionError:
        raise
    except zipfile.BadZipFile:
        raise DocumentExtractionError(log_context={"reason": "docx_not_a_zip"}) from None

    if compressed > 0 and uncompressed / compressed > MAX_ZIP_EXPANSION_RATIO:
        raise DocumentExtractionError(
            log_context={
                "reason": "docx_expansion_ratio_exceeded",
                "ratio": round(uncompressed / compressed),
            }
        )


_EXTRACTORS: Final[dict[str, Callable[[bytes, int], list[str]]]] = {
    CONTENT_TYPE_TXT: extract_txt,
    CONTENT_TYPE_PDF: extract_pdf,
    CONTENT_TYPE_DOCX: extract_docx,
}

EXTRACTABLE_CONTENT_TYPES: Final = frozenset(_EXTRACTORS)


__all__ = [
    "EXTRACTABLE_CONTENT_TYPES",
    "MAX_ZIP_ENTRIES",
    "MAX_ZIP_EXPANSION_RATIO",
    "extract_docx",
    "extract_pdf",
    "extract_text",
    "extract_txt",
]
