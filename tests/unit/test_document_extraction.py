"""Extraction: what comes out, and what is refused.

Two halves. The first asserts that the offset chain holds by construction --
``ExtractedDocument`` cannot be built with pages that gap, overlap, or fail to
cover the buffer, so an offset bug becomes a constructor error rather than a
span protecting the wrong text.

The second is about refusing things. Phase 1 checked eight magic bytes and
stored whatever followed, so this is the first stage that actually parses
attacker-supplied files. Every entry in ``TestHostileFiles`` is a file that
parses to nothing useful and must fail closed rather than crash, hang, or
quietly return garbage.
"""

from __future__ import annotations

import pytest

from app.documents.extraction.extractors import (
    MAX_ZIP_ENTRIES,
    extract_docx,
    extract_pdf,
    extract_text,
    extract_txt,
    silence_parser_logging,
)
from app.documents.extraction.models import (
    ExtractedDocument,
    PageRef,
    build_extracted_document,
)
from app.documents.models import CONTENT_TYPE_DOCX, CONTENT_TYPE_PDF, CONTENT_TYPE_TXT
from app.domain.errors import DocumentExtractionError
from tests.fixtures.document_files import (
    HEADER_ONLY_PDF,
    NOT_A_ZIP_DOCX,
    TRUNCATED_PDF,
    make_docx,
    make_encrypted_pdf,
    make_pdf,
    make_zip_bomb,
    make_zip_with_many_entries,
)
from tests.fixtures.documents import CANARIES

LIMIT = 1_000_000


# ---------------------------------------------------------------------------
# The offset chain
# ---------------------------------------------------------------------------
class TestExtractedDocument:
    def test_pages_are_views_into_one_buffer(self) -> None:
        extracted = build_extracted_document(page_texts=["alpha", "beta", "gamma"])

        assert extracted.text == "alpha\nbeta\ngamma"
        assert [extracted.page_text(page) for page in extracted.pages] == [
            "alpha\n",
            "beta\n",
            "gamma",
        ]
        assert extracted.page_count == 3
        assert extracted.character_count == len(extracted.text)

    def test_page_numbers_are_one_based(self) -> None:
        extracted = build_extracted_document(page_texts=["a", "b"])

        assert [page.number for page in extracted.pages] == [1, 2]

    def test_a_page_that_extracted_nothing_still_occupies_its_number(self) -> None:
        # A PDF page holding only an image yields no text. Dropping it would
        # renumber every page after it, so a citation of "page 7" would point
        # at page 6 of the original.
        extracted = build_extracted_document(page_texts=["a", "", "c"])

        assert [page.number for page in extracted.pages] == [1, 2, 3]
        assert extracted.page_text(extracted.pages[1]) == "\n"

    @pytest.mark.parametrize(
        ("pages", "reason"),
        [
            ((PageRef(number=1, start=0, end=3),), "pages_do_not_cover_text"),
            (
                (PageRef(number=1, start=0, end=2), PageRef(number=2, start=3, end=5)),
                "pages_not_contiguous",
            ),
            (
                (PageRef(number=1, start=0, end=4), PageRef(number=2, start=2, end=5)),
                "pages_not_contiguous",
            ),
            ((), "no_pages"),
        ],
        ids=["short-coverage", "gap", "overlap", "empty"],
    )
    def test_a_broken_offset_chain_cannot_be_constructed(
        self, pages: tuple[PageRef, ...], reason: str
    ) -> None:
        # The invariant is enforced, not documented. A gap or an overlap in the
        # page ranges is exactly the drift that makes a protected span cover
        # the wrong characters.
        with pytest.raises(DocumentExtractionError) as caught:
            ExtractedDocument(text="hello", pages=pages)

        assert caught.value.log_context["reason"] == reason

    @pytest.mark.parametrize(
        ("number", "start", "end"),
        [(0, 0, 1), (-1, 0, 1), (1, -1, 1), (1, 5, 4)],
    )
    def test_a_malformed_page_reference_is_refused(self, number: int, start: int, end: int) -> None:
        with pytest.raises(DocumentExtractionError):
            PageRef(number=number, start=start, end=end)

    def test_pages_covering_reports_every_page_a_span_touches(self) -> None:
        extracted = build_extracted_document(page_texts=["a" * 10, "b" * 10, "c" * 10])

        assert extracted.pages_covering(0, 5) == (1,)
        assert extracted.pages_covering(5, 15) == (1, 2)
        assert extracted.pages_covering(0, extracted.character_count) == (1, 2, 3)

    def test_pages_covering_places_an_insertion_point_on_one_page(self) -> None:
        extracted = build_extracted_document(page_texts=["a" * 10, "b" * 10])

        assert extracted.pages_covering(3, 3) == (1,)
        assert extracted.pages_covering(15, 15) == (2,)

    def test_pages_covering_refuses_a_backwards_span(self) -> None:
        extracted = build_extracted_document(page_texts=["abc"])

        with pytest.raises(DocumentExtractionError):
            extracted.pages_covering(3, 1)

    def test_the_repr_hides_the_document(self) -> None:
        extracted = build_extracted_document(page_texts=[CANARIES["person_name"]])

        assert CANARIES["person_name"] not in repr(extracted)
        assert "characters=" in repr(extracted)


# ---------------------------------------------------------------------------
# The three supported types
# ---------------------------------------------------------------------------
class TestPlainText:
    def test_extracts_a_utf8_file_as_one_page(self) -> None:
        body = f"{CANARIES['person_name']}\n{CANARIES['email']}\n".encode()

        pages = extract_txt(body, LIMIT)

        assert pages == [body.decode("utf-8")]

    def test_refuses_a_file_that_is_not_utf8(self) -> None:
        # Decoding with replacement would corrupt the very characters detection
        # is about to run over, and a mangled identifier is one no recognizer
        # matches -- a fail-open outcome dressed as resilience.
        with pytest.raises(DocumentExtractionError) as caught:
            extract_txt(b"\xff\xfe\x00valid ascii after", LIMIT)

        assert caught.value.log_context["reason"] == "text_not_utf8"

    def test_refuses_a_file_over_the_character_limit(self) -> None:
        with pytest.raises(DocumentExtractionError) as caught:
            extract_txt(b"x" * 100, 50)

        assert caught.value.log_context["reason"] == "extracted_text_over_limit"


class TestPdf:
    def test_extracts_one_entry_per_page(self) -> None:
        data = make_pdf(["first page", "second page", "third page"])

        pages = extract_pdf(data, LIMIT)

        assert len(pages) == 3
        assert "first page" in pages[0]
        assert "third page" in pages[2]

    def test_page_structure_survives_into_the_document(self) -> None:
        # Page references are the only source reference a PDF offers, and
        # docs/document-processing.md requires them to survive extraction.
        data = make_pdf([CANARIES["person_name"], CANARIES["mrn"]])

        extracted = build_extracted_document(page_texts=extract_pdf(data, LIMIT))

        assert extracted.page_count == 2
        found = extracted.text.index(CANARIES["mrn"])
        assert extracted.pages_covering(found, found + len(CANARIES["mrn"])) == (2,)

    def test_a_long_document_over_the_limit_is_refused(self) -> None:
        data = make_pdf(["padding " * 200] * 5)

        with pytest.raises(DocumentExtractionError) as caught:
            extract_pdf(data, 100)

        assert caught.value.log_context["reason"] == "extracted_text_over_limit"


class TestDocx:
    def test_extracts_paragraphs_in_order(self) -> None:
        data = make_docx(["first", "second", "third"])

        pages = extract_docx(data, LIMIT)

        assert pages[0].splitlines() == ["first", "second", "third"]

    def test_extracts_table_cells(self) -> None:
        # Forms put names and identifiers in tables. An extractor that walked
        # only paragraphs would miss them, and the miss would look like an
        # extraction detail rather than the detection gap it is.
        data = make_docx(
            ["Patient record"],
            table=[["Name", "MRN"], [CANARIES["person_name"], CANARIES["mrn"]]],
        )

        text = extract_docx(data, LIMIT)[0]

        assert CANARIES["person_name"] in text
        assert CANARIES["mrn"] in text

    def test_adjacent_cells_do_not_run_together(self) -> None:
        # `Jane` and `Doe` in neighbouring cells must not become `JaneDoe`,
        # which no recognizer would match.
        data = make_docx([], table=[["Jane", "Doe"]])

        text = extract_docx(data, LIMIT)[0]

        assert "JaneDoe" not in text
        assert "Jane\tDoe" in text

    def test_reports_a_single_page(self) -> None:
        # A DOCX stores no pagination -- that is a rendering decision made by
        # the reader. Inventing page numbers would put fabricated references
        # into an audit trail.
        data = make_docx(["a", "b", "c"])

        assert len(extract_docx(data, LIMIT)) == 1


# ---------------------------------------------------------------------------
# Files that must be refused
# ---------------------------------------------------------------------------
class TestHostileFiles:
    @pytest.mark.parametrize(
        ("data", "content_type", "reason"),
        [
            (TRUNCATED_PDF, CONTENT_TYPE_PDF, "pdf_unreadable"),
            (HEADER_ONLY_PDF, CONTENT_TYPE_PDF, "pdf_unreadable"),
            (b"%PDF-1.7\n" + b"\x00" * 400, CONTENT_TYPE_PDF, "pdf_unreadable"),
            (NOT_A_ZIP_DOCX, CONTENT_TYPE_DOCX, "docx_not_a_zip"),
            (b"\xff\xfe\x00\x01", CONTENT_TYPE_TXT, "text_not_utf8"),
        ],
        ids=["truncated-pdf", "header-only-pdf", "pdf-of-nulls", "docx-not-zip", "txt-binary"],
    )
    def test_a_file_that_passed_phase_one_can_still_be_refused(
        self, data: bytes, content_type: str, reason: str
    ) -> None:
        # Every one of these has valid magic bytes and is stored happily by
        # Phase 1. Extraction is where the claim is actually checked.
        with pytest.raises(DocumentExtractionError) as caught:
            extract_text(data=data, content_type=content_type, max_characters=LIMIT)

        assert caught.value.log_context["reason"] == reason

    def test_an_encrypted_pdf_is_refused_rather_than_unlocked(self) -> None:
        # pypdf offers an empty-password unlock. Taking it would mean silently
        # processing a document whose author chose to restrict it.
        with pytest.raises(DocumentExtractionError) as caught:
            extract_pdf(make_encrypted_pdf(), LIMIT)

        assert caught.value.log_context["reason"] == "pdf_encrypted"

    def test_a_decompression_bomb_is_refused_before_it_expands(self) -> None:
        # A few kilobytes declaring hundreds of megabytes. The guard reads the
        # central directory, which expands nothing, so the refusal costs a
        # directory read rather than the memory the bomb is asking for.
        bomb = make_zip_bomb(entries=4, uncompressed_mib=64)
        assert len(bomb) < 1_000_000, "the fixture should be small on disk"

        with pytest.raises(DocumentExtractionError) as caught:
            extract_docx(bomb, LIMIT)

        assert caught.value.log_context["reason"] == "docx_expansion_ratio_exceeded"

    def test_an_archive_with_absurdly_many_members_is_refused(self) -> None:
        with pytest.raises(DocumentExtractionError) as caught:
            extract_docx(make_zip_with_many_entries(MAX_ZIP_ENTRIES + 1), LIMIT)

        assert caught.value.log_context["reason"] == "docx_too_many_entries"

    def test_a_valid_zip_that_is_not_a_docx_is_refused(self) -> None:
        with pytest.raises(DocumentExtractionError) as caught:
            extract_docx(make_zip_with_many_entries(3), LIMIT)

        assert caught.value.log_context["reason"] == "docx_unreadable"

    def test_an_unextractable_content_type_is_refused(self) -> None:
        with pytest.raises(DocumentExtractionError) as caught:
            extract_text(data=b"x", content_type="image/png", max_characters=LIMIT)

        assert caught.value.log_context["reason"] == "content_type_not_extractable"

    def test_no_refusal_quotes_the_file(self) -> None:
        # The reason code is the diagnosis. Echoing bytes back would describe
        # the document to whoever supplied it, and put it in a log line.
        for data, content_type in (
            (TRUNCATED_PDF, CONTENT_TYPE_PDF),
            (NOT_A_ZIP_DOCX, CONTENT_TYPE_DOCX),
        ):
            with pytest.raises(DocumentExtractionError) as caught:
                extract_text(data=data, content_type=content_type, max_characters=LIMIT)
            rendered = f"{caught.value.public_message} {caught.value.log_context}"
            assert "PDF" not in rendered
            assert "PK" not in rendered


# ---------------------------------------------------------------------------
# Third-party logging
# ---------------------------------------------------------------------------
class TestParserLogging:
    def test_the_parser_log_floor_is_raised(self) -> None:
        # The third time this project has met this leak class: presidio logged
        # match context at DEBUG, the OpenAI SDK logged request bodies, and
        # pypdf quotes object contents in its structural warnings.
        import logging

        logging.getLogger("pypdf").setLevel(logging.NOTSET)

        silence_parser_logging()

        assert logging.getLogger("pypdf").level >= logging.INFO

    def test_a_stricter_setting_is_left_alone(self) -> None:
        import logging

        logging.getLogger("pypdf").setLevel(logging.ERROR)

        silence_parser_logging()

        assert logging.getLogger("pypdf").level == logging.ERROR

    def test_extracting_a_broken_pdf_emits_no_document_bytes(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        caplog.set_level(logging.DEBUG)
        data = make_pdf([CANARIES["person_name"]])[:120]

        with pytest.raises(DocumentExtractionError):
            extract_pdf(data, LIMIT)

        emitted = "\n".join(
            record.getMessage() + repr(record.__dict__) for record in caplog.records
        )
        for canary in CANARIES.values():
            assert canary not in emitted
