"""The full boundary-validation matrix.

``tests/unit/test_documents.py`` covers the representative cases. This file is
the exhaustive one, and it exists because validation is where a control most
easily reads as protective while failing open -- the shape of two defects
already found in this project, including one in this very module: ``verify_magic``
once accepted a PDF body under a ``.txt`` name, because plain text has no
signature and a PDF header is valid ASCII.

Three claims are tested to destruction:

* a type is believed only when the extension, the declared MIME type, and the
  file's own first bytes all agree;
* a filename is *rejected* when it is unsafe, never quietly rewritten into
  something the caller did not ask for and would not recognise;
* a filename that legitimately contains a person's name or a diagnosis is
  accepted, encrypted, and never logged -- rejecting it would be the wrong fix
  for the right worry.

Where Phase 1 deliberately stops is stated in the tests themselves. Magic bytes
are a header check, not a parse: a well-formed header followed by nonsense is
stored, because parsing a document is extraction, and extraction is Phase 2.
Pretending otherwise here would be the same failure mode as the bug above.
"""

from __future__ import annotations

import pytest

from app.documents.models import CONTENT_TYPE_DOCX, CONTENT_TYPE_PDF, CONTENT_TYPE_TXT
from app.documents.validation import (
    MAX_FILENAME_CHARS,
    enforce_declared_length,
    enforce_streamed_length,
    normalize_filename,
    resolve_content_type,
    verify_magic,
)
from app.domain.errors import (
    DocumentInvalidError,
    DocumentTooLargeError,
    DocumentTypeUnsupportedError,
)
from tests.fixtures.documents import CANARIES

PDF_HEAD = b"%PDF-1.7"
DOCX_HEAD = b"PK\x03\x04\x14\x00\x00\x00"
ZIP_HEAD = b"PK\x03\x04\x14\x00\x08\x00"
EXE_HEAD = b"MZ\x90\x00\x03\x00\x00\x00"
ELF_HEAD = b"\x7fELF\x02\x01\x01\x00"
TXT_HEAD = b"Dear Dr Okonkwo,\n"


# ---------------------------------------------------------------------------
# Filenames that must be refused
# ---------------------------------------------------------------------------
class TestHostileFilenames:
    @pytest.mark.parametrize(
        ("name", "why"),
        [
            ("../../etc/passwd", "posix traversal"),
            ("....//....//etc/passwd", "doubled-up traversal"),
            ("..\\..\\windows\\system32\\config\\sam", "windows traversal"),
            ("/etc/shadow", "absolute posix path"),
            ("C:\\Windows\\System32\\drivers\\etc\\hosts", "absolute windows path"),
            ("C:report.pdf", "windows drive-relative path"),
            ("\\\\server\\share\\report.pdf", "UNC path"),
            ("sub/dir/report.pdf", "nested posix path"),
            ("sub\\dir\\report.pdf", "nested windows path"),
            (".", "current directory"),
            ("..", "parent directory"),
            ("", "empty"),
            ("    ", "whitespace only"),
            ("con.txt", "reserved windows device"),
            ("PRN.pdf", "reserved windows device, upper case"),
            ("lpt9.docx", "reserved windows device"),
            ("nul", "reserved windows device, no extension"),
        ],
    )
    def test_a_path_or_device_name_is_refused(self, name: str, why: str) -> None:
        with pytest.raises(DocumentInvalidError):
            normalize_filename(name)

    def test_a_percent_encoded_path_is_stored_as_the_literal_name(self) -> None:
        # `..%2f..%2fetc%2fpasswd` contains no separator and is not traversal
        # unless something decodes it. Nothing here does: the name is stored
        # sealed and is only ever emitted percent-encoded in a
        # Content-Disposition header, so a browser decodes it back to this
        # exact literal rather than to a path. Refusing it would be theatre.
        name = "..%2f..%2fetc%2fpasswd.txt"

        assert normalize_filename(name) == name

    @pytest.mark.parametrize(
        ("name", "why"),
        [
            ("report\x00.pdf", "null byte truncates the name for a C consumer"),
            ("report\n.pdf", "newline could split a log line or a header"),
            ("report\r\n.pdf", "CRLF response splitting"),
            ("report\t.pdf", "tab"),
            ("\x1b[2Jreport.pdf", "ANSI escape rewrites a terminal reading the logs"),
            ("report\x7f.pdf", "delete"),
        ],
    )
    def test_a_control_character_is_refused(self, name: str, why: str) -> None:
        with pytest.raises(DocumentInvalidError):
            normalize_filename(name)

    @pytest.mark.parametrize(
        ("name", "why"),
        [
            ("report\u202etxt.pdf", "right-to-left override -- displays as report.fdp.txt"),
            ("invoice\u202dexe.pdf", "left-to-right override"),
            ("notes\u202bmalicious.pdf", "right-to-left embedding"),
            ("notes\u202amalicious.pdf", "left-to-right embedding"),
            ("notes\u202cmalicious.pdf", "pop directional formatting"),
            ("notes\u2066spoofed.pdf", "left-to-right isolate"),
            ("notes\u2067spoofed.pdf", "right-to-left isolate"),
            ("notes\u2068spoofed.pdf", "first-strong isolate"),
            ("notes\u2069spoofed.pdf", "pop directional isolate"),
            ("notes\u200fspoofed.pdf", "right-to-left mark"),
            ("notes\u200espoofed.pdf", "left-to-right mark"),
            ("notes\u061cspoofed.pdf", "arabic letter mark"),
        ],
    )
    def test_a_bidirectional_override_is_refused(self, name: str, why: str) -> None:
        # These characters reorder how a name *renders* without changing what it
        # *is*, so a reviewer approving "summary.txt" can be approving
        # "summary.exe". They have no legitimate use in a filename.
        with pytest.raises(DocumentInvalidError):
            normalize_filename(name)

    def test_an_excessively_long_name_is_refused(self) -> None:
        with pytest.raises(DocumentInvalidError):
            normalize_filename("a" * (MAX_FILENAME_CHARS + 1) + ".pdf")

    def test_a_name_at_the_limit_is_accepted(self) -> None:
        name = "a" * (MAX_FILENAME_CHARS - 4) + ".pdf"

        assert normalize_filename(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "../../etc/passwd",
            "sub/dir/report.pdf",
            "report\x00.pdf",
            "report\u202etxt.pdf",
        ],
    )
    def test_refusal_is_never_a_silent_rewrite(self, name: str) -> None:
        # The tempting fix is to strip the offending part and carry on. That
        # stores a document under a name the caller never chose, which is worse
        # than refusing: the caller believes something else happened.
        with pytest.raises(DocumentInvalidError) as caught:
            normalize_filename(name)

        assert "reason" in caught.value.log_context


# ---------------------------------------------------------------------------
# Filenames that must be accepted
# ---------------------------------------------------------------------------
class TestLegitimateFilenames:
    @pytest.mark.parametrize(
        "name",
        [
            "report.pdf",
            "Q3 financials (final).docx",
            "contrat-signé.pdf",
            "отчёт.pdf",
            "報告書.pdf",
            "notes_2026-01-14.txt",
            "report.v2.final.pdf",
        ],
    )
    def test_an_ordinary_name_survives_unchanged(self, name: str) -> None:
        assert normalize_filename(name) == name

    def test_a_name_carrying_a_person_and_a_diagnosis_is_accepted(self) -> None:
        # This is a real filename, not an attack. Refusing it would push users
        # to rename files to get past the gateway, which is worse for privacy
        # than accepting it and encrypting it. It is Restricted, so it is
        # sealed at rest and never logged -- see the canary suite.
        name = CANARIES["filename"]

        assert normalize_filename(name) == name

    def test_equivalent_unicode_spellings_normalize_to_one_name(self) -> None:
        # Composed and decomposed forms render identically. Two stored names
        # that look the same and are not is a support problem waiting to happen.
        assert normalize_filename("cafe\u0301.pdf") == normalize_filename("café.pdf")

    def test_surrounding_whitespace_is_trimmed(self) -> None:
        assert normalize_filename("  report.pdf  ") == "report.pdf"

    def test_a_zero_width_joiner_is_not_treated_as_hostile(self) -> None:
        # ZWJ and ZWNJ are ordinary in Persian, Hindi, and emoji sequences.
        # Rejecting the whole Cf category to catch bidi overrides would refuse
        # legitimate names in those scripts.
        name = "\u0645\u0633\u062a\u0646\u062f\u200c\u0631\u0633\u0645\u06cc.pdf"

        assert normalize_filename(name) == name


# ---------------------------------------------------------------------------
# Type resolution: extension against declared MIME type
# ---------------------------------------------------------------------------
class TestTypeResolution:
    @pytest.mark.parametrize(
        ("filename", "declared", "expected"),
        [
            ("report.pdf", CONTENT_TYPE_PDF, CONTENT_TYPE_PDF),
            ("report.PDF", CONTENT_TYPE_PDF, CONTENT_TYPE_PDF),
            ("notes.txt", CONTENT_TYPE_TXT, CONTENT_TYPE_TXT),
            ("notes.txt", "text/plain; charset=utf-8", CONTENT_TYPE_TXT),
            ("contract.docx", CONTENT_TYPE_DOCX, CONTENT_TYPE_DOCX),
            ("report.pdf", None, CONTENT_TYPE_PDF),
            ("notes.txt", None, CONTENT_TYPE_TXT),
        ],
    )
    def test_agreement_is_accepted(
        self, filename: str, declared: str | None, expected: str
    ) -> None:
        assert resolve_content_type(filename=filename, declared=declared) == expected

    @pytest.mark.parametrize(
        ("filename", "declared", "why"),
        [
            ("payload.exe", None, "unsupported extension"),
            ("payload.exe", "application/pdf", "unsupported extension, plausible MIME"),
            ("archive.zip", None, "unsupported extension"),
            ("script.js", "text/plain", "unsupported extension"),
            ("noextension", None, "no extension at all"),
            ("report.pdf", "application/octet-stream", "unsupported declared type"),
            ("report.pdf", "image/png", "unsupported declared type"),
            ("report.pdf", CONTENT_TYPE_TXT, "extension and MIME disagree"),
            ("notes.txt", CONTENT_TYPE_PDF, "extension and MIME disagree"),
            ("contract.docx", CONTENT_TYPE_PDF, "extension and MIME disagree"),
            ("report.pdf.exe", CONTENT_TYPE_PDF, "double extension, last one wins"),
        ],
    )
    def test_disagreement_or_an_unknown_type_is_refused(
        self, filename: str, declared: str | None, why: str
    ) -> None:
        with pytest.raises(DocumentTypeUnsupportedError):
            resolve_content_type(filename=filename, declared=declared)

    def test_a_harmless_looking_double_extension_still_resolves_by_the_last_one(
        self,
    ) -> None:
        # `report.exe.pdf` is a PDF as far as the name goes. The magic-byte
        # check below is what refuses it if the body is really an executable.
        assert resolve_content_type(filename="report.exe.pdf", declared=None) == (CONTENT_TYPE_PDF)


# ---------------------------------------------------------------------------
# Magic bytes: the type against the file's own contents
# ---------------------------------------------------------------------------
class TestMagicBytes:
    @pytest.mark.parametrize(
        ("content_type", "head"),
        [
            (CONTENT_TYPE_PDF, PDF_HEAD),
            (CONTENT_TYPE_DOCX, DOCX_HEAD),
            (CONTENT_TYPE_DOCX, b"PK\x05\x06" + b"\x00" * 5),
            (CONTENT_TYPE_DOCX, b"PK\x07\x08" + b"\x00" * 5),
            (CONTENT_TYPE_TXT, TXT_HEAD),
            (CONTENT_TYPE_TXT, "Dear Dr Okonkwo — お世話になります".encode()),
        ],
    )
    def test_a_body_that_matches_its_type_is_accepted(self, content_type: str, head: bytes) -> None:
        verify_magic(content_type=content_type, head=head)

    @pytest.mark.parametrize(
        ("content_type", "head", "why"),
        [
            (CONTENT_TYPE_PDF, EXE_HEAD, "windows executable renamed to .pdf"),
            (CONTENT_TYPE_PDF, ELF_HEAD, "linux executable renamed to .pdf"),
            (CONTENT_TYPE_PDF, DOCX_HEAD, "docx renamed to .pdf"),
            (CONTENT_TYPE_PDF, ZIP_HEAD, "zip renamed to .pdf"),
            (CONTENT_TYPE_PDF, TXT_HEAD, "text renamed to .pdf"),
            (CONTENT_TYPE_PDF, b"%PDF", "truncated signature"),
            (CONTENT_TYPE_PDF, b"\n%PDF-1.7", "signature not at offset zero"),
            (CONTENT_TYPE_DOCX, PDF_HEAD, "pdf renamed to .docx"),
            (CONTENT_TYPE_DOCX, EXE_HEAD, "executable renamed to .docx"),
            (CONTENT_TYPE_DOCX, TXT_HEAD, "text renamed to .docx"),
            (CONTENT_TYPE_TXT, PDF_HEAD, "pdf renamed to .txt"),
            (CONTENT_TYPE_TXT, DOCX_HEAD, "docx renamed to .txt"),
            (CONTENT_TYPE_TXT, ZIP_HEAD, "zip renamed to .txt"),
        ],
    )
    def test_a_body_that_belies_its_type_is_refused(
        self, content_type: str, head: bytes, why: str
    ) -> None:
        with pytest.raises((DocumentTypeUnsupportedError, DocumentInvalidError)):
            verify_magic(content_type=content_type, head=head)

    def test_a_signature_less_type_is_still_checked_against_the_others(self) -> None:
        # The regression that motivates this file. Plain text has no signature,
        # and `%PDF-1.7` decodes as ASCII, so a decodability-only check waved a
        # PDF through under a .txt name -- and the next phase's text extractor
        # would then be handed a binary container.
        with pytest.raises(DocumentTypeUnsupportedError) as caught:
            verify_magic(content_type=CONTENT_TYPE_TXT, head=PDF_HEAD)

        assert caught.value.log_context["reason"] == "magic_bytes_match_another_type"
        assert caught.value.log_context["actual_content_type"] == CONTENT_TYPE_PDF

    @pytest.mark.parametrize(
        "head",
        [b"\xff\xfe\x00\x41", b"\x80\x81\x82\x83", b"\xc3\x28", b"\xed\xa0\x80"],
    )
    def test_text_that_is_not_utf8_is_refused(self, head: bytes) -> None:
        with pytest.raises(DocumentInvalidError):
            verify_magic(content_type=CONTENT_TYPE_TXT, head=head)

    def test_a_multibyte_character_cut_at_the_sniff_boundary_is_not_an_error(self) -> None:
        # The sniff window ends wherever it ends. Truncating a valid document's
        # first character must not look like a malformed one.
        whole = "日本語のドキュメント".encode()

        verify_magic(content_type=CONTENT_TYPE_TXT, head=whole[:7])

    def test_a_well_formed_header_over_nonsense_is_accepted_by_design(self) -> None:
        # Phase 1 checks headers, not structure. A PDF header followed by
        # garbage is stored, because deciding whether a PDF really parses means
        # parsing it, and parsing is extraction -- Phase 2. Asserting this
        # keeps the boundary explicit instead of implied.
        verify_magic(content_type=CONTENT_TYPE_PDF, head=b"%PDF-\xff\xff\xff")
        verify_magic(content_type=CONTENT_TYPE_DOCX, head=b"PK\x03\x04\xff\xff\xff\xff")


# ---------------------------------------------------------------------------
# Length
# ---------------------------------------------------------------------------
class TestLength:
    @pytest.mark.parametrize("declared", [0, 1, 999, 1_000])
    def test_a_declared_length_within_the_limit_passes(self, declared: int) -> None:
        enforce_declared_length(declared=declared, limit=1_000)

    def test_an_absent_declared_length_is_not_a_refusal(self) -> None:
        # A chunked upload has no Content-Length. The streamed count is what
        # actually enforces the limit.
        enforce_declared_length(declared=None, limit=1_000)

    def test_a_declared_length_over_the_limit_is_refused_early(self) -> None:
        with pytest.raises(DocumentTooLargeError):
            enforce_declared_length(declared=1_001, limit=1_000)

    def test_a_negative_declared_length_is_malformed(self) -> None:
        with pytest.raises(DocumentInvalidError):
            enforce_declared_length(declared=-1, limit=1_000)

    @pytest.mark.parametrize("received", [0, 1, 1_000])
    def test_a_streamed_count_within_the_limit_passes(self, received: int) -> None:
        enforce_streamed_length(received=received, limit=1_000)

    def test_the_streamed_count_is_what_actually_enforces_the_limit(self) -> None:
        # A client that understates or omits Content-Length gets stopped here.
        enforce_declared_length(declared=10, limit=1_000)

        with pytest.raises(DocumentTooLargeError):
            enforce_streamed_length(received=1_001, limit=1_000)

    def test_neither_check_names_the_document(self) -> None:
        # A size refusal is returned to the caller. Its context carries a
        # reason and a limit, and nothing about what was being uploaded.
        with pytest.raises(DocumentTooLargeError) as caught:
            enforce_streamed_length(received=2_000, limit=1_000)

        assert set(caught.value.log_context) == {"reason", "limit"}
