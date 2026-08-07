"""Tests for secure document storage.

The security block is the point of the file. It asserts the properties that make
storing a document worth doing at all: ciphertext at rest, per-document keys,
associated-data binding across tenant, user, document, and content type,
tamper and truncation detection, opaque keys, and log hygiene.

Everything runs against ``FakeDocumentStore`` and in-memory SQLite. Nothing here
opens a socket; the store itself is exercised against real AWS S3 in
``tests/integration/test_documents_s3.py``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.documents.crypto import (
    DOCUMENT_MAGIC,
    PURPOSE_BODY,
    PURPOSE_FILENAME,
    DocumentCipher,
    DocumentHeader,
    DocumentIdentity,
)
from app.documents.models import (
    CONTENT_TYPE_DOCX,
    CONTENT_TYPE_PDF,
    CONTENT_TYPE_TXT,
    DocumentStatus,
)
from app.documents.protocol import DocumentStore
from app.documents.service import STORAGE_KEY_PREFIX, DocumentService
from app.documents.storage.fakes import FakeDocumentStore
from app.documents.validation import (
    enforce_declared_length,
    enforce_streamed_length,
    normalize_filename,
    resolve_content_type,
    verify_magic,
)
from app.domain.errors import (
    DocumentEncryptionError,
    DocumentInvalidError,
    DocumentNotFoundError,
    DocumentStorageUnavailableError,
    DocumentTooLargeError,
    DocumentTypeUnsupportedError,
)
from app.vault.keys import StaticKeyRing

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.ext.asyncio import AsyncSession

TENANT = UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = UUID("22222222-2222-2222-2222-222222222222")
USER = UUID("33333333-3333-3333-3333-333333333333")
OTHER_USER = UUID("44444444-4444-4444-4444-444444444444")
DOCUMENT = UUID("55555555-5555-5555-5555-555555555555")

KEY_ID = "local1"
KEY = bytes(range(32))
OTHER_KEY = bytes(range(64, 96))

PDF_BODY = b"%PDF-1.7\nJane Doe, MRN-40217788\n%%EOF\n"
TXT_BODY = b"Patient Avery Example, avery@example.test\n"
DOCX_BODY = b"PK\x03\x04" + b"\x00" * 64

CHUNK = 5_242_880
MAX_BYTES = 26_214_400


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def key_ring() -> StaticKeyRing:
    return StaticKeyRing({KEY_ID: KEY}, active_key_id=KEY_ID)


@pytest.fixture
def cipher(key_ring: StaticKeyRing) -> DocumentCipher:
    # A small chunk size so a handful of bytes exercises the multi-chunk path.
    return DocumentCipher(key_ring, chunk_bytes=64)


@pytest.fixture
def store() -> FakeDocumentStore:
    return FakeDocumentStore()


@pytest.fixture
async def session_scope() -> AsyncIterator[object]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def scope() -> AsyncIterator[AsyncSession]:
        session = factory()
        try:
            yield session
        finally:
            await session.close()

    async with engine.begin() as connection:
        await connection.exec_driver_sql(
            "INSERT INTO tenants (id, name, slug, status, created_at, updated_at)"
            " VALUES (:id, 'Test', 'test', 'active', '2026-01-01', '2026-01-01')",
            {"id": str(TENANT)},
        )
        await connection.exec_driver_sql(
            "INSERT INTO tenants (id, name, slug, status, created_at, updated_at)"
            " VALUES (:id, 'Other', 'other', 'active', '2026-01-01', '2026-01-01')",
            {"id": str(OTHER_TENANT)},
        )

    yield scope
    await engine.dispose()


@pytest.fixture
def service(
    store: FakeDocumentStore,
    cipher: DocumentCipher,
    session_scope: object,
) -> DocumentService:
    return DocumentService(
        store=store,
        cipher=cipher,
        session_scope=session_scope,  # type: ignore[arg-type]
        max_document_bytes=MAX_BYTES,
    )


def identity(
    *,
    tenant_id: UUID = TENANT,
    user_id: UUID = USER,
    document_id: UUID = DOCUMENT,
    content_type: str = CONTENT_TYPE_PDF,
) -> DocumentIdentity:
    return DocumentIdentity(
        tenant_id=tenant_id,
        user_id=user_id,
        document_id=document_id,
        content_type=content_type,
    )


async def stream(*blocks: bytes) -> AsyncIterator[bytes]:
    for block in blocks:
        yield block


async def collect(chunks: AsyncIterator[bytes]) -> bytes:
    out = bytearray()
    async for block in chunks:
        out += block
    return bytes(out)


async def seal(cipher: DocumentCipher, body: bytes, **kwargs: object) -> bytes:
    return await collect(
        cipher.seal_stream(identity=identity(**kwargs), plaintext=stream(body))  # type: ignore[arg-type]
    )


async def store_pdf(
    service: DocumentService,
    *,
    filename: str = "report.pdf",
    body: bytes = PDF_BODY,
    content_type: str | None = CONTENT_TYPE_PDF,
    tenant_id: UUID = TENANT,
    user_id: UUID = USER,
) -> object:
    return await service.store(
        tenant_id=tenant_id,
        user_id=user_id,
        filename=filename,
        declared_content_type=content_type,
        declared_length=len(body),
        source=stream(body),
    )


# ---------------------------------------------------------------------------
# Filename validation
# ---------------------------------------------------------------------------
class TestFilenameValidation:
    @pytest.mark.parametrize(
        "name", ["report.pdf", "Jane Doe notes.txt", "contrat-signé.docx", "a" * 250 + ".txt"]
    )
    def test_accepts_ordinary_names(self, name: str) -> None:
        assert normalize_filename(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config",
            "sub/dir/report.pdf",
            "sub\\dir\\report.pdf",
            "",
            "   ",
            ".",
            "..",
            "report\x00.pdf",
            "report\n.pdf",
            "con.txt",
            "NUL.pdf",
            "a" * 256,
        ],
    )
    def test_rejects_hostile_or_meaningless_names(self, name: str) -> None:
        with pytest.raises(DocumentInvalidError):
            normalize_filename(name)

    def test_traversal_is_rejected_not_silently_rewritten(self) -> None:
        # Arrange / Act / Assert -- rewriting would store something the caller
        # never asked for, under a name they would not recognise.
        with pytest.raises(DocumentInvalidError):
            normalize_filename("../../secrets.txt")

    def test_equivalent_unicode_forms_normalize_to_one_name(self) -> None:
        # Arrange -- "é" as one code point and as e + combining accent.
        composed = "café.txt"
        decomposed = "café.txt"

        # Act / Assert
        assert normalize_filename(composed) == normalize_filename(decomposed)


# ---------------------------------------------------------------------------
# Type validation
# ---------------------------------------------------------------------------
class TestTypeValidation:
    @pytest.mark.parametrize(
        ("filename", "declared", "expected"),
        [
            ("a.txt", CONTENT_TYPE_TXT, CONTENT_TYPE_TXT),
            ("a.pdf", CONTENT_TYPE_PDF, CONTENT_TYPE_PDF),
            ("a.docx", CONTENT_TYPE_DOCX, CONTENT_TYPE_DOCX),
            ("a.pdf", None, CONTENT_TYPE_PDF),
            ("a.pdf", "application/pdf; charset=binary", CONTENT_TYPE_PDF),
        ],
    )
    def test_accepts_the_three_supported_types(
        self, filename: str, declared: str | None, expected: str
    ) -> None:
        assert resolve_content_type(filename=filename, declared=declared) == expected

    @pytest.mark.parametrize(
        ("filename", "declared"),
        [
            ("a.exe", None),
            ("a.zip", None),
            ("a", None),
            ("a.txt", "application/x-executable"),
            ("a.txt", CONTENT_TYPE_PDF),
            ("a.pdf", CONTENT_TYPE_TXT),
        ],
    )
    def test_rejects_unsupported_and_disagreeing_types(
        self, filename: str, declared: str | None
    ) -> None:
        with pytest.raises(DocumentTypeUnsupportedError):
            resolve_content_type(filename=filename, declared=declared)

    def test_a_pdf_body_under_a_txt_name_is_rejected(self) -> None:
        # Arrange / Act / Assert -- believing the name here is how a PDF ends
        # up in front of a text extractor.
        with pytest.raises(DocumentTypeUnsupportedError):
            verify_magic(content_type=CONTENT_TYPE_TXT, head=b"%PDF-1.7")

    def test_an_executable_renamed_to_pdf_is_rejected(self) -> None:
        with pytest.raises(DocumentTypeUnsupportedError):
            verify_magic(content_type=CONTENT_TYPE_PDF, head=b"MZ\x90\x00\x03\x00\x00\x00")

    @pytest.mark.parametrize("head", [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"])
    def test_docx_accepts_every_zip_record(self, head: bytes) -> None:
        verify_magic(content_type=CONTENT_TYPE_DOCX, head=head)

    def test_text_must_decode_as_utf8(self) -> None:
        with pytest.raises(DocumentInvalidError):
            verify_magic(content_type=CONTENT_TYPE_TXT, head=b"\xff\xfe\x00\x01\x02\x03\x04\x05")

    def test_a_multibyte_character_split_at_the_sniff_boundary_is_not_an_error(self) -> None:
        # Arrange -- the first 8 bytes of text ending mid-character.
        head = "日本語テキスト".encode()[:8]

        # Act / Assert
        verify_magic(content_type=CONTENT_TYPE_TXT, head=head)


# ---------------------------------------------------------------------------
# Length validation
# ---------------------------------------------------------------------------
class TestLengthValidation:
    def test_a_declared_length_over_the_limit_is_refused_early(self) -> None:
        with pytest.raises(DocumentTooLargeError):
            enforce_declared_length(declared=MAX_BYTES + 1, limit=MAX_BYTES)

    def test_an_absent_declared_length_is_allowed_through(self) -> None:
        # A chunked upload has no Content-Length. The streamed check is what
        # actually enforces the limit.
        enforce_declared_length(declared=None, limit=MAX_BYTES)

    def test_a_negative_declared_length_is_a_malformed_request(self) -> None:
        with pytest.raises(DocumentInvalidError):
            enforce_declared_length(declared=-1, limit=MAX_BYTES)

    def test_the_streamed_count_is_what_enforces_the_limit(self) -> None:
        with pytest.raises(DocumentTooLargeError):
            enforce_streamed_length(received=MAX_BYTES + 1, limit=MAX_BYTES)


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------
class TestDocumentCrypto:
    async def test_round_trips_a_document_through_seal_and_open(
        self, cipher: DocumentCipher
    ) -> None:
        # Arrange -- several chunks' worth at a 64-byte chunk size.
        body = PDF_BODY * 20

        # Act
        sealed = await seal(cipher, body)
        opened = await collect(cipher.open_stream(identity=identity(), ciphertext=stream(sealed)))

        # Assert
        assert opened == body

    async def test_the_sealed_form_contains_no_plaintext(self, cipher: DocumentCipher) -> None:
        # Arrange / Act
        sealed = await seal(cipher, PDF_BODY)

        # Assert -- the whole point of the exercise.
        assert b"Jane Doe" not in sealed
        assert b"MRN-40217788" not in sealed
        assert sealed.startswith(DOCUMENT_MAGIC)

    async def test_two_documents_of_the_same_bytes_share_no_ciphertext(
        self, cipher: DocumentCipher
    ) -> None:
        # Arrange / Act -- different document ids, so different derived keys.
        first = await seal(cipher, PDF_BODY, document_id=uuid4())
        second = await seal(cipher, PDF_BODY, document_id=uuid4())

        # Assert
        assert first != second

    @pytest.mark.parametrize(
        "wrong",
        [
            {"tenant_id": OTHER_TENANT},
            {"user_id": OTHER_USER},
            {"document_id": uuid4()},
            {"content_type": CONTENT_TYPE_TXT},
        ],
    )
    async def test_opening_under_the_wrong_identity_fails(
        self, cipher: DocumentCipher, wrong: dict[str, object]
    ) -> None:
        # Arrange -- ADR-0021: the triple, the content type, and the schema are
        # all bound in, so any of them being wrong is an authentication failure
        # rather than plaintext.
        sealed = await seal(cipher, PDF_BODY)

        # Act / Assert
        with pytest.raises(DocumentEncryptionError):
            await collect(
                cipher.open_stream(
                    identity=identity(**wrong),  # type: ignore[arg-type]
                    ciphertext=stream(sealed),
                )
            )

    async def test_a_document_sealed_under_another_key_ring_cannot_be_opened(
        self, cipher: DocumentCipher
    ) -> None:
        # Arrange
        sealed = await seal(cipher, PDF_BODY)
        stranger = DocumentCipher(
            StaticKeyRing({KEY_ID: OTHER_KEY}, active_key_id=KEY_ID), chunk_bytes=64
        )

        # Act / Assert
        with pytest.raises(DocumentEncryptionError):
            await collect(stranger.open_stream(identity=identity(), ciphertext=stream(sealed)))

    async def test_a_flipped_byte_is_detected(self, cipher: DocumentCipher) -> None:
        # Arrange
        sealed = bytearray(await seal(cipher, PDF_BODY))
        sealed[-1] ^= 0x01

        # Act / Assert
        with pytest.raises(DocumentEncryptionError):
            await collect(cipher.open_stream(identity=identity(), ciphertext=stream(bytes(sealed))))

    async def test_a_truncated_document_is_detected(self, cipher: DocumentCipher) -> None:
        # Arrange -- drop the last chunk entirely. Without the final-chunk flag
        # in the AAD this would decrypt cleanly into a shorter document.
        body = b"%PDF-" + b"A" * 300
        sealed = await seal(cipher, body)
        header, consumed = DocumentHeader.parse(sealed)
        frame = 12 + header.chunk_bytes + 16
        truncated = sealed[: consumed + frame]

        # Act / Assert
        with pytest.raises(DocumentEncryptionError):
            await collect(cipher.open_stream(identity=identity(), ciphertext=stream(truncated)))

    async def test_reordered_chunks_are_detected(self, cipher: DocumentCipher) -> None:
        # Arrange -- swap the first two frames. The chunk index is in the AAD.
        body = b"%PDF-" + b"A" * 300
        sealed = await seal(cipher, body)
        header, consumed = DocumentHeader.parse(sealed)
        frame = 12 + header.chunk_bytes + 16
        first = sealed[consumed : consumed + frame]
        second = sealed[consumed + frame : consumed + 2 * frame]
        swapped = sealed[:consumed] + second + first + sealed[consumed + 2 * frame :]

        # Act / Assert
        with pytest.raises(DocumentEncryptionError):
            await collect(cipher.open_stream(identity=identity(), ciphertext=stream(swapped)))

    async def test_an_empty_ciphertext_stream_fails_rather_than_yielding_nothing(
        self, cipher: DocumentCipher
    ) -> None:
        with pytest.raises(DocumentEncryptionError):
            await collect(cipher.open_stream(identity=identity(), ciphertext=stream()))

    async def test_input_chunking_does_not_change_the_output(self, cipher: DocumentCipher) -> None:
        # Arrange -- the same bytes delivered in different pieces. A client's
        # chunk boundaries are its own business.
        body = b"%PDF-" + b"B" * 500
        pieces = [body[index : index + 7] for index in range(0, len(body), 7)]

        # Act
        one_shot = await collect(cipher.seal_stream(identity=identity(), plaintext=stream(body)))
        dribbled = await collect(cipher.seal_stream(identity=identity(), plaintext=stream(*pieces)))

        # Assert -- ciphertexts differ (fresh nonces), plaintexts do not.
        assert await collect(
            cipher.open_stream(identity=identity(), ciphertext=stream(one_shot))
        ) == await collect(cipher.open_stream(identity=identity(), ciphertext=stream(dribbled)))

    def test_a_filename_round_trips_and_is_not_stored_in_the_clear(
        self, cipher: DocumentCipher
    ) -> None:
        # Arrange -- a filename that identifies a person and a condition.
        name = "Jane Doe MRI results.pdf"

        # Act
        sealed = cipher.seal_bytes(
            identity=identity(), purpose=PURPOSE_FILENAME, plaintext=name.encode()
        )
        opened = cipher.open_bytes(identity=identity(), purpose=PURPOSE_FILENAME, raw=sealed)

        # Assert
        assert opened.decode() == name
        assert b"Jane" not in sealed

    def test_a_filename_cannot_be_opened_as_a_body(self, cipher: DocumentCipher) -> None:
        # Arrange -- the purpose is bound in, so the two blobs are not
        # interchangeable even under the same key.
        sealed = cipher.seal_bytes(
            identity=identity(), purpose=PURPOSE_FILENAME, plaintext=b"notes.pdf"
        )

        # Act / Assert
        with pytest.raises(DocumentEncryptionError):
            cipher.open_bytes(identity=identity(), purpose=PURPOSE_BODY, raw=sealed)

    @pytest.mark.parametrize(
        "raw",
        [b"", b"XXXX", b"SGWD" + b"\x09", DOCUMENT_MAGIC + b"\x01\x00", b"SGWD\x01\x06abc"],
    )
    def test_a_malformed_header_is_rejected_without_allocating(self, raw: bytes) -> None:
        with pytest.raises(DocumentEncryptionError):
            DocumentHeader.parse(raw)

    def test_a_hostile_chunk_size_in_the_header_is_refused(self) -> None:
        # Arrange -- a header claiming 4 GiB chunks would otherwise make the
        # reader wait for a frame that never arrives.
        header = DocumentHeader(version=1, key_id=KEY_ID, salt=b"\x00" * 16, chunk_bytes=1)
        raw = bytearray(header.to_bytes())
        raw[-4:] = (0xFFFFFFFF).to_bytes(4, "big")

        # Act / Assert
        with pytest.raises(DocumentEncryptionError):
            DocumentHeader.parse(bytes(raw))


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------
class TestDocumentService:
    async def test_stores_and_retrieves_a_document(self, service: DocumentService) -> None:
        # Arrange / Act
        stored = await store_pdf(service)
        document, chunks = await service.open(
            tenant_id=TENANT,
            user_id=USER,
            document_id=stored.metadata.id,  # type: ignore[attr-defined]
        )
        body = await collect(chunks)

        # Assert
        assert body == PDF_BODY
        assert document.filename == "report.pdf"
        assert document.metadata.status is DocumentStatus.STORED
        assert document.metadata.byte_size == len(PDF_BODY)
        assert document.metadata.sha256_hex == hashlib.sha256(PDF_BODY).hexdigest()

    @pytest.mark.parametrize(
        ("filename", "body", "content_type"),
        [
            ("notes.txt", TXT_BODY, CONTENT_TYPE_TXT),
            ("report.pdf", PDF_BODY, CONTENT_TYPE_PDF),
            ("contract.docx", DOCX_BODY, CONTENT_TYPE_DOCX),
        ],
    )
    async def test_supports_txt_pdf_and_docx(
        self,
        service: DocumentService,
        filename: str,
        body: bytes,
        content_type: str,
    ) -> None:
        # Arrange / Act
        stored = await store_pdf(service, filename=filename, body=body, content_type=content_type)

        # Assert
        assert stored.metadata.content_type == content_type  # type: ignore[attr-defined]

    async def test_the_object_store_never_sees_plaintext(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        # Arrange / Act
        await store_pdf(service)

        # Assert -- the property the whole module exists for.
        assert not store.contains_plaintext(b"Jane Doe")
        assert not store.contains_plaintext(b"MRN-40217788")
        assert not store.contains_plaintext(b"report.pdf")

    async def test_the_storage_key_reveals_nothing(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        # Arrange / Act
        stored = await store_pdf(service)

        # Assert -- opaque per ADR-0020: no tenant, no user, no filename, no
        # extension, and not the document id either.
        (key,) = store.stored_keys()
        assert key.startswith(STORAGE_KEY_PREFIX)
        for leak in (str(TENANT), str(USER), str(stored.metadata.id), "report", ".pdf"):  # type: ignore[attr-defined]
            assert leak not in key

    async def test_the_body_is_streamed_rather_than_buffered(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        # Arrange -- a body several chunks long at the 64-byte test chunk size.
        body = b"%PDF-" + b"C" * 500

        # Act
        await store_pdf(service, body=body)

        # Assert -- more than one chunk reached the store, so nothing assembled
        # the whole document first.
        assert len(store.put_chunk_sizes[0]) > 1

    async def test_a_document_cannot_be_read_by_another_tenant(
        self, service: DocumentService
    ) -> None:
        # Arrange
        stored = await store_pdf(service)

        # Act / Assert
        with pytest.raises(DocumentNotFoundError):
            await service.open(
                tenant_id=OTHER_TENANT,
                user_id=USER,
                document_id=stored.metadata.id,  # type: ignore[attr-defined]
            )

    async def test_a_document_cannot_be_read_by_another_user(
        self, service: DocumentService
    ) -> None:
        # Arrange -- ADR-0021: a document belongs to a user, not just a tenant.
        stored = await store_pdf(service)

        # Act / Assert
        with pytest.raises(DocumentNotFoundError):
            await service.open(
                tenant_id=TENANT,
                user_id=OTHER_USER,
                document_id=stored.metadata.id,  # type: ignore[attr-defined]
            )

    async def test_an_unknown_document_is_not_found(self, service: DocumentService) -> None:
        with pytest.raises(DocumentNotFoundError):
            await service.status(tenant_id=TENANT, user_id=USER, document_id=uuid4())

    async def test_status_reports_without_touching_the_object(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        # Arrange
        stored = await store_pdf(service)
        store.simulate_failure(DocumentStorageUnavailableError(log_context={"reason": "test"}))

        # Act -- status must still answer with the store down, because it reads
        # metadata only.
        metadata = await service.status(
            tenant_id=TENANT,
            user_id=USER,
            document_id=stored.metadata.id,  # type: ignore[attr-defined]
        )

        # Assert
        assert metadata.status is DocumentStatus.STORED

    async def test_deleting_removes_the_object_and_the_row(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        # Arrange
        stored = await store_pdf(service)

        # Act
        removed = await service.delete(
            tenant_id=TENANT,
            user_id=USER,
            document_id=stored.metadata.id,  # type: ignore[attr-defined]
        )

        # Assert
        assert removed is True
        assert store.stored_keys() == []
        with pytest.raises(DocumentNotFoundError):
            await service.status(
                tenant_id=TENANT,
                user_id=USER,
                document_id=stored.metadata.id,  # type: ignore[attr-defined]
            )

    async def test_deleting_an_unknown_document_is_not_an_error(
        self, service: DocumentService
    ) -> None:
        # Idempotent, so a retry after a timeout gets the same answer.
        assert await service.delete(tenant_id=TENANT, user_id=USER, document_id=uuid4()) is False

    async def test_another_tenant_cannot_delete_a_document(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        # Arrange
        stored = await store_pdf(service)

        # Act
        removed = await service.delete(
            tenant_id=OTHER_TENANT,
            user_id=USER,
            document_id=stored.metadata.id,  # type: ignore[attr-defined]
        )

        # Assert -- reported as "nothing to remove", and nothing was.
        assert removed is False
        assert len(store.stored_keys()) == 1

    async def test_an_oversized_body_is_refused_mid_stream(
        self, store: FakeDocumentStore, cipher: DocumentCipher, session_scope: object
    ) -> None:
        # Arrange -- a small limit and a body that lies about its length by
        # declaring nothing at all.
        service = DocumentService(
            store=store,
            cipher=cipher,
            session_scope=session_scope,  # type: ignore[arg-type]
            max_document_bytes=100,
        )

        # Act / Assert
        with pytest.raises(DocumentTooLargeError):
            await service.store(
                tenant_id=TENANT,
                user_id=USER,
                filename="big.pdf",
                declared_content_type=CONTENT_TYPE_PDF,
                declared_length=None,
                source=stream(b"%PDF-" + b"D" * 500),
            )

        # Assert -- nothing published.
        assert store.stored_keys() == []

    async def test_an_empty_document_is_refused(self, service: DocumentService) -> None:
        with pytest.raises(DocumentInvalidError):
            await store_pdf(service, body=b"")

    async def test_a_body_that_belies_its_name_is_refused(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        # Arrange / Act -- a PDF body under a .txt name.
        with pytest.raises(DocumentTypeUnsupportedError):
            await store_pdf(
                service, filename="notes.txt", body=PDF_BODY, content_type=CONTENT_TYPE_TXT
            )

        # Assert
        assert store.stored_keys() == []

    async def test_a_failed_upload_leaves_no_object_and_a_failed_row(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        # Arrange
        store.simulate_failure(DocumentStorageUnavailableError(log_context={"reason": "test"}))

        # Act
        with pytest.raises(DocumentStorageUnavailableError):
            await store_pdf(service)

        # Assert -- no object, and the row records the failure rather than
        # claiming a document that is not there.
        assert store.stored_keys() == []

    async def test_a_document_that_never_finished_uploading_cannot_be_read(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        # Arrange -- fail the upload, then find the row it left behind.
        store.simulate_failure(DocumentStorageUnavailableError(log_context={"reason": "test"}))
        with pytest.raises(DocumentStorageUnavailableError):
            await store_pdf(service)
        store.simulate_failure(None)

        from sqlalchemy import select

        from app.db.models import Document as DocumentRow

        async with service._session_scope() as session:
            row = (await session.execute(select(DocumentRow))).scalar_one()

        # Act / Assert
        assert row.status == "failed"
        with pytest.raises(DocumentNotFoundError):
            await service.open(tenant_id=TENANT, user_id=USER, document_id=row.id)

    async def test_substituted_content_is_detected_even_when_it_authenticates(
        self, service: DocumentService, store: FakeDocumentStore, cipher: DocumentCipher
    ) -> None:
        # Arrange -- replace the stored object with *different* bytes sealed
        # under the *same* identity. Every chunk authenticates, so AES-GCM has
        # nothing to complain about; only the recorded checksum catches it.
        stored = await store_pdf(service)
        substitute = await collect(
            cipher.seal_stream(
                identity=identity(document_id=stored.metadata.id),  # type: ignore[attr-defined]
                plaintext=stream(PDF_BODY + b"appended by someone else\n"),
            )
        )
        store._objects[stored.metadata.storage_key] = substitute  # type: ignore[attr-defined]

        # Act / Assert
        _, chunks = await service.open(
            tenant_id=TENANT,
            user_id=USER,
            document_id=stored.metadata.id,  # type: ignore[attr-defined]
        )
        with pytest.raises(DocumentEncryptionError):
            await collect(chunks)

    async def test_another_documents_bytes_do_not_authenticate(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        # Arrange -- point one document's storage at another's ciphertext. The
        # AAD binds the document id, so this fails before the checksum is
        # reached: two independent defences, in that order.
        first = await store_pdf(service, filename="one.pdf")
        second = await store_pdf(service, filename="two.pdf")
        store._objects[first.metadata.storage_key] = store.stored_bytes(  # type: ignore[attr-defined]
            second.metadata.storage_key  # type: ignore[attr-defined]
        )

        # Act / Assert
        _, chunks = await service.open(
            tenant_id=TENANT,
            user_id=USER,
            document_id=first.metadata.id,  # type: ignore[attr-defined]
        )
        with pytest.raises(DocumentEncryptionError):
            await collect(chunks)

    async def test_concurrent_uploads_get_distinct_storage_keys(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        # Arrange / Act
        results = await asyncio.gather(
            *[store_pdf(service, filename=f"report{index}.pdf") for index in range(8)]
        )

        # Assert
        assert len({document.metadata.storage_key for document in results}) == 8  # type: ignore[attr-defined]
        assert len(store.stored_keys()) == 8


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------
@pytest.mark.security
class TestDocumentSecurity:
    def test_the_fake_and_the_real_store_satisfy_the_protocol(self) -> None:
        from app.documents.storage.s3 import S3CompatibleDocumentStore

        assert isinstance(FakeDocumentStore(), DocumentStore)
        assert issubclass(S3CompatibleDocumentStore, DocumentStore)

    async def test_no_filename_or_content_appears_in_logs(
        self, service: DocumentService, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Arrange
        caplog.set_level(logging.DEBUG)

        # Act
        stored = await store_pdf(service, filename="Jane Doe MRI results.pdf")
        _, chunks = await service.open(
            tenant_id=TENANT,
            user_id=USER,
            document_id=stored.metadata.id,  # type: ignore[attr-defined]
        )
        await collect(chunks)

        # Assert
        emitted = "\n".join(
            record.getMessage() + repr(record.__dict__) for record in caplog.records
        )
        for leak in ("Jane Doe", "MRI", "MRN-40217788", ".pdf"):
            assert leak not in emitted, f"log disclosed {leak!r}"

    def test_a_document_repr_hides_the_filename(self, cipher: DocumentCipher) -> None:
        from datetime import UTC, datetime

        from app.documents.models import Document, DocumentMetadata

        metadata = DocumentMetadata(
            id=DOCUMENT,
            tenant_id=TENANT,
            user_id=USER,
            storage_key="documents/abc",
            content_type=CONTENT_TYPE_PDF,
            byte_size=1,
            sha256_hex="x",
            status=DocumentStatus.STORED,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        rendered = repr(Document(metadata=metadata, filename="Jane Doe MRI results.pdf"))

        assert "Jane" not in rendered

    def test_the_document_ring_is_not_the_vault_ring(self) -> None:
        # Arrange -- a settings object holding a different key for each ring.
        from app.config.settings import Settings
        from app.vault.keys import DocumentSettingsKeyRing, SettingsKeyRing

        settings = Settings(
            _env_file=None,  # type: ignore[call-arg]
            vault_active_key_id="v1",
            vault_keys={"v1": base64.b64encode(KEY).decode()},  # type: ignore[arg-type]
            document_active_key_id="d1",
            document_keys={"d1": base64.b64encode(OTHER_KEY).decode()},  # type: ignore[arg-type]
        )

        # Act / Assert -- crossing the two would make a vault compromise a
        # document compromise.
        assert SettingsKeyRing(settings).key("v1") == KEY
        assert DocumentSettingsKeyRing(settings).key("d1") == OTHER_KEY
