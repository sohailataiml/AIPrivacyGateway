"""Storage to segments, through the real decryption path.

These tests run the Phase 1 service for real -- ``FakeDocumentStore`` and
in-memory SQLite, but genuine chunked AES-256-GCM and genuine per-document HKDF
keys -- so the seam between the two phases is exercised rather than assumed. A
processor tested against a stub that hands back plaintext would not notice if
the decrypt call were wired wrongly.

The extraction runner is the inline one here. Isolation is not what this file is
about, and paying process startup per test would buy nothing;
``tests/security/test_document_extraction_isolation.py`` covers the real runner.

The assertion worth reading is ``test_nothing_is_retained_anywhere``. Extracted
text is Restricted with "prefer none" storage, and this is the test that keeps
that honest as the code grows.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import insert, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.models import Tenant
from app.documents.extraction.runner import InlineExtractionRunner
from app.documents.models import CONTENT_TYPE_DOCX, CONTENT_TYPE_PDF, CONTENT_TYPE_TXT
from app.documents.processing import DocumentProcessor
from app.documents.segmentation import Segmenter
from app.documents.service import DocumentService
from app.documents.storage.fakes import FakeDocumentStore
from app.domain.errors import (
    DocumentExtractionError,
    DocumentNotFoundError,
    DocumentTooLargeError,
)
from app.observability.logging import configure_logging
from tests.fixtures.document_files import TRUNCATED_PDF, make_docx, make_pdf
from tests.fixtures.documents import (
    CANARIES,
    MAX_BYTES,
    OTHER_TENANT,
    OTHER_USER,
    TENANT,
    USER,
    make_cipher,
    stream,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator
    from contextlib import AbstractAsyncContextManager
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

CANARY_TXT_FILENAME = CANARIES["filename"].replace(".pdf", ".txt")

TXT_BODY = (
    f"{CANARIES['person_name']} attended the clinic.\n"
    f"Record {CANARIES['mrn']}, contact {CANARIES['email']}.\n"
).encode()


@pytest.fixture
def store() -> FakeDocumentStore:
    return FakeDocumentStore()


@pytest.fixture
async def session_scope() -> AsyncIterator[Callable[[], AbstractAsyncContextManager[AsyncSession]]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        for tenant, name in ((TENANT, "test"), (OTHER_TENANT, "other")):
            await connection.execute(
                insert(Tenant).values(id=tenant, name=name, slug=name, status="active")
            )
    factory = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def scope() -> AsyncIterator[AsyncSession]:
        session = factory()
        try:
            yield session
        finally:
            await session.close()

    yield scope
    await engine.dispose()


@pytest.fixture
def documents(
    store: FakeDocumentStore,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> DocumentService:
    return DocumentService(
        store=store,
        cipher=make_cipher(chunk_bytes=512),
        session_scope=session_scope,
        max_document_bytes=MAX_BYTES,
    )


@pytest.fixture
def logs(caplog: pytest.LogCaptureFixture) -> Iterator[pytest.LogCaptureFixture]:
    """Capture what the application actually logs.

    Without ``configure_logging``, structlog's default factory writes straight
    to stdout and emits **no stdlib records at all** -- so a test that reads
    ``caplog`` alone asserts "no sensitive value in the logs" against an empty
    list and passes for the wrong reason. That is defect 16 in miniature.

    So this configures logging the way the application does, then re-attaches
    pytest's handler, because ``configure_logging`` calls
    ``logging.basicConfig(force=True)`` and removes it. ``tests/conftest.py``
    puts the global configuration back afterwards.
    """
    import logging

    configure_logging(level="DEBUG", json_output=False)
    root = logging.getLogger()
    caplog.set_level(logging.DEBUG)
    root.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        root.removeHandler(caplog.handler)


def rendered(caplog: pytest.LogCaptureFixture) -> str:
    return "\n".join(record.getMessage() + repr(record.__dict__) for record in caplog.records)


@pytest.fixture
def processor(documents: DocumentService) -> DocumentProcessor:
    return DocumentProcessor(
        source=documents,
        runner=InlineExtractionRunner(),
        segmenter=Segmenter(max_characters=200, overlap_characters=48),
        max_document_bytes=MAX_BYTES,
    )


async def upload(
    documents: DocumentService,
    *,
    body: bytes,
    filename: str,
    content_type: str,
    tenant_id: UUID = TENANT,
    user_id: UUID = USER,
) -> UUID:
    stored = await documents.store(
        tenant_id=tenant_id,
        user_id=user_id,
        filename=filename,
        declared_content_type=content_type,
        declared_length=len(body),
        source=stream(body),
    )
    return stored.metadata.id


class TestTheHappyPath:
    async def test_a_stored_text_document_becomes_segments(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        document_id = await upload(
            documents, body=TXT_BODY, filename="notes.txt", content_type=CONTENT_TYPE_TXT
        )

        segmented = await processor.segment(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert segmented.document.text == TXT_BODY.decode("utf-8")
        assert segmented.segment_count >= 1

    async def test_a_stored_pdf_keeps_its_pages(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        body = make_pdf([CANARIES["person_name"], CANARIES["mrn"], "third page"])
        document_id = await upload(
            documents, body=body, filename="report.pdf", content_type=CONTENT_TYPE_PDF
        )

        segmented = await processor.segment(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert segmented.document.page_count == 3
        assert all(segment.pages for segment in segmented.segments)

    async def test_a_stored_docx_extracts_its_tables(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        body = make_docx(
            ["Patient record"],
            table=[["Name", "MRN"], [CANARIES["person_name"], CANARIES["mrn"]]],
        )
        document_id = await upload(
            documents,
            body=body,
            filename="record.docx",
            content_type=CONTENT_TYPE_DOCX,
        )

        segmented = await processor.segment(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert CANARIES["mrn"] in segmented.document.text

    async def test_offsets_map_back_to_the_decrypted_document(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        # The end-to-end version of the offset invariant: a position found in a
        # segment must name the same characters in the document it came from.
        document_id = await upload(
            documents,
            body=TXT_BODY * 8,
            filename="notes.txt",
            content_type=CONTENT_TYPE_TXT,
        )

        segmented = await processor.segment(tenant_id=TENANT, user_id=USER, document_id=document_id)

        found = 0
        for segment in segmented.segments:
            local = segmented.text_of(segment).find(CANARIES["mrn"])
            if local == -1:
                continue
            found += 1
            start = segment.to_global(local)
            assert segmented.document.text[start:].startswith(CANARIES["mrn"])
        assert found, "the canary should appear in at least one segment"


class TestAuthorization:
    async def test_another_principal_cannot_extract_it(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        # Extraction is a read. It inherits Phase 1's scoping rather than
        # opening a second, laxer path to the same bytes.
        document_id = await upload(
            documents, body=TXT_BODY, filename="notes.txt", content_type=CONTENT_TYPE_TXT
        )

        for tenant_id, user_id in (
            (TENANT, OTHER_USER),
            (OTHER_TENANT, USER),
            (OTHER_TENANT, OTHER_USER),
        ):
            with pytest.raises(DocumentNotFoundError):
                await processor.segment(
                    tenant_id=tenant_id, user_id=user_id, document_id=document_id
                )

    async def test_an_unknown_document_is_not_found(self, processor: DocumentProcessor) -> None:
        from uuid import uuid4

        with pytest.raises(DocumentNotFoundError):
            await processor.segment(tenant_id=TENANT, user_id=USER, document_id=uuid4())


class TestRefusals:
    async def test_a_file_that_stored_cleanly_can_still_fail_to_parse(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        # Phase 1 checked eight magic bytes. This is where the claim is
        # actually tested, and the document stays stored -- extraction failing
        # is not a reason to destroy the caller's file.
        document_id = await upload(
            documents,
            body=TRUNCATED_PDF,
            filename="broken.pdf",
            content_type=CONTENT_TYPE_PDF,
        )

        with pytest.raises(DocumentExtractionError):
            await processor.segment(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert await documents.status(tenant_id=TENANT, user_id=USER, document_id=document_id)

    async def test_a_document_with_no_text_layer_is_refused_clearly(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        # A scanned PDF. Producing zero segments would look like success and
        # send an empty prompt onward.
        document_id = await upload(
            documents,
            body=make_pdf([""]),
            filename="scan.pdf",
            content_type=CONTENT_TYPE_PDF,
        )

        with pytest.raises(DocumentExtractionError) as caught:
            await processor.segment(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert caught.value.log_context["reason"] == "no_extractable_text"

    async def test_a_decrypted_body_over_the_bound_is_refused(
        self, documents: DocumentService, session_scope
    ) -> None:
        # The stored size is already bounded, but this reads a decrypted
        # stream, and a bound only verified after the fact is not a bound.
        document_id = await upload(
            documents,
            body=b"x" * 4_000,
            filename="notes.txt",
            content_type=CONTENT_TYPE_TXT,
        )
        tiny = DocumentProcessor(
            source=documents,
            runner=InlineExtractionRunner(),
            max_document_bytes=1_000,
        )

        with pytest.raises(DocumentTooLargeError) as caught:
            await tiny.segment(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert caught.value.log_context["reason"] == "decrypted_length_over_limit"


class TestRetentionAndLogging:
    async def test_nothing_is_retained_anywhere(
        self,
        documents: DocumentService,
        processor: DocumentProcessor,
        store: FakeDocumentStore,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        # Extracted text is Restricted with "prefer none" storage. Phase 2
        # honours that literally: no row, no object, no temporary file. This
        # test is what keeps it true as the code grows.
        document_id = await upload(
            documents, body=TXT_BODY, filename="notes.txt", content_type=CONTENT_TYPE_TXT
        )
        objects_before = set(store.stored_keys())

        await processor.segment(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert set(store.stored_keys()) == objects_before
        for canary in CANARIES.values():
            assert not store.contains_plaintext(canary.encode("utf-8"))

        async with session_scope() as session:
            result = await session.execute(text("SELECT count(*) FROM documents"))
            assert result.scalar_one() == 1
            names = await session.execute(
                text("SELECT name FROM sqlite_master WHERE type = 'table'")
            )
            tables = {row[0] for row in names.all()}
        assert not {name for name in tables if "segment" in name or "extract" in name}

    async def test_no_canary_reaches_the_logs(
        self,
        documents: DocumentService,
        processor: DocumentProcessor,
        logs: pytest.LogCaptureFixture,
    ) -> None:
        # The filename is itself a canary, so this covers the filename channel
        # as well as the content one.
        document_id = await upload(
            documents,
            body=TXT_BODY,
            filename=CANARY_TXT_FILENAME,
            content_type=CONTENT_TYPE_TXT,
        )

        await processor.segment(tenant_id=TENANT, user_id=USER, document_id=document_id)

        emitted = rendered(logs)
        assert "document_segmented" in emitted, "the run logged nothing to search"
        for name, canary in CANARIES.items():
            if name == "filename":
                continue
            assert canary not in emitted
        assert CANARY_TXT_FILENAME not in emitted

    async def test_the_summary_log_carries_counts_only(
        self,
        documents: DocumentService,
        processor: DocumentProcessor,
        logs: pytest.LogCaptureFixture,
    ) -> None:
        document_id = await upload(
            documents, body=TXT_BODY, filename="notes.txt", content_type=CONTENT_TYPE_TXT
        )

        await processor.segment(tenant_id=TENANT, user_id=USER, document_id=document_id)

        summaries = [
            entry.getMessage()
            for entry in logs.records
            if "document_segmented" in entry.getMessage()
        ]
        assert summaries, "the summary line was not logged"
        line = summaries[0]
        assert "segment_count" in line
        assert "page_count" in line
        assert "notes.txt" not in line

    async def test_aclose_releases_the_runner(self, processor: DocumentProcessor) -> None:
        await processor.aclose()
        await processor.aclose()
