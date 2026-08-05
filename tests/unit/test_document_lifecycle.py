"""Streaming behaviour and store/database consistency.

Two properties are asserted here, and both are the kind that a round-trip test
cannot see.

**The document is never held whole.** A test that uploads a file and gets it
back passes just as happily against an implementation that buffers 25 MiB of
plaintext per request. The tests in ``TestStreaming`` instead watch the
*interleaving* between the source producing bytes and the store receiving them:
if the service buffered, every block would be produced before the first one was
stored, and the recorded event sequence would say so.

**Every failure boundary leaves one consistent state.** A document is a row in
PostgreSQL and an object in a bucket, and there is no transaction spanning the
two. So each step that can fail gets its own test, and each asserts the same
invariant from a different angle: ``status == stored`` is never true unless the
object is genuinely there, and nothing is left in the bucket that no row points
at. The failure injection is deliberately placed at every step -- validation,
insert, seal, upload, completion -- because "we tested the failure path" usually
means one of them.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any
from uuid import UUID

import pytest
from sqlalchemy import insert, text, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.models import Document as DocumentRow
from app.db.models import Tenant
from app.documents.models import DocumentStatus
from app.documents.repository import SqlAlchemyDocumentRepository
from app.documents.service import DocumentService
from app.documents.storage.fakes import FakeDocumentStore
from app.domain.errors import (
    DocumentEncryptionError,
    DocumentInvalidError,
    DocumentNotFoundError,
    DocumentStorageUnavailableError,
    DocumentTooLargeError,
)
from tests.fixtures.documents import (
    MAX_BYTES,
    OTHER_TENANT,
    TENANT,
    USER,
    collect,
    make_cipher,
    stream,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from app.documents.models import Document

CHUNK = 4_096
PDF_HEAD = b"%PDF-1.7\n"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
class RecordingStore(FakeDocumentStore):
    """A store that timestamps its writes against a shared event log.

    The log is what makes streaming observable: an implementation that buffers
    produces every ``produced`` event before the first ``stored`` one.
    """

    def __init__(self, log: list[str]) -> None:
        super().__init__()
        self._log = log

    async def put(
        self, *, key: str, chunks: AsyncIterator[bytes], content_type: str | None = None
    ) -> int:
        async def logged() -> AsyncIterator[bytes]:
            async for block in chunks:
                self._log.append("stored")
                yield block

        return await super().put(key=key, chunks=logged(), content_type=content_type)


@pytest.fixture
def log() -> list[str]:
    return []


@pytest.fixture
def store(log: list[str]) -> RecordingStore:
    return RecordingStore(log)


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

    scope.engine = engine  # type: ignore[attr-defined]
    yield scope
    await engine.dispose()


@pytest.fixture
def service(
    store: RecordingStore,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> DocumentService:
    return DocumentService(
        store=store,
        cipher=make_cipher(chunk_bytes=CHUNK),
        session_scope=session_scope,
        max_document_bytes=MAX_BYTES,
    )


async def rows(
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> list[tuple[Any, ...]]:
    async with session_scope() as session:
        result = await session.execute(
            text("SELECT id, status, byte_size, sha256_hex FROM documents")
        )
        return [tuple(row) for row in result.all()]


async def force_status(
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    *,
    document_id: UUID,
    status: DocumentStatus,
) -> None:
    """Put a row into a state only a crash could produce.

    Goes through the ORM rather than raw SQL on purpose: SQLite stores a UUID
    column as undashed hex, so a hand-written ``WHERE id = :id`` bound to
    ``str(uuid)`` matches nothing and updates nothing -- which is exactly how
    the first version of these two tests passed for the wrong reason.
    """
    async with session_scope() as session:
        await session.execute(
            update(DocumentRow).where(DocumentRow.id == document_id).values(status=str(status))
        )
        await session.commit()


async def upload(
    service: DocumentService,
    *,
    body: bytes,
    filename: str = "report.pdf",
    declared_length: int | None = None,
    source: AsyncIterator[bytes] | None = None,
) -> Document:
    return await service.store(
        tenant_id=TENANT,
        user_id=USER,
        filename=filename,
        declared_content_type="application/pdf",
        declared_length=len(body) if declared_length is None else declared_length,
        source=source if source is not None else stream(body),
    )


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------
class TestStreaming:
    async def test_the_body_is_stored_while_it_is_still_being_produced(
        self, service: DocumentService, log: list[str]
    ) -> None:
        # Arrange -- a source that announces each block as it hands it over.
        blocks = 12

        async def source() -> AsyncIterator[bytes]:
            yield PDF_HEAD
            for _ in range(blocks):
                log.append("produced")
                yield b"A" * CHUNK

        # Act
        await upload(service, body=PDF_HEAD, source=source(), declared_length=None)

        # Assert -- interleaved, not two phases. A buffering implementation
        # produces the whole document before storing any of it, so its log is
        # every "produced" followed by every "stored".
        assert log.count("produced") == blocks
        assert log.count("stored") > 1
        buffered = ["produced"] * blocks + ["stored"] * log.count("stored")
        assert log != buffered
        assert log.index("stored") < blocks

    async def test_the_source_is_never_more_than_two_chunks_ahead_of_the_store(
        self, service: DocumentService, log: list[str]
    ) -> None:
        # Arrange -- the precise version of the property above. The cipher holds
        # one chunk back so it can mark the last one final; anything beyond that
        # is buffering.
        async def source() -> AsyncIterator[bytes]:
            yield PDF_HEAD
            for _ in range(20):
                log.append("produced")
                yield b"B" * CHUNK

        # Act
        await upload(service, body=PDF_HEAD, source=source(), declared_length=None)

        # Assert
        lead = 0
        worst = 0
        for event in log:
            lead += 1 if event == "produced" else -1
            worst = max(worst, lead)
        assert worst <= 3, f"source ran {worst} chunks ahead of the store"

    async def test_the_object_arrives_in_many_pieces(
        self, service: DocumentService, store: RecordingStore
    ) -> None:
        body = PDF_HEAD + b"C" * (CHUNK * 6)

        await upload(service, body=body)

        sizes = store.put_chunk_sizes[0]
        assert len(sizes) > 6
        # Header plus sealed frames. No piece is the whole document.
        assert max(sizes) < len(body)

    async def test_the_download_arrives_in_many_pieces(self, service: DocumentService) -> None:
        body = PDF_HEAD + b"D" * (CHUNK * 6)
        stored = await upload(service, body=body)

        _, chunks = await service.open(
            tenant_id=TENANT, user_id=USER, document_id=stored.metadata.id
        )
        pieces = [len(block) async for block in chunks]

        assert len(pieces) > 1
        assert sum(pieces) == len(body)
        assert max(pieces) <= CHUNK

    async def test_an_oversized_body_is_refused_before_it_is_fully_read(
        self,
        store: RecordingStore,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        # Arrange -- a limit far below what the source is willing to produce.
        # Reading to the end before checking would mean a client could pin
        # memory simply by refusing to stop sending.
        small = DocumentService(
            store=store,
            cipher=make_cipher(chunk_bytes=CHUNK),
            session_scope=session_scope,
            max_document_bytes=CHUNK * 4,
        )
        produced = 0

        async def endless() -> AsyncIterator[bytes]:
            nonlocal produced
            yield PDF_HEAD
            while True:
                produced += 1
                yield b"E" * CHUNK

        # Act
        with pytest.raises(DocumentTooLargeError):
            await upload(small, body=PDF_HEAD, source=endless(), declared_length=None)

        # Assert -- stopped near the limit, not after some unbounded read.
        assert produced <= 8
        assert store.stored_keys() == []


# ---------------------------------------------------------------------------
# Cancellation -- a client that hangs up part-way
# ---------------------------------------------------------------------------
class TestCancellation:
    async def test_a_cancelled_upload_stores_nothing(
        self,
        service: DocumentService,
        store: RecordingStore,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        # Arrange -- a client that disconnects mid-upload arrives here as task
        # cancellation, which is a BaseException. Cleanup written for `except
        # Exception` would skip it and leave a receiving row and a part-written
        # object behind on every dropped connection.
        started = asyncio.Event()

        async def stalling() -> AsyncIterator[bytes]:
            yield PDF_HEAD + b"F" * CHUNK
            started.set()
            await asyncio.sleep(60)
            yield b"never"

        task = asyncio.create_task(
            upload(service, body=PDF_HEAD, source=stalling(), declared_length=None)
        )
        await asyncio.wait_for(started.wait(), timeout=10)

        # Act
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # Assert -- nothing published, and the write was abandoned.
        assert store.stored_keys() == []
        assert len(store.aborted_keys) == 1

    async def test_a_cancelled_upload_leaves_a_failed_row(
        self,
        service: DocumentService,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        # Arrange
        started = asyncio.Event()

        async def stalling() -> AsyncIterator[bytes]:
            yield PDF_HEAD + b"G" * CHUNK
            started.set()
            await asyncio.sleep(60)
            yield b"never"

        task = asyncio.create_task(
            upload(service, body=PDF_HEAD, source=stalling(), declared_length=None)
        )
        await asyncio.wait_for(started.wait(), timeout=10)

        # Act
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # Assert -- visible as failed rather than stuck in receiving forever.
        # A row that never leaves receiving is indistinguishable from one still
        # in flight, so nothing can ever safely reap it.
        recorded = await rows(session_scope)
        assert [row[1] for row in recorded] == [str(DocumentStatus.FAILED)]

    async def test_abandoning_a_download_part_way_is_clean(self, service: DocumentService) -> None:
        # Arrange
        body = PDF_HEAD + b"H" * (CHUNK * 6)
        stored = await upload(service, body=body)
        _, chunks = await service.open(
            tenant_id=TENANT, user_id=USER, document_id=stored.metadata.id
        )

        # Act -- one chunk, then hang up.
        first = await anext(chunks)
        await chunks.aclose()

        # Assert -- the document is untouched and still readable in full. A
        # download that mutated state would show up here.
        assert len(first) > 0
        _, again = await service.open(
            tenant_id=TENANT, user_id=USER, document_id=stored.metadata.id
        )
        assert await collect(again) == body


# ---------------------------------------------------------------------------
# Consistency at every failure boundary
# ---------------------------------------------------------------------------
class TestConsistency:
    async def test_a_validation_failure_leaves_no_row_and_no_object(
        self,
        service: DocumentService,
        store: RecordingStore,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        # Validation is pure and runs first, so a rejected request creates no
        # state anywhere -- not even a failed row to clean up later.
        with pytest.raises(DocumentInvalidError):
            await upload(service, body=PDF_HEAD, filename="../../etc/passwd.pdf")

        assert await rows(session_scope) == []
        assert store.stored_keys() == []

    async def test_an_empty_body_leaves_a_failed_row_and_no_object(
        self,
        service: DocumentService,
        store: RecordingStore,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        # Emptiness is only knowable after reading, which is after the row
        # exists. The row must therefore end up failed, not receiving.
        with pytest.raises(DocumentInvalidError):
            await upload(service, body=b"", declared_length=0)

        assert [row[1] for row in await rows(session_scope)] == [str(DocumentStatus.FAILED)]
        assert store.stored_keys() == []

    async def test_an_insert_failure_never_reaches_the_object_store(
        self,
        service: DocumentService,
        store: RecordingStore,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The row is written first on purpose: a database that refuses the
        # insert must not leave an object nothing points at.
        async def refuse(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("insert refused")

        monkeypatch.setattr(SqlAlchemyDocumentRepository, "create", refuse)

        with pytest.raises(RuntimeError, match="insert refused"):
            await upload(service, body=PDF_HEAD)

        assert store.stored_keys() == []

    async def test_a_seal_failure_leaves_a_failed_row_and_no_object(
        self,
        store: RecordingStore,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        # Arrange -- a cipher whose stream dies after the header.
        class BrokenCipher:
            def __init__(self) -> None:
                self._real = make_cipher(chunk_bytes=CHUNK)

            def seal_bytes(self, **kwargs: Any) -> bytes:
                return self._real.seal_bytes(**kwargs)

            async def seal_stream(self, **_kwargs: Any) -> AsyncIterator[bytes]:
                yield b"SGWD"
                raise DocumentEncryptionError(log_context={"reason": "test"})

        broken = DocumentService(
            store=store,
            cipher=BrokenCipher(),  # type: ignore[arg-type]
            session_scope=session_scope,
            max_document_bytes=MAX_BYTES,
        )

        # Act
        with pytest.raises(DocumentEncryptionError):
            await upload(broken, body=PDF_HEAD)

        # Assert
        assert [row[1] for row in await rows(session_scope)] == [str(DocumentStatus.FAILED)]
        assert store.stored_keys() == []

    async def test_an_upload_failure_leaves_a_failed_row_and_no_object(
        self,
        service: DocumentService,
        store: RecordingStore,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        store.simulate_failure(DocumentStorageUnavailableError(log_context={"reason": "test"}))

        with pytest.raises(DocumentStorageUnavailableError):
            await upload(service, body=PDF_HEAD)

        recorded = await rows(session_scope)
        assert [row[1] for row in recorded] == [str(DocumentStatus.FAILED)]
        # The size and checksum stay at their insert-time defaults, because
        # nothing was ever measured to completion.
        assert recorded[0][2] == 0
        assert recorded[0][3] == ""

    async def test_a_completion_failure_never_reports_stored(
        self,
        service: DocumentService,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The last step is the one that flips the row to stored. If it fails,
        # the caller must get an error rather than a success for a document
        # nothing will admit is stored.
        async def refuse(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("update refused")

        monkeypatch.setattr(SqlAlchemyDocumentRepository, "mark_stored", refuse)

        with pytest.raises(RuntimeError, match="update refused"):
            await upload(service, body=PDF_HEAD)

        assert [row[1] for row in await rows(session_scope)] != [str(DocumentStatus.STORED)]

    async def test_a_receiving_document_cannot_be_downloaded(
        self,
        service: DocumentService,
        store: RecordingStore,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        # Arrange -- a row stuck in receiving, as a crash between insert and
        # completion would leave it.
        stored = await upload(service, body=PDF_HEAD)
        await force_status(
            session_scope, document_id=stored.metadata.id, status=DocumentStatus.RECEIVING
        )
        assert [row[1] for row in await rows(session_scope)] == [str(DocumentStatus.RECEIVING)]

        # Act / Assert -- reported missing rather than served as a 200 that
        # dies mid-stream.
        with pytest.raises(DocumentNotFoundError):
            await service.open(tenant_id=TENANT, user_id=USER, document_id=stored.metadata.id)

    async def test_a_failed_document_cannot_be_downloaded(
        self,
        service: DocumentService,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        stored = await upload(service, body=PDF_HEAD)
        await force_status(
            session_scope, document_id=stored.metadata.id, status=DocumentStatus.FAILED
        )
        assert [row[1] for row in await rows(session_scope)] == [str(DocumentStatus.FAILED)]

        with pytest.raises(DocumentNotFoundError):
            await service.open(tenant_id=TENANT, user_id=USER, document_id=stored.metadata.id)

    async def test_status_never_says_stored_for_a_document_with_no_object(
        self,
        service: DocumentService,
        store: RecordingStore,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        # The central invariant, stated directly: across every failure the
        # suite can inject, no row ends up claiming `stored` without an object.
        store.simulate_failure(DocumentStorageUnavailableError(log_context={"reason": "test"}))
        with pytest.raises(DocumentStorageUnavailableError):
            await upload(service, body=PDF_HEAD)
        store.simulate_failure(None)

        for row in await rows(session_scope):
            assert row[1] != str(DocumentStatus.STORED)
        assert store.stored_keys() == []

    async def test_a_failed_object_delete_keeps_the_row(
        self,
        service: DocumentService,
        store: RecordingStore,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        # Arrange -- deletion removes the object first. If that fails, the row
        # must survive: dropping it would strand bytes in the bucket that
        # nothing points at and nothing can ever delete.
        stored = await upload(service, body=PDF_HEAD)
        store.simulate_failure(DocumentStorageUnavailableError(log_context={"reason": "test"}))

        # Act
        with pytest.raises(DocumentStorageUnavailableError):
            await service.delete(tenant_id=TENANT, user_id=USER, document_id=stored.metadata.id)

        # Assert -- still one row, still pointing at the object, so a retry
        # deletes both.
        store.simulate_failure(None)
        assert len(await rows(session_scope)) == 1
        assert await service.delete(tenant_id=TENANT, user_id=USER, document_id=stored.metadata.id)
        assert await rows(session_scope) == []
        assert store.stored_keys() == []

    async def test_deleting_is_idempotent(self, service: DocumentService) -> None:
        stored = await upload(service, body=PDF_HEAD)

        first = await service.delete(tenant_id=TENANT, user_id=USER, document_id=stored.metadata.id)
        second = await service.delete(
            tenant_id=TENANT, user_id=USER, document_id=stored.metadata.id
        )

        assert (first, second) == (True, False)

    async def test_a_stored_document_matches_its_recorded_size_and_checksum(
        self,
        service: DocumentService,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        import hashlib

        body = PDF_HEAD + b"I" * (CHUNK * 3 + 11)

        stored = await upload(service, body=body)

        recorded = await rows(session_scope)
        assert recorded[0][1] == str(DocumentStatus.STORED)
        assert recorded[0][2] == len(body)
        assert recorded[0][3] == hashlib.sha256(body).hexdigest()
        assert stored.metadata.byte_size == len(body)

    async def test_concurrent_uploads_stay_independent(
        self,
        service: DocumentService,
        store: RecordingStore,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        # Arrange -- one of them fails. The other must be unaffected: a shared
        # buffer or a shared counter between requests would show up as a wrong
        # size, a wrong checksum, or a missing object.
        good = PDF_HEAD + b"J" * CHUNK

        async def failing() -> Document:
            with pytest.raises(DocumentInvalidError):
                await upload(service, body=b"", declared_length=0)
            raise DocumentInvalidError(log_context={"reason": "expected"})

        results = await asyncio.gather(
            upload(service, body=good),
            upload(service, body=good),
            failing(),
            return_exceptions=True,
        )

        succeeded = [result for result in results if not isinstance(result, BaseException)]
        assert len(succeeded) == 2
        assert len({document.metadata.storage_key for document in succeeded}) == 2
        stored_rows = [row for row in await rows(session_scope) if row[1] == "stored"]
        assert len(stored_rows) == 2
        assert all(row[2] == len(good) for row in stored_rows)


# ---------------------------------------------------------------------------
# Identifiers
# ---------------------------------------------------------------------------
class TestStorageKeys:
    async def test_a_storage_key_names_nothing(self, service: DocumentService) -> None:
        stored = await upload(service, body=PDF_HEAD, filename="Marguerite oncology summary.pdf")

        key = stored.metadata.storage_key
        assert "marguerite" not in key.lower()
        assert "oncology" not in key.lower()
        assert str(TENANT) not in key
        assert str(USER) not in key
        assert str(stored.metadata.id) not in key
        assert not key.endswith(".pdf")

    async def test_storage_keys_are_not_sequential(self, service: DocumentService) -> None:
        # A predictable key would let anyone with bucket read access enumerate
        # every document, which is the one thing opaque naming is for.
        keys = [(await upload(service, body=PDF_HEAD)).metadata.storage_key for _ in range(8)]

        assert len(set(keys)) == len(keys)
        assert keys != sorted(keys)


def test_uuids_used_by_this_module_are_distinct() -> None:
    # Cheap guard: a copy-paste that made TENANT and OTHER_TENANT equal would
    # make every isolation assertion in this package pass vacuously.
    assert len({TENANT, OTHER_TENANT, USER}) == 3
    assert isinstance(TENANT, UUID)
