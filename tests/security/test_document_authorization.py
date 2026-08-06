"""Who can reach a stored document, and what happens when they cannot.

The gateway defends a document twice, and this file tests both layers on
purpose.

The **first** defence is the query: every repository method puts ``tenant_id``
and ``user_id`` in the WHERE clause, so a document id belonging to someone else
simply is not there. The **second** is the ciphertext: even a row fetched in
error decrypts under an identity that includes tenant, user, and document, so a
mistake in the first layer produces an authentication failure rather than
plaintext.

Testing only the first layer would be the common mistake. A query filter is one
forgotten argument away from wrong, and a suite that never checks what happens
after such a mistake cannot tell the difference between "correctly scoped" and
"scoped by luck". The tests at the end of this file deliberately bypass the
query and hand the service another principal's bytes.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import pytest
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.models import Tenant
from app.documents.models import DocumentStatus
from app.documents.service import DocumentService
from app.documents.storage.fakes import FakeDocumentStore
from app.domain.errors import DocumentEncryptionError, DocumentNotFoundError
from tests.fixtures.documents import (
    CANARIES,
    CANARY_PDF,
    MAX_BYTES,
    OTHER_TENANT,
    OTHER_USER,
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

pytestmark = pytest.mark.security

FILENAME = CANARIES["filename"]


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
def service(
    store: FakeDocumentStore,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> DocumentService:
    return DocumentService(
        store=store,
        cipher=make_cipher(chunk_bytes=64),
        session_scope=session_scope,
        max_document_bytes=MAX_BYTES,
    )


async def upload(
    service: DocumentService,
    *,
    tenant_id: UUID = TENANT,
    user_id: UUID = USER,
    body: bytes = CANARY_PDF,
) -> Document:
    return await service.store(
        tenant_id=tenant_id,
        user_id=user_id,
        filename=FILENAME,
        declared_content_type="application/pdf",
        declared_length=len(body),
        source=stream(body),
    )


# ---------------------------------------------------------------------------
# The owner
# ---------------------------------------------------------------------------
class TestTheOwner:
    async def test_the_uploading_principal_can_read_it_back(self, service: DocumentService) -> None:
        stored = await upload(service)

        document, chunks = await service.open(
            tenant_id=TENANT, user_id=USER, document_id=stored.metadata.id
        )

        assert await collect(chunks) == CANARY_PDF
        assert document.filename == FILENAME

    async def test_the_owner_can_read_its_status(self, service: DocumentService) -> None:
        stored = await upload(service)

        metadata = await service.status(
            tenant_id=TENANT, user_id=USER, document_id=stored.metadata.id
        )

        assert metadata.status is DocumentStatus.STORED

    async def test_the_owner_can_delete_it(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        stored = await upload(service)

        assert await service.delete(tenant_id=TENANT, user_id=USER, document_id=stored.metadata.id)
        assert store.stored_keys() == []


# ---------------------------------------------------------------------------
# Everyone else
# ---------------------------------------------------------------------------
class TestEveryoneElse:
    @pytest.fixture
    async def stored(self, service: DocumentService) -> Document:
        return await upload(service)

    @pytest.mark.parametrize(
        ("tenant_id", "user_id"),
        [
            (TENANT, OTHER_USER),
            (OTHER_TENANT, USER),
            (OTHER_TENANT, OTHER_USER),
        ],
        ids=["same-tenant-other-user", "other-tenant-same-user", "other-tenant-other-user"],
    )
    async def test_no_one_else_can_download_it(
        self,
        service: DocumentService,
        stored: Document,
        tenant_id: UUID,
        user_id: UUID,
    ) -> None:
        with pytest.raises(DocumentNotFoundError):
            await service.open(tenant_id=tenant_id, user_id=user_id, document_id=stored.metadata.id)

    @pytest.mark.parametrize(
        ("tenant_id", "user_id"),
        [(TENANT, OTHER_USER), (OTHER_TENANT, USER), (OTHER_TENANT, OTHER_USER)],
        ids=["same-tenant-other-user", "other-tenant-same-user", "other-tenant-other-user"],
    )
    async def test_no_one_else_can_read_its_status(
        self,
        service: DocumentService,
        stored: Document,
        tenant_id: UUID,
        user_id: UUID,
    ) -> None:
        with pytest.raises(DocumentNotFoundError):
            await service.status(
                tenant_id=tenant_id, user_id=user_id, document_id=stored.metadata.id
            )

    @pytest.mark.parametrize(
        ("tenant_id", "user_id"),
        [(TENANT, OTHER_USER), (OTHER_TENANT, USER)],
        ids=["same-tenant-other-user", "other-tenant-same-user"],
    )
    async def test_no_one_else_can_delete_it(
        self,
        service: DocumentService,
        store: FakeDocumentStore,
        stored: Document,
        tenant_id: UUID,
        user_id: UUID,
    ) -> None:
        # Answers "nothing removed" rather than "forbidden": a different answer
        # would confirm that the id exists.
        removed = await service.delete(
            tenant_id=tenant_id, user_id=user_id, document_id=stored.metadata.id
        )

        assert removed is False
        assert len(store.stored_keys()) == 1

    async def test_an_unknown_id_is_the_same_answer_as_someone_elses(
        self, service: DocumentService, stored: Document
    ) -> None:
        # Both are DocumentNotFoundError, so the API cannot be used to
        # enumerate which document ids are real.
        with pytest.raises(DocumentNotFoundError):
            await service.status(tenant_id=TENANT, user_id=USER, document_id=uuid4())
        with pytest.raises(DocumentNotFoundError):
            await service.status(
                tenant_id=OTHER_TENANT, user_id=OTHER_USER, document_id=stored.metadata.id
            )

    async def test_a_refusal_carries_no_canary(
        self, service: DocumentService, stored: Document
    ) -> None:
        with pytest.raises(DocumentNotFoundError) as caught:
            await service.open(
                tenant_id=OTHER_TENANT, user_id=OTHER_USER, document_id=stored.metadata.id
            )

        rendered = f"{caught.value!r} {caught.value.log_context}"
        for canary in CANARIES.values():
            assert canary not in rendered


# ---------------------------------------------------------------------------
# When the query layer is wrong anyway
# ---------------------------------------------------------------------------
class TestCryptographyBacksUpTheQuery:
    async def test_an_object_copied_under_another_key_does_not_open(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        # Arrange -- the victim's bytes are moved onto the attacker's own
        # document, which is the strongest form of the attack: the attacker
        # owns the row, so every WHERE clause is satisfied.
        victim = await upload(service)
        attacker = await upload(
            service, tenant_id=OTHER_TENANT, user_id=OTHER_USER, body=b"%PDF-1.7\nmine\n"
        )
        victim_bytes = store.stored_bytes(victim.metadata.storage_key)

        async def victims_bytes(*, key: str) -> AsyncIterator[bytes]:
            yield victim_bytes

        # Act -- swap what the store returns for the attacker's key.
        store.get = victims_bytes  # type: ignore[method-assign]

        _, chunks = await service.open(
            tenant_id=OTHER_TENANT, user_id=OTHER_USER, document_id=attacker.metadata.id
        )

        # Assert -- the AAD names the tenant, the user, and the document, so
        # none of the three match and nothing decrypts.
        with pytest.raises(DocumentEncryptionError):
            await collect(chunks)

    async def test_no_plaintext_is_emitted_before_the_refusal(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        victim = await upload(service)
        attacker = await upload(
            service, tenant_id=OTHER_TENANT, user_id=OTHER_USER, body=b"%PDF-1.7\nmine\n"
        )
        victim_bytes = store.stored_bytes(victim.metadata.storage_key)

        async def victims_bytes(*, key: str) -> AsyncIterator[bytes]:
            yield victim_bytes

        store.get = victims_bytes  # type: ignore[method-assign]
        _, chunks = await service.open(
            tenant_id=OTHER_TENANT, user_id=OTHER_USER, document_id=attacker.metadata.id
        )

        seen = bytearray()
        with pytest.raises(DocumentEncryptionError):
            async for block in chunks:
                seen += block

        assert bytes(seen) == b""
        for canary in CANARIES.values():
            assert canary.encode("utf-8") not in bytes(seen)

    async def test_two_principals_uploading_the_same_bytes_share_nothing(
        self, service: DocumentService, store: FakeDocumentStore
    ) -> None:
        # Identical input, different owners. Identical stored bytes would let
        # an operator with bucket access correlate them without decrypting.
        mine = await upload(service)
        theirs = await upload(service, tenant_id=OTHER_TENANT, user_id=OTHER_USER)

        assert store.stored_bytes(mine.metadata.storage_key) != store.stored_bytes(
            theirs.metadata.storage_key
        )
        assert mine.metadata.storage_key != theirs.metadata.storage_key
