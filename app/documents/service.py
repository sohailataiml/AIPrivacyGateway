"""Secure document storage.

Order of operations is a safety property here, not a style choice:

1. Validate the filename, the type, and the declared length -- all pure, before
   any state exists anywhere.
2. Seal the filename and insert a ``receiving`` row, so a document that fails
   mid-upload is a visible failed record rather than an orphaned object.
3. Stream the body through one pass that counts bytes, hashes them, enforces the
   real length limit, and checks the magic bytes -- then seals it, then uploads
   it. The plaintext is never buffered whole and never touches disk.
4. Only once the object is complete does the row become ``stored``.

Steps 1 and 2 come first so a request destined to fail leaves nothing to clean
up. Step 4 comes last so that "the row says stored" is never true of a document
that is not actually there -- a reader must never be told to expect bytes that
were abandoned.

**What this phase does not do.** It stores documents. It does not extract text,
detect entities, tokenize, or restore. There is no status this service cannot
reach, and no column describing work it does not perform.

Nothing here logs a filename or a byte of content. Identifiers, sizes, and
counts only.
"""

from __future__ import annotations

import hashlib
from contextlib import suppress
from typing import TYPE_CHECKING, Final
from uuid import UUID, uuid4

from app.documents.crypto import PURPOSE_FILENAME, DocumentCipher, DocumentIdentity
from app.documents.models import Document, DocumentMetadata, DocumentStatus
from app.documents.repository import SqlAlchemyDocumentRepository
from app.documents.validation import (
    MAGIC_SNIFF_BYTES,
    enforce_declared_length,
    enforce_streamed_length,
    normalize_filename,
    resolve_content_type,
    verify_magic,
)
from app.domain.errors import DocumentInvalidError, DocumentNotFoundError, GatewayError
from app.observability.logging import get_logger

# The canonical opaque-id grammar, shared with the vault: random, fixed length,
# not sequential and not timestamped, as ADR-0020 requires of a storage key.
# Reused rather than reimplemented -- a second id grammar is a second thing to
# get wrong.
from app.tokenization.ids import new_token_id

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from app.db.models import Document as DocumentRow
    from app.documents.protocol import DocumentStore

logger = get_logger(__name__)

STORAGE_KEY_PREFIX: Final = "documents/"
OPAQUE_OBJECT_CONTENT_TYPE: Final = "application/octet-stream"
"""What the object store is told.

Deliberately not the real type. The store holds ciphertext and has no business
knowing whether it is a medical PDF or a spreadsheet -- that is metadata about
the content, and ADR-0020 keeps content knowledge out of the store. The
authoritative type is the database column, bound into the AAD.
"""


class DocumentService:
    """Stores, retrieves, and deletes encrypted documents."""

    __slots__ = ("_cipher", "_max_bytes", "_session_scope", "_store")

    def __init__(
        self,
        *,
        store: DocumentStore,
        cipher: DocumentCipher,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
        max_document_bytes: int,
    ) -> None:
        self._store = store
        self._cipher = cipher
        self._session_scope = session_scope
        self._max_bytes = max_document_bytes

    # -- Commands ---------------------------------------------------------
    async def store(
        self,
        *,
        tenant_id: UUID,
        user_id: UUID,
        filename: str,
        declared_content_type: str | None,
        declared_length: int | None,
        source: AsyncIterator[bytes],
    ) -> Document:
        """Validate, seal, and store one document.

        Raises:
            DocumentInvalidError: the filename or the body failed validation.
            DocumentTypeUnsupportedError: the type is not accepted.
            DocumentTooLargeError: the body exceeds the configured limit.
            DocumentStorageUnavailableError: the object store is unreachable.
            DocumentEncryptionError: the body could not be sealed.
        """
        safe_name = normalize_filename(filename)
        content_type = resolve_content_type(filename=safe_name, declared=declared_content_type)
        enforce_declared_length(declared=declared_length, limit=self._max_bytes)

        document_id = uuid4()
        storage_key = f"{STORAGE_KEY_PREFIX}{new_token_id()}"
        identity = DocumentIdentity(
            tenant_id=tenant_id,
            user_id=user_id,
            document_id=document_id,
            content_type=content_type,
        )

        filename_ciphertext = self._cipher.seal_bytes(
            identity=identity, purpose=PURPOSE_FILENAME, plaintext=safe_name.encode("utf-8")
        )

        async with self._session_scope() as session:
            await SqlAlchemyDocumentRepository(session).create(
                document_id=document_id,
                tenant_id=tenant_id,
                user_id=user_id,
                storage_key=storage_key,
                filename_ciphertext=filename_ciphertext,
                content_type=content_type,
                status=DocumentStatus.RECEIVING,
            )
            await session.commit()

        digest = hashlib.sha256()
        counter = _ByteCounter()
        try:
            measured = self._measure(
                source, content_type=content_type, digest=digest, counter=counter
            )
            await self._store.put(
                key=storage_key,
                chunks=self._cipher.seal_stream(identity=identity, plaintext=measured),
                content_type=OPAQUE_OBJECT_CONTENT_TYPE,
            )
        except BaseException:
            await self._abandon(
                document_id=document_id,
                tenant_id=tenant_id,
                user_id=user_id,
                storage_key=storage_key,
            )
            raise

        async with self._session_scope() as session:
            row = await SqlAlchemyDocumentRepository(session).mark_stored(
                document_id=document_id,
                tenant_id=tenant_id,
                user_id=user_id,
                byte_size=counter.total,
                sha256_hex=digest.hexdigest(),
            )
            await session.commit()
            if row is None:  # pragma: no cover - the row was inserted above
                raise DocumentNotFoundError(log_context={"reason": "row_vanished_during_upload"})
            metadata = _to_metadata(row)

        # Identifiers and sizes. Never the filename, never a byte of content.
        logger.info(
            "document_stored",
            tenant_id=str(tenant_id),
            document_id=str(document_id),
            content_type=content_type,
            byte_size=counter.total,
        )
        return Document(metadata=metadata, filename=safe_name)

    async def delete(self, *, tenant_id: UUID, user_id: UUID, document_id: UUID) -> bool:
        """Destroy the object and its row. Returns whether anything was removed.

        Idempotent, for the same reason session deletion is: distinguishing
        "never existed" from "already gone" would make this an oracle for which
        document ids are real, and a caller retrying after a timeout deserves
        the answer the first caller got.

        The object is deleted before the row. The other order can leave bytes in
        the bucket with nothing left pointing at them -- unreachable, undeletable,
        and still Restricted.
        """
        async with self._session_scope() as session:
            repository = SqlAlchemyDocumentRepository(session)
            row = await repository.get(
                document_id=document_id, tenant_id=tenant_id, user_id=user_id
            )
            if row is None:
                return False
            storage_key = row.storage_key

        await self._store.delete(key=storage_key)

        async with self._session_scope() as session:
            removed = await SqlAlchemyDocumentRepository(session).delete(
                document_id=document_id, tenant_id=tenant_id, user_id=user_id
            )
            await session.commit()

        logger.info(
            "document_deleted",
            tenant_id=str(tenant_id),
            document_id=str(document_id),
            removed=removed,
        )
        return removed

    # -- Queries ----------------------------------------------------------
    async def status(
        self, *, tenant_id: UUID, user_id: UUID, document_id: UUID
    ) -> DocumentMetadata:
        """Return metadata only. Touches no key and no object.

        Raises:
            DocumentNotFoundError: no such document for this principal.
        """
        async with self._session_scope() as session:
            row = await SqlAlchemyDocumentRepository(session).get(
                document_id=document_id, tenant_id=tenant_id, user_id=user_id
            )
        if row is None:
            raise DocumentNotFoundError(log_context={"reason": "no_such_document"})
        return _to_metadata(row)

    async def open(
        self, *, tenant_id: UUID, user_id: UUID, document_id: UUID
    ) -> tuple[Document, AsyncIterator[bytes]]:
        """Return the document and a stream of its plaintext.

        The metadata is resolved eagerly so a missing document fails before any
        response has begun; the body is a lazy stream so retrieval costs one
        chunk of memory rather than the whole file.

        Raises:
            DocumentNotFoundError: no such document, or it never finished
                uploading.
            DocumentEncryptionError: the stored bytes failed authentication.
        """
        async with self._session_scope() as session:
            row = await SqlAlchemyDocumentRepository(session).get(
                document_id=document_id, tenant_id=tenant_id, user_id=user_id
            )
            if row is None:
                raise DocumentNotFoundError(log_context={"reason": "no_such_document"})
            metadata = _to_metadata(row)
            storage_key = row.storage_key
            filename_ciphertext = bytes(row.filename_ciphertext)

        if metadata.status is not DocumentStatus.STORED:
            # An abandoned upload has no object behind it. Reporting it as
            # missing is honest; streaming a 200 that then fails is not.
            raise DocumentNotFoundError(log_context={"reason": "document_not_stored"})

        identity = DocumentIdentity(
            tenant_id=tenant_id,
            user_id=user_id,
            document_id=document_id,
            content_type=metadata.content_type,
        )
        filename = self._cipher.open_bytes(
            identity=identity, purpose=PURPOSE_FILENAME, raw=filename_ciphertext
        ).decode("utf-8")

        return Document(metadata=metadata, filename=filename), self._read(
            identity=identity, metadata=metadata, storage_key=storage_key
        )

    # -- Internals --------------------------------------------------------
    async def _measure(
        self,
        source: AsyncIterator[bytes],
        *,
        content_type: str,
        digest: hashlib._Hash,
        counter: _ByteCounter,
    ) -> AsyncIterator[bytes]:
        """One pass over the plaintext: count, hash, bound, and sniff.

        A single pass matters. Reading the stream twice would mean buffering it,
        and buffering a Restricted document is the thing this design avoids.
        """
        head = bytearray()
        checked = False

        async for block in source:
            counter.total += len(block)
            # Checked as it arrives, not from the declared length: a client can
            # omit or understate Content-Length, and a chunked upload has none.
            enforce_streamed_length(received=counter.total, limit=self._max_bytes)
            digest.update(block)

            if not checked:
                head += block
                if len(head) >= MAGIC_SNIFF_BYTES:
                    verify_magic(content_type=content_type, head=bytes(head))
                    checked = True

            yield block

        if counter.total == 0:
            # A zero-byte upload is a client bug, and storing one would create a
            # document that can never be extracted from.
            raise DocumentInvalidError(log_context={"reason": "document_empty"})
        if not checked:
            # Shorter than the sniff window, so it is checked at the end on
            # whatever did arrive.
            verify_magic(content_type=content_type, head=bytes(head))

    async def _read(
        self,
        *,
        identity: DocumentIdentity,
        metadata: DocumentMetadata,
        storage_key: str,
    ) -> AsyncIterator[bytes]:
        """Stream plaintext, verifying the checksum as the last act."""
        digest = hashlib.sha256()
        total = 0
        async for block in self._cipher.open_stream(
            identity=identity, ciphertext=self._store.get(key=storage_key)
        ):
            digest.update(block)
            total += len(block)
            yield block

        if total != metadata.byte_size or digest.hexdigest() != metadata.sha256_hex:
            # Every chunk already authenticated, so reaching here means the
            # database and the object disagree about which document this is.
            # Failing mid-stream truncates the response, which is the correct
            # outcome: a caller must not silently receive a different document.
            from app.domain.errors import DocumentEncryptionError

            raise DocumentEncryptionError(log_context={"reason": "checksum_mismatch"})

    async def _abandon(
        self, *, document_id: UUID, tenant_id: UUID, user_id: UUID, storage_key: str
    ) -> None:
        """Mark the row failed and remove whatever reached the store.

        Best effort by design: the caller is already raising, and a cleanup
        failure must not replace the original error with a less useful one.
        """
        with suppress(Exception):
            await self._store.delete(key=storage_key)
        try:
            async with self._session_scope() as session:
                await SqlAlchemyDocumentRepository(session).mark_failed(
                    document_id=document_id, tenant_id=tenant_id, user_id=user_id
                )
                await session.commit()
        except Exception:  # pragma: no cover - defensive
            logger.warning("document_failure_not_recorded", document_id=str(document_id))

    async def aclose(self) -> None:
        """Release the store's client, if it holds one.

        The Protocol does not require a store to be closeable -- the in-memory
        fake is not -- so this asks rather than assumes.
        """
        closer = getattr(self._store, "aclose", None)
        if closer is not None:
            await closer()

    async def health(self) -> None:
        """Raise unless object storage is usable. Used by readiness."""
        await self._store.health()

    def __repr__(self) -> str:
        return f"DocumentService(max_document_bytes={self._max_bytes})"


class _ByteCounter:
    """A mutable total, so the streaming pass can report back to its caller."""

    __slots__ = ("total",)

    def __init__(self) -> None:
        self.total = 0


def _to_metadata(row: DocumentRow) -> DocumentMetadata:
    return DocumentMetadata(
        id=row.id,
        tenant_id=row.tenant_id,
        user_id=row.user_id,
        storage_key=row.storage_key,
        content_type=row.content_type,
        byte_size=row.byte_size,
        sha256_hex=row.sha256_hex,
        status=DocumentStatus(row.status),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


__all__ = ["OPAQUE_OBJECT_CONTENT_TYPE", "STORAGE_KEY_PREFIX", "DocumentService", "GatewayError"]
