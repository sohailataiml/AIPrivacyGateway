"""Document metadata repository.

Every method takes ``tenant_id`` *and* ``user_id`` and puts both in the WHERE
clause. There is deliberately no ``get(document_id)``: a lookup by id alone
would be one forgotten argument away from a cross-tenant read, and ADR-0021's
whole premise is that a document id is not a credential.

That said, this layer is the *first* of two defences, not the only one. Even if
a query here were wrong, the ciphertext is bound to the tenant, user, and
document (``app.documents.crypto``), so a row fetched for the wrong principal
still fails to decrypt. The database check keeps honest callers correct; the
cryptography keeps a bug from becoming a breach.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, cast
from uuid import UUID

from sqlalchemy import delete, select, update

from app.db.models import Document

if TYPE_CHECKING:
    from sqlalchemy import CursorResult
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.documents.models import DocumentStatus


class DocumentRepository(Protocol):
    """Tenant- and user-scoped access to document metadata."""

    async def create(
        self,
        *,
        document_id: UUID,
        tenant_id: UUID,
        user_id: UUID,
        storage_key: str,
        filename_ciphertext: bytes,
        content_type: str,
        status: DocumentStatus,
    ) -> Document:
        """Insert a row before the object exists, in ``receiving`` status."""
        ...

    async def mark_stored(
        self,
        *,
        document_id: UUID,
        tenant_id: UUID,
        user_id: UUID,
        byte_size: int,
        sha256_hex: str,
    ) -> Document | None:
        """Record a completed upload. Returns ``None`` if the row is not there."""
        ...

    async def mark_failed(self, *, document_id: UUID, tenant_id: UUID, user_id: UUID) -> None: ...

    async def get(self, *, document_id: UUID, tenant_id: UUID, user_id: UUID) -> Document | None:
        """Return the document, or ``None`` if this principal cannot see it."""
        ...

    async def delete(self, *, document_id: UUID, tenant_id: UUID, user_id: UUID) -> bool:
        """Remove the row. Returns whether one was removed."""
        ...


class SqlAlchemyDocumentRepository:
    """``DocumentRepository`` backed by an async SQLAlchemy session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        document_id: UUID,
        tenant_id: UUID,
        user_id: UUID,
        storage_key: str,
        filename_ciphertext: bytes,
        content_type: str,
        status: DocumentStatus,
    ) -> Document:
        document = Document(
            id=document_id,
            tenant_id=tenant_id,
            user_id=user_id,
            storage_key=storage_key,
            filename_ciphertext=filename_ciphertext,
            content_type=content_type,
            byte_size=0,
            sha256_hex="",
            status=str(status),
        )
        self._session.add(document)
        await self._session.flush()
        return document

    async def mark_stored(
        self,
        *,
        document_id: UUID,
        tenant_id: UUID,
        user_id: UUID,
        byte_size: int,
        sha256_hex: str,
    ) -> Document | None:
        from app.documents.models import DocumentStatus as Status

        await self._session.execute(
            update(Document)
            .where(
                Document.id == document_id,
                Document.tenant_id == tenant_id,
                Document.user_id == user_id,
            )
            .values(byte_size=byte_size, sha256_hex=sha256_hex, status=str(Status.STORED))
        )
        await self._session.flush()
        return await self.get(document_id=document_id, tenant_id=tenant_id, user_id=user_id)

    async def mark_failed(self, *, document_id: UUID, tenant_id: UUID, user_id: UUID) -> None:
        from app.documents.models import DocumentStatus as Status

        await self._session.execute(
            update(Document)
            .where(
                Document.id == document_id,
                Document.tenant_id == tenant_id,
                Document.user_id == user_id,
            )
            .values(status=str(Status.FAILED))
        )
        await self._session.flush()

    async def get(self, *, document_id: UUID, tenant_id: UUID, user_id: UUID) -> Document | None:
        result = await self._session.execute(
            select(Document).where(
                Document.id == document_id,
                Document.tenant_id == tenant_id,
                Document.user_id == user_id,
            )
        )
        return result.scalar_one_or_none()

    async def delete(self, *, document_id: UUID, tenant_id: UUID, user_id: UUID) -> bool:
        result = await self._session.execute(
            delete(Document).where(
                Document.id == document_id,
                Document.tenant_id == tenant_id,
                Document.user_id == user_id,
            )
        )
        await self._session.flush()
        # CursorResult carries rowcount; the base Result type does not declare it.
        return bool(cast("CursorResult[Any]", result).rowcount)


__all__ = ["DocumentRepository", "SqlAlchemyDocumentRepository"]
