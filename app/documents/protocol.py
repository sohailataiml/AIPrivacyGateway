"""The object-storage seam.

Every consumer -- the document service, the API, the readiness probe -- depends
on this Protocol and never on ``S3CompatibleDocumentStore``. Three properties
are contractual:

1. **The store handles ciphertext only.** Encryption happens above this seam, in
   ``app.documents.crypto``. An implementation that decrypted, inspected, or
   transformed the bytes would be violating ADR-0020 by making the store
   something that can read documents.
2. **Both directions stream.** ``put`` consumes an async iterator and ``get``
   produces one, so neither side ever requires the whole document in memory.
   An implementation that buffers internally has defeated the point.
3. **Failure is closed.** An implementation that cannot reach its backing store
   raises ``DocumentStorageUnavailableError``; it never returns empty bytes or a
   short object that a caller could read as "the document is fine".

The keys handed to this seam are opaque (ADR-0020): they carry no tenant, user,
or filename, so a leaked key names nothing and grants nothing on its own.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@runtime_checkable
class DocumentStore(Protocol):
    """Stores and retrieves opaque byte streams under opaque keys."""

    async def put(
        self,
        *,
        key: str,
        chunks: AsyncIterator[bytes],
        content_type: str | None = None,
    ) -> int:
        """Write ``chunks`` under ``key`` and return the bytes stored.

        The write is not observable until it completes: a reader must never see
        a partially written object. An implementation that fails part-way
        removes whatever it began.

        ``content_type`` is metadata for the store's own bookkeeping and is
        never trusted on the way back out -- the authoritative type lives in the
        database and is bound into the ciphertext's associated data.

        Raises:
            DocumentStorageUnavailableError: the backing store is unreachable.
        """
        ...

    def get(self, *, key: str) -> AsyncIterator[bytes]:
        """Yield the stored bytes in order.

        Returns an async iterator rather than being one, so that a missing
        object raises when the caller starts reading rather than at some
        arbitrary later point.

        Raises:
            DocumentNotFoundError: no object exists under ``key``.
            DocumentStorageUnavailableError: the backing store is unreachable.
        """
        ...

    async def delete(self, *, key: str) -> None:
        """Remove the object under ``key``.

        Deleting an absent object is not an error: a caller retrying after a
        timeout deserves the same answer as the one who succeeded, and "the
        object is gone" is true either way.

        Raises:
            DocumentStorageUnavailableError: the backing store is unreachable.
        """
        ...

    async def health(self) -> None:
        """Raise unless the store is reachable and the bucket is usable.

        Called by readiness. A store that answers "healthy" without touching
        the bucket would let a deployment pass readiness and fail every upload.

        Raises:
            DocumentStorageUnavailableError: the store is not usable.
        """
        ...


__all__ = ["DocumentStore"]
