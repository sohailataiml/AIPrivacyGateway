"""From a stored document to segments a detector can run over.

Three steps, in one place: open and decrypt (Phase 1), extract (subprocess),
segment. Each is behind a seam, so the isolation strategy, the parsers, and the
boundary rules can each be replaced without the others noticing.

**Extraction cannot stream, and this is the one place that admits it.** Storage
streams end to end -- a 25 MiB upload costs one chunk of memory. A PDF parser
needs random access to the whole file: the cross-reference table is at the end
and points backwards. So the bytes are buffered here, bounded by the same
``MAX_DOCUMENT_BYTES`` that bounded the upload, and the buffer is the reason
extraction runs in another process rather than this one.

**Nothing here is retained.** ``docs/data-classification.md`` classes extracted
text as Restricted with "prefer none" storage, and this module honours that
literally: no row, no object, no temporary file. The segments exist for the life
of one call. That is also why Phase 2 adds no ``DocumentStatus`` member -- there
is no persisted state for a status to describe, and a status the system cannot
reach is a lie told to whoever polls for it.

Nothing here logs a filename or a byte of content. Identifiers and counts only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from app.documents.segmentation import Segmenter
from app.domain.errors import DocumentTooLargeError
from app.observability.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from uuid import UUID

    from app.documents.extraction.runner import ExtractionRunner
    from app.documents.models import Document
    from app.documents.segmentation import SegmentedDocument

logger = get_logger(__name__)


class DocumentSource(Protocol):
    """The narrow slice of document storage this module needs.

    Deliberately not ``DocumentService``: extraction needs to open a document
    and nothing else, and depending on the whole service would let it grow a
    dependency on storing or deleting one.
    """

    async def open(
        self, *, tenant_id: UUID, user_id: UUID, document_id: UUID
    ) -> tuple[Document, AsyncIterator[bytes]]:
        """Return the document and a stream of its plaintext."""
        ...


class DocumentProcessor:
    """Opens, extracts, and segments a stored document."""

    __slots__ = ("_max_bytes", "_runner", "_segmenter", "_source")

    def __init__(
        self,
        *,
        source: DocumentSource,
        runner: ExtractionRunner,
        segmenter: Segmenter | None = None,
        max_document_bytes: int,
    ) -> None:
        self._source = source
        self._runner = runner
        self._segmenter = segmenter if segmenter is not None else Segmenter()
        self._max_bytes = max_document_bytes

    async def segment(
        self, *, tenant_id: UUID, user_id: UUID, document_id: UUID
    ) -> SegmentedDocument:
        """Open, decrypt, extract, and segment one document.

        Raises:
            DocumentNotFoundError: no such document for this principal.
            DocumentEncryptionError: the stored bytes failed authentication.
            DocumentTooLargeError: the plaintext exceeded the configured bound.
            DocumentExtractionError: the file could not be parsed, or holds no
                extractable text.
            DocumentExtractionTimeoutError: extraction exceeded its budget.
        """
        document, chunks = await self._source.open(
            tenant_id=tenant_id, user_id=user_id, document_id=document_id
        )
        data = await self._collect(chunks)

        extracted = await self._runner.run(data=data, content_type=document.metadata.content_type)
        segmented = self._segmenter.segment(extracted)

        # Counts and identifiers. Never the filename, never a byte of content.
        logger.info(
            "document_segmented",
            tenant_id=str(tenant_id),
            document_id=str(document_id),
            content_type=document.metadata.content_type,
            page_count=extracted.page_count,
            character_count=extracted.character_count,
            segment_count=segmented.segment_count,
        )
        return segmented

    async def aclose(self) -> None:
        await self._runner.aclose()

    # -- Internals --------------------------------------------------------
    async def _collect(self, chunks: AsyncIterator[bytes]) -> bytes:
        """Buffer the plaintext, refusing to exceed the configured bound.

        Checked while accumulating rather than at the end. The stored size is
        already bounded, but this reads a decrypted stream and a bound that is
        only verified after the fact is not a bound.
        """
        buffer = bytearray()
        async for block in chunks:
            buffer += block
            if len(buffer) > self._max_bytes:
                raise DocumentTooLargeError(
                    log_context={
                        "reason": "decrypted_length_over_limit",
                        "limit": self._max_bytes,
                    }
                )
        return bytes(buffer)

    def __repr__(self) -> str:
        return f"DocumentProcessor(max_document_bytes={self._max_bytes})"


__all__ = ["DocumentProcessor", "DocumentSource"]
