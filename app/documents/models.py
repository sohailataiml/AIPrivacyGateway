"""Document domain contracts.

Two types, and the distinction between them is the point:

* ``DocumentMetadata`` is Internal data -- identifiers, sizes, a checksum, a
  status. It is safe to log, safe to return, safe to keep.
* ``Document`` is that metadata plus the decrypted filename, which is Restricted
  (see ``docs/data-classification.md``). A filename routinely carries a person's
  name, a case number, or a diagnosis, which is why it is stored encrypted and
  why this type has a ``__repr__`` that hides it.

Keeping them separate means the safe half can be passed around freely and the
unsafe half has to be asked for by name.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Final
from uuid import UUID

CONTENT_TYPE_TXT: Final = "text/plain"
CONTENT_TYPE_PDF: Final = "application/pdf"
CONTENT_TYPE_DOCX: Final = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


class DocumentStatus(StrEnum):
    """Lifecycle of a stored document.

    Version 1 stores documents and does nothing else with them. Extraction,
    detection, and protection are later phases, so there is deliberately no
    ``EXTRACTED`` or ``PROTECTED`` member here: a status the system cannot
    reach is a lie told to whoever polls for it.
    """

    RECEIVING = "receiving"
    """Bytes are being read and sealed. Not yet retrievable."""

    STORED = "stored"
    """Sealed, uploaded, and retrievable."""

    FAILED = "failed"
    """Upload did not complete. No object is retained."""


@dataclass(frozen=True, slots=True)
class SupportedType:
    """One accepted document type and the evidence required to believe it."""

    content_type: str
    extensions: tuple[str, ...]
    magic: tuple[bytes, ...]
    """Byte prefixes that must match. Empty means the type has no signature."""


SUPPORTED_TYPES: Final[dict[str, SupportedType]] = {
    CONTENT_TYPE_TXT: SupportedType(
        content_type=CONTENT_TYPE_TXT,
        extensions=(".txt",),
        # Plain text has no signature. It is validated by decoding instead.
        magic=(),
    ),
    CONTENT_TYPE_PDF: SupportedType(
        content_type=CONTENT_TYPE_PDF,
        extensions=(".pdf",),
        magic=(b"%PDF-",),
    ),
    CONTENT_TYPE_DOCX: SupportedType(
        content_type=CONTENT_TYPE_DOCX,
        extensions=(".docx",),
        # DOCX is a ZIP container. All three ZIP records are accepted
        # because a writer may emit an empty or spanned archive marker.
        magic=(b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    ),
}

SUPPORTED_CONTENT_TYPES: Final = MappingProxyType(SUPPORTED_TYPES)

EXTENSION_TO_CONTENT_TYPE: Final = MappingProxyType(
    {
        extension: supported.content_type
        for supported in SUPPORTED_TYPES.values()
        for extension in supported.extensions
    }
)


@dataclass(frozen=True, slots=True)
class DocumentMetadata:
    """Everything about a document except its name and its contents.

    Internal data: safe to log and safe to return to the owning principal.
    ``storage_key`` is opaque and carries no tenant, user, or filename, so
    seeing it reveals nothing and possessing it grants nothing.
    """

    id: UUID
    tenant_id: UUID
    user_id: UUID
    storage_key: str
    content_type: str
    byte_size: int
    sha256_hex: str
    status: DocumentStatus
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class Document:
    """Metadata plus the decrypted filename. Restricted -- never log one."""

    metadata: DocumentMetadata
    filename: str

    def __repr__(self) -> str:
        # Defensive: a stray repr() in a traceback must not leak the filename.
        return f"Document(id={self.metadata.id!r}, status={self.metadata.status!r})"


__all__ = [
    "CONTENT_TYPE_DOCX",
    "CONTENT_TYPE_PDF",
    "CONTENT_TYPE_TXT",
    "EXTENSION_TO_CONTENT_TYPE",
    "SUPPORTED_CONTENT_TYPES",
    "SUPPORTED_TYPES",
    "Document",
    "DocumentMetadata",
    "DocumentStatus",
    "SupportedType",
]
