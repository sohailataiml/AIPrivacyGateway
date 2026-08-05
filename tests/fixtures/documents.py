"""Shared building blocks for the document suites.

Three files need the same identities, keys, bodies, and stream helpers:
``tests/unit/test_documents.py`` and its siblings, the security suite, and the
privacy canary sweep. Duplicating them invites the quiet kind of drift where one
copy stops matching the code and its assertions stop meaning anything.

``CANARIES`` is the important part. Every value in it is a distinctive string
that appears nowhere else in the repository, so a single search over captured
logs, metrics, SQL, and stored bytes answers "did any of this leak" without
false positives.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

from app.documents.crypto import (
    GCM_TAG_BYTES,
    NONCE_BYTES,
    DocumentCipher,
    DocumentHeader,
    DocumentIdentity,
)
from app.documents.models import CONTENT_TYPE_PDF
from app.vault.keys import StaticKeyRing

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

TENANT: Final = UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT: Final = UUID("22222222-2222-2222-2222-222222222222")
USER: Final = UUID("33333333-3333-3333-3333-333333333333")
OTHER_USER: Final = UUID("44444444-4444-4444-4444-444444444444")
DOCUMENT: Final = UUID("55555555-5555-5555-5555-555555555555")
OTHER_DOCUMENT: Final = UUID("66666666-6666-6666-6666-666666666666")

KEY_ID: Final = "local1"
KEY: Final = bytes(range(32))
OTHER_KEY: Final = bytes(range(64, 96))

CANARIES: Final[dict[str, str]] = {
    "person_name": "Marguerite Okonkwo-Vasquez",
    "email": "marguerite.okonkwo@zzcanary-clinic.test",
    "ssn": "451-88-7396",
    "mrn": "MRN-ZZ4471903",
    "icd10": "C50.911-canary",
    "filename": "Okonkwo-Vasquez-oncology-summary.pdf",
    "phone": "+1-415-555-0197",
}
"""Distinctive values that must never reach a log, a metric, or a bucket.

Each is deliberately unlike anything else in the tree, so a hit in captured
output is a leak rather than a coincidence.
"""

CANARY_PDF: Final = (
    b"%PDF-1.7\n"
    + "\n".join(
        (
            CANARIES["person_name"],
            CANARIES["email"],
            CANARIES["ssn"],
            CANARIES["mrn"],
            CANARIES["icd10"],
            CANARIES["phone"],
        )
    ).encode("utf-8")
    + b"\n%%EOF\n"
)

PDF_BODY: Final = b"%PDF-1.7\nJane Doe, MRN-40217788\n%%EOF\n"
TXT_BODY: Final = b"Patient Avery Example, avery@example.test\n"
DOCX_BODY: Final = b"PK\x03\x04" + b"\x00" * 64

MAX_BYTES: Final = 26_214_400


def key_ring(key: bytes = KEY) -> StaticKeyRing:
    return StaticKeyRing({KEY_ID: key}, active_key_id=KEY_ID)


def make_cipher(*, chunk_bytes: int = 64, key: bytes = KEY) -> DocumentCipher:
    """A cipher with a small chunk size, so short bodies exercise many frames."""
    return DocumentCipher(key_ring(key), chunk_bytes=chunk_bytes)


def identity_for(**overrides: Any) -> DocumentIdentity:
    fields: dict[str, Any] = {
        "tenant_id": TENANT,
        "user_id": USER,
        "document_id": DOCUMENT,
        "content_type": CONTENT_TYPE_PDF,
    }
    fields.update(overrides)
    return DocumentIdentity(**fields)


async def stream(*blocks: bytes) -> AsyncIterator[bytes]:
    for block in blocks:
        yield block


async def collect(chunks: AsyncIterator[bytes]) -> bytes:
    out = bytearray()
    async for block in chunks:
        out += block
    return bytes(out)


def split_frames(raw: bytes) -> tuple[bytes, list[bytes]]:
    """Split a sealed document into its header and its sealed frames.

    Tamper tests need to move, drop, and duplicate whole frames rather than
    flip bytes: a reader that only rejected corrupt bytes would still accept a
    document whose intact frames had been rearranged.
    """
    header, consumed = DocumentHeader.parse(raw)
    frame_size = NONCE_BYTES + header.chunk_bytes + GCM_TAG_BYTES
    body = raw[consumed:]
    frames: list[bytes] = []
    while len(body) > frame_size:
        frames.append(body[:frame_size])
        body = body[frame_size:]
    frames.append(body)
    return raw[:consumed], frames


def rejoin(header: bytes, frames: list[bytes]) -> bytes:
    return header + b"".join(frames)


__all__ = [
    "CANARIES",
    "CANARY_PDF",
    "DOCUMENT",
    "DOCX_BODY",
    "KEY",
    "KEY_ID",
    "MAX_BYTES",
    "OTHER_DOCUMENT",
    "OTHER_KEY",
    "OTHER_TENANT",
    "OTHER_USER",
    "PDF_BODY",
    "TENANT",
    "TXT_BODY",
    "USER",
    "collect",
    "identity_for",
    "key_ring",
    "make_cipher",
    "rejoin",
    "split_frames",
    "stream",
]
