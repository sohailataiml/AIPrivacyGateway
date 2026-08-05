"""Chunked AES-256-GCM encryption for stored documents.

The vault seals a short string in one shot. A document cannot be treated that
way: AES-GCM authenticates a whole message, so a single-shot design would have
to hold the entire file in memory to encrypt it and again to verify it before
the first byte could be trusted. A 25 MiB upload would then cost 50 MiB of
plaintext resident per concurrent request, and the plaintext of a Restricted
document is precisely the thing this module exists to keep out of memory.

So a document is sealed as a **sequence of independently authenticated chunks**,
which is what makes streaming honest: each chunk is verified as it arrives and
the caller never holds more than one chunk of plaintext.

Wire format (version 1), big-endian::

    header
      0      4   magic b"SGWD"
      4      1   version (1)
      5      1   key id length (1..255)
      6      n   key id, UTF-8
      6+n   16   HKDF salt, fresh per document
     22+n    4   plaintext chunk size, uint32
    then, repeated to the end of the object:
      12         GCM nonce, fresh per chunk
      ..         ciphertext with the 16-byte tag appended

Like the vault's envelope, the key id travels with the data, which is what lets
a rotated ring still open documents sealed before the rotation.

**Per-document keys (ADR-0021).** The ring key is never used to encrypt
anything. A data key is derived with HKDF-SHA256 from the ring key, the
per-document salt, and the ``tenant | user | document`` triple, so two documents
never share a key and a key recovered from one reveals nothing about another.

**What the associated data buys.** Every chunk's AAD carries the domain, the
version, the identity triple, the content type, the schema version, the purpose,
the chunk index, and whether the chunk is the last one. That single structure
defeats four different attacks:

* a chunk moved to another document, user, or tenant fails to authenticate;
* chunks reordered within a document fail, because the index is bound in;
* a document truncated part-way fails, because the new last chunk was sealed
  with ``final=False`` and is opened expecting ``final=True``;
* a document reinterpreted under another content type or schema fails.

Dropping any of those fields silently removes one of those defences. Do not.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.domain.errors import DocumentEncryptionError, GatewayError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from app.vault.keys import VaultKeyRing

DOCUMENT_MAGIC: Final = b"SGWD"
DOCUMENT_FORMAT_VERSION: Final = 1
NONCE_BYTES: Final = 12
GCM_TAG_BYTES: Final = 16
SALT_BYTES: Final = 16
DATA_KEY_BYTES: Final = 32
MAX_KEY_ID_BYTES: Final = 255

PURPOSE_BODY: Final = "body"
PURPOSE_FILENAME: Final = "filename"

_HEADER_PREFIX = struct.Struct("!4sBB")
_HEADER_SUFFIX = struct.Struct("!I")
_AAD_DOMAIN: Final = b"sgw.document.aad.v1"
_HKDF_DOMAIN: Final = b"sgw.document.datakey.v1"

MAX_CHUNK_BYTES: Final = 67_108_864
"""64 MiB. A declared chunk size above this is rejected rather than allocated."""


@dataclass(frozen=True, slots=True)
class DocumentIdentity:
    """The context a document's ciphertext is cryptographically bound to.

    ``user_id`` is the authenticated subject. Supplying the wrong tenant, user,
    document, content type, or schema version produces an authentication
    failure rather than plaintext -- ADR-0021's central requirement.
    """

    tenant_id: UUID
    user_id: UUID
    document_id: UUID
    content_type: str
    schema_version: int = DOCUMENT_FORMAT_VERSION

    def info(self) -> bytes:
        """HKDF ``info``: the triple that makes the data key document-specific."""
        return _length_prefixed(
            _HKDF_DOMAIN,
            str(self.tenant_id).encode("utf-8"),
            str(self.user_id).encode("utf-8"),
            str(self.document_id).encode("utf-8"),
        )

    def aad(self, *, purpose: str, chunk_index: int, final: bool) -> bytes:
        """Associated data for one chunk. Authenticated, not encrypted."""
        return _length_prefixed(
            _AAD_DOMAIN,
            bytes((DOCUMENT_FORMAT_VERSION,)),
            str(self.tenant_id).encode("utf-8"),
            str(self.user_id).encode("utf-8"),
            str(self.document_id).encode("utf-8"),
            self.content_type.encode("utf-8"),
            str(self.schema_version).encode("utf-8"),
            purpose.encode("utf-8"),
            str(chunk_index).encode("utf-8"),
            b"1" if final else b"0",
        )


def _length_prefixed(*fields: bytes) -> bytes:
    """Join fields unambiguously.

    Every field is length-prefixed so no combination of values can serialize to
    the same bytes as a different combination.
    """
    return b"".join(len(field).to_bytes(2, "big") + field for field in fields)


@dataclass(frozen=True, slots=True)
class DocumentHeader:
    """The self-describing prefix of a sealed document."""

    version: int
    key_id: str
    salt: bytes
    chunk_bytes: int

    def to_bytes(self) -> bytes:
        key_id = self.key_id.encode("utf-8")
        if not 0 < len(key_id) <= MAX_KEY_ID_BYTES:
            raise DocumentEncryptionError(log_context={"reason": "key_id_length_invalid"})
        return (
            _HEADER_PREFIX.pack(DOCUMENT_MAGIC, self.version, len(key_id))
            + key_id
            + self.salt
            + _HEADER_SUFFIX.pack(self.chunk_bytes)
        )

    @classmethod
    def parse(cls, raw: bytes) -> tuple[DocumentHeader, int]:
        """Parse a header, returning it and the number of bytes consumed.

        Raises:
            DocumentEncryptionError: on anything malformed. The reason code
                never contains a byte of the document.
        """
        if len(raw) < _HEADER_PREFIX.size:
            raise DocumentEncryptionError(log_context={"reason": "header_truncated"})

        magic, version, key_id_length = _HEADER_PREFIX.unpack_from(raw)
        if magic != DOCUMENT_MAGIC:
            raise DocumentEncryptionError(log_context={"reason": "header_magic_mismatch"})
        if version != DOCUMENT_FORMAT_VERSION:
            raise DocumentEncryptionError(
                log_context={"reason": "header_version_unsupported", "version": version}
            )
        if key_id_length == 0:
            raise DocumentEncryptionError(log_context={"reason": "header_key_id_missing"})

        key_id_end = _HEADER_PREFIX.size + key_id_length
        salt_end = key_id_end + SALT_BYTES
        total = salt_end + _HEADER_SUFFIX.size
        if len(raw) < total:
            raise DocumentEncryptionError(log_context={"reason": "header_truncated"})

        try:
            key_id = raw[_HEADER_PREFIX.size : key_id_end].decode("utf-8")
        except UnicodeDecodeError:
            raise DocumentEncryptionError(log_context={"reason": "header_key_id_invalid"}) from None

        (chunk_bytes,) = _HEADER_SUFFIX.unpack_from(raw, salt_end)
        if not 0 < chunk_bytes <= MAX_CHUNK_BYTES:
            # A hostile header must not be able to make the reader allocate.
            raise DocumentEncryptionError(log_context={"reason": "header_chunk_size_invalid"})

        return cls(
            version=version,
            key_id=key_id,
            salt=raw[key_id_end:salt_end],
            chunk_bytes=chunk_bytes,
        ), total

    @staticmethod
    def minimum_size() -> int:
        return _HEADER_PREFIX.size + 1 + SALT_BYTES + _HEADER_SUFFIX.size

    def __repr__(self) -> str:
        return f"DocumentHeader(version={self.version}, key_id={self.key_id!r})"


class DocumentCipher:
    """Seals and opens documents under a rotating key ring.

    Knows nothing about object storage, HTTP, or the database. Given a stream of
    plaintext it produces a stream of opaque bytes, and given those bytes back it
    either yields the exact plaintext or raises. There is no third outcome.
    """

    __slots__ = ("_chunk_bytes", "_key_ring")

    def __init__(self, key_ring: VaultKeyRing, *, chunk_bytes: int) -> None:
        if not 0 < chunk_bytes <= MAX_CHUNK_BYTES:
            raise ValueError(f"chunk_bytes must be within 1..{MAX_CHUNK_BYTES}")
        self._key_ring = key_ring
        self._chunk_bytes = chunk_bytes

    # -- Whole values -----------------------------------------------------
    def seal_bytes(self, *, identity: DocumentIdentity, purpose: str, plaintext: bytes) -> bytes:
        """Seal one short value -- a filename -- as a single-chunk document."""
        key_id = self._key_ring.active_key_id
        salt = os.urandom(SALT_BYTES)
        data_key = self._derive(key_id=key_id, salt=salt, identity=identity)
        header = DocumentHeader(
            version=DOCUMENT_FORMAT_VERSION,
            key_id=key_id,
            salt=salt,
            chunk_bytes=max(len(plaintext), 1),
        )
        frame = _seal_chunk(
            data_key,
            plaintext=plaintext,
            aad=identity.aad(purpose=purpose, chunk_index=0, final=True),
        )
        return header.to_bytes() + frame

    def open_bytes(self, *, identity: DocumentIdentity, purpose: str, raw: bytes) -> bytes:
        """Open a value sealed by :meth:`seal_bytes`."""
        header, consumed = DocumentHeader.parse(raw)
        data_key = self._derive(key_id=header.key_id, salt=header.salt, identity=identity)
        return _open_chunk(
            data_key,
            frame=raw[consumed:],
            aad=identity.aad(purpose=purpose, chunk_index=0, final=True),
        )

    # -- Streams ----------------------------------------------------------
    async def seal_stream(
        self,
        *,
        identity: DocumentIdentity,
        plaintext: AsyncIterator[bytes],
    ) -> AsyncIterator[bytes]:
        """Yield the header, then one sealed frame per plaintext chunk.

        Chunks are emitted one behind the input so the last one can be sealed
        with ``final=True``. That one-chunk delay is what makes truncation
        detectable, and it is why this cannot be a straight map over the input.
        """
        key_id = self._key_ring.active_key_id
        salt = os.urandom(SALT_BYTES)
        data_key = self._derive(key_id=key_id, salt=salt, identity=identity)

        yield DocumentHeader(
            version=DOCUMENT_FORMAT_VERSION,
            key_id=key_id,
            salt=salt,
            chunk_bytes=self._chunk_bytes,
        ).to_bytes()

        index = 0
        pending: bytes | None = None
        async for block in _rechunk(plaintext, self._chunk_bytes):
            if pending is not None:
                yield _seal_chunk(
                    data_key,
                    plaintext=pending,
                    aad=identity.aad(purpose=PURPOSE_BODY, chunk_index=index, final=False),
                )
                index += 1
            pending = block

        # An empty document still gets one authenticated final chunk, so "zero
        # bytes" is a fact the format records rather than an absence anyone
        # could manufacture by deleting frames.
        yield _seal_chunk(
            data_key,
            plaintext=pending if pending is not None else b"",
            aad=identity.aad(purpose=PURPOSE_BODY, chunk_index=index, final=True),
        )

    async def open_stream(
        self,
        *,
        identity: DocumentIdentity,
        ciphertext: AsyncIterator[bytes],
    ) -> AsyncIterator[bytes]:
        """Yield plaintext chunks, authenticating each one as it is read.

        A chunk is only known to be final once the stream ends, so a full frame
        is held back until at least one more byte arrives. Nothing is yielded
        before it has been authenticated.
        """
        buffer = bytearray()
        header: DocumentHeader | None = None
        data_key = b""
        frame_size = 0
        index = 0

        async for block in ciphertext:
            buffer += block

            if header is None:
                if len(buffer) < DocumentHeader.minimum_size():
                    continue
                header, consumed = DocumentHeader.parse(bytes(buffer))
                data_key = self._derive(key_id=header.key_id, salt=header.salt, identity=identity)
                frame_size = NONCE_BYTES + header.chunk_bytes + GCM_TAG_BYTES
                del buffer[:consumed]

            # Strictly greater: a buffer holding exactly one frame might be the
            # last one, and opening it as non-final would reject a valid
            # document.
            while len(buffer) > frame_size:
                yield _open_chunk(
                    data_key,
                    frame=bytes(buffer[:frame_size]),
                    aad=identity.aad(purpose=PURPOSE_BODY, chunk_index=index, final=False),
                )
                del buffer[:frame_size]
                index += 1

        if header is None:
            raise DocumentEncryptionError(log_context={"reason": "header_truncated"})

        yield _open_chunk(
            data_key,
            frame=bytes(buffer),
            aad=identity.aad(purpose=PURPOSE_BODY, chunk_index=index, final=True),
        )

    # -- Internals --------------------------------------------------------
    def _derive(self, *, key_id: str, salt: bytes, identity: DocumentIdentity) -> bytes:
        """Derive this document's data key. The ring key encrypts nothing."""
        try:
            master = self._key_ring.key(key_id)
        except GatewayError as exc:
            # The ring already speaks in safe reason codes -- `unknown_key_id`,
            # `key_length_invalid` -- so pass its answer through rather than
            # flattening every failure to "unknown". Reporting a wrong-length
            # key as a missing one sends an operator looking for a key that is
            # sitting right there, which is exactly what happened once.
            reason = exc.log_context.get("reason", "key_unavailable")
            raise DocumentEncryptionError(log_context={"reason": reason}) from exc
        except Exception as exc:
            # Reason codes only -- never the key id's value in a message body.
            raise DocumentEncryptionError(log_context={"reason": "key_unavailable"}) from exc
        return HKDF(
            algorithm=hashes.SHA256(),
            length=DATA_KEY_BYTES,
            salt=salt,
            info=identity.info(),
        ).derive(master)

    def __repr__(self) -> str:
        return f"DocumentCipher(chunk_bytes={self._chunk_bytes})"


def _seal_chunk(data_key: bytes, *, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    try:
        return nonce + AESGCM(data_key).encrypt(nonce, plaintext, aad)
    except Exception as exc:  # pragma: no cover - defensive
        raise DocumentEncryptionError(log_context={"reason": "seal_failed"}) from exc


def _open_chunk(data_key: bytes, *, frame: bytes, aad: bytes) -> bytes:
    if len(frame) < NONCE_BYTES + GCM_TAG_BYTES:
        raise DocumentEncryptionError(log_context={"reason": "chunk_truncated"})
    try:
        return AESGCM(data_key).decrypt(frame[:NONCE_BYTES], frame[NONCE_BYTES:], aad)
    except InvalidTag:
        # Wrong tenant, wrong user, wrong document, wrong content type, altered
        # bytes, reordered chunk, truncated stream -- all one answer.
        raise DocumentEncryptionError(log_context={"reason": "authentication_failed"}) from None
    except ValueError as exc:
        raise DocumentEncryptionError(log_context={"reason": "open_failed"}) from exc


async def _rechunk(source: AsyncIterator[bytes], size: int) -> AsyncIterator[bytes]:
    """Regroup an arbitrarily chunked stream into fixed-size blocks.

    A client's chunk boundaries are its own business; the format's boundaries
    must be fixed, or the reader cannot know how much to read.
    """
    buffer = bytearray()
    async for block in source:
        buffer += block
        while len(buffer) >= size:
            yield bytes(buffer[:size])
            del buffer[:size]
    if buffer:
        yield bytes(buffer)


__all__ = [
    "DATA_KEY_BYTES",
    "DOCUMENT_FORMAT_VERSION",
    "DOCUMENT_MAGIC",
    "GCM_TAG_BYTES",
    "NONCE_BYTES",
    "PURPOSE_BODY",
    "PURPOSE_FILENAME",
    "SALT_BYTES",
    "DocumentCipher",
    "DocumentHeader",
    "DocumentIdentity",
]
