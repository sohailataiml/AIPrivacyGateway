"""Proof that document encryption cannot be bypassed.

``tests/unit/test_documents.py`` shows the happy path works and that the obvious
attacks fail. This file is the exhaustive version: every field bound into the
associated data gets its own test, and every structural manipulation of the
sealed form -- reorder, duplicate, drop, truncate, retag -- gets its own test.

The reason for the separation is that these are the assertions that would still
matter if the rest of the gateway were rewritten. AES-GCM gives integrity only
over what is actually bound into it, so each of these tests corresponds to one
field that could be dropped from ``DocumentIdentity.aad`` during a refactor
without breaking a single round-trip test.

Every failure is the same failure -- ``DocumentEncryptionError`` with reason
``authentication_failed`` -- which is intentional. A reader that distinguished
"wrong tenant" from "corrupt bytes" would be an oracle.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from uuid import uuid4

import pytest

from app.documents.crypto import (
    GCM_TAG_BYTES,
    NONCE_BYTES,
    PURPOSE_BODY,
    PURPOSE_FILENAME,
    DocumentCipher,
    DocumentHeader,
)
from app.documents.models import CONTENT_TYPE_DOCX, CONTENT_TYPE_PDF, CONTENT_TYPE_TXT
from app.domain.errors import DocumentEncryptionError
from tests.fixtures.documents import (
    CANARIES,
    CANARY_PDF,
    OTHER_DOCUMENT,
    OTHER_KEY,
    OTHER_TENANT,
    OTHER_USER,
    collect,
    identity_for,
    make_cipher,
    rejoin,
    split_frames,
    stream,
)

if TYPE_CHECKING:
    from app.documents.crypto import DocumentIdentity

pytestmark = pytest.mark.security

CHUNK = 64


@pytest.fixture
def cipher() -> DocumentCipher:
    return make_cipher(chunk_bytes=CHUNK)


async def seal(cipher: DocumentCipher, body: bytes, identity: DocumentIdentity) -> bytes:
    return await collect(cipher.seal_stream(identity=identity, plaintext=stream(body)))


async def open_sealed(cipher: DocumentCipher, raw: bytes, identity: DocumentIdentity) -> bytes:
    return await collect(cipher.open_stream(identity=identity, ciphertext=stream(raw)))


# ---------------------------------------------------------------------------
# Shapes: the sizes that exercise different paths through the format
# ---------------------------------------------------------------------------
class TestDocumentShapes:
    async def test_an_empty_document_round_trips(self, cipher: DocumentCipher) -> None:
        # Zero bytes is still one authenticated final frame, so "empty" is a
        # fact the format records rather than an absence anyone can manufacture
        # by deleting frames.
        identity = identity_for()

        sealed = await collect(cipher.seal_stream(identity=identity, plaintext=stream()))

        assert await open_sealed(cipher, sealed, identity) == b""
        _, frames = split_frames(sealed)
        assert len(frames) == 1

    async def test_a_single_chunk_document_round_trips(self, cipher: DocumentCipher) -> None:
        identity = identity_for()
        body = b"%PDF-1.7\n"

        sealed = await seal(cipher, body, identity)

        assert await open_sealed(cipher, sealed, identity) == body
        _, frames = split_frames(sealed)
        assert len(frames) == 1

    async def test_a_document_exactly_one_chunk_long_round_trips(
        self, cipher: DocumentCipher
    ) -> None:
        # The boundary case: the last full frame is also the final frame, and
        # the reader's "hold one frame back" rule has to get this right.
        identity = identity_for()
        body = os.urandom(CHUNK)

        sealed = await seal(cipher, body, identity)

        assert await open_sealed(cipher, sealed, identity) == body

    async def test_a_multi_chunk_document_round_trips(self, cipher: DocumentCipher) -> None:
        identity = identity_for()
        body = os.urandom(CHUNK * 5 + 7)

        sealed = await seal(cipher, body, identity)

        assert await open_sealed(cipher, sealed, identity) == body
        _, frames = split_frames(sealed)
        assert len(frames) == 6

    async def test_a_document_an_exact_multiple_of_the_chunk_size_round_trips(
        self, cipher: DocumentCipher
    ) -> None:
        identity = identity_for()
        body = os.urandom(CHUNK * 4)

        sealed = await seal(cipher, body, identity)

        assert await open_sealed(cipher, sealed, identity) == body


# ---------------------------------------------------------------------------
# Structure: whole frames moved, copied, or removed
# ---------------------------------------------------------------------------
class TestStructuralTampering:
    @pytest.fixture
    async def sealed(self, cipher: DocumentCipher) -> bytes:
        return await seal(cipher, os.urandom(CHUNK * 4 + 5), identity_for())

    async def test_reordering_two_chunks_is_detected(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        # Every frame is individually valid. Only the bound-in index says they
        # are in the wrong places.
        header, frames = split_frames(sealed)
        frames[0], frames[1] = frames[1], frames[0]

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, rejoin(header, frames), identity_for())

    async def test_reversing_every_chunk_is_detected(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        header, frames = split_frames(sealed)

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, rejoin(header, frames[::-1]), identity_for())

    async def test_duplicating_a_chunk_is_detected(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        # A replayed frame would otherwise repeat a block of the document --
        # enough to forge a plausible-looking altered file.
        header, frames = split_frames(sealed)
        duplicated = [frames[0], frames[0], *frames[1:]]

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, rejoin(header, duplicated), identity_for())

    async def test_removing_a_middle_chunk_is_detected(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        # Deleting a paragraph from a signed document without invalidating it
        # is the whole attack this defends against.
        header, frames = split_frames(sealed)
        del frames[1]

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, rejoin(header, frames), identity_for())

    async def test_removing_the_first_chunk_is_detected(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        header, frames = split_frames(sealed)

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, rejoin(header, frames[1:]), identity_for())

    async def test_truncating_the_final_chunk_away_is_detected(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        # The new last frame was sealed with final=False and is now read as
        # final=True. Without that flag in the AAD this would decrypt cleanly
        # and silently return a shorter document.
        header, frames = split_frames(sealed)

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, rejoin(header, frames[:-1]), identity_for())

    async def test_truncating_to_a_single_chunk_is_detected(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        header, frames = split_frames(sealed)

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, rejoin(header, frames[:1]), identity_for())

    async def test_appending_a_replayed_final_chunk_is_detected(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        # Extending a document with a copy of its own last frame.
        header, frames = split_frames(sealed)

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, rejoin(header, [*frames, frames[-1]]), identity_for())

    async def test_a_document_with_no_frames_at_all_is_detected(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        header, _ = split_frames(sealed)

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, header, identity_for())


# ---------------------------------------------------------------------------
# Bytes: nonce, ciphertext, tag, header
# ---------------------------------------------------------------------------
class TestByteTampering:
    @pytest.fixture
    async def sealed(self, cipher: DocumentCipher) -> bytes:
        return await seal(cipher, os.urandom(CHUNK * 3), identity_for())

    async def test_a_modified_nonce_is_detected(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        header, frames = split_frames(sealed)
        first = bytearray(frames[0])
        first[0] ^= 0x01
        frames[0] = bytes(first)

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, rejoin(header, frames), identity_for())

    async def test_modified_ciphertext_is_detected(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        header, frames = split_frames(sealed)
        first = bytearray(frames[0])
        first[NONCE_BYTES] ^= 0x01
        frames[0] = bytes(first)

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, rejoin(header, frames), identity_for())

    async def test_a_modified_tag_is_detected(self, cipher: DocumentCipher, sealed: bytes) -> None:
        header, frames = split_frames(sealed)
        first = bytearray(frames[0])
        first[-1] ^= 0x01
        frames[0] = bytes(first)

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, rejoin(header, frames), identity_for())

    async def test_a_modified_salt_is_detected(self, cipher: DocumentCipher, sealed: bytes) -> None:
        # The salt is not authenticated, but it feeds HKDF: changing it derives
        # a different data key, so every frame stops authenticating. Failing
        # closed here is what makes an unauthenticated header safe.
        parsed, consumed = DocumentHeader.parse(sealed)
        raw = bytearray(sealed)
        salt_offset = consumed - 4 - len(parsed.salt)
        raw[salt_offset] ^= 0xFF

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, bytes(raw), identity_for())

    async def test_a_substituted_key_id_is_detected(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        # Naming a key the ring does not hold must refuse rather than fall back
        # to the active key.
        parsed, _ = DocumentHeader.parse(sealed)
        forged = DocumentHeader(
            version=parsed.version,
            key_id="attacker",
            salt=parsed.salt,
            chunk_bytes=parsed.chunk_bytes,
        )
        raw = forged.to_bytes() + sealed[len(parsed.to_bytes()) :]

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, raw, identity_for())

    async def test_a_shortened_frame_is_detected(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, sealed[: -GCM_TAG_BYTES - 1], identity_for())


# ---------------------------------------------------------------------------
# Identity: every field bound into the associated data
# ---------------------------------------------------------------------------
class TestIdentityBinding:
    @pytest.fixture
    async def sealed(self, cipher: DocumentCipher) -> bytes:
        return await seal(cipher, CANARY_PDF, identity_for())

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("tenant_id", OTHER_TENANT),
            ("user_id", OTHER_USER),
            ("document_id", OTHER_DOCUMENT),
            ("content_type", CONTENT_TYPE_TXT),
            ("content_type", CONTENT_TYPE_DOCX),
            ("schema_version", 2),
        ],
        ids=[
            "wrong-tenant",
            "wrong-user",
            "wrong-document",
            "wrong-content-type-txt",
            "wrong-content-type-docx",
            "wrong-schema-version",
        ],
    )
    async def test_one_wrong_field_is_enough_to_refuse(
        self, cipher: DocumentCipher, sealed: bytes, field: str, value: object
    ) -> None:
        # Each parameter corresponds to one field in DocumentIdentity.aad. If a
        # refactor dropped that field, exactly one of these would start failing
        # and every round-trip test would keep passing.
        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, sealed, identity_for(**{field: value}))

    async def test_a_wrong_field_yields_no_plaintext_at_all(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        # Not merely "raises": nothing may be yielded before the failure, or a
        # streaming consumer would already have written a partial document.
        yielded: list[bytes] = []

        with pytest.raises(DocumentEncryptionError):
            async for block in cipher.open_stream(
                identity=identity_for(tenant_id=OTHER_TENANT), ciphertext=stream(sealed)
            ):
                yielded.append(block)

        assert yielded == []
        joined = b"".join(yielded)
        for canary in CANARIES.values():
            assert canary.encode("utf-8") not in joined

    async def test_the_whole_identity_being_wrong_is_refused(
        self, cipher: DocumentCipher, sealed: bytes
    ) -> None:
        attacker = identity_for(
            tenant_id=OTHER_TENANT,
            user_id=OTHER_USER,
            document_id=uuid4(),
            content_type=CONTENT_TYPE_TXT,
        )

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, sealed, attacker)

    async def test_another_ring_key_cannot_open_the_document(self, sealed: bytes) -> None:
        # Same key id, different bytes: a ring restored from the wrong backup,
        # or a second environment sharing a bucket.
        with pytest.raises(DocumentEncryptionError):
            await open_sealed(make_cipher(chunk_bytes=CHUNK, key=OTHER_KEY), sealed, identity_for())

    async def test_two_documents_of_identical_bytes_share_no_ciphertext(
        self, cipher: DocumentCipher
    ) -> None:
        # Per-document HKDF derivation (ADR-0021). Identical ciphertext would
        # let an operator with bucket access tell that two users hold the same
        # file, which is a disclosure even without decryption.
        first = await seal(cipher, CANARY_PDF, identity_for())
        second = await seal(cipher, CANARY_PDF, identity_for(document_id=OTHER_DOCUMENT))

        assert first != second
        _, first_frames = split_frames(first)
        _, second_frames = split_frames(second)
        assert set(first_frames).isdisjoint(second_frames)


# ---------------------------------------------------------------------------
# Purpose: the filename and the body are not interchangeable
# ---------------------------------------------------------------------------
class TestPurposeSeparation:
    async def test_a_filename_does_not_open_as_a_body(self, cipher: DocumentCipher) -> None:
        identity = identity_for()
        sealed = cipher.seal_bytes(
            identity=identity,
            purpose=PURPOSE_FILENAME,
            plaintext=CANARIES["filename"].encode("utf-8"),
        )

        with pytest.raises(DocumentEncryptionError):
            await open_sealed(cipher, sealed, identity)

    async def test_a_body_does_not_open_as_a_filename(self, cipher: DocumentCipher) -> None:
        identity = identity_for()
        sealed = await seal(cipher, CANARY_PDF, identity)

        with pytest.raises(DocumentEncryptionError):
            cipher.open_bytes(identity=identity, purpose=PURPOSE_FILENAME, raw=sealed)

    def test_an_unknown_purpose_cannot_open_a_filename(self, cipher: DocumentCipher) -> None:
        identity = identity_for()
        sealed = cipher.seal_bytes(
            identity=identity, purpose=PURPOSE_FILENAME, plaintext=b"report.pdf"
        )

        with pytest.raises(DocumentEncryptionError):
            cipher.open_bytes(identity=identity, purpose="body-v2", raw=sealed)

    def test_the_two_purposes_are_distinct_constants(self) -> None:
        # Guards against a merge that collapses them into one value, which
        # would make every assertion above pass for the wrong reason.
        assert PURPOSE_BODY != PURPOSE_FILENAME

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("tenant_id", OTHER_TENANT),
            ("user_id", OTHER_USER),
            ("document_id", OTHER_DOCUMENT),
            ("content_type", CONTENT_TYPE_TXT),
        ],
    )
    def test_a_filename_is_bound_to_its_identity_too(
        self, cipher: DocumentCipher, field: str, value: object
    ) -> None:
        # A filename is Restricted for the same reasons the body is, and is
        # sealed under the same identity.
        sealed = cipher.seal_bytes(
            identity=identity_for(),
            purpose=PURPOSE_FILENAME,
            plaintext=CANARIES["filename"].encode("utf-8"),
        )

        with pytest.raises(DocumentEncryptionError):
            cipher.open_bytes(
                identity=identity_for(**{field: value}),
                purpose=PURPOSE_FILENAME,
                raw=sealed,
            )


# ---------------------------------------------------------------------------
# What the ciphertext discloses on its own
# ---------------------------------------------------------------------------
class TestCiphertextDiscloses:
    async def test_no_canary_survives_sealing(self, cipher: DocumentCipher) -> None:
        sealed = await seal(cipher, CANARY_PDF, identity_for())

        for name, value in CANARIES.items():
            assert value.encode("utf-8") not in sealed, name

    async def test_the_sealed_form_names_no_identity(self, cipher: DocumentCipher) -> None:
        # The header is deliberately readable, but it carries a key id, a salt,
        # and a chunk size -- never who the document belongs to.
        identity = identity_for()
        sealed = await seal(cipher, CANARY_PDF, identity)

        for value in (identity.tenant_id, identity.user_id, identity.document_id):
            assert str(value).encode("utf-8") not in sealed
            assert value.bytes not in sealed
        assert CONTENT_TYPE_PDF.encode("utf-8") not in sealed

    async def test_sealing_the_same_document_twice_differs(self, cipher: DocumentCipher) -> None:
        # Fresh salt and fresh nonces. Identical output across two seals would
        # mean a nonce was being reused, which is fatal for GCM.
        identity = identity_for()

        first = await seal(cipher, CANARY_PDF, identity)
        second = await seal(cipher, CANARY_PDF, identity)

        assert first != second

    async def test_every_nonce_in_a_document_is_distinct(self, cipher: DocumentCipher) -> None:
        # Reusing a nonce under one key leaks the XOR of two plaintexts and
        # allows tag forgery. This is the cheapest possible check for it.
        sealed = await seal(cipher, os.urandom(CHUNK * 20), identity_for())

        _, frames = split_frames(sealed)
        nonces = [frame[:NONCE_BYTES] for frame in frames]
        assert len(set(nonces)) == len(nonces)
