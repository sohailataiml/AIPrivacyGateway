"""Object-store integration tests. Require a disposable MinIO.

Marked ``integration`` and skipped when ``TEST_OBJECT_STORE_ENDPOINT`` is unset,
so the default unit run collects them without failing::

    docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d \\
        minio minio-init

    TEST_OBJECT_STORE_ENDPOINT=http://localhost:9000 \\
    TEST_OBJECT_STORE_ACCESS_KEY_ID=sgw-local-access-key \\
    TEST_OBJECT_STORE_SECRET_ACCESS_KEY=sgw-local-secret-key-not-for-production \\
        pytest tests/integration/test_documents_minio.py -m integration

These assertions are the ones ``FakeDocumentStore`` cannot make. The fake is a
dictionary; it will happily accept a 1-byte multipart part, sign nothing, and
never disagree with the gateway about what an object key means. Everything that
actually breaks in production lives here:

* **multipart uploads**, including S3's 5 MiB minimum part size -- the fake
  cannot fail that rule, so only this suite proves a large document uploads at
  all;
* **request signing and path-style addressing**, which is the difference
  between MinIO and AWS S3 and the most likely thing to be misconfigured;
* **streaming downloads** through a real HTTP body rather than a list slice;
* **abort on failure**, proved by asking the server whether an upload is still
  open -- a leaked multipart upload is invisible in an object listing and is
  billed until something removes it.

Four of this project's eleven defects so far were visible only from a running
container, and the first run of this file found a twelfth: its own fixture
patched an attribute on a ``__slots__`` class, which had never executed.
A storage adapter verified solely against an in-memory dictionary is the same
shape of risk.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

import aioboto3
import httpx
import pytest
from botocore.config import Config

from app.documents.crypto import (
    PURPOSE_BODY,
    PURPOSE_FILENAME,
    DocumentCipher,
    DocumentIdentity,
)
from app.documents.models import CONTENT_TYPE_PDF
from app.documents.storage.s3 import MIN_PART_BYTES, S3CompatibleDocumentStore
from app.domain.errors import (
    DocumentEncryptionError,
    DocumentNotFoundError,
    DocumentStorageUnavailableError,
)
from app.vault.keys import StaticKeyRing

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

pytestmark = pytest.mark.integration

ENDPOINT = os.environ.get("TEST_OBJECT_STORE_ENDPOINT")
ACCESS_KEY = os.environ.get("TEST_OBJECT_STORE_ACCESS_KEY_ID", "sgw-local-access-key")
SECRET_KEY = os.environ.get(
    "TEST_OBJECT_STORE_SECRET_ACCESS_KEY", "sgw-local-secret-key-not-for-production"
)
BUCKET = os.environ.get("TEST_OBJECT_STORE_BUCKET", "sgw-documents")

requires_object_store = pytest.mark.skipif(
    not ENDPOINT,
    reason="set TEST_OBJECT_STORE_ENDPOINT to a disposable MinIO to run these",
)


def test_this_suite_is_not_silently_skipped() -> None:
    """Fail rather than skip where the object store is supposed to be present.

    A skipped test reports as a pass. CI sets ``REQUIRE_OBJECT_STORE_TESTS=1``,
    so a MinIO that failed to start, or an environment variable that got
    dropped from the workflow, turns into a red build instead of a green one
    with thirty-five silent skips.
    """
    if os.environ.get("REQUIRE_OBJECT_STORE_TESTS") == "1":
        assert ENDPOINT, (
            "REQUIRE_OBJECT_STORE_TESTS=1 but TEST_OBJECT_STORE_ENDPOINT is unset, "
            "so the object store suite would have skipped"
        )


TENANT = UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = UUID("22222222-2222-2222-2222-222222222222")
USER = UUID("33333333-3333-3333-3333-333333333333")
OTHER_USER = UUID("44444444-4444-4444-4444-444444444444")
KEY_ID = "integration"
KEY = bytes(range(32))
OTHER_KEY = bytes(range(32, 64))


def build_store(**overrides: Any) -> S3CompatibleDocumentStore:
    """A store pointed at the disposable MinIO, with per-test overrides."""
    settings: dict[str, Any] = {
        "bucket": BUCKET,
        "region": "us-east-1",
        "endpoint_url": ENDPOINT,
        "access_key_id": ACCESS_KEY,
        "secret_access_key": SECRET_KEY,
        "part_bytes": MIN_PART_BYTES,
        "use_path_style": True,
    }
    settings.update(overrides)
    return S3CompatibleDocumentStore(**settings)


@pytest.fixture
def keys() -> list[str]:
    """Keys this test touched, removed on teardown by the ``store`` fixture."""
    return []


@pytest.fixture
def object_key(keys: list[str]) -> Callable[[], str]:
    """Mint an object key and register it for cleanup.

    The first version of this fixture reassigned ``store.put`` to record keys.
    ``S3CompatibleDocumentStore`` defines ``__slots__``, so that raised
    ``AttributeError`` on every test in the file -- which is what a suite that
    has never been executed looks like. Recording at the point the key is
    created needs no patching and cannot be defeated by the class.
    """

    def mint() -> str:
        key = f"documents/test-{uuid4().hex}"
        keys.append(key)
        return key

    return mint


@pytest.fixture
async def store(keys: list[str]) -> AsyncIterator[S3CompatibleDocumentStore]:
    built = build_store()
    try:
        yield built
    finally:
        for key in keys:
            # Cleanup must not mask the failure that brought us here.
            with contextlib.suppress(Exception):
                await built.delete(key=key)
        await built.aclose()


@pytest.fixture
async def probe() -> AsyncIterator[Any]:
    """A raw S3 client, so assertions do not run through the code under test.

    Used for the questions the adapter has no method for: is a multipart upload
    still open, what does the server think this object's metadata is, and what
    happens when the same bytes are copied to a different key.
    """
    session = aioboto3.Session()
    async with session.client(
        "s3",
        region_name="us-east-1",
        endpoint_url=ENDPOINT,
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        config=Config(s3={"addressing_style": "path"}, signature_version="s3v4"),
    ) as client:
        yield client


def cipher(chunk_bytes: int = MIN_PART_BYTES, key: bytes = KEY) -> DocumentCipher:
    return DocumentCipher(
        StaticKeyRing({KEY_ID: key}, active_key_id=KEY_ID), chunk_bytes=chunk_bytes
    )


def identity_for(document_id: UUID, **overrides: Any) -> DocumentIdentity:
    fields: dict[str, Any] = {
        "tenant_id": TENANT,
        "user_id": USER,
        "document_id": document_id,
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


async def open_uploads(probe: Any, key: str) -> list[str]:
    """Upload ids still open for ``key``, straight from the server."""
    response = await probe.list_multipart_uploads(Bucket=BUCKET, Prefix=key)
    return [str(upload["UploadId"]) for upload in response.get("Uploads", [])]


@requires_object_store
class TestRoundTrips:
    async def test_a_small_object_round_trips(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange
        key = object_key()
        body = b"%PDF-1.7\nsmall\n"

        # Act
        written = await store.put(key=key, chunks=stream(body))
        read_back = await collect(store.get(key=key))

        # Assert
        assert written == len(body)
        assert read_back == body

    async def test_a_multipart_upload_round_trips(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange -- over one part, so the multipart path runs and S3's 5 MiB
        # minimum applies to every part but the last. The fake cannot fail this.
        key = object_key()
        body = os.urandom(MIN_PART_BYTES + 1024)

        # Act
        written = await store.put(key=key, chunks=stream(body[:100_000], body[100_000:]))
        read_back = await collect(store.get(key=key))

        # Assert
        assert written == len(body)
        assert hashlib.sha256(read_back).hexdigest() == hashlib.sha256(body).hexdigest()

    async def test_a_three_part_upload_round_trips(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange -- two full parts plus a short final one.
        key = object_key()
        body = os.urandom(2 * MIN_PART_BYTES + 4096)

        # Act
        await store.put(key=key, chunks=stream(body))
        read_back = await collect(store.get(key=key))

        # Assert
        assert read_back == body

    async def test_a_completed_multipart_upload_is_no_longer_open(
        self,
        store: S3CompatibleDocumentStore,
        probe: Any,
        object_key: Callable[[], str],
    ) -> None:
        # Arrange
        key = object_key()

        # Act
        await store.put(key=key, chunks=stream(os.urandom(2 * MIN_PART_BYTES + 17)))

        # Assert -- completion, not just success. An upload that returned
        # without a CompleteMultipartUpload leaves parts the listing hides.
        assert await open_uploads(probe, key) == []

    async def test_a_single_byte_object_round_trips(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        key = object_key()

        await store.put(key=key, chunks=stream(b"x"))

        assert await collect(store.get(key=key)) == b"x"

    async def test_an_empty_object_round_trips(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # The service refuses empty uploads, but the store is a lower layer and
        # must not corrupt one: PutObject with no body is a legal object.
        key = object_key()

        await store.put(key=key, chunks=stream())

        assert await collect(store.get(key=key)) == b""

    async def test_the_upload_is_sent_as_parts_rather_than_one_body(
        self,
        store: S3CompatibleDocumentStore,
        probe: Any,
        object_key: Callable[[], str],
    ) -> None:
        # Arrange -- 15 MiB at a 5 MiB part size.
        key = object_key()

        # Act
        await store.put(key=key, chunks=stream(os.urandom(3 * MIN_PART_BYTES)))

        # Assert -- a multipart object's ETag ends in `-<part count>`. This is
        # the server's own record of how the bytes arrived, so it cannot be
        # satisfied by an adapter that buffered the file and sent it in one
        # PutObject: that produces a plain MD5 with no suffix.
        head = await probe.head_object(Bucket=BUCKET, Key=key)
        etag = str(head["ETag"]).strip('"')
        assert "-" in etag, f"expected a multipart ETag, got {etag!r}"
        assert int(etag.rsplit("-", 1)[1]) >= 3

    async def test_an_exact_multiple_of_the_part_size_round_trips(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange -- the buffer is empty when the stream ends, so the adapter
        # sends a zero-byte final part. S3 permits that only for the last part,
        # and a service that rejects it would break every upload whose length
        # happens to divide evenly.
        key = object_key()
        body = os.urandom(2 * MIN_PART_BYTES)

        # Act
        written = await store.put(key=key, chunks=stream(body))

        # Assert
        assert written == len(body)
        assert await collect(store.get(key=key)) == body

    async def test_the_download_arrives_in_more_than_one_piece(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange
        key = object_key()
        await store.put(key=key, chunks=stream(os.urandom(2 * MIN_PART_BYTES)))

        # Act
        pieces = [len(block) async for block in store.get(key=key)]

        # Assert -- a real HTTP body handed over in chunks. One giant piece
        # would mean the adapter read the whole object before yielding.
        assert len(pieces) > 1
        assert sum(pieces) == 2 * MIN_PART_BYTES


@requires_object_store
class TestFailuresAreClosed:
    async def test_a_missing_object_is_not_found(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        with pytest.raises(DocumentNotFoundError):
            await collect(store.get(key=object_key()))

    async def test_deleting_an_absent_object_is_not_an_error(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Idempotent: a retry after a timeout gets the first caller's answer.
        await store.delete(key=object_key())

    async def test_delete_removes_the_object(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange
        key = object_key()
        await store.put(key=key, chunks=stream(b"%PDF-1.7\n"))

        # Act
        await store.delete(key=key)

        # Assert
        with pytest.raises(DocumentNotFoundError):
            await collect(store.get(key=key))

    async def test_health_reports_a_reachable_bucket(
        self, store: S3CompatibleDocumentStore
    ) -> None:
        await store.health()

    async def test_health_fails_closed_against_a_missing_bucket(self) -> None:
        # Arrange
        wrong = build_store(bucket=f"nonexistent-{uuid4().hex}")

        # Act / Assert -- either answer is a refusal; neither is "healthy".
        try:
            with pytest.raises((DocumentStorageUnavailableError, DocumentNotFoundError)):
                await wrong.health()
        finally:
            await wrong.aclose()

    async def test_a_missing_bucket_cannot_be_written_to(
        self, object_key: Callable[[], str]
    ) -> None:
        wrong = build_store(bucket=f"nonexistent-{uuid4().hex}")

        try:
            with pytest.raises((DocumentStorageUnavailableError, DocumentNotFoundError)):
                await wrong.put(key=object_key(), chunks=stream(b"%PDF-1.7\n"))
        finally:
            await wrong.aclose()

    async def test_bad_credentials_fail_closed(self) -> None:
        # Arrange -- proves requests are signed at all. An unsigned or
        # wrongly-signed request must not reach the bucket.
        wrong = build_store(
            access_key_id="wrong-access-key",
            secret_access_key="wrong-secret-key-wrong-secret-key",
        )

        # Act / Assert
        try:
            with pytest.raises(DocumentStorageUnavailableError):
                await wrong.health()
        finally:
            await wrong.aclose()

    async def test_bad_credentials_cannot_write(self, object_key: Callable[[], str]) -> None:
        wrong = build_store(
            access_key_id="wrong-access-key",
            secret_access_key="wrong-secret-key-wrong-secret-key",
        )

        try:
            with pytest.raises(DocumentStorageUnavailableError):
                await wrong.put(key=object_key(), chunks=stream(b"%PDF-1.7\n"))
        finally:
            await wrong.aclose()

    async def test_an_unsigned_request_cannot_read_a_stored_object(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange -- the bucket is private (deploy/compose/minio-init.sh), so
        # possessing a key must not be enough. Opaque key naming is a defence
        # in depth, not the access control.
        key = object_key()
        await store.put(key=key, chunks=stream(b"%PDF-1.7\nsecret\n"))

        # Act -- no signature, no credentials.
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{ENDPOINT}/{BUCKET}/{key}")

        # Assert
        assert response.status_code in {401, 403}
        assert b"secret" not in response.content

    async def test_an_unreachable_endpoint_fails_closed(self) -> None:
        # Arrange -- a port nothing listens on.
        unreachable = build_store(
            endpoint_url="http://127.0.0.1:1",
            connect_timeout_seconds=1.0,
            read_timeout_seconds=1.0,
        )

        # Act / Assert
        try:
            with pytest.raises(DocumentStorageUnavailableError):
                await unreachable.health()
        finally:
            await unreachable.aclose()

    async def test_a_silent_endpoint_times_out_rather_than_hanging(self) -> None:
        # Arrange -- a server that completes the TCP handshake and then says
        # nothing. Connect succeeds; the read must not wait forever, or one
        # sick endpoint pins a worker per request until the process dies.
        #
        # The handler waits on an event rather than sleeping. Python 3.12's
        # Server.wait_closed() blocks until every handler has returned, so a
        # sleeping handler makes teardown hang -- which is exactly how this
        # test failed the first time it was run.
        shutdown = asyncio.Event()

        async def accept_and_stall(
            _reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                await shutdown.wait()
            finally:
                writer.close()

        server = await asyncio.start_server(accept_and_stall, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        stalling = build_store(
            endpoint_url=f"http://127.0.0.1:{port}",
            connect_timeout_seconds=2.0,
            read_timeout_seconds=1.0,
        )

        # Act / Assert -- bounded by the read timeout and its retries, not by
        # how long the server is prepared to stay silent.
        started = asyncio.get_running_loop().time()
        try:
            async with asyncio.timeout(30):
                with pytest.raises(DocumentStorageUnavailableError):
                    await stalling.health()
            assert asyncio.get_running_loop().time() - started < 30
        finally:
            await stalling.aclose()
            shutdown.set()
            server.close()
            await server.wait_closed()

    async def test_a_virtual_host_client_cannot_reach_a_path_style_endpoint(self) -> None:
        # Arrange -- MinIO addresses buckets by path. A store configured for
        # virtual-host addressing asks for `bucket.127.0.0.1`, which does not
        # resolve. This proves the setting is wired to something real rather
        # than being accepted and ignored.
        virtual = build_store(use_path_style=False, connect_timeout_seconds=2.0)

        try:
            with pytest.raises((DocumentStorageUnavailableError, DocumentNotFoundError)):
                await virtual.health()
        finally:
            await virtual.aclose()

    async def test_aclose_is_safe_to_call_twice(self, object_key: Callable[[], str]) -> None:
        # Shutdown runs every closer even when an earlier one raised, so this
        # is called on paths that may already have closed it.
        built = build_store()
        await built.health()

        await built.aclose()
        await built.aclose()


@requires_object_store
class TestMultipartCleanup:
    async def test_a_failed_multipart_upload_leaves_no_object(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange -- a source that dies after the first part is uploaded.
        key = object_key()

        async def failing() -> AsyncIterator[bytes]:
            yield os.urandom(MIN_PART_BYTES + 1)
            raise RuntimeError("upload interrupted")

        # Act
        with pytest.raises(RuntimeError):
            await store.put(key=key, chunks=failing())

        # Assert
        with pytest.raises(DocumentNotFoundError):
            await collect(store.get(key=key))

    async def test_a_failed_multipart_upload_leaves_no_open_upload(
        self,
        store: S3CompatibleDocumentStore,
        probe: Any,
        object_key: Callable[[], str],
    ) -> None:
        # Arrange -- the assertion above only proves no *object* exists, which
        # is also true of an upload that was abandoned without an abort. Parts
        # left that way are invisible in an object listing and billed until a
        # lifecycle rule finds them. Ask the server directly.
        key = object_key()

        async def failing() -> AsyncIterator[bytes]:
            yield os.urandom(MIN_PART_BYTES + 1)
            raise RuntimeError("upload interrupted")

        # Act
        with pytest.raises(RuntimeError):
            await store.put(key=key, chunks=failing())

        # Assert
        assert await open_uploads(probe, key) == []

    async def test_a_two_part_failure_still_aborts(
        self,
        store: S3CompatibleDocumentStore,
        probe: Any,
        object_key: Callable[[], str],
    ) -> None:
        # Arrange -- fails after the *second* part, so the abort has to clean
        # up more than the upload's first moments.
        key = object_key()

        async def failing() -> AsyncIterator[bytes]:
            yield os.urandom(MIN_PART_BYTES)
            yield os.urandom(MIN_PART_BYTES)
            raise RuntimeError("upload interrupted late")

        # Act
        with pytest.raises(RuntimeError):
            await store.put(key=key, chunks=failing())

        # Assert
        assert await open_uploads(probe, key) == []
        with pytest.raises(DocumentNotFoundError):
            await collect(store.get(key=key))

    async def test_cancellation_aborts_the_multipart_upload(
        self,
        store: S3CompatibleDocumentStore,
        probe: Any,
        object_key: Callable[[], str],
    ) -> None:
        # Arrange -- a client disconnect arrives as task cancellation, which is
        # a BaseException and not an Exception. Cleanup written for `except
        # Exception` would silently skip it and leak an upload per dropped
        # connection.
        key = object_key()
        first_part_uploaded = asyncio.Event()

        async def stalling() -> AsyncIterator[bytes]:
            yield os.urandom(MIN_PART_BYTES + 1)
            # Reached only after the adapter has uploaded part one.
            first_part_uploaded.set()
            await asyncio.sleep(60)
            yield b"never"

        task = asyncio.create_task(store.put(key=key, chunks=stalling()))
        await asyncio.wait_for(first_part_uploaded.wait(), timeout=30)

        # Act
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # Assert
        assert await open_uploads(probe, key) == []
        with pytest.raises(DocumentNotFoundError):
            await collect(store.get(key=key))

    async def test_cancelling_a_download_closes_the_stream(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange -- a client that disconnects part-way through a download.
        key = object_key()
        await store.put(key=key, chunks=stream(os.urandom(2 * MIN_PART_BYTES)))

        # Act -- take one chunk, then abandon the generator.
        chunks = store.get(key=key)
        first = await anext(chunks)
        await chunks.aclose()

        # Assert -- the connection was released, so the next request works. A
        # leaked body would exhaust the connection pool after a few disconnects.
        assert len(first) > 0
        await store.health()
        assert await collect(store.get(key=key)) is not None


@requires_object_store
class TestSealedDocumentsThroughRealStorage:
    async def test_a_sealed_document_survives_a_real_round_trip(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange -- the whole stack minus the database: seal, upload through
        # multipart, download, open. Binary ciphertext through a real HTTP body
        # is where an encoding bug would show up.
        engine = cipher()
        identity = identity_for(uuid4())
        body = b"%PDF-1.7\n" + os.urandom(MIN_PART_BYTES) + b"\n%%EOF\n"
        key = object_key()

        # Act
        await store.put(
            key=key, chunks=engine.seal_stream(identity=identity, plaintext=stream(body))
        )
        opened = await collect(engine.open_stream(identity=identity, ciphertext=store.get(key=key)))

        # Assert
        assert opened == body

    async def test_a_multi_chunk_document_survives_a_real_round_trip(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange -- several sealed frames, so chunk indexing and the final
        # flag are exercised across real part boundaries.
        engine = cipher()
        identity = identity_for(uuid4())
        body = b"%PDF-1.7\n" + os.urandom(3 * MIN_PART_BYTES) + b"\n%%EOF\n"
        key = object_key()

        await store.put(
            key=key, chunks=engine.seal_stream(identity=identity, plaintext=stream(body))
        )

        assert (
            await collect(engine.open_stream(identity=identity, ciphertext=store.get(key=key)))
            == body
        )

    async def test_the_stored_object_holds_no_plaintext(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange
        engine = cipher()
        identity = identity_for(uuid4())
        key = object_key()
        body = b"%PDF-1.7\nJane Doe, MRN-40217788\n%%EOF\n"

        # Act
        await store.put(
            key=key, chunks=engine.seal_stream(identity=identity, plaintext=stream(body))
        )
        raw = await collect(store.get(key=key))

        # Assert -- read straight from the bucket, as an operator with storage
        # access would.
        assert b"Jane Doe" not in raw
        assert b"MRN-40217788" not in raw

    async def test_the_object_metadata_names_nothing(
        self,
        store: S3CompatibleDocumentStore,
        probe: Any,
        object_key: Callable[[], str],
    ) -> None:
        # Arrange -- an operator with bucket access sees keys and metadata
        # without ever decrypting anything, so neither may carry content.
        engine = cipher()
        identity = identity_for(uuid4())
        key = object_key()
        await store.put(
            key=key,
            chunks=engine.seal_stream(identity=identity, plaintext=stream(b"%PDF-1.7\nJane Doe\n")),
            content_type="application/octet-stream",
        )

        # Act
        head = await probe.head_object(Bucket=BUCKET, Key=key)

        # Assert -- the store is told the object is opaque bytes, never that it
        # is a PDF, and carries no user metadata at all.
        assert head["ContentType"] == "application/octet-stream"
        assert head.get("Metadata", {}) == {}
        assert "jane" not in key.lower()

    async def test_a_copy_under_another_key_does_not_open(
        self,
        store: S3CompatibleDocumentStore,
        probe: Any,
        object_key: Callable[[], str],
        keys: list[str],
    ) -> None:
        # Arrange -- an attacker with bucket write access copies one tenant's
        # object over another's key, hoping the gateway decrypts by key. It
        # decrypts by identity, so the AAD refuses.
        engine = cipher()
        victim = identity_for(uuid4())
        source_key = object_key()
        await store.put(
            key=source_key,
            chunks=engine.seal_stream(identity=victim, plaintext=stream(b"%PDF-1.7\nprivate\n")),
        )

        target_key = object_key()
        await probe.copy_object(
            Bucket=BUCKET, Key=target_key, CopySource={"Bucket": BUCKET, "Key": source_key}
        )
        keys.append(target_key)

        # Act / Assert -- the copy is byte-identical, so the bytes are there.
        # They still do not authenticate as anyone else's document.
        assert await collect(store.get(key=target_key)) == await collect(store.get(key=source_key))
        attacker = identity_for(uuid4(), tenant_id=OTHER_TENANT, user_id=OTHER_USER)
        with pytest.raises(DocumentEncryptionError):
            await collect(
                engine.open_stream(identity=attacker, ciphertext=store.get(key=target_key))
            )

    async def test_another_ring_key_cannot_open_a_stored_document(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange -- same key id, different key material: a restored-from-backup
        # ring, or a second environment pointed at the same bucket.
        identity = identity_for(uuid4())
        key = object_key()
        await store.put(
            key=key,
            chunks=cipher().seal_stream(identity=identity, plaintext=stream(b"%PDF-1.7\nx\n")),
        )

        # Act / Assert
        with pytest.raises(DocumentEncryptionError):
            await collect(
                cipher(key=OTHER_KEY).open_stream(identity=identity, ciphertext=store.get(key=key))
            )

    async def test_a_stored_body_does_not_open_as_a_filename(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange -- the two ciphertexts are produced by the same cipher under
        # the same identity, and must still not be interchangeable.
        engine = cipher()
        identity = identity_for(uuid4())
        key = object_key()
        await store.put(
            key=key,
            chunks=engine.seal_stream(identity=identity, plaintext=stream(b"%PDF-1.7\nbody\n")),
        )
        raw = await collect(store.get(key=key))

        # Act / Assert
        with pytest.raises(DocumentEncryptionError):
            engine.open_bytes(identity=identity, purpose=PURPOSE_FILENAME, raw=raw)

    async def test_a_stored_filename_does_not_open_as_a_body(
        self, store: S3CompatibleDocumentStore, object_key: Callable[[], str]
    ) -> None:
        # Arrange
        engine = cipher()
        identity = identity_for(uuid4())
        sealed = engine.seal_bytes(
            identity=identity, purpose=PURPOSE_FILENAME, plaintext=b"discharge-summary.pdf"
        )
        key = object_key()
        await store.put(key=key, chunks=stream(sealed))

        # Act / Assert -- open_stream uses PURPOSE_BODY, so the AAD differs.
        assert PURPOSE_BODY != PURPOSE_FILENAME
        with pytest.raises(DocumentEncryptionError):
            await collect(engine.open_stream(identity=identity, ciphertext=store.get(key=key)))
