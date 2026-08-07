"""S3-compatible object store, backed by aioboto3.

Targets AWS S3 (ADR-0035), and any other S3-compatible endpoint, through one
implementation. The difference between them is entirely configuration --
endpoint, credentials, addressing style -- resolved in ``Settings`` and handed
here already reduced to plain values. Nothing in this module knows or can ask
which service it is talking to, and there is deliberately no provider flag to
branch on: the moment one exists, provider-specific behaviour starts
accumulating behind it and the two paths drift.

That holds because the gateway needs no vendor extension to do its job. It
encrypts documents itself before they arrive here (chunked AES-256-GCM, per
document keys), so it does not reach for SSE-KMS on AWS; it addresses objects
by key, so it needs no admin API, no console, no bucket policy language. What
is left is ``PutObject``, multipart, ``GetObject``, ``DeleteObject``, and
``HeadBucket`` -- the intersection both services implement identically.

**Why multipart.** S3 requires the full object length up front for a simple
``PutObject``, which a streaming upload does not know. Multipart is how a stream
becomes an object without first landing somewhere to be measured, and it is the
only reason the gateway never needs the whole document in memory or on disk.
Small documents still take the single-request path, because a multipart upload
costs three round trips and most uploads fit in one part.

**Why 5 MiB matters.** S3 rejects any part except the last below 5 MiB, so the
buffer is filled to the part size before a part is sent, rather than forwarding
whatever chunk happened to arrive.

**Failure is closed and leaves nothing behind.** A multipart upload that fails
part-way is explicitly aborted; without that the parts persist, invisible in
listings, and are billed until a lifecycle rule notices them.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, Final

import aioboto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.domain.errors import DocumentNotFoundError, DocumentStorageUnavailableError
from app.observability.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from app.config.settings import Settings

logger = get_logger(__name__)

MIN_PART_BYTES: Final = 5_242_880
"""S3's minimum size for every part except the last."""

DOWNLOAD_CHUNK_BYTES: Final = 65_536

_MISSING_OBJECT_CODES: Final = frozenset({"NoSuchKey", "404", "NoSuchBucket"})


class S3CompatibleDocumentStore:
    """``DocumentStore`` over any S3-compatible endpoint.

    The client is opened lazily and kept for the life of the process. Building
    one per request would pay TLS and endpoint resolution on every upload.
    """

    __slots__ = ("_bucket", "_client", "_client_kwargs", "_part_bytes", "_session", "_stack")

    def __init__(
        self,
        *,
        bucket: str,
        region: str,
        endpoint_url: str | None,
        access_key_id: str | None,
        secret_access_key: str | None,
        part_bytes: int = MIN_PART_BYTES,
        use_path_style: bool = True,
        connect_timeout_seconds: float = 5.0,
        read_timeout_seconds: float = 30.0,
    ) -> None:
        if part_bytes < MIN_PART_BYTES:
            raise ValueError(f"part_bytes must be at least {MIN_PART_BYTES}")
        self._bucket = bucket
        self._part_bytes = part_bytes
        self._session = aioboto3.Session()
        self._client: Any = None
        self._stack: contextlib.AsyncExitStack | None = None
        self._client_kwargs: dict[str, Any] = {
            "service_name": "s3",
            "region_name": region,
            "endpoint_url": endpoint_url,
            "aws_access_key_id": access_key_id,
            "aws_secret_access_key": secret_access_key,
            "config": Config(
                # AWS S3 wants virtual-host; other services address by path.
                s3={"addressing_style": "path" if use_path_style else "virtual"},
                connect_timeout=connect_timeout_seconds,
                read_timeout=read_timeout_seconds,
                retries={"max_attempts": 3, "mode": "standard"},
                signature_version="s3v4",
            ),
        }

    @classmethod
    def from_settings(cls, settings: Settings) -> S3CompatibleDocumentStore:
        access_key = settings.object_store_access_key_id
        secret_key = settings.object_store_secret_access_key
        return cls(
            bucket=settings.object_store_bucket,
            region=settings.object_store_region,
            endpoint_url=settings.object_store_endpoint_url,
            access_key_id=access_key.get_secret_value() if access_key else None,
            secret_access_key=secret_key.get_secret_value() if secret_key else None,
            part_bytes=max(settings.document_chunk_bytes, MIN_PART_BYTES),
            # Resolved, not raw: the provider supplies the convention when the
            # deployment did not state one. This is the only place the provider
            # reaches the store, and it arrives already reduced to a boolean --
            # the store stays a single implementation that cannot branch on
            # which vendor it is talking to.
            use_path_style=settings.object_store_uses_path_style,
            connect_timeout_seconds=settings.object_store_connect_timeout_seconds,
            read_timeout_seconds=settings.object_store_read_timeout_seconds,
        )

    # -- Lifecycle --------------------------------------------------------
    async def _open(self) -> Any:
        if self._client is None:
            stack = contextlib.AsyncExitStack()
            try:
                self._client = await stack.enter_async_context(
                    self._session.client(**self._client_kwargs)
                )
            except (BotoCoreError, ClientError, OSError) as exc:
                await stack.aclose()
                raise _unavailable("client_open", exc) from exc
            self._stack = stack
        return self._client

    async def aclose(self) -> None:
        """Release the client. Safe to call more than once."""
        if self._stack is not None:
            with contextlib.suppress(Exception):
                await self._stack.aclose()
        self._stack = None
        self._client = None

    # -- DocumentStore ----------------------------------------------------
    async def put(
        self,
        *,
        key: str,
        chunks: AsyncIterator[bytes],
        content_type: str | None = None,
    ) -> int:
        """Stream ``chunks`` into one object, switching to multipart as needed."""
        client = await self._open()
        extra: dict[str, Any] = {"ContentType": content_type} if content_type else {}

        buffer = bytearray()
        upload_id: str | None = None
        parts: list[dict[str, Any]] = []
        total = 0

        try:
            async for block in chunks:
                buffer += block
                total += len(block)
                while len(buffer) >= self._part_bytes:
                    if upload_id is None:
                        upload_id = await self._begin_multipart(client, key=key, extra=extra)
                    parts.append(
                        await self._upload_part(
                            client,
                            key=key,
                            upload_id=upload_id,
                            number=len(parts) + 1,
                            body=bytes(buffer[: self._part_bytes]),
                        )
                    )
                    del buffer[: self._part_bytes]

            if upload_id is None:
                # Small enough to have never needed a multipart upload.
                await self._call(
                    "put_object",
                    client.put_object(Bucket=self._bucket, Key=key, Body=bytes(buffer), **extra),
                )
                return total

            # The last part is the only one allowed below the minimum size, and
            # a multipart upload must have at least one part.
            parts.append(
                await self._upload_part(
                    client,
                    key=key,
                    upload_id=upload_id,
                    number=len(parts) + 1,
                    body=bytes(buffer),
                )
            )
            await self._call(
                "complete_multipart_upload",
                client.complete_multipart_upload(
                    Bucket=self._bucket,
                    Key=key,
                    UploadId=upload_id,
                    MultipartUpload={"Parts": parts},
                ),
            )
            return total
        except BaseException:
            # Includes cancellation: an abandoned upload leaves parts behind
            # that no listing shows and that nothing else will clean up.
            if upload_id is not None:
                await self._abort(client, key=key, upload_id=upload_id)
            raise

    async def get(self, *, key: str) -> AsyncIterator[bytes]:
        """Yield the object's bytes in order."""
        client = await self._open()
        response = await self._call("get_object", client.get_object(Bucket=self._bucket, Key=key))
        body = response["Body"]
        try:
            async for chunk in body.iter_chunks(DOWNLOAD_CHUNK_BYTES):
                yield chunk
        except (BotoCoreError, ClientError, OSError) as exc:
            # A stream that dies mid-object must not look like a short file.
            raise _unavailable("get_object_stream", exc) from exc
        finally:
            with contextlib.suppress(Exception):
                body.close()

    async def delete(self, *, key: str) -> None:
        client = await self._open()
        await self._call("delete_object", client.delete_object(Bucket=self._bucket, Key=key))

    async def health(self) -> None:
        """Prove the bucket is actually reachable, not merely configured."""
        client = await self._open()
        await self._call("head_bucket", client.head_bucket(Bucket=self._bucket))

    # -- Internals --------------------------------------------------------
    async def _begin_multipart(self, client: Any, *, key: str, extra: dict[str, Any]) -> str:
        response = await self._call(
            "create_multipart_upload",
            client.create_multipart_upload(Bucket=self._bucket, Key=key, **extra),
        )
        return str(response["UploadId"])

    async def _upload_part(
        self, client: Any, *, key: str, upload_id: str, number: int, body: bytes
    ) -> dict[str, Any]:
        response = await self._call(
            "upload_part",
            client.upload_part(
                Bucket=self._bucket,
                Key=key,
                PartNumber=number,
                UploadId=upload_id,
                Body=body,
            ),
        )
        return {"ETag": response["ETag"], "PartNumber": number}

    async def _abort(self, client: Any, *, key: str, upload_id: str) -> None:
        try:
            await client.abort_multipart_upload(Bucket=self._bucket, Key=key, UploadId=upload_id)
        except Exception:
            # The original failure is what the caller needs to see; a failed
            # abort is an operational note, not a replacement for it.
            logger.warning("document_multipart_abort_failed")

    @staticmethod
    async def _call(operation: str, awaitable: Any) -> Any:
        """Await one S3 call, translating its failures into domain errors."""
        try:
            return await awaitable
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if code in _MISSING_OBJECT_CODES or status == 404:
                raise DocumentNotFoundError(log_context={"reason": "object_missing"}) from None
            raise _unavailable(operation, exc) from exc
        except (BotoCoreError, OSError) as exc:
            raise _unavailable(operation, exc) from exc

    def __repr__(self) -> str:
        return f"S3CompatibleDocumentStore(bucket={self._bucket!r})"


def _unavailable(operation: str, exc: BaseException) -> DocumentStorageUnavailableError:
    """Build the closed failure, naming the operation and never the endpoint.

    An endpoint URL or a bucket ARN in a public message is deployment
    reconnaissance, so only the failure's type reaches the log context.
    """
    logger.warning(
        "document_store_unavailable",
        operation=operation,
        failure_type=type(exc).__name__,
    )
    return DocumentStorageUnavailableError(log_context={"operation": operation})


__all__ = ["DOWNLOAD_CHUNK_BYTES", "MIN_PART_BYTES", "S3CompatibleDocumentStore"]
