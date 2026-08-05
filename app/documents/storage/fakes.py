"""In-memory ``DocumentStore`` for tests in other packages.

This fake exists so the document service, the API, and the privacy suites do not
need MinIO. It reproduces the parts of the contract those tests can get wrong:

* a partially written object is never readable -- ``put`` publishes only on
  success, exactly as a completed multipart upload does;
* a missing key raises ``DocumentNotFoundError`` rather than yielding nothing;
* failure is closed, via ``simulate_failure`` -- assert that your code refuses
  to record a document it could not store.

It also records the chunk sizes it was handed, so a test can prove the caller
streamed rather than buffered.

It does **not** talk to S3 and does not enforce the 5 MiB part minimum. Use it
to test the code around the store; use the integration suite against MinIO to
test the store itself.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.domain.errors import DocumentNotFoundError, GatewayError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class FakeDocumentStore:
    """A ``DocumentStore`` backed by a dictionary."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}
        self._failure: GatewayError | None = None
        self.put_chunk_sizes: list[list[int]] = []
        """One entry per ``put``, holding the size of each chunk it received."""

        self.aborted_keys: list[str] = []
        """Keys whose write failed part-way and left nothing behind."""

    # -- Test controls ----------------------------------------------------
    def simulate_failure(self, error: GatewayError | None) -> None:
        """Make every subsequent call raise ``error``. Pass ``None`` to clear."""
        self._failure = error

    def stored_keys(self) -> list[str]:
        return sorted(self._objects)

    def stored_bytes(self, key: str) -> bytes:
        """The exact bytes held under ``key``. For assertions only."""
        return self._objects[key]

    def contains_plaintext(self, needle: bytes) -> bool:
        """Whether any stored object contains ``needle``. For privacy assertions."""
        return any(needle in blob for blob in self._objects.values())

    # -- DocumentStore ----------------------------------------------------
    async def put(
        self,
        *,
        key: str,
        chunks: AsyncIterator[bytes],
        content_type: str | None = None,
    ) -> int:
        self._guard()
        sizes: list[int] = []
        buffer = bytearray()
        try:
            async for block in chunks:
                self._guard()
                sizes.append(len(block))
                buffer += block
        except BaseException:
            # Nothing is published, mirroring an aborted multipart upload.
            self.aborted_keys.append(key)
            raise
        self.put_chunk_sizes.append(sizes)
        self._objects[key] = bytes(buffer)
        return len(buffer)

    async def get(self, *, key: str) -> AsyncIterator[bytes]:
        self._guard()
        blob = self._objects.get(key)
        if blob is None:
            raise DocumentNotFoundError(log_context={"reason": "object_missing"})
        # Deliberately handed back in pieces: a caller that only works when the
        # whole object arrives at once is not streaming.
        step = 64 * 1024
        for offset in range(0, max(len(blob), 1), step):
            yield blob[offset : offset + step]

    async def delete(self, *, key: str) -> None:
        self._guard()
        self._objects.pop(key, None)

    async def health(self) -> None:
        self._guard()

    # -- Internals --------------------------------------------------------
    def _guard(self) -> None:
        if self._failure is not None:
            raise self._failure

    def __repr__(self) -> str:
        return f"FakeDocumentStore(objects={len(self._objects)})"


__all__ = ["FakeDocumentStore"]
