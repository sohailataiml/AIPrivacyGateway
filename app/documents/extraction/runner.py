"""Running extraction where a hostile file cannot take the gateway with it.

``docs/threat-model.md`` says the exposure from malicious document content
"begins when extraction parses it, which is where a sandboxed, bounded
extraction path becomes load-bearing rather than merely planned". This module is
that path.

**Why a subprocess and not a thread.** pypdf and python-docx are pure Python, so
a thread pool would bound concurrency and nothing else. Three failure modes
survive a thread and do not survive a process boundary:

* a parser that does not terminate — a Python thread cannot be killed, so the
  worker is lost for the life of the process;
* a parser that allocates without bound — the whole gateway is what the OOM
  killer sees;
* a native crash in a C extension — ``lxml`` is C, and a segfault ends every
  in-flight request, not just the one holding the bad file.

**Why one process per document rather than a ``ProcessPoolExecutor``.** A future
returned by ``ProcessPoolExecutor`` cannot be cancelled once it starts running,
so a timeout on it is a lie: the parent stops waiting and the child keeps going,
holding a core. Concurrency here is bounded by a semaphore and each extraction
gets its own process, which ``terminate()`` genuinely ends. The cost is process
startup per document, which is small next to parsing a file large enough to be
worth worrying about.

**What crosses the boundary.** Bytes in, a list of strings out, and a reason
code on failure — all builtins. Exceptions are never pickled across: a reason
code is data, and an exception is a call stack that may have a document's
contents in a frame.
"""

from __future__ import annotations

import asyncio
import multiprocessing
from typing import TYPE_CHECKING, Any, Final, Protocol

from app.documents.extraction.extractors import extract_text
from app.documents.extraction.models import ExtractedDocument, build_extracted_document
from app.domain.errors import (
    DocumentExtractionError,
    DocumentExtractionTimeoutError,
    GatewayError,
)
from app.observability.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = get_logger(__name__)

type PipeEnd = Any
"""One end of the parent/child pipe.

Not ``multiprocessing.connection.Connection``: Windows hands back a
``PipeConnection`` instead, and the two are unrelated types. The only methods
used are ``send``, ``recv``, ``poll``, and ``close``, which both provide.
"""

DEFAULT_MAX_WORKERS: Final = 2
DEFAULT_TIMEOUT_SECONDS: Final = 30.0
DEFAULT_MAX_CHARACTERS: Final = 4_000_000
"""Roughly 4 MB of text -- about 1,500 pages of dense prose.

Generous for a document anyone means to send to a model, and far below what an
expansion attack aims for.
"""

_TERMINATE_GRACE_SECONDS: Final = 5.0


class ExtractionRunner(Protocol):
    """Where extraction actually happens.

    A Protocol so the isolation strategy can be swapped without the service
    above it knowing, and so tests of *callers* can use an in-process fake
    without paying process startup.
    """

    async def run(self, *, data: bytes, content_type: str) -> ExtractedDocument:
        """Extract one document, or raise.

        Raises:
            DocumentExtractionError: the file could not be parsed.
            DocumentExtractionTimeoutError: extraction exceeded its budget.
        """
        ...

    async def aclose(self) -> None:
        """Release whatever the runner holds. Safe to call more than once."""
        ...


def _worker(connection: PipeEnd, data: bytes, content_type: str, limit: int) -> None:
    """The child process. Never raises across the boundary; always answers.

    Runs in a fresh interpreter under the ``spawn`` start method, so it inherits
    no file descriptors, no database pool, and no key material from the parent.
    That is a second reason to prefer a process: the thing parsing a hostile
    file holds nothing worth stealing.
    """
    try:
        pages = extract_text(data=data, content_type=content_type, max_characters=limit)
    except GatewayError as exc:
        # A reason code, not an exception object. Pickling the exception would
        # carry its traceback, and a traceback holds frames that hold the
        # document.
        connection.send(("error", str(exc.log_context.get("reason", "extraction_failed"))))
    except BaseException:
        connection.send(("error", "extraction_crashed"))
    else:
        connection.send(("ok", pages))
    finally:
        connection.close()


class SubprocessExtractionRunner:
    """Bounded, killable extraction in one process per document."""

    __slots__ = ("_context", "_limit", "_semaphore", "_timeout")

    def __init__(
        self,
        *,
        max_workers: int = DEFAULT_MAX_WORKERS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_characters: int = DEFAULT_MAX_CHARACTERS,
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_characters < 1:
            raise ValueError("max_characters must be at least 1")
        self._semaphore = asyncio.Semaphore(max_workers)
        self._timeout = timeout_seconds
        self._limit = max_characters
        # `spawn` everywhere, including on Linux where `fork` is the default.
        # A forked child inherits the parent's memory -- key material, open
        # sockets, the audit queue -- into a process whose whole job is running
        # a parser over an attacker's file.
        self._context = multiprocessing.get_context("spawn")

    async def run(self, *, data: bytes, content_type: str) -> ExtractedDocument:
        async with self._semaphore:
            pages = await asyncio.to_thread(self._extract, data, content_type)
        return build_extracted_document(page_texts=pages)

    async def aclose(self) -> None:
        """Nothing is held between calls, so there is nothing to release."""
        return

    # -- Internals --------------------------------------------------------
    def _extract(self, data: bytes, content_type: str) -> list[str]:
        """Blocking. Runs on a worker thread so the event loop keeps serving."""
        parent, child = self._context.Pipe(duplex=False)
        process = self._context.Process(
            target=_worker, args=(child, data, content_type, self._limit), daemon=True
        )
        process.start()
        # The parent's copy of the write end must be closed, or `poll` never
        # reports EOF when the child dies and a crash looks like a hang.
        child.close()

        try:
            return self._await_result(parent, process)
        finally:
            parent.close()
            self._reap(process)

    def _await_result(self, parent: PipeEnd, process: Any) -> list[str]:
        if not parent.poll(self._timeout):
            # Nothing arrived in the budget. Either the parser is still working
            # or it will never finish; the answer is the same, and the process
            # is killed rather than left holding a core.
            logger.warning("document_extraction_timeout", timeout_seconds=self._timeout)
            raise DocumentExtractionTimeoutError(log_context={"reason": "timeout"})

        try:
            outcome, payload = parent.recv()
        except EOFError:
            # The child exited without answering: a segfault in a C extension,
            # or the OOM killer. This is the case a thread pool cannot survive.
            logger.warning("document_extraction_worker_died")
            raise DocumentExtractionError(log_context={"reason": "worker_died"}) from None

        if outcome == "error":
            raise DocumentExtractionError(log_context={"reason": str(payload)})
        return _as_pages(payload)

    def _reap(self, process: Any) -> None:
        """Leave no child behind, on any path out of ``_extract``."""
        if process.is_alive():
            process.terminate()
            process.join(_TERMINATE_GRACE_SECONDS)
        if process.is_alive():  # pragma: no cover - only a wedged kernel gets here
            process.kill()
            process.join(_TERMINATE_GRACE_SECONDS)
        process.close()

    def __repr__(self) -> str:
        return f"SubprocessExtractionRunner(timeout_seconds={self._timeout})"


class InlineExtractionRunner:
    """Extraction in the calling process. For tests of *callers* only.

    Deliberately not the default anywhere. It provides no isolation whatsoever,
    which is the entire point of the real runner -- so the isolation tests use
    ``SubprocessExtractionRunner`` and nothing else.
    """

    __slots__ = ("_limit",)

    def __init__(self, *, max_characters: int = DEFAULT_MAX_CHARACTERS) -> None:
        self._limit = max_characters

    async def run(self, *, data: bytes, content_type: str) -> ExtractedDocument:
        pages = extract_text(data=data, content_type=content_type, max_characters=self._limit)
        return build_extracted_document(page_texts=pages)

    async def aclose(self) -> None:
        return

    def __repr__(self) -> str:
        return "InlineExtractionRunner()"


def _as_pages(payload: object) -> list[str]:
    """Validate what came back before trusting it.

    The child is our own code, but it is a separate process and the boundary is
    a good place to stop assuming.
    """
    if not isinstance(payload, list) or not all(isinstance(page, str) for page in payload):
        raise DocumentExtractionError(log_context={"reason": "worker_payload_invalid"})
    return payload


def pages_of(document: ExtractedDocument) -> Sequence[str]:
    """Every page's text, in order. Convenience for tests and callers."""
    return [document.page_text(page) for page in document.pages]


__all__ = [
    "DEFAULT_MAX_CHARACTERS",
    "DEFAULT_MAX_WORKERS",
    "DEFAULT_TIMEOUT_SECONDS",
    "ExtractionRunner",
    "InlineExtractionRunner",
    "SubprocessExtractionRunner",
    "pages_of",
]
