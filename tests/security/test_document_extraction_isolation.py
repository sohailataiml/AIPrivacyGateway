"""Proof that extraction isolation is real rather than decorative.

``docs/threat-model.md`` claims the exposure from malicious document content is
contained by "a sandboxed, bounded extraction path". A claim like that is worth
exactly what its tests are worth, so these run against
``SubprocessExtractionRunner`` and never against the inline one -- the inline
runner provides no isolation at all, which is why it exists only for tests of
*callers*.

Four properties, and each corresponds to a way the containment could be quietly
absent:

* **the timeout fires**, so a parser that never terminates does not hold a
  request forever;
* **the worker is killed and reaped**, so a timeout leaves no orphan burning a
  core -- the failure mode a ``ProcessPoolExecutor`` cannot avoid, because its
  futures cannot be cancelled once running;
* **the gateway survives**, so the process after a timeout is still able to
  extract;
* **concurrency is bounded**, so a burst of uploads cannot start a process per
  request.

These are slower than the rest of the unit suite because they start real
processes. That is the point: a fast version of this file would be testing
something else.
"""

from __future__ import annotations

import asyncio
import contextlib
import multiprocessing
import time

import pytest

from app.documents.extraction.runner import (
    InlineExtractionRunner,
    SubprocessExtractionRunner,
)
from app.documents.models import CONTENT_TYPE_PDF, CONTENT_TYPE_TXT
from app.domain.errors import DocumentExtractionError, DocumentExtractionTimeoutError
from tests.fixtures.document_files import TRUNCATED_PDF, make_pdf
from tests.fixtures.documents import CANARIES

pytestmark = pytest.mark.security

TXT = f"{CANARIES['person_name']}\n{CANARIES['mrn']}\n".encode()


@pytest.fixture
async def runner():
    built = SubprocessExtractionRunner(max_workers=2, timeout_seconds=30.0)
    yield built
    await built.aclose()


class TestItActuallyWorks:
    async def test_a_document_round_trips_through_the_subprocess(self, runner) -> None:
        extracted = await runner.run(data=TXT, content_type=CONTENT_TYPE_TXT)

        assert extracted.text == TXT.decode("utf-8")
        assert extracted.page_count == 1

    async def test_a_pdf_round_trips_with_its_pages(self, runner) -> None:
        data = make_pdf([CANARIES["person_name"], CANARIES["mrn"]])

        extracted = await runner.run(data=data, content_type=CONTENT_TYPE_PDF)

        assert extracted.page_count == 2
        assert CANARIES["mrn"] in extracted.text

    async def test_the_subprocess_and_inline_runners_agree(self, runner) -> None:
        # If the two disagreed, every test written against the inline runner
        # would be testing a different system from the one that ships.
        data = make_pdf(["alpha page", "beta page"])
        inline = InlineExtractionRunner()

        from_subprocess = await runner.run(data=data, content_type=CONTENT_TYPE_PDF)
        from_inline = await inline.run(data=data, content_type=CONTENT_TYPE_PDF)

        assert from_subprocess.text == from_inline.text
        assert from_subprocess.pages == from_inline.pages

    async def test_a_parse_failure_crosses_the_boundary_as_a_reason_code(self, runner) -> None:
        # The child never pickles an exception back: a traceback holds frames,
        # and a frame holds the document. Only the reason code travels.
        with pytest.raises(DocumentExtractionError) as caught:
            await runner.run(data=TRUNCATED_PDF, content_type=CONTENT_TYPE_PDF)

        assert caught.value.log_context["reason"] == "pdf_unreadable"


class TestContainment:
    async def test_a_timeout_fires_and_kills_the_worker(self) -> None:
        # Arrange -- a budget shorter than a process can even start in. Any
        # extraction overruns it, which is what makes this deterministic rather
        # than a race against a slow parser.
        strict = SubprocessExtractionRunner(max_workers=1, timeout_seconds=0.01)

        # Act
        started = time.monotonic()
        with pytest.raises(DocumentExtractionTimeoutError):
            await strict.run(data=make_pdf(["x"] * 20), content_type=CONTENT_TYPE_PDF)
        elapsed = time.monotonic() - started

        # Assert -- bounded by the budget plus the kill, not by the parse.
        assert elapsed < 20.0
        await strict.aclose()

    async def test_a_timeout_leaves_no_orphaned_process(self) -> None:
        # The failure this design exists to avoid. A ProcessPoolExecutor future
        # cannot be cancelled once it is running, so its timeout stops the
        # parent waiting and leaves the child holding a core indefinitely.
        strict = SubprocessExtractionRunner(max_workers=1, timeout_seconds=0.01)
        before = len(multiprocessing.active_children())

        for _ in range(3):
            with pytest.raises(DocumentExtractionTimeoutError):
                await strict.run(data=make_pdf(["x"] * 20), content_type=CONTENT_TYPE_PDF)

        # active_children() reaps as it reports, so this is both the assertion
        # and the cleanup a leak would defeat.
        assert len(multiprocessing.active_children()) <= before
        await strict.aclose()

    async def test_the_gateway_still_works_after_a_timeout(self) -> None:
        # Containment means the damage stops at the worker. A runner that was
        # left unusable afterwards would have converted one bad document into
        # an outage.
        strict = SubprocessExtractionRunner(max_workers=1, timeout_seconds=0.01)
        with pytest.raises(DocumentExtractionTimeoutError):
            await strict.run(data=TXT, content_type=CONTENT_TYPE_TXT)
        await strict.aclose()

        generous = SubprocessExtractionRunner(max_workers=1, timeout_seconds=30.0)
        extracted = await generous.run(data=TXT, content_type=CONTENT_TYPE_TXT)

        assert extracted.text == TXT.decode("utf-8")
        await generous.aclose()

    async def test_repeated_extractions_do_not_accumulate_processes(self, runner) -> None:
        # One process per document is only acceptable if each one is reaped.
        before = len(multiprocessing.active_children())

        for _ in range(4):
            await runner.run(data=TXT, content_type=CONTENT_TYPE_TXT)

        assert len(multiprocessing.active_children()) <= before

    async def test_the_child_is_spawned_rather_than_forked(self) -> None:
        # A security property with no public accessor, so the test reads the
        # attribute directly. `fork` would hand the parser a copy of the
        # parent's memory: key rings, open sockets, the audit queue. `spawn`
        # gives it a fresh interpreter holding nothing worth stealing.
        built = SubprocessExtractionRunner()

        assert built._context.get_start_method() == "spawn"

        await built.aclose()


class TestBoundedConcurrency:
    async def test_concurrency_is_capped_at_max_workers(self) -> None:
        # Unbounded extraction is a denial-of-service vector: a handful of
        # large uploads would start a process each and starve the request path.
        limited = SubprocessExtractionRunner(max_workers=1, timeout_seconds=30.0)
        data = make_pdf(["page"] * 4)

        peak = 0

        async def watch() -> None:
            # Samples until cancelled rather than a fixed number of times: a
            # sampler that stops early would report a peak of zero and pass.
            nonlocal peak
            while True:
                peak = max(peak, len(multiprocessing.active_children()))
                await asyncio.sleep(0.01)

        watcher = asyncio.create_task(watch())
        await asyncio.gather(
            *(limited.run(data=data, content_type=CONTENT_TYPE_PDF) for _ in range(4))
        )
        watcher.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await watcher

        assert peak >= 1, "the sampler never observed a worker; it proves nothing"

        assert peak <= 1, f"{peak} workers ran at once with max_workers=1"
        await limited.aclose()

    async def test_several_documents_all_extract_correctly_in_parallel(self, runner) -> None:
        # Bounding concurrency must not mix results between callers.
        bodies = [f"document number {index} for {CANARIES['mrn']}" for index in range(6)]

        results = await asyncio.gather(
            *(runner.run(data=body.encode(), content_type=CONTENT_TYPE_TXT) for body in bodies)
        )

        assert [extracted.text for extracted in results] == bodies

    @pytest.mark.parametrize(
        ("max_workers", "timeout_seconds", "max_characters"),
        [(0, 1.0, 1), (-1, 1.0, 1), (1, 0.0, 1), (1, -1.0, 1), (1, 1.0, 0)],
    )
    def test_an_unworkable_configuration_is_refused_at_construction(
        self, max_workers: int, timeout_seconds: float, max_characters: int
    ) -> None:
        # A zero bound is not a bound. Failing at construction makes it a
        # startup error rather than an unbounded runtime.
        with pytest.raises(ValueError):
            SubprocessExtractionRunner(
                max_workers=max_workers,
                timeout_seconds=timeout_seconds,
                max_characters=max_characters,
            )


class TestTheBoundaryItself:
    async def test_the_character_limit_is_enforced_inside_the_child(self) -> None:
        # The limit travels with the work rather than being checked on return.
        # Checking afterwards would mean the child had already allocated the
        # thing the limit exists to prevent.
        strict = SubprocessExtractionRunner(max_workers=1, timeout_seconds=30.0, max_characters=8)

        with pytest.raises(DocumentExtractionError) as caught:
            await strict.run(data=b"x" * 500, content_type=CONTENT_TYPE_TXT)

        assert caught.value.log_context["reason"] == "extracted_text_over_limit"
        await strict.aclose()

    async def test_aclose_is_safe_to_call_twice(self, runner) -> None:
        await runner.aclose()
        await runner.aclose()

    async def test_no_canary_reaches_a_log_during_extraction(
        self, runner, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        caplog.set_level(logging.DEBUG)

        await runner.run(data=TXT, content_type=CONTENT_TYPE_TXT)
        with pytest.raises(DocumentExtractionError):
            await runner.run(data=TRUNCATED_PDF, content_type=CONTENT_TYPE_PDF)

        emitted = "\n".join(
            record.getMessage() + repr(record.__dict__) for record in caplog.records
        )
        for canary in CANARIES.values():
            assert canary not in emitted
