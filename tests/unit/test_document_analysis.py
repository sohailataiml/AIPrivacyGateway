"""Stored document to labeled spans, through the real decryption path.

Like ``test_document_processing.py``, these run Phase 1 for real — the in-memory
store and SQLite, but genuine chunked AES-256-GCM and genuine per-document HKDF
keys — so the seam between storage, extraction, segmentation, and detection is
exercised rather than assumed. The detector is
:class:`~app.detection.fakes.FakeDetector`, which shares
``app.detection.postprocess.finalize`` with the Presidio engine, so thresholds,
allowlists, checksum validation, and within-segment overlap resolution behave
exactly as they do in production. What differs is only which candidates are
proposed, and that is not what this file is about.

The assertion worth reading is
``test_a_value_on_a_segment_boundary_is_found_whole_and_once``. Everything else
here is orchestration; that one is the fail-open condition the whole phase
exists to close, tested against the real segmenter rather than a hand-built
segment list.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import pytest
from sqlalchemy import insert, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.models import Tenant
from app.detection.config import DetectionConfig
from app.detection.entities import EMAIL_ADDRESS, MEDICAL_RECORD_NUMBER, PERSON, US_SSN
from app.detection.fakes import FakeDetector
from app.documents.analysis.analyzer import DocumentAnalyzer, _first_failure
from app.documents.extraction.runner import InlineExtractionRunner
from app.documents.models import CONTENT_TYPE_TXT
from app.documents.processing import DocumentProcessor
from app.documents.segmentation import Segmenter
from app.documents.service import DocumentService
from app.documents.storage.fakes import FakeDocumentStore
from app.domain.errors import (
    DetectorUnavailableError,
    DocumentNotFoundError,
    EntityLimitExceededError,
    PolicyNotFoundError,
    PolicyViolationError,
)
from app.domain.models import DetectedEntity, EntityAction
from app.policy.models import EntityRule
from tests.fixtures.documents import (
    CANARIES,
    MAX_BYTES,
    OTHER_USER,
    TENANT,
    USER,
    make_cipher,
    stream,
)
from tests.fixtures.policies import FailingPolicySource, FakePolicySource, snapshot

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from contextlib import AbstractAsyncContextManager
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from app.detection.base import Detector
    from app.policy.models import PolicySnapshot

DETECTABLE_MRN = "MRN-40217788"
"""The shipped MRN format -- ``MRN-`` plus eight digits, per ``recognizers.py``.

Deliberately not ``CANARIES["mrn"]``. That value is ``MRN-ZZ4471903``, which
neither the real recognizer nor the fake matches, and the canary suite records
that gap on purpose. A happy-path test needs a value detection actually finds;
building one on a value it cannot see would assert nothing while looking
thorough.
"""

BODY = (
    f"{CANARIES['person_name']} attended the oncology clinic on Tuesday.\n"
    f"Record number {DETECTABLE_MRN}, contact {CANARIES['email']} for follow-up.\n"
).encode()

PROTECT_EVERYTHING = {
    PERSON: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    EMAIL_ADDRESS: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    MEDICAL_RECORD_NUMBER: EntityRule(action=EntityAction.REDACT, min_score=0.5),
    US_SSN: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
}


# ---------------------------------------------------------------------------
# Detectors that record or misbehave
# ---------------------------------------------------------------------------
class RecordingDetector:
    """Wraps a detector and records how it was called, and how concurrently."""

    def __init__(self, inner: Detector) -> None:
        self._inner = inner
        self.calls: list[dict[str, Any]] = []
        self.active = 0
        self.peak = 0

    async def detect(
        self,
        text: str,
        *,
        language: str = "en",
        requested_entities: set[str] | None = None,
        diagnostic: bool = False,
    ) -> list[DetectedEntity]:
        self.calls.append(
            {
                "length": len(text),
                "language": language,
                "requested_entities": requested_entities,
                "diagnostic": diagnostic,
            }
        )
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            # Yield the loop so a bound that is not enforced shows up as a peak
            # above the limit rather than as one call at a time by accident.
            await asyncio.sleep(0)
            return await self._inner.detect(
                text,
                language=language,
                requested_entities=requested_entities,
                diagnostic=diagnostic,
            )
        finally:
            self.active -= 1


class FailingDetector:
    """Raises on its ``fail_on``-th call. Counts every call it receives.

    The ``await`` before the failure matters. Without it a coroutine raises on
    its very first step, so every task in the group fails before the group has
    had a chance to cancel anything -- and a cancellation test would pass or
    fail on event-loop scheduling rather than on the behaviour under test.
    """

    def __init__(self, error: BaseException, *, fail_on: int = 1) -> None:
        self._error = error
        self._fail_on = fail_on
        self.call_count = 0

    async def detect(
        self,
        text: str,
        *,
        language: str = "en",
        requested_entities: set[str] | None = None,
        diagnostic: bool = False,
    ) -> list[DetectedEntity]:
        self.call_count += 1
        await asyncio.sleep(0)
        if self.call_count >= self._fail_on:
            raise self._error
        return []


class ScriptedDetector:
    """Returns fixed spans by offset within whatever text it is given.

    Used where a test needs an exact number of detections rather than whatever
    the regex rules happen to find.
    """

    def __init__(self, per_segment: int, *, entity_type: str = PERSON) -> None:
        self._per_segment = per_segment
        self._entity_type = entity_type

    async def detect(
        self,
        text: str,
        *,
        language: str = "en",
        requested_entities: set[str] | None = None,
        diagnostic: bool = False,
    ) -> list[DetectedEntity]:
        spans: list[DetectedEntity] = []
        for index in range(self._per_segment):
            start = index * 4
            if start + 3 > len(text):
                break
            spans.append(
                DetectedEntity(entity_type=self._entity_type, start=start, end=start + 3, score=0.9)
            )
        return spans


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def store() -> FakeDocumentStore:
    return FakeDocumentStore()


@pytest.fixture
async def session_scope() -> AsyncIterator[Callable[[], AbstractAsyncContextManager[AsyncSession]]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        await connection.execute(
            insert(Tenant).values(id=TENANT, name="test", slug="test", status="active")
        )
    factory = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def scope() -> AsyncIterator[AsyncSession]:
        session = factory()
        try:
            yield session
        finally:
            await session.close()

    yield scope
    await engine.dispose()


@pytest.fixture
def documents(
    store: FakeDocumentStore,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> DocumentService:
    return DocumentService(
        store=store,
        cipher=make_cipher(chunk_bytes=512),
        session_scope=session_scope,
        max_document_bytes=MAX_BYTES,
    )


def processor_of(
    documents: DocumentService, *, max_characters: int, overlap: int
) -> DocumentProcessor:
    return DocumentProcessor(
        source=documents,
        runner=InlineExtractionRunner(),
        segmenter=Segmenter(max_characters=max_characters, overlap_characters=overlap),
        max_document_bytes=MAX_BYTES,
    )


@pytest.fixture
def processor(documents: DocumentService) -> DocumentProcessor:
    return processor_of(documents, max_characters=200, overlap=48)


def policy_of(
    entities: dict[str, EntityRule] | None = None, *, version: int = 7, max_entities: int = 500
) -> PolicySnapshot:
    return snapshot(
        entities if entities is not None else PROTECT_EVERYTHING,
        tenant_id=TENANT,
        version=version,
        max_entities=max_entities,
    )


def analyzer_of(
    processor: DocumentProcessor,
    detector: Detector,
    *,
    policy: PolicySnapshot | None = None,
    policies: Any = None,
    max_entities: int = 10_000,
    concurrency: int = 4,
) -> DocumentAnalyzer:
    return DocumentAnalyzer(
        source=processor,
        detector=detector,
        policies=policies if policies is not None else FakePolicySource(policy or policy_of()),
        max_entities=max_entities,
        concurrency=concurrency,
    )


def fake_detector() -> Detector:
    return FakeDetector(config=DetectionConfig(), person_names=(CANARIES["person_name"],))


def surrounded(padding: str, value: str, offset: int) -> str:
    """``value`` inserted at ``offset``, with whitespace on both sides.

    The spaces are load-bearing. Splicing an email straight into ``word word``
    yields ``...clinic.testword``, which the address recognizer happily matches
    whole -- so the span would be a superset of the value and every assertion
    comparing against the value exactly would fail for a reason that has
    nothing to do with segment boundaries.
    """
    return f"{padding[:offset]} {value} {padding[offset:]}"


async def upload(
    documents: DocumentService,
    *,
    body: bytes,
    filename: str = "notes.txt",
    content_type: str = CONTENT_TYPE_TXT,
    user_id: UUID = USER,
) -> UUID:
    stored = await documents.store(
        tenant_id=TENANT,
        user_id=user_id,
        filename=filename,
        declared_content_type=content_type,
        declared_length=len(body),
        source=stream(body),
    )
    return stored.metadata.id


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------
class TestTheHappyPath:
    async def test_a_stored_document_becomes_labeled_global_spans(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        document_id = await upload(documents, body=BODY)
        analyzer = analyzer_of(processor, fake_detector())

        analyzed = await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert analyzed.span_count > 0, "the canary body must produce detections"
        # The offsets are the point: each must address the exact characters it
        # claims, in the document's own coordinate system.
        for span in analyzed.spans:
            assert analyzed.text_of(span) == BODY.decode()[span.start : span.end]

    async def test_the_canaries_are_the_values_that_were_found(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        document_id = await upload(documents, body=BODY)
        analyzer = analyzer_of(processor, fake_detector())

        analyzed = await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        found = {analyzed.text_of(span) for span in analyzed.spans}
        assert CANARIES["email"] in found
        assert DETECTABLE_MRN in found
        assert CANARIES["person_name"] in found

    async def test_the_policy_action_and_version_travel_with_the_result(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        document_id = await upload(documents, body=BODY)
        analyzer = analyzer_of(processor, fake_detector(), policy=policy_of(version=41))

        analyzed = await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert analyzed.policy_version == 41
        by_type = {span.entity_type: span.action for span in analyzed.spans}
        assert by_type[EMAIL_ADDRESS] is EntityAction.TOKENIZE
        assert by_type[MEDICAL_RECORD_NUMBER] is EntityAction.REDACT

    async def test_every_span_names_a_page_and_a_segment(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        document_id = await upload(documents, body=BODY)
        analyzer = analyzer_of(processor, fake_detector())

        analyzed = await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        for span in analyzed.spans:
            assert span.pages, "a span with no page cannot be traced in an audit trail"
            assert span.segments
            assert list(span.segments) == sorted(span.segments)

    async def test_a_clean_document_is_a_result_not_a_failure(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        # "Nothing sensitive found" must be distinguishable from "detection
        # failed". A detector that cannot run raises; an empty result means the
        # text is clean.
        document_id = await upload(documents, body=b"The weather was unremarkable all week.\n")
        analyzer = analyzer_of(processor, fake_detector())

        analyzed = await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert analyzed.span_count == 0
        assert analyzed.counts_by_action() == {}


# ---------------------------------------------------------------------------
# Boundaries: the fail-open condition, against the real segmenter
# ---------------------------------------------------------------------------
class TestBoundaries:
    @pytest.mark.parametrize("offset", [0, 17, 40, 63, 78, 95])
    async def test_a_value_on_a_segment_boundary_is_found_whole_and_once(
        self, documents: DocumentService, offset: int
    ) -> None:
        # Arrange -- segment the document small enough that a boundary lands in
        # the middle of the padding, and slide the canary email across it.
        # Segmentation promises the value appears whole in some segment; this
        # asserts detection over those segments then yields exactly one span
        # covering it, not two and not a fragment.
        padding = "word " * 40
        body = surrounded(padding, CANARIES["email"], offset).encode()
        document_id = await upload(documents, body=body)
        analyzer = analyzer_of(
            processor_of(documents, max_characters=100, overlap=48), fake_detector()
        )

        # Act
        analyzed = await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        # Assert
        matches = [span for span in analyzed.spans if analyzed.text_of(span) == CANARIES["email"]]
        assert len(matches) == 1, (
            f"{CANARIES['email']} at offset {offset} produced {len(matches)} spans"
        )

    async def test_a_value_seen_in_two_segments_records_both(
        self, documents: DocumentService
    ) -> None:
        # Provenance, and the proof that deduplication actually happened rather
        # than the value simply never landing in an overlap.
        padding = "word " * 40
        body = surrounded(padding, CANARIES["email"], 60).encode()
        document_id = await upload(documents, body=body)
        analyzer = analyzer_of(
            processor_of(documents, max_characters=120, overlap=96), fake_detector()
        )

        analyzed = await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        matches = [span for span in analyzed.spans if analyzed.text_of(span) == CANARIES["email"]]
        assert len(matches) == 1
        assert len(matches[0].segments) >= 2, "the fixture must place the value in an overlap"


# ---------------------------------------------------------------------------
# How the detector is asked
# ---------------------------------------------------------------------------
class TestDetectorContract:
    async def test_detection_is_not_narrowed_to_the_policy_entity_types(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        # Defect 7, which this must not reintroduce: the policy defaults an
        # unconfigured type to TOKENIZE, so narrowing the detector to
        # policy-listed types means an unlisted sensitive type is never detected
        # and the protective default can never fire.
        document_id = await upload(documents, body=BODY)
        detector = RecordingDetector(fake_detector())
        narrow = policy_of({PERSON: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5)})

        await analyzer_of(processor, detector, policy=narrow).analyze(
            tenant_id=TENANT, user_id=USER, document_id=document_id
        )

        assert detector.calls
        assert all(call["requested_entities"] is None for call in detector.calls)

    async def test_an_unlisted_sensitive_type_still_reaches_the_result(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        # The consequence of the above, stated as an outcome rather than a call
        # shape: with only PERSON configured, the email is still labeled, and
        # labeled with the protective default.
        document_id = await upload(documents, body=BODY)
        narrow = policy_of({PERSON: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5)})

        analyzed = await analyzer_of(processor, fake_detector(), policy=narrow).analyze(
            tenant_id=TENANT, user_id=USER, document_id=document_id
        )

        emails = [span for span in analyzed.spans if span.entity_type == EMAIL_ADDRESS]
        assert emails
        assert emails[0].action is EntityAction.TOKENIZE

    async def test_diagnostics_are_never_requested(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        document_id = await upload(documents, body=BODY)
        detector = RecordingDetector(fake_detector())

        await analyzer_of(processor, detector).analyze(
            tenant_id=TENANT, user_id=USER, document_id=document_id
        )

        assert all(call["diagnostic"] is False for call in detector.calls)

    async def test_every_segment_is_offered_to_the_detector(
        self, documents: DocumentService
    ) -> None:
        document_id = await upload(documents, body=BODY * 20)
        processor = processor_of(documents, max_characters=200, overlap=48)
        detector = RecordingDetector(fake_detector())
        analyzer = analyzer_of(processor, detector)

        analyzed = await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert analyzed.segment_count > 1, "the fixture must produce several segments"
        assert len(detector.calls) == analyzed.segment_count


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------
class TestBounds:
    async def test_concurrency_is_capped(self, documents: DocumentService) -> None:
        document_id = await upload(documents, body=BODY * 30)
        detector = RecordingDetector(fake_detector())
        analyzer = analyzer_of(
            processor_of(documents, max_characters=120, overlap=32), detector, concurrency=2
        )

        analyzed = await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert analyzed.segment_count > 4, "too few segments to demonstrate a bound"
        assert detector.peak >= 1, "non-vacuity: the sampler must have seen a call"
        assert detector.peak <= 2

    async def test_the_bound_is_shared_across_concurrent_documents(
        self, documents: DocumentService
    ) -> None:
        # The semaphore lives on the analyzer, not on the call, so two documents
        # analysed at once cannot each open their own budget.
        first = await upload(documents, body=BODY * 20, filename="a.txt")
        second = await upload(documents, body=BODY * 20, filename="b.txt")
        detector = RecordingDetector(fake_detector())
        analyzer = analyzer_of(
            processor_of(documents, max_characters=120, overlap=32), detector, concurrency=2
        )

        await asyncio.gather(
            analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=first),
            analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=second),
        )

        assert detector.peak <= 2

    async def test_an_over_budget_document_is_refused(self, documents: DocumentService) -> None:
        document_id = await upload(documents, body=BODY)
        analyzer = analyzer_of(
            processor_of(documents, max_characters=200, overlap=0),
            ScriptedDetector(per_segment=8),
            max_entities=3,
        )

        with pytest.raises(EntityLimitExceededError) as caught:
            await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert caught.value.log_context["reason"] == "document_entity_budget_exceeded"
        assert caught.value.log_context["limit"] == 3

    async def test_a_document_at_the_budget_is_accepted(self, documents: DocumentService) -> None:
        # The boundary in the other direction, so the check is `>` and not `>=`.
        document_id = await upload(documents, body=BODY)
        analyzer = analyzer_of(
            processor_of(documents, max_characters=4_000, overlap=0),
            ScriptedDetector(per_segment=3),
            max_entities=3,
        )

        analyzed = await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert analyzed.span_count == 3

    @pytest.mark.parametrize(("max_entities", "concurrency"), [(0, 1), (1, 0), (-1, 1)])
    def test_an_unworkable_bound_is_refused_at_construction(
        self, documents: DocumentService, max_entities: int, concurrency: int
    ) -> None:
        with pytest.raises(ValueError):
            DocumentAnalyzer(
                source=processor_of(documents, max_characters=100, overlap=0),
                detector=fake_detector(),
                policies=FakePolicySource(policy_of()),
                max_entities=max_entities,
                concurrency=concurrency,
            )


class TestFailureReporting:
    def test_a_nested_failure_group_still_reports_a_domain_error(self) -> None:
        # TaskGroup nests groups when a task is itself a group's parent, and the
        # flattening is the difference between reporting "the detector is down"
        # and reporting a generic 500 nobody can act on.
        inner = ExceptionGroup("inner", [DetectorUnavailableError(log_context={"stage": "inner"})])
        outer = ExceptionGroup("outer", [inner])

        assert _first_failure(outer).log_context["stage"] == "inner"

    def test_a_group_with_no_domain_error_is_converted(self) -> None:
        group = ExceptionGroup("boom", [RuntimeError(CANARIES["email"])])

        failure = _first_failure(group)

        assert isinstance(failure, DetectorUnavailableError)
        assert CANARIES["email"] not in f"{failure.public_message}{failure.log_context}"

    def test_the_analyzer_repr_carries_its_bound_and_nothing_else(
        self, documents: DocumentService
    ) -> None:
        analyzer = analyzer_of(
            processor_of(documents, max_characters=100, overlap=0),
            fake_detector(),
            max_entities=77,
        )

        assert repr(analyzer) == "DocumentAnalyzer(max_entities=77)"


# ---------------------------------------------------------------------------
# Policy refusals
# ---------------------------------------------------------------------------
class TestPolicyRefusals:
    async def test_a_blocked_entity_type_refuses_the_document(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        body = f"Contact {CANARIES['email']} about SSN {CANARIES['ssn']}.\n".encode()
        document_id = await upload(documents, body=body)
        blocking = policy_of(
            {
                US_SSN: EntityRule(action=EntityAction.BLOCK, min_score=0.5),
                EMAIL_ADDRESS: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
            }
        )

        with pytest.raises(PolicyViolationError) as caught:
            await analyzer_of(processor, fake_detector(), policy=blocking).analyze(
                tenant_id=TENANT, user_id=USER, document_id=document_id
            )

        assert caught.value.log_context["entity_type"] == US_SSN
        assert caught.value.log_context["reason"] == "policy_blocked_entity"

    async def test_a_block_carries_no_value_anywhere(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        body = f"SSN {CANARIES['ssn']}\n".encode()
        document_id = await upload(documents, body=body)
        blocking = policy_of({US_SSN: EntityRule(action=EntityAction.BLOCK, min_score=0.5)})

        with pytest.raises(PolicyViolationError) as caught:
            await analyzer_of(processor, fake_detector(), policy=blocking).analyze(
                tenant_id=TENANT, user_id=USER, document_id=document_id
            )

        rendered = f"{caught.value.public_message}{caught.value.log_context}"
        assert CANARIES["ssn"] not in rendered
        # Non-vacuity: the log context has to be carrying something, or the
        # absence above is absence of everything.
        assert caught.value.log_context["entity_type"] == US_SSN

    async def test_a_sub_threshold_span_is_dropped_rather_than_allowed(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        # The fake scores an email at 1.0 and an MRN at 0.85. A 0.95 floor for
        # the MRN means it is not a detection at all -- it appears in no count
        # and no summary claims it was considered and permitted.
        document_id = await upload(documents, body=BODY)
        strict = policy_of(
            {
                EMAIL_ADDRESS: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
                MEDICAL_RECORD_NUMBER: EntityRule(action=EntityAction.TOKENIZE, min_score=0.95),
            }
        )

        analyzed = await analyzer_of(processor, fake_detector(), policy=strict).analyze(
            tenant_id=TENANT, user_id=USER, document_id=document_id
        )

        types = analyzed.counts_by_entity_type()
        assert EMAIL_ADDRESS in types
        assert MEDICAL_RECORD_NUMBER not in types

    async def test_no_active_policy_refuses_before_the_document_is_opened(
        self, documents: DocumentService, store: FakeDocumentStore
    ) -> None:
        # The expensive work is decrypt-extract-segment. A tenant with no usable
        # policy is refused before any of it, so a misconfigured tenant cannot
        # buy CPU by uploading.
        document_id = await upload(documents, body=BODY)
        detector = RecordingDetector(fake_detector())
        analyzer = analyzer_of(
            processor_of(documents, max_characters=200, overlap=48),
            detector,
            policies=FailingPolicySource(PolicyNotFoundError(log_context={"reason": "none"})),
        )

        with pytest.raises(PolicyNotFoundError):
            await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert detector.calls == [], "detection ran despite there being no policy"


# ---------------------------------------------------------------------------
# Failing closed
# ---------------------------------------------------------------------------
class TestFailsClosed:
    async def test_a_detector_outage_propagates_as_itself(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        # Not translated into "document unreadable": the remedies differ, and an
        # operator reading the log needs to know which dependency is down.
        document_id = await upload(documents, body=BODY)
        analyzer = analyzer_of(
            processor,
            FailingDetector(DetectorUnavailableError(log_context={"stage": "analyze"})),
        )

        with pytest.raises(DetectorUnavailableError) as caught:
            await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert caught.value.log_context["stage"] == "analyze"

    async def test_an_unexpected_detector_exception_is_converted_and_stripped(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        # A third-party exception string can carry the text being analyzed --
        # this is the same leak class as defects 3 and 4, arriving through an
        # error rather than a log call.
        document_id = await upload(documents, body=BODY)
        analyzer = analyzer_of(
            processor, FailingDetector(RuntimeError(f"failed on {CANARIES['email']}"))
        )

        with pytest.raises(DetectorUnavailableError) as caught:
            await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        rendered = f"{caught.value.public_message}{caught.value.log_context}"
        assert CANARIES["email"] not in rendered
        assert caught.value.log_context["reason"] == "stage_failed"

    async def test_one_failing_segment_stops_the_rest(self, documents: DocumentService) -> None:
        # With gather, the first failure propagates while its siblings keep
        # running, so a document that is already refused goes on paying for
        # detection over every remaining segment.
        document_id = await upload(documents, body=BODY * 20)
        detector = FailingDetector(DetectorUnavailableError(), fail_on=2)
        processor = processor_of(documents, max_characters=120, overlap=32)
        # Serialized, so every segment after the failing one is parked on the
        # semaphore and can be cancelled rather than already in flight.
        analyzer = analyzer_of(processor, detector, concurrency=1)

        with pytest.raises(DetectorUnavailableError):
            await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        segmented = await processor.segment(tenant_id=TENANT, user_id=USER, document_id=document_id)
        assert segmented.segment_count >= 10, "too few segments to demonstrate cancellation"
        assert detector.call_count < segmented.segment_count

    async def test_a_document_belonging_to_another_user_is_not_found(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        # Scoping is Phase 1's and is inherited rather than reimplemented. The
        # assertion is that analysis reads through the scoped path and not
        # around it.
        document_id = await upload(documents, body=BODY, user_id=OTHER_USER)
        analyzer = analyzer_of(processor, fake_detector())

        with pytest.raises(DocumentNotFoundError):
            await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

    async def test_an_absent_document_is_not_found(self, processor: DocumentProcessor) -> None:
        analyzer = analyzer_of(processor, fake_detector())

        with pytest.raises(DocumentNotFoundError):
            await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=uuid4())


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------
class TestNothingIsRetained:
    async def test_analysis_writes_nothing_anywhere(
        self,
        documents: DocumentService,
        processor: DocumentProcessor,
        store: FakeDocumentStore,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        # ADR-0030 covers extracted text; spans and their offsets are a
        # description of that text and are covered by the same rule. Nothing
        # this phase produces is written down.
        document_id = await upload(documents, body=BODY)
        objects_before = {key: store.stored_bytes(key) for key in store.stored_keys()}
        async with session_scope() as session:
            rows_before = (await session.execute(text("SELECT COUNT(*) FROM documents"))).scalar()

        analyzed = await analyzer_of(processor, fake_detector()).analyze(
            tenant_id=TENANT, user_id=USER, document_id=document_id
        )

        assert analyzed.span_count > 0, "non-vacuity: the run must have produced spans"
        assert {key: store.stored_bytes(key) for key in store.stored_keys()} == objects_before
        async with session_scope() as session:
            rows_after = (await session.execute(text("SELECT COUNT(*) FROM documents"))).scalar()
            tables = [
                row[0]
                for row in (
                    await session.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
                ).all()
            ]
        assert rows_after == rows_before
        for table in tables:
            assert "span" not in table
            assert "analys" not in table
            assert "detection" not in table

    async def test_the_document_status_gains_no_new_member(self) -> None:
        # A status the system cannot reach is a lie told to whoever polls for
        # it, and nothing here persists a thing for a status to describe.
        from app.documents.models import DocumentStatus

        assert {member.value for member in DocumentStatus} == {"receiving", "stored", "failed"}


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------
class TestDeterminism:
    async def test_two_runs_over_one_document_agree_exactly(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        # Segments are detected concurrently, so the order they finish in varies.
        # The result must not.
        document_id = await upload(documents, body=BODY * 5)
        analyzer = analyzer_of(processor, fake_detector())

        first = await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)
        second = await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert first.spans == second.spans

    async def test_spans_are_ordered_and_never_overlap(
        self, documents: DocumentService, processor: DocumentProcessor
    ) -> None:
        document_id = await upload(documents, body=BODY * 5)

        analyzed = await analyzer_of(processor, fake_detector()).analyze(
            tenant_id=TENANT, user_id=USER, document_id=document_id
        )

        assert analyzed.span_count > 1
        boundary = 0
        for span in analyzed.spans:
            assert span.start >= boundary
            boundary = span.end
