"""Canary sweep over detection: finding a value must not disclose it.

Detection is the first stage that *knows where the sensitive values are*. That
makes it the stage with the most to leak and the most tempting things to log:
the matched text, an offset, a per-type breakdown. None of them may escape.

The channels swept here are the ones this stage actually has:

* **application logs**, including every structlog key-value pair rather than the
  rendered message alone -- a leak usually arrives as an extra field;
* **the ``repr`` of every type that holds or points at document text**, because
  a traceback renders those without asking;
* **domain errors**, which is where a refusal is most likely to explain itself
  by quoting the thing it refused;
* **the entity-type breakdown**, which is not a value but is a description of
  the document's contents and belongs in an audit record rather than a log line.

Every sweep asserts it found something before asserting it found nothing bad.
That habit is what caught defects 16 and 18: an assertion that a value is absent
from an empty string passes for the wrong reason, and looks identical to one
that passed for the right one.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.models import Tenant
from app.detection.config import DetectionConfig
from app.detection.entities import EMAIL_ADDRESS, PERSON, US_SSN
from app.detection.fakes import FakeDetector
from app.documents.analysis.analyzer import DocumentAnalyzer
from app.documents.analysis.spans import GlobalDetection, to_global
from app.documents.extraction.models import build_extracted_document
from app.documents.extraction.runner import InlineExtractionRunner
from app.documents.models import CONTENT_TYPE_TXT
from app.documents.processing import DocumentProcessor
from app.documents.segmentation import Segmenter
from app.documents.service import DocumentService
from app.documents.storage.fakes import FakeDocumentStore
from app.domain.errors import EntityLimitExceededError, PolicyViolationError
from app.domain.models import DetectedEntity, EntityAction
from app.observability.logging import DROPPED_KEY_MARKER, configure_logging
from app.policy.models import EntityRule
from tests.fixtures.documents import CANARIES, MAX_BYTES, TENANT, USER, make_cipher, stream
from tests.fixtures.policies import FakePolicySource, snapshot

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator
    from contextlib import AbstractAsyncContextManager
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = pytest.mark.privacy

BODY = (
    f"{CANARIES['person_name']} attended the oncology clinic.\n"
    f"Contact {CANARIES['email']} or {CANARIES['phone']}.\n"
    f"Social security number {CANARIES['ssn']}.\n"
).encode()

DETECTED_CANARIES = ("person_name", "email", "phone", "ssn")
"""The canaries the fake detector actually finds in ``BODY``.

Stated explicitly so the non-vacuity assertions can require that detection
happened at all. ``mrn`` and ``icd10`` are absent from this list because
neither the shipped recognizer nor the fake matches them -- a gap the canary
suite records rather than papers over.
"""

PROTECT_EVERYTHING = {
    PERSON: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    EMAIL_ADDRESS: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    US_SSN: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
}


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


@pytest.fixture
def logs(caplog: pytest.LogCaptureFixture) -> Iterator[pytest.LogCaptureFixture]:
    """Capture what the application actually logs.

    Without ``configure_logging`` structlog writes straight to stdout and emits
    no stdlib records at all, so a sweep over ``caplog`` alone would search an
    empty list and pass. ``configure_logging`` then calls
    ``logging.basicConfig(force=True)``, which removes pytest's handler, so it
    is re-attached afterwards. ``tests/conftest.py`` restores the global
    configuration when the test ends.
    """
    configure_logging(level="DEBUG", json_output=False)
    root = logging.getLogger()
    caplog.set_level(logging.DEBUG)
    root.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        root.removeHandler(caplog.handler)


def rendered(caplog: pytest.LogCaptureFixture) -> str:
    """Every message *and* every structured field, as one searchable string."""
    return "\n".join(record.getMessage() + repr(record.__dict__) for record in caplog.records)


def analyzer_of(
    documents: DocumentService,
    *,
    entities: dict[str, EntityRule] | None = None,
    max_entities: int = 10_000,
) -> DocumentAnalyzer:
    return DocumentAnalyzer(
        source=DocumentProcessor(
            source=documents,
            runner=InlineExtractionRunner(),
            segmenter=Segmenter(max_characters=120, overlap_characters=48),
            max_document_bytes=MAX_BYTES,
        ),
        detector=FakeDetector(config=DetectionConfig(), person_names=(CANARIES["person_name"],)),
        policies=FakePolicySource(
            snapshot(
                entities if entities is not None else PROTECT_EVERYTHING,
                tenant_id=TENANT,
                version=7,
            )
        ),
        max_entities=max_entities,
    )


async def upload(documents: DocumentService, body: bytes = BODY) -> UUID:
    stored = await documents.store(
        tenant_id=TENANT,
        user_id=USER,
        filename=CANARIES["filename"].replace(".pdf", ".txt"),
        declared_content_type=CONTENT_TYPE_TXT,
        declared_length=len(body),
        source=stream(body),
    )
    return stored.metadata.id


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------
class TestLogs:
    async def test_a_successful_analysis_logs_no_canary(
        self, documents: DocumentService, logs: pytest.LogCaptureFixture
    ) -> None:
        document_id = await upload(documents)

        analyzed = await analyzer_of(documents).analyze(
            tenant_id=TENANT, user_id=USER, document_id=document_id
        )

        captured = rendered(logs)
        # Non-vacuity, twice over: the sweep must have something to search, and
        # the run must have actually found the values it is not allowed to log.
        assert "document_analyzed" in captured, "the analyzer logged nothing to search"
        assert analyzed.span_count >= len(DETECTED_CANARIES)
        for name in (*DETECTED_CANARIES, "filename"):
            assert CANARIES[name] not in captured, f"{name} reached a log line"

    async def test_the_log_line_says_something_an_operator_can_use(
        self, documents: DocumentService, logs: pytest.LogCaptureFixture
    ) -> None:
        # Defect 20 in miniature. ``drop_unlisted_keys`` is deny-by-default, so
        # a field that is not on the allowlist vanishes and the call site never
        # finds out. A log line that survives the sweep by having no content is
        # not evidence of anything.
        document_id = await upload(documents)

        analyzed = await analyzer_of(documents).analyze(
            tenant_id=TENANT, user_id=USER, document_id=document_id
        )

        captured = rendered(logs)
        assert str(document_id) in captured, "the analysis cannot be traced to a document"
        assert f"detected={analyzed.span_count}" in captured

    async def test_no_document_log_line_loses_fields_to_the_allowlist(
        self, documents: DocumentService, logs: pytest.LogCaptureFixture
    ) -> None:
        # The general form, covering storage and segmentation as well as
        # analysis. ``DROPPED_KEY_MARKER`` is the allowlist reporting that a
        # call site tried to log something it does not know about -- safe, and
        # always a bug at the call site or a gap in the allowlist.
        document_id = await upload(documents)

        await analyzer_of(documents).analyze(
            tenant_id=TENANT, user_id=USER, document_id=document_id
        )

        captured = rendered(logs)
        # Non-vacuity: all three stages must have logged, or "nothing was
        # dropped" is a statement about an empty search.
        assert "document_stored" in captured, "storage logged nothing to check"
        assert "document_segmented" in captured
        assert "document_analyzed" in captured
        assert DROPPED_KEY_MARKER not in captured

    async def test_no_entity_type_breakdown_reaches_a_log_line(
        self, documents: DocumentService, logs: pytest.LogCaptureFixture
    ) -> None:
        # A count per entity type is not a value, and on a single document it is
        # still a description of the contents -- "this file holds two social
        # security numbers" is a disclosure to anyone reading stdout. It belongs
        # in an audit record, which is access-controlled.
        document_id = await upload(documents)

        analyzed = await analyzer_of(documents).analyze(
            tenant_id=TENANT, user_id=USER, document_id=document_id
        )

        captured = rendered(logs)
        assert analyzed.counts_by_entity_type(), "non-vacuity: there were types to leak"
        for entity_type in analyzed.counts_by_entity_type():
            assert entity_type not in captured, f"{entity_type} reached a log line"

    async def test_no_offset_reaches_a_log_line(
        self, documents: DocumentService, logs: pytest.LogCaptureFixture
    ) -> None:
        # An offset plus the stored ciphertext is a map of where the sensitive
        # values are. It is not the value, and it is not for stdout either.
        document_id = await upload(documents)

        analyzed = await analyzer_of(documents).analyze(
            tenant_id=TENANT, user_id=USER, document_id=document_id
        )

        line = next(
            record.getMessage()
            for record in logs.records
            if "document_analyzed" in record.getMessage()
        )
        assert analyzed.spans, "non-vacuity: there were offsets to leak"
        for field in ("start=", "end=", "offset=", "spans="):
            assert field not in line, f"{field} reached a log line"


# ---------------------------------------------------------------------------
# repr
# ---------------------------------------------------------------------------
class TestRepr:
    async def test_an_analyzed_document_repr_hides_the_document(
        self, documents: DocumentService
    ) -> None:
        document_id = await upload(documents)

        analyzed = await analyzer_of(documents).analyze(
            tenant_id=TENANT, user_id=USER, document_id=document_id
        )

        text = repr(analyzed)
        assert f"spans={analyzed.span_count}" in text, "non-vacuity: the repr said something"
        for name in DETECTED_CANARIES:
            assert CANARIES[name] not in text

    async def test_the_nested_reprs_hide_it_too(self, documents: DocumentService) -> None:
        # A traceback renders the whole chain, not just the outermost object.
        document_id = await upload(documents)

        analyzed = await analyzer_of(documents).analyze(
            tenant_id=TENANT, user_id=USER, document_id=document_id
        )

        nested = repr(analyzed.segmented) + repr(analyzed.segmented.document)
        for name in DETECTED_CANARIES:
            assert CANARIES[name] not in nested

    def test_a_labeled_span_holds_no_text_to_leak(self) -> None:
        # Structural rather than a string search: a span is offsets and a type,
        # so there is no field a value could hide in. Reading one requires the
        # buffer, which requires an AnalyzedDocument.
        segmented = Segmenter(max_characters=200, overlap_characters=0).segment(
            build_extracted_document(page_texts=[CANARIES["email"]])
        )
        promoted = to_global(
            segmented.segments[0],
            [DetectedEntity(EMAIL_ADDRESS, 0, len(CANARIES["email"]), 0.9)],
        )

        assert isinstance(promoted[0], GlobalDetection)
        assert CANARIES["email"] not in repr(promoted[0])


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class TestErrors:
    async def test_a_policy_block_quotes_nothing(
        self, documents: DocumentService, logs: pytest.LogCaptureFixture
    ) -> None:
        document_id = await upload(documents)
        analyzer = analyzer_of(
            documents,
            entities={US_SSN: EntityRule(action=EntityAction.BLOCK, min_score=0.5)},
        )

        with pytest.raises(PolicyViolationError) as caught:
            await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        surface = f"{caught.value.public_message}{caught.value.log_context}{rendered(logs)}"
        assert caught.value.log_context["entity_type"] == US_SSN, "non-vacuity"
        for name in DETECTED_CANARIES:
            assert CANARIES[name] not in surface

    async def test_an_over_budget_refusal_quotes_nothing(
        self, documents: DocumentService, logs: pytest.LogCaptureFixture
    ) -> None:
        document_id = await upload(documents)
        analyzer = analyzer_of(documents, max_entities=1)

        with pytest.raises(EntityLimitExceededError) as caught:
            await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        surface = f"{caught.value.public_message}{caught.value.log_context}{rendered(logs)}"
        assert caught.value.log_context["limit"] == 1, "non-vacuity"
        for name in DETECTED_CANARIES:
            assert CANARIES[name] not in surface

    async def test_a_refusal_leaves_the_stored_document_untouched(
        self, documents: DocumentService, store: FakeDocumentStore
    ) -> None:
        # A document the policy refuses is still the caller's document. Refusing
        # to process it must not destroy it.
        document_id = await upload(documents)
        before = {key: store.stored_bytes(key) for key in store.stored_keys()}
        analyzer = analyzer_of(
            documents,
            entities={US_SSN: EntityRule(action=EntityAction.BLOCK, min_score=0.5)},
        )

        with pytest.raises(PolicyViolationError):
            await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        assert before, "non-vacuity: something was stored to begin with"
        assert {key: store.stored_bytes(key) for key in store.stored_keys()} == before
