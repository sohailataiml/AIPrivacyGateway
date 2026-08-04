"""Audit logging tests.

Everything here is pure Python plus an event loop: no database, no Redis, no
provider. The sink is a Protocol, so a list-backed fake is a complete
implementation of what :class:`~app.audit.service.AuditService` depends on.

The highest-value test in this file is
``TestAuditRecord.test_declares_no_prohibited_field``: it fails the moment a
future edit adds a field that could carry message content, an original value, a
decrypted mapping, a complete gateway token, or a credential.
"""

from __future__ import annotations

import asyncio
from dataclasses import fields
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
import structlog
from prometheus_client import REGISTRY

from app.audit import metrics
from app.audit.correlation import (
    AUDIT_CORRELATION_LABEL,
    CorrelationHasher,
    derive_correlation_key,
)
from app.audit.models import (
    ALLOWED_FIELD_NAMES,
    PROHIBITED_FIELD_SUBSTRINGS,
    AuditRecord,
    counts_from_summary,
    enforce_field_policy,
)
from app.audit.service import AuditService, to_draft
from app.config.settings import Settings
from app.domain.errors import AuditUnavailableError
from app.domain.models import PrivacySummary
from app.repositories.audit_events import AuditEventDraft
from app.tokenization.fingerprint import FINGERPRINT_LABEL, derive_fingerprint_key

TENANT = UUID("11111111-1111-4111-8111-111111111111")
OTHER_TENANT = UUID("22222222-2222-4222-8222-222222222222")
SESSION = UUID("33333333-3333-4333-8333-333333333333")
ROOT_SECRET = b"root-secret-material-for-tests-0123456789"

CANARY = "SENSITIVE_CANARY_EMAIL_7f91@example.test"


def make_record(**overrides: Any) -> AuditRecord:
    """One valid record. Overrides keep each test's intent visible."""
    defaults: dict[str, Any] = {
        "tenant_id": TENANT,
        "request_id": uuid4(),
        "status_code": 200,
    }
    return AuditRecord(**{**defaults, **overrides})


class RecordingSink:
    """An ``AuditSink`` that keeps what it was given.

    ``fail_next`` makes the next write raise, ``gate`` holds a write open so a
    test can fill the queue behind it.
    """

    def __init__(self, *, gate: asyncio.Event | None = None) -> None:
        self.drafts: list[AuditEventDraft] = []
        self.fail_next = 0
        self.gate = gate

    async def record(self, draft: AuditEventDraft) -> object:
        if self.gate is not None:
            await self.gate.wait()
        if self.fail_next > 0:
            self.fail_next -= 1
            raise RuntimeError("audit storage is unavailable")
        self.drafts.append(draft)
        return draft


def counter_value(name: str, **labels: str) -> float:
    """Current value of a labelled counter, zero when it has no samples yet."""
    value = REGISTRY.get_sample_value(name, labels)
    return 0.0 if value is None else value


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
class TestAuditRecord:
    def test_declares_no_prohibited_field(self) -> None:
        # Arrange
        declared = AuditRecord.field_names()

        # Act
        offending = {
            name
            for name in declared
            for fragment in PROHIBITED_FIELD_SUBSTRINGS
            if fragment in name.casefold()
        }

        # Assert
        assert offending == set()
        assert declared <= ALLOWED_FIELD_NAMES
        for forbidden in (
            "content",
            "prompt",
            "response",
            "messages",
            "original_value",
            "original_values",
            "mappings",
            "token",
            "tokens",
            "api_key",
            "provider_api_key",
            "authorization",
        ):
            assert forbidden not in declared

    def test_declared_fields_match_the_allowlist_exactly(self) -> None:
        # Arrange / Act
        declared = AuditRecord.field_names()

        # Assert -- a removed field is as much a contract change as a new one.
        assert declared == ALLOWED_FIELD_NAMES

    def test_field_policy_rejects_a_prohibited_name(self) -> None:
        # Arrange
        hypothetical = {*ALLOWED_FIELD_NAMES, "prompt_content"}

        # Act / Assert
        with pytest.raises(RuntimeError, match="not on the audit allowlist"):
            enforce_field_policy(hypothetical)

    def test_field_policy_rejects_an_allowlisted_but_unsafe_name(self) -> None:
        # Arrange -- both nets, so widening the allowlist alone is not enough.
        allowlisted_but_unsafe = {"prompt_hmac", "message_text"}

        # Act / Assert
        with pytest.raises(RuntimeError):
            enforce_field_policy(allowlisted_but_unsafe)

    def test_repr_exposes_only_identifiers_and_counts(self) -> None:
        # Arrange
        record = make_record(
            provider_alias="mock",
            prompt_hmac="a" * 64,
            entity_counts={"EMAIL_ADDRESS": 2},
        )

        # Act
        rendered = repr(record)

        # Assert
        assert "a" * 64 not in rendered
        assert "detected=2" in rendered

    def test_rejects_a_naive_timestamp(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            make_record(occurred_at=datetime(2026, 1, 1, 12, 0, 0))  # noqa: DTZ001

    def test_rejects_an_impossible_status_code(self) -> None:
        with pytest.raises(ValueError, match="valid HTTP status"):
            make_record(status_code=42)

    def test_rejects_negative_counts(self) -> None:
        with pytest.raises(ValueError, match="must not be negative"):
            make_record(input_character_count=-1)

    def test_rejects_prose_in_a_digest_field(self) -> None:
        # A caller who passes text where a digest belongs is refused outright.
        with pytest.raises(ValueError, match="hexadecimal"):
            make_record(prompt_hmac=CANARY)

    def test_rejects_prose_in_an_alias_field(self) -> None:
        with pytest.raises(ValueError, match="identifier-shaped"):
            make_record(provider_alias="the user said " + CANARY)

    def test_rejects_a_count_key_that_is_not_a_type_name(self) -> None:
        with pytest.raises(ValueError, match="identifier-shaped"):
            make_record(entity_counts={CANARY: 1})

    def test_rejects_a_non_integer_count(self) -> None:
        with pytest.raises(ValueError, match="non-negative integers"):
            make_record(actions={"tokenized": True})

    def test_copies_count_maps_so_a_caller_cannot_edit_a_queued_record(self) -> None:
        # Arrange
        counts = {"EMAIL_ADDRESS": 1}
        record = make_record(entity_counts=counts)

        # Act
        counts["EMAIL_ADDRESS"] = 99

        # Assert
        assert record.entity_counts == {"EMAIL_ADDRESS": 1}

    def test_counts_from_summary_carries_names_and_numbers_only(self) -> None:
        # Arrange
        summary = PrivacySummary(
            detected=3,
            tokenized=2,
            redacted=1,
            restored=2,
            entity_types={"EMAIL_ADDRESS": 1, "US_SSN": 1, "PERSON": 1},
        )

        # Act
        entity_counts, actions = counts_from_summary(summary)

        # Assert
        assert entity_counts == {"EMAIL_ADDRESS": 1, "US_SSN": 1, "PERSON": 1}
        assert actions["tokenized"] == 2
        assert actions["restored"] == 2
        assert all(isinstance(value, int) for value in actions.values())


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------
class TestCorrelation:
    @pytest.fixture
    def hasher(self) -> CorrelationHasher:
        return CorrelationHasher(derive_correlation_key(ROOT_SECRET))

    def test_digest_is_deterministic(self, hasher: CorrelationHasher) -> None:
        # Arrange / Act
        first = hasher.prompt_digest(tenant_id=TENANT, segments=["hello"])
        second = hasher.prompt_digest(tenant_id=TENANT, segments=["hello"])

        # Assert
        assert first == second
        assert len(first) == 64

    def test_prompt_and_response_digests_are_not_interchangeable(
        self, hasher: CorrelationHasher
    ) -> None:
        # Arrange
        text = "the same words on both sides of the request"

        # Act
        prompt = hasher.prompt_digest(tenant_id=TENANT, segments=[text])
        response = hasher.response_digest(tenant_id=TENANT, text=text)

        # Assert
        assert prompt != response

    def test_digests_are_scoped_to_a_tenant(self, hasher: CorrelationHasher) -> None:
        # Arrange / Act
        mine = hasher.prompt_digest(tenant_id=TENANT, segments=["shared text"])
        theirs = hasher.prompt_digest(tenant_id=OTHER_TENANT, segments=["shared text"])

        # Assert
        assert mine != theirs

    def test_segments_are_length_prefixed(self, hasher: CorrelationHasher) -> None:
        # Arrange -- the same bytes, cut in two places.
        first = hasher.prompt_digest(tenant_id=TENANT, segments=["AB", "C"])
        second = hasher.prompt_digest(tenant_id=TENANT, segments=["A", "BC"])

        # Assert
        assert first != second

    def test_session_digest_fits_the_audit_column(self, hasher: CorrelationHasher) -> None:
        # Arrange / Act
        digest = hasher.session_digest(tenant_id=TENANT, session_id=SESSION)

        # Assert -- session_id_hash is String(64).
        assert len(digest) == 64
        assert str(SESSION) not in digest

    def test_audit_key_is_independent_of_the_tokenization_key(self) -> None:
        # Arrange / Act
        audit_key = derive_correlation_key(ROOT_SECRET)
        fingerprint_key = derive_fingerprint_key(ROOT_SECRET)

        # Assert
        assert AUDIT_CORRELATION_LABEL != FINGERPRINT_LABEL
        assert audit_key != fingerprint_key
        assert audit_key != ROOT_SECRET

    def test_rejects_a_short_key(self) -> None:
        with pytest.raises(ValueError, match="at least"):
            CorrelationHasher(b"tooshort")

    def test_rejects_a_short_root_secret(self) -> None:
        with pytest.raises(ValueError, match="at least"):
            derive_correlation_key(b"short")

    def test_repr_hides_key_material(self, hasher: CorrelationHasher) -> None:
        assert repr(hasher) == "CorrelationHasher(key=<redacted>)"

    def test_from_settings_uses_the_audit_hmac_key(self) -> None:
        # Arrange
        settings = Settings(audit_hmac_key="a-configured-audit-key-long-enough")  # type: ignore[call-arg]

        # Act
        hasher = CorrelationHasher.from_settings(settings)
        expected = CorrelationHasher(derive_correlation_key(b"a-configured-audit-key-long-enough"))

        # Assert
        assert hasher.prompt_digest(tenant_id=TENANT, segments=["x"]) == expected.prompt_digest(
            tenant_id=TENANT, segments=["x"]
        )


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------
class TestAuditService:
    async def test_writes_a_submitted_record_through_to_the_sink(self) -> None:
        # Arrange
        sink = RecordingSink()
        service = AuditService(sink)
        record = make_record(provider_alias="mock", model_alias="mock-echo-1")

        # Act
        async with service:
            await service.submit(record)
            assert await service.flush(wait_seconds=1.0)

        # Assert
        assert len(sink.drafts) == 1
        assert sink.drafts[0].request_id == record.request_id
        assert sink.drafts[0].provider_alias == "mock"

    async def test_stamps_the_submission_time_not_the_write_time(self) -> None:
        # Arrange
        sink = RecordingSink()
        service = AuditService(sink)
        before = datetime.now(UTC)

        # Act
        async with service:
            await service.submit(make_record())
            assert await service.flush(wait_seconds=1.0)

        # Assert
        occurred_at = sink.drafts[0].occurred_at
        assert occurred_at is not None
        assert occurred_at >= before
        assert occurred_at.tzinfo is not None

    async def test_preserves_an_explicit_timestamp(self) -> None:
        # Arrange
        stamped = datetime(2026, 3, 1, 9, 30, tzinfo=UTC)
        sink = RecordingSink()
        service = AuditService(sink)

        # Act
        async with service:
            await service.submit(make_record(occurred_at=stamped))
            assert await service.flush(wait_seconds=1.0)

        # Assert
        assert sink.drafts[0].occurred_at == stamped

    async def test_rejects_the_request_when_saturated_and_fail_closed(self) -> None:
        # Arrange -- the gate holds the writer so the queue cannot drain, and the
        # bound is 2, so the third submission has nowhere to go.
        gate = asyncio.Event()
        sink = RecordingSink(gate=gate)
        service = AuditService(sink, fail_closed=True, max_queue_size=2)
        before = counter_value("sgw_audit_failures_total", reason=metrics.REASON_QUEUE_FULL)

        # Act / Assert
        await service.start()
        try:
            await service.submit(make_record())
            await service.submit(make_record())
            with pytest.raises(AuditUnavailableError):
                await service.submit(make_record())
        finally:
            gate.set()
            await service.stop()

        after = counter_value("sgw_audit_failures_total", reason=metrics.REASON_QUEUE_FULL)
        assert after > before

    async def test_never_blocks_the_caller_when_saturated(self) -> None:
        # Arrange -- backpressure would make this call wait for the gate forever.
        gate = asyncio.Event()
        service = AuditService(RecordingSink(gate=gate), fail_closed=False, max_queue_size=1)

        # Act
        await service.start()
        try:
            await service.submit(make_record())
            async with asyncio.timeout(1.0):
                await service.submit(make_record())
        finally:
            gate.set()
            await service.stop()

        # Assert -- reaching here at all is the assertion.
        assert service.queue_depth == 0

    async def test_drops_and_counts_when_saturated_and_fail_open(self) -> None:
        # Arrange
        gate = asyncio.Event()
        sink = RecordingSink(gate=gate)
        service = AuditService(sink, fail_closed=False, max_queue_size=2)
        before = counter_value("sgw_audit_events_total", outcome=metrics.OUTCOME_DROPPED)

        # Act
        await service.start()
        try:
            await service.submit(make_record())
            await service.submit(make_record())
            await service.submit(make_record())  # dropped, no exception
        finally:
            gate.set()
            await service.stop()

        # Assert
        after = counter_value("sgw_audit_events_total", outcome=metrics.OUTCOME_DROPPED)
        assert after >= before + 1
        assert len(sink.drafts) == 2

    async def test_queue_depth_is_published(self) -> None:
        # Arrange
        gate = asyncio.Event()
        service = AuditService(RecordingSink(gate=gate), max_queue_size=8)

        # Act
        await service.start()
        try:
            await service.submit(make_record())
            await service.submit(make_record())
            await asyncio.sleep(0)
            depth = REGISTRY.get_sample_value("sgw_audit_queue_depth")
        finally:
            gate.set()
            await service.stop()

        # Assert
        assert depth is not None
        assert depth >= 1

    async def test_a_write_failure_degrades_a_fail_closed_service(self) -> None:
        # Arrange
        sink = RecordingSink()
        sink.fail_next = 1
        service = AuditService(sink, fail_closed=True)

        # Act
        await service.start()
        try:
            await service.submit(make_record())
            assert await service.flush(wait_seconds=1.0)

            # Assert -- the failed request already returned; the next one is refused.
            assert service.degraded
            with pytest.raises(AuditUnavailableError):
                await service.submit(make_record())
        finally:
            await service.stop()

    async def test_a_refused_record_is_still_queued_so_storage_can_recover(self) -> None:
        # Arrange
        sink = RecordingSink()
        sink.fail_next = 1
        service = AuditService(sink, fail_closed=True)

        # Act
        async with service:
            await service.submit(make_record())
            assert await service.flush(wait_seconds=1.0)
            with pytest.raises(AuditUnavailableError):
                await service.submit(make_record())
            assert await service.flush(wait_seconds=1.0)

            # Assert -- the refused request's event was written once storage
            # recovered, and the service is serving again.
            assert len(sink.drafts) == 1
            assert not service.degraded

    async def test_a_write_failure_does_not_stop_a_fail_open_service(self) -> None:
        # Arrange
        sink = RecordingSink()
        sink.fail_next = 1
        service = AuditService(sink, fail_closed=False)

        # Act
        async with service:
            await service.submit(make_record())
            assert await service.flush(wait_seconds=1.0)
            await service.submit(make_record())
            assert await service.flush(wait_seconds=1.0)

        # Assert -- the first was lost, the second was written.
        assert len(sink.drafts) == 1

    async def test_recovers_from_degraded_after_a_successful_write(self) -> None:
        # Arrange
        sink = RecordingSink()
        sink.fail_next = 1
        service = AuditService(sink, fail_closed=False)

        # Act
        async with service:
            await service.submit(make_record())
            assert await service.flush(wait_seconds=1.0)
            assert service.degraded
            await service.submit(make_record())
            assert await service.flush(wait_seconds=1.0)

            # Assert
            assert not service.degraded

    async def test_a_write_failure_logs_no_event_payload(self) -> None:
        # Arrange
        sink = RecordingSink()
        sink.fail_next = 1
        service = AuditService(sink, fail_closed=False)
        record = make_record(entity_counts={"EMAIL_ADDRESS": 1}, prompt_hmac="b" * 64)

        # Act
        with structlog.testing.capture_logs() as captured:
            async with service:
                await service.submit(record)
                assert await service.flush(wait_seconds=1.0)

        # Assert
        assert captured, "the failure should be logged at all"
        for entry in captured:
            assert "b" * 64 not in str(entry)
            assert "EMAIL_ADDRESS" not in str(entry)
            assert set(entry) <= {"event", "log_level", "stage", "reason", "request_id"}

    async def test_stop_drains_what_is_queued(self) -> None:
        # Arrange
        sink = RecordingSink()
        service = AuditService(sink, max_queue_size=16)

        # Act
        await service.start()
        for _ in range(5):
            await service.submit(make_record())
        await service.stop()

        # Assert
        assert len(sink.drafts) == 5

    async def test_stop_gives_up_on_a_stuck_writer(self) -> None:
        # Arrange -- the gate is never set, so the writer cannot finish.
        gate = asyncio.Event()
        service = AuditService(
            RecordingSink(gate=gate), max_queue_size=4, drain_timeout_seconds=0.01
        )
        before = counter_value("sgw_audit_failures_total", reason=metrics.REASON_DRAIN_TIMEOUT)

        # Act
        await service.start()
        await service.submit(make_record())
        await service.submit(make_record())
        await service.stop()

        # Assert
        after = counter_value("sgw_audit_failures_total", reason=metrics.REASON_DRAIN_TIMEOUT)
        assert after > before

    async def test_refuses_submissions_after_stop_when_fail_closed(self) -> None:
        # Arrange
        service = AuditService(RecordingSink(), fail_closed=True)

        # Act
        await service.start()
        await service.stop()

        # Assert
        with pytest.raises(AuditUnavailableError):
            await service.submit(make_record())

    async def test_from_settings_follows_the_configured_failure_mode(self) -> None:
        # Arrange
        open_settings = Settings(audit_fail_closed=False)  # type: ignore[call-arg]
        closed_settings = Settings(audit_fail_closed=True)  # type: ignore[call-arg]

        # Act
        fail_open = AuditService.from_settings(RecordingSink(), open_settings)
        fail_closed = AuditService.from_settings(RecordingSink(), closed_settings)

        # Assert
        assert not fail_open.fail_closed
        assert fail_closed.fail_closed

    def test_rejects_an_unbounded_queue(self) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            AuditService(RecordingSink(), max_queue_size=0)

    def test_to_draft_maps_every_declared_field(self) -> None:
        # Arrange
        record = make_record(
            api_key_id=uuid4(),
            session_id_hash="c" * 64,
            policy_id=uuid4(),
            policy_version=3,
            provider_alias="mock",
            model_alias="mock-echo-1",
            input_character_count=120,
            output_character_count=80,
            entity_counts={"EMAIL_ADDRESS": 1},
            actions={"tokenized": 1},
            blocked=False,
            provider_latency_ms=12,
            pipeline_latency_ms=30,
            error_code="NONE",
            prompt_hmac="d" * 64,
            response_hmac="e" * 64,
            occurred_at=datetime.now(UTC),
        )

        # Act
        draft = to_draft(record)

        # Assert -- the draft carries no field the record does not have.
        draft_fields = {field.name for field in fields(AuditEventDraft)}
        assert draft_fields == AuditRecord.field_names()
        for name in draft_fields:
            assert getattr(draft, name) == getattr(record, name)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
class TestMetrics:
    def test_rejects_an_unknown_outcome_label(self) -> None:
        # An unbounded label is a cardinality incident, so it fails loudly.
        with pytest.raises(ValueError, match="unknown audit outcome"):
            metrics.record_event("something-new")

    def test_rejects_an_unknown_failure_reason(self) -> None:
        with pytest.raises(ValueError, match="unknown audit failure reason"):
            metrics.record_failure(CANARY)

    def test_label_sets_are_closed_and_small(self) -> None:
        # Arrange / Act / Assert
        assert len(metrics.EVENT_OUTCOMES) <= 8
        assert len(metrics.FAILURE_REASONS) <= 8

    def test_queue_capacity_is_published(self) -> None:
        # Arrange / Act
        metrics.set_queue_capacity(64)

        # Assert
        assert REGISTRY.get_sample_value("sgw_audit_queue_capacity") == 64
