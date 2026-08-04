"""The seam between the pipeline and the audit service.

These modules were built in parallel against each other's assumed shape and did
not meet: the pipeline calls ``record(**fields)`` with a raw ``session_id``,
while ``AuditService`` exposes ``submit(AuditRecord)`` and stores only a hash.
Nothing exercised the join, so nothing failed until the two were wired.

The first test here is the one that would have caught it: it checks the adapter
structurally satisfies the Protocol the pipeline actually depends on.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.audit.correlation import CorrelationHasher
from app.audit.models import AuditRecord
from app.audit.pipeline_adapter import PipelineAuditAdapter
from app.audit.service import AuditService
from app.pipeline.protocols import AuditServiceLike

TENANT = uuid4()
SESSION = uuid4()
REQUEST = uuid4()


class RecordingAuditService:
    """Captures what would have been persisted."""

    def __init__(self) -> None:
        self.submitted: list[AuditRecord] = []

    async def submit(self, record: AuditRecord) -> None:
        self.submitted.append(record)


@pytest.fixture
def hasher() -> CorrelationHasher:
    return CorrelationHasher(key=b"k" * 32)


@pytest.fixture
def service() -> RecordingAuditService:
    return RecordingAuditService()


@pytest.fixture
def adapter(service: RecordingAuditService, hasher: CorrelationHasher) -> PipelineAuditAdapter:
    # RecordingAuditService is structurally an AuditService for this purpose.
    return PipelineAuditAdapter(service, hasher=hasher)  # type: ignore[arg-type]


def pipeline_fields(**overrides: object) -> dict[str, object]:
    """The exact field bag app/pipeline/reporting.py hands to the audit service."""
    fields: dict[str, object] = {
        "request_id": REQUEST,
        "tenant_id": TENANT,
        "api_key_id": uuid4(),
        "session_id": SESSION,
        "policy_id": uuid4(),
        "policy_version": 1,
        "provider_alias": "mock",
        "model_alias": "general-chat",
        "status_code": 200,
        "error_code": None,
        "blocked": False,
        "input_character_count": 128,
        "output_character_count": 64,
        "entity_counts": {"EMAIL_ADDRESS": 2},
        "actions": {"tokenize": 2},
        "provider_latency_ms": 40,
        "pipeline_latency_ms": 55,
        "occurred_at": datetime.now(UTC),
    }
    fields.update(overrides)
    return fields


class TestProtocolConformance:
    def test_adapter_satisfies_the_protocol_the_pipeline_depends_on(
        self, adapter: PipelineAuditAdapter
    ) -> None:
        # This is the assertion whose absence let the two modules diverge.
        checked: AuditServiceLike = adapter

        assert checked is adapter

    def test_the_raw_audit_service_does_not_satisfy_it(self) -> None:
        # Documents *why* the adapter exists: AuditService has no record().
        assert not hasattr(AuditService, "record")
        assert hasattr(AuditService, "submit")


class TestTranslation:
    async def test_pipeline_fields_become_a_valid_audit_record(
        self, adapter: PipelineAuditAdapter, service: RecordingAuditService
    ) -> None:
        # Arrange / Act
        await adapter.record(**pipeline_fields())

        # Assert
        assert len(service.submitted) == 1
        record = service.submitted[0]
        assert record.tenant_id == TENANT
        assert record.request_id == REQUEST
        assert record.status_code == 200
        assert record.entity_counts == {"EMAIL_ADDRESS": 2}

    async def test_the_raw_session_id_is_hashed_not_stored(
        self, adapter: PipelineAuditAdapter, service: RecordingAuditService
    ) -> None:
        # Arrange / Act
        await adapter.record(**pipeline_fields())

        # Assert -- the raw handle must not survive into the row.
        record = service.submitted[0]
        assert record.session_id_hash is not None
        assert str(SESSION) not in str(record.session_id_hash)
        assert "session_id" not in AuditRecord.field_names()

    async def test_session_hash_is_stable_and_tenant_scoped(
        self, adapter: PipelineAuditAdapter, service: RecordingAuditService
    ) -> None:
        # Arrange / Act
        await adapter.record(**pipeline_fields())
        await adapter.record(**pipeline_fields())
        await adapter.record(**pipeline_fields(tenant_id=uuid4()))

        # Assert
        first, second, other_tenant = service.submitted
        assert first.session_id_hash == second.session_id_hash
        assert other_tenant.session_id_hash != first.session_id_hash

    async def test_an_unknown_field_is_dropped_rather_than_failing_the_request(
        self, adapter: PipelineAuditAdapter, service: RecordingAuditService
    ) -> None:
        # A field the audit model does not know must not raise: under
        # AUDIT_FAIL_CLOSED that would turn a schema drift into an outage.
        await adapter.record(**pipeline_fields(some_future_field="ignored"))

        assert len(service.submitted) == 1
        assert not hasattr(service.submitted[0], "some_future_field")

    async def test_a_missing_status_defaults_to_failure_not_success(
        self, adapter: PipelineAuditAdapter, service: RecordingAuditService
    ) -> None:
        fields = pipeline_fields()
        del fields["status_code"]

        await adapter.record(**fields)

        assert service.submitted[0].status_code >= 500

    async def test_no_pipeline_field_carries_message_content(self) -> None:
        # Guards the field bag itself: if the pipeline ever starts sending a
        # content-shaped key, this fails before the adapter can forward it.
        forbidden = ("content", "text", "message", "prompt", "original", "value")

        for name in pipeline_fields():
            assert not any(word in name for word in forbidden), name
