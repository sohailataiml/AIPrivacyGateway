"""Stage order, and what happens on the paths that do not reach a provider.

``tests/privacy/test_document_workflow.py`` proves the happy path end to end
through the real route. This file proves the things that are hard to see from
there: that a stage did *not* run, that the same bytes were used three times,
and that the blocked path still writes its evidence.

Fakes throughout, because the assertions are about ordering and about which
collaborator was touched. A test that ran the real stack could observe the
outcome but not that the provider was never reached.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import uuid4

import pytest

from app.audit.correlation import CorrelationHasher
from app.audit.models import AuditRecord
from app.detection.config import DetectionConfig
from app.detection.entities import EMAIL_ADDRESS, PERSON
from app.detection.fakes import FakeDetector
from app.documents.outbound import serialize_outbound
from app.documents.pipeline import DocumentAnswer, DocumentPipeline
from app.documents.protection import ProtectedDocument
from app.domain.errors import (
    PolicyViolationError,
    ProviderNotAllowedError,
    RequestTooLargeError,
    VaultUnavailableError,
)
from app.domain.models import (
    EntityAction,
    Principal,
    PrivacySummary,
    ProviderResponse,
    Scope,
)
from app.llm.registry import ProviderRegistry
from app.policy.models import EntityRule
from app.restoration.results import RestoredOutput
from tests.fixtures.documents import CANARIES, TENANT, USER
from tests.fixtures.policies import snapshot

if TYPE_CHECKING:
    from uuid import UUID

    from app.policy.models import PolicySnapshot

SESSION = uuid4()
REQUEST = uuid4()
DOCUMENT = uuid4()

TOKEN = "⟦SGW:EMAIL_ADDRESS:01J8Z6J4M7Y9Q2K3T4V5W6X7Y8⟧"

PROTECT_EVERYTHING = {
    PERSON: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    EMAIL_ADDRESS: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
}

PRINCIPAL = Principal(
    tenant_id=TENANT,
    api_key_id=USER,
    api_key_prefix="sgw_test",
    scopes=frozenset(Scope),
)

HASHER = CorrelationHasher(key=bytes(range(32)))


def policy_of(entities: dict[str, EntityRule] | None = None) -> PolicySnapshot:
    return snapshot(entities or PROTECT_EVERYTHING, tenant_id=TENANT, version=7)


# ---------------------------------------------------------------------------
# Collaborators
# ---------------------------------------------------------------------------
class FakeProtection:
    def __init__(self, text: str = f"Contact {TOKEN} today.") -> None:
        self._text = text
        self.calls = 0

    async def protect(
        self, *, tenant_id: UUID, user_id: UUID, session_id: UUID, document_id: UUID
    ) -> ProtectedDocument:
        self.calls += 1
        return ProtectedDocument(
            tenant_id=tenant_id,
            session_id=session_id,
            document_id=document_id,
            text=self._text,
            summary=PrivacySummary(detected=1, tokenized=1, entity_types={EMAIL_ADDRESS: 1}),
            policy_version=7,
        )


class FailingProtection:
    def __init__(self, error: Exception) -> None:
        self._error = error

    async def protect(self, **_kwargs: object) -> ProtectedDocument:
        raise self._error


class FakePolicies:
    def __init__(self, resolved: PolicySnapshot | None = None) -> None:
        self._snapshot = resolved or policy_of()
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, *, tenant_id: UUID, provider: str, model: str) -> PolicySnapshot:
        self.calls.append((provider, model))
        return self._snapshot


class RecordingProvider:
    alias = "mock"

    def __init__(self) -> None:
        self.seen: list[Any] = []

    async def complete(self, request: Any) -> ProviderResponse:
        self.seen.append(request)
        return ProviderResponse(content=request.messages[-1].content, model="general-chat")


class FakeRestorer:
    def __init__(self, error: Exception | None = None) -> None:
        self._error = error
        self.calls = 0

    async def restore(self, *, tenant_id: UUID, session_id: UUID, response: Any, policy: Any):
        self.calls += 1
        if self._error is not None:
            raise self._error
        return RestoredOutput(
            text=response.content.replace(TOKEN, CANARIES["email"]),
            summary=PrivacySummary(restored=1),
            model=response.model,
            usage=None,
        )


class RecordingAudit:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    async def submit(self, record: AuditRecord) -> None:
        self.records.append(record)


def build(
    *,
    protection: Any = None,
    policies: Any = None,
    provider: Any = None,
    restorer: Any = None,
    audit: Any = None,
    detector: Any = None,
    instruction_max_chars: int = 4_000,
) -> tuple[DocumentPipeline, RecordingProvider, RecordingAudit]:
    adapter = provider or RecordingProvider()
    sink = audit or RecordingAudit()
    pipeline = DocumentPipeline(
        protection=protection or FakeProtection(),
        policies=policies or FakePolicies(),
        detector=detector
        or FakeDetector(config=DetectionConfig(), person_names=(CANARIES["person_name"],)),
        providers=ProviderRegistry.from_providers(adapter),
        restorer=restorer or FakeRestorer(),
        audit=sink,
        hasher=HASHER,
        instruction_max_chars=instruction_max_chars,
    )
    return pipeline, adapter, sink


async def run(pipeline: DocumentPipeline, *, instruction: str = "Summarise.") -> DocumentAnswer:
    return await pipeline.run(
        principal=PRINCIPAL,
        request_id=REQUEST,
        session_id=SESSION,
        user_id=USER,
        document_id=DOCUMENT,
        provider="mock",
        model="general-chat",
        instruction=instruction,
    )


# ---------------------------------------------------------------------------
# Order
# ---------------------------------------------------------------------------
class TestStageOrder:
    async def test_the_destination_is_authorized_before_the_document_is_touched(self) -> None:
        # An unpermitted provider must not be able to buy a decrypt, an extract,
        # and a detection pass. This is the cheapest refusal in the phase and it
        # has to come first.
        protection = FakeProtection()
        pipeline, _adapter, _audit = build(protection=protection)

        with pytest.raises(ProviderNotAllowedError):
            await pipeline.run(
                principal=PRINCIPAL,
                request_id=REQUEST,
                session_id=SESSION,
                user_id=USER,
                document_id=DOCUMENT,
                provider="not-registered",
                model="general-chat",
                instruction="Summarise.",
            )

        assert protection.calls == 0

    async def test_an_oversized_instruction_is_refused_before_anything_else(self) -> None:
        policies = FakePolicies()
        protection = FakeProtection()
        pipeline, _adapter, _audit = build(protection=protection, policies=policies)

        with pytest.raises(RequestTooLargeError):
            await run(pipeline, instruction="x" * 5_000)

        assert policies.calls == []
        assert protection.calls == 0

    async def test_the_instruction_and_the_document_stay_in_separate_messages(self) -> None:
        # Splicing a caller's instruction into the same turn as the document
        # would let it be read as part of the content, which is a
        # prompt-injection foothold the gateway should not hand out for free.
        pipeline, adapter, _audit = build()

        await run(pipeline, instruction="Summarise this referral.")

        sent = adapter.seen[0]
        assert [message.role for message in sent.messages] == ["system", "user"]
        assert sent.messages[0].content == "Summarise this referral."
        assert TOKEN in sent.messages[1].content

    async def test_restoration_runs_after_the_provider(self) -> None:
        restorer = FakeRestorer()
        pipeline, adapter, _audit = build(restorer=restorer)

        answer = await run(pipeline)

        assert adapter.seen, "the provider was not called"
        assert restorer.calls == 1
        assert CANARIES["email"] in answer.text


# ---------------------------------------------------------------------------
# One payload, used three times
# ---------------------------------------------------------------------------
class TestAttestation:
    async def test_the_attested_bytes_are_the_transmitted_bytes(self) -> None:
        # The property that makes an attestation mean anything. If the scan ran
        # over one rendering and the adapter sent another, the digest would
        # prove something nobody checked.
        pipeline, adapter, _audit = build()

        answer = await run(pipeline)

        expected = HASHER.outbound_digest(
            tenant_id=TENANT, payload=serialize_outbound(adapter.seen[0])
        )
        assert answer.outbound_hmac == expected

    async def test_the_audit_row_carries_the_attestation_and_the_verdict(self) -> None:
        pipeline, _adapter, audit = build()

        answer = await run(pipeline)

        assert len(audit.records) == 1
        record = audit.records[0]
        assert record.outbound_hmac == answer.outbound_hmac
        assert record.outbound_scan == "clean"
        assert record.blocked is False
        assert record.status_code == 200

    async def test_the_correlation_digests_are_populated(self) -> None:
        # ADR-0024: a column that is always null is worse than an absent one.
        pipeline, _adapter, audit = build()

        await run(pipeline)

        record = audit.records[0]
        assert record.session_id_hash
        assert record.response_hmac
        assert record.policy_version == 7


# ---------------------------------------------------------------------------
# The blocked path
# ---------------------------------------------------------------------------
class TestOutboundBlock:
    async def test_a_surviving_original_stops_the_request(self) -> None:
        # Protection that "succeeded" but left an address in the text. The scan
        # is the last place to catch it and the answer is to refuse.
        leaking = FakeProtection(text=f"Contact {CANARIES['email']} today.")
        pipeline, adapter, _audit = build(protection=leaking)

        with pytest.raises(PolicyViolationError) as caught:
            await run(pipeline)

        assert adapter.seen == [], "the payload was transmitted despite the scan"
        assert caught.value.log_context["reason"] == "outbound_scan_found_entities"

    async def test_the_blocked_path_still_writes_its_evidence(self) -> None:
        # ADR-0024 is explicit: a request stopped by the scan is the case most
        # worth auditing.
        leaking = FakeProtection(text=f"Contact {CANARIES['email']} today.")
        pipeline, _adapter, audit = build(protection=leaking)

        with pytest.raises(PolicyViolationError):
            await run(pipeline)

        assert len(audit.records) == 1
        record = audit.records[0]
        assert record.blocked is True
        assert record.outbound_scan == "blocked"
        assert record.outbound_hmac, "the refused payload was not attested"
        assert record.block_reason_code == "outbound_scan"
        assert record.status_code == 422

    async def test_the_block_names_types_and_never_values(self) -> None:
        leaking = FakeProtection(text=f"Contact {CANARIES['email']} today.")
        pipeline, _adapter, audit = build(protection=leaking)

        with pytest.raises(PolicyViolationError) as caught:
            await run(pipeline)

        surface = f"{caught.value.public_message}{caught.value.log_context}{audit.records[0]!r}"
        assert EMAIL_ADDRESS in caught.value.log_context["entity_type"], "non-vacuity"
        assert CANARIES["email"] not in surface


# ---------------------------------------------------------------------------
# Failing closed
# ---------------------------------------------------------------------------
class TestFailsClosed:
    async def test_a_protection_failure_reaches_no_provider(self) -> None:
        pipeline, adapter, audit = build(
            protection=FailingProtection(VaultUnavailableError()),
        )

        with pytest.raises(VaultUnavailableError):
            await run(pipeline)

        assert adapter.seen == []
        assert audit.records == [], "nothing was serialised, so nothing to attest"

    async def test_a_restoration_failure_returns_nothing(self) -> None:
        # Half-restored text would be indistinguishable from a successful answer
        # with fewer entities, so the caller gets an error instead.
        pipeline, _adapter, _audit = build(restorer=FakeRestorer(error=VaultUnavailableError()))

        with pytest.raises(VaultUnavailableError):
            await run(pipeline)

    def test_an_unworkable_bound_is_refused_at_construction(self) -> None:
        with pytest.raises(ValueError):
            build(instruction_max_chars=0)


class TestReporting:
    async def test_the_answer_repr_hides_the_restored_text(self) -> None:
        pipeline, _adapter, _audit = build()

        answer = await run(pipeline)

        assert CANARIES["email"] not in repr(answer)
        assert "characters=" in repr(answer)

    async def test_the_summary_merges_protection_and_restoration(self) -> None:
        pipeline, _adapter, _audit = build()

        answer = await run(pipeline)

        assert answer.privacy.detected == 1
        assert answer.privacy.tokenized == 1
        assert answer.privacy.restored == 1

    def test_the_pipeline_repr_carries_its_bound(self) -> None:
        pipeline, _adapter, _audit = build(instruction_max_chars=99)

        assert repr(pipeline) == "DocumentPipeline(instruction_max_chars=99)"
