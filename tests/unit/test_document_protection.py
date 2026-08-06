"""Stored document to provider-safe text, through the real tokenizer and vault.

These run the whole path for real below the object store: genuine chunked
AES-256-GCM, genuine extraction, genuine segmentation, the shared
``app.detection.postprocess.finalize``, the production ``Tokenizer``, and a
``RecordingVault`` that mints real tokens under the real grammar. Only the
object store and the database are in-memory.

That matters more here than anywhere else in the document path, because
protection is the first stage whose output *leaves* the gateway. A test that
stubbed the tokenizer would prove the wiring and nothing about whether the
document that comes out still has a patient's name in it.

Three assertions carry the file:

* ``test_no_original_survives_in_the_protected_text`` — the whole point.
* ``test_a_span_that_analysis_labeled_is_never_silently_dropped`` — the reason
  reusing the prompt tokenizer is safe rather than merely convenient.
* ``TestNothingLeaks`` — the originals are in the vault and nowhere else.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING
from uuid import uuid4

import pytest
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.models import Tenant
from app.detection.config import DetectionConfig
from app.detection.entities import (
    EMAIL_ADDRESS,
    MEDICAL_RECORD_NUMBER,
    PERSON,
    PHONE_NUMBER,
    US_SSN,
)
from app.detection.fakes import FakeDetector
from app.documents.analysis.analyzer import DocumentAnalyzer
from app.documents.extraction.runner import InlineExtractionRunner
from app.documents.models import CONTENT_TYPE_TXT
from app.documents.processing import DocumentProcessor
from app.documents.protection import (
    DocumentProtector,
    ProtectedDocument,
    _DocumentEntityBudget,
)
from app.documents.segmentation import Segmenter
from app.documents.service import DocumentService
from app.documents.storage.fakes import FakeDocumentStore
from app.domain.errors import (
    DocumentNotFoundError,
    EntityLimitExceededError,
    GatewayError,
    PolicyViolationError,
    VaultUnavailableError,
)
from app.domain.models import EntityAction, PrivacySummary, TransformedText, VaultWriteRequest
from app.policy.models import EntityRule
from app.tokenization.grammar import parse_token
from app.tokenization.tokenizer import Tokenizer
from app.vault.fakes import InMemoryTokenVault
from tests.fixtures.documents import (
    CANARIES,
    MAX_BYTES,
    OTHER_USER,
    TENANT,
    USER,
    make_cipher,
    stream,
)
from tests.fixtures.policies import FakePolicySource, snapshot

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Sequence
    from contextlib import AbstractAsyncContextManager
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from app.documents.protection import PolicyLike
    from app.domain.models import DetectedEntity
    from app.policy.models import PolicySnapshot

SESSION = uuid4()

DETECTABLE_MRN = "MRN-40217788"

BODY = (
    f"{CANARIES['person_name']} attended the oncology clinic on Tuesday.\n"
    f"Record number {DETECTABLE_MRN}, contact {CANARIES['email']} for follow-up.\n"
    f"Reachable on {CANARIES['phone']} during the week.\n"
).encode()

ORIGINALS = (CANARIES["person_name"], CANARIES["email"], DETECTABLE_MRN)
"""The values the fake detector finds in ``BODY`` and the policy below acts on.

Stated so every "no original survives" assertion can first require that these
were actually found. An absence assertion over an empty set passes for the
wrong reason.
"""

PROTECT_EVERYTHING = {
    PERSON: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    EMAIL_ADDRESS: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    MEDICAL_RECORD_NUMBER: EntityRule(action=EntityAction.REDACT, min_score=0.5),
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


class RecordingVault:
    """``InMemoryTokenVault`` plus a count of write calls and their sessions.

    Wrapping the shipped fake rather than writing a new one: it mints real
    tokens under the real grammar and enforces the same atomicity, which is what
    makes "the same value twice gets the same token" a real assertion. What it
    does not record is *how many round trips* a protection cost -- the whole of
    ADR-0022 -- so that is added here.
    """

    def __init__(self) -> None:
        self._inner = InMemoryTokenVault()
        self.write_calls = 0
        self.sessions: list[UUID] = []

    def fail_with(self, error: GatewayError | None) -> None:
        self._inner.simulate_failure(error)

    def stored_original_values(self) -> list[str]:
        return self._inner.stored_original_values()

    async def get_or_create_many(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        entries: Sequence[VaultWriteRequest],
        ttl_seconds: int,
    ) -> tuple[str, ...]:
        self.write_calls += 1
        self.sessions.append(session_id)
        return await self._inner.get_or_create_many(
            tenant_id=tenant_id,
            session_id=session_id,
            entries=entries,
            ttl_seconds=ttl_seconds,
        )


@pytest.fixture
def vault() -> RecordingVault:
    return RecordingVault()


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
    documents: DocumentService,
    *,
    policy: PolicySnapshot | None = None,
    max_entities: int = 10_000,
) -> DocumentAnalyzer:
    return DocumentAnalyzer(
        source=DocumentProcessor(
            source=documents,
            runner=InlineExtractionRunner(),
            segmenter=Segmenter(max_characters=200, overlap_characters=48),
            max_document_bytes=MAX_BYTES,
        ),
        detector=FakeDetector(config=DetectionConfig(), person_names=(CANARIES["person_name"],)),
        policies=FakePolicySource(policy or policy_of()),
        max_entities=max_entities,
    )


def protector_of(
    documents: DocumentService,
    vault: RecordingVault,
    *,
    policy: PolicySnapshot | None = None,
    max_entities: int = 10_000,
) -> DocumentProtector:
    return DocumentProtector(
        analysis=analyzer_of(documents, policy=policy, max_entities=max_entities),
        tokenizer=Tokenizer(vault=vault),
        detector=FakeDetector(config=DetectionConfig(), person_names=(CANARIES["person_name"],)),
        max_entities=max_entities,
    )


async def upload(documents: DocumentService, *, body: bytes = BODY, user_id: UUID = USER) -> UUID:
    stored = await documents.store(
        tenant_id=TENANT,
        user_id=user_id,
        filename="referral.txt",
        declared_content_type=CONTENT_TYPE_TXT,
        declared_length=len(body),
        source=stream(body),
    )
    return stored.metadata.id


# ---------------------------------------------------------------------------
# The point of the whole system
# ---------------------------------------------------------------------------
class TestProtection:
    async def test_no_original_survives_in_the_protected_text(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        document_id = await upload(documents)

        protected = await protector_of(documents, vault).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        # Non-vacuity first: the run must have found the values it is now
        # asserted not to contain, or this passes against an empty document.
        assert protected.summary.detected >= len(ORIGINALS)
        for original in ORIGINALS:
            assert original not in protected.text, f"{original!r} survived protection"

    async def test_tokenized_values_are_replaced_by_real_tokens(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        document_id = await upload(documents)

        protected = await protector_of(documents, vault).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        # Parsed with the production grammar rather than matched as a substring.
        # A placeholder that merely looks token-shaped passes a substring check
        # and fails restoration later, which is the expensive place to find out.
        #
        # Redactions share the delimiters and are deliberately *not* tokens --
        # `⟦SGW:REDACTED:TYPE⟧` has no identifier because there is nothing to
        # resolve. Separating them here is the assertion that the two remain
        # distinguishable to the parser that reads provider output.
        placeholders = [word.strip(".,\n") for word in protected.text.split()]
        redactions = [item for item in placeholders if item.startswith("⟦SGW:REDACTED:")]
        tokens = [
            parse_token(item)
            for item in placeholders
            if item.startswith("⟦SGW:") and item not in redactions
        ]

        assert tokens, "non-vacuity: the policy tokenizes, so tokens must appear"
        assert all(token is not None for token in tokens)
        assert {token.entity_type for token in tokens if token} == {
            PERSON,
            EMAIL_ADDRESS,
            PHONE_NUMBER,
        }
        assert redactions == [f"⟦SGW:REDACTED:{MEDICAL_RECORD_NUMBER}⟧"]

    async def test_an_unconfigured_type_is_protected_by_the_default(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        # PHONE_NUMBER is absent from the policy above, so it resolves to
        # UNKNOWN_ENTITY_ACTION -- TOKENIZE. Defaulting to ALLOW would ship a
        # newly detectable class of value to the provider in the clear, which is
        # the failure defect 7 made unreachable and this keeps unreachable.
        document_id = await upload(documents)

        protected = await protector_of(documents, vault).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        assert CANARIES["phone"] not in protected.text

    async def test_a_redacted_value_creates_no_vault_mapping(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        # REDACT is deliberately irreversible. A mapping would make it
        # reversible while every count still called it a redaction.
        document_id = await upload(documents)

        protected = await protector_of(documents, vault).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        assert protected.summary.redacted == 1, "non-vacuity: the MRN must have been redacted"
        assert DETECTABLE_MRN not in protected.text
        assert DETECTABLE_MRN not in vault.stored_original_values()

    async def test_the_surrounding_text_is_untouched(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        # The splice must replace spans and nothing else. An off-by-one here
        # corrupts the prose the model is supposed to reason about.
        document_id = await upload(documents)

        protected = await protector_of(documents, vault).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        assert "attended the oncology clinic on Tuesday." in protected.text
        assert "during the week." in protected.text

    async def test_the_same_value_twice_gets_the_same_token(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        # Repeated-entity consistency, which is what makes a protected document
        # readable to a model rather than a wall of distinct opaque strings.
        body = f"{CANARIES['email']} and again {CANARIES['email']}.\n".encode()
        document_id = await upload(documents, body=body)

        protected = await protector_of(documents, vault).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        tokens = [word for word in protected.text.split() if word.startswith("⟦SGW:")]
        assert len(tokens) == 2
        assert tokens[0] == tokens[1].rstrip(".")

    async def test_a_clean_document_comes_back_unchanged(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        body = b"The weather was unremarkable all week.\n"
        document_id = await upload(documents, body=body)

        protected = await protector_of(documents, vault).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        assert protected.text == body.decode()
        assert protected.summary.detected == 0
        assert vault.stored_original_values() == []

    async def test_the_policy_version_travels_to_the_result(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        document_id = await upload(documents)

        protected = await protector_of(documents, vault, policy=policy_of(version=41)).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        assert protected.policy_version == 41


# ---------------------------------------------------------------------------
# The vault
# ---------------------------------------------------------------------------
class TestVaultInteraction:
    async def test_every_mapping_is_written_in_one_call(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        # ADR-0022. A round trip per span is arithmetically fatal on a document,
        # and the count is the assertion that holds on any hardware.
        document_id = await upload(documents, body=BODY * 8)

        protected = await protector_of(documents, vault).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        assert protected.summary.tokenized > 1, "non-vacuity: several spans needed a mapping"
        assert vault.write_calls == 1

    async def test_the_mappings_are_scoped_to_the_session_the_caller_gave(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        # A token minted in one session does not resolve in another, so a
        # protector that invented its own session would mint mappings the
        # conversation quoting them could never resolve.
        document_id = await upload(documents)

        await protector_of(documents, vault).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        assert vault.sessions == [SESSION]

    async def test_a_vault_outage_yields_no_protected_text(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        # Fail closed. Half-protected text must never be constructible, because
        # the type is what the provider boundary trusts.
        document_id = await upload(documents)
        vault.fail_with(VaultUnavailableError())

        with pytest.raises(VaultUnavailableError):
            await protector_of(documents, vault).protect(
                tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
            )

    async def test_a_blocked_document_reaches_no_vault_call(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        # The block is raised by analysis, before protection starts, so a
        # request destined to fail leaves no mapping and no TTL to wait out.
        body = f"SSN {CANARIES['ssn']} and {CANARIES['email']}.\n".encode()
        document_id = await upload(documents, body=body)
        blocking = policy_of(
            {
                US_SSN: EntityRule(action=EntityAction.BLOCK, min_score=0.5),
                EMAIL_ADDRESS: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
            }
        )

        with pytest.raises(PolicyViolationError):
            await protector_of(documents, vault, policy=blocking).protect(
                tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
            )

        assert vault.write_calls == 0
        assert vault.stored_original_values() == []


# ---------------------------------------------------------------------------
# The seam with analysis
# ---------------------------------------------------------------------------
class TestAgreementWithAnalysis:
    async def test_the_actions_applied_are_the_actions_labeled(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        # The tokenizer re-derives actions from the policy it is handed. Because
        # that policy is the one analysis used, the derivation must reproduce the
        # labels exactly -- checked here rather than assumed.
        document_id = await upload(documents)
        analyzer = analyzer_of(documents)
        analyzed = await analyzer.analyze(tenant_id=TENANT, user_id=USER, document_id=document_id)

        protected = await DocumentProtector(
            analysis=analyzer,
            tokenizer=Tokenizer(vault=vault),
            detector=FakeDetector(config=DetectionConfig()),
            max_entities=10_000,
        ).protect(tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id)

        labeled = analyzed.counts_by_action()
        assert protected.summary.detected == analyzed.span_count
        assert protected.summary.tokenized == labeled.get(EntityAction.TOKENIZE, 0)
        assert protected.summary.redacted == labeled.get(EntityAction.REDACT, 0)

    async def test_a_span_that_analysis_labeled_is_never_silently_dropped(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        # The guard that makes reusing the prompt tokenizer safe. A tokenizer
        # that dropped a span would otherwise return text with an original still
        # in it, and a summary that called the document protected.
        document_id = await upload(documents)

        protector = DocumentProtector(
            analysis=analyzer_of(documents),
            tokenizer=_DroppingTokenizer(Tokenizer(vault=vault)),
            detector=FakeDetector(config=DetectionConfig()),
            max_entities=10_000,
        )

        with pytest.raises(GatewayError) as caught:
            await protector.protect(
                tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
            )

        assert caught.value.log_context["reason"] == "protection_dropped_labeled_spans"

    async def test_the_document_budget_is_used_and_not_the_policys(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        # The tokenizer enforces policy.max_entities, which is sized for a chat
        # request. Without the budget view, a document with more spans than a
        # prompt is allowed would be refused at the very end of the most
        # expensive path in the system.
        document_id = await upload(documents, body=BODY * 4)
        narrow = policy_of(max_entities=2)

        protected = await protector_of(documents, vault, policy=narrow).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        assert protected.summary.detected > 2, "the fixture must exceed the prompt ceiling"

    async def test_the_document_budget_still_refuses_an_over_budget_document(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        # The other direction, so the view is a substitution and not a bypass.
        document_id = await upload(documents, body=BODY * 4)

        with pytest.raises(EntityLimitExceededError):
            await protector_of(documents, vault, max_entities=2).protect(
                tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
            )

    def test_the_budget_view_changes_only_the_ceiling(self) -> None:
        snapshot_of = policy_of(max_entities=500)
        view = _DocumentEntityBudget(snapshot=snapshot_of, document_max_entities=9_000)

        assert view.max_entities == 9_000
        assert view.session_ttl_seconds == snapshot_of.session_ttl_seconds
        assert view.action_for(PERSON) is snapshot_of.action_for(PERSON)
        assert view.min_score_for(PERSON) == snapshot_of.min_score_for(PERSON)
        assert view.action_for("NEVER_CONFIGURED") is snapshot_of.action_for("NEVER_CONFIGURED")


# ---------------------------------------------------------------------------
# Refusals inherited from the stages below
# ---------------------------------------------------------------------------
class TestRefusals:
    async def test_another_users_document_cannot_be_protected(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        document_id = await upload(documents, user_id=OTHER_USER)

        with pytest.raises(DocumentNotFoundError):
            await protector_of(documents, vault).protect(
                tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
            )

    async def test_an_absent_document_is_not_found(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        with pytest.raises(DocumentNotFoundError):
            await protector_of(documents, vault).protect(
                tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=uuid4()
            )

    def test_the_protector_repr_carries_its_bound_and_nothing_else(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        protector = protector_of(documents, vault, max_entities=88)

        assert repr(protector) == "DocumentProtector(max_entities=88)"

    @pytest.mark.parametrize("max_entities", [0, -1])
    def test_an_unworkable_budget_is_refused_at_construction(
        self, documents: DocumentService, vault: RecordingVault, max_entities: int
    ) -> None:
        with pytest.raises(ValueError):
            DocumentProtector(
                analysis=analyzer_of(documents),
                tokenizer=Tokenizer(vault=vault),
                detector=FakeDetector(config=DetectionConfig()),
                max_entities=max_entities,
            )


# ---------------------------------------------------------------------------
# Nothing leaks
# ---------------------------------------------------------------------------
class TestNothingLeaks:
    async def test_the_result_carries_no_mapping_and_no_original(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        # The originals live in the vault. Carrying them alongside the text would
        # put a Restricted value on the object handed to a provider adapter.
        document_id = await upload(documents)

        protected = await protector_of(documents, vault).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        assert not hasattr(protected, "mappings")
        assert vault.stored_original_values(), "non-vacuity: they exist, just not here"

    async def test_the_repr_hides_the_document(
        self, documents: DocumentService, vault: RecordingVault
    ) -> None:
        document_id = await upload(documents)

        protected = await protector_of(documents, vault).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        text = repr(protected)
        assert "characters=" in text, "non-vacuity: the repr said something"
        assert "oncology" not in text
        for original in ORIGINALS:
            assert original not in text

    async def test_nothing_is_persisted(
        self,
        documents: DocumentService,
        vault: RecordingVault,
        store: FakeDocumentStore,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        from sqlalchemy import text as sql

        document_id = await upload(documents)
        before = {key: store.stored_bytes(key) for key in store.stored_keys()}

        protected = await protector_of(documents, vault).protect(
            tenant_id=TENANT, user_id=USER, session_id=SESSION, document_id=document_id
        )

        assert protected.summary.detected > 0
        assert {key: store.stored_bytes(key) for key in store.stored_keys()} == before
        async with session_scope() as session:
            tables = [
                row[0]
                for row in (
                    await session.execute(sql("SELECT name FROM sqlite_master WHERE type='table'"))
                ).all()
            ]
        for table in tables:
            assert "protect" not in table
            assert "span" not in table

    def test_a_protected_document_must_carry_text(self) -> None:
        # Analysis refuses a document with no extractable text, so an empty
        # result here would mean the splice consumed everything.
        with pytest.raises(ValueError, match="must carry text"):
            ProtectedDocument(
                tenant_id=TENANT,
                session_id=SESSION,
                document_id=uuid4(),
                text="",
                instruction="",
                summary=PrivacySummary(),
                policy_version=1,
            )


class _DroppingTokenizer:
    """A tokenizer that silently loses one span. Exists to be caught."""

    def __init__(self, inner: Tokenizer) -> None:
        self._inner = inner

    async def transform(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        text: str,
        entities: Sequence[DetectedEntity],
        policy: PolicyLike,
    ) -> TransformedText:
        transformed = await self._inner.transform(
            tenant_id=tenant_id,
            session_id=session_id,
            text=text,
            entities=entities[:-1],
            policy=policy,
        )
        return transformed
