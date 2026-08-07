"""The draft/publish lifecycle, against a real database.

ADR-0037 makes three promises, and every test here exists to hold one of them:
published versions are immutable, publishing creates a new version rather than
editing one, and a request already holding a ``PolicySnapshot`` keeps it.

SQLite in memory rather than the fake repository, because two of the guarantees
-- the one-draft-per-name index and the unchanged-rows-after-publish property --
are enforced by the schema and by SQL, and a fake would happily agree with
whatever the code did.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

from app.db.base import Base
from app.db.models import POLICY_STATUS_DRAFT, POLICY_STATUS_PUBLISHED, Tenant
from app.db.session import build_session_factory
from app.domain.models import EntityAction
from app.policy.defaults import DEFAULT_POLICY
from app.policy.models import PolicyDocument, PolicySnapshot
from app.repositories.policies import SqlAlchemyPolicyRepository

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.ext.asyncio import AsyncSession

TENANT = UUID("11111111-1111-1111-1111-111111111111")
NAME = "default"


def document(**overrides: Any) -> dict[str, Any]:
    base = DEFAULT_POLICY.model_dump(mode="json")
    base.update(overrides)
    return base


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = build_session_factory(engine)
    async with factory() as opened:
        opened.add(Tenant(id=TENANT, name="test", slug="test"))
        await opened.flush()
        yield opened
    await engine.dispose()


@pytest.fixture
def repo(session: AsyncSession) -> SqlAlchemyPolicyRepository:
    return SqlAlchemyPolicyRepository(session)


async def published_v1(repo: SqlAlchemyPolicyRepository) -> Any:
    return await repo.create_version(
        TENANT, name=NAME, version=1, document=document(), is_active=True
    )


class TestDraftCreation:
    async def test_a_draft_takes_the_next_version_number(
        self, repo: SqlAlchemyPolicyRepository
    ) -> None:
        await published_v1(repo)

        draft = await repo.create_draft(TENANT, name=NAME, document=document())

        assert draft.version == 2
        assert draft.status == POLICY_STATUS_DRAFT
        assert draft.published_at is None
        assert draft.is_active is False

    async def test_a_draft_is_not_active_and_does_not_displace_the_live_version(
        self, repo: SqlAlchemyPolicyRepository
    ) -> None:
        # The point of a draft: editing it changes nothing for live traffic.
        await published_v1(repo)

        await repo.create_draft(TENANT, name=NAME, document=document(max_entities=9))

        active = await repo.get_active(TENANT)
        assert active is not None
        assert active.version == 1
        assert active.document["max_entities"] == 500

    async def test_only_one_draft_may_be_open_at_a_time(
        self, repo: SqlAlchemyPolicyRepository, session: AsyncSession
    ) -> None:
        # Enforced by a partial unique index, not by a read-then-write check,
        # so two concurrent callers cannot both win.
        await published_v1(repo)
        await repo.create_draft(TENANT, name=NAME, document=document())

        with pytest.raises(IntegrityError):
            await repo.create_draft(TENANT, name=NAME, document=document())
        await session.rollback()

    async def test_the_first_version_of_a_new_policy_is_version_one(
        self, repo: SqlAlchemyPolicyRepository
    ) -> None:
        draft = await repo.create_draft(TENANT, name="fresh", document=document(name="fresh"))

        assert draft.version == 1


class TestDraftEditing:
    async def test_editing_a_draft_replaces_its_document(
        self, repo: SqlAlchemyPolicyRepository
    ) -> None:
        await published_v1(repo)
        await repo.create_draft(TENANT, name=NAME, document=document())

        updated = await repo.update_draft(TENANT, name=NAME, document=document(max_entities=42))

        assert updated is not None
        assert updated.document["max_entities"] == 42

    async def test_editing_reports_absence_rather_than_creating_one(
        self, repo: SqlAlchemyPolicyRepository
    ) -> None:
        await published_v1(repo)

        assert await repo.update_draft(TENANT, name=NAME, document=document()) is None

    async def test_discarding_removes_the_draft_and_leaves_history_intact(
        self, repo: SqlAlchemyPolicyRepository
    ) -> None:
        await published_v1(repo)
        await repo.create_draft(TENANT, name=NAME, document=document())

        assert await repo.discard_draft(TENANT, name=NAME) is True
        assert await repo.get_draft(TENANT, name=NAME) is None
        assert [p.version for p in await repo.list_versions(TENANT, name=NAME)] == [1]

    async def test_discarding_nothing_says_so(self, repo: SqlAlchemyPolicyRepository) -> None:
        await published_v1(repo)

        assert await repo.discard_draft(TENANT, name=NAME) is False


class TestPublishing:
    async def test_publishing_creates_a_new_active_version(
        self, repo: SqlAlchemyPolicyRepository
    ) -> None:
        await published_v1(repo)
        await repo.create_draft(TENANT, name=NAME, document=document(max_entities=99))

        published = await repo.publish_draft(TENANT, name=NAME)

        assert published is not None
        assert published.version == 2
        assert published.status == POLICY_STATUS_PUBLISHED
        assert published.is_active is True
        assert published.published_at is not None

    async def test_the_previous_version_is_unchanged_except_for_being_superseded(
        self, repo: SqlAlchemyPolicyRepository
    ) -> None:
        # "Previous versions remain unchanged" is the promise. Only is_active
        # moves; the document, version, and creation time must not.
        first = await published_v1(repo)
        before = (dict(first.document), first.version, first.created_at)
        await repo.create_draft(TENANT, name=NAME, document=document(max_entities=99))

        await repo.publish_draft(TENANT, name=NAME)

        v1 = await repo.get_version(TENANT, name=NAME, version=1)
        assert v1 is not None
        assert (dict(v1.document), v1.version, v1.created_at) == before
        assert v1.is_active is False

    async def test_publishing_closes_the_draft_so_a_new_one_can_open(
        self, repo: SqlAlchemyPolicyRepository
    ) -> None:
        await published_v1(repo)
        await repo.create_draft(TENANT, name=NAME, document=document())
        await repo.publish_draft(TENANT, name=NAME)

        assert await repo.get_draft(TENANT, name=NAME) is None
        third = await repo.create_draft(TENANT, name=NAME, document=document())
        assert third.version == 3

    async def test_publishing_without_a_draft_reports_absence(
        self, repo: SqlAlchemyPolicyRepository
    ) -> None:
        await published_v1(repo)

        assert await repo.publish_draft(TENANT, name=NAME) is None

    async def test_history_accumulates_rather_than_being_overwritten(
        self, repo: SqlAlchemyPolicyRepository
    ) -> None:
        await published_v1(repo)
        for entities in (10, 20, 30):
            await repo.create_draft(TENANT, name=NAME, document=document(max_entities=entities))
            await repo.publish_draft(TENANT, name=NAME)

        versions = await repo.list_versions(TENANT, name=NAME)
        assert [p.version for p in versions] == [1, 2, 3, 4]
        assert [p.document["max_entities"] for p in versions] == [500, 10, 20, 30]
        assert sum(1 for p in versions if p.is_active) == 1


class TestSnapshotIsolation:
    def test_a_snapshot_taken_before_a_publish_is_unaffected_by_it(self) -> None:
        # The core in-flight guarantee. A snapshot is a frozen value built from
        # a document, not a view onto a row, so nothing that happens to the
        # database afterwards can reach it.
        original = PolicySnapshot.from_document(
            DEFAULT_POLICY, policy_id=uuid4(), tenant_id=TENANT, version=1
        )
        before = (original.version, original.entities, original.max_entities)

        edited = PolicyDocument.model_validate(document(max_entities=1))
        PolicySnapshot.from_document(edited, policy_id=uuid4(), tenant_id=TENANT, version=2)

        assert (original.version, original.entities, original.max_entities) == before

    def test_a_snapshot_cannot_be_mutated_through_its_indexes(self) -> None:
        snapshot = PolicySnapshot.from_document(
            DEFAULT_POLICY, policy_id=uuid4(), tenant_id=TENANT, version=1
        )

        with pytest.raises(TypeError):
            snapshot._entity_index["EMAIL_ADDRESS"] = None  # type: ignore[index]


class TestDisabledRules:
    def test_a_disabled_rule_is_dropped_from_the_snapshot(self) -> None:
        raw = document()
        raw["entities"]["PERSON"]["enabled"] = False

        snapshot = PolicySnapshot.from_document(
            PolicyDocument.model_validate(raw), policy_id=uuid4(), tenant_id=TENANT, version=1
        )

        assert "PERSON" not in snapshot.entity_types

    def test_disabling_a_rule_protects_the_value_rather_than_releasing_it(self) -> None:
        # The safety property worth stating out loud: an operator who unticks a
        # box does not thereby send that entity type to the provider in clear
        # text. It falls through to the fail-safe default.
        raw = document()
        raw["entities"]["PERSON"]["enabled"] = False

        snapshot = PolicySnapshot.from_document(
            PolicyDocument.model_validate(raw), policy_id=uuid4(), tenant_id=TENANT, version=1
        )

        assert snapshot.action_for("PERSON") is EntityAction.TOKENIZE
        assert snapshot.action_for("PERSON") is not EntityAction.ALLOW

    def test_documents_written_before_enabled_existed_behave_identically(self) -> None:
        # Backward compatibility, asserted rather than assumed: every stored
        # policy predates these fields.
        legacy = {
            "schema_version": 1,
            "name": "legacy",
            "session_ttl_seconds": 1800,
            "max_entities": 500,
            "providers": {"mock": {"models": ["general-chat"]}},
            "entities": {"EMAIL_ADDRESS": {"action": "tokenize", "min_score": 0.7}},
            "unknown_output_token_action": "preserve",
        }

        snapshot = PolicySnapshot.from_document(
            PolicyDocument.model_validate(legacy), policy_id=uuid4(), tenant_id=TENANT, version=1
        )

        assert snapshot.entity_types == frozenset({"EMAIL_ADDRESS"})
        assert snapshot.action_for("EMAIL_ADDRESS") is EntityAction.TOKENIZE
        assert snapshot.min_score_for("EMAIL_ADDRESS") == 0.7
