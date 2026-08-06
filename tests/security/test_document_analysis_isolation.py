"""Detection over documents, wired the way production wires it.

The suites in ``tests/unit/`` build a :class:`DocumentAnalyzer` directly, which
proves the analyzer behaves. It does not prove the *composition root* assembles
one, that the one it assembles reads through the tenant- and user-scoped path,
or that the detector it uses is the same detector the chat pipeline uses. Those
are three separate ways for a correct component to be wired into an incorrect
system, and the project has already shipped that class of defect twice --
defects 1 and 6 both existed because each module was right on its own.

So everything here goes through ``build_services``.

The shared detector is the subtle one. A second ``PresidioDetector`` would work,
cost another spaCy load, and could be configured differently -- and then a value
protected in a prompt might not be protected in a document, with nothing in
either module wrong.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING
from uuid import uuid4

import fakeredis.aioredis
import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import create_async_engine

from app.api.composition import Services, build_services, stop_services
from app.config.settings import Settings
from app.db.base import Base
from app.db.models import Policy, Tenant
from app.db.session import build_session_factory
from app.documents.analysis.analyzer import DocumentAnalyzer
from app.documents.models import CONTENT_TYPE_TXT
from app.documents.storage.fakes import FakeDocumentStore
from app.domain.errors import DocumentNotFoundError
from app.policy.defaults import DEFAULT_POLICY
from tests.fixtures.documents import CANARIES, OTHER_TENANT, OTHER_USER, TENANT, USER, stream

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from uuid import UUID

pytestmark = pytest.mark.security

BODY = f"Contact {CANARIES['email']} about the referral.\n".encode()


DOCUMENT_KEY = SecretStr(base64.b64encode(bytes(range(32))).decode())
VAULT_KEY = SecretStr(base64.b64encode(bytes(range(1, 33))).decode())


def settings_of(*, documents_enabled: bool = True) -> Settings:
    return Settings(
        app_env="test",
        documents_enabled=documents_enabled,
        vault_keys={"local1": VAULT_KEY},
        document_keys={"local1": DOCUMENT_KEY},
    )


@pytest.fixture
async def services() -> AsyncIterator[Services]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with build_session_factory(engine)() as session:
        for tenant, name in ((TENANT, "test"), (OTHER_TENANT, "other")):
            session.add(Tenant(id=tenant, name=name, slug=name))
            # Both tenants get the shipped default policy. Without one the
            # analyzer refuses on PolicyNotFoundError before it ever looks at
            # the document, and an isolation test would pass without exercising
            # the scoping it claims to check.
            session.add(
                Policy(
                    tenant_id=tenant,
                    name=DEFAULT_POLICY.name,
                    version=1,
                    document=DEFAULT_POLICY.model_dump(mode="json"),
                    is_active=True,
                )
            )
        await session.commit()

    built = await build_services(
        settings_of(),
        redis=fakeredis.aioredis.FakeRedis(decode_responses=False),
        engine=engine,
        document_store=FakeDocumentStore(),
    )
    yield built
    await stop_services(built)


async def upload(services: Services, *, tenant_id: UUID = TENANT, user_id: UUID = USER) -> UUID:
    assert services.documents is not None
    stored = await services.documents.store(
        tenant_id=tenant_id,
        user_id=user_id,
        filename="referral.txt",
        declared_content_type=CONTENT_TYPE_TXT,
        declared_length=len(BODY),
        source=stream(BODY),
    )
    return stored.metadata.id


class TestComposition:
    async def test_an_analyzer_is_assembled_when_documents_are_enabled(
        self, services: Services
    ) -> None:
        assert isinstance(services.document_analyzer, DocumentAnalyzer)

    async def test_no_analyzer_exists_when_documents_are_disabled(self) -> None:
        # A deployment that accepts no uploads builds nothing to analyze them
        # with, rather than building a component wired to a store it never
        # opened.
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        built = await build_services(
            settings_of(documents_enabled=False),
            redis=fakeredis.aioredis.FakeRedis(decode_responses=False),
            engine=engine,
        )
        try:
            assert built.documents is None
            assert built.document_processor is None
            assert built.document_analyzer is None
        finally:
            await stop_services(built)

    async def test_the_analyzer_shares_the_pipeline_detector(self, services: Services) -> None:
        # Identity, not equality. Two separately configured detectors would let
        # a value be protected in a prompt and not in a document, with neither
        # module doing anything wrong.
        assert services.document_analyzer is not None
        assert services.document_analyzer.detector is services.detector


class TestIsolation:
    async def test_another_users_document_cannot_be_analyzed(self, services: Services) -> None:
        # The same answer as "no such document". Distinguishing them would make
        # analysis an oracle for which document ids exist in a tenant.
        assert services.document_analyzer is not None
        document_id = await upload(services, user_id=OTHER_USER)

        with pytest.raises(DocumentNotFoundError):
            await services.document_analyzer.analyze(
                tenant_id=TENANT, user_id=USER, document_id=document_id
            )

    async def test_another_tenants_document_cannot_be_analyzed(self, services: Services) -> None:
        assert services.document_analyzer is not None
        document_id = await upload(services, tenant_id=OTHER_TENANT, user_id=USER)

        with pytest.raises(DocumentNotFoundError):
            await services.document_analyzer.analyze(
                tenant_id=TENANT, user_id=USER, document_id=document_id
            )

    async def test_an_unknown_document_is_the_same_refusal(self, services: Services) -> None:
        # Non-vacuity for the two above: absence and denial must be the same
        # error, so proving denial requires knowing what absence looks like.
        assert services.document_analyzer is not None

        with pytest.raises(DocumentNotFoundError):
            await services.document_analyzer.analyze(
                tenant_id=TENANT, user_id=USER, document_id=uuid4()
            )
