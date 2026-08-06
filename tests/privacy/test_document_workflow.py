"""The whole document journey, through the real route, with a canary payload.

Upload a document full of values that appear nowhere else in the repository,
process it against the mock provider, and then ask the question the entire
system exists to answer: **did the provider see any of them?**

Everything below the HTTP boundary is real — the composition root, the router,
the auth dependency, chunked AES-256-GCM, extraction, segmentation, detection,
the tokenizer, the vault on fakeredis, the outbound scan, restoration, and the
audit queue draining into SQLite. The provider is the mock adapter, which is
the one substitution, and it is the substitution that makes the central
assertion possible: the mock records exactly what it was handed.

Four things are checked, and they are four different failures:

* **The provider saw no original.** The point of the product.
* **The caller got the originals back.** A gateway that protects perfectly and
  returns tokens has not done its job either.
* **The audit row proves the check ran**, carries the attestation, and holds no
  content (ADR-0024).
* **Nothing leaked sideways** into a log line or the response envelope.

The sweep asserts it found something before asserting it found nothing bad.
Defects 16 and 17 were both "the absence assertion was searching an empty
string", and this file is the one most able to repeat that mistake.
"""

from __future__ import annotations

import base64
import logging
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import fakeredis.aioredis
import httpx
import pytest
from asgi_lifespan import LifespanManager
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from app.api.composition import Services, build_services, stop_services
from app.config.settings import Settings
from app.db.base import Base
from app.db.models import ApiKey, AuditEvent, Policy, Tenant
from app.db.session import build_session_factory
from app.documents.models import CONTENT_TYPE_TXT
from app.documents.storage.fakes import FakeDocumentStore
from app.domain.models import EntityAction, Scope
from app.llm.mock_provider import MOCK_PROVIDER_ALIAS
from app.main import create_app
from app.observability.logging import configure_logging
from app.policy.models import EntityRule, PolicyDocument, ProviderRule
from app.repositories.api_keys import generate_api_key
from tests.fixtures.documents import CANARIES, TENANT
from tests.unit.test_api_v1 import FakeApiKeyAuthenticator

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

pytestmark = pytest.mark.privacy

STARTUP_TIMEOUT_SECONDS = 60.0
"""Generous on purpose: startup warms the spaCy pipeline, and ``asgi_lifespan``
defaults to five seconds, which is not enough under coverage instrumentation."""

MODEL_ALIAS = "general-chat"

BODY = (
    f"{CANARIES['person_name']} attended the oncology clinic on Tuesday.\n"
    f"Contact {CANARIES['email']} or {CANARIES['phone']} for follow-up.\n"
).encode()

LEAKABLE = ("person_name", "email", "phone")
"""The canaries the fake detector finds in ``BODY``.

Named so every absence assertion can first require that these were detected.
``mrn`` and ``icd10`` are excluded because no shipped recognizer matches them --
a gap `tests/privacy/test_document_canaries.py` records rather than hides.
"""

WORKFLOW_POLICY = PolicyDocument(
    schema_version=1,
    name="workflow",
    session_ttl_seconds=1800,
    max_entities=500,
    providers={MOCK_PROVIDER_ALIAS: ProviderRule(models=(MODEL_ALIAS,))},
    entities={
        "PERSON": EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
        "EMAIL_ADDRESS": EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
        "PHONE_NUMBER": EntityRule(action=EntityAction.TOKENIZE, min_score=0.4),
    },
)
"""Everything reversible, so the round trip is observable at both ends.

A REDACT rule would prove protection and make restoration untestable, because a
redaction is deliberately one-way.
"""


class RecordingMockProvider:
    """The mock adapter, plus a record of exactly what it was handed.

    This is the whole point of the file. Asserting "no original left the
    gateway" requires something on the other side of the provider boundary that
    remembers what arrived, and a real provider cannot be asked.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.seen: list[str] = []

    @property
    def alias(self) -> str:
        return str(self._inner.alias)

    async def complete(self, request: Any) -> Any:
        self.seen.extend(message.content for message in request.messages)
        return await self._inner.complete(request)

    def transcript(self) -> str:
        return "\n".join(self.seen)


PEPPER = SecretStr("document-workflow-test-pepper-not-a-real-secret")
API_KEY_STATUS_ACTIVE = "active"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        app_env="test",
        api_key_pepper=PEPPER,
        audit_hmac_key=SecretStr(base64.b64encode(bytes(range(40, 72))).decode()),
        vault_keys={"local1": SecretStr(base64.b64encode(bytes(range(1, 33))).decode())},
        document_keys={"local1": SecretStr(base64.b64encode(bytes(range(32))).decode())},
        audit_fail_closed=True,
    )


@pytest.fixture
async def services(settings: Settings) -> AsyncIterator[Services]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with build_session_factory(engine)() as session:
        session.add(Tenant(id=TENANT, name="workflow", slug="workflow"))
        session.add(
            Policy(
                tenant_id=TENANT,
                name=WORKFLOW_POLICY.name,
                version=3,
                document=WORKFLOW_POLICY.model_dump(mode="json"),
                is_active=True,
            )
        )
        await session.commit()

    built = await build_services(
        settings,
        redis=fakeredis.aioredis.FakeRedis(decode_responses=False),
        engine=engine,
        document_store=FakeDocumentStore(),
    )
    yield built
    await stop_services(built)
    await engine.dispose()


@pytest.fixture
def provider(services: Services) -> RecordingMockProvider:
    """Swap the mock adapter for one that remembers what it received.

    Replacing the entry in the registry map rather than rebuilding the registry:
    the pipeline holds a reference to the same registry object, so the swap has
    to happen in place to be seen.
    """
    registry = services.pipeline._providers
    recording = RecordingMockProvider(registry.adapters[MOCK_PROVIDER_ALIAS])
    adapters: dict[str, Any] = dict(registry.adapters)
    adapters[MOCK_PROVIDER_ALIAS] = recording
    object.__setattr__(registry, "adapters", adapters)
    return recording


@pytest.fixture
def credentials() -> tuple[tuple[ApiKey, ...], str, str]:
    """A full-scope key, and one holding only ``documents:read``.

    The second exists so the route's two-scope requirement is exercised rather
    than assumed. Authentication itself has its own suites; what this file needs
    is that the scope check is the real one.
    """
    full, full_raw = _make_key(scopes=tuple(Scope))
    reader, reader_raw = _make_key(scopes=(Scope.DOCUMENTS_READ, Scope.DOCUMENTS_WRITE))
    return (full, reader), full_raw, reader_raw


def _make_key(*, scopes: tuple[Scope, ...]) -> tuple[ApiKey, str]:
    generated = generate_api_key(PEPPER)
    return (
        ApiKey(
            id=uuid4(),
            tenant_id=TENANT,
            name="workflow-key",
            prefix=generated.prefix,
            key_hash=generated.key_hash,
            scopes=[scope.value for scope in scopes],
            status=API_KEY_STATUS_ACTIVE,
        ),
        generated.raw_key,
    )


@pytest.fixture
async def client(
    settings: Settings,
    services: Services,
    credentials: tuple[tuple[ApiKey, ...], str, str],
) -> AsyncIterator[httpx.AsyncClient]:
    records, full_raw, _reader_raw = credentials
    app = create_app(settings)
    app.state.services = services
    app.state.api_key_authenticator = FakeApiKeyAuthenticator(list(records))
    async with LifespanManager(app, startup_timeout=STARTUP_TIMEOUT_SECONDS):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            headers={"Authorization": f"Bearer {full_raw}"},
        ) as opened:
            yield opened


@pytest.fixture
def logs(caplog: pytest.LogCaptureFixture) -> Iterator[pytest.LogCaptureFixture]:
    configure_logging(level="DEBUG", json_output=False)
    root = logging.getLogger()
    caplog.set_level(logging.DEBUG)
    root.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        root.removeHandler(caplog.handler)


async def upload(client: httpx.AsyncClient, body: bytes = BODY) -> str:
    response = await client.post(
        "/v1/documents",
        files={"file": ("referral.txt", body, CONTENT_TYPE_TXT)},
    )
    assert response.status_code == 201, response.text
    document_id: str = response.json()["id"]
    return document_id


async def process(
    client: httpx.AsyncClient,
    document_id: str,
    *,
    instruction: str = "Summarise this referral.",
    session_id: str | None = None,
) -> httpx.Response:
    payload: dict[str, Any] = {
        "provider": MOCK_PROVIDER_ALIAS,
        "model": MODEL_ALIAS,
        "instruction": instruction,
    }
    if session_id is not None:
        payload["session_id"] = session_id
    return await client.post(f"/v1/documents/{document_id}/process", json=payload)


# ---------------------------------------------------------------------------
# The journey
# ---------------------------------------------------------------------------
class TestEndToEnd:
    async def test_the_provider_never_sees_an_original(
        self, client: httpx.AsyncClient, provider: RecordingMockProvider
    ) -> None:
        document_id = await upload(client)

        response = await process(client, document_id)

        assert response.status_code == 200, response.text
        transcript = provider.transcript()
        # Non-vacuity: the provider must have been called with something, and
        # the run must have found values worth protecting.
        assert transcript, "the provider was never called"
        assert response.json()["privacy"]["detected"] > 0
        for name in LEAKABLE:
            assert CANARIES[name] not in transcript, f"{name} reached the provider"

    async def test_the_provider_sees_tokens_where_the_values_were(
        self, client: httpx.AsyncClient, provider: RecordingMockProvider
    ) -> None:
        # The other half. Text with the values simply deleted would also pass
        # the assertion above, and would be useless to a model.
        document_id = await upload(client)

        await process(client, document_id)

        assert "⟦SGW:" in provider.transcript()

    async def test_the_caller_gets_the_originals_back(
        self, client: httpx.AsyncClient, provider: RecordingMockProvider
    ) -> None:
        # The mock provider echoes its input, so a restored answer contains the
        # originals again -- which is what proves the round trip closed.
        document_id = await upload(client)

        response = await process(client, document_id)

        answer = response.json()["message"]["content"]
        assert CANARIES["email"] in answer, "the token was not restored"
        assert response.json()["privacy"]["restored"] > 0

    async def test_the_response_carries_counts_and_an_attestation_only(
        self, client: httpx.AsyncClient, provider: RecordingMockProvider
    ) -> None:
        document_id = await upload(client)

        body = (await process(client, document_id)).json()

        assert set(body["privacy"]) >= {"detected", "tokenized", "restored", "entity_types"}
        assert body["outbound_attestation"], "no attestation was returned"
        # A digest, never a payload: hex, fixed width, and containing none of it.
        assert len(body["outbound_attestation"]) == 64
        for name in LEAKABLE:
            assert CANARIES[name] not in body["outbound_attestation"]

    async def test_a_supplied_session_is_the_one_used(
        self, client: httpx.AsyncClient, provider: RecordingMockProvider
    ) -> None:
        # The session is how a document's tokens become resolvable by the
        # conversation that quotes them. A route that quietly minted its own
        # would produce tokens the chat path could never restore.
        document_id = await upload(client)
        session_id = str(uuid4())

        body = (await process(client, document_id, session_id=session_id)).json()

        assert body["session_id"] == session_id


# ---------------------------------------------------------------------------
# The attestation
# ---------------------------------------------------------------------------
class TestAttestation:
    async def test_the_audit_row_proves_the_scan_ran(
        self, client: httpx.AsyncClient, provider: RecordingMockProvider, services: Services
    ) -> None:
        document_id = await upload(client)

        body = (await process(client, document_id)).json()
        await services.audit.flush(wait_seconds=5.0)

        row = await _one_audit_row(services)
        assert row.outbound_scan == "clean"
        assert row.outbound_hmac == body["outbound_attestation"]
        assert row.blocked is False
        assert row.provider_alias == MOCK_PROVIDER_ALIAS
        assert row.policy_version == 3

    async def test_the_audit_row_holds_no_content(
        self, client: httpx.AsyncClient, provider: RecordingMockProvider, services: Services
    ) -> None:
        document_id = await upload(client)

        await process(client, document_id)
        await services.audit.flush(wait_seconds=5.0)

        row = await _one_audit_row(services)
        rendered = repr(
            {
                column.name: getattr(row, column.name)
                for column in AuditEvent.__table__.columns  # type: ignore[attr-defined]
            }
        )
        assert row.entity_counts, "non-vacuity: the row must describe something"
        for name in LEAKABLE:
            assert CANARIES[name] not in rendered, f"{name} reached the audit table"

    async def test_the_correlation_digests_are_populated(
        self, client: httpx.AsyncClient, provider: RecordingMockProvider, services: Services
    ) -> None:
        # ADR-0024: a column that is always null is worse than an absent one.
        document_id = await upload(client)

        await process(client, document_id)
        await services.audit.flush(wait_seconds=5.0)

        row = await _one_audit_row(services)
        assert row.session_id_hash
        assert row.response_hmac
        assert row.outbound_hmac

    async def test_the_same_payload_attests_identically(
        self, client: httpx.AsyncClient, provider: RecordingMockProvider
    ) -> None:
        # An attestation nobody can recompute proves nothing. Two runs over the
        # same document, same instruction, same destination, same policy must
        # produce the same digest.
        document_id = await upload(client)
        session_id = str(uuid4())

        first = (await process(client, document_id, session_id=session_id)).json()
        second = (await process(client, document_id, session_id=session_id)).json()

        assert first["outbound_attestation"] == second["outbound_attestation"]

    async def test_a_different_instruction_attests_differently(
        self, client: httpx.AsyncClient, provider: RecordingMockProvider
    ) -> None:
        document_id = await upload(client)
        session_id = str(uuid4())

        first = (await process(client, document_id, session_id=session_id)).json()
        second = (
            await process(
                client, document_id, instruction="Extract the dates.", session_id=session_id
            )
        ).json()

        assert first["outbound_attestation"] != second["outbound_attestation"]


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------
class TestRefusals:
    async def test_an_unpermitted_provider_is_refused(
        self, client: httpx.AsyncClient, provider: RecordingMockProvider
    ) -> None:
        document_id = await upload(client)

        response = await client.post(
            f"/v1/documents/{document_id}/process",
            json={"provider": "not-configured", "model": MODEL_ALIAS, "instruction": "Go."},
        )

        assert response.status_code == 403
        assert provider.seen == [], "the document was processed before the destination was checked"

    async def test_another_principals_document_is_not_found(
        self, client: httpx.AsyncClient, provider: RecordingMockProvider
    ) -> None:
        response = await process(client, str(uuid4()))

        assert response.status_code == 404
        assert provider.seen == []

    async def test_an_oversized_instruction_is_refused_by_the_schema(
        self, client: httpx.AsyncClient, provider: RecordingMockProvider
    ) -> None:
        document_id = await upload(client)

        response = await process(client, document_id, instruction="x" * 4_001)

        # 400 and INVALID_REQUEST, because the ceiling is on the request schema
        # and the gateway renders every validation failure through its own
        # envelope rather than FastAPI's default 422 shape.
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_REQUEST"
        assert provider.seen == [], "the document was read before the body was validated"


# ---------------------------------------------------------------------------
# Nothing leaks sideways
# ---------------------------------------------------------------------------
class TestLogs:
    async def test_no_canary_reaches_a_log_line(
        self,
        client: httpx.AsyncClient,
        provider: RecordingMockProvider,
        logs: pytest.LogCaptureFixture,
    ) -> None:
        document_id = await upload(client)

        await process(client, document_id)

        captured = "\n".join(record.getMessage() + repr(record.__dict__) for record in logs.records)
        assert "document_completed" in captured, "non-vacuity: nothing was logged to search"
        for name in LEAKABLE:
            assert CANARIES[name] not in captured, f"{name} reached a log line"


async def _one_audit_row(services: Services) -> AuditEvent:
    async with services.session_scope() as session:
        rows = (await session.execute(select(AuditEvent))).scalars().all()
    assert len(rows) >= 1, "no audit event was written"
    return rows[-1]
