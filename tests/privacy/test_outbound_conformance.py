"""ADR-0024 for both routes, and the instruction that used to travel in clear.

Two things were true after Phase 5 and are not true now, and this file is where
either would come back.

**The chat path had no outbound controls.** It protected, transmitted, and
audited without ever scanning the payload it sent or attesting what it sent. The
document path did all three. A control that exists on one route and not the
other is the shape of problem ADR-0024 was written about, so the first half of
this file asserts the two routes behave identically at the boundary — including
that they reach a provider through the *same object*.

**A document instruction was sent as written.** A caller who typed "summarise
Marguerite Okonkwo-Vasquez's referral" put an original into the payload, and the
gateway protected the document around it. The second half asserts the
instruction is detected, protected, and — when it names a value the document
also names — collapsed onto the *same session token*, so the model sees one
identifier for one person.

Canaries throughout, and every absence assertion first requires that something
was found. An empty transcript would satisfy "no original reached the provider"
while proving nothing.
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
from app.tokenization.grammar import find_tokens
from tests.fixtures.documents import CANARIES, TENANT
from tests.unit.test_api_v1 import FakeApiKeyAuthenticator

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

pytestmark = pytest.mark.privacy

STARTUP_TIMEOUT_SECONDS = 60.0
MODEL_ALIAS = "general-chat"
API_KEY_STATUS_ACTIVE = "active"
PEPPER = SecretStr("outbound-conformance-test-pepper-not-a-real-secret")

DOCUMENT_BODY = (
    f"{CANARIES['person_name']} attended the oncology clinic on Tuesday.\n"
    f"Contact {CANARIES['email']} for follow-up.\n"
).encode()

SHARED_POLICY = PolicyDocument(
    schema_version=1,
    name="conformance",
    session_ttl_seconds=1800,
    max_entities=500,
    providers={MOCK_PROVIDER_ALIAS: ProviderRule(models=(MODEL_ALIAS,))},
    entities={
        "PERSON": EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
        "EMAIL_ADDRESS": EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
        "PHONE_NUMBER": EntityRule(action=EntityAction.TOKENIZE, min_score=0.4),
        "US_SSN": EntityRule(action=EntityAction.BLOCK, min_score=0.5),
    },
)
"""One policy for both routes, so a difference in behaviour is a difference in
the code rather than in the configuration each path happened to get."""


class RecordingProvider:
    """The mock adapter, remembering exactly what crossed the boundary."""

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


@pytest.fixture
def settings() -> Settings:
    return Settings(
        app_env="test",
        api_key_pepper=PEPPER,
        audit_hmac_key=SecretStr(base64.b64encode(bytes(range(40, 72))).decode()),
        vault_keys={"local1": SecretStr(base64.b64encode(bytes(range(1, 33))).decode())},
        document_keys={"local1": SecretStr(base64.b64encode(bytes(range(32))).decode())},
    )


@pytest.fixture
async def services(settings: Settings) -> AsyncIterator[Services]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with build_session_factory(engine)() as session:
        session.add(Tenant(id=TENANT, name="conformance", slug="conformance"))
        session.add(
            Policy(
                tenant_id=TENANT,
                name=SHARED_POLICY.name,
                version=5,
                document=SHARED_POLICY.model_dump(mode="json"),
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
def provider(services: Services) -> RecordingProvider:
    registry = services.pipeline._providers
    recording = RecordingProvider(registry.adapters[MOCK_PROVIDER_ALIAS])
    adapters: dict[str, Any] = dict(registry.adapters)
    adapters[MOCK_PROVIDER_ALIAS] = recording
    object.__setattr__(registry, "adapters", adapters)
    return recording


@pytest.fixture
async def client(settings: Settings, services: Services) -> AsyncIterator[httpx.AsyncClient]:
    generated = generate_api_key(PEPPER)
    record = ApiKey(
        id=uuid4(),
        tenant_id=TENANT,
        name="conformance-key",
        prefix=generated.prefix,
        key_hash=generated.key_hash,
        scopes=[scope.value for scope in Scope],
        status=API_KEY_STATUS_ACTIVE,
    )
    app = create_app(settings)
    app.state.services = services
    app.state.api_key_authenticator = FakeApiKeyAuthenticator([record])
    async with LifespanManager(app, startup_timeout=STARTUP_TIMEOUT_SECONDS):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            headers={"Authorization": f"Bearer {generated.raw_key}"},
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


async def upload(client: httpx.AsyncClient, body: bytes = DOCUMENT_BODY) -> str:
    response = await client.post(
        "/v1/documents", files={"file": ("referral.txt", body, CONTENT_TYPE_TXT)}
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


async def chat(client: httpx.AsyncClient, content: str, *, session_id: str | None = None):
    payload: dict[str, Any] = {
        "provider": MOCK_PROVIDER_ALIAS,
        "model": MODEL_ALIAS,
        "messages": [{"role": "user", "content": content}],
    }
    if session_id is not None:
        payload["session_id"] = session_id
    return await client.post("/v1/chat", json=payload)


async def process(
    client: httpx.AsyncClient,
    document_id: str,
    *,
    instruction: str = "Summarise this referral.",
    session_id: str | None = None,
):
    payload: dict[str, Any] = {
        "provider": MOCK_PROVIDER_ALIAS,
        "model": MODEL_ALIAS,
        "instruction": instruction,
    }
    if session_id is not None:
        payload["session_id"] = session_id
    return await client.post(f"/v1/documents/{document_id}/process", json=payload)


async def audit_rows(services: Services) -> list[AuditEvent]:
    await services.audit.flush(wait_seconds=5.0)
    async with services.session_scope() as session:
        return list((await session.execute(select(AuditEvent))).scalars().all())


# ---------------------------------------------------------------------------
# One boundary, two routes
# ---------------------------------------------------------------------------
class TestSharedOutbound:
    def test_both_routes_transmit_through_the_same_component(self, services: Services) -> None:
        # Identity, because "both call something that scans" is satisfiable by
        # two objects that could be configured differently. One object cannot.
        assert services.document_pipeline is not None
        assert services.document_pipeline._outbound is services.pipeline._outbound

    async def test_chat_originals_never_reach_the_provider(
        self, client: httpx.AsyncClient, provider: RecordingProvider
    ) -> None:
        response = await chat(client, f"Email {CANARIES['email']} about the referral.")

        assert response.status_code == 200, response.text
        assert provider.transcript(), "the provider was never called"
        assert response.json()["privacy"]["detected"] > 0
        assert CANARIES["email"] not in provider.transcript()

    async def test_chat_answers_restore_the_originals(
        self, client: httpx.AsyncClient, provider: RecordingProvider
    ) -> None:
        # The mock echoes its input, so a restored answer holds the original
        # again -- which is what proves the round trip closed rather than the
        # value simply having been deleted.
        response = await chat(client, f"Email {CANARIES['email']} please.")

        assert CANARIES["email"] in response.json()["message"]["content"]

    async def test_chat_populates_every_attestation_field(
        self, client: httpx.AsyncClient, provider: RecordingProvider, services: Services
    ) -> None:
        # The gap this phase closed. Before it, a chat row had four null
        # digest columns and no verdict.
        await chat(client, f"Email {CANARIES['email']} please.")

        row = (await audit_rows(services))[-1]
        assert row.outbound_scan == "clean"
        assert row.outbound_hmac
        assert row.prompt_hmac
        assert row.response_hmac
        assert row.session_id_hash

    async def test_documents_populate_every_attestation_field(
        self, client: httpx.AsyncClient, provider: RecordingProvider, services: Services
    ) -> None:
        document_id = await upload(client)

        await process(client, document_id)

        row = (await audit_rows(services))[-1]
        assert row.outbound_scan == "clean"
        assert row.outbound_hmac
        assert row.prompt_hmac
        assert row.response_hmac

    async def test_a_refusal_before_serialization_leaves_the_digests_null(
        self, client: httpx.AsyncClient, provider: RecordingProvider, services: Services
    ) -> None:
        # Legacy nullable semantics, preserved deliberately. A request refused
        # before a payload existed has nothing to attest, and a null column
        # saying so is more honest than a digest of something never assembled.
        response = await chat(client, f"My SSN is {CANARIES['ssn']}.")

        assert response.status_code == 422
        row = (await audit_rows(services))[-1]
        assert row.blocked is True
        assert row.outbound_hmac is None
        assert row.outbound_scan is None
        assert provider.seen == []


# ---------------------------------------------------------------------------
# The instruction
# ---------------------------------------------------------------------------
class TestInstructionProtection:
    async def test_instruction_originals_never_reach_the_provider(
        self, client: httpx.AsyncClient, provider: RecordingProvider
    ) -> None:
        # The hole this phase closed: the document was protected and the
        # caller's own sentence about it was sent verbatim.
        document_id = await upload(client)

        response = await process(
            client,
            document_id,
            instruction=f"Summarise the referral for {CANARIES['person_name']}.",
        )

        assert response.status_code == 200, response.text
        assert provider.transcript(), "the provider was never called"
        assert CANARIES["person_name"] not in provider.transcript()

    async def test_instruction_only_pii_is_protected(
        self, client: httpx.AsyncClient, provider: RecordingProvider
    ) -> None:
        # A value the *document* never contains. Nothing upstream would have
        # tokenized it, so this fails unless the instruction is detected over
        # in its own right.
        document_id = await upload(client, body=b"An unremarkable week, clinically.\n")

        response = await process(
            client, document_id, instruction=f"Send the summary to {CANARIES['email']}."
        )

        assert response.status_code == 200, response.text
        assert CANARIES["email"] not in provider.transcript()
        assert "⟦SGW:" in provider.transcript(), "the value was dropped rather than tokenized"

    async def test_a_value_in_both_gets_one_token(
        self, client: httpx.AsyncClient, provider: RecordingProvider
    ) -> None:
        # Same tenant, same session, same policy, same tokenizer, same vault --
        # so the fingerprint matches and the vault returns the token the
        # document already minted. The model should see one identifier for one
        # person, not two.
        document_id = await upload(client)

        await process(
            client,
            document_id,
            instruction=f"What does the note say about {CANARIES['person_name']}?",
        )

        transcript = provider.transcript()
        person_tokens = {
            match.text for match in find_tokens(transcript) if match.token.entity_type == "PERSON"
        }
        assert len(person_tokens) == 1, f"one person, {len(person_tokens)} tokens"
        # Non-vacuity: the name must actually appear in both halves.
        assert transcript.count(next(iter(person_tokens))) >= 2

    async def test_the_answer_restores_instruction_values_too(
        self, client: httpx.AsyncClient, provider: RecordingProvider
    ) -> None:
        document_id = await upload(client, body=b"An unremarkable week, clinically.\n")

        response = await process(
            client, document_id, instruction=f"Send the summary to {CANARIES['email']}."
        )

        assert CANARIES["email"] in response.json()["message"]["content"]

    async def test_a_blocked_instruction_reaches_no_provider(
        self, client: httpx.AsyncClient, provider: RecordingProvider
    ) -> None:
        # US_SSN is BLOCK in the shared policy. The refusal has to come before
        # transmission, and before the document's vault write.
        document_id = await upload(client)

        response = await process(
            client, document_id, instruction=f"Cross-check SSN {CANARIES['ssn']}."
        )

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "POLICY_VIOLATION"
        assert provider.seen == []

    async def test_an_empty_instruction_is_refused_by_the_schema(
        self, client: httpx.AsyncClient, provider: RecordingProvider
    ) -> None:
        document_id = await upload(client)

        response = await process(client, document_id, instruction="")

        assert response.status_code == 400
        assert provider.seen == []


# ---------------------------------------------------------------------------
# Nothing leaks
# ---------------------------------------------------------------------------
class TestNoLeaks:
    async def test_no_canary_reaches_a_log_line_on_either_route(
        self,
        client: httpx.AsyncClient,
        provider: RecordingProvider,
        logs: pytest.LogCaptureFixture,
    ) -> None:
        document_id = await upload(client)
        await chat(client, f"Email {CANARIES['email']}.")
        await process(client, document_id, instruction=f"Summarise for {CANARIES['person_name']}.")

        captured = "\n".join(record.getMessage() + repr(record.__dict__) for record in logs.records)
        assert "pipeline.completed" in captured, "non-vacuity: chat logged nothing"
        assert "document_completed" in captured, "non-vacuity: the document logged nothing"
        for name in ("person_name", "email", "phone"):
            assert CANARIES[name] not in captured, f"{name} reached a log line"

    async def test_no_canary_reaches_an_audit_row_on_either_route(
        self, client: httpx.AsyncClient, provider: RecordingProvider, services: Services
    ) -> None:
        document_id = await upload(client)
        await chat(client, f"Email {CANARIES['email']}.")
        await process(client, document_id, instruction=f"Summarise for {CANARIES['person_name']}.")

        rows = await audit_rows(services)
        assert len(rows) >= 2, "non-vacuity: both routes must have written a row"
        rendered = repr(
            [
                {
                    column.name: getattr(row, column.name)
                    for column in AuditEvent.__table__.columns  # type: ignore[attr-defined]
                }
                for row in rows
            ]
        )
        for name in ("person_name", "email", "phone"):
            assert CANARIES[name] not in rendered
        # Nor a full token, nor the payload it was computed over.
        assert "⟦SGW:" not in rendered
