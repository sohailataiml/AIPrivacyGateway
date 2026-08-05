"""Canary sweep: nothing about a document escapes except to its owner.

Every value in ``tests.fixtures.documents.CANARIES`` is a distinctive string --
a person's name, an email, an SSN, a medical record number, an ICD-10 code, a
phone number, and a filename that names a patient and a specialty. They appear
nowhere else in the repository, so a single search over everything the gateway
emitted during a real request answers the question directly.

The sweep covers every channel a document's contents could plausibly reach:

* **application logs**, including every structlog key-value pair rather than
  just the rendered message -- a leak usually arrives as an extra field, not as
  formatted text;
* **SQL statements**, captured with engine echo on, because a bound parameter
  in a query log is a leak that no amount of care in the application layer
  prevents;
* **Prometheus metrics**, where the danger is a label value rather than a
  sample;
* **HTTP responses**, including the ones that failed;
* **the object store**: keys, stored bytes, and the content type the bucket is
  told;
* **exception text**, which is the channel most often forgotten, because an
  error is written once and read only when something has already gone wrong.

A test that only checked the log message would pass against an implementation
that leaked through any of the other six.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import fakeredis.aioredis
import httpx
import pytest
from asgi_lifespan import LifespanManager
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import create_async_engine

from app.api.composition import Services, build_services, stop_services
from app.config.settings import Settings
from app.db.base import Base
from app.db.models import Tenant
from app.db.session import build_session_factory
from app.documents.models import CONTENT_TYPE_PDF
from app.documents.storage.fakes import FakeDocumentStore
from app.domain.models import Scope
from app.main import create_app
from app.observability import metrics as http_metrics
from tests.fixtures.documents import CANARIES, CANARY_PDF
from tests.unit.test_api_documents import DOCUMENT_KEY, TENANT_A, TENANT_B, _auth, make_key
from tests.unit.test_api_v1 import PEPPER, VAULT_KEY, FakeApiKeyAuthenticator

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

    from sqlalchemy.ext.asyncio import AsyncEngine

    from app.db.models import ApiKey

pytestmark = pytest.mark.privacy

FILENAME = CANARIES["filename"]

STARTUP_TIMEOUT_SECONDS = 60.0
"""Generous on purpose.

``asgi_lifespan`` defaults to five seconds, and startup warms the spaCy
pipeline. Under ``pytest --cov`` that instrumented load overruns the default
and every test in the file errors at setup -- a red suite that says nothing
about the code. Still bounded, so a genuinely hung startup fails rather than
blocking the run forever.
"""


@pytest.fixture
def settings() -> Settings:
    return Settings(
        app_env="test",
        api_key_pepper=PEPPER,
        vault_active_key_id="local1",
        vault_keys={"local1": SecretStr(VAULT_KEY)},
        document_active_key_id="local1",
        document_keys={"local1": SecretStr(DOCUMENT_KEY)},
        max_document_bytes=200_000,
        max_request_bytes=8_192,
    )


@pytest.fixture
def store() -> FakeDocumentStore:
    return FakeDocumentStore()


@pytest.fixture
def credentials() -> tuple[list[ApiKey], str, str]:
    owner_record, owner = make_key(tenant_id=TENANT_A, scopes=tuple(Scope))
    other_record, other = make_key(tenant_id=TENANT_B, scopes=tuple(Scope))
    return [owner_record, other_record], owner, other


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    # echo=True so every statement and its bound parameters reach the logging
    # system, where caplog can see them. This is the channel an application
    # cannot protect by being careful.
    built = create_async_engine("sqlite+aiosqlite:///:memory:", echo=True)
    async with built.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with build_session_factory(built)() as session:
        session.add(Tenant(id=TENANT_A, name="Tenant A", slug="tenant-a"))
        session.add(Tenant(id=TENANT_B, name="Tenant B", slug="tenant-b"))
        await session.commit()
    yield built
    await built.dispose()


@pytest.fixture
async def services(
    settings: Settings, engine: AsyncEngine, store: FakeDocumentStore
) -> AsyncIterator[Services]:
    built = await build_services(
        settings,
        redis=fakeredis.aioredis.FakeRedis(decode_responses=False),
        engine=engine,
        document_store=store,
    )
    yield built
    await stop_services(built)


@pytest.fixture
async def client(
    settings: Settings,
    services: Services,
    credentials: tuple[list[ApiKey], str, str],
) -> AsyncIterator[httpx.AsyncClient]:
    records, _owner, _other = credentials
    app = create_app(settings)
    app.state.services = services
    app.state.api_key_authenticator = FakeApiKeyAuthenticator(records)
    async with LifespanManager(app, startup_timeout=STARTUP_TIMEOUT_SECONDS):
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as http:
            yield http


@pytest.fixture
def capture_logs(
    client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> Iterator[pytest.LogCaptureFixture]:
    """Capture logs from a *started* application.

    ``configure_logging`` runs during lifespan startup and calls
    ``logging.basicConfig(..., force=True)``, which removes every existing root
    handler -- pytest's included. So a fixture that merely calls
    ``caplog.set_level`` before the app starts captures the test harness and
    none of the request path, and every assertion over it passes against an
    empty string. Re-attaching the handler after startup is what makes this
    sweep mean anything.
    """
    root = logging.getLogger()
    caplog.set_level(logging.DEBUG)
    root.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        root.removeHandler(caplog.handler)


def captured(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """Every record from setup and call, not just call.

    The work these tests sweep over happens in a fixture, so it is recorded in
    the *setup* phase. ``caplog.records`` holds only the call phase, and reading
    it alone made every assertion in this file pass against an empty string --
    which is why each test below also asserts that it found something to search.
    """
    return [*caplog.get_records("setup"), *caplog.records]


def rendered(caplog: pytest.LogCaptureFixture) -> str:
    """Everything logged, message and structured fields alike."""
    return "\n".join(record.getMessage() + repr(record.__dict__) for record in captured(caplog))


def assert_clean(haystack: str | bytes, channel: str) -> None:
    text = haystack.decode("utf-8", "replace") if isinstance(haystack, bytes) else haystack
    for name, canary in CANARIES.items():
        assert canary not in text, f"{channel} disclosed the {name} canary"


class TestTheFullRequestPath:
    @pytest.fixture
    async def exercised(
        self,
        client: httpx.AsyncClient,
        credentials: tuple[list[ApiKey], str, str],
        capture_logs: pytest.LogCaptureFixture,
    ) -> tuple[UUID, list[httpx.Response]]:
        """Upload, download, poll, refuse, and delete -- with logs captured."""
        _records, owner, other = credentials

        created = await client.post(
            "/v1/documents",
            headers=_auth(owner),
            files={"file": (FILENAME, CANARY_PDF, CONTENT_TYPE_PDF)},
        )
        assert created.status_code == 201, created.text
        document_id = UUID(created.json()["id"])

        responses = [
            created,
            await client.get(f"/v1/documents/{document_id}", headers=_auth(owner)),
            await client.get(f"/v1/documents/{document_id}/status", headers=_auth(owner)),
            # Refusals, which is where an error message would carry the name.
            await client.get(f"/v1/documents/{document_id}", headers=_auth(other)),
            await client.get(f"/v1/documents/{uuid4()}", headers=_auth(owner)),
            await client.post(
                "/v1/documents",
                headers=_auth(owner),
                files={"file": (f"../../{FILENAME}", CANARY_PDF, CONTENT_TYPE_PDF)},
            ),
            await client.post(
                "/v1/documents",
                headers=_auth(owner),
                files={"file": (FILENAME + ".exe", CANARY_PDF, "application/pdf")},
            ),
            await client.delete(f"/v1/documents/{document_id}", headers=_auth(owner)),
        ]
        return document_id, responses

    async def test_the_owner_gets_their_document_back_intact(
        self, exercised: tuple[UUID, list[httpx.Response]]
    ) -> None:
        # The sweep is only meaningful if the request actually worked.
        _document_id, responses = exercised
        download = responses[1]

        assert download.status_code == 200
        assert download.content == CANARY_PDF
        assert responses[0].json()["filename"] == FILENAME

    async def test_no_canary_reaches_the_application_logs(
        self, exercised: tuple[UUID, list[httpx.Response]], caplog: pytest.LogCaptureFixture
    ) -> None:
        emitted = rendered(caplog)

        # A sweep over nothing is not a passing sweep.
        assert "document_stored" in emitted, "the upload logged nothing to search"
        assert_clean(emitted, "the application log")

    async def test_no_canary_reaches_a_sql_statement(
        self, exercised: tuple[UUID, list[httpx.Response]], caplog: pytest.LogCaptureFixture
    ) -> None:
        # Engine echo is on, so this covers statements and bound parameters.
        sql = "\n".join(
            record.getMessage() + repr(record.__dict__)
            for record in captured(caplog)
            if record.name.startswith("sqlalchemy")
        )
        assert "INSERT INTO documents" in sql, "engine echo captured no document writes"
        assert_clean(sql, "a SQL statement")

    async def test_no_canary_reaches_the_metrics(
        self, exercised: tuple[UUID, list[httpx.Response]]
    ) -> None:
        # A filename used as a label value would be unbounded cardinality as
        # well as a disclosure.
        payload, _content_type = http_metrics.render()

        assert_clean(payload, "a metric")

    async def test_no_refusal_names_the_document(
        self, exercised: tuple[UUID, list[httpx.Response]]
    ) -> None:
        _document_id, responses = exercised
        refusals = [response for response in responses if response.status_code >= 400]

        assert len(refusals) >= 3
        for response in refusals:
            assert_clean(response.text, f"a {response.status_code} response")

    async def test_only_the_owner_routes_return_the_filename(
        self, exercised: tuple[UUID, list[httpx.Response]]
    ) -> None:
        # The filename is Restricted, but it belongs to the caller who uploaded
        # it. Withholding it from them would be theatre; the requirement is
        # that nobody else sees it.
        _document_id, responses = exercised
        created, download, status_response, other_tenant = responses[:4]

        assert FILENAME in created.text
        assert FILENAME in urllib_unquote(download.headers["content-disposition"])
        assert FILENAME not in status_response.text
        assert FILENAME not in other_tenant.text

    async def test_the_status_route_leaks_nothing_at_all(
        self, exercised: tuple[UUID, list[httpx.Response]]
    ) -> None:
        _document_id, responses = exercised

        assert_clean(responses[2].text, "the status response")


class TestTheObjectStore:
    async def test_no_canary_reaches_the_stored_bytes(
        self,
        client: httpx.AsyncClient,
        credentials: tuple[list[ApiKey], str, str],
        store: FakeDocumentStore,
    ) -> None:
        _records, owner, _other = credentials

        await client.post(
            "/v1/documents",
            headers=_auth(owner),
            files={"file": (FILENAME, CANARY_PDF, CONTENT_TYPE_PDF)},
        )

        for name, canary in CANARIES.items():
            assert not store.contains_plaintext(canary.encode("utf-8")), name

    async def test_no_canary_reaches_an_object_key(
        self,
        client: httpx.AsyncClient,
        credentials: tuple[list[ApiKey], str, str],
        store: FakeDocumentStore,
    ) -> None:
        # An operator listing the bucket sees keys and nothing else. They must
        # therefore say nothing -- not the filename, not the tenant, not the
        # extension.
        _records, owner, _other = credentials

        await client.post(
            "/v1/documents",
            headers=_auth(owner),
            files={"file": (FILENAME, CANARY_PDF, CONTENT_TYPE_PDF)},
        )

        keys = store.stored_keys()
        assert len(keys) == 1
        assert_clean(keys[0], "an object key")
        assert str(TENANT_A) not in keys[0]
        assert not keys[0].endswith(".pdf")

    async def test_the_bucket_is_never_told_the_real_content_type(
        self,
        client: httpx.AsyncClient,
        credentials: tuple[list[ApiKey], str, str],
        store: FakeDocumentStore,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # ADR-0020 keeps content knowledge out of the store. "This is a PDF" is
        # metadata about the content, and the store holds ciphertext.
        _records, owner, _other = credentials
        seen: list[str | None] = []
        original = FakeDocumentStore.put

        async def recording(
            self: FakeDocumentStore, *, key: str, chunks: object, content_type: str | None = None
        ) -> int:
            seen.append(content_type)
            return await original(self, key=key, chunks=chunks, content_type=content_type)  # type: ignore[arg-type]

        monkeypatch.setattr(FakeDocumentStore, "put", recording)

        await client.post(
            "/v1/documents",
            headers=_auth(owner),
            files={"file": (FILENAME, CANARY_PDF, CONTENT_TYPE_PDF)},
        )

        assert seen == ["application/octet-stream"]


class TestExceptionText:
    @pytest.mark.parametrize(
        "filename",
        [
            f"../../{FILENAME}",
            FILENAME + ".exe",
            "‮" + FILENAME,
        ],
        ids=["traversal", "unsupported-type", "bidi-override"],
    )
    async def test_a_rejected_upload_names_nothing_in_its_error(
        self,
        client: httpx.AsyncClient,
        credentials: tuple[list[ApiKey], str, str],
        capture_logs: pytest.LogCaptureFixture,
        filename: str,
    ) -> None:
        # The refusal is the moment the gateway is holding the hostile value and
        # is most tempted to quote it back.
        _records, owner, _other = credentials
        caplog = capture_logs

        response = await client.post(
            "/v1/documents",
            headers=_auth(owner),
            files={"file": (filename, CANARY_PDF, CONTENT_TYPE_PDF)},
        )

        assert response.status_code in {400, 415}
        assert_clean(response.text, "the refusal body")
        assert_clean(rendered(caplog), "the refusal log")


def urllib_unquote(value: str) -> str:
    import urllib.parse

    return urllib.parse.unquote(value)
