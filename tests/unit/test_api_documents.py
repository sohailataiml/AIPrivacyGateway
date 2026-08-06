"""Router tests for the document endpoints.

Drives the real application through ASGI: real middleware, real auth
dependencies, real service, real crypto. Only the object store, Redis, the
database, and the API-key lookup are fakes, because those are the pieces that
would otherwise need a network.

The assertions worth reading are the ones about what does *not* happen: an
upload larger than the JSON body limit is still accepted, a key from another
tenant sees nothing, and no filename or document content appears in a response
that was not asked for it.
"""

from __future__ import annotations

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
from app.db.models import ApiKey, Tenant
from app.db.session import build_session_factory
from app.documents.models import CONTENT_TYPE_PDF
from app.documents.storage.fakes import FakeDocumentStore
from app.domain.models import Scope
from app.main import create_app
from app.repositories.api_keys import generate_api_key
from tests.unit.test_api_v1 import PEPPER, VAULT_KEY, FakeApiKeyAuthenticator

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from sqlalchemy.ext.asyncio import AsyncEngine

TENANT_A = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
TENANT_B = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

DOCUMENT_KEY = "ZG9jdW1lbnQta2V5LWZvci11bml0LXRlc3RzLTMyYnk="

PDF_BODY = b"%PDF-1.7\nJane Doe, MRN-40217788\n%%EOF\n"
TXT_BODY = b"Avery Example, avery@example.test\n"

API_KEY_STATUS_ACTIVE = "active"

STARTUP_TIMEOUT_SECONDS = 60.0
"""Generous on purpose.

``asgi_lifespan`` defaults to five seconds, and startup warms the spaCy
pipeline. Under ``pytest --cov`` that instrumented load overruns the default
and every test in the file errors at setup -- a red suite that says nothing
about the code. Still bounded, so a genuinely hung startup fails rather than
blocking the run forever.
"""


def _auth(raw_key: str | None) -> dict[str, str]:
    return {} if raw_key is None else {"Authorization": f"Bearer {raw_key}"}


def make_key(*, tenant_id: UUID, scopes: Sequence[Scope]) -> tuple[ApiKey, str]:
    generated = generate_api_key(PEPPER)
    record = ApiKey(
        id=uuid4(),
        tenant_id=tenant_id,
        name="document-test-key",
        prefix=generated.prefix,
        key_hash=generated.key_hash,
        scopes=[scope.value for scope in scopes],
        status=API_KEY_STATUS_ACTIVE,
    )
    return record, generated.raw_key


class Keys:
    """Every credential these tests need, and the records behind them."""

    def __init__(self) -> None:
        self.full_a_record, self.full_a = make_key(tenant_id=TENANT_A, scopes=tuple(Scope))
        self.second_a_record, self.second_a = make_key(tenant_id=TENANT_A, scopes=tuple(Scope))
        self.reader_a_record, self.reader_a = make_key(
            tenant_id=TENANT_A, scopes=(Scope.DOCUMENTS_READ,)
        )
        self.chat_only_record, self.chat_only = make_key(
            tenant_id=TENANT_A, scopes=(Scope.CHAT_INVOKE,)
        )
        self.full_b_record, self.full_b = make_key(tenant_id=TENANT_B, scopes=tuple(Scope))

    @property
    def records(self) -> tuple[ApiKey, ...]:
        return (
            self.full_a_record,
            self.second_a_record,
            self.reader_a_record,
            self.chat_only_record,
            self.full_b_record,
        )


@pytest.fixture
def settings() -> Settings:
    return Settings(
        app_env="test",
        api_key_pepper=PEPPER,
        vault_active_key_id="local1",
        vault_keys={"local1": SecretStr(VAULT_KEY)},
        document_active_key_id="local1",
        document_keys={"local1": SecretStr(DOCUMENT_KEY)},
        # Small enough that a test can exceed it without shipping megabytes,
        # and deliberately far above max_request_bytes so the upload path's
        # exemption from the JSON body limit is observable.
        max_document_bytes=200_000,
        max_request_bytes=8_192,
    )


@pytest.fixture
def keys() -> Keys:
    return Keys()


@pytest.fixture
def store() -> FakeDocumentStore:
    return FakeDocumentStore()


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    built = create_async_engine("sqlite+aiosqlite:///:memory:")
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
    settings: Settings, services: Services, keys: Keys
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings)
    app.state.services = services
    app.state.api_key_authenticator = FakeApiKeyAuthenticator(keys.records)
    async with LifespanManager(app, startup_timeout=STARTUP_TIMEOUT_SECONDS):
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as http:
            yield http


async def upload(
    client: httpx.AsyncClient,
    key: str | None,
    *,
    filename: str = "report.pdf",
    body: bytes = PDF_BODY,
    content_type: str = CONTENT_TYPE_PDF,
) -> httpx.Response:
    return await client.post(
        "/v1/documents",
        headers=_auth(key),
        files={"file": (filename, body, content_type)},
    )


# ---------------------------------------------------------------------------
# POST /v1/documents
# ---------------------------------------------------------------------------
class TestUpload:
    async def test_rejects_a_request_with_no_credential(self, client: httpx.AsyncClient) -> None:
        response = await upload(client, None)

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"

    async def test_rejects_a_key_without_the_write_scope(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        response = await upload(client, keys.chat_only)

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "AUTHORIZATION_FAILED"

    async def test_stores_a_document_and_returns_its_metadata(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        response = await upload(client, keys.full_a)

        assert response.status_code == 201
        body = response.json()
        assert body["filename"] == "report.pdf"
        assert body["content_type"] == CONTENT_TYPE_PDF
        assert body["byte_size"] == len(PDF_BODY)
        assert body["status"] == "stored"
        # Internal detail that buys a caller nothing.
        assert "storage_key" not in body

    async def test_the_stored_object_holds_no_plaintext(
        self, client: httpx.AsyncClient, keys: Keys, store: FakeDocumentStore
    ) -> None:
        await upload(client, keys.full_a, filename="Jane Doe MRI.pdf")

        assert not store.contains_plaintext(b"Jane Doe")
        assert not store.contains_plaintext(b"MRN-40217788")

    @pytest.mark.parametrize(
        ("filename", "body", "content_type"),
        [
            ("notes.txt", TXT_BODY, "text/plain"),
            ("report.pdf", PDF_BODY, CONTENT_TYPE_PDF),
            (
                "contract.docx",
                b"PK\x03\x04" + b"\x00" * 32,
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
        ],
    )
    async def test_accepts_txt_pdf_and_docx(
        self,
        client: httpx.AsyncClient,
        keys: Keys,
        filename: str,
        body: bytes,
        content_type: str,
    ) -> None:
        response = await upload(
            client, keys.full_a, filename=filename, body=body, content_type=content_type
        )

        assert response.status_code == 201

    async def test_rejects_an_unsupported_type(self, client: httpx.AsyncClient, keys: Keys) -> None:
        response = await upload(
            client,
            keys.full_a,
            filename="payload.exe",
            body=b"MZ\x90\x00",
            content_type="application/octet-stream",
        )

        assert response.status_code == 415
        assert response.json()["error"]["code"] == "DOCUMENT_TYPE_UNSUPPORTED"

    async def test_rejects_a_traversing_filename(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        response = await upload(client, keys.full_a, filename="../../etc/passwd.txt")

        assert response.status_code == 400
        assert response.json()["error"]["code"] == "DOCUMENT_INVALID"

    async def test_rejects_a_body_over_the_document_limit(
        self, client: httpx.AsyncClient, keys: Keys, store: FakeDocumentStore
    ) -> None:
        # 200_000 is the configured ceiling for these tests.
        response = await upload(client, keys.full_a, body=b"%PDF-" + b"A" * 250_000)

        assert response.status_code == 413
        assert store.stored_keys() == []

    async def test_an_upload_larger_than_the_json_body_limit_is_still_accepted(
        self, client: httpx.AsyncClient, keys: Keys, settings: Settings
    ) -> None:
        # Uploads legitimately exceed the JSON body limit. Without the
        # per-path exemption this is a REQUEST_TOO_LARGE from the transport
        # layer before the route is ever reached.
        body = b"%PDF-" + b"B" * 150_000
        assert len(body) > settings.max_request_bytes

        response = await upload(client, keys.full_a, body=body)

        assert response.status_code == 201
        assert response.json()["byte_size"] == len(body)


# ---------------------------------------------------------------------------
# GET /v1/documents/{id}
# ---------------------------------------------------------------------------
class TestDownload:
    async def test_returns_the_exact_bytes(self, client: httpx.AsyncClient, keys: Keys) -> None:
        created = await upload(client, keys.full_a)
        document_id = created.json()["id"]

        response = await client.get(f"/v1/documents/{document_id}", headers=_auth(keys.full_a))

        assert response.status_code == 200
        assert response.content == PDF_BODY
        assert response.headers["content-type"].startswith(CONTENT_TYPE_PDF)
        assert response.headers["cache-control"] == "no-store"
        assert "report.pdf" in response.headers["content-disposition"]

    async def test_a_non_ascii_filename_is_encoded_in_the_header(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        created = await upload(client, keys.full_a, filename="contrat-signé.pdf")
        document_id = created.json()["id"]

        response = await client.get(f"/v1/documents/{document_id}", headers=_auth(keys.full_a))

        # RFC 5987, so a raw non-ASCII byte never reaches a response header.
        assert "filename*=UTF-8''" in response.headers["content-disposition"]
        assert response.status_code == 200

    async def test_another_tenant_cannot_download_it(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        created = await upload(client, keys.full_a)
        document_id = created.json()["id"]

        response = await client.get(f"/v1/documents/{document_id}", headers=_auth(keys.full_b))

        assert response.status_code == 404
        assert response.json()["error"]["code"] == "DOCUMENT_NOT_FOUND"

    async def test_another_key_in_the_same_tenant_cannot_download_it(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        # ADR-0021: decryption is bound to the user, and the API key is the
        # authenticated subject. Same tenant is not the same principal.
        created = await upload(client, keys.full_a)
        document_id = created.json()["id"]

        response = await client.get(f"/v1/documents/{document_id}", headers=_auth(keys.second_a))

        assert response.status_code == 404

    async def test_an_unknown_id_is_not_found(self, client: httpx.AsyncClient, keys: Keys) -> None:
        response = await client.get(f"/v1/documents/{uuid4()}", headers=_auth(keys.full_a))

        assert response.status_code == 404

    async def test_rejects_a_key_without_the_read_scope(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        created = await upload(client, keys.full_a)
        document_id = created.json()["id"]

        response = await client.get(f"/v1/documents/{document_id}", headers=_auth(keys.chat_only))

        assert response.status_code == 403


# ---------------------------------------------------------------------------
# GET /v1/documents/{id}/status
# ---------------------------------------------------------------------------
class TestStatus:
    async def test_reports_stored_without_the_filename(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        created = await upload(client, keys.full_a, filename="Jane Doe MRI.pdf")
        document_id = created.json()["id"]

        response = await client.get(
            f"/v1/documents/{document_id}/status", headers=_auth(keys.full_a)
        )

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "stored"
        assert body["byte_size"] == len(PDF_BODY)
        # The cheap polling route does not decrypt, so it has no filename to give.
        assert "filename" not in body
        assert "Jane" not in response.text

    async def test_another_tenant_gets_not_found(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        created = await upload(client, keys.full_a)
        document_id = created.json()["id"]

        response = await client.get(
            f"/v1/documents/{document_id}/status", headers=_auth(keys.full_b)
        )

        assert response.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /v1/documents/{id}
# ---------------------------------------------------------------------------
class TestDelete:
    async def test_destroys_the_document(
        self, client: httpx.AsyncClient, keys: Keys, store: FakeDocumentStore
    ) -> None:
        created = await upload(client, keys.full_a)
        document_id = created.json()["id"]

        response = await client.delete(f"/v1/documents/{document_id}", headers=_auth(keys.full_a))

        assert response.status_code == 204
        assert store.stored_keys() == []
        follow_up = await client.get(f"/v1/documents/{document_id}", headers=_auth(keys.full_a))
        assert follow_up.status_code == 404

    async def test_deleting_an_unknown_document_answers_204(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        # Idempotent, and not an oracle for which ids exist.
        response = await client.delete(f"/v1/documents/{uuid4()}", headers=_auth(keys.full_a))

        assert response.status_code == 204

    async def test_another_tenant_cannot_delete_it(
        self, client: httpx.AsyncClient, keys: Keys, store: FakeDocumentStore
    ) -> None:
        created = await upload(client, keys.full_a)
        document_id = created.json()["id"]

        response = await client.delete(f"/v1/documents/{document_id}", headers=_auth(keys.full_b))

        # 204 because deletion is idempotent, and nothing was removed.
        assert response.status_code == 204
        assert len(store.stored_keys()) == 1

    async def test_rejects_a_key_without_the_delete_scope(
        self, client: httpx.AsyncClient, keys: Keys
    ) -> None:
        created = await upload(client, keys.full_a)
        document_id = created.json()["id"]

        response = await client.delete(f"/v1/documents/{document_id}", headers=_auth(keys.reader_a))

        assert response.status_code == 403


# ---------------------------------------------------------------------------
# Failure behaviour
# ---------------------------------------------------------------------------
class TestFailureBehaviour:
    async def test_an_unreachable_store_fails_the_upload_closed(
        self, client: httpx.AsyncClient, keys: Keys, store: FakeDocumentStore
    ) -> None:
        from app.domain.errors import DocumentStorageUnavailableError

        store.simulate_failure(DocumentStorageUnavailableError(log_context={"reason": "test"}))

        response = await upload(client, keys.full_a)

        assert response.status_code == 503
        assert response.json()["error"]["code"] == "DOCUMENT_STORAGE_UNAVAILABLE"

    async def test_an_error_response_names_no_infrastructure(
        self, client: httpx.AsyncClient, keys: Keys, store: FakeDocumentStore
    ) -> None:
        from app.domain.errors import DocumentStorageUnavailableError

        store.simulate_failure(DocumentStorageUnavailableError(log_context={"reason": "test"}))

        response = await upload(client, keys.full_a)

        text = response.text.lower()
        for leak in ("minio", "s3", "bucket", "amazonaws", "endpoint", "9000"):
            assert leak not in text, f"error disclosed {leak!r}"
