"""Phase 1 acceptance: correlation, safe logging, error shape, size limits."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from uuid import UUID, uuid4

import httpx
import pytest
import structlog
from fastapi import FastAPI

from app.api.errors import REQUEST_ID_HEADER
from app.config.settings import Settings
from app.domain.errors import ErrorCode, VaultUnavailableError
from app.main import create_app
from app.observability.logging import (
    DROPPED_KEY_MARKER,
    REDACTED,
    drop_unlisted_keys,
    scrub_values,
)

CANARY_EMAIL = "SENSITIVE_CANARY_EMAIL_7f91@example.test"
CANARY_SSN = "123-45-6789"


@pytest.fixture
def settings() -> Settings:
    return Settings(app_env="test", max_request_bytes=2048)


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    application = create_app(settings)

    @application.post("/_test/echo")
    async def echo(payload: dict[str, str]) -> dict[str, str]:
        return payload

    @application.get("/_test/boom")
    async def boom() -> None:
        raise VaultUnavailableError(log_context={"stage": "get_or_create"})

    @application.get("/_test/crash")
    async def crash() -> None:
        raise RuntimeError(f"leaky message containing {CANARY_EMAIL}")

    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    # Starlette's ServerErrorMiddleware re-raises after sending the 500 so the
    # server can log it. The test client must not treat that as a transport
    # failure -- the response is what is under test.
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as instance:
        yield instance


class TestRequestId:
    async def test_response_carries_a_request_id(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/health/live")

        assert response.status_code == 200
        UUID(response.headers[REQUEST_ID_HEADER])  # parses, therefore well-formed

    async def test_client_supplied_uuid_is_echoed(self, client: httpx.AsyncClient) -> None:
        supplied = str(uuid4())

        response = await client.get("/health/live", headers={REQUEST_ID_HEADER: supplied})

        assert response.headers[REQUEST_ID_HEADER] == supplied

    async def test_non_uuid_request_id_is_replaced_not_reflected(
        self, client: httpx.AsyncClient
    ) -> None:
        # Reflecting arbitrary text would let a caller inject into log records.
        injected = 'not-a-uuid\n{"level":"error"}'

        response = await client.get("/health/live", headers={REQUEST_ID_HEADER: injected})

        returned = response.headers[REQUEST_ID_HEADER]
        assert returned != injected
        UUID(returned)


class TestErrorEnvelope:
    async def test_domain_error_uses_the_documented_shape(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/_test/boom")

        assert response.status_code == 503
        body = response.json()
        assert set(body) == {"error"}
        assert body["error"]["code"] == ErrorCode.VAULT_UNAVAILABLE.value
        assert body["error"]["message"] == "The secure mapping service is unavailable."
        UUID(body["error"]["request_id"])

    async def test_unhandled_exception_does_not_echo_its_message(
        self, client: httpx.AsyncClient
    ) -> None:
        # A stray f-string in an internal error must not become a data leak.
        response = await client.get("/_test/crash")

        assert response.status_code == 500
        assert CANARY_EMAIL not in response.text
        assert response.json()["error"]["code"] == ErrorCode.INTERNAL_ERROR.value

    async def test_validation_error_does_not_echo_the_body(self, client: httpx.AsyncClient) -> None:
        # Pydantic's default error representation includes the rejected input.
        response = await client.post("/_test/echo", json={"field": {"nested": CANARY_SSN}})

        assert response.status_code == 400
        assert CANARY_SSN not in response.text
        assert response.json()["error"]["code"] == ErrorCode.INVALID_REQUEST.value

    async def test_error_responses_carry_security_headers(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/_test/boom")

        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Content-Type-Options"] == "nosniff"

    async def test_unknown_route_returns_the_envelope(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/does-not-exist")

        assert response.status_code == 404
        assert "error" in response.json()


class TestSecurityHeaders:
    async def test_applied_to_successful_responses(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/health/live")

        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "camera=()" in response.headers["Permissions-Policy"]


class TestBodySizeLimit:
    async def test_oversized_declared_body_is_rejected(self, client: httpx.AsyncClient) -> None:
        oversized = {"field": "x" * 4096}

        response = await client.post("/_test/echo", json=oversized)

        assert response.status_code == 413
        assert response.json()["error"]["code"] == ErrorCode.REQUEST_TOO_LARGE.value

    async def test_chunked_body_cannot_bypass_the_limit(self, client: httpx.AsyncClient) -> None:
        # No Content-Length is sent for a streamed body, so a declared-size
        # check alone would let this through.
        async def oversized_stream() -> AsyncIterator[bytes]:
            for _ in range(8):
                yield b"x" * 1024

        response = await client.post(
            "/_test/echo",
            content=oversized_stream(),
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 413

    async def test_malformed_content_length_is_rejected(self, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/_test/echo",
            content=b'{"field":"ok"}',
            headers={"Content-Length": "not-a-number", "Content-Type": "application/json"},
        )

        assert response.status_code == 400

    async def test_body_within_the_limit_passes(self, client: httpx.AsyncClient) -> None:
        response = await client.post("/_test/echo", json={"field": "small"})

        assert response.status_code == 200
        assert response.json() == {"field": "small"}


class TestSafeLogging:
    def test_unlisted_keys_are_dropped_by_name(self) -> None:
        event = {"event": "x", "request_id": "r", "prompt": CANARY_EMAIL}

        result = drop_unlisted_keys(None, "info", event)  # type: ignore[arg-type]

        assert "prompt" not in result
        assert result[DROPPED_KEY_MARKER] == ["prompt"]
        assert CANARY_EMAIL not in json.dumps(result)

    @pytest.mark.parametrize(
        "value",
        [
            "user avery@example.test signed in",
            "ssn 123-45-6789 seen",
            "token ⟦SGW:EMAIL_ADDRESS:01ARZ3NDEKTSV4RRFFQ69G5FAV⟧",
            "key sgw_live_AbCdEf0123456789",
            "provider key sk-abcdefghij0123456789",
            "Authorization: Bearer abc.def.ghi",
            "card 4111 1111 1111 1111",
        ],
    )
    def test_credential_shaped_values_are_scrubbed(self, value: str) -> None:
        result = scrub_values(None, "info", {"reason": value})  # type: ignore[arg-type]

        assert REDACTED in result["reason"]

    def test_allowed_counts_survive(self) -> None:
        event = {"event": "done", "tokenized": 3, "entity_type": "EMAIL_ADDRESS"}

        result = drop_unlisted_keys(None, "info", event)  # type: ignore[arg-type]

        assert result == event

    async def test_request_logs_never_contain_the_body(self, client: httpx.AsyncClient) -> None:
        with structlog.testing.capture_logs() as captured:
            await client.post("/_test/echo", json={"field": CANARY_EMAIL})
            await client.get("/_test/boom")

        rendered = json.dumps(captured, default=str)
        assert CANARY_EMAIL not in rendered
