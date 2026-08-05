"""Provider adapter tests, all against a mocked transport.

``respx`` refuses any request a test did not register, so a regression that
reaches the real API fails the suite instead of billing an account, and the whole
file passes with no ``OPENAI_API_KEY`` set. The privacy assertions are the point:
the outbound body must carry gateway tokens and never the original values, and no
credential may reach an exception, a log record, or a response.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from collections.abc import Iterator
from typing import Any
from uuid import uuid4

import httpx
import pytest
import respx
from pydantic import SecretStr

from app.config.settings import Settings
from app.domain.errors import (
    GatewayError,
    ModelNotAllowedError,
    ProviderNotAllowedError,
    ProviderResponseInvalidError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from app.domain.models import ChatMessage, ChatRequest, ProtectedChatRequest
from app.llm.base import LLMProvider, ModelCatalog, overall_deadline_seconds
from app.llm.mock_provider import MockProvider
from app.llm.openai_provider import OpenAIProvider
from app.llm.registry import ProviderRegistry, build_default_registry

FAKE_API_KEY = "sk-test-0000000000000000000000"
RESPONSES_URL = "https://api.openai.com/v1/responses"
MODEL_ALIAS = "default"
PROVIDER_MODEL_ID = "gpt-4.1-mini"

EMAIL_TOKEN = "⟦SGW:EMAIL_ADDRESS:01J8ZQ9V5K7C3B2N4M6P8R0TVW⟧"
PHONE_TOKEN = "⟦SGW:PHONE_NUMBER:01J8ZQ9V5K7C3B2N4M6P8R0TVX⟧"
ORIGINAL_EMAIL = "alice@example.com"
ORIGINAL_PHONE = "+1-415-555-0142"

RAW_REQUEST = ChatRequest(
    provider="openai",
    model=MODEL_ALIAS,
    messages=[ChatMessage(role="user", content=ORIGINAL_EMAIL)],
)


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    """A transport that answers only what a test registered."""
    with respx.mock(assert_all_called=False) as mock_router:
        yield mock_router


def build_provider(**overrides: Any) -> OpenAIProvider:
    params: dict[str, Any] = {
        "api_key": FAKE_API_KEY,
        "models": ModelCatalog.from_mapping({MODEL_ALIAS: PROVIDER_MODEL_ID}),
        "connect_timeout_seconds": 0.5,
        "read_timeout_seconds": 1.0,
        "max_retries": 2,
        # Zero backoff keeps retry tests fast without changing the retry count.
        "backoff_base_seconds": 0.0,
    }
    params.update(overrides)
    return OpenAIProvider(**params)


def build_request(
    *,
    contents: tuple[str, ...] = (f"Email {EMAIL_TOKEN} now.",),
    model_alias: str = MODEL_ALIAS,
    sampling: bool = True,
) -> ProtectedChatRequest:
    return ProtectedChatRequest(
        request_id=uuid4(),
        tenant_id=uuid4(),
        session_id=uuid4(),
        provider_alias="openai",
        model_alias=model_alias,
        messages=tuple(ChatMessage(role="user", content=text) for text in contents),
        policy_version=1,
        temperature=0.2 if sampling else None,
        max_output_tokens=256 if sampling else None,
    )


def response_body(*, text: str = f"Replying to {EMAIL_TOKEN}", **overrides: Any) -> dict[str, Any]:
    message = {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    }
    body: dict[str, Any] = {
        "id": "resp_test",
        "object": "response",
        "created_at": 1,
        "model": PROVIDER_MODEL_ID,
        "status": "completed",
        "output": [message],
        "usage": {"input_tokens": 11, "output_tokens": 7, "total_tokens": 18},
    }
    return body | overrides


def ok(**kwargs: Any) -> httpx.Response:
    return httpx.Response(200, json=response_body(**kwargs))


# --- The central safety property ---
@pytest.mark.parametrize("provider", [build_provider(), MockProvider()], ids=["openai", "mock"])
@pytest.mark.parametrize(
    "payload", [RAW_REQUEST, ORIGINAL_EMAIL, {"messages": [{"content": ORIGINAL_EMAIL}]}, None]
)
async def test_complete_rejects_anything_but_a_protected_request(
    provider: LLMProvider, payload: object
) -> None:
    with pytest.raises(TypeError, match="ProtectedChatRequest"):
        await provider.complete(payload)  # type: ignore[arg-type]


def test_adapter_surface_admits_no_raw_text_and_no_routing_control() -> None:
    """``complete`` takes one protected parameter, and nothing on the path can
    redirect egress or inject headers."""
    complete = inspect.signature(OpenAIProvider.complete)
    constructor = inspect.signature(OpenAIProvider.__init__).parameters
    forbidden = {"base_url", "headers", "default_headers", "extra_headers", "extra_query"}

    assert list(complete.parameters) == ["self", "request"]
    assert complete.parameters["request"].annotation == "ProtectedChatRequest"
    assert isinstance(build_provider(), LLMProvider)
    assert isinstance(MockProvider(), LLMProvider)
    assert not forbidden & set(constructor)
    assert not [p for p in constructor.values() if p.kind is inspect.Parameter.VAR_KEYWORD]
    assert not forbidden & set(ProtectedChatRequest.__dataclass_fields__)


@pytest.mark.privacy
async def test_outbound_payload_carries_tokens_and_no_originals(router: respx.MockRouter) -> None:
    # Arrange
    route = router.post(RESPONSES_URL).mock(return_value=ok())
    request = build_request(
        contents=(f"Contact {EMAIL_TOKEN} or {PHONE_TOKEN}.", f"Confirm {EMAIL_TOKEN}.")
    )

    # Act -- deliberately generous timeouts. The default ones here are tuned for
    # the retry and deadline tests, and the OpenAI SDK resolves platform details
    # in a worker thread on its first request; under `pytest --cov` that lands
    # outside a 4.5-second budget and this test fails on timing rather than on
    # what it is actually asserting.
    await build_provider(connect_timeout_seconds=5.0, read_timeout_seconds=15.0).complete(request)

    # Assert
    sent = route.calls.last.request
    raw_body = sent.content.decode("utf-8")
    sent_contents = [item["content"] for item in json.loads(raw_body)["input"]]
    assert EMAIL_TOKEN in sent_contents[0]
    assert PHONE_TOKEN in sent_contents[0]
    assert ORIGINAL_EMAIL not in raw_body
    assert ORIGINAL_PHONE not in raw_body
    assert ORIGINAL_EMAIL.encode() not in sent.content
    assert str(sent.url) == RESPONSES_URL


async def test_outbound_payload_uses_server_side_configuration(router: respx.MockRouter) -> None:
    route = router.post(RESPONSES_URL).mock(return_value=ok())
    provider = build_provider()

    await provider.complete(build_request())
    await provider.complete(build_request(sampling=False))

    sampled, bare = (json.loads(call.request.content) for call in route.calls)
    assert sampled["model"] == PROVIDER_MODEL_ID  # the alias, resolved by the catalog
    assert sampled["store"] is False  # provider-side retention disabled
    assert (sampled["temperature"], sampled["max_output_tokens"]) == (0.2, 256)
    assert "temperature" not in bare  # unset sampling fields are omitted, not nulled
    assert "max_output_tokens" not in bare


async def test_successful_response_is_mapped(router: respx.MockRouter) -> None:
    router.post(RESPONSES_URL).mock(return_value=ok())

    result = await build_provider().complete(build_request())

    assert result.content == f"Replying to {EMAIL_TOKEN}"
    assert result.model == PROVIDER_MODEL_ID
    assert result.finish_reason == "completed"
    assert result.usage is not None
    assert (result.usage.input_tokens, result.usage.output_tokens) == (11, 7)
    assert result.usage.total_tokens == 18


async def test_usage_absent_yields_no_usage(router: respx.MockRouter) -> None:
    """Missing telemetry is not a reason to fail an otherwise usable completion."""
    body = response_body(status="incomplete", incomplete_details={"reason": "max_output_tokens"})
    body.pop("usage")
    router.post(RESPONSES_URL).mock(return_value=httpx.Response(200, json=body))

    result = await build_provider().complete(build_request())

    assert result.usage is None
    assert result.content
    assert result.finish_reason == "max_output_tokens"


@pytest.mark.parametrize(
    "body",
    [{"id": "x", "object": "response", "output": []}, {"id": "x"}, {"foo": "bar"}],
    ids=["empty-output", "missing-output", "unrelated-shape"],
)
async def test_invalid_response_structure_is_rejected(
    router: respx.MockRouter, body: dict[str, Any]
) -> None:
    router.post(RESPONSES_URL).mock(return_value=httpx.Response(200, json=body))

    with pytest.raises(ProviderResponseInvalidError):
        await build_provider().complete(build_request())


# --- Failure mapping, retry, and deadline ---
@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (httpx.ReadTimeout("slow"), ProviderTimeoutError),
        (httpx.ConnectTimeout("slow"), ProviderTimeoutError),
        (httpx.ConnectError("refused"), ProviderUnavailableError),
    ],
)
async def test_transport_failures_are_retried_then_mapped(
    router: respx.MockRouter, failure: Exception, expected: type[GatewayError]
) -> None:
    route = router.post(RESPONSES_URL).mock(side_effect=failure)

    with pytest.raises(expected):
        await build_provider(max_retries=2).complete(build_request())

    assert route.call_count == 3  # the initial attempt plus two retries


async def test_rate_limit_then_success(router: respx.MockRouter) -> None:
    route = router.post(RESPONSES_URL).mock(
        side_effect=[httpx.Response(429, json={"error": {"message": "slow down"}}), ok()]
    )

    result = await build_provider(max_retries=2).complete(build_request())

    assert result.content
    assert route.call_count == 2


@pytest.mark.parametrize(
    ("status", "expected_attempts"),
    [(429, 3), (500, 3), (502, 3), (503, 3), (400, 1), (401, 1), (403, 1), (404, 1), (422, 1)],
)
async def test_statuses_are_retried_only_when_a_retry_could_help(
    router: respx.MockRouter, status: int, expected_attempts: int
) -> None:
    """Transient statuses consume the whole budget. Invalid input, authentication
    failure, and a policy block cannot succeed on a second attempt, so they
    consume exactly one."""
    route = router.post(RESPONSES_URL).mock(return_value=httpx.Response(status, json={}))

    with pytest.raises(ProviderUnavailableError) as caught:
        await build_provider(max_retries=2).complete(build_request())

    assert route.call_count == expected_attempts
    assert caught.value.log_context["provider_status"] == status
    assert caught.value.log_context["attempts"] == expected_attempts


async def test_overall_deadline_fires_inside_per_attempt_timeouts(router: respx.MockRouter) -> None:
    # Arrange: a reply that arrives well inside the read timeout but long after
    # the budget for the whole call.
    async def stalled(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.5)
        return ok()

    router.post(RESPONSES_URL).mock(side_effect=stalled)
    provider = build_provider(read_timeout_seconds=5.0, deadline_seconds=0.05)

    # Act / Assert
    with pytest.raises(ProviderTimeoutError) as caught:
        await provider.complete(build_request())

    assert caught.value.log_context["reason"] == "deadline"
    derived = overall_deadline_seconds(
        connect_timeout_seconds=5.0, read_timeout_seconds=60.0, max_retries=2
    )
    assert derived > 3 * 65.0  # the default budget outlasts every attempt and backoff


# --- Credential and content containment ---
@pytest.mark.security
async def test_credential_never_reaches_an_error(router: respx.MockRouter) -> None:
    router.post(RESPONSES_URL).mock(
        return_value=httpx.Response(401, json={"error": {"message": "bad key"}})
    )

    with pytest.raises(ProviderUnavailableError) as caught:
        await build_provider().complete(build_request())

    rendered = f"{caught.value}{caught.value!r}{caught.value.log_context}"
    assert FAKE_API_KEY not in rendered
    assert "bad key" not in rendered  # provider bodies can echo submitted content


@pytest.mark.security
async def test_client_logs_no_request_or_response_content(
    router: respx.MockRouter, caplog: pytest.LogCaptureFixture
) -> None:
    # Arrange
    caplog.set_level(logging.DEBUG)
    router.post(RESPONSES_URL).mock(return_value=ok())

    # Act
    await build_provider().complete(build_request())

    # Assert
    emitted = "\n".join(record.getMessage() for record in caplog.records)
    assert EMAIL_TOKEN not in emitted
    assert FAKE_API_KEY not in emitted
    assert PROVIDER_MODEL_ID not in emitted


async def test_unknown_model_alias_is_refused_before_any_request(router: respx.MockRouter) -> None:
    route = router.post(RESPONSES_URL).mock(return_value=ok())
    catalog = ModelCatalog.from_mapping({"Default": PROVIDER_MODEL_ID})

    with pytest.raises(ModelNotAllowedError):
        await build_provider().complete(build_request(model_alias="not-configured"))

    assert route.call_count == 0
    assert catalog.resolve("DEFAULT") == PROVIDER_MODEL_ID  # aliases are case-insensitive
    with pytest.raises(ModelNotAllowedError) as caught:
        catalog.resolve(f"{ORIGINAL_EMAIL} is my email")
    assert ORIGINAL_EMAIL not in str(caught.value.log_context)  # no caller text in logs


# --- Registry ---
def test_registry_resolves_registered_aliases_and_refuses_the_rest() -> None:
    provider = MockProvider()
    registry = ProviderRegistry.from_providers(provider)

    assert registry.get("  MOCK ") is provider
    assert "mock" in registry
    assert registry.aliases() == ("mock",)
    with pytest.raises(ProviderNotAllowedError) as caught:
        registry.get("anthropic")
    assert caught.value.log_context["provider_alias"] == "anthropic"
    assert "mock" not in caught.value.public_message  # no probing the deployment
    with pytest.raises(ValueError, match="duplicate provider alias"):
        ProviderRegistry.from_providers(MockProvider(), MockProvider())


def test_registry_composition_follows_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without a credential the OpenAI adapter is absent rather than broken."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    without_key = Settings(_env_file=None, openai_api_key=None)
    with_key = Settings(_env_file=None, openai_api_key=SecretStr(FAKE_API_KEY))

    bare = build_default_registry(without_key)
    configured = build_default_registry(with_key)

    assert bare.aliases() == ("mock",)
    with pytest.raises(ProviderNotAllowedError):
        bare.get("openai")
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        OpenAIProvider.from_settings(without_key)
    assert configured.aliases() == ("mock", "openai")
    assert isinstance(configured.get("openai"), OpenAIProvider)


async def test_mock_provider_echoes_tokens_for_restoration(router: respx.MockRouter) -> None:
    request = build_request(
        contents=(f"Mail {EMAIL_TOKEN} and {PHONE_TOKEN}.", f"Again {EMAIL_TOKEN}.")
    )
    provider = MockProvider()

    first = await provider.complete(request)
    second = await provider.complete(request)
    without_tokens = await provider.complete(build_request(contents=("nothing sensitive",)))

    assert first.content.count(EMAIL_TOKEN) == 1  # deduplicated, first-seen order
    assert first.content.index(EMAIL_TOKEN) < first.content.index(PHONE_TOKEN)
    assert first == second  # deterministic
    assert first.usage is not None
    assert first.usage.total_tokens == (first.usage.input_tokens or 0) + (
        first.usage.output_tokens or 0
    )
    assert "⟦SGW:" not in without_tokens.content
    assert router.calls.call_count == 0  # no network, ever
