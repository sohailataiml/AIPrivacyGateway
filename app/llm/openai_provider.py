"""OpenAI adapter built on the Responses API.

Everything routable or authenticating is fixed at construction from settings:
the endpoint is the SDK default, the credential comes from the environment, and
the model id comes from a server-side catalog. A request contributes message
content, a model alias, and two sampling knobs -- nothing more.

Three independent bounds protect the caller: a connect timeout, a read timeout,
and an overall deadline covering every retry and every backoff sleep. Retries are
bounded and apply only to transient transport failures and the statuses in
``RETRYABLE_STATUS_CODES``; authentication failures and invalid input are never
re-sent.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, Final, cast

import httpx
import openai
from openai import AsyncOpenAI, omit
from openai.types.responses import ResponseInputParam

from app.config.settings import Settings
from app.domain.errors import (
    GatewayError,
    ProviderResponseInvalidError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from app.domain.models import ProtectedChatRequest, ProviderResponse, ProviderUsage
from app.llm.base import (
    DEFAULT_RETRY_BACKOFF_BASE_SECONDS,
    ModelCatalog,
    ensure_protected_request,
    error_for_status,
    is_retryable_status,
    overall_deadline_seconds,
    retry_backoff_seconds,
    safe_alias_for_log,
    silence_transport_logging,
)

OPENAI_PROVIDER_ALIAS: Final[str] = "openai"

DEFAULT_OPENAI_MODELS: Final[Mapping[str, str]] = {
    "default": "gpt-4.1-mini",
    "fast": "gpt-4o-mini",
    "balanced": "gpt-4.1",
    "gpt-4.1": "gpt-4.1",
    "gpt-4.1-mini": "gpt-4.1-mini",
    "gpt-4o": "gpt-4o",
    "gpt-4o-mini": "gpt-4o-mini",
}
"""Alias to provider model id. Aliases are the public contract; the ids behind
them are a deployment detail and may be re-pointed without an API change."""

_OUTPUT_TEXT_PART_TYPE: Final[str] = "output_text"
_STORE_RESPONSES: Final[bool] = False
"""Provider-side retention is disabled. Protected text still carries structure,
and the gateway is the only system that should hold any form of it."""


class OpenAIProvider:
    """``LLMProvider`` implementation for the OpenAI Responses API."""

    alias: str

    def __init__(
        self,
        *,
        api_key: str,
        models: ModelCatalog,
        connect_timeout_seconds: float,
        read_timeout_seconds: float,
        max_retries: int,
        alias: str = OPENAI_PROVIDER_ALIAS,
        backoff_base_seconds: float = DEFAULT_RETRY_BACKOFF_BASE_SECONDS,
        deadline_seconds: float | None = None,
    ) -> None:
        # No base_url and no header parameters exist by design: an adapter that
        # cannot be pointed elsewhere cannot be used for SSRF or silent egress.
        silence_transport_logging()
        self.alias = alias
        self._models = models
        self._max_retries = max_retries
        self._backoff_base_seconds = backoff_base_seconds
        self._deadline_seconds = deadline_seconds or overall_deadline_seconds(
            connect_timeout_seconds=connect_timeout_seconds,
            read_timeout_seconds=read_timeout_seconds,
            max_retries=max_retries,
            backoff_base_seconds=backoff_base_seconds,
        )
        self._client = AsyncOpenAI(
            api_key=api_key,
            # Retries belong to this adapter. Leaving the SDK's own retry budget
            # in place would multiply attempts and blow past the deadline.
            max_retries=0,
            timeout=httpx.Timeout(read_timeout_seconds, connect=connect_timeout_seconds),
        )

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        models: ModelCatalog | None = None,
        alias: str = OPENAI_PROVIDER_ALIAS,
    ) -> OpenAIProvider:
        """Build an adapter from application settings.

        Raises:
            ValueError: if no provider credential is configured. The message names
                the variable, never its value.
        """
        if settings.openai_api_key is None:
            raise ValueError("OPENAI_API_KEY is required to build the OpenAI provider")
        return cls(
            api_key=settings.openai_api_key.get_secret_value(),
            models=models or ModelCatalog.from_mapping(DEFAULT_OPENAI_MODELS),
            connect_timeout_seconds=settings.provider_connect_timeout_seconds,
            read_timeout_seconds=settings.provider_read_timeout_seconds,
            max_retries=settings.provider_max_retries,
            alias=alias,
        )

    async def complete(self, request: ProtectedChatRequest) -> ProviderResponse:
        """Send a protected request and return the provider's protected reply.

        Raises:
            ModelNotAllowedError: the model alias is not in this adapter's catalog.
            ProviderTimeoutError: an attempt or the overall deadline expired.
            ProviderUnavailableError: transport failure or an unusable status.
            ProviderResponseInvalidError: the response carried no usable text.
        """
        protected = ensure_protected_request(request)
        model_id = self._models.resolve(protected.model_alias)
        try:
            async with asyncio.timeout(self._deadline_seconds):
                return await self._send_with_retries(protected, model_id)
        except TimeoutError as exc:
            raise ProviderTimeoutError(log_context=self._log_context(reason="deadline")) from exc

    async def aclose(self) -> None:
        """Release the underlying connection pool."""
        await self._client.close()

    # -- internals --------------------------------------------------------
    async def _send_with_retries(
        self, request: ProtectedChatRequest, model_id: str
    ) -> ProviderResponse:
        attempts = self._max_retries + 1
        last_error: GatewayError | None = None
        last_cause: BaseException | None = None

        for attempt in range(attempts):
            try:
                raw = await self._send_once(request, model_id)
            except openai.APITimeoutError as exc:
                last_error, last_cause = self._timeout_error(attempt), exc
            except openai.APIConnectionError as exc:
                last_error, last_cause = self._unavailable_error(attempt, "connection"), exc
            except openai.APIStatusError as exc:
                error = error_for_status(exc.status_code, alias=self.alias, attempts=attempt + 1)
                if not is_retryable_status(exc.status_code):
                    raise error from exc
                last_error, last_cause = error, exc
            except openai.OpenAIError as exc:
                # Client-side SDK failure (bad configuration, unusable payload).
                # Converted immediately so no SDK detail reaches the caller.
                raise self._unavailable_error(attempt, "client") from exc
            else:
                return _to_provider_response(raw, model_id)

            if attempt + 1 < attempts:
                await asyncio.sleep(
                    retry_backoff_seconds(attempt, base_seconds=self._backoff_base_seconds)
                )

        if last_error is None:  # pragma: no cover - the loop body always sets it
            raise self._unavailable_error(attempts - 1, "exhausted")
        raise last_error from last_cause

    async def _send_once(self, request: ProtectedChatRequest, model_id: str) -> object:
        return await self._client.responses.create(
            model=model_id,
            input=_build_input(request),
            store=_STORE_RESPONSES,
            temperature=request.temperature if request.temperature is not None else omit,
            max_output_tokens=(
                request.max_output_tokens if request.max_output_tokens is not None else omit
            ),
        )

    def _timeout_error(self, attempt: int) -> ProviderTimeoutError:
        return ProviderTimeoutError(log_context=self._log_context(attempts=attempt + 1))

    def _unavailable_error(self, attempt: int, reason: str) -> ProviderUnavailableError:
        return ProviderUnavailableError(
            log_context=self._log_context(attempts=attempt + 1, reason=reason)
        )

    def _log_context(self, **extra: Any) -> dict[str, Any]:
        """Structured detail for operators. Content and credentials never appear."""
        return {"provider_alias": safe_alias_for_log(self.alias), **extra}


def _build_input(request: ProtectedChatRequest) -> ResponseInputParam:
    """Project protected messages onto the Responses API input shape."""
    items = [{"role": message.role, "content": message.content} for message in request.messages]
    return cast(ResponseInputParam, items)


def _to_provider_response(raw: object, model_id: str) -> ProviderResponse:
    """Validate the provider payload and narrow it to the domain contract."""
    content = _extract_output_text(raw)
    if not content:
        raise ProviderResponseInvalidError(log_context={"reason": "empty_output"})
    reported_model = getattr(raw, "model", None)
    return ProviderResponse(
        content=content,
        model=reported_model if isinstance(reported_model, str) and reported_model else model_id,
        usage=_extract_usage(raw),
        finish_reason=_extract_finish_reason(raw),
    )


def _extract_output_text(raw: object) -> str:
    """Concatenate output text parts, tolerating any shape the SDK hands back.

    A mocked or misbehaving endpoint can return a plain string, a model with
    ``output=None``, or items without content. Every one of those is a malformed
    response rather than an internal error, so structural failures are converted
    here instead of escaping as ``TypeError``.
    """
    try:
        items = getattr(raw, "output", None)
        if not isinstance(items, list):
            raise ProviderResponseInvalidError(log_context={"reason": "missing_output"})
        parts: list[str] = []
        for item in items:
            for part in getattr(item, "content", None) or ():
                text = getattr(part, "text", None)
                if getattr(part, "type", None) == _OUTPUT_TEXT_PART_TYPE and isinstance(text, str):
                    parts.append(text)
        return "".join(parts)
    except (AttributeError, TypeError) as exc:
        raise ProviderResponseInvalidError(log_context={"reason": "unreadable_output"}) from exc


def _extract_usage(raw: object) -> ProviderUsage | None:
    """Read token accounting when the provider reports it.

    Usage is telemetry, not content: a completion that is otherwise valid is not
    failed because its counters are missing or unusable.
    """
    usage = getattr(raw, "usage", None)
    if usage is None:
        return None
    counts = {
        field: value
        for field in ("input_tokens", "output_tokens", "total_tokens")
        if isinstance(value := getattr(usage, field, None), int)
    }
    return ProviderUsage(**counts) if counts else None


def _extract_finish_reason(raw: object) -> str | None:
    """Prefer the specific incomplete reason over the coarse status."""
    details = getattr(raw, "incomplete_details", None)
    reason = getattr(details, "reason", None)
    if isinstance(reason, str) and reason:
        return reason
    status = getattr(raw, "status", None)
    return status if isinstance(status, str) and status else None
