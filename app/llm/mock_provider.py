"""Deterministic in-process provider. The default everywhere except production.

A fresh checkout and a CI run must be able to exercise the whole pipeline
without a credential, without egress, and without spending money, so this is
what ``DEFAULT_PROVIDER`` points at until a deployment says otherwise.

The reply deliberately echoes back every gateway token found in the request.
Restoration is the next stage of the pipeline, and it needs a response that
actually contains tokens to resolve -- a canned "hello" would let restoration
pass its tests while doing nothing.
"""

from __future__ import annotations

import re
from typing import Final

from app.domain.models import ProtectedChatRequest, ProviderResponse, ProviderUsage
from app.llm.base import ensure_protected_request

MOCK_PROVIDER_ALIAS: Final[str] = "mock"
MOCK_MODEL_ID: Final[str] = "mock-echo-1"

TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"⟦SGW:[A-Z0-9_]{1,64}:[0-9A-HJKMNP-TV-Z]{26}⟧")
"""The token grammar, matched whole. Loose matching would let the mock echo
fragments that restoration could never resolve."""

CHARS_PER_TOKEN: Final[int] = 4
"""Crude but stable divisor for synthetic usage counts. Deterministic output
matters more than fidelity here."""

_REPLY_PREFIX: Final[str] = "Mock provider reply."
_ECHO_PREFIX: Final[str] = " Echoed values:"
_NO_TOKENS: Final[str] = " No protected values were present."


class MockProvider:
    """``LLMProvider`` implementation with no network and no configuration."""

    alias: str

    def __init__(self, *, alias: str = MOCK_PROVIDER_ALIAS, model_id: str = MOCK_MODEL_ID) -> None:
        self.alias = alias
        self._model_id = model_id

    async def complete(self, request: ProtectedChatRequest) -> ProviderResponse:
        """Return a deterministic reply that repeats the request's tokens.

        Raises:
            TypeError: if handed anything other than a ``ProtectedChatRequest``.
        """
        protected = ensure_protected_request(request)
        content = _build_reply(protected)
        return ProviderResponse(
            content=content,
            model=self._model_id,
            usage=_synthetic_usage(protected, content),
            finish_reason="completed",
        )

    async def aclose(self) -> None:
        """Match the adapter lifecycle. There is nothing to release."""


def _build_reply(request: ProtectedChatRequest) -> str:
    tokens = _tokens_in_order(request)
    if not tokens:
        return f"{_REPLY_PREFIX}{_NO_TOKENS}"
    return f"{_REPLY_PREFIX}{_ECHO_PREFIX} {' '.join(tokens)}"


def _tokens_in_order(request: ProtectedChatRequest) -> tuple[str, ...]:
    """Every distinct token across the conversation, first-seen order preserved."""
    seen: dict[str, None] = {}
    for message in request.messages:
        for token in TOKEN_PATTERN.findall(message.content):
            seen.setdefault(token, None)
    return tuple(seen)


def _synthetic_usage(request: ProtectedChatRequest, reply: str) -> ProviderUsage:
    input_tokens = sum(len(message.content) for message in request.messages) // CHARS_PER_TOKEN
    output_tokens = len(reply) // CHARS_PER_TOKEN
    return ProviderUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
    )
