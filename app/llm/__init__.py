"""Provider adapters. Every one of them accepts only a ``ProtectedChatRequest``."""

from __future__ import annotations

from app.llm.base import (
    LLMProvider,
    ModelCatalog,
    ensure_protected_request,
    silence_transport_logging,
)
from app.llm.mock_provider import MOCK_PROVIDER_ALIAS, MockProvider
from app.llm.openai_provider import DEFAULT_OPENAI_MODELS, OPENAI_PROVIDER_ALIAS, OpenAIProvider
from app.llm.registry import ProviderRegistry, build_default_registry

__all__ = [
    "DEFAULT_OPENAI_MODELS",
    "MOCK_PROVIDER_ALIAS",
    "OPENAI_PROVIDER_ALIAS",
    "LLMProvider",
    "MockProvider",
    "ModelCatalog",
    "OpenAIProvider",
    "ProviderRegistry",
    "build_default_registry",
    "ensure_protected_request",
    "silence_transport_logging",
]
