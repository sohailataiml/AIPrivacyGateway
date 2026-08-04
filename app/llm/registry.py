"""Alias-to-adapter lookup. The only way the pipeline reaches a provider.

A request names a provider with an alias. The registry decides whether that
alias exists and what it means; a caller can never supply a URL, a credential, or
a model id. An unregistered alias is refused rather than defaulted, so adding a
provider is an explicit deployment act.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from app.config.settings import Settings
from app.domain.errors import ProviderNotAllowedError
from app.llm.base import LLMProvider, ModelCatalog, safe_alias_for_log
from app.llm.mock_provider import MOCK_PROVIDER_ALIAS, MockProvider
from app.llm.openai_provider import DEFAULT_OPENAI_MODELS, OPENAI_PROVIDER_ALIAS, OpenAIProvider

_ALIAS_ALREADY_REGISTERED: Final[str] = "duplicate provider alias in registry: "


@dataclass(frozen=True, slots=True)
class ProviderRegistry:
    """Immutable alias to adapter map.

    Built once at startup. Nothing mutates it afterwards, so a request cannot
    add, replace, or re-point a provider.
    """

    adapters: Mapping[str, LLMProvider]

    @classmethod
    def from_providers(cls, *providers: LLMProvider) -> ProviderRegistry:
        """Build a registry, refusing duplicate aliases rather than silently
        letting the last registration win."""
        adapters: dict[str, LLMProvider] = {}
        for provider in providers:
            alias = _normalize(provider.alias)
            if alias in adapters:
                raise ValueError(_ALIAS_ALREADY_REGISTERED + safe_alias_for_log(provider.alias))
            adapters[alias] = provider
        return cls(adapters=adapters)

    def get(self, alias: str) -> LLMProvider:
        """Return the adapter registered under ``alias``.

        Raises:
            ProviderNotAllowedError: if nothing is registered under that alias.
                The error names no configured provider, so a caller cannot probe
                the registry for what a deployment supports.
        """
        adapter = self.adapters.get(_normalize(alias))
        if adapter is None:
            raise ProviderNotAllowedError(
                log_context={"provider_alias": safe_alias_for_log(alias)},
            )
        return adapter

    def __contains__(self, alias: str) -> bool:
        return _normalize(alias) in self.adapters

    def aliases(self) -> tuple[str, ...]:
        return tuple(sorted(self.adapters))

    async def aclose(self) -> None:
        """Close every adapter that owns a connection pool."""
        for adapter in self.adapters.values():
            closer = getattr(adapter, "aclose", None)
            if closer is not None:
                await closer()


def _normalize(alias: str) -> str:
    return alias.strip().lower()


def build_default_registry(settings: Settings) -> ProviderRegistry:
    """Assemble the registry a deployment's settings call for.

    The mock adapter is always present: it costs nothing and keeps local runs and
    CI working. The OpenAI adapter appears only when a credential is configured,
    which is what makes ``ProviderNotAllowedError`` -- rather than a startup crash
    or an unauthenticated call -- the outcome on a credential-free machine.
    """
    providers: list[LLMProvider] = [MockProvider(alias=MOCK_PROVIDER_ALIAS)]
    if settings.openai_api_key is not None:
        providers.append(
            OpenAIProvider.from_settings(
                settings,
                models=ModelCatalog.from_mapping(DEFAULT_OPENAI_MODELS),
                alias=OPENAI_PROVIDER_ALIAS,
            )
        )
    return ProviderRegistry.from_providers(*providers)
