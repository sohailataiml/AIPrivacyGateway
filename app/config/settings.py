"""Typed application settings.

Production startup is a gate, not a formality. ``Settings`` refuses to build if
the environment still carries a development pepper, a short or default vault
key, or a missing audit key. A misconfigured deployment fails at boot rather
than quietly protecting nothing.

Every secret is a ``SecretStr``: model dumps, tracebacks, and ``repr`` output
show ``**********`` instead of the value.
"""

from __future__ import annotations

import base64
import binascii
from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

VAULT_KEY_BYTES = 32
"""AES-256-GCM key length."""

MIN_SECRET_CHARS = 32
"""Shortest acceptable pepper or HMAC key in production."""

# Values shipped in .env.example. Present in production means "nobody set this".
# The example vault key is deliberately absent: it decodes to 32 zero bytes and
# is caught by the stronger all-zero check in _vault_key_problems.
DEVELOPMENT_PLACEHOLDERS = frozenset(
    {
        "local-development-pepper-do-not-use-in-production",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        "change-me",
        "changeme",
        "secret",
    }
)


class AppEnv(StrEnum):
    LOCAL = "local"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """All runtime configuration. Constructed once during application startup."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # -- Application ------------------------------------------------------
    app_env: AppEnv = AppEnv.LOCAL
    app_host: str = "127.0.0.1"
    app_port: int = Field(default=8000, ge=1, le=65535)
    log_level: str = "INFO"

    # -- Dependencies -----------------------------------------------------
    database_url: SecretStr = SecretStr(
        "postgresql+asyncpg://gateway:gateway@localhost:5432/gateway"
    )
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")

    # -- Secrets ----------------------------------------------------------
    api_key_pepper: SecretStr = SecretStr("local-development-pepper-do-not-use-in-production")
    audit_hmac_key: SecretStr = SecretStr("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    vault_active_key_id: str = "local1"
    vault_keys: dict[str, SecretStr] = Field(default_factory=dict)
    """Key ring, populated from ``VAULT_KEY_<KEY_ID>`` variables at load time.

    Retired key ids stay here so records written before a rotation still decrypt.
    """

    openai_api_key: SecretStr | None = None

    # -- Limits -----------------------------------------------------------
    default_session_ttl_seconds: int = Field(default=1800, ge=60, le=86_400)
    max_request_bytes: int = Field(default=262_144, ge=1_024)
    max_message_chars: int = Field(default=32_768, ge=1)
    max_entities_per_request: int = Field(default=500, ge=1, le=10_000)

    # -- Provider ---------------------------------------------------------
    default_provider: str = "mock"
    """Local default is the mock provider so a fresh checkout cannot spend money."""

    provider_connect_timeout_seconds: float = Field(default=5.0, gt=0)
    provider_read_timeout_seconds: float = Field(default=60.0, gt=0)
    provider_max_retries: int = Field(default=2, ge=0, le=5)

    # -- Behaviour flags --------------------------------------------------
    # NoDecode keeps pydantic-settings from JSON-parsing the raw env value so the
    # comma-separated form below is what actually reaches the validator.
    cors_allowed_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    """Empty by default. CORS stays off unless a deployment opts in."""

    diagnostics_return_matched_text: bool = False
    """Privileged diagnostic mode. Forced off in production."""

    audit_fail_closed: bool = True
    """When true, an audit write failure fails the request."""

    # -- Observability ----------------------------------------------------
    metrics_enabled: bool = True
    """Whether ``GET /metrics`` is mounted at all.

    A deployment that scrapes through a sidecar, or that has decided the
    endpoint is not worth the surface area, turns it off here rather than
    relying on the route being unreachable by accident.
    """

    metrics_token: SecretStr | None = None
    """Bearer credential a scraper must present to read ``/metrics``.

    Deliberately *not* an API key from the database: metrics are most valuable
    when PostgreSQL is the thing that is broken, so the check guarding them must
    not depend on it. Unset leaves the endpoint open, which production refuses
    to start with.
    """

    otel_exporter_otlp_endpoint: str | None = None

    # -- Validation -------------------------------------------------------
    @field_validator("log_level")
    @classmethod
    def _valid_log_level(cls, value: str) -> str:
        allowed = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}")
        return upper

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @model_validator(mode="after")
    def _load_vault_key_ring(self) -> Self:
        """Read ``VAULT_KEY_<ID>`` variables into the key ring."""
        import os

        if not self.vault_keys:
            discovered = {
                name.removeprefix("VAULT_KEY_").lower(): SecretStr(raw)
                for name, raw in os.environ.items()
                if name.startswith("VAULT_KEY_") and raw
            }
            # model_config is not frozen, so assignment here is intentional and
            # happens exactly once, during construction.
            object.__setattr__(self, "vault_keys", discovered)
        return self

    @model_validator(mode="after")
    def _enforce_production_hardening(self) -> Self:
        if self.app_env is not AppEnv.PRODUCTION:
            return self

        problems: list[str] = []

        if self.api_key_pepper.get_secret_value() in DEVELOPMENT_PLACEHOLDERS:
            problems.append("API_KEY_PEPPER is still the development placeholder")
        if len(self.api_key_pepper.get_secret_value()) < MIN_SECRET_CHARS:
            problems.append(f"API_KEY_PEPPER must be at least {MIN_SECRET_CHARS} characters")

        if self.audit_hmac_key.get_secret_value() in DEVELOPMENT_PLACEHOLDERS:
            problems.append("AUDIT_HMAC_KEY is still the development placeholder")

        active = self.vault_keys.get(self.vault_active_key_id.lower())
        if active is None:
            problems.append(
                f"no VAULT_KEY_ entry matches VAULT_ACTIVE_KEY_ID={self.vault_active_key_id!r}"
            )
        else:
            problems.extend(self._vault_key_problems(active))

        if self.diagnostics_return_matched_text:
            problems.append("DIAGNOSTICS_RETURN_MATCHED_TEXT must be false in production")

        if "*" in self.cors_allowed_origins:
            problems.append("CORS_ALLOWED_ORIGINS must not be a wildcard in production")

        if self.metrics_enabled and self.metrics_token is None:
            # /metrics publishes request rates, error rates, and dependency
            # health. That is a reconnaissance surface, and an unauthenticated
            # one is not something a deployment should be able to ship by
            # forgetting a variable.
            problems.append("METRICS_TOKEN must be set when METRICS_ENABLED is true in production")

        if self.metrics_token is not None:
            problems.extend(self._metrics_token_problems(self.metrics_token))

        if problems:
            # Names of misconfigured variables only. No values.
            raise ValueError("invalid production configuration: " + "; ".join(problems))

        return self

    @staticmethod
    def _metrics_token_problems(token: SecretStr) -> list[str]:
        raw = token.get_secret_value()
        if raw in DEVELOPMENT_PLACEHOLDERS:
            return ["METRICS_TOKEN is still a development placeholder"]
        if len(raw) < MIN_SECRET_CHARS:
            return [f"METRICS_TOKEN must be at least {MIN_SECRET_CHARS} characters"]
        return []

    @staticmethod
    def _vault_key_problems(key: SecretStr) -> list[str]:
        raw = key.get_secret_value()
        if raw in DEVELOPMENT_PLACEHOLDERS:
            return ["the active vault key is still the development placeholder"]
        try:
            decoded = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            return ["the active vault key is not valid base64"]
        if len(decoded) != VAULT_KEY_BYTES:
            return [f"the active vault key must decode to exactly {VAULT_KEY_BYTES} bytes"]
        if decoded == bytes(VAULT_KEY_BYTES):
            return ["the active vault key is all zero bytes"]
        return []

    # -- Derived helpers --------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.app_env is AppEnv.PRODUCTION

    @property
    def diagnostics_allowed(self) -> bool:
        """Matched-text diagnostics are never available in production."""
        return self.diagnostics_return_matched_text and not self.is_production

    def active_vault_key(self) -> bytes:
        """Return the raw active encryption key.

        Raises:
            ValueError: if the active key id has no entry or is malformed.
        """
        secret = self.vault_keys.get(self.vault_active_key_id.lower())
        if secret is None:
            raise ValueError("the active vault key id is not present in the key ring")
        return base64.b64decode(secret.get_secret_value(), validate=True)

    def vault_key(self, key_id: str) -> bytes:
        """Return a specific key from the ring so rotated records still decrypt."""
        secret = self.vault_keys.get(key_id.lower())
        if secret is None:
            raise ValueError("the requested vault key id is not present in the key ring")
        return base64.b64decode(secret.get_secret_value(), validate=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton.

    Tests call ``get_settings.cache_clear()`` after patching the environment.
    """
    return Settings()
