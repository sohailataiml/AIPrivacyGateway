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


class ObjectStoreProvider(StrEnum):
    """Which S3-compatible service the document store is pointed at.

    This selects *configuration*, never an implementation. There is one
    ``S3CompatibleDocumentStore`` and every provider speaks the same API to it;
    what differs is endpoint addressing, whether a custom endpoint is expected,
    and where credentials come from. Encoding that difference as an enum rather
    than leaving it implicit in three independent variables means a deployment
    states its intent once and gets checked against it, instead of silently
    talking to the wrong service because ``OBJECT_STORE_ENDPOINT_URL`` was left
    unset.

    ``AWS`` is the default and the only backend the project runs (ADR-0035).
    ``COMPATIBLE`` remains because the adapter is genuinely S3-compatible and
    the endpoint-plus-static-credentials shape is what every such service needs;
    it is the escape hatch for pointing at one, not a supported deployment.
    """

    AWS = "aws"
    COMPATIBLE = "compatible"


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

    document_active_key_id: str = "local1"
    document_keys: dict[str, SecretStr] = Field(default_factory=dict)
    """Document key ring, populated from ``DOCUMENT_KEY_<KEY_ID>`` variables.

    Separate from the vault ring on purpose. The two protect data with different
    lifetimes -- session mappings expire in minutes to hours, stored documents
    persist -- so they rotate on different schedules, and a compromise of one
    ring should not be a compromise of the other.
    """

    # -- Object storage (ADR-0020, ADR-0034, ADR-0035) --------------------
    documents_enabled: bool = True
    """Whether the document routes are mounted and object storage is opened.

    A deployment that does not accept uploads turns this off rather than
    configuring a bucket it will never use -- and production then stops
    demanding document keys it has no documents to protect.
    """

    object_store_provider: ObjectStoreProvider = ObjectStoreProvider.AWS
    """Which S3-compatible service to talk to. AWS S3 unless stated otherwise."""

    object_store_endpoint_url: str | None = None
    """A custom endpoint. Must be ``None`` for AWS S3, which resolves its own."""

    object_store_region: str = "us-east-1"
    object_store_bucket: str = "sgw-documents"
    object_store_access_key_id: SecretStr | None = None
    object_store_secret_access_key: SecretStr | None = None
    """Static credentials.

    Optional on AWS, where leaving both unset selects botocore's default
    credential chain -- the instance or task role. That is the better posture
    there: a role issues short-lived credentials that rotate themselves, so
    demanding a long-lived key pair would force a deployment into weaker
    handling of a secret it never needed to hold. Required for any other
    S3-compatible service, which has no ambient identity to fall back on.
    """

    object_store_use_path_style: bool | None = None
    """Bucket addressing. ``None`` follows the provider's own convention.

    AWS S3 wants virtual-host style; other S3-compatible services generally
    address buckets by path. Left unset this is derived from
    ``object_store_provider``, so the common case needs no variable at all. Set
    it explicitly only to override -- an S3-compatible service behind a VPC
    endpoint can need path style while still being AWS.
    """

    object_store_connect_timeout_seconds: float = Field(default=5.0, gt=0)
    object_store_read_timeout_seconds: float = Field(default=30.0, gt=0)

    # -- Limits -----------------------------------------------------------
    default_session_ttl_seconds: int = Field(default=1800, ge=60, le=86_400)
    max_request_bytes: int = Field(default=262_144, ge=1_024)
    max_message_chars: int = Field(default=32_768, ge=1)
    max_entities_per_request: int = Field(default=500, ge=1, le=10_000)

    max_document_bytes: int = Field(default=26_214_400, ge=1_024, le=1_073_741_824)
    """25 MiB. The JSON limit above stays small; only the upload route gets this."""

    document_chunk_bytes: int = Field(default=5_242_880, ge=5_242_880, le=67_108_864)
    """Plaintext bytes sealed per chunk, and the multipart part size.

    Floored at S3's 5 MiB minimum part size: every part except the last must
    reach it, so a smaller value would make multipart uploads fail on the
    second part rather than on a boundary anyone would notice in testing.
    """

    # -- Document extraction and segmentation (ADR-0028, ADR-0029, ADR-0030) --
    extraction_max_workers: int = Field(default=2, ge=1, le=32)
    """Documents extracted at once. Each gets its own process.

    Bounded because unbounded extraction is a denial-of-service vector: a
    handful of large uploads would start a process each and starve the request
    path. Two is deliberately conservative -- parsing is CPU-bound, so this
    should track available cores rather than expected traffic.
    """

    extraction_timeout_seconds: float = Field(default=30.0, gt=0, le=600.0)
    """Wall-clock budget for one extraction, after which the worker is killed.

    A real deadline rather than a hope: the worker runs in its own process, so
    the timeout ends it instead of merely abandoning it.
    """

    max_extracted_characters: int = Field(default=4_000_000, ge=1_024, le=100_000_000)
    """Ceiling on extracted text. Roughly 1,500 pages of dense prose.

    Enforced inside the worker while accumulating, so a file that expands
    without bound is stopped part-way rather than after it has already been
    allocated.
    """

    segment_max_characters: int = Field(default=12_000, ge=64, le=1_000_000)
    """Largest segment handed to the detector.

    Inside every current model's context window, and short enough that
    detection accuracy does not degrade with length.
    """

    segment_overlap_characters: int = Field(default=256, ge=0, le=100_000)
    """How much of the previous segment each segment repeats.

    This is a **privacy** control, not a tuning knob. An entity shorter than the
    overlap is guaranteed to appear whole in at least one segment; anything
    longer can be split across a boundary and seen only in fragments, which no
    recognizer matches. Lowering it trades detection coverage for throughput.
    """

    # -- Detection over documents (ADR-0002, ADR-0014, ADR-0031) ----------
    document_detection_concurrency: int = Field(default=4, ge=1, le=64)
    """Segments detected at once, across every document in flight.

    Presidio analysis is CPU-bound and runs on a worker thread per call, so an
    unbounded fan-out over a long document asks for a thread per segment and
    starves the request path rather than finishing sooner. The bound is shared
    by the whole process, not applied per document.
    """

    max_document_entities: int = Field(default=10_000, ge=1, le=100_000)
    """Ceiling on labeled spans in one document.

    Deliberately not ``max_entities_per_request``: 500 is generous for a prompt
    and refuses an ordinary clinical document. This bound exists to stop one
    upload from becoming an unbounded batch of vault writes in the phase that
    protects it. The default matches ``MAX_POLICY_ENTITY_BUDGET``, the most a
    policy document is permitted to ask for.
    """

    @model_validator(mode="after")
    def _segments_must_be_able_to_advance(self) -> Self:
        """An overlap at or above the segment size makes segmentation stall.

        Caught here rather than at the first upload, because the failure would
        otherwise be a hang in a request rather than a refusal at startup.
        """
        if self.segment_overlap_characters >= self.segment_max_characters:
            raise ValueError(
                "SEGMENT_OVERLAP_CHARACTERS must be smaller than SEGMENT_MAX_CHARACTERS"
            )
        return self

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

    @field_validator("object_store_access_key_id", "object_store_secret_access_key", mode="before")
    @classmethod
    def _blank_credential_is_absent(cls, value: object) -> object:
        """Treat an empty environment variable as unset, not as an empty secret.

        ``OBJECT_STORE_ACCESS_KEY_ID=`` and an absent variable mean the same
        thing to an operator, and every templating layer that renders an unset
        value -- Compose's ``${VAR:-}``, Helm, Terraform -- produces the empty
        string. Without this they mean opposite things to botocore: absent
        selects the default credential chain, while empty is a credential, so
        requests get signed with nothing and fail authentication instead of
        falling back to the instance role. The provider validation above would
        also read it as "credentials supplied" and stop asking for real ones.
        """
        if isinstance(value, str) and not value.strip():
            return None
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
    def _load_document_key_ring(self) -> Self:
        """Read ``DOCUMENT_KEY_<ID>`` variables into the document key ring."""
        import os

        if not self.document_keys:
            discovered = {
                name.removeprefix("DOCUMENT_KEY_").lower(): SecretStr(raw)
                for name, raw in os.environ.items()
                if name.startswith("DOCUMENT_KEY_") and raw
            }
            object.__setattr__(self, "document_keys", discovered)
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

        if self.documents_enabled:
            problems.extend(self._document_storage_problems())

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

    def _document_storage_problems(self) -> list[str]:
        """Production refuses to accept uploads it cannot protect or store."""
        problems: list[str] = []

        active = self.document_keys.get(self.document_active_key_id.lower())
        if active is None:
            problems.append(
                "no DOCUMENT_KEY_ entry matches "
                f"DOCUMENT_ACTIVE_KEY_ID={self.document_active_key_id!r}"
            )
        else:
            problems.extend(
                problem.replace("vault key", "document key")
                for problem in self._vault_key_problems(active)
            )

        if not self.object_store_bucket:
            problems.append("OBJECT_STORE_BUCKET must be set when DOCUMENTS_ENABLED is true")

        problems.extend(self._object_store_provider_problems())

        for name, secret in (
            ("OBJECT_STORE_ACCESS_KEY_ID", self.object_store_access_key_id),
            ("OBJECT_STORE_SECRET_ACCESS_KEY", self.object_store_secret_access_key),
        ):
            if secret is not None and secret.get_secret_value() in DEVELOPMENT_PLACEHOLDERS:
                problems.append(f"{name} is still a development placeholder")

        return problems

    def _object_store_provider_problems(self) -> list[str]:
        """Check endpoint and credentials against the declared provider.

        Each rule exists because the failure it prevents is quiet. A deployment
        pointed at a compatible service that forgets its endpoint does not
        error -- botocore resolves real AWS S3 and the gateway tries to store
        documents in an account nobody intended, with credentials meant for
        somewhere else. An AWS deployment that keeps a stale endpoint from an
        old ``.env`` sends production traffic to a host that is not there.
        Neither is visible in a health check that only proves the client was
        constructible.
        """
        has_id = self.object_store_access_key_id is not None
        has_secret = self.object_store_secret_access_key is not None

        if self.object_store_provider is ObjectStoreProvider.COMPATIBLE:
            problems = []
            if not self.object_store_endpoint_url:
                problems.append(
                    "OBJECT_STORE_ENDPOINT_URL must be set when "
                    "OBJECT_STORE_PROVIDER is 'compatible'"
                )
            if not has_id:
                problems.append(
                    "OBJECT_STORE_ACCESS_KEY_ID must be set when "
                    "OBJECT_STORE_PROVIDER is 'compatible'"
                )
            if not has_secret:
                problems.append(
                    "OBJECT_STORE_SECRET_ACCESS_KEY must be set when "
                    "OBJECT_STORE_PROVIDER is 'compatible'"
                )
            return problems

        problems = []
        if self.object_store_endpoint_url:
            problems.append(
                "OBJECT_STORE_ENDPOINT_URL must not be set when OBJECT_STORE_PROVIDER is 'aws'"
            )
        # Both or neither. One alone is not a working credential, and botocore
        # would fall through to the default chain and use an identity the
        # operator did not think they were using.
        if has_id != has_secret:
            problems.append(
                "OBJECT_STORE_ACCESS_KEY_ID and OBJECT_STORE_SECRET_ACCESS_KEY "
                "must be set together, or both left unset to use the AWS "
                "default credential chain"
            )
        return problems

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
    def object_store_uses_path_style(self) -> bool:
        """Resolve bucket addressing, honouring an explicit override.

        The provider decides only when nothing was stated. Keeping the override
        meaningful matters: an S3-compatible service behind a VPC endpoint can
        need path style while still being AWS, and a provider enum that silently
        overruled the operator would make that deployment unreachable.
        """
        if self.object_store_use_path_style is not None:
            return self.object_store_use_path_style
        return self.object_store_provider is ObjectStoreProvider.COMPATIBLE

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

    def document_key(self, key_id: str) -> bytes:
        """Return a specific document key so documents sealed earlier still open."""
        secret = self.document_keys.get(key_id.lower())
        if secret is None:
            raise ValueError("the requested document key id is not present in the key ring")
        return base64.b64decode(secret.get_secret_value(), validate=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton.

    Tests call ``get_settings.cache_clear()`` after patching the environment.
    """
    return Settings()
