"""Canonical domain contracts shared by every module.

This module is the seam that lets the policy, detection, tokenization, vault,
provider, and restoration packages be built independently. Treat it as an API:
additive changes are cheap, renames are not.

The central safety property lives here. ``ChatRequest`` is raw caller input;
``ProtectedChatRequest`` is the only type a provider adapter accepts. Because
the two are distinct types with no inheritance between them, sending
unprocessed text to a provider is a type error rather than a review miss.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

MessageRole = Literal["system", "user", "assistant"]


# ---------------------------------------------------------------------------
# API boundary models
# ---------------------------------------------------------------------------
class ChatMessage(BaseModel):
    """One conversational turn. ``content`` is raw until the pipeline runs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    role: MessageRole
    content: str


class ChatRequest(BaseModel):
    """Unprocessed caller input. Never hand this to a provider adapter."""

    model_config = ConfigDict(extra="forbid")

    session_id: UUID | None = None
    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=128)
    messages: list[ChatMessage] = Field(min_length=1)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_output_tokens: int | None = Field(default=None, ge=1, le=32_768)


class ChatResponse(BaseModel):
    """Restored response returned only to the authorized request principal."""

    model_config = ConfigDict(extra="forbid")

    request_id: UUID
    session_id: UUID
    provider: str
    model: str
    message: ChatMessage
    privacy: PrivacySummary
    usage: ProviderUsage | None = None


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------
class EntityAction(StrEnum):
    """What the policy does with a detected entity."""

    ALLOW = "allow"
    """Leave the value in place. Use only for entity types that are not sensitive."""

    TOKENIZE = "tokenize"
    """Replace with a reversible opaque token backed by a vault mapping."""

    REDACT = "redact"
    """Replace with a non-reversible placeholder. No vault mapping is created."""

    PSEUDONYMIZE = "pseudonymize"
    """Replace with a stable surrogate of the same shape. Reversible via the vault."""

    BLOCK = "block"
    """Refuse the request. The provider is never called."""


class UnknownTokenAction(StrEnum):
    """What restoration does with a token-shaped string it cannot resolve."""

    PRESERVE = "preserve"
    """Leave the token text in the response. The default: it reveals nothing."""

    REDACT = "redact"
    """Replace with a placeholder."""

    FAIL = "fail"
    """Fail the request. Strictest option."""


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class DetectedEntity:
    """A span of text the detector believes is sensitive.

    Offsets are Python string indices into the exact text passed to the
    detector -- not bytes, and not offsets into any normalized form.
    """

    entity_type: str
    start: int
    end: int
    score: float
    recognizer: str | None = None
    """Populated only in diagnostic mode. Never returned by the public API."""

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError("entity span must be a non-empty forward range")
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("entity score must be within [0.0, 1.0]")

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: DetectedEntity) -> bool:
        return self.start < other.end and other.start < self.end


# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class EntityMapping:
    """A token and the original value it stands for.

    Instances exist only inside the pipeline and the vault. Never log one,
    never serialize one into an audit row, and never place one on a response.
    """

    token: str
    token_id: str
    entity_type: str
    original_value: str
    normalized_hmac: str

    def __repr__(self) -> str:
        # Defensive: a stray repr() in a traceback must not leak the original.
        return f"EntityMapping(entity_type={self.entity_type!r}, token_id={self.token_id!r})"


@dataclass(frozen=True, slots=True)
class VaultWriteRequest:
    """One mapping to mint or reuse, as handed to the vault in a batch.

    This type lives in the domain layer rather than in ``app.vault`` because it
    is the contract *between* the tokenizer and the vault, and the tokenizer
    must not import the vault package -- see ``app.tokenization.protocols``.

    Like ``EntityMapping``, an instance carries an original value and must never
    be logged or serialized.
    """

    entity_type: str
    normalized_hmac: str
    original_value: str

    def __repr__(self) -> str:
        # Defensive: a stray repr() in a traceback must not leak the original.
        return f"VaultWriteRequest(entity_type={self.entity_type!r})"


class PrivacySummary(BaseModel):
    """Counts only. This is the sole privacy detail that leaves the gateway."""

    model_config = ConfigDict(extra="forbid")

    detected: int = 0
    tokenized: int = 0
    redacted: int = 0
    pseudonymized: int = 0
    blocked: int = 0
    allowed: int = 0
    restored: int = 0
    unknown_tokens: int = 0
    entity_types: dict[str, int] = Field(default_factory=dict)
    """Count per entity type. Type names only -- never values."""

    def merged_with(self, other: PrivacySummary) -> PrivacySummary:
        """Return a new summary combining both. Neither input is mutated."""
        combined_types = dict(self.entity_types)
        for entity_type, count in other.entity_types.items():
            combined_types[entity_type] = combined_types.get(entity_type, 0) + count

        return PrivacySummary(
            detected=self.detected + other.detected,
            tokenized=self.tokenized + other.tokenized,
            redacted=self.redacted + other.redacted,
            pseudonymized=self.pseudonymized + other.pseudonymized,
            blocked=self.blocked + other.blocked,
            allowed=self.allowed + other.allowed,
            restored=self.restored + other.restored,
            unknown_tokens=self.unknown_tokens + other.unknown_tokens,
            entity_types=combined_types,
        )


@dataclass(frozen=True, slots=True)
class TransformedText:
    """Result of applying policy actions to one message."""

    text: str
    """Protected text. Safe to send to a provider."""

    mappings: tuple[EntityMapping, ...]
    summary: PrivacySummary


# ---------------------------------------------------------------------------
# Provider boundary
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ProtectedChatRequest:
    """The only request type a provider adapter accepts.

    Construction is the privacy checkpoint: an instance asserts that every
    message has already passed detection, policy, and tokenization, and that any
    resulting mappings are durably stored in the vault. Build one only in the
    pipeline, never in a router or a provider adapter.
    """

    request_id: UUID
    tenant_id: UUID
    session_id: UUID
    provider_alias: str
    model_alias: str
    messages: tuple[ChatMessage, ...]
    policy_version: int
    temperature: float | None = None
    max_output_tokens: int | None = None

    def __post_init__(self) -> None:
        if not self.messages:
            raise ValueError("a protected request must carry at least one message")


class ProviderUsage(BaseModel):
    """Token accounting reported by the provider. Contains no content."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    """Raw provider output. Still contains gateway tokens, not originals."""

    content: str
    model: str
    usage: ProviderUsage | None = None
    finish_reason: str | None = None


# ---------------------------------------------------------------------------
# Request context
# ---------------------------------------------------------------------------
class Scope(StrEnum):
    """Capabilities an API key may be granted."""

    CHAT_INVOKE = "chat:invoke"
    DETECT_INVOKE = "detect:invoke"
    SESSIONS_DELETE = "sessions:delete"
    DOCUMENTS_WRITE = "documents:write"
    DOCUMENTS_READ = "documents:read"
    DOCUMENTS_DELETE = "documents:delete"


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller. Immutable for the life of a request.

    ``api_key_id`` identifies the key record, never the key itself. There is no
    field on this type that can hold a credential.
    """

    tenant_id: UUID
    api_key_id: UUID
    api_key_prefix: str
    scopes: frozenset[Scope]

    def has_scope(self, scope: Scope) -> bool:
        return scope in self.scopes


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Correlation identifiers carried through every stage of one request."""

    request_id: UUID
    principal: Principal
    session_id: UUID
    started_at: datetime
    policy_version: int
    diagnostics_enabled: bool = False


# ---------------------------------------------------------------------------
# Detection API surface (shared by /v1/detect and the pipeline)
# ---------------------------------------------------------------------------
class DetectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1)
    language: str = Field(default="en", pattern=r"^[a-z]{2}$")
    entity_types: list[str] | None = None


class DetectedEntityView(BaseModel):
    """Public projection of a detection. Carries no matched text by default."""

    model_config = ConfigDict(extra="forbid")

    entity_type: str
    start: int
    end: int
    score: float
    action: EntityAction
    text: str | None = None
    """Populated only when privileged diagnostics are explicitly enabled."""

    @model_validator(mode="after")
    def _span_is_valid(self) -> Self:
        if self.end <= self.start:
            raise ValueError("end must be greater than start")
        return self


class DetectResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: UUID
    entities: list[DetectedEntityView] = Field(default_factory=list)
    summary: PrivacySummary = Field(default_factory=PrivacySummary)


# Resolve forward references declared before their targets.
ChatResponse.model_rebuild()
