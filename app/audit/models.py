"""The audit event domain model.

``AuditRecord`` is the only shape the audit service accepts. It is the second
enforcement point for the prohibited-field list in architecture.md section 9.9
and implementation.md section 17 -- the first being the database table itself.

Two mechanisms keep it honest:

1. **Shape.** The field set is frozen against :data:`ALLOWED_FIELD_NAMES` and
   screened against :data:`PROHIBITED_FIELD_SUBSTRINGS` at import time. Adding a
   ``prompt_text``, ``original_value``, or ``mapping`` field raises before the
   process can serve a request, and trips ``tests/unit/test_audit.py``.
2. **Contents.** Every field that could carry free text is narrowed. Digests
   must be lowercase hex, aliases and codes must match a conservative identifier
   charset, and the two JSON columns are ``str -> int`` maps. There is no field
   on this model that a caller could stuff a prompt into, even by accident.

Nothing here logs, and nothing here holds a secret.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime
from typing import Final
from uuid import UUID

from app.domain.models import PrivacySummary

MAX_KEY_CHARS: Final = 64
MAX_PROVIDER_ALIAS_CHARS: Final = 64
MAX_MODEL_ALIAS_CHARS: Final = 128
MAX_CODE_CHARS: Final = 64
MAX_DIGEST_CHARS: Final = 128
MIN_DIGEST_CHARS: Final = 32
MIN_STATUS_CODE: Final = 100
MAX_STATUS_CODE: Final = 599

_HEX_PATTERN: Final = re.compile(r"\A[0-9a-f]+\Z")
"""Digest fields accept lowercase hex and nothing else."""

_CODE_PATTERN: Final = re.compile(r"\A[A-Za-z0-9._:-]{1,64}\Z")
"""Aliases and codes: identifier-shaped, so prose cannot be smuggled through."""

_COUNT_KEY_PATTERN: Final = re.compile(r"\A[A-Za-z0-9_]{1,64}\Z")
"""Entity-type and action names. Names only -- the values they stood for never
reach this module."""

ALLOWED_FIELD_NAMES: Final[frozenset[str]] = frozenset(
    {
        "occurred_at",
        "tenant_id",
        "request_id",
        "api_key_id",
        "session_id_hash",
        "policy_id",
        "policy_version",
        "provider_alias",
        "model_alias",
        "input_character_count",
        "output_character_count",
        "entity_counts",
        "actions",
        "blocked",
        "block_reason_code",
        "provider_latency_ms",
        "pipeline_latency_ms",
        "status_code",
        "error_code",
        "prompt_hmac",
        "response_hmac",
    }
)
"""Every field ``AuditRecord`` is permitted to declare.

Exhaustive on purpose. A new field is a deliberate act that has to be added
here, which is the moment to ask whether it can hold sensitive text.
"""

PROHIBITED_FIELD_SUBSTRINGS: Final[tuple[str, ...]] = (
    "content",
    "body",
    "text",
    "message",
    "prompt_raw",
    "response_raw",
    "original",
    "plaintext",
    "decrypted",
    "mapping",
    "token",
    "secret",
    "credential",
    "password",
    "value",
    "payload",
)
"""Name fragments that describe the prohibited categories.

A second net under the allowlist: it catches a field whose name announces that
it holds raw content, a mapping, a complete gateway token, or a credential --
even if somebody also added that name to the allowlist above.
"""


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """A privacy-safe description of one completed request.

    Immutable: the audit path hands the same instance to a queue, a metric, and
    a repository, and none of them may edit what the others see.
    """

    tenant_id: UUID
    request_id: UUID
    status_code: int
    occurred_at: datetime | None = None
    api_key_id: UUID | None = None
    session_id_hash: str | None = None
    policy_id: UUID | None = None
    policy_version: int | None = None
    provider_alias: str | None = None
    model_alias: str | None = None
    input_character_count: int = 0
    output_character_count: int = 0
    entity_counts: Mapping[str, int] = field(default_factory=dict)
    actions: Mapping[str, int] = field(default_factory=dict)
    blocked: bool = False
    block_reason_code: str | None = None
    provider_latency_ms: int | None = None
    pipeline_latency_ms: int | None = None
    error_code: str | None = None
    prompt_hmac: str | None = None
    response_hmac: str | None = None

    def __post_init__(self) -> None:
        if not MIN_STATUS_CODE <= self.status_code <= MAX_STATUS_CODE:
            raise ValueError("status_code must be a valid HTTP status")
        if self.occurred_at is not None and self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")

        _require_non_negative(self.input_character_count, "input_character_count")
        _require_non_negative(self.output_character_count, "output_character_count")
        for name in ("policy_version", "provider_latency_ms", "pipeline_latency_ms"):
            optional: int | None = getattr(self, name)
            if optional is not None:
                _require_non_negative(optional, name)

        _require_code(self.provider_alias, "provider_alias", MAX_PROVIDER_ALIAS_CHARS)
        _require_code(self.model_alias, "model_alias", MAX_MODEL_ALIAS_CHARS)
        _require_code(self.block_reason_code, "block_reason_code", MAX_CODE_CHARS)
        _require_code(self.error_code, "error_code", MAX_CODE_CHARS)

        _require_digest(self.session_id_hash, "session_id_hash", maximum=MAX_KEY_CHARS)
        _require_digest(self.prompt_hmac, "prompt_hmac")
        _require_digest(self.response_hmac, "response_hmac")

        # Normalize to plain dicts so the record owns its own copies and a
        # caller cannot mutate a queued event after submitting it.
        object.__setattr__(self, "entity_counts", _validated_counts(self.entity_counts, "entity"))
        object.__setattr__(self, "actions", _validated_counts(self.actions, "action"))

    @classmethod
    def field_names(cls) -> frozenset[str]:
        """The declared field set. Used by the prohibited-field regression test."""
        return frozenset(field.name for field in fields(cls))

    def __repr__(self) -> str:
        # Counts and identifiers only, so an accidental repr() in a traceback
        # stays as safe as the record itself.
        return (
            f"AuditRecord(request_id={self.request_id!s}, status_code={self.status_code}, "
            f"blocked={self.blocked}, detected={sum(self.entity_counts.values())})"
        )


def counts_from_summary(summary: PrivacySummary) -> tuple[dict[str, int], dict[str, int]]:
    """Project a :class:`PrivacySummary` onto the two audit count maps.

    Returns ``(entity_counts, actions)``. Both are counts keyed by a name; no
    value that was detected, tokenized, or restored appears in either.
    """
    entity_counts = {name: int(count) for name, count in summary.entity_types.items()}
    actions = {
        "detected": summary.detected,
        "tokenized": summary.tokenized,
        "redacted": summary.redacted,
        "pseudonymized": summary.pseudonymized,
        "blocked": summary.blocked,
        "allowed": summary.allowed,
        "restored": summary.restored,
        "unknown_tokens": summary.unknown_tokens,
    }
    return entity_counts, actions


def _require_non_negative(value: int, name: str) -> None:
    if value < 0:
        raise ValueError(f"{name} must not be negative")


def _require_code(value: str | None, name: str, maximum: int) -> None:
    if value is None:
        return
    if len(value) > maximum or _CODE_PATTERN.match(value) is None:
        raise ValueError(f"{name} must be a short identifier-shaped code")


def _require_digest(value: str | None, name: str, *, maximum: int = MAX_DIGEST_CHARS) -> None:
    """Digest fields hold keyed HMAC output, never text that produced it."""
    if value is None:
        return
    if not MIN_DIGEST_CHARS <= len(value) <= maximum or _HEX_PATTERN.match(value) is None:
        raise ValueError(f"{name} must be lowercase hexadecimal digest output")


def _validated_counts(counts: Mapping[str, int], kind: str) -> Mapping[str, int]:
    if not counts:
        return {}
    validated: dict[str, int] = {}
    for key, count in dict(counts).items():
        if _COUNT_KEY_PATTERN.match(key) is None:
            raise ValueError(f"{kind} count keys must be short identifier-shaped names")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError(f"{kind} counts must be non-negative integers")
        validated[key] = count
    return validated


def enforce_field_policy(declared: Iterable[str]) -> None:
    """Raise if a field set steps outside the audit allowlist.

    Public so the regression test can prove the screen actually rejects a
    prohibited name rather than trusting that it would.
    """
    declared = frozenset(declared)

    unexpected = sorted(declared - ALLOWED_FIELD_NAMES)
    if unexpected:
        raise RuntimeError(
            "AuditRecord declares fields that are not on the audit allowlist: "
            + ", ".join(unexpected)
        )

    offending = sorted(
        name
        for name in declared
        for fragment in PROHIBITED_FIELD_SUBSTRINGS
        if fragment in name.casefold()
    )
    if offending:
        raise RuntimeError(
            "AuditRecord declares fields whose names describe prohibited content: "
            + ", ".join(offending)
        )


enforce_field_policy(AuditRecord.field_names())
