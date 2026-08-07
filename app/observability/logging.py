"""Structured logging configured to be incapable of emitting request content.

The gateway's whole value proposition is that sensitive text does not escape.
Logging is the easiest way to break that, so this module takes a deny-by-default
stance: a processor drops any event key that is not on an allowlist, and a
second processor scrubs values that look like credentials or gateway tokens.

If you need a new field in the logs, add it to ``ALLOWED_EVENT_KEYS`` explicitly
and think about what could end up in it.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any, Final

import structlog
from structlog.typing import EventDict, WrappedLogger

# Only these keys survive into a log record. Everything else is dropped.
ALLOWED_EVENT_KEYS: Final[frozenset[str]] = frozenset(
    {
        # structlog/stdlib machinery
        "event",
        "level",
        "logger",
        "timestamp",
        "exc_info",
        "exception",
        "stack_info",
        # request correlation
        "request_id",
        "session_id",
        "tenant_id",
        "api_key_id",
        "api_key_prefix",
        "method",
        "path",
        "status_code",
        "duration_ms",
        # domain outcome
        "error_code",
        "reason",
        "stage",
        "provider_alias",
        "model_alias",
        "policy_version",
        "entity_type",
        "recognizer",
        "action",
        # counts -- never values
        "detected",
        "tokenized",
        "redacted",
        "pseudonymized",
        "blocked",
        "allowed",
        "restored",
        "unknown_tokens",
        "entity_count",
        "attempt",
        "retry_after",
        "key_id",
        # Document pipeline. Every one of these is Internal by
        # docs/data-classification.md -- an opaque id, a declared MIME type, or
        # a count. The filename is Restricted and is deliberately *not* here.
        #
        # They were missing until the detection phase, so every document log line
        # silently lost its fields to the allowlist and reported nothing an
        # operator could correlate to a document. Deny-by-default failed safe,
        # which is why nothing broke and nobody noticed; PROGRESS.md defect 20.
        "document_id",
        "content_type",
        "byte_size",
        "page_count",
        "character_count",
        "segment_count",
        "removed",
        "limit",
        "page_index",
        "timeout_seconds",
        "operation",
        "failure_type",
        # Policy management (ADR-0037). Names, version numbers, counts, and
        # outcomes -- all Internal. The policy *document* is not here and never
        # will be: an operator may type a real identifier into a rule's
        # description while drafting, so the document is data this allowlist
        # exists to keep out of logs, not metadata to correlate on.
        "policy_name",
        "from_version",
        "to_version",
        "policy_status",
        "change_count",
        "valid",
        "problem_count",
        "warning_count",
    }
)

DROPPED_KEY_MARKER: Final = "_dropped_keys"
REDACTED: Final = "[redacted]"

# Belt and braces: even an allowlisted field gets scrubbed if its value looks
# like a credential or a gateway token.
_SCRUB_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"⟦SGW:[A-Z0-9_]{1,64}:[0-9A-HJKMNP-TV-Z]{26}⟧"),
    re.compile(r"sgw_(?:live|test)_[A-Za-z0-9_\-]+"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]+", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\d[ \-]?){13,19}\b"),
)


def drop_unlisted_keys(_logger: WrappedLogger, _name: str, event_dict: EventDict) -> EventDict:
    """Remove every key that is not explicitly allowed.

    A dropped key is reported by name only, so an operator can see that a call
    site tried to log something unexpected without the value being written.
    """
    dropped = [key for key in event_dict if key not in ALLOWED_EVENT_KEYS]
    if not dropped:
        return event_dict

    cleaned = {key: value for key, value in event_dict.items() if key in ALLOWED_EVENT_KEYS}
    cleaned[DROPPED_KEY_MARKER] = sorted(dropped)
    return cleaned


def scrub_values(_logger: WrappedLogger, _name: str, event_dict: EventDict) -> EventDict:
    """Replace credential- and token-shaped substrings in any string value."""
    scrubbed: EventDict = {}
    for key, value in event_dict.items():
        scrubbed[key] = _scrub(value) if isinstance(value, str) else value
    return scrubbed


def _scrub(value: str) -> str:
    for pattern in _SCRUB_PATTERNS:
        value = pattern.sub(REDACTED, value)
    return value


def configure_logging(*, level: str = "INFO", json_output: bool = True) -> None:
    """Install the logging pipeline. Call once during application startup."""
    numeric_level = logging.getLevelNamesMapping()[level.upper()]

    # Route through stdlib logging so uvicorn's own records pass through the
    # same handler, and so add_logger_name has a real logger to read a name from.
    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=numeric_level, force=True)

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        drop_unlisted_keys,
        scrub_values,
    ]
    processors.append(
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=False)
    )

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a bound logger. Prefer module-level ``__name__``."""
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger
