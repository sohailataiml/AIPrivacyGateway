"""The provider seam: one Protocol, one model allowlist, one error mapping.

Every adapter in this package obeys the same rule. ``complete`` accepts a
:class:`~app.domain.models.ProtectedChatRequest` and nothing else -- not
``ChatRequest``, not ``str``, not ``dict``, and no ``**kwargs`` that could smuggle
raw text past detection and tokenization. Because the protected and raw request
types share no ancestor, "the gateway never sends raw data to a provider" is a
property a type checker can prove rather than one a reviewer has to remember.

Two more rules follow from that one:

* An adapter takes its endpoint, credentials, and model ids from server-side
  configuration. Nothing routable or authenticating ever comes from a request.
* Nothing here logs message content, tokens, or credentials. Adapters call
  :func:`silence_transport_logging` so a third-party SDK cannot do it either.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol, runtime_checkable

from app.domain.errors import (
    GatewayError,
    ModelNotAllowedError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from app.domain.models import ProtectedChatRequest, ProviderResponse

# ---------------------------------------------------------------------------
# Retry and deadline policy
# ---------------------------------------------------------------------------
RETRYABLE_STATUS_CODES: Final[frozenset[int]] = frozenset({408, 429, 500, 502, 503, 504})
"""Statuses that may be safely re-sent. Authentication, authorization, and
invalid-input responses are absent on purpose: retrying them cannot succeed and
would only multiply load against the provider."""

TIMEOUT_STATUS_CODES: Final[frozenset[int]] = frozenset({408, 504})

DEFAULT_RETRY_BACKOFF_BASE_SECONDS: Final[float] = 0.25
RETRY_BACKOFF_MULTIPLIER: Final[float] = 2.0
RETRY_BACKOFF_MAX_SECONDS: Final[float] = 8.0
DEADLINE_SLACK_SECONDS: Final[float] = 1.0
"""Head-room added to the computed overall deadline so the per-attempt read
timeout, not the outer deadline, is what normally fires first."""

# ---------------------------------------------------------------------------
# Logging containment
# ---------------------------------------------------------------------------
TRANSPORT_LOGGER_NAMES: Final[tuple[str, ...]] = (
    "openai",
    "openai._base_client",
    "httpx",
    "httpcore",
)
MIN_TRANSPORT_LOG_LEVEL: Final[int] = logging.WARNING

_SAFE_ALIAS_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
_REDACTED_ALIAS: Final[str] = "<unloggable>"


def silence_transport_logging() -> None:
    """Stop HTTP client debug logging from emitting prompt or response bodies.

    The OpenAI SDK and httpx both log full request options at ``DEBUG``. An
    operator who turns on debug logging for the application would otherwise get
    protected message content in the log stream. Raising these loggers to
    ``WARNING`` makes that impossible; levels already at ``WARNING`` or stricter
    are left alone.
    """
    for name in TRANSPORT_LOGGER_NAMES:
        logger = logging.getLogger(name)
        if logger.level == logging.NOTSET or logger.level < MIN_TRANSPORT_LOG_LEVEL:
            logger.setLevel(MIN_TRANSPORT_LOG_LEVEL)


def safe_alias_for_log(alias: str) -> str:
    """Return ``alias`` only if it is plainly an identifier.

    Provider and model aliases arrive from caller-supplied request fields. An
    operator wants to see which alias was refused, but a caller must not be able
    to write arbitrary text -- or a copied-in secret -- into the log stream.
    """
    return alias if _SAFE_ALIAS_PATTERN.match(alias) else _REDACTED_ALIAS


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------
def is_retryable_status(status_code: int) -> bool:
    """Whether a provider status may be retried. See ``RETRYABLE_STATUS_CODES``."""
    return status_code in RETRYABLE_STATUS_CODES


def error_for_status(status_code: int, *, alias: str, attempts: int) -> GatewayError:
    """Map a provider HTTP status onto a domain error.

    ``log_context`` carries the status, the adapter alias, and the attempt count
    -- never a response body, a header, or a credential. Provider bodies can echo
    submitted content, so they are dropped rather than forwarded.
    """
    context: dict[str, Any] = {
        "provider_alias": safe_alias_for_log(alias),
        "provider_status": status_code,
        "attempts": attempts,
    }
    if status_code in TIMEOUT_STATUS_CODES:
        return ProviderTimeoutError(log_context=context)
    return ProviderUnavailableError(log_context=context)


def retry_backoff_seconds(attempt: int, *, base_seconds: float) -> float:
    """Exponential backoff for a zero-indexed attempt, capped."""
    return min(base_seconds * RETRY_BACKOFF_MULTIPLIER**attempt, RETRY_BACKOFF_MAX_SECONDS)


def overall_deadline_seconds(
    *,
    connect_timeout_seconds: float,
    read_timeout_seconds: float,
    max_retries: int,
    backoff_base_seconds: float = DEFAULT_RETRY_BACKOFF_BASE_SECONDS,
) -> float:
    """Budget for one ``complete`` call including every retry and every sleep.

    Connect and read timeouts bound a single attempt. Without an outer bound, a
    provider that stalls just under the read timeout on each attempt could hold a
    request open for the sum of all of them, so the deadline is derived from that
    worst case rather than guessed.
    """
    attempts = max_retries + 1
    attempt_budget = attempts * (connect_timeout_seconds + read_timeout_seconds)
    backoff_budget = sum(
        retry_backoff_seconds(attempt, base_seconds=backoff_base_seconds)
        for attempt in range(max_retries)
    )
    return attempt_budget + backoff_budget + DEADLINE_SLACK_SECONDS


# ---------------------------------------------------------------------------
# Model allowlist
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ModelCatalog:
    """Server-controlled map from a public model alias to a provider model id.

    The provider model id is never read from a request. A caller picks an alias;
    configuration decides what that alias means. Swapping the model behind an
    alias is then a deployment change, not an API change.
    """

    entries: Mapping[str, str]

    @classmethod
    def from_mapping(cls, entries: Mapping[str, str]) -> ModelCatalog:
        """Build a catalog with case-insensitive aliases."""
        return cls(entries={alias.strip().lower(): model_id for alias, model_id in entries.items()})

    def resolve(self, alias: str) -> str:
        """Return the provider model id for ``alias``.

        Raises:
            ModelNotAllowedError: if the alias is not configured for this adapter.
        """
        model_id = self.entries.get(alias.strip().lower())
        if model_id is None:
            raise ModelNotAllowedError(
                log_context={"model_alias": safe_alias_for_log(alias)},
            )
        return model_id

    def aliases(self) -> tuple[str, ...]:
        return tuple(sorted(self.entries))


# ---------------------------------------------------------------------------
# The provider seam
# ---------------------------------------------------------------------------
@runtime_checkable
class LLMProvider(Protocol):
    """The only interface the pipeline uses to reach a model.

    Implementations must not add parameters to ``complete``. Every knob a caller
    is allowed to turn already lives on ``ProtectedChatRequest``; anything else
    belongs to adapter configuration.
    """

    alias: str
    """Stable server-side name this adapter is registered under."""

    async def complete(self, request: ProtectedChatRequest) -> ProviderResponse: ...


def ensure_protected_request(request: object) -> ProtectedChatRequest:
    """Reject anything that is not a fully processed request.

    Static typing already forbids handing a raw ``ChatRequest``, a ``str``, or a
    ``dict`` to an adapter. This is the runtime backstop for untyped call sites:
    reaching it means a caller bypassed the pipeline, which is a defect in the
    gateway rather than a caller error, so it raises ``TypeError`` instead of a
    ``GatewayError`` and surfaces as an internal error.
    """
    if not isinstance(request, ProtectedChatRequest):
        raise TypeError(
            "a provider adapter accepts only ProtectedChatRequest; "
            f"received {type(request).__name__}"
        )
    return request
