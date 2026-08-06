"""Request-path Prometheus metrics.

Same cardinality rule as :mod:`app.vault.metrics` and :mod:`app.auth.metrics`: a
label value comes from a set closed at import time, and the recorder functions
raise on anything else so a dynamic string fails a test rather than growing the
registry in production.

Three of the label sets here are enums or frozensets defined in this repository
(:class:`~app.pipeline.stages.PipelineStage`, the outcome names below, the
refusal reasons below). The fourth, ``provider``, is the alias an adapter is
*registered* under, which comes from deployment configuration and is fixed when
the registry is built. Deliberately not labelled: the model alias. It reaches
the provider stage caller-supplied and is only validated inside the adapter's
own catalog, so labelling by it would let a caller mint series. The model of
record for a request is in its audit row, which is the right place for a value
that varies per request.

Nothing here accepts message content, an original value, a token, a tenant, or a
session. Only stage names, outcome names, and numbers.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

from prometheus_client import Counter, Histogram

from app.domain.errors import (
    EntityLimitExceededError,
    GatewayError,
    ModelNotAllowedError,
    PolicyNotFoundError,
    PolicyViolationError,
    ProviderNotAllowedError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from app.pipeline.stages import DEADLINE_EXCEEDED, PipelineStage

# -- Closed label sets --------------------------------------------------------
OUTCOME_SUCCESS: Final = "success"
OUTCOME_DEADLINE_EXCEEDED: Final = "deadline_exceeded"
OUTCOME_FAILED: Final = "failed"

STAGE_OUTCOMES: Final[frozenset[str]] = frozenset(
    {OUTCOME_SUCCESS, OUTCOME_DEADLINE_EXCEEDED, OUTCOME_FAILED}
)

PROVIDER_RESULT_SUCCESS: Final = "success"
PROVIDER_RESULT_TIMEOUT: Final = "timeout"
PROVIDER_RESULT_UNAVAILABLE: Final = "unavailable"
PROVIDER_RESULT_CANCELLED: Final = "cancelled"
PROVIDER_RESULT_ERROR: Final = "error"

PROVIDER_RESULTS: Final[frozenset[str]] = frozenset(
    {
        PROVIDER_RESULT_SUCCESS,
        PROVIDER_RESULT_TIMEOUT,
        PROVIDER_RESULT_UNAVAILABLE,
        PROVIDER_RESULT_CANCELLED,
        PROVIDER_RESULT_ERROR,
    }
)

REASON_BLOCKED_ENTITY: Final = "blocked_entity"
REASON_ENTITY_LIMIT: Final = "entity_limit_exceeded"
REASON_PROVIDER_NOT_ALLOWED: Final = "provider_not_allowed"
REASON_MODEL_NOT_ALLOWED: Final = "model_not_allowed"
REASON_POLICY_NOT_FOUND: Final = "policy_not_found"

REFUSAL_REASONS: Final[frozenset[str]] = frozenset(
    {
        REASON_BLOCKED_ENTITY,
        REASON_ENTITY_LIMIT,
        REASON_PROVIDER_NOT_ALLOWED,
        REASON_MODEL_NOT_ALLOWED,
        REASON_POLICY_NOT_FOUND,
    }
)

_REFUSAL_BY_ERROR: Final[tuple[tuple[type[GatewayError], str], ...]] = (
    # Ordered most specific first; the first match wins.
    (PolicyViolationError, REASON_BLOCKED_ENTITY),
    (EntityLimitExceededError, REASON_ENTITY_LIMIT),
    (ModelNotAllowedError, REASON_MODEL_NOT_ALLOWED),
    (ProviderNotAllowedError, REASON_PROVIDER_NOT_ALLOWED),
    (PolicyNotFoundError, REASON_POLICY_NOT_FOUND),
)
"""Which refusals count as a policy block.

Deriving the reason from the error type keeps every raise site free of a metrics
import -- ``app.policy`` and ``app.pipeline.guards`` stay unaware that metrics
exist -- and makes the label set closed by construction: it is a tuple of
classes, not a string a call site chooses.

Absent on purpose: ``RequestTooLargeError``. An oversized message is a
deployment ceiling rather than a policy decision, and it already shows up as an
HTTP 413 in ``sgw_http_requests_total``.
"""

# -- Instruments --------------------------------------------------------------
PIPELINE_STAGE_SECONDS: Final = Histogram(
    "sgw_pipeline_stage_duration_seconds",
    "Time spent in one pipeline stage. Detection and tokenization are observed "
    "once per message, every other stage once per request.",
    labelnames=("stage",),
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)

PIPELINE_STAGE_TOTAL: Final = Counter(
    "sgw_pipeline_stage_total",
    "Pipeline stage executions by outcome.",
    labelnames=("stage", "outcome"),
)

POLICY_BLOCKS_TOTAL: Final = Counter(
    "sgw_policy_blocks_total",
    "Requests refused by policy, by reason.",
    labelnames=("reason",),
)

PROVIDER_REQUESTS_TOTAL: Final = Counter(
    "sgw_provider_requests_total",
    "Provider calls by registered adapter alias and result.",
    labelnames=("provider", "result"),
)

PROVIDER_DURATION_SECONDS: Final = Histogram(
    "sgw_provider_duration_seconds",
    "Provider call latency, including the adapter's own retries and backoff.",
    labelnames=("provider",),
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0),
)

RESTORATION_UNKNOWN_TOKENS_TOTAL: Final = Counter(
    "sgw_restoration_unknown_tokens_total",
    "Tokens present in provider output that resolved to no vault mapping. "
    "A sustained non-zero rate means mappings are expiring inside a conversation.",
)


def _checked(value: str, allowed: frozenset[str], what: str) -> str:
    if value not in allowed:
        raise ValueError(f"{what} label must be one of {sorted(allowed)}")
    return value


def record_stage(*, stage: PipelineStage, outcome: str, duration_seconds: float) -> None:
    """Record one stage execution.

    Args:
        stage: A ``PipelineStage`` member, not a string, so the label set stays
            closed even if a caller has a stage name in hand.
        outcome: One of :data:`STAGE_OUTCOMES`.
        duration_seconds: Wall time the stage took, successful or not.

    Raises:
        TypeError: if ``stage`` is not a ``PipelineStage``.
        ValueError: if ``outcome`` is outside :data:`STAGE_OUTCOMES`.
    """
    if not isinstance(stage, PipelineStage):
        raise TypeError("stage must be a PipelineStage member so the label set stays closed")
    label = str(stage)
    PIPELINE_STAGE_SECONDS.labels(stage=label).observe(duration_seconds)
    PIPELINE_STAGE_TOTAL.labels(
        stage=label, outcome=_checked(outcome, STAGE_OUTCOMES, "stage outcome")
    ).inc()


def refusal_reason(error: BaseException) -> str | None:
    """Return the policy-block reason for ``error``, or ``None`` if it is not one.

    A failure that is not a refusal -- a detector outage, a provider timeout --
    returns ``None`` and is left to the stage counter, which is where an
    operator looks for a dependency problem rather than a policy decision.
    """
    for error_type, reason in _REFUSAL_BY_ERROR:
        if isinstance(error, error_type):
            return reason
    return None


def record_refusal(error: BaseException) -> None:
    """Count ``error`` as a policy block if it is one, otherwise do nothing."""
    reason = refusal_reason(error)
    if reason is not None:
        POLICY_BLOCKS_TOTAL.labels(
            reason=_checked(reason, REFUSAL_REASONS, "policy block reason")
        ).inc()


def record_provider_call(*, provider: str, result: str, duration_seconds: float) -> None:
    """Record one provider call.

    Args:
        provider: The alias the adapter is *registered* under -- read it from
            the adapter, never from the request, so the label cannot be chosen
            by a caller.
        result: One of :data:`PROVIDER_RESULTS`.
        duration_seconds: Wall time including retries and backoff.

    Raises:
        ValueError: if ``result`` is outside :data:`PROVIDER_RESULTS`.
    """
    PROVIDER_REQUESTS_TOTAL.labels(
        provider=provider, result=_checked(result, PROVIDER_RESULTS, "provider result")
    ).inc()
    PROVIDER_DURATION_SECONDS.labels(provider=provider).observe(duration_seconds)


def record_unknown_tokens(count: int) -> None:
    """Count tokens in provider output that no mapping could resolve."""
    if count > 0:
        RESTORATION_UNKNOWN_TOKENS_TOTAL.inc(count)


# -- Timing wrappers ----------------------------------------------------------
#
# Both are context managers rather than decorators so a call site keeps the
# stage's own ``await`` visible. Both record in a ``finally``, so a stage that
# raises, times out, or is cancelled is still measured -- a histogram that only
# sees successes reports a system as fast precisely when it is failing.
def _stage_outcome(error: BaseException) -> str:
    """Classify a stage failure without inspecting the exception's message."""
    if isinstance(error, GatewayError) and error.log_context.get("reason") == DEADLINE_EXCEEDED:
        return OUTCOME_DEADLINE_EXCEEDED
    return OUTCOME_FAILED


@contextmanager
def observe_stage(stage: PipelineStage) -> Iterator[None]:
    """Time one stage and classify how it ended."""
    started = time.perf_counter()
    outcome = OUTCOME_SUCCESS
    try:
        yield
    except BaseException as exc:
        outcome = _stage_outcome(exc)
        raise
    finally:
        record_stage(
            stage=stage,
            outcome=outcome,
            duration_seconds=max(time.perf_counter() - started, 0.0),
        )


def _provider_result(error: BaseException) -> str:
    """Classify a provider failure by exception type only."""
    if isinstance(error, ProviderTimeoutError):
        return PROVIDER_RESULT_TIMEOUT
    if isinstance(error, ProviderUnavailableError):
        return PROVIDER_RESULT_UNAVAILABLE
    if isinstance(error, GatewayError):
        return PROVIDER_RESULT_ERROR
    # Not a GatewayError: almost always the request deadline cancelling the
    # call from outside. Recorded distinctly, because "we gave up on the
    # provider" and "the provider failed" have different remedies.
    return PROVIDER_RESULT_CANCELLED


@contextmanager
def observe_provider_call(provider: str) -> Iterator[None]:
    """Time one provider call and classify its result."""
    started = time.perf_counter()
    result = PROVIDER_RESULT_SUCCESS
    try:
        yield
    except BaseException as exc:
        result = _provider_result(exc)
        raise
    finally:
        record_provider_call(
            provider=provider,
            result=result,
            duration_seconds=max(time.perf_counter() - started, 0.0),
        )
