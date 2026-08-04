"""Stage execution: one deadline, one failure translation, no leaks.

Every await in the request path goes through :func:`run_stage`, which gives the
pipeline three properties it would otherwise have to re-implement per call site:

1. **A single deadline.** The bound is absolute -- ``asyncio.timeout_at`` against
   the event loop clock -- so nesting it around each stage costs nothing and the
   sum of the stages can never exceed the request budget. This is *in addition*
   to the provider adapter's own deadline: a provider that ignores its timeout,
   or a detector that wedges, still cannot hold a request open.

2. **Fail closed.** An exception that is not already a ``GatewayError`` is
   translated into the domain error that stage is supposed to produce. Nothing
   is swallowed and nothing degrades into "no entities found".

3. **No detail escapes.** The translated error carries the stage name and a
   fixed reason code, never the original exception's message -- a third-party
   client can and does put request payloads into exception strings.

``asyncio.CancelledError`` inherits from ``BaseException``, so a real
cancellation propagates untouched rather than being reported as a stage fault.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Final

from app.domain.errors import GatewayError


class PipelineStage(StrEnum):
    """Named stages, used for log context and failure attribution."""

    POLICY = "policy"
    DETECTION = "detection"
    TOKENIZATION = "tokenization"
    PROVIDER = "provider"
    RESTORATION = "restoration"
    AUDIT = "audit"


DEADLINE_EXCEEDED: Final[str] = "deadline_exceeded"
STAGE_FAILED: Final[str] = "stage_failed"

StageFailure = Callable[[PipelineStage, str], GatewayError]
"""Builds the domain error for a stage, given the stage and a reason code."""


def stage_failure(
    error_type: type[GatewayError],
    *,
    timeout_type: type[GatewayError] | None = None,
) -> StageFailure:
    """Return a failure builder for one stage.

    Args:
        error_type: Raised when the stage fails unexpectedly.
        timeout_type: Raised instead when the failure was the deadline. Only the
            provider stage needs this -- a stalled upstream is a gateway timeout,
            while a stalled detector or vault is that dependency being down.
    """

    def build(stage: PipelineStage, reason: str) -> GatewayError:
        chosen = (
            timeout_type if reason == DEADLINE_EXCEEDED and timeout_type is not None else error_type
        )
        return chosen(log_context={"stage": str(stage), "reason": reason})

    return build


async def run_stage[T](
    awaitable: Awaitable[T],
    *,
    stage: PipelineStage,
    deadline: float,
    failure: StageFailure,
) -> T:
    """Await one stage under the request deadline, failing closed.

    Args:
        awaitable: The stage's work. Not started until awaited here.
        stage: Which stage this is, for log context.
        deadline: Absolute event-loop time the whole request must finish by.
        failure: Builds the domain error this stage raises.

    Returns:
        Whatever the stage returned.

    Raises:
        GatewayError: unchanged if the stage raised one; otherwise built by
            ``failure`` from the deadline or the unexpected exception.
    """
    try:
        async with asyncio.timeout_at(deadline):
            return await awaitable
    except GatewayError:
        # Already a domain error with a vetted public message. Passing it
        # through keeps "vault down" from being reported as "detector down".
        raise
    except TimeoutError as exc:
        raise failure(stage, DEADLINE_EXCEEDED) from exc
    except Exception as exc:
        # Converted, never propagated raw: an arbitrary exception reaching the
        # API layer would be rendered with a message nobody has reviewed.
        raise failure(stage, STAGE_FAILED) from exc
