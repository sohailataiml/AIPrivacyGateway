"""Whole-request guards that run before anything is written or sent.

The tokenizer already refuses an over-budget or blocked *message*. That is not
sufficient here: a request is a set of messages, and enforcing per message would
let a caller split five hundred values across five turns, and would let a block
in the last message land only after the first four had already written mappings
into the vault.

So these run as a pre-pass over every message's detections, before the first
vault call:

1. message sizes, against the deployment's ceiling;
2. the entity budget, summed across the whole request;
3. blocked entity types, anywhere in the request.

Selection is pure and deterministic, so running it here and again inside the
tokenizer costs a little CPU and buys the guarantee that a request destined to
fail leaves nothing behind -- no mapping, no ciphertext, no TTL to wait out.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.domain.errors import (
    EntityLimitExceededError,
    PolicyViolationError,
    ProviderResponseInvalidError,
    RequestTooLargeError,
)
from app.domain.models import ChatMessage, DetectedEntity, EntityAction, ProviderResponse
from app.policy.models import PolicySnapshot
from app.tokenization.selection import select_entities

Selections = tuple[tuple[DetectedEntity, ...], ...]
"""Selected spans per message, positionally aligned with the request."""


def enforce_message_sizes(messages: Sequence[ChatMessage], *, max_chars: int) -> None:
    """Reject a request carrying an oversized message.

    Checked before detection: analyzing megabytes of text to then refuse the
    request is work an unauthenticated-adjacent caller should not be able to buy.

    Raises:
        RequestTooLargeError: if any message exceeds ``max_chars``.
    """
    for message in messages:
        if len(message.content) > max_chars:
            # The position of the offending message is withheld on purpose: the
            # logging allowlist has no key for it, and a caller does not need a
            # length oracle to fix an oversized request.
            raise RequestTooLargeError(log_context={"reason": "message_too_long"})


def entity_budget(*, policy: PolicySnapshot, deployment_max_entities: int) -> int:
    """Return the entity ceiling for one request.

    The stricter of the two wins. A policy may tighten the deployment ceiling;
    it may never raise it, so a policy edit cannot turn one request into an
    unbounded number of vault writes.
    """
    return min(policy.max_entities, deployment_max_entities)


def select_request_entities(
    *,
    messages: Sequence[ChatMessage],
    detections: Sequence[Sequence[DetectedEntity]],
    policy: PolicySnapshot,
) -> Selections:
    """Return the spans the policy will act on, per message.

    Raises:
        InvalidRequestError: if a span lies outside its message's text.
    """
    return tuple(
        select_entities(text=message.content, entities=entities, policy=policy)
        for message, entities in zip(messages, detections, strict=True)
    )


def enforce_entity_budget(selections: Selections, *, budget: int) -> int:
    """Return the request-wide entity count, refusing an over-budget request.

    Raises:
        EntityLimitExceededError: if the whole request exceeds ``budget``.
    """
    total = sum(len(selected) for selected in selections)
    if total > budget:
        raise EntityLimitExceededError(
            log_context={"entity_count": total, "reason": "request_entity_budget_exceeded"}
        )
    return total


def validate_provider_response(response: ProviderResponse) -> ProviderResponse:
    """Reject provider output the rest of the pipeline cannot process.

    A runtime backstop on the one boundary where static typing stops helping:
    the adapter's return value is shaped by whatever the upstream sent back.
    Treating a non-string body as a bad upstream response is safer than letting
    ``None`` reach restoration and be reported as a gateway fault.

    Raises:
        ProviderResponseInvalidError: if ``content`` is not text.
    """
    if not isinstance(response.content, str):
        raise ProviderResponseInvalidError(
            log_context={"stage": "provider", "reason": "content_not_text"}
        )
    return response


def reject_blocked_entities(selections: Selections, *, policy: PolicySnapshot) -> None:
    """Refuse the request if any message holds a blocked entity type.

    Runs before the vault and long before the provider. The entity *type* is
    safe to record; the value it stood for is deliberately absent from both the
    message and the log context.

    Raises:
        PolicyViolationError: if any selected span resolves to ``BLOCK``.
    """
    for selected in selections:
        for entity in selected:
            if policy.action_for(entity.entity_type) is EntityAction.BLOCK:
                raise PolicyViolationError(
                    log_context={
                        "entity_type": entity.entity_type,
                        "reason": "policy_blocked_entity",
                    }
                )
