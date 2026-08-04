"""The tokenizer: apply policy actions to detected spans and splice the text.

Order of operations is a safety property, not a style choice:

1. Select spans (bounds, confidence, overlaps) -- pure, no I/O.
2. Enforce the entity limit -- before any vault write.
3. Reject the whole request if any span is ``BLOCK`` -- before any vault write,
   and long before a provider could be called.
4. Only then walk the spans right to left, minting or reusing tokens.

Steps 2 and 3 come first so that a request destined to fail leaves nothing
behind: no mapping in the vault, no ciphertext, no TTL to wait out.

Replacement runs right to left because every offset in ``DetectedEntity`` indexes
the *original* string. Splicing from the left would shift every later span by the
difference between a value's length and its token's; going backwards means each
span is spliced while its offsets are still valid.

Nothing in this module logs. The values passing through are exactly the ones the
gateway exists to protect, and the cheapest way to guarantee they are never
logged is to have no logging statements at all. The one observability call it
does make, :func:`app.tokenization.metrics.record_plan`, is handed entity types
and policy actions -- never the text of a span.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final
from uuid import UUID

from app.domain.errors import (
    EntityLimitExceededError,
    ErrorCode,
    GatewayError,
    PolicyViolationError,
)
from app.domain.models import (
    DetectedEntity,
    EntityAction,
    EntityMapping,
    PrivacySummary,
    TransformedText,
)
from app.tokenization import metrics
from app.tokenization.fingerprint import Fingerprinter
from app.tokenization.grammar import Token, format_redaction, is_valid_token_id, parse_token
from app.tokenization.normalization import normalize
from app.tokenization.protocols import PolicyLike, VaultLike
from app.tokenization.pseudonyms import surrogate_for
from app.tokenization.selection import select_entities

_MAPPING_ACTIONS: Final = frozenset({EntityAction.TOKENIZE, EntityAction.PSEUDONYMIZE})


@dataclass(frozen=True, slots=True)
class _Outcome:
    """What one span turned into. ``replacement`` is ``None`` when text is left as is."""

    replacement: str | None
    mapping: EntityMapping | None


class Tokenizer:
    """Transforms one message's text according to policy.

    The vault is a constructor dependency rather than a call argument so that a
    single tokenizer instance can be shared for the life of the process while
    each call stays scoped to one tenant, session, and message.
    """

    __slots__ = ("_fingerprinter", "_vault")

    def __init__(self, *, vault: VaultLike, fingerprinter: Fingerprinter | None = None) -> None:
        self._vault = vault
        self._fingerprinter = (
            fingerprinter if fingerprinter is not None else Fingerprinter.from_settings()
        )

    async def transform(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        text: str,
        entities: Sequence[DetectedEntity],
        policy: PolicyLike,
    ) -> TransformedText:
        """Return the protected text, its mappings, and a counts-only summary.

        Raises:
            InvalidRequestError: if a span lies outside ``text``.
            EntityLimitExceededError: if more spans survive selection than the
                policy permits.
            PolicyViolationError: if any surviving span is ``BLOCK``.
        """
        selected = select_entities(text=text, entities=entities, policy=policy)
        self._enforce_limit(selected, policy)
        plan = tuple((entity, policy.action_for(entity.entity_type)) for entity in selected)
        # Before the block check, so a blocked span is counted rather than
        # vanishing along with the request it stopped. Type names and decision
        # names only -- see app.tokenization.metrics.
        metrics.record_plan(plan)
        _reject_blocked(plan)

        pieces: list[str] = []
        mappings: list[EntityMapping] = []
        cursor = len(text)

        # Right to left: every span is spliced while its offsets still hold.
        for entity, action in sorted(plan, key=lambda item: item[0].start, reverse=True):
            outcome = await self._apply(
                tenant_id=tenant_id,
                session_id=session_id,
                original=text[entity.start : entity.end],
                entity_type=entity.entity_type,
                action=action,
                ttl_seconds=policy.session_ttl_seconds,
            )
            if outcome.mapping is not None:
                mappings.append(outcome.mapping)
            if outcome.replacement is None:
                continue
            pieces.append(text[entity.end : cursor])
            pieces.append(outcome.replacement)
            cursor = entity.start
        pieces.append(text[:cursor])

        return TransformedText(
            text="".join(reversed(pieces)),
            mappings=tuple(reversed(mappings)),
            summary=_summarize(plan),
        )

    @staticmethod
    def _enforce_limit(selected: Sequence[DetectedEntity], policy: PolicyLike) -> None:
        if len(selected) <= policy.max_entities:
            return
        raise EntityLimitExceededError(
            log_context={"entity_count": len(selected), "max_entities": policy.max_entities}
        )

    async def _apply(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        original: str,
        entity_type: str,
        action: EntityAction,
        ttl_seconds: int,
    ) -> _Outcome:
        """Resolve one span into its replacement text and optional mapping."""
        if action is EntityAction.ALLOW:
            return _Outcome(replacement=None, mapping=None)
        if action is EntityAction.REDACT:
            # No vault call: a redaction is intentionally not reversible.
            return _Outcome(replacement=format_redaction(entity_type), mapping=None)
        if action not in _MAPPING_ACTIONS:  # pragma: no cover - blocked earlier
            raise AssertionError("unexpected action reached the replacement stage")

        normalized = normalize(entity_type, original)
        normalized_hmac = self._fingerprinter.fingerprint(
            tenant_id=tenant_id,
            session_id=session_id,
            entity_type=entity_type,
            normalized_value=normalized,
        )
        raw_token = await self._vault.get_or_create(
            tenant_id=tenant_id,
            session_id=session_id,
            entity_type=entity_type,
            normalized_hmac=normalized_hmac,
            original_value=original,
            ttl_seconds=ttl_seconds,
        )
        token = _coerce_vault_token(raw_token, entity_type)
        mapping = EntityMapping(
            token=token.text,
            token_id=token.token_id,
            entity_type=entity_type,
            original_value=original,
            normalized_hmac=normalized_hmac,
        )

        if action is EntityAction.PSEUDONYMIZE:
            replacement = surrogate_for(
                entity_type=entity_type,
                original_value=original,
                fingerprint=normalized_hmac,
            )
        else:
            replacement = token.text
        return _Outcome(replacement=replacement, mapping=mapping)


def _reject_blocked(plan: Sequence[tuple[DetectedEntity, EntityAction]]) -> None:
    """Fail the request if any span is blocked, before any state is created."""
    for entity, action in plan:
        if action is EntityAction.BLOCK:
            # The type name is safe to log; the value it stood for is not, and
            # is deliberately absent from both the message and the context.
            raise PolicyViolationError(log_context={"entity_type": entity.entity_type})


def _coerce_vault_token(raw_token: str, entity_type: str) -> Token:
    """Interpret what the vault returned as a token.

    The vault mints the token so that create-or-reuse stays atomic. It may
    return the canonical token string or the bare 26-character identifier;
    anything else means the vault and this module disagree about the grammar,
    which is an internal fault rather than a caller error.
    """
    parsed = parse_token(raw_token)
    if parsed is not None:
        if parsed.entity_type != entity_type:
            raise GatewayError(
                code=ErrorCode.INTERNAL_ERROR,
                log_context={
                    "reason": "vault token entity type does not match the request",
                    "expected_entity_type": entity_type,
                    "token_entity_type": parsed.entity_type,
                },
            )
        return parsed
    if is_valid_token_id(raw_token):
        return Token(entity_type=entity_type, token_id=raw_token)
    raise GatewayError(
        code=ErrorCode.INTERNAL_ERROR,
        log_context={"reason": "vault returned a malformed token", "entity_type": entity_type},
    )


def _summarize(plan: Sequence[tuple[DetectedEntity, EntityAction]]) -> PrivacySummary:
    """Build the counts-only summary. Entity type *names* only, never values.

    ``detected`` counts the spans that survived selection, which is exactly the
    set the policy acted on. Spans dropped for scoring below their type's
    threshold are not detections as far as the policy is concerned.
    """
    entity_types: dict[str, int] = {}
    for entity, _action in plan:
        entity_types[entity.entity_type] = entity_types.get(entity.entity_type, 0) + 1

    tallies = Counter(action for _entity, action in plan)
    return PrivacySummary(
        detected=len(plan),
        tokenized=tallies[EntityAction.TOKENIZE],
        redacted=tallies[EntityAction.REDACT],
        pseudonymized=tallies[EntityAction.PSEUDONYMIZE],
        allowed=tallies[EntityAction.ALLOW],
        entity_types=entity_types,
    )
