"""Tokenization Prometheus metrics.

The tokenizer is the only place that knows both halves of the pair an operator
wants: the entity *type* a span was, and the *action* policy chose for it. The
detector knows the type but not the decision; the privacy summary carries both
but flattened into separate tallies, so the cross-product is unrecoverable
downstream. Hence this module rather than one in ``app/pipeline``.

Cardinality rule, as everywhere else: both label values come from sets closed at
import time. ``entity_type`` is folded onto
:data:`~app.detection.entities.SUPPORTED_ENTITY_TYPES`, with anything else --
a custom recognizer, a policy naming a type the detector does not produce --
collapsed onto :data:`ENTITY_TYPE_OTHER`. ``action`` must be an
:class:`~app.domain.models.EntityAction` member, not a string.

What is recorded is a type name and a decision name. The value the span held is
not passed to this module, which is the same line the audit record and the
privacy summary already draw: counts and type names leave the gateway, values do
not.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from prometheus_client import Counter

from app.detection.entities import SUPPORTED_ENTITY_TYPES
from app.domain.models import DetectedEntity, EntityAction

ENTITY_TYPE_OTHER: Final = "OTHER"
"""Label for an entity type outside the detector's supported set."""

ENTITIES_DETECTED_TOTAL: Final = Counter(
    "sgw_entities_detected_total",
    "Detected spans by entity type and the action policy took on them.",
    labelnames=("entity_type", "action"),
)


def normalize_entity_type(entity_type: str) -> str:
    """Fold an entity type onto the closed label set."""
    return entity_type if entity_type in SUPPORTED_ENTITY_TYPES else ENTITY_TYPE_OTHER


def record_entity(*, entity_type: str, action: EntityAction, count: int = 1) -> None:
    """Count spans of one type that received one action.

    Raises:
        TypeError: if ``action`` is not an ``EntityAction`` member.
    """
    if not isinstance(action, EntityAction):
        raise TypeError("action must be an EntityAction member so the label set stays closed")
    if count:
        ENTITIES_DETECTED_TOTAL.labels(
            entity_type=normalize_entity_type(entity_type), action=action.value
        ).inc(count)


def record_plan(plan: Iterable[tuple[DetectedEntity, EntityAction]]) -> None:
    """Count every span in one message's action plan.

    Called before the plan is executed, so a span that policy blocks -- and that
    therefore aborts the request before any vault write -- is still counted as
    detected. A blocked entity that never appears in the metrics would make the
    control that stopped it look like it never fired.
    """
    tallies: dict[tuple[str, EntityAction], int] = {}
    for entity, action in plan:
        key = (entity.entity_type, action)
        tallies[key] = tallies.get(key, 0) + 1

    for (entity_type, action), count in tallies.items():
        record_entity(entity_type=entity_type, action=action, count=count)
