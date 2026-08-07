"""The detector catalog: what the detector can find, as configuration data.

Every field here is *derived* from `app.detection.entities`, which is the module
that already decides the gateway's vocabulary. Nothing is restated. That matters
because a second hand-maintained list of entity types is exactly how a UI ends
up offering a rule for a type the detector never emits, or omitting one it does
-- and the omission is the dangerous direction, since an entity type absent from
the policy falls through to the fail-safe default rather than to the rule an
operator thought they had written.

The one thing this module adds is prose. `DESCRIPTIONS` explains what each type
is for a human reading the policy editor; it is documentation of the detector's
own types, not policy configuration, and a missing entry degrades to no
description rather than to a wrong one.

This is what makes "entity detection is configuration-driven" demonstrable: the
catalog is read from the detector, the thresholds are the detector's defaults,
and adding a new type to `SUPPORTED_ENTITY_TYPES` makes it appear here -- and
therefore in the policy editor -- with no change to the tokenizer or the vault.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from app.detection.entities import (
    DEFAULT_ENTITY_THRESHOLDS,
    DEFAULT_MIN_SCORE,
    ENTITY_PRIORITY,
    SUPPORTED_ENTITY_TYPES,
)
from app.domain.models import EntityAction

RECOGNIZER_CUSTOM: Final = "custom-regex"
RECOGNIZER_BUILTIN: Final = "presidio-builtin"

CUSTOM_RECOGNIZER_TYPES: Final[frozenset[str]] = frozenset(
    {
        "API_KEY",
        "ACCESS_TOKEN",
        "MEDICAL_RECORD_NUMBER",
        "HEALTH_PLAN_ID",
        "ACCOUNT_NUMBER",
        "CUSTOM_IDENTIFIER",
    }
)
"""Types supplied by this project's own recognizers (`app/detection/recognizers.py`).

Named here rather than introspected from the recognizer objects because
`build_custom_recognizers` constructs a spaCy-backed registry, and building one
to answer a catalog request would make a cheap read expensive.
"""

DESCRIPTIONS: Final[dict[str, str]] = {
    "PERSON": "Personal names identified by the NER model.",
    "EMAIL_ADDRESS": "Email addresses, including internal-only domains.",
    "PHONE_NUMBER": "Telephone numbers. Scored low by the detector without nearby context.",
    "US_SSN": "US Social Security numbers.",
    "CREDIT_CARD": "Payment card numbers, checksum-validated.",
    "IP_ADDRESS": "IPv4 and IPv6 addresses.",
    "LOCATION": "Places identified by the NER model.",
    "DATE_TIME": "Dates and times, including dates of birth.",
    "US_DRIVER_LICENSE": "US driver licence numbers.",
    "US_PASSPORT": "US passport numbers.",
    "MEDICAL_RECORD_NUMBER": "Medical record numbers in the MRN-######## form.",
    "HEALTH_PLAN_ID": "Health plan and member identifiers.",
    "ACCOUNT_NUMBER": "Enterprise account numbers.",
    "API_KEY": "Credential-shaped strings that look like API keys.",
    "ACCESS_TOKEN": "Bearer tokens and similar access credentials.",
    "CUSTOM_IDENTIFIER": "Organisation-specific identifiers matched by a custom pattern.",
}


@dataclass(frozen=True, slots=True)
class DetectorCatalogEntry:
    """One entity type the detector can emit, described for an operator.

    Carries no matched values and no pattern source: a regex that finds API keys
    is a map of what a credential looks like here, and the catalog is readable by
    anyone with `policies:read`.
    """

    entity_type: str
    recognizer_type: str
    default_threshold: float
    severity: int
    supported_actions: tuple[str, ...]
    description: str | None


def _supported_actions() -> tuple[str, ...]:
    """Every action, for every type.

    There is no per-type restriction to express: the pipeline applies any action
    to any type, and a policy that blocks `DATE_TIME` is unusual rather than
    invalid. Restricting the list here would invent a rule the engine does not
    enforce.
    """
    return tuple(action.value for action in EntityAction)


def detector_catalog() -> list[DetectorCatalogEntry]:
    """The full catalog, ordered by descending severity then name.

    Severity-first ordering puts the types whose misconfiguration costs most at
    the top of the editor.
    """
    entries = [
        DetectorCatalogEntry(
            entity_type=entity_type,
            recognizer_type=(
                RECOGNIZER_CUSTOM if entity_type in CUSTOM_RECOGNIZER_TYPES else RECOGNIZER_BUILTIN
            ),
            default_threshold=DEFAULT_ENTITY_THRESHOLDS.get(entity_type, DEFAULT_MIN_SCORE),
            severity=ENTITY_PRIORITY.get(entity_type, 0),
            supported_actions=_supported_actions(),
            description=DESCRIPTIONS.get(entity_type),
        )
        for entity_type in SUPPORTED_ENTITY_TYPES
    ]
    entries.sort(key=lambda entry: (-entry.severity, entry.entity_type))
    return entries


def known_entity_types() -> frozenset[str]:
    """Types a policy may configure. The validator's allowlist."""
    return SUPPORTED_ENTITY_TYPES


def known_recognizers() -> frozenset[str]:
    """Recognizer identifiers a policy rule may name."""
    return frozenset({RECOGNIZER_CUSTOM, RECOGNIZER_BUILTIN})
