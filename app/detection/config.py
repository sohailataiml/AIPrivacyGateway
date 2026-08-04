"""Detector configuration: languages, thresholds, allowlist, and limits.

One immutable object carries every knob that changes what the detector returns,
so a test can vary one dimension without touching Presidio and the production
path cannot be reconfigured mid-request.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from app.detection.entities import (
    DEFAULT_ENTITY_THRESHOLDS,
    DEFAULT_MIN_SCORE,
    ENTITY_PRIORITY,
    SUPPORTED_ENTITY_TYPES,
)

DEFAULT_SPACY_MODEL = "en_core_web_lg"
"""Installed via ``python -m spacy download en_core_web_lg``. See README setup."""

DEFAULT_MAX_ENTITIES = 500
"""Matches ``max_entities`` in the default policy document."""

SUPPORTED_LANGUAGES = frozenset({"en"})
"""v1 ships English only. Adding a language means adding a spaCy model *and*
re-tuning thresholds, so the set is explicit rather than derived."""


def normalize_allowlist_value(value: str) -> str:
    """Return the comparison form of an allowlist entry or a matched span."""
    return value.strip().casefold()


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """Immutable detector tuning. Construct once, share freely."""

    supported_languages: frozenset[str] = SUPPORTED_LANGUAGES
    enabled_entities: frozenset[str] = SUPPORTED_ENTITY_TYPES
    entity_thresholds: Mapping[str, float] = field(
        default_factory=lambda: DEFAULT_ENTITY_THRESHOLDS
    )
    entity_priority: Mapping[str, int] = field(default_factory=lambda: ENTITY_PRIORITY)
    min_score: float = DEFAULT_MIN_SCORE
    allowlist: frozenset[str] = frozenset()
    """Exact values that are never reported. Compared case-insensitively after
    stripping surrounding whitespace."""

    max_entities: int = DEFAULT_MAX_ENTITIES
    spacy_model: str = DEFAULT_SPACY_MODEL

    def __post_init__(self) -> None:
        if not 0.0 <= self.min_score <= 1.0:
            raise ValueError("min_score must be within [0.0, 1.0]")
        if self.max_entities < 1:
            raise ValueError("max_entities must be at least 1")
        if not self.supported_languages:
            raise ValueError("at least one language must be supported")

        normalized = frozenset(
            normalized_value
            for value in self.allowlist
            if (normalized_value := normalize_allowlist_value(value))
        )
        # Frozen dataclass: normalize exactly once, during construction, so
        # every later comparison is a plain set membership test.
        object.__setattr__(self, "allowlist", normalized)

    def threshold_for(self, entity_type: str) -> float:
        """Return the effective minimum score: the per-type value or the floor."""
        return max(self.min_score, self.entity_thresholds.get(entity_type, self.min_score))

    def is_allowlisted(self, value: str) -> bool:
        """Return ``True`` when ``value`` must never be reported as an entity."""
        if not self.allowlist:
            return False
        return normalize_allowlist_value(value) in self.allowlist

    def supports_language(self, language: str) -> bool:
        return language in self.supported_languages

    def with_allowlist(self, values: Iterable[str]) -> DetectionConfig:
        """Return a copy carrying ``values`` as the allowlist. Self is unchanged."""
        return DetectionConfig(
            supported_languages=self.supported_languages,
            enabled_entities=self.enabled_entities,
            entity_thresholds=self.entity_thresholds,
            entity_priority=self.entity_priority,
            min_score=self.min_score,
            allowlist=frozenset(values),
            max_entities=self.max_entities,
            spacy_model=self.spacy_model,
        )
