"""A deterministic in-memory detector for tests.

Use this anywhere a :class:`~app.detection.base.Detector` is needed but real NER
is not: the pipeline, policy, tokenization, restoration, and API test suites.
It loads no spaCy model and no Presidio recognizer, so it costs microseconds
instead of the seconds a real engine needs to start.

It shares :func:`~app.detection.postprocess.finalize` with the production
detector, so allowlists, thresholds, Luhn validation, overlap resolution, the
entity cap, and diagnostic-only recognizer names behave identically. What
differs is only *which* candidates are proposed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from app.detection.config import DetectionConfig
from app.detection.entities import (
    ACCESS_TOKEN,
    ACCOUNT_NUMBER,
    API_KEY,
    CREDIT_CARD,
    EMAIL_ADDRESS,
    HEALTH_PLAN_ID,
    IP_ADDRESS,
    MEDICAL_RECORD_NUMBER,
    PERSON,
    PHONE_NUMBER,
    US_SSN,
)
from app.detection.postprocess import Candidate, finalize
from app.domain.errors import UnsupportedLanguageError
from app.domain.models import DetectedEntity


@dataclass(frozen=True, slots=True)
class FakeRule:
    """One regex rule. ``group`` selects the reported span."""

    entity_type: str
    pattern: re.Pattern[str]
    score: float
    group: int | str = 0

    @property
    def recognizer(self) -> str:
        return f"Fake{self.entity_type.title().replace('_', '')}Rule"


DEFAULT_PERSON_NAMES: frozenset[str] = frozenset(
    {"Jordan Rivera", "Dana Whitfield", "Priya Raman", "Mikael Lindqvist", "Zoë Ferreira"}
)
"""Invented names the fake reports as ``PERSON``. Callers may replace them."""

DEFAULT_FAKE_RULES: tuple[FakeRule, ...] = (
    FakeRule(EMAIL_ADDRESS, re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 1.0),
    FakeRule(
        PHONE_NUMBER,
        re.compile(r"(?:\+1[-. ]?)?(?:\(\d{3}\)\s?|\d{3}[-. ])\d{3}[-. ]?\d{4}\b"),
        0.75,
    ),
    FakeRule(US_SSN, re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.85),
    FakeRule(CREDIT_CARD, re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), 0.9),
    FakeRule(IP_ADDRESS, re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 0.6),
    FakeRule(API_KEY, re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), 0.9),
    FakeRule(
        ACCESS_TOKEN,
        re.compile(r"\bbearer\s+(?P<value>[A-Za-z0-9\-._~+/]{20,}={0,2})", re.IGNORECASE),
        0.85,
        group="value",
    ),
    FakeRule(MEDICAL_RECORD_NUMBER, re.compile(r"\bMRN-\d{8}\b"), 0.85),
    FakeRule(HEALTH_PLAN_ID, re.compile(r"\bHPID-[A-Z0-9]{10}\b"), 0.85),
    FakeRule(ACCOUNT_NUMBER, re.compile(r"\bACCT-\d{4}-\d{6}\b"), 0.85),
)


class FakeDetector:
    """A :class:`~app.detection.base.Detector` backed by fixed regex rules.

    Args:
        config: Thresholds, allowlist, and limits. Defaults to production values.
        rules: Regex rules. Defaults to :data:`DEFAULT_FAKE_RULES`.
        person_names: Exact strings reported as ``PERSON``.
        scripted: Exact input text mapped to the candidates to return for it.
            Overrides the rules entirely for a matching input, which is how a
            test pins an awkward case (overlaps, invalid spans) without
            contorting a regex.
    """

    def __init__(
        self,
        *,
        config: DetectionConfig | None = None,
        rules: Sequence[FakeRule] | None = None,
        person_names: Iterable[str] | None = None,
        scripted: Mapping[str, Sequence[Candidate]] | None = None,
    ) -> None:
        self._config = config if config is not None else DetectionConfig()
        self._rules = tuple(rules) if rules is not None else DEFAULT_FAKE_RULES
        self._person_names = tuple(
            sorted(DEFAULT_PERSON_NAMES if person_names is None else person_names)
        )
        self._scripted = dict(scripted) if scripted else {}
        self.call_count = 0
        """How many times :meth:`detect` ran. Never records the analyzed text."""

    @property
    def config(self) -> DetectionConfig:
        return self._config

    async def warm_up(self) -> None:
        """No-op: there is nothing to load."""

    async def detect(
        self,
        text: str,
        *,
        language: str = "en",
        requested_entities: set[str] | None = None,
        diagnostic: bool = False,
    ) -> list[DetectedEntity]:
        """Return non-overlapping entities sorted by ``(start, end)``."""
        if not self._config.supports_language(language):
            raise UnsupportedLanguageError(log_context={"requested_language_supported": False})

        self.call_count += 1
        if not text.strip():
            return []

        candidates = self._scripted.get(text)
        if candidates is None:
            candidates = self._candidates(text)

        return finalize(
            candidates,
            text=text,
            config=self._config,
            requested_entities=(
                frozenset(requested_entities) if requested_entities is not None else None
            ),
            diagnostic=diagnostic,
        )

    def _candidates(self, text: str) -> list[Candidate]:
        found: list[Candidate] = []

        for rule in self._rules:
            for match in rule.pattern.finditer(text):
                start, end = match.span(rule.group)
                if start < 0 or end <= start:
                    continue
                found.append(Candidate(rule.entity_type, start, end, rule.score, rule.recognizer))

        for name in self._person_names:
            start = text.find(name)
            while start != -1:
                found.append(
                    Candidate(PERSON, start, start + len(name), 0.85, "FakePersonNameRule")
                )
                start = text.find(name, start + 1)

        return found
