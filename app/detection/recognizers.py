"""Custom recognizers for identifiers Presidio does not ship.

All patterns are compiled once at import. Each recognizer reports a single
entity type and may expose a named ``value`` group so that a labelled match
(``"api_key": "sk-live-..."``) reports only the secret, not the label -- the
stock ``PatternRecognizer`` always reports the whole match, which would drag the
field name into the tokenized span.

Sample identifier formats
-------------------------
The last three are *sample* enterprise formats. Real deployments override them.
Each is documented on its class and pinned by the test corpus:

======================= ============================ ======================
Entity                  Canonical form               Example
======================= ============================ ======================
MEDICAL_RECORD_NUMBER   ``MRN-`` + 8 digits          ``MRN-40217788``
HEALTH_PLAN_ID          ``HPID-`` + 10 upper alnum   ``HPID-8KD93JF01M``
ACCOUNT_NUMBER          ``ACCT-`` + 4 + ``-`` + 6    ``ACCT-2024-778301``
======================= ============================ ======================

Each also has a weaker labelled variant (``MRN: 40217788``) that scores lower
and leans on context words for its confidence boost.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from presidio_analyzer import (
    AnalysisExplanation,
    EntityRecognizer,
    LocalRecognizer,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import NlpArtifacts

from app.detection.checksums import has_low_character_variety
from app.detection.entities import (
    ACCESS_TOKEN,
    ACCOUNT_NUMBER,
    API_KEY,
    HEALTH_PLAN_ID,
    MEDICAL_RECORD_NUMBER,
)


@dataclass(frozen=True, slots=True)
class CompiledPattern:
    """A pattern compiled at import time.

    ``group`` selects the reported span: ``0`` is the whole match, a string
    names a capture group.
    """

    name: str
    regex: re.Pattern[str]
    score: float
    group: int | str = 0


class RegexRecognizer(LocalRecognizer):
    """Base for the custom recognizers: pre-compiled patterns, group spans.

    Subclasses set :attr:`ENTITY`, :attr:`PATTERNS`, and optionally
    :attr:`CONTEXT` and :meth:`is_valid`.
    """

    ENTITY: ClassVar[str] = ""
    PATTERNS: ClassVar[tuple[CompiledPattern, ...]] = ()
    CONTEXT: ClassVar[tuple[str, ...]] = ()

    def __init__(self, supported_language: str = "en") -> None:
        super().__init__(
            supported_entities=[self.ENTITY],
            name=type(self).__name__,
            supported_language=supported_language,
            context=list(self.CONTEXT),
        )

    @property
    def recognizer_name(self) -> str:
        """The reported name. Always the class name, by construction."""
        return type(self).__name__

    def load(self) -> None:
        """No state to load: every pattern is already compiled."""

    def is_valid(self, value: str) -> bool:
        """Reject placeholder filler such as ``MRN-00000000`` or ``sk-xxxxxxxxxxxxxxxx``.

        Only the body after the last literal separator is judged, so a fixed
        prefix cannot lend variety to an otherwise uniform identifier.
        """
        return not has_low_character_variety(value.rsplit("-", 1)[-1], minimum_distinct=2)

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        """Return every pattern hit for this recognizer's entity type."""
        if self.ENTITY not in entities:
            return []

        results: list[RecognizerResult] = []
        for pattern in self.PATTERNS:
            for match in pattern.regex.finditer(text):
                start, end = match.span(pattern.group)
                if start < 0 or end <= start:
                    continue
                if not self.is_valid(text[start:end]):
                    continue
                results.append(
                    RecognizerResult(
                        entity_type=self.ENTITY,
                        start=start,
                        end=end,
                        score=pattern.score,
                        # Presidio's context enhancer writes the supportive word
                        # onto this object; omitting it makes a context boost
                        # raise. It records the pattern name only, never a value.
                        analysis_explanation=AnalysisExplanation(
                            recognizer=self.recognizer_name,
                            original_score=pattern.score,
                            pattern_name=pattern.name,
                        ),
                        recognition_metadata={
                            RecognizerResult.RECOGNIZER_NAME_KEY: self.recognizer_name,
                            RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                        },
                    )
                )
        return results


class ApiKeyRecognizer(RegexRecognizer):
    """Vendor-prefixed API keys and labelled secret assignments.

    Prefixed forms (``sk-``, ``AKIA``, ``ghp_``, ``xoxb-``, ``AIza``) are
    unambiguous and score high. The labelled form catches an opaque secret in
    JSON or code by its field name and reports only the value.
    """

    ENTITY: ClassVar[str] = API_KEY
    CONTEXT: ClassVar[tuple[str, ...]] = (
        "api",
        "key",
        "secret",
        "credential",
        "token",
        "authorization",
    )
    PATTERNS: ClassVar[tuple[CompiledPattern, ...]] = (
        CompiledPattern("openai style key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), 0.9),
        CompiledPattern("aws access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.9),
        CompiledPattern("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), 0.9),
        CompiledPattern("slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0.85),
        CompiledPattern("google api key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0.9),
        CompiledPattern(
            "labelled secret assignment",
            re.compile(
                r"(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret"
                r"|access[_-]?key|private[_-]?key|password)"
                r"[\"']?\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9_\-./+]{16,})",
                re.IGNORECASE,
            ),
            0.7,
            group="value",
        ),
    )


class BearerTokenRecognizer(RegexRecognizer):
    """``Authorization: Bearer <token>`` values and bare JWTs.

    The bearer pattern reports the token only, so the ``Bearer`` scheme keyword
    survives tokenization and the protected text stays a valid header.
    """

    ENTITY: ClassVar[str] = ACCESS_TOKEN
    CONTEXT: ClassVar[tuple[str, ...]] = ("authorization", "bearer", "token", "jwt", "auth")
    PATTERNS: ClassVar[tuple[CompiledPattern, ...]] = (
        CompiledPattern(
            "authorization bearer",
            re.compile(r"\bbearer\s+(?P<value>[A-Za-z0-9\-._~+/]{20,}={0,2})", re.IGNORECASE),
            0.85,
            group="value",
        ),
        CompiledPattern(
            "json web token",
            re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
            0.9,
        ),
    )


class MedicalRecordNumberRecognizer(RegexRecognizer):
    """Sample MRN format: ``MRN-`` followed by exactly 8 digits.

    ``MRN-40217788`` is reported whole -- the prefix is part of the identifier.
    The labelled variant (``MRN: 40217788``, ``mrn 40217788``) reports the
    digits alone and scores lower.
    """

    ENTITY: ClassVar[str] = MEDICAL_RECORD_NUMBER
    CONTEXT: ClassVar[tuple[str, ...]] = (
        "mrn",
        "medical",
        "record",
        "patient",
        "chart",
        "hospital",
        "admission",
    )
    PATTERNS: ClassVar[tuple[CompiledPattern, ...]] = (
        CompiledPattern("mrn prefixed", re.compile(r"\bMRN-\d{8}\b"), 0.85),
        CompiledPattern(
            "mrn labelled",
            re.compile(r"\bMRN\s*[:#]?\s*(?P<value>\d{8})\b", re.IGNORECASE),
            0.6,
            group="value",
        ),
    )


class HealthPlanIdRecognizer(RegexRecognizer):
    """Sample health plan identifier: ``HPID-`` plus 10 uppercase alphanumerics.

    Example ``HPID-8KD93JF01M``. The labelled variant matches
    ``member id: 8KD93JF01M`` and similar phrasing at a lower score.
    """

    ENTITY: ClassVar[str] = HEALTH_PLAN_ID
    CONTEXT: ClassVar[tuple[str, ...]] = (
        "health",
        "plan",
        "member",
        "insurance",
        "policy",
        "subscriber",
        "coverage",
        "hpid",
    )
    PATTERNS: ClassVar[tuple[CompiledPattern, ...]] = (
        CompiledPattern("hpid prefixed", re.compile(r"\bHPID-[A-Z0-9]{10}\b"), 0.85),
        CompiledPattern(
            "health plan labelled",
            re.compile(
                r"\b(?:health\s+plan|member|subscriber|policy)\s*(?:id|number|no\.?|#)"
                r"\s*[:#]?\s*(?P<value>[A-Z0-9]{9,12})\b",
                re.IGNORECASE,
            ),
            0.6,
            group="value",
        ),
    )


class EnterpriseAccountNumberRecognizer(RegexRecognizer):
    """Sample enterprise account number: ``ACCT-YYYY-NNNNNN``.

    Example ``ACCT-2024-778301`` -- a four digit opening year and a six digit
    sequence. The labelled variant catches ``account number: 778301425`` and
    reports the digits alone.
    """

    ENTITY: ClassVar[str] = ACCOUNT_NUMBER
    CONTEXT: ClassVar[tuple[str, ...]] = (
        "account",
        "acct",
        "customer",
        "billing",
        "invoice",
        "contract",
    )
    PATTERNS: ClassVar[tuple[CompiledPattern, ...]] = (
        CompiledPattern("acct prefixed", re.compile(r"\bACCT-\d{4}-\d{6}\b"), 0.85),
        CompiledPattern(
            "account labelled",
            re.compile(
                r"\bacc(?:oun)?t\s*(?:number|no\.?|#|id)\s*[:#]?\s*(?P<value>\d{8,12})\b",
                re.IGNORECASE,
            ),
            0.55,
            group="value",
        ),
    )


CUSTOM_RECOGNIZER_TYPES: tuple[type[RegexRecognizer], ...] = (
    ApiKeyRecognizer,
    BearerTokenRecognizer,
    MedicalRecordNumberRecognizer,
    HealthPlanIdRecognizer,
    EnterpriseAccountNumberRecognizer,
)


def build_custom_recognizers(language: str = "en") -> list[EntityRecognizer]:
    """Instantiate one of every custom recognizer for ``language``."""
    return [
        recognizer_type(supported_language=language) for recognizer_type in CUSTOM_RECOGNIZER_TYPES
    ]
