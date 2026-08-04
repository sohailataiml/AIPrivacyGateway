"""Entity types the v1 detector may emit, plus the per-type tuning tables.

Nothing outside this module invents an entity type name. A recognizer that
produces a type absent from :data:`SUPPORTED_ENTITY_TYPES` is dropped during
post-processing, so an upstream Presidio upgrade cannot silently widen the
gateway's vocabulary (and therefore its policy surface).
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

# -- Entity type names -------------------------------------------------------
PERSON: Final = "PERSON"
EMAIL_ADDRESS: Final = "EMAIL_ADDRESS"
PHONE_NUMBER: Final = "PHONE_NUMBER"
US_SSN: Final = "US_SSN"
CREDIT_CARD: Final = "CREDIT_CARD"
IP_ADDRESS: Final = "IP_ADDRESS"
LOCATION: Final = "LOCATION"
DATE_TIME: Final = "DATE_TIME"
US_DRIVER_LICENSE: Final = "US_DRIVER_LICENSE"
US_PASSPORT: Final = "US_PASSPORT"
MEDICAL_RECORD_NUMBER: Final = "MEDICAL_RECORD_NUMBER"
HEALTH_PLAN_ID: Final = "HEALTH_PLAN_ID"
ACCOUNT_NUMBER: Final = "ACCOUNT_NUMBER"
API_KEY: Final = "API_KEY"
ACCESS_TOKEN: Final = "ACCESS_TOKEN"  # noqa: S105 -- an entity type name, not a secret
CUSTOM_IDENTIFIER: Final = "CUSTOM_IDENTIFIER"

SUPPORTED_ENTITY_TYPES: Final[frozenset[str]] = frozenset(
    {
        PERSON,
        EMAIL_ADDRESS,
        PHONE_NUMBER,
        US_SSN,
        CREDIT_CARD,
        IP_ADDRESS,
        LOCATION,
        DATE_TIME,
        US_DRIVER_LICENSE,
        US_PASSPORT,
        MEDICAL_RECORD_NUMBER,
        HEALTH_PLAN_ID,
        ACCOUNT_NUMBER,
        API_KEY,
        ACCESS_TOKEN,
        CUSTOM_IDENTIFIER,
    }
)

# -- Confidence ---------------------------------------------------------------
DEFAULT_MIN_SCORE: Final = 0.35
"""Global floor. No candidate below this is ever returned, whatever its type."""

DEFAULT_ENTITY_THRESHOLDS: Final[Mapping[str, float]] = MappingProxyType(
    {
        # Deterministic formats: a match is a match.
        EMAIL_ADDRESS: 0.5,
        CREDIT_CARD: 0.5,
        US_SSN: 0.5,
        IP_ADDRESS: 0.5,
        API_KEY: 0.5,
        ACCESS_TOKEN: 0.5,
        MEDICAL_RECORD_NUMBER: 0.5,
        HEALTH_PLAN_ID: 0.5,
        ACCOUNT_NUMBER: 0.5,
        CUSTOM_IDENTIFIER: 0.5,
        # Presidio scores an unenhanced US phone match at 0.40; anything lower is
        # a bare digit run we do not want.
        PHONE_NUMBER: 0.4,
        US_DRIVER_LICENSE: 0.4,
        US_PASSPORT: 0.4,
        # NER output. Held higher because a wrong PERSON span mangles prose.
        PERSON: 0.6,
        LOCATION: 0.6,
        DATE_TIME: 0.6,
    }
)

# -- Severity (first key of overlap resolution) -------------------------------
SEVERITY_CRITICAL: Final = 40
"""Credentials. Leaking one is an incident on its own."""

SEVERITY_HIGH: Final = 30
"""Regulated or financially exploitable identifiers."""

SEVERITY_MEDIUM: Final = 20
"""Direct contact identifiers."""

SEVERITY_LOW: Final = 10
"""Free-text NER output: useful, but the weakest evidence we act on."""

SEVERITY_UNKNOWN: Final = 0
"""Fallback for a type with no entry. Loses every severity comparison."""

ENTITY_PRIORITY: Final[Mapping[str, int]] = MappingProxyType(
    {
        API_KEY: SEVERITY_CRITICAL,
        ACCESS_TOKEN: SEVERITY_CRITICAL,
        US_SSN: SEVERITY_HIGH,
        CREDIT_CARD: SEVERITY_HIGH,
        US_PASSPORT: SEVERITY_HIGH,
        US_DRIVER_LICENSE: SEVERITY_HIGH,
        MEDICAL_RECORD_NUMBER: SEVERITY_HIGH,
        HEALTH_PLAN_ID: SEVERITY_HIGH,
        ACCOUNT_NUMBER: SEVERITY_HIGH,
        EMAIL_ADDRESS: SEVERITY_MEDIUM,
        PHONE_NUMBER: SEVERITY_MEDIUM,
        IP_ADDRESS: SEVERITY_MEDIUM,
        CUSTOM_IDENTIFIER: SEVERITY_MEDIUM,
        PERSON: SEVERITY_LOW,
        LOCATION: SEVERITY_LOW,
        DATE_TIME: SEVERITY_LOW,
    }
)
