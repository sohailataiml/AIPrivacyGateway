"""Synthetic detection corpus.

Every value here is invented. No string in this module is, or is derived from,
a real person's data: names are made up, phone numbers use the ``555-01xx``
range reserved for fiction, email domains are ``example.com``/``example.org``
(RFC 2606), and card numbers are checksum-crafted for this file. The SSNs
deliberately avoid the placeholder sequences Presidio itself rejects
(``123-45-6789``, ``987-65-4320``, ``078-05-1120``) and the never-issued
``000``/``666`` area prefixes, so a passing test proves detection rather than
proving Presidio's blocklist.

Secrets look like credentials but authenticate nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.detection.entities import (
    ACCESS_TOKEN,
    ACCOUNT_NUMBER,
    API_KEY,
    CREDIT_CARD,
    EMAIL_ADDRESS,
    HEALTH_PLAN_ID,
    LOCATION,
    MEDICAL_RECORD_NUMBER,
    PERSON,
    PHONE_NUMBER,
    US_SSN,
)


@dataclass(frozen=True, slots=True)
class CorpusCase:
    """One text with the detection outcome it must produce."""

    name: str
    text: str
    expected_types: frozenset[str] = field(default_factory=frozenset)
    """Types that must appear at least once."""

    forbidden_types: frozenset[str] = field(default_factory=frozenset)
    """Types that must not appear at all."""

    expected_values: tuple[str, ...] = ()
    """Substrings that must each be fully covered by one returned span."""

    forbidden_values: tuple[str, ...] = ()
    """Substrings that must not be covered by any returned span."""


# -- Individual values --------------------------------------------------------
EMAIL = "jordan.rivera@example.com"
SHARED_MAILBOX = "support@example.com"
PHONE_PARENS = "(415) 555-0132"
PHONE_DASHED = "628-555-0177"
SSN = "412-88-3719"
SSN_ALT = "512-44-2901"

CARD_LUHN_VALID = "4532-0151-1283-0366"
"""Passes Luhn. Crafted for this corpus; not issued to anyone."""

CARD_LUHN_INVALID = "4532-0151-1283-0367"
"""Same digits with a wrong check digit. Must never be reported as a card."""

CARD_LUHN_VALID_PLAIN = "4532015112830366"
CARD_LUHN_INVALID_PLAIN = "4532015112830369"

PERSON_NAME = "Jordan Rivera"
PERSON_NAME_UNICODE = "Zoë Ferreira"
CITY = "Mountain View"

MRN = "MRN-40217788"
HEALTH_PLAN = "HPID-8KD93JF01M"
ACCOUNT = "ACCT-2024-778301"

OPENAI_STYLE_KEY = "sk-live-7f2ad91b44c6e803aa"
AWS_KEY_ID = "AKIA6QW3XZLP2NMTY4RB"
GITHUB_TOKEN = "ghp_9fA2bK7dQ1zRt4Xy8Lm3Nv6Ce0Hs5Jw2Pu1O"
JWT = (
    "eyJhbGciOiJIUzI1NiJ9"
    ".eyJzdWIiOiJzeW50aGV0aWMtdGVzdCJ9"
    ".Rq7dK2mXpL0vT4nB8sYc1UwZ6hJ3aQeF9gN5rM2iVxO"
)

# -- Case texts ---------------------------------------------------------------
EMAIL_CASE = CorpusCase(
    name="email_address",
    text=f"Please forward the invoice to {EMAIL} before Friday.",
    expected_types=frozenset({EMAIL_ADDRESS}),
    expected_values=(EMAIL,),
)

PHONE_CASE = CorpusCase(
    name="us_phone_numbers",
    text=f"Reach the desk at {PHONE_PARENS} or the mobile {PHONE_DASHED}.",
    expected_types=frozenset({PHONE_NUMBER}),
    expected_values=(PHONE_PARENS, PHONE_DASHED),
)

SSN_CASE = CorpusCase(
    name="us_ssn",
    text=f"The social security number on the application is {SSN}.",
    expected_types=frozenset({US_SSN}),
    expected_values=(SSN,),
)

CREDIT_CARD_VALID_CASE = CorpusCase(
    name="credit_card_passing_luhn",
    text=f"Charge the card {CARD_LUHN_VALID} for the annual plan.",
    expected_types=frozenset({CREDIT_CARD}),
    expected_values=(CARD_LUHN_VALID,),
)

CREDIT_CARD_INVALID_CASE = CorpusCase(
    name="credit_card_failing_luhn",
    text=f"The number {CARD_LUHN_INVALID} was rejected at the terminal.",
    forbidden_types=frozenset({CREDIT_CARD}),
)

NAME_AND_LOCATION_CASE = CorpusCase(
    name="name_and_location",
    text=f"{PERSON_NAME} relocated to {CITY}, California last spring.",
    expected_types=frozenset({PERSON, LOCATION}),
    expected_values=(PERSON_NAME, CITY),
)

OVERLAPPING_CASE = CorpusCase(
    name="overlapping_card_and_date",
    text=f"Card {CARD_LUHN_VALID} on file.",
    expected_types=frozenset({CREDIT_CARD}),
    expected_values=(CARD_LUHN_VALID,),
)
"""A hyphenated card also parses as a date. Exactly one span must survive."""

REPEATED_CASE = CorpusCase(
    name="repeated_entities",
    text=f"Write to {EMAIL}. If that bounces, try {EMAIL} again, then {EMAIL}.",
    expected_types=frozenset({EMAIL_ADDRESS}),
)

UNICODE_CASE = CorpusCase(
    name="unicode_names_and_offsets",
    text=f"Café notes 📌 for {PERSON_NAME_UNICODE} — reply to {EMAIL} or {PHONE_DASHED}.",
    expected_types=frozenset({EMAIL_ADDRESS, PHONE_NUMBER}),
    expected_values=(EMAIL, PHONE_DASHED),
)
"""Astral-plane and accented characters ahead of every span: offsets are Python
character indices, so a byte-based engine would return the wrong slice."""

ALLOWLIST_VALUES = frozenset({SHARED_MAILBOX, "ACME Corporation"})

ALLOWLIST_CASE = CorpusCase(
    name="allowlisted_shared_mailbox",
    text=f"Copy {SHARED_MAILBOX} on the thread and reply to {EMAIL} directly.",
    expected_values=(EMAIL,),
    forbidden_values=(SHARED_MAILBOX,),
)

JSON_SECRET_CASE = CorpusCase(
    name="secret_embedded_in_json",
    text=(
        "{\n"
        '  "service": "billing",\n'
        f'  "api_key": "{OPENAI_STYLE_KEY}",\n'
        f'  "aws_access_key_id": "{AWS_KEY_ID}"\n'
        "}"
    ),
    expected_types=frozenset({API_KEY}),
    expected_values=(OPENAI_STYLE_KEY, AWS_KEY_ID),
)

CODE_SECRET_CASE = CorpusCase(
    name="secret_embedded_in_code",
    text=(
        "def client():\n"
        f'    token = "{GITHUB_TOKEN}"\n'
        f'    headers = {{"Authorization": "Bearer {JWT}"}}\n'
        "    return headers\n"
    ),
    expected_types=frozenset({API_KEY, ACCESS_TOKEN}),
    expected_values=(GITHUB_TOKEN, JWT),
)

ENTERPRISE_IDENTIFIER_CASE = CorpusCase(
    name="enterprise_and_health_identifiers",
    text=(
        f"Patient chart {MRN} is linked to health plan {HEALTH_PLAN} and billing account {ACCOUNT}."
    ),
    expected_types=frozenset({MEDICAL_RECORD_NUMBER, HEALTH_PLAN_ID, ACCOUNT_NUMBER}),
    expected_values=(MRN, HEALTH_PLAN, ACCOUNT),
)

EMPTY_CASE = CorpusCase(name="empty_string", text="")
WHITESPACE_CASE = CorpusCase(name="whitespace_only", text="   \n\t  \r\n ")

FALSE_POSITIVE_CASE = CorpusCase(
    name="benign_numbers_are_not_identifiers",
    text=("The build finished in 1283 seconds and the queue held 40217788 jobs across 4 workers."),
    forbidden_types=frozenset({CREDIT_CARD, US_SSN, MEDICAL_RECORD_NUMBER}),
)

LONG_SAFE_TEXT = (
    "the deployment pipeline runs unit tests, then integration tests, then a "
    "smoke check against the staging cluster before promoting the image. "
) * 200
"""About 26k characters of prose with no sensitive value in it."""

LONG_SAFE_CASE = CorpusCase(
    name="very_long_safe_text",
    text=LONG_SAFE_TEXT,
    forbidden_types=frozenset({EMAIL_ADDRESS, US_SSN, CREDIT_CARD, PHONE_NUMBER, API_KEY}),
)


def emails_text(count: int) -> str:
    """Return text holding exactly ``count`` distinct synthetic addresses."""
    return " ".join(f"user{index:04d}@example.org" for index in range(count))


MAX_ENTITY_COUNT = 40
"""Entity count used by the cap tests. Small enough to stay fast."""

MAX_ENTITY_CASE = CorpusCase(
    name="maximum_entity_count",
    text=emails_text(MAX_ENTITY_COUNT),
    expected_types=frozenset({EMAIL_ADDRESS}),
)

ALL_CASES: tuple[CorpusCase, ...] = (
    EMAIL_CASE,
    PHONE_CASE,
    SSN_CASE,
    CREDIT_CARD_VALID_CASE,
    CREDIT_CARD_INVALID_CASE,
    NAME_AND_LOCATION_CASE,
    OVERLAPPING_CASE,
    REPEATED_CASE,
    UNICODE_CASE,
    JSON_SECRET_CASE,
    CODE_SECRET_CASE,
    ENTERPRISE_IDENTIFIER_CASE,
    EMPTY_CASE,
    WHITESPACE_CASE,
    FALSE_POSITIVE_CASE,
    LONG_SAFE_CASE,
    MAX_ENTITY_CASE,
)

FAKE_DETECTOR_CASES: tuple[CorpusCase, ...] = (
    EMAIL_CASE,
    PHONE_CASE,
    SSN_CASE,
    CREDIT_CARD_VALID_CASE,
    CREDIT_CARD_INVALID_CASE,
    REPEATED_CASE,
    UNICODE_CASE,
    ENTERPRISE_IDENTIFIER_CASE,
    EMPTY_CASE,
    WHITESPACE_CASE,
    LONG_SAFE_CASE,
    MAX_ENTITY_CASE,
)
"""Cases the regex-only fake is expected to handle. It has no NER, so the
name, location, and labelled-secret cases are excluded."""
