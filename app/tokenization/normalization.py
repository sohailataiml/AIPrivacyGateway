"""Entity-specific canonicalization used only for fingerprint matching.

Normalization decides when two spans of text mean *the same thing* inside one
session, so that ``jane@Example.com`` and ``  JANE@example.com `` collapse to a
single token. It never touches the value that is stored or restored: the vault
always keeps the original span exactly as it appeared, so restoration is
byte-for-byte faithful.

Every function here is pure and total. Unknown entity types fall back to
:func:`normalize_default`, which is the conservative choice -- it only removes
presentation noise (Unicode compatibility forms and redundant whitespace) and
never changes case, so two genuinely different values cannot be merged.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Final

Normalizer = Callable[[str], str]


def _compatibility_form(value: str) -> str:
    """Fold Unicode compatibility variants (full-width, ligatures, superscripts)."""
    return unicodedata.normalize("NFKC", value)


def _collapse_whitespace(value: str) -> str:
    """Trim the ends and reduce every internal whitespace run to one space."""
    return " ".join(value.split())


def _ascii_digits(value: str) -> str:
    """Keep decimal digits only, converting non-ASCII decimals to ASCII."""
    return "".join(str(unicodedata.decimal(char)) for char in value if char.isdecimal())


def _alphanumeric_upper(value: str) -> str:
    """Keep letters and digits only, upper-cased. Drops presentation separators."""
    return "".join(char for char in _compatibility_form(value) if char.isalnum()).upper()


def normalize_default(value: str) -> str:
    """Default for every entity type without a dedicated rule.

    Applies NFKC folding and whitespace collapsing. Case is preserved because
    lowering it would merge values that a recognizer treats as distinct.
    """
    return _collapse_whitespace(_compatibility_form(value))


def normalize_email(value: str) -> str:
    """Lower-case the whole address after trimming.

    Domains are case-insensitive by specification, and every mail provider in
    practice treats the local part that way too, so matching on the lower-cased
    form is what a human means by "the same address".
    """
    return _collapse_whitespace(_compatibility_form(value)).lower()


def normalize_phone(value: str) -> str:
    """Reduce to digits only, so formatting and punctuation stop mattering."""
    return _ascii_digits(_compatibility_form(value))


def normalize_person(value: str) -> str:
    """Trim and collapse whitespace; case is left alone.

    Names are not case-insensitive identifiers -- lowering them is a policy
    decision, not a canonicalization, so it is deliberately not done here.
    """
    return _collapse_whitespace(_compatibility_form(value))


def normalize_numeric_identifier(value: str) -> str:
    """Digits only. For identifiers whose separators are pure presentation."""
    return _ascii_digits(_compatibility_form(value))


def normalize_alphanumeric_identifier(value: str) -> str:
    """Letters and digits only, upper-cased. For IBANs, passports, licences."""
    return _alphanumeric_upper(value)


def normalize_hostname(value: str) -> str:
    """Lower-case and trim. For hosts, domains, and IP literals."""
    return _collapse_whitespace(_compatibility_form(value)).lower()


def normalize_case_sensitive(value: str) -> str:
    """Trim only. For values where case carries meaning, such as crypto addresses."""
    return _compatibility_form(value).strip()


NORMALIZERS: Final[Mapping[str, Normalizer]] = MappingProxyType(
    {
        "EMAIL_ADDRESS": normalize_email,
        "PHONE_NUMBER": normalize_phone,
        "PERSON": normalize_person,
        "LOCATION": normalize_person,
        "ORGANIZATION": normalize_person,
        "NRP": normalize_person,
        "US_SSN": normalize_numeric_identifier,
        "US_ITIN": normalize_numeric_identifier,
        "US_BANK_NUMBER": normalize_numeric_identifier,
        "CREDIT_CARD": normalize_numeric_identifier,
        "UK_NHS": normalize_numeric_identifier,
        "IBAN_CODE": normalize_alphanumeric_identifier,
        "US_PASSPORT": normalize_alphanumeric_identifier,
        "US_DRIVER_LICENSE": normalize_alphanumeric_identifier,
        "MEDICAL_LICENSE": normalize_alphanumeric_identifier,
        "IP_ADDRESS": normalize_hostname,
        "URL": normalize_hostname,
        "DOMAIN_NAME": normalize_hostname,
        "CRYPTO": normalize_case_sensitive,
    }
)
"""Entity type to normalizer. Lookup is case-insensitive via :func:`normalize`."""


def normalizer_for(entity_type: str) -> Normalizer:
    """Return the normalizer for ``entity_type``, or the documented default."""
    return NORMALIZERS.get(entity_type.upper(), normalize_default)


def normalize(entity_type: str, value: str) -> str:
    """Canonicalize ``value`` for matching, using the rule for ``entity_type``."""
    return normalizer_for(entity_type)(value)
