"""Checksum validators used to suppress structurally plausible false positives.

A sixteen-digit number is not a credit card; a sixteen-digit number that passes
Luhn probably is. Running the checksum here -- rather than trusting whichever
recognizer produced the span -- means the guarantee holds for every detector
implementation, including the test fake.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType

from app.detection.entities import CREDIT_CARD

MIN_CARD_DIGITS = 13
MAX_CARD_DIGITS = 19


def digits_only(value: str) -> str:
    """Return only the decimal digits of ``value``."""
    return "".join(char for char in value if char.isdigit())


def luhn_is_valid(value: str) -> bool:
    """Return ``True`` when the digits of ``value`` satisfy the Luhn checksum.

    Separators are ignored, so ``4532-0151-1283-0366`` and its unspaced form
    give the same answer. An empty or single-digit string is never valid.
    """
    digits = digits_only(value)
    if len(digits) < 2:
        return False

    total = 0
    # Walk right to left, doubling every second digit.
    for position, char in enumerate(reversed(digits)):
        digit = ord(char) - ord("0")
        if position % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def is_valid_credit_card(value: str) -> bool:
    """Return ``True`` for a plausible card number: right length and Luhn-clean."""
    digits = digits_only(value)
    if not MIN_CARD_DIGITS <= len(digits) <= MAX_CARD_DIGITS:
        return False
    return luhn_is_valid(digits)


def has_low_character_variety(value: str, *, minimum_distinct: int = 3) -> bool:
    """Return ``True`` for filler like ``0000000000`` or ``xxxxxxxxxxxx``.

    Placeholder values dominate configuration samples and documentation, and
    tokenizing them wastes vault rows without protecting anything.
    """
    return len(set(value.casefold())) < minimum_distinct


VALUE_VALIDATORS: Mapping[str, Callable[[str], bool]] = MappingProxyType(
    {CREDIT_CARD: is_valid_credit_card}
)
"""Per-entity-type value validators applied to every candidate before scoring.

A type absent from this table has no value-level check.
"""
