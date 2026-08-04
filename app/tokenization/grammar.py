"""The gateway token grammar: builder, strict parser, and scanner.

This module is deliberately standalone. It imports nothing from the rest of the
application so that restoration (Phase 10) can depend on it without pulling in
policy, vault, or settings machinery.

Canonical form::

    ⟦SGW:PERSON:01J8Z6J4M7Y9Q2K3T4V5W6X7Y8⟧

The delimiters are U+27E6 MATHEMATICAL LEFT WHITE SQUARE BRACKET and U+27E7.
They are chosen because they effectively never occur in natural prose, so a
caller cannot fabricate a token by accident, and a model is unlikely to emit one
that was not placed there by the gateway.

Two properties matter downstream:

1. ``parse_token`` is *strict*. It is a hand-written scanner, not a permissive
   regex, and it validates every field: delimiters, namespace, entity-type
   charset and length, and the 26-character Crockford base32 identifier. A
   near-miss is rejected outright rather than partially accepted.
2. ``REDACTED`` is a reserved marker, never an entity type. A redaction
   placeholder such as ``⟦SGW:REDACTED:EMAIL_ADDRESS⟧`` therefore can never be
   mistaken for a resolvable token, whatever the entity type happens to be.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass
from typing import Final

LEFT_DELIMITER: Final = "⟦"
"""U+27E6 MATHEMATICAL LEFT WHITE SQUARE BRACKET."""

RIGHT_DELIMITER: Final = "⟧"
"""U+27E7 MATHEMATICAL RIGHT WHITE SQUARE BRACKET."""

NAMESPACE: Final = "SGW"
FIELD_SEPARATOR: Final = ":"

REDACTED_MARKER: Final = "REDACTED"
"""Reserved second field of a redaction placeholder. Never a valid entity type."""

TOKEN_ID_LENGTH: Final = 26
MAX_ENTITY_TYPE_LENGTH: Final = 64

CROCKFORD_ALPHABET: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
"""Crockford base32: no I, L, O, or U, so a token cannot be misread aloud."""

_CROCKFORD_CHARS: Final = frozenset(CROCKFORD_ALPHABET)
_ENTITY_TYPE_CHARS: Final = frozenset(string.ascii_uppercase + string.digits + "_")

ENTITY_TYPE_PATTERN: Final = "[A-Z0-9_]{1,64}"
IDENTIFIER_PATTERN: Final = "[0-9A-HJKMNP-TV-Z]{26}"

TOKEN_PATTERN: Final = re.compile(
    f"{re.escape(LEFT_DELIMITER)}{NAMESPACE}{FIELD_SEPARATOR}"
    f"(?P<entity_type>{ENTITY_TYPE_PATTERN}){FIELD_SEPARATOR}"
    f"(?P<token_id>{IDENTIFIER_PATTERN}){re.escape(RIGHT_DELIMITER)}"
)
"""Candidate finder for scanning. Every hit is re-validated by ``parse_token``."""

_FIELD_COUNT: Final = 3


@dataclass(frozen=True, slots=True)
class Token:
    """A parsed gateway token. Carries no sensitive value, only identifiers."""

    entity_type: str
    token_id: str

    @property
    def text(self) -> str:
        """The canonical rendering of this token."""
        return format_token(self.entity_type, self.token_id)


@dataclass(frozen=True, slots=True)
class TokenMatch:
    """A token located inside a larger string, with its offsets."""

    token: Token
    start: int
    end: int

    @property
    def text(self) -> str:
        return self.token.text


def is_valid_entity_type(entity_type: str) -> bool:
    """Return whether ``entity_type`` is usable as the type field of a token."""
    if not 1 <= len(entity_type) <= MAX_ENTITY_TYPE_LENGTH:
        return False
    if entity_type == REDACTED_MARKER:
        return False
    return all(char in _ENTITY_TYPE_CHARS for char in entity_type)


def is_valid_token_id(token_id: str) -> bool:
    """Return whether ``token_id`` is a 26-character Crockford base32 identifier."""
    if len(token_id) != TOKEN_ID_LENGTH:
        return False
    return all(char in _CROCKFORD_CHARS for char in token_id)


def format_token(entity_type: str, token_id: str) -> str:
    """Build the canonical token string.

    Raises:
        ValueError: if either field would produce a token the parser rejects.
    """
    if not is_valid_entity_type(entity_type):
        raise ValueError(f"invalid token entity type: {entity_type!r}")
    if not is_valid_token_id(token_id):
        raise ValueError("invalid token id: expected 26 Crockford base32 characters")
    return (
        f"{LEFT_DELIMITER}{NAMESPACE}{FIELD_SEPARATOR}"
        f"{entity_type}{FIELD_SEPARATOR}{token_id}{RIGHT_DELIMITER}"
    )


def format_redaction(entity_type: str) -> str:
    """Build a non-reversible redaction placeholder for ``entity_type``.

    The result is intentionally *not* a parseable token: ``REDACTED`` is a
    reserved marker, so restoration can never try to resolve a redacted span.
    """
    if not is_valid_entity_type(entity_type):
        raise ValueError(f"invalid token entity type: {entity_type!r}")
    return (
        f"{LEFT_DELIMITER}{NAMESPACE}{FIELD_SEPARATOR}"
        f"{REDACTED_MARKER}{FIELD_SEPARATOR}{entity_type}{RIGHT_DELIMITER}"
    )


def parse_token(candidate: str) -> Token | None:
    """Parse ``candidate`` as a complete token, or return ``None``.

    Strict: the whole string must be exactly one token. Surrounding whitespace,
    nesting, a wrong namespace, a mis-sized identifier, or a character outside
    the Crockford alphabet all mean rejection rather than best-effort recovery.
    """
    minimum_length = len(LEFT_DELIMITER) + len(NAMESPACE) + 2 + 1 + TOKEN_ID_LENGTH + 1
    if len(candidate) < minimum_length:
        return None
    if not candidate.startswith(LEFT_DELIMITER) or not candidate.endswith(RIGHT_DELIMITER):
        return None

    body = candidate[len(LEFT_DELIMITER) : -len(RIGHT_DELIMITER)]
    fields = body.split(FIELD_SEPARATOR)
    if len(fields) != _FIELD_COUNT:
        return None

    namespace, entity_type, token_id = fields
    if namespace != NAMESPACE:
        return None
    if not is_valid_entity_type(entity_type):
        return None
    if not is_valid_token_id(token_id):
        return None
    return Token(entity_type=entity_type, token_id=token_id)


def is_token(candidate: str) -> bool:
    """Return whether ``candidate`` is exactly one well-formed token."""
    return parse_token(candidate) is not None


def find_tokens(text: str) -> tuple[TokenMatch, ...]:
    """Return every token embedded in ``text``, in order of appearance.

    Matches never overlap. Each candidate found by the scanner is re-validated
    through ``parse_token``, so the pattern can only ever be an accelerator --
    it can never widen what counts as a token.
    """
    matches: list[TokenMatch] = []
    for match in TOKEN_PATTERN.finditer(text):
        token = parse_token(match.group(0))
        if token is None:
            continue
        matches.append(TokenMatch(token=token, start=match.start(), end=match.end()))
    return tuple(matches)


def find_token_strings(text: str) -> tuple[str, ...]:
    """Return the distinct token strings in ``text``, in order of first appearance."""
    seen: dict[str, None] = {}
    for match in find_tokens(text):
        seen.setdefault(match.text, None)
    return tuple(seen)
