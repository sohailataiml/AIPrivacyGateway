"""Local token grammar helper.

INTEGRATION NOTE: ``app.tokenization.grammar`` owns the canonical token
grammar. Once that module lands, replace ``format_token`` here with
``app.tokenization.grammar.format_token`` and delete this module. It exists so
the vault can be built and tested independently of the tokenization package.

Canonical form::

    ⟦SGW:EMAIL_ADDRESS:01J8Z6J4M7Y9Q2K3T4V5W6X7Y8⟧

The delimiters are U+27E6 / U+27E7 (mathematical white square brackets): they
do not occur in normal prose, are not produced by tokenizers as word pieces,
and survive JSON transport. The trailing segment is a 26-character Crockford
base32 ULID, so tokens are unguessable and non-sequential.
"""

from __future__ import annotations

import re
from typing import Final

from ulid import ULID

# The S105 suppressions below are false positives: these are public grammar
# literals, not secrets. The rule fires on "TOKEN" in the constant names.
TOKEN_OPEN: Final = "⟦"  # noqa: S105
TOKEN_CLOSE: Final = "⟧"  # noqa: S105
TOKEN_NAMESPACE: Final = "SGW"  # noqa: S105

ENTITY_TYPE_PATTERN: Final = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
"""Entity types reach Redis key names, so the alphabet is restricted here."""

TOKEN_ID_PATTERN: Final = re.compile(r"^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{26}$")
"""Crockford base32 -- no I, L, O, or U."""

_TOKEN_PATTERN: Final = re.compile(
    rf"^{TOKEN_OPEN}{TOKEN_NAMESPACE}:"
    r"([A-Z][A-Z0-9_]{0,63}):"
    r"([0-9ABCDEFGHJKMNPQRSTVWXYZ]{26})"
    rf"{TOKEN_CLOSE}$"
)


def new_token_id() -> str:
    """Return a fresh 26-character ULID."""
    return str(ULID())


def validate_entity_type(entity_type: str) -> str:
    """Return ``entity_type`` unchanged, or raise if it is not key-safe."""
    if not ENTITY_TYPE_PATTERN.match(entity_type):
        raise ValueError("entity_type must be uppercase ASCII with underscores")
    return entity_type


def format_token(*, entity_type: str, token_id: str) -> str:
    """Build a canonical token. Both components are validated first."""
    validate_entity_type(entity_type)
    if not TOKEN_ID_PATTERN.match(token_id):
        raise ValueError("token_id must be a 26-character Crockford base32 ULID")
    return f"{TOKEN_OPEN}{TOKEN_NAMESPACE}:{entity_type}:{token_id}{TOKEN_CLOSE}"


def parse_token(token: str) -> tuple[str, str] | None:
    """Return ``(entity_type, token_id)``, or ``None`` if ``token`` is not one.

    Returning ``None`` rather than raising is intentional: restoration feeds
    arbitrary provider output through here, and a token-shaped string that is
    not actually a token is an ordinary event, not an error.
    """
    match = _TOKEN_PATTERN.match(token)
    if match is None:
        return None
    return match.group(1), match.group(2)
