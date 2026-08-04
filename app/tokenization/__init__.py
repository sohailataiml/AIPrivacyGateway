"""Tokenization: turn detected sensitive spans into reversible opaque tokens.

Public entry point is :class:`~app.tokenization.tokenizer.Tokenizer`. Restoration
depends only on :mod:`app.tokenization.grammar`, which is standalone by design.
"""

from __future__ import annotations

from app.tokenization.fingerprint import Fingerprinter, derive_fingerprint_key
from app.tokenization.grammar import (
    CROCKFORD_ALPHABET,
    LEFT_DELIMITER,
    NAMESPACE,
    REDACTED_MARKER,
    RIGHT_DELIMITER,
    TOKEN_ID_LENGTH,
    TOKEN_PATTERN,
    Token,
    TokenMatch,
    find_token_strings,
    find_tokens,
    format_redaction,
    format_token,
    is_token,
    is_valid_entity_type,
    is_valid_token_id,
    parse_token,
)
from app.tokenization.ids import encode_crockford, new_token_id
from app.tokenization.normalization import NORMALIZERS, normalize, normalizer_for
from app.tokenization.protocols import PolicyLike, VaultLike
from app.tokenization.pseudonyms import surrogate_for
from app.tokenization.selection import resolve_overlaps, select_entities
from app.tokenization.tokenizer import Tokenizer

__all__ = [
    "CROCKFORD_ALPHABET",
    "LEFT_DELIMITER",
    "NAMESPACE",
    "NORMALIZERS",
    "REDACTED_MARKER",
    "RIGHT_DELIMITER",
    "TOKEN_ID_LENGTH",
    "TOKEN_PATTERN",
    "Fingerprinter",
    "PolicyLike",
    "Token",
    "TokenMatch",
    "Tokenizer",
    "VaultLike",
    "derive_fingerprint_key",
    "encode_crockford",
    "find_token_strings",
    "find_tokens",
    "format_redaction",
    "format_token",
    "is_token",
    "is_valid_entity_type",
    "is_valid_token_id",
    "new_token_id",
    "normalize",
    "normalizer_for",
    "parse_token",
    "resolve_overlaps",
    "select_entities",
    "surrogate_for",
]
