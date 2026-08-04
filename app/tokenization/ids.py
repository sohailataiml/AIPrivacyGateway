"""Token identifier generation.

Identifiers are 26-character Crockford base32 strings -- the ULID encoding --
but every one of the 128 bits comes from :mod:`secrets`. A standard ULID puts a
millisecond timestamp in the leading 48 bits, which makes consecutive ids sort
together and leaks issue time. Neither is acceptable here: a token id must be
unguessable and must reveal nothing about when or in what order it was minted.

The encoding is preserved so that ids remain drop-in compatible with ULID
tooling and with the token grammar's 26-character identifier field.
"""

from __future__ import annotations

import secrets
from typing import Final

from app.tokenization.grammar import CROCKFORD_ALPHABET, TOKEN_ID_LENGTH

TOKEN_ID_BYTES: Final = 16
"""128 bits of entropy, matching the ULID payload width."""

_BITS_PER_CHARACTER: Final = 5
_CHARACTER_MASK: Final = 0x1F
_HIGHEST_SHIFT: Final = _BITS_PER_CHARACTER * (TOKEN_ID_LENGTH - 1)


def encode_crockford(raw: bytes) -> str:
    """Encode exactly 16 bytes as a 26-character Crockford base32 string.

    Raises:
        ValueError: if ``raw`` is not 16 bytes.
    """
    if len(raw) != TOKEN_ID_BYTES:
        raise ValueError(f"token ids encode exactly {TOKEN_ID_BYTES} bytes")

    value = int.from_bytes(raw, "big")
    return "".join(
        CROCKFORD_ALPHABET[(value >> shift) & _CHARACTER_MASK]
        for shift in range(_HIGHEST_SHIFT, -1, -_BITS_PER_CHARACTER)
    )


def new_token_id() -> str:
    """Return a fresh, cryptographically random token identifier."""
    return encode_crockford(secrets.token_bytes(TOKEN_ID_BYTES))
