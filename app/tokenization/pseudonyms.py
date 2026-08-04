"""Shape-preserving surrogates for the ``PSEUDONYMIZE`` action.

A pseudonym replaces a value with a different value of the same *shape*: digits
stay digits, letters stay letters of the same case, and separators such as
``@``, ``.``, and ``-`` are preserved. A downstream model therefore still sees
something that parses and reads like an email address or a phone number, which
keeps prompts coherent, while the real value never leaves the gateway.

The surrogate is derived from the session-scoped fingerprint, so it is:

- stable -- the same value in the same session always yields the same surrogate;
- session-scoped -- the same value in another session yields another surrogate;
- unlinkable without the fingerprint key, since that key seeds the derivation.

Shape preservation deliberately leaks the length and character classes of the
original. That is inherent to pseudonymization; use ``TOKENIZE`` when even the
shape must be hidden.
"""

from __future__ import annotations

import hashlib
import string
from typing import Final

_DIGITS: Final = string.digits
_LOWER: Final = string.ascii_lowercase
_UPPER: Final = string.ascii_uppercase
_BLOCK_BYTES: Final = 64
_COUNTER_BYTES: Final = 4


def _keystream(seed: bytes, length: int) -> bytes:
    """Expand ``seed`` into ``length`` deterministic bytes."""
    if length <= 0:
        return b""
    blocks = bytearray()
    counter = 0
    while len(blocks) < length:
        payload = seed + counter.to_bytes(_COUNTER_BYTES, "big")
        blocks += hashlib.blake2b(payload, digest_size=_BLOCK_BYTES).digest()
        counter += 1
    return bytes(blocks[:length])


def surrogate_for(*, entity_type: str, original_value: str, fingerprint: str) -> str:
    """Return a stable, same-shape surrogate for ``original_value``.

    ``fingerprint`` is the keyed session fingerprint of the normalized value; it
    is what makes the result stable within a session and unpredictable outside
    the gateway.
    """
    seed = f"{fingerprint}:{entity_type}".encode()
    stream = _keystream(seed, len(original_value))
    return "".join(
        _substitute(source, noise) for source, noise in zip(original_value, stream, strict=True)
    )


def _substitute(source: str, noise: int) -> str:
    """Map one character onto another of the same class, or keep it verbatim.

    Digits and letters are replaced; punctuation, whitespace, and symbols pass
    through so the surrogate keeps the original's readable structure.
    """
    if source.isdigit():
        return _DIGITS[noise % len(_DIGITS)]
    if source.isalpha():
        # Non-ASCII letters become ASCII letters: preserving the script would
        # narrow down the original without adding usable structure.
        if source.isascii() and source.isupper():
            return _UPPER[noise % len(_UPPER)]
        return _LOWER[noise % len(_LOWER)]
    return source
