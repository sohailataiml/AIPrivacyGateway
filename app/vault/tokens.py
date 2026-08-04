"""Vault-side validation for values that become Redis key segments.

The token grammar itself lives in :mod:`app.tokenization.grammar`, which is the
single source of truth for how a token is built and parsed. This module holds
only the one concern the vault owns that the grammar does not: entity types
reach Redis *key names*, so the vault needs a raising check rather than the
grammar's boolean predicate.
"""

from __future__ import annotations

from app.tokenization.grammar import is_valid_entity_type


def validate_entity_type(entity_type: str) -> str:
    """Return ``entity_type`` unchanged, or raise if it is not key-safe.

    A key segment carrying ``:`` or other punctuation could escape its
    namespace and address another tenant's keyspace, so this runs before any
    entity type is interpolated into a key.
    """
    if not is_valid_entity_type(entity_type):
        raise ValueError("entity_type must be uppercase ASCII with underscores")
    return entity_type
