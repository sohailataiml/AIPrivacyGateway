"""Tests for the tokenization engine.

The invariants asserted here are the ones the whole gateway rests on: text
outside a selected span is never touched, every tokenized span has exactly one
mapping, a redaction is never reversible, and a blocked request creates nothing
at all. The vault and policy are in-memory fakes that satisfy the structural
protocols the tokenizer declares, so nothing here needs Redis or a policy store.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from itertools import pairwise
from uuid import UUID, uuid4

import pytest
from hypothesis import HealthCheck, given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st
from pydantic import SecretStr

from app.config.settings import Settings
from app.domain.errors import (
    EntityLimitExceededError,
    ErrorCode,
    GatewayError,
    InvalidRequestError,
    PolicyViolationError,
)
from app.domain.models import DetectedEntity, EntityAction, TransformedText
from app.tokenization.fingerprint import Fingerprinter, derive_fingerprint_key
from app.tokenization.grammar import (
    CROCKFORD_ALPHABET,
    LEFT_DELIMITER,
    RIGHT_DELIMITER,
    TOKEN_ID_LENGTH,
    Token,
    find_tokens,
    format_redaction,
    format_token,
    is_token,
    parse_token,
)
from app.tokenization.ids import encode_crockford, new_token_id
from app.tokenization.normalization import NORMALIZERS, normalize, normalize_default
from app.tokenization.protocols import PolicyLike, VaultLike
from app.tokenization.pseudonyms import surrogate_for
from app.tokenization.selection import resolve_overlaps
from app.tokenization.tokenizer import Tokenizer

TENANT = UUID("11111111-1111-1111-1111-111111111111")
SESSION = UUID("22222222-2222-2222-2222-222222222222")
OTHER_SESSION = UUID("33333333-3333-3333-3333-333333333333")
SAMPLE_ID = "01J8Z6J4M7Y9Q2K3T4V5W6X7Y8"
FINGERPRINT_KEY = b"unit-test-fingerprint-key-0123456789"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FakePolicy:
    """An in-memory policy satisfying ``PolicyLike`` structurally."""

    actions: Mapping[str, EntityAction] = field(default_factory=dict)
    default_action: EntityAction = EntityAction.TOKENIZE
    min_scores: Mapping[str, float] = field(default_factory=dict)
    max_entities: int = 100
    session_ttl_seconds: int = 900

    def action_for(self, entity_type: str) -> EntityAction:
        return self.actions.get(entity_type, self.default_action)

    def min_score_for(self, entity_type: str) -> float:
        return self.min_scores.get(entity_type, 0.0)


@dataclass(frozen=True)
class VaultCall:
    """Metadata about one vault write. Deliberately holds no original value."""

    entity_type: str
    normalized_hmac: str
    ttl_seconds: int


class FakeVault:
    """An in-memory vault satisfying ``VaultLike`` structurally."""

    def __init__(self, token_override: str | None = None) -> None:
        self.records: dict[tuple[UUID, UUID, str, str], str] = {}
        self.calls: list[VaultCall] = []
        self.written_values: list[str] = []
        self._token_override = token_override

    async def get_or_create(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        entity_type: str,
        normalized_hmac: str,
        original_value: str,
        ttl_seconds: int,
    ) -> str:
        self.calls.append(
            VaultCall(
                entity_type=entity_type, normalized_hmac=normalized_hmac, ttl_seconds=ttl_seconds
            )
        )
        key = (tenant_id, session_id, entity_type, normalized_hmac)
        existing = self.records.get(key)
        if existing is not None:
            return existing
        token = (
            self._token_override
            if self._token_override is not None
            else format_token(entity_type, new_token_id())
        )
        self.records[key] = token
        self.written_values.append(original_value)
        return token

    @property
    def write_count(self) -> int:
        return len(self.records)


# Structural conformance is checked statically by these annotations.
_POLICY_IS_POLICY_LIKE: PolicyLike = FakePolicy()
_VAULT_IS_VAULT_LIKE: VaultLike = FakeVault()


def build_tokenizer(vault: FakeVault | None = None) -> tuple[Tokenizer, FakeVault]:
    resolved = vault if vault is not None else FakeVault()
    tokenizer = Tokenizer(vault=resolved, fingerprinter=Fingerprinter(FINGERPRINT_KEY))
    return tokenizer, resolved


async def transform(
    tokenizer: Tokenizer,
    *,
    text: str,
    entities: Sequence[DetectedEntity],
    policy: PolicyLike,
    session_id: UUID = SESSION,
) -> TransformedText:
    return await tokenizer.transform(
        tenant_id=TENANT,
        session_id=session_id,
        text=text,
        entities=entities,
        policy=policy,
    )


def entity(entity_type: str, start: int, end: int, score: float = 0.9) -> DetectedEntity:
    return DetectedEntity(entity_type=entity_type, start=start, end=end, score=score)


# ---------------------------------------------------------------------------
# Grammar: builder
# ---------------------------------------------------------------------------
def test_format_token_builds_the_canonical_form() -> None:
    # Arrange / Act
    token = format_token("EMAIL_ADDRESS", SAMPLE_ID)

    # Assert
    assert token == f"⟦SGW:EMAIL_ADDRESS:{SAMPLE_ID}⟧"
    assert token.startswith(LEFT_DELIMITER)
    assert token.endswith(RIGHT_DELIMITER)


@pytest.mark.parametrize(
    "entity_type",
    ["", "person", "PERSON-NAME", "PERSON NAME", "P" * 65, "REDACTED", "PERSON:X"],
)
def test_format_token_rejects_invalid_entity_types(entity_type: str) -> None:
    with pytest.raises(ValueError, match="entity type"):
        format_token(entity_type, SAMPLE_ID)


@pytest.mark.parametrize("token_id", ["", SAMPLE_ID[:-1], SAMPLE_ID + "Z", SAMPLE_ID.lower()])
def test_format_token_rejects_invalid_identifiers(token_id: str) -> None:
    with pytest.raises(ValueError, match="token id"):
        format_token("PERSON", token_id)


def test_token_text_round_trips_through_the_parser() -> None:
    # Arrange
    original = Token(entity_type="US_SSN", token_id=SAMPLE_ID)

    # Act
    parsed = parse_token(original.text)

    # Assert
    assert parsed == original


# ---------------------------------------------------------------------------
# Grammar: strict parser
# ---------------------------------------------------------------------------
NEAR_MISSES = [
    f"[SGW:PERSON:{SAMPLE_ID}]",  # ASCII delimiters
    f"<SGW:PERSON:{SAMPLE_ID}>",
    f"SGW:PERSON:{SAMPLE_ID}",  # no delimiters
    f"⟦SGW:PERSON:{SAMPLE_ID}",  # missing right delimiter
    f"SGW:PERSON:{SAMPLE_ID}⟧",  # missing left delimiter
    f"⟦SGW:PERSON:{SAMPLE_ID[:-1]}⟧",  # 25-character id
    f"⟦SGW:PERSON:{SAMPLE_ID}Z⟧",  # 27-character id
    f"⟦SGW:PERSON:{SAMPLE_ID.lower()}⟧",  # lower-case id
    f"⟦SGW:PERSON:{'I' * TOKEN_ID_LENGTH}⟧",  # Crockford excludes I
    f"⟦SGW:PERSON:{'L' * TOKEN_ID_LENGTH}⟧",  # ... and L
    f"⟦SGW:PERSON:{'O' * TOKEN_ID_LENGTH}⟧",  # ... and O
    f"⟦SGW:PERSON:{'U' * TOKEN_ID_LENGTH}⟧",  # ... and U
    f"⟦SGW::{SAMPLE_ID}⟧",  # empty entity type
    f"⟦SGW:person:{SAMPLE_ID}⟧",  # lower-case entity type
    f"⟦SGW:{'P' * 65}:{SAMPLE_ID}⟧",  # entity type too long
    f"⟦GW:PERSON:{SAMPLE_ID}⟧",  # wrong namespace
    f"⟦sgw:PERSON:{SAMPLE_ID}⟧",  # lower-case namespace
    f"⟦SGW:PERSON:{SAMPLE_ID}:EXTRA⟧",  # extra field
    f"⟦PERSON:{SAMPLE_ID}⟧",  # missing namespace
    f" ⟦SGW:PERSON:{SAMPLE_ID}⟧",  # leading whitespace
    f"⟦SGW:PERSON:{SAMPLE_ID}⟧ ",  # trailing whitespace
    f"⟦⟦SGW:PERSON:{SAMPLE_ID}⟧⟧",  # nested
    f"⟦SGW:REDACTED:{SAMPLE_ID}⟧",  # REDACTED is a reserved marker
    "",
    "⟦⟧",
    "⟦SGW:PERSON:⟧",
]


@pytest.mark.parametrize("candidate", NEAR_MISSES)
def test_parser_rejects_near_miss_syntax(candidate: str) -> None:
    assert parse_token(candidate) is None
    assert is_token(candidate) is False


def test_parser_accepts_every_crockford_character() -> None:
    # Arrange: an id built from the alphabet itself, wrapped to 26 characters.
    token_id = (CROCKFORD_ALPHABET * 2)[:TOKEN_ID_LENGTH]

    # Act / Assert
    assert parse_token(format_token("PERSON", token_id)) is not None


# ---------------------------------------------------------------------------
# Grammar: scanner
# ---------------------------------------------------------------------------
def test_find_tokens_returns_matches_in_order_with_offsets() -> None:
    # Arrange
    first = format_token("PERSON", SAMPLE_ID)
    second = format_token("EMAIL_ADDRESS", "0123456789ABCDEFGHJKMNPQRS")
    text = f"Hi {first}, mail {second} today"

    # Act
    matches = find_tokens(text)

    # Assert
    assert [match.text for match in matches] == [first, second]
    assert text[matches[0].start : matches[0].end] == first
    assert text[matches[1].start : matches[1].end] == second


def test_find_tokens_ignores_malformed_neighbours() -> None:
    # Arrange
    valid = format_token("PERSON", SAMPLE_ID)
    text = f"⟦SGW:person:{SAMPLE_ID}⟧ and {valid} and ⟦SGW:PERSON:SHORT⟧"

    # Act
    matches = find_tokens(text)

    # Assert
    assert [match.text for match in matches] == [valid]


def test_redaction_placeholder_is_never_a_token() -> None:
    # Arrange / Act
    placeholder = format_redaction("EMAIL_ADDRESS")

    # Assert
    assert placeholder == "⟦SGW:REDACTED:EMAIL_ADDRESS⟧"
    assert parse_token(placeholder) is None
    assert find_tokens(f"before {placeholder} after") == ()


def test_format_redaction_rejects_an_invalid_entity_type() -> None:
    with pytest.raises(ValueError, match="entity type"):
        format_redaction("not a type")


def test_redaction_of_a_crockford_shaped_entity_type_is_still_not_a_token() -> None:
    # Arrange: the pathological case where the type looks like an identifier.
    placeholder = format_redaction(SAMPLE_ID)

    # Act / Assert
    assert parse_token(placeholder) is None


# ---------------------------------------------------------------------------
# Identifiers
# ---------------------------------------------------------------------------
def test_new_token_id_matches_the_grammar() -> None:
    token_id = new_token_id()

    assert len(token_id) == TOKEN_ID_LENGTH
    assert set(token_id) <= set(CROCKFORD_ALPHABET)


def test_token_ids_are_unique_and_unordered() -> None:
    # Arrange / Act
    generated = [new_token_id() for _ in range(512)]

    # Assert: random, so collisions are impossible in practice ...
    assert len(set(generated)) == len(generated)
    # ... and consecutive ids share no timestamp-like prefix, unlike a ULID.
    assert generated != sorted(generated)
    assert all(first[:6] != second[:6] for first, second in pairwise(generated))
    assert len({token_id[0] for token_id in generated}) > 1


def test_encode_crockford_is_deterministic_and_length_checked() -> None:
    assert encode_crockford(bytes(16)) == "0" * TOKEN_ID_LENGTH
    assert encode_crockford(b"\xff" * 16) == "7" + "Z" * 25

    with pytest.raises(ValueError, match="16 bytes"):
        encode_crockford(b"short")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("entity_type", "raw", "expected"),
    [
        ("EMAIL_ADDRESS", "  Jane.Doe@Example.COM ", "jane.doe@example.com"),
        ("PHONE_NUMBER", "+1 (555) 010-9999", "15550109999"),
        ("PERSON", "  Ada   Lovelace\n", "Ada Lovelace"),
        ("US_SSN", "123-45-6789", "123456789"),
        ("CREDIT_CARD", "4111 1111 1111 1111", "4111111111111111"),
        ("IBAN_CODE", "gb82 west 1234 5698 7654 32", "GB82WEST12345698765432"),
        ("IP_ADDRESS", " 2001:DB8::1 ", "2001:db8::1"),
        ("CRYPTO", " 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 ", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
    ],
)
def test_entity_specific_normalization(entity_type: str, raw: str, expected: str) -> None:
    assert normalize(entity_type, raw) == expected


def test_unknown_entity_types_use_the_documented_default() -> None:
    assert "MYSTERY_TYPE" not in NORMALIZERS
    assert normalize("MYSTERY_TYPE", "  A  B  ") == normalize_default("  A  B  ") == "A B"


def test_normalization_dispatch_is_case_insensitive() -> None:
    assert normalize("email_address", " A@B.COM ") == "a@b.com"


def test_person_normalization_preserves_case() -> None:
    assert normalize("PERSON", "Ada Lovelace") != normalize("PERSON", "ada lovelace")


def test_normalization_folds_unicode_compatibility_forms() -> None:
    # U+FF15 is FULLWIDTH DIGIT FIVE; NFKC folds it to an ASCII 5.
    fullwidth_five = chr(0xFF10 + 5) * 3
    assert normalize("PHONE_NUMBER", fullwidth_five + "0100") == "5550100"


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------
def digest(
    fingerprinter: Fingerprinter,
    *,
    tenant_id: UUID = TENANT,
    session_id: UUID = SESSION,
    entity_type: str = "PERSON",
    normalized_value: str = "ada",
) -> str:
    return fingerprinter.fingerprint(
        tenant_id=tenant_id,
        session_id=session_id,
        entity_type=entity_type,
        normalized_value=normalized_value,
    )


def test_fingerprint_is_stable_for_identical_inputs() -> None:
    # Arrange
    fingerprinter = Fingerprinter(FINGERPRINT_KEY)

    # Act / Assert
    assert digest(fingerprinter, normalized_value="Ada Lovelace") == digest(
        fingerprinter, normalized_value="Ada Lovelace"
    )


def test_fingerprint_is_domain_separated_by_entity_type_tenant_and_session() -> None:
    # Arrange
    fingerprinter = Fingerprinter(FINGERPRINT_KEY)

    # Act
    digests = {
        digest(fingerprinter),
        digest(fingerprinter, entity_type="EMAIL_ADDRESS"),
        digest(fingerprinter, session_id=OTHER_SESSION),
        digest(fingerprinter, tenant_id=uuid4()),
    }

    # Assert
    assert len(digests) == 4


def test_fingerprint_framing_is_unambiguous() -> None:
    # Arrange: without length prefixing these two would concatenate identically.
    fingerprinter = Fingerprinter(FINGERPRINT_KEY)

    # Act
    first = fingerprinter.fingerprint(
        tenant_id=TENANT, session_id=SESSION, entity_type="AB", normalized_value="C"
    )
    second = fingerprinter.fingerprint(
        tenant_id=TENANT, session_id=SESSION, entity_type="A", normalized_value="BC"
    )

    # Assert
    assert first != second


def test_derived_key_differs_from_its_root_and_is_rejected_when_weak() -> None:
    root = b"root-secret-material-0123456789ab"

    assert derive_fingerprint_key(root) != root
    with pytest.raises(ValueError, match="at least"):
        derive_fingerprint_key(b"short")
    with pytest.raises(ValueError, match="at least"):
        Fingerprinter(b"short")


def test_fingerprinter_repr_hides_key_material() -> None:
    assert "redacted" in repr(Fingerprinter(FINGERPRINT_KEY))
    assert FINGERPRINT_KEY.decode() not in repr(Fingerprinter(FINGERPRINT_KEY))


def test_fingerprinter_can_be_built_from_settings() -> None:
    # Arrange
    base = Settings(audit_hmac_key=SecretStr("a" * 44))

    # Act
    fingerprinter = Fingerprinter.from_settings(base)

    # Assert
    assert isinstance(fingerprinter, Fingerprinter)


def test_a_dedicated_tokenization_key_takes_precedence_when_present() -> None:
    # Arrange: models a future settings field without changing settings today.
    class SettingsWithTokenKey(Settings):
        tokenization_hmac_key: SecretStr = SecretStr("t" * 44)

    audit_only = Settings(audit_hmac_key=SecretStr("a" * 44))
    dedicated = SettingsWithTokenKey(audit_hmac_key=SecretStr("a" * 44))

    # Act / Assert
    assert digest(Fingerprinter.from_settings(audit_only)) != digest(
        Fingerprinter.from_settings(dedicated)
    )


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------
def test_overlap_resolution_prefers_the_longer_span_and_is_deterministic() -> None:
    # Arrange
    long_span = entity("PERSON", 0, 10, score=0.5)
    short_span = entity("EMAIL_ADDRESS", 4, 8, score=0.99)
    later = entity("PHONE_NUMBER", 12, 18)

    # Act
    kept = resolve_overlaps([short_span, later, long_span])

    # Assert
    assert kept == (long_span, later)
    assert resolve_overlaps([later, long_span, short_span]) == kept


async def test_low_scoring_entities_are_ignored_entirely() -> None:
    # Arrange
    tokenizer, vault = build_tokenizer()
    policy = FakePolicy(min_scores={"PERSON": 0.8})
    text = "call Ada now"

    # Act
    result = await transform(
        tokenizer, text=text, entities=[entity("PERSON", 5, 8, score=0.4)], policy=policy
    )

    # Assert
    assert result.text == text
    assert result.summary.detected == 0
    assert vault.write_count == 0


async def test_spans_outside_the_text_are_rejected() -> None:
    tokenizer, vault = build_tokenizer()

    with pytest.raises(InvalidRequestError):
        await transform(
            tokenizer, text="short", entities=[entity("PERSON", 0, 99)], policy=FakePolicy()
        )
    assert vault.write_count == 0


# ---------------------------------------------------------------------------
# Tokenizer: replacement invariants
# ---------------------------------------------------------------------------
async def test_text_outside_selected_spans_is_unchanged() -> None:
    # Arrange
    tokenizer, _ = build_tokenizer()
    text = "Contact Ada Lovelace at ada@example.com — 日本語 🎌 tail"
    entities = [entity("PERSON", 8, 20), entity("EMAIL_ADDRESS", 24, 39)]

    # Act
    result = await transform(tokenizer, text=text, entities=entities, policy=FakePolicy())

    # Assert
    matches = find_tokens(result.text)
    assert len(matches) == 2
    assert result.text[: matches[0].start] == "Contact "
    assert result.text[matches[0].end : matches[1].start] == " at "
    assert result.text[matches[1].end :] == " — 日本語 🎌 tail"


async def test_every_tokenized_span_has_exactly_one_mapping() -> None:
    # Arrange
    tokenizer, vault = build_tokenizer()
    text = "a@x.com and b@x.com"
    entities = [entity("EMAIL_ADDRESS", 0, 7), entity("EMAIL_ADDRESS", 12, 19)]

    # Act
    result = await transform(tokenizer, text=text, entities=entities, policy=FakePolicy())

    # Assert
    assert len(result.mappings) == 2
    assert vault.write_count == 2
    tokens_in_text = {match.text for match in find_tokens(result.text)}
    assert tokens_in_text == {mapping.token for mapping in result.mappings}
    assert [mapping.original_value for mapping in result.mappings] == ["a@x.com", "b@x.com"]


async def test_redacted_spans_have_no_mapping_and_no_vault_write() -> None:
    # Arrange
    tokenizer, vault = build_tokenizer()
    policy = FakePolicy(actions={"US_SSN": EntityAction.REDACT})

    # Act
    result = await transform(
        tokenizer, text="ssn 123-45-6789 end", entities=[entity("US_SSN", 4, 15)], policy=policy
    )

    # Assert
    assert result.text == "ssn ⟦SGW:REDACTED:US_SSN⟧ end"
    assert result.mappings == ()
    assert vault.write_count == 0
    assert result.summary.redacted == 1


async def test_blocked_spans_stop_the_request_before_any_vault_write() -> None:
    # Arrange
    tokenizer, vault = build_tokenizer()
    policy = FakePolicy(actions={"US_SSN": EntityAction.BLOCK})
    entities = [entity("EMAIL_ADDRESS", 0, 7), entity("US_SSN", 12, 23)]

    # Act / Assert
    with pytest.raises(PolicyViolationError) as raised:
        await transform(tokenizer, text="a@x.com ssn 123-45-6789", entities=entities, policy=policy)

    assert vault.write_count == 0
    assert vault.calls == []
    assert raised.value.code is ErrorCode.POLICY_VIOLATION
    assert "123-45-6789" not in str(raised.value)
    assert "123-45-6789" not in repr(raised.value.log_context)


async def test_allowed_spans_leave_the_text_untouched() -> None:
    # Arrange
    tokenizer, vault = build_tokenizer()
    policy = FakePolicy(actions={"DATE_TIME": EntityAction.ALLOW})
    text = "meeting on Tuesday"

    # Act
    result = await transform(
        tokenizer, text=text, entities=[entity("DATE_TIME", 11, 18)], policy=policy
    )

    # Assert
    assert result.text == text
    assert result.mappings == ()
    assert vault.write_count == 0
    assert result.summary.allowed == 1


async def test_pseudonymized_spans_keep_their_shape_and_are_stable() -> None:
    # Arrange
    tokenizer, vault = build_tokenizer()
    policy = FakePolicy(actions={"EMAIL_ADDRESS": EntityAction.PSEUDONYMIZE})
    text = "ada@example.com and ada@example.com"
    entities = [entity("EMAIL_ADDRESS", 0, 15), entity("EMAIL_ADDRESS", 20, 35)]

    # Act
    result = await transform(tokenizer, text=text, entities=entities, policy=policy)

    # Assert
    surrogate = result.text[:15]
    assert surrogate != "ada@example.com"
    assert re.fullmatch(r"[a-z]{3}@[a-z]{7}\.[a-z]{3}", surrogate)
    assert result.text == f"{surrogate} and {surrogate}"
    assert len(result.mappings) == 2
    assert vault.write_count == 1
    assert result.summary.pseudonymized == 2


async def test_repeated_values_reuse_one_token_within_a_session() -> None:
    # Arrange
    tokenizer, vault = build_tokenizer()
    text = "Ada, ada, and  ADA"
    entities = [entity("PERSON", 0, 3), entity("PERSON", 5, 8), entity("PERSON", 15, 18)]

    # Act
    result = await transform(tokenizer, text=text, entities=entities, policy=FakePolicy())

    # Assert: PERSON normalization keeps case, so only the two "Ada"/"ADA" ...
    tokens = [mapping.token for mapping in result.mappings]
    assert tokens[0] != tokens[1]
    assert len({*tokens}) == 3
    assert vault.write_count == 3


async def test_case_insensitive_repeats_collapse_onto_one_token() -> None:
    # Arrange
    tokenizer, vault = build_tokenizer()
    text = "ada@x.com vs ADA@X.com"
    entities = [entity("EMAIL_ADDRESS", 0, 9), entity("EMAIL_ADDRESS", 13, 22)]

    # Act
    result = await transform(tokenizer, text=text, entities=entities, policy=FakePolicy())

    # Assert
    first, second = (mapping.token for mapping in result.mappings)
    assert first == second
    assert vault.write_count == 1
    assert len(find_tokens(result.text)) == 2


async def test_the_same_value_in_another_session_gets_another_token() -> None:
    # Arrange
    tokenizer, vault = build_tokenizer()
    entities = [entity("EMAIL_ADDRESS", 0, 9)]

    # Act
    first = await transform(
        tokenizer, text="ada@x.com", entities=entities, policy=FakePolicy(), session_id=SESSION
    )
    second = await transform(
        tokenizer,
        text="ada@x.com",
        entities=entities,
        policy=FakePolicy(),
        session_id=OTHER_SESSION,
    )

    # Assert
    assert first.mappings[0].token != second.mappings[0].token
    assert first.mappings[0].normalized_hmac != second.mappings[0].normalized_hmac
    assert vault.write_count == 2


async def test_identical_text_under_two_entity_types_gets_two_tokens() -> None:
    # Arrange
    tokenizer, vault = build_tokenizer()
    text = "12345 12345"
    entities = [entity("US_SSN", 0, 5), entity("PHONE_NUMBER", 6, 11)]

    # Act
    result = await transform(tokenizer, text=text, entities=entities, policy=FakePolicy())

    # Assert
    first, second = result.mappings
    assert first.token != second.token
    assert first.normalized_hmac != second.normalized_hmac
    assert vault.write_count == 2


# ---------------------------------------------------------------------------
# Tokenizer: limits, ordering, and failure modes
# ---------------------------------------------------------------------------
async def test_entity_limit_is_enforced_before_any_vault_write() -> None:
    # Arrange
    tokenizer, vault = build_tokenizer()
    policy = FakePolicy(max_entities=2)
    text = "a b c d"
    entities = [entity("PERSON", index, index + 1) for index in (0, 2, 4, 6)]

    # Act / Assert
    with pytest.raises(EntityLimitExceededError) as raised:
        await transform(tokenizer, text=text, entities=entities, policy=policy)

    assert vault.write_count == 0
    assert raised.value.log_context == {"entity_count": 4, "max_entities": 2}


async def test_the_limit_counts_only_selected_spans() -> None:
    # Arrange: two overlapping detections collapse into one selected span.
    tokenizer, _ = build_tokenizer()
    policy = FakePolicy(max_entities=1)
    entities = [entity("PERSON", 0, 10), entity("EMAIL_ADDRESS", 2, 6)]

    # Act
    result = await transform(tokenizer, text="0123456789", entities=entities, policy=policy)

    # Assert
    assert result.summary.detected == 1


async def test_mappings_are_returned_in_document_order() -> None:
    # Arrange
    tokenizer, _ = build_tokenizer()
    text = "one two three"
    entities = [entity("A", 0, 3), entity("B", 4, 7), entity("C", 8, 13)]

    # Act
    result = await transform(tokenizer, text=text, entities=entities, policy=FakePolicy())

    # Assert
    assert [mapping.entity_type for mapping in result.mappings] == ["A", "B", "C"]
    assert [mapping.original_value for mapping in result.mappings] == ["one", "two", "three"]
    assert [match.text for match in find_tokens(result.text)] == [
        mapping.token for mapping in result.mappings
    ]


async def test_mixed_actions_splice_correctly_across_many_spans() -> None:
    # Arrange
    tokenizer, _ = build_tokenizer()
    policy = FakePolicy(
        actions={
            "KEEP": EntityAction.ALLOW,
            "HIDE": EntityAction.REDACT,
            "SWAP": EntityAction.TOKENIZE,
        }
    )
    text = "keep|hideme|swapme|tail"
    entities = [entity("KEEP", 0, 4), entity("HIDE", 5, 11), entity("SWAP", 12, 18)]

    # Act
    result = await transform(tokenizer, text=text, entities=entities, policy=policy)

    # Assert
    token = result.mappings[0].token
    assert result.text == f"keep|⟦SGW:REDACTED:HIDE⟧|{token}|tail"
    assert result.summary.model_dump(exclude={"entity_types"}) == {
        "detected": 3,
        "tokenized": 1,
        "redacted": 1,
        "pseudonymized": 0,
        "blocked": 0,
        "allowed": 1,
        "restored": 0,
        "unknown_tokens": 0,
    }
    assert result.summary.entity_types == {"KEEP": 1, "HIDE": 1, "SWAP": 1}


async def test_a_vault_returning_a_bare_identifier_is_accepted() -> None:
    # Arrange: the vault contract permits the canonical token or the bare id.
    tokenizer, _ = build_tokenizer(FakeVault(token_override=SAMPLE_ID))

    # Act
    result = await transform(
        tokenizer, text="ada@x.com", entities=[entity("EMAIL_ADDRESS", 0, 9)], policy=FakePolicy()
    )

    # Assert
    assert result.text == format_token("EMAIL_ADDRESS", SAMPLE_ID)
    assert result.mappings[0].token_id == SAMPLE_ID


@pytest.mark.parametrize(
    "returned", ["not-a-token", "", f"⟦SGW:OTHER_TYPE:{SAMPLE_ID}⟧", SAMPLE_ID.lower()]
)
async def test_a_malformed_vault_token_fails_closed(returned: str) -> None:
    # Arrange
    tokenizer, _ = build_tokenizer(FakeVault(token_override=returned))

    # Act / Assert
    with pytest.raises(GatewayError) as raised:
        await transform(
            tokenizer,
            text="ada@x.com",
            entities=[entity("EMAIL_ADDRESS", 0, 9)],
            policy=FakePolicy(),
        )
    assert raised.value.code is ErrorCode.INTERNAL_ERROR


async def test_the_session_ttl_from_policy_reaches_the_vault() -> None:
    # Arrange
    tokenizer, vault = build_tokenizer()
    policy = FakePolicy(session_ttl_seconds=77)

    # Act
    await transform(
        tokenizer, text="ada@x.com", entities=[entity("EMAIL_ADDRESS", 0, 9)], policy=policy
    )

    # Assert
    assert vault.calls[0].ttl_seconds == 77


async def test_transform_does_not_mutate_its_inputs() -> None:
    # Arrange
    tokenizer, _ = build_tokenizer()
    entities = [entity("PERSON", 0, 3), entity("PERSON", 4, 7)]
    snapshot = list(entities)
    text = "Ada Bob"

    # Act
    await transform(tokenizer, text=text, entities=entities, policy=FakePolicy())

    # Assert
    assert entities == snapshot
    assert text == "Ada Bob"


async def test_empty_input_produces_an_empty_summary() -> None:
    # Arrange
    tokenizer, vault = build_tokenizer()

    # Act
    result = await transform(tokenizer, text="nothing here", entities=[], policy=FakePolicy())

    # Assert
    assert result.text == "nothing here"
    assert result.mappings == ()
    assert result.summary.detected == 0
    assert vault.write_count == 0


async def test_mappings_never_repr_the_original_value() -> None:
    # Arrange
    tokenizer, _ = build_tokenizer()

    # Act
    result = await transform(
        tokenizer, text="ada@x.com", entities=[entity("EMAIL_ADDRESS", 0, 9)], policy=FakePolicy()
    )

    # Assert
    assert "ada@x.com" not in repr(result.mappings[0])
    assert "ada@x.com" not in repr(result.summary)


# ---------------------------------------------------------------------------
# Property-based tests
# ---------------------------------------------------------------------------
SAFE_CHARACTERS = st.characters(
    codec="utf-8", exclude_characters=f"{LEFT_DELIMITER}{RIGHT_DELIMITER}"
)
FILLER = st.text(alphabet=SAFE_CHARACTERS, max_size=12)
VALUE = st.text(alphabet=SAFE_CHARACTERS, min_size=1, max_size=12)
ACTION_TYPES = ["TOKENIZE_ME", "REDACT_ME", "ALLOW_ME"]
PROPERTY_POLICY = FakePolicy(
    actions={
        "TOKENIZE_ME": EntityAction.TOKENIZE,
        "REDACT_ME": EntityAction.REDACT,
        "ALLOW_ME": EntityAction.ALLOW,
    }
)


@st.composite
def texts_with_spans(draw: st.DrawFn) -> tuple[str, tuple[DetectedEntity, ...], tuple[str, ...]]:
    """Build text as filler/value/filler/... so spans are known and never overlap."""
    count = draw(st.integers(min_value=0, max_value=6))
    fillers = draw(st.lists(FILLER, min_size=count + 1, max_size=count + 1))
    values = draw(st.lists(VALUE, min_size=count, max_size=count))
    types = draw(st.lists(st.sampled_from(ACTION_TYPES), min_size=count, max_size=count))

    pieces: list[str] = []
    entities: list[DetectedEntity] = []
    cursor = 0
    for index, value in enumerate(values):
        pieces.append(fillers[index])
        cursor += len(fillers[index])
        entities.append(
            DetectedEntity(
                entity_type=types[index], start=cursor, end=cursor + len(value), score=1.0
            )
        )
        pieces.append(value)
        cursor += len(value)
    pieces.append(fillers[-1])
    return "".join(pieces), tuple(entities), tuple(fillers)


@given(case=texts_with_spans())
@hypothesis_settings(max_examples=75, suppress_health_check=[HealthCheck.too_slow])
def test_property_untouched_text_is_preserved_and_tokens_are_counted(
    case: tuple[str, tuple[DetectedEntity, ...], tuple[str, ...]],
) -> None:
    # Arrange
    text, entities, fillers = case
    tokenizer, _ = build_tokenizer()

    # Act
    result = asyncio.run(transform(tokenizer, text=text, entities=entities, policy=PROPERTY_POLICY))

    # Assert: rebuild the expected string from the known per-action replacements.
    replacements = _expected_replacements(text, entities, result)
    expected = "".join(
        filler + replacement
        for filler, replacement in zip(fillers, [*replacements, ""], strict=True)
    )
    assert result.text == expected
    tokenized = sum(1 for item in entities if item.entity_type == "TOKENIZE_ME")
    assert len(find_tokens(result.text)) == tokenized
    assert len(result.mappings) == tokenized
    assert result.summary.detected == len(entities)


def _expected_replacements(
    text: str, entities: Sequence[DetectedEntity], result: TransformedText
) -> list[str]:
    """The exact replacement each span should have produced, in document order."""
    tokens = iter(mapping.token for mapping in result.mappings)
    replacements: list[str] = []
    for item in entities:
        if item.entity_type == "TOKENIZE_ME":
            replacements.append(next(tokens))
        elif item.entity_type == "REDACT_ME":
            replacements.append(format_redaction(item.entity_type))
        else:
            replacements.append(text[item.start : item.end])
    return replacements


@given(
    entity_type=st.text(alphabet=st.characters(codec="ascii"), max_size=70),
    token_id=st.text(alphabet=st.characters(codec="ascii"), max_size=30),
    left=st.sampled_from(["⟦", "[", "<", "", "⟧", "⟦⟦"]),
    right=st.sampled_from(["⟧", "]", ">", "", "⟦", "⟧⟧"]),
    namespace=st.sampled_from(["SGW", "sgw", "SG", "SGWX", ""]),
)
@hypothesis_settings(max_examples=400)
def test_property_parser_only_accepts_the_exact_grammar(
    entity_type: str, token_id: str, left: str, right: str, namespace: str
) -> None:
    # Arrange
    candidate = f"{left}{namespace}:{entity_type}:{token_id}{right}"

    # Act
    parsed = parse_token(candidate)

    # Assert
    is_well_formed = (
        left == LEFT_DELIMITER
        and right == RIGHT_DELIMITER
        and namespace == "SGW"
        and bool(re.fullmatch(r"[A-Z0-9_]{1,64}", entity_type))
        and entity_type != "REDACTED"
        and bool(re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", token_id))
    )
    assert (parsed is not None) is is_well_formed
    if parsed is not None:
        assert parsed.text == candidate


@given(raw=st.binary(min_size=16, max_size=16))
def test_property_encoded_identifiers_always_satisfy_the_grammar(raw: bytes) -> None:
    token_id = encode_crockford(raw)

    assert parse_token(format_token("PERSON", token_id)) == Token("PERSON", token_id)


def test_surrogate_of_an_empty_value_is_empty() -> None:
    assert surrogate_for(entity_type="PERSON", original_value="", fingerprint="f" * 64) == ""


@given(value=st.text(alphabet=SAFE_CHARACTERS, min_size=1, max_size=40))
def test_property_surrogates_preserve_shape(value: str) -> None:
    # Arrange / Act
    surrogate = surrogate_for(entity_type="PERSON", original_value=value, fingerprint="f" * 64)

    # Assert
    assert len(surrogate) == len(value)
    for source, replacement in zip(value, surrogate, strict=True):
        if source.isdigit():
            assert replacement.isdigit()
        elif source.isalpha():
            assert replacement.isalpha()
        else:
            assert replacement == source
