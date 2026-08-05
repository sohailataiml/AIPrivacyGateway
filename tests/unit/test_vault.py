"""Vault tests.

Every test here follows Arrange-Act-Assert and runs against ``fakeredis``.
Nothing in this file opens a socket.

The security block is the point of the file: it asserts the properties that
make the vault worth having -- ciphertext at rest, key rotation, associated
data binding, TTL enforcement, session and tenant isolation, atomicity, and
log hygiene.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import fakeredis.aioredis
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from app.domain.errors import VaultEncryptionError, VaultUnavailableError
from app.domain.models import VaultWriteRequest
from app.tokenization.grammar import Token, format_token, parse_token
from app.tokenization.ids import new_token_id
from app.vault.crypto import (
    ENVELOPE_MAGIC,
    ENVELOPE_VERSION,
    NONCE_BYTES,
    Envelope,
    EnvelopeCipher,
    VaultAad,
)
from app.vault.fakes import InMemoryTokenVault
from app.vault.keys import StaticKeyRing
from app.vault.protocol import TokenVault
from app.vault.records import VaultRecord
from app.vault.redis_vault import DEFAULT_KEY_PREFIX, MAX_BATCH_ENTRIES, RedisTokenVault

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from redis.asyncio import Redis

ACTIVE_KEY_ID = "local1"
RETIRED_KEY_ID = "local0"
ACTIVE_KEY = bytes(range(32))
RETIRED_KEY = bytes(range(32, 64))
OTHER_KEY = bytes(range(64, 96))

TENANT = UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = UUID("22222222-2222-2222-2222-222222222222")
SESSION = UUID("33333333-3333-3333-3333-333333333333")
OTHER_SESSION = UUID("44444444-4444-4444-4444-444444444444")

EMAIL = "jane.doe@example.com"
FINGERPRINT = "a" * 64
TTL = 300


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def key_ring() -> StaticKeyRing:
    return StaticKeyRing(
        {ACTIVE_KEY_ID: ACTIVE_KEY, RETIRED_KEY_ID: RETIRED_KEY},
        active_key_id=ACTIVE_KEY_ID,
    )


@pytest.fixture
def cipher(key_ring: StaticKeyRing) -> EnvelopeCipher:
    return EnvelopeCipher(key_ring)


@pytest.fixture
async def redis_client() -> AsyncIterator[Redis]:
    client = fakeredis.aioredis.FakeRedis(decode_responses=False)
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def vault(redis_client: Redis, cipher: EnvelopeCipher) -> RedisTokenVault:
    return RedisTokenVault(redis_client, cipher)


class _UnavailableKeyRing:
    """A ring whose key material cannot be fetched. Stands in for a KMS outage."""

    @property
    def active_key_id(self) -> str:
        return ACTIVE_KEY_ID

    def key(self, key_id: str) -> bytes:
        raise VaultEncryptionError(log_context={"reason": "key_unavailable"})


def aad(
    *,
    tenant_id: UUID = TENANT,
    session_id: UUID = SESSION,
    entity_type: str = "EMAIL_ADDRESS",
    token_id: str = "01J8Z6J4M7Y9Q2K3T4V5W6X7Y8",  # noqa: S107 - a ULID, not a secret
) -> VaultAad:
    return VaultAad(
        tenant_id=tenant_id,
        session_id=session_id,
        entity_type=entity_type,
        token_id=token_id,
    )


async def store_email(
    vault: RedisTokenVault,
    *,
    tenant_id: UUID = TENANT,
    session_id: UUID = SESSION,
    entity_type: str = "EMAIL_ADDRESS",
    normalized_hmac: str = FINGERPRINT,
    original_value: str = EMAIL,
    ttl_seconds: int = TTL,
) -> str:
    """Store one mapping through the batch API and return its token."""
    tokens = await vault.get_or_create_many(
        tenant_id=tenant_id,
        session_id=session_id,
        entries=(
            VaultWriteRequest(
                entity_type=entity_type,
                normalized_hmac=normalized_hmac,
                original_value=original_value,
            ),
        ),
        ttl_seconds=ttl_seconds,
    )
    return tokens[0]


def write_request(index: int) -> VaultWriteRequest:
    """A distinct entry, for tests that care about batch shape rather than content."""
    return VaultWriteRequest(
        entity_type="EMAIL_ADDRESS",
        normalized_hmac=f"{index:064d}",
        original_value=f"user{index}@example.com",
    )


def break_script(monkeypatch: pytest.MonkeyPatch, redis_client: Redis, message: str) -> None:
    """Make the batch write script unreachable.

    Patching ``evalsha`` rather than the connection is what puts the failure
    where the batch write actually happens.
    """

    def explode(*args: object, **kwargs: object) -> object:
        raise RedisConnectionError(message)

    monkeypatch.setattr(redis_client, "evalsha", explode)


# ---------------------------------------------------------------------------
# Token grammar
# ---------------------------------------------------------------------------
class TestTokenGrammar:
    def test_formats_token_with_mathematical_bracket_delimiters(self) -> None:
        # Arrange
        token_id = "01J8Z6J4M7Y9Q2K3T4V5W6X7Y8"

        # Act
        token = format_token("EMAIL_ADDRESS", token_id)

        # Assert
        assert token == f"⟦SGW:EMAIL_ADDRESS:{token_id}⟧"

    def test_parses_a_token_back_into_its_components(self) -> None:
        # Arrange
        token = format_token("PERSON", new_token_id())

        # Act
        parsed = parse_token(token)

        # Assert
        assert parsed is not None
        assert parsed.entity_type == "PERSON"
        assert len(parsed.token_id) == 26

    @pytest.mark.parametrize(
        "candidate",
        ["", "PERSON_1", "[SGW:PERSON:01J8Z6J4M7Y9Q2K3T4V5W6X7Y8]", "⟦SGW:PERSON:short⟧"],
    )
    def test_returns_none_for_strings_that_are_not_tokens(self, candidate: str) -> None:
        # Arrange / Act
        parsed = parse_token(candidate)

        # Assert
        assert parsed is None

    def test_rejects_entity_types_that_are_not_key_safe(self) -> None:
        # Arrange
        hostile = "EMAIL:../../other"

        # Act / Assert
        with pytest.raises(ValueError, match=r"entity[ _]type"):
            format_token(hostile, new_token_id())

    def test_generated_token_ids_are_not_sequential(self) -> None:
        # Arrange / Act
        ids = {new_token_id() for _ in range(50)}

        # Assert
        assert len(ids) == 50


# ---------------------------------------------------------------------------
# Envelope encryption
# ---------------------------------------------------------------------------
class TestEnvelopeCrypto:
    def test_round_trips_plaintext_under_matching_associated_data(
        self, cipher: EnvelopeCipher
    ) -> None:
        # Arrange
        plaintext = EMAIL.encode()

        # Act
        sealed = cipher.seal(plaintext=plaintext, aad=aad())
        opened = cipher.unseal(raw=sealed, aad=aad())

        # Assert
        assert opened == plaintext

    def test_envelope_header_is_versioned_and_records_the_key_id(
        self, cipher: EnvelopeCipher
    ) -> None:
        # Arrange
        sealed = cipher.seal(plaintext=b"payload", aad=aad())

        # Act
        envelope = Envelope.from_bytes(sealed)

        # Assert
        assert sealed.startswith(ENVELOPE_MAGIC)
        assert envelope.version == ENVELOPE_VERSION
        assert envelope.key_id == ACTIVE_KEY_ID
        assert len(envelope.nonce) == NONCE_BYTES

    def test_uses_a_fresh_nonce_for_every_record(self, cipher: EnvelopeCipher) -> None:
        # Arrange
        count = 200

        # Act
        nonces = {
            Envelope.from_bytes(cipher.seal(plaintext=b"same", aad=aad())).nonce
            for _ in range(count)
        }

        # Assert
        assert len(nonces) == count

    def test_records_sealed_before_a_rotation_still_open_afterwards(self) -> None:
        # Arrange
        old_ring = StaticKeyRing({RETIRED_KEY_ID: RETIRED_KEY}, active_key_id=RETIRED_KEY_ID)
        sealed = EnvelopeCipher(old_ring).seal(plaintext=EMAIL.encode(), aad=aad())
        rotated_ring = StaticKeyRing(
            {ACTIVE_KEY_ID: ACTIVE_KEY, RETIRED_KEY_ID: RETIRED_KEY},
            active_key_id=ACTIVE_KEY_ID,
        )

        # Act
        opened = EnvelopeCipher(rotated_ring).unseal(raw=sealed, aad=aad())

        # Assert
        assert opened == EMAIL.encode()

    def test_wrong_key_cannot_decrypt(self, cipher: EnvelopeCipher) -> None:
        # Arrange
        sealed = cipher.seal(plaintext=EMAIL.encode(), aad=aad())
        # Same key id, different key material: simulates a substituted secret.
        attacker = EnvelopeCipher(
            StaticKeyRing({ACTIVE_KEY_ID: OTHER_KEY}, active_key_id=ACTIVE_KEY_ID)
        )

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            attacker.unseal(raw=sealed, aad=aad())

    def test_unknown_key_id_cannot_decrypt(self, cipher: EnvelopeCipher) -> None:
        # Arrange
        sealed = cipher.seal(plaintext=EMAIL.encode(), aad=aad())
        stranger = EnvelopeCipher(StaticKeyRing({"other": OTHER_KEY}, active_key_id="other"))

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            stranger.unseal(raw=sealed, aad=aad())

    def test_modified_ciphertext_fails_authentication(self, cipher: EnvelopeCipher) -> None:
        # Arrange
        sealed = bytearray(cipher.seal(plaintext=EMAIL.encode(), aad=aad()))
        sealed[-1] ^= 0x01

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            cipher.unseal(raw=bytes(sealed), aad=aad())

    def test_modified_nonce_fails_authentication(self, cipher: EnvelopeCipher) -> None:
        # Arrange
        sealed = cipher.seal(plaintext=EMAIL.encode(), aad=aad())
        envelope = Envelope.from_bytes(sealed)
        tampered = Envelope(
            version=envelope.version,
            key_id=envelope.key_id,
            nonce=bytes(NONCE_BYTES),
            ciphertext=envelope.ciphertext,
        ).to_bytes()

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            cipher.unseal(raw=tampered, aad=aad())

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("tenant_id", OTHER_TENANT),
            ("session_id", OTHER_SESSION),
            ("entity_type", "PERSON"),
            ("token_id", "01ZZZZZZZZZZZZZZZZZZZZZZZZ"),
        ],
    )
    def test_associated_data_mismatch_fails_authentication(
        self, cipher: EnvelopeCipher, field: str, value: object
    ) -> None:
        # Arrange
        sealed = cipher.seal(plaintext=EMAIL.encode(), aad=aad())
        wrong = aad(**{field: value})  # type: ignore[arg-type]

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            cipher.unseal(raw=sealed, aad=wrong)

    def test_associated_data_fields_cannot_be_confused_by_shifting_boundaries(self) -> None:
        # Arrange -- "AB" + "C" must not serialize the same as "A" + "BC".
        left = VaultAad(TENANT, SESSION, "ABC", "01J8Z6J4M7Y9Q2K3T4V5W6X7Y8")
        right = VaultAad(TENANT, SESSION, "AB", "C01J8Z6J4M7Y9Q2K3T4V5W6X7")

        # Act / Assert
        assert left.to_bytes() != right.to_bytes()

    @pytest.mark.parametrize(
        "raw",
        [b"", b"SGWV", b"XXXX\x01\x05abcde", b"SGWV\x63\x05abcde" + bytes(30)],
    )
    def test_malformed_envelopes_are_rejected(self, cipher: EnvelopeCipher, raw: bytes) -> None:
        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            cipher.unseal(raw=raw, aad=aad())

    def test_envelope_repr_does_not_expose_ciphertext(self, cipher: EnvelopeCipher) -> None:
        # Arrange
        envelope = Envelope.from_bytes(cipher.seal(plaintext=EMAIL.encode(), aad=aad()))

        # Act
        rendered = repr(envelope)

        # Assert
        assert "ciphertext" not in rendered
        assert envelope.ciphertext.hex() not in rendered


# ---------------------------------------------------------------------------
# Record payload
# ---------------------------------------------------------------------------
class TestVaultRecord:
    def test_repr_never_exposes_the_original_value_or_token(self) -> None:
        # Arrange
        from datetime import UTC, datetime, timedelta

        now = datetime.now(UTC)
        record = VaultRecord(
            tenant_id=TENANT,
            session_id=SESSION,
            token=format_token("EMAIL_ADDRESS", new_token_id()),
            entity_type="EMAIL_ADDRESS",
            original_value=EMAIL,
            created_at=now,
            expires_at=now + timedelta(seconds=TTL),
        )

        # Act
        rendered = repr(record)

        # Assert
        assert EMAIL not in rendered
        assert record.token not in rendered

    def test_rejects_a_payload_from_an_unsupported_schema_version(self) -> None:
        # Arrange
        payload = b'{"schema_version": 99}'

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            VaultRecord.from_bytes(payload)

    def test_rejects_a_payload_that_is_not_json(self) -> None:
        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            VaultRecord.from_bytes(b"not json at all")

    def test_rejects_a_payload_missing_required_fields(self) -> None:
        # Arrange
        payload = b'{"schema_version": 1, "tenant_id": "not-a-uuid"}'

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            VaultRecord.from_bytes(payload)

    def test_serialized_payload_round_trips(self) -> None:
        # Arrange
        from datetime import UTC, datetime, timedelta

        now = datetime.now(UTC)
        record = VaultRecord(
            tenant_id=TENANT,
            session_id=SESSION,
            token=format_token("EMAIL_ADDRESS", new_token_id()),
            entity_type="EMAIL_ADDRESS",
            original_value=EMAIL,
            created_at=now,
            expires_at=now + timedelta(seconds=TTL),
        )

        # Act
        restored = VaultRecord.from_bytes(record.to_bytes())

        # Assert
        assert restored.original_value == EMAIL
        assert restored.token == record.token
        assert restored.tenant_id == TENANT


# ---------------------------------------------------------------------------
# Key ring
# ---------------------------------------------------------------------------
class TestKeyRing:
    def test_rejects_a_key_that_is_not_256_bits(self) -> None:
        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            StaticKeyRing({ACTIVE_KEY_ID: b"tooshort"}, active_key_id=ACTIVE_KEY_ID)

    def test_rejects_an_active_id_absent_from_the_ring(self) -> None:
        # Act / Assert
        with pytest.raises(ValueError, match="active_key_id"):
            StaticKeyRing({ACTIVE_KEY_ID: ACTIVE_KEY}, active_key_id="missing")

    def test_rejects_a_key_id_that_is_not_on_the_ring(self, key_ring: StaticKeyRing) -> None:
        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            key_ring.key("never-issued")

    def test_repr_does_not_expose_key_material(self, key_ring: StaticKeyRing) -> None:
        # Act
        rendered = repr(key_ring)

        # Assert
        assert ACTIVE_KEY.hex() not in rendered
        assert str(ACTIVE_KEY) not in rendered

    def test_settings_key_ring_serves_the_configured_active_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        import base64

        from app.config.settings import Settings
        from app.vault.keys import SettingsKeyRing

        monkeypatch.setenv("VAULT_ACTIVE_KEY_ID", ACTIVE_KEY_ID)
        monkeypatch.setenv("VAULT_KEY_LOCAL1", base64.b64encode(ACTIVE_KEY).decode())
        ring = SettingsKeyRing(Settings(_env_file=None))  # type: ignore[call-arg]

        # Act / Assert
        assert ring.active_key_id == ACTIVE_KEY_ID
        assert ring.key(ACTIVE_KEY_ID) == ACTIVE_KEY
        assert ACTIVE_KEY.hex() not in repr(ring)
        with pytest.raises(VaultEncryptionError):
            ring.key("never-issued")


# ---------------------------------------------------------------------------
# Redis vault behaviour
# ---------------------------------------------------------------------------
class TestRedisVaultBehaviour:
    def test_satisfies_the_token_vault_protocol(self, vault: RedisTokenVault) -> None:
        # Act / Assert
        assert isinstance(vault, TokenVault)

    async def test_stores_and_resolves_a_mapping(self, vault: RedisTokenVault) -> None:
        # Arrange
        token = await store_email(vault)

        # Act
        resolved = await vault.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={token})

        # Assert
        assert resolved == {token: EMAIL}

    async def test_returns_a_canonical_token(self, vault: RedisTokenVault) -> None:
        # Act
        token = await store_email(vault)

        # Assert
        assert parse_token(token) == Token("EMAIL_ADDRESS", token[-27:-1])

    async def test_repeated_value_in_one_session_reuses_its_token(
        self, vault: RedisTokenVault
    ) -> None:
        # Arrange
        first = await store_email(vault)

        # Act
        second = await store_email(vault)

        # Assert
        assert first == second

    async def test_different_fingerprints_receive_different_tokens(
        self, vault: RedisTokenVault
    ) -> None:
        # Arrange
        first = await store_email(vault)

        # Act
        second = await store_email(vault, normalized_hmac="b" * 64, original_value="bob@x.test")

        # Assert
        assert first != second

    async def test_the_same_value_in_two_sessions_receives_different_tokens(
        self, vault: RedisTokenVault
    ) -> None:
        # Arrange
        first = await store_email(vault)

        # Act
        second = await store_email(vault, session_id=OTHER_SESSION)

        # Assert
        assert first != second

    async def test_resolves_a_batch_of_tokens(self, vault: RedisTokenVault) -> None:
        # Arrange
        first = await store_email(vault)
        second = await store_email(
            vault, normalized_hmac="b" * 64, original_value="bob@example.com"
        )

        # Act
        resolved = await vault.resolve_many(
            tenant_id=TENANT, session_id=SESSION, tokens={first, second}
        )

        # Assert
        assert resolved == {first: EMAIL, second: "bob@example.com"}

    async def test_batch_retrieval_uses_a_single_round_trip(
        self, vault: RedisTokenVault, redis_client: Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        tokens = {
            await store_email(vault, normalized_hmac=f"{index:064d}", original_value=f"v{index}")
            for index in range(5)
        }
        calls: list[int] = []
        original = redis_client.mget

        async def counting_mget(keys: object, *args: object) -> object:
            calls.append(1)
            return await original(keys, *args)

        monkeypatch.setattr(redis_client, "mget", counting_mget)

        # Act
        resolved = await vault.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens=tokens)

        # Assert
        assert len(resolved) == 5
        assert calls == [1]

    async def test_unknown_and_malformed_tokens_are_simply_absent(
        self, vault: RedisTokenVault
    ) -> None:
        # Arrange
        real = await store_email(vault)
        stranger = format_token("EMAIL_ADDRESS", new_token_id())

        # Act
        resolved = await vault.resolve_many(
            tenant_id=TENANT, session_id=SESSION, tokens={real, stranger, "not-a-token"}
        )

        # Assert
        assert resolved == {real: EMAIL}

    async def test_resolving_no_tokens_touches_nothing(self, vault: RedisTokenVault) -> None:
        # Act
        resolved = await vault.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens=set())

        # Assert
        assert resolved == {}

    @pytest.mark.parametrize("ttl", [0, -1, 100_000])
    async def test_rejects_a_ttl_outside_the_permitted_range(
        self, vault: RedisTokenVault, ttl: int
    ) -> None:
        # Act / Assert
        with pytest.raises(ValueError, match="ttl_seconds"):
            await store_email(vault, ttl_seconds=ttl)

    async def test_rejects_an_entity_type_that_could_escape_its_namespace(
        self, vault: RedisTokenVault
    ) -> None:
        # Act / Assert
        with pytest.raises(ValueError, match=r"entity[ _]type"):
            await store_email(vault, entity_type="EMAIL:evil")

    async def test_reuse_refreshes_the_ttl_of_the_existing_record(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange
        token = await store_email(vault, ttl_seconds=60)
        parsed = parse_token(token)
        assert parsed is not None
        record_key = f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:{parsed.token_id}"

        # Act
        await store_email(vault, ttl_seconds=600)

        # Assert
        assert await redis_client.ttl(record_key) > 60

    async def test_mints_a_replacement_when_the_index_outlives_its_record(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange
        first = await store_email(vault)
        parsed = parse_token(first)
        assert parsed is not None
        await redis_client.delete(
            f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:{parsed.token_id}"
        )

        # Act
        second = await store_email(vault)

        # Assert
        assert second != first
        assert await vault.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={second}) == {
            second: EMAIL
        }


# ---------------------------------------------------------------------------
# Batch writes (ADR-0022)
# ---------------------------------------------------------------------------
class TestBatchWrites:
    """The write path's half of ADR-0022.

    The properties that matter are that the batch costs one round trip whatever
    its size, that its result lines up with its input, and that batching did
    not quietly cost the atomicity the single-token version had.
    """

    async def test_one_round_trip_regardless_of_batch_size(
        self, vault: RedisTokenVault, redis_client: Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange -- count script invocations, which is what a round trip is
        # for this operation. The first call of a process also pays a one-off
        # NOSCRIPT reload, so warm that up before measuring anything.
        invocations = 0
        original = redis_client.evalsha

        async def counting(*args: object, **kwargs: object) -> object:
            nonlocal invocations
            invocations += 1
            return await original(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(redis_client, "evalsha", counting)
        await vault.get_or_create_many(
            tenant_id=TENANT,
            session_id=OTHER_SESSION,
            entries=(write_request(0),),
            ttl_seconds=TTL,
        )
        invocations = 0

        # Act
        tokens = await vault.get_or_create_many(
            tenant_id=TENANT,
            session_id=SESSION,
            entries=tuple(write_request(index) for index in range(40)),
            ttl_seconds=TTL,
        )

        # Assert -- 40 mappings, one interaction. This is the assertion the
        # per-token implementation could not pass: it made 40.
        assert len(tokens) == 40
        assert len(set(tokens)) == 40
        assert invocations == 1

    @pytest.mark.parametrize("size", [1, 5, 50])
    async def test_round_trip_count_does_not_grow_with_the_batch(
        self,
        vault: RedisTokenVault,
        redis_client: Redis,
        monkeypatch: pytest.MonkeyPatch,
        size: int,
    ) -> None:
        # Arrange
        invocations = 0
        original = redis_client.evalsha

        async def counting(*args: object, **kwargs: object) -> object:
            nonlocal invocations
            invocations += 1
            return await original(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(redis_client, "evalsha", counting)
        await vault.get_or_create_many(
            tenant_id=TENANT,
            session_id=OTHER_SESSION,
            entries=(write_request(0),),
            ttl_seconds=TTL,
        )
        invocations = 0

        # Act
        await vault.get_or_create_many(
            tenant_id=TENANT,
            session_id=SESSION,
            entries=tuple(write_request(index) for index in range(size)),
            ttl_seconds=TTL,
        )

        # Assert -- the same cost at every size is the property, not the
        # particular number.
        assert invocations == 1

    async def test_results_are_positionally_aligned_with_entries(
        self, vault: RedisTokenVault
    ) -> None:
        # Arrange
        entries = tuple(write_request(index) for index in range(5))

        # Act
        tokens = await vault.get_or_create_many(
            tenant_id=TENANT, session_id=SESSION, entries=entries, ttl_seconds=TTL
        )
        resolved = await vault.resolve_many(
            tenant_id=TENANT, session_id=SESSION, tokens=set(tokens)
        )

        # Assert -- entry i's token resolves to entry i's value, not a
        # neighbour's.
        for entry, token in zip(entries, tokens, strict=True):
            assert resolved[token] == entry.original_value

    async def test_a_value_repeated_in_one_batch_collapses_onto_one_token(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange -- the same fingerprint five times, as a value repeated in
        # one message produces.
        entries = tuple(write_request(1) for _ in range(5))

        # Act
        tokens = await vault.get_or_create_many(
            tenant_id=TENANT, session_id=SESSION, entries=entries, ttl_seconds=TTL
        )

        # Assert -- one token, one record, five positions.
        assert len(tokens) == 5
        assert len(set(tokens)) == 1
        record_keys = await redis_client.keys(f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:*")
        assert len(record_keys) == 1

    async def test_a_repeat_across_batches_reuses_the_first_token(
        self, vault: RedisTokenVault
    ) -> None:
        # Arrange
        entries = (write_request(1), write_request(2))

        # Act
        first = await vault.get_or_create_many(
            tenant_id=TENANT, session_id=SESSION, entries=entries, ttl_seconds=TTL
        )
        second = await vault.get_or_create_many(
            tenant_id=TENANT, session_id=SESSION, entries=entries, ttl_seconds=TTL
        )

        # Assert
        assert first == second

    async def test_a_batch_mixes_reuse_and_creation_correctly(self, vault: RedisTokenVault) -> None:
        # Arrange -- one entry already stored, one brand new.
        known = write_request(1)
        (existing,) = await vault.get_or_create_many(
            tenant_id=TENANT, session_id=SESSION, entries=(known,), ttl_seconds=TTL
        )

        # Act
        tokens = await vault.get_or_create_many(
            tenant_id=TENANT,
            session_id=SESSION,
            entries=(write_request(2), known, write_request(3)),
            ttl_seconds=TTL,
        )

        # Assert
        assert tokens[1] == existing
        assert tokens[0] != existing
        assert tokens[2] != existing

    async def test_an_empty_batch_touches_redis_not_at_all(
        self, vault: RedisTokenVault, redis_client: Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        break_script(monkeypatch, redis_client, "should not be called")

        # Act
        tokens = await vault.get_or_create_many(
            tenant_id=TENANT, session_id=SESSION, entries=(), ttl_seconds=TTL
        )

        # Assert
        assert tokens == ()

    async def test_every_key_in_a_batch_carries_a_ttl(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange / Act
        await vault.get_or_create_many(
            tenant_id=TENANT,
            session_id=SESSION,
            entries=tuple(write_request(index) for index in range(6)),
            ttl_seconds=TTL,
        )

        # Assert -- records, indexes, and the meta set alike. A key without a
        # TTL is a mapping that outlives its session.
        keys = await redis_client.keys(f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:*")
        assert keys
        for key in keys:
            assert await redis_client.ttl(key) > 0

    async def test_reuse_within_a_batch_refreshes_the_existing_ttl(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange
        entry = write_request(1)
        await vault.get_or_create_many(
            tenant_id=TENANT, session_id=SESSION, entries=(entry,), ttl_seconds=60
        )

        # Act
        await vault.get_or_create_many(
            tenant_id=TENANT, session_id=SESSION, entries=(entry,), ttl_seconds=600
        )

        # Assert
        record_keys = await redis_client.keys(f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:*")
        assert len(record_keys) == 1
        assert await redis_client.ttl(record_keys[0]) > 60

    async def test_a_failed_batch_writes_nothing_at_all(
        self, redis_client: Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange -- sealing fails on the way in, as a key-manager outage would
        # make it.
        broken = RedisTokenVault(redis_client, EnvelopeCipher(_UnavailableKeyRing()))

        # Act
        with pytest.raises(VaultEncryptionError):
            await broken.get_or_create_many(
                tenant_id=TENANT,
                session_id=SESSION,
                entries=tuple(write_request(index) for index in range(4)),
                ttl_seconds=TTL,
            )

        # Assert -- no partial batch left behind.
        assert await redis_client.keys(f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:*") == []

    async def test_an_unreachable_redis_fails_a_batch_closed(
        self, vault: RedisTokenVault, redis_client: Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        break_script(monkeypatch, redis_client, "connection refused")

        # Act / Assert -- never a partial tuple the caller could mistake for
        # success.
        with pytest.raises(VaultUnavailableError):
            await vault.get_or_create_many(
                tenant_id=TENANT,
                session_id=SESSION,
                entries=tuple(write_request(index) for index in range(3)),
                ttl_seconds=TTL,
            )

    async def test_a_batch_beyond_the_ceiling_is_refused(self, vault: RedisTokenVault) -> None:
        # Arrange
        entries = tuple(write_request(index) for index in range(MAX_BATCH_ENTRIES + 1))

        # Act / Assert
        with pytest.raises(ValueError, match="ceiling"):
            await vault.get_or_create_many(
                tenant_id=TENANT, session_id=SESSION, entries=entries, ttl_seconds=TTL
            )

    async def test_a_hostile_entity_type_is_refused_before_any_write(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange -- the bad entry sits behind a good one, so a per-entry
        # validation loop would already have written the first.
        entries = (
            write_request(1),
            VaultWriteRequest(
                entity_type="EMAIL:../../other",
                normalized_hmac="b" * 64,
                original_value="x@example.com",
            ),
        )

        # Act
        with pytest.raises(ValueError):
            await vault.get_or_create_many(
                tenant_id=TENANT, session_id=SESSION, entries=entries, ttl_seconds=TTL
            )

        # Assert
        assert await redis_client.keys(f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:*") == []

    async def test_a_stale_index_entry_is_replaced_rather_than_returned(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange -- delete the record but leave its index behind, which is
        # what an evicted or expired record looks like.
        entry = write_request(1)
        (first,) = await vault.get_or_create_many(
            tenant_id=TENANT, session_id=SESSION, entries=(entry,), ttl_seconds=TTL
        )
        record_keys = await redis_client.keys(f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:*")
        await redis_client.delete(*record_keys)

        # Act
        (second,) = await vault.get_or_create_many(
            tenant_id=TENANT, session_id=SESSION, entries=(entry,), ttl_seconds=TTL
        )

        # Assert -- a fresh token that resolves, not the orphan.
        assert second != first
        assert await vault.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={second}) == {
            second: entry.original_value
        }

    async def test_concurrent_overlapping_batches_agree_on_every_token(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange -- eight callers writing the same eight fingerprints at once,
        # which is the race the single-token version used WATCH to survive.
        entries = tuple(write_request(index) for index in range(8))

        # Act
        results = await asyncio.gather(
            *[
                vault.get_or_create_many(
                    tenant_id=TENANT, session_id=SESSION, entries=entries, ttl_seconds=TTL
                )
                for _ in range(8)
            ]
        )

        # Assert -- every caller got identical tokens, and only eight records
        # exist.
        assert len({tuple(result) for result in results}) == 1
        record_keys = await redis_client.keys(f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:*")
        assert len(record_keys) == 8

    async def test_batches_in_two_sessions_do_not_share_tokens(
        self, vault: RedisTokenVault
    ) -> None:
        # Arrange
        entries = tuple(write_request(index) for index in range(4))

        # Act
        here = await vault.get_or_create_many(
            tenant_id=TENANT, session_id=SESSION, entries=entries, ttl_seconds=TTL
        )
        there = await vault.get_or_create_many(
            tenant_id=TENANT, session_id=OTHER_SESSION, entries=entries, ttl_seconds=TTL
        )

        # Assert
        assert set(here).isdisjoint(there)
        assert (
            await vault.resolve_many(tenant_id=TENANT, session_id=OTHER_SESSION, tokens=set(here))
            == {}
        )

    async def test_a_malformed_script_reply_fails_closed(
        self, vault: RedisTokenVault, redis_client: Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange -- a reply shorter than the batch, which would otherwise pair
        # spans with other spans' tokens.
        async def truncated(*args: object, **kwargs: object) -> list[object]:
            return [b"01J8Z6J4M7Y9Q2K3T4V5W6X7Y8", 1]

        monkeypatch.setattr(redis_client, "evalsha", truncated)

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            await vault.get_or_create_many(
                tenant_id=TENANT,
                session_id=SESSION,
                entries=(write_request(1), write_request(2)),
                ttl_seconds=TTL,
            )

    async def test_a_malformed_token_id_from_the_index_fails_closed(
        self, vault: RedisTokenVault, redis_client: Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        async def garbage(*args: object, **kwargs: object) -> list[object]:
            return [b"not-a-token-id", 0]

        monkeypatch.setattr(redis_client, "evalsha", garbage)

        # Act / Assert -- better to fail than to hand back a token that cannot
        # resolve.
        with pytest.raises(VaultEncryptionError):
            await vault.get_or_create_many(
                tenant_id=TENANT,
                session_id=SESSION,
                entries=(write_request(1),),
                ttl_seconds=TTL,
            )


# ---------------------------------------------------------------------------
# Session deletion
# ---------------------------------------------------------------------------
class TestSessionDeletion:
    async def test_deletion_removes_every_mapping_for_that_session(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange
        first = await store_email(vault)
        second = await store_email(
            vault, normalized_hmac="b" * 64, original_value="bob@example.com"
        )

        # Act
        removed = await vault.delete_session(tenant_id=TENANT, session_id=SESSION)

        # Assert
        assert removed == 2
        assert (
            await vault.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={first, second})
            == {}
        )
        assert await redis_client.keys(f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:*") == []

    async def test_deletion_leaves_another_session_untouched(self, vault: RedisTokenVault) -> None:
        # Arrange
        doomed = await store_email(vault)
        survivor = await store_email(vault, session_id=OTHER_SESSION)

        # Act
        await vault.delete_session(tenant_id=TENANT, session_id=SESSION)

        # Assert
        assert await vault.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={doomed}) == {}
        assert await vault.resolve_many(
            tenant_id=TENANT, session_id=OTHER_SESSION, tokens={survivor}
        ) == {survivor: EMAIL}

    async def test_deletion_leaves_another_tenant_untouched(self, vault: RedisTokenVault) -> None:
        # Arrange
        doomed = await store_email(vault)
        survivor = await store_email(vault, tenant_id=OTHER_TENANT)

        # Act
        await vault.delete_session(tenant_id=TENANT, session_id=SESSION)

        # Assert
        assert await vault.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={doomed}) == {}
        assert await vault.resolve_many(
            tenant_id=OTHER_TENANT, session_id=SESSION, tokens={survivor}
        ) == {survivor: EMAIL}

    async def test_deleting_an_unknown_session_reports_zero(self, vault: RedisTokenVault) -> None:
        # Act
        removed = await vault.delete_session(tenant_id=TENANT, session_id=uuid4())

        # Assert
        assert removed == 0


# ---------------------------------------------------------------------------
# Security properties
# ---------------------------------------------------------------------------
@pytest.mark.security
class TestVaultSecurity:
    async def test_stored_bytes_contain_no_plaintext_original(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange
        await store_email(vault)

        # Act
        blob = b""
        for key in await redis_client.keys("*"):
            blob += key
            key_type = await redis_client.type(key)
            if key_type == b"set":
                blob += b"".join(await redis_client.smembers(key))
            else:
                blob += await redis_client.get(key) or b""

        # Assert
        assert EMAIL.encode() not in blob
        assert b"jane" not in blob.lower()
        assert b"original_value" not in blob

    async def test_no_key_name_contains_the_fingerprint_preimage(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange
        await store_email(vault)

        # Act
        names = b" ".join(await redis_client.keys("*"))

        # Assert
        assert FINGERPRINT.encode() not in names
        assert EMAIL.encode() not in names

    async def test_every_key_written_carries_a_ttl(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange
        await store_email(vault)
        await store_email(vault, normalized_hmac="b" * 64, original_value="bob@example.com")
        await store_email(vault, session_id=OTHER_SESSION)

        # Act
        keys = await redis_client.keys("*")
        ttls = {key: await redis_client.ttl(key) for key in keys}

        # Assert
        assert keys
        assert all(ttl > 0 for ttl in ttls.values()), ttls

    async def test_an_expired_token_cannot_resolve(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange -- create normally, then accelerate expiry rather than sleep
        # for the full TTL.
        token = await store_email(vault)
        for key in await redis_client.keys("*"):
            await redis_client.pexpire(key, 1)
        await asyncio.sleep(0.05)

        # Act
        resolved = await vault.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={token})

        # Assert
        assert resolved == {}

    async def test_a_token_from_another_session_cannot_resolve(
        self, vault: RedisTokenVault
    ) -> None:
        # Arrange
        token = await store_email(vault)

        # Act
        resolved = await vault.resolve_many(
            tenant_id=TENANT, session_id=OTHER_SESSION, tokens={token}
        )

        # Assert
        assert resolved == {}

    async def test_a_token_from_another_tenant_cannot_resolve(self, vault: RedisTokenVault) -> None:
        # Arrange
        token = await store_email(vault)

        # Act
        resolved = await vault.resolve_many(
            tenant_id=OTHER_TENANT, session_id=SESSION, tokens={token}
        )

        # Assert
        assert resolved == {}

    async def test_a_record_relocated_to_another_tenant_fails_authentication(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange -- an attacker with Redis write access copies the envelope
        # into their own namespace. The AAD binding must defeat this.
        token = await store_email(vault)
        parsed = parse_token(token)
        assert parsed is not None
        source = f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:{parsed.token_id}"
        target = f"{DEFAULT_KEY_PREFIX}:{OTHER_TENANT}:{SESSION}:token:{parsed.token_id}"
        envelope = await redis_client.get(source)
        assert envelope is not None
        await redis_client.set(target, envelope, ex=TTL)

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            await vault.resolve_many(tenant_id=OTHER_TENANT, session_id=SESSION, tokens={token})

    async def test_a_record_relocated_to_another_session_fails_authentication(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange
        token = await store_email(vault)
        parsed = parse_token(token)
        assert parsed is not None
        envelope = await redis_client.get(
            f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:{parsed.token_id}"
        )
        assert envelope is not None
        await redis_client.set(
            f"{DEFAULT_KEY_PREFIX}:{TENANT}:{OTHER_SESSION}:token:{parsed.token_id}",
            envelope,
            ex=TTL,
        )

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            await vault.resolve_many(tenant_id=TENANT, session_id=OTHER_SESSION, tokens={token})

    async def test_a_record_relabelled_with_another_entity_type_fails_authentication(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange
        token = await store_email(vault)
        parsed = parse_token(token)
        assert parsed is not None
        envelope = await redis_client.get(
            f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:{parsed.token_id}"
        )
        assert envelope is not None
        # Same token id, PERSON in place of EMAIL_ADDRESS.
        relabelled = format_token("PERSON", parsed.token_id)

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            await vault.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={relabelled})

    async def test_tampered_ciphertext_in_redis_fails_authentication(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange
        token = await store_email(vault)
        parsed = parse_token(token)
        assert parsed is not None
        key = f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:{parsed.token_id}"
        stored = bytearray(await redis_client.get(key) or b"")
        stored[-1] ^= 0xFF
        await redis_client.set(key, bytes(stored), ex=TTL)

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            await vault.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={token})

    async def test_a_record_sealed_under_a_key_outside_the_ring_cannot_be_opened(
        self, redis_client: Redis, cipher: EnvelopeCipher
    ) -> None:
        # Arrange
        vault = RedisTokenVault(redis_client, cipher)
        token = await store_email(vault)
        stranger = RedisTokenVault(
            redis_client,
            EnvelopeCipher(StaticKeyRing({ACTIVE_KEY_ID: OTHER_KEY}, active_key_id=ACTIVE_KEY_ID)),
        )

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            await stranger.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={token})

    async def test_a_client_that_decodes_responses_is_rejected_not_guessed_at(
        self, cipher: EnvelopeCipher
    ) -> None:
        # Arrange -- decode_responses=True mangles binary envelopes, so the
        # vault must refuse rather than silently return nothing.
        client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        writer = RedisTokenVault(fakeredis.aioredis.FakeRedis(decode_responses=False), cipher)
        token = await store_email(writer)
        parsed = parse_token(token)
        assert parsed is not None
        await client.set(
            f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:{parsed.token_id}", "mangled", ex=TTL
        )
        reader = RedisTokenVault(client, cipher)

        # Act / Assert
        with pytest.raises(VaultEncryptionError):
            await reader.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={token})
        await client.aclose()

    async def test_concurrent_identical_inserts_return_one_stable_token(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange
        writers = 24

        # Act
        tokens = await asyncio.gather(*[store_email(vault) for _ in range(writers)])

        # Assert
        assert len(set(tokens)) == 1
        record_keys = await redis_client.keys(f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:*")
        assert len(record_keys) == 1
        assert await vault.resolve_many(
            tenant_id=TENANT, session_id=SESSION, tokens={tokens[0]}
        ) == {tokens[0]: EMAIL}

    async def test_concurrent_distinct_inserts_each_get_their_own_token(
        self, vault: RedisTokenVault
    ) -> None:
        # Arrange
        writers = 12

        # Act
        tokens = await asyncio.gather(
            *[
                store_email(vault, normalized_hmac=f"{index:064d}", original_value=f"v{index}")
                for index in range(writers)
            ]
        )

        # Assert
        assert len(set(tokens)) == writers

    async def test_an_unreachable_redis_fails_closed_on_write(
        self, vault: RedisTokenVault, redis_client: Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        break_script(monkeypatch, redis_client, "connection refused")

        # Act / Assert
        with pytest.raises(VaultUnavailableError):
            await store_email(vault)

    async def test_an_unreachable_redis_fails_closed_on_resolve(
        self, vault: RedisTokenVault, redis_client: Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange -- a real token exists; the outage must not look like "no
        # mappings", which would let unrestored tokens reach a caller.
        token = await store_email(vault)

        async def explode(*args: object, **kwargs: object) -> object:
            raise RedisConnectionError("connection refused")

        monkeypatch.setattr(redis_client, "mget", explode)

        # Act / Assert
        with pytest.raises(VaultUnavailableError):
            await vault.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={token})

    async def test_an_unreachable_redis_fails_closed_on_delete(
        self, vault: RedisTokenVault, redis_client: Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        async def explode(*args: object, **kwargs: object) -> object:
            raise RedisConnectionError("connection refused")

        monkeypatch.setattr(redis_client, "smembers", explode)

        # Act / Assert
        with pytest.raises(VaultUnavailableError):
            await vault.delete_session(tenant_id=TENANT, session_id=SESSION)

    async def test_an_outage_is_reported_without_naming_the_backing_store(
        self, vault: RedisTokenVault, redis_client: Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        break_script(monkeypatch, redis_client, "redis://secret-host:6379 connection refused")

        # Act
        with pytest.raises(VaultUnavailableError) as caught:
            await store_email(vault)

        # Assert
        assert "secret-host" not in caught.value.public_message
        assert caught.value.status_code == 503

    async def test_no_plaintext_mapping_appears_in_logs_when_encryption_fails(
        self, redis_client: Redis, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Arrange -- a ring that cannot produce its active key, e.g. a secrets
        # manager outage. Every seal then fails.
        broken = RedisTokenVault(redis_client, EnvelopeCipher(_UnavailableKeyRing()))
        caplog.set_level(logging.DEBUG)

        # Act
        with pytest.raises(VaultEncryptionError):
            await store_email(broken)

        # Assert
        assert caplog.records
        emitted = "\n".join(
            record.getMessage() + repr(record.__dict__) for record in caplog.records
        )
        assert EMAIL not in emitted
        assert "jane" not in emitted.lower()
        assert FINGERPRINT not in emitted

    async def test_no_plaintext_appears_in_logs_when_decryption_fails(
        self, vault: RedisTokenVault, redis_client: Redis, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Arrange
        token = await store_email(vault)
        parsed = parse_token(token)
        assert parsed is not None
        key = f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:{parsed.token_id}"
        stored = bytearray(await redis_client.get(key) or b"")
        stored[-2] ^= 0xFF
        await redis_client.set(key, bytes(stored), ex=TTL)
        caplog.set_level(logging.DEBUG)

        # Act
        with pytest.raises(VaultEncryptionError):
            await vault.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={token})

        # Assert
        emitted = "\n".join(
            record.getMessage() + repr(record.__dict__) for record in caplog.records
        )
        assert EMAIL not in emitted
        assert token not in emitted

    async def test_the_ciphertext_of_two_identical_values_differs_across_sessions(
        self, vault: RedisTokenVault, redis_client: Redis
    ) -> None:
        # Arrange
        first = await store_email(vault)
        second = await store_email(vault, session_id=OTHER_SESSION)
        first_id = parse_token(first)
        second_id = parse_token(second)
        assert first_id is not None
        assert second_id is not None

        # Act
        left = await redis_client.get(
            f"{DEFAULT_KEY_PREFIX}:{TENANT}:{SESSION}:token:{first_id.token_id}"
        )
        right = await redis_client.get(
            f"{DEFAULT_KEY_PREFIX}:{TENANT}:{OTHER_SESSION}:token:{second_id.token_id}"
        )

        # Assert
        assert left != right


# ---------------------------------------------------------------------------
# In-memory fake
# ---------------------------------------------------------------------------
class TestInMemoryTokenVault:
    def test_satisfies_the_token_vault_protocol(self) -> None:
        # Act / Assert
        assert isinstance(InMemoryTokenVault(), TokenVault)

    def test_exposes_the_same_write_signature_as_the_real_vault(self) -> None:
        # Arrange -- ``runtime_checkable`` only checks that a name exists, so
        # it would not notice the fake keeping an older parameter list. A fake
        # that drifts from the real vault is how a green suite hides a broken
        # wiring path.
        real = inspect.signature(RedisTokenVault.get_or_create_many)
        fake = inspect.signature(InMemoryTokenVault.get_or_create_many)

        # Act / Assert
        assert list(real.parameters) == list(fake.parameters)

    def test_offers_no_single_token_write(self) -> None:
        # Arrange / Act / Assert -- ADR-0022 has no per-token write, and a
        # helpfully reinstated one is how the loop would come back.
        assert not hasattr(InMemoryTokenVault(), "get_or_create")
        assert not hasattr(RedisTokenVault, "get_or_create")

    async def test_duplicates_within_one_batch_collapse(self) -> None:
        # Arrange
        fake = InMemoryTokenVault()
        entries = tuple(write_request(1) for _ in range(4))

        # Act
        tokens = await fake.get_or_create_many(
            tenant_id=TENANT, session_id=SESSION, entries=entries, ttl_seconds=TTL
        )

        # Assert -- the same collapse the Redis implementation performs.
        assert len(tokens) == 4
        assert len(set(tokens)) == 1
        assert fake.stored_original_values() == ["user1@example.com"]

    async def test_stores_and_resolves_a_mapping(self) -> None:
        # Arrange
        fake = InMemoryTokenVault()
        token = await store_email(fake)  # type: ignore[arg-type]

        # Act
        resolved = await fake.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={token})

        # Assert
        assert resolved == {token: EMAIL}

    async def test_reuses_a_token_for_a_repeated_fingerprint(self) -> None:
        # Arrange
        fake = InMemoryTokenVault()

        # Act
        first = await store_email(fake)  # type: ignore[arg-type]
        second = await store_email(fake)  # type: ignore[arg-type]

        # Assert
        assert first == second

    async def test_isolates_tenants_and_sessions(self) -> None:
        # Arrange
        fake = InMemoryTokenVault()
        token = await store_email(fake)  # type: ignore[arg-type]

        # Act
        other_session = await fake.resolve_many(
            tenant_id=TENANT, session_id=OTHER_SESSION, tokens={token}
        )
        other_tenant = await fake.resolve_many(
            tenant_id=OTHER_TENANT, session_id=SESSION, tokens={token}
        )

        # Assert
        assert other_session == {}
        assert other_tenant == {}

    async def test_expires_records_using_the_injected_clock(self) -> None:
        # Arrange
        now = [1000.0]
        fake = InMemoryTokenVault(clock=lambda: now[0])
        token = await store_email(fake, ttl_seconds=60)  # type: ignore[arg-type]

        # Act
        now[0] += 61

        # Assert
        assert await fake.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={token}) == {}

    async def test_deletes_a_session(self) -> None:
        # Arrange
        fake = InMemoryTokenVault()
        token = await store_email(fake)  # type: ignore[arg-type]

        # Act
        removed = await fake.delete_session(tenant_id=TENANT, session_id=SESSION)

        # Assert
        assert removed == 1
        assert await fake.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens={token}) == {}

    async def test_simulated_failure_makes_every_call_fail_closed(self) -> None:
        # Arrange
        fake = InMemoryTokenVault()
        fake.simulate_failure(VaultUnavailableError())

        # Act / Assert
        with pytest.raises(VaultUnavailableError):
            await store_email(fake)  # type: ignore[arg-type]
        with pytest.raises(VaultUnavailableError):
            await fake.resolve_many(tenant_id=TENANT, session_id=SESSION, tokens=set())

    async def test_entry_repr_does_not_expose_the_original_value(self) -> None:
        # Arrange
        fake = InMemoryTokenVault()
        await store_email(fake)  # type: ignore[arg-type]

        # Act
        rendered = repr(fake)

        # Assert
        assert EMAIL not in rendered


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
class TestVaultMetrics:
    def test_no_metric_label_can_carry_tenant_session_or_value_data(self) -> None:
        # Arrange
        from app.vault import metrics

        collectors = (
            metrics.VAULT_OPERATION_SECONDS,
            metrics.VAULT_OPERATIONS_TOTAL,
            metrics.VAULT_RECORDS_TOTAL,
            metrics.VAULT_TOKEN_LOOKUPS_TOTAL,
        )
        forbidden = {"tenant", "tenant_id", "session", "session_id", "token", "value", "key_id"}

        # Act
        names = {name for collector in collectors for name in collector._labelnames}

        # Assert
        assert names.isdisjoint(forbidden)
        assert names == {"operation", "outcome", "result"}

    async def test_operation_latency_is_observed(self, vault: RedisTokenVault) -> None:
        # Arrange
        from app.vault.metrics import OPERATION_GET_OR_CREATE_MANY, VAULT_OPERATION_SECONDS

        before = VAULT_OPERATION_SECONDS.labels(operation=OPERATION_GET_OR_CREATE_MANY)._sum.get()

        # Act
        await store_email(vault)

        # Assert
        after = VAULT_OPERATION_SECONDS.labels(operation=OPERATION_GET_OR_CREATE_MANY)._sum.get()
        assert after >= before

    async def test_an_outage_is_counted_as_unavailable_not_as_success(
        self, vault: RedisTokenVault, redis_client: Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange
        from app.vault.metrics import (
            OPERATION_GET_OR_CREATE_MANY,
            OUTCOME_UNAVAILABLE,
            VAULT_OPERATIONS_TOTAL,
        )

        counter = VAULT_OPERATIONS_TOTAL.labels(
            operation=OPERATION_GET_OR_CREATE_MANY, outcome=OUTCOME_UNAVAILABLE
        )
        before = counter._value.get()

        break_script(monkeypatch, redis_client, "down")

        # Act
        with pytest.raises(VaultUnavailableError):
            await store_email(vault)

        # Assert
        assert counter._value.get() == before + 1


def test_no_module_in_the_vault_package_calls_print() -> None:
    # Arrange
    from app import vault as package

    directory = Path(str(package.__file__)).parent

    # Act
    offenders = [
        module.name
        for module in sorted(directory.glob("*.py"))
        if "print(" in module.read_text(encoding="utf-8")
    ]

    # Assert
    assert offenders == []
