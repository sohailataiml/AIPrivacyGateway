"""Output restoration tests.

The point of this file is the negative space: what restoration refuses to do.
It must not resolve a token minted for another session or tenant, must not
resolve a token whose entity type was rewritten in flight, must not treat
near-miss syntax as a token, must not rescan a restored value, and must not
return half-restored text when the vault goes down after the provider replied.

Every test uses ``InMemoryTokenVault``, which reproduces tenant and session
scoping exactly. Nothing here opens a socket.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Final, cast
from uuid import UUID

import pytest

from app.domain.errors import (
    ProviderResponseInvalidError,
    RestorationError,
    VaultEncryptionError,
    VaultUnavailableError,
)
from app.domain.models import (
    PrivacySummary,
    ProviderResponse,
    ProviderUsage,
    UnknownTokenAction,
    VaultWriteRequest,
)
from app.restoration import DEFAULT_MAX_OUTPUT_CHARS, OutputPipeline, RestoredOutput
from app.restoration.protocols import PolicyLike, VaultLike
from app.tokenization.grammar import format_redaction, format_token, parse_token
from app.vault.fakes import InMemoryTokenVault

Vault = InMemoryTokenVault
"""Short alias: it appears in almost every signature in this file."""

TENANT = UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = UUID("22222222-2222-2222-2222-222222222222")
SESSION = UUID("33333333-3333-3333-3333-333333333333")
OTHER_SESSION = UUID("44444444-4444-4444-4444-444444444444")

EMAIL: Final = "jane.doe@example.com"
PERSON: Final = "Jane Doe"
PHONE: Final = "+1-555-0100"
TTL: Final = 300

UNMINTED_ID: Final = "01J8Z6J4M7Y9Q2K3T4V5W6X7Y8"
UNKNOWN_TOKEN: Final = format_token("EMAIL_ADDRESS", UNMINTED_ID)

NOT_TOKENS: Final = [
    # Malformed or split token syntax.
    f"⟦SGW:EMAIL_ADDRESS:{UNMINTED_ID}",  # no closing delimiter
    f"SGW:EMAIL_ADDRESS:{UNMINTED_ID}⟧",  # no opening delimiter
    f"⟦SGW:EMAIL_ADDRESS:\n{UNMINTED_ID}⟧",  # split across a line break
    f"⟦SGW:EMAIL_ADDRESS:{UNMINTED_ID[:-1]}⟧",  # identifier one character short
    f"⟦SGW:EMAIL_ADDRESS:{UNMINTED_ID.lower()}⟧",  # lowercase identifier
    f"⟦XXX:EMAIL_ADDRESS:{UNMINTED_ID}⟧",  # wrong namespace
    f"⟦SGW:EMAIL_ADDRESS:EXTRA:{UNMINTED_ID}⟧",  # extra field
    f"⟦SGW:email_address:{UNMINTED_ID}⟧",  # lowercase entity type
    # Natural text that merely resembles part of the grammar.
    "Our SGW: prefix is documented in the ⟦ style guide.",
    "The namespace SGW and the type EMAIL_ADDRESS are separate ideas.",
    "⟦SGW:EMAIL_ADDRESS⟧ is a redaction marker shape, not a token.",
    "Use the ⟦ ⟧ brackets sparingly.",
]


# --- Fixtures and doubles --------------------------------------------------
@dataclass(frozen=True, slots=True)
class StubPolicy:
    """The single policy field restoration reads."""

    unknown_output_token_action: UnknownTokenAction = UnknownTokenAction.PRESERVE


class RecordingVault:
    """Counts vault round trips so tests can assert batching."""

    def __init__(self, inner: VaultLike) -> None:
        self._inner = inner
        self.calls: list[frozenset[str]] = []

    async def resolve_many(
        self, *, tenant_id: UUID, session_id: UUID, tokens: set[str]
    ) -> dict[str, str]:
        self.calls.append(frozenset(tokens))
        return await self._inner.resolve_many(
            tenant_id=tenant_id, session_id=session_id, tokens=tokens
        )


@pytest.fixture
def vault() -> Vault:
    return InMemoryTokenVault()


async def mint(
    vault: Vault,
    *,
    value: str,
    entity_type: str = "EMAIL_ADDRESS",
    tenant_id: UUID = TENANT,
    session_id: UUID = SESSION,
) -> str:
    """Store one mapping and return its token."""
    tokens = await vault.get_or_create_many(
        tenant_id=tenant_id,
        session_id=session_id,
        entries=(
            VaultWriteRequest(
                entity_type=entity_type,
                normalized_hmac=f"hmac::{entity_type}::{value}",
                original_value=value,
            ),
        ),
        ttl_seconds=TTL,
    )
    return tokens[0]


async def run(
    target: OutputPipeline | VaultLike,
    content: str,
    *,
    policy: PolicyLike | None = None,
) -> RestoredOutput:
    """Restore ``content``, building a default pipeline around a bare vault."""
    pipeline = target if isinstance(target, OutputPipeline) else OutputPipeline(vault=target)
    return await pipeline.restore(
        tenant_id=TENANT,
        session_id=SESSION,
        response=ProviderResponse(content=content, model="mock-echo-1"),
        policy=policy or StubPolicy(),
    )


# --- Happy-path restoration ------------------------------------------------
class TestRestoration:
    async def test_restores_a_single_token(self, vault: Vault) -> None:
        # Arrange
        token = await mint(vault, value=EMAIL)
        # Act
        output = await run(vault, f"Contact {token} today.")
        # Assert
        assert output.text == f"Contact {EMAIL} today."
        assert output.summary.restored == 1
        assert output.summary.unknown_tokens == 0

    async def test_restores_multiple_distinct_tokens(self, vault: Vault) -> None:
        # Arrange
        email = await mint(vault, value=EMAIL)
        person = await mint(vault, value=PERSON, entity_type="PERSON")
        phone = await mint(vault, value=PHONE, entity_type="PHONE_NUMBER")
        # Act
        output = await run(vault, f"{person} <{email}> tel {phone}")
        # Assert
        assert output.text == f"{PERSON} <{EMAIL}> tel {PHONE}"
        assert output.summary.restored == 3

    async def test_restores_every_occurrence_of_a_repeated_token(self, vault: Vault) -> None:
        # Arrange
        token = await mint(vault, value=EMAIL)
        # Act
        output = await run(vault, f"{token} and again {token} and {token}")
        # Assert: three substitutions, one distinct token in the count.
        assert output.text == f"{EMAIL} and again {EMAIL} and {EMAIL}"
        assert output.summary.restored == 1

    async def test_restores_adjacent_tokens_without_separator(self, vault: Vault) -> None:
        # Arrange
        first = await mint(vault, value=PERSON, entity_type="PERSON")
        second = await mint(vault, value=EMAIL)
        # Act
        output = await run(vault, f"{first}{second}")
        # Assert
        assert output.text == f"{PERSON}{EMAIL}"
        assert output.summary.restored == 2

    async def test_resolves_all_candidates_in_one_vault_call(self, vault: Vault) -> None:
        # Arrange
        recording = RecordingVault(vault)
        first = await mint(vault, value=EMAIL)
        second = await mint(vault, value=PERSON, entity_type="PERSON")
        # Act
        await run(recording, f"{first} {second} {first}")
        # Assert
        assert len(recording.calls) == 1
        assert recording.calls[0] == frozenset({first, second})

    async def test_makes_no_vault_call_when_no_tokens_are_present(self, vault: Vault) -> None:
        # Arrange
        recording = RecordingVault(vault)
        # Act
        output = await run(recording, "A reply with nothing to restore.")
        # Assert
        assert recording.calls == []
        assert output.text == "A reply with nothing to restore."
        assert output.summary.restored == 0

    async def test_passes_through_provider_model_and_usage(self, vault: Vault) -> None:
        # Arrange
        token = await mint(vault, value=EMAIL)
        usage = ProviderUsage(input_tokens=11, output_tokens=7, total_tokens=18)
        # Act
        output = await OutputPipeline(vault=vault).restore(
            tenant_id=TENANT,
            session_id=SESSION,
            response=ProviderResponse(content=token, model="mock-echo-1", usage=usage),
            policy=StubPolicy(),
        )
        # Assert
        assert output.text == EMAIL
        assert output.model == "mock-echo-1"
        assert output.usage == usage


# --- What is not a token ---------------------------------------------------
class TestStrictParsing:
    @pytest.mark.parametrize("content", NOT_TOKENS)
    async def test_text_that_is_not_a_complete_token_is_untouched(
        self, vault: Vault, content: str
    ) -> None:
        # Arrange: a real mapping exists, so a sloppy parser would restore it.
        await mint(vault, value=EMAIL)
        # Act
        output = await run(vault, content)
        # Assert
        assert output.text == content
        assert EMAIL not in output.text
        assert output.summary.restored == 0
        assert output.summary.unknown_tokens == 0

    async def test_redaction_placeholder_is_never_resolvable(self, vault: Vault) -> None:
        # Arrange
        placeholder = format_redaction("EMAIL_ADDRESS")
        # Act
        output = await run(vault, f"We removed {placeholder} from the note.")
        # Assert: REDACTED is reserved, so this is not even a candidate.
        assert parse_token(placeholder) is None
        assert output.text == f"We removed {placeholder} from the note."
        assert output.summary.unknown_tokens == 0


# --- Isolation: other sessions, other tenants, rewritten types -------------
class TestIsolation:
    @pytest.mark.parametrize(
        ("tenant_id", "session_id"),
        [
            pytest.param(TENANT, OTHER_SESSION, id="another-session"),
            pytest.param(OTHER_TENANT, SESSION, id="another-tenant"),
            pytest.param(OTHER_TENANT, OTHER_SESSION, id="another-tenant-and-session"),
        ],
    )
    async def test_token_minted_in_another_scope_does_not_resolve(
        self, vault: Vault, tenant_id: UUID, session_id: UUID
    ) -> None:
        # Arrange
        token = await mint(vault, value=EMAIL, tenant_id=tenant_id, session_id=session_id)
        # Act: the request runs as TENANT/SESSION.
        output = await run(vault, f"Contact {token}.")
        # Assert
        assert output.text == f"Contact {token}."
        assert EMAIL not in output.text
        assert output.summary.restored == 0
        assert output.summary.unknown_tokens == 1

    async def test_provider_cannot_rewrite_the_entity_type_of_a_real_token(
        self, vault: Vault
    ) -> None:
        # Arrange: keep the minted identifier, claim a different entity type.
        minted = await mint(vault, value=EMAIL, entity_type="EMAIL_ADDRESS")
        parsed = parse_token(minted)
        assert parsed is not None
        forged = format_token("PERSON", parsed.token_id)
        # Act
        output = await run(vault, f"Ask {forged} about it.")
        # Assert: the vault binds the entity type, so the identifier alone
        # resolves nothing. The forged token is unknown and stays as written.
        assert output.text == f"Ask {forged} about it."
        assert EMAIL not in output.text
        assert output.summary.restored == 0
        assert output.summary.unknown_tokens == 1

    async def test_a_vault_that_rejects_a_rewritten_type_fails_the_request(
        self, vault: Vault
    ) -> None:
        # Arrange: the Redis vault binds the entity type into its AAD, so there
        # a rewritten type fails authentication instead of missing the lookup.
        token = await mint(vault, value=EMAIL)
        vault.simulate_failure(VaultEncryptionError())
        # Act / Assert: fail closed, no partially restored text.
        with pytest.raises(VaultEncryptionError):
            await run(vault, f"Ask {token} about it.")


# --- Unknown-token policy --------------------------------------------------
class TestUnknownTokens:
    @pytest.mark.parametrize(
        ("action", "expected"),
        [
            pytest.param(UnknownTokenAction.PRESERVE, UNKNOWN_TOKEN, id="preserve"),
            pytest.param(UnknownTokenAction.REDACT, format_redaction("EMAIL_ADDRESS"), id="redact"),
        ],
    )
    async def test_unknown_token_follows_policy(
        self, vault: Vault, action: UnknownTokenAction, expected: str
    ) -> None:
        # Arrange
        policy = StubPolicy(unknown_output_token_action=action)
        # Act
        output = await run(vault, f"Reply about {UNKNOWN_TOKEN}.", policy=policy)
        # Assert
        assert output.text == f"Reply about {expected}."
        assert output.summary.unknown_tokens == 1
        assert output.summary.restored == 0

    async def test_unknown_token_fails_the_request_when_policy_says_so(self, vault: Vault) -> None:
        # Arrange
        policy = StubPolicy(unknown_output_token_action=UnknownTokenAction.FAIL)
        # Act / Assert
        with pytest.raises(RestorationError) as caught:
            await run(vault, f"Reply about {UNKNOWN_TOKEN}.", policy=policy)
        assert caught.value.log_context == {"unknown_tokens": 1}

    async def test_known_and_unknown_tokens_are_counted_separately(self, vault: Vault) -> None:
        # Arrange
        known = await mint(vault, value=EMAIL)
        # Act
        output = await run(vault, f"{known} and {UNKNOWN_TOKEN}")
        # Assert
        assert output.text == f"{EMAIL} and {UNKNOWN_TOKEN}"
        assert output.summary.restored == 1
        assert output.summary.unknown_tokens == 1


# --- Recursion, size, and malformed payloads -------------------------------
class TestPayloadSafety:
    async def test_a_restored_value_that_looks_like_a_token_is_not_rescanned(
        self, vault: Vault
    ) -> None:
        # Arrange: the stored original is itself a valid, resolvable token.
        inner = await mint(vault, value=PERSON, entity_type="PERSON")
        outer = await mint(vault, value=inner, entity_type="NOTE")
        recording = RecordingVault(vault)
        # Act
        output = await run(recording, f"See {outer}.")
        # Assert: one pass over the original text, so the substituted value is
        # emitted verbatim and is never resolved a second time.
        assert output.text == f"See {inner}."
        assert PERSON not in output.text
        assert len(recording.calls) == 1
        assert recording.calls[0] == frozenset({outer})
        assert output.summary.restored == 1

    async def test_oversized_output_is_rejected_before_any_vault_call(self, vault: Vault) -> None:
        # Arrange
        recording = RecordingVault(vault)
        pipeline = OutputPipeline(vault=recording, max_output_chars=64)
        token = await mint(vault, value=EMAIL)
        # Act / Assert
        with pytest.raises(ProviderResponseInvalidError) as caught:
            await run(pipeline, f"{token}{'x' * 64}")
        assert caught.value.log_context["reason"] == "output_too_large"
        assert recording.calls == []

    async def test_output_exactly_at_the_limit_is_accepted(self, vault: Vault) -> None:
        # Act
        output = await run(OutputPipeline(vault=vault, max_output_chars=16), "x" * 16)
        # Assert
        assert len(output.text) == 16

    @pytest.mark.parametrize(
        ("content", "model", "reason"),
        [
            (cast(str, 12345), "mock-echo-1", "content_not_text"),
            (cast(str, None), "mock-echo-1", "content_not_text"),
            ("hello", "", "missing_model"),
            ("hello", "   ", "missing_model"),
        ],
    )
    async def test_malformed_provider_payload_is_rejected(
        self, vault: Vault, content: str, model: str, reason: str
    ) -> None:
        # Act / Assert
        with pytest.raises(ProviderResponseInvalidError) as caught:
            await OutputPipeline(vault=vault).restore(
                tenant_id=TENANT,
                session_id=SESSION,
                response=ProviderResponse(content=content, model=model),
                policy=StubPolicy(),
            )
        assert caught.value.log_context["reason"] == reason

    async def test_construction_rejects_a_useless_size_limit(self, vault: Vault) -> None:
        # Act / Assert
        with pytest.raises(ValueError, match="max_output_chars"):
            OutputPipeline(vault=vault, max_output_chars=0)

    async def test_newly_generated_email_is_passed_through_untouched(self, vault: Vault) -> None:
        # Arrange: the model invents an address that was never in the input, so
        # it is not a token and has no mapping. Restoration never invents a
        # substitution for text it did not tokenize; detecting such output is a
        # separate optional scan, and version 1 reports rather than claims
        # prevention (architecture 9.8).
        token = await mint(vault, value=EMAIL)
        invented = "someone.else@example.org"
        # Act
        output = await run(vault, f"{token} or try {invented}")
        # Assert
        assert output.text == f"{EMAIL} or try {invented}"
        assert output.summary.restored == 1
        assert output.summary.unknown_tokens == 0


# --- Failing closed and staying quiet --------------------------------------
class TestFailureAndHygiene:
    async def test_vault_outage_after_the_provider_reply_fails_closed(self, vault: Vault) -> None:
        # Arrange
        first = await mint(vault, value=EMAIL)
        second = await mint(vault, value=PERSON, entity_type="PERSON")
        vault.simulate_failure(VaultUnavailableError())
        # Act / Assert: no partially restored text is returned.
        with pytest.raises(VaultUnavailableError):
            await run(vault, f"{first} and {second}")

    async def test_restored_text_is_never_logged(
        self, vault: Vault, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Arrange
        token = await mint(vault, value=EMAIL)
        parsed = parse_token(token)
        assert parsed is not None
        # Act
        with caplog.at_level(logging.DEBUG):
            output = await run(vault, f"{token} and {UNKNOWN_TOKEN}")
        # Assert
        emitted = "\n".join(f"{record.getMessage()} {record.__dict__}" for record in caplog.records)
        assert EMAIL not in emitted
        assert token not in emitted
        assert parsed.token_id not in emitted
        assert output.summary.unknown_tokens == 1

    async def test_repr_describes_the_result_without_revealing_it(self) -> None:
        # Arrange
        output = RestoredOutput(
            text=f"secret {EMAIL}", summary=PrivacySummary(restored=1), model="mock-echo-1"
        )
        # Act
        rendered = repr(output)
        # Assert
        assert EMAIL not in rendered
        assert "characters=" in rendered

    def test_protocols_are_satisfied_by_the_real_types(self, vault: Vault) -> None:
        # Assert: structural typing holds at runtime as well as statically.
        assert isinstance(vault, VaultLike)
        assert isinstance(StubPolicy(), PolicyLike)
        assert DEFAULT_MAX_OUTPUT_CHARS > 0
