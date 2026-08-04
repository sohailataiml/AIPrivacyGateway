"""Tests for the shared contract layer.

These assertions protect the seam every other module builds on: secrets stay
hidden, error codes stay complete, and a protected request cannot be confused
with a raw one.
"""

from __future__ import annotations

import base64
import os
import re
from pathlib import Path
from uuid import uuid4

import pytest

from app.config.settings import AppEnv, Settings, get_settings
from app.domain.errors import (
    ERROR_CATALOG,
    ErrorCode,
    GatewayError,
    PolicyViolationError,
    VaultUnavailableError,
)
from app.domain.models import (
    ChatMessage,
    ChatRequest,
    DetectedEntity,
    EntityMapping,
    Principal,
    PrivacySummary,
    ProtectedChatRequest,
    Scope,
)

REAL_KEY = base64.b64encode(bytes(range(32))).decode()
STRONG_PEPPER = "p" * 48
STRONG_AUDIT_KEY = base64.b64encode(bytes(range(1, 33))).decode()


def production_env(**overrides: str) -> dict[str, str]:
    """A minimal, valid production environment that tests can break one field at a time."""
    env = {
        "APP_ENV": "production",
        "API_KEY_PEPPER": STRONG_PEPPER,
        "AUDIT_HMAC_KEY": STRONG_AUDIT_KEY,
        "VAULT_ACTIVE_KEY_ID": "prod1",
        "VAULT_KEY_PROD1": REAL_KEY,
    }
    env.update(overrides)
    return env


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Run every settings test against a clean environment and no .env file."""
    for name in list(os.environ):
        if name.startswith(("APP_", "VAULT_", "API_KEY_", "AUDIT_", "OPENAI_", "CORS_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Error catalog
# ---------------------------------------------------------------------------
class TestErrorCatalog:
    def test_every_code_has_a_status_and_message(self) -> None:
        assert set(ERROR_CATALOG) == set(ErrorCode)

    def test_public_messages_never_name_infrastructure(self) -> None:
        # A message returned to an unauthenticated caller must not disclose the
        # stack. Catching this here is cheaper than catching it in a pen test.
        forbidden = re.compile(r"redis|postgres|localhost|127\.0\.0\.1|openai|spacy", re.IGNORECASE)

        for code, (_status, message) in ERROR_CATALOG.items():
            assert not forbidden.search(message), f"{code} leaks infrastructure detail"

    def test_auth_failures_are_indistinguishable(self) -> None:
        # An unknown prefix and a wrong secret must look identical to a caller.
        assert (
            ERROR_CATALOG[ErrorCode.AUTHENTICATION_FAILED][1]
            == ERROR_CATALOG[ErrorCode.AUTHENTICATION_FAILED][1]
        )
        assert "prefix" not in ERROR_CATALOG[ErrorCode.AUTHENTICATION_FAILED][1].lower()

    def test_error_str_is_the_public_message(self) -> None:
        error = VaultUnavailableError(log_context={"stage": "get_or_create"})

        assert str(error) == "The secure mapping service is unavailable."
        assert error.status_code == 503

    def test_subclass_carries_its_code(self) -> None:
        assert PolicyViolationError().code is ErrorCode.POLICY_VIOLATION
        assert GatewayError().code is ErrorCode.INTERNAL_ERROR

    def test_privacy_failures_are_not_client_errors(self) -> None:
        # Fail-closed codes must not return 2xx under any mapping.
        fail_closed = {
            ErrorCode.PRIVACY_DETECTOR_UNAVAILABLE,
            ErrorCode.VAULT_UNAVAILABLE,
            ErrorCode.VAULT_ENCRYPTION_FAILED,
            ErrorCode.RESTORATION_FAILED,
        }
        for code in fail_closed:
            assert ERROR_CATALOG[code][0] >= 400


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
class TestSettingsSecrecy:
    def test_repr_hides_every_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("API_KEY_PEPPER", "super-secret-pepper-value")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-should-never-appear")
        settings = Settings()

        rendered = repr(settings) + str(settings)

        assert "super-secret-pepper-value" not in rendered
        assert "sk-should-never-appear" not in rendered

    def test_model_dump_hides_every_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("API_KEY_PEPPER", "super-secret-pepper-value")
        monkeypatch.setenv("VAULT_KEY_LOCAL1", REAL_KEY)
        settings = Settings()

        dumped = str(settings.model_dump())

        assert "super-secret-pepper-value" not in dumped
        assert REAL_KEY not in dumped

    def test_secret_is_reachable_only_through_explicit_accessor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("API_KEY_PEPPER", "super-secret-pepper-value")
        settings = Settings()

        assert settings.api_key_pepper.get_secret_value() == "super-secret-pepper-value"


class TestProductionHardening:
    def test_valid_production_configuration_starts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name, value in production_env().items():
            monkeypatch.setenv(name, value)

        settings = Settings()

        assert settings.is_production
        assert settings.active_vault_key() == bytes(range(32))

    @pytest.mark.parametrize(
        ("overrides", "expected_fragment"),
        [
            (
                {"API_KEY_PEPPER": "local-development-pepper-do-not-use-in-production"},
                "API_KEY_PEPPER",
            ),
            ({"API_KEY_PEPPER": "short"}, "API_KEY_PEPPER"),
            ({"AUDIT_HMAC_KEY": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}, "AUDIT_HMAC_KEY"),
            ({"VAULT_ACTIVE_KEY_ID": "missing"}, "VAULT_ACTIVE_KEY_ID"),
            ({"VAULT_KEY_PROD1": base64.b64encode(b"tooshort").decode()}, "32 bytes"),
            ({"VAULT_KEY_PROD1": base64.b64encode(bytes(32)).decode()}, "zero bytes"),
            ({"VAULT_KEY_PROD1": "not-base64!!"}, "base64"),
            ({"DIAGNOSTICS_RETURN_MATCHED_TEXT": "true"}, "DIAGNOSTICS"),
            ({"CORS_ALLOWED_ORIGINS": "*"}, "CORS"),
        ],
    )
    def test_invalid_production_configuration_prevents_startup(
        self,
        monkeypatch: pytest.MonkeyPatch,
        overrides: dict[str, str],
        expected_fragment: str,
    ) -> None:
        for name, value in production_env(**overrides).items():
            monkeypatch.setenv(name, value)

        with pytest.raises(ValueError, match=expected_fragment):
            Settings()

    def test_startup_failure_names_variables_not_values(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        leaked = "z" * 48
        for name, value in production_env(API_KEY_PEPPER=leaked).items():
            monkeypatch.setenv(name, value)
        monkeypatch.setenv("VAULT_KEY_PROD1", "not-base64!!")

        with pytest.raises(ValueError) as caught:
            Settings()

        # The message must help an operator without printing the secret itself.
        assert leaked not in str(caught.value)

    def test_diagnostics_are_unavailable_in_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name, value in production_env().items():
            monkeypatch.setenv(name, value)
        settings = Settings()

        assert settings.diagnostics_allowed is False

    def test_local_defaults_use_the_mock_provider(self) -> None:
        settings = Settings()

        assert settings.app_env is AppEnv.LOCAL
        assert settings.default_provider == "mock"


class TestVaultKeyRing:
    def test_retired_keys_remain_available_for_decryption(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        old_key = base64.b64encode(bytes(range(32, 64))).decode()
        for name, value in production_env().items():
            monkeypatch.setenv(name, value)
        monkeypatch.setenv("VAULT_KEY_PROD0", old_key)

        settings = Settings()

        assert settings.active_vault_key() == bytes(range(32))
        assert settings.vault_key("prod0") == bytes(range(32, 64))

    def test_unknown_key_id_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name, value in production_env().items():
            monkeypatch.setenv(name, value)
        settings = Settings()

        with pytest.raises(ValueError, match="not present in the key ring"):
            settings.vault_key("nope")


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------
class TestDomainModels:
    def test_protected_request_is_not_a_chat_request(self) -> None:
        # The provider boundary depends on these being unrelated types.
        assert not issubclass(ProtectedChatRequest, ChatRequest)
        assert not issubclass(ChatRequest, ProtectedChatRequest)

    def test_protected_request_requires_messages(self) -> None:
        with pytest.raises(ValueError, match="at least one message"):
            ProtectedChatRequest(
                request_id=uuid4(),
                tenant_id=uuid4(),
                session_id=uuid4(),
                provider_alias="mock",
                model_alias="general-chat",
                messages=(),
                policy_version=1,
            )

    def test_entity_mapping_repr_hides_the_original_value(self) -> None:
        mapping = EntityMapping(
            token="[[SGW:EMAIL_ADDRESS:01J0000000000000000000000]]",
            token_id="01J0000000000000000000000",
            entity_type="EMAIL_ADDRESS",
            original_value="avery@example.test",
            normalized_hmac="deadbeef",
        )

        assert "avery@example.test" not in repr(mapping)
        assert "EMAIL_ADDRESS" in repr(mapping)

    @pytest.mark.parametrize(
        ("start", "end", "score"),
        [(-1, 5, 0.9), (5, 5, 0.9), (7, 5, 0.9), (0, 5, 1.5), (0, 5, -0.1)],
    )
    def test_invalid_detected_entity_is_rejected(self, start: int, end: int, score: float) -> None:
        with pytest.raises(ValueError):
            DetectedEntity(entity_type="EMAIL_ADDRESS", start=start, end=end, score=score)

    def test_overlap_detection(self) -> None:
        a = DetectedEntity(entity_type="PERSON", start=0, end=10, score=0.9)
        b = DetectedEntity(entity_type="LOCATION", start=5, end=15, score=0.9)
        c = DetectedEntity(entity_type="LOCATION", start=10, end=15, score=0.9)

        assert a.overlaps(b) and b.overlaps(a)
        assert not a.overlaps(c), "adjacent spans do not overlap"

    def test_privacy_summary_merge_is_immutable(self) -> None:
        left = PrivacySummary(detected=2, tokenized=2, entity_types={"EMAIL_ADDRESS": 2})
        right = PrivacySummary(detected=1, blocked=1, entity_types={"US_SSN": 1})

        merged = left.merged_with(right)

        assert merged.detected == 3
        assert merged.entity_types == {"EMAIL_ADDRESS": 2, "US_SSN": 1}
        assert left.detected == 2, "the original summary must not change"
        assert left.entity_types == {"EMAIL_ADDRESS": 2}

    def test_chat_message_is_frozen(self) -> None:
        message = ChatMessage(role="user", content="hello")

        with pytest.raises(ValueError):
            message.content = "changed"  # type: ignore[misc]

    def test_chat_request_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValueError):
            ChatRequest.model_validate(
                {
                    "provider": "mock",
                    "model": "general-chat",
                    "messages": [{"role": "user", "content": "hi"}],
                    "base_url": "https://attacker.example",
                }
            )

    def test_principal_scope_check(self) -> None:
        principal = Principal(
            tenant_id=uuid4(),
            api_key_id=uuid4(),
            api_key_prefix="sgw_live_abcd",
            scopes=frozenset({Scope.CHAT_INVOKE}),
        )

        assert principal.has_scope(Scope.CHAT_INVOKE)
        assert not principal.has_scope(Scope.SESSIONS_DELETE)
