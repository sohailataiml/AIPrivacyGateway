"""Configuration is the only thing that distinguishes one S3 backend from another.

``S3CompatibleDocumentStore`` is one implementation with no provider flag inside
it, so everything that points a deployment at AWS S3 rather than at some other
S3-compatible service is resolved here, in ``Settings``. That makes these tests
the whole seam: if the provider does not reach ``from_settings`` correctly, the
store cannot notice, because it was built without the ability to ask.

AWS S3 is the backend the project runs (ADR-0035). ``compatible`` is retained as
an escape hatch, and it is tested because an untested escape hatch is a
liability rather than an option.

Two classes of failure are covered, and the second is the reason this file
exists. The first is ordinary defaulting -- virtual-host addressing for AWS,
path style otherwise. The second is *quiet misconfiguration*: a deployment
pointed at a compatible service that omits its endpoint does not fail, it
resolves real AWS S3 and tries to store documents in an account nobody intended.
A health check cannot catch that -- ``head_bucket`` against a bucket that
happens to exist would pass -- so it has to be refused at startup, where the
intent is still stated.
"""

from __future__ import annotations

import base64

import pytest
from pydantic import SecretStr

from app.config.settings import ObjectStoreProvider, Settings
from app.documents.storage.s3 import S3CompatibleDocumentStore

VAULT_KEY = SecretStr(base64.b64encode(bytes(range(32))).decode())
DOCUMENT_KEY = SecretStr(base64.b64encode(bytes(range(1, 33))).decode())

SECRET = SecretStr("v" * 48)
"""Long enough to clear MIN_SECRET_CHARS and not a shipped placeholder."""


def settings_of(**overrides: object) -> Settings:
    """Build settings for the local environment, where hardening does not run."""
    base: dict[str, object] = {
        "app_env": "local",
        "documents_enabled": True,
        "vault_keys": {"local1": VAULT_KEY},
        "document_keys": {"local1": DOCUMENT_KEY},
    }
    return Settings(**(base | overrides))  # type: ignore[arg-type]


def production_settings(**overrides: object) -> Settings:
    """Build an otherwise-valid production configuration.

    Every field here exists to get *past* the unrelated production checks, so a
    failure below is attributable to object storage rather than to a missing
    pepper. The object-store fields are deliberately absent: each test supplies
    exactly the ones it is about.
    """
    base: dict[str, object] = {
        "app_env": "production",
        "documents_enabled": True,
        "api_key_pepper": SECRET,
        "audit_hmac_key": SECRET,
        "vault_active_key_id": "local1",
        "document_active_key_id": "local1",
        "vault_keys": {"local1": VAULT_KEY},
        "document_keys": {"local1": DOCUMENT_KEY},
        "cors_allowed_origins": ["https://workspace.example.com"],
        "metrics_enabled": False,
    }
    return Settings(**(base | overrides))  # type: ignore[arg-type]


class TestAddressingStyle:
    def test_a_compatible_service_addresses_buckets_by_path(self) -> None:
        settings = settings_of(object_store_provider=ObjectStoreProvider.COMPATIBLE)

        assert settings.object_store_uses_path_style is True

    def test_aws_addresses_buckets_by_virtual_host(self) -> None:
        # Not merely "not path": AWS deprecated path-style addressing, and a
        # deployment that quietly kept it would be relying on a compatibility
        # behaviour rather than the documented one.
        settings = settings_of(object_store_provider=ObjectStoreProvider.AWS)

        assert settings.object_store_uses_path_style is False

    def test_the_default_provider_is_aws(self) -> None:
        # Non-vacuity for the two above: they only prove the enum is read if the
        # default is not already the value being asserted for both.
        assert settings_of().object_store_provider is ObjectStoreProvider.AWS

    @pytest.mark.parametrize("provider", list(ObjectStoreProvider))
    @pytest.mark.parametrize("override", [True, False])
    def test_an_explicit_setting_overrides_the_provider_convention(
        self, provider: ObjectStoreProvider, override: bool
    ) -> None:
        # An S3-compatible service behind a VPC endpoint can need path style
        # while still being AWS. A provider enum that overruled the operator
        # would make that deployment unreachable with no way to say otherwise.
        settings = settings_of(object_store_provider=provider, object_store_use_path_style=override)

        assert settings.object_store_uses_path_style is override


class TestProviderReachesTheStore:
    def test_the_store_is_built_with_the_resolved_addressing_style(self) -> None:
        # The store has no provider field to inspect, which is the design: it
        # receives a boolean and cannot branch on a vendor. So this asserts on
        # the botocore config it actually built.
        settings = settings_of(
            object_store_provider=ObjectStoreProvider.AWS,
            object_store_endpoint_url=None,
            object_store_access_key_id=SecretStr("id"),
            object_store_secret_access_key=SecretStr("secret"),
        )

        store = S3CompatibleDocumentStore.from_settings(settings)

        config = store._client_kwargs["config"]
        assert config.s3["addressing_style"] == "virtual"

    def test_a_compatible_deployment_builds_a_path_style_client(self) -> None:
        settings = settings_of(
            object_store_provider=ObjectStoreProvider.COMPATIBLE,
            object_store_endpoint_url="http://localhost:9000",
            object_store_access_key_id=SecretStr("id"),
            object_store_secret_access_key=SecretStr("secret"),
        )

        store = S3CompatibleDocumentStore.from_settings(settings)

        config = store._client_kwargs["config"]
        assert config.s3["addressing_style"] == "path"
        assert store._client_kwargs["endpoint_url"] == "http://localhost:9000"

    def test_aws_without_static_credentials_defers_to_the_default_chain(self) -> None:
        # Passing None is what tells botocore to resolve an instance or task
        # role. Passing empty strings would not: they are credentials, and bad
        # ones, so the request would be signed and rejected.
        settings = settings_of(object_store_provider=ObjectStoreProvider.AWS)

        store = S3CompatibleDocumentStore.from_settings(settings)

        assert store._client_kwargs["aws_access_key_id"] is None
        assert store._client_kwargs["aws_secret_access_key"] is None
        assert store._client_kwargs["endpoint_url"] is None


class TestBlankCredentialsAreAbsent:
    """An empty variable and an unset one must mean the same thing.

    Compose renders ``${VAR:-}`` as the empty string, and so does every other
    templating layer asked for a value nobody supplied. Without normalisation
    the two diverge exactly where it hurts: absent selects the instance role,
    empty is a credential, so S3 rejects the signature instead of falling back.
    """

    @pytest.mark.parametrize("blank", ["", "   "])
    def test_an_empty_credential_reads_as_unset(self, blank: str) -> None:
        settings = settings_of(
            object_store_access_key_id=blank, object_store_secret_access_key=blank
        )

        assert settings.object_store_access_key_id is None
        assert settings.object_store_secret_access_key is None

    def test_an_empty_credential_still_selects_the_default_chain(self) -> None:
        # The property that actually matters downstream: botocore is handed
        # None, not "", so it resolves a role instead of signing with nothing.
        settings = settings_of(
            object_store_provider=ObjectStoreProvider.AWS,
            object_store_access_key_id="",
            object_store_secret_access_key="",
        )

        store = S3CompatibleDocumentStore.from_settings(settings)

        assert store._client_kwargs["aws_access_key_id"] is None

    def test_production_treats_empty_credentials_as_missing(self) -> None:
        # Otherwise a compatible-service deployment with blank credentials would
        # pass validation and fail at the first upload instead of at startup.
        with pytest.raises(ValueError, match="OBJECT_STORE_ACCESS_KEY_ID"):
            production_settings(
                object_store_provider=ObjectStoreProvider.COMPATIBLE,
                object_store_endpoint_url="http://objects.internal:9000",
                object_store_access_key_id="",
                object_store_secret_access_key=SECRET,
            )

    def test_a_real_credential_is_untouched(self) -> None:
        # Non-vacuity: the normaliser must not be eating every value.
        settings = settings_of(object_store_access_key_id="AKIAEXAMPLE")

        assert settings.object_store_access_key_id is not None
        assert settings.object_store_access_key_id.get_secret_value() == "AKIAEXAMPLE"


class TestProductionRefusesQuietMisconfiguration:
    def test_a_compatible_service_without_an_endpoint_is_refused(self) -> None:
        # The failure this prevents: botocore resolves real AWS S3 and the
        # gateway stores documents in an account nobody intended to use.
        with pytest.raises(ValueError, match="OBJECT_STORE_ENDPOINT_URL"):
            production_settings(
                object_store_provider=ObjectStoreProvider.COMPATIBLE,
                object_store_access_key_id=SECRET,
                object_store_secret_access_key=SECRET,
            )

    def test_aws_with_a_leftover_endpoint_is_refused(self) -> None:
        # The mirror failure: a stale endpoint carried over from a local .env
        # sends production traffic to a host that is not there.
        with pytest.raises(ValueError, match="OBJECT_STORE_ENDPOINT_URL"):
            production_settings(
                object_store_provider=ObjectStoreProvider.AWS,
                object_store_endpoint_url="http://localhost:9000",
            )

    @pytest.mark.parametrize(
        "missing", ["object_store_access_key_id", "object_store_secret_access_key"]
    )
    def test_a_compatible_service_without_credentials_is_refused(self, missing: str) -> None:
        # A compatible service has no ambient identity to fall back on, so
        # absent credentials are always an error there -- unlike on AWS.
        supplied = {
            "object_store_access_key_id": SECRET,
            "object_store_secret_access_key": SECRET,
        }
        del supplied[missing]

        with pytest.raises(ValueError, match=missing.upper()):
            production_settings(
                object_store_provider=ObjectStoreProvider.COMPATIBLE,
                object_store_endpoint_url="http://objects.internal:9000",
                **supplied,
            )

    def test_aws_without_credentials_is_accepted(self) -> None:
        # The whole point of the provider split. Requiring a static key pair on
        # AWS would force every hosted deployment to hold a long-lived secret
        # instead of using a role that rotates itself.
        settings = production_settings(object_store_provider=ObjectStoreProvider.AWS)

        assert settings.object_store_access_key_id is None
        assert settings.object_store_uses_path_style is False

    @pytest.mark.parametrize(
        "supplied", ["object_store_access_key_id", "object_store_secret_access_key"]
    )
    def test_aws_with_half_a_credential_is_refused(self, supplied: str) -> None:
        # Half a credential is not "no credential": botocore would fall through
        # to the default chain and sign as an identity the operator did not
        # think they were using. Refusing is the only way that is visible.
        with pytest.raises(ValueError, match="must be set together"):
            production_settings(object_store_provider=ObjectStoreProvider.AWS, **{supplied: SECRET})

    def test_a_valid_compatible_production_configuration_is_accepted(self) -> None:
        # Non-vacuity for every refusal above: they prove nothing unless a
        # correct configuration of the same shape is known to pass.
        settings = production_settings(
            object_store_provider=ObjectStoreProvider.COMPATIBLE,
            object_store_endpoint_url="http://objects.internal:9000",
            object_store_access_key_id=SECRET,
            object_store_secret_access_key=SECRET,
        )

        assert settings.object_store_uses_path_style is True

    def test_documents_disabled_skips_object_store_checks_entirely(self) -> None:
        # A deployment that accepts no uploads should not have to configure a
        # bucket it will never open.
        settings = production_settings(documents_enabled=False)

        assert settings.documents_enabled is False
