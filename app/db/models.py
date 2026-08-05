"""ORM mappings for the gateway's system-of-record tables.

Tenancy is structural here, not conventional: every table except ``tenants``
carries a non-null ``tenant_id`` (policies allow ``NULL`` for the built-in
default only), and the repository layer requires it on every call. There is no
"lookup by id" that can cross a tenant boundary because no such column
combination is unique on its own.

Nothing in these tables is a secret. ``api_keys`` stores a one-way hash;
``provider_configs`` stores the *name* of an environment variable, never the
credential it points at.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.db.base import Base, JsonDocument, StringList, UtcDateTime, utc_now

TENANT_STATUS_ACTIVE = "active"
TENANT_STATUS_SUSPENDED = "suspended"
TENANT_STATUSES = (TENANT_STATUS_ACTIVE, TENANT_STATUS_SUSPENDED)

API_KEY_STATUS_ACTIVE = "active"
API_KEY_STATUS_REVOKED = "revoked"
API_KEY_STATUSES = (API_KEY_STATUS_ACTIVE, API_KEY_STATUS_REVOKED)

SECRET_REF_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
"""A provider secret reference must look like an environment variable name.

The shape check is the guardrail that keeps an operator from pasting an actual
API key into this column: real credentials contain lowercase characters,
punctuation, or both, and are rejected before they reach the database.
"""


class Tenant(Base):
    """An isolated customer of the gateway. The root of every ownership chain."""

    __tablename__ = "tenants"

    id: Mapped[UUID] = mapped_column(Uuid(), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    """Stable human-readable identifier. Unique, so seeding is idempotent."""

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=TENANT_STATUS_ACTIVE,
        server_default=TENANT_STATUS_ACTIVE,
    )
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'suspended')",
            name="status_known",
        ),
    )

    @property
    def is_active(self) -> bool:
        return self.status == TENANT_STATUS_ACTIVE


class ApiKey(Base):
    """A credential record. The credential itself is never here.

    ``key_hash`` is a keyed one-way digest of the full raw key; ``prefix`` is the
    non-secret leading fragment an operator can read off a dashboard to identify
    which key is which.
    """

    __tablename__ = "api_keys"

    id: Mapped[UUID] = mapped_column(Uuid(), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        Uuid(), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    prefix: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(StringList, nullable=False, default=list)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=API_KEY_STATUS_ACTIVE,
        server_default=API_KEY_STATUS_ACTIVE,
    )
    expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_api_keys_tenant_id_name"),
        CheckConstraint(
            "status IN ('active', 'revoked')",
            name="status_known",
        ),
    )

    def is_usable(self, *, now: datetime) -> bool:
        """Whether the key may authenticate a request at ``now``."""
        if self.status != API_KEY_STATUS_ACTIVE:
            return False
        return self.expires_at is None or self.expires_at > now


class Policy(Base):
    """A versioned privacy policy document.

    ``tenant_id`` is ``NULL`` for the built-in default policy that ships with the
    gateway. Tenant-scoped repository reads never return those rows; a dedicated,
    explicitly named method fetches the default.
    """

    __tablename__ = "policies"

    id: Mapped[UUID] = mapped_column(Uuid(), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID | None] = mapped_column(
        Uuid(), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JsonDocument, nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", "version", name="uq_policies_tenant_id_name_version"),
        # A composite UNIQUE does not constrain rows where tenant_id IS NULL,
        # so the built-in default policy needs its own partial index.
        Index(
            "uq_policies_default_name_version",
            "name",
            "version",
            unique=True,
            sqlite_where=text("tenant_id IS NULL"),
            postgresql_where=text("tenant_id IS NULL"),
        ),
        CheckConstraint("version > 0", name="version_positive"),
    )


class ProviderConfig(Base):
    """Non-secret configuration for one upstream provider alias.

    ``secret_ref`` names an environment variable. The credential is resolved at
    call time from the process environment and is never persisted, so a database
    dump discloses which variable to look for and nothing more.
    """

    __tablename__ = "provider_configs"

    id: Mapped[UUID] = mapped_column(Uuid(), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        Uuid(), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    alias: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False)
    secret_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    allowed_models: Mapped[list[str]] = mapped_column(StringList, nullable=False, default=list)
    connect_timeout_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=5, server_default="5"
    )
    read_timeout_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=60, server_default="60"
    )
    max_retries: Mapped[int] = mapped_column(Integer, nullable=False, default=2, server_default="2")
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "alias", name="uq_provider_configs_tenant_id_alias"),
        # Belt and braces alongside the Python validator: a direct SQL INSERT
        # still cannot park a whitespace-bearing credential in this column.
        CheckConstraint(
            "length(secret_ref) BETWEEN 1 AND 128 AND secret_ref NOT LIKE '% %'",
            name="secret_ref_is_reference",
        ),
        CheckConstraint("max_retries BETWEEN 0 AND 5", name="max_retries_bounded"),
    )

    @validates("secret_ref")
    def _validate_secret_ref(self, _key: str, value: str) -> str:
        """Reject anything that is not shaped like an environment variable name."""
        if not SECRET_REF_PATTERN.match(value):
            raise ValueError(
                "secret_ref must be an environment variable name "
                "(uppercase letters, digits, underscore), not a secret value"
            )
        return value


class Document(Base):
    """Metadata for one uploaded document. Never its contents.

    Prohibited by construction, per ADR-0020: there is no column for document
    bytes and none for extracted text. The bytes live in object storage, sealed
    (ADR-0021), and this row holds only what is needed to find, describe, and
    authorize them.

    ``filename_ciphertext`` is the one encrypted column. A filename is
    Restricted -- "Jane Doe MRI results.pdf" identifies a person and a condition
    before the file is opened -- so it is sealed under the same per-document key
    as the body and is unreadable without it.

    ``storage_key`` is opaque: no tenant, no user, no filename, no extension.
    Reading it from a bucket listing reveals nothing about whose document it is.
    """

    __tablename__ = "documents"

    id: Mapped[UUID] = mapped_column(Uuid(), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        Uuid(), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[UUID] = mapped_column(Uuid(), nullable=False)
    """The authenticated subject the document is bound to (ADR-0021).

    Today that is the API key id, because the gateway authenticates keys rather
    than people. When a user model arrives this column is where it lands, and
    the cryptographic binding already depends on it.
    """

    storage_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    filename_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    content_type: Mapped[str] = mapped_column(String(128), nullable=False)
    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    """Plaintext length. The stored object is larger by the per-chunk overhead."""

    sha256_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    """Checksum of the plaintext, for integrity verification on retrieval."""

    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="receiving", server_default="receiving"
    )
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        # Every read is scoped by tenant and user, so that is the index.
        Index("ix_documents_tenant_id_user_id", "tenant_id", "user_id"),
        CheckConstraint(
            "status IN ('receiving', 'stored', 'failed')",
            name="status_known",
        ),
        CheckConstraint("byte_size >= 0", name="byte_size_non_negative"),
    )


class AuditEvent(Base):
    """A privacy-safe record of one gateway request.

    Prohibited by construction: there is no column for message content, response
    content, original values, decrypted mappings, complete gateway tokens, or
    credentials. ``prompt_hmac`` and ``response_hmac`` are keyed digests used for
    correlation only.

    The primary key is ``(id, occurred_at)`` and the table carries no foreign
    keys. Both choices exist so the table can be converted to PostgreSQL
    declarative RANGE partitioning on ``occurred_at`` without a rewrite: a
    partitioned table requires the partition key inside every unique constraint,
    and inbound foreign keys complicate partition detach.
    """

    __tablename__ = "audit_events"

    id: Mapped[UUID] = mapped_column(Uuid(), primary_key=True, default=uuid4)
    occurred_at: Mapped[datetime] = mapped_column(
        UtcDateTime, primary_key=True, nullable=False, default=utc_now
    )
    tenant_id: Mapped[UUID] = mapped_column(Uuid(), nullable=False)
    request_id: Mapped[UUID] = mapped_column(Uuid(), nullable=False)
    api_key_id: Mapped[UUID | None] = mapped_column(Uuid(), nullable=True)
    session_id_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_id: Mapped[UUID | None] = mapped_column(Uuid(), nullable=True)
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    provider_alias: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model_alias: Mapped[str | None] = mapped_column(String(128), nullable=True)
    input_character_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    output_character_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    entity_counts: Mapped[dict[str, Any]] = mapped_column(
        JsonDocument, nullable=False, default=dict
    )
    actions: Mapped[dict[str, Any]] = mapped_column(JsonDocument, nullable=False, default=dict)
    blocked: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    block_reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pipeline_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt_hmac: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_hmac: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_audit_events_tenant_id_occurred_at", "tenant_id", "occurred_at"),
        Index("ix_audit_events_request_id", "request_id"),
    )
