"""Documents: metadata for encrypted objects held in object storage.

Written by hand for the same reason as 0001: the constraint names and the
composite index are explicit and reviewable rather than dialect-dependent.

What this table deliberately does not have is as important as what it does.
There is no column for document bytes and none for extracted text -- both live
outside PostgreSQL by ADR-0020, and adding either later would turn the audit
database into a store of Restricted content. ``filename_ciphertext`` is binary
because a filename is Restricted and is sealed under the document's own key.

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "documents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("storage_key", sa.String(length=128), nullable=False),
        sa.Column("filename_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("content_type", sa.String(length=128), nullable=False),
        sa.Column("byte_size", sa.BigInteger(), nullable=False),
        sa.Column("sha256_hex", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="receiving", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_documents"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_documents_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        # Deleting a tenant must take its documents' rows with it. The objects
        # themselves are removed by the service; an orphaned row would leave a
        # storage key nothing can reach.
        sa.UniqueConstraint("storage_key", name="uq_documents_storage_key"),
        sa.CheckConstraint(
            "status IN ('receiving', 'stored', 'failed')",
            name="ck_documents_status_known",
        ),
        sa.CheckConstraint("byte_size >= 0", name="ck_documents_byte_size_non_negative"),
    )
    # Every read is scoped by tenant and user, so no other index earns its cost.
    op.create_index("ix_documents_tenant_id_user_id", "documents", ["tenant_id", "user_id"])


def downgrade() -> None:
    op.drop_index("ix_documents_tenant_id_user_id", table_name="documents")
    op.drop_table("documents")
