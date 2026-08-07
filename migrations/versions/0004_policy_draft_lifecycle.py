"""Draft/publish lifecycle for policy versions (ADR-0037).

Two columns on ``policies``.

``status`` is ``draft`` or ``published``, and it defaults to ``published`` for
every row that already exists. That default is a statement about the past, not
a convenience: before this migration there was no way to write a draft, so no
stored row can be one, and treating existing rows as immutable is the only
reading that is true.

``published_at`` is nullable because a draft genuinely has no publication time.
Backfilling it with ``created_at`` would erase the distinction between "created
and published together", which is what every pre-existing row is, and "created
as a draft, published later", which is what the new workflow produces. For rows
that predate this migration the two timestamps are the same event, so
``created_at`` is copied across -- they were published, and pretending we do not
know when would lose information we have.

A partial unique index enforces at most one draft per ``(tenant_id, name)``.
Two concurrent "create draft" calls would otherwise both succeed and the second
would silently orphan the first operator's edits. Postgres evaluates the
predicate per row, so published versions are unaffected.

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-07
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DRAFT_INDEX = "uq_policies_one_draft_per_name"


def upgrade() -> None:
    op.add_column(
        "policies",
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default="published",
        ),
    )
    op.add_column("policies", sa.Column("published_at", sa.DateTime(timezone=True), nullable=True))

    # Every pre-existing row was published at the moment it was created.
    op.execute("UPDATE policies SET published_at = created_at WHERE published_at IS NULL")

    op.create_index(
        _DRAFT_INDEX,
        "policies",
        ["tenant_id", "name"],
        unique=True,
        postgresql_where=sa.text("status = 'draft'"),
        sqlite_where=sa.text("status = 'draft'"),
    )


def downgrade() -> None:
    # Drafts have no representation once the column is gone, and leaving them
    # behind would make them indistinguishable from published versions -- which
    # is exactly the confusion this migration exists to prevent. They are
    # removed rather than silently promoted.
    op.execute("DELETE FROM policies WHERE status = 'draft'")
    op.drop_index(_DRAFT_INDEX, table_name="policies")
    op.drop_column("policies", "published_at")
    op.drop_column("policies", "status")
