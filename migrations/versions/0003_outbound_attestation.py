"""Outbound payload attestation on the audit record (ADR-0024).

Two nullable columns. Nullable rather than defaulted, because rows written
before this migration genuinely have no attestation and inventing a value for
them would be the audit-table equivalent of a lie: an operator reading an old
row must be able to tell "the check did not exist yet" from "the check ran and
found nothing".

``outbound_hmac`` holds a keyed digest of the exact bytes handed to a provider
adapter. It is a digest and never a payload -- ADR-0013 keeps raw conversation
content out of durable storage, and ADR-0015 requires the keyed construction so
low-entropy content cannot be recovered by brute force. The column is named
``outbound_hmac`` and not ``payload_hmac`` because ``AuditRecord`` screens field
names against a prohibited-substring list that includes ``payload``, and the
screen is right to.

``outbound_scan`` holds the verdict of the pre-transmission scan: ``clean`` or
``blocked``. Both columns are written on both paths -- a request the scan
stopped is the case most worth auditing.

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("outbound_hmac", sa.String(length=128), nullable=True))
    op.add_column("audit_events", sa.Column("outbound_scan", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_events", "outbound_scan")
    op.drop_column("audit_events", "outbound_hmac")
