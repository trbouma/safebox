"""Add persisted nonce table for NFC requester replay protection.

Revision ID: 20260310_0002
Revises: 20260220_0001
Create Date: 2026-03-10 18:30:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260310_0002"
down_revision = "20260220_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "nfcrequesternonce",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("requester_pubkey", sa.String(), nullable=False),
        sa.Column("flow", sa.String(), nullable=False),
        sa.Column("nonce", sa.String(), nullable=False),
        sa.Column("requester_ts", sa.Integer(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("requester_pubkey", "flow", "nonce", name="uq_nfc_requester_nonce"),
    )
    op.create_index(
        op.f("ix_nfcrequesternonce_requester_pubkey"),
        "nfcrequesternonce",
        ["requester_pubkey"],
        unique=False,
    )
    op.create_index(op.f("ix_nfcrequesternonce_flow"), "nfcrequesternonce", ["flow"], unique=False)
    op.create_index(op.f("ix_nfcrequesternonce_nonce"), "nfcrequesternonce", ["nonce"], unique=False)
    op.create_index(op.f("ix_nfcrequesternonce_used_at"), "nfcrequesternonce", ["used_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_nfcrequesternonce_used_at"), table_name="nfcrequesternonce")
    op.drop_index(op.f("ix_nfcrequesternonce_nonce"), table_name="nfcrequesternonce")
    op.drop_index(op.f("ix_nfcrequesternonce_flow"), table_name="nfcrequesternonce")
    op.drop_index(op.f("ix_nfcrequesternonce_requester_pubkey"), table_name="nfcrequesternonce")
    op.drop_table("nfcrequesternonce")
