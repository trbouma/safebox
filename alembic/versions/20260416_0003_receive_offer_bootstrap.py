"""Add receive-offer bootstrap table for compact QR handoff.

Revision ID: 20260416_0003
Revises: 20260310_0002
Create Date: 2026-04-16 20:20:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260416_0003"
down_revision = "20260310_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "receiveofferbootstrap",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("nonce", sa.String(), nullable=False),
        sa.Column("nauth", sa.String(), nullable=False),
        sa.Column("grant_kind", sa.Integer(), nullable=False),
        sa.Column("offer_kind", sa.Integer(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("nonce"),
    )
    op.create_index(op.f("ix_receiveofferbootstrap_nonce"), "receiveofferbootstrap", ["nonce"], unique=False)
    op.create_index(
        op.f("ix_receiveofferbootstrap_grant_kind"),
        "receiveofferbootstrap",
        ["grant_kind"],
        unique=False,
    )
    op.create_index(
        op.f("ix_receiveofferbootstrap_offer_kind"),
        "receiveofferbootstrap",
        ["offer_kind"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_receiveofferbootstrap_offer_kind"), table_name="receiveofferbootstrap")
    op.drop_index(op.f("ix_receiveofferbootstrap_grant_kind"), table_name="receiveofferbootstrap")
    op.drop_index(op.f("ix_receiveofferbootstrap_nonce"), table_name="receiveofferbootstrap")
    op.drop_table("receiveofferbootstrap")
