"""Baseline schema for Safebox SQLModel tables.

Revision ID: 20260220_0001
Revises:
Create Date: 2026-02-20 12:00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260220_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "registeredsafebox",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("handle", sa.String(), nullable=False),
        sa.Column("custom_handle", sa.String(), nullable=True),
        sa.Column("npub", sa.String(), nullable=False),
        sa.Column("nsec", sa.String(), nullable=True),
        sa.Column("home_relay", sa.String(), nullable=False),
        sa.Column("onboard_code", sa.String(), nullable=False),
        sa.Column("access_key", sa.String(), nullable=True),
        sa.Column("balance", sa.Integer(), nullable=False),
        sa.Column("owner", sa.String(), nullable=True),
        sa.Column("session_nonce", sa.String(), nullable=True),
        sa.Column("emergency_code", sa.String(), nullable=True),
        sa.Column("currency_code", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("custom_handle"),
        sa.UniqueConstraint("emergency_code"),
    )
    op.create_index("uq_registeredsafebox_handle", "registeredsafebox", ["handle"], unique=True)
    op.create_index("uq_registeredsafebox_npub", "registeredsafebox", ["npub"], unique=True)
    op.create_index(
        "uq_registeredsafebox_access_key",
        "registeredsafebox",
        ["access_key"],
        unique=True,
        sqlite_where=sa.text("access_key IS NOT NULL"),
        postgresql_where=sa.text("access_key IS NOT NULL"),
    )
    op.create_index(op.f("ix_registeredsafebox_handle"), "registeredsafebox", ["handle"], unique=False)
    op.create_index(op.f("ix_registeredsafebox_npub"), "registeredsafebox", ["npub"], unique=False)
    op.create_index(op.f("ix_registeredsafebox_access_key"), "registeredsafebox", ["access_key"], unique=False)

    op.create_table(
        "paymentquote",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("nsec", sa.String(), nullable=False),
        sa.Column("handle", sa.String(), nullable=False),
        sa.Column("quote", sa.String(), nullable=False),
        sa.Column("amount", sa.Integer(), nullable=False),
        sa.Column("mint", sa.String(), nullable=False),
        sa.Column("paid", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "currencyrate",
        sa.Column("currency_code", sa.String(), nullable=False),
        sa.Column("currency_rate", sa.Float(), nullable=True),
        sa.Column("currency_symbol", sa.String(), nullable=True),
        sa.Column("currency_description", sa.String(), nullable=True),
        sa.Column("refresh_time", sa.DateTime(), nullable=True),
        sa.Column("fractional_unit", sa.String(), nullable=True),
        sa.Column("number_to_base", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("currency_code"),
    )

    op.create_table(
        "nwcevent",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id"),
    )

    op.create_table(
        "nwcsecret",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("nwc_secret", sa.String(), nullable=False),
        sa.Column("npub", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("nwc_secret"),
    )


def downgrade() -> None:
    op.drop_table("nwcsecret")
    op.drop_table("nwcevent")
    op.drop_table("currencyrate")
    op.drop_table("paymentquote")

    op.drop_index(op.f("ix_registeredsafebox_access_key"), table_name="registeredsafebox")
    op.drop_index(op.f("ix_registeredsafebox_npub"), table_name="registeredsafebox")
    op.drop_index(op.f("ix_registeredsafebox_handle"), table_name="registeredsafebox")
    op.drop_index("uq_registeredsafebox_access_key", table_name="registeredsafebox")
    op.drop_index("uq_registeredsafebox_npub", table_name="registeredsafebox")
    op.drop_index("uq_registeredsafebox_handle", table_name="registeredsafebox")
    op.drop_table("registeredsafebox")
