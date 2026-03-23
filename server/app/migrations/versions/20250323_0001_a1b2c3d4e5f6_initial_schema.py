"""initial schema

Revision ID: a1b2c3d4e5f6
Revises:
Create Date: 2025-03-23 00:01:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "key_bundles",
        sa.Column("device_id", sa.String(128), primary_key=True),
        sa.Column("ik_sign_pub", sa.Text, nullable=False),
        sa.Column("ik_dh_pub", sa.Text, nullable=False),
        sa.Column("spk_id", sa.String(36), nullable=False),
        sa.Column("spk_pub", sa.Text, nullable=False),
        sa.Column("spk_sig", sa.Text, nullable=False),
        sa.Column("pqspk_id", sa.String(36), nullable=True),
        sa.Column("pqspk_pub", sa.Text, nullable=True),
        sa.Column("pqspk_sig", sa.Text, nullable=True),
        sa.Column("device_secret_hash", sa.String(64), nullable=True),
        sa.Column("updated_at_ms", sa.BigInteger, nullable=False),
    )

    op.create_table(
        "one_time_prekeys",
        sa.Column("opk_id", sa.String(36), primary_key=True),
        sa.Column(
            "device_id",
            sa.String(128),
            sa.ForeignKey("key_bundles.device_id"),
            nullable=False,
        ),
        sa.Column("opk_pub", sa.Text, nullable=False),
    )
    op.create_index("ix_opk_device_id", "one_time_prekeys", ["device_id"])

    op.create_table(
        "message_queue",
        sa.Column("msg_id", sa.String(36), primary_key=True),
        sa.Column("client_msg_id", sa.String(36), nullable=False),
        sa.Column("from_device_id", sa.String(128), nullable=False),
        sa.Column("to_device_id", sa.String(128), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("header_b64", sa.Text, nullable=False, server_default=""),
        sa.Column("ciphertext_b64", sa.Text, nullable=False),
        sa.Column("created_at_ms", sa.BigInteger, nullable=False),
        sa.Column("ttl_seconds", sa.Integer, nullable=False, server_default="604800"),
        sa.Column("group_id", sa.String(36), nullable=True),
        sa.Column("group_meta", sa.Text, nullable=True),
        sa.UniqueConstraint("from_device_id", "client_msg_id", name="uq_from_clientmsg"),
    )
    op.create_index(
        "ix_queue_to_device_created",
        "message_queue",
        ["to_device_id", "created_at_ms"],
    )


def downgrade() -> None:
    op.drop_index("ix_queue_to_device_created", table_name="message_queue")
    op.drop_table("message_queue")
    op.drop_index("ix_opk_device_id", table_name="one_time_prekeys")
    op.drop_table("one_time_prekeys")
    op.drop_table("key_bundles")
