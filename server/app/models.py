from sqlalchemy import String, BigInteger, Integer, Text, UniqueConstraint, Index, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from typing import Optional
from .db import Base


class KeyBundle(Base):
    """Public key bundle for a device (identity + signed prekey)."""
    __tablename__ = "key_bundles"

    device_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    ik_sign_pub: Mapped[str] = mapped_column(Text, nullable=False)   # Ed25519 pub, base64
    ik_dh_pub: Mapped[str] = mapped_column(Text, nullable=False)     # Curve25519 pub, base64
    spk_id: Mapped[str] = mapped_column(String(36), nullable=False)  # UUID of current SPK
    spk_pub: Mapped[str] = mapped_column(Text, nullable=False)       # Curve25519 pub, base64
    spk_sig: Mapped[str] = mapped_column(Text, nullable=False)       # Ed25519 sig of spk_pub
    pqspk_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)   # UUID of PQSPK
    pqspk_pub: Mapped[Optional[str]] = mapped_column(Text, nullable=True)        # Kyber1024 pub, base64
    pqspk_sig: Mapped[Optional[str]] = mapped_column(Text, nullable=True)        # Ed25519 sig of pqspk_pub
    updated_at_ms: Mapped[int] = mapped_column(BigInteger, nullable=False)


class OneTimePrekey(Base):
    """One-time prekeys for a device. Each row is consumed (deleted) on first use."""
    __tablename__ = "one_time_prekeys"

    opk_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("key_bundles.device_id"), nullable=False
    )
    opk_pub: Mapped[str] = mapped_column(Text, nullable=False)  # Curve25519 pub, base64

    __table_args__ = (
        Index("ix_opk_device_id", "device_id"),
    )


class MessageQueue(Base):
    __tablename__ = "message_queue"

    msg_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    client_msg_id: Mapped[str] = mapped_column(String(36), nullable=False)

    from_device_id: Mapped[str] = mapped_column(String(128), nullable=False)
    to_device_id: Mapped[str] = mapped_column(String(128), nullable=False)

    type: Mapped[str] = mapped_column(String(32), nullable=False)  # direct/control/group later
    header_b64: Mapped[str] = mapped_column(Text, nullable=False, default="")
    ciphertext_b64: Mapped[str] = mapped_column(Text, nullable=False)

    created_at_ms: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=604800)
    group_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, default=None)
    group_meta: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)

    __table_args__ = (
        # Dedup for idempotent retries
        UniqueConstraint("from_device_id", "client_msg_id", name="uq_from_clientmsg"),
        Index("ix_queue_to_device_created", "to_device_id", "created_at_ms"),
    )