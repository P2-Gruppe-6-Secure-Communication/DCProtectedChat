from pydantic import BaseModel, Field
from typing import Optional, Literal


class OpkEntry(BaseModel):
    opk_id: str
    opk_pub: str  # base64 Curve25519 public key


class KeyBundleIn(BaseModel):
    """Payload a device POSTs to register/update its key bundle."""
    ik_sign_pub: str          # base64 Ed25519 verify key
    ik_dh_pub: str            # base64 Curve25519 public key
    spk_id: str               # UUID of the signed prekey
    spk_pub: str              # base64 Curve25519 public key
    spk_sig: str              # base64 Ed25519 signature of spk_pub
    pqspk_id: str             # UUID of the Kyber1024 prekey
    pqspk_pub: str            # base64 Kyber1024 public key
    pqspk_sig: str            # base64 Ed25519 signature of pqspk_pub
    opk_pubs: list[OpkEntry]  # batch of one-time prekeys to upload
    device_secret: Optional[str] = None  # random secret for auth; stored as SHA-256 hash


class KeyBundleOut(BaseModel):
    """Response from GET /v1/keys/{device_id}. Includes at most one OPK."""
    device_id: str
    ik_sign_pub: str
    ik_dh_pub: str
    spk_id: str
    spk_pub: str
    spk_sig: str
    pqspk_id: str
    pqspk_pub: str
    pqspk_sig: str
    opk: Optional[OpkEntry] = None  # None if no OPKs remain


class EnvelopeIn(BaseModel):
    msg_id: str = Field(..., min_length=10)
    client_msg_id: str = Field(..., min_length=10)
    from_device_id: str
    to_device_id: str
    type: Literal["direct", "control", "group"]
    header_b64: str = ""
    ciphertext_b64: str
    created_at_ms: int
    ttl_seconds: int = 7 * 24 * 3600
    group_id: Optional[str] = None
    group_meta: Optional[str] = None  # JSON: {"name": str, "members": [str, ...]}

class EnvelopeOut(EnvelopeIn):
    pass

class SendResponse(BaseModel):
    status: Literal["stored", "duplicate"]
    msg_id: str