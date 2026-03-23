from pydantic import BaseModel, Field
from typing import Optional, Literal


class OpkEntry(BaseModel):
    opk_id: str = Field(..., max_length=128)
    opk_pub: str = Field(..., max_length=256)  # base64 Curve25519 public key


class KeyBundleIn(BaseModel):
    """Payload a device POSTs to register/update its key bundle."""
    ik_sign_pub: str = Field(..., max_length=256)      # base64 Ed25519 verify key
    ik_dh_pub: str = Field(..., max_length=256)         # base64 Curve25519 public key
    spk_id: str = Field(..., max_length=128)            # UUID of the signed prekey
    spk_pub: str = Field(..., max_length=256)           # base64 Curve25519 public key
    spk_sig: str = Field(..., max_length=256)           # base64 Ed25519 signature of spk_pub
    pqspk_id: str = Field(..., max_length=128)          # UUID of the Kyber1024 prekey
    pqspk_pub: str = Field(..., max_length=4_096)       # base64 Kyber1024 public key (~2096 b64 chars)
    pqspk_sig: str = Field(..., max_length=256)         # base64 Ed25519 signature of pqspk_pub
    opk_pubs: list[OpkEntry] = Field(..., max_length=50)  # max 50 OPKs per upload
    device_secret: Optional[str] = Field(None, max_length=128)  # stored as SHA-256 hash


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
    msg_id: str = Field(..., min_length=10, max_length=128)
    client_msg_id: str = Field(..., min_length=10, max_length=128)
    from_device_id: str = Field(..., max_length=128)
    to_device_id: str = Field(..., max_length=128)
    type: Literal["direct", "control", "group"]
    header_b64: str = Field("", max_length=8_192)           # ~6 KB decoded
    ciphertext_b64: str = Field(..., max_length=131_072)    # ~96 KB decoded
    created_at_ms: int
    ttl_seconds: int = Field(7 * 24 * 3600, ge=1, le=30 * 24 * 3600)
    group_id: Optional[str] = Field(None, max_length=128)
    group_meta: Optional[str] = Field(None, max_length=4_096)

class EnvelopeOut(EnvelopeIn):
    pass

class SendResponse(BaseModel):
    status: Literal["stored", "duplicate"]
    msg_id: str
