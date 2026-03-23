"""
Key generation and local persistence for the X3DH identity bundle.

Layout on disk:
  ~/.p2chat/<device_id>/identity.json

identity.json schema:
{
  "device_id": str,
  "ik_sign_priv": str,          # base64 Ed25519 private seed (32 bytes)
  "ik_sign_pub":  str,          # base64 Ed25519 public key   (32 bytes)
  "ik_dh_priv":   str,          # base64 Curve25519 private key
  "ik_dh_pub":    str,          # base64 Curve25519 public key
  "spk_id":       str,          # UUID of current signed prekey
  "spk_priv":     str,          # base64 Curve25519 private key
  "spk_pub":      str,          # base64 Curve25519 public key
  "spk_sig":      str,          # base64 Ed25519 signature of spk_pub
  "opks": {
    "<opk_id>": {
      "priv": str,              # base64 Curve25519 private key
      "pub":  str               # base64 Curve25519 public key
    },
    ...
  }
}
"""

from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path

from kyber_py.kyber import Kyber1024
import nacl.signing
import nacl.public

_DATA_ROOT = Path.home() / ".p2chat"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _identity_path(device_id: str) -> Path:
    return _DATA_ROOT / device_id / "identity.json"


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def _gen_signing_keypair() -> tuple[nacl.signing.SigningKey, nacl.signing.VerifyKey]:
    sk = nacl.signing.SigningKey.generate()
    return sk, sk.verify_key


def _gen_dh_keypair() -> nacl.public.PrivateKey:
    return nacl.public.PrivateKey.generate()


def _gen_pqspk() -> tuple[bytes, bytes]:
    """Generate a Kyber1024 KEM keypair. Returns (pub_bytes, priv_bytes)."""
    pub, priv = Kyber1024.keygen()
    return pub, priv


def _sign_spk(ik_sign: nacl.signing.SigningKey, spk_pub_bytes: bytes) -> bytes:
    """Sign the raw bytes of a Curve25519 public key with Ed25519."""
    signed = ik_sign.sign(spk_pub_bytes)
    # nacl.signing returns a SignedMessage whose first 64 bytes are the signature
    return bytes(signed.signature)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_identity(device_id: str, num_opks: int = 10) -> dict:
    """Generate a fresh identity bundle and persist it. Returns the bundle dict."""
    ik_sign = nacl.signing.SigningKey.generate()
    ik_dh = nacl.public.PrivateKey.generate()
    spk = nacl.public.PrivateKey.generate()
    spk_id = str(uuid.uuid4())
    spk_sig = _sign_spk(ik_sign, bytes(spk.public_key))

    pqspk_pub, pqspk_priv = _gen_pqspk()
    pqspk_id = str(uuid.uuid4())
    pqspk_sig = _sign_spk(ik_sign, pqspk_pub)

    opks: dict[str, dict] = {}
    for _ in range(num_opks):
        opk = nacl.public.PrivateKey.generate()
        opk_id = str(uuid.uuid4())
        opks[opk_id] = {
            "priv": _b64e(bytes(opk)),
            "pub": _b64e(bytes(opk.public_key)),
        }

    identity = {
        "device_id": device_id,
        "ik_sign_priv": _b64e(bytes(ik_sign)),
        "ik_sign_pub": _b64e(bytes(ik_sign.verify_key)),
        "ik_dh_priv": _b64e(bytes(ik_dh)),
        "ik_dh_pub": _b64e(bytes(ik_dh.public_key)),
        "spk_id": spk_id,
        "spk_priv": _b64e(bytes(spk)),
        "spk_pub": _b64e(bytes(spk.public_key)),
        "spk_sig": _b64e(spk_sig),
        "pqspk_id": pqspk_id,
        "pqspk_pub": _b64e(pqspk_pub),
        "pqspk_priv": _b64e(pqspk_priv),
        "pqspk_sig": _b64e(pqspk_sig),
        "opks": opks,
    }

    save_identity(device_id, identity)
    return identity


def load_identity(device_id: str) -> dict | None:
    """Load identity from disk. Returns None if not found."""
    path = _identity_path(device_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def save_identity(device_id: str, identity: dict) -> None:
    path = _identity_path(device_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(identity, indent=2), encoding="utf-8")


def load_or_generate_identity(device_id: str) -> dict:
    """Load existing identity or create a new one."""
    return load_identity(device_id) or generate_identity(device_id)


def build_bundle(identity: dict) -> dict:
    """
    Build the public key bundle dict that gets uploaded to the server.
    Includes all unused OPK public keys.
    """
    opk_pubs = [
        {"opk_id": opk_id, "opk_pub": opk["pub"]}
        for opk_id, opk in identity["opks"].items()
    ]
    return {
        "device_id": identity["device_id"],
        "ik_sign_pub": identity["ik_sign_pub"],
        "ik_dh_pub": identity["ik_dh_pub"],
        "spk_id": identity["spk_id"],
        "spk_pub": identity["spk_pub"],
        "spk_sig": identity["spk_sig"],
        "pqspk_id": identity["pqspk_id"],
        "pqspk_pub": identity["pqspk_pub"],
        "pqspk_sig": identity["pqspk_sig"],
        "opk_pubs": opk_pubs,
    }


def get_opk_private(identity: dict, opk_id: str) -> nacl.public.PrivateKey | None:
    """Return the PrivateKey for the given OPK id, or None if not found."""
    entry = identity["opks"].get(opk_id)
    if entry is None:
        return None
    return nacl.public.PrivateKey(_b64d(entry["priv"]))


def remove_opk(identity: dict, opk_id: str) -> None:
    """Remove a consumed OPK from the identity (call save_identity after)."""
    identity["opks"].pop(opk_id, None)


def ik_dh_private(identity: dict) -> nacl.public.PrivateKey:
    return nacl.public.PrivateKey(_b64d(identity["ik_dh_priv"]))


def ik_sign_private(identity: dict) -> nacl.signing.SigningKey:
    return nacl.signing.SigningKey(_b64d(identity["ik_sign_priv"]))


def spk_private(identity: dict) -> nacl.public.PrivateKey:
    return nacl.public.PrivateKey(_b64d(identity["spk_priv"]))


def pqspk_public_bytes(identity: dict) -> bytes:
    return _b64d(identity["pqspk_pub"])


def pqspk_private_bytes(identity: dict) -> bytes:
    return _b64d(identity["pqspk_priv"])
