"""
X3DH (Extended Triple Diffie-Hellman) key agreement.

Spec reference: https://signal.org/docs/specifications/x3dh/

Key types used:
  IK  - Identity Key        (Curve25519 DH keypair)
  SPK - Signed PreKey       (Curve25519 DH keypair, signed by Ed25519 IK_sign)
  OPK - One-Time PreKey     (Curve25519 DH keypair, optional)
  EK  - Ephemeral Key       (Curve25519 DH keypair, generated per session init)

Initiator (Alice) computes:
  DH1 = DH(IK_a,  SPK_b)
  DH2 = DH(EK_a,  IK_b_dh)
  DH3 = DH(EK_a,  SPK_b)
  DH4 = DH(EK_a,  OPK_b)   [omitted if no OPK]
  SK  = HKDF(DH1 || DH2 || DH3 [|| DH4])

Responder (Bob) computes the same SK from the other side.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import uuid

from kyber_py.kyber import Kyber1024
import nacl.bindings
import nacl.public
import nacl.signing

from .keys import (
    ik_dh_private,
    ik_sign_private,
    spk_private,
    pqspk_private_bytes,
    get_opk_private,
    remove_opk,
    save_identity,
)

_HKDF_INFO = b"p2chat-pqxdh-v1"
_HKDF_SALT = b"\x00" * 32  # 32 zero bytes per Signal spec
_PQ_DOMAIN_SEP = b"\xff" * 32  # PQXDH domain separator


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _raw_dh(priv: nacl.public.PrivateKey, pub_bytes: bytes) -> bytes:
    """Raw X25519 Diffie-Hellman scalar multiplication."""
    return nacl.bindings.crypto_scalarmult(bytes(priv), pub_bytes)


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 extract-then-expand."""
    # Extract
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    # Expand
    t = b""
    okm = b""
    for i in range(1, -(-length // 32) + 1):  # ceil(length/32)
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


# ---------------------------------------------------------------------------
# KEM helpers (Kyber1024 via liboqs)
# ---------------------------------------------------------------------------

def _kem_encaps(pub_bytes: bytes) -> tuple[bytes, bytes]:
    """Encapsulate to a Kyber1024 public key. Returns (ciphertext, shared_secret)."""
    ss, ct = Kyber1024.encaps(pub_bytes)  # kyber-py returns (ss, ct)
    return ct, ss


def _kem_decaps(priv_bytes: bytes, ct: bytes) -> bytes:
    """Decapsulate a Kyber1024 ciphertext. Returns shared_secret."""
    return Kyber1024.decaps(priv_bytes, ct)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def initiate(my_identity: dict, their_bundle: dict) -> tuple[bytes, dict]:
    """
    Alice initiates an X3DH session with Bob.

    Returns:
      sk            - 32-byte shared secret
      x3dh_header   - dict to embed in the first message's header_b64
                      (contains Alice's public keys so Bob can reproduce SK)
    """
    # Verify Bob's SPK signature
    their_ik_sign_pub = nacl.signing.VerifyKey(_b64d(their_bundle["ik_sign_pub"]))
    spk_pub_bytes = _b64d(their_bundle["spk_pub"])
    spk_sig_bytes = _b64d(their_bundle["spk_sig"])
    their_ik_sign_pub.verify(spk_pub_bytes, spk_sig_bytes)  # raises if invalid

    # Verify Bob's PQSPK signature
    their_pqspk_pub = _b64d(their_bundle["pqspk_pub"])
    pqspk_sig_bytes = _b64d(their_bundle["pqspk_sig"])
    their_ik_sign_pub.verify(their_pqspk_pub, pqspk_sig_bytes)  # raises if invalid

    # My keys
    my_ik_dh = ik_dh_private(my_identity)
    ek = nacl.public.PrivateKey.generate()

    # Their public keys
    their_ik_dh_pub = _b64d(their_bundle["ik_dh_pub"])
    their_spk_pub = _b64d(their_bundle["spk_pub"])

    # DH computations
    dh1 = _raw_dh(my_ik_dh, their_spk_pub)
    dh2 = _raw_dh(ek, their_ik_dh_pub)
    dh3 = _raw_dh(ek, their_spk_pub)

    # KEM encapsulation (PQXDH step)
    pqspk_ct, ssq = _kem_encaps(their_pqspk_pub)

    ikm = _PQ_DOMAIN_SEP + dh1 + dh2 + dh3
    opk_id: str | None = None

    opk_entry = their_bundle.get("opk")  # server returns a single OPK or null
    if opk_entry:
        opk_id = opk_entry["opk_id"]
        their_opk_pub = _b64d(opk_entry["opk_pub"])
        dh4 = _raw_dh(ek, their_opk_pub)
        ikm += dh4

    ikm += ssq

    sk = _hkdf_sha256(ikm, _HKDF_SALT, _HKDF_INFO)

    x3dh_header = {
        "type": "x3dh_init",
        "ik_dh_pub": _b64e(bytes(my_ik_dh.public_key)),
        "ek_pub": _b64e(bytes(ek.public_key)),
        "spk_id": their_bundle["spk_id"],
        "opk_id": opk_id,
        "pqspk_id": their_bundle["pqspk_id"],
        "pqspk_ct": _b64e(pqspk_ct),
    }

    return sk, x3dh_header


def accept(my_identity: dict, x3dh_header: dict) -> bytes:
    """
    Bob accepts an X3DH session initiated by Alice.

    Returns:
      sk  - 32-byte shared secret (same as what Alice computed)

    Side effect: consumes (removes) the used OPK from identity and saves it.
    """
    their_ik_dh_pub = _b64d(x3dh_header["ik_dh_pub"])
    their_ek_pub = _b64d(x3dh_header["ek_pub"])
    opk_id: str | None = x3dh_header.get("opk_id")
    pqspk_ct = _b64d(x3dh_header["pqspk_ct"])

    my_ik_dh = ik_dh_private(my_identity)
    my_spk = spk_private(my_identity)

    # DH computations (mirror of Alice's)
    dh1 = _raw_dh(my_spk, their_ik_dh_pub)
    dh2 = _raw_dh(my_ik_dh, their_ek_pub)
    dh3 = _raw_dh(my_spk, their_ek_pub)

    # KEM decapsulation (PQXDH step)
    ssq = _kem_decaps(pqspk_private_bytes(my_identity), pqspk_ct)

    ikm = _PQ_DOMAIN_SEP + dh1 + dh2 + dh3

    if opk_id:
        my_opk = get_opk_private(my_identity, opk_id)
        if my_opk is not None:
            dh4 = _raw_dh(my_opk, their_ek_pub)
            ikm += dh4
            # Consume the OPK — it must never be reused
            remove_opk(my_identity, opk_id)
            save_identity(my_identity["device_id"], my_identity)

    ikm += ssq

    sk = _hkdf_sha256(ikm, _HKDF_SALT, _HKDF_INFO)
    return sk
