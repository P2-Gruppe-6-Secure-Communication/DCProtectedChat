"""
Double Ratchet Algorithm implementation.

Spec reference: https://signal.org/docs/specifications/doubleratchet/

The Double Ratchet combines two ratchets:
  1. DH Ratchet   — advances when a new DH public key is received, providing
                    break-in recovery (future secrecy / healing)
  2. Symmetric-key Ratchet — KDF chain that advances with every message,
                    providing forward secrecy

State:
  DHs       — our current sending DH keypair (Curve25519)
  DHr       — their latest DH public key (bytes or None)
  RK        — 32-byte root key
  CKs       — 32-byte sending chain key (None until first DH ratchet step)
  CKr       — 32-byte receiving chain key (None until first message received)
  Ns        — message number in sending chain
  Nr        — message number in receiving chain
  PN        — number of messages in the previous sending chain
  MKSKIPPED — {(dh_pub_hex, n): message_key} for out-of-order messages

Encryption: nacl.secret.SecretBox (XSalsa20-Poly1305)
KDF:        HKDF-SHA256 (hmac + hashlib only, no extra deps)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Optional

import nacl.bindings
import nacl.public
import nacl.secret

_MAX_SKIP = 1000   # maximum skipped messages to store

_INFO_RK  = b"p2chat-dr-rk-v1"
_INFO_CK  = b"p2chat-dr-ck-v1"
_INFO_MK  = b"p2chat-dr-mk-v1"
_HKDF_SALT = b"\x00" * 32


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _raw_dh(priv: nacl.public.PrivateKey, pub_bytes: bytes) -> bytes:
    return nacl.bindings.crypto_scalarmult(bytes(priv), pub_bytes)


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t, okm = b"", b""
    for i in range(1, -(-length // 32) + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def _kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Root-key KDF: (new_RK, new_CK) = KDF(RK, DH_output)."""
    out = _hkdf(dh_out, salt=rk, info=_INFO_RK, length=64)
    return out[:32], out[32:]


def _kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """Chain-key KDF: (new_CK, MK) = KDF(CK)."""
    mk = hmac.new(ck, b"\x01", hashlib.sha256).digest()
    new_ck = hmac.new(ck, b"\x02", hashlib.sha256).digest()
    return new_ck, mk


# ---------------------------------------------------------------------------
# Ratchet state
# ---------------------------------------------------------------------------

@dataclass
class RatchetState:
    DHs: nacl.public.PrivateKey
    DHr: Optional[bytes]         # raw 32-byte Curve25519 public key
    RK: bytes
    CKs: Optional[bytes]
    CKr: Optional[bytes]
    Ns: int = 0
    Nr: int = 0
    PN: int = 0
    MKSKIPPED: dict = field(default_factory=dict)  # key: "<dh_hex>:<n>"

    # --- Serialisation ---

    def to_dict(self) -> dict:
        return {
            "DHs_priv": _b64e(bytes(self.DHs)),
            "DHs_pub":  _b64e(bytes(self.DHs.public_key)),
            "DHr":      _b64e(self.DHr) if self.DHr else None,
            "RK":       _b64e(self.RK),
            "CKs":      _b64e(self.CKs) if self.CKs else None,
            "CKr":      _b64e(self.CKr) if self.CKr else None,
            "Ns":       self.Ns,
            "Nr":       self.Nr,
            "PN":       self.PN,
            "MKSKIPPED": {k: _b64e(v) for k, v in self.MKSKIPPED.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RatchetState":
        return cls(
            DHs=nacl.public.PrivateKey(_b64d(d["DHs_priv"])),
            DHr=_b64d(d["DHr"]) if d["DHr"] else None,
            RK=_b64d(d["RK"]),
            CKs=_b64d(d["CKs"]) if d["CKs"] else None,
            CKr=_b64d(d["CKr"]) if d["CKr"] else None,
            Ns=d["Ns"],
            Nr=d["Nr"],
            PN=d["PN"],
            MKSKIPPED={k: _b64d(v) for k, v in d.get("MKSKIPPED", {}).items()},
        )


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def init_sender(sk: bytes, their_spk_pub_bytes: bytes) -> RatchetState:
    """
    Alice initialises the ratchet after X3DH.
    - sk: shared secret from X3DH
    - their_spk_pub_bytes: Bob's signed prekey public key (becomes initial DHr)
    """
    dhs = nacl.public.PrivateKey.generate()
    dh_out = _raw_dh(dhs, their_spk_pub_bytes)
    rk, cks = _kdf_rk(sk, dh_out)
    return RatchetState(
        DHs=dhs,
        DHr=their_spk_pub_bytes,
        RK=rk,
        CKs=cks,
        CKr=None,
    )


def init_receiver(sk: bytes, my_spk_priv: nacl.public.PrivateKey) -> RatchetState:
    """
    Bob initialises the ratchet after accepting the X3DH init message.
    - sk: shared secret from X3DH
    - my_spk_priv: Bob's signed prekey private key (used as initial DHs)
    """
    return RatchetState(
        DHs=my_spk_priv,
        DHr=None,
        RK=sk,
        CKs=None,
        CKr=None,
    )


# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------

def encrypt(state: RatchetState, plaintext: bytes) -> tuple[dict, bytes]:
    """
    Encrypt plaintext, advancing the sending chain.

    Returns:
      header    - dict to serialise into header_b64
                  {"dh": <b64 pub>, "pn": int, "n": int}
      ciphertext - encrypted bytes (SecretBox output, includes nonce + MAC)
    """
    assert state.CKs is not None, "Sender chain not initialised"
    state.CKs, mk = _kdf_ck(state.CKs)
    header = {
        "dh": _b64e(bytes(state.DHs.public_key)),
        "pn": state.PN,
        "n":  state.Ns,
    }
    state.Ns += 1
    box = nacl.secret.SecretBox(mk)
    ciphertext = bytes(box.encrypt(plaintext))
    return header, ciphertext


def decrypt(state: RatchetState, header: dict, ciphertext: bytes) -> bytes:
    """
    Decrypt a received message, advancing the receiving chain (and possibly
    performing a DH ratchet step first).

    Handles out-of-order messages by storing/looking up skipped message keys.
    """
    their_dh_pub = _b64d(header["dh"])
    n = header["n"]
    pn = header["pn"]

    # Check skipped message keys first
    skip_key = f"{_b64e(their_dh_pub)}:{n}"
    if skip_key in state.MKSKIPPED:
        mk = state.MKSKIPPED.pop(skip_key)
        return _decrypt_with_key(mk, ciphertext)

    # DH ratchet step if we see a new ratchet key
    if their_dh_pub != state.DHr:
        # Skip remaining messages from the previous chain
        _skip_message_keys(state, pn)
        # Perform DH ratchet
        _dh_ratchet(state, their_dh_pub)

    # Skip ahead to message n in receiving chain
    _skip_message_keys(state, n)

    # Decrypt with the next receiving chain key
    assert state.CKr is not None
    state.CKr, mk = _kdf_ck(state.CKr)
    state.Nr += 1
    return _decrypt_with_key(mk, ciphertext)


def _decrypt_with_key(mk: bytes, ciphertext: bytes) -> bytes:
    box = nacl.secret.SecretBox(mk)
    return bytes(box.decrypt(ciphertext))


def _skip_message_keys(state: RatchetState, until: int) -> None:
    if state.CKr is None:
        return
    if state.Nr + _MAX_SKIP < until:
        raise ValueError(f"Too many skipped messages: {until - state.Nr}")
    while state.Nr < until:
        state.CKr, mk = _kdf_ck(state.CKr)
        key = f"{_b64e(state.DHr)}:{state.Nr}" if state.DHr else f"none:{state.Nr}"
        state.MKSKIPPED[key] = mk
        state.Nr += 1


def _dh_ratchet(state: RatchetState, their_dh_pub: bytes) -> None:
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = their_dh_pub

    # Receiving chain from their new key
    dh_out = _raw_dh(state.DHs, their_dh_pub)
    state.RK, state.CKr = _kdf_rk(state.RK, dh_out)

    # New sending key pair + sending chain
    state.DHs = nacl.public.PrivateKey.generate()
    dh_out2 = _raw_dh(state.DHs, their_dh_pub)
    state.RK, state.CKs = _kdf_rk(state.RK, dh_out2)
