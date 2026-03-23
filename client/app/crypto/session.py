"""
Session manager — ties X3DH and Double Ratchet together.

Responsibilities:
  - Ensure local identity keys exist (generate on first run)
  - Upload key bundle to server when needed
  - Fetch peer's key bundle from server for new sessions
  - Run X3DH to establish a shared secret
  - Initialise a Double Ratchet session from that secret
  - Persist / load ratchet state per peer
  - Expose encrypt_for() / decrypt_from() to the rest of the app

Session files on disk:
  ~/.p2chat/<device_id>/sessions/<peer_id>.json
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Optional

import httpx

from .keys import (
    build_bundle,
    load_or_generate_identity,
    ik_sign_private,
    spk_private,
    save_identity,
)
from .x3dh import initiate, accept
from .ratchet import (
    RatchetState,
    init_sender,
    init_receiver,
    encrypt,
    decrypt,
)

_DATA_ROOT = Path.home() / ".p2chat"
_RELAY = "http://127.0.0.1:8000"


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# Session manager
# ---------------------------------------------------------------------------

class SessionManager:
    def __init__(self, device_id: str) -> None:
        self.device_id = device_id
        self._identity = load_or_generate_identity(device_id)
        self._ensure_registered()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def _ensure_registered(self) -> None:
        """Upload our key bundle to the server if not already done."""
        flag = _DATA_ROOT / self.device_id / ".registered"
        if flag.exists():
            return
        self._upload_bundle()
        flag.parent.mkdir(parents=True, exist_ok=True)
        flag.touch()

    def _upload_bundle(self) -> None:
        bundle = build_bundle(self._identity)
        resp = httpx.post(f"{_RELAY}/v1/keys/{self.device_id}", json=bundle)
        resp.raise_for_status()

    # ------------------------------------------------------------------
    # Session persistence
    # ------------------------------------------------------------------

    def _session_path(self, peer_id: str) -> Path:
        return _DATA_ROOT / self.device_id / "sessions" / f"{peer_id}.json"

    def _save_session(self, peer_id: str, state: RatchetState) -> None:
        path = self._session_path(peer_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state.to_dict(), indent=2), encoding="utf-8")

    def _load_session(self, peer_id: str) -> Optional[RatchetState]:
        path = self._session_path(peer_id)
        if not path.exists():
            return None
        return RatchetState.from_dict(json.loads(path.read_text(encoding="utf-8")))

    # ------------------------------------------------------------------
    # Encrypt
    # ------------------------------------------------------------------

    def encrypt_for(self, peer_id: str, plaintext: str) -> tuple[str, str]:
        """
        Encrypt plaintext for peer_id.

        Returns (header_b64, ciphertext_b64).
        On first message: header contains X3DH init data + DR header.
        Subsequent messages: header contains only the DR header.
        """
        state = self._load_session(peer_id)

        if state is None:
            # First message — run X3DH
            their_bundle = self._fetch_bundle(peer_id)
            sk, x3dh_hdr = initiate(self._identity, their_bundle)
            their_spk_pub = _b64d(their_bundle["spk_pub"])
            state = init_sender(sk, their_spk_pub)
            dr_header, ciphertext = encrypt(state, plaintext.encode("utf-8"))
            # Combine X3DH header with DR header
            full_header = {**x3dh_hdr, "dr": dr_header}
        else:
            dr_header, ciphertext = encrypt(state, plaintext.encode("utf-8"))
            full_header = {"type": "dr", "dr": dr_header}

        self._save_session(peer_id, state)

        header_b64 = _b64e(json.dumps(full_header).encode("utf-8"))
        ciphertext_b64 = _b64e(ciphertext)
        return header_b64, ciphertext_b64

    # ------------------------------------------------------------------
    # Decrypt
    # ------------------------------------------------------------------

    def decrypt_from(self, peer_id: str, header_b64: str, ciphertext_b64: str) -> str:
        """
        Decrypt a message from peer_id.

        Handles both X3DH init messages and ongoing DR messages.
        """
        header = json.loads(_b64d(header_b64).decode("utf-8"))
        ciphertext = _b64d(ciphertext_b64)

        state = self._load_session(peer_id)

        if header.get("type") == "x3dh_init":
            # First message from this peer — run X3DH accept
            sk = accept(self._identity, header)
            # save_identity already called inside accept() if OPK was consumed
            self._identity = load_or_generate_identity(self.device_id)
            my_spk = spk_private(self._identity)
            state = init_receiver(sk, my_spk)
            dr_header = header["dr"]
        elif header.get("type") == "dr":
            if state is None:
                raise ValueError(f"No session found for peer {peer_id!r} but received DR message")
            dr_header = header["dr"]
        else:
            raise ValueError(f"Unknown header type: {header.get('type')!r}")

        plaintext_bytes = decrypt(state, dr_header, ciphertext)
        self._save_session(peer_id, state)
        return plaintext_bytes.decode("utf-8")

    # ------------------------------------------------------------------
    # Key bundle fetch
    # ------------------------------------------------------------------

    def _fetch_bundle(self, peer_id: str) -> dict:
        resp = httpx.get(f"{_RELAY}/v1/keys/{peer_id}")
        resp.raise_for_status()
        return resp.json()
