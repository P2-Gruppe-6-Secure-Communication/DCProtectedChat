from pathlib import Path
import json
import time
import uuid
import webview
import httpx

from app.crypto.session import SessionManager
from app.crypto.groups import (
    create_group as _create_group,
    load_group,
    list_groups,
    save_group,
)

import os

# Allow relay URL override via config file or env var
def _load_relay() -> str:
    config_path = Path.home() / ".p2chat" / "config.json"
    if config_path.exists():
        try:
            cfg = json.loads(config_path.read_text(encoding="utf-8"))
            if cfg.get("relay"):
                return cfg["relay"]
        except Exception:
            pass
    return os.environ.get("P2_RELAY", "http://127.0.0.1:8000")

RELAY = _load_relay()


class PyAPI:
    def __init__(self):
        self._relay = RELAY
        self.client = httpx.Client(timeout=10.0)
        self._sessions: dict[str, SessionManager] = {}
        # Track devices whose registration is still pending (avoids log spam)
        self._pending_registration: set[str] = set()

    def _auth_header(self, me: str) -> dict:
        """Return the Authorization header for the given device, if registered."""
        session = self._sessions.get(me)
        if session:
            return session.auth_header()
        return {}

    def register(self, me: str) -> dict:
        """Explicitly register (or re-register) a device and return status."""
        me = me.strip()
        if not me:
            return {"ok": False, "error": "Device ID cannot be empty"}
        # Remove cached session and delete the local flag so _ensure_registered()
        # always does a real upload — prevents stale flag from skipping the server call.
        self._sessions.pop(me, None)
        self._pending_registration.discard(me)
        flag = Path.home() / ".p2chat" / me / ".registered"
        flag.unlink(missing_ok=True)
        try:
            self._sessions[me] = SessionManager(me, relay=self._relay)
            return {"ok": True, "device_id": me}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _session(self, me: str) -> SessionManager | None:
        """
        Return (or lazily create) the SessionManager for device `me`.
        Returns None and logs nothing if registration is still in progress or
        failed — the caller should handle None gracefully.
        """
        if me in self._sessions:
            return self._sessions[me]
        try:
            self._sessions[me] = SessionManager(me, relay=self._relay)
            self._pending_registration.discard(me)
            return self._sessions[me]
        except Exception as exc:
            self._pending_registration.add(me)
            # Return the error string so the caller can decide whether to surface it
            raise RuntimeError(f"Key setup for '{me}' failed: {exc}") from exc

    def send_message(self, me: str, to: str, text: str):
        try:
            session = self._session(me)
        except RuntimeError as exc:
            return {"error": str(exc)}

        try:
            header_b64, ciphertext_b64 = session.encrypt_for(to, text)
        except Exception as exc:
            # Common case: recipient has not registered their keys yet
            msg = str(exc)
            if "404" in msg or "not registered" in msg.lower():
                return {"error": f"Recipient '{to}' is not registered yet. Have them open the app first."}
            return {"error": f"Encryption failed: {exc}"}

        payload = {
            "msg_id": str(uuid.uuid4()),
            "client_msg_id": str(uuid.uuid4()),
            "from_device_id": me,
            "to_device_id": to,
            "type": "direct",
            "header_b64": header_b64,
            "ciphertext_b64": ciphertext_b64,
            "created_at_ms": int(time.time() * 1000),
            "ttl_seconds": 7 * 24 * 3600,
        }
        r = self.client.post(f"{self._relay}/v1/messages", json=payload, headers=self._auth_header(me))
        r.raise_for_status()
        return r.json()

    def create_group(self, me: str, name: str, members_csv: str) -> dict:
        """Create a group locally and return it."""
        me = me.strip()
        members = [m.strip() for m in members_csv.split(",") if m.strip()]
        try:
            group = _create_group(me, name, members)
            return {"ok": True, "group": group}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def get_groups(self, me: str) -> list:
        """Return all locally-stored groups for device `me`."""
        me = me.strip()
        try:
            return list_groups(me)
        except Exception as exc:
            print(f"[get_groups] error for '{me}': {exc}", flush=True)
            return []

    def send_group_message(self, me: str, group_id: str, text: str) -> dict:
        """
        Fan-out: encrypt `text` for each group member (except self) and post
        one envelope per member. Partial failures collected as warnings.
        """
        me = me.strip()
        group = load_group(me, group_id)
        if group is None:
            return {"ok": False, "error": f"Group {group_id!r} not found locally"}

        try:
            session = self._session(me)
        except RuntimeError as exc:
            return {"ok": False, "error": str(exc)}

        recipients = [m for m in group["members"] if m != me]
        if not recipients:
            return {"ok": False, "error": "No other members in group"}

        errors: list = []
        sent = 0
        now_ms = int(time.time() * 1000)

        for peer_id in recipients:
            try:
                header_b64, ciphertext_b64 = session.encrypt_for(peer_id, text)
            except Exception as exc:
                msg = str(exc)
                if "404" in msg or "not registered" in msg.lower():
                    errors.append(f"{peer_id}: not registered yet")
                else:
                    errors.append(f"{peer_id}: encryption failed — {exc}")
                continue

            payload = {
                "msg_id": str(uuid.uuid4()),
                "client_msg_id": str(uuid.uuid4()),
                "from_device_id": me,
                "to_device_id": peer_id,
                "type": "group",
                "header_b64": header_b64,
                "ciphertext_b64": ciphertext_b64,
                "created_at_ms": now_ms,
                "ttl_seconds": 7 * 24 * 3600,
                "group_id": group_id,
                "group_meta": json.dumps({"name": group["name"], "members": group["members"]}),
            }
            try:
                r = self.client.post(f"{self._relay}/v1/messages", json=payload, headers=self._auth_header(me))
                r.raise_for_status()
                sent += 1
            except Exception as exc:
                errors.append(f"{peer_id}: server error — {exc}")

        result: dict = {"ok": True, "sent": sent}
        if errors:
            result["warnings"] = errors
        return result

    def poll(self, me: str):
        # Never raise to JavaScript — all errors are printed to the Python
        # console and the UI simply gets an empty list, retrying in 800 ms.
        try:
            r = self.client.get(
                f"{self._relay}/v1/messages/poll",
                params={"device_id": me},
                headers=self._auth_header(me),
            )
            r.raise_for_status()
            envelopes = r.json()
        except Exception as exc:
            print(f"[poll] server unreachable for '{me}': {exc}", flush=True)
            return []

        try:
            session = self._session(me)
        except RuntimeError as exc:
            print(f"[poll] key setup pending for '{me}': {exc}", flush=True)
            return []

        out = []
        for e in envelopes:
            try:
                plaintext = session.decrypt_from(
                    e["from_device_id"],
                    e["header_b64"],
                    e["ciphertext_b64"],
                )
            except Exception as exc:
                plaintext = f"[decryption error: {exc}]"
            group_id = e.get("group_id")
            if group_id and e.get("group_meta") and load_group(me, group_id) is None:
                try:
                    meta = json.loads(e["group_meta"])
                    save_group(me, {
                        "group_id": group_id,
                        "name": meta.get("name", "Group " + group_id[:8]),
                        "members": meta.get("members", [e["from_device_id"]]),
                        "created_at_ms": int(time.time() * 1000),
                    })
                except Exception:
                    pass
            out.append({
                "msg_id": e["msg_id"],
                "from": e["from_device_id"],
                "plaintext": plaintext,
                "group_id": group_id,
                "group_meta": e.get("group_meta"),
            })
            try:
                self.client.post(
                    f"{self._relay}/v1/messages/{e['msg_id']}/ack",
                    headers=self._auth_header(me),
                )
            except Exception:
                pass  # non-critical; message will be re-delivered on next poll
        return out


def main():
    api = PyAPI()

    client_root = Path(__file__).resolve().parents[1]   # .../client
    ui_file = client_root / "ui" / "index.html"

    if not ui_file.exists():
        raise FileNotFoundError(f"UI file not found: {ui_file}")

    webview.create_window(
        "P2 Chat",
        str(ui_file),
        js_api=api,
        width=900,
        height=700,
    )
    webview.start()


if __name__ == "__main__":
    main()
