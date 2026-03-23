"""
API integration tests for the P2 relay server.
All tests run against an in-memory SQLite DB (see conftest.py).
"""
import uuid


# ── Fixtures & helpers ────────────────────────────────────────────────────────

DEVICE_SECRET = "deadbeef" * 8  # 64-char hex


def _bundle(device_secret: str = DEVICE_SECRET) -> dict:
    """Minimal valid key bundle payload."""
    return {
        "ik_sign_pub": "aGVsbG8=",
        "ik_dh_pub": "aGVsbG8=",
        "spk_id": str(uuid.uuid4()),
        "spk_pub": "aGVsbG8=",
        "spk_sig": "aGVsbG8=",
        "pqspk_id": str(uuid.uuid4()),
        "pqspk_pub": "aGVsbG8=",
        "pqspk_sig": "aGVsbG8=",
        "opk_pubs": [{"opk_id": str(uuid.uuid4()), "opk_pub": "aGVsbG8="}],
        "device_secret": device_secret,
    }


def _register(client, device_id: str, secret: str = DEVICE_SECRET) -> None:
    r = client.post(f"/v1/keys/{device_id}", json=_bundle(secret))
    assert r.status_code == 200, r.text


def _auth(secret: str = DEVICE_SECRET) -> dict:
    return {"Authorization": f"Bearer {secret}"}


# ── Health ────────────────────────────────────────────────────────────────────

def test_health(client):
    assert client.get("/health").json() == {"ok": True}


# ── Registration ──────────────────────────────────────────────────────────────

def test_register_new_device(client):
    r = client.post("/v1/keys/alice", json=_bundle())
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_register_is_idempotent(client):
    _register(client, "alice")
    # Second call with valid auth should succeed (upsert)
    r = client.post("/v1/keys/alice", json=_bundle(), headers=_auth())
    assert r.status_code == 200


def test_register_update_wrong_token(client):
    _register(client, "alice")
    r = client.post("/v1/keys/alice", json=_bundle(), headers=_auth("wrongsecret" * 6))
    assert r.status_code == 403


# ── Key fetch ─────────────────────────────────────────────────────────────────

def test_fetch_keys_returns_bundle_and_opk(client):
    _register(client, "alice")
    r = client.get("/v1/keys/alice")
    assert r.status_code == 200
    data = r.json()
    assert data["device_id"] == "alice"
    assert data["opk"] is not None  # one OPK was uploaded


def test_fetch_keys_opk_consumed(client):
    _register(client, "alice")
    r1 = client.get("/v1/keys/alice")
    assert r1.json()["opk"] is not None
    r2 = client.get("/v1/keys/alice")
    assert r2.json()["opk"] is None  # consumed on first fetch


def test_fetch_unknown_device(client):
    assert client.get("/v1/keys/nobody").status_code == 404


# ── OPK count ─────────────────────────────────────────────────────────────────

def test_opk_count(client):
    _register(client, "alice")
    r = client.get("/v1/keys/alice/opk-count", headers=_auth())
    assert r.status_code == 200
    assert r.json()["count"] == 1  # one OPK was uploaded


def test_opk_count_no_auth(client):
    _register(client, "alice")
    assert client.get("/v1/keys/alice/opk-count").status_code == 403


# ── Messages ──────────────────────────────────────────────────────────────────

def _msg(from_id: str, to_id: str) -> dict:
    return {
        "msg_id": str(uuid.uuid4()),
        "client_msg_id": str(uuid.uuid4()),
        "from_device_id": from_id,
        "to_device_id": to_id,
        "type": "direct",
        "header_b64": "aGVsbG8=",
        "ciphertext_b64": "aGVsbG8=",
        "created_at_ms": 1_000_000,
        "ttl_seconds": 604800,
    }


def test_send_and_poll(client):
    _register(client, "alice")
    _register(client, "bob")

    payload = _msg("alice", "bob")
    r = client.post("/v1/messages", json=payload, headers=_auth())
    assert r.status_code == 200
    assert r.json()["status"] == "stored"

    r = client.get("/v1/messages/poll", params={"device_id": "bob"}, headers=_auth())
    assert r.status_code == 200
    msgs = r.json()
    assert len(msgs) == 1
    assert msgs[0]["from_device_id"] == "alice"


def test_poll_no_auth(client):
    _register(client, "bob")
    assert client.get("/v1/messages/poll", params={"device_id": "bob"}).status_code == 403


def test_poll_limit_clamped(client):
    _register(client, "bob")
    # limit > 200 should be rejected with 422
    r = client.get(
        "/v1/messages/poll",
        params={"device_id": "bob", "limit": 999999},
        headers=_auth(),
    )
    assert r.status_code == 422


def test_send_no_auth(client):
    _register(client, "alice")
    _register(client, "bob")
    assert client.post("/v1/messages", json=_msg("alice", "bob")).status_code == 403


def test_send_wrong_sender_token(client):
    _register(client, "alice")
    _register(client, "bob")
    # Try sending as alice but using bob's token
    r = client.post("/v1/messages", json=_msg("alice", "bob"), headers=_auth("wrongtoken" * 7))
    assert r.status_code == 403


def test_idempotent_send(client):
    _register(client, "alice")
    _register(client, "bob")

    payload = _msg("alice", "bob")
    r1 = client.post("/v1/messages", json=payload, headers=_auth())
    assert r1.json()["status"] == "stored"

    r2 = client.post("/v1/messages", json=payload, headers=_auth())
    assert r2.json()["status"] == "duplicate"


def test_ack_deletes_message(client):
    _register(client, "alice")
    _register(client, "bob")

    payload = _msg("alice", "bob")
    client.post("/v1/messages", json=payload, headers=_auth())

    msg_id = payload["msg_id"]
    # Bob acknowledges — must pass device_id=bob and bob's token
    r = client.post(
        f"/v1/messages/{msg_id}/ack",
        params={"device_id": "bob"},
        headers=_auth(),
    )
    assert r.status_code == 200
    assert r.json()["deleted"] is True

    # Poll should now be empty
    msgs = client.get("/v1/messages/poll", params={"device_id": "bob"}, headers=_auth()).json()
    assert len(msgs) == 0


def test_ack_idempotent(client):
    _register(client, "alice")
    # ACK a message that doesn't exist — should return 200 with deleted=False
    r = client.post(
        f"/v1/messages/{str(uuid.uuid4())}/ack",
        params={"device_id": "alice"},
        headers=_auth(),
    )
    assert r.status_code == 200
    assert r.json()["deleted"] is False


def test_ack_requires_device_id(client):
    # Missing device_id query param → 422 Unprocessable Entity
    r = client.post(f"/v1/messages/{str(uuid.uuid4())}/ack", headers=_auth())
    assert r.status_code == 422


def test_ack_no_auth(client):
    _register(client, "alice")
    # Valid device_id but no auth token → 403
    r = client.post(
        f"/v1/messages/{str(uuid.uuid4())}/ack",
        params={"device_id": "alice"},
    )
    assert r.status_code == 403


def test_ack_wrong_recipient_cannot_delete(client):
    _register(client, "alice")
    _register(client, "bob")

    payload = _msg("alice", "bob")
    client.post("/v1/messages", json=payload, headers=_auth())

    msg_id = payload["msg_id"]
    # Alice tries to ack a message addressed to bob — should return deleted=False
    r = client.post(
        f"/v1/messages/{msg_id}/ack",
        params={"device_id": "alice"},
        headers=_auth(),
    )
    assert r.status_code == 200
    assert r.json()["deleted"] is False  # alice can't delete bob's message


# ── Payload size limits ───────────────────────────────────────────────────────

def test_oversized_ciphertext_rejected(client):
    _register(client, "alice")
    _register(client, "bob")
    payload = _msg("alice", "bob")
    payload["ciphertext_b64"] = "A" * 200_000  # way over 131_072
    r = client.post("/v1/messages", json=payload, headers=_auth())
    assert r.status_code == 422
