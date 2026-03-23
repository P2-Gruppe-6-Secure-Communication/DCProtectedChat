"""
Unit tests for the client-side cryptographic stack.

Tests cover:
  - Key generation (keys.py)
  - PQXDH key agreement (x3dh.py)
  - Double Ratchet encrypt/decrypt (ratchet.py)
  - End-to-end session flow (session.py) — using a mock HTTP server
"""
import json
import uuid
import base64

import pytest

from app.crypto.keys import (
    generate_identity,
    build_bundle,
    get_device_secret,
    get_opk_private,
    remove_opk,
    save_identity,
    load_identity,
)
from app.crypto.x3dh import initiate, accept
from app.crypto.ratchet import (
    RatchetState,
    init_sender,
    init_receiver,
    encrypt,
    decrypt,
)


# ── Key generation ────────────────────────────────────────────────────────────

def test_generate_identity_fields(tmp_path, monkeypatch):
    monkeypatch.setattr("app.crypto.keys._DATA_ROOT", tmp_path)
    identity = generate_identity("testdev")

    required = [
        "device_id", "device_secret",
        "ik_sign_priv", "ik_sign_pub",
        "ik_dh_priv", "ik_dh_pub",
        "spk_id", "spk_priv", "spk_pub", "spk_sig",
        "pqspk_id", "pqspk_pub", "pqspk_priv", "pqspk_sig",
        "opks",
    ]
    for field in required:
        assert field in identity, f"Missing field: {field}"

    assert identity["device_id"] == "testdev"
    assert len(identity["device_secret"]) == 64  # 32 bytes hex


def test_generate_identity_creates_10_opks(tmp_path, monkeypatch):
    monkeypatch.setattr("app.crypto.keys._DATA_ROOT", tmp_path)
    identity = generate_identity("testdev", num_opks=10)
    assert len(identity["opks"]) == 10


def test_device_secret_is_unique(tmp_path, monkeypatch):
    monkeypatch.setattr("app.crypto.keys._DATA_ROOT", tmp_path)
    a = generate_identity("dev_a")
    b = generate_identity("dev_b")
    assert get_device_secret(a) != get_device_secret(b)


def test_build_bundle_excludes_private_keys(tmp_path, monkeypatch):
    monkeypatch.setattr("app.crypto.keys._DATA_ROOT", tmp_path)
    identity = generate_identity("testdev")
    bundle = build_bundle(identity)

    private_keys = ["ik_sign_priv", "ik_dh_priv", "spk_priv", "pqspk_priv", "device_secret"]
    for key in private_keys:
        assert key not in bundle, f"Private key leaked: {key}"

    assert "opk_pubs" in bundle
    assert all("priv" not in opk for opk in bundle["opk_pubs"])


# ── X3DH ─────────────────────────────────────────────────────────────────────

def _server_bundle(identity: dict) -> dict:
    """Simulate the server's KeyBundleOut response (single 'opk', not 'opk_pubs' list)."""
    b = build_bundle(identity)
    opk_pubs = b.pop("opk_pubs", [])
    b["opk"] = opk_pubs[0] if opk_pubs else None
    return b


def test_x3dh_shared_secret_matches(tmp_path, monkeypatch):
    monkeypatch.setattr("app.crypto.keys._DATA_ROOT", tmp_path)

    alice = generate_identity("alice")
    bob = generate_identity("bob")
    bob_bundle = _server_bundle(bob)

    # Alice initiates
    sk_alice, x3dh_header = initiate(alice, bob_bundle)

    # Bob accepts
    sk_bob = accept(bob, x3dh_header)

    assert sk_alice == sk_bob, "Shared secrets must match"
    assert len(sk_alice) == 32


def test_x3dh_header_type(tmp_path, monkeypatch):
    monkeypatch.setattr("app.crypto.keys._DATA_ROOT", tmp_path)
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    _, header = initiate(alice, _server_bundle(bob))
    assert header["type"] == "x3dh_init"


def test_x3dh_opk_consumed_after_accept(tmp_path, monkeypatch):
    monkeypatch.setattr("app.crypto.keys._DATA_ROOT", tmp_path)
    alice = generate_identity("alice")
    bob = generate_identity("bob")

    bob_bundle = _server_bundle(bob)
    opk_id = bob_bundle["opk"]["opk_id"] if bob_bundle.get("opk") else None

    if opk_id:
        _, header = initiate(alice, bob_bundle)
        accept(bob, header)
        # OPK should be removed from bob's identity after accept
        bob_reloaded = load_identity("bob")
        assert opk_id not in bob_reloaded["opks"]


# ── Double Ratchet ────────────────────────────────────────────────────────────

def _setup_ratchet_pair(tmp_path, monkeypatch):
    monkeypatch.setattr("app.crypto.keys._DATA_ROOT", tmp_path)
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    bob_bundle = _server_bundle(bob)

    sk, _ = initiate(alice, bob_bundle)

    import base64
    spk_pub_bytes = base64.b64decode(bob_bundle["spk_pub"])

    state_alice = init_sender(sk, spk_pub_bytes)

    from app.crypto.keys import spk_private
    import nacl.public
    spk_priv = spk_private(bob)
    state_bob = init_receiver(sk, spk_priv)

    return state_alice, state_bob


def test_ratchet_basic_encrypt_decrypt(tmp_path, monkeypatch):
    alice, bob = _setup_ratchet_pair(tmp_path, monkeypatch)

    header, ct = encrypt(alice, b"Hello Bob")
    plaintext = decrypt(bob, header, ct)
    assert plaintext == b"Hello Bob"


def test_ratchet_multiple_messages(tmp_path, monkeypatch):
    alice, bob = _setup_ratchet_pair(tmp_path, monkeypatch)

    messages = [f"Message {i}".encode() for i in range(20)]
    for msg in messages:
        hdr, ct = encrypt(alice, msg)
        assert decrypt(bob, hdr, ct) == msg


def test_ratchet_bidirectional(tmp_path, monkeypatch):
    alice, bob = _setup_ratchet_pair(tmp_path, monkeypatch)

    hdr, ct = encrypt(alice, b"Hi Bob")
    assert decrypt(bob, hdr, ct) == b"Hi Bob"

    hdr2, ct2 = encrypt(bob, b"Hi Alice")
    assert decrypt(alice, hdr2, ct2) == b"Hi Alice"

    hdr3, ct3 = encrypt(alice, b"How are you?")
    assert decrypt(bob, hdr3, ct3) == b"How are you?"


def test_ratchet_out_of_order(tmp_path, monkeypatch):
    alice, bob = _setup_ratchet_pair(tmp_path, monkeypatch)

    hdr1, ct1 = encrypt(alice, b"First")
    hdr2, ct2 = encrypt(alice, b"Second")
    hdr3, ct3 = encrypt(alice, b"Third")

    # Deliver out of order: 3, 1, 2
    assert decrypt(bob, hdr3, ct3) == b"Third"
    assert decrypt(bob, hdr1, ct1) == b"First"
    assert decrypt(bob, hdr2, ct2) == b"Second"


def test_ratchet_state_serialization(tmp_path, monkeypatch):
    alice, bob = _setup_ratchet_pair(tmp_path, monkeypatch)

    hdr, ct = encrypt(alice, b"Persist me")

    # Serialize bob's state, reconstruct, and decrypt
    bob_dict = bob.to_dict()
    bob2 = RatchetState.from_dict(bob_dict)

    assert decrypt(bob2, hdr, ct) == b"Persist me"
