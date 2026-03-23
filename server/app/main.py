import sys
import time
from pathlib import Path

# Ensure the server root is on sys.path so relative imports work in all
# execution contexts (direct run, uvicorn --reload subprocess, etc.)
_server_root = str(Path(__file__).resolve().parents[1])
if _server_root not in sys.path:
    sys.path.insert(0, _server_root)

from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .db import SessionLocal, engine
from .models import MessageQueue, KeyBundle, OneTimePrekey, Base
from .schemas import EnvelopeIn, EnvelopeOut, SendResponse, KeyBundleIn, KeyBundleOut, OpkEntry

app = FastAPI(title="P2 Relay Server (MVP)")

# Create tables automatically for MVP (later move to Alembic migrations)
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/v1/messages", response_model=SendResponse)
def post_message(env: EnvelopeIn, db: Session = Depends(get_db)):
    row = MessageQueue(
        msg_id=env.msg_id,
        client_msg_id=env.client_msg_id,
        from_device_id=env.from_device_id,
        to_device_id=env.to_device_id,
        type=env.type,
        header_b64=env.header_b64,
        ciphertext_b64=env.ciphertext_b64,
        created_at_ms=env.created_at_ms,
        ttl_seconds=env.ttl_seconds,
        group_id=env.group_id,
        group_meta=env.group_meta,
    )
    db.add(row)
    try:
        db.commit()
        return SendResponse(status="stored", msg_id=env.msg_id)
    except IntegrityError:
        # duplicate send (same from_device_id + client_msg_id)
        db.rollback()
        # fetch existing msg_id to return stable idempotent response
        stmt = select(MessageQueue.msg_id).where(
            MessageQueue.from_device_id == env.from_device_id,
            MessageQueue.client_msg_id == env.client_msg_id,
        )
        existing = db.execute(stmt).scalar_one_or_none()
        return SendResponse(status="duplicate", msg_id=existing or env.msg_id)

@app.get("/v1/messages/poll", response_model=list[EnvelopeOut])
def poll(device_id: str, limit: int = 50, db: Session = Depends(get_db)):
    stmt = (
        select(MessageQueue)
        .where(MessageQueue.to_device_id == device_id)
        .order_by(MessageQueue.created_at_ms.asc())
        .limit(limit)
    )
    rows = db.execute(stmt).scalars().all()
    return [
        EnvelopeOut(
            msg_id=str(r.msg_id),
            client_msg_id=str(r.client_msg_id),
            from_device_id=r.from_device_id,
            to_device_id=r.to_device_id,
            type=r.type,
            header_b64=r.header_b64,
            ciphertext_b64=r.ciphertext_b64,
            created_at_ms=r.created_at_ms,
            ttl_seconds=r.ttl_seconds,
            group_id=r.group_id,
            group_meta=r.group_meta,
        )
        for r in rows
    ]

@app.post("/v1/keys/{device_id}", status_code=200)
def upload_keys(device_id: str, bundle: KeyBundleIn, db: Session = Depends(get_db)):
    """
    Register or update a device's public key bundle.
    Upserts the KeyBundle row and bulk-inserts any new OPKs (skips duplicates).
    """
    now_ms = int(time.time() * 1000)

    existing = db.get(KeyBundle, device_id)
    if existing is None:
        db.add(KeyBundle(
            device_id=device_id,
            ik_sign_pub=bundle.ik_sign_pub,
            ik_dh_pub=bundle.ik_dh_pub,
            spk_id=bundle.spk_id,
            spk_pub=bundle.spk_pub,
            spk_sig=bundle.spk_sig,
            pqspk_id=bundle.pqspk_id,
            pqspk_pub=bundle.pqspk_pub,
            pqspk_sig=bundle.pqspk_sig,
            updated_at_ms=now_ms,
        ))
    else:
        existing.ik_sign_pub = bundle.ik_sign_pub
        existing.ik_dh_pub = bundle.ik_dh_pub
        existing.spk_id = bundle.spk_id
        existing.spk_pub = bundle.spk_pub
        existing.spk_sig = bundle.spk_sig
        existing.pqspk_id = bundle.pqspk_id
        existing.pqspk_pub = bundle.pqspk_pub
        existing.pqspk_sig = bundle.pqspk_sig
        existing.updated_at_ms = now_ms

    for opk_entry in bundle.opk_pubs:
        # Skip if this OPK id already exists (idempotent upload)
        if db.get(OneTimePrekey, opk_entry.opk_id) is None:
            db.add(OneTimePrekey(
                opk_id=opk_entry.opk_id,
                device_id=device_id,
                opk_pub=opk_entry.opk_pub,
            ))

    db.commit()
    return {"ok": True}


@app.get("/v1/keys/{device_id}", response_model=KeyBundleOut)
def fetch_keys(device_id: str, db: Session = Depends(get_db)):
    """
    Fetch a device's public key bundle.
    Atomically pops one OPK (if any remain) and returns it alongside the bundle.
    """
    kb = db.get(KeyBundle, device_id)
    if kb is None:
        raise HTTPException(status_code=404, detail="Device not registered")

    # Atomically pop one OPK
    stmt = (
        select(OneTimePrekey)
        .where(OneTimePrekey.device_id == device_id)
        .limit(1)
    )
    opk_row = db.execute(stmt).scalar_one_or_none()
    opk: OpkEntry | None = None
    if opk_row is not None:
        opk = OpkEntry(opk_id=opk_row.opk_id, opk_pub=opk_row.opk_pub)
        db.delete(opk_row)
        db.commit()

    return KeyBundleOut(
        device_id=device_id,
        ik_sign_pub=kb.ik_sign_pub,
        ik_dh_pub=kb.ik_dh_pub,
        spk_id=kb.spk_id,
        spk_pub=kb.spk_pub,
        spk_sig=kb.spk_sig,
        pqspk_id=kb.pqspk_id,
        pqspk_pub=kb.pqspk_pub,
        pqspk_sig=kb.pqspk_sig,
        opk=opk,
    )


@app.post("/v1/messages/{msg_id}/ack")
def ack(msg_id: str, db: Session = Depends(get_db)):
    stmt = select(MessageQueue).where(MessageQueue.msg_id == msg_id)
    row = db.execute(stmt).scalar_one_or_none()
    if row is None:
        # idempotent ack
        return {"ok": True, "deleted": False}
    db.delete(row)
    db.commit()
    return {"ok": True, "deleted": True}