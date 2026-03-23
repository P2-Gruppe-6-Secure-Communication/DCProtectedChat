import asyncio
import hashlib
import secrets
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Header, WebSocket, WebSocketDisconnect, Query
from sqlalchemy.orm import Session
from sqlalchemy import select, delete, func
from sqlalchemy.exc import IntegrityError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request

# Ensure the server root is on sys.path so relative imports work in all
# execution contexts (direct run, uvicorn --reload subprocess, etc.)
_server_root = str(Path(__file__).resolve().parents[1])
if _server_root not in sys.path:
    sys.path.insert(0, _server_root)

from .db import SessionLocal, engine
from .models import MessageQueue, KeyBundle, OneTimePrekey, Base
from .schemas import EnvelopeIn, EnvelopeOut, SendResponse, KeyBundleIn, KeyBundleOut, OpkEntry


# ── WebSocket connection manager ──────────────────────────────────────────────

class ConnectionManager:
    """In-memory WebSocket registry. Works for a single-process deployment."""

    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}

    async def connect(self, device_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._connections[device_id] = ws

    def disconnect(self, device_id: str) -> None:
        self._connections.pop(device_id, None)

    async def push(self, device_id: str, payload: dict) -> None:
        ws = self._connections.get(device_id)
        if ws:
            try:
                await ws.send_json(payload)
            except Exception:
                self.disconnect(device_id)


manager = ConnectionManager()


# ── TTL expiry background task ────────────────────────────────────────────────

async def _expire_messages_loop() -> None:
    while True:
        await asyncio.sleep(3600)  # run hourly
        with SessionLocal() as db:
            now_ms = int(time.time() * 1000)
            db.execute(
                delete(MessageQueue).where(
                    (MessageQueue.created_at_ms + MessageQueue.ttl_seconds * 1000) < now_ms
                )
            )
            db.commit()


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables (idempotent — production uses Alembic upgrade head)
    Base.metadata.create_all(bind=engine)
    task = asyncio.create_task(_expire_messages_loop())
    yield
    task.cancel()


# ── App & rate limiter ────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="P2 Relay Server", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── DB dependency ─────────────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _verify_device_auth(
    device_id: str,
    authorization: Optional[str],
    db: Session,
) -> None:
    """Raise HTTP 403 if the Bearer token does not match the stored hash."""
    kb = db.get(KeyBundle, device_id)
    if kb is None:
        raise HTTPException(status_code=403, detail="Device not found")
    if not kb.device_secret_hash:
        # Device registered without a secret (legacy/dev) — pass through
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=403, detail="Missing authorization")
    token = authorization[len("Bearer "):]
    if not secrets.compare_digest(_hash_secret(token), kb.device_secret_hash):
        raise HTTPException(status_code=403, detail="Invalid token")


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"ok": True}


# ── Messages ──────────────────────────────────────────────────────────────────

@app.post("/v1/messages", response_model=SendResponse)
@limiter.limit("60/minute")
async def post_message(
    request: Request,
    env: EnvelopeIn,
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    _verify_device_auth(env.from_device_id, authorization, db)

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
    except IntegrityError:
        db.rollback()
        stmt = select(MessageQueue.msg_id).where(
            MessageQueue.from_device_id == env.from_device_id,
            MessageQueue.client_msg_id == env.client_msg_id,
        )
        existing = db.execute(stmt).scalar_one_or_none()
        return SendResponse(status="duplicate", msg_id=existing or env.msg_id)

    # Push to recipient's WebSocket connection if they're online
    envelope_dict = {
        "msg_id": str(row.msg_id),
        "client_msg_id": str(row.client_msg_id),
        "from_device_id": row.from_device_id,
        "to_device_id": row.to_device_id,
        "type": row.type,
        "header_b64": row.header_b64,
        "ciphertext_b64": row.ciphertext_b64,
        "created_at_ms": row.created_at_ms,
        "ttl_seconds": row.ttl_seconds,
        "group_id": row.group_id,
        "group_meta": row.group_meta,
    }
    await manager.push(env.to_device_id, envelope_dict)

    return SendResponse(status="stored", msg_id=env.msg_id)


@app.get("/v1/messages/poll", response_model=list[EnvelopeOut])
@limiter.limit("120/minute")
def poll(
    request: Request,
    device_id: str,
    limit: int = Query(50, ge=1, le=200),
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    _verify_device_auth(device_id, authorization, db)
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


@app.post("/v1/messages/{msg_id}/ack")
@limiter.limit("120/minute")
def ack(
    request: Request,
    msg_id: str,
    device_id: str,
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    # Verify auth before touching the DB to avoid leaking message existence
    _verify_device_auth(device_id, authorization, db)
    stmt = select(MessageQueue).where(
        MessageQueue.msg_id == msg_id,
        MessageQueue.to_device_id == device_id,
    )
    row = db.execute(stmt).scalar_one_or_none()
    if row is None:
        return {"ok": True, "deleted": False}
    db.delete(row)
    db.commit()
    return {"ok": True, "deleted": True}


# ── Keys ──────────────────────────────────────────────────────────────────────

@app.post("/v1/keys/{device_id}", status_code=200)
@limiter.limit("10/minute")
def upload_keys(
    request: Request,
    device_id: str,
    bundle: KeyBundleIn,
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    """
    Register or update a device's public key bundle.
    New registrations: store device_secret hash.
    Updates: require valid Authorization Bearer token.
    """
    now_ms = int(time.time() * 1000)
    existing = db.get(KeyBundle, device_id)

    if existing is not None:
        # Device already registered — prove ownership before updating
        _verify_device_auth(device_id, authorization, db)
        existing.ik_sign_pub = bundle.ik_sign_pub
        existing.ik_dh_pub = bundle.ik_dh_pub
        existing.spk_id = bundle.spk_id
        existing.spk_pub = bundle.spk_pub
        existing.spk_sig = bundle.spk_sig
        existing.pqspk_id = bundle.pqspk_id
        existing.pqspk_pub = bundle.pqspk_pub
        existing.pqspk_sig = bundle.pqspk_sig
        existing.updated_at_ms = now_ms
    else:
        secret_hash = _hash_secret(bundle.device_secret) if bundle.device_secret else None
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
            device_secret_hash=secret_hash,
            updated_at_ms=now_ms,
        ))

    for opk_entry in bundle.opk_pubs:
        if db.get(OneTimePrekey, opk_entry.opk_id) is None:
            db.add(OneTimePrekey(
                opk_id=opk_entry.opk_id,
                device_id=device_id,
                opk_pub=opk_entry.opk_pub,
            ))

    db.commit()
    return {"ok": True}


@app.get("/v1/keys/{device_id}", response_model=KeyBundleOut)
@limiter.limit("60/minute")
def fetch_keys(request: Request, device_id: str, db: Session = Depends(get_db)):
    """
    Fetch a device's public key bundle (public endpoint — needed for X3DH).
    Atomically pops one OPK (if any remain) and returns it alongside the bundle.
    """
    kb = db.get(KeyBundle, device_id)
    if kb is None:
        raise HTTPException(status_code=404, detail="Device not registered")

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


@app.get("/v1/keys/{device_id}/opk-count")
@limiter.limit("30/minute")
def opk_count(
    request: Request,
    device_id: str,
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    """Return the number of OPKs remaining for a device (for client replenishment logic)."""
    _verify_device_auth(device_id, authorization, db)
    count = db.execute(
        select(func.count()).select_from(OneTimePrekey).where(OneTimePrekey.device_id == device_id)
    ).scalar_one()
    return {"count": count}


# ── WebSocket ──────────────────────────────────────────────────────────────────

@app.websocket("/v1/ws/{device_id}")
async def websocket_endpoint(
    device_id: str,
    ws: WebSocket,
    token: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """
    Real-time push channel. Client authenticates via ?token=<device_secret>.
    On connect: flushes any queued messages.
    Receives {"type": "ack", "msg_id": "..."} to delete delivered messages.
    """
    kb = db.get(KeyBundle, device_id)
    if kb is None:
        await ws.close(code=4403)
        return
    if kb.device_secret_hash:
        if not token or not secrets.compare_digest(_hash_secret(token), kb.device_secret_hash):
            await ws.close(code=4403)
            return

    await manager.connect(device_id, ws)

    # Flush any already-queued messages immediately on connect
    stmt = (
        select(MessageQueue)
        .where(MessageQueue.to_device_id == device_id)
        .order_by(MessageQueue.created_at_ms.asc())
        .limit(50)
    )
    rows = db.execute(stmt).scalars().all()
    for r in rows:
        try:
            await ws.send_json({
                "msg_id": str(r.msg_id),
                "client_msg_id": str(r.client_msg_id),
                "from_device_id": r.from_device_id,
                "to_device_id": r.to_device_id,
                "type": r.type,
                "header_b64": r.header_b64,
                "ciphertext_b64": r.ciphertext_b64,
                "created_at_ms": r.created_at_ms,
                "ttl_seconds": r.ttl_seconds,
                "group_id": r.group_id,
                "group_meta": r.group_meta,
            })
        except Exception:
            break

    try:
        while True:
            data = await ws.receive_json()
            if data.get("type") == "ack" and "msg_id" in data:
                stmt = select(MessageQueue).where(
                    MessageQueue.msg_id == data["msg_id"],
                    MessageQueue.to_device_id == device_id,
                )
                row = db.execute(stmt).scalar_one_or_none()
                if row:
                    db.delete(row)
                    db.commit()
    except WebSocketDisconnect:
        manager.disconnect(device_id)
    except Exception:
        manager.disconnect(device_id)
