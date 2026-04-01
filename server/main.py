"""Encrypted clipboard relay server.

Stateless message routing with WebSocket push and HTTP polling fallback.
Zero-knowledge: only routes encrypted blobs, never reads content.
WebSocket connections are authenticated via X25519 challenge-response.
"""

import asyncio
import hashlib
import hmac as hmac_mod
import os
import time
from base64 import b64decode, b64encode
from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from pydantic import BaseModel

# --- Configuration ---

MESSAGE_TTL = 86400  # 24 hours
MAX_QUEUE_SIZE = 100  # per recipient
MAX_MESSAGE_SIZE = 1_048_576  # 1 MB
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 60  # messages per window per sender
EVICTION_INTERVAL = 300  # run TTL eviction every 5 minutes
AUTH_TIMEOUT = 10  # seconds to complete challenge-response


# --- Data structures ---


@dataclass
class QueuedMessage:
    from_id: str
    payload: str
    timestamp: float


@dataclass
class RateBucket:
    count: int = 0
    window_start: float = 0.0


@dataclass
class RelayState:
    # user_id -> list of queued messages
    queues: dict[str, list[QueuedMessage]] = field(default_factory=lambda: defaultdict(list))
    # user_id -> set of active WebSocket connections
    connections: dict[str, set[WebSocket]] = field(default_factory=lambda: defaultdict(set))
    # sender_id -> rate limit bucket
    rate_limits: dict[str, RateBucket] = field(default_factory=dict)


state = RelayState()


# --- Auth helpers ---


def user_id_from_public_key(public_key_bytes: bytes) -> str:
    """Derive user ID from public key, matching the Rust plugin's logic."""
    h = hashlib.sha256(public_key_bytes).digest()
    return h[:8].hex()


def verify_auth(
    user_id: str,
    client_public_key_b64: str,
    client_hmac_hex: str,
    server_private_key: X25519PrivateKey,
    nonce: bytes,
) -> bool:
    """Verify the client's challenge-response auth."""
    try:
        client_pk_bytes = b64decode(client_public_key_b64)
        if len(client_pk_bytes) != 32:
            return False

        # Verify user_id matches the public key
        if user_id_from_public_key(client_pk_bytes) != user_id:
            return False

        # ECDH to get shared secret
        client_pk = X25519PublicKey.from_public_bytes(client_pk_bytes)
        shared_secret = server_private_key.exchange(client_pk)

        # Verify HMAC-SHA256(shared_secret, nonce)
        expected = hmac_mod.new(shared_secret, nonce, hashlib.sha256).hexdigest()
        return hmac_mod.compare_digest(expected, client_hmac_hex)
    except Exception:
        return False


# --- Rate limiting ---


def check_rate_limit(sender_id: str) -> bool:
    """Returns True if the sender is within rate limits, False if exceeded."""
    now = time.time()
    bucket = state.rate_limits.get(sender_id)

    if bucket is None or now - bucket.window_start >= RATE_LIMIT_WINDOW:
        state.rate_limits[sender_id] = RateBucket(count=1, window_start=now)
        return True

    if bucket.count >= RATE_LIMIT_MAX:
        return False

    bucket.count += 1
    return True


# --- TTL eviction ---


def evict_expired():
    """Remove messages older than MESSAGE_TTL."""
    now = time.time()
    empty_keys = []
    for user_id, messages in state.queues.items():
        state.queues[user_id] = [m for m in messages if now - m.timestamp < MESSAGE_TTL]
        if not state.queues[user_id]:
            empty_keys.append(user_id)
    for key in empty_keys:
        del state.queues[key]


async def eviction_loop():
    """Background task that periodically evicts expired messages."""
    while True:
        await asyncio.sleep(EVICTION_INTERVAL)
        evict_expired()


# --- App lifecycle ---


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(eviction_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="clipygo-relay", lifespan=lifespan)


# --- Models ---


class SendRequest(BaseModel):
    to: str
    from_id: str  # using from_id since "from" is a Python keyword
    payload: str


# --- REST endpoints ---


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/send")
async def send_message(body: SendRequest, request: Request):
    if len(body.payload) > MAX_MESSAGE_SIZE:
        raise HTTPException(status_code=413, detail="Payload too large")

    if not check_rate_limit(body.from_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    msg = QueuedMessage(
        from_id=body.from_id,
        payload=body.payload,
        timestamp=time.time(),
    )

    # If recipient has active WebSocket connections, push immediately
    ws_connections = state.connections.get(body.to, set())
    if ws_connections:
        data = {
            "from": msg.from_id,
            "payload": msg.payload,
            "timestamp": msg.timestamp,
        }
        dead = set()
        for ws in ws_connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.add(ws)
        for ws in dead:
            ws_connections.discard(ws)
        return {"status": "delivered"}

    # Otherwise queue it
    queue = state.queues[body.to]
    if len(queue) >= MAX_QUEUE_SIZE:
        queue.pop(0)  # evict oldest
    queue.append(msg)
    return {"status": "queued"}


@app.get("/poll/{user_id}")
async def poll(user_id: str):
    messages = state.queues.pop(user_id, [])
    return [
        {
            "from": m.from_id,
            "payload": m.payload,
            "timestamp": m.timestamp,
        }
        for m in messages
    ]


# --- WebSocket ---


@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    await websocket.accept()

    # --- Challenge-response authentication ---
    server_private = X25519PrivateKey.generate()
    server_public_bytes = server_private.public_key().public_bytes_raw()
    nonce = os.urandom(32)

    await websocket.send_json({
        "type": "challenge",
        "server_public_key": b64encode(server_public_bytes).decode(),
        "nonce": nonce.hex(),
    })

    try:
        auth_msg = await asyncio.wait_for(
            websocket.receive_json(), timeout=AUTH_TIMEOUT
        )
    except (asyncio.TimeoutError, WebSocketDisconnect):
        await websocket.close(code=4001, reason="Auth timeout")
        return

    if (
        not isinstance(auth_msg, dict)
        or auth_msg.get("type") != "auth"
        or not auth_msg.get("public_key")
        or not auth_msg.get("hmac")
    ):
        await websocket.close(code=4002, reason="Invalid auth message")
        return

    if not verify_auth(
        user_id, auth_msg["public_key"], auth_msg["hmac"], server_private, nonce
    ):
        await websocket.close(code=4003, reason="Auth failed")
        return

    # --- Authenticated ---
    state.connections[user_id].add(websocket)

    # Flush pending messages
    pending = state.queues.pop(user_id, [])
    for msg in pending:
        await websocket.send_json({
            "from": msg.from_id,
            "payload": msg.payload,
            "timestamp": msg.timestamp,
        })

    try:
        while True:
            # Keep connection alive; ignore client messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        state.connections[user_id].discard(websocket)
        if not state.connections[user_id]:
            del state.connections[user_id]


# --- Entry point ---

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
