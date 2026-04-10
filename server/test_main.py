"""Tests for the relay server."""

import hashlib
import hmac as hmac_mod
import time
from base64 import b64decode, b64encode

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from main import (
    app,
    state,
    QueuedMessage,
    RateBucket,
    check_rate_limit,
    evict_expired,
    user_id_from_public_key,
    verify_auth,
    MESSAGE_TTL,
    MAX_QUEUE_SIZE,
    RATE_LIMIT_MAX,
    RATE_LIMIT_WINDOW,
    MAX_MESSAGE_SIZE,
)


@pytest.fixture(autouse=True)
def reset_state():
    """Clear all server state between tests."""
    state.queues.clear()
    state.connections.clear()
    state.rate_limits.clear()
    yield


@pytest.fixture
def client():
    return TestClient(app)


def make_keypair():
    """Generate a client X25519 keypair and user_id."""
    private = X25519PrivateKey.generate()
    public_bytes = private.public_key().public_bytes_raw()
    uid = user_id_from_public_key(public_bytes)
    return private, public_bytes, uid


def do_ws_auth(ws, client_private, client_public_bytes):
    """Perform the challenge-response handshake on an open WebSocket."""
    challenge = ws.receive_json()
    assert challenge["type"] == "challenge"

    server_pk_bytes = b64decode(challenge["server_public_key"])
    nonce = bytes.fromhex(challenge["nonce"])

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    server_pk = X25519PublicKey.from_public_bytes(server_pk_bytes)
    shared_secret = client_private.exchange(server_pk)

    mac = hmac_mod.new(shared_secret, nonce, hashlib.sha256).hexdigest()

    ws.send_json({
        "type": "auth",
        "public_key": b64encode(client_public_bytes).decode(),
        "hmac": mac,
    })


# --- Health ---


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


# --- POST /send ---


def test_send_queues_message(client):
    r = client.post("/send", json={"to": "alice", "from_id": "bob", "payload": "encrypted_blob"})
    assert r.status_code == 200
    assert r.json()["status"] == "queued"
    assert len(state.queues["alice"]) == 1
    assert state.queues["alice"][0].from_id == "bob"
    assert state.queues["alice"][0].payload == "encrypted_blob"


def test_send_payload_too_large(client):
    payload = "x" * (MAX_MESSAGE_SIZE + 1)
    r = client.post("/send", json={"to": "alice", "from_id": "bob", "payload": payload})
    assert r.status_code == 413


def test_send_rate_limited(client):
    # Exhaust rate limit
    for _ in range(RATE_LIMIT_MAX):
        r = client.post("/send", json={"to": "alice", "from_id": "bob", "payload": "blob"})
        assert r.status_code == 200

    # Next request should be rate limited
    r = client.post("/send", json={"to": "alice", "from_id": "bob", "payload": "blob"})
    assert r.status_code == 429


def test_send_evicts_oldest_when_queue_full(client):
    # Fill the queue
    for i in range(MAX_QUEUE_SIZE):
        state.queues["alice"].append(
            QueuedMessage(from_id="bob", payload=f"msg-{i}", timestamp=time.time())
        )

    # Send one more
    r = client.post("/send", json={"to": "alice", "from_id": "bob", "payload": "overflow"})
    assert r.status_code == 200
    assert len(state.queues["alice"]) == MAX_QUEUE_SIZE
    # Oldest (msg-0) should be evicted, newest should be "overflow"
    assert state.queues["alice"][-1].payload == "overflow"
    assert state.queues["alice"][0].payload == "msg-1"


# --- GET /poll ---


def test_poll_returns_pending_messages(client):
    state.queues["alice"] = [
        QueuedMessage(from_id="bob", payload="msg1", timestamp=1000.0),
        QueuedMessage(from_id="carol", payload="msg2", timestamp=2000.0),
    ]
    r = client.get("/poll/alice")
    assert r.status_code == 200
    messages = r.json()
    assert len(messages) == 2
    assert messages[0]["from"] == "bob"
    assert messages[1]["from"] == "carol"
    # Queue should be cleared after poll
    assert "alice" not in state.queues


def test_poll_empty(client):
    r = client.get("/poll/unknown_user")
    assert r.status_code == 200
    assert r.json() == []


# --- WebSocket with auth ---


def test_websocket_auth_and_pending_flush(client):
    private, public_bytes, uid = make_keypair()

    state.queues[uid] = [
        QueuedMessage(from_id="bob", payload="queued_msg", timestamp=1000.0),
    ]

    with client.websocket_connect(f"/ws/{uid}") as ws:
        do_ws_auth(ws, private, public_bytes)

        # Should receive the pending message after auth
        data = ws.receive_json()
        assert data["from"] == "bob"
        assert data["payload"] == "queued_msg"

    # Queue should be drained
    assert uid not in state.queues


def test_websocket_live_delivery(client):
    private, public_bytes, uid = make_keypair()

    with client.websocket_connect(f"/ws/{uid}") as ws:
        do_ws_auth(ws, private, public_bytes)

        # Send a message while connected
        r = client.post(
            "/send", json={"to": uid, "from_id": "bob", "payload": "live_msg"}
        )
        assert r.status_code == 200
        assert r.json()["status"] == "delivered"

        data = ws.receive_json()
        assert data["from"] == "bob"
        assert data["payload"] == "live_msg"


def test_websocket_cleanup_on_disconnect(client):
    private, public_bytes, uid = make_keypair()

    with client.websocket_connect(f"/ws/{uid}") as ws:
        do_ws_auth(ws, private, public_bytes)
        # Server processes auth in a background thread; poll until registered
        deadline = time.monotonic() + 2.0
        while uid not in state.connections and time.monotonic() < deadline:
            time.sleep(0.01)
        assert uid in state.connections

    # After disconnect, connection should be cleaned up
    assert uid not in state.connections


def test_websocket_auth_wrong_key_rejected(client):
    """An attacker who doesn't hold the private key can't authenticate."""
    private, public_bytes, uid = make_keypair()

    # Attacker generates a different keypair
    attacker_private = X25519PrivateKey.generate()

    with client.websocket_connect(f"/ws/{uid}") as ws:
        challenge = ws.receive_json()
        assert challenge["type"] == "challenge"

        server_pk_bytes = b64decode(challenge["server_public_key"])
        nonce = bytes.fromhex(challenge["nonce"])

        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        server_pk = X25519PublicKey.from_public_bytes(server_pk_bytes)
        # Attacker uses their own private key — shared secret will differ
        shared_secret = attacker_private.exchange(server_pk)
        mac = hmac_mod.new(shared_secret, nonce, hashlib.sha256).hexdigest()

        # But claims to be the legitimate user by sending their public key
        ws.send_json({
            "type": "auth",
            "public_key": b64encode(public_bytes).decode(),
            "hmac": mac,
        })

        # Server should reject — connection closed
    assert uid not in state.connections


def test_websocket_auth_wrong_user_id_rejected(client):
    """User ID must match the public key."""
    private, public_bytes, uid = make_keypair()

    # Connect with a different user_id
    with client.websocket_connect("/ws/deadbeefdeadbeef") as ws:
        challenge = ws.receive_json()

        server_pk_bytes = b64decode(challenge["server_public_key"])
        nonce = bytes.fromhex(challenge["nonce"])

        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        server_pk = X25519PublicKey.from_public_bytes(server_pk_bytes)
        shared_secret = private.exchange(server_pk)
        mac = hmac_mod.new(shared_secret, nonce, hashlib.sha256).hexdigest()

        ws.send_json({
            "type": "auth",
            "public_key": b64encode(public_bytes).decode(),
            "hmac": mac,
        })

    # Should not be registered
    assert "deadbeefdeadbeef" not in state.connections


def test_websocket_auth_invalid_message_rejected(client):
    """Garbage auth messages should be rejected."""
    _, _, uid = make_keypair()

    with client.websocket_connect(f"/ws/{uid}") as ws:
        _ = ws.receive_json()  # challenge
        ws.send_json({"type": "auth"})  # missing fields

    assert uid not in state.connections


# --- Auth helpers ---


def test_user_id_from_public_key_matches_rust():
    """user_id derivation must match the Rust plugin."""
    # Known test vector: SHA256 of 32 zero bytes
    pk_bytes = bytes(32)
    uid = user_id_from_public_key(pk_bytes)
    expected = hashlib.sha256(pk_bytes).digest()[:8].hex()
    assert uid == expected
    assert len(uid) == 16


def test_verify_auth_valid():
    server_private = X25519PrivateKey.generate()
    client_private, client_public_bytes, uid = make_keypair()
    nonce = b"test_nonce_12345"

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    server_pk = server_private.public_key()
    shared = client_private.exchange(server_pk)
    mac = hmac_mod.new(shared, nonce, hashlib.sha256).hexdigest()

    assert verify_auth(uid, b64encode(client_public_bytes).decode(), mac, server_private, nonce)


def test_verify_auth_wrong_hmac():
    server_private = X25519PrivateKey.generate()
    _, client_public_bytes, uid = make_keypair()
    nonce = b"test_nonce_12345"

    assert not verify_auth(uid, b64encode(client_public_bytes).decode(), "badhex", server_private, nonce)


# --- Rate limiting ---


def test_rate_limit_resets_after_window():
    # Exhaust limit
    for _ in range(RATE_LIMIT_MAX):
        assert check_rate_limit("sender1")
    assert not check_rate_limit("sender1")

    # Simulate window expiry
    state.rate_limits["sender1"].window_start -= RATE_LIMIT_WINDOW + 1
    assert check_rate_limit("sender1")


def test_rate_limit_independent_per_sender():
    for _ in range(RATE_LIMIT_MAX):
        assert check_rate_limit("sender_a")
    assert not check_rate_limit("sender_a")
    # Different sender should be unaffected
    assert check_rate_limit("sender_b")


# --- TTL eviction ---


def test_evict_expired_removes_old_messages():
    state.queues["alice"] = [
        QueuedMessage(from_id="bob", payload="old", timestamp=time.time() - MESSAGE_TTL - 1),
        QueuedMessage(from_id="bob", payload="fresh", timestamp=time.time()),
    ]
    evict_expired()
    assert len(state.queues["alice"]) == 1
    assert state.queues["alice"][0].payload == "fresh"


def test_evict_expired_removes_empty_queues():
    state.queues["alice"] = [
        QueuedMessage(from_id="bob", payload="old", timestamp=time.time() - MESSAGE_TTL - 1),
    ]
    evict_expired()
    assert "alice" not in state.queues


def test_evict_expired_no_op_when_empty():
    evict_expired()
    assert len(state.queues) == 0


# --- E2E: REST send → WebSocket receive ---


def test_e2e_send_rest_receive_websocket(client):
    """Full flow: sender POSTs a message, recipient receives it over authenticated WebSocket."""
    private, public_bytes, uid = make_keypair()

    with client.websocket_connect(f"/ws/{uid}") as ws:
        do_ws_auth(ws, private, public_bytes)

        # Sender POSTs a message (simulating the encrypted blob)
        fake_payload = "base64-encrypted-blob-abc123"
        r = client.post(
            "/send", json={"to": uid, "from_id": "sender_xyz", "payload": fake_payload}
        )
        assert r.status_code == 200
        assert r.json()["status"] == "delivered"

        # Recipient receives it on the WebSocket
        data = ws.receive_json()
        assert data["from"] == "sender_xyz"
        assert data["payload"] == fake_payload
        assert "timestamp" in data


def test_e2e_offline_then_connect_receives_all(client):
    """Messages sent while offline are delivered when the recipient connects."""
    private, public_bytes, uid = make_keypair()

    # Send 3 messages while recipient is offline
    for i in range(3):
        r = client.post(
            "/send", json={"to": uid, "from_id": f"sender_{i}", "payload": f"msg_{i}"}
        )
        assert r.status_code == 200
        assert r.json()["status"] == "queued"

    # Recipient connects — all 3 should be flushed
    with client.websocket_connect(f"/ws/{uid}") as ws:
        do_ws_auth(ws, private, public_bytes)

        received = []
        for _ in range(3):
            received.append(ws.receive_json())

        assert [m["payload"] for m in received] == ["msg_0", "msg_1", "msg_2"]
        assert [m["from"] for m in received] == ["sender_0", "sender_1", "sender_2"]

    # Queue should be empty
    assert uid not in state.queues


def test_e2e_payload_integrity_preserved(client):
    """The relay preserves the exact payload bytes — critical for encrypted content."""
    private, public_bytes, uid = make_keypair()

    # Payload with special characters, unicode, and base64 padding
    payloads = [
        "eyJlcGhlbWVyYWxfcHVibGljX2tleSI6ICJhYmMxMjMifQ==",  # base64
        '{"nonce": "abc", "ct": "xyz+/="}',  # JSON with base64 chars
        "Hello 🔐 World 🌍",  # Unicode
        "a" * 10000,  # Large payload
    ]

    with client.websocket_connect(f"/ws/{uid}") as ws:
        do_ws_auth(ws, private, public_bytes)

        for payload in payloads:
            r = client.post(
                "/send", json={"to": uid, "from_id": "sender", "payload": payload}
            )
            assert r.status_code == 200

            data = ws.receive_json()
            assert data["payload"] == payload, f"Payload mismatch for: {payload[:50]}..."


def test_e2e_two_users_independent_delivery(client):
    """Two authenticated users each receive only their own messages."""
    priv_a, pub_a, uid_a = make_keypair()
    priv_b, pub_b, uid_b = make_keypair()

    with client.websocket_connect(f"/ws/{uid_a}") as ws_a:
        do_ws_auth(ws_a, priv_a, pub_a)

        with client.websocket_connect(f"/ws/{uid_b}") as ws_b:
            do_ws_auth(ws_b, priv_b, pub_b)

            # Send to A
            client.post("/send", json={"to": uid_a, "from_id": "x", "payload": "for_a"})
            # Send to B
            client.post("/send", json={"to": uid_b, "from_id": "y", "payload": "for_b"})

            data_a = ws_a.receive_json()
            assert data_a["payload"] == "for_a"
            assert data_a["from"] == "x"

            data_b = ws_b.receive_json()
            assert data_b["payload"] == "for_b"
            assert data_b["from"] == "y"
