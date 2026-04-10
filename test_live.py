"""Test the live relay server via SSH tunnel.

Tests the relay server's HTTP and WebSocket endpoints directly,
simulating what the plugin binary does.

Requires: SSH tunnel on localhost:18000 -> relay VM localhost:8000
    ssh -f -N -L 18000:localhost:8000 root@2a01:4f9:c013:d1fc::1
"""

import asyncio
import base64
import hashlib
import json
import os

import httpx
import websockets

RELAY_URL = "http://localhost:18000"
WS_URL = "ws://localhost:18000"


def make_keypair():
    """Generate X25519 keypair using cryptography library."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    private = X25519PrivateKey.generate()
    public = private.public_key()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, NoEncryption, PrivateFormat
    pub_bytes = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return priv_bytes, pub_bytes


def user_id_from_pubkey(pub_bytes):
    return hashlib.sha256(pub_bytes).hexdigest()[:16]


def compute_hmac(shared_secret: bytes, nonce: bytes) -> str:
    import hmac as hmac_mod
    mac = hmac_mod.new(shared_secret, nonce, hashlib.sha256)
    return mac.hexdigest()


async def ws_auth_and_receive(ws_url, priv_bytes, pub_bytes, timeout=8):
    """Connect to WebSocket, perform challenge-response auth, receive messages."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

    user_id = user_id_from_pubkey(pub_bytes)
    url = f"{ws_url}/ws/{user_id}"

    messages = []

    async with websockets.connect(url) as ws:
        # Receive challenge
        challenge_raw = await asyncio.wait_for(ws.recv(), timeout=5)
        challenge = json.loads(challenge_raw)
        assert challenge["type"] == "challenge", f"Expected challenge, got {challenge}"

        nonce = bytes.fromhex(challenge["nonce"])
        server_ephemeral_pub = base64.b64decode(challenge["server_public_key"])

        # Compute ECDH shared secret
        my_private = X25519PrivateKey.from_private_bytes(priv_bytes)
        server_pub = X25519PublicKey.from_public_bytes(server_ephemeral_pub)
        shared_secret = my_private.exchange(server_pub)

        # Compute HMAC
        hmac_hex = compute_hmac(shared_secret, nonce)

        # Send auth response (type="auth", public_key as base64)
        auth_msg = json.dumps({
            "type": "auth",
            "hmac": hmac_hex,
            "public_key": base64.b64encode(pub_bytes).decode(),
        })
        await ws.send(auth_msg)
        print(f"  Auth OK for {user_id}")

        # Collect messages
        try:
            while True:
                msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
                parsed = json.loads(msg)
                messages.append(parsed)
                print(f"  Received: {json.dumps(parsed)[:100]}")
        except asyncio.TimeoutError:
            pass

    return messages


async def main():
    # Generate two keypairs
    alice_priv, alice_pub = make_keypair()
    bob_priv, bob_pub = make_keypair()
    alice_id = user_id_from_pubkey(alice_pub)
    bob_id = user_id_from_pubkey(bob_pub)

    print(f"Alice: {alice_id}")
    print(f"Bob:   {bob_id}")

    # Test 1: Health check
    print("\n=== Test 1: Health check ===")
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{RELAY_URL}/health")
        print(f"  {resp.status_code}: {resp.text}")
        assert resp.status_code == 200

    # Test 2: Send message from Alice to Bob (Bob offline)
    print("\n=== Test 2: Alice sends message (Bob offline) ===")
    # Encrypt a test payload (normally plugin does XChaCha20Poly1305, but
    # for server routing we just need valid JSON with the right structure)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    # Build encrypted payload the same way the Rust plugin does:
    # ephemeral ECDH -> shared secret -> XChaCha20Poly1305
    alice_ephemeral = X25519PrivateKey.generate()
    alice_eph_pub = alice_ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    bob_pub_key = X25519PublicKey.from_public_bytes(bob_pub)
    shared = alice_ephemeral.exchange(bob_pub_key)
    derived_key = hashlib.sha256(shared).digest()

    # The Rust plugin uses XChaCha20Poly1305 with 24-byte nonce
    # Python's cryptography lib has ChaCha20Poly1305 (12-byte nonce)
    # Let's just send a simple payload and test server routing —
    # the actual decryption test is already covered by unit tests

    # For a full E2E test, encode like the plugin: ephemeral_pub(32) + nonce(24) + ciphertext
    # We'll use a dummy encrypted payload that Bob can't decrypt, but it proves routing works
    import secrets
    nonce = secrets.token_bytes(24)
    dummy_ciphertext = secrets.token_bytes(64)
    payload = alice_eph_pub + nonce + dummy_ciphertext
    payload_b64 = base64.b64encode(payload).decode()

    send_body = {
        "from_id": alice_id,
        "to": bob_id,
        "payload": payload_b64,
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{RELAY_URL}/send", json=send_body)
        print(f"  Send response: {resp.status_code} {resp.text}")
        assert resp.status_code == 200

    # Test 3: Bob connects via WebSocket and receives the message
    print("\n=== Test 3: Bob connects and receives ===")
    messages = await ws_auth_and_receive(WS_URL, bob_priv, bob_pub, timeout=5)

    if messages:
        msg = messages[0]
        assert msg.get("from") == alice_id, f"Expected from={alice_id}, got {msg.get('from')}"
        assert msg.get("payload") == payload_b64
        print(f"  Message from {msg['from']}, payload matches!")
        print("\n=== ALL TESTS PASSED ===")
    else:
        print("\n=== FAILED: No messages received ===")


if __name__ == "__main__":
    asyncio.run(main())
