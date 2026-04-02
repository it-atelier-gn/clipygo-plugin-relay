# clipygo-plugin-relay

[![Build](https://github.com/it-atelier-gn/clipygo-plugin-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/it-atelier-gn/clipygo-plugin-relay/actions)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An encrypted clipboard relay plugin for [clipygo](https://github.com/it-atelier-gn/clipygo).

## What it does

This plugin lets you share clipboard content with other users through end-to-end encryption. No accounts, no passwords — identity is a keypair generated on first run. Users exchange public keys out-of-band and can then send clipboard content to each other through a lightweight relay server.

The relay server is zero-knowledge: it routes encrypted blobs without ever being able to read the content.

## How it works

1. On first run, the plugin generates an X25519 keypair and a stable user ID
2. You share your public key + ID with contacts (and they share theirs with you)
3. Each contact appears as a target in clipygo
4. When you send content, it's encrypted with ephemeral ECDH + XChaCha20-Poly1305 and posted to the relay
5. The recipient's plugin connects via WebSocket, decrypts incoming messages, and shows a notification in clipygo

## Configuration

Configure the plugin through clipygo's Settings → Plugins → ⚙ config UI:

| Field | Description |
|---|---|
| `relay_url` | URL of the relay server (e.g. `https://clipygo-relay.return-co.de`) |
| `display_name` | Your name shown to message recipients |

### Contacts

Contacts are stored in the config file at:

| Platform | Path |
|---|---|
| Windows | `%APPDATA%\clipygo-plugin-relay\config.json` |
| macOS | `~/Library/Application Support/clipygo-plugin-relay/config.json` |
| Linux | `~/.local/share/clipygo-plugin-relay/config.json` |

Add contacts manually:

```json
{
  "relay_url": "https://clipygo-relay.return-co.de",
  "display_name": "Alice",
  "contacts": [
    {
      "name": "Bob",
      "id": "a1b2c3d4e5f6a7b8",
      "public_key": "<base64-encoded 32-byte X25519 public key>"
    }
  ]
}
```

Use the **Share My Relay Key** target to get your own public key and ID for sharing.

## Relay server

A lightweight Python (FastAPI) relay server is included in `server/`.

### Running the server

```sh
cd server
uv venv && uv pip install -r requirements.txt
uv run uvicorn main:app --host 0.0.0.0 --port 8000
```

Or with Docker:

```sh
cd server
docker build -t clipygo-relay .
docker run -p 8000:8000 clipygo-relay
```

### Server API

| Method | Path | Description |
|---|---|---|
| `POST /send` | Send an encrypted message | Body: `{"to": "...", "from_id": "...", "payload": "..."}` |
| `GET /poll/{user_id}` | Poll for pending messages | Returns array, clears queue |
| `GET /health` | Health check | `{"status": "ok"}` |
| `WS /ws/{user_id}` | Authenticated WebSocket for real-time delivery | X25519 challenge-response handshake |

### WebSocket authentication

WebSocket connections are authenticated via X25519 ECDH challenge-response:

1. Server sends a challenge with an ephemeral public key and random nonce
2. Client computes ECDH shared secret and responds with `HMAC-SHA256(shared_secret, nonce)`
3. Server verifies the HMAC and that the user ID matches the client's public key

This prevents an attacker from connecting as another user to intercept their messages.

Messages for offline recipients are queued in memory with a 24-hour TTL. Rate limiting: 60 messages/minute per sender. Max queue: 100 messages per recipient. Max message size: 1 MB.

## Security

- **E2E encryption**: X25519 ECDH with ephemeral keys + XChaCha20-Poly1305 per message
- **Forward secrecy**: Ephemeral keypair generated for each message
- **Authenticated WebSocket**: X25519 challenge-response prevents message interception
- **Zero-knowledge relay**: Server only sees encrypted blobs and sender/recipient IDs
- **No custom crypto**: Standard NaCl-style sealed box pattern using audited libraries (`x25519-dalek`, `chacha20poly1305`)

## Plugin events

This plugin uses clipygo's plugin event protocol to push notifications:

| Event | Description |
|---|---|
| `incoming_message` | A message was received and decrypted |
| `connection_status` | WebSocket connection state changed (`connecting`, `connected`, `disconnected`) |

## Project structure

```
src/
└── main.rs               # Plugin binary — protocol, crypto, config, WebSocket client
server/
├── main.py               # FastAPI relay server
├── test_main.py           # Server tests (pytest)
├── requirements.txt       # Server dependencies
├── requirements-dev.txt   # Test dependencies
└── Dockerfile             # Server container
```

## Building

```sh
cargo build --release
```

The binary is at `target/release/clipygo-plugin-relay` (or `.exe` on Windows).

### Running tests

```sh
# Rust plugin tests
cargo test

# Server tests
cd server
uv venv && uv pip install -r requirements.txt -r requirements-dev.txt
uv run pytest test_main.py -v
```

## Releases

Pre-built binaries for Windows, Linux, and macOS are published automatically via GitHub Actions on every `v*` tag.

| Platform | Artifact |
|---|---|
| Windows x64 | `clipygo-plugin-relay-windows-x64.exe` |
| Linux x64 | `clipygo-plugin-relay-linux-x64` |
| macOS ARM64 | `clipygo-plugin-relay-macos-arm64` |

SHA256 checksums are published alongside each binary.

## Registering in clipygo

In clipygo Settings → Plugins, add the path to the downloaded binary as the command. Or install it directly from the [clipygo plugin registry](https://github.com/it-atelier-gn/clipygo-plugins).
