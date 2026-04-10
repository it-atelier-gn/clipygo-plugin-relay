# clipygo-plugin-relay

[![Build](https://github.com/it-atelier-gn/clipygo-plugin-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/it-atelier-gn/clipygo-plugin-relay/actions)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A [clipygo](https://github.com/it-atelier-gn/clipygo) plugin for sharing clipboard content between users through end-to-end encryption. No accounts, no passwords — identity is a keypair generated on first run.

Users exchange public keys out-of-band. Each contact shows up as a target in clipygo. Content is encrypted with ephemeral X25519 ECDH + XChaCha20-Poly1305 and routed through a lightweight relay server that never sees plaintext.

## How it works

1. First run generates an X25519 keypair and a stable user ID
2. Share your public key + ID with contacts (shown in the config UI)
3. Each contact appears as a clipygo target
4. Sent content is encrypted per-message with forward secrecy and posted to the relay
5. Recipients connect via authenticated WebSocket and get a notification in clipygo

## Configuration

Configure through clipygo's Settings → Plugins → Configure.

Config file location:

| Platform | Path |
|---|---|
| Windows | `%APPDATA%\clipygo-plugin-relay\config.json` |
| macOS | `~/Library/Application Support/clipygo-plugin-relay/config.json` |
| Linux | `~/.local/share/clipygo-plugin-relay/config.json` |

### Contacts

Add contacts to the config file:

```json
{
  "relay_url": "https://clipygo-relay.return-co.de",
  "display_name": "Alice",
  "contacts": [
    {
      "name": "Bob",
      "id": "a1b2c3d4e5f6a7b8",
      "public_key": "<base64-encoded X25519 public key>"
    }
  ]
}
```

## Relay server

A Python (FastAPI) relay server is included in `server/`.

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

The server is zero-knowledge — it routes encrypted blobs without being able to read them. WebSocket connections are authenticated via X25519 challenge-response. Messages for offline recipients are queued in memory (1h TTL, max 5 per recipient).

## Security

- X25519 ECDH with ephemeral keys + XChaCha20-Poly1305 per message
- Forward secrecy through per-message ephemeral keypairs
- Authenticated WebSocket prevents message interception
- No custom crypto — standard NaCl-style sealed box pattern using `x25519-dalek` and `chacha20poly1305`

## Building

```sh
cargo build --release
```

### Tests

```sh
cargo test

cd server
uv venv && uv pip install -r requirements.txt -r requirements-dev.txt
uv run pytest test_main.py -v
```

## Installing

Either download a pre-built binary from [Releases](https://github.com/it-atelier-gn/clipygo-plugin-relay/releases), or install directly from the plugin registry in clipygo's Settings.

To register manually: Settings → Plugins → add the path to the binary as the command.

## License

MIT © 2026 Georg Nelles
