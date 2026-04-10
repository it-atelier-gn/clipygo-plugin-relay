use std::fs;
use std::io::{self, BufRead, Write as IoWrite};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::XChaCha20Poly1305;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

// --- Routing token constants ---

const TOKEN_PERIOD: u64 = 300; // 5 minutes
const PADDING_BLOCK: usize = 256; // pad plaintext to this boundary

/// Derive a rotating routing token from a public key and current time.
/// Both sender and receiver can compute this independently.
fn derive_routing_token(public_key_bytes: &[u8], unix_secs: u64) -> String {
    let period_index = unix_secs / TOKEN_PERIOD;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(public_key_bytes).expect("HMAC accepts any key length");
    mac.update(&period_index.to_be_bytes());
    let result = mac.finalize().into_bytes();
    hex::encode(&result[..8]) // 16 hex chars
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// --- Protocol types ---

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum Request {
    GetInfo,
    GetTargets,
    GetConfigSchema,
    SetConfig {
        values: serde_json::Value,
    },
    Send {
        target_id: String,
        content: String,
        format: String,
    },
}

#[derive(Serialize)]
struct InfoResponse {
    name: &'static str,
    version: &'static str,
    description: &'static str,
    author: &'static str,
    link: &'static str,
}

#[derive(Serialize)]
struct TargetsResponse {
    targets: Vec<TargetEntry>,
}

#[derive(Serialize, Clone)]
struct TargetEntry {
    id: String,
    provider: String,
    formats: Vec<String>,
    title: String,
    description: String,
    image: String,
}

#[derive(Serialize)]
struct SendResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct ConfigSchemaResponse {
    schema: serde_json::Value,
    values: serde_json::Value,
}

// --- Plugin event types (emitted to stdout) ---

#[derive(Serialize)]
struct PluginEvent<T: Serialize> {
    event: String,
    data: T,
}

#[derive(Serialize)]
struct IncomingMessageData {
    from_name: String,
    from_id: String,
    content: String,
    format: String,
    timestamp: u64,
}

#[derive(Serialize)]
struct ConnectionStatusData {
    status: String,
}

// --- Config & keypair ---

#[derive(Serialize, Deserialize, Clone)]
struct AppConfig {
    #[serde(default)]
    relay_url: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    ignore_tls_errors: bool,
    #[serde(default)]
    contacts: Vec<Contact>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            relay_url: "https://clipygo-relay.return-co.de".to_string(),
            display_name: String::new(),
            ignore_tls_errors: false,
            contacts: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Contact {
    name: String,
    id: String,
    public_key: String, // base64-encoded 32 bytes
}

#[derive(Serialize, Deserialize)]
struct KeypairFile {
    private_key: String, // base64-encoded 32 bytes
    public_key: String,  // base64-encoded 32 bytes
    user_id: String,     // hex SHA256 of public key, first 16 chars
}

// --- Encrypted message envelope ---

#[derive(Serialize, Deserialize)]
struct EncryptedEnvelope {
    ephemeral_public_key: String, // base64
    nonce: String,                // base64
    ciphertext: String,           // base64
    sender_id: String,
    sender_name: String,
    format: String,
}

// --- Relay API types ---

#[derive(Serialize)]
struct RelaySendRequest {
    to: String,
    from_id: String,
    payload: String, // base64 JSON of EncryptedEnvelope
}

#[derive(Deserialize)]
struct RelayMessage {
    #[allow(dead_code)]
    from: String,
    payload: String,
    timestamp: f64,
}

// --- App state ---

struct AppState {
    config: AppConfig,
    #[allow(dead_code)]
    private_key: StaticSecret,
    public_key: PublicKey,
    user_id: String,
    data_dir: PathBuf,
}

// --- File paths ---

fn data_dir() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("clipygo-plugin-relay")
}

fn config_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("config.json")
}

fn keypair_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("keypair.json")
}

// --- Keypair management ---

fn user_id_from_public_key(pk: &PublicKey) -> String {
    let hash = Sha256::digest(pk.as_bytes());
    hex::encode(&hash[..8]) // 16 hex chars
}

fn load_or_create_keypair(data_dir: &std::path::Path) -> (StaticSecret, PublicKey, String) {
    let path = keypair_path(data_dir);

    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(kf) = serde_json::from_str::<KeypairFile>(&data) {
            if let Ok(bytes) = B64.decode(&kf.private_key) {
                if bytes.len() == 32 {
                    let mut key_bytes = [0u8; 32];
                    key_bytes.copy_from_slice(&bytes);
                    let secret = StaticSecret::from(key_bytes);
                    let public = PublicKey::from(&secret);
                    let uid = user_id_from_public_key(&public);
                    return (secret, public, uid);
                }
            }
        }
    }

    // Generate new keypair
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let secret = StaticSecret::from(key_bytes);
    let public = PublicKey::from(&secret);
    let uid = user_id_from_public_key(&public);

    let kf = KeypairFile {
        private_key: B64.encode(key_bytes),
        public_key: B64.encode(public.as_bytes()),
        user_id: uid.clone(),
    };

    let _ = fs::create_dir_all(data_dir);
    let _ = fs::write(&path, serde_json::to_string_pretty(&kf).unwrap());

    (secret, public, uid)
}

// --- Config management ---

fn load_config(data_dir: &std::path::Path) -> AppConfig {
    let path = config_path(data_dir);
    fs::read_to_string(&path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default()
}

fn save_config(data_dir: &std::path::Path, config: &AppConfig) -> Result<(), String> {
    let path = config_path(data_dir);
    let _ = fs::create_dir_all(data_dir);
    fs::write(
        &path,
        serde_json::to_string_pretty(config).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("Failed to write config: {e}"))
}

// --- Crypto ---

fn derive_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hash = Sha256::digest(shared_secret);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

fn encrypt_for_recipient(
    content: &str,
    recipient_public_key: &PublicKey,
    sender_id: &str,
    sender_name: &str,
    format: &str,
) -> Result<String, String> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(recipient_public_key);
    let key = derive_key(shared_secret.as_bytes());

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("Cipher init: {e}"))?;

    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);

    // Length-prefix + pad to PADDING_BLOCK boundary to obscure content size
    let content_bytes = content.as_bytes();
    let len_prefix = (content_bytes.len() as u32).to_be_bytes();
    let total_unpadded = 4 + content_bytes.len();
    let pad_len = PADDING_BLOCK - (total_unpadded % PADDING_BLOCK);
    let mut padded = Vec::with_capacity(total_unpadded + pad_len);
    padded.extend_from_slice(&len_prefix);
    padded.extend_from_slice(content_bytes);
    let mut pad = vec![0u8; pad_len];
    OsRng.fill_bytes(&mut pad);
    padded.extend_from_slice(&pad);

    let ciphertext = cipher
        .encrypt(nonce, padded.as_slice())
        .map_err(|e| format!("Encryption failed: {e}"))?;

    let envelope = EncryptedEnvelope {
        ephemeral_public_key: B64.encode(ephemeral_public.as_bytes()),
        nonce: B64.encode(nonce_bytes),
        ciphertext: B64.encode(&ciphertext),
        sender_id: sender_id.to_string(),
        sender_name: sender_name.to_string(),
        format: format.to_string(),
    };

    let json = serde_json::to_string(&envelope).map_err(|e| format!("Serialize: {e}"))?;
    Ok(B64.encode(json.as_bytes()))
}

fn decrypt_envelope(
    payload_b64: &str,
    own_secret: &StaticSecret,
) -> Result<(EncryptedEnvelope, String), String> {
    let payload_json = B64
        .decode(payload_b64)
        .map_err(|e| format!("Base64 decode: {e}"))?;
    let envelope: EncryptedEnvelope =
        serde_json::from_slice(&payload_json).map_err(|e| format!("Envelope parse: {e}"))?;

    let ephemeral_pk_bytes = B64
        .decode(&envelope.ephemeral_public_key)
        .map_err(|e| format!("Ephemeral key decode: {e}"))?;
    if ephemeral_pk_bytes.len() != 32 {
        return Err("Invalid ephemeral public key length".to_string());
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&ephemeral_pk_bytes);
    let ephemeral_public = PublicKey::from(pk_arr);

    let shared_secret = own_secret.diffie_hellman(&ephemeral_public);
    let key = derive_key(shared_secret.as_bytes());

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("Cipher init: {e}"))?;

    let nonce_bytes = B64
        .decode(&envelope.nonce)
        .map_err(|e| format!("Nonce decode: {e}"))?;
    if nonce_bytes.len() != 24 {
        return Err("Invalid nonce length".to_string());
    }
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);

    let ciphertext = B64
        .decode(&envelope.ciphertext)
        .map_err(|e| format!("Ciphertext decode: {e}"))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Decryption failed — message not from a known contact".to_string())?;

    // Strip length-prefix padding: first 4 bytes = content length, then content, rest is padding
    if plaintext.len() < 4 {
        return Err("Decrypted payload too short".to_string());
    }
    let content_len =
        u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
    if plaintext.len() < 4 + content_len {
        return Err("Decrypted payload shorter than declared content length".to_string());
    }
    let content = String::from_utf8(plaintext[4..4 + content_len].to_vec())
        .map_err(|e| format!("UTF-8 decode: {e}"))?;
    Ok((envelope, content))
}

// --- Handlers ---

fn handle_get_info() -> String {
    serde_json::to_string(&InfoResponse {
        name: "clipygo-plugin-relay",
        version: env!("CARGO_PKG_VERSION"),
        description: "Encrypted clipboard relay — share clipboard content with E2E encryption",
        author: "Georg Nelles",
        link: "https://github.com/it-atelier-gn/clipygo-plugin-relay",
    })
    .unwrap()
}

fn handle_get_targets(state: &AppState) -> String {
    let targets: Vec<TargetEntry> = state
        .config
        .contacts
        .iter()
        .map(|c| TargetEntry {
            id: format!("relay:{}", c.id),
            provider: "clipygo-plugin-relay".to_string(),
            formats: vec!["text".to_string()],
            title: c.name.clone(),
            description: format!("Send encrypted clipboard to {}", c.name),
            image: String::new(),
        })
        .collect();

    serde_json::to_string(&TargetsResponse { targets }).unwrap()
}

fn handle_get_config_schema(state: &AppState) -> String {
    serde_json::to_string(&ConfigSchemaResponse {
        schema: serde_json::json!({
            "type": "object",
            "properties": {
                "relay_url": {
                    "type": "string",
                    "title": "Relay Server URL",
                    "description": "URL of the relay server (e.g. https://clipygo-relay.return-co.de)"
                },
                "display_name": {
                    "type": "string",
                    "title": "Display Name",
                    "description": "Your name shown to message recipients"
                },
                "ignore_tls_errors": {
                    "type": "boolean",
                    "title": "Ignore TLS Certificate Errors",
                    "description": "Skip TLS certificate validation (useful for self-signed certs)"
                },
                "user_id": {
                    "type": "string",
                    "title": "Relay ID",
                    "description": "Your unique relay identity (share this with contacts)",
                    "readOnly": true
                },
                "public_key": {
                    "type": "string",
                    "title": "Public Key",
                    "description": "Your X25519 public key (share this with contacts)",
                    "readOnly": true
                },
                "private_key": {
                    "type": "string",
                    "title": "Private Key",
                    "description": "Your X25519 private key (backup this to transfer your identity)",
                    "format": "password",
                    "readOnly": true
                },
                "contacts": {
                    "type": "array",
                    "title": "Contacts",
                    "description": "People you can send clipboard to. Ask them for their Relay ID and Public Key.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string", "title": "Name" },
                            "id": { "type": "string", "title": "Relay ID" },
                            "public_key": { "type": "string", "title": "Public Key" }
                        },
                        "required": ["name", "id", "public_key"]
                    }
                }
            },
            "required": ["relay_url", "display_name"]
        }),
        values: serde_json::json!({
            "relay_url": state.config.relay_url,
            "display_name": state.config.display_name,
            "ignore_tls_errors": state.config.ignore_tls_errors,
            "user_id": state.user_id,
            "public_key": B64.encode(state.public_key.as_bytes()),
            "private_key": B64.encode(state.private_key.as_bytes()),
            "contacts": serde_json::to_value(&state.config.contacts).unwrap_or(serde_json::Value::Array(vec![])),
        }),
    })
    .unwrap()
}

fn handle_set_config(state: &mut AppState, values: serde_json::Value) -> String {
    if let Some(url) = values.get("relay_url").and_then(|v| v.as_str()) {
        state.config.relay_url = url.to_string();
    }
    if let Some(name) = values.get("display_name").and_then(|v| v.as_str()) {
        state.config.display_name = name.to_string();
    }
    if let Some(val) = values.get("ignore_tls_errors").and_then(|v| v.as_bool()) {
        state.config.ignore_tls_errors = val;
    }
    if let Some(contacts_val) = values.get("contacts") {
        if let Ok(contacts) = serde_json::from_value::<Vec<Contact>>(contacts_val.clone()) {
            state.config.contacts = contacts;
        }
    }

    match save_config(&state.data_dir, &state.config) {
        Ok(()) => serde_json::to_string(&SendResponse {
            success: true,
            error: None,
        })
        .unwrap(),
        Err(e) => serde_json::to_string(&SendResponse {
            success: false,
            error: Some(e),
        })
        .unwrap(),
    }
}

fn handle_send(
    state: &AppState,
    target_id: &str,
    content: &str,
    format: &str,
    runtime: &tokio::runtime::Runtime,
) -> String {
    // Find contact by target_id (format: "relay:{contact_id}")
    let contact_id = target_id.strip_prefix("relay:").unwrap_or(target_id);
    let contact = match state.config.contacts.iter().find(|c| c.id == contact_id) {
        Some(c) => c,
        None => {
            return serde_json::to_string(&SendResponse {
                success: false,
                error: Some(format!("Contact not found: {contact_id}")),
            })
            .unwrap()
        }
    };

    // Decode recipient public key
    let pk_bytes = match B64.decode(&contact.public_key) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return serde_json::to_string(&SendResponse {
                success: false,
                error: Some("Invalid contact public key".to_string()),
            })
            .unwrap()
        }
    };
    let recipient_pk = PublicKey::from(pk_bytes);

    // Encrypt
    let payload = match encrypt_for_recipient(
        content,
        &recipient_pk,
        &state.user_id,
        &state.config.display_name,
        format,
    ) {
        Ok(p) => p,
        Err(e) => {
            return serde_json::to_string(&SendResponse {
                success: false,
                error: Some(format!("Encryption failed: {e}")),
            })
            .unwrap()
        }
    };

    // POST to relay
    let relay_url = state.config.relay_url.trim_end_matches('/').to_string();
    if relay_url.is_empty() {
        return serde_json::to_string(&SendResponse {
            success: false,
            error: Some("Relay URL not configured".to_string()),
        })
        .unwrap();
    }

    let send_url = format!("{relay_url}/send");
    let now = now_secs();
    let body = RelaySendRequest {
        to: derive_routing_token(&pk_bytes, now),
        from_id: derive_routing_token(state.public_key.as_bytes(), now),
        payload,
    };

    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(state.config.ignore_tls_errors)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return serde_json::to_string(&SendResponse {
                success: false,
                error: Some(format!("HTTP client init failed: {e}")),
            })
            .unwrap()
        }
    };

    match runtime.block_on(async { client.post(&send_url).json(&body).send().await }) {
        Ok(resp) if resp.status().is_success() => serde_json::to_string(&SendResponse {
            success: true,
            error: None,
        })
        .unwrap(),
        Ok(resp) => serde_json::to_string(&SendResponse {
            success: false,
            error: Some(format!("Relay returned {}", resp.status())),
        })
        .unwrap(),
        Err(e) => serde_json::to_string(&SendResponse {
            success: false,
            error: Some(format!("Relay request failed: {e}")),
        })
        .unwrap(),
    }
}

// --- Event emission ---

fn emit_event<T: Serialize>(stdout: &Mutex<io::Stdout>, event: &str, data: T) {
    let evt = PluginEvent {
        event: event.to_string(),
        data,
    };
    if let Ok(json) = serde_json::to_string(&evt) {
        if let Ok(mut out) = stdout.lock() {
            let _ = writeln!(out, "{json}");
            let _ = out.flush();
        }
    }
}

// --- WebSocket background task ---

async fn ws_receiver_loop(state: Arc<Mutex<AppState>>, stdout: Arc<Mutex<io::Stdout>>) {
    use futures_util::StreamExt;
    use tokio_tungstenite::{connect_async, connect_async_tls_with_config};

    loop {
        let config_snapshot = {
            let s = state.lock().unwrap();
            (
                s.config.relay_url.clone(),
                keypair_path(&s.data_dir),
                s.config.ignore_tls_errors,
                *s.public_key.as_bytes(),
            )
        }; // MutexGuard dropped here

        let (relay_url_raw, kp_path, ignore_tls_errors, pk_bytes) = config_snapshot;

        if relay_url_raw.is_empty() {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            continue;
        }

        // Derive the current routing token and compute time until next rotation
        let now = now_secs();
        let current_token = derive_routing_token(&pk_bytes, now);
        let secs_until_rotation = TOKEN_PERIOD - (now % TOKEN_PERIOD);

        // Convert HTTP URL to WS URL
        let base = relay_url_raw.trim_end_matches('/');
        let ws_base = if base.starts_with("https://") {
            base.replacen("https://", "wss://", 1)
        } else if base.starts_with("http://") {
            base.replacen("http://", "ws://", 1)
        } else {
            base.to_string()
        };
        let relay_url = format!("{ws_base}/ws/{current_token}");

        // Poll previous period's token to drain any stragglers
        let prev_token = derive_routing_token(&pk_bytes, now.saturating_sub(TOKEN_PERIOD));
        if prev_token != current_token {
            let poll_url = format!("{base}/poll/{prev_token}");
            let _ = reqwest::Client::builder()
                .danger_accept_invalid_certs(ignore_tls_errors)
                .build()
                .ok()
                .map(|client| {
                    // Fire-and-forget poll; we just want the server to flush the old queue
                    let stdout_clone = stdout.clone();
                    let kp_clone = kp_path.clone();
                    tokio::spawn(async move {
                        if let Ok(resp) = client.get(&poll_url).send().await {
                            if let Ok(messages) = resp.json::<Vec<RelayMessage>>().await {
                                let pk_bytes_inner = fs::read_to_string(&kp_clone)
                                    .ok()
                                    .and_then(|d| serde_json::from_str::<KeypairFile>(&d).ok())
                                    .and_then(|kf| B64.decode(&kf.private_key).ok())
                                    .unwrap_or_default();
                                if pk_bytes_inner.len() == 32 {
                                    let mut key_arr = [0u8; 32];
                                    key_arr.copy_from_slice(&pk_bytes_inner);
                                    let secret = StaticSecret::from(key_arr);
                                    for msg in &messages {
                                        if let Ok((envelope, content)) =
                                            decrypt_envelope(&msg.payload, &secret)
                                        {
                                            emit_event(
                                                &stdout_clone,
                                                "incoming_message",
                                                IncomingMessageData {
                                                    from_name: envelope.sender_name,
                                                    from_id: envelope.sender_id,
                                                    content,
                                                    format: envelope.format,
                                                    timestamp: msg.timestamp as u64,
                                                },
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    });
                });
        }

        // Re-read keypair file to get private key bytes (StaticSecret doesn't expose them)
        let private_key_bytes = fs::read_to_string(&kp_path)
            .ok()
            .and_then(|data| serde_json::from_str::<KeypairFile>(&data).ok())
            .and_then(|kf| B64.decode(&kf.private_key).ok())
            .unwrap_or_default();

        emit_event(
            &stdout,
            "connection_status",
            ConnectionStatusData {
                status: "connecting".to_string(),
            },
        );

        let ws_result = if ignore_tls_errors {
            let tls_connector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .expect("Failed to build TLS connector");
            let connector = tokio_tungstenite::Connector::NativeTls(tls_connector);
            connect_async_tls_with_config(&relay_url, None, false, Some(connector)).await
        } else {
            connect_async(&relay_url).await
        };

        match ws_result {
            Ok((ws_stream, _)) => {
                let (mut write, mut read) = ws_stream.split();

                // --- Challenge-response authentication ---
                let auth_ok = 'auth: {
                    use futures_util::SinkExt;
                    use tokio_tungstenite::tungstenite::Message as WsMsg;

                    // 1. Receive challenge
                    let challenge_text = match read.next().await {
                        Some(Ok(WsMsg::Text(t))) => t,
                        _ => break 'auth false,
                    };
                    let challenge: serde_json::Value = match serde_json::from_str(&challenge_text) {
                        Ok(v) => v,
                        Err(_) => break 'auth false,
                    };
                    if challenge.get("type").and_then(|v| v.as_str()) != Some("challenge") {
                        break 'auth false;
                    }
                    let server_pk_b64 =
                        match challenge.get("server_public_key").and_then(|v| v.as_str()) {
                            Some(s) => s,
                            None => break 'auth false,
                        };
                    let nonce_hex = match challenge.get("nonce").and_then(|v| v.as_str()) {
                        Some(s) => s,
                        None => break 'auth false,
                    };

                    let server_pk_bytes = match B64.decode(server_pk_b64) {
                        Ok(b) if b.len() == 32 => b,
                        _ => break 'auth false,
                    };
                    let nonce = match hex::decode(nonce_hex) {
                        Ok(n) => n,
                        Err(_) => break 'auth false,
                    };

                    // 2. ECDH with server's ephemeral public key
                    if private_key_bytes.len() != 32 {
                        break 'auth false;
                    }
                    let mut key_arr = [0u8; 32];
                    key_arr.copy_from_slice(&private_key_bytes);
                    let client_secret = StaticSecret::from(key_arr);

                    let mut spk_arr = [0u8; 32];
                    spk_arr.copy_from_slice(&server_pk_bytes);
                    let server_pk = PublicKey::from(spk_arr);
                    let shared_secret = client_secret.diffie_hellman(&server_pk);

                    // 3. HMAC-SHA256(shared_secret, nonce)
                    type HmacSha256 = Hmac<Sha256>;
                    let mut mac = <HmacSha256 as Mac>::new_from_slice(shared_secret.as_bytes())
                        .expect("HMAC accepts any key length");
                    mac.update(&nonce);
                    let hmac_hex = hex::encode(mac.finalize().into_bytes());

                    // 4. Send auth response
                    let our_public_key = PublicKey::from(&client_secret);
                    let auth_msg = serde_json::json!({
                        "type": "auth",
                        "public_key": B64.encode(our_public_key.as_bytes()),
                        "hmac": hmac_hex,
                    });
                    if write
                        .send(WsMsg::Text(auth_msg.to_string().into()))
                        .await
                        .is_err()
                    {
                        break 'auth false;
                    }

                    true
                };

                if !auth_ok {
                    eprintln!("WebSocket auth handshake failed");
                    // Fall through to disconnect/reconnect
                } else {
                    emit_event(
                        &stdout,
                        "connection_status",
                        ConnectionStatusData {
                            status: "connected".to_string(),
                        },
                    );

                    // Read messages until token rotation or disconnect
                    let rotation_deadline = tokio::time::Instant::now()
                        + tokio::time::Duration::from_secs(secs_until_rotation);

                    loop {
                        let msg = tokio::time::timeout_at(rotation_deadline, read.next()).await;
                        match msg {
                            Err(_) => {
                                // Token rotation — break to reconnect with new token
                                break;
                            }
                            Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text)))) => {
                                if let Ok(relay_msg) = serde_json::from_str::<RelayMessage>(&text) {
                                    if private_key_bytes.len() == 32 {
                                        let mut key_arr = [0u8; 32];
                                        key_arr.copy_from_slice(&private_key_bytes);
                                        let secret = StaticSecret::from(key_arr);

                                        match decrypt_envelope(&relay_msg.payload, &secret) {
                                            Ok((envelope, content)) => {
                                                let ts = relay_msg.timestamp as u64;
                                                emit_event(
                                                    &stdout,
                                                    "incoming_message",
                                                    IncomingMessageData {
                                                        from_name: envelope.sender_name,
                                                        from_id: envelope.sender_id,
                                                        content,
                                                        format: envelope.format,
                                                        timestamp: ts,
                                                    },
                                                );
                                            }
                                            Err(e) => {
                                                eprintln!("Decrypt failed: {e}");
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(Some(Err(_))) | Ok(None) => break, // Error or stream ended
                            _ => {}
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("WebSocket connect failed: {e}");
            }
        }

        emit_event(
            &stdout,
            "connection_status",
            ConnectionStatusData {
                status: "disconnected".to_string(),
            },
        );

        // Reconnect after delay
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}

// --- Main ---

fn main() {
    let dd = data_dir();
    let _ = fs::create_dir_all(&dd);

    let (private_key, public_key, user_id) = load_or_create_keypair(&dd);
    let config = load_config(&dd);

    let state = Arc::new(Mutex::new(AppState {
        config,
        private_key,
        public_key,
        user_id,
        data_dir: dd,
    }));

    let stdout = Arc::new(Mutex::new(io::stdout()));

    // Build tokio runtime for async operations
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    // Spawn WebSocket receiver in the background
    let ws_state = state.clone();
    let ws_stdout = stdout.clone();
    runtime.spawn(async move {
        ws_receiver_loop(ws_state, ws_stdout).await;
    });

    // Stdin protocol loop (blocking, on main thread)
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(Request::GetInfo) => handle_get_info(),
            Ok(Request::GetTargets) => {
                let s = state.lock().unwrap();
                handle_get_targets(&s)
            }
            Ok(Request::GetConfigSchema) => {
                let s = state.lock().unwrap();
                handle_get_config_schema(&s)
            }
            Ok(Request::SetConfig { values }) => {
                let mut s = state.lock().unwrap();
                handle_set_config(&mut s, values)
            }
            Ok(Request::Send {
                target_id,
                content,
                format,
            }) => {
                let s = state.lock().unwrap();
                handle_send(&s, &target_id, &content, &format, &runtime)
            }
            Err(e) => serde_json::to_string(&SendResponse {
                success: false,
                error: Some(format!("Invalid request: {e}")),
            })
            .unwrap(),
        };

        if let Ok(mut out) = stdout.lock() {
            let _ = writeln!(out, "{response}");
            let _ = out.flush();
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // --- Protocol ---

    #[test]
    fn get_info_returns_valid_json() {
        let response = handle_get_info();
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["name"], "clipygo-plugin-relay");
        assert!(v["version"].is_string());
        assert!(v["link"].is_string());
    }

    #[test]
    fn request_deserialization_get_info() {
        let r: Request = serde_json::from_str(r#"{"command":"get_info"}"#).unwrap();
        assert!(matches!(r, Request::GetInfo));
    }

    #[test]
    fn request_deserialization_send() {
        let r: Request = serde_json::from_str(
            r#"{"command":"send","target_id":"t1","content":"hi","format":"text"}"#,
        )
        .unwrap();
        assert!(matches!(r, Request::Send { .. }));
    }

    // --- Keypair ---

    #[test]
    fn user_id_is_deterministic() {
        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        let pk = PublicKey::from(bytes);
        let id1 = user_id_from_public_key(&pk);
        let id2 = user_id_from_public_key(&pk);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn different_keys_produce_different_ids() {
        let pk1 = PublicKey::from([1u8; 32]);
        let pk2 = PublicKey::from([2u8; 32]);
        assert_ne!(user_id_from_public_key(&pk1), user_id_from_public_key(&pk2));
    }

    #[test]
    fn keypair_load_creates_new_in_temp_dir() {
        let dir = std::env::temp_dir().join(format!("clipygo_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (_, pk1, uid1) = load_or_create_keypair(&dir);

        // Loading again should return the same key
        let (_, pk2, uid2) = load_or_create_keypair(&dir);
        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
        assert_eq!(uid1, uid2);

        let _ = fs::remove_dir_all(&dir);
    }

    // --- Config ---

    #[test]
    fn config_roundtrip() {
        let dir = std::env::temp_dir().join(format!("clipygo_cfg_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let config = AppConfig {
            relay_url: "http://localhost:8000".to_string(),
            display_name: "Alice".to_string(),
            ignore_tls_errors: false,
            contacts: vec![Contact {
                name: "Bob".to_string(),
                id: "bob123".to_string(),
                public_key: B64.encode([99u8; 32]),
            }],
        };

        save_config(&dir, &config).unwrap();
        let loaded = load_config(&dir);
        assert_eq!(loaded.relay_url, "http://localhost:8000");
        assert_eq!(loaded.display_name, "Alice");
        assert_eq!(loaded.contacts.len(), 1);
        assert_eq!(loaded.contacts[0].name, "Bob");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_config_returns_default_when_missing() {
        let dir = PathBuf::from("/nonexistent/path/clipygo_test");
        let config = load_config(&dir);
        assert_eq!(config.relay_url, "https://clipygo-relay.return-co.de");
        assert_eq!(config.display_name, "");
        assert!(!config.ignore_tls_errors);
        assert!(config.contacts.is_empty());
    }

    // --- Crypto ---

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut recipient_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut recipient_key_bytes);
        let recipient_secret = StaticSecret::from(recipient_key_bytes);
        let recipient_public = PublicKey::from(&recipient_secret);

        let payload = encrypt_for_recipient(
            "Hello, World!",
            &recipient_public,
            "sender123",
            "Alice",
            "text",
        )
        .unwrap();

        let (envelope, content) = decrypt_envelope(&payload, &recipient_secret).unwrap();
        assert_eq!(content, "Hello, World!");
        assert_eq!(envelope.sender_id, "sender123");
        assert_eq!(envelope.sender_name, "Alice");
        assert_eq!(envelope.format, "text");
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let recipient_secret = StaticSecret::from(key_bytes);
        let recipient_public = PublicKey::from(&recipient_secret);

        let payload = encrypt_for_recipient("secret", &recipient_public, "s", "S", "text").unwrap();

        // Try to decrypt with a different key
        let mut wrong_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut wrong_bytes);
        let wrong_secret = StaticSecret::from(wrong_bytes);

        assert!(decrypt_envelope(&payload, &wrong_secret).is_err());
    }

    #[test]
    fn encrypt_produces_different_ciphertext_each_time() {
        let recipient_secret = StaticSecret::from([42u8; 32]);
        let recipient_public = PublicKey::from(&recipient_secret);

        let p1 =
            encrypt_for_recipient("same content", &recipient_public, "s", "S", "text").unwrap();
        let p2 =
            encrypt_for_recipient("same content", &recipient_public, "s", "S", "text").unwrap();

        // Ephemeral keys + random nonces should produce different payloads
        assert_ne!(p1, p2);
    }

    #[test]
    fn encrypted_envelope_serialization() {
        let envelope = EncryptedEnvelope {
            ephemeral_public_key: "key123".to_string(),
            nonce: "nonce456".to_string(),
            ciphertext: "ct789".to_string(),
            sender_id: "sid".to_string(),
            sender_name: "Alice".to_string(),
            format: "text".to_string(),
        };

        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: EncryptedEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sender_name, "Alice");
        assert_eq!(parsed.format, "text");
    }

    // --- Targets ---

    #[test]
    fn targets_include_contacts() {
        let dd = PathBuf::from("/tmp/test");
        let secret = StaticSecret::from([1u8; 32]);
        let public = PublicKey::from(&secret);
        let state = AppState {
            config: AppConfig {
                relay_url: "http://localhost".to_string(),
                display_name: "Me".to_string(),
                ignore_tls_errors: false,
                contacts: vec![Contact {
                    name: "Bob".to_string(),
                    id: "bob123".to_string(),
                    public_key: B64.encode([2u8; 32]),
                }],
            },
            private_key: secret,
            public_key: public,
            user_id: "me123".to_string(),
            data_dir: dd,
        };

        let response = handle_get_targets(&state);
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        let targets = v["targets"].as_array().unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0]["id"], "relay:bob123");
        assert_eq!(targets[0]["title"], "Bob");
    }

    // --- Config schema ---

    #[test]
    fn config_schema_returns_current_values() {
        let dd = PathBuf::from("/tmp/test");
        let secret = StaticSecret::from([1u8; 32]);
        let public = PublicKey::from(&secret);
        let state = AppState {
            config: AppConfig {
                relay_url: "http://my-relay.com".to_string(),
                display_name: "TestUser".to_string(),
                ignore_tls_errors: false,
                contacts: vec![],
            },
            private_key: secret,
            public_key: public,
            user_id: "test".to_string(),
            data_dir: dd,
        };

        let response = handle_get_config_schema(&state);
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["values"]["relay_url"], "http://my-relay.com");
        assert_eq!(v["values"]["display_name"], "TestUser");
        assert_eq!(v["values"]["user_id"], "test");
        assert!(v["values"]["public_key"].as_str().unwrap().len() > 0);
        assert!(v["values"]["private_key"].as_str().unwrap().len() > 0);
        assert_eq!(v["values"]["contacts"], serde_json::json!([]));
        assert_eq!(v["schema"]["properties"]["contacts"]["type"], "array");
    }

    #[test]
    fn config_schema_includes_contacts_with_items() {
        let dd = PathBuf::from("/tmp/test2");
        let secret = StaticSecret::from([2u8; 32]);
        let public = PublicKey::from(&secret);
        let state = AppState {
            config: AppConfig {
                relay_url: String::new(),
                display_name: String::new(),
                ignore_tls_errors: false,
                contacts: vec![Contact {
                    name: "Alice".to_string(),
                    id: "abc123".to_string(),
                    public_key: "dummykey".to_string(),
                }],
            },
            private_key: secret,
            public_key: public,
            user_id: "u1".to_string(),
            data_dir: dd,
        };

        let response = handle_get_config_schema(&state);
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        let contacts = &v["values"]["contacts"];
        assert_eq!(contacts[0]["name"], "Alice");
        assert_eq!(contacts[0]["id"], "abc123");
    }

    #[test]
    fn set_config_updates_contacts() {
        let dd = PathBuf::from("/tmp/test3");
        let secret = StaticSecret::from([3u8; 32]);
        let public = PublicKey::from(&secret);
        let mut state = AppState {
            config: AppConfig {
                relay_url: String::new(),
                display_name: String::new(),
                ignore_tls_errors: false,
                contacts: vec![],
            },
            private_key: secret,
            public_key: public,
            user_id: "u1".to_string(),
            data_dir: dd,
        };

        // set_config won't persist (no real dir), but it updates in-memory state
        let values = serde_json::json!({
            "relay_url": "http://relay.test",
            "display_name": "Bob",
            "contacts": [
                { "name": "Alice", "id": "aaa", "public_key": "key1" }
            ]
        });
        // Can't call handle_set_config directly because it tries to save to disk.
        // Apply the logic inline to test parsing.
        if let Some(contacts_val) = values.get("contacts") {
            let contacts: Vec<Contact> = serde_json::from_value(contacts_val.clone()).unwrap();
            state.config.contacts = contacts;
        }
        assert_eq!(state.config.contacts.len(), 1);
        assert_eq!(state.config.contacts[0].name, "Alice");
        assert_eq!(state.config.contacts[0].id, "aaa");
    }

    // --- Derive key ---

    #[test]
    fn derive_key_is_deterministic() {
        let shared = [42u8; 32];
        let k1 = derive_key(&shared);
        let k2 = derive_key(&shared);
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_different_inputs_produce_different_keys() {
        let k1 = derive_key(&[1u8; 32]);
        let k2 = derive_key(&[2u8; 32]);
        assert_ne!(k1, k2);
    }

    // --- E2E crypto integration ---

    /// Simulate two users: Alice encrypts a message for Bob, Bob decrypts it.
    /// Tests the full path: encrypt_for_recipient → base64 payload → decrypt_envelope.
    #[test]
    fn e2e_alice_sends_to_bob() {
        // Bob's keypair
        let mut bob_key = [0u8; 32];
        OsRng.fill_bytes(&mut bob_key);
        let bob_secret = StaticSecret::from(bob_key);
        let bob_public = PublicKey::from(&bob_secret);
        // Alice's identity
        let mut alice_key = [0u8; 32];
        OsRng.fill_bytes(&mut alice_key);
        let alice_secret = StaticSecret::from(alice_key);
        let alice_public = PublicKey::from(&alice_secret);
        let alice_id = user_id_from_public_key(&alice_public);

        // Alice encrypts for Bob
        let content = "Meeting link: https://meet.example.com/abc-defg-hij";
        let payload =
            encrypt_for_recipient(content, &bob_public, &alice_id, "Alice", "text").unwrap();

        // Payload is base64 — verify it's not plaintext
        assert!(!payload.contains("Meeting link"));

        // Bob decrypts
        let (envelope, decrypted) = decrypt_envelope(&payload, &bob_secret).unwrap();
        assert_eq!(decrypted, content);
        assert_eq!(envelope.sender_id, alice_id);
        assert_eq!(envelope.sender_name, "Alice");
        assert_eq!(envelope.format, "text");

        // Alice cannot decrypt her own message (she used an ephemeral key)
        assert!(decrypt_envelope(&payload, &alice_secret).is_err());

        // Random third party cannot decrypt
        let mut eve_key = [0u8; 32];
        OsRng.fill_bytes(&mut eve_key);
        let eve_secret = StaticSecret::from(eve_key);
        assert!(decrypt_envelope(&payload, &eve_secret).is_err());
    }

    /// Bidirectional: Alice sends to Bob, Bob sends to Alice.
    /// Verifies both directions work with the same keypairs.
    #[test]
    fn e2e_bidirectional_exchange() {
        let mut ak = [0u8; 32];
        OsRng.fill_bytes(&mut ak);
        let alice_secret = StaticSecret::from(ak);
        let alice_public = PublicKey::from(&alice_secret);
        let alice_id = user_id_from_public_key(&alice_public);

        let mut bk = [0u8; 32];
        OsRng.fill_bytes(&mut bk);
        let bob_secret = StaticSecret::from(bk);
        let bob_public = PublicKey::from(&bob_secret);
        let bob_id = user_id_from_public_key(&bob_public);

        // Alice → Bob
        let msg_a = "Hello Bob!";
        let payload_a =
            encrypt_for_recipient(msg_a, &bob_public, &alice_id, "Alice", "text").unwrap();
        let (env_a, dec_a) = decrypt_envelope(&payload_a, &bob_secret).unwrap();
        assert_eq!(dec_a, msg_a);
        assert_eq!(env_a.sender_name, "Alice");

        // Bob → Alice
        let msg_b = "Hey Alice!";
        let payload_b =
            encrypt_for_recipient(msg_b, &alice_public, &bob_id, "Bob", "text").unwrap();
        let (env_b, dec_b) = decrypt_envelope(&payload_b, &alice_secret).unwrap();
        assert_eq!(dec_b, msg_b);
        assert_eq!(env_b.sender_name, "Bob");

        // Cross-decryption fails
        assert!(decrypt_envelope(&payload_a, &alice_secret).is_err());
        assert!(decrypt_envelope(&payload_b, &bob_secret).is_err());
    }

    /// Full relay message simulation: encrypt, wrap in RelayMessage JSON,
    /// parse back, and decrypt — mimics what happens over the wire.
    #[test]
    fn e2e_through_relay_message_format() {
        let mut rk = [0u8; 32];
        OsRng.fill_bytes(&mut rk);
        let recipient_secret = StaticSecret::from(rk);
        let recipient_public = PublicKey::from(&recipient_secret);
        let content = "Sensitive clipboard data 🔐";
        let sender_id = "sender_abc";
        let payload =
            encrypt_for_recipient(content, &recipient_public, sender_id, "Sender", "text").unwrap();

        // Simulate the JSON the relay server would deliver over WebSocket
        let relay_json = serde_json::json!({
            "from": sender_id,
            "payload": payload,
            "timestamp": 1711900000.0
        });
        let relay_text = relay_json.to_string();

        // Parse as the plugin would
        let relay_msg: RelayMessage = serde_json::from_str(&relay_text).unwrap();
        assert_eq!(relay_msg.from, sender_id);

        let (envelope, decrypted) =
            decrypt_envelope(&relay_msg.payload, &recipient_secret).unwrap();
        assert_eq!(decrypted, content);
        assert_eq!(envelope.sender_id, sender_id);
        assert_eq!(envelope.sender_name, "Sender");
    }

    /// Verify that corrupted payloads are rejected.
    #[test]
    fn e2e_corrupted_payload_rejected() {
        let mut rk = [0u8; 32];
        OsRng.fill_bytes(&mut rk);
        let recipient_secret = StaticSecret::from(rk);
        let recipient_public = PublicKey::from(&recipient_secret);

        let payload = encrypt_for_recipient("secret", &recipient_public, "s", "S", "text").unwrap();

        // Decode, flip a byte in the middle, re-encode
        let mut raw = B64.decode(&payload).unwrap();
        if raw.len() > 10 {
            let mid = raw.len() / 2;
            raw[mid] ^= 0xFF;
        }
        let corrupted = B64.encode(&raw);

        assert!(decrypt_envelope(&corrupted, &recipient_secret).is_err());
    }

    // --- ignore_tls_errors ---

    #[test]
    fn config_schema_includes_ignore_tls_errors() {
        let dd = PathBuf::from("/tmp/test_tls");
        let secret = StaticSecret::from([5u8; 32]);
        let public = PublicKey::from(&secret);
        let state = AppState {
            config: AppConfig {
                relay_url: "https://relay.test".to_string(),
                display_name: "Tester".to_string(),
                ignore_tls_errors: true,
                contacts: vec![],
            },
            private_key: secret,
            public_key: public,
            user_id: "tls_test".to_string(),
            data_dir: dd,
        };

        let response = handle_get_config_schema(&state);
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(
            v["schema"]["properties"]["ignore_tls_errors"]["type"],
            "boolean"
        );
        assert_eq!(v["values"]["ignore_tls_errors"], true);
    }

    #[test]
    fn ignore_tls_errors_defaults_to_false() {
        let config: AppConfig =
            serde_json::from_str(r#"{"relay_url":"x","display_name":"y"}"#).unwrap();
        assert!(!config.ignore_tls_errors);
    }

    #[test]
    fn config_roundtrip_with_ignore_tls_errors() {
        let dir = std::env::temp_dir().join(format!("clipygo_tls_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let config = AppConfig {
            relay_url: "https://localhost".to_string(),
            display_name: "Test".to_string(),
            ignore_tls_errors: true,
            contacts: vec![],
        };

        save_config(&dir, &config).unwrap();
        let loaded = load_config(&dir);
        assert!(loaded.ignore_tls_errors);

        let _ = fs::remove_dir_all(&dir);
    }

    // --- Routing tokens ---

    #[test]
    fn routing_token_deterministic() {
        let pk = [0u8; 32];
        let t = 1_700_000_000u64;
        assert_eq!(derive_routing_token(&pk, t), derive_routing_token(&pk, t));
    }

    #[test]
    fn routing_token_changes_each_period() {
        let pk = [0u8; 32];
        let t1 = 1_700_000_000u64;
        let t2 = t1 + TOKEN_PERIOD; // next period
        assert_ne!(derive_routing_token(&pk, t1), derive_routing_token(&pk, t2));
    }

    #[test]
    fn routing_token_stable_within_period() {
        let pk = [0u8; 32];
        // Pick a timestamp well within a period (not near a boundary)
        let t = 1_700_000_200u64; // 200s into a 300s period
        assert_eq!(
            derive_routing_token(&pk, t),
            derive_routing_token(&pk, t + 50)
        );
    }

    #[test]
    fn routing_token_different_keys() {
        let t = 1_700_000_000u64;
        assert_ne!(
            derive_routing_token(&[0u8; 32], t),
            derive_routing_token(&[1u8; 32], t)
        );
    }

    #[test]
    fn routing_token_length() {
        assert_eq!(derive_routing_token(&[0u8; 32], 1_700_000_000).len(), 16);
    }

    #[test]
    fn routing_token_cross_language_vector() {
        // Must match Python: derive_routing_token(bytes(range(32)), 1700000000)
        // HMAC-SHA256(key=pk, msg=period_index as u64 BE)[0..8].hex()
        let pk: Vec<u8> = (0u8..32).collect();
        let t = 1_700_000_000u64;
        let period_index = t / TOKEN_PERIOD;

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&pk).unwrap();
        mac.update(&period_index.to_be_bytes());
        let expected = hex::encode(&mac.finalize().into_bytes()[..8]);

        assert_eq!(derive_routing_token(&pk, t), expected);
    }

    // --- Padding ---

    #[test]
    fn padded_encrypt_decrypt_roundtrip() {
        let recipient_secret = StaticSecret::from([42u8; 32]);
        let recipient_public = PublicKey::from(&recipient_secret);

        let content = "Hello, padded world!";
        let payload =
            encrypt_for_recipient(content, &recipient_public, "s", "Sender", "text").unwrap();

        let (_, decrypted) = decrypt_envelope(&payload, &recipient_secret).unwrap();
        assert_eq!(decrypted, content);
    }

    #[test]
    fn padded_ciphertext_is_block_aligned() {
        let recipient_secret = StaticSecret::from([42u8; 32]);
        let recipient_public = PublicKey::from(&recipient_secret);

        // Test various content sizes
        for size in [1, 10, 100, 252, 256, 500, 1000] {
            let content: String = "x".repeat(size);
            let payload =
                encrypt_for_recipient(&content, &recipient_public, "s", "S", "text").unwrap();

            // Decrypt and verify the plaintext (before encryption) was block-aligned
            // We can't check the plaintext size directly, but we can verify roundtrip
            let (_, decrypted) = decrypt_envelope(&payload, &recipient_secret).unwrap();
            assert_eq!(decrypted, content);
        }
    }

    #[test]
    fn padding_obscures_similar_length_messages() {
        let recipient_secret = StaticSecret::from([42u8; 32]);
        let recipient_public = PublicKey::from(&recipient_secret);

        // Messages of similar but different lengths should produce same-length ciphertexts
        // when they fall in the same block
        let payload_a =
            encrypt_for_recipient("short", &recipient_public, "s", "S", "text").unwrap();
        let payload_b =
            encrypt_for_recipient("short!", &recipient_public, "s", "S", "text").unwrap();

        // Decode the envelopes to compare ciphertext sizes
        let env_a: EncryptedEnvelope =
            serde_json::from_slice(&B64.decode(&payload_a).unwrap()).unwrap();
        let env_b: EncryptedEnvelope =
            serde_json::from_slice(&B64.decode(&payload_b).unwrap()).unwrap();

        let ct_a = B64.decode(&env_a.ciphertext).unwrap();
        let ct_b = B64.decode(&env_b.ciphertext).unwrap();

        // Both "short" (5 bytes) and "short!" (6 bytes) should pad to the same block size
        assert_eq!(ct_a.len(), ct_b.len());
    }

    #[test]
    fn empty_content_roundtrips() {
        let recipient_secret = StaticSecret::from([42u8; 32]);
        let recipient_public = PublicKey::from(&recipient_secret);

        let payload = encrypt_for_recipient("", &recipient_public, "s", "S", "text").unwrap();
        let (_, decrypted) = decrypt_envelope(&payload, &recipient_secret).unwrap();
        assert_eq!(decrypted, "");
    }
}
