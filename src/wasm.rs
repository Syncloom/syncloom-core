//! WebAssembly exports for the browser app. Everything cryptographic that the web UI needs lives here so
//! the browser, the server and all native clients agree bit for bit. Structured data crosses the
//! boundary as JSON strings; keys and blobs as base64url strings or byte arrays.
use crate::{b64, chunking, crypto, names, node, vault};
use wasm_bindgen::prelude::*;

fn js<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

fn key(s: &str) -> Result<crypto::Key, JsError> {
    crypto::key_from_slice(&b64::decode(s).map_err(js)?).map_err(js)
}

fn k64(k: &crypto::Key) -> String {
    b64::encode(k)
}

#[wasm_bindgen(start)]
pub fn init() {}

// ---------- vault ----------

/// Returns JSON: `{ bundle, recovery_key, auth_secret, master, secret }`.
#[wasm_bindgen]
pub fn vault_create(password: &str) -> Result<String, JsError> {
    let c = vault::Vault::create(password, vault::KdfParams::new()).map_err(js)?;
    let (master, secret) = c.vault.export_secrets();
    Ok(serde_json::json!({
        "bundle": c.bundle, "recovery_key": c.recovery_key, "auth_secret": c.auth_secret,
        "master": k64(&master), "secret": k64(&secret),
    })
    .to_string())
}

/// The value sent to the server instead of the password. `kdf_json` comes from `/auth/prelogin`.
#[wasm_bindgen]
pub fn auth_secret(password: &str, kdf_json: &str) -> Result<String, JsError> {
    let kdf: vault::KdfParams = serde_json::from_str(kdf_json).map_err(js)?;
    vault::auth_secret(password, &kdf).map_err(js)
}

/// Returns JSON `{ master, secret }`.
#[wasm_bindgen]
pub fn vault_unlock(password: &str, bundle_json: &str) -> Result<String, JsError> {
    let b: vault::VaultBundle = serde_json::from_str(bundle_json).map_err(js)?;
    let v = vault::Vault::unlock(password, &b).map_err(js)?;
    let (m, s) = v.export_secrets();
    Ok(serde_json::json!({ "master": k64(&m), "secret": k64(&s) }).to_string())
}

#[wasm_bindgen]
pub fn vault_unlock_recovery(recovery_key: &str, bundle_json: &str) -> Result<String, JsError> {
    let b: vault::VaultBundle = serde_json::from_str(bundle_json).map_err(js)?;
    let v = vault::Vault::unlock_with_recovery(recovery_key, &b).map_err(js)?;
    let (m, s) = v.export_secrets();
    Ok(serde_json::json!({ "master": k64(&m), "secret": k64(&s) }).to_string())
}

/// Returns JSON `{ bundle, auth_secret }` with the master key re-wrapped under the new password.
#[wasm_bindgen]
pub fn vault_change_password(master: &str, secret: &str, bundle_json: &str, new_password: &str) -> Result<String, JsError> {
    let b: vault::VaultBundle = serde_json::from_str(bundle_json).map_err(js)?;
    let v = vault::Vault::from_secrets(key(master)?, key(secret)?);
    let (nb, auth) = v.change_password(&b, new_password, vault::KdfParams::new()).map_err(js)?;
    Ok(serde_json::json!({ "bundle": nb, "auth_secret": auth }).to_string())
}

// ---------- node keys, names, metadata ----------

#[wasm_bindgen]
pub fn new_uuid() -> String {
    crypto::new_uuid()
}

#[wasm_bindgen]
pub fn new_key() -> String {
    k64(&crypto::random_key())
}

#[wasm_bindgen]
pub fn wrap_node_key(parent_key: &str, node_id: &str, node_key: &str) -> Result<String, JsError> {
    Ok(b64::encode(&node::wrap_node_key(&key(parent_key)?, node_id, &key(node_key)?).map_err(js)?))
}

#[wasm_bindgen]
pub fn unwrap_node_key(parent_key: &str, node_id: &str, wrapped: &str) -> Result<String, JsError> {
    let w = b64::decode(wrapped).map_err(js)?;
    Ok(k64(&node::unwrap_node_key(&key(parent_key)?, node_id, &w).map_err(js)?))
}

#[wasm_bindgen]
pub fn encrypt_name(node_key: &str, node_id: &str, name: &str) -> Result<String, JsError> {
    Ok(b64::encode(&node::encrypt_name(&key(node_key)?, node_id, name).map_err(js)?))
}

#[wasm_bindgen]
pub fn decrypt_name(node_key: &str, node_id: &str, enc: &str) -> Result<String, JsError> {
    node::decrypt_name(&key(node_key)?, node_id, &b64::decode(enc).map_err(js)?).map_err(js)
}

#[wasm_bindgen]
pub fn encrypt_meta(node_key: &str, node_id: &str, meta_json: &str) -> Result<String, JsError> {
    let m: node::NodeMeta = serde_json::from_str(meta_json).map_err(js)?;
    Ok(b64::encode(&node::encrypt_meta(&key(node_key)?, node_id, &m).map_err(js)?))
}

#[wasm_bindgen]
pub fn decrypt_meta(node_key: &str, node_id: &str, enc: &str) -> Result<String, JsError> {
    let m = node::decrypt_meta(&key(node_key)?, node_id, &b64::decode(enc).map_err(js)?).map_err(js)?;
    serde_json::to_string(&m).map_err(js)
}

#[wasm_bindgen]
pub fn validate_name(name: &str) -> Result<(), JsError> {
    names::validate(name).map_err(js)
}

#[wasm_bindgen]
pub fn normalize_name(name: &str) -> String {
    names::normalize(name)
}

#[wasm_bindgen]
pub fn collision_key(name: &str) -> String {
    names::collision_key(name)
}

// ---------- file content ----------

/// Chunk and encrypt one block of a file. JSON result: `[{ "hash": "...", "len": n }, ...]`; the
/// ciphertexts are returned through `take_chunk`. Process big files block by block (e.g. 16 MiB).
#[wasm_bindgen]
pub struct BlockEncryptor {
    key: crypto::Key,
    node_id: String,
    pending: Vec<chunking::EncryptedChunk>,
    content: blake3::Hasher,
    manifest: chunking::Manifest,
}

#[wasm_bindgen]
impl BlockEncryptor {
    #[wasm_bindgen(constructor)]
    pub fn new(node_key: &str, node_id: &str) -> Result<BlockEncryptor, JsError> {
        Ok(BlockEncryptor { key: key(node_key)?, node_id: node_id.into(), pending: vec![], content: blake3::Hasher::new(), manifest: Default::default() })
    }

    /// Returns the number of chunks produced for this block.
    pub fn push_block(&mut self, data: &[u8]) -> Result<usize, JsError> {
        self.content.update(data);
        let mut produced = 0;
        let node_id = self.node_id.clone();
        let m = chunking::encrypt_reader(&self.key, &node_id, data, |c| {
            self.pending.push(c);
            produced += 1;
            Ok(())
        })
        .map_err(js)?;
        self.manifest.size += m.size;
        self.manifest.chunks.extend(m.chunks);
        Ok(produced)
    }

    /// Hash of the next ready chunk, or an empty string when none is left.
    pub fn next_hash(&self) -> String {
        self.pending.first().map(|c| c.hash.clone()).unwrap_or_default()
    }

    /// Ciphertext of the next ready chunk (removes it from the queue).
    pub fn take_chunk(&mut self) -> Vec<u8> {
        if self.pending.is_empty() {
            return vec![];
        }
        self.pending.remove(0).data
    }

    /// Finish: returns JSON `{ manifest (sealed, base64url), size, chunks: [hashes] }`.
    pub fn finish(&mut self) -> Result<String, JsError> {
        self.manifest.content_hash = self.content.finalize().to_hex().to_string();
        let sealed = chunking::seal_manifest(&self.key, &self.node_id, &self.manifest).map_err(js)?;
        Ok(serde_json::json!({
            "manifest": b64::encode(&sealed),
            "size": self.manifest.size,
            "chunks": self.manifest.chunks.iter().map(|c| c.hash.clone()).collect::<Vec<_>>(),
            "content_hash": self.manifest.content_hash,
        })
        .to_string())
    }
}

/// Returns JSON of the manifest: `{ size, content_hash, chunks: [{hash, len}] }`.
#[wasm_bindgen]
pub fn open_manifest(node_key: &str, node_id: &str, sealed: &str) -> Result<String, JsError> {
    let m = chunking::open_manifest(&key(node_key)?, node_id, &b64::decode(sealed).map_err(js)?).map_err(js)?;
    serde_json::to_string(&m).map_err(js)
}

#[wasm_bindgen]
pub fn decrypt_chunk(node_key: &str, node_id: &str, ciphertext: &[u8], hash: &str) -> Result<Vec<u8>, JsError> {
    chunking::decrypt_chunk(&key(node_key)?, node_id, ciphertext, hash).map_err(js)
}

/// Incremental BLAKE3 over decrypted content, to verify `content_hash` after a download.
#[wasm_bindgen]
pub struct ContentHasher(blake3::Hasher);

#[wasm_bindgen]
impl ContentHasher {
    #[wasm_bindgen(constructor)]
    pub fn new() -> ContentHasher {
        ContentHasher(blake3::Hasher::new())
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    pub fn finalize(&self) -> String {
        self.0.finalize().to_hex().to_string()
    }
}

impl Default for ContentHasher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------- key/value ----------

#[wasm_bindgen]
pub fn encrypt_kv(ns_key: &str, ns_id: &str, kv_key: &str, value: &[u8]) -> Result<String, JsError> {
    Ok(b64::encode(&node::encrypt_kv(&key(ns_key)?, ns_id, kv_key, value).map_err(js)?))
}

#[wasm_bindgen]
pub fn decrypt_kv(ns_key: &str, ns_id: &str, kv_key: &str, enc: &str) -> Result<Vec<u8>, JsError> {
    node::decrypt_kv(&key(ns_key)?, ns_id, kv_key, &b64::decode(enc).map_err(js)?).map_err(js)
}

// ---------- sharing ----------

#[wasm_bindgen]
pub fn share_key_with(recipient_public: &str, node_key: &str, node_id: &str) -> Result<String, JsError> {
    let pk = b64::decode(recipient_public).map_err(js)?;
    Ok(b64::encode(&vault::share_key_with(&pk, &key(node_key)?, node_id).map_err(js)?))
}

#[wasm_bindgen]
pub fn open_shared_key(master: &str, secret: &str, sealed: &str, node_id: &str) -> Result<String, JsError> {
    let v = vault::Vault::from_secrets(key(master)?, key(secret)?);
    Ok(k64(&v.open_shared_key(&b64::decode(sealed).map_err(js)?, node_id).map_err(js)?))
}

/// Link envelope: the node key encrypted with a fresh link key. Returns JSON `{ link_key, envelope }`.
#[wasm_bindgen]
pub fn make_link_envelope(node_key: &str, node_id: &str) -> Result<String, JsError> {
    let lk = crypto::random_key();
    let env = crypto::seal(&lk, &key(node_key)?, format!("syncloom/link/{node_id}").as_bytes()).map_err(js)?;
    Ok(serde_json::json!({ "link_key": k64(&lk), "envelope": b64::encode(&env) }).to_string())
}

#[wasm_bindgen]
pub fn open_link_envelope(link_key: &str, node_id: &str, envelope: &str) -> Result<String, JsError> {
    let k = crypto::open(&key(link_key)?, &b64::decode(envelope).map_err(js)?, format!("syncloom/link/{node_id}").as_bytes()).map_err(js)?;
    Ok(b64::encode(&k))
}
