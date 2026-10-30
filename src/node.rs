//! Node-level encryption helpers: names, metadata, key wrapping along the tree.
use crate::crypto::{self, Key};
use crate::error::Result;
use serde::{Deserialize, Serialize};

/// Encrypted alongside the name; extensible without a server change.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct NodeMeta {
    /// Last modification time of the file content, milliseconds since epoch.
    #[serde(default)]
    pub mtime_ms: i64,
    #[serde(default)]
    pub executable: bool,
}

fn aad(kind: &str, node_id: &str) -> Vec<u8> {
    format!("syncloom/{kind}/{node_id}").into_bytes()
}

pub fn encrypt_name(node_key: &Key, node_id: &str, name: &str) -> Result<Vec<u8>> {
    crypto::seal(node_key, crate::names::normalize(name).as_bytes(), &aad("name", node_id))
}
pub fn decrypt_name(node_key: &Key, node_id: &str, blob: &[u8]) -> Result<String> {
    String::from_utf8(crypto::open(node_key, blob, &aad("name", node_id))?)
        .map_err(|_| crate::error::Error::Crypto("name is not utf-8".into()))
}
pub fn encrypt_meta(node_key: &Key, node_id: &str, meta: &NodeMeta) -> Result<Vec<u8>> {
    crypto::seal(node_key, &serde_json::to_vec(meta)?, &aad("meta", node_id))
}
pub fn decrypt_meta(node_key: &Key, node_id: &str, blob: &[u8]) -> Result<NodeMeta> {
    Ok(serde_json::from_slice(&crypto::open(node_key, blob, &aad("meta", node_id))?)?)
}
/// Wrap a node's key under its parent's key (or the master key for root nodes).
pub fn wrap_node_key(parent_key: &Key, node_id: &str, node_key: &Key) -> Result<Vec<u8>> {
    crypto::wrap_key(parent_key, node_key, &aad("key", node_id))
}
pub fn unwrap_node_key(parent_key: &Key, node_id: &str, wrapped: &[u8]) -> Result<Key> {
    crypto::unwrap_key(parent_key, wrapped, &aad("key", node_id))
}

/// KV values are sealed with the namespace node key; the key name is bound as AAD.
pub fn encrypt_kv(ns_key: &Key, ns_id: &str, key: &str, value: &[u8]) -> Result<Vec<u8>> {
    crypto::seal(ns_key, value, format!("syncloom/kv/{ns_id}/{key}").as_bytes())
}
pub fn decrypt_kv(ns_key: &Key, ns_id: &str, key: &str, blob: &[u8]) -> Result<Vec<u8>> {
    crypto::open(ns_key, blob, format!("syncloom/kv/{ns_id}/{key}").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_bound_to_node() {
        let k = crypto::random_key();
        let blob = encrypt_name(&k, "n1", "e\u{0301}.txt").unwrap();
        assert_eq!(decrypt_name(&k, "n1", &blob).unwrap(), "\u{e9}.txt");
        assert!(decrypt_name(&k, "n2", &blob).is_err());
    }
    #[test]
    fn kv_bound_to_key() {
        let k = crypto::random_key();
        let blob = encrypt_kv(&k, "ns", "a", b"v").unwrap();
        assert_eq!(decrypt_kv(&k, "ns", "a", &blob).unwrap(), b"v");
        assert!(decrypt_kv(&k, "ns", "b", &blob).is_err());
    }
    #[test]
    fn key_wrapping_chain() {
        let master = crypto::random_key();
        let folder = crypto::random_key();
        let w = wrap_node_key(&master, "f", &folder).unwrap();
        assert_eq!(unwrap_node_key(&master, "f", &w).unwrap(), folder);
        assert!(unwrap_node_key(&master, "g", &w).is_err());
    }
}
