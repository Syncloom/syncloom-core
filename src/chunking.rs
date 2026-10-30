//! Content-defined chunking (FastCDC) + per-chunk encryption.
//!
//! A chunk's identity is the BLAKE3 hash of its *ciphertext*, so the server can verify
//! uploads and de-duplicate identical chunks without learning anything about plaintext.
use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use fastcdc::v2020::StreamCDC;
use serde::{Deserialize, Serialize};
use std::io::Read;

pub const MIN_CHUNK: u32 = 64 * 1024;
pub const AVG_CHUNK: u32 = 256 * 1024;
pub const MAX_CHUNK: u32 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChunkRef {
    /// BLAKE3 of the ciphertext, hex.
    pub hash: String,
    /// Plaintext length.
    pub len: u32,
}

/// Describes one file version. Stored sealed (encrypted) on the server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Manifest {
    pub size: u64,
    /// BLAKE3 of the plaintext, hex. Lets clients detect local changes and no-op uploads.
    pub content_hash: String,
    pub chunks: Vec<ChunkRef>,
}

pub struct EncryptedChunk {
    pub hash: String,
    pub data: Vec<u8>,
}

fn chunk_aad(node_id: &str) -> Vec<u8> {
    format!("syncloom/chunk/{node_id}").into_bytes()
}
fn manifest_aad(node_id: &str) -> Vec<u8> {
    format!("syncloom/manifest/{node_id}").into_bytes()
}

pub fn hash_ciphertext(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Chunk + encrypt everything from `reader`, calling `sink` for each encrypted chunk.
pub fn encrypt_reader<R: Read>(
    key: &Key,
    node_id: &str,
    reader: R,
    mut sink: impl FnMut(EncryptedChunk) -> Result<()>,
) -> Result<Manifest> {
    let aad = chunk_aad(node_id);
    let mut manifest = Manifest::default();
    let mut content = blake3::Hasher::new();
    for chunk in StreamCDC::new(reader, MIN_CHUNK, AVG_CHUNK, MAX_CHUNK) {
        let chunk = chunk.map_err(|e| Error::Io(e.to_string()))?;
        content.update(&chunk.data);
        let ct = crypto::seal(key, &chunk.data, &aad)?;
        let hash = hash_ciphertext(&ct);
        manifest.size += chunk.data.len() as u64;
        manifest.chunks.push(ChunkRef { hash: hash.clone(), len: chunk.data.len() as u32 });
        sink(EncryptedChunk { hash, data: ct })?;
    }
    manifest.content_hash = content.finalize().to_hex().to_string();
    Ok(manifest)
}

pub fn encrypt_bytes(key: &Key, node_id: &str, data: &[u8]) -> Result<(Manifest, Vec<EncryptedChunk>)> {
    let mut out = Vec::new();
    let m = encrypt_reader(key, node_id, data, |c| {
        out.push(c);
        Ok(())
    })?;
    Ok((m, out))
}

pub fn decrypt_chunk(key: &Key, node_id: &str, ciphertext: &[u8], expected_hash: &str) -> Result<Vec<u8>> {
    if hash_ciphertext(ciphertext) != expected_hash {
        return Err(Error::Crypto("chunk hash mismatch".into()));
    }
    crypto::open(key, ciphertext, &chunk_aad(node_id))
}

pub fn seal_manifest(key: &Key, node_id: &str, m: &Manifest) -> Result<Vec<u8>> {
    crypto::seal(key, &serde_json::to_vec(m)?, &manifest_aad(node_id))
}

pub fn open_manifest(key: &Key, node_id: &str, blob: &[u8]) -> Result<Manifest> {
    Ok(serde_json::from_slice(&crypto::open(key, blob, &manifest_aad(node_id))?)?)
}

pub fn content_hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudo_random(n: usize) -> Vec<u8> {
        let mut x = 0x1234_5678_9abc_def0u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn roundtrip_multi_chunk() {
        let key = crypto::random_key();
        let data = pseudo_random(3 * 1024 * 1024 + 123);
        let (m, chunks) = encrypt_bytes(&key, "n1", &data).unwrap();
        assert!(chunks.len() > 2);
        assert_eq!(m.size, data.len() as u64);
        assert_eq!(m.content_hash, content_hash(&data));
        let mut out = Vec::new();
        for (c, r) in chunks.iter().zip(&m.chunks) {
            assert_eq!(c.hash, r.hash);
            out.extend(decrypt_chunk(&key, "n1", &c.data, &r.hash).unwrap());
        }
        assert_eq!(out, data);
    }

    #[test]
    fn small_edit_reuses_most_chunks_in_plaintext_boundaries() {
        // Boundaries are content-defined, so inserting bytes at the front keeps later boundaries.
        let key = crypto::random_key();
        let data = pseudo_random(2 * 1024 * 1024);
        let mut edited = b"prefix".to_vec();
        edited.extend_from_slice(&data);
        let (m1, _) = encrypt_bytes(&key, "n", &data).unwrap();
        let (m2, _) = encrypt_bytes(&key, "n", &edited).unwrap();
        let l1: Vec<u32> = m1.chunks.iter().map(|c| c.len).collect();
        let l2: Vec<u32> = m2.chunks.iter().map(|c| c.len).collect();
        let shared = l1.iter().filter(|l| l2.contains(l)).count();
        assert!(shared >= l1.len() - 2, "{shared} of {}", l1.len());
    }

    #[test]
    fn wrong_node_or_hash_fails() {
        let key = crypto::random_key();
        let (m, c) = encrypt_bytes(&key, "n1", b"hello world").unwrap();
        assert!(decrypt_chunk(&key, "n2", &c[0].data, &m.chunks[0].hash).is_err());
        assert!(decrypt_chunk(&key, "n1", &c[0].data, "deadbeef").is_err());
    }

    #[test]
    fn empty_file() {
        let key = crypto::random_key();
        let (m, c) = encrypt_bytes(&key, "n", b"").unwrap();
        assert_eq!(m.size, 0);
        assert!(c.is_empty());
    }

    #[test]
    fn manifest_seal() {
        let key = crypto::random_key();
        let (m, _) = encrypt_bytes(&key, "n", b"abc").unwrap();
        let blob = seal_manifest(&key, "n", &m).unwrap();
        assert_eq!(open_manifest(&key, "n", &blob).unwrap(), m);
        assert!(open_manifest(&key, "other", &blob).is_err());
    }
}

/// Pull-style variant of [`encrypt_reader`] so async callers can upload chunks as they are produced
/// without holding the whole file in memory.
pub struct ChunkEncryptor<R: Read> {
    inner: StreamCDC<R>,
    key: Key,
    aad: Vec<u8>,
    manifest: Manifest,
    content: blake3::Hasher,
}

impl<R: Read> ChunkEncryptor<R> {
    pub fn new(key: &Key, node_id: &str, reader: R) -> Self {
        ChunkEncryptor {
            inner: StreamCDC::new(reader, MIN_CHUNK, AVG_CHUNK, MAX_CHUNK),
            key: *key,
            aad: chunk_aad(node_id),
            manifest: Manifest::default(),
            content: blake3::Hasher::new(),
        }
    }

    pub fn next_chunk(&mut self) -> Result<Option<EncryptedChunk>> {
        match self.inner.next() {
            None => Ok(None),
            Some(Err(e)) => Err(Error::Io(e.to_string())),
            Some(Ok(chunk)) => {
                self.content.update(&chunk.data);
                let ct = crypto::seal(&self.key, &chunk.data, &self.aad)?;
                let hash = hash_ciphertext(&ct);
                self.manifest.size += chunk.data.len() as u64;
                self.manifest.chunks.push(ChunkRef { hash: hash.clone(), len: chunk.data.len() as u32 });
                Ok(Some(EncryptedChunk { hash, data: ct }))
            }
        }
    }

    /// Call after `next_chunk` returned `None`.
    pub fn finish(mut self) -> Manifest {
        self.manifest.content_hash = self.content.finalize().to_hex().to_string();
        self.manifest
    }
}
