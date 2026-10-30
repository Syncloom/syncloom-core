//! Primitive operations: XChaCha20-Poly1305 sealing, X25519 sealed boxes.
use crate::error::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub type Key = [u8; 32];
const NONCE_LEN: usize = 24;

pub fn random_key() -> Key {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

/// Returns `nonce || ciphertext`.
pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto("encryption failed".into()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(key: &Key, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + 16 {
        return Err(Error::Crypto("ciphertext too short".into()));
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::Crypto("decryption failed (wrong key or corrupted data)".into()))
}

pub fn key_from_slice(b: &[u8]) -> Result<Key> {
    b.try_into().map_err(|_| Error::Crypto("key must be 32 bytes".into()))
}

pub fn wrap_key(parent: &Key, key: &Key, aad: &[u8]) -> Result<Vec<u8>> {
    seal(parent, key, aad)
}

pub fn unwrap_key(parent: &Key, wrapped: &[u8], aad: &[u8]) -> Result<Key> {
    key_from_slice(&open(parent, wrapped, aad)?)
}

fn sealed_box_key(shared: &[u8], eph_pub: &[u8], recipient: &[u8]) -> Result<Key> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph_pub);
    salt.extend_from_slice(recipient);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut out = [0u8; 32];
    hk.expand(b"syncloom-sealed-box-v1", &mut out)
        .map_err(|_| Error::Crypto("hkdf".into()))?;
    Ok(out)
}

/// Encrypt `data` so that only the holder of the private key for `recipient` can read it.
/// Output: `ephemeral_public(32) || sealed`.
pub fn seal_to_public(recipient: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let eph = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient));
    let key = sealed_box_key(shared.as_bytes(), eph_pub.as_bytes(), recipient)?;
    let mut out = eph_pub.as_bytes().to_vec();
    out.extend(seal(&key, data, aad)?);
    Ok(out)
}

pub fn open_sealed(secret: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 32 {
        return Err(Error::Crypto("sealed box too short".into()));
    }
    let (eph_pub, sealed) = blob.split_at(32);
    let sk = StaticSecret::from(*secret);
    let my_pub = PublicKey::from(&sk);
    let eph: [u8; 32] = eph_pub.try_into().unwrap();
    let shared = sk.diffie_hellman(&PublicKey::from(eph));
    let key = sealed_box_key(shared.as_bytes(), eph_pub, my_pub.as_bytes())?;
    open(&key, sealed, aad)
}

pub fn new_keypair() -> ([u8; 32], [u8; 32]) {
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);
    (sk.to_bytes(), *pk.as_bytes())
}

pub fn public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(*secret)).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_and_tamper() {
        let k = random_key();
        let ct = seal(&k, b"hello", b"aad").unwrap();
        assert_eq!(open(&k, &ct, b"aad").unwrap(), b"hello");
        assert!(open(&k, &ct, b"other").is_err());
        let mut bad = ct.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&k, &bad, b"aad").is_err());
        assert!(open(&random_key(), &ct, b"aad").is_err());
    }

    #[test]
    fn sealed_box_roundtrip() {
        let (sk, pk) = new_keypair();
        let blob = seal_to_public(&pk, b"secret key", b"share").unwrap();
        assert_eq!(open_sealed(&sk, &blob, b"share").unwrap(), b"secret key");
        let (sk2, _) = new_keypair();
        assert!(open_sealed(&sk2, &blob, b"share").is_err());
    }
}

/// Random (v4) UUID in canonical form, without needing a uuid dependency.
pub fn new_uuid() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}
