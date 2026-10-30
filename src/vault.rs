//! The per-user vault: password-derived keys, master key, recovery key, key pair.
//!
//! The password is stretched with Argon2id into 64 bytes. The first half is the
//! *auth secret* sent to the server (which stores only a hash of it); the second half is
//! the key-encryption key that wraps the master key and never leaves the client.
use crate::b64;
use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KdfParams {
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    pub fn new() -> Self {
        KdfParams { salt: crypto::random_bytes(16), m_kib: 64 * 1024, t: 3, p: 1 }
    }
    /// Cheap parameters, for tests only.
    pub fn fast_for_tests() -> Self {
        KdfParams { salt: crypto::random_bytes(16), m_kib: 8, t: 1, p: 1 }
    }
    /// Deterministic fake parameters returned for unknown users, so that
    /// `prelogin` does not reveal which usernames exist.
    pub fn fake_for(username: &str, secret: &[u8]) -> Self {
        let mut h = blake3::Hasher::new_keyed(&blake3::hash(secret).into());
        h.update(username.as_bytes());
        let salt = h.finalize().as_bytes()[..16].to_vec();
        KdfParams { salt, m_kib: 64 * 1024, t: 3, p: 1 }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::new()
    }
}

/// Everything the server stores for a vault. All fields are ciphertext or public.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultBundle {
    pub kdf: KdfParams,
    #[serde(with = "b64")]
    pub wrapped_master_pw: Vec<u8>,
    #[serde(with = "b64")]
    pub wrapped_master_recovery: Vec<u8>,
    #[serde(with = "b64")]
    pub public_key: Vec<u8>,
    #[serde(with = "b64")]
    pub wrapped_private_key: Vec<u8>,
}

pub struct Vault {
    master: Key,
    secret: [u8; 32],
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.master.zeroize();
        self.secret.zeroize();
    }
}

fn stretch(password: &str, kdf: &KdfParams) -> Result<([u8; 32], [u8; 32])> {
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(64))
        .map_err(|e| Error::Crypto(format!("bad kdf params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 64];
    argon
        .hash_password_into(password.as_bytes(), &kdf.salt, &mut out)
        .map_err(|e| Error::Crypto(format!("kdf failed: {e}")))?;
    let mut auth = [0u8; 32];
    let mut kek = [0u8; 32];
    auth.copy_from_slice(&out[..32]);
    kek.copy_from_slice(&out[32..]);
    out.zeroize();
    Ok((auth, kek))
}

/// The value sent to the server in place of the password.
pub fn auth_secret(password: &str, kdf: &KdfParams) -> Result<String> {
    let (auth, mut kek) = stretch(password, kdf)?;
    kek.zeroize();
    Ok(b64::encode(&auth))
}

pub fn format_recovery_key(key: &Key) -> String {
    hex::encode_upper(key)
        .as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn parse_recovery_key(s: &str) -> Result<Key> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let bytes = hex::decode(cleaned).map_err(|_| Error::Invalid("bad recovery key".into()))?;
    crypto::key_from_slice(&bytes).map_err(|_| Error::Invalid("bad recovery key length".into()))
}

const AAD_PW: &[u8] = b"syncloom/vault/master/pw";
const AAD_RECOVERY: &[u8] = b"syncloom/vault/master/recovery";
const AAD_PRIVATE: &[u8] = b"syncloom/vault/private-key";

pub struct CreatedVault {
    pub vault: Vault,
    pub bundle: VaultBundle,
    pub recovery_key: String,
    pub auth_secret: String,
}

impl Vault {
    pub fn create(password: &str, kdf: KdfParams) -> Result<CreatedVault> {
        let (auth, kek) = stretch(password, &kdf)?;
        let master = crypto::random_key();
        let recovery = crypto::random_key();
        let (secret, public) = crypto::new_keypair();
        let bundle = VaultBundle {
            wrapped_master_pw: crypto::seal(&kek, &master, AAD_PW)?,
            wrapped_master_recovery: crypto::seal(&recovery, &master, AAD_RECOVERY)?,
            public_key: public.to_vec(),
            wrapped_private_key: crypto::seal(&master, &secret, AAD_PRIVATE)?,
            kdf,
        };
        Ok(CreatedVault {
            vault: Vault { master, secret },
            bundle,
            recovery_key: format_recovery_key(&recovery),
            auth_secret: b64::encode(&auth),
        })
    }

    fn from_master(master: Key, bundle: &VaultBundle) -> Result<Vault> {
        let secret = crypto::key_from_slice(&crypto::open(&master, &bundle.wrapped_private_key, AAD_PRIVATE)?)?;
        if crypto::public_from_secret(&secret).as_slice() != bundle.public_key.as_slice() {
            return Err(Error::Crypto("vault public key mismatch".into()));
        }
        Ok(Vault { master, secret })
    }

    pub fn unlock(password: &str, bundle: &VaultBundle) -> Result<Vault> {
        let (_, kek) = stretch(password, &bundle.kdf)?;
        let master = crypto::key_from_slice(
            &crypto::open(&kek, &bundle.wrapped_master_pw, AAD_PW)
                .map_err(|_| Error::Auth("wrong password".into()))?,
        )?;
        Self::from_master(master, bundle)
    }

    pub fn unlock_with_recovery(recovery_key: &str, bundle: &VaultBundle) -> Result<Vault> {
        let rk = parse_recovery_key(recovery_key)?;
        let master = crypto::key_from_slice(
            &crypto::open(&rk, &bundle.wrapped_master_recovery, AAD_RECOVERY)
                .map_err(|_| Error::Auth("wrong recovery key".into()))?,
        )?;
        Self::from_master(master, bundle)
    }

    /// Re-wrap the master key under a new password. Returns the new bundle and auth secret.
    pub fn change_password(&self, bundle: &VaultBundle, new_password: &str, kdf: KdfParams) -> Result<(VaultBundle, String)> {
        let (auth, kek) = stretch(new_password, &kdf)?;
        let mut nb = bundle.clone();
        nb.wrapped_master_pw = crypto::seal(&kek, &self.master, AAD_PW)?;
        nb.kdf = kdf;
        Ok((nb, b64::encode(&auth)))
    }

    pub fn public_key(&self) -> [u8; 32] {
        crypto::public_from_secret(&self.secret)
    }
    pub fn secret_key(&self) -> [u8; 32] {
        self.secret
    }

    /// The key that wraps root-level nodes.
    pub fn master_key(&self) -> &Key {
        &self.master
    }

    /// Open a key that was shared with us (sealed to our public key).
    pub fn open_shared_key(&self, sealed: &[u8], node_id: &str) -> Result<Key> {
        crypto::key_from_slice(&crypto::open_sealed(&self.secret, sealed, share_aad(node_id).as_slice())?)
    }

    pub fn export_secrets(&self) -> (Key, [u8; 32]) {
        (self.master, self.secret)
    }
    pub fn from_secrets(master: Key, secret: [u8; 32]) -> Vault {
        Vault { master, secret }
    }
}

pub fn share_aad(node_id: &str) -> Vec<u8> {
    format!("syncloom/share/{node_id}").into_bytes()
}

/// Seal a node key for another user's public key.
pub fn share_key_with(recipient_public: &[u8], key: &Key, node_id: &str) -> Result<Vec<u8>> {
    let pk: [u8; 32] = recipient_public.try_into().map_err(|_| Error::Crypto("bad public key".into()))?;
    crypto::seal_to_public(&pk, key, &share_aad(node_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_unlock_recover_change() {
        let c = Vault::create("hunter2", KdfParams::fast_for_tests()).unwrap();
        let v2 = Vault::unlock("hunter2", &c.bundle).unwrap();
        assert_eq!(v2.master_key(), c.vault.master_key());
        assert!(Vault::unlock("wrong", &c.bundle).is_err());
        let v3 = Vault::unlock_with_recovery(&c.recovery_key, &c.bundle).unwrap();
        assert_eq!(v3.master_key(), c.vault.master_key());
        assert_eq!(auth_secret("hunter2", &c.bundle.kdf).unwrap(), c.auth_secret);

        let (nb, new_auth) = c.vault.change_password(&c.bundle, "new pw", KdfParams::fast_for_tests()).unwrap();
        assert!(Vault::unlock("hunter2", &nb).is_err());
        assert_eq!(Vault::unlock("new pw", &nb).unwrap().master_key(), c.vault.master_key());
        assert_eq!(auth_secret("new pw", &nb.kdf).unwrap(), new_auth);
        assert_ne!(new_auth, c.auth_secret);
    }

    #[test]
    fn share_between_users() {
        let alice = Vault::create("a", KdfParams::fast_for_tests()).unwrap();
        let bob = Vault::create("b", KdfParams::fast_for_tests()).unwrap();
        let node_key = crypto::random_key();
        let sealed = share_key_with(&bob.bundle.public_key, &node_key, "node-1").unwrap();
        assert_eq!(bob.vault.open_shared_key(&sealed, "node-1").unwrap(), node_key);
        assert!(alice.vault.open_shared_key(&sealed, "node-1").is_err());
        assert!(bob.vault.open_shared_key(&sealed, "node-2").is_err());
    }

    #[test]
    fn recovery_key_format() {
        let k = crypto::random_key();
        let s = format_recovery_key(&k);
        assert_eq!(s.len(), 64 + 7);
        assert_eq!(parse_recovery_key(&s.to_lowercase()).unwrap(), k);
    }
}
