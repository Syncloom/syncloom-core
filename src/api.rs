//! Wire types shared by the server and every client (REST/JSON).
use crate::b64;
use crate::vault::{KdfParams, VaultBundle};
use serde::{Deserialize, Serialize};

pub const API_PREFIX: &str = "/api/v1";

// ---------- auth ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct PreloginResp {
    pub kdf: KdfParams,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterReq {
    pub username: String,
    pub auth_secret: String,
    pub vault: VaultBundle,
    /// Required unless this is the very first user (who becomes admin).
    pub invite: Option<String>,
    pub device_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub auth_secret: String,
    pub device_name: String,
}

/// `status`: `ok` (token is a full device token), `mfa_required` (token is a short-lived
/// MFA token; `methods` lists what the user has enrolled) or `enroll_required` (built-in
/// accounts must enroll a second factor before getting a device token).
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResp {
    pub status: String,
    pub token: String,
    #[serde(default)]
    pub methods: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaVerifyReq {
    /// `totp` or `recovery`
    pub method: String,
    pub code: String,
    pub device_name: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TotpSetupReq {
    /// Label for this authenticator (e.g. "iPhone", "KeePass").
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpSetupResp {
    pub id: String,
    pub secret: String,
    pub otpauth_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpConfirmReq {
    /// The pending authenticator from `TotpSetupResp::id`.
    pub id: String,
    pub code: String,
    pub device_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpConfirmResp {
    /// Only filled when this was the first second factor of the account.
    pub recovery_codes: Vec<String>,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub role: String,
    pub quota_bytes: Option<i64>,
    pub used_bytes: i64,
    pub mfa_methods: Vec<String>,
    pub auth_provider: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MeResp {
    pub user: UserInfo,
    pub vault: Option<VaultBundle>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordReq {
    pub old_auth_secret: String,
    pub new_auth_secret: String,
    pub vault: VaultBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub current: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyResp {
    #[serde(with = "b64")]
    pub public_key: Vec<u8>,
}

// ---------- nodes ----------

pub const KIND_FILE: &str = "file";
pub const KIND_FOLDER: &str = "folder";
/// A key/value namespace. It lives in the node tree so sharing, trash and quotas are shared.
pub const KIND_KV: &str = "kv";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeDto {
    pub id: String,
    pub parent_id: Option<String>,
    pub owner_id: String,
    pub kind: String,
    #[serde(with = "b64")]
    pub enc_name: Vec<u8>,
    #[serde(with = "b64")]
    pub enc_meta: Vec<u8>,
    /// Node key wrapped under the parent's key (or the master key for roots). For shared
    /// roots this is the key sealed to the viewer's public key.
    #[serde(with = "b64")]
    pub wrapped_key: Vec<u8>,
    pub head_version: Option<String>,
    pub size: i64,
    pub deleted: bool,
    pub updated_at: i64,
    /// `rw`, `ro` for shared nodes, `owner` for own nodes.
    pub access: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateNodeReq {
    /// Client-chosen UUID, so the name/key AADs can be computed before the request.
    pub id: String,
    pub parent_id: Option<String>,
    pub kind: String,
    #[serde(with = "b64")]
    pub enc_name: Vec<u8>,
    #[serde(with = "b64")]
    pub enc_meta: Vec<u8>,
    #[serde(with = "b64")]
    pub wrapped_key: Vec<u8>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UpdateNodeReq {
    /// Move. `Some(None)` is not expressible, root moves use `to_root`.
    pub parent_id: Option<String>,
    #[serde(default)]
    pub to_root: bool,
    #[serde(default, with = "opt_b64", skip_serializing_if = "Option::is_none")]
    pub enc_name: Option<Vec<u8>>,
    #[serde(default, with = "opt_b64", skip_serializing_if = "Option::is_none")]
    pub enc_meta: Option<Vec<u8>>,
    /// Required when `parent_id` or `to_root` changes (the key is re-wrapped).
    #[serde(default, with = "opt_b64", skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VersionDto {
    pub id: String,
    pub node_id: String,
    pub parent_version: Option<String>,
    pub size: i64,
    #[serde(with = "b64")]
    pub manifest: Vec<u8>,
    pub chunks: Vec<String>,
    pub created_at: i64,
    pub device: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateVersionReq {
    pub id: String,
    /// The version this one was based on (`None` for the first version). If it is not the
    /// current head, the server answers 409 with the current head.
    pub base_version: Option<String>,
    pub size: i64,
    #[serde(with = "b64")]
    pub manifest: Vec<u8>,
    pub chunks: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConflictResp {
    pub error: String,
    pub head_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MissingChunksReq {
    pub hashes: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct MissingChunksResp {
    pub missing: Vec<String>,
}

// ---------- changes ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChangeDto {
    pub cursor: i64,
    pub node_id: String,
    /// `node`, `version`, `trash`, `restore`, `purge`, `kv`, `share`
    pub kind: String,
    pub version_id: Option<String>,
    pub kv_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangesResp {
    pub changes: Vec<ChangeDto>,
    pub next_cursor: i64,
}

// ---------- key/value ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KvEntryDto {
    pub key: String,
    #[serde(with = "b64")]
    pub value: Vec<u8>,
    pub version: i64,
    pub deleted: bool,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KvPutReq {
    #[serde(with = "b64")]
    pub value: Vec<u8>,
    /// Compare-and-set: `Some(v)` only succeeds if the current version is `v`
    /// (`Some(0)` = key must not exist). `None` = last writer wins.
    pub if_version: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KvConflictResp {
    pub error: String,
    pub current: Option<KvEntryDto>,
}

pub const KV_MAX_VALUE: usize = 256 * 1024;

// ---------- sharing ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateShareReq {
    pub node_id: String,
    pub grantee: String,
    /// `rw` or `ro`
    pub permission: String,
    /// The node key sealed to the grantee's public key.
    #[serde(with = "b64")]
    pub sealed_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareDto {
    pub id: String,
    pub node_id: String,
    pub grantee: String,
    pub permission: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateLinkReq {
    pub node_id: String,
    pub password: Option<String>,
    pub expires_at: Option<i64>,
    pub max_downloads: Option<i64>,
    /// The node key encrypted with the link key (which only lives in the URL fragment).
    #[serde(with = "b64")]
    pub key_envelope: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateLinkResp {
    pub id: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkDto {
    pub id: String,
    pub node_id: String,
    pub has_password: bool,
    pub expires_at: Option<i64>,
    pub max_downloads: Option<i64>,
    pub downloads: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicLinkResp {
    pub node: NodeDto,
    #[serde(with = "b64")]
    pub key_envelope: Vec<u8>,
}

// ---------- admin ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminUserDto {
    pub id: String,
    pub username: String,
    pub role: String,
    pub quota_bytes: Option<i64>,
    pub used_bytes: i64,
    pub disabled: bool,
    pub mfa_methods: Vec<String>,
    pub auth_provider: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AdminUpdateUserReq {
    pub role: Option<String>,
    pub quota_bytes: Option<i64>,
    pub clear_quota: Option<bool>,
    pub disabled: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateInviteResp {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub trash_days: i64,
    pub version_days: i64,
    pub keep_latest_versions: i64,
    pub default_quota_bytes: Option<i64>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { trash_days: 30, version_days: 90, keep_latest_versions: 5, default_quota_bytes: None }
    }
}

mod opt_b64 {
    use crate::b64;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_str(&b64::encode(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let o: Option<String> = Option::deserialize(d)?;
        o.map(|s| b64::decode(&s).map_err(serde::de::Error::custom)).transpose()
    }
}

/// One enrolled second factor. A user can have any number of them and needs only one per login.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MfaMethodDto {
    pub id: String,
    /// `totp` or `webauthn`
    pub kind: String,
    pub name: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RenameMfaReq {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryCodesResp {
    pub recovery_codes: Vec<String>,
}
