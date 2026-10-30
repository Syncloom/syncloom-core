//! Blocking, FFI-friendly facade over the async client for Swift (macOS/iOS) and Kotlin (Android).
//! Generated bindings expose `Authenticator` (sign-in and enrolment) and `Session` (an unlocked vault
//! connected to a server).
use crate::client::{self, Auth, Client, LoginOutcome};
use crate::error::{Error, Result};
use crate::node::NodeMeta;
use crate::state::StateDb;
use crate::sync::{SyncConfig, SyncEngine, SyncReport};
use crate::vault::{KdfParams, Vault};
use std::sync::{Arc, Mutex, OnceLock};

fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("tokio runtime"))
}

#[derive(uniffi::Record, Clone)]
pub struct FfiNode {
    pub id: String,
    pub parent_id: Option<String>,
    pub owner_id: String,
    pub kind: String,
    pub name: String,
    pub size: i64,
    pub mtime_ms: i64,
    pub executable: bool,
    pub head_version: Option<String>,
    pub deleted: bool,
    pub updated_at: i64,
    pub access: String,
}

impl From<client::Node> for FfiNode {
    fn from(n: client::Node) -> Self {
        FfiNode {
            id: n.id,
            parent_id: n.parent_id,
            owner_id: n.owner_id,
            kind: n.kind,
            name: n.name,
            size: n.size,
            mtime_ms: n.meta.mtime_ms,
            executable: n.meta.executable,
            head_version: n.head_version,
            deleted: n.deleted,
            updated_at: n.updated_at,
            access: n.access,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiVersion {
    pub id: String,
    pub size: u64,
    pub content_hash: String,
    pub created_at: i64,
    pub device: String,
}

#[derive(uniffi::Enum)]
pub enum FfiLogin {
    Ok { token: String },
    MfaRequired { token: String, methods: Vec<String> },
    EnrollRequired { token: String },
}

impl From<LoginOutcome> for FfiLogin {
    fn from(o: LoginOutcome) -> Self {
        match o {
            LoginOutcome::Ok { token } => FfiLogin::Ok { token },
            LoginOutcome::MfaRequired { token, methods } => FfiLogin::MfaRequired { token, methods },
            LoginOutcome::EnrollRequired { token } => FfiLogin::EnrollRequired { token },
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiRegistration {
    pub login: FfiLogin,
    /// Show exactly once; without it (and the password) data cannot be recovered.
    pub recovery_key: String,
}

#[derive(uniffi::Record)]
pub struct FfiTotpSetup {
    pub id: String,
    pub secret: String,
    pub otpauth_url: String,
}

#[derive(uniffi::Record)]
pub struct FfiTotpConfirm {
    pub recovery_codes: Vec<String>,
    pub token: String,
}

#[derive(uniffi::Record)]
pub struct FfiMfaMethod {
    pub id: String,
    pub kind: String,
    pub name: String,
}

#[derive(uniffi::Record)]
pub struct FfiUser {
    pub id: String,
    pub username: String,
    pub role: String,
    pub quota_bytes: Option<i64>,
    pub used_bytes: i64,
}

#[derive(uniffi::Record)]
pub struct FfiChange {
    pub cursor: i64,
    pub node_id: String,
    pub kind: String,
}

#[derive(uniffi::Record)]
pub struct FfiChanges {
    pub changes: Vec<FfiChange>,
    pub next_cursor: i64,
}

#[derive(uniffi::Record)]
pub struct FfiKvEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub version: i64,
}

#[derive(uniffi::Record)]
pub struct FfiLink {
    pub id: String,
    /// Full URL including the key fragment, e.g. `https://host/s/<token>#k=<key>`.
    pub url: String,
}

// ---------- sign-in ----------

#[derive(uniffi::Object)]
pub struct Authenticator {
    auth: Auth,
    base: String,
}

#[uniffi::export]
impl Authenticator {
    #[uniffi::constructor]
    pub fn new(server: String) -> Arc<Self> {
        Arc::new(Authenticator { auth: Auth::new(&server), base: server })
    }

    pub fn register(&self, username: String, password: String, invite: Option<String>, device: String) -> Result<FfiRegistration> {
        let r = rt().block_on(self.auth.register(&username, &password, invite.as_deref(), &device))?;
        Ok(FfiRegistration { login: r.outcome.into(), recovery_key: r.recovery_key })
    }

    pub fn login(&self, username: String, password: String, device: String) -> Result<FfiLogin> {
        Ok(rt().block_on(self.auth.login(&username, &password, &device))?.into())
    }

    /// `method` is `totp` or `recovery`. Returns the device token.
    pub fn mfa_verify(&self, mfa_token: String, method: String, code: String, device: String) -> Result<String> {
        rt().block_on(self.auth.mfa_verify(&mfa_token, &method, &code, &device))
    }

    pub fn totp_setup(&self, token: String, name: String) -> Result<FfiTotpSetup> {
        let r = rt().block_on(self.auth.totp_setup(&token, &name))?;
        Ok(FfiTotpSetup { id: r.id, secret: r.secret, otpauth_url: r.otpauth_url })
    }

    pub fn totp_confirm(&self, token: String, id: String, code: String, device: String) -> Result<FfiTotpConfirm> {
        let r = rt().block_on(self.auth.totp_confirm(&token, &id, &code, &device))?;
        Ok(FfiTotpConfirm { recovery_codes: r.recovery_codes, token: r.token })
    }

    pub fn server(&self) -> String {
        self.base.clone()
    }
}

// ---------- unlocked session ----------

#[derive(uniffi::Object)]
pub struct Session {
    client: Client,
}

fn ensure_dir(p: &str) -> Result<()> {
    if let Some(d) = std::path::Path::new(p).parent() {
        std::fs::create_dir_all(d)?;
    }
    Ok(())
}

#[uniffi::export]
impl Session {
    /// Unlock the vault with the account password.
    #[uniffi::constructor]
    pub fn connect(server: String, token: String, password: String) -> Result<Arc<Self>> {
        Ok(Arc::new(Session { client: rt().block_on(Client::connect(&server, &token, &password))? }))
    }

    /// Restore from keys previously saved in the keychain (see `export_secrets`).
    #[uniffi::constructor]
    pub fn from_secrets(server: String, token: String, secrets: Vec<u8>) -> Result<Arc<Self>> {
        if secrets.len() != 64 {
            return Err(Error::Invalid("secrets must be 64 bytes".into()));
        }
        let (mut m, mut s) = ([0u8; 32], [0u8; 32]);
        m.copy_from_slice(&secrets[..32]);
        s.copy_from_slice(&secrets[32..]);
        let vault = Vault::from_secrets(m, s);
        Ok(Arc::new(Session { client: rt().block_on(Client::with_vault(&server, &token, vault))? }))
    }

    /// 64 bytes (master key, private key) for the system keychain. Treat as highly sensitive.
    pub fn export_secrets(&self) -> Vec<u8> {
        let (m, s) = self.client.vault().export_secrets();
        [m.as_slice(), s.as_slice()].concat()
    }

    pub fn me(&self) -> Result<FfiUser> {
        let u = rt().block_on(self.client.me())?.user;
        Ok(FfiUser { id: u.id, username: u.username, role: u.role, quota_bytes: u.quota_bytes, used_bytes: u.used_bytes })
    }

    pub fn logout(&self) -> Result<()> {
        rt().block_on(self.client.logout())
    }

    // browsing
    pub fn list(&self, parent: Option<String>) -> Result<Vec<FfiNode>> {
        Ok(rt().block_on(self.client.list(parent.as_deref()))?.into_iter().map(Into::into).collect())
    }
    pub fn get(&self, id: String) -> Result<FfiNode> {
        Ok(rt().block_on(self.client.get(&id))?.into())
    }
    pub fn shared_with_me(&self) -> Result<Vec<FfiNode>> {
        Ok(rt().block_on(self.client.shared_with_me())?.into_iter().map(Into::into).collect())
    }
    pub fn trash_list(&self) -> Result<Vec<FfiNode>> {
        Ok(rt().block_on(self.client.trash_list())?.into_iter().map(Into::into).collect())
    }

    // changes
    pub fn changes_head(&self) -> Result<i64> {
        rt().block_on(self.client.changes_head())
    }
    pub fn changes(&self, since: i64, limit: i64) -> Result<FfiChanges> {
        let r = rt().block_on(self.client.changes(since, limit))?;
        Ok(FfiChanges { next_cursor: r.next_cursor, changes: r.changes.into_iter().map(|c| FfiChange { cursor: c.cursor, node_id: c.node_id, kind: c.kind }).collect() })
    }

    // mutations
    pub fn create_folder(&self, parent: Option<String>, name: String) -> Result<FfiNode> {
        Ok(rt().block_on(self.client.create_folder(parent.as_deref(), &name))?.into())
    }
    pub fn rename(&self, id: String, name: String) -> Result<FfiNode> {
        Ok(rt().block_on(self.client.rename(&id, &name))?.into())
    }
    pub fn move_to(&self, id: String, new_parent: Option<String>) -> Result<FfiNode> {
        Ok(rt().block_on(self.client.move_to(&id, new_parent.as_deref()))?.into())
    }
    pub fn trash(&self, id: String) -> Result<()> {
        rt().block_on(self.client.trash(&id))
    }
    pub fn restore(&self, id: String) -> Result<FfiNode> {
        Ok(rt().block_on(self.client.restore(&id))?.into())
    }
    pub fn purge(&self, id: String) -> Result<()> {
        rt().block_on(self.client.purge(&id))
    }

    /// Create a file under `parent` with the content of the local file at `path`.
    pub fn upload_new_file(&self, parent: Option<String>, name: String, path: String, mtime_ms: i64, executable: bool) -> Result<FfiNode> {
        rt().block_on(async {
            let n = self.client.create_file_node(parent.as_deref(), &name, &NodeMeta { mtime_ms, executable }).await?;
            if let Err(e) = self.client.upload_version(&n.id, None, std::fs::File::open(&path)?).await {
                let _ = self.client.trash(&n.id).await;
                return Err(e);
            }
            Ok::<_, Error>(self.client.get(&n.id).await?.into())
        })
    }

    /// New version of an existing file from the local file at `path`. `base_version` must be the current head.
    pub fn upload_version(&self, id: String, base_version: Option<String>, path: String, mtime_ms: i64) -> Result<FfiNode> {
        rt().block_on(async {
            self.client.upload_version(&id, base_version.as_deref(), std::fs::File::open(&path)?).await?;
            let _ = self.client.update_meta(&id, &NodeMeta { mtime_ms, executable: false }).await;
            Ok::<_, Error>(self.client.get(&id).await?.into())
        })
    }

    /// Decrypt a version (default: head) into the local file `dest`.
    pub fn download_file(&self, id: String, version: Option<String>, dest: String) -> Result<()> {
        ensure_dir(&dest)?;
        let tmp = format!("{dest}.syncloom-part");
        let res = rt().block_on(async {
            let mut f = std::fs::File::create(&tmp)?;
            self.client.download_to(&id, version.as_deref(), &mut f).await.map(|_| ())
        });
        match res {
            Ok(()) => Ok(std::fs::rename(&tmp, &dest)?),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
    }

    pub fn versions(&self, id: String) -> Result<Vec<FfiVersion>> {
        Ok(rt()
            .block_on(self.client.versions(&id))?
            .into_iter()
            .map(|v| FfiVersion { id: v.id, size: v.size, content_hash: v.content_hash, created_at: v.created_at, device: v.device })
            .collect())
    }
    pub fn restore_version(&self, id: String, version: String) -> Result<()> {
        rt().block_on(self.client.restore_version(&id, &version)).map(|_| ())
    }

    // sharing
    pub fn share(&self, id: String, username: String, read_only: bool) -> Result<()> {
        rt().block_on(self.client.share(&id, &username, if read_only { "ro" } else { "rw" })).map(|_| ())
    }
    pub fn create_link(&self, id: String, password: Option<String>, expires_at_ms: Option<i64>, max_downloads: Option<i64>) -> Result<FfiLink> {
        let l = rt().block_on(self.client.create_link(&id, password.as_deref(), expires_at_ms, max_downloads))?;
        Ok(FfiLink { id: l.id, url: format!("{}/s/{}#k={}", self.client.base(), l.token, l.link_key) })
    }

    // second factors
    pub fn mfa_methods(&self) -> Result<Vec<FfiMfaMethod>> {
        Ok(rt().block_on(self.client.mfa_methods())?.into_iter().map(|m| FfiMfaMethod { id: m.id, kind: m.kind, name: m.name }).collect())
    }
    pub fn add_totp(&self, name: String) -> Result<FfiTotpSetup> {
        let r = rt().block_on(self.client.add_totp(&name))?;
        Ok(FfiTotpSetup { id: r.id, secret: r.secret, otpauth_url: r.otpauth_url })
    }
    pub fn confirm_totp(&self, id: String, code: String) -> Result<()> {
        rt().block_on(self.client.confirm_totp(&id, &code))
    }
    pub fn remove_mfa(&self, id: String) -> Result<()> {
        rt().block_on(self.client.remove_mfa(&id))
    }
    pub fn new_recovery_codes(&self) -> Result<Vec<String>> {
        rt().block_on(self.client.new_recovery_codes())
    }

    // key/value
    pub fn kv_create_namespace(&self, name: String) -> Result<FfiNode> {
        Ok(rt().block_on(self.client.kv_create_namespace(None, &name))?.into())
    }
    pub fn kv_put(&self, ns: String, key: String, value: Vec<u8>, if_version: Option<i64>) -> Result<i64> {
        Ok(rt().block_on(self.client.kv_put(&ns, &key, &value, if_version))?.version)
    }
    pub fn kv_get(&self, ns: String, key: String) -> Result<Option<FfiKvEntry>> {
        Ok(rt().block_on(self.client.kv_get(&ns, &key))?.map(|e| FfiKvEntry { key: e.key, value: e.value, version: e.version }))
    }
    pub fn kv_list(&self, ns: String, prefix: String) -> Result<Vec<FfiKvEntry>> {
        Ok(rt().block_on(self.client.kv_list(&ns, &prefix))?.into_iter().map(|e| FfiKvEntry { key: e.key, value: e.value, version: e.version }).collect())
    }
    pub fn kv_delete(&self, ns: String, key: String) -> Result<()> {
        rt().block_on(self.client.kv_delete(&ns, &key, None))
    }
}

/// Cheap parameters so mobile unit tests stay fast. Production builds use the defaults.
#[uniffi::export]
pub fn recommended_kdf_memory_kib() -> u32 {
    KdfParams::new().m_kib
}

/// Used by the C ABI: one sync pass over a local folder.
pub fn run_sync(session: &Session, cfg: SyncConfig, db: StateDb) -> Result<SyncReport> {
    // the engine needs its own handle on the client; sessions share the same server and vault
    let (m, sec) = session.client.vault().export_secrets();
    let client = rt().block_on(Client::with_vault(session.client.base(), session.client.token(), Vault::from_secrets(m, sec)))?;
    let mut engine = SyncEngine::new(Arc::new(client), cfg, db)?;
    rt().block_on(engine.sync_once())
}

// ---------- live change notifications ----------

/// Implemented by the app. Called from a background thread whenever something changed on the server
/// (a file, a share, a key/value entry), including changes made by this device.
#[uniffi::export(with_foreign)]
pub trait ChangeListener: Send + Sync {
    fn changed(&self, cursor: i64);
}

/// A running subscription. Dropping or cancelling it stops the stream.
#[derive(uniffi::Object)]
pub struct Watch {
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[uniffi::export]
impl Watch {
    pub fn cancel(&self) {
        if let Some(t) = self.task.lock().unwrap().take() {
            t.abort();
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[uniffi::export]
impl Session {
    /// Subscribe to the server's change feed (gRPC server-streaming, so changes arrive immediately).
    /// If the stream cannot be opened (a proxy without HTTP/2, say) it falls back to checking the change
    /// counter every few seconds, and tries the stream again afterwards. Reconnects on its own.
    pub fn watch(self: Arc<Self>, listener: Arc<dyn ChangeListener>) -> Arc<Watch> {
        let task = rt().spawn(async move {
            let mut since = self.client.changes_head().await.unwrap_or(0);
            loop {
                match self.client.subscribe(since).await {
                    Ok(mut stream) => {
                        while let Ok(Some(c)) = stream.next_change().await {
                            since = since.max(c.cursor);
                            listener.changed(c.cursor);
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    Err(_) => {
                        // polling fallback for about a minute, then try the stream again
                        for _ in 0..20 {
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            if let Ok(head) = self.client.changes_head().await {
                                if head > since {
                                    since = head;
                                    listener.changed(head);
                                }
                            }
                        }
                    }
                }
            }
        });
        Arc::new(Watch { task: Mutex::new(Some(task)) })
    }
}
