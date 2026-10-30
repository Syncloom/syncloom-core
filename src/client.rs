//! Async client for the Syncloom server. All encryption/decryption happens here, so callers
//! (CLI, sync engine, mobile bindings) only see plaintext names and bytes.
use crate::api::*;
use crate::b64;
use crate::chunking::{self, ChunkEncryptor, Manifest};
use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::names;
use crate::node::{self, NodeMeta};
use crate::vault::{self, auth_secret, KdfParams, Vault};
use reqwest::{Method, RequestBuilder, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

fn http() -> reqwest::Client {
    reqwest::Client::builder().user_agent("syncloom-core").build().expect("http client")
}

fn base_url(s: &str) -> String {
    s.trim_end_matches('/').to_string()
}

async fn parse<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let status = resp.status();
    if status.is_success() {
        let bytes = resp.bytes().await.map_err(|e| Error::Http(e.to_string()))?;
        return serde_json::from_slice(&bytes).map_err(|e| Error::Http(format!("bad response: {e}")));
    }
    Err(error_from(status, resp).await)
}

async fn error_from(status: StatusCode, resp: reqwest::Response) -> Error {
    let text = resp.text().await.unwrap_or_default();
    let message = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str().map(String::from)))
        .unwrap_or(text);
    match status {
        StatusCode::CONFLICT => Error::Conflict,
        StatusCode::NOT_FOUND => Error::NotFound,
        StatusCode::UNAUTHORIZED => Error::Auth(message),
        _ => Error::Server { status: status.as_u16(), message },
    }
}

// ---------- unauthenticated / pre-session flows ----------

#[derive(Debug, Clone, PartialEq)]
pub enum LoginOutcome {
    /// Signed in, `token` is a device token.
    Ok { token: String },
    /// A second factor is needed. Call [`Auth::mfa_verify`] with `token`.
    MfaRequired { token: String, methods: Vec<String> },
    /// The account has no second factor yet: enroll one with `totp_setup` / `totp_confirm` using `token`.
    EnrollRequired { token: String },
}

fn outcome(r: LoginResp) -> LoginOutcome {
    match r.status.as_str() {
        "ok" => LoginOutcome::Ok { token: r.token },
        "mfa_required" => LoginOutcome::MfaRequired { token: r.token, methods: r.methods },
        _ => LoginOutcome::EnrollRequired { token: r.token },
    }
}

pub struct RegisterOutcome {
    pub outcome: LoginOutcome,
    /// Shown to the user exactly once. Without it (and the password) data cannot be recovered.
    pub recovery_key: String,
}

#[derive(Clone)]
pub struct Auth {
    http: reqwest::Client,
    base: String,
}

impl Auth {
    pub fn new(base: &str) -> Auth {
        Auth { http: http(), base: base_url(base) }
    }
    fn url(&self, p: &str) -> String {
        format!("{}{}{}", self.base, API_PREFIX, p)
    }

    pub async fn prelogin(&self, username: &str) -> Result<KdfParams> {
        let r = self.http.get(self.url("/auth/prelogin")).query(&[("username", username)]).send().await.map_err(|e| Error::Http(e.to_string()))?;
        Ok(parse::<PreloginResp>(r).await?.kdf)
    }

    pub async fn register(&self, username: &str, password: &str, invite: Option<&str>, device: &str) -> Result<RegisterOutcome> {
        self.register_with(username, password, invite, device, KdfParams::new()).await
    }

    pub async fn register_with(&self, username: &str, password: &str, invite: Option<&str>, device: &str, kdf: KdfParams) -> Result<RegisterOutcome> {
        let created = Vault::create(password, kdf)?;
        let req = RegisterReq { username: username.into(), auth_secret: created.auth_secret, vault: created.bundle, invite: invite.map(String::from), device_name: device.into() };
        let r = self.http.post(self.url("/auth/register")).json(&req).send().await.map_err(|e| Error::Http(e.to_string()))?;
        Ok(RegisterOutcome { outcome: outcome(parse(r).await?), recovery_key: created.recovery_key })
    }

    pub async fn login(&self, username: &str, password: &str, device: &str) -> Result<LoginOutcome> {
        let kdf = self.prelogin(username).await?;
        let secret = auth_secret(password, &kdf)?;
        let r = self
            .http
            .post(self.url("/auth/login"))
            .json(&LoginReq { username: username.into(), auth_secret: secret, device_name: device.into() })
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        Ok(outcome(parse(r).await?))
    }

    pub async fn mfa_verify(&self, mfa_token: &str, method: &str, code: &str, device: &str) -> Result<String> {
        let r = self
            .http
            .post(self.url("/auth/mfa/verify"))
            .bearer_auth(mfa_token)
            .json(&MfaVerifyReq { method: method.into(), code: code.into(), device_name: device.into() })
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        Ok(parse::<LoginResp>(r).await?.token)
    }

    pub async fn totp_setup(&self, token: &str, name: &str) -> Result<TotpSetupResp> {
        let r = self.http.post(self.url("/auth/totp/setup")).bearer_auth(token).json(&TotpSetupReq { name: name.into() }).send().await.map_err(|e| Error::Http(e.to_string()))?;
        parse(r).await
    }

    /// Returns the recovery codes and, when called with an enrollment token, the device token.
    pub async fn totp_confirm(&self, token: &str, id: &str, code: &str, device: &str) -> Result<TotpConfirmResp> {
        let r = self
            .http
            .post(self.url("/auth/totp/confirm"))
            .bearer_auth(token)
            .json(&TotpConfirmReq { id: id.into(), code: code.into(), device_name: device.into() })
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        parse(r).await
    }

    pub async fn health(&self) -> Result<()> {
        let r = self.http.get(format!("{}/health", self.base)).send().await.map_err(|e| Error::Http(e.to_string()))?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(Error::Http(format!("health check returned {}", r.status())))
        }
    }
}

// ---------- decrypted views ----------

#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub id: String,
    pub parent_id: Option<String>,
    pub owner_id: String,
    pub kind: String,
    pub name: String,
    pub meta: NodeMeta,
    pub head_version: Option<String>,
    pub size: i64,
    pub deleted: bool,
    pub updated_at: i64,
    pub access: String,
}

impl Node {
    pub fn is_folder(&self) -> bool {
        self.kind == KIND_FOLDER
    }
    pub fn is_file(&self) -> bool {
        self.kind == KIND_FILE
    }
}

#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub id: String,
    pub parent_version: Option<String>,
    pub size: u64,
    pub content_hash: String,
    pub created_at: i64,
    pub device: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KvEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub version: i64,
}

#[derive(Debug, Clone)]
pub struct LinkInfo {
    pub id: String,
    /// Token for `/public/<token>`.
    pub token: String,
    /// Base64url link key. It belongs in the URL fragment (`#k=...`) and never goes to the server.
    pub link_key: String,
}

fn link_aad(node_id: &str) -> Vec<u8> {
    format!("syncloom/link/{node_id}").into_bytes()
}

// ---------- authenticated client ----------

pub struct Client {
    http: reqwest::Client,
    base: String,
    token: String,
    vault: Arc<Vault>,
    user_id: String,
    keys: Mutex<HashMap<String, Key>>,
    shared_roots: Mutex<Option<HashMap<String, Vec<u8>>>>,
}

impl Client {
    /// Fetches the encrypted vault and unlocks it with the password.
    pub async fn connect(base: &str, token: &str, password: &str) -> Result<Client> {
        let http = http();
        let base = base_url(base);
        let r = http.get(format!("{base}{API_PREFIX}/me")).bearer_auth(token).send().await.map_err(|e| Error::Http(e.to_string()))?;
        let me: MeResp = parse(r).await?;
        let bundle = me.vault.ok_or_else(|| Error::Invalid("account has no vault yet".into()))?;
        let vault = Vault::unlock(password, &bundle)?;
        Ok(Client::from_parts(http, base, token.to_string(), Arc::new(vault), me.user.id))
    }

    /// Reconnect from an already unlocked vault (e.g. secrets restored from the OS keychain).
    pub async fn with_vault(base: &str, token: &str, vault: Vault) -> Result<Client> {
        let http = http();
        let base = base_url(base);
        let r = http.get(format!("{base}{API_PREFIX}/me")).bearer_auth(token).send().await.map_err(|e| Error::Http(e.to_string()))?;
        let me: MeResp = parse(r).await?;
        Ok(Client::from_parts(http, base, token.to_string(), Arc::new(vault), me.user.id))
    }

    fn from_parts(http: reqwest::Client, base: String, token: String, vault: Arc<Vault>, user_id: String) -> Client {
        Client { http, base, token, vault, user_id, keys: Mutex::new(HashMap::new()), shared_roots: Mutex::new(None) }
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn base(&self) -> &str {
        &self.base
    }
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    fn req(&self, m: Method, path: &str) -> RequestBuilder {
        self.http.request(m, format!("{}{}{}", self.base, API_PREFIX, path)).bearer_auth(&self.token)
    }

    async fn send<T: DeserializeOwned>(&self, rb: RequestBuilder) -> Result<T> {
        parse(rb.send().await.map_err(|e| Error::Http(e.to_string()))?).await
    }
    async fn send_empty(&self, rb: RequestBuilder) -> Result<()> {
        let r = rb.send().await.map_err(|e| Error::Http(e.to_string()))?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(error_from(r.status(), r).await)
        }
    }
    async fn json<B: Serialize, T: DeserializeOwned>(&self, m: Method, path: &str, body: &B) -> Result<T> {
        self.send(self.req(m, path).json(body)).await
    }

    pub async fn me(&self) -> Result<MeResp> {
        self.send(self.req(Method::GET, "/me")).await
    }

    pub async fn logout(&self) -> Result<()> {
        self.send_empty(self.req(Method::POST, "/auth/logout")).await
    }

    pub async fn change_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        let me = self.me().await?;
        let bundle = me.vault.ok_or_else(|| Error::Invalid("no vault".into()))?;
        let old_secret = auth_secret(old_password, &bundle.kdf)?;
        // verifies the old password locally before anything is sent
        Vault::unlock(old_password, &bundle)?;
        let (nb, new_secret) = self.vault.change_password(&bundle, new_password, KdfParams::new())?;
        self.send_empty(self.req(Method::POST, "/me/password").json(&ChangePasswordReq { old_auth_secret: old_secret, new_auth_secret: new_secret, vault: nb })).await
    }

    /// Enrolled second factors. Any one of them is enough to sign in.
    pub async fn mfa_methods(&self) -> Result<Vec<MfaMethodDto>> {
        self.send(self.req(Method::GET, "/me/mfa")).await
    }

    /// Start adding another authenticator app; confirm with [`Client::confirm_totp`].
    pub async fn add_totp(&self, name: &str) -> Result<TotpSetupResp> {
        self.json(Method::POST, "/auth/totp/setup", &TotpSetupReq { name: name.into() }).await
    }

    pub async fn confirm_totp(&self, id: &str, code: &str) -> Result<()> {
        let _: TotpConfirmResp = self.json(Method::POST, "/auth/totp/confirm", &TotpConfirmReq { id: id.into(), code: code.into(), device_name: String::new() }).await?;
        Ok(())
    }

    pub async fn rename_mfa(&self, id: &str, name: &str) -> Result<()> {
        self.send_empty(self.req(Method::PATCH, &format!("/me/mfa/{id}")).json(&RenameMfaReq { name: name.into() })).await
    }

    /// Fails with a conflict if it is the account's last second factor.
    pub async fn remove_mfa(&self, id: &str) -> Result<()> {
        self.send_empty(self.req(Method::DELETE, &format!("/me/mfa/{id}"))).await
    }

    /// Replaces all recovery codes with ten new ones.
    pub async fn new_recovery_codes(&self) -> Result<Vec<String>> {
        Ok(self.send::<RecoveryCodesResp>(self.req(Method::POST, "/me/recovery-codes")).await?.recovery_codes)
    }

    pub async fn devices(&self) -> Result<Vec<DeviceInfo>> {
        self.send(self.req(Method::GET, "/me/devices")).await
    }

    // ----- key resolution -----

    async fn load_shared_roots(&self, force: bool) -> Result<()> {
        if !force && self.shared_roots.lock().unwrap().is_some() {
            return Ok(());
        }
        let list: Vec<NodeDto> = self.send(self.req(Method::GET, "/shared")).await?;
        let map = list.into_iter().map(|n| (n.id, n.wrapped_key)).collect();
        *self.shared_roots.lock().unwrap() = Some(map);
        Ok(())
    }

    fn shared_root_key(&self, id: &str) -> Result<Option<Key>> {
        let sealed = self.shared_roots.lock().unwrap().as_ref().and_then(|m| m.get(id).cloned());
        match sealed {
            Some(s) => Ok(Some(self.vault.open_shared_key(&s, id)?)),
            None => Ok(None),
        }
    }

    pub async fn node_dto(&self, id: &str) -> Result<NodeDto> {
        self.send(self.req(Method::GET, &format!("/nodes/{id}"))).await
    }

    /// Resolve the key of any node we can access by walking up to the master key or a share root.
    pub fn node_key<'a>(&'a self, id: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Key>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(k) = self.keys.lock().unwrap().get(id) {
                return Ok(*k);
            }
            self.load_shared_roots(false).await?;
            let mut key = self.shared_root_key(id)?;
            if key.is_none() {
                let dto = self.node_dto(id).await?;
                key = Some(match &dto.parent_id {
                    Some(p) => match self.node_key(p).await {
                        Ok(pk) => node::unwrap_node_key(&pk, id, &dto.wrapped_key)?,
                        Err(Error::NotFound) => {
                            // a share we have not seen yet
                            self.load_shared_roots(true).await?;
                            self.shared_root_key(id)?.ok_or(Error::NotFound)?
                        }
                        Err(e) => return Err(e),
                    },
                    None if dto.owner_id == self.user_id => node::unwrap_node_key(self.vault.master_key(), id, &dto.wrapped_key)?,
                    None => return Err(Error::NotFound),
                });
            }
            let k = key.unwrap();
            self.keys.lock().unwrap().insert(id.to_string(), k);
            Ok(k)
        })
    }

    fn remember_key(&self, id: &str, key: Key) {
        self.keys.lock().unwrap().insert(id.to_string(), key);
    }

    /// Decrypt a node DTO given the key of its *parent* (or the master key for roots / share keys for share roots).
    fn decrypt_node(&self, dto: &NodeDto, key: &Key) -> Result<Node> {
        Ok(Node {
            id: dto.id.clone(),
            parent_id: dto.parent_id.clone(),
            owner_id: dto.owner_id.clone(),
            kind: dto.kind.clone(),
            name: node::decrypt_name(key, &dto.id, &dto.enc_name)?,
            meta: node::decrypt_meta(key, &dto.id, &dto.enc_meta).unwrap_or_default(),
            head_version: dto.head_version.clone(),
            size: dto.size,
            deleted: dto.deleted,
            updated_at: dto.updated_at,
            access: dto.access.clone(),
        })
    }

    async fn decrypt_list(&self, list: Vec<NodeDto>, parent_key: Option<Key>) -> Result<Vec<Node>> {
        let mut out = Vec::with_capacity(list.len());
        for dto in list {
            let k = match (&dto.parent_id, parent_key) {
                (Some(_), Some(pk)) => node::unwrap_node_key(&pk, &dto.id, &dto.wrapped_key)?,
                _ => node::unwrap_node_key(self.vault.master_key(), &dto.id, &dto.wrapped_key)?,
            };
            self.remember_key(&dto.id, k);
            out.push(self.decrypt_node(&dto, &k)?);
        }
        Ok(out)
    }

    // ----- browsing -----

    /// `None` lists the root of your own tree.
    pub async fn list(&self, parent: Option<&str>) -> Result<Vec<Node>> {
        match parent {
            None => {
                let list: Vec<NodeDto> = self.send(self.req(Method::GET, "/nodes")).await?;
                self.decrypt_list(list, None).await
            }
            Some(p) => {
                let pk = self.node_key(p).await?;
                let list: Vec<NodeDto> = self.send(self.req(Method::GET, "/nodes").query(&[("parent", p)])).await?;
                self.decrypt_list(list, Some(pk)).await
            }
        }
    }

    pub async fn get(&self, id: &str) -> Result<Node> {
        let dto = self.node_dto(id).await?;
        let key = self.node_key(id).await?;
        self.decrypt_node(&dto, &key)
    }

    pub async fn trash_list(&self) -> Result<Vec<Node>> {
        let list: Vec<NodeDto> = self.send(self.req(Method::GET, "/nodes").query(&[("trash", "true")])).await?;
        // trashed nodes may sit below other nodes, so resolve each key through its chain
        let mut out = Vec::new();
        for dto in list {
            let key = self.node_key(&dto.id).await?;
            out.push(self.decrypt_node(&dto, &key)?);
        }
        Ok(out)
    }

    pub async fn shared_with_me(&self) -> Result<Vec<Node>> {
        let list: Vec<NodeDto> = self.send(self.req(Method::GET, "/shared")).await?;
        self.load_shared_roots(true).await?;
        let mut out = Vec::new();
        for dto in list {
            let key = self.vault.open_shared_key(&dto.wrapped_key, &dto.id)?;
            self.remember_key(&dto.id, key);
            out.push(self.decrypt_node(&dto, &key)?);
        }
        Ok(out)
    }

    // ----- mutations -----

    async fn create_node(&self, parent: Option<&str>, kind: &str, name: &str, meta: &NodeMeta, id: Option<String>) -> Result<Node> {
        names::validate(name)?;
        let id = id.unwrap_or_else(crypto::new_uuid);
        let key = crypto::random_key();
        let parent_key = match parent {
            Some(p) => self.node_key(p).await?,
            None => *self.vault.master_key(),
        };
        let req = CreateNodeReq {
            id: id.clone(),
            parent_id: parent.map(String::from),
            kind: kind.into(),
            enc_name: node::encrypt_name(&key, &id, name)?,
            enc_meta: node::encrypt_meta(&key, &id, meta)?,
            wrapped_key: node::wrap_node_key(&parent_key, &id, &key)?,
        };
        let dto: NodeDto = self.json(Method::POST, "/nodes", &req).await?;
        self.remember_key(&id, key);
        self.decrypt_node(&dto, &key)
    }

    pub async fn create_folder(&self, parent: Option<&str>, name: &str) -> Result<Node> {
        self.create_node(parent, KIND_FOLDER, name, &NodeMeta::default(), None).await
    }

    pub async fn create_file_node(&self, parent: Option<&str>, name: &str, meta: &NodeMeta) -> Result<Node> {
        self.create_node(parent, KIND_FILE, name, meta, None).await
    }

    pub async fn rename(&self, id: &str, new_name: &str) -> Result<Node> {
        names::validate(new_name)?;
        let key = self.node_key(id).await?;
        let req = UpdateNodeReq { enc_name: Some(node::encrypt_name(&key, id, new_name)?), ..Default::default() };
        let dto: NodeDto = self.json(Method::PATCH, &format!("/nodes/{id}"), &req).await?;
        self.decrypt_node(&dto, &key)
    }

    pub async fn update_meta(&self, id: &str, meta: &NodeMeta) -> Result<()> {
        let key = self.node_key(id).await?;
        let req = UpdateNodeReq { enc_meta: Some(node::encrypt_meta(&key, id, meta)?), ..Default::default() };
        let _: NodeDto = self.json(Method::PATCH, &format!("/nodes/{id}"), &req).await?;
        Ok(())
    }

    /// Move to `new_parent` (`None` = root of your tree) and re-wrap the node key.
    pub async fn move_to(&self, id: &str, new_parent: Option<&str>) -> Result<Node> {
        let key = self.node_key(id).await?;
        let parent_key = match new_parent {
            Some(p) => self.node_key(p).await?,
            None => *self.vault.master_key(),
        };
        let req = UpdateNodeReq {
            parent_id: new_parent.map(String::from),
            to_root: new_parent.is_none(),
            wrapped_key: Some(node::wrap_node_key(&parent_key, id, &key)?),
            ..Default::default()
        };
        let dto: NodeDto = self.json(Method::PATCH, &format!("/nodes/{id}"), &req).await?;
        self.decrypt_node(&dto, &key)
    }

    pub async fn trash(&self, id: &str) -> Result<()> {
        self.send_empty(self.req(Method::DELETE, &format!("/nodes/{id}"))).await
    }
    pub async fn restore(&self, id: &str) -> Result<Node> {
        let dto: NodeDto = self.send(self.req(Method::POST, &format!("/nodes/{id}/restore"))).await?;
        let key = self.node_key(id).await?;
        self.decrypt_node(&dto, &key)
    }
    pub async fn purge(&self, id: &str) -> Result<()> {
        self.send_empty(self.req(Method::DELETE, &format!("/trash/{id}"))).await
    }

    // ----- file content -----

    /// Upload `reader` as a new version based on `base_version` (`None` for a new file).
    /// Returns [`Error::Conflict`] when the head moved; fetch the node and merge.
    pub async fn upload_version<R: Read>(&self, node_id: &str, base_version: Option<&str>, reader: R) -> Result<VersionInfo> {
        let key = self.node_key(node_id).await?;
        let mut enc = ChunkEncryptor::new(&key, node_id, reader);
        let mut batch: Vec<chunking::EncryptedChunk> = Vec::new();
        loop {
            let next = enc.next_chunk()?;
            let done = next.is_none();
            if let Some(c) = next {
                batch.push(c);
            }
            if batch.len() >= 32 || (done && !batch.is_empty()) {
                self.upload_chunks(std::mem::take(&mut batch)).await?;
            }
            if done {
                break;
            }
        }
        let manifest = enc.finish();
        let req = CreateVersionReq {
            id: crypto::new_uuid(),
            base_version: base_version.map(String::from),
            size: manifest.size as i64,
            manifest: chunking::seal_manifest(&key, node_id, &manifest)?,
            chunks: manifest.chunks.iter().map(|c| c.hash.clone()).collect(),
        };
        let v: VersionDto = self.json(Method::POST, &format!("/nodes/{node_id}/versions"), &req).await?;
        Ok(VersionInfo {
            id: v.id,
            parent_version: v.parent_version,
            size: manifest.size,
            content_hash: manifest.content_hash,
            created_at: v.created_at,
            device: v.device,
        })
    }

    pub async fn upload_bytes(&self, node_id: &str, base_version: Option<&str>, data: &[u8]) -> Result<VersionInfo> {
        self.upload_version(node_id, base_version, data).await
    }

    async fn upload_chunks(&self, chunks: Vec<chunking::EncryptedChunk>) -> Result<()> {
        let hashes: Vec<String> = chunks.iter().map(|c| c.hash.clone()).collect();
        let missing: MissingChunksResp = self.json(Method::POST, "/chunks/missing", &MissingChunksReq { hashes }).await?;
        let missing: std::collections::HashSet<_> = missing.missing.into_iter().collect();
        for c in chunks.into_iter().filter(|c| missing.contains(&c.hash)) {
            self.send_empty(self.req(Method::PUT, &format!("/chunks/{}", c.hash)).body(c.data)).await?;
        }
        Ok(())
    }

    pub async fn versions(&self, node_id: &str) -> Result<Vec<VersionInfo>> {
        let key = self.node_key(node_id).await?;
        let list: Vec<VersionDto> = self.send(self.req(Method::GET, &format!("/nodes/{node_id}/versions"))).await?;
        list.into_iter()
            .map(|v| {
                let m = chunking::open_manifest(&key, node_id, &v.manifest)?;
                Ok(VersionInfo { id: v.id, parent_version: v.parent_version, size: m.size, content_hash: m.content_hash, created_at: v.created_at, device: v.device })
            })
            .collect()
    }

    /// Download a version (default: head) into `out`. Verifies chunk hashes and the content hash.
    pub async fn download_to<W: Write>(&self, node_id: &str, version: Option<&str>, out: &mut W) -> Result<Manifest> {
        let key = self.node_key(node_id).await?;
        let vid = match version {
            Some(v) => v.to_string(),
            None => self.node_dto(node_id).await?.head_version.ok_or(Error::NotFound)?,
        };
        let v: VersionDto = self.send(self.req(Method::GET, &format!("/versions/{vid}"))).await?;
        let manifest = chunking::open_manifest(&key, node_id, &v.manifest)?;
        let mut content = blake3::Hasher::new();
        for c in &manifest.chunks {
            let r = self.req(Method::GET, &format!("/chunks/{}", c.hash)).send().await.map_err(|e| Error::Http(e.to_string()))?;
            if !r.status().is_success() {
                return Err(error_from(r.status(), r).await);
            }
            let ct = r.bytes().await.map_err(|e| Error::Http(e.to_string()))?;
            let plain = chunking::decrypt_chunk(&key, node_id, &ct, &c.hash)?;
            content.update(&plain);
            out.write_all(&plain)?;
        }
        if content.finalize().to_hex().as_str() != manifest.content_hash {
            return Err(Error::Crypto("content hash mismatch".into()));
        }
        Ok(manifest)
    }

    pub async fn download_bytes(&self, node_id: &str, version: Option<&str>) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.download_to(node_id, version, &mut buf).await?;
        Ok(buf)
    }

    /// Restore an old version by re-publishing its chunks as a new head version (no data is copied).
    pub async fn restore_version(&self, node_id: &str, version: &str) -> Result<VersionInfo> {
        let key = self.node_key(node_id).await?;
        let head = self.node_dto(node_id).await?.head_version;
        let old: VersionDto = self.send(self.req(Method::GET, &format!("/versions/{version}"))).await?;
        let m = chunking::open_manifest(&key, node_id, &old.manifest)?;
        let req = CreateVersionReq { id: crypto::new_uuid(), base_version: head, size: old.size, manifest: old.manifest.clone(), chunks: old.chunks.clone() };
        let v: VersionDto = self.json(Method::POST, &format!("/nodes/{node_id}/versions"), &req).await?;
        Ok(VersionInfo { id: v.id, parent_version: v.parent_version, size: m.size, content_hash: m.content_hash, created_at: v.created_at, device: v.device })
    }

    /// Convenience: create a file node and upload its first version.
    pub async fn put_file(&self, parent: Option<&str>, name: &str, data: &[u8]) -> Result<Node> {
        let n = self.create_file_node(parent, name, &NodeMeta { mtime_ms: 0, executable: false }).await?;
        self.upload_bytes(&n.id, None, data).await?;
        self.get(&n.id).await
    }

    // ----- key/value -----

    pub async fn kv_create_namespace(&self, parent: Option<&str>, name: &str) -> Result<Node> {
        self.create_node(parent, KIND_KV, name, &NodeMeta::default(), None).await
    }

    pub async fn kv_put(&self, ns: &str, key: &str, value: &[u8], if_version: Option<i64>) -> Result<KvEntry> {
        if value.len() > KV_MAX_VALUE {
            return Err(Error::Invalid(format!("value exceeds {KV_MAX_VALUE} bytes")));
        }
        let nk = self.node_key(ns).await?;
        let req = KvPutReq { value: node::encrypt_kv(&nk, ns, key, value)?, if_version };
        let e: KvEntryDto = self.json(Method::PUT, &format!("/kv/{ns}/e/{key}"), &req).await?;
        Ok(KvEntry { key: e.key, value: value.to_vec(), version: e.version })
    }

    pub async fn kv_get(&self, ns: &str, key: &str) -> Result<Option<KvEntry>> {
        let nk = self.node_key(ns).await?;
        match self.send::<KvEntryDto>(self.req(Method::GET, &format!("/kv/{ns}/e/{key}"))).await {
            Ok(e) => Ok(Some(KvEntry { value: node::decrypt_kv(&nk, ns, &e.key, &e.value)?, key: e.key, version: e.version })),
            Err(Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn kv_list(&self, ns: &str, prefix: &str) -> Result<Vec<KvEntry>> {
        let nk = self.node_key(ns).await?;
        let list: Vec<KvEntryDto> = self.send(self.req(Method::GET, &format!("/kv/{ns}/list")).query(&[("prefix", prefix)])).await?;
        list.into_iter().map(|e| Ok(KvEntry { value: node::decrypt_kv(&nk, ns, &e.key, &e.value)?, key: e.key, version: e.version })).collect()
    }

    pub async fn kv_delete(&self, ns: &str, key: &str, if_version: Option<i64>) -> Result<()> {
        let mut rb = self.req(Method::DELETE, &format!("/kv/{ns}/e/{key}"));
        if let Some(v) = if_version {
            rb = rb.query(&[("if_version", v)]);
        }
        self.send_empty(rb).await
    }

    // ----- sharing -----

    pub async fn share(&self, node_id: &str, username: &str, permission: &str) -> Result<ShareDto> {
        let pk: PublicKeyResp = self.send(self.req(Method::GET, &format!("/users/{}/pubkey", username.to_lowercase()))).await?;
        let key = self.node_key(node_id).await?;
        let req = CreateShareReq { node_id: node_id.into(), grantee: username.into(), permission: permission.into(), sealed_key: vault::share_key_with(&pk.public_key, &key, node_id)? };
        self.json(Method::POST, "/shares", &req).await
    }

    pub async fn shares(&self, node_id: &str) -> Result<Vec<ShareDto>> {
        self.send(self.req(Method::GET, "/shares").query(&[("node_id", node_id)])).await
    }

    pub async fn unshare(&self, share_id: &str) -> Result<()> {
        self.send_empty(self.req(Method::DELETE, &format!("/shares/{share_id}"))).await
    }

    pub async fn create_link(&self, node_id: &str, password: Option<&str>, expires_at: Option<i64>, max_downloads: Option<i64>) -> Result<LinkInfo> {
        let key = self.node_key(node_id).await?;
        let link_key = crypto::random_key();
        let req = CreateLinkReq {
            node_id: node_id.into(),
            password: password.map(String::from),
            expires_at,
            max_downloads,
            key_envelope: crypto::seal(&link_key, &key, &link_aad(node_id))?,
        };
        let r: CreateLinkResp = self.json(Method::POST, "/links", &req).await?;
        Ok(LinkInfo { id: r.id, token: r.token, link_key: b64::encode(&link_key) })
    }

    pub async fn links(&self, node_id: &str) -> Result<Vec<LinkDto>> {
        self.send(self.req(Method::GET, "/links").query(&[("node_id", node_id)])).await
    }
    pub async fn delete_link(&self, id: &str) -> Result<()> {
        self.send_empty(self.req(Method::DELETE, &format!("/links/{id}"))).await
    }

    // ----- changes -----

    pub async fn changes(&self, since: i64, limit: i64) -> Result<ChangesResp> {
        self.send(self.req(Method::GET, "/changes").query(&[("since", since), ("limit", limit)])).await
    }
    pub async fn changes_head(&self) -> Result<i64> {
        Ok(self.send::<ChangesResp>(self.req(Method::GET, "/changes/head")).await?.next_cursor)
    }

    /// Open the gRPC change stream. Heartbeats (cursor 0) are filtered by [`next_change`].
    pub async fn subscribe(&self, since: i64) -> Result<ChangeStream> {
        use crate::grpc::{sync_client::SyncClient, SubscribeRequest};
        let mut endpoint = tonic::transport::Channel::from_shared(self.base.clone()).map_err(|e| Error::Http(e.to_string()))?;
        if self.base.starts_with("https") {
            endpoint = endpoint.tls_config(tonic::transport::ClientTlsConfig::new().with_native_roots()).map_err(|e| Error::Http(e.to_string()))?;
        }
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| Error::Http(format!("grpc connect: {e}")))?;
        let mut client = SyncClient::new(channel);
        let mut req = tonic::Request::new(SubscribeRequest { since });
        req.metadata_mut().insert("authorization", format!("Bearer {}", self.token).parse().map_err(|_| Error::Invalid("token".into()))?);
        let stream = client.subscribe(req).await.map_err(|s| Error::Http(format!("grpc: {}", s.message())))?.into_inner();
        Ok(ChangeStream { inner: stream })
    }
}

pub struct ChangeStream {
    inner: tonic::Streaming<crate::grpc::Change>,
}

impl ChangeStream {
    /// Next real change; heartbeats are skipped. `None` when the server closed the stream.
    pub async fn next_change(&mut self) -> Result<Option<ChangeDto>> {
        loop {
            match self.inner.message().await {
                Ok(Some(c)) if c.cursor == 0 => continue,
                Ok(Some(c)) => {
                    return Ok(Some(ChangeDto {
                        cursor: c.cursor,
                        node_id: c.node_id,
                        kind: c.kind,
                        version_id: Some(c.version_id).filter(|s| !s.is_empty()),
                        kv_key: Some(c.kv_key).filter(|s| !s.is_empty()),
                    }))
                }
                Ok(None) => return Ok(None),
                Err(s) => return Err(Error::Http(format!("grpc: {}", s.message()))),
            }
        }
    }
}

// ---------- public link access (no account) ----------

pub struct PublicClient {
    http: reqwest::Client,
    base: String,
    token: String,
    password: Option<String>,
    key: Key,
    pub root: Node,
}

impl PublicClient {
    /// `link_key` is the base64url value from the URL fragment.
    pub async fn open(base: &str, token: &str, link_key: &str, password: Option<&str>) -> Result<PublicClient> {
        let http = http();
        let base = base_url(base);
        let mut rb = http.get(format!("{base}{API_PREFIX}/public/{token}"));
        if let Some(p) = password {
            rb = rb.header("x-link-password", p);
        }
        let link: PublicLinkResp = parse(rb.send().await.map_err(|e| Error::Http(e.to_string()))?).await?;
        let lk = crypto::key_from_slice(&b64::decode(link_key).map_err(|_| Error::Invalid("bad link key".into()))?)?;
        let node_key = crypto::open(&lk, &link.key_envelope, &link_aad(&link.node.id)).and_then(|k| crypto::key_from_slice(&k))?;
        let dto = &link.node;
        let root = Node {
            id: dto.id.clone(),
            parent_id: None,
            owner_id: dto.owner_id.clone(),
            kind: dto.kind.clone(),
            name: node::decrypt_name(&node_key, &dto.id, &dto.enc_name)?,
            meta: node::decrypt_meta(&node_key, &dto.id, &dto.enc_meta).unwrap_or_default(),
            head_version: dto.head_version.clone(),
            size: dto.size,
            deleted: false,
            updated_at: dto.updated_at,
            access: "ro".into(),
        };
        Ok(PublicClient { http, base, token: token.into(), password: password.map(String::from), key: node_key, root })
    }

    fn get(&self, path: &str) -> RequestBuilder {
        let mut rb = self.http.get(format!("{}{}/public/{}{}", self.base, API_PREFIX, self.token, path));
        if let Some(p) = &self.password {
            rb = rb.header("x-link-password", p);
        }
        rb
    }

    /// List a folder inside the link. Keys are derived down the tree from the link's node key.
    pub async fn list(&self, parent: Option<&Node>, parent_key: Option<&Key>) -> Result<Vec<(Node, Key)>> {
        let (pid, pkey) = match (parent, parent_key) {
            (Some(p), Some(k)) => (p.id.clone(), *k),
            _ => (self.root.id.clone(), self.key),
        };
        let list: Vec<NodeDto> = parse(self.get("/nodes").query(&[("parent", pid.as_str())]).send().await.map_err(|e| Error::Http(e.to_string()))?).await?;
        list.into_iter()
            .map(|dto| {
                let k = node::unwrap_node_key(&pkey, &dto.id, &dto.wrapped_key)?;
                let n = Node {
                    id: dto.id.clone(),
                    parent_id: dto.parent_id.clone(),
                    owner_id: dto.owner_id.clone(),
                    kind: dto.kind.clone(),
                    name: node::decrypt_name(&k, &dto.id, &dto.enc_name)?,
                    meta: node::decrypt_meta(&k, &dto.id, &dto.enc_meta).unwrap_or_default(),
                    head_version: dto.head_version.clone(),
                    size: dto.size,
                    deleted: false,
                    updated_at: dto.updated_at,
                    access: "ro".into(),
                };
                Ok((n, k))
            })
            .collect()
    }

    pub fn root_key(&self) -> Key {
        self.key
    }

    pub async fn download(&self, node: &Node, key: &Key) -> Result<Vec<u8>> {
        let v: VersionDto = parse(self.get(&format!("/versions/{}", node.id)).send().await.map_err(|e| Error::Http(e.to_string()))?).await?;
        let manifest = chunking::open_manifest(key, &node.id, &v.manifest)?;
        let mut out = Vec::new();
        for c in &manifest.chunks {
            let r = self.get(&format!("/chunks/{}", c.hash)).send().await.map_err(|e| Error::Http(e.to_string()))?;
            if !r.status().is_success() {
                return Err(error_from(r.status(), r).await);
            }
            let ct = r.bytes().await.map_err(|e| Error::Http(e.to_string()))?;
            out.extend(chunking::decrypt_chunk(key, &node.id, &ct, &c.hash)?);
        }
        if chunking::content_hash(&out) != manifest.content_hash {
            return Err(Error::Crypto("content hash mismatch".into()));
        }
        Ok(out)
    }
}
