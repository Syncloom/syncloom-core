//! A tiny C ABI: `syncloom_call(request_json) -> response_json`. Used by the Windows app (P/Invoke) and any
//! host that cannot use the generated bindings. Every response is `{"ok": ...}` or `{"error": "..."}`.
//! Sessions are kept in the library and referred to by an integer `handle`.
use crate::ffi::{Authenticator, FfiLogin, FfiNode, Session};
use crate::state::StateDb;
use crate::sync::SyncConfig;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::{c_char, CStr, CString};
use std::sync::{Arc, Mutex, OnceLock};

fn sessions() -> &'static Mutex<HashMap<u64, Arc<Session>>> {
    static S: OnceLock<Mutex<HashMap<u64, Arc<Session>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_handle() -> u64 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn node(n: &FfiNode) -> Value {
    json!({ "id": n.id, "parent_id": n.parent_id, "owner_id": n.owner_id, "kind": n.kind, "name": n.name, "size": n.size,
            "mtime_ms": n.mtime_ms, "executable": n.executable, "head_version": n.head_version, "deleted": n.deleted,
            "updated_at": n.updated_at, "access": n.access })
}

fn login(l: FfiLogin) -> Value {
    match l {
        FfiLogin::Ok { token } => json!({ "status": "ok", "token": token }),
        FfiLogin::MfaRequired { token, methods } => json!({ "status": "mfa_required", "token": token, "methods": methods }),
        FfiLogin::EnrollRequired { token } => json!({ "status": "enroll_required", "token": token }),
    }
}

fn s(v: &Value, k: &str) -> Result<String, String> {
    v.get(k).and_then(|x| x.as_str()).map(String::from).ok_or_else(|| format!("missing string field `{k}`"))
}
fn opt(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(String::from)
}

fn session(v: &Value) -> Result<Arc<Session>, String> {
    let h = v.get("handle").and_then(|x| x.as_u64()).ok_or("missing `handle`")?;
    sessions().lock().unwrap().get(&h).cloned().ok_or_else(|| "unknown or closed handle".to_string())
}

fn dispatch(req: &Value) -> Result<Value, String> {
    let e = |e: crate::Error| e.to_string();
    let op = s(req, "op")?;
    match op.as_str() {
        "login" => Ok(login(Authenticator::new(s(req, "server")?).login(s(req, "username")?, s(req, "password")?, s(req, "device")?).map_err(e)?)),
        "register" => {
            let r = Authenticator::new(s(req, "server")?).register(s(req, "username")?, s(req, "password")?, opt(req, "invite"), s(req, "device")?).map_err(e)?;
            Ok(json!({ "login": login(r.login), "recovery_key": r.recovery_key }))
        }
        "mfa_verify" => Ok(json!({ "token": Authenticator::new(s(req, "server")?).mfa_verify(s(req, "token")?, s(req, "method")?, s(req, "code")?, s(req, "device")?).map_err(e)? })),
        "totp_setup" => {
            let r = Authenticator::new(s(req, "server")?).totp_setup(s(req, "token")?, s(req, "name")?).map_err(e)?;
            Ok(json!({ "id": r.id, "secret": r.secret, "otpauth_url": r.otpauth_url }))
        }
        "totp_confirm" => {
            let r = Authenticator::new(s(req, "server")?).totp_confirm(s(req, "token")?, s(req, "id")?, s(req, "code")?, s(req, "device")?).map_err(e)?;
            Ok(json!({ "recovery_codes": r.recovery_codes, "token": r.token }))
        }
        "connect" | "from_secrets" => {
            let sess = if op == "connect" {
                Session::connect(s(req, "server")?, s(req, "token")?, s(req, "password")?)
            } else {
                let secrets = B64.decode(s(req, "secrets")?).map_err(|e| e.to_string())?;
                Session::from_secrets(s(req, "server")?, s(req, "token")?, secrets)
            }
            .map_err(e)?;
            let secrets = B64.encode(sess.export_secrets());
            let h = next_handle();
            sessions().lock().unwrap().insert(h, sess);
            Ok(json!({ "handle": h, "secrets": secrets }))
        }
        "close" => {
            let h = req.get("handle").and_then(|x| x.as_u64()).ok_or("missing `handle`")?;
            sessions().lock().unwrap().remove(&h);
            Ok(json!(true))
        }
        "me" => {
            let u = session(req)?.me().map_err(e)?;
            Ok(json!({ "id": u.id, "username": u.username, "role": u.role, "quota_bytes": u.quota_bytes, "used_bytes": u.used_bytes }))
        }
        "list" => Ok(Value::Array(session(req)?.list(opt(req, "parent")).map_err(e)?.iter().map(node).collect())),
        "get" => Ok(node(&session(req)?.get(s(req, "id")?).map_err(e)?)),
        "shared_with_me" => Ok(Value::Array(session(req)?.shared_with_me().map_err(e)?.iter().map(node).collect())),
        "trash_list" => Ok(Value::Array(session(req)?.trash_list().map_err(e)?.iter().map(node).collect())),
        "create_folder" => Ok(node(&session(req)?.create_folder(opt(req, "parent"), s(req, "name")?).map_err(e)?)),
        "rename" => Ok(node(&session(req)?.rename(s(req, "id")?, s(req, "name")?).map_err(e)?)),
        "trash" => session(req)?.trash(s(req, "id")?).map(|_| json!(true)).map_err(e),
        "restore" => Ok(node(&session(req)?.restore(s(req, "id")?).map_err(e)?)),
        "upload_new_file" => Ok(node(&session(req)?.upload_new_file(opt(req, "parent"), s(req, "name")?, s(req, "path")?, req.get("mtime_ms").and_then(|x| x.as_i64()).unwrap_or(0), false).map_err(e)?)),
        "download_file" => session(req)?.download_file(s(req, "id")?, opt(req, "version"), s(req, "dest")?).map(|_| json!(true)).map_err(e),
        "upload_version" => Ok(node(&session(req)?.upload_version(s(req, "id")?, opt(req, "base_version"), s(req, "path")?, req.get("mtime_ms").and_then(|x| x.as_i64()).unwrap_or(0)).map_err(e)?)),
        "versions" => Ok(Value::Array(session(req)?.versions(s(req, "id")?).map_err(e)?.iter().map(|v| json!({ "id": v.id, "size": v.size, "content_hash": v.content_hash, "created_at": v.created_at, "device": v.device })).collect())),
        // the content hash of a local file, the same BLAKE3 that versions carry, to tell whether a local file equals a version on the server
        "hash_file" => {
            use std::io::Read;
            let mut f = std::fs::File::open(s(req, "path")?).map_err(|x| x.to_string())?;
            let (mut h, mut buf) = (blake3::Hasher::new(), vec![0u8; 1 << 20]);
            loop {
                let n = f.read(&mut buf).map_err(|x| x.to_string())?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(json!(h.finalize().to_hex().to_string()))
        }
        "move_to" => Ok(node(&session(req)?.move_to(s(req, "id")?, opt(req, "new_parent")).map_err(e)?)),
        "changes" => {
            let r = session(req)?.changes(req.get("since").and_then(|x| x.as_i64()).unwrap_or(0), req.get("limit").and_then(|x| x.as_i64()).unwrap_or(500)).map_err(e)?;
            Ok(json!({ "next_cursor": r.next_cursor, "changes": r.changes.iter().map(|c| json!({ "cursor": c.cursor, "node_id": c.node_id, "kind": c.kind })).collect::<Vec<_>>() }))
        }
        "create_link" => Ok(json!({ "url": session(req)?.create_link(s(req, "id")?, opt(req, "password"), None, None).map_err(e)?.url })),
        "mfa_methods" => Ok(Value::Array(session(req)?.mfa_methods().map_err(e)?.iter().map(|m| json!({ "id": m.id, "kind": m.kind, "name": m.name })).collect())),
        "changes_head" => Ok(json!(session(req)?.changes_head().map_err(e)?)),
        "sync_once" => {
            // reconcile a local folder with the server (the folder-sync engine of the desktop clients)
            let sess = session(req)?;
            let cfg = SyncConfig { root: s(req, "root")?.into(), device: s(req, "device")? };
            let db = StateDb::open(std::path::Path::new(&s(req, "state_db")?)).map_err(e)?;
            let r = crate::ffi::run_sync(&sess, cfg, db).map_err(e)?;
            Ok(json!({ "uploaded": r.uploaded, "downloaded": r.downloaded, "deleted_local": r.deleted_local, "trashed_remote": r.trashed_remote,
                       "merged": r.merged, "moved": r.moved, "conflicts": r.conflicts, "errors": r.errors }))
        }
        other => Err(format!("unknown op `{other}`")),
    }
}

/// Handle one request. The returned string must be released with [`syncloom_free`].
///
/// # Safety
/// `request` must point to a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn syncloom_call(request: *const c_char) -> *mut c_char {
    let out = std::panic::catch_unwind(|| {
        let text = unsafe { CStr::from_ptr(request) }.to_string_lossy().to_string();
        match serde_json::from_str::<Value>(&text).map_err(|e| e.to_string()).and_then(|v| dispatch(&v)) {
            Ok(v) => json!({ "ok": v }),
            Err(m) => json!({ "error": m }),
        }
    })
    .unwrap_or_else(|_| json!({ "error": "internal panic" }));
    CString::new(out.to_string()).unwrap().into_raw()
}

/// # Safety
/// `p` must come from [`syncloom_call`] and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn syncloom_free(p: *mut c_char) {
    if !p.is_null() {
        drop(unsafe { CString::from_raw(p) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(v: Value) -> Value {
        let req = CString::new(v.to_string()).unwrap();
        let p = unsafe { syncloom_call(req.as_ptr()) };
        let out = unsafe { CStr::from_ptr(p) }.to_string_lossy().to_string();
        unsafe { syncloom_free(p) };
        serde_json::from_str(&out).unwrap()
    }

    #[test]
    fn hash_file_matches_the_hash_versions_carry() {
        let path = std::env::temp_dir().join(format!("syncloom-hash-{}", std::process::id()));
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i * 31 % 251) as u8).collect(); // more than one read buffer
        std::fs::write(&path, &data).unwrap();
        let r = call(json!({ "op": "hash_file", "path": path.to_str().unwrap() }));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(r["ok"].as_str().unwrap(), crate::chunking::content_hash(&data));
        assert!(call(json!({ "op": "hash_file", "path": "/no/such/file" }))["error"].is_string());
    }

    #[test]
    fn errors_are_reported_as_json() {
        assert!(call(json!({ "op": "nope" }))["error"].as_str().unwrap().contains("unknown op"));
        assert!(call(json!({ "op": "list", "handle": 12345 }))["error"].as_str().unwrap().contains("handle"));
        assert!(call(json!({ "op": "login" }))["error"].as_str().unwrap().contains("missing"));
        for op in ["upload_version", "move_to", "changes", "versions"] {
            assert!(call(json!({ "op": op, "handle": 12345 }))["error"].as_str().unwrap().contains("handle"), "{op} is part of the C ABI");
        }
        assert!(call(json!("not an object"))["error"].is_string());
        let unreachable = call(json!({ "op": "login", "server": "http://127.0.0.1:1", "username": "a", "password": "b", "device": "t" }));
        assert!(unreachable["error"].is_string());
    }
}
