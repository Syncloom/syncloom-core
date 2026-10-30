//! Folder sync engine.
//!
//! Every pass reconciles three views of each file: the *base* (what local disk and server agreed on
//! at the last sync, stored in [`StateDb`]), the *local* file system, and the *remote* tree (a mirror
//! kept current through the change feed). Nodes are identified by their server id, never by path, so
//! renames and moves merge cleanly.
use crate::chunking;
use crate::client::{Client, Node};
use crate::error::{Error, Result};
use crate::merge::{self, MergeOutcome};
use crate::names;
use crate::node::NodeMeta;
use crate::state::{Entry, MirrorNode, StateDb};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TMP_PREFIX: &str = ".syncloom-tmp-";
const MAX_ROUNDS: usize = 4;

#[derive(Clone)]
pub struct SyncConfig {
    /// The local folder to keep in sync.
    pub root: PathBuf,
    /// Shown in conflict-copy names.
    pub device: String,
}

#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub uploaded: Vec<String>,
    pub downloaded: Vec<String>,
    pub deleted_local: Vec<String>,
    pub trashed_remote: Vec<String>,
    /// Concurrent edits that were merged automatically.
    pub merged: Vec<String>,
    /// Local renames/moves that were applied on the server without transferring content (`new path`).
    pub moved: Vec<String>,
    /// Paths of conflict copies that were created.
    pub conflicts: Vec<String>,
    pub skipped: Vec<(String, String)>,
    pub errors: Vec<String>,
}

impl SyncReport {
    pub fn is_empty(&self) -> bool {
        self.uploaded.is_empty()
            && self.downloaded.is_empty()
            && self.deleted_local.is_empty()
            && self.trashed_remote.is_empty()
            && self.merged.is_empty()
            && self.moved.is_empty()
            && self.conflicts.is_empty()
    }
    fn absorb(&mut self, o: SyncReport) {
        self.uploaded.extend(o.uploaded);
        self.downloaded.extend(o.downloaded);
        self.deleted_local.extend(o.deleted_local);
        self.trashed_remote.extend(o.trashed_remote);
        self.merged.extend(o.merged);
        self.moved.extend(o.moved);
        self.conflicts.extend(o.conflicts);
        self.skipped.extend(o.skipped);
        self.errors.extend(o.errors);
    }
}

#[derive(Debug, Clone)]
struct LocalInfo {
    dir: bool,
    size: u64,
    mtime_ms: i64,
    exec: bool,
    ino: u64,
}

struct Round {
    mirror: HashMap<String, MirrorNode>,
    entries: HashMap<String, Entry>,
    local: HashMap<String, LocalInfo>,
    report: SyncReport,
    retry: bool,
}

pub struct SyncEngine {
    client: Arc<Client>,
    cfg: SyncConfig,
    db: StateDb,
}

// ---------- small helpers ----------

fn depth(p: &str) -> usize {
    p.matches('/').count()
}
fn parent_of(p: &str) -> &str {
    p.rfind('/').map(|i| &p[..i]).unwrap_or("")
}
fn name_of(p: &str) -> &str {
    p.rfind('/').map(|i| &p[i + 1..]).unwrap_or(p)
}
fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}
fn under(p: &str, prefix: &str) -> bool {
    p == prefix || (p.starts_with(prefix) && p.as_bytes().get(prefix.len()) == Some(&b'/'))
}

fn mtime_ms(m: &fs::Metadata) -> i64 {
    m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[cfg(unix)]
fn ino_of(m: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.ino()
}
#[cfg(not(unix))]
fn ino_of(_: &fs::Metadata) -> u64 {
    0
}

#[cfg(unix)]
fn is_exec(m: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode() & 0o111 != 0
}
#[cfg(not(unix))]
fn is_exec(_: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn set_exec(path: &Path, exec: bool) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 }));
}
#[cfg(not(unix))]
fn set_exec(_: &Path, _: bool) {}

/// `YYYY-MM-DD` (UTC) without a date crate.
pub fn today_string() -> String {
    let days = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 / 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

fn hash_file(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path)?;
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().to_hex().to_string())
}

fn mirror_node(n: &Node) -> MirrorNode {
    MirrorNode {
        id: n.id.clone(),
        parent: n.parent_id.clone(),
        name: n.name.clone(),
        kind: n.kind.clone(),
        head: n.head_version.clone(),
        size: n.size,
        mtime_ms: n.meta.mtime_ms,
        executable: n.meta.executable,
        deleted: n.deleted,
    }
}

/// Where every live remote node should be on disk. Case/normalization collisions between siblings are
/// resolved deterministically so every pass computes the same names.
fn remote_paths(mirror: &HashMap<String, MirrorNode>) -> HashMap<String, String> {
    let mut kids: HashMap<Option<&str>, Vec<&MirrorNode>> = HashMap::new();
    for n in mirror.values().filter(|n| !n.deleted && (n.kind == "file" || n.kind == "folder")) {
        kids.entry(n.parent.as_deref()).or_default().push(n);
    }
    for v in kids.values_mut() {
        v.sort_by(|a, b| names::collision_key(&a.name).cmp(&names::collision_key(&b.name)).then(a.id.cmp(&b.id)));
    }
    let mut out = HashMap::new();
    let mut stack: Vec<(Option<&str>, String)> = vec![(None, String::new())];
    while let Some((parent, dir)) = stack.pop() {
        let mut used: Vec<String> = Vec::new();
        for n in kids.get(&parent).map(|v| v.as_slice()).unwrap_or(&[]) {
            let name = names::unique_name(used.iter().map(|s| s.as_str()), &names::sanitize(&n.name));
            used.push(name.clone());
            let path = join(&dir, &name);
            out.insert(n.id.clone(), path.clone());
            if n.kind == "folder" {
                stack.push((Some(n.id.as_str()), path));
            }
        }
    }
    out
}

impl SyncEngine {
    pub fn new(client: Arc<Client>, cfg: SyncConfig, db: StateDb) -> Result<SyncEngine> {
        fs::create_dir_all(&cfg.root)?;
        Ok(SyncEngine { client, cfg, db })
    }

    fn abs(&self, rel: &str) -> PathBuf {
        self.cfg.root.join(rel)
    }

    fn scan(&self) -> Result<(HashMap<String, LocalInfo>, Vec<(String, String)>)> {
        let mut out = HashMap::new();
        let mut skipped = Vec::new();
        for e in walkdir::WalkDir::new(&self.cfg.root).min_depth(1).follow_links(false).sort_by_file_name() {
            let e = match e {
                Ok(e) => e,
                Err(err) => {
                    skipped.push((String::new(), err.to_string()));
                    continue;
                }
            };
            let fname = e.file_name().to_string_lossy().to_string();
            if fname.starts_with(TMP_PREFIX) {
                continue;
            }
            let ft = e.file_type();
            if !ft.is_dir() && !ft.is_file() {
                continue; // symlinks and special files are not synced
            }
            let rel = e.path().strip_prefix(&self.cfg.root).unwrap().components().map(|c| c.as_os_str().to_string_lossy().to_string()).collect::<Vec<_>>().join("/");
            if let Err(err) = names::validate(&fname) {
                skipped.push((rel, err.to_string()));
                continue;
            }
            let m = e.metadata().map_err(|e| Error::Io(e.to_string()))?;
            out.insert(rel, LocalInfo { dir: ft.is_dir(), size: m.len(), mtime_ms: mtime_ms(&m), exec: is_exec(&m), ino: ino_of(&m) });
        }
        // anything below a skipped directory is not reachable either
        Ok((out, skipped))
    }

    // ---------- pulling remote changes ----------

    async fn refresh_node(&self, mirror: &mut HashMap<String, MirrorNode>, id: &str) -> Result<()> {
        match self.client.get(id).await {
            Ok(n) if n.owner_id == self.client.user_id() && (n.kind == "file" || n.kind == "folder") => {
                mirror.insert(n.id.clone(), mirror_node(&n));
            }
            Ok(_) => {}
            Err(Error::NotFound) => {
                mirror.remove(id);
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    async fn pull(&self, mirror: &mut HashMap<String, MirrorNode>, cursor: Option<i64>) -> Result<i64> {
        match cursor {
            None => {
                let head = self.client.changes_head().await?;
                mirror.clear();
                let mut stack: Vec<Option<String>> = vec![None];
                while let Some(parent) = stack.pop() {
                    for n in self.client.list(parent.as_deref()).await? {
                        if n.kind == "folder" {
                            stack.push(Some(n.id.clone()));
                        }
                        if n.kind == "file" || n.kind == "folder" {
                            mirror.insert(n.id.clone(), mirror_node(&n));
                        }
                    }
                }
                Ok(head)
            }
            Some(mut cur) => loop {
                let r = self.client.changes(cur, 500).await?;
                if r.changes.is_empty() {
                    return Ok(cur);
                }
                let mut seen = HashSet::new();
                for ch in r.changes {
                    match ch.kind.as_str() {
                        "kv" | "share" => {}
                        "purge" => {
                            mirror.remove(&ch.node_id);
                        }
                        _ => {
                            if seen.insert(ch.node_id.clone()) {
                                self.refresh_node(mirror, &ch.node_id).await?;
                            }
                        }
                    }
                }
                cur = r.next_cursor;
            },
        }
    }

    // ---------- main entry points ----------

    /// Reconcile once. Retries a few rounds when the server moved underneath us.
    pub async fn sync_once(&mut self) -> Result<SyncReport> {
        let mut total = SyncReport::default();
        for _ in 0..MAX_ROUNDS {
            let (report, retry) = self.round().await?;
            total.absorb(report);
            if !retry {
                break;
            }
        }
        Ok(total)
    }

    /// Keep syncing: wakes on server pushes (gRPC), and rescans the local folder every `poll`.
    pub async fn run(&mut self, mut stop: tokio::sync::watch::Receiver<bool>, poll: Duration, mut on_report: impl FnMut(&SyncReport)) -> Result<()> {
        let mut backoff = Duration::from_secs(1);
        loop {
            match self.sync_once().await {
                Ok(r) => {
                    if !r.is_empty() || !r.errors.is_empty() {
                        on_report(&r);
                    }
                    backoff = Duration::from_secs(1);
                }
                Err(Error::Auth(m)) => return Err(Error::Auth(m)),
                Err(e) => {
                    let mut r = SyncReport::default();
                    r.errors.push(e.to_string());
                    on_report(&r);
                    tokio::select! { _ = tokio::time::sleep(backoff) => {}, _ = stop.changed() => return Ok(()) }
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                    continue;
                }
            }
            let since = self.db.cursor()?.unwrap_or(0);
            let mut stream = self.client.subscribe(since).await.ok();
            let wake = async {
                match stream.as_mut() {
                    Some(s) => {
                        let _ = s.next_change().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                _ = wake => {},
                _ = tokio::time::sleep(poll) => {},
                _ = stop.changed() => return Ok(()),
            }
            if *stop.borrow() {
                return Ok(());
            }
        }
    }

    async fn round(&mut self) -> Result<(SyncReport, bool)> {
        let mut mirror = self.db.load_mirror()?;
        let entries = self.db.load_entries()?;
        let cursor = self.pull(&mut mirror, self.db.cursor()?).await?;
        let (local, skipped) = self.scan()?;
        let mut r = Round { mirror, entries, local, report: SyncReport::default(), retry: false };
        r.report.skipped = skipped;

        self.detect_moves(&mut r).await;
        let rpaths = remote_paths(&r.mirror);
        self.apply_remote(&mut r, &rpaths).await;
        self.apply_remote_deletions(&mut r, &rpaths).await;
        // local state changed a lot, take a fresh look before looking for new files
        match self.scan() {
            Ok((l, _)) => r.local = l,
            Err(e) => r.report.errors.push(e.to_string()),
        }
        self.apply_new_local(&mut r).await;

        self.db.save(Some(cursor), &r.mirror, &r.entries)?;
        Ok((r.report, r.retry))
    }

    // ---------- local renames and moves ----------

    /// A path that vanished and a new path with the same inode is a rename or move. Applying it as such
    /// keeps the node (history, shares, links) and transfers no content.
    async fn detect_moves(&self, r: &mut Round) {
        let known: HashSet<String> = r.entries.values().map(|e| e.path.clone()).collect();
        let mut by_ino: HashMap<u64, String> = HashMap::new();
        for (p, i) in &r.local {
            if i.ino != 0 && !known.contains(p) {
                by_ino.insert(i.ino, p.clone());
            }
        }
        if by_ino.is_empty() {
            return;
        }
        let mut moves: Vec<(String, String, String)> = Vec::new();
        for e in r.entries.values() {
            if e.ino == 0 || r.local.contains_key(&e.path) {
                continue;
            }
            if let Some(np) = by_ino.get(&e.ino) {
                let li = &r.local[np];
                let kind_ok = (e.kind == "folder") == li.dir;
                let content_ok = e.kind == "folder" || li.size == e.size || li.mtime_ms == e.mtime_ms;
                if kind_ok && content_ok {
                    moves.push((e.id.clone(), e.path.clone(), np.clone()));
                }
            }
        }
        // parents first, so a moved folder is already in place when its content moves
        moves.sort_by(|a, b| depth(&a.2).cmp(&depth(&b.2)).then(a.2.cmp(&b.2)));
        for (id, old, new) in moves {
            if let Err(e) = self.apply_move(r, &id, &old, &new).await {
                match e {
                    Error::Conflict => r.retry = true,
                    e => r.report.errors.push(format!("{old} -> {new}: {e}")),
                }
            }
        }
    }

    async fn apply_move(&self, r: &mut Round, id: &str, old: &str, new: &str) -> Result<()> {
        if r.entries.get(id).map(|e| e.path == new).unwrap_or(false) {
            return Ok(()); // already carried along by the move of its parent folder
        }
        let new_dir = parent_of(new).to_string();
        // make sure the destination folder exists remotely (create unknown ancestors top-down)
        let mut chain: Vec<String> = Vec::new();
        let mut d = new_dir.as_str();
        while !d.is_empty() && !r.entries.values().any(|e| e.path == d && e.kind == "folder") {
            chain.push(d.to_string());
            d = parent_of(d);
        }
        for anc in chain.into_iter().rev() {
            self.create_remote(r, &anc).await?;
        }
        let parent_id: Option<String> = if new_dir.is_empty() {
            None
        } else {
            match r.entries.values().find(|e| e.path == new_dir && e.kind == "folder") {
                Some(e) => Some(e.id.clone()),
                None => return Ok(()), // could not create it, fall back to delete + create
            }
        };
        let m = r.mirror.get(id).cloned().ok_or(Error::NotFound)?;
        if m.parent != parent_id {
            self.client.move_to(id, parent_id.as_deref()).await?;
            if let Some(x) = r.mirror.get_mut(id) {
                x.parent = parent_id;
            }
        }
        let new_name = name_of(new);
        if m.name != new_name {
            self.client.rename(id, new_name).await?;
            if let Some(x) = r.mirror.get_mut(id) {
                x.name = new_name.to_string();
            }
        }
        for e in r.entries.values_mut() {
            if under(&e.path, old) {
                e.path = format!("{new}{}", &e.path[old.len()..]);
            }
        }
        r.report.moved.push(new.to_string());
        Ok(())
    }

    // ---------- (a) nodes that exist on the server ----------

    async fn apply_remote(&self, r: &mut Round, rpaths: &HashMap<String, String>) {
        let mut order: Vec<(&String, &String)> = rpaths.iter().collect();
        order.sort_by(|a, b| depth(a.1).cmp(&depth(b.1)).then(a.1.cmp(b.1)));
        for (id, rpath) in order {
            if Self::under_deleted(r, id) {
                continue; // an ancestor was just trashed by us; handled via the entries it took with it
            }
            let res = match r.entries.get(id).cloned() {
                None => self.new_remote(r, id, rpath).await,
                Some(base) => self.existing(r, id, rpath, base).await,
            };
            if let Err(e) = res {
                match e {
                    Error::Conflict => r.retry = true,
                    e => r.report.errors.push(format!("{rpath}: {e}")),
                }
            }
        }
    }

    /// True if the node or any ancestor is trashed in the mirror.
    fn under_deleted(r: &Round, id: &str) -> bool {
        let mut cur = Some(id);
        let mut hops = 0;
        while let Some(c) = cur {
            match r.mirror.get(c) {
                Some(n) if n.deleted => return true,
                Some(n) => cur = n.parent.as_deref(),
                None => return false,
            }
            hops += 1;
            if hops > 4096 {
                return false;
            }
        }
        false
    }

    fn rebase(r: &mut Round, old: &str, new: &str) {
        for e in r.entries.values_mut() {
            if under(&e.path, old) {
                e.path = format!("{new}{}", &e.path[old.len()..]);
            }
        }
        let moved: Vec<String> = r.local.keys().filter(|k| under(k, old)).cloned().collect();
        for k in moved {
            if let Some(v) = r.local.remove(&k) {
                r.local.insert(format!("{new}{}", &k[old.len()..]), v);
            }
        }
    }

    fn ensure_parent(&self, rel: &str) -> Result<()> {
        if let Some(p) = self.abs(rel).parent() {
            fs::create_dir_all(p)?;
        }
        Ok(())
    }

    async fn download(&self, r: &mut Round, id: &str, rel: &str) -> Result<()> {
        let m = r.mirror.get(id).cloned().ok_or(Error::NotFound)?;
        self.ensure_parent(rel)?;
        let abs = self.abs(rel);
        let tmp = abs.with_file_name(format!("{TMP_PREFIX}{id}"));
        let manifest = {
            let mut f = fs::File::create(&tmp)?;
            let man = self.client.download_to(id, m.head.as_deref(), &mut f).await.inspect_err(|_| {
                let _ = fs::remove_file(&tmp);
            })?;
            f.flush()?;
            if m.mtime_ms > 0 {
                let _ = f.set_modified(UNIX_EPOCH + Duration::from_millis(m.mtime_ms as u64));
            }
            man
        };
        set_exec(&tmp, m.executable);
        if abs.is_dir() {
            let _ = fs::remove_file(&tmp);
            return Err(Error::Io(format!("{rel} is a directory locally")));
        }
        fs::rename(&tmp, &abs)?;
        let meta = fs::metadata(&abs)?;
        r.local.insert(rel.to_string(), LocalInfo { dir: false, size: meta.len(), mtime_ms: mtime_ms(&meta), exec: is_exec(&meta), ino: ino_of(&meta) });
        r.entries.insert(id.to_string(), Entry { id: id.into(), path: rel.into(), kind: "file".into(), version: m.head.clone(), hash: manifest.content_hash, size: manifest.size, mtime_ms: mtime_ms(&meta), ino: ino_of(&meta) });
        r.report.downloaded.push(rel.to_string());
        Ok(())
    }

    /// A node we have never synced.
    async fn new_remote(&self, r: &mut Round, id: &str, rpath: &str) -> Result<()> {
        let m = r.mirror.get(id).cloned().ok_or(Error::NotFound)?;
        if m.kind == "folder" {
            let abs = self.abs(rpath);
            if abs.is_file() {
                self.move_aside(r, rpath)?;
            }
            fs::create_dir_all(&abs)?;
            r.local.insert(rpath.to_string(), LocalInfo { dir: true, size: 0, mtime_ms: 0, exec: false, ino: 0 });
            r.entries.insert(id.to_string(), Entry { id: id.into(), path: rpath.into(), kind: "folder".into(), version: None, hash: String::new(), size: 0, mtime_ms: 0, ino: fs::metadata(&abs).map(|m| ino_of(&m)).unwrap_or(0) });
            return Ok(());
        }
        if let Some(l) = r.local.get(rpath).cloned() {
            if !l.dir {
                // same path exists on both sides: identical content is simply adopted, otherwise the local one becomes a conflict copy
                let remote = self.client.download_bytes(id, m.head.as_deref()).await?;
                if chunking::content_hash(&remote) == hash_file(&self.abs(rpath))? {
                    let meta = fs::metadata(self.abs(rpath))?;
                    r.entries.insert(id.to_string(), Entry { id: id.into(), path: rpath.into(), kind: "file".into(), version: m.head.clone(), hash: chunking::content_hash(&remote), size: remote.len() as u64, mtime_ms: mtime_ms(&meta), ino: ino_of(&meta) });
                    return Ok(());
                }
                self.move_aside(r, rpath)?;
            }
        }
        self.download(r, id, rpath).await
    }

    /// Rename a local file to a conflict-copy name so something else can take its place.
    fn move_aside(&self, r: &mut Round, rel: &str) -> Result<String> {
        let dir = parent_of(rel).to_string();
        let siblings: Vec<String> = r.local.keys().filter(|k| parent_of(k) == dir).map(|k| name_of(k).to_string()).collect();
        let desired = names::conflict_name(name_of(rel), &self.cfg.device, &today_string());
        let new_name = names::unique_name(siblings.iter().map(|s| s.as_str()), &desired);
        let new_rel = join(&dir, &new_name);
        fs::rename(self.abs(rel), self.abs(&new_rel))?;
        if let Some(info) = r.local.remove(rel) {
            r.local.insert(new_rel.clone(), info);
        }
        r.report.conflicts.push(new_rel.clone());
        Ok(new_rel)
    }

    async fn local_changed(&self, r: &mut Round, base: &Entry, rel: &str, info: &LocalInfo) -> Result<bool> {
        if info.size == base.size && info.mtime_ms == base.mtime_ms {
            return Ok(false);
        }
        if hash_file(&self.abs(rel))? == base.hash {
            if let Some(e) = r.entries.get_mut(&base.id) {
                e.mtime_ms = info.mtime_ms;
            }
            return Ok(false);
        }
        Ok(true)
    }

    async fn upload_version(&self, r: &mut Round, id: &str, rel: &str, base_version: Option<&str>) -> Result<()> {
        let before = fs::metadata(self.abs(rel))?;
        let v = self.client.upload_version(id, base_version, fs::File::open(self.abs(rel))?).await?;
        let meta = NodeMeta { mtime_ms: mtime_ms(&before), executable: is_exec(&before) };
        let _ = self.client.update_meta(id, &meta).await;
        if let Some(m) = r.mirror.get_mut(id) {
            m.head = Some(v.id.clone());
            m.size = v.size as i64;
            m.mtime_ms = meta.mtime_ms;
        }
        r.entries.insert(id.to_string(), Entry { id: id.into(), path: rel.into(), kind: "file".into(), version: Some(v.id), hash: v.content_hash, size: v.size, mtime_ms: mtime_ms(&before), ino: ino_of(&before) });
        r.report.uploaded.push(rel.to_string());
        Ok(())
    }

    async fn existing(&self, r: &mut Round, id: &str, rpath: &str, base: Entry) -> Result<()> {
        let m = r.mirror.get(id).cloned().ok_or(Error::NotFound)?;
        let lp = base.path.clone();
        let local_here = r.local.get(&lp).cloned();

        if m.kind == "folder" {
            match local_here {
                Some(l) if l.dir => {
                    if lp != rpath {
                        self.ensure_parent(rpath)?;
                        fs::rename(self.abs(&lp), self.abs(rpath))?;
                        Self::rebase(r, &lp, rpath);
                    }
                }
                Some(_) => return Err(Error::Io(format!("{lp} was a folder but is now a file"))),
                None => {
                    // deleted locally: remove it remotely, unless somebody added content there meanwhile
                    let unsynced_remote = r.mirror.values().any(|c| !c.deleted && c.parent.as_deref() == Some(id) && !r.entries.contains_key(&c.id));
                    if unsynced_remote {
                        fs::create_dir_all(self.abs(rpath))?;
                    } else {
                        self.trash_remote(r, id, &lp).await?;
                        return Ok(());
                    }
                }
            }
            if let Some(e) = r.entries.get_mut(id) {
                e.path = rpath.to_string();
            }
            r.local.entry(rpath.to_string()).or_insert(LocalInfo { dir: true, size: 0, mtime_ms: 0, exec: false, ino: 0 });
            return Ok(());
        }

        let remote_changed = m.head != base.version;
        let Some(l) = local_here.filter(|l| !l.dir) else {
            // the file is gone locally
            if remote_changed {
                return self.download(r, id, rpath).await;
            }
            return self.trash_remote(r, id, &lp).await;
        };
        let mut info = l;
        if lp != rpath {
            self.ensure_parent(rpath)?;
            if self.abs(rpath).exists() {
                return Err(Error::Io(format!("cannot move {lp} to {rpath}: target exists")));
            }
            fs::rename(self.abs(&lp), self.abs(rpath))?;
            if let Some(i) = r.local.remove(&lp) {
                r.local.insert(rpath.to_string(), i.clone());
                info = i;
            }
            if let Some(e) = r.entries.get_mut(id) {
                e.path = rpath.to_string();
            }
        }
        let base = r.entries.get(id).cloned().unwrap_or(base);
        let local_changed = self.local_changed(r, &base, rpath, &info).await?;
        match (local_changed, remote_changed) {
            (false, false) => Ok(()),
            (false, true) => self.download(r, id, rpath).await,
            (true, false) => self.upload_version(r, id, rpath, base.version.as_deref()).await,
            (true, true) => self.resolve_both(r, id, rpath, &base, &m).await,
        }
    }

    /// Both sides changed the same file since the last sync.
    async fn resolve_both(&self, r: &mut Round, id: &str, rel: &str, base: &Entry, m: &MirrorNode) -> Result<()> {
        let local_hash = hash_file(&self.abs(rel))?;
        let small = (m.size as usize) <= merge::MAX_TEXT_SIZE && (base.size as usize) <= merge::MAX_TEXT_SIZE && fs::metadata(self.abs(rel))?.len() as usize <= merge::MAX_TEXT_SIZE;
        if small {
            let remote = self.client.download_bytes(id, m.head.as_deref()).await?;
            if chunking::content_hash(&remote) == local_hash {
                // both sides made the same change
                let meta = fs::metadata(self.abs(rel))?;
                r.entries.insert(id.to_string(), Entry { id: id.into(), path: rel.into(), kind: "file".into(), version: m.head.clone(), hash: local_hash, size: remote.len() as u64, mtime_ms: mtime_ms(&meta), ino: ino_of(&meta) });
                return Ok(());
            }
            let local = fs::read(self.abs(rel))?;
            if let Some(bv) = base.version.as_deref() {
                if let Ok(basebytes) = self.client.download_bytes(id, Some(bv)).await {
                    if let MergeOutcome::Merged(merged) = merge::merge(&basebytes, &local, &remote) {
                        let tmp = self.abs(rel).with_file_name(format!("{TMP_PREFIX}{id}"));
                        fs::write(&tmp, &merged)?;
                        fs::rename(&tmp, self.abs(rel))?;
                        // publish on top of the remote head so nothing of theirs is lost
                        self.upload_version(r, id, rel, m.head.as_deref()).await?;
                        r.report.merged.push(rel.to_string());
                        return Ok(());
                    }
                }
            }
        }
        // could not merge: the server's version keeps the name, ours becomes a conflict copy that is uploaded as a new file
        self.move_aside(r, rel)?;
        self.download(r, id, rel).await
    }

    async fn trash_remote(&self, r: &mut Round, id: &str, rel: &str) -> Result<()> {
        match self.client.trash(id).await {
            Ok(()) | Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        if let Some(m) = r.mirror.get_mut(id) {
            m.deleted = true;
        }
        let gone: Vec<String> = r.entries.values().filter(|e| under(&e.path, rel)).map(|e| e.id.clone()).collect();
        for g in gone {
            r.entries.remove(&g);
        }
        r.report.trashed_remote.push(rel.to_string());
        Ok(())
    }

    // ---------- (b) nodes that disappeared from the server ----------

    /// Restore the topmost trashed ancestor-or-self of `id` ("an edit beats a delete").
    async fn restore_chain(&self, r: &mut Round, id: &str) -> Result<bool> {
        let mut top: Option<String> = None;
        let mut cur = Some(id.to_string());
        while let Some(c) = cur {
            match r.mirror.get(&c) {
                Some(n) => {
                    if n.deleted {
                        top = Some(n.id.clone());
                    }
                    cur = n.parent.clone();
                }
                None => break,
            }
        }
        match top {
            Some(t) => match self.client.restore(&t).await {
                Ok(_) | Err(Error::Conflict) => Ok(true),
                Err(Error::NotFound) => Ok(false),
                Err(e) => Err(e),
            },
            None => Ok(false),
        }
    }

    async fn apply_remote_deletions(&self, r: &mut Round, rpaths: &HashMap<String, String>) {
        let mut gone: Vec<Entry> = r.entries.values().filter(|e| !rpaths.contains_key(&e.id)).cloned().collect();
        gone.sort_by(|a, b| depth(&b.path).cmp(&depth(&a.path)).then(b.path.cmp(&a.path)));
        for e in gone {
            if !r.entries.contains_key(&e.id) {
                continue; // already dropped (e.g. we trashed its parent)
            }
            if let Err(err) = self.handle_deleted(r, &e).await {
                r.report.errors.push(format!("{}: {err}", e.path));
            }
        }
    }

    async fn handle_deleted(&self, r: &mut Round, e: &Entry) -> Result<()> {
        let info = r.local.get(&e.path).cloned();
        let Some(info) = info else {
            r.entries.remove(&e.id);
            return Ok(());
        };
        if e.kind == "folder" {
            let known: HashSet<&str> = r.entries.values().filter(|x| under(&x.path, &e.path) && x.id != e.id).map(|x| x.path.as_str()).collect();
            let has_unsynced = r.local.keys().any(|k| under(k, &e.path) && k != &e.path && !known.contains(k.as_str()));
            if has_unsynced {
                if self.restore_chain(r, &e.id).await? {
                    r.retry = true;
                } else {
                    r.entries.remove(&e.id);
                }
                return Ok(());
            }
            if r.local.keys().any(|k| under(k, &e.path) && k != &e.path) {
                // children are handled first (deeper paths); if some are left something else is going on
                return Ok(());
            }
            let _ = fs::remove_dir(self.abs(&e.path));
            r.local.remove(&e.path);
            r.entries.remove(&e.id);
            r.report.deleted_local.push(e.path.clone());
            return Ok(());
        }
        let changed = if info.dir { false } else { self.local_changed(r, e, &e.path, &info).await? };
        if changed {
            // we edited what someone else deleted: bring it back
            if self.restore_chain(r, &e.id).await? {
                r.retry = true;
            } else {
                // purged for good: the file becomes a brand new node
                r.entries.remove(&e.id);
            }
            return Ok(());
        }
        fs::remove_file(self.abs(&e.path))?;
        r.local.remove(&e.path);
        r.entries.remove(&e.id);
        r.report.deleted_local.push(e.path.clone());
        Ok(())
    }

    // ---------- (c) files and folders that are new locally ----------

    async fn apply_new_local(&self, r: &mut Round) {
        let known: HashSet<String> = r.entries.values().map(|e| e.path.clone()).collect();
        let mut fresh: Vec<String> = r.local.keys().filter(|k| !known.contains(*k)).cloned().collect();
        fresh.sort_by(|a, b| depth(a).cmp(&depth(b)).then(a.cmp(b)));
        for rel in fresh {
            if !r.local.contains_key(&rel) {
                continue;
            }
            if let Err(e) = self.create_remote(r, &rel).await {
                match e {
                    Error::Conflict => r.retry = true,
                    e => r.report.errors.push(format!("{rel}: {e}")),
                }
            }
        }
    }

    async fn create_remote(&self, r: &mut Round, rel: &str) -> Result<()> {
        let dir = parent_of(rel).to_string();
        let parent_id: Option<String> = if dir.is_empty() {
            None
        } else {
            match r.entries.values().find(|e| e.path == dir && e.kind == "folder") {
                Some(e) => Some(e.id.clone()),
                None => return Ok(()), // the parent could not be created (yet), try again next pass
            }
        };
        let info = r.local.get(rel).cloned().ok_or(Error::NotFound)?;
        let mut rel = rel.to_string();
        // a sibling with the same (case-/normalization-insensitive) name that we do not map to this path
        let sibling_names: Vec<String> = r.mirror.values().filter(|n| !n.deleted && n.parent == parent_id).map(|n| n.name.clone()).collect();
        if names::find_collision(sibling_names.iter().map(|s| s.as_str()), name_of(&rel)).is_some() {
            if info.dir {
                let unique = names::unique_name(sibling_names.iter().map(|s| s.as_str()), name_of(&rel));
                let new_rel = join(&dir, &unique);
                fs::rename(self.abs(&rel), self.abs(&new_rel))?;
                if let Some(i) = r.local.remove(&rel) {
                    r.local.insert(new_rel.clone(), i);
                }
                Self::rebase_locals_only(r, &rel, &new_rel);
                rel = new_rel;
            } else {
                rel = self.move_aside(r, &rel)?;
            }
        }
        let name = name_of(&rel).to_string();
        if info.dir {
            let n = self.client.create_folder(parent_id.as_deref(), &name).await?;
            r.mirror.insert(n.id.clone(), mirror_node(&n));
            r.entries.insert(n.id.clone(), Entry { id: n.id, path: rel.clone(), kind: "folder".into(), version: None, hash: String::new(), size: 0, mtime_ms: 0, ino: info.ino });
            r.report.uploaded.push(rel);
            return Ok(());
        }
        let meta = NodeMeta { mtime_ms: info.mtime_ms, executable: info.exec };
        let n = self.client.create_file_node(parent_id.as_deref(), &name, &meta).await?;
        r.mirror.insert(n.id.clone(), mirror_node(&n));
        self.upload_version(r, &n.id, &rel, None).await
    }

    fn rebase_locals_only(r: &mut Round, old: &str, new: &str) {
        let moved: Vec<String> = r.local.keys().filter(|k| k.len() > old.len() && under(k, old)).cloned().collect();
        for k in moved {
            if let Some(v) = r.local.remove(&k) {
                r.local.insert(format!("{new}{}", &k[old.len()..]), v);
            }
        }
    }
}
