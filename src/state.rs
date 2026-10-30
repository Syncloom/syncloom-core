//! Local SQLite state of the sync engine: a mirror of the server tree plus the last synced snapshot.
use crate::error::{Error, Result};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::Path;

fn db_err(e: rusqlite::Error) -> Error {
    Error::Db(e.to_string())
}

/// A node as last seen on the server.
#[derive(Debug, Clone, PartialEq)]
pub struct MirrorNode {
    pub id: String,
    pub parent: Option<String>,
    pub name: String,
    pub kind: String,
    pub head: Option<String>,
    pub size: i64,
    pub mtime_ms: i64,
    pub executable: bool,
    pub deleted: bool,
}

/// What the local file system and the server agreed on at the last successful sync of a node.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub id: String,
    pub path: String,
    pub kind: String,
    pub version: Option<String>,
    pub hash: String,
    pub size: u64,
    pub mtime_ms: i64,
    /// Inode number (Unix), used to recognise renames and moves. 0 = unknown.
    pub ino: u64,
}

pub struct StateDb {
    conn: std::sync::Mutex<Connection>,
}

impl StateDb {
    pub fn open(path: &Path) -> Result<StateDb> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        Self::init(Connection::open(path).map_err(db_err)?)
    }

    pub fn in_memory() -> Result<StateDb> {
        Self::init(Connection::open_in_memory().map_err(db_err)?)
    }

    fn init(conn: Connection) -> Result<StateDb> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS mirror (
                 id TEXT PRIMARY KEY, parent TEXT, name TEXT NOT NULL, kind TEXT NOT NULL, head TEXT,
                 size INTEGER NOT NULL, mtime_ms INTEGER NOT NULL, executable INTEGER NOT NULL, deleted INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS entries (
                 id TEXT PRIMARY KEY, path TEXT NOT NULL, kind TEXT NOT NULL, version TEXT, hash TEXT NOT NULL,
                 size INTEGER NOT NULL, mtime_ms INTEGER NOT NULL, ino INTEGER NOT NULL DEFAULT 0);",
        )
        .map_err(db_err)?;
        Ok(StateDb { conn: std::sync::Mutex::new(conn) })
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        match self.conn.lock().unwrap().query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| r.get(0)) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err(e)),
        }
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.lock().unwrap().execute("INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", params![key, value]).map_err(db_err)?;
        Ok(())
    }

    pub fn cursor(&self) -> Result<Option<i64>> {
        Ok(self.get_meta("cursor")?.and_then(|v| v.parse().ok()))
    }

    pub fn load_mirror(&self) -> Result<HashMap<String, MirrorNode>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn.prepare("SELECT id, parent, name, kind, head, size, mtime_ms, executable, deleted FROM mirror").map_err(db_err)?;
        let rows = st
            .query_map([], |r| {
                Ok(MirrorNode {
                    id: r.get(0)?,
                    parent: r.get(1)?,
                    name: r.get(2)?,
                    kind: r.get(3)?,
                    head: r.get(4)?,
                    size: r.get(5)?,
                    mtime_ms: r.get(6)?,
                    executable: r.get::<_, i64>(7)? != 0,
                    deleted: r.get::<_, i64>(8)? != 0,
                })
            })
            .map_err(db_err)?;
        let mut m = HashMap::new();
        for r in rows {
            let n = r.map_err(db_err)?;
            m.insert(n.id.clone(), n);
        }
        Ok(m)
    }

    pub fn load_entries(&self) -> Result<HashMap<String, Entry>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn.prepare("SELECT id, path, kind, version, hash, size, mtime_ms, ino FROM entries").map_err(db_err)?;
        let rows = st
            .query_map([], |r| Ok(Entry { id: r.get(0)?, path: r.get(1)?, kind: r.get(2)?, version: r.get(3)?, hash: r.get(4)?, size: r.get::<_, i64>(5)? as u64, mtime_ms: r.get(6)?, ino: r.get::<_, i64>(7)? as u64 }))
            .map_err(db_err)?;
        let mut m = HashMap::new();
        for r in rows {
            let e = r.map_err(db_err)?;
            m.insert(e.id.clone(), e);
        }
        Ok(m)
    }

    /// Replace everything in one transaction.
    pub fn save(&mut self, cursor: Option<i64>, mirror: &HashMap<String, MirrorNode>, entries: &HashMap<String, Entry>) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(db_err)?;
        tx.execute("DELETE FROM mirror", []).map_err(db_err)?;
        tx.execute("DELETE FROM entries", []).map_err(db_err)?;
        {
            let mut ins = tx.prepare("INSERT INTO mirror VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)").map_err(db_err)?;
            for n in mirror.values() {
                ins.execute(params![n.id, n.parent, n.name, n.kind, n.head, n.size, n.mtime_ms, n.executable as i64, n.deleted as i64]).map_err(db_err)?;
            }
            let mut ins = tx.prepare("INSERT INTO entries VALUES (?1,?2,?3,?4,?5,?6,?7,?8)").map_err(db_err)?;
            for e in entries.values() {
                ins.execute(params![e.id, e.path, e.kind, e.version, e.hash, e.size as i64, e.mtime_ms, e.ino as i64]).map_err(db_err)?;
            }
        }
        if let Some(c) = cursor {
            tx.execute("INSERT INTO meta (key, value) VALUES ('cursor', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value", params![c.to_string()]).map_err(db_err)?;
        }
        tx.commit().map_err(db_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut db = StateDb::in_memory().unwrap();
        assert_eq!(db.cursor().unwrap(), None);
        let mut mirror = HashMap::new();
        mirror.insert("a".into(), MirrorNode { id: "a".into(), parent: None, name: "x".into(), kind: "file".into(), head: Some("v".into()), size: 3, mtime_ms: 4, executable: true, deleted: false });
        let mut entries = HashMap::new();
        entries.insert("a".into(), Entry { id: "a".into(), path: "x".into(), kind: "file".into(), version: Some("v".into()), hash: "h".into(), size: 3, mtime_ms: 4, ino: 9 });
        db.save(Some(42), &mirror, &entries).unwrap();
        assert_eq!(db.cursor().unwrap(), Some(42));
        assert_eq!(db.load_mirror().unwrap(), mirror);
        assert_eq!(db.load_entries().unwrap(), entries);
    }
}
