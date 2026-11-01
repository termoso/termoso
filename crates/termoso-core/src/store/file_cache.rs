//! Offline copies of remote files (SFTP). A file lands in the cache only when
//! it is read; the body is an encrypted file on disk (vault key, like session
//! logs) and the index is a device-local table that is never synced. Cached
//! directory listings let the browser work read-only while offline.

use std::path::{Path, PathBuf};

use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use termoso_crypto::aead::{self, Aad};
use uuid::Uuid;

use super::{Store, parse_time, parse_uuid};
use crate::error::{CoreError, Result};

/// How the Android documents provider behaves when the host is unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SafOfflineMode {
    /// Fail the request and let the app ask the user first.
    #[default]
    Ask,
    /// Serve local copies right away.
    Serve,
}

/// Per-host cache settings, stored on this device only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCacheConfig {
    /// Keep local copies of files read from this host.
    #[serde(default)]
    pub enabled: bool,
    /// Files larger than this are never cached.
    #[serde(default = "FileCacheConfig::default_max_file_bytes")]
    pub max_file_bytes: u64,
    /// Total budget for this host; oldest entries are evicted past it.
    #[serde(default = "FileCacheConfig::default_max_total_bytes")]
    pub max_total_bytes: u64,
    /// Only paths under these prefixes are cached. Empty = everything.
    #[serde(default)]
    pub include_paths: Vec<String>,
    /// Paths under these prefixes are never cached.
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    /// Documents-provider behaviour when the host is unreachable.
    #[serde(default)]
    pub saf_offline: SafOfflineMode,
}

impl Default for FileCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_file_bytes: Self::default_max_file_bytes(),
            max_total_bytes: Self::default_max_total_bytes(),
            include_paths: Vec::new(),
            exclude_paths: Vec::new(),
            saf_offline: SafOfflineMode::Ask,
        }
    }
}

impl FileCacheConfig {
    fn default_max_file_bytes() -> u64 {
        32 * 1024 * 1024
    }
    fn default_max_total_bytes() -> u64 {
        512 * 1024 * 1024
    }

    /// Whether a file at `path` of `size` bytes may be cached under this config.
    pub fn accepts(&self, path: &str, size: u64) -> bool {
        if !self.enabled || size > self.max_file_bytes || size > self.max_total_bytes {
            return false;
        }
        if self.exclude_paths.iter().any(|p| under(path, p)) {
            return false;
        }
        self.include_paths.is_empty() || self.include_paths.iter().any(|p| under(path, p))
    }
}

fn under(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    path == prefix || path.starts_with(prefix) && path[prefix.len()..].starts_with('/')
}

/// What a cache row holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheKind {
    /// File content.
    File,
    /// A directory listing (JSON array of entries).
    Dir,
}

impl CacheKind {
    fn as_str(self) -> &'static str {
        match self {
            CacheKind::File => "file",
            CacheKind::Dir => "dir",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        match s {
            "file" => Ok(CacheKind::File),
            "dir" => Ok(CacheKind::Dir),
            other => Err(CoreError::Invalid(format!("bad cache kind {other}"))),
        }
    }
}

/// Index row of a cached file or directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedEntry {
    /// Host the copy belongs to.
    pub host_id: Uuid,
    /// Remote path (directory path for listings).
    pub path: String,
    /// File or listing.
    pub kind: CacheKind,
    /// Remote size for files, number of entries for listings.
    pub size: u64,
    /// Remote mtime (unix seconds) as seen when cached.
    pub mtime: Option<i64>,
    /// When the copy was taken.
    pub cached_at: chrono::DateTime<Utc>,
    /// Last read through the cache; drives LRU eviction.
    pub last_used: chrono::DateTime<Utc>,
    /// Bytes on disk (ciphertext).
    pub bytes: u64,
}

impl CachedEntry {
    /// True when the remote file still matches what we cached.
    pub fn is_fresh(&self, remote_size: u64, remote_mtime: Option<i64>) -> bool {
        self.size == remote_size && self.mtime == remote_mtime
    }
}

/// Cache footprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FileCacheUsage {
    /// Cached files.
    pub files: u64,
    /// Cached directory listings.
    pub dirs: u64,
    /// Ciphertext bytes on disk.
    pub bytes: u64,
}

fn body_aad(host_id: Uuid, path: &str) -> Aad {
    Aad::label(&["fcache", &host_id.to_string(), path])
}

/// Deterministic file name so a re-cache of the same path overwrites in place.
fn body_name(host_id: Uuid, kind: CacheKind, path: &str) -> String {
    let mut h = Sha256::new();
    h.update(host_id.as_bytes());
    h.update([0u8]);
    h.update(kind.as_str().as_bytes());
    h.update([0u8]);
    h.update(path.as_bytes());
    format!("{}.tfc", hex::encode(&h.finalize()[..20]))
}

fn dir_key(path: &str) -> String {
    format!("{}\u{0}dir", path.trim_end_matches('/'))
}

fn norm(path: &str) -> &str {
    if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    }
}

impl Store {
    // ---- config ---------------------------------------------------------

    /// Cache settings of a host (defaults when never configured).
    pub fn file_cache_config(&self, host_id: Uuid) -> Result<FileCacheConfig> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT config FROM file_cache_config WHERE host_id = ?1",
                params![host_id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match json {
            Some(j) => serde_json::from_str(&j)?,
            None => FileCacheConfig::default(),
        })
    }

    /// Saving a disabled config also drops the host's copies.
    pub fn set_file_cache_config(&self, host_id: Uuid, cfg: &FileCacheConfig) -> Result<()> {
        self.conn().execute(
            "INSERT INTO file_cache_config (host_id, config) VALUES (?1, ?2)
             ON CONFLICT(host_id) DO UPDATE SET config = excluded.config",
            params![host_id.to_string(), serde_json::to_string(cfg)?],
        )?;
        if !cfg.enabled {
            self.clear_file_cache(Some(host_id))?;
        } else {
            self.evict_file_cache(host_id, cfg.max_total_bytes)?;
        }
        Ok(())
    }

    // ---- files ------------------------------------------------------------

    /// Store a copy of `path` read from `host_id`. Returns `Ok(false)` when
    /// the host config rejects it (disabled, too large, outside include
    /// paths); nothing is written then.
    pub fn cache_file(
        &self,
        host_id: Uuid,
        vault_id: Uuid,
        path: &str,
        mtime: Option<i64>,
        body: &[u8],
        dir: &Path,
    ) -> Result<bool> {
        let cfg = self.file_cache_config(host_id)?;
        let path = norm(path);
        if !cfg.accepts(path, body.len() as u64) {
            return Ok(false);
        }
        self.write_entry(
            host_id,
            vault_id,
            CacheKind::File,
            path,
            body.len() as u64,
            mtime,
            body,
            dir,
        )?;
        self.evict_file_cache(host_id, cfg.max_total_bytes)?;
        Ok(true)
    }

    /// Index entry for `path`, if cached. Does not touch `last_used`.
    pub fn cached_file(&self, host_id: Uuid, path: &str) -> Result<Option<CachedEntry>> {
        self.entry(host_id, norm(path))
    }

    /// Decrypted content of a cached file; bumps `last_used`.
    pub fn read_cached_file(&self, host_id: Uuid, path: &str) -> Result<Vec<u8>> {
        let path = norm(path);
        let (row, local) = self
            .entry_with_path(host_id, path)?
            .ok_or_else(|| CoreError::NotFound(format!("{path} is not cached")))?;
        let body = self.read_body(&row, &local, path)?;
        self.touch(host_id, path)?;
        Ok(body)
    }

    /// Cached listing of `dir_path`, if any.
    pub fn cached_dir(&self, host_id: Uuid, dir_path: &str) -> Result<Option<CachedEntry>> {
        self.entry(host_id, &dir_key(dir_path))
    }

    /// Store a directory listing (any serializable entries). Listings are
    /// kept whenever the cache is enabled; they do not count against size
    /// limits beyond their own bytes.
    pub fn cache_dir<T: Serialize>(
        &self,
        host_id: Uuid,
        vault_id: Uuid,
        dir_path: &str,
        entries: &[T],
        dir: &Path,
    ) -> Result<bool> {
        if !self.file_cache_config(host_id)?.enabled {
            return Ok(false);
        }
        let body = serde_json::to_vec(entries)?;
        self.write_entry(
            host_id,
            vault_id,
            CacheKind::Dir,
            &dir_key(dir_path),
            entries.len() as u64,
            None,
            &body,
            dir,
        )?;
        Ok(true)
    }

    /// Decode a cached listing; bumps `last_used`.
    pub fn read_cached_dir<T: for<'de> Deserialize<'de>>(
        &self,
        host_id: Uuid,
        dir_path: &str,
    ) -> Result<Vec<T>> {
        let key = dir_key(dir_path);
        let (row, local) = self
            .entry_with_path(host_id, &key)?
            .ok_or_else(|| CoreError::NotFound(format!("{dir_path} listing is not cached")))?;
        let body = self.read_body(&row, &local, &key)?;
        self.touch(host_id, &key)?;
        Ok(serde_json::from_slice(&body)?)
    }

    /// Remove one cached file or listing.
    pub fn remove_cached(&self, host_id: Uuid, path: &str, is_dir: bool) -> Result<()> {
        let key = if is_dir {
            dir_key(path)
        } else {
            norm(path).to_string()
        };
        let local: Option<String> = self
            .conn()
            .query_row(
                "SELECT local_path FROM file_cache WHERE host_id = ?1 AND path = ?2",
                params![host_id.to_string(), key],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(local) = local {
            let _ = std::fs::remove_file(local);
            self.conn().execute(
                "DELETE FROM file_cache WHERE host_id = ?1 AND path = ?2",
                params![host_id.to_string(), key],
            )?;
        }
        Ok(())
    }

    // ---- browsing / housekeeping --------------------------------------------

    /// All cached files (not listings) of a host, newest first.
    pub fn cached_files(&self, host_id: Uuid) -> Result<Vec<CachedEntry>> {
        let conn = self.conn();
        let mut st = conn.prepare(
            "SELECT host_id, path, kind, size, mtime, cached_at, last_used, bytes
             FROM file_cache WHERE host_id = ?1 AND kind = 'file' ORDER BY cached_at DESC",
        )?;
        let rows = st.query_map(params![host_id.to_string()], row_entry)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Hosts that have anything cached, with usage.
    pub fn file_cache_hosts(&self) -> Result<Vec<(Uuid, FileCacheUsage)>> {
        let conn = self.conn();
        let mut st = conn.prepare(
            "SELECT host_id,
                    SUM(kind = 'file'), SUM(kind = 'dir'), SUM(bytes)
             FROM file_cache GROUP BY host_id",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                FileCacheUsage {
                    files: r.get::<_, i64>(1)? as u64,
                    dirs: r.get::<_, i64>(2)? as u64,
                    bytes: r.get::<_, i64>(3)? as u64,
                },
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, u) = r?;
            out.push((parse_uuid(&id)?, u));
        }
        Ok(out)
    }

    /// Footprint of one host, or of the whole cache.
    pub fn file_cache_usage(&self, host_id: Option<Uuid>) -> Result<FileCacheUsage> {
        let conn = self.conn();
        let q = |sql: &str, p: &[&dyn rusqlite::ToSql]| {
            conn.query_row(sql, p, |r| {
                Ok(FileCacheUsage {
                    files: r.get::<_, Option<i64>>(0)?.unwrap_or(0) as u64,
                    dirs: r.get::<_, Option<i64>>(1)?.unwrap_or(0) as u64,
                    bytes: r.get::<_, Option<i64>>(2)?.unwrap_or(0) as u64,
                })
            })
        };
        Ok(match host_id {
            Some(h) => q(
                "SELECT SUM(kind = 'file'), SUM(kind = 'dir'), SUM(bytes) FROM file_cache WHERE host_id = ?1",
                &[&h.to_string()],
            )?,
            None => q(
                "SELECT SUM(kind = 'file'), SUM(kind = 'dir'), SUM(bytes) FROM file_cache",
                &[],
            )?,
        })
    }

    /// Delete every copy of one host, or of all hosts. Also called on
    /// sign-out, vault reset and host deletion.
    pub fn clear_file_cache(&self, host_id: Option<Uuid>) -> Result<u64> {
        let conn = self.conn();
        let paths: Vec<String> = {
            let (sql, p): (&str, Vec<String>) = match host_id {
                Some(h) => (
                    "SELECT local_path FROM file_cache WHERE host_id = ?1",
                    vec![h.to_string()],
                ),
                None => ("SELECT local_path FROM file_cache", vec![]),
            };
            let mut st = conn.prepare(sql)?;
            let rows = st.query_map(rusqlite::params_from_iter(p.iter()), |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for p in &paths {
            let _ = std::fs::remove_file(p);
        }
        match host_id {
            Some(h) => conn.execute(
                "DELETE FROM file_cache WHERE host_id = ?1",
                params![h.to_string()],
            )?,
            None => conn.execute("DELETE FROM file_cache", [])?,
        };
        Ok(paths.len() as u64)
    }

    /// Drop least recently used files of `host_id` until the host is within
    /// `max_total_bytes`. Listings are evicted last.
    pub fn evict_file_cache(&self, host_id: Uuid, max_total_bytes: u64) -> Result<u64> {
        let mut evicted = 0;
        loop {
            let used = self.file_cache_usage(Some(host_id))?.bytes;
            if used <= max_total_bytes {
                return Ok(evicted);
            }
            let victim: Option<(String, String)> = self
                .conn()
                .query_row(
                    "SELECT path, local_path FROM file_cache WHERE host_id = ?1
                     ORDER BY (kind = 'dir'), last_used ASC LIMIT 1",
                    params![host_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((path, local)) = victim else {
                return Ok(evicted);
            };
            let _ = std::fs::remove_file(local);
            self.conn().execute(
                "DELETE FROM file_cache WHERE host_id = ?1 AND path = ?2",
                params![host_id.to_string(), path],
            )?;
            evicted += 1;
        }
    }

    // ---- internals ----------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn write_entry(
        &self,
        host_id: Uuid,
        vault_id: Uuid,
        kind: CacheKind,
        key: &str,
        size: u64,
        mtime: Option<i64>,
        body: &[u8],
        dir: &Path,
    ) -> Result<PathBuf> {
        let vkey = self.vault_key(vault_id)?;
        let ct = aead::encrypt(&vkey, &body_aad(host_id, key), body)?;
        std::fs::create_dir_all(dir)?;
        let path = dir.join(body_name(host_id, kind, key));
        let tmp = path.with_extension("tfc.tmp");
        std::fs::write(&tmp, &ct)?;
        std::fs::rename(&tmp, &path)?;
        let now = Utc::now().to_rfc3339();
        self.conn().execute(
            "INSERT INTO file_cache
               (host_id, vault_id, path, kind, size, mtime, cached_at, last_used, local_path, bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?9)
             ON CONFLICT(host_id, path) DO UPDATE SET
               vault_id = excluded.vault_id, size = excluded.size, mtime = excluded.mtime,
               cached_at = excluded.cached_at, last_used = excluded.last_used,
               local_path = excluded.local_path, bytes = excluded.bytes",
            params![
                host_id.to_string(),
                vault_id.to_string(),
                key,
                kind.as_str(),
                size as i64,
                mtime,
                now,
                path.to_string_lossy().to_string(),
                ct.len() as i64,
            ],
        )?;
        Ok(path)
    }

    fn entry(&self, host_id: Uuid, key: &str) -> Result<Option<CachedEntry>> {
        Ok(self.entry_with_path(host_id, key)?.map(|(e, _)| e))
    }

    fn entry_with_path(&self, host_id: Uuid, key: &str) -> Result<Option<(CachedEntry, Body)>> {
        let conn = self.conn();
        let mut st = conn.prepare(
            "SELECT host_id, path, kind, size, mtime, cached_at, last_used, bytes, local_path, vault_id
             FROM file_cache WHERE host_id = ?1 AND path = ?2",
        )?;
        let row = st
            .query_row(params![host_id.to_string(), key], |r| {
                Ok((
                    row_entry(r)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                ))
            })
            .optional()?;
        match row {
            Some((e, local, vault)) => Ok(Some((
                e,
                Body {
                    local: PathBuf::from(local),
                    vault_id: parse_uuid(&vault)?,
                },
            ))),
            None => Ok(None),
        }
    }

    fn read_body(&self, row: &CachedEntry, body: &Body, key: &str) -> Result<Vec<u8>> {
        let vkey = self.vault_key(body.vault_id)?;
        let ct = match std::fs::read(&body.local) {
            Ok(ct) => ct,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Body vanished (external cleanup): drop the dangling row.
                self.conn().execute(
                    "DELETE FROM file_cache WHERE host_id = ?1 AND path = ?2",
                    params![row.host_id.to_string(), key],
                )?;
                return Err(CoreError::NotFound(format!("{} is not cached", row.path)));
            }
            Err(e) => return Err(e.into()),
        };
        Ok(aead::decrypt(&vkey, &body_aad(row.host_id, key), &ct)?)
    }

    fn touch(&self, host_id: Uuid, key: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE file_cache SET last_used = ?3 WHERE host_id = ?1 AND path = ?2",
            params![host_id.to_string(), key, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }
}

/// Where a row's ciphertext lives and which vault key opens it.
struct Body {
    local: PathBuf,
    vault_id: Uuid,
}

fn row_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<CachedEntry> {
    let conv = |e: CoreError| rusqlite::Error::ToSqlConversionFailure(Box::new(e));
    let raw_path: String = r.get(1)?;
    let kind = CacheKind::parse(&r.get::<_, String>(2)?).map_err(conv)?;
    let path = match kind {
        CacheKind::Dir => raw_path.trim_end_matches("\u{0}dir").to_string(),
        CacheKind::File => raw_path,
    };
    Ok(CachedEntry {
        host_id: parse_uuid(&r.get::<_, String>(0)?).map_err(conv)?,
        path,
        kind,
        size: r.get::<_, i64>(3)? as u64,
        mtime: r.get(4)?,
        cached_at: parse_time(&r.get::<_, String>(5)?).map_err(conv)?,
        last_used: parse_time(&r.get::<_, String>(6)?).map_err(conv)?,
        bytes: r.get::<_, i64>(7)? as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoso_crypto::keys::SymmetricKey;

    fn store() -> (Store, Uuid, Uuid) {
        let store = Store::open_in_memory(SymmetricKey::generate()).unwrap();
        let vault = store.local_vault().unwrap().id;
        (store, vault, Uuid::new_v4())
    }

    fn enabled(store: &Store, host: Uuid, total: u64) -> FileCacheConfig {
        let cfg = FileCacheConfig {
            enabled: true,
            max_total_bytes: total,
            ..FileCacheConfig::default()
        };
        store.set_file_cache_config(host, &cfg).unwrap();
        cfg
    }

    #[test]
    fn disabled_by_default_and_rejects() {
        let (store, vault, host) = store();
        let dir = tempfile::tempdir().unwrap();
        assert!(!store.file_cache_config(host).unwrap().enabled);
        assert!(
            !store
                .cache_file(host, vault, "/etc/hosts", None, b"x", dir.path())
                .unwrap()
        );
        assert!(store.cached_file(host, "/etc/hosts").unwrap().is_none());
    }

    #[test]
    fn roundtrip_encrypted_and_fresh() {
        let (store, vault, host) = store();
        let dir = tempfile::tempdir().unwrap();
        enabled(&store, host, 1 << 20);
        let body = b"hello offline".repeat(50);
        assert!(
            store
                .cache_file(host, vault, "/srv/a.txt/", Some(1700), &body, dir.path())
                .unwrap()
        );
        let e = store.cached_file(host, "/srv/a.txt").unwrap().unwrap();
        assert_eq!(e.size, body.len() as u64);
        assert!(e.is_fresh(body.len() as u64, Some(1700)));
        assert!(!e.is_fresh(body.len() as u64, Some(1701)));
        let on_disk = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(on_disk, 1);
        for f in std::fs::read_dir(dir.path()).unwrap() {
            assert!(
                !std::fs::read(f.unwrap().path())
                    .unwrap()
                    .windows(5)
                    .any(|w| w == b"hello")
            );
        }
        assert_eq!(store.read_cached_file(host, "/srv/a.txt").unwrap(), body);
        // Re-cache replaces in place.
        store
            .cache_file(host, vault, "/srv/a.txt", Some(1800), b"new", dir.path())
            .unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(store.read_cached_file(host, "/srv/a.txt").unwrap(), b"new");
        let u = store.file_cache_usage(Some(host)).unwrap();
        assert_eq!(u.files, 1);
        assert!(u.bytes > 3);
    }

    #[test]
    fn limits_and_paths() {
        let (store, vault, host) = store();
        let dir = tempfile::tempdir().unwrap();
        let cfg = FileCacheConfig {
            enabled: true,
            max_file_bytes: 10,
            include_paths: vec!["/home/me/".into()],
            exclude_paths: vec!["/home/me/.ssh".into()],
            ..FileCacheConfig::default()
        };
        store.set_file_cache_config(host, &cfg).unwrap();
        assert_eq!(store.file_cache_config(host).unwrap(), cfg);
        assert!(
            store
                .cache_file(host, vault, "/home/me/a", None, b"12345", dir.path())
                .unwrap()
        );
        assert!(
            !store
                .cache_file(
                    host,
                    vault,
                    "/home/me/big",
                    None,
                    b"12345678901",
                    dir.path()
                )
                .unwrap()
        );
        assert!(
            !store
                .cache_file(host, vault, "/home/meow/a", None, b"1", dir.path())
                .unwrap()
        );
        assert!(
            !store
                .cache_file(host, vault, "/home/me/.ssh/id", None, b"1", dir.path())
                .unwrap()
        );
        assert!(
            !store
                .cache_file(host, vault, "/etc/passwd", None, b"1", dir.path())
                .unwrap()
        );
        assert_eq!(store.cached_files(host).unwrap().len(), 1);
    }

    #[test]
    fn lru_eviction() {
        let (store, vault, host) = store();
        let dir = tempfile::tempdir().unwrap();
        // Each 100-byte body becomes ~100 + overhead bytes on disk.
        let one = {
            enabled(&store, host, 1 << 20);
            store
                .cache_file(host, vault, "/p", None, &[0u8; 100], dir.path())
                .unwrap();
            store.file_cache_usage(Some(host)).unwrap().bytes
        };
        store.clear_file_cache(Some(host)).unwrap();
        enabled(&store, host, one * 2 + one / 2);
        for p in ["/a", "/b", "/c"] {
            store
                .cache_file(host, vault, p, None, &[0u8; 100], dir.path())
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let left: Vec<_> = store
            .cached_files(host)
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert_eq!(left.len(), 2);
        assert!(!left.contains(&"/a".to_string()), "{left:?}");
        // Reading /b makes it most recent, so /c goes next.
        std::thread::sleep(std::time::Duration::from_millis(5));
        store.read_cached_file(host, "/b").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        store
            .cache_file(host, vault, "/d", None, &[0u8; 100], dir.path())
            .unwrap();
        let left: Vec<_> = store
            .cached_files(host)
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert!(
            left.contains(&"/b".to_string()) && left.contains(&"/d".to_string()),
            "{left:?}"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn dir_listings_clear_and_disable() {
        let (store, vault, host) = store();
        let other = Uuid::new_v4();
        let dir = tempfile::tempdir().unwrap();
        enabled(&store, host, 1 << 20);
        enabled(&store, other, 1 << 20);
        let names = vec!["a".to_string(), "b".to_string()];
        assert!(
            store
                .cache_dir(host, vault, "/srv/", &names, dir.path())
                .unwrap()
        );
        store
            .cache_file(host, vault, "/srv/a", None, b"a", dir.path())
            .unwrap();
        store
            .cache_file(other, vault, "/x", None, b"x", dir.path())
            .unwrap();
        let d = store.cached_dir(host, "/srv").unwrap().unwrap();
        assert_eq!(
            (d.kind, d.size, d.path.as_str()),
            (CacheKind::Dir, 2, "/srv")
        );
        assert_eq!(
            store.read_cached_dir::<String>(host, "/srv").unwrap(),
            names
        );
        assert!(store.cached_file(host, "/srv").unwrap().is_none());
        let hosts = store.file_cache_hosts().unwrap();
        assert_eq!(hosts.len(), 2);
        store.remove_cached(host, "/srv", true).unwrap();
        assert!(store.cached_dir(host, "/srv").unwrap().is_none());
        // Disabling purges the host, leaves others.
        store
            .set_file_cache_config(host, &FileCacheConfig::default())
            .unwrap();
        assert_eq!(store.file_cache_usage(Some(host)).unwrap().files, 0);
        assert_eq!(store.file_cache_usage(Some(other)).unwrap().files, 1);
        assert_eq!(store.clear_file_cache(None).unwrap(), 1);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        assert!(store.read_cached_file(other, "/x").is_err());
    }

    #[test]
    fn missing_body_drops_row() {
        let (store, vault, host) = store();
        let dir = tempfile::tempdir().unwrap();
        enabled(&store, host, 1 << 20);
        store
            .cache_file(host, vault, "/a", None, b"a", dir.path())
            .unwrap();
        for f in std::fs::read_dir(dir.path()).unwrap() {
            std::fs::remove_file(f.unwrap().path()).unwrap();
        }
        assert!(matches!(
            store.read_cached_file(host, "/a"),
            Err(CoreError::NotFound(_))
        ));
        assert!(store.cached_file(host, "/a").unwrap().is_none());
    }
}
