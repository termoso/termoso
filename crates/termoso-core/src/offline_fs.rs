//! Offline copies on the [`RemoteFs`] interface: [`CachingFs`] wraps a live
//! remote and fills the per-host cache as files are read; [`OfflineFs`]
//! serves that cache read-only when the host cannot be reached. Both sit
//! behind the same trait, so file panels need no special casing.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::error::{CoreError, Result};
use crate::remote::{RemoteCapabilities, RemoteFile, RemoteFs, RemoteProtocol, parent};
use crate::sftp::{EntryKind, OpenMode, RemoteEntry, TransferOptions};
use crate::store::Store;
use uuid::Uuid;

fn read_only() -> CoreError {
    CoreError::Invalid("read-only while offline".into())
}

/// Which host's cache a wrapper writes to / reads from.
#[derive(Clone)]
pub struct CacheTarget {
    /// Index + keys.
    pub store: Arc<Store>,
    /// Host the copies belong to.
    pub host_id: Uuid,
    /// Vault whose key encrypts the bodies.
    pub vault_id: Uuid,
    /// Directory for the encrypted bodies.
    pub dir: PathBuf,
}

impl CacheTarget {
    /// `Some` when the host keeps local copies and its team policy allows
    /// them; purges stale copies when the policy says deny.
    pub fn for_host(
        store: Arc<Store>,
        host_id: Uuid,
        vault_id: Uuid,
        dir: PathBuf,
    ) -> Option<Self> {
        if crate::policy::offline_cache_denied(&store, vault_id) {
            let _ = store.clear_file_cache(Some(host_id));
            return None;
        }
        if !store.file_cache_config(host_id).ok()?.enabled {
            return None;
        }
        Some(Self {
            store,
            host_id,
            vault_id,
            dir,
        })
    }

    /// True when the cache holds anything for this host.
    pub fn has_copies(store: &Store, host_id: Uuid) -> bool {
        store
            .file_cache_usage(Some(host_id))
            .is_ok_and(|u| u.files + u.dirs > 0)
    }
}

/// Live remote plus write-through into the offline cache.
pub struct CachingFs {
    inner: Arc<dyn RemoteFs>,
    cache: CacheTarget,
}

impl CachingFs {
    /// Wrap `inner`; reads and downloads land in `cache`.
    pub fn new(inner: Arc<dyn RemoteFs>, cache: CacheTarget) -> Self {
        Self { inner, cache }
    }

    fn accepts(&self, path: &str, size: u64) -> bool {
        self.cache
            .store
            .file_cache_config(self.cache.host_id)
            .is_ok_and(|c| c.accepts(path, size))
    }

    fn put(&self, path: &str, mtime: Option<i64>, body: &[u8]) {
        let _ = self.cache.store.cache_file(
            self.cache.host_id,
            self.cache.vault_id,
            path,
            mtime,
            body,
            &self.cache.dir,
        );
    }
}

#[async_trait]
impl RemoteFs for CachingFs {
    fn protocol(&self) -> RemoteProtocol {
        self.inner.protocol()
    }
    fn capabilities(&self) -> RemoteCapabilities {
        self.inner.capabilities()
    }
    fn home(&self) -> &str {
        self.inner.home()
    }
    async fn canonicalize(&self, path: &str) -> Result<String> {
        self.inner.canonicalize(path).await
    }
    async fn list(&self, dir: &str) -> Result<Vec<RemoteEntry>> {
        let entries = self.inner.list(dir).await?;
        let _ = self.cache.store.cache_dir(
            self.cache.host_id,
            self.cache.vault_id,
            dir,
            &entries,
            &self.cache.dir,
        );
        Ok(entries)
    }
    async fn stat(&self, path: &str) -> Result<RemoteEntry> {
        self.inner.stat(path).await
    }
    async fn exists(&self, path: &str) -> Result<bool> {
        self.inner.exists(path).await
    }
    async fn mkdir(&self, path: &str) -> Result<()> {
        self.inner.mkdir(path).await
    }
    async fn mkdir_all(&self, path: &str) -> Result<()> {
        self.inner.mkdir_all(path).await
    }
    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.inner.rename(from, to).await?;
        let _ = self
            .cache
            .store
            .remove_cached(self.cache.host_id, from, false);
        Ok(())
    }
    async fn copy(&self, from: &str, to: &str) -> Result<()> {
        self.inner.copy(from, to).await
    }
    async fn remove_file(&self, path: &str) -> Result<()> {
        self.inner.remove_file(path).await?;
        let _ = self
            .cache
            .store
            .remove_cached(self.cache.host_id, path, false);
        Ok(())
    }
    async fn remove_dir(&self, path: &str) -> Result<()> {
        self.inner.remove_dir(path).await?;
        let _ = self
            .cache
            .store
            .remove_cached(self.cache.host_id, path, true);
        Ok(())
    }
    async fn remove_dir_all(&self, path: &str, cancel: &CancellationToken) -> Result<()> {
        self.inner.remove_dir_all(path, cancel).await?;
        let _ = self
            .cache
            .store
            .remove_cached(self.cache.host_id, path, true);
        Ok(())
    }
    async fn chmod(&self, path: &str, mode: u32) -> Result<()> {
        self.inner.chmod(path, mode).await
    }
    /// Serve the copy when the remote still matches it, refetch otherwise.
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let st = self.inner.stat(path).await?;
        let mtime = st.mtime.map(i64::from);
        if let (Some(size), Ok(Some(e))) = (
            st.size,
            self.cache.store.cached_file(self.cache.host_id, path),
        ) && e.is_fresh(size, mtime)
            && let Ok(body) = self.cache.store.read_cached_file(self.cache.host_id, path)
        {
            return Ok(body);
        }
        let body = self.inner.read(path).await?;
        self.put(path, mtime, &body);
        Ok(body)
    }
    async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        self.inner.write(path, data).await?;
        if let Ok(st) = self.inner.stat(path).await {
            self.put(path, st.mtime.map(i64::from), data);
        }
        Ok(())
    }
    async fn open_file(&self, path: &str, mode: OpenMode) -> Result<Box<dyn RemoteFile>> {
        self.inner.open_file(path, mode).await
    }
    /// A download is a read: the file lands in the cache too (within limits).
    async fn download(&self, remote: &str, local: &Path, opts: &TransferOptions) -> Result<u64> {
        let n = self.inner.download(remote, local, opts).await?;
        if self.accepts(remote, n)
            && let Ok(st) = self.inner.stat(remote).await
            && st.kind != EntryKind::Dir
            && let Ok(body) = tokio::fs::read(local).await
        {
            self.put(remote, st.mtime.map(i64::from), &body);
        }
        Ok(n)
    }
    async fn upload(&self, local: &Path, remote: &str, opts: &TransferOptions) -> Result<u64> {
        self.inner.upload(local, remote, opts).await
    }
    async fn close(&self) -> Result<()> {
        self.inner.close().await
    }
}

/// Read-only view of a host's offline copies.
pub struct OfflineFs {
    store: Arc<Store>,
    host_id: Uuid,
    home: String,
}

impl OfflineFs {
    /// Starts at the folder of the newest copy (or `/`).
    pub fn new(store: Arc<Store>, host_id: Uuid) -> Self {
        let home = store
            .cached_files(host_id)
            .ok()
            .and_then(|v| v.into_iter().next())
            .and_then(|e| parent(&e.path))
            .unwrap_or_else(|| "/".into());
        Self {
            store,
            host_id,
            home,
        }
    }

    /// What an offline view supports: nothing that writes.
    pub fn caps() -> RemoteCapabilities {
        RemoteCapabilities {
            permissions: false,
            symlinks: false,
            ownership: false,
            server_copy: false,
            resume_upload: false,
        }
    }

    fn norm(path: &str) -> String {
        let p = path.trim();
        let p = if p.len() > 1 {
            p.trim_end_matches('/')
        } else {
            p
        };
        if p.is_empty() { "/".into() } else { p.into() }
    }

    fn dir_entry(path: &str) -> RemoteEntry {
        RemoteEntry {
            name: path.rsplit('/').next().unwrap_or(path).to_string(),
            path: path.to_string(),
            kind: EntryKind::Dir,
            size: None,
            mode: None,
            uid: None,
            gid: None,
            user: None,
            group: None,
            mtime: None,
            atime: None,
            link_target: None,
            target_kind: None,
        }
    }
}

#[async_trait]
impl RemoteFs for OfflineFs {
    fn protocol(&self) -> RemoteProtocol {
        RemoteProtocol::Sftp
    }
    fn capabilities(&self) -> RemoteCapabilities {
        Self::caps()
    }
    fn home(&self) -> &str {
        &self.home
    }
    async fn canonicalize(&self, path: &str) -> Result<String> {
        let p = path.trim();
        Ok(if p.is_empty() || p == "~" {
            self.home.clone()
        } else if let Some(rest) = p.strip_prefix("~/") {
            format!("{}/{rest}", self.home.trim_end_matches('/'))
        } else {
            Self::norm(p)
        })
    }
    async fn list(&self, dir: &str) -> Result<Vec<RemoteEntry>> {
        let dir = Self::norm(dir);
        if self.store.cached_dir(self.host_id, &dir)?.is_some() {
            return self.store.read_cached_dir(self.host_id, &dir);
        }
        // No listing kept: synthesize one from the copies below this folder.
        let mut out: Vec<RemoteEntry> = Vec::new();
        let prefix = if dir == "/" {
            "/".to_string()
        } else {
            format!("{dir}/")
        };
        for e in self.store.cached_files(self.host_id)? {
            let Some(rest) = e.path.strip_prefix(&prefix) else {
                continue;
            };
            match rest.split_once('/') {
                None => out.push(RemoteEntry {
                    name: rest.to_string(),
                    path: e.path.clone(),
                    kind: EntryKind::File,
                    size: Some(e.size),
                    mode: None,
                    uid: None,
                    gid: None,
                    user: None,
                    group: None,
                    mtime: e.mtime.and_then(|t| u32::try_from(t).ok()),
                    atime: None,
                    link_target: None,
                    target_kind: None,
                }),
                Some((first, _)) => {
                    let p = format!("{prefix}{first}");
                    if !out.iter().any(|x| x.path == p) {
                        out.push(Self::dir_entry(&p));
                    }
                }
            }
        }
        if out.is_empty() && dir != "/" {
            return Err(CoreError::NotFound(format!("{dir}: no offline copy")));
        }
        out.sort_by(|a, b| {
            (b.kind == EntryKind::Dir)
                .cmp(&(a.kind == EntryKind::Dir))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(out)
    }
    async fn stat(&self, path: &str) -> Result<RemoteEntry> {
        let p = Self::norm(path);
        if let Some(parent) = parent(&p)
            && let Ok(entries) = self.list(&parent).await
            && let Some(e) = entries.into_iter().find(|e| e.path == p)
        {
            return Ok(e);
        }
        if p == "/" || self.store.cached_dir(self.host_id, &p)?.is_some() {
            return Ok(Self::dir_entry(&p));
        }
        Err(CoreError::NotFound(format!("{p}: no offline copy")))
    }
    async fn exists(&self, path: &str) -> Result<bool> {
        Ok(self.stat(path).await.is_ok())
    }
    async fn mkdir(&self, _: &str) -> Result<()> {
        Err(read_only())
    }
    async fn mkdir_all(&self, _: &str) -> Result<()> {
        Err(read_only())
    }
    async fn rename(&self, _: &str, _: &str) -> Result<()> {
        Err(read_only())
    }
    async fn copy(&self, _: &str, _: &str) -> Result<()> {
        Err(read_only())
    }
    async fn remove_file(&self, _: &str) -> Result<()> {
        Err(read_only())
    }
    async fn remove_dir(&self, _: &str) -> Result<()> {
        Err(read_only())
    }
    async fn remove_dir_all(&self, _: &str, _: &CancellationToken) -> Result<()> {
        Err(read_only())
    }
    async fn chmod(&self, _: &str, _: u32) -> Result<()> {
        Err(read_only())
    }
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        Ok(self
            .store
            .read_cached_file(self.host_id, &Self::norm(path))?)
    }
    async fn write(&self, _: &str, _: &[u8]) -> Result<()> {
        Err(read_only())
    }
    async fn open_file(&self, path: &str, mode: OpenMode) -> Result<Box<dyn RemoteFile>> {
        if mode != OpenMode::Read {
            return Err(read_only());
        }
        Ok(Box::new(CachedBody(self.read(path).await?)))
    }
    async fn download(&self, remote: &str, local: &Path, _: &TransferOptions) -> Result<u64> {
        let body = self.read(remote).await?;
        if let Some(parent) = local.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(local, &body).await?;
        Ok(body.len() as u64)
    }
    async fn upload(&self, _: &Path, _: &str, _: &TransferOptions) -> Result<u64> {
        Err(read_only())
    }
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

struct CachedBody(Vec<u8>);

#[async_trait]
impl RemoteFile for CachedBody {
    async fn size(&self) -> Result<u64> {
        Ok(self.0.len() as u64)
    }
    async fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let start = (offset as usize).min(self.0.len());
        let end = start.saturating_add(len).min(self.0.len());
        Ok(self.0[start..end].to_vec())
    }
    async fn write_at(&self, _: u64, _: &[u8]) -> Result<()> {
        Err(read_only())
    }
    async fn truncate(&self, _: u64) -> Result<()> {
        Err(read_only())
    }
    async fn sync(&self) -> Result<()> {
        Ok(())
    }
    async fn close(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::FileCacheConfig;
    use termoso_crypto::keys::SymmetricKey;

    #[tokio::test]
    async fn offline_fs_lists_and_reads_copies_read_only() {
        let store = Arc::new(Store::open_in_memory(SymmetricKey::generate()).unwrap());
        let vault = store.local_vault().unwrap().id;
        let host = Uuid::new_v4();
        let dir = tempfile::tempdir().unwrap();
        store
            .set_file_cache_config(
                host,
                &FileCacheConfig {
                    enabled: true,
                    ..FileCacheConfig::default()
                },
            )
            .unwrap();
        store
            .cache_file(
                host,
                vault,
                "/srv/www/index.html",
                Some(10),
                b"<h1>",
                dir.path(),
            )
            .unwrap();
        store
            .cache_file(host, vault, "/srv/notes.txt", Some(20), b"hi", dir.path())
            .unwrap();
        let fs = OfflineFs::new(store.clone(), host);
        assert_eq!(fs.home(), "/srv");
        let names: Vec<_> = fs
            .list("/srv")
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["www", "notes.txt"]);
        assert_eq!(fs.stat("/srv/www").await.unwrap().kind, EntryKind::Dir);
        assert_eq!(fs.read("/srv/www/index.html").await.unwrap(), b"<h1>");
        assert!(fs.write("/srv/x", b"no").await.is_err());
        assert!(
            fs.open_file("/srv/notes.txt", OpenMode::Write)
                .await
                .is_err()
        );
        let f = fs
            .open_file("/srv/notes.txt", OpenMode::Read)
            .await
            .unwrap();
        assert_eq!(f.read_at(1, 10).await.unwrap(), b"i");
        assert!(fs.list("/nope").await.is_err());
    }
}
