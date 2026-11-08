//! Protocol-neutral view of a remote filesystem, implemented by
//! [`Sftp`](crate::sftp::Sftp), [`WebDav`](crate::webdav::WebDav),
//! [`S3`](crate::s3::S3) and [`LocalFs`](crate::localfs::LocalFs) so the file panels, transfer queues
//! and the Android documents provider drive any of them through one object.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::error::{CoreError, Result};
use crate::sftp::{EntryKind, OpenMode, Progress, RemoteEntry, TransferOptions};

/// Which wire protocol a [`RemoteFs`] speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteProtocol {
    /// SFTP over SSH.
    Sftp,
    /// WebDAV over HTTP(S).
    WebDav,
    /// S3-compatible object storage over HTTP(S).
    S3,
    /// A directory on this device.
    Local,
}

impl RemoteProtocol {
    /// Lowercase wire name (`"sftp"`, `"webdav"`, `"s3"`, `"local"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sftp => "sftp",
            Self::WebDav => "webdav",
            Self::S3 => "s3",
            Self::Local => "local",
        }
    }
}

/// What a backend can do beyond the common listing/transfer set, so UIs
/// hide the controls a protocol has no answer for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteCapabilities {
    /// Unix permission bits can be changed (`chmod`).
    pub permissions: bool,
    /// Symlinks are reported and can be created.
    pub symlinks: bool,
    /// Owner / group are reported.
    pub ownership: bool,
    /// Server-side copy without downloading (`copy`).
    pub server_copy: bool,
    /// Interrupted uploads can continue from the bytes already there.
    pub resume_upload: bool,
}

/// An open remote file with positional access.
#[async_trait]
pub trait RemoteFile: Send + Sync {
    /// Current size in bytes.
    async fn size(&self) -> Result<u64>;
    /// Up to `len` bytes starting at `offset`; shorter only at end of file.
    async fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>>;
    /// Write all of `data` at `offset`, growing the file as needed.
    async fn write_at(&self, offset: u64, data: &[u8]) -> Result<()>;
    /// Set the file's length.
    async fn truncate(&self, size: u64) -> Result<()>;
    /// Push pending writes to the server.
    async fn sync(&self) -> Result<()>;
    /// Flush and release the handle.
    async fn close(self: Box<Self>) -> Result<()>;
}

/// A connected remote filesystem. Paths are absolute, `/`-separated.
#[async_trait]
pub trait RemoteFs: Send + Sync {
    /// Wire protocol.
    fn protocol(&self) -> RemoteProtocol;
    /// Feature set.
    fn capabilities(&self) -> RemoteCapabilities;
    /// Directory a fresh panel opens on.
    fn home(&self) -> &str;
    /// Make a path absolute and normalised per the server.
    async fn canonicalize(&self, path: &str) -> Result<String>;
    /// List a directory (directories first, then by name).
    async fn list(&self, dir: &str) -> Result<Vec<RemoteEntry>>;
    /// Stat a path.
    async fn stat(&self, path: &str) -> Result<RemoteEntry>;
    /// Does `path` exist?
    async fn exists(&self, path: &str) -> Result<bool>;
    /// Create a single directory.
    async fn mkdir(&self, path: &str) -> Result<()>;
    /// Create a directory and all missing parents.
    async fn mkdir_all(&self, path: &str) -> Result<()>;
    /// Rename / move; fails when `to` already exists.
    async fn rename(&self, from: &str, to: &str) -> Result<()>;
    /// Server-side copy; only when `capabilities().server_copy`.
    async fn copy(&self, from: &str, to: &str) -> Result<()>;
    /// Remove a file.
    async fn remove_file(&self, path: &str) -> Result<()>;
    /// Remove an empty directory.
    async fn remove_dir(&self, path: &str) -> Result<()>;
    /// Remove a directory tree.
    async fn remove_dir_all(&self, path: &str, cancel: &CancellationToken) -> Result<()>;
    /// Set permission bits; only when `capabilities().permissions`.
    async fn chmod(&self, path: &str, mode: u32) -> Result<()>;
    /// Read a whole file into memory (refuses very large files).
    async fn read(&self, path: &str) -> Result<Vec<u8>>;
    /// Write a whole file (truncating).
    async fn write(&self, path: &str, data: &[u8]) -> Result<()>;
    /// Open `path` for positional access.
    async fn open_file(&self, path: &str, mode: OpenMode) -> Result<Box<dyn RemoteFile>>;
    /// Download `remote` to `local`; returns bytes moved by this call.
    async fn download(&self, remote: &str, local: &Path, opts: &TransferOptions) -> Result<u64>;
    /// Upload `local` to `remote`; returns bytes moved by this call.
    async fn upload(&self, local: &Path, remote: &str, opts: &TransferOptions) -> Result<u64>;
    /// Release the connection.
    async fn close(&self) -> Result<()>;
}

/// Shared handle to any backend.
pub type SharedRemoteFs = Arc<dyn RemoteFs>;

/// Parent of an absolute `/`-separated path; `None` at the root.
pub fn parent(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rfind('/') {
        Some(0) => Some("/".to_string()),
        Some(i) => Some(trimmed[..i].to_string()),
        None => None,
    }
}

/// Bytes per hop of a relay: one SFTP read, one write.
pub const RELAY_CHUNK: usize = 256 * 1024;

/// Streams one file from one remote to another through this client; nothing
/// is written to the local disk. With `resume`, a shorter copy already at the
/// destination is continued from its end.
pub async fn relay_file(
    from: &dyn RemoteFs,
    to: &dyn RemoteFs,
    src: &str,
    dest: &str,
    opts: &TransferOptions,
) -> Result<u64> {
    let reader = from.open_file(src, OpenMode::Read).await?;
    let total = reader.size().await?;
    let mut offset = 0u64;
    let mut writer = None;
    let existing = if opts.resume {
        to.stat(dest).await.ok()
    } else {
        None
    };
    if let Some(e) = existing {
        let have = e.size.unwrap_or(0);
        if e.kind == EntryKind::File && have > 0 && have <= total {
            offset = have;
            writer = Some(to.open_file(dest, OpenMode::ReadWrite).await?);
        }
    }
    let writer = match writer {
        Some(w) => w,
        None => to.open_file(dest, OpenMode::Write).await?,
    };
    let mut moved = 0u64;
    while offset < total {
        if opts.cancel.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
        let want = usize::try_from(total - offset)
            .unwrap_or(RELAY_CHUNK)
            .min(RELAY_CHUNK);
        let buf = reader.read_at(offset, want).await?;
        if buf.is_empty() {
            break;
        }
        writer.write_at(offset, &buf).await?;
        offset += buf.len() as u64;
        moved += buf.len() as u64;
        if let Some(p) = &opts.progress {
            p(Progress {
                done: offset,
                total: Some(total),
            });
        }
    }
    let _ = writer.sync().await;
    writer.close().await?;
    reader.close().await?;
    Ok(moved)
}

/// Join `name` onto directory `dir`.
pub fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_of_paths() {
        assert_eq!(parent("/"), None);
        assert_eq!(parent(""), None);
        assert_eq!(parent("/a"), Some("/".into()));
        assert_eq!(parent("/a/"), Some("/".into()));
        assert_eq!(parent("/a/b/c"), Some("/a/b".into()));
        assert_eq!(parent("rel"), None);
    }

    #[test]
    fn join_paths() {
        assert_eq!(join("/", "a"), "/a");
        assert_eq!(join("/a", "b"), "/a/b");
        assert_eq!(join("/a/", "b"), "/a/b");
    }
}
