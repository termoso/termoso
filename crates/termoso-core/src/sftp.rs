//! SFTP over an [`SshClient`](crate::ssh::SshClient), with typed listing and
//! resumable, cancellable transfers that report progress.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::{StreamExt, stream};
use russh_sftp::client::fs::File;
use russh_sftp::client::{Config as SftpConfig, SftpSession};
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::error::{CoreError, Result};
use crate::remote::{self, RemoteCapabilities, RemoteFs, RemoteProtocol, join};
use crate::ssh::SshClient;

/// Chunk size for transfers.
const CHUNK: usize = 256 * 1024;
/// Requests kept in flight per open file; with 256 KiB packets this allows
/// 8 MiB outstanding, enough to fill a 100+ ms RTT link.
const IN_FLIGHT: usize = 32;
/// Per-request response deadline. The last of the in-flight requests waits
/// behind everything queued before it (8 MiB per file, several files at
/// once), which on a slow mobile link takes minutes; a dead connection is
/// caught by SSH keepalives, so this only has to be a safety net.
const REQUEST_TIMEOUT_SECS: u64 = 600;

/// Directory entry kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// Directory.
    Dir,
    /// Regular file.
    File,
    /// Symbolic link.
    Symlink,
    /// Device, socket, fifo…
    Other,
}

impl From<FileType> for EntryKind {
    fn from(t: FileType) -> Self {
        match t {
            FileType::Dir => Self::Dir,
            FileType::File => Self::File,
            FileType::Symlink => Self::Symlink,
            FileType::Other => Self::Other,
        }
    }
}

/// A remote file or directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteEntry {
    /// Name without directory.
    pub name: String,
    /// Absolute path.
    pub path: String,
    /// Kind.
    pub kind: EntryKind,
    /// Size in bytes.
    pub size: Option<u64>,
    /// Unix mode bits (permissions only).
    pub mode: Option<u32>,
    /// Owner uid.
    pub uid: Option<u32>,
    /// Owner gid.
    pub gid: Option<u32>,
    /// Owner name if the server sent one.
    pub user: Option<String>,
    /// Group name if the server sent one.
    pub group: Option<String>,
    /// Modification time (unix seconds).
    pub mtime: Option<u32>,
    /// Access time (unix seconds).
    pub atime: Option<u32>,
    /// Link target for symlinks (filled by [`Sftp::list`]).
    pub link_target: Option<String>,
    /// What a symlink points at; `None` for non-links and dangling links.
    pub target_kind: Option<EntryKind>,
}

impl RemoteEntry {
    fn from_attrs(name: String, path: String, a: &FileAttributes) -> Self {
        Self {
            name,
            path,
            kind: a.file_type().into(),
            size: a.size,
            mode: a.permissions.map(|p| p & 0o7777),
            uid: a.uid,
            gid: a.gid,
            user: a.user.clone(),
            group: a.group.clone(),
            mtime: a.mtime,
            atime: a.atime,
            link_target: None,
            target_kind: None,
        }
    }
}

/// Transfer progress snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    /// Bytes moved so far (including any resumed offset).
    pub done: u64,
    /// Total bytes if known.
    pub total: Option<u64>,
}

/// Progress sink.
pub type ProgressFn = Arc<dyn Fn(Progress) + Send + Sync>;

/// Options for one transfer.
#[derive(Clone)]
pub struct TransferOptions {
    /// Continue an interrupted transfer if the destination already has a
    /// prefix of the file.
    pub resume: bool,
    /// Copy mtime to the destination.
    pub preserve_mtime: bool,
    /// Cancellation.
    pub cancel: CancellationToken,
    /// Called after every chunk.
    pub progress: Option<ProgressFn>,
}

impl Default for TransferOptions {
    fn default() -> Self {
        Self {
            resume: false,
            preserve_mtime: true,
            cancel: CancellationToken::new(),
            progress: None,
        }
    }
}

impl TransferOptions {
    pub(crate) fn report(&self, done: u64, total: Option<u64>) {
        if let Some(p) = &self.progress {
            p(Progress { done, total });
        }
    }
}

/// How [`Sftp::open_file`] opens a remote file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Existing file, reads only.
    Read,
    /// Create or truncate, writes only.
    Write,
    /// Create if missing, keep contents, reads and writes at any offset.
    ReadWrite,
}

impl OpenMode {
    fn flags(self) -> OpenFlags {
        match self {
            Self::Read => OpenFlags::READ,
            Self::Write => OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            Self::ReadWrite => OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE,
        }
    }
}

/// An open remote file with positional reads and writes, for callers that
/// serve an arbitrary-size file piecewise (a proxy file descriptor, a media
/// player seeking around) instead of transferring it whole.
pub struct SftpFile {
    file: tokio::sync::Mutex<Positioned>,
}

/// The handle plus the offset its stream is known to sit at. Seeking resets
/// the crate's read-ahead pipeline, so sequential callers must not seek: a
/// `None` position forces one before the next access.
struct Positioned {
    file: File,
    pos: Option<u64>,
}

impl Positioned {
    async fn seek_to(&mut self, offset: u64) -> Result<()> {
        if self.pos != Some(offset) {
            self.file.seek(std::io::SeekFrom::Start(offset)).await?;
            self.pos = Some(offset);
        }
        Ok(())
    }
}

impl std::fmt::Debug for SftpFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpFile").finish_non_exhaustive()
    }
}

impl SftpFile {
    /// Current size in bytes as the server reports it.
    pub async fn size(&self) -> Result<u64> {
        let file = self.file.lock().await;
        let meta = file.file.metadata().await.map_err(sftp_err)?;
        meta.size
            .ok_or_else(|| CoreError::Sftp("server did not report the file size".into()))
    }

    /// Up to `len` bytes starting at `offset`; shorter only at end of file.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut f = self.file.lock().await;
        f.seek_to(offset).await?;
        let mut out = vec![0u8; len];
        let mut filled = 0;
        while filled < len {
            let n = match f.file.read(&mut out[filled..]).await {
                Ok(n) => n,
                Err(e) => {
                    f.pos = None;
                    return Err(e.into());
                }
            };
            if n == 0 {
                break;
            }
            filled += n;
        }
        f.pos = if filled == len {
            Some(offset + filled as u64)
        } else {
            None
        };
        out.truncate(filled);
        Ok(out)
    }

    /// Write all of `data` at `offset`, growing the file as needed.
    pub async fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        let mut f = self.file.lock().await;
        f.seek_to(offset).await?;
        f.pos = None;
        f.file.write_all(data).await?;
        f.file.flush().await?;
        f.pos = Some(offset + data.len() as u64);
        Ok(())
    }

    /// Set the file's length (`SSH_FXP_FSETSTAT` with size).
    pub async fn truncate(&self, size: u64) -> Result<()> {
        let mut f = self.file.lock().await;
        let mut a = FileAttributes::empty();
        a.size = Some(size);
        f.file.set_metadata(a).await.map_err(sftp_err)?;
        f.pos = None;
        Ok(())
    }

    /// Push pending writes and ask the server to sync them to disk when it
    /// supports `fsync@openssh.com`; servers without it just acknowledge.
    pub async fn sync(&self) -> Result<()> {
        let mut f = self.file.lock().await;
        f.file.flush().await?;
        match f.file.sync_all().await {
            Ok(()) => Ok(()),
            Err(russh_sftp::client::error::Error::Status(s))
                if s.status_code == StatusCode::OpUnsupported =>
            {
                Ok(())
            }
            Err(e) => Err(sftp_err(e)),
        }
    }

    /// Flush and release the server handle.
    pub async fn close(self) -> Result<()> {
        let mut file = self.file.into_inner().file;
        file.flush().await?;
        file.close().await?;
        Ok(())
    }
}

/// SFTP session on top of an SSH connection.
pub struct Sftp {
    session: SftpSession,
    home: String,
}

impl std::fmt::Debug for Sftp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sftp").field("home", &self.home).finish()
    }
}

fn sftp_err(e: russh_sftp::client::error::Error) -> CoreError {
    match &e {
        russh_sftp::client::error::Error::Status(s) if s.status_code == StatusCode::NoSuchFile => {
            CoreError::NotFound(s.error_message.clone())
        }
        _ => CoreError::Sftp(e.to_string()),
    }
}

/// How many symlinks `list` resolves in flight at once.
const SYMLINK_RESOLVE_CONCURRENCY: usize = 16;

impl Sftp {
    /// Request the `sftp` subsystem on `client`.
    pub async fn open(client: &SshClient) -> Result<Self> {
        let channel = client.open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let cfg = SftpConfig {
            max_packet_len: CHUNK as u32,
            max_write_packet_len: CHUNK as u32,
            max_concurrent_reads: IN_FLIGHT,
            max_concurrent_writes: IN_FLIGHT,
            request_timeout_secs: REQUEST_TIMEOUT_SECS,
        };
        let session = SftpSession::new_with_config(channel.into_stream(), cfg)
            .await
            .map_err(sftp_err)?;
        let home = session.canonicalize(".").await.map_err(sftp_err)?;
        Ok(Self { session, home })
    }

    /// Start `sftp-server` under `sudo` (the user's password is fed to
    /// `sudo -S`), so the session browses and edits files as root. Needs a
    /// sudoers entry that allows the binary; the common install paths are tried.
    pub async fn open_sudo(client: &SshClient, password: &str) -> Result<Self> {
        let channel = client.open_session().await?;
        let cmd = "sudo -S -p '' sh -c 'for p in /usr/lib/openssh/sftp-server /usr/libexec/sftp-server \
                  /usr/lib/ssh/sftp-server /usr/libexec/openssh/sftp-server /usr/lib64/misc/sftp-server; \
                  do [ -x \"$p\" ] && exec \"$p\"; done; command -v sftp-server >/dev/null && exec sftp-server; \
                  echo \"sftp-server not found\" >&2; exit 127'";
        channel.exec(true, cmd).await?;
        let mut secret = zeroize::Zeroizing::new(password.to_string());
        secret.push('\n');
        channel.data(secret.as_bytes()).await?;
        let cfg = SftpConfig {
            max_packet_len: CHUNK as u32,
            max_write_packet_len: CHUNK as u32,
            max_concurrent_reads: IN_FLIGHT,
            max_concurrent_writes: IN_FLIGHT,
            request_timeout_secs: REQUEST_TIMEOUT_SECS,
        };
        let session = SftpSession::new_with_config(channel.into_stream(), cfg)
            .await
            .map_err(|e| {
                CoreError::Sftp(format!(
                    "sudo sftp-server did not start (wrong password or no sudoers rule?): {e}"
                ))
            })?;
        let home = session.canonicalize(".").await.map_err(sftp_err)?;
        Ok(Self { session, home })
    }

    /// The user's home directory (server's idea of `.`).
    pub fn home(&self) -> &str {
        &self.home
    }

    /// Make a path absolute per the server.
    pub async fn canonicalize(&self, path: &str) -> Result<String> {
        self.session.canonicalize(path).await.map_err(sftp_err)
    }

    /// List a directory, sorted directories-first then by name. Symlink
    /// targets are resolved so the UI can show where they point and whether
    /// they can be followed.
    pub async fn list(&self, dir: &str) -> Result<Vec<RemoteEntry>> {
        let dir = self.canonicalize(dir).await?;
        let rd = self.session.read_dir(&dir).await.map_err(sftp_err)?;
        let mut out = Vec::new();
        let mut links = Vec::new();
        for e in rd {
            let name = e.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let path = join(&dir, &name);
            let entry = RemoteEntry::from_attrs(name, path, &e.metadata());
            if entry.kind == EntryKind::Symlink {
                links.push(out.len());
            }
            out.push(entry);
        }
        // Symlink targets need two extra round-trips each; resolve them
        // concurrently (bounded) so a directory full of links does not
        // take `links * 2 * RTT` to list.
        let resolved: Vec<(usize, Option<String>, Option<EntryKind>)> = stream::iter(links)
            .map(|i| {
                let path = out[i].path.clone();
                async move {
                    let (target, meta) =
                        tokio::join!(self.session.read_link(&path), self.session.metadata(&path));
                    (i, target.ok(), meta.ok().map(|a| a.file_type().into()))
                }
            })
            .buffer_unordered(SYMLINK_RESOLVE_CONCURRENCY)
            .collect()
            .await;
        for (i, target, kind) in resolved {
            out[i].link_target = target;
            out[i].target_kind = kind;
        }
        out.sort_by(|a, b| {
            let da = a.kind == EntryKind::Dir;
            let db = b.kind == EntryKind::Dir;
            db.cmp(&da)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(out)
    }

    /// Stat a path (follows symlinks).
    pub async fn stat(&self, path: &str) -> Result<RemoteEntry> {
        let a = self.session.metadata(path).await.map_err(sftp_err)?;
        let name = path.rsplit('/').next().unwrap_or(path).to_string();
        Ok(RemoteEntry::from_attrs(name, path.to_string(), &a))
    }

    /// Does `path` exist?
    pub async fn exists(&self, path: &str) -> Result<bool> {
        self.session.try_exists(path).await.map_err(sftp_err)
    }

    /// Create a single directory.
    pub async fn mkdir(&self, path: &str) -> Result<()> {
        self.session.create_dir(path).await.map_err(sftp_err)
    }

    /// Create a directory and all missing parents.
    pub async fn mkdir_all(&self, path: &str) -> Result<()> {
        let mut cur = if path.starts_with('/') {
            String::from("/")
        } else {
            String::new()
        };
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            if !cur.is_empty() && !cur.ends_with('/') {
                cur.push('/');
            }
            cur.push_str(seg);
            match self.session.metadata(&cur).await {
                Ok(a) if a.is_dir() => continue,
                Ok(_) => {
                    return Err(CoreError::Sftp(format!(
                        "{cur} exists and is not a directory"
                    )));
                }
                Err(_) => self.session.create_dir(&cur).await.map_err(sftp_err)?,
            }
        }
        Ok(())
    }

    /// Rename / move.
    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.session.rename(from, to).await.map_err(sftp_err)
    }

    /// Remove a file.
    pub async fn remove_file(&self, path: &str) -> Result<()> {
        self.session.remove_file(path).await.map_err(sftp_err)
    }

    /// Remove an empty directory.
    pub async fn remove_dir(&self, path: &str) -> Result<()> {
        self.session.remove_dir(path).await.map_err(sftp_err)
    }

    /// Remove a directory tree. Symlinks are unlinked, not followed.
    pub async fn remove_dir_all(&self, path: &str, cancel: &CancellationToken) -> Result<()> {
        let mut stack = vec![path.to_string()];
        let mut dirs = Vec::new();
        while let Some(d) = stack.pop() {
            if cancel.is_cancelled() {
                return Err(CoreError::Cancelled);
            }
            let rd = self.session.read_dir(&d).await.map_err(sftp_err)?;
            for e in rd {
                let name = e.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                let p = join(&d, &name);
                if e.file_type().is_dir() {
                    stack.push(p);
                } else {
                    self.session.remove_file(&p).await.map_err(sftp_err)?;
                }
            }
            dirs.push(d);
        }
        for d in dirs.into_iter().rev() {
            self.session.remove_dir(&d).await.map_err(sftp_err)?;
        }
        Ok(())
    }

    /// Set permission bits.
    pub async fn chmod(&self, path: &str, mode: u32) -> Result<()> {
        let mut a = self.session.metadata(path).await.map_err(sftp_err)?;
        let ftype = a.permissions.unwrap_or(0) & !0o7777;
        a.permissions = Some(ftype | (mode & 0o7777));
        a.size = None;
        a.uid = None;
        a.gid = None;
        a.user = None;
        a.group = None;
        a.atime = None;
        a.mtime = None;
        self.session.set_metadata(path, a).await.map_err(sftp_err)
    }

    /// Create a symlink at `link` pointing to `target`.
    pub async fn symlink(&self, link: &str, target: &str) -> Result<()> {
        self.session.symlink(link, target).await.map_err(sftp_err)
    }

    /// Read a whole file into memory (for editors/preview; refuses > 64 MiB).
    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let a = self.session.metadata(path).await.map_err(sftp_err)?;
        if a.size.unwrap_or(0) > 64 * 1024 * 1024 {
            return Err(CoreError::Sftp("file too large to read into memory".into()));
        }
        self.session.read(path).await.map_err(sftp_err)
    }

    /// Write a whole file (truncating).
    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let mut f = self.session.create(path).await.map_err(sftp_err)?;
        f.write_all(data).await?;
        f.close().await?;
        Ok(())
    }

    /// Open `path` for positional access; directories are refused.
    pub async fn open_file(&self, path: &str, mode: OpenMode) -> Result<SftpFile> {
        if mode == OpenMode::Read || self.exists(path).await? {
            let attrs = self.session.metadata(path).await.map_err(sftp_err)?;
            if attrs.is_dir() {
                return Err(CoreError::Sftp(format!("{path} is a directory")));
            }
        }
        let file = self
            .session
            .open_with_flags(path, mode.flags())
            .await
            .map_err(sftp_err)?;
        Ok(SftpFile {
            file: tokio::sync::Mutex::new(Positioned { file, pos: Some(0) }),
        })
    }

    /// Download `remote` to `local`. Returns the number of bytes transferred by
    /// this call (excluding any resumed prefix).
    pub async fn download(
        &self,
        remote: &str,
        local: &Path,
        opts: &TransferOptions,
    ) -> Result<u64> {
        let attrs = self.session.metadata(remote).await.map_err(sftp_err)?;
        if attrs.is_dir() {
            return Err(CoreError::Sftp(format!("{remote} is a directory")));
        }
        let total = attrs.size;

        let mut offset = 0u64;
        let mut file = if opts.resume && local.exists() {
            let mut f = tokio::fs::OpenOptions::new()
                .append(true)
                .open(local)
                .await?;
            offset = f.metadata().await?.len();
            if let Some(t) = total
                && offset > t
            {
                // Local is longer than remote: start over.
                f = tokio::fs::File::create(local).await?;
                offset = 0;
            }
            f
        } else {
            if let Some(parent) = local.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::File::create(local).await?
        };

        let mut src = self
            .session
            .open_with_flags(remote, OpenFlags::READ)
            .await
            .map_err(sftp_err)?;
        if offset > 0 {
            src.seek(std::io::SeekFrom::Start(offset)).await?;
        }
        opts.report(offset, total);

        let done = AtomicU64::new(offset);
        let mut buf = vec![0u8; CHUNK];
        loop {
            if opts.cancel.is_cancelled() {
                file.flush().await?;
                return Err(CoreError::Cancelled);
            }
            let n = tokio::select! {
                r = src.read(&mut buf) => r?,
                _ = opts.cancel.cancelled() => { file.flush().await?; return Err(CoreError::Cancelled) }
            };
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n]).await?;
            let d = done.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
            opts.report(d, total);
        }
        file.flush().await?;
        drop(file);
        let _ = src.close().await;

        if opts.preserve_mtime
            && let Some(mtime) = attrs.mtime
        {
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime as u64);
            let f = std::fs::File::open(local)?;
            let _ = f.set_modified(t);
        }
        Ok(done.load(Ordering::Relaxed) - offset)
    }

    /// Upload `local` to `remote`. Returns the number of bytes transferred by
    /// this call (excluding any resumed prefix).
    pub async fn upload(&self, local: &Path, remote: &str, opts: &TransferOptions) -> Result<u64> {
        let meta = tokio::fs::metadata(local).await?;
        if meta.is_dir() {
            return Err(CoreError::Sftp(format!(
                "{} is a directory",
                local.display()
            )));
        }
        let total = Some(meta.len());

        let mut offset = 0u64;
        let mut flags = OpenFlags::WRITE | OpenFlags::CREATE;
        if opts.resume
            && let Ok(existing) = self.session.metadata(remote).await
        {
            let have = existing.size.unwrap_or(0);
            if have <= meta.len() {
                offset = have;
                flags |= OpenFlags::APPEND;
            } else {
                flags |= OpenFlags::TRUNCATE;
            }
        } else {
            flags |= OpenFlags::TRUNCATE;
        }

        let mut src = tokio::fs::File::open(local).await?;
        if offset > 0 {
            src.seek(std::io::SeekFrom::Start(offset)).await?;
        }
        let mut dst = self
            .session
            .open_with_flags(remote, flags)
            .await
            .map_err(sftp_err)?;
        // O_APPEND servers ignore the offset; the rest need it.
        if offset > 0 {
            dst.seek(std::io::SeekFrom::Start(offset)).await?;
        }
        opts.report(offset, total);

        let mut done = offset;
        let mut buf = vec![0u8; CHUNK];
        loop {
            if opts.cancel.is_cancelled() {
                let _ = dst.close().await;
                return Err(CoreError::Cancelled);
            }
            let n = src.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            tokio::select! {
                r = dst.write_all(&buf[..n]) => r?,
                _ = opts.cancel.cancelled() => { let _ = dst.close().await; return Err(CoreError::Cancelled) }
            }
            done += n as u64;
            opts.report(done, total);
        }
        dst.flush().await?;
        dst.close().await?;

        if opts.preserve_mtime
            && let Ok(modified) = meta.modified()
        {
            let secs = modified
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            let mut a = FileAttributes::empty();
            a.mtime = Some(secs);
            a.atime = Some(secs);
            let _ = self.session.set_metadata(remote, a).await;
        }
        Ok(done - offset)
    }

    /// Close the subsystem channel.
    pub async fn close(&self) -> Result<()> {
        self.session.close().await.map_err(sftp_err)
    }
}

#[async_trait::async_trait]
impl remote::RemoteFile for SftpFile {
    async fn size(&self) -> Result<u64> {
        SftpFile::size(self).await
    }
    async fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        SftpFile::read_at(self, offset, len).await
    }
    async fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        SftpFile::write_at(self, offset, data).await
    }
    async fn truncate(&self, size: u64) -> Result<()> {
        SftpFile::truncate(self, size).await
    }
    async fn sync(&self) -> Result<()> {
        SftpFile::sync(self).await
    }
    async fn close(self: Box<Self>) -> Result<()> {
        SftpFile::close(*self).await
    }
}

#[async_trait::async_trait]
impl RemoteFs for Sftp {
    fn protocol(&self) -> RemoteProtocol {
        RemoteProtocol::Sftp
    }
    fn capabilities(&self) -> RemoteCapabilities {
        RemoteCapabilities {
            permissions: true,
            symlinks: true,
            ownership: true,
            server_copy: false,
            resume_upload: true,
        }
    }
    fn home(&self) -> &str {
        Sftp::home(self)
    }
    async fn canonicalize(&self, path: &str) -> Result<String> {
        Sftp::canonicalize(self, path).await
    }
    async fn list(&self, dir: &str) -> Result<Vec<RemoteEntry>> {
        Sftp::list(self, dir).await
    }
    async fn stat(&self, path: &str) -> Result<RemoteEntry> {
        Sftp::stat(self, path).await
    }
    async fn exists(&self, path: &str) -> Result<bool> {
        Sftp::exists(self, path).await
    }
    async fn mkdir(&self, path: &str) -> Result<()> {
        Sftp::mkdir(self, path).await
    }
    async fn mkdir_all(&self, path: &str) -> Result<()> {
        Sftp::mkdir_all(self, path).await
    }
    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        Sftp::rename(self, from, to).await
    }
    async fn copy(&self, _from: &str, _to: &str) -> Result<()> {
        Err(CoreError::Sftp(
            "server-side copy is not supported over SFTP".into(),
        ))
    }
    async fn remove_file(&self, path: &str) -> Result<()> {
        Sftp::remove_file(self, path).await
    }
    async fn remove_dir(&self, path: &str) -> Result<()> {
        Sftp::remove_dir(self, path).await
    }
    async fn remove_dir_all(&self, path: &str, cancel: &CancellationToken) -> Result<()> {
        Sftp::remove_dir_all(self, path, cancel).await
    }
    async fn chmod(&self, path: &str, mode: u32) -> Result<()> {
        Sftp::chmod(self, path, mode).await
    }
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        Sftp::read(self, path).await
    }
    async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        Sftp::write(self, path, data).await
    }
    async fn open_file(&self, path: &str, mode: OpenMode) -> Result<Box<dyn remote::RemoteFile>> {
        Ok(Box::new(Sftp::open_file(self, path, mode).await?))
    }
    async fn download(&self, remote: &str, local: &Path, opts: &TransferOptions) -> Result<u64> {
        Sftp::download(self, remote, local, opts).await
    }
    async fn upload(&self, local: &Path, remote: &str, opts: &TransferOptions) -> Result<u64> {
        Sftp::upload(self, local, remote, opts).await
    }
    async fn close(&self) -> Result<()> {
        Sftp::close(self).await
    }
}
