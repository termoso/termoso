//! Remote file systems — SFTP over the shared SSH connection path, WebDAV
//! over HTTP(S) — behind one [`SftpSession`] per remote: synchronous
//! directory operations (the caller runs them off the main thread) and
//! background transfers that report through [`SftpListener`]. The name
//! predates WebDAV; the API is protocol-neutral, see [`SftpSession::protocol`]
//! and [`SftpSession::capabilities`].
//!
//! Local paths are plain files Kotlin owns (its cache directory); moving
//! bytes between those and SAF documents is Kotlin's job. Rust never sees
//! content URIs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use termoso_core::localfs::LocalFs;
use termoso_core::model::ResolvedHost;
use termoso_core::remote::{RemoteFile, RemoteFs, relay_file};
use termoso_core::sftp::{
    self, OpenMode, Progress, ProgressFn, RemoteEntry, Sftp, TransferOptions,
};
use termoso_core::ssh::{SshClient, SshTarget};
use termoso_core::store::{CachedEntry, ConnectionHistory, Store};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::connect::{
    ConnectStage, ConnectUi, Connector, PromptAnswer, PromptRequest, SecretCache, connect_resolved,
};
use crate::error::{MobileError, Result};
use crate::presence::Slot;
use crate::session::SessionState;
use crate::settings::MobileSettings;
use crate::webdav::connect_webdav;

/// Progress callbacks are coalesced to this rate; the final one always goes out.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(120);
/// Transfers moving bytes at once; the rest wait as `Queued`.
const MAX_PARALLEL: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum, serde::Serialize, serde::Deserialize)]
pub enum EntryKind {
    Dir,
    File,
    Symlink,
    Other,
}

impl From<sftp::EntryKind> for EntryKind {
    fn from(k: sftp::EntryKind) -> Self {
        match k {
            sftp::EntryKind::Dir => Self::Dir,
            sftp::EntryKind::File => Self::File,
            sftp::EntryKind::Symlink => Self::Symlink,
            sftp::EntryKind::Other => Self::Other,
        }
    }
}

/// Wire protocol behind a [`SftpSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FileProtocol {
    Sftp,
    Webdav,
    /// The local shell's home directory on this device.
    Local,
}

impl FileProtocol {
    /// Lowercase wire name, as stored in connection history and presence.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sftp => "sftp",
            Self::Webdav => "webdav",
            Self::Local => "local",
        }
    }
}

/// What the protocol can do beyond listing and transfers; the UI hides the
/// controls for anything `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FileCapabilities {
    /// `chmod` works and entries carry a mode.
    pub permissions: bool,
    /// Symlinks are reported.
    pub symlinks: bool,
    /// Owner / group are reported.
    pub ownership: bool,
    /// Server-side copy without downloading.
    pub server_copy: bool,
    /// Interrupted uploads continue from the bytes already there.
    pub resume_upload: bool,
}

/// One directory entry, ready to display.
#[derive(Debug, Clone, uniffi::Record, serde::Serialize, serde::Deserialize)]
pub struct SftpEntry {
    pub name: String,
    pub path: String,
    pub kind: EntryKind,
    /// What a symlink points at; equals `kind` for everything else.
    pub target_kind: EntryKind,
    /// Navigable: a directory or a symlink to one.
    pub is_dir: bool,
    pub size: Option<u64>,
    pub mode: Option<u32>,
    /// `drwxr-xr-x` style; `None` when the protocol has no mode bits.
    pub permissions: Option<String>,
    /// `user:group` (names when the server sends them, ids otherwise).
    pub owner: Option<String>,
    pub modified_ms: Option<i64>,
    pub link_target: Option<String>,
    pub hidden: bool,
}

/// How [`SftpSession::open_file`] opens a remote file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FileMode {
    /// Existing file, reads only.
    Read,
    /// Create or truncate, writes only.
    Write,
    /// Create if missing, keep contents, reads and writes at any offset.
    ReadWrite,
}

impl From<FileMode> for OpenMode {
    fn from(m: FileMode) -> Self {
        match m {
            FileMode::Read => Self::Read,
            FileMode::Write => Self::Write,
            FileMode::ReadWrite => Self::ReadWrite,
        }
    }
}

/// A remote file held open for positional reads and writes, so Kotlin can
/// serve it piecewise (a proxy file descriptor handed to another app)
/// without ever holding the whole file. Calls block; run them off the main
/// thread. Dropping the object closes the handle.
#[derive(uniffi::Object)]
pub struct SftpFile {
    file: Mutex<Option<Box<dyn RemoteFile>>>,
    /// Whole body when served through the offline cache (read-only).
    cached: Option<Arc<Vec<u8>>>,
    /// `None` for a file served from the offline cache.
    _live: Option<Arc<Live>>,
    runtime: tokio::runtime::Handle,
}

impl SftpFile {
    fn with<T>(&self, f: impl FnOnce(&dyn RemoteFile) -> Result<T>) -> Result<T> {
        if let Some(bytes) = &self.cached {
            return f(&CachedBody(bytes.clone()));
        }
        let guard = self.file.lock().expect("file poisoned");
        match guard.as_ref() {
            Some(file) => f(file.as_ref()),
            None => Err(MobileError::Closed),
        }
    }
}

/// A file served from the offline cache: whole body in memory, read-only.
struct CachedBody(Arc<Vec<u8>>);

#[async_trait::async_trait]
impl RemoteFile for CachedBody {
    async fn size(&self) -> termoso_core::error::Result<u64> {
        Ok(self.0.len() as u64)
    }
    async fn read_at(&self, offset: u64, len: usize) -> termoso_core::error::Result<Vec<u8>> {
        let start = (offset as usize).min(self.0.len());
        let end = start.saturating_add(len).min(self.0.len());
        Ok(self.0[start..end].to_vec())
    }
    async fn write_at(&self, _offset: u64, _data: &[u8]) -> termoso_core::error::Result<()> {
        Err(read_only())
    }
    async fn truncate(&self, _size: u64) -> termoso_core::error::Result<()> {
        Err(read_only())
    }
    async fn sync(&self) -> termoso_core::error::Result<()> {
        Ok(())
    }
    async fn close(self: Box<Self>) -> termoso_core::error::Result<()> {
        Ok(())
    }
}

fn read_only() -> termoso_core::error::CoreError {
    termoso_core::error::CoreError::Invalid("read-only while offline".into())
}

#[uniffi::export]
impl SftpFile {
    /// Current size in bytes.
    pub fn size(&self) -> Result<u64> {
        self.with(|file| self.runtime.block_on(async { Ok(file.size().await?) }))
    }

    /// Up to `len` bytes at `offset`; shorter only at end of file.
    pub fn read_at(&self, offset: u64, len: u32) -> Result<Vec<u8>> {
        self.with(|file| {
            self.runtime
                .block_on(async { Ok(file.read_at(offset, len as usize).await?) })
        })
    }

    /// Write `data` at `offset`, growing the file as needed.
    pub fn write_at(&self, offset: u64, data: Vec<u8>) -> Result<()> {
        self.with(|file| {
            self.runtime
                .block_on(async { Ok(file.write_at(offset, &data).await?) })
        })
    }

    /// Set the file's length.
    pub fn truncate(&self, size: u64) -> Result<()> {
        self.with(|file| {
            self.runtime
                .block_on(async { Ok(file.truncate(size).await?) })
        })
    }

    /// Flush pending writes to the server (and to disk where it supports that).
    pub fn sync(&self) -> Result<()> {
        self.with(|file| self.runtime.block_on(async { Ok(file.sync().await?) }))
    }

    /// Flush and release the server handle; later calls fail with `Closed`.
    /// (`release`, not `close`: the generated Kotlin object already has
    /// `AutoCloseable.close()` for the native handle.)
    pub fn release(&self) -> Result<()> {
        let file = self.file.lock().expect("file poisoned").take();
        match file {
            Some(file) => self.runtime.block_on(async { Ok(file.close().await?) }),
            None => Ok(()),
        }
    }
}

impl Drop for SftpFile {
    fn drop(&mut self) {
        if let Some(file) = self.file.lock().expect("file poisoned").take() {
            self.runtime.spawn(async move {
                let _ = file.close().await;
            });
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TransferDirection {
    Upload,
    Download,
    /// Remote to remote through this device (`relay`): `remote_path` is
    /// the source on this session, `local_path` the destination on the
    /// peer session named by `to_session`.
    Relay,
}

/// `Queued` → `Running` once a slot is free. `Paused` and `Failed` keep the
/// partial file and go back to `Queued` on resume, continuing from where
/// they stopped; `Cancelled` and `Done` are final.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TransferStatus {
    Queued,
    Running,
    Paused,
    Done,
    Failed { message: String },
    Cancelled,
}

impl TransferStatus {
    /// Still owned by the queue: `dismiss` leaves it alone.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Queued | Self::Running | Self::Paused)
    }

    /// Can go back to `Queued`.
    pub fn is_resumable(&self) -> bool {
        matches!(self, Self::Paused | Self::Failed { .. })
    }
}

/// A queued, running, paused or finished transfer.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TransferCard {
    pub id: u64,
    pub direction: TransferDirection,
    /// Remote file name.
    pub name: String,
    pub remote_path: String,
    pub local_path: String,
    /// `SftpSession::id` of the destination of a relay.
    pub to_session: Option<String>,
    pub done: u64,
    pub total: Option<u64>,
    pub bytes_per_sec: u64,
    pub status: TransferStatus,
}

/// Callbacks into Kotlin, from Rust worker threads.
#[uniffi::export(with_foreign)]
pub trait SftpListener: Send + Sync {
    fn on_state(&self, state: SessionState);
    /// Answer with [`SftpSession::answer`] using the same `prompt_id`.
    fn on_prompt(&self, prompt_id: u64, request: PromptRequest);
    /// A transfer was queued, progressed or finished.
    fn on_transfer(&self, transfer: TransferCard);
}

struct SftpUi {
    listener: Arc<dyn SftpListener>,
    state: Arc<Mutex<SessionState>>,
}

impl ConnectUi for SftpUi {
    fn phase(&self, stage: ConnectStage, hop: Option<String>) {
        let state = SessionState::connecting(stage, hop);
        *self.state.lock().expect("state poisoned") = state.clone();
        self.listener.on_state(state);
    }

    fn prompt(&self, prompt_id: u64, request: PromptRequest) {
        self.listener.on_prompt(prompt_id, request);
    }
}

struct Live {
    fs: Arc<dyn RemoteFs>,
    /// The SSH transport SFTP runs over, with the jump clients that must
    /// outlive it. `None` for WebDAV: the HTTP client lives inside `fs`.
    ssh: Option<(Arc<SshClient>, Vec<Arc<SshClient>>)>,
}

impl Live {
    async fn close(&self) {
        let _ = self.fs.close().await;
        if let Some((client, _)) = &self.ssh {
            let _ = client.disconnect().await;
        }
    }
}

/// Which remote a session opens.
pub(crate) enum Backend {
    Sftp {
        target: SshTarget,
        resolved: Option<ResolvedHost>,
    },
    WebDav {
        resolved: ResolvedHost,
        /// App-writable directory where write-mode files spool before the
        /// PUT.
        spool_dir: PathBuf,
    },
    /// The local shell's home; paths are relative to it and cannot leave it.
    Local { root: PathBuf, home: String },
    /// SFTP over the SSH connection of an open terminal: no new login, no
    /// prompts — exactly what the terminal already authenticated with.
    Session {
        client: Arc<SshClient>,
        host_id: Option<Uuid>,
        label: String,
        target_display: String,
    },
}

impl Backend {
    fn protocol(&self) -> FileProtocol {
        match self {
            Self::Sftp { .. } | Self::Session { .. } => FileProtocol::Sftp,
            Self::WebDav { .. } => FileProtocol::Webdav,
            Self::Local { .. } => FileProtocol::Local,
        }
    }

    fn capabilities(&self) -> FileCapabilities {
        match self {
            Self::Sftp { .. } | Self::Session { .. } => FileCapabilities {
                permissions: true,
                symlinks: true,
                ownership: true,
                server_copy: false,
                resume_upload: true,
            },
            Self::WebDav { .. } => FileCapabilities {
                permissions: false,
                symlinks: false,
                ownership: false,
                server_copy: true,
                resume_upload: false,
            },
            Self::Local { .. } => FileCapabilities {
                permissions: true,
                symlinks: true,
                ownership: false,
                server_copy: true,
                resume_upload: true,
            },
        }
    }
}

struct Transfer {
    card: TransferCard,
    /// Destination session of a relay; weak so a session relaying to
    /// itself does not keep itself alive.
    peer: Option<Weak<Inner>>,
    /// Replaced for every run; cancelled to pause as well as to discard.
    cancel: CancellationToken,
    /// The pending cancellation means pause, not discard.
    pausing: bool,
    /// The next run continues an existing partial file instead of
    /// replacing it.
    resume: bool,
    started: Instant,
    /// `done` when the current run began (resumed prefix), for the rate.
    base: u64,
    /// The first progress report of the run sets `base`.
    fresh: bool,
    last_report: Instant,
}

/// One run of a transfer, handed to the worker.
struct Launch {
    id: u64,
    direction: TransferDirection,
    peer: Option<Weak<Inner>>,
    remote: String,
    local: String,
    resume: bool,
    cancel: CancellationToken,
}

/// Transfer bookkeeping: what to start, what changed. Every method that
/// changes a card's status returns it so the caller can notify.
struct TransferQueue {
    transfers: BTreeMap<u64, Transfer>,
    next_id: u64,
    /// Parent of every transfer's token; fired by `disconnect`.
    closed: CancellationToken,
}

impl TransferQueue {
    fn new(closed: CancellationToken) -> Self {
        Self {
            transfers: BTreeMap::new(),
            next_id: 1,
            closed,
        }
    }

    #[cfg(test)]
    fn enqueue(
        &mut self,
        direction: TransferDirection,
        remote: String,
        local: String,
    ) -> TransferCard {
        self.enqueue_with(direction, remote, local, None)
    }

    fn enqueue_with(
        &mut self,
        direction: TransferDirection,
        remote: String,
        local: String,
        peer: Option<(String, Weak<Inner>)>,
    ) -> TransferCard {
        let id = self.next_id;
        self.next_id += 1;
        let name = remote.rsplit('/').next().unwrap_or(&remote).to_string();
        let card = TransferCard {
            id,
            direction,
            name,
            remote_path: remote,
            local_path: local,
            to_session: peer.as_ref().map(|(id, _)| id.clone()),
            done: 0,
            total: None,
            bytes_per_sec: 0,
            status: TransferStatus::Queued,
        };
        let now = Instant::now();
        self.transfers.insert(
            id,
            Transfer {
                card: card.clone(),
                peer: peer.map(|(_, p)| p),
                cancel: self.closed.child_token(),
                pausing: false,
                resume: false,
                started: now,
                base: 0,
                fresh: true,
                last_report: now,
            },
        );
        card
    }

    fn cards(&self) -> Vec<TransferCard> {
        self.transfers.values().map(|t| t.card.clone()).collect()
    }

    fn running(&self) -> usize {
        self.transfers
            .values()
            .filter(|t| t.card.status == TransferStatus::Running)
            .count()
    }

    /// Move queued transfers into free slots, oldest first.
    fn take_ready(&mut self) -> Vec<(Launch, TransferCard)> {
        let mut free = MAX_PARALLEL.saturating_sub(self.running());
        let mut out = Vec::new();
        for (&id, t) in self.transfers.iter_mut() {
            if free == 0 {
                break;
            }
            if t.card.status != TransferStatus::Queued {
                continue;
            }
            free -= 1;
            let now = Instant::now();
            t.card.status = TransferStatus::Running;
            t.card.bytes_per_sec = 0;
            t.cancel = self.closed.child_token();
            t.pausing = false;
            t.started = now;
            t.last_report = now;
            t.fresh = true;
            out.push((
                Launch {
                    id,
                    direction: t.card.direction,
                    peer: t.peer.clone(),
                    remote: t.card.remote_path.clone(),
                    local: t.card.local_path.clone(),
                    resume: t.resume,
                    cancel: t.cancel.clone(),
                },
                t.card.clone(),
            ));
        }
        out
    }

    /// Keep the transfer for `resume`. Returns the card when it changed on
    /// the spot (queued → paused); a running one changes when its worker
    /// stops.
    fn pause(&mut self, id: u64) -> Option<TransferCard> {
        let t = self.transfers.get_mut(&id)?;
        match t.card.status {
            TransferStatus::Queued => {
                t.card.status = TransferStatus::Paused;
                Some(t.card.clone())
            }
            TransferStatus::Running => {
                t.pausing = true;
                t.cancel.cancel();
                None
            }
            _ => None,
        }
    }

    /// Put a paused or failed transfer back in line; it continues from the
    /// partial file both sides already have.
    fn resume(&mut self, id: u64) -> Option<TransferCard> {
        let t = self.transfers.get_mut(&id)?;
        if !t.card.status.is_resumable() {
            return None;
        }
        t.card.status = TransferStatus::Queued;
        t.card.bytes_per_sec = 0;
        t.pausing = false;
        t.resume = true;
        Some(t.card.clone())
    }

    /// Discard the transfer. Returns the card when it changed on the spot;
    /// a running one changes when its worker stops.
    fn cancel(&mut self, id: u64) -> Option<TransferCard> {
        let t = self.transfers.get_mut(&id)?;
        match t.card.status {
            TransferStatus::Queued | TransferStatus::Paused | TransferStatus::Failed { .. } => {
                t.card.status = TransferStatus::Cancelled;
                t.card.bytes_per_sec = 0;
                Some(t.card.clone())
            }
            TransferStatus::Running => {
                t.pausing = false;
                t.cancel.cancel();
                None
            }
            TransferStatus::Done | TransferStatus::Cancelled => None,
        }
    }

    /// Remote path of the partial file a cancelled upload left behind, if
    /// it ever ran.
    fn remote_leftover(&self, id: u64) -> Option<(String, Option<Weak<Inner>>)> {
        let t = self.transfers.get(&id)?;
        if t.card.status != TransferStatus::Cancelled || !t.resume {
            return None;
        }
        match t.card.direction {
            TransferDirection::Upload => Some((t.card.remote_path.clone(), None)),
            TransferDirection::Relay => Some((t.card.local_path.clone(), t.peer.clone())),
            TransferDirection::Download => None,
        }
    }

    /// Forget a finished transfer; active ones are left alone.
    fn dismiss(&mut self, id: u64) -> bool {
        if self
            .transfers
            .get(&id)
            .is_some_and(|t| !t.card.status.is_active())
        {
            self.transfers.remove(&id);
            true
        } else {
            false
        }
    }

    /// Returns the card when the UI should see it (rate-limited).
    fn progress(&mut self, id: u64, p: Progress) -> Option<TransferCard> {
        let t = self.transfers.get_mut(&id)?;
        if t.card.status != TransferStatus::Running {
            return None;
        }
        if t.fresh {
            t.fresh = false;
            t.base = p.done;
        }
        t.card.done = p.done;
        t.card.total = p.total;
        let elapsed = t.started.elapsed().as_secs_f64();
        if elapsed > 0.2 {
            t.card.bytes_per_sec = ((p.done.saturating_sub(t.base)) as f64 / elapsed) as u64;
        }
        let now = Instant::now();
        let finished = p.total.is_some_and(|total| p.done >= total);
        if !finished && now.duration_since(t.last_report) < PROGRESS_INTERVAL {
            return None;
        }
        t.last_report = now;
        Some(t.card.clone())
    }

    /// The worker stopped: settle the status. A cancelled run becomes
    /// `Paused` when that was the intent, `Cancelled` otherwise; anything
    /// short of `Done` keeps its partial file for a later resume.
    fn finish(&mut self, id: u64, result: Result<()>) -> Option<TransferCard> {
        let t = self.transfers.get_mut(&id)?;
        if t.card.status != TransferStatus::Running {
            return None;
        }
        let interrupted = t.cancel.is_cancelled();
        t.card.status = match result {
            Ok(()) => {
                if let Some(total) = t.card.total {
                    t.card.done = total;
                }
                TransferStatus::Done
            }
            Err(e) if interrupted || matches!(e, MobileError::Cancelled) => {
                if t.pausing {
                    TransferStatus::Paused
                } else {
                    TransferStatus::Cancelled
                }
            }
            Err(e) => TransferStatus::Failed {
                message: e.to_string(),
            },
        };
        t.card.bytes_per_sec = 0;
        t.pausing = false;
        t.resume = true;
        Some(t.card.clone())
    }
}

struct Inner {
    store: Arc<Store>,
    conn: Arc<Connector>,
    listener: Arc<dyn SftpListener>,
    state: Arc<Mutex<SessionState>>,
    protocol: FileProtocol,
    capabilities: FileCapabilities,
    live: Mutex<Option<Arc<Live>>>,
    queue: Mutex<TransferQueue>,
    runtime: tokio::runtime::Handle,
    /// Fired by `disconnect`: aborts the connect and every transfer.
    closed: CancellationToken,
    /// Settings → transfer speed limit, KiB/s (0 = unlimited).
    rate_limit_kib: u32,
    /// Team presence registration for a saved team-vault host.
    presence: Option<Slot>,
    /// Offline file cache of the saved host this session opens, when the
    /// host has one enabled and its team policy allows it.
    cache: Option<CacheCtx>,
}

struct CacheCtx {
    host_id: Uuid,
    vault_id: Uuid,
    dir: PathBuf,
}

impl CacheCtx {
    fn resolve(store: &Store, backend: &Backend, dir: PathBuf) -> Option<Self> {
        let (host_id, vault_id) = match backend {
            Backend::Sftp {
                resolved: Some(r), ..
            } => (r.host.id, r.host.vault_id),
            Backend::WebDav { resolved, .. } => (resolved.host.id, resolved.host.vault_id),
            Backend::Session {
                host_id: Some(h), ..
            } => {
                let host = store
                    .get::<termoso_proto::entities::payload::Host>(*h)
                    .ok()
                    .flatten()?;
                (host.id, host.vault_id)
            }
            _ => return None,
        };
        if termoso_core::policy::offline_cache_denied(store, vault_id) {
            // Policy flipped to deny since the copies were taken.
            let _ = store.clear_file_cache(Some(host_id));
            return None;
        }
        if !store.file_cache_config(host_id).ok()?.enabled {
            return None;
        }
        Some(Self {
            host_id,
            vault_id,
            dir,
        })
    }
}

/// A remote file system (SFTP or WebDAV). Drop-safe: dropping the last
/// reference closes the connection and cancels its transfers.
#[derive(uniffi::Object)]
pub struct SftpSession {
    id: Uuid,
    inner: Arc<Inner>,
    runtime: tokio::runtime::Handle,
}

pub(crate) struct SftpLaunch {
    pub store: Arc<Store>,
    pub secrets: Arc<SecretCache>,
    pub backend: Backend,
    pub settings: MobileSettings,
    pub listener: Arc<dyn SftpListener>,
    pub presence: Option<Slot>,
    /// Where encrypted offline copies live (profile directory).
    pub cache_dir: PathBuf,
}

impl SftpSession {
    pub(crate) fn launch(runtime: tokio::runtime::Handle, launch: SftpLaunch) -> Arc<Self> {
        let SftpLaunch {
            store,
            secrets,
            backend,
            settings,
            listener,
            presence,
            cache_dir,
        } = launch;
        let cache = CacheCtx::resolve(&store, &backend, cache_dir);
        let state = Arc::new(Mutex::new(SessionState::connecting(
            ConnectStage::Connecting,
            None,
        )));
        let conn = Arc::new(Connector::new(
            store.clone(),
            secrets.clone(),
            Arc::new(SftpUi {
                listener: listener.clone(),
                state: state.clone(),
            }),
        ));
        let closed = CancellationToken::new();
        let inner = Arc::new(Inner {
            store,
            conn,
            listener,
            state,
            protocol: backend.protocol(),
            capabilities: backend.capabilities(),
            live: Mutex::new(None),
            queue: Mutex::new(TransferQueue::new(closed.clone())),
            runtime: runtime.clone(),
            closed,
            rate_limit_kib: settings.transfer_rate_limit_kib,
            presence,
            cache,
        });
        let session = Arc::new(Self {
            id: Uuid::new_v4(),
            inner: inner.clone(),
            runtime: runtime.clone(),
        });
        runtime.spawn(run(inner, backend, settings));
        session
    }

    fn live(&self) -> Result<Arc<Live>> {
        match self.inner.live.lock().expect("live poisoned").clone() {
            Some(l) => Ok(l),
            None => match self.state() {
                SessionState::Connecting { .. } => Err(MobileError::invalid("still connecting")),
                _ => Err(MobileError::Closed),
            },
        }
    }

    /// The host is unreachable (connect failed or the link dropped) and the
    /// session may fall back to offline copies.
    fn offline(&self) -> Option<&CacheCtx> {
        if self.inner.live.lock().expect("live poisoned").is_some() {
            return None;
        }
        match self.state() {
            SessionState::Failed { .. } | SessionState::Closed { .. } => self.inner.cache.as_ref(),
            _ => None,
        }
    }

    /// Whether offline copies of this host can be browsed right now: the
    /// connection failed and the cache holds something for it.
    pub fn offline_copies_available(&self) -> bool {
        self.offline().is_some_and(|c| {
            self.inner
                .store
                .file_cache_usage(Some(c.host_id))
                .is_ok_and(|u| u.files + u.dirs > 0)
        })
    }

    /// True while requests are served from the offline cache.
    pub fn is_offline(&self) -> bool {
        self.offline().is_some()
    }

    /// Cached files of this host (newest first), for the "local copies" list.
    pub fn offline_copies(&self) -> Result<Vec<OfflineCopy>> {
        let Some(c) = self.inner.cache.as_ref() else {
            return Ok(Vec::new());
        };
        Ok(self
            .inner
            .store
            .cached_files(c.host_id)?
            .into_iter()
            .map(OfflineCopy::from)
            .collect())
    }

    /// When the copy of `path` was taken, if there is one.
    pub fn cached_at(&self, path: String) -> Result<Option<i64>> {
        let Some(c) = self.inner.cache.as_ref() else {
            return Ok(None);
        };
        Ok(self
            .inner
            .store
            .cached_file(c.host_id, &path)?
            .map(|e| e.cached_at.timestamp_millis()))
    }

    fn cache_listing(&self, dir: &str, entries: &[SftpEntry]) {
        if let Some(c) = &self.inner.cache {
            let _ = self
                .inner
                .store
                .cache_dir(c.host_id, c.vault_id, dir, entries, &c.dir);
        }
    }

    fn cache_body(&self, path: &str, mtime: Option<i64>, body: &[u8]) {
        if let Some(c) = &self.inner.cache {
            let _ = self
                .inner
                .store
                .cache_file(c.host_id, c.vault_id, path, mtime, body, &c.dir);
        }
    }

    /// Serve `path` from the cache when the remote still matches (`stat`
    /// says same size and mtime); refetch and replace otherwise.
    async fn read_through(&self, live: &Live, path: &str) -> Result<Vec<u8>> {
        let Some(c) = &self.inner.cache else {
            return Ok(live.fs.read(path).await?);
        };
        let st = live.fs.stat(path).await?;
        let mtime = st.mtime.map(i64::from);
        if let (Some(size), Ok(Some(e))) = (st.size, self.inner.store.cached_file(c.host_id, path))
            && e.is_fresh(size, mtime)
            && let Ok(body) = self.inner.store.read_cached_file(c.host_id, path)
        {
            return Ok(body);
        }
        let body = live.fs.read(path).await?;
        self.cache_body(path, mtime, &body);
        Ok(body)
    }

    fn offline_stat(&self, c: &CacheCtx, path: &str) -> Result<SftpEntry> {
        let p = if path.len() > 1 {
            path.trim_end_matches('/')
        } else {
            path
        };
        if let Some(parent) = termoso_core::remote::parent(p)
            && let Ok(entries) = self
                .inner
                .store
                .read_cached_dir::<SftpEntry>(c.host_id, &parent)
            && let Some(e) = entries.into_iter().find(|e| e.path == p)
        {
            return Ok(e);
        }
        if let Some(e) = self.inner.store.cached_file(c.host_id, p)? {
            return Ok(offline_entry(&e));
        }
        if self.inner.store.cached_dir(c.host_id, p)?.is_some() {
            return Ok(SftpEntry {
                name: p.rsplit('/').next().unwrap_or(p).to_string(),
                path: p.to_string(),
                kind: EntryKind::Dir,
                target_kind: EntryKind::Dir,
                is_dir: true,
                size: None,
                mode: None,
                permissions: None,
                owner: None,
                modified_ms: None,
                link_target: None,
                hidden: false,
            });
        }
        Err(MobileError::not_found(format!("{p}: no offline copy")))
    }

    fn queue(&self, direction: TransferDirection, remote: String, local: String) -> u64 {
        self.queue_with(direction, remote, local, None)
    }

    fn queue_with(
        &self,
        direction: TransferDirection,
        remote: String,
        local: String,
        peer: Option<(String, Weak<Inner>)>,
    ) -> u64 {
        let card = self
            .inner
            .queue
            .lock()
            .expect("queue poisoned")
            .enqueue_with(direction, remote, local, peer);
        let id = card.id;
        self.inner.listener.on_transfer(card);
        self.inner.pump();
        id
    }
}

#[uniffi::export]
impl SftpSession {
    pub fn id(&self) -> String {
        self.id.to_string()
    }

    pub fn state(&self) -> SessionState {
        self.inner.state.lock().expect("state poisoned").clone()
    }

    /// Wire protocol; known before the connection is up.
    pub fn protocol(&self) -> FileProtocol {
        self.inner.protocol
    }

    /// What this protocol supports; known before the connection is up.
    pub fn capabilities(&self) -> FileCapabilities {
        self.inner.capabilities
    }

    /// The remote home directory; empty until connected.
    pub fn home(&self) -> String {
        self.inner
            .live
            .lock()
            .expect("live poisoned")
            .as_ref()
            .map(|l| l.fs.home().to_string())
            .unwrap_or_default()
    }

    /// Reply to a prompt. Returns `false` if the prompt is no longer waiting.
    pub fn answer(&self, prompt_id: u64, answer: PromptAnswer) -> bool {
        self.inner.conn.answer(prompt_id, answer)
    }

    /// Directory listing, directories first, then by name; `.`/`..` excluded.
    pub fn list(&self, dir: String) -> Result<Vec<SftpEntry>> {
        if let Some(c) = self.offline() {
            return Ok(self.inner.store.read_cached_dir(c.host_id, &dir)?);
        }
        let live = self.live()?;
        let entries = self.runtime.block_on(async {
            let mut entries: Vec<SftpEntry> = live
                .fs
                .list(&dir)
                .await?
                .into_iter()
                .map(entry_from)
                .collect();
            entries.sort_by(|a, b| {
                b.is_dir
                    .cmp(&a.is_dir)
                    .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            });
            Ok::<_, MobileError>(entries)
        })?;
        self.cache_listing(&dir, &entries);
        Ok(entries)
    }

    pub fn stat(&self, path: String) -> Result<SftpEntry> {
        if let Some(c) = self.offline() {
            return self.offline_stat(c, &path);
        }
        let live = self.live()?;
        self.runtime
            .block_on(async move { Ok(entry_from(live.fs.stat(&path).await?)) })
    }

    /// Absolute, symlink-free form of `path` (`~` and relative paths resolve
    /// against the home directory).
    pub fn canonicalize(&self, path: String) -> Result<String> {
        let live = self.live()?;
        self.runtime.block_on(async move {
            let p = path.trim();
            let p = if p.is_empty() || p == "~" {
                live.fs.home().to_string()
            } else if let Some(rest) = p.strip_prefix("~/") {
                format!("{}/{rest}", live.fs.home().trim_end_matches('/'))
            } else {
                p.to_string()
            };
            Ok(live.fs.canonicalize(&p).await?)
        })
    }

    pub fn exists(&self, path: String) -> Result<bool> {
        let live = self.live()?;
        self.runtime
            .block_on(async move { Ok(live.fs.exists(&path).await?) })
    }

    pub fn mkdir(&self, path: String) -> Result<()> {
        let live = self.live()?;
        self.runtime
            .block_on(async move { Ok(live.fs.mkdir(&path).await?) })
    }

    pub fn rename(&self, from: String, to: String) -> Result<()> {
        let live = self.live()?;
        self.runtime
            .block_on(async move { Ok(live.fs.rename(&from, &to).await?) })
    }

    /// Server-side copy of a file or directory tree; only when
    /// [`FileCapabilities::server_copy`] is set.
    pub fn copy(&self, from: String, to: String) -> Result<()> {
        let live = self.live()?;
        self.runtime
            .block_on(async move { Ok(live.fs.copy(&from, &to).await?) })
    }

    /// Remove a file, symlink or (recursively) a directory.
    pub fn remove(&self, path: String) -> Result<()> {
        let live = self.live()?;
        let cancel = self.inner.closed.child_token();
        self.runtime.block_on(async move {
            let entry = live.fs.stat(&path).await?;
            if entry.kind == sftp::EntryKind::Dir {
                live.fs.remove_dir_all(&path, &cancel).await?;
            } else {
                live.fs.remove_file(&path).await?;
            }
            Ok(())
        })
    }

    /// `mode` is the permission bits only (e.g. `0o644`).
    pub fn chmod(&self, path: String, mode: u32) -> Result<()> {
        let live = self.live()?;
        self.runtime
            .block_on(async move { Ok(live.fs.chmod(&path, mode & 0o7777).await?) })
    }

    /// Small text files for previews; refuses anything over 64 MiB.
    pub fn read(&self, path: String) -> Result<Vec<u8>> {
        if let Some(c) = self.offline() {
            return Ok(self.inner.store.read_cached_file(c.host_id, &path)?);
        }
        let live = self.live()?;
        self.runtime
            .block_on(async { self.read_through(&live, &path).await })
    }

    /// Overwrite (or create) `path` with `data`; for saving edited text
    /// files. The file's mode is preserved when it already exists.
    pub fn write(&self, path: String, data: Vec<u8>) -> Result<()> {
        if self.offline().is_some() {
            return Err(MobileError::ReadOnlyOffline);
        }
        let live = self.live()?;
        self.runtime
            .block_on(async move { Ok(live.fs.write(&path, &data).await?) })
    }

    /// Open `path` for positional access (see [`SftpFile`]); directories
    /// are refused.
    pub fn open_file(&self, path: String, mode: FileMode) -> Result<Arc<SftpFile>> {
        if let Some(c) = self.offline() {
            if mode != FileMode::Read {
                return Err(MobileError::ReadOnlyOffline);
            }
            let body = self.inner.store.read_cached_file(c.host_id, &path)?;
            return Ok(Arc::new(SftpFile {
                file: Mutex::new(None),
                cached: Some(Arc::new(body)),
                _live: None,
                runtime: self.runtime.clone(),
            }));
        }
        let live = self.live()?;
        // A read of a cacheable file goes through the cache: whole body
        // fetched once, served from memory, kept for offline use.
        if mode == FileMode::Read
            && let Some(c) = &self.inner.cache
            && let Ok(st) = self.runtime.block_on(live.fs.stat(&path))
            && st.kind != sftp::EntryKind::Dir
            && let Some(size) = st.size
            && self
                .inner
                .store
                .file_cache_config(c.host_id)
                .is_ok_and(|cfg| cfg.accepts(&path, size))
        {
            let body = self
                .runtime
                .block_on(async { self.read_through(&live, &path).await })?;
            return Ok(Arc::new(SftpFile {
                file: Mutex::new(None),
                cached: Some(Arc::new(body)),
                _live: Some(live),
                runtime: self.runtime.clone(),
            }));
        }
        let file = self
            .runtime
            .block_on(async { live.fs.open_file(&path, mode.into()).await })?;
        Ok(Arc::new(SftpFile {
            file: Mutex::new(Some(file)),
            cached: None,
            _live: Some(live),
            runtime: self.runtime.clone(),
        }))
    }

    /// Queue a download of `remote` into the local file `local_path`
    /// (parents are created, an existing file is replaced). Returns the
    /// transfer id; progress arrives on the listener.
    pub fn download(&self, remote: String, local_path: String) -> u64 {
        self.queue(TransferDirection::Download, remote, local_path)
    }

    /// Queue an upload of the local file `local_path` to `remote`
    /// (replaced if it exists).
    pub fn upload(&self, local_path: String, remote: String) -> u64 {
        self.queue(TransferDirection::Upload, remote, local_path)
    }

    /// Queue a copy of `remote` on this session to `dest` on `to` (a path
    /// including the file name), streamed through this device without
    /// touching its storage; `dest` is replaced if it exists. Progress
    /// arrives on this session's listener.
    pub fn relay(&self, remote: String, to: Arc<SftpSession>, dest: String) -> u64 {
        let peer = (to.id(), Arc::downgrade(&to.inner));
        self.queue_with(TransferDirection::Relay, remote, dest, Some(peer))
    }

    pub fn transfers(&self) -> Vec<TransferCard> {
        self.inner.queue.lock().expect("queue poisoned").cards()
    }

    /// Stop a queued or running transfer, keeping its partial file so
    /// `resume_transfer` can continue it.
    pub fn pause_transfer(&self, id: u64) {
        let card = self.inner.queue.lock().expect("queue poisoned").pause(id);
        if let Some(card) = card {
            self.inner.listener.on_transfer(card);
        }
        self.inner.pump();
    }

    /// Put a paused or failed transfer back in the queue; it continues from
    /// the bytes already on the destination rather than starting over.
    pub fn resume_transfer(&self, id: u64) {
        let card = self.inner.queue.lock().expect("queue poisoned").resume(id);
        if let Some(card) = card {
            self.inner.listener.on_transfer(card);
            self.inner.pump();
        }
    }

    /// Discard a transfer in any non-final state. A cancelled upload's
    /// remote partial is removed; the local file is the caller's to clean up.
    pub fn cancel_transfer(&self, id: u64) {
        let card = self.inner.queue.lock().expect("queue poisoned").cancel(id);
        if let Some(card) = card {
            self.inner.settled(card);
        }
        self.inner.pump();
    }

    /// Forget a finished transfer; queued, running and paused ones are left
    /// alone and `false` comes back.
    pub fn dismiss_transfer(&self, id: u64) -> bool {
        self.inner.queue.lock().expect("queue poisoned").dismiss(id)
    }

    /// Tear the connection down; the object stays usable for `state()`.
    pub fn disconnect(&self) {
        self.inner.conn.cancel_prompts();
        self.inner.closed.cancel();
        let live = self.inner.live.lock().expect("live poisoned").take();
        if let Some(live) = live {
            self.runtime.spawn(async move { live.close().await });
        }
    }
}

impl Drop for SftpSession {
    fn drop(&mut self) {
        self.disconnect();
    }
}

impl Inner {
    fn rate_limit(&self) -> Option<u64> {
        (self.rate_limit_kib > 0).then(|| u64::from(self.rate_limit_kib) * 1024)
    }

    fn set_state(&self, state: SessionState) {
        if let Some(p) = &self.presence {
            match state {
                SessionState::Connected => p.connected(),
                SessionState::Connecting { .. }
                | SessionState::Closed { .. }
                | SessionState::Failed { .. } => p.gone(),
            }
        }
        *self.state.lock().expect("state poisoned") = state.clone();
        self.listener.on_state(state);
    }

    /// Start queued transfers while slots are free.
    fn pump(self: &Arc<Self>) {
        let ready = self.queue.lock().expect("queue poisoned").take_ready();
        for (launch, card) in ready {
            self.listener.on_transfer(card);
            let inner = self.clone();
            self.runtime.spawn(async move {
                let result = inner.run_transfer(&launch).await;
                inner.finish(launch.id, result);
            });
        }
    }

    async fn run_transfer(self: &Arc<Self>, launch: &Launch) -> Result<()> {
        let live = self
            .live
            .lock()
            .expect("live poisoned")
            .clone()
            .ok_or(MobileError::Closed)?;
        let id = launch.id;
        let reporter = self.clone();
        let progress: ProgressFn = Arc::new(move |p: Progress| reporter.progress(id, p));
        let opts = TransferOptions {
            resume: launch.resume,
            preserve_mtime: true,
            cancel: launch.cancel.clone(),
            progress: Some(progress),
            rate_limit: self.rate_limit(),
        };
        match launch.direction {
            TransferDirection::Download => {
                live.fs
                    .download(&launch.remote, Path::new(&launch.local), &opts)
                    .await?;
            }
            TransferDirection::Upload => {
                live.fs
                    .upload(Path::new(&launch.local), &launch.remote, &opts)
                    .await?;
            }
            TransferDirection::Relay => {
                let to = Self::peer_live(launch.peer.as_ref())?;
                relay_file(
                    live.fs.as_ref(),
                    to.fs.as_ref(),
                    &launch.remote,
                    &launch.local,
                    &opts,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// The destination of a relay, which must still be connected.
    fn peer_live(peer: Option<&Weak<Inner>>) -> Result<Arc<Live>> {
        let peer = peer
            .and_then(Weak::upgrade)
            .ok_or_else(|| MobileError::invalid("destination connection is closed"))?;
        let live = peer.live.lock().expect("live poisoned").clone();
        live.ok_or_else(|| MobileError::invalid("destination connection is closed"))
    }

    fn progress(&self, id: u64, p: Progress) {
        let card = self.queue.lock().expect("queue poisoned").progress(id, p);
        if let Some(card) = card {
            self.listener.on_transfer(card);
        }
    }

    fn finish(self: &Arc<Self>, id: u64, result: Result<()>) {
        let card = self
            .queue
            .lock()
            .expect("queue poisoned")
            .finish(id, result);
        if let Some(card) = card {
            self.settled(card);
        }
        self.pump();
    }

    /// Announce a final card; a cancelled upload first loses its remote
    /// partial so the listing the UI refreshes to is already clean.
    fn settled(self: &Arc<Self>, card: TransferCard) {
        let leftover = self
            .queue
            .lock()
            .expect("queue poisoned")
            .remote_leftover(card.id);
        let live = match &leftover {
            Some((_, Some(peer))) => Self::peer_live(Some(peer)).ok(),
            _ => self.live.lock().expect("live poisoned").clone(),
        };
        match (leftover, live) {
            (Some((path, _)), Some(live)) => {
                let inner = self.clone();
                self.runtime.spawn(async move {
                    let _ = live.fs.remove_file(&path).await;
                    inner.listener.on_transfer(card);
                });
            }
            _ => self.listener.on_transfer(card),
        }
    }
}

fn permissions(mode: Option<u32>, kind: EntryKind) -> Option<String> {
    let mode = mode?;
    let type_char = match kind {
        EntryKind::Dir => 'd',
        EntryKind::Symlink => 'l',
        EntryKind::File | EntryKind::Other => '-',
    };
    let mut out = String::with_capacity(10);
    out.push(type_char);
    let bits = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    for (i, (bit, ch)) in bits.iter().enumerate() {
        let set = mode & bit != 0;
        let special = match i {
            2 => mode & 0o4000 != 0,
            5 => mode & 0o2000 != 0,
            8 => mode & 0o1000 != 0,
            _ => false,
        };
        out.push(match (set, special, i) {
            (true, true, 8) => 't',
            (false, true, 8) => 'T',
            (true, true, _) => 's',
            (false, true, _) => 'S',
            (true, false, _) => *ch,
            (false, false, _) => '-',
        });
    }
    Some(out)
}

/// A file kept in the offline cache.
#[derive(Debug, Clone, uniffi::Record)]
pub struct OfflineCopy {
    pub path: String,
    pub size: u64,
    pub modified_ms: Option<i64>,
    pub cached_at_ms: i64,
}

impl From<CachedEntry> for OfflineCopy {
    fn from(e: CachedEntry) -> Self {
        Self {
            path: e.path,
            size: e.size,
            modified_ms: e.mtime.map(|t| t * 1000),
            cached_at_ms: e.cached_at.timestamp_millis(),
        }
    }
}

fn offline_entry(e: &CachedEntry) -> SftpEntry {
    SftpEntry {
        name: e.path.rsplit('/').next().unwrap_or(&e.path).to_string(),
        path: e.path.clone(),
        kind: EntryKind::File,
        target_kind: EntryKind::File,
        is_dir: false,
        size: Some(e.size),
        mode: None,
        permissions: None,
        owner: None,
        modified_ms: e.mtime.map(|t| t * 1000),
        link_target: None,
        hidden: e
            .path
            .rsplit('/')
            .next()
            .is_some_and(|n| n.starts_with('.')),
    }
}

fn entry_from(e: RemoteEntry) -> SftpEntry {
    let kind = EntryKind::from(e.kind);
    let target_kind = e.target_kind.map(EntryKind::from).unwrap_or(kind);
    let owner = match (&e.user, &e.group, e.uid, e.gid) {
        (Some(u), Some(g), _, _) => Some(format!("{u}:{g}")),
        (Some(u), None, _, Some(g)) => Some(format!("{u}:{g}")),
        (None, Some(g), Some(u), _) => Some(format!("{u}:{g}")),
        (None, None, Some(u), Some(g)) => Some(format!("{u}:{g}")),
        _ => None,
    };
    SftpEntry {
        hidden: e.name.starts_with('.'),
        permissions: permissions(e.mode, kind),
        is_dir: target_kind == EntryKind::Dir,
        owner,
        modified_ms: e.mtime.map(|t| t as i64 * 1000),
        name: e.name,
        path: e.path,
        kind,
        target_kind,
        size: e.size,
        mode: e.mode.map(|m| m & 0o7777),
        link_target: e.link_target,
    }
}

async fn run(inner: Arc<Inner>, backend: Backend, settings: MobileSettings) {
    if let Backend::Local { root, home } = &backend {
        // No connection to record: the directory is right here.
        let result = tokio::select! {
            r = LocalFs::open_at(root, home) => r,
            _ = inner.closed.cancelled() => {
                inner.set_state(SessionState::Closed { reason: None });
                return;
            }
        };
        match result {
            Ok(fs) => {
                *inner.live.lock().expect("live poisoned") = Some(Arc::new(Live {
                    fs: Arc::new(fs),
                    ssh: None,
                }));
                inner.set_state(SessionState::Connected);
                inner.closed.cancelled().await;
                inner.set_state(SessionState::Closed { reason: None });
            }
            Err(e) => {
                let e = MobileError::from(e);
                inner.set_state(SessionState::Failed {
                    kind: e.kind(),
                    message: e.to_string(),
                });
            }
        }
        return;
    }
    let started = Instant::now();
    let (host_id, label, target_display) = match &backend {
        Backend::Sftp { target, resolved } => (
            resolved.as_ref().map(|r| r.host.id),
            resolved
                .as_ref()
                .map(|r| r.host.data.label.clone())
                .unwrap_or_else(|| target.host.clone()),
            target.display(),
        ),
        Backend::WebDav { resolved, .. } => (
            Some(resolved.host.id),
            resolved.host.data.label.clone(),
            resolved
                .webdav
                .as_ref()
                .map(|w| w.url.clone())
                .unwrap_or_default(),
        ),
        Backend::Session {
            host_id,
            label,
            target_display,
            ..
        } => (*host_id, label.clone(), target_display.clone()),
        Backend::Local { .. } => unreachable!("handled above"),
    };
    let protocol = backend.protocol();
    let history = |duration: Option<u64>, error: Option<String>| ConnectionHistory {
        host_id,
        label: label.clone(),
        target: target_display.clone(),
        protocol: protocol.as_str().into(),
        duration_secs: duration,
        error,
    };
    let history_id = inner.store.record_connection(&history(None, None)).ok();
    let finish = |error: Option<String>| {
        if let Some(id) = history_id {
            let _ = inner
                .store
                .update_connection(id, &history(Some(started.elapsed().as_secs()), error));
        }
    };

    let connect = async {
        match &backend {
            Backend::Sftp { target, resolved } => {
                let (client, jumps) =
                    connect_resolved(&inner.conn, &settings, target.clone(), resolved.as_ref())
                        .await?;
                inner.set_state(SessionState::connecting(ConnectStage::OpeningSftp, None));
                let sftp = Sftp::open(&client).await?;
                Ok::<_, MobileError>(Live {
                    fs: Arc::new(sftp),
                    ssh: Some((client, jumps)),
                })
            }
            Backend::WebDav {
                resolved,
                spool_dir,
            } => {
                let dav = connect_webdav(&inner.conn, resolved, spool_dir.clone()).await?;
                Ok(Live {
                    fs: Arc::new(dav),
                    ssh: None,
                })
            }
            Backend::Session { client, .. } => {
                inner.set_state(SessionState::connecting(ConnectStage::OpeningSftp, None));
                let sftp = Sftp::open(client).await?;
                Ok(Live {
                    fs: Arc::new(sftp),
                    ssh: Some((client.clone(), Vec::new())),
                })
            }
            Backend::Local { .. } => unreachable!("handled above"),
        }
    };
    let live = tokio::select! {
        r = connect => match r {
            Ok(l) => l,
            Err(e) => {
                let e = inner.conn.map_error(e);
                finish(Some(e.to_string()));
                inner.set_state(SessionState::Failed { kind: e.kind(), message: e.to_string() });
                return;
            }
        },
        _ = inner.closed.cancelled() => {
            finish(Some("cancelled".into()));
            inner.set_state(SessionState::Closed { reason: None });
            return;
        }
    };
    if inner.closed.is_cancelled() {
        live.close().await;
        finish(Some("cancelled".into()));
        inner.set_state(SessionState::Closed { reason: None });
        return;
    }
    *inner.live.lock().expect("live poisoned") = Some(Arc::new(live));
    inner.set_state(SessionState::Connected);

    inner.closed.cancelled().await;
    finish(None);
    inner.set_state(SessionState::Closed { reason: None });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_strings() {
        let p = |m, k| permissions(Some(m), k).unwrap();
        assert_eq!(p(0o755, EntryKind::Dir), "drwxr-xr-x");
        assert_eq!(p(0o644, EntryKind::File), "-rw-r--r--");
        assert_eq!(p(0o4755, EntryKind::File), "-rwsr-xr-x");
        assert_eq!(p(0o1777, EntryKind::Dir), "drwxrwxrwt");
        assert_eq!(permissions(None, EntryKind::Symlink), None);
    }

    #[test]
    fn entry_mapping() {
        let e = entry_from(RemoteEntry {
            name: ".bashrc".into(),
            path: "/home/u/.bashrc".into(),
            kind: sftp::EntryKind::Symlink,
            size: Some(12),
            mode: Some(0o100777),
            uid: Some(1000),
            gid: Some(1000),
            user: Some("u".into()),
            group: None,
            mtime: Some(1_700_000_000),
            atime: None,
            link_target: Some("/etc/skel/.bashrc".into()),
            target_kind: Some(sftp::EntryKind::File),
        });
        assert!(e.hidden);
        assert!(!e.is_dir);
        assert_eq!(e.kind, EntryKind::Symlink);
        assert_eq!(e.target_kind, EntryKind::File);
        assert_eq!(e.mode, Some(0o777));
        assert_eq!(e.permissions.as_deref(), Some("lrwxrwxrwx"));
        assert_eq!(e.owner.as_deref(), Some("u:1000"));
        assert_eq!(e.modified_ms, Some(1_700_000_000_000));
    }

    fn queue_with(n: usize) -> (TransferQueue, Vec<u64>) {
        let mut q = TransferQueue::new(CancellationToken::new());
        let ids = (0..n)
            .map(|i| {
                q.enqueue(
                    TransferDirection::Download,
                    format!("/srv/f{i}"),
                    format!("/tmp/f{i}"),
                )
                .id
            })
            .collect();
        (q, ids)
    }

    fn status(q: &TransferQueue, id: u64) -> TransferStatus {
        q.transfers[&id].card.status.clone()
    }

    #[test]
    fn slots_are_limited_and_refilled_in_order() {
        let (mut q, ids) = queue_with(5);
        let ready = q.take_ready();
        assert_eq!(
            ready.iter().map(|(l, _)| l.id).collect::<Vec<_>>(),
            ids[..3]
        );
        assert!(
            ready
                .iter()
                .all(|(l, c)| !l.resume && c.status == TransferStatus::Running)
        );
        assert_eq!(status(&q, ids[3]), TransferStatus::Queued);
        assert!(q.take_ready().is_empty());

        let done = q.finish(ids[0], Ok(())).unwrap();
        assert_eq!(done.status, TransferStatus::Done);
        let next = q.take_ready();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].0.id, ids[3]);
    }

    #[test]
    fn pause_queued_then_resume_continues_partial() {
        let (mut q, ids) = queue_with(4);
        q.take_ready();
        let paused = q.pause(ids[3]).unwrap();
        assert_eq!(paused.status, TransferStatus::Paused);
        q.finish(ids[0], Ok(()));
        assert!(
            q.take_ready().is_empty(),
            "paused must not take the free slot"
        );

        let queued = q.resume(ids[3]).unwrap();
        assert_eq!(queued.status, TransferStatus::Queued);
        let next = q.take_ready();
        assert_eq!(next[0].0.id, ids[3]);
        assert!(next[0].0.resume);
    }

    #[test]
    fn pausing_a_running_transfer_keeps_it_for_resume() {
        let (mut q, ids) = queue_with(1);
        let (launch, _) = q.take_ready().remove(0);
        assert!(q.pause(ids[0]).is_none(), "worker reports the change");
        assert!(launch.cancel.is_cancelled());
        q.progress(
            ids[0],
            Progress {
                done: 500,
                total: Some(1000),
            },
        );
        // Whatever error the interrupted worker surfaces, the intent wins.
        let card = q
            .finish(
                ids[0],
                Err(MobileError::Ssh {
                    detail: "eof".into(),
                }),
            )
            .unwrap();
        assert_eq!(card.status, TransferStatus::Paused);
        assert_eq!(card.done, 500);
        assert!(!q.dismiss(ids[0]), "paused transfers stay in the list");

        q.resume(ids[0]).unwrap();
        let (launch, card) = q.take_ready().remove(0);
        assert!(launch.resume);
        assert!(!launch.cancel.is_cancelled(), "fresh token per run");
        assert_eq!(card.done, 500, "progress so far stays on the card");
        // A resumed run reports from its offset; the rate must not count it.
        q.progress(
            ids[0],
            Progress {
                done: 500,
                total: Some(1000),
            },
        );
        assert_eq!(q.transfers[&ids[0]].base, 500);
        assert_eq!(q.transfers[&ids[0]].card.bytes_per_sec, 0);
        let done = q.finish(ids[0], Ok(())).unwrap();
        assert_eq!(done.status, TransferStatus::Done);
        assert_eq!(done.done, 1000);
    }

    #[test]
    fn cancel_discards_from_any_non_final_state() {
        let (mut q, ids) = queue_with(4);
        let launches = q.take_ready();
        assert!(q.cancel(ids[0]).is_none());
        assert!(launches[0].0.cancel.is_cancelled());
        assert_eq!(
            q.finish(ids[0], Err(MobileError::Cancelled))
                .unwrap()
                .status,
            TransferStatus::Cancelled
        );
        assert_eq!(q.cancel(ids[3]).unwrap().status, TransferStatus::Cancelled);

        q.pause(ids[1]);
        q.finish(ids[1], Err(MobileError::Cancelled));
        assert_eq!(status(&q, ids[1]), TransferStatus::Paused);
        assert_eq!(q.cancel(ids[1]).unwrap().status, TransferStatus::Cancelled);
        assert!(q.resume(ids[1]).is_none(), "cancelled is final");

        let failed = q
            .finish(
                ids[2],
                Err(MobileError::Ssh {
                    detail: "boom".into(),
                }),
            )
            .unwrap();
        assert!(matches!(failed.status, TransferStatus::Failed { .. }));
        assert!(
            q.resume(ids[2]).is_some(),
            "failed retries from the partial file"
        );
        assert!(q.take_ready()[0].0.resume);
        assert!(q.cancel(ids[3]).is_none(), "already cancelled");
        assert!(q.dismiss(ids[3]));
        assert!(!q.dismiss(ids[2]), "running again");
    }

    #[test]
    fn cancelled_upload_that_ran_leaves_a_remote_partial_to_remove() {
        let mut q = TransferQueue::new(CancellationToken::new());
        let ids: Vec<u64> = (0..3)
            .map(|i| {
                q.enqueue(
                    TransferDirection::Upload,
                    format!("/srv/up{i}"),
                    format!("/tmp/up{i}"),
                )
                .id
            })
            .collect();
        let dl = q
            .enqueue(
                TransferDirection::Download,
                "/srv/dl".into(),
                "/tmp/dl".into(),
            )
            .id;
        assert_eq!(q.take_ready().len(), 3, "the three uploads run, dl waits");

        // Running upload cancelled outright.
        q.cancel(ids[0]);
        q.finish(ids[0], Err(MobileError::Cancelled));
        assert_eq!(
            q.remote_leftover(ids[0]).map(|(p, _)| p).as_deref(),
            Some("/srv/up0")
        );

        // Paused after a partial run, then cancelled.
        q.pause(ids[1]);
        q.finish(ids[1], Err(MobileError::Cancelled));
        assert!(q.remote_leftover(ids[1]).is_none(), "paused keeps it");
        q.cancel(ids[1]);
        assert_eq!(
            q.remote_leftover(ids[1]).map(|(p, _)| p).as_deref(),
            Some("/srv/up1")
        );

        // Finished uploads and downloads have nothing to remove remotely.
        q.finish(ids[2], Ok(()));
        assert!(q.remote_leftover(ids[2]).is_none());
        q.take_ready();
        q.cancel(dl);
        q.finish(dl, Err(MobileError::Cancelled));
        assert_eq!(status(&q, dl), TransferStatus::Cancelled);
        assert!(q.remote_leftover(dl).is_none());

        // A queued upload that never ran.
        let fresh = q
            .enqueue(
                TransferDirection::Upload,
                "/srv/up9".into(),
                "/tmp/up9".into(),
            )
            .id;
        q.cancel(fresh);
        assert!(q.remote_leftover(fresh).is_none());
    }

    #[test]
    fn stray_reports_after_settling_are_ignored() {
        let (mut q, ids) = queue_with(1);
        q.take_ready();
        q.cancel(ids[0]);
        q.finish(ids[0], Err(MobileError::Cancelled));
        assert!(
            q.progress(
                ids[0],
                Progress {
                    done: 1,
                    total: None
                }
            )
            .is_none()
        );
        assert!(q.finish(ids[0], Ok(())).is_none());
        assert_eq!(status(&q, ids[0]), TransferStatus::Cancelled);
    }
}
