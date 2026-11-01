//! An interactive SSH session: connect (jump hosts, proxy, saved credentials,
//! prompts for anything missing), open a shell, pump the byte stream into
//! the emulator and tell Kotlin when to repaint.
//!
//! Everything the UI needs to answer — host key confirmation, password,
//! passphrase, keyboard-interactive — arrives as a [`PromptRequest`] on the
//! listener and is answered through [`SshSession::answer`]; the Rust side
//! blocks its own connection task, never a UI thread.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use termoso_core::api::ApiClient;
use termoso_core::live::{HostShare, LiveEvent, ViewerJoin};
use termoso_core::model::ResolvedHost;
use termoso_core::mosh::{self, MoshError};
use termoso_core::pty::{LocalShellOptions, LocalTerminal};
use termoso_core::sftp::{Progress, Sftp, TransferOptions};
use termoso_core::ssh::proxy::ProxyConfig;
use termoso_core::ssh::{IpVersion, SshClient, SshTarget};
use termoso_core::store::{CommandHistory, ConnectionHistory, LogMeta, Recorder, Store};
use termoso_core::telnet::{TelnetOptions, TelnetTerminal};
use termoso_core::terminal::{SharedTerminal, TermEvent, TermEvents, TermSize};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::autocomplete::{Completer, SuggestionItem};
use crate::connect::{
    ConnectStage, ConnectUi, Connector, PromptAnswer, PromptRequest, SecretCache, connect_resolved,
    stage_label,
};
use crate::error::{MobileError, Result};
use crate::keys::{KeyMods, SpecialKey, encode_key, encode_text};
use crate::live::{LiveListener, LiveParticipantCard, LiveShare, ShareState, ViewState};
use crate::presence::Slot;
use crate::serial::PipeTerminal;
use crate::settings::MobileSettings;
use crate::terminal::{
    Emulator, GridFrame, GridSnapshot, InputMark, SearchHit, TermSignal, TerminalPalette,
};

/// Give the shell time to print its prompt before the startup snippet lands.
const STARTUP_SNIPPET_DELAY: Duration = Duration::from_millis(400);

/// Telnet TCP connect timeout.
const TELNET_TIMEOUT: Duration = Duration::from_secs(20);

/// Longest command line kept in the history (matches the desktop).
const MAX_COMMAND_CHARS: usize = 4096;
/// How long after Enter the command line is re-read for late echo.
const ECHO_GRACE: Duration = Duration::from_millis(250);

/// Files sent into a terminal land here on the remote side.
const REMOTE_DROP_DIR: &str = "/tmp";

/// Where the session is.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SessionState {
    /// Connecting; `stage` is what to show (localised by the UI), `hop` the
    /// jump host it belongs to, `detail` the English rendering of both.
    Connecting {
        detail: String,
        stage: ConnectStage,
        hop: Option<String>,
    },
    Connected,
    /// The remote shell ended or the connection dropped.
    Closed {
        reason: Option<String>,
    },
    Failed {
        kind: String,
        message: String,
    },
}

/// Callbacks into Kotlin. Invoked from Rust worker threads; keep them quick
/// (post to the main thread, do not block).
#[uniffi::export(with_foreign)]
pub trait SessionListener: Send + Sync {
    fn on_state(&self, state: SessionState);
    /// The grid changed; fetch a fresh [`GridSnapshot`].
    fn on_render(&self);
    /// Answer with [`SshSession::answer`] using the same `prompt_id`.
    fn on_prompt(&self, prompt_id: u64, request: PromptRequest);
    fn on_title(&self, title: Option<String>);
    fn on_bell(&self);
    /// OSC 52 copy request from the remote.
    fn on_clipboard(&self, text: String);
    /// The remote OS was recognised (stored on the host when there is one).
    fn on_os_detected(&self, os_name: String);
}

/// Progress of a file being sent into a terminal ([`SshSession::send_file`]).
#[uniffi::export(with_foreign)]
pub trait FileDropListener: Send + Sync {
    /// `total` is 0 when unknown.
    fn on_progress(&self, done: u64, total: u64);
}

/// A file name safe to use under the remote temp directory: no path
/// separators, control characters or shell-hostile leading dashes.
pub(crate) fn safe_drop_name(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\'' | '`' | '$' => '_',
            c if c.is_control() || c.is_whitespace() => '_',
            c => c,
        })
        .collect();
    while out.starts_with('-') || out.starts_with('.') {
        out.remove(0);
    }
    if out.chars().count() > 120 {
        let ext = out.rsplit_once('.').map(|(_, e)| e.to_string());
        out = out.chars().take(100).collect();
        if let Some(ext) = ext.filter(|e| e.len() <= 10) {
            out.push('.');
            out.push_str(&ext);
        }
    }
    if out.is_empty() {
        out = format!("termoso-{}", Uuid::new_v4().simple());
    }
    out
}

/// Which transport carries the shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Transport {
    /// Whatever the host is configured for (Mosh when its SSH section says
    /// so, plain SSH otherwise).
    Auto,
    Ssh,
    /// Bootstrap `mosh-server` over SSH, then talk Mosh over UDP.
    Mosh,
    /// The host's Telnet section (errors when it has none).
    Telnet,
}

/// How to open the terminal.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TerminalOptions {
    pub cols: u16,
    pub rows: u16,
    /// `TERM` value; empty → from settings (default `xterm-256color`).
    pub term_type: String,
    /// `None` → the scheme chosen in settings.
    pub palette: Option<TerminalPalette>,
    pub transport: Transport,
}

/// Connect-stage callbacks routed onto the terminal listener.
struct TerminalUi {
    listener: Arc<dyn SessionListener>,
    state: Arc<Mutex<SessionState>>,
}

impl SessionState {
    pub(crate) fn connecting(stage: ConnectStage, hop: Option<String>) -> Self {
        Self::Connecting {
            detail: stage_label(&stage, hop.as_deref()),
            stage,
            hop,
        }
    }
}

impl ConnectUi for TerminalUi {
    fn phase(&self, stage: ConnectStage, hop: Option<String>) {
        let state = SessionState::connecting(stage, hop);
        *self.state.lock().expect("state poisoned") = state.clone();
        self.listener.on_state(state);
    }

    fn prompt(&self, prompt_id: u64, request: PromptRequest) {
        self.listener.on_prompt(prompt_id, request);
    }
}

struct Inner {
    store: Arc<Store>,
    listener: Arc<dyn SessionListener>,
    conn: Arc<Connector>,
    emulator: Mutex<Emulator>,
    terminal: Mutex<Option<SharedTerminal>>,
    /// Latest view size; the PTY is opened with whatever is current then.
    size: Mutex<TermSize>,
    /// Typed bytes go through one ordered queue drained by a single writer
    /// task once the terminal is up, so keystrokes never overtake each other
    /// (and anything typed before the shell opens is delivered then).
    input: mpsc::UnboundedSender<Vec<u8>>,
    input_rx: Mutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>,
    state: Arc<Mutex<SessionState>>,
    closed: tokio::sync::Notify,
    /// Last title the remote set (what a share announces).
    title: Mutex<Option<String>>,
    /// Set while this terminal is being shared: output is mirrored into it.
    share: Mutex<Option<Arc<ShareState>>>,
    /// Set when this terminal *is* a view of somebody else's share.
    view: Option<Arc<ViewState>>,
    /// Team presence registration for a saved team-vault host.
    presence: Option<Slot>,
    /// Saved host this terminal is on, for command history and recordings.
    host_id: Option<Uuid>,
    /// Vault of that host; scopes the snippets offered by autocomplete.
    vault_id: Option<Uuid>,
    /// A local shell's starting directory and home (`~` and relative paths
    /// in suggestions resolve against them); `None` for anything remote.
    local: Option<(String, String)>,
    /// Where the cursor was when the current command line started being
    /// typed; `None` while nothing is pending.
    typed: Mutex<Option<InputMark>>,
    /// Autocomplete state (directory listing cache).
    completer: Completer,
    /// The authenticated SSH connection while a plain SSH shell is up
    /// (Mosh drops its SSH leg), for side channels such as file drops.
    ssh: Mutex<Option<Arc<SshClient>>>,
    /// Encrypted output capture, when recording is on for this session.
    recorder: Mutex<Option<Arc<Recorder>>>,
    /// Where finished recordings are written.
    logs_dir: std::path::PathBuf,
    /// Sync trigger for a finished recording.
    account: Option<Arc<crate::account::AccountRuntime>>,
}

impl Inner {
    fn recorder(&self) -> Option<Arc<Recorder>> {
        self.recorder.lock().expect("recorder poisoned").clone()
    }

    /// Begin capturing output when the user's switch or the team vault's
    /// policy says so. Failures only disable the recording.
    fn start_recording(&self, settings: &MobileSettings, vault_id: Option<Uuid>, meta: LogMeta) {
        let vault_id = match vault_id.or_else(|| self.store.local_vault().ok().map(|v| v.id)) {
            Some(v) => v,
            None => return,
        };
        let team_policy = self.store.vault(vault_id).ok().is_some_and(|v| {
            v.kind == termoso_core::store::LocalVaultKind::Team && v.session_logging
        });
        if !settings.record_sessions && !team_policy {
            return;
        }
        match Recorder::begin(&self.store, vault_id, meta) {
            Ok(r) => *self.recorder.lock().expect("recorder poisoned") = Some(Arc::new(r)),
            Err(e) => tracing::warn!("session recording disabled: {e}"),
        }
    }

    /// Persist the capture (if any) and let the sync engine upload it.
    fn finish_recording(&self) {
        let Some(rec) = self.recorder.lock().expect("recorder poisoned").take() else {
            return;
        };
        match rec.finish(&self.store, &self.logs_dir) {
            Ok(()) => {
                if let Some(account) = &self.account {
                    account.sync_in_background();
                }
            }
            Err(e) => tracing::warn!("saving session recording failed: {e}"),
        }
    }

    /// Remember where the command line starts, unless one is pending.
    fn mark_typing(&self) {
        let mut typed = self.typed.lock().expect("typed poisoned");
        if typed.is_none() {
            *typed = Some(
                self.emulator
                    .lock()
                    .expect("emulator poisoned")
                    .input_mark(),
            );
        }
    }

    fn forget_typing(&self) {
        *self.typed.lock().expect("typed poisoned") = None;
        self.completer.invalidate();
    }

    /// What has been typed at the current prompt so far, as echoed by the
    /// remote. `None` while nothing is pending, on the alternate screen
    /// (editors, pagers) and for a view of somebody else's terminal.
    fn typed_line(&self) -> Option<String> {
        if self.view.is_some() {
            return None;
        }
        let mark = (*self.typed.lock().expect("typed poisoned"))?;
        let em = self.emulator.lock().expect("emulator poisoned");
        let until = em.input_mark();
        em.input_between(&mark, &until)
    }

    /// Enter was pressed: the echoed line since the mark is the command.
    /// Reads the screen, so whatever the remote refused to echo (passwords)
    /// is not there; obvious inline secrets are skipped as well. The line
    /// is read again shortly after, since the echo of the last keystrokes
    /// may still be in flight.
    fn commit_typing(self: &Arc<Self>, runtime: &tokio::runtime::Handle) {
        let Some(mark) = self.typed.lock().expect("typed poisoned").take() else {
            return;
        };
        self.completer.invalidate();
        if self.view.is_some() {
            return;
        }
        let (until, first) = {
            let em = self.emulator.lock().expect("emulator poisoned");
            let until = em.input_mark();
            (until, em.input_between(&mark, &until))
        };
        let inner = self.clone();
        runtime.spawn(async move {
            tokio::time::sleep(ECHO_GRACE).await;
            let later = inner
                .emulator
                .lock()
                .expect("emulator poisoned")
                .input_between(&mark, &until);
            let command = match (first, later) {
                (Some(f), Some(l)) if l.starts_with(&f) => l,
                (Some(f), _) => f,
                (None, Some(l)) => l,
                (None, None) => return,
            };
            inner.record_command(command);
        });
    }

    fn record_command(&self, command: String) {
        if command.is_empty()
            || command.chars().count() > MAX_COMMAND_CHARS
            || looks_like_secret(&command)
        {
            return;
        }
        let _ = self.store.record_command(&CommandHistory {
            host_id: self.host_id,
            command,
        });
    }
}

/// Mirror of the desktop's `looksLikeSecret`: command lines that carry a
/// credential inline are not worth keeping.
pub(crate) fn looks_like_secret(command: &str) -> bool {
    let c = command.trim();
    let lower = c.to_ascii_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();

    // `password=…`, `token: …`, `API_KEY=…`, `--secret=…` anywhere.
    const NAMES: [&str; 11] = [
        "password",
        "passwd",
        "pass",
        "secret",
        "token",
        "apikey",
        "api_key",
        "api-key",
        "private_key",
        "private-key",
        "access_key",
    ];
    let assigns = lower
        .split(|ch: char| ch.is_whitespace() || ch == ';' || ch == '|' || ch == '&')
        .any(|tok| {
            let Some(idx) = tok.find(['=', ':']) else {
                return false;
            };
            let (name, value) = tok.split_at(idx);
            let name = name.trim_start_matches('-').trim_start_matches('$');
            let value = value[1..].trim_start_matches(['=', ':']);
            !value.is_empty()
                && !value.starts_with('/')
                && (NAMES.iter().any(|n| name.contains(n))
                    || name.ends_with("_key")
                    || name.ends_with("-key"))
        });
    if assigns {
        return true;
    }

    // `export FOO_TOKEN=…`
    if words
        .windows(2)
        .any(|w| w[0] == "export" && w[1].contains('=') && has_secret_hint(w[1]))
    {
        return true;
    }
    // `mysql … -pSECRET`
    let db = ["mysql", "mysqladmin", "mysqldump", "mariadb"];
    if words.iter().any(|w| db.contains(w))
        && words.iter().any(|w| w.len() > 2 && w.starts_with("-p"))
    {
        return true;
    }
    // `sshpass -p SECRET`
    if words.windows(3).any(|w| w[0] == "sshpass" && w[1] == "-p") {
        return true;
    }
    // `curl -u user:pass`
    let http = ["curl", "wget", "http"];
    if words.iter().any(|w| http.contains(w))
        && words
            .windows(2)
            .any(|w| (w[0] == "-u" || w[0] == "--user") && w[1].contains(':'))
    {
        return true;
    }
    if lower.contains("authorization:") && (lower.contains("bearer ") || lower.contains("basic ")) {
        return true;
    }
    // `echo secret | sudo passwd`, `printf … | chpasswd`
    if (words.first() == Some(&"echo") || words.first() == Some(&"printf")) && lower.contains('|') {
        let tail = lower.rsplit('|').next().unwrap_or("");
        let tail = tail.trim().trim_start_matches("sudo ").trim();
        if tail.starts_with("passwd")
            || tail.starts_with("chpasswd")
            || tail.starts_with("su ")
            || tail == "su"
        {
            return true;
        }
    }
    false
}

fn has_secret_hint(assignment: &str) -> bool {
    let name = assignment.split('=').next().unwrap_or("");
    ["key", "token", "secret", "pass"]
        .iter()
        .any(|k| name.contains(k))
}

impl Inner {
    /// Drain the input queue into `terminal` in order; ends when the queue
    /// closes, the terminal is gone, or a write fails.
    fn start_writer(self: &Arc<Self>, runtime: &tokio::runtime::Handle, terminal: SharedTerminal) {
        let Some(mut rx) = self.input_rx.lock().expect("input poisoned").take() else {
            return;
        };
        let weak = Arc::downgrade(self);
        runtime.spawn(async move {
            while let Some(data) = rx.recv().await {
                let open = weak.upgrade().is_some_and(|inner| {
                    inner.terminal.lock().expect("terminal poisoned").is_some()
                });
                if !open || terminal.write(&data).await.is_err() {
                    break;
                }
            }
        });
    }

    fn share(&self) -> Option<Arc<ShareState>> {
        self.share.lock().expect("share poisoned").clone()
    }

    /// The terminal is going away: end its share, if any.
    fn end_share(&self, runtime: &tokio::runtime::Handle) {
        if let Some(share) = self.share.lock().expect("share poisoned").take() {
            share.shutdown(runtime);
        }
    }
}

/// A live terminal. Drop-safe: dropping the last reference closes the
/// connection.
#[derive(uniffi::Object)]
pub struct SshSession {
    id: Uuid,
    inner: Arc<Inner>,
    runtime: tokio::runtime::Handle,
}

/// What a [`Launch`] opens.
pub(crate) enum LaunchTarget {
    /// SSH (or Mosh bootstrapped over it) to a saved or ad-hoc host.
    Ssh {
        target: SshTarget,
        resolved: Option<Box<ResolvedHost>>,
    },
    /// Plain telnet; `host_id`/`label` are set for a saved host.
    Telnet {
        host: String,
        port: u16,
        ip_version: IpVersion,
        host_id: Option<Uuid>,
        vault_id: Option<Uuid>,
        label: String,
        proxy: Option<ProxyConfig>,
    },
    /// A shell on this device.
    Local {
        argv: Vec<String>,
        cwd: Option<std::path::PathBuf>,
        env: Vec<(String, String)>,
    },
    /// A USB-UART console the app drives; bytes arrive through a [`PipeTerminal`].
    Serial {
        label: String,
        device: String,
        terminal: Arc<PipeTerminal>,
        events: TermEvents,
    },
}

pub(crate) struct Launch {
    pub store: Arc<Store>,
    pub secrets: Arc<SecretCache>,
    pub target: LaunchTarget,
    pub settings: MobileSettings,
    pub options: TerminalOptions,
    pub listener: Arc<dyn SessionListener>,
    pub presence: Option<Slot>,
    /// Directory for finished recordings (`<profile>/logs`).
    pub logs_dir: std::path::PathBuf,
    pub account: Option<Arc<crate::account::AccountRuntime>>,
}

/// The `history` row of one connection: opened when the attempt starts,
/// completed with the duration and outcome when it ends.
struct HistoryEntry {
    store: Arc<Store>,
    id: Option<Uuid>,
    row: ConnectionHistory,
    started: Instant,
}

impl HistoryEntry {
    fn start(store: Arc<Store>, row: ConnectionHistory) -> Self {
        let id = store.record_connection(&row).ok();
        Self {
            store,
            id,
            row,
            started: Instant::now(),
        }
    }

    fn finish(&self, error: Option<String>) {
        let Some(id) = self.id else {
            return;
        };
        let _ = self.store.update_connection(
            id,
            &ConnectionHistory {
                duration_secs: Some(self.started.elapsed().as_secs()),
                error,
                ..self.row.clone()
            },
        );
    }
}

pub(crate) struct ViewerLaunch {
    pub store: Arc<Store>,
    pub settings: MobileSettings,
    pub options: TerminalOptions,
    pub listener: Arc<dyn SessionListener>,
    pub joined: ViewerJoin,
    pub live_events: mpsc::Receiver<LiveEvent>,
    pub live_listener: Arc<dyn LiveListener>,
}

impl SshSession {
    pub(crate) fn launch(runtime: tokio::runtime::Handle, launch: Launch) -> Arc<Self> {
        let Launch {
            store,
            secrets,
            target,
            settings,
            options,
            listener,
            presence,
            logs_dir,
            account,
        } = launch;
        let host_id = match &target {
            LaunchTarget::Ssh { resolved, .. } => resolved.as_ref().map(|r| r.host.id),
            LaunchTarget::Telnet { host_id, .. } => *host_id,
            LaunchTarget::Local { .. } | LaunchTarget::Serial { .. } => None,
        };
        let vault_id = match &target {
            LaunchTarget::Ssh { resolved, .. } => resolved.as_ref().map(|r| r.host.vault_id),
            LaunchTarget::Telnet { .. }
            | LaunchTarget::Local { .. }
            | LaunchTarget::Serial { .. } => None,
        };
        let local = match &target {
            LaunchTarget::Local { cwd, env, .. } => {
                let home = env
                    .iter()
                    .find(|(k, _)| k == "HOME")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                let cwd = cwd
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| home.clone());
                Some((cwd, home))
            }
            _ => None,
        };
        let palette = options
            .palette
            .clone()
            .unwrap_or_else(|| crate::themes::palette_for_in(&store, &settings.terminal_theme));
        let (emulator, signals) = Emulator::new(
            options.cols,
            options.rows,
            settings.scrollback_lines,
            palette,
        );
        let state = Arc::new(Mutex::new(SessionState::connecting(
            ConnectStage::Connecting,
            None,
        )));
        let conn = Arc::new(
            Connector::new(
                store.clone(),
                secrets.clone(),
                Arc::new(TerminalUi {
                    listener: listener.clone(),
                    state: state.clone(),
                }),
            )
            .with_account(account.clone()),
        );
        let (input, input_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            store,
            listener,
            conn,
            emulator: Mutex::new(emulator),
            terminal: Mutex::new(None),
            size: Mutex::new(TermSize {
                cols: options.cols.max(2),
                rows: options.rows.max(1),
            }),
            input,
            input_rx: Mutex::new(Some(input_rx)),
            state,
            closed: tokio::sync::Notify::new(),
            title: Mutex::new(None),
            share: Mutex::new(None),
            view: None,
            presence,
            host_id,
            vault_id,
            local,
            typed: Mutex::new(None),
            completer: Completer::new(),
            ssh: Mutex::new(None),
            recorder: Mutex::new(None),
            logs_dir,
            account,
        });
        let session = Arc::new(Self {
            id: Uuid::new_v4(),
            inner: inner.clone(),
            runtime: runtime.clone(),
        });
        let term_type = if options.term_type.trim().is_empty() {
            settings.term_type.clone()
        } else {
            options.term_type.clone()
        };
        match target {
            LaunchTarget::Ssh { target, resolved } => {
                let mosh = match options.transport {
                    Transport::Mosh => true,
                    Transport::Ssh | Transport::Telnet => false,
                    Transport::Auto => resolved.as_ref().is_some_and(|r| r.ssh.use_mosh),
                };
                runtime.spawn(run(
                    inner,
                    target,
                    resolved.map(|r| *r),
                    settings,
                    term_type,
                    mosh,
                    signals,
                ));
            }
            LaunchTarget::Telnet {
                host,
                port,
                ip_version,
                host_id,
                vault_id,
                label,
                proxy,
            } => {
                runtime.spawn(run_telnet(
                    inner,
                    TelnetLaunch {
                        host,
                        port,
                        ip_version,
                        host_id,
                        vault_id,
                        label,
                        term_type,
                        proxy,
                    },
                    settings,
                    signals,
                ));
            }
            LaunchTarget::Local { argv, cwd, env } => {
                runtime.spawn(run_local(
                    inner, argv, cwd, env, term_type, settings, signals,
                ));
            }
            LaunchTarget::Serial {
                label,
                device,
                terminal,
                events,
            } => {
                runtime.spawn(run_serial(
                    inner, label, device, terminal, events, settings, signals,
                ));
            }
        }
        session
    }

    /// A terminal that mirrors a share somebody else is hosting. The grid
    /// follows the host's geometry; input is silently dropped until the host
    /// grants control (see [`LiveListener::on_control`]).
    pub(crate) fn launch_viewer(
        runtime: tokio::runtime::Handle,
        launch: ViewerLaunch,
    ) -> Arc<Self> {
        let ViewerLaunch {
            store,
            settings,
            options,
            listener,
            joined,
            live_events,
            live_listener,
        } = launch;
        let ViewerJoin {
            term,
            events,
            user_id,
            participants,
        } = joined;
        let palette = options
            .palette
            .clone()
            .unwrap_or_else(|| crate::themes::palette_for_in(&store, &settings.terminal_theme));
        let (emulator, signals) = Emulator::new(
            options.cols,
            options.rows,
            settings.scrollback_lines,
            palette,
        );
        let state = Arc::new(Mutex::new(SessionState::Connected));
        let conn = Arc::new(Connector::new(
            store.clone(),
            Arc::new(SecretCache::default()),
            Arc::new(TerminalUi {
                listener: listener.clone(),
                state: state.clone(),
            }),
        ));
        let view = Arc::new(ViewState {
            me: user_id,
            participants: Mutex::new(participants),
            can_write: AtomicBool::new(false),
        });
        let (input, input_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            store,
            listener: listener.clone(),
            conn,
            emulator: Mutex::new(emulator),
            terminal: Mutex::new(Some(term.clone())),
            size: Mutex::new(TermSize {
                cols: options.cols.max(2),
                rows: options.rows.max(1),
            }),
            input,
            input_rx: Mutex::new(Some(input_rx)),
            state,
            closed: tokio::sync::Notify::new(),
            title: Mutex::new(None),
            share: Mutex::new(None),
            view: Some(view.clone()),
            presence: None,
            host_id: None,
            vault_id: None,
            local: None,
            typed: Mutex::new(None),
            completer: Completer::new(),
            ssh: Mutex::new(None),
            recorder: Mutex::new(None),
            logs_dir: std::path::PathBuf::new(),
            account: None,
        });
        let session = Arc::new(Self {
            id: Uuid::new_v4(),
            inner: inner.clone(),
            runtime: runtime.clone(),
        });
        inner.start_writer(&runtime, term.clone());
        set_state(&inner, SessionState::Connected);
        live_listener.on_participants(view.cards());
        {
            let resize_inner = inner.clone();
            let resize: Box<dyn Fn(u16, u16) + Send + Sync> = Box::new(move |cols, rows| {
                let cols = cols.max(2);
                let rows = rows.max(1);
                *resize_inner.size.lock().expect("size poisoned") = TermSize { cols, rows };
                resize_inner
                    .emulator
                    .lock()
                    .expect("emulator poisoned")
                    .resize(cols, rows);
                resize_inner.listener.on_render();
            });
            let title_inner = inner.clone();
            let title: Box<dyn Fn(String) + Send + Sync> = Box::new(move |t| {
                let t = (!t.trim().is_empty()).then_some(t);
                *title_inner.title.lock().expect("title poisoned") = t.clone();
                title_inner.listener.on_title(t);
            });
            runtime.spawn(crate::live::forward_viewer(
                live_events,
                view,
                live_listener,
                resize,
                title,
            ));
        }
        runtime.spawn(run_viewer(inner, term, events, signals));
        session
    }

    /// Start sharing this terminal. Fails unless the shell is open.
    pub(crate) async fn share(
        self: &Arc<Self>,
        api: Arc<ApiClient>,
        listener: Arc<dyn LiveListener>,
        label: String,
    ) -> Result<Arc<LiveShare>> {
        if self.inner.view.is_some() {
            return Err(MobileError::invalid(
                "this terminal is already a shared view",
            ));
        }
        if self.inner.share().is_some() {
            return Err(MobileError::invalid("this terminal is already shared"));
        }
        let term = self
            .inner
            .terminal
            .lock()
            .expect("terminal poisoned")
            .clone()
            .ok_or_else(|| MobileError::invalid("connect before sharing"))?;
        let size = *self.inner.size.lock().expect("size poisoned");
        let title = self
            .inner
            .title
            .lock()
            .expect("title poisoned")
            .clone()
            .unwrap_or(label);
        let (tx, rx) = mpsc::channel(64);
        let share = HostShare::start(api, term, size, title, tx).await?;
        let weak = Arc::downgrade(&self.inner);
        let detach: Box<dyn Fn() + Send + Sync> = Box::new(move || {
            if let Some(inner) = weak.upgrade() {
                *inner.share.lock().expect("share poisoned") = None;
            }
        });
        let weak = Arc::downgrade(&self.inner);
        let resize: Box<dyn Fn(u16, u16) + Send + Sync> = Box::new(move |cols, rows| {
            if let Some(inner) = weak.upgrade() {
                apply_grid(&inner, cols, rows);
            }
        });
        let (live, state) =
            LiveShare::attach(self.runtime.clone(), share, rx, listener, detach, resize);
        *self.inner.share.lock().expect("share poisoned") = Some(state);
        Ok(live)
    }

    /// Entries of `dir` as seen by this session, or `None` when it cannot
    /// list (Telnet, Mosh, disconnected, timed out).
    fn list_dir(&self, dir: &str) -> Option<Vec<termoso_core::autocomplete::DirEntry>> {
        if dir.contains('\0') || dir.len() > 4096 {
            return None;
        }
        if let Some((cwd, home)) = &self.inner.local {
            let expanded = match dir.strip_prefix('~') {
                Some(rest) if !home.is_empty() => {
                    format!("{home}/{}", rest.trim_start_matches('/'))
                }
                _ => dir.to_string(),
            };
            return Some(termoso_core::autocomplete::list_local_dir(
                Some(cwd.as_str()).filter(|c| !c.is_empty()),
                &expanded,
            ));
        }
        let client = self.inner.ssh.lock().expect("ssh poisoned").clone()?;
        let cmd = termoso_core::autocomplete::remote_ls_command(None, dir);
        let out = self.runtime.block_on(async move {
            tokio::time::timeout(crate::autocomplete::LIST_TIMEOUT, client.exec(&cmd, None))
                .await
                .ok()?
                .ok()
        })?;
        Some(termoso_core::autocomplete::parse_ls(&out.stdout_str()))
    }
}

/// Follow a grid size decided elsewhere (a controlling viewer): the local
/// emulator and bookkeeping change, nothing is sent back.
fn apply_grid(inner: &Inner, cols: u16, rows: u16) {
    let cols = cols.max(2);
    let rows = rows.max(1);
    *inner.size.lock().expect("size poisoned") = TermSize { cols, rows };
    inner
        .emulator
        .lock()
        .expect("emulator poisoned")
        .resize(cols, rows);
    inner.listener.on_render();
}

impl SshSession {
    /// The authenticated SSH connection behind a plain SSH shell, for side
    /// channels (SFTP over the same login); `None` for Mosh, Telnet, local
    /// and shared views.
    pub(crate) fn ssh_client(&self) -> Option<Arc<SshClient>> {
        self.inner.ssh.lock().expect("ssh poisoned").clone()
    }

    pub(crate) fn saved_host_id(&self) -> Option<Uuid> {
        self.inner.host_id
    }
}

#[uniffi::export]
impl SshSession {
    pub fn id(&self) -> String {
        self.id.to_string()
    }

    pub fn state(&self) -> SessionState {
        self.inner.state.lock().expect("state poisoned").clone()
    }

    /// Current frame.
    pub fn snapshot(&self) -> GridSnapshot {
        self.inner
            .emulator
            .lock()
            .expect("emulator poisoned")
            .snapshot()
    }

    /// Current frame, packed for the FFI (see [`GridFrame`]).
    pub fn frame(&self) -> GridFrame {
        self.snapshot().pack()
    }

    /// Encode a special key for the terminal's current cursor mode and send
    /// it.
    pub fn send_key(&self, key: SpecialKey, mods: KeyMods) {
        let app_cursor = self
            .inner
            .emulator
            .lock()
            .expect("emulator poisoned")
            .mode()
            .contains(alacritty_terminal::term::TermMode::APP_CURSOR);
        match key {
            SpecialKey::Enter if !mods.ctrl && !mods.alt => self.inner.commit_typing(&self.runtime),
            SpecialKey::Enter | SpecialKey::Escape => self.inner.forget_typing(),
            _ => self.inner.mark_typing(),
        }
        self.write(encode_key(key, mods, app_cursor));
    }

    /// Send typed text, applying Ctrl/Alt from the key panel.
    pub fn send_text(&self, text: String, mods: KeyMods) {
        if mods.ctrl {
            // ^C, ^D, ^L… abandon whatever was being typed.
            self.inner.forget_typing();
        } else {
            self.inner.mark_typing();
        }
        self.write(encode_text(&text, mods));
        if !mods.ctrl && text.contains(['\r', '\n']) {
            self.inner.commit_typing(&self.runtime);
        }
    }

    /// What the user has typed at the current prompt, or `None` when there
    /// is nothing to complete (nothing pending, alternate screen, a view).
    pub fn typed_line(&self) -> Option<String> {
        self.inner.typed_line()
    }

    /// Suggestions for the line being typed, best first (see
    /// [`SuggestionItem`]). Sources: the command catalogue, this device's
    /// command history, one-line snippets of the host's vault and, for SSH
    /// and local shells, a listing of the directory the current token
    /// points at (fetched over a side channel, so the interactive shell
    /// never sees it; relative paths resolve against the home directory).
    /// Blocks the calling thread for at most a few seconds while a remote
    /// listing is fetched; call it off the UI thread. Empty when nothing is
    /// being typed.
    pub fn suggestions(&self) -> Vec<SuggestionItem> {
        let Some(line) = self.inner.typed_line() else {
            return Vec::new();
        };
        let (items, path) = Completer::offline(&self.inner.store, self.inner.vault_id, &line);
        let Some(query) = path else {
            return crate::autocomplete::finish(items, None);
        };
        let entries = match self.inner.completer.cached(&query.dir) {
            Some(entries) => Some(entries),
            None => {
                let fetched = self.list_dir(&query.dir);
                if let Some(entries) = &fetched {
                    self.inner.completer.remember(&query.dir, entries.clone());
                }
                fetched
            }
        };
        crate::autocomplete::finish(items, entries.map(|e| (&query, e)))
    }

    /// Visible screen as text (for copy / accessibility).
    pub fn visible_text(&self) -> Vec<String> {
        self.inner
            .emulator
            .lock()
            .expect("emulator poisoned")
            .visible_text()
    }

    /// Send raw bytes to the remote (key presses already encoded).
    pub fn write(&self, data: Vec<u8>) {
        let _ = self.inner.input.send(data);
        if let Some(share) = self.inner.share() {
            share.typing();
        }
    }

    /// Send text as typed; wraps it in bracketed-paste markers when the
    /// application asked for them.
    pub fn paste(&self, text: String) {
        let bracketed = self
            .inner
            .emulator
            .lock()
            .expect("emulator poisoned")
            .mode()
            .contains(alacritty_terminal::term::TermMode::BRACKETED_PASTE);
        let mut data = Vec::with_capacity(text.len() + 12);
        if bracketed {
            data.extend_from_slice(b"\x1b[200~");
        }
        data.extend_from_slice(text.replace("\r\n", "\r").replace('\n', "\r").as_bytes());
        if bracketed {
            data.extend_from_slice(b"\x1b[201~");
        }
        self.inner.mark_typing();
        self.write(data);
    }

    /// Type `command` and run it, as if entered at the prompt.
    pub fn run_command(&self, command: String) {
        let line = command.trim_end_matches(['\r', '\n']).to_string();
        if line.is_empty() {
            return;
        }
        self.paste(line);
        self.send_key(SpecialKey::Enter, KeyMods::default());
    }

    /// `true` when [`SshSession::send_file`] can work: a plain SSH shell
    /// that is connected right now.
    pub fn can_send_files(&self) -> bool {
        self.inner.ssh.lock().expect("ssh poisoned").is_some()
    }

    /// Copy a local file to the remote's temp directory over a side SFTP
    /// channel of this session's connection and type the resulting path at
    /// the prompt (shell-quoted, no newline). `name` is the file name to
    /// use remotely; it is sanitised and made unique. Returns the remote
    /// path. Blocks the calling thread while uploading; `listener` gets
    /// progress.
    /// Commands from the remote shell's history files (bash, zsh, fish), most
    /// recent last, de-duplicated. Opt-in from Settings; nothing is stored —
    /// the panel shows them for the life of the session. Empty for local,
    /// telnet and viewer sessions.
    pub fn import_shell_history(&self, limit: u32) -> Result<Vec<String>> {
        let client = match self.inner.ssh.lock().expect("ssh poisoned").clone() {
            Some(c) => c,
            None => return Ok(Vec::new()),
        };
        let n = limit.clamp(1, 5000);
        let cmd = format!(
            "cat ~/.bash_history ~/.zsh_history ~/.local/share/fish/fish_history 2>/dev/null | tail -n {n}"
        );
        let out = self
            .runtime
            .block_on(async move { client.exec(&cmd, None).await })?;
        let text = String::from_utf8_lossy(&out.stdout);
        let mut seen = std::collections::HashSet::new();
        let mut lines: Vec<String> = Vec::new();
        for raw in text.lines().rev() {
            let line = raw.trim();
            // zsh extended history: ": 1700000000:0;command"; fish: "- cmd: command".
            let line = line
                .strip_prefix(": ")
                .and_then(|l| l.split_once(';').map(|(_, c)| c))
                .or_else(|| line.strip_prefix("- cmd: "))
                .unwrap_or(line)
                .trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("  when:") {
                continue;
            }
            if seen.insert(line.to_string()) {
                lines.push(line.to_string());
            }
        }
        lines.reverse();
        Ok(lines)
    }

    pub fn send_file(
        &self,
        local_path: String,
        name: String,
        listener: Option<Arc<dyn FileDropListener>>,
    ) -> Result<String> {
        let client = self
            .inner
            .ssh
            .lock()
            .expect("ssh poisoned")
            .clone()
            .ok_or_else(|| MobileError::invalid("This terminal cannot receive files"))?;
        let local = std::path::PathBuf::from(&local_path);
        let base = safe_drop_name(&name);
        let remote = self.runtime.block_on(async move {
            let sftp = Sftp::open(&client).await?;
            let mut remote = format!("{REMOTE_DROP_DIR}/{base}");
            let mut n = 1;
            while sftp.exists(&remote).await? {
                n += 1;
                remote = match base.rsplit_once('.') {
                    Some((stem, ext)) if !stem.is_empty() => {
                        format!("{REMOTE_DROP_DIR}/{stem}-{n}.{ext}")
                    }
                    _ => format!("{REMOTE_DROP_DIR}/{base}-{n}"),
                };
            }
            let progress = listener.clone().map(|l| {
                Arc::new(move |p: Progress| l.on_progress(p.done, p.total.unwrap_or(0)))
                    as termoso_core::sftp::ProgressFn
            });
            let opts = TransferOptions {
                progress,
                ..TransferOptions::default()
            };
            let result = sftp.upload(&local, &remote, &opts).await;
            let _ = sftp.close().await;
            result.map(|_| remote).map_err(MobileError::from)
        })?;
        self.paste(format!("'{}' ", remote.replace('\'', "'\\''")));
        Ok(remote)
    }

    /// `true` for a terminal that mirrors somebody else's share.
    pub fn is_view(&self) -> bool {
        self.inner.view.is_some()
    }

    /// Viewer only: whether the host has granted control right now.
    pub fn can_write(&self) -> bool {
        self.inner
            .view
            .as_ref()
            .is_none_or(|v| v.can_write.load(Ordering::Relaxed))
    }

    /// Everyone connected to the share this terminal belongs to (viewer side;
    /// hosts ask their [`LiveShare`]).
    pub fn live_participants(&self) -> Vec<LiveParticipantCard> {
        self.inner
            .view
            .as_ref()
            .map(|v| v.cards())
            .unwrap_or_default()
    }

    /// `true` while this terminal is being shared.
    pub fn is_shared(&self) -> bool {
        self.inner.share().is_some()
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        // The grid belongs to whoever holds control (tmux's `window-size
        // latest`): a view without control and a host with a controlling
        // viewer keep the remote size and only scale it to fit.
        if let Some(v) = &self.inner.view {
            if !v.can_write.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
        } else if self.inner.share().is_some_and(|s| s.pinned()) {
            return;
        }
        let cols = cols.max(2);
        let rows = rows.max(1);
        *self.inner.size.lock().expect("size poisoned") = TermSize { cols, rows };
        if let Some(share) = self.inner.share() {
            share.resized(TermSize { cols, rows });
        }
        self.inner
            .emulator
            .lock()
            .expect("emulator poisoned")
            .resize(cols, rows);
        let term = self
            .inner
            .terminal
            .lock()
            .expect("terminal poisoned")
            .clone();
        if let Some(t) = term {
            self.runtime.spawn(async move {
                let _ = t.resize(TermSize { cols, rows }).await;
            });
        }
        self.inner.listener.on_render();
    }

    /// Scroll the view: positive = towards history, negative = towards live.
    pub fn scroll(&self, lines: i32) {
        self.inner
            .emulator
            .lock()
            .expect("emulator poisoned")
            .scroll(lines);
        self.inner.listener.on_render();
    }

    pub fn scroll_to_bottom(&self) {
        self.inner
            .emulator
            .lock()
            .expect("emulator poisoned")
            .scroll_to_bottom();
        self.inner.listener.on_render();
    }

    /// Scroll so that scrollback-absolute `line` (from [`SshSession::search`])
    /// is at the top of the screen.
    pub fn scroll_to_line(&self, line: i64) {
        self.inner
            .emulator
            .lock()
            .expect("emulator poisoned")
            .scroll_to_line(line);
        self.inner.listener.on_render();
    }

    /// Case-insensitive search through scrollback and screen, oldest first,
    /// at most 2000 hits.
    pub fn search(&self, query: String) -> Vec<SearchHit> {
        self.inner
            .emulator
            .lock()
            .expect("emulator poisoned")
            .search(&query, 2000)
    }

    /// Text between two scrollback-absolute cells (see
    /// [`SshSession::search`] for the line numbering), for copying a
    /// selection that spans more than the visible screen.
    pub fn text_range(
        &self,
        start_line: i64,
        start_col: u32,
        end_line: i64,
        end_col: u32,
    ) -> String {
        self.inner
            .emulator
            .lock()
            .expect("emulator poisoned")
            .text_range(start_line, start_col, end_line, end_col)
    }

    /// Scrollback and screen as plain text (last `max_lines` lines), to carry
    /// over into a reconnected session with [`SshSession::preload`].
    pub fn dump_text(&self, max_lines: u32) -> String {
        self.inner
            .emulator
            .lock()
            .expect("emulator poisoned")
            .dump_text(max_lines as usize)
    }

    /// Write text straight into the emulator (not to the remote): the previous
    /// session's screen, shown above the fresh shell after a reconnect.
    pub fn preload(&self, text: String) {
        if text.is_empty() {
            return;
        }
        self.inner
            .emulator
            .lock()
            .expect("emulator poisoned")
            .feed(text.as_bytes());
        self.inner.listener.on_render();
    }

    pub fn set_palette(&self, palette: TerminalPalette) {
        self.inner
            .emulator
            .lock()
            .expect("emulator poisoned")
            .set_palette(palette);
        self.inner.listener.on_render();
    }

    /// Reply to a prompt. Returns `false` if the prompt is no longer waiting.
    pub fn answer(&self, prompt_id: u64, answer: PromptAnswer) -> bool {
        self.inner.conn.answer(prompt_id, answer)
    }

    /// Tear the connection down; the object stays usable for `state()`/`snapshot()`.
    pub fn disconnect(&self) {
        self.inner.conn.cancel_prompts();
        self.inner.closed.notify_waiters();
        self.inner.closed.notify_one();
        self.inner.end_share(&self.runtime);
        let term = self
            .inner
            .terminal
            .lock()
            .expect("terminal poisoned")
            .take();
        if let Some(t) = term {
            self.runtime.spawn(async move {
                let _ = t.close().await;
            });
        }
    }
}

impl Drop for SshSession {
    fn drop(&mut self) {
        self.disconnect();
    }
}

fn set_state(inner: &Inner, state: SessionState) {
    if let Some(p) = &inner.presence {
        match state {
            SessionState::Connected => p.connected(),
            SessionState::Connecting { .. }
            | SessionState::Closed { .. }
            | SessionState::Failed { .. } => p.gone(),
        }
    }
    *inner.state.lock().expect("state poisoned") = state.clone();
    inner.listener.on_state(state);
}

async fn run(
    inner: Arc<Inner>,
    target: SshTarget,
    resolved: Option<ResolvedHost>,
    settings: MobileSettings,
    term_type: String,
    mosh: bool,
    signals: mpsc::UnboundedReceiver<TermSignal>,
) {
    let protocol = if mosh { "mosh" } else { "ssh" };
    let row = ConnectionHistory {
        host_id: resolved.as_ref().map(|r| r.host.id),
        label: resolved
            .as_ref()
            .map(|r| r.host.data.label.clone())
            .unwrap_or_else(|| target.host.clone()),
        target: target.display(),
        protocol: protocol.into(),
        duration_secs: None,
        error: None,
    };
    let vault_id = resolved.as_ref().map(|r| r.host.vault_id);
    let history = HistoryEntry::start(inner.store.clone(), row.clone());
    let finish = |error: Option<String>| history.finish(error);
    let fail = |inner: &Inner, e: MobileError| {
        finish(Some(e.to_string()));
        set_state(
            inner,
            SessionState::Failed {
                kind: e.kind(),
                message: e.to_string(),
            },
        );
    };

    // Jump hosts and proxies carry TCP only; the UDP leg needs a direct route.
    if mosh && let Some(r) = resolved.as_ref() {
        let blocker = if !r.chain.is_empty() {
            Some("jump hosts")
        } else if r.proxy.is_some() {
            Some("proxy")
        } else {
            None
        };
        if let Some(what) = blocker {
            fail(
                &inner,
                MobileError::from(termoso_core::error::CoreError::from(
                    MoshError::NoDirectPath(what),
                )),
            );
            return;
        }
    }

    let connect = connect_resolved(&inner.conn, &settings, target.clone(), resolved.as_ref());
    let (client, jumps) = tokio::select! {
        r = connect => match r {
            Ok(c) => c,
            Err(e) => {
                let e = inner.conn.map_error(e);
                finish(Some(e.to_string()));
                set_state(&inner, SessionState::Failed { kind: e.kind(), message: e.to_string() });
                return;
            }
        },
        _ = inner.closed.notified() => {
            finish(Some("cancelled".into()));
            set_state(&inner, SessionState::Closed { reason: None });
            return;
        }
    };

    let detect_os = settings.detect_os
        && resolved
            .as_ref()
            .is_none_or(|r| r.host.data.os_name.is_none());
    let host_id = resolved.as_ref().map(|r| r.host.id);

    let (terminal, events, ssh) = if mosh {
        // The SSH leg is closed once mosh-server is up, so probe the OS while
        // it is still there.
        let opened = tokio::select! {
            r = async {
                let open = open_mosh(&inner, &client, &target, resolved.as_ref());
                if detect_os {
                    tokio::join!(open, detect_os_and_save(&inner, &client, host_id)).0
                } else {
                    open.await
                }
            } => r,
            _ = inner.closed.notified() => Err(MobileError::Cancelled),
        };
        let _ = client.disconnect().await;
        for jump in jumps.into_iter().rev() {
            let _ = jump.disconnect().await;
        }
        match opened {
            Ok((t, e)) => (t, e, None),
            Err(MobileError::Cancelled) => {
                finish(Some("cancelled".into()));
                set_state(&inner, SessionState::Closed { reason: None });
                return;
            }
            Err(e) => {
                fail(&inner, e);
                return;
            }
        }
    } else {
        set_state(
            &inner,
            SessionState::connecting(ConnectStage::OpeningShell, None),
        );
        let size = *inner.size.lock().expect("size poisoned");
        match client.shell(&term_type, size).await {
            Ok((t, e)) => (t as SharedTerminal, e, Some(client)),
            Err(e) => {
                fail(&inner, MobileError::from(e));
                return;
            }
        }
    };
    *inner.terminal.lock().expect("terminal poisoned") = Some(terminal.clone());
    *inner.ssh.lock().expect("ssh poisoned") = ssh.clone();
    inner.start_writer(&tokio::runtime::Handle::current(), terminal.clone());
    inner.start_recording(&settings, vault_id, log_meta(&row, &inner));
    set_state(&inner, SessionState::Connected);
    if let Some(script) = crate::snippets::startup_script(
        &inner.store,
        resolved
            .as_ref()
            .and_then(|r| r.host.data.startup_snippet_id),
    ) {
        let terminal = terminal.clone();
        tokio::spawn(async move {
            tokio::time::sleep(STARTUP_SNIPPET_DELAY).await;
            let _ = terminal.write(script.as_bytes()).await;
        });
    }

    if detect_os && let Some(client) = &ssh {
        let (inner, client) = (inner.clone(), client.clone());
        tokio::spawn(async move { detect_os_and_save(&inner, &client, host_id).await });
    }

    let reason = pump(&inner, &terminal, events, signals).await;
    finish(reason.clone());
    *inner.terminal.lock().expect("terminal poisoned") = None;
    inner.ssh.lock().expect("ssh poisoned").take();
    inner.end_share(&tokio::runtime::Handle::current());
    if let Some(client) = ssh {
        let _ = client.disconnect().await;
    }
    inner.finish_recording();
    set_state(&inner, SessionState::Closed { reason });
}

/// Recording metadata for the connection `row`, sized to the current view.
fn log_meta(row: &ConnectionHistory, inner: &Inner) -> LogMeta {
    let size = *inner.size.lock().expect("size poisoned");
    LogMeta {
        host_id: row.host_id,
        label: row.label.clone(),
        target: row.target.clone(),
        protocol: row.protocol.clone(),
        started_at: chrono::Utc::now(),
        ended_at: None,
        cols: size.cols,
        rows: size.rows,
    }
}

/// Open a terminal that needs no SSH leg (telnet, local shell): record it,
/// open it, pump it. `open` runs against the current view size.
async fn run_direct<F, Fut>(
    inner: Arc<Inner>,
    row: ConnectionHistory,
    recording: Option<(MobileSettings, Option<Uuid>)>,
    stage: ConnectStage,
    open: F,
    signals: mpsc::UnboundedReceiver<TermSignal>,
) where
    F: FnOnce(TermSize) -> Fut,
    Fut: std::future::Future<Output = Result<(SharedTerminal, TermEvents)>>,
{
    let history = HistoryEntry::start(inner.store.clone(), row.clone());
    set_state(&inner, SessionState::connecting(stage, None));
    let size = *inner.size.lock().expect("size poisoned");
    let opened = tokio::select! {
        r = open(size) => r,
        _ = inner.closed.notified() => Err(MobileError::Cancelled),
    };
    let (terminal, events) = match opened {
        Ok(t) => t,
        Err(MobileError::Cancelled) => {
            history.finish(Some("cancelled".into()));
            set_state(&inner, SessionState::Closed { reason: None });
            return;
        }
        Err(e) => {
            history.finish(Some(e.to_string()));
            set_state(
                &inner,
                SessionState::Failed {
                    kind: e.kind(),
                    message: e.to_string(),
                },
            );
            return;
        }
    };
    *inner.terminal.lock().expect("terminal poisoned") = Some(terminal.clone());
    inner.start_writer(&tokio::runtime::Handle::current(), terminal.clone());
    if let Some((settings, vault_id)) = &recording {
        inner.start_recording(settings, *vault_id, log_meta(&row, &inner));
    }
    set_state(&inner, SessionState::Connected);

    let reason = pump(&inner, &terminal, events, signals).await;
    history.finish(reason.clone());
    *inner.terminal.lock().expect("terminal poisoned") = None;
    inner.end_share(&tokio::runtime::Handle::current());
    let _ = terminal.close().await;
    inner.finish_recording();
    set_state(&inner, SessionState::Closed { reason });
}

struct TelnetLaunch {
    host: String,
    port: u16,
    ip_version: IpVersion,
    host_id: Option<Uuid>,
    vault_id: Option<Uuid>,
    label: String,
    term_type: String,
    proxy: Option<ProxyConfig>,
}

async fn run_telnet(
    inner: Arc<Inner>,
    launch: TelnetLaunch,
    settings: MobileSettings,
    signals: mpsc::UnboundedReceiver<TermSignal>,
) {
    let TelnetLaunch {
        host,
        port,
        ip_version,
        host_id,
        vault_id,
        label,
        term_type,
        proxy,
    } = launch;
    let row = ConnectionHistory {
        host_id,
        label: if label.trim().is_empty() {
            host.clone()
        } else {
            label
        },
        target: format!("{host}:{port}"),
        protocol: "telnet".into(),
        duration_secs: None,
        error: None,
    };
    let stage = ConnectStage::ConnectingTo {
        target: format!("{host}:{port}"),
    };
    run_direct(
        inner,
        row,
        Some((settings, vault_id)),
        stage,
        |size| async move {
            let (term, events) = TelnetTerminal::connect(TelnetOptions {
                host,
                port,
                term: term_type,
                size,
                timeout: TELNET_TIMEOUT,
                ip_version,
                proxy,
            })
            .await?;
            Ok((term as SharedTerminal, events))
        },
        signals,
    )
    .await;
}

/// The adapter is already open on the Kotlin side, so "connecting" is
/// immediate; the session lives until the device goes away or is closed.
async fn run_serial(
    inner: Arc<Inner>,
    label: String,
    device: String,
    terminal: Arc<PipeTerminal>,
    events: TermEvents,
    settings: MobileSettings,
    signals: mpsc::UnboundedReceiver<TermSignal>,
) {
    let row = ConnectionHistory {
        host_id: None,
        label: if label.trim().is_empty() {
            device.clone()
        } else {
            label
        },
        target: device.clone(),
        protocol: "serial".into(),
        duration_secs: None,
        error: None,
    };
    let stage = ConnectStage::ConnectingTo { target: device };
    run_direct(
        inner,
        row,
        Some((settings, None)),
        stage,
        |_size| async move { Ok((terminal as SharedTerminal, events)) },
        signals,
    )
    .await;
}

async fn run_local(
    inner: Arc<Inner>,
    argv: Vec<String>,
    cwd: Option<std::path::PathBuf>,
    mut env: Vec<(String, String)>,
    term_type: String,
    settings: MobileSettings,
    signals: mpsc::UnboundedReceiver<TermSignal>,
) {
    let row = ConnectionHistory {
        host_id: None,
        label: "Local".into(),
        target: argv
            .first()
            .cloned()
            .unwrap_or_else(|| "local shell".into()),
        protocol: "local".into(),
        duration_secs: None,
        error: None,
    };
    env.push(("TERM".into(), term_type));
    // A local shell is recorded only on the user's own say-so.
    let recording = settings.record_sessions.then_some((settings, None));
    run_direct(
        inner,
        row,
        recording,
        ConnectStage::StartingShell,
        |size| async move {
            let (term, events) = LocalTerminal::spawn(LocalShellOptions {
                argv,
                cwd,
                env,
                size,
            })?;
            Ok((term as SharedTerminal, events))
        },
        signals,
    )
    .await;
}

/// Start `mosh-server` over the authenticated `client` and open the UDP
/// session to it. The caller closes the SSH leg either way.
async fn open_mosh(
    inner: &Arc<Inner>,
    client: &Arc<SshClient>,
    target: &SshTarget,
    resolved: Option<&ResolvedHost>,
) -> Result<(SharedTerminal, TermEvents)> {
    set_state(
        inner,
        SessionState::connecting(ConnectStage::MoshServer, None),
    );
    let command = resolved.and_then(|r| r.ssh.mosh_server_command.as_deref());
    let boot = mosh::start_server(client, command).await?;
    let ip_version = resolved
        .map(|r| IpVersion::parse(&r.host.data.ip_version))
        .unwrap_or_default();
    let ip = mosh::udp_target(&target.host, ip_version, &boot).await?;
    set_state(
        inner,
        SessionState::connecting(ConnectStage::MoshWaiting { port: boot.port }, None),
    );
    let size = *inner.size.lock().expect("size poisoned");
    let (term, events) = mosh::connect(&ip, &boot, size).await?;
    Ok((term as SharedTerminal, events))
}

/// Detect the remote OS on a side channel and remember it on the host.
async fn detect_os_and_save(inner: &Inner, client: &SshClient, host_id: Option<Uuid>) {
    let Some(os) = termoso_core::osdetect::detect(client).await else {
        return;
    };
    let saved = (|| -> termoso_core::error::Result<()> {
        let Some(host_id) = host_id else {
            return Ok(());
        };
        let mut host = inner.store.require::<termoso_core::model::Host>(host_id)?;
        if host.data.os_name.is_some() {
            return Ok(());
        }
        host.data.os_name = Some(os.to_string());
        inner.store.update(host.id, &host.data)
    })();
    if saved.is_ok() {
        inner.listener.on_os_detected(os.to_string());
    }
}

/// Viewer counterpart of [`run`]: the relay stream is already open, so just
/// pump it until the host stops or the tab closes.
async fn run_viewer(
    inner: Arc<Inner>,
    terminal: SharedTerminal,
    events: TermEvents,
    signals: mpsc::UnboundedReceiver<TermSignal>,
) {
    let reason = pump(&inner, &terminal, events, signals).await;
    *inner.terminal.lock().expect("terminal poisoned") = None;
    let _ = terminal.close().await;
    set_state(&inner, SessionState::Closed { reason });
}

/// Feed remote output into the emulator and route emulator signals back.
/// Returns the close reason (`None` = clean exit).
async fn pump(
    inner: &Arc<Inner>,
    terminal: &SharedTerminal,
    mut events: TermEvents,
    mut signals: mpsc::UnboundedReceiver<TermSignal>,
) -> Option<String> {
    let recorder = inner.recorder();
    loop {
        tokio::select! {
            ev = events.recv() => {
                let ev = ev?;
                let mut batch = vec![ev];
                while let Ok(more) = events.try_recv() {
                    batch.push(more);
                    if batch.len() >= 64 {
                        break;
                    }
                }
                let mut dirty = false;
                let share = inner.share();
                for ev in batch {
                    match ev {
                        TermEvent::Output(bytes) => {
                            if let Some(share) = &share {
                                share.publisher.publish(Bytes::copy_from_slice(&bytes));
                            }
                            if let Some(rec) = &recorder {
                                rec.append(&bytes);
                            }
                            inner.emulator.lock().expect("emulator poisoned").feed(&bytes);
                            dirty = true;
                        }
                        TermEvent::Notice(text) => {
                            let line = format!("\r\n\x1b[2m{text}\x1b[0m\r\n");
                            inner.emulator.lock().expect("emulator poisoned").feed(line.as_bytes());
                            dirty = true;
                        }
                        TermEvent::Error(text) => {
                            if dirty {
                                inner.listener.on_render();
                            }
                            return Some(text);
                        }
                        TermEvent::Exit { code, signal } => {
                            if dirty {
                                inner.listener.on_render();
                            }
                            return match (code, signal) {
                                (Some(0), _) | (None, None) => None,
                                (Some(c), _) => Some(format!("exit status {c}")),
                                (None, Some(s)) => Some(format!("signal {s}")),
                            };
                        }
                        TermEvent::Closed => {
                            if dirty {
                                inner.listener.on_render();
                            }
                            return None;
                        }
                    }
                }
                if dirty {
                    inner.listener.on_render();
                }
            }
            sig = signals.recv() => {
                match sig {
                    Some(TermSignal::PtyWrite(bytes)) => {
                        let _ = terminal.write(&bytes).await;
                    }
                    Some(TermSignal::Title(t)) => {
                        *inner.title.lock().expect("title poisoned") = t.clone();
                        if let (Some(share), Some(t)) = (inner.share(), &t) {
                            share.retitled(t.clone());
                        }
                        inner.listener.on_title(t);
                    }
                    Some(TermSignal::Bell) => inner.listener.on_bell(),
                    Some(TermSignal::Clipboard(text)) => inner.listener.on_clipboard(text),
                    None => {}
                }
            }
            _ = inner.closed.notified() => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_filter_matches_desktop() {
        for c in [
            "mysql -u root -pS3cret db",
            "export API_TOKEN=abc",
            "curl -u bob:hunter2 https://x",
            "sshpass -p hunter2 ssh host",
            "echo hunter2 | sudo passwd bob",
            "PASSWORD=x ./run",
            "curl -H 'Authorization: Bearer abc' x",
            "docker login --password=hunter2",
        ] {
            assert!(looks_like_secret(c), "{c}");
        }
        for c in [
            "ls -la",
            "cat /etc/passwd",
            "ssh-keygen -t ed25519",
            "mysql -u root -p db",
            "export PATH=/usr/bin",
            "git push --force",
            "grep token= config.example",
        ] {
            assert!(!looks_like_secret(c), "{c}");
        }
    }

    #[test]
    fn drop_names_are_shell_safe() {
        assert_eq!(safe_drop_name("photo.jpg"), "photo.jpg");
        assert_eq!(safe_drop_name("../a/b c'$x.txt"), "_a_b_c__x.txt");
        assert_eq!(safe_drop_name("--rf"), "rf");
        assert!(safe_drop_name("").starts_with("termoso-"));
        let long = safe_drop_name(&format!("{}.tar.gz", "x".repeat(300)));
        assert!(long.chars().count() <= 111 && long.ends_with(".gz"));
    }
}
