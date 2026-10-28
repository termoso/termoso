//! Live terminal sessions: connect (SSH / telnet / local shell), pump output
//! into an IPC channel, accept input, resize, close.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Emitter, Manager, Runtime};
use termoso_core::error::CoreError;
use termoso_core::fido2::{self, Fido2Error};
use termoso_core::hostkey::KnownHosts;
use termoso_core::live::Publisher;
use termoso_core::model::{Entity, Identity, ResolvedHost, Snippet, SshConfig};
use termoso_core::pty::{LocalShellOptions, LocalTerminal};
use termoso_core::serial::SerialTerminal;
use termoso_core::ssh::proxy::{ProxyConfig, ProxyKind};
use termoso_core::ssh::{
    Algorithms, AuthMethod, ConnectOptions, ConnectPhase, ConnectProgress, IpVersion, LocalDisplay,
    SshClient, SshTarget, X11Forward,
};
use termoso_core::store::{ConnectionHistory, LocalVaultKind, LogMeta};
use termoso_core::telnet::{TelnetOptions, TelnetTerminal};
use termoso_core::terminal::{SharedTerminal, TermEvent, TermEvents, TermSize};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{DesktopError, Result};
use crate::hosts::SerialLine;
use crate::logs::Recorder;
use crate::prompts::{PromptAnswer, PromptRequest, UiHostKeyPrompt, UiInteractivePrompt};
use crate::snippets;
use crate::sshid;
use crate::state::AppState;
use termoso_core::ssh::totp::TotpResponder;

pub const SESSION_EVENT: &str = "session";
const MAX_PASSWORD_ATTEMPTS: usize = 3;

/// Split the `localShell` setting into argv: a program path plus optional
/// arguments (`wsl.exe -d Ubuntu`); empty = platform default. A bare path
/// that exists on disk is taken whole, so `C:\Program Files\...\pwsh.exe`
/// picked from the list works without quoting; otherwise double quotes group
/// words and `\"` escapes a quote.
pub fn local_shell_argv(setting: &str) -> Vec<String> {
    let setting = setting.trim();
    if setting.is_empty() {
        return Vec::new();
    }
    if std::path::Path::new(setting).is_file() {
        return vec![setting.to_string()];
    }
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut has_token = false;
    let mut chars = setting.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                has_token = true;
            }
            '\\' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            c if c.is_whitespace() && !quoted => {
                if has_token {
                    out.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            c => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        out.push(cur);
    }
    out
}

/// Shells available for local terminals, login shell first.
pub fn local_shells() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: String| {
        if !s.is_empty() && !out.contains(&s) {
            out.push(s);
        }
    };
    if cfg!(windows) {
        for name in ["pwsh.exe", "powershell.exe", "cmd.exe"] {
            if which(name) {
                push(name.to_string());
            }
        }
        if let Ok(comspec) = std::env::var("COMSPEC") {
            push(comspec);
        }
        for distro in wsl_distros() {
            push(format!("wsl.exe -d {distro}"));
        }
    } else {
        if let Ok(shell) = std::env::var("SHELL") {
            push(shell);
        }
        if let Ok(list) = std::fs::read_to_string("/etc/shells") {
            for line in list.lines() {
                let path = line.trim();
                if !path.is_empty()
                    && !path.starts_with('#')
                    && std::path::Path::new(path).is_file()
                {
                    push(path.to_string());
                }
            }
        }
    }
    out
}

fn which(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
        .unwrap_or(false)
}

/// Installed WSL distributions (`wsl.exe -l -q`, UTF-16LE output); empty when
/// WSL is absent.
fn wsl_distros() -> Vec<String> {
    if !cfg!(windows) {
        return Vec::new();
    }
    let mut cmd = std::process::Command::new("wsl.exe");
    cmd.args(["-l", "-q"]);
    hide_console_window(&mut cmd);
    let Ok(output) = cmd.output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let units: Vec<u16> = output
        .stdout
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
        .lines()
        .map(|l| l.trim_matches(['\r', '\0', ' ']).to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Child processes of a GUI app get their own console on Windows unless
/// told otherwise, which shows up as a `cmd` window blinking for a frame.
pub(crate) fn hide_console_window(cmd: &mut std::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    {
        let _ = cmd;
    }
}

/// Display name of the shell a local terminal runs.
fn local_shell_name(argv: &[String]) -> Option<String> {
    match argv.first() {
        None => termoso_core::pty::default_shell_name(),
        Some(program) => program
            .rsplit(['/', '\\'])
            .next()
            .map(|n| n.trim_end_matches(".exe"))
            .filter(|n| !n.is_empty())
            .map(str::to_string),
    }
}

/// What the UI asked to open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OpenTarget {
    /// A saved host; `protocol` picks one of its sections (`ssh` / `telnet`),
    /// default SSH when the host has it. `vault_id` is the vault the caller
    /// took the host from: the open is refused if the host lives elsewhere,
    /// so a stale or foreign id never reaches another vault's credentials.
    Host {
        host_id: Uuid,
        #[serde(default)]
        vault_id: Option<Uuid>,
        #[serde(default)]
        protocol: Option<String>,
    },
    /// A local serial console (not a saved host).
    Serial { path: String, line: SerialLine },
    /// Ad-hoc `user@host:port` typed into the quick-connect bar.
    Quick {
        address: String,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        port: Option<u16>,
        /// `ssh` (default) or `telnet`.
        #[serde(default)]
        protocol: Option<String>,
    },
    /// Shell on this machine.
    Local,
    /// Someone else's terminal, via a multiplayer link.
    Live { link: String },
}

/// Public view of a session.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: Uuid,
    /// `ssh` | `telnet` | `serial` | `local`.
    pub protocol: String,
    pub title: String,
    /// `user@host:port` or the local shell.
    pub target: String,
    pub host_id: Option<Uuid>,
    pub started_at: DateTime<Utc>,
    pub state: SessionState,
    /// Negotiated SSH algorithms (`None` for local / telnet / still connecting).
    pub algorithms: Option<Algorithms>,
    /// Jump hosts the connection went through, outermost first (`user@host:port`).
    pub via: Vec<String>,
    /// Colour scheme configured on the host (or inherited from its groups).
    pub color_scheme: Option<String>,
    /// Base name of the user's shell (`bash`, `zsh`, `fish`, …) when known.
    /// Local shells know it at once; SSH sessions learn it from a probe and
    /// report it through [`SessionEvent::Shell`].
    pub shell: Option<String>,
    /// The host's shell integration override (`None` follows the setting).
    pub shell_integration: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Connecting,
    Connected,
}

/// Something happened to a session; emitted as the `session` event.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    Connecting {
        id: Uuid,
        info: SessionInfo,
    },
    Connected {
        id: Uuid,
        info: SessionInfo,
    },
    /// Where the connection attempt is. `hop` names the jump host being
    /// dialled when the stage belongs to one of the intermediate hops.
    Progress {
        id: Uuid,
        hop: Option<String>,
        phase: ConnectPhase,
    },
    Notice {
        id: Uuid,
        message: String,
    },
    /// The remote login shell was identified (see `SessionInfo::shell`).
    Shell {
        id: Uuid,
        shell: String,
    },
    Exit {
        id: Uuid,
        code: Option<u32>,
        signal: Option<String>,
    },
    Error {
        id: Uuid,
        message: String,
    },
    Closed {
        id: Uuid,
    },
    /// The remote started `sz` (receive) or `rz` (send); the UI picks files / a folder.
    Zmodem {
        id: Uuid,
        kind: crate::zmodem::Kind,
    },
    ZmodemProgress {
        id: Uuid,
        kind: crate::zmodem::Kind,
        name: String,
        done: u64,
        total: Option<u64>,
        files: u32,
    },
    ZmodemDone {
        id: Uuid,
        ok: bool,
        files: u32,
        error: Option<String>,
    },
}

struct Live {
    info: SessionInfo,
    term: SharedTerminal,
    /// SSH transport; SFTP and forwarding share it.
    client: Option<Arc<SshClient>>,
    /// Jump hosts, outermost first. Dropped with the session.
    #[allow(dead_code)]
    jumps: Vec<Arc<SshClient>>,
    output: Arc<Mutex<Channel<InvokeResponseBody>>>,
    /// Multiplayer mirror of the output stream while the tab is shared.
    tap: Arc<Mutex<Option<Publisher>>>,
    /// Last size the UI asked for.
    size: Mutex<TermSize>,
    pump: JoinHandle<()>,
    cancel: CancellationToken,
    history_id: Option<Uuid>,
    recorder: Option<Arc<Recorder>>,
    /// ZMODEM detector / running transfer on this session's byte stream.
    zmodem: Arc<crate::zmodem::Slot>,
}

/// Registry of sessions. Connection attempts are registered up-front so the UI
/// can cancel them and prompts can be routed.
#[derive(Default)]
pub struct Sessions {
    live: Mutex<HashMap<Uuid, Live>>,
    pending: Mutex<HashMap<Uuid, CancellationToken>>,
}

impl Sessions {
    pub fn list(&self) -> Vec<SessionInfo> {
        let mut v: Vec<SessionInfo> = self
            .live
            .lock()
            .expect("sessions poisoned")
            .values()
            .map(|l| l.info.clone())
            .collect();
        v.sort_by_key(|s| s.started_at);
        v
    }

    pub fn info(&self, id: Uuid) -> Result<SessionInfo> {
        self.live
            .lock()
            .expect("sessions poisoned")
            .get(&id)
            .map(|l| l.info.clone())
            .ok_or_else(|| DesktopError::not_found(format!("session {id}")))
    }

    pub fn zmodem(&self, id: Uuid) -> Result<Arc<crate::zmodem::Slot>> {
        self.live
            .lock()
            .expect("sessions poisoned")
            .get(&id)
            .map(|l| l.zmodem.clone())
            .ok_or_else(|| DesktopError::not_found(format!("session {id}")))
    }

    pub fn terminal(&self, id: Uuid) -> Result<SharedTerminal> {
        self.live
            .lock()
            .expect("sessions poisoned")
            .get(&id)
            .map(|l| l.term.clone())
            .ok_or_else(|| DesktopError::not_found(format!("session {id}")))
    }

    /// SSH transport of a live session (`None` for local / telnet).
    pub fn client(&self, id: Uuid) -> Result<Arc<SshClient>> {
        self.live
            .lock()
            .expect("sessions poisoned")
            .get(&id)
            .ok_or_else(|| DesktopError::not_found(format!("session {id}")))?
            .client
            .clone()
            .ok_or_else(|| DesktopError::invalid("session is not SSH"))
    }

    pub fn attach(&self, id: Uuid, channel: Channel<InvokeResponseBody>) -> Result<()> {
        let live = self.live.lock().expect("sessions poisoned");
        let l = live
            .get(&id)
            .ok_or_else(|| DesktopError::not_found(format!("session {id}")))?;
        *l.output.lock().expect("output poisoned") = channel;
        Ok(())
    }

    /// Start (or stop, with `None`) mirroring the output stream of a session.
    pub fn set_tap(&self, id: Uuid, tap: Option<Publisher>) -> Result<()> {
        let live = self.live.lock().expect("sessions poisoned");
        let l = live
            .get(&id)
            .ok_or_else(|| DesktopError::not_found(format!("session {id}")))?;
        *l.tap.lock().expect("tap poisoned") = tap;
        Ok(())
    }

    /// Remember the size the UI asked for.
    pub fn set_size(&self, id: Uuid, size: TermSize) {
        if let Some(l) = self.live.lock().expect("sessions poisoned").get(&id) {
            *l.size.lock().expect("size poisoned") = size;
        }
    }

    /// Last size the UI asked for.
    pub fn size(&self, id: Uuid) -> Result<TermSize> {
        self.live
            .lock()
            .expect("sessions poisoned")
            .get(&id)
            .map(|l| *l.size.lock().expect("size poisoned"))
            .ok_or_else(|| DesktopError::not_found(format!("session {id}")))
    }

    /// Every live session plus every connection attempt in flight.
    pub fn ids(&self) -> Vec<Uuid> {
        let mut ids: Vec<Uuid> = self
            .live
            .lock()
            .expect("sessions poisoned")
            .keys()
            .copied()
            .collect();
        ids.extend(self.pending.lock().expect("sessions poisoned").keys());
        ids
    }

    /// Cancel a connection attempt or close a live session.
    fn close(&self, id: Uuid) -> Option<Live> {
        if let Some(tok) = self.pending.lock().expect("sessions poisoned").remove(&id) {
            tok.cancel();
        }
        self.live.lock().expect("sessions poisoned").remove(&id)
    }

    fn begin(&self, id: Uuid) -> Result<CancellationToken> {
        if self
            .live
            .lock()
            .expect("sessions poisoned")
            .contains_key(&id)
        {
            return Err(DesktopError::invalid(format!("session {id} already open")));
        }
        let mut pending = self.pending.lock().expect("sessions poisoned");
        if pending.contains_key(&id) {
            return Err(DesktopError::invalid(format!(
                "session {id} already opening"
            )));
        }
        let tok = CancellationToken::new();
        pending.insert(id, tok.clone());
        Ok(tok)
    }

    fn finish_pending(&self, id: Uuid) -> bool {
        self.pending
            .lock()
            .expect("sessions poisoned")
            .remove(&id)
            .is_some()
    }
}

/// Open a session and start streaming its output into `output`. The UI may
/// pick the `id` so it can address the tab before the connection completes.
pub async fn open<R: Runtime>(
    app: AppHandle<R>,
    id: Option<Uuid>,
    target: OpenTarget,
    size: TermSize,
    output: Channel<InvokeResponseBody>,
) -> Result<SessionInfo> {
    let state = app.state::<AppState>();
    let id = id.unwrap_or_else(Uuid::new_v4);
    let cancel = state.sessions.begin(id)?;

    let result = tokio::select! {
        r = connect(&app, id, &target, size) => r,
        _ = cancel.cancelled() => Err(CoreError::Cancelled.into()),
    };
    state.prompts.cancel_session(id);
    // Cancelled while connecting: whoever cancelled already removed us.
    let still_wanted = state.sessions.finish_pending(id);

    let opened = match result {
        Ok(o) => o,
        Err(e) => {
            if still_wanted && e.kind != "cancelled" {
                let _ = app.emit(
                    SESSION_EVENT,
                    SessionEvent::Error {
                        id,
                        message: e.message.clone(),
                    },
                );
            }
            return Err(e);
        }
    };
    if !still_wanted {
        let _ = opened.term.close().await;
        return Err(CoreError::Cancelled.into());
    }

    let info = SessionInfo {
        id,
        protocol: opened.protocol.into(),
        title: opened.title,
        target: opened.target,
        host_id: opened.host_id,
        started_at: Utc::now(),
        state: SessionState::Connected,
        algorithms: opened.client.as_ref().and_then(|c| c.algorithms().cloned()),
        via: opened.jumps.iter().map(|j| j.target().display()).collect(),
        color_scheme: opened.color_scheme,
        shell: opened.shell,
        shell_integration: opened.shell_integration,
    };
    let viewer = info.protocol == crate::multiplayer::PROTOCOL;
    let history_id = if viewer {
        None
    } else {
        state
            .store()?
            .record_connection(&ConnectionHistory {
                host_id: info.host_id,
                label: info.title.clone(),
                target: info.target.clone(),
                protocol: info.protocol.clone(),
                duration_secs: None,
                error: None,
            })
            .ok()
    };
    let recorder = if viewer {
        None
    } else {
        start_recording(&state, &info, opened.vault_id, size)
    };

    let output = Arc::new(Mutex::new(output));
    let tap: Arc<Mutex<Option<Publisher>>> = Arc::default();
    let zmodem: Arc<crate::zmodem::Slot> = Arc::default();
    let pump = tokio::spawn(pump(
        app.clone(),
        id,
        opened.events,
        output.clone(),
        tap.clone(),
        recorder.clone(),
        zmodem.clone(),
    ));
    let live = Live {
        info: info.clone(),
        term: opened.term.clone(),
        client: opened.client.clone(),
        jumps: opened.jumps,
        output,
        tap,
        size: Mutex::new(size),
        pump,
        cancel,
        history_id,
        recorder,
        zmodem,
    };
    state
        .sessions
        .live
        .lock()
        .expect("sessions poisoned")
        .insert(id, live);
    let _ = app.emit(
        SESSION_EVENT,
        SessionEvent::Connected {
            id,
            info: info.clone(),
        },
    );
    crate::presence::refresh(&app);
    if let Some(client) = opened.client {
        detect_shell_in_background(&app, id, client);
    }
    if !opened.startup.is_empty() {
        let term = opened.term;
        let script = opened.startup;
        tokio::spawn(async move {
            tokio::time::sleep(STARTUP_SNIPPET_DELAY).await;
            if let Err(e) = term.write(script.as_bytes()).await {
                tracing::debug!(session = %id, "startup snippet not delivered: {e}");
            }
        });
    }
    Ok(info)
}

/// Begin capturing output when the user enabled recording. Failures only
/// disable the recording for this session.
fn start_recording(
    state: &AppState,
    info: &SessionInfo,
    vault_id: Option<Uuid>,
    size: TermSize,
) -> Option<Arc<Recorder>> {
    let settings = state.settings().ok()?;
    let vault_id = match vault_id {
        Some(v) => v,
        None => state.store().ok()?.local_vault().ok()?.id,
    };
    // The user's own switch records everything; a team vault whose manager
    // turned session logging on records its hosts' sessions for the team
    // regardless.
    let team_policy = state
        .store()
        .ok()?
        .vault(vault_id)
        .ok()
        .is_some_and(|v| v.kind == LocalVaultKind::Team && v.session_logging);
    if !settings.record_sessions && !team_policy {
        return None;
    }
    let meta = LogMeta {
        host_id: info.host_id,
        label: info.title.clone(),
        target: info.target.clone(),
        protocol: info.protocol.clone(),
        started_at: info.started_at,
        ended_at: None,
        cols: size.cols,
        rows: size.rows,
    };
    match Recorder::begin(&*state.store().ok()?, vault_id, meta) {
        Ok(r) => {
            tracing::debug!(session = %info.id, log = %r.id(), "recording session");
            Some(Arc::new(r))
        }
        Err(e) => {
            tracing::warn!("session recording disabled: {e}");
            None
        }
    }
}

/// Persist a finished recording and let the sync engine upload it right
/// away, so a shared team recording reaches teammates without waiting for
/// the periodic pass.
async fn finish_recording<R: Runtime>(app: &AppHandle<R>, recorder: Option<Arc<Recorder>>) {
    let Some(rec) = recorder else {
        return;
    };
    let state = app.state::<AppState>();
    let Ok(store) = state.store() else {
        tracing::warn!("saving session recording skipped: vault locked");
        return;
    };
    match rec.finish(&store, &state.logs_dir()) {
        Ok(()) => {
            if let Some(engine) = crate::account::engine(app).await {
                engine.request_sync();
            }
        }
        Err(e) => tracing::warn!("saving session recording failed: {e}"),
    }
    if let Ok(settings) = state.settings()
        && let Err(e) = crate::logs::prune(&store, settings.log_retention_days)
    {
        tracing::debug!("log retention sweep failed: {e}");
    }
}

/// Startup snippet of the host, ready to type once the shell is up.
fn startup_script(state: &AppState, resolved: &ResolvedHost) -> String {
    resolved
        .host
        .data
        .startup_snippet_id
        .and_then(|id| state.store().ok()?.require::<Snippet>(id).ok())
        .map(|s| snippets::script_to_send(&s.data.script))
        .unwrap_or_default()
}

/// Close a session (or abort its connection attempt).
pub async fn close<R: Runtime>(app: &AppHandle<R>, id: Uuid) -> Result<()> {
    let state = app.state::<AppState>();
    state.prompts.cancel_session(id);
    state.multiplayer.detach(id);
    if let Some(live) = state.sessions.close(id) {
        live.cancel.cancel();
        let _ = live.term.close().await;
        live.pump.abort();
        if let Some(hid) = live.history_id {
            finish_history(&state, hid, &live.info, None);
        }
        finish_recording(app, live.recorder).await;
        let _ = app.emit(SESSION_EVENT, SessionEvent::Closed { id });
        crate::presence::refresh(app);
    }
    Ok(())
}

/// Close every terminal session and abort every pending connection.
pub async fn close_all<R: Runtime>(app: &AppHandle<R>) {
    let ids = app.state::<AppState>().sessions.ids();
    for id in ids {
        if let Err(e) = close(app, id).await {
            tracing::debug!(session = %id, "close on lock: {e}");
        }
    }
}

fn finish_history(state: &AppState, history_id: Uuid, info: &SessionInfo, error: Option<String>) {
    let duration = Utc::now()
        .signed_duration_since(info.started_at)
        .num_seconds()
        .max(0) as u64;
    let Ok(store) = state.store() else {
        return;
    };
    let _ = store.update_connection(
        history_id,
        &ConnectionHistory {
            host_id: info.host_id,
            label: info.title.clone(),
            target: info.target.clone(),
            protocol: info.protocol.clone(),
            duration_secs: Some(duration),
            error,
        },
    );
}

async fn pump<R: Runtime>(
    app: AppHandle<R>,
    id: Uuid,
    mut events: TermEvents,
    output: Arc<Mutex<Channel<InvokeResponseBody>>>,
    tap: Arc<Mutex<Option<Publisher>>>,
    recorder: Option<Arc<Recorder>>,
    zmodem: Arc<crate::zmodem::Slot>,
) {
    let mut error: Option<String> = None;
    while let Some(ev) = events.recv().await {
        match ev {
            TermEvent::Output(bytes) => {
                let Some(bytes) = crate::zmodem::filter(&app, id, &zmodem, bytes) else {
                    continue;
                };
                if bytes.is_empty() {
                    continue;
                }
                if let Some(rec) = &recorder {
                    rec.append(&bytes);
                }
                if let Some(p) = tap.lock().expect("tap poisoned").as_ref() {
                    p.publish(bytes.clone());
                }
                let ch = output.lock().expect("output poisoned").clone();
                if let Err(e) = ch.send(InvokeResponseBody::Raw(bytes.to_vec())) {
                    tracing::debug!(error = %e, "terminal channel gone");
                }
            }
            TermEvent::Notice(message) => {
                let _ = app.emit(SESSION_EVENT, SessionEvent::Notice { id, message });
            }
            TermEvent::Exit { code, signal } => {
                let _ = app.emit(SESSION_EVENT, SessionEvent::Exit { id, code, signal });
            }
            TermEvent::Error(message) => {
                error = Some(message.clone());
                let _ = app.emit(SESSION_EVENT, SessionEvent::Error { id, message });
            }
            TermEvent::Closed => break,
        }
    }
    zmodem.shutdown();
    let state = app.state::<AppState>();
    state.multiplayer.detach(id);
    if let Some(live) = state.sessions.close(id) {
        if let Some(hid) = live.history_id {
            finish_history(&state, hid, &live.info, error);
        }
        finish_recording(&app, live.recorder).await;
    }
    let _ = app.emit(SESSION_EVENT, SessionEvent::Closed { id });
    crate::presence::refresh(&app);
}

const STARTUP_SNIPPET_DELAY: Duration = Duration::from_millis(400);

pub(crate) struct Opened {
    pub(crate) protocol: &'static str,
    pub(crate) title: String,
    pub(crate) target: String,
    pub(crate) host_id: Option<Uuid>,
    /// Vault of the host (recordings are stored alongside it).
    pub(crate) vault_id: Option<Uuid>,
    pub(crate) term: SharedTerminal,
    pub(crate) events: TermEvents,
    pub(crate) client: Option<Arc<SshClient>>,
    pub(crate) jumps: Vec<Arc<SshClient>>,
    /// Script typed into the shell right after connecting.
    pub(crate) startup: String,
    pub(crate) color_scheme: Option<String>,
    pub(crate) shell: Option<String>,
    pub(crate) shell_integration: Option<bool>,
}

async fn connect<R: Runtime>(
    app: &AppHandle<R>,
    id: Uuid,
    target: &OpenTarget,
    size: TermSize,
) -> Result<Opened> {
    let state = app.state::<AppState>();
    let settings = state.settings().unwrap_or_default();
    let term_type = settings.term_type.as_str();
    match target {
        OpenTarget::Live { link } => crate::multiplayer::join(app, id, link).await,
        OpenTarget::Local => {
            let argv = local_shell_argv(&settings.local_shell);
            let shell = local_shell_name(&argv);
            let (term, events) = LocalTerminal::spawn(LocalShellOptions {
                argv,
                cwd: dirs_home(),
                env: vec![("TERM".into(), term_type.into())],
                size,
            })?;
            Ok(Opened {
                protocol: "local",
                title: "Local".into(),
                target: "local shell".into(),
                host_id: None,
                vault_id: None,
                term,
                events,
                client: None,
                jumps: Vec::new(),
                startup: String::new(),
                color_scheme: None,
                shell,
                shell_integration: None,
            })
        }
        OpenTarget::Quick {
            address,
            username,
            port,
            protocol,
        } => {
            let telnet = match protocol.as_deref().map(str::trim) {
                None | Some("") | Some("ssh") => false,
                Some("telnet") => true,
                Some(other) => {
                    return Err(DesktopError::invalid(format!(
                        "quick connect supports ssh and telnet, not {other}"
                    )));
                }
            };
            let (user, host, p) =
                parse_quick(address, username.as_deref(), port.or(telnet.then_some(23)))?;
            if telnet {
                let display = format!("{host}:{p}");
                emit_connecting(app, id, "telnet", &display, &display, None, None);
                let (term, events) = TelnetTerminal::connect(TelnetOptions {
                    host,
                    port: p,
                    term: term_type.into(),
                    size,
                    timeout: Duration::from_secs(20),
                    ip_version: IpVersion::Auto,
                    proxy: None,
                })
                .await?;
                return Ok(Opened {
                    protocol: "telnet",
                    title: display.clone(),
                    target: display,
                    host_id: None,
                    vault_id: None,
                    term,
                    events,
                    client: None,
                    jumps: Vec::new(),
                    startup: String::new(),
                    color_scheme: None,
                    shell: None,
                    shell_integration: None,
                });
            }
            let target = SshTarget {
                host,
                port: p,
                username: user,
            };
            let display = target.display();
            emit_connecting(app, id, "ssh", &display, &display, None, None);
            let (client, jumps) = ssh_connect(app, id, target, None, &[], None, None).await?;
            let (term, events) = client.shell(term_type, size).await?;
            Ok(Opened {
                protocol: "ssh",
                title: display.clone(),
                target: display,
                host_id: None,
                vault_id: None,
                term,
                events,
                client: Some(client),
                jumps,
                startup: String::new(),
                color_scheme: None,
                shell: None,
                shell_integration: None,
            })
        }
        OpenTarget::Serial { path, line } => {
            let serial = line.clone().into_config(path.trim());
            termoso_core::serial::validate(&serial)?;
            let title = serial
                .path
                .rsplit(['/', '\\'])
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or(&serial.path)
                .to_string();
            let display = format!(
                "{} · {}",
                serial.path,
                termoso_core::serial::describe(&serial)
            );
            emit_connecting(app, id, "serial", &title, &display, None, None);
            let (term, events) = SerialTerminal::open(&serial)?;
            Ok(Opened {
                protocol: "serial",
                title,
                target: display,
                host_id: None,
                vault_id: None,
                term,
                events,
                client: None,
                jumps: Vec::new(),
                startup: String::new(),
                color_scheme: None,
                shell: None,
                shell_integration: None,
            })
        }
        OpenTarget::Host {
            host_id,
            vault_id,
            protocol,
        } => {
            let resolved = state.store()?.resolve_host_in(*host_id, *vault_id)?;
            let label = resolved.host.data.label.clone();
            if host_protocol(&resolved, protocol.as_deref())? == "telnet" {
                let telnet = resolved.telnet.clone().unwrap_or_default();
                let port = telnet.port.unwrap_or(23);
                let display = format!("{}:{}", resolved.host.data.address, port);
                let scheme = telnet.color_scheme.clone();
                emit_connecting(
                    app,
                    id,
                    "telnet",
                    &label,
                    &display,
                    Some(*host_id),
                    scheme.clone(),
                );
                let (term, events) = TelnetTerminal::connect(TelnetOptions {
                    host: resolved.host.data.address.clone(),
                    port,
                    term: term_type.into(),
                    size,
                    timeout: Duration::from_secs(20),
                    ip_version: IpVersion::parse(&resolved.host.data.ip_version),
                    proxy: match &resolved.proxy {
                        Some(p) => Some(proxy_config(&state, &p.data)?),
                        None => None,
                    },
                })
                .await?;
                return Ok(Opened {
                    protocol: "telnet",
                    title: label,
                    target: display,
                    host_id: Some(*host_id),
                    vault_id: Some(resolved.host.vault_id),
                    term,
                    events,
                    client: None,
                    jumps: Vec::new(),
                    startup: startup_script(&state, &resolved),
                    color_scheme: scheme,
                    shell: None,
                    shell_integration: resolved.host.data.shell_integration,
                });
            }
            let target = ssh_target(&resolved);
            let display = target.display();
            let scheme = resolved.ssh.color_scheme.clone();
            if host_protocol(&resolved, protocol.as_deref())? == "mosh" {
                return open_mosh(app, id, &resolved, label, display, scheme, size).await;
            }
            emit_connecting(
                app,
                id,
                "ssh",
                &label,
                &display,
                Some(*host_id),
                scheme.clone(),
            );
            let (client, jumps) = connect_resolved(app, id, &resolved).await?;
            let (term, events) = client.shell(term_type, size).await?;
            detect_os_in_background(app, &resolved, client.clone());
            Ok(Opened {
                protocol: "ssh",
                title: label,
                target: display,
                host_id: Some(*host_id),
                vault_id: Some(resolved.host.vault_id),
                term,
                events,
                client: Some(client),
                jumps,
                startup: startup_script(&state, &resolved),
                color_scheme: scheme,
                shell: None,
                shell_integration: resolved.host.data.shell_integration,
            })
        }
    }
}

/// Mosh: bootstrap `mosh-server` over our SSH connection, then run
/// `mosh-client` locally. Jump hosts and proxies carry TCP only, so the UDP
/// session needs a direct route to the host.
async fn open_mosh<R: Runtime>(
    app: &AppHandle<R>,
    id: Uuid,
    resolved: &ResolvedHost,
    label: String,
    display: String,
    scheme: Option<String>,
    size: TermSize,
) -> Result<Opened> {
    let state = app.state::<AppState>();
    let settings = state.settings().unwrap_or_default();
    let host_id = resolved.host.id;
    let Some(client_bin) = crate::mosh::client_path() else {
        return Err(DesktopError::new(
            "mosh_missing",
            "mosh-client is not installed on this computer — install Mosh (e.g. `apt install mosh`, `brew install mosh`) and try again",
        ));
    };
    if !resolved.chain.is_empty() {
        return Err(DesktopError::invalid(
            "Mosh needs a direct UDP path to the host; remove the jump hosts or connect with SSH",
        ));
    }
    if resolved.proxy.is_some() {
        return Err(DesktopError::invalid(
            "Mosh cannot go through a proxy; remove it or connect with SSH",
        ));
    }
    emit_connecting(
        app,
        id,
        "mosh",
        &label,
        &display,
        Some(host_id),
        scheme.clone(),
    );
    let (client, jumps) = connect_resolved(app, id, resolved).await?;
    let _ = app.emit(
        SESSION_EVENT,
        SessionEvent::Progress {
            id,
            hop: None,
            phase: ConnectPhase::MoshServer,
        },
    );
    let boot =
        crate::mosh::start_server(&client, resolved.ssh.mosh_server_command.as_deref()).await;
    // The SSH leg has done its job either way.
    let _ = client.disconnect().await;
    for jump in jumps.into_iter().rev() {
        let _ = jump.disconnect().await;
    }
    let boot = boot?;
    // Prefer the address we resolve ourselves — the one SSH just reached; the
    // server's own `MOSH IP` is wrong behind NAT or a port forward.
    let ip = match crate::mosh::resolve_ip(
        &resolved.host.data.address,
        IpVersion::parse(&resolved.host.data.ip_version),
    )
    .await
    {
        Ok(ip) => ip,
        Err(e) => boot.ip.clone().ok_or(e)?,
    };
    let (term, events) =
        crate::mosh::spawn_client(client_bin, &ip, &boot, settings.term_type.as_str(), size)?;
    Ok(Opened {
        protocol: "mosh",
        title: label,
        target: format!("{display} · mosh udp/{}", boot.port),
        host_id: Some(host_id),
        vault_id: Some(resolved.host.vault_id),
        term,
        events,
        client: None,
        jumps: Vec::new(),
        startup: startup_script(&state, resolved),
        color_scheme: scheme,
        shell: None,
        shell_integration: resolved.host.data.shell_integration,
    })
}

fn has_ssh(resolved: &ResolvedHost) -> bool {
    resolved.host.data.ssh_config_id.is_some()
        || (resolved.telnet.is_none() && resolved.webdav.is_none())
}

/// Which section of a saved host to open: the requested one if the host has
/// it, otherwise SSH (over Mosh when the section says so), otherwise Telnet.
fn host_protocol(resolved: &ResolvedHost, requested: Option<&str>) -> Result<&'static str> {
    let ssh = has_ssh(resolved);
    let telnet = resolved.telnet.is_some();
    match requested.map(str::trim) {
        Some("telnet") if telnet => Ok("telnet"),
        Some("telnet") => Err(DesktopError::invalid("this host has no Telnet section")),
        Some("ssh") if ssh => Ok("ssh"),
        Some("ssh") => Err(DesktopError::invalid("this host has no SSH section")),
        Some("mosh") if ssh => Ok("mosh"),
        Some("mosh") => Err(DesktopError::invalid(
            "Mosh runs over the SSH section, which this host does not have",
        )),
        None | Some("") if !ssh && !telnet => Err(DesktopError::invalid(
            "this host has no terminal section; open it from Files",
        )),
        None | Some("") => Ok(if !ssh {
            "telnet"
        } else if resolved.ssh.use_mosh {
            "mosh"
        } else {
            "ssh"
        }),
        Some(other) => Err(DesktopError::invalid(format!(
            "hosts open over ssh, mosh or telnet, not {other}"
        ))),
    }
}

/// An SSH transport to a saved host, without a shell (used by SFTP).
pub struct HostConnection {
    pub label: String,
    pub display: String,
    pub client: Arc<SshClient>,
    pub jumps: Vec<Arc<SshClient>>,
}

impl HostConnection {
    /// Tear down the target and every hop, innermost first.
    pub async fn close(self) {
        let _ = self.client.disconnect().await;
        for jump in self.jumps.into_iter().rev() {
            let _ = jump.disconnect().await;
        }
    }
}

/// Connect to a saved SSH host, asking the UI for anything missing. Prompts
/// are routed under `session_id`. `vault_id` is the vault the caller expects
/// the host in (see [`OpenTarget::Host`]).
pub async fn connect_host<R: Runtime>(
    app: &AppHandle<R>,
    session_id: Uuid,
    host_id: Uuid,
    vault_id: Option<Uuid>,
) -> Result<HostConnection> {
    let state = app.state::<AppState>();
    let resolved = state.store()?.resolve_host_in(host_id, vault_id)?;
    if !has_ssh(&resolved) {
        return Err(DesktopError::invalid(
            "SFTP and port forwarding need an SSH section on the host",
        ));
    }
    let display = ssh_target(&resolved).display();
    let (client, jumps) = connect_resolved(app, session_id, &resolved).await?;
    detect_os_in_background(app, &resolved, client.clone());
    Ok(HostConnection {
        label: resolved.host.data.label.clone(),
        display,
        client,
        jumps,
    })
}

/// Fill in `os_name` for a host that has none yet, so its card gets the
/// right icon after the first successful connection. Runs off the session
/// path: a slow or refused probe never delays the shell, and failures are
/// silently dropped (the next connection tries again).
fn detect_os_in_background<R: Runtime>(
    app: &AppHandle<R>,
    resolved: &ResolvedHost,
    client: Arc<SshClient>,
) {
    let state = app.state::<AppState>();
    let enabled = state.settings().map(|s| s.detect_os).unwrap_or(true);
    if !enabled || resolved.host.data.os_name.is_some() {
        return;
    }
    let app = app.clone();
    let host_id = resolved.host.id;
    tauri::async_runtime::spawn(async move {
        let Some(os) = termoso_core::osdetect::detect(&client).await else {
            return;
        };
        let state = app.state::<AppState>();
        let saved = (|| -> Result<Uuid> {
            let mut host = state
                .store()?
                .require::<termoso_core::model::Host>(host_id)?;
            if host.data.os_name.is_some() {
                return Ok(host.vault_id);
            }
            host.data.os_name = Some(os.to_string());
            state.store()?.update(host.id, &host.data)?;
            Ok(host.vault_id)
        })();
        match saved {
            Ok(vault_id) => {
                let _ = app.emit(
                    crate::account::SYNC_EVENT,
                    crate::account::SyncNotice::EntitiesChanged { vault_id },
                );
            }
            Err(e) => tracing::debug!("saving detected os failed: {e}"),
        }
    });
}

/// Find out which shell the session runs so the UI can install its OSC 133
/// integration. Off the session path like the OS probe; skipped entirely
/// when the user turned shell integration off.
fn detect_shell_in_background<R: Runtime>(app: &AppHandle<R>, id: Uuid, client: Arc<SshClient>) {
    let state = app.state::<AppState>();
    let enabled = state
        .settings()
        .map(|s| s.shell_integration)
        .unwrap_or(true);
    if !enabled {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let Some(shell) = termoso_core::osdetect::detect_shell(&client).await else {
            return;
        };
        let state = app.state::<AppState>();
        let known = {
            let mut live = state.sessions.live.lock().expect("sessions poisoned");
            match live.get_mut(&id) {
                Some(l) => {
                    l.info.shell = Some(shell.clone());
                    true
                }
                None => false,
            }
        };
        if known {
            let _ = app.emit(SESSION_EVENT, SessionEvent::Shell { id, shell });
        }
    });
}

fn ssh_target(resolved: &ResolvedHost) -> SshTarget {
    SshTarget {
        host: resolved.host.data.address.clone(),
        port: resolved.port(),
        username: resolved.username().unwrap_or_default(),
    }
}

/// Ask for the login name when the target has none; an empty answer asks
/// again, dismissing the prompt cancels the connection.
async fn ask_username<R: Runtime>(
    app: &AppHandle<R>,
    session_id: Uuid,
    target: &SshTarget,
    resolved: Option<&ResolvedHost>,
) -> Result<String> {
    let state = app.state::<AppState>();
    let host = resolved
        .map(|r| r.host.data.label.clone())
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| target.host.clone());
    let mut retry = false;
    loop {
        let answer = state
            .prompts
            .ask(
                app,
                session_id,
                target.display(),
                PromptRequest::Username {
                    host: host.clone(),
                    retry,
                },
            )
            .await;
        match answer {
            Some(PromptAnswer::Secret { value, remember }) => {
                let value = value.trim().to_string();
                if value.is_empty() {
                    retry = true;
                    continue;
                }
                if remember && let Some(r) = resolved {
                    remember_username(&state, r, &value);
                }
                return Ok(value);
            }
            _ => return Err(CoreError::Cancelled.into()),
        }
    }
}

async fn connect_resolved<R: Runtime>(
    app: &AppHandle<R>,
    session_id: Uuid,
    resolved: &ResolvedHost,
) -> Result<(Arc<SshClient>, Vec<Arc<SshClient>>)> {
    if resolved.chain.is_empty()
        && termoso_core::policy::jump_required(
            &*app.state::<AppState>().store()?,
            resolved.host.vault_id,
        )
    {
        return Err(DesktopError::invalid(
            termoso_core::policy::Denied::DirectConnection.message(),
        ));
    }
    ssh_connect(
        app,
        session_id,
        ssh_target(resolved),
        Some(resolved),
        &resolved.chain,
        None,
        None,
    )
    .await
}

/// Forwards [`ConnectPhase`]s of one SSH leg to the UI as `Progress` events.
struct UiProgress<R: Runtime> {
    app: AppHandle<R>,
    session_id: Uuid,
    hop: Option<String>,
}

impl<R: Runtime> ConnectProgress for UiProgress<R> {
    fn phase(&self, phase: ConnectPhase) {
        let _ = self.app.emit(
            SESSION_EVENT,
            SessionEvent::Progress {
                id: self.session_id,
                hop: self.hop.clone(),
                phase,
            },
        );
    }
}

fn emit_connecting<R: Runtime>(
    app: &AppHandle<R>,
    id: Uuid,
    protocol: &str,
    title: &str,
    target: &str,
    host_id: Option<Uuid>,
    color_scheme: Option<String>,
) {
    let _ = app.emit(
        SESSION_EVENT,
        SessionEvent::Connecting {
            id,
            info: SessionInfo {
                id,
                protocol: protocol.into(),
                title: title.into(),
                target: target.into(),
                host_id,
                started_at: Utc::now(),
                state: SessionState::Connecting,
                algorithms: None,
                via: Vec::new(),
                color_scheme,
                shell: None,
                shell_integration: None,
            },
        },
    );
}

pub(crate) fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(Into::into)
}

/// `[user@]host[:port]` → (user, host, port). IPv6 literals go in brackets.
/// The user is empty when not given; the connect path asks for it.
fn parse_quick(
    address: &str,
    username: Option<&str>,
    port: Option<u16>,
) -> Result<(String, String, u16)> {
    let s = address.trim();
    if s.is_empty() {
        return Err(DesktopError::invalid("address is empty"));
    }
    let (user_part, rest) = match s.rsplit_once('@') {
        Some((u, r)) => (Some(u), r),
        None => (None, s),
    };
    let (host, port_part) = if let Some(r) = rest.strip_prefix('[') {
        let (h, tail) = r
            .split_once(']')
            .ok_or_else(|| DesktopError::invalid("unterminated IPv6 literal"))?;
        (h.to_string(), tail.strip_prefix(':'))
    } else if rest.matches(':').count() == 1 {
        let (h, p) = rest.split_once(':').unwrap_or((rest, ""));
        (h.to_string(), Some(p))
    } else {
        (rest.to_string(), None)
    };
    if host.is_empty() {
        return Err(DesktopError::invalid("host is empty"));
    }
    let port = match (port, port_part) {
        (Some(p), _) => p,
        (None, Some(p)) if !p.is_empty() => p
            .parse()
            .map_err(|_| DesktopError::invalid(format!("bad port {p}")))?,
        _ => 22,
    };
    let user = username
        .map(str::to_string)
        .or_else(|| user_part.map(str::to_string))
        .filter(|u| !u.is_empty())
        .unwrap_or_default();
    Ok((user, host, port))
}

/// Connect to `target`, going through `chain` jump hosts first. Asks the UI
/// for a password/passphrase when the stored credentials are not enough.
/// `hop` is the label reported with progress events when this leg is itself
/// a jump host on the way to the real target.
#[allow(clippy::too_many_arguments)]
async fn ssh_connect<R: Runtime>(
    app: &AppHandle<R>,
    session_id: Uuid,
    target: SshTarget,
    resolved: Option<&ResolvedHost>,
    chain: &[Entity<termoso_core::model::Host>],
    jump: Option<Arc<SshClient>>,
    hop: Option<String>,
) -> Result<(Arc<SshClient>, Vec<Arc<SshClient>>)> {
    let state = app.state::<AppState>();
    let mut target = target;
    if target.username.trim().is_empty() {
        target.username = ask_username(app, session_id, &target, resolved).await?;
    }
    let mut jumps: Vec<Arc<SshClient>> = Vec::new();

    // Jump hosts first, in the order saved on the host chain. Each hop is
    // dialled through the previous one (direct-tcpip), uses its own
    // credentials, proxy and known-host entry, and is kept alive for the
    // whole session. A hop's own chain is deliberately not followed: the
    // chain on the target host is the single source of truth for the route,
    // which also rules out cycles.
    let mut via = jump;
    for link in chain {
        let hop_resolved = state
            .store()?
            .resolve_host_in(link.id, Some(link.vault_id))?;
        let hop_target = SshTarget {
            host: hop_resolved.host.data.address.clone(),
            port: hop_resolved.port(),
            username: hop_resolved.username().unwrap_or_default(),
        };
        let (client, _) = Box::pin(ssh_connect(
            app,
            session_id,
            hop_target,
            Some(&hop_resolved),
            &[],
            via.clone(),
            Some(hop_resolved.host.data.label.clone()),
        ))
        .await?;
        jumps.push(client.clone());
        via = Some(client);
    }

    let known_hosts = KnownHosts::new(state.store()?.clone(), state.store()?.local_vault()?.id);
    let display = target.display();
    let ssh_cfg = resolved.map(|r| r.ssh.clone()).unwrap_or_default();
    let identity = resolved.and_then(|r| r.identity.clone());
    let mut password: Option<Zeroizing<String>> = identity
        .as_ref()
        .and_then(|i| i.data.password.clone())
        .filter(|p| !p.is_empty())
        .map(Zeroizing::new);
    let mut passphrase: Option<Zeroizing<String>> = resolved
        .and_then(|r| r.key.as_ref())
        .and_then(|k| k.data.passphrase.clone())
        .filter(|p| !p.is_empty())
        .map(Zeroizing::new);
    if let Some(p) = &password
        && termoso_core::extsecret::is_reference(p)
    {
        password = Some(termoso_core::extsecret::resolve(p).await?);
    }
    if let Some(p) = &passphrase
        && termoso_core::extsecret::is_reference(p)
    {
        passphrase = Some(termoso_core::extsecret::resolve(p).await?);
    }
    let totp = identity
        .as_ref()
        .and_then(|i| i.data.totp_secret.as_deref())
        .filter(|t| !t.is_empty())
        .map(|t| TotpResponder::parse(t).map_err(DesktopError::from))
        .transpose()?;
    let proxy = match resolved.and_then(|r| r.proxy.as_ref()) {
        Some(p) => Some(proxy_config(&state, &p.data)?),
        None => None,
    };
    let mut pin: Option<Zeroizing<String>> = None;

    let mut attempts = 0;
    loop {
        let mut auth: Vec<AuthMethod> = Vec::new();
        // Team CA certificate first (hosts in a team vault; cached by the
        // account sync, see `termoso_core::ca`).
        if let Some(m) = resolved
            .and_then(|r| termoso_core::ca::auth_method(&*state.store().ok()?, r.host.vault_id))
        {
            auth.push(m);
        }
        if identity.as_ref().is_some_and(|i| i.data.ssh_id) {
            let preferred = identity.as_ref().and_then(|i| i.data.ssh_id_key_type);
            auth.extend(sshid::auth_methods(
                &*state.store()?,
                preferred,
                pin.clone(),
            )?);
        }
        let mut agent_key_selected = false;
        if let Some(key) = resolved.and_then(|r| r.key.as_ref()) {
            let certificate = resolved
                .and_then(|r| r.certificate.as_ref())
                .map(|c| c.data.certificate.clone());
            if key.data.is_agent_backed() {
                let public_key = key.data.public_key.clone().ok_or_else(|| {
                    DesktopError::invalid(format!(
                        "agent key \"{}\" has no public key",
                        key.data.label
                    ))
                })?;
                agent_key_selected = true;
                auth.push(AuthMethod::AgentKey {
                    public_key,
                    certificate,
                });
            } else if fido2::is_sk_type(&key.data.key_type) {
                auth.push(AuthMethod::SecurityKey {
                    private_key: Zeroizing::new(key.data.private_key.clone()),
                    passphrase: passphrase.clone(),
                    pin: pin.clone(),
                    backend: Arc::new(fido2::UsbBackend::default()),
                    certificate,
                });
            } else {
                auth.push(AuthMethod::Key {
                    private_key: Zeroizing::new(key.data.private_key.clone()),
                    passphrase: passphrase.clone(),
                    certificate,
                });
            }
        }
        if !agent_key_selected && state.settings().map(|s| s.use_ssh_agent).unwrap_or(true) {
            auth.push(AuthMethod::Agent);
        }
        // Team policy `auth = keys_only`: no password-class methods at all.
        let keys_only = resolved.is_some_and(|r| {
            state
                .store()
                .is_ok_and(|st| termoso_core::policy::keys_only(&st, r.host.vault_id))
        });
        if keys_only {
            if auth.is_empty() {
                return Err(DesktopError::invalid(
                    termoso_core::policy::Denied::PasswordAuth.message(),
                ));
            }
        } else {
            if let Some(pw) = &password {
                auth.push(AuthMethod::Password(pw.clone()));
            }
            auth.push(AuthMethod::KeyboardInteractive);
        }

        let ui_prompt: Arc<dyn termoso_core::ssh::InteractivePrompt> =
            Arc::new(UiInteractivePrompt {
                app: app.clone(),
                session_id,
                target: display.clone(),
            });
        let interactive: Option<Arc<dyn termoso_core::ssh::InteractivePrompt>> =
            match (&totp, &password) {
                (Some(t), _) => Some(Arc::new(TotpResponder::new(
                    t.clone(),
                    password.clone(),
                    Some(ui_prompt),
                ))),
                (None, Some(_)) => None,
                (None, None) => Some(ui_prompt),
            };
        let opts = ConnectOptions {
            target: target.clone(),
            auth,
            known_hosts: known_hosts.clone(),
            host_key_prompt: Arc::new(UiHostKeyPrompt {
                app: app.clone(),
                session_id,
                target: display.clone(),
            }),
            interactive,
            keepalive: keepalive(&state, &ssh_cfg),
            timeout: Duration::from_secs(ssh_cfg.timeout.unwrap_or(20).clamp(1, 600) as u64),
            proxy: proxy.clone(),
            gateway: gateway_dial(app, resolved).await,
            env: ssh_cfg.env_variables.clone(),
            agent_forwarding: ssh_cfg.agent_forwarding,
            x11: (ssh_cfg.forward_x11 && hop.is_none())
                .then(|| LocalDisplay::detect(None))
                .flatten()
                .map(|d| Arc::new(X11Forward::new(d))),
            agent_socket: None,
            post_quantum_kex: state.settings().map(|s| s.post_quantum_kex).unwrap_or(true),
            progress: Some(Arc::new(UiProgress {
                app: app.clone(),
                session_id,
                hop: hop.clone(),
            })),
            ip_version: resolved
                .map(|r| IpVersion::parse(&r.host.data.ip_version))
                .unwrap_or_default(),
        };

        let result = match &via {
            Some(j) => SshClient::connect_via(j, opts).await,
            None => SshClient::connect(opts).await,
        };
        match result {
            Ok(client) => return Ok((Arc::new(client), jumps)),
            Err(CoreError::AuthFailed { remaining })
                if attempts < MAX_PASSWORD_ATTEMPTS
                    && remaining
                        .iter()
                        .any(|m| m == "password" || m == "keyboard-interactive") =>
            {
                attempts += 1;
                let answer = state
                    .prompts
                    .ask(
                        app,
                        session_id,
                        display.clone(),
                        PromptRequest::Password {
                            username: target.username.clone(),
                            retry: password.is_some(),
                        },
                    )
                    .await;
                match answer {
                    Some(PromptAnswer::Secret { value, remember }) => {
                        if remember && let Some(r) = resolved {
                            remember_password(&state, r, &target.username, &value);
                        }
                        password = Some(value);
                    }
                    _ => return Err(CoreError::Cancelled.into()),
                }
            }
            Err(CoreError::Key(msg))
                if attempts < MAX_PASSWORD_ATTEMPTS && msg.contains("passphrase") =>
            {
                attempts += 1;
                let label = resolved
                    .and_then(|r| r.key.as_ref())
                    .map(|k| k.data.label.clone())
                    .unwrap_or_default();
                let answer = state
                    .prompts
                    .ask(
                        app,
                        session_id,
                        display.clone(),
                        PromptRequest::Passphrase { key_label: label },
                    )
                    .await;
                match answer {
                    Some(PromptAnswer::Secret { value, remember }) => {
                        if remember && let Some(key) = resolved.and_then(|r| r.key.as_ref()) {
                            let mut data = key.data.clone();
                            data.passphrase = Some(value.to_string());
                            let _ = state.store()?.update(key.id, &data);
                        }
                        passphrase = Some(value);
                    }
                    _ => return Err(CoreError::Cancelled.into()),
                }
            }
            Err(CoreError::Fido2(
                e @ (Fido2Error::PinRequired | Fido2Error::PinInvalid { .. }),
            )) if attempts < MAX_PASSWORD_ATTEMPTS => {
                attempts += 1;
                let label = resolved
                    .and_then(|r| r.key.as_ref())
                    .map(|k| k.data.label.clone())
                    .or_else(|| {
                        resolved
                            .and_then(|r| r.ssh_id_handle.as_deref())
                            .map(|h| format!("SSH ID @{h}"))
                    })
                    .unwrap_or_default();
                let retries = match e {
                    Fido2Error::PinInvalid { retries } => retries,
                    _ => None,
                };
                let answer = state
                    .prompts
                    .ask(
                        app,
                        session_id,
                        display.clone(),
                        PromptRequest::Pin {
                            key_label: label,
                            retry: pin.is_some(),
                            retries,
                        },
                    )
                    .await;
                match answer {
                    Some(PromptAnswer::Secret { value, .. }) => pin = Some(value),
                    _ => return Err(CoreError::Cancelled.into()),
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn keepalive(state: &AppState, cfg: &SshConfig) -> Option<Duration> {
    let secs = cfg
        .keep_alive_interval
        .or_else(|| state.settings().ok().map(|s| s.keep_alive_seconds))
        .unwrap_or(30);
    (secs > 0).then(|| Duration::from_secs(secs as u64))
}

pub(crate) fn proxy_config(
    state: &AppState,
    p: &termoso_core::model::Proxy,
) -> Result<ProxyConfig> {
    let kind = ProxyKind::parse(&p.kind)
        .ok_or_else(|| DesktopError::invalid(format!("unsupported proxy type {}", p.kind)))?;
    let (username, password) = match p.identity_id {
        Some(id) => {
            let ident = state.store()?.get::<Identity>(id)?;
            (
                ident.as_ref().map(|i| i.data.username.clone()),
                ident
                    .and_then(|i| i.data.password)
                    .filter(|p| !p.is_empty())
                    .map(Zeroizing::new),
            )
        }
        None => (
            p.username.clone().filter(|u| !u.is_empty()),
            p.password
                .clone()
                .filter(|s| !s.is_empty())
                .map(Zeroizing::new),
        ),
    };
    Ok(ProxyConfig {
        kind,
        host: p.host.clone(),
        port: p.port,
        username,
        password: password.filter(|_| kind.supports_password()),
    })
}

/// Store a credential the user asked to remember on the host's identity
/// when it has one, otherwise on a new hidden identity attached to the
/// host's SSH config (created if missing). `username` is the login the
/// connection is using; `edit` applies the remembered value.
fn remember_on_identity(
    state: &AppState,
    resolved: &ResolvedHost,
    username: &str,
    what: &str,
    edit: impl Fn(&mut Identity),
) {
    let Ok(store) = state.store() else {
        return;
    };
    let result = (|| -> termoso_core::error::Result<()> {
        if let Some(ident) = &resolved.identity {
            let mut data = ident.data.clone();
            edit(&mut data);
            return store.update(ident.id, &data);
        }
        let vault_id = resolved.host.vault_id;
        let mut identity = Identity {
            external_id: None,
            label: format!("{username}@{}", resolved.host.data.address),
            username: username.to_string(),
            password: None,
            ssh_key_id: None,
            ssh_certificate_id: None,
            is_visible: false,
            ssh_id: false,
            ssh_id_key_type: None,
            bearer_token: None,
            client_certificate: None,
            totp_secret: None,
        };
        edit(&mut identity);
        let identity_id = store.insert(vault_id, &identity)?;
        match resolved.host.data.ssh_config_id {
            Some(cfg_id) => {
                let cfg = store.require::<SshConfig>(cfg_id)?;
                let mut data = cfg.data;
                data.identity_id = Some(identity_id);
                store.update(cfg_id, &data)
            }
            None => {
                let cfg_id = store.insert(
                    vault_id,
                    &SshConfig {
                        identity_id: Some(identity_id),
                        ..resolved.ssh.clone()
                    },
                )?;
                let mut host = resolved.host.data.clone();
                host.ssh_config_id = Some(cfg_id);
                store.update(resolved.host.id, &host)
            }
        }
    })();
    if let Err(e) = result {
        tracing::warn!(error = %e, "could not remember {what}");
    }
}

fn remember_password(state: &AppState, resolved: &ResolvedHost, username: &str, value: &str) {
    remember_on_identity(state, resolved, username, "password", |i| {
        i.password = Some(value.to_string())
    });
}

fn remember_username(state: &AppState, resolved: &ResolvedHost, username: &str) {
    remember_on_identity(state, resolved, username, "username", |i| {
        i.username = username.to_string()
    });
}

/// Tunnel through the host's gateway (an API bridge in gateway mode), if it has one.
async fn gateway_dial<R: Runtime>(
    app: &AppHandle<R>,
    resolved: Option<&termoso_core::model::ResolvedHost>,
) -> Option<termoso_core::gateway::GatewayDial> {
    let r = resolved?;
    let gateway_id = r.gateway_id?;
    let api = crate::account::api(app).await.ok()?;
    Some(termoso_core::gateway::GatewayDial {
        api,
        gateway_id,
        vault_id: r.host.vault_id,
        host_id: r.host.id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_shell_setting_splits_into_argv_and_names_the_shell() {
        assert!(local_shell_argv("").is_empty());
        assert_eq!(local_shell_argv("  /bin/zsh "), ["/bin/zsh"]);
        assert_eq!(
            local_shell_argv("wsl.exe -d Ubuntu"),
            ["wsl.exe", "-d", "Ubuntu"]
        );
        assert_eq!(
            local_shell_name(&local_shell_argv("/usr/bin/fish")).as_deref(),
            Some("fish")
        );
        assert_eq!(
            local_shell_argv(r#""C:\Program Files\PowerShell\7\pwsh.exe" -NoLogo"#),
            [r"C:\Program Files\PowerShell\7\pwsh.exe", "-NoLogo"]
        );
        assert_eq!(
            local_shell_name(&local_shell_argv(
                r#""C:\Program Files\PowerShell\7\pwsh.exe""#
            ))
            .as_deref(),
            Some("pwsh")
        );
        assert_eq!(
            local_shell_argv(r#"sh -c "echo \"hi\"""#),
            ["sh", "-c", r#"echo "hi""#]
        );
    }

    #[test]
    fn local_shell_existing_path_with_spaces_is_one_program() {
        let dir = std::env::temp_dir().join(format!("termoso shell {}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("my shell");
        std::fs::write(&exe, b"").unwrap();
        let setting = exe.to_string_lossy().into_owned();
        assert_eq!(local_shell_argv(&setting), std::slice::from_ref(&setting));
        assert_eq!(
            local_shell_name(&local_shell_argv(&setting)).as_deref(),
            Some("my shell")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn local_shells_lists_the_login_shell_first_without_duplicates() {
        let shells = local_shells();
        if let Ok(login) = std::env::var("SHELL")
            && !cfg!(windows)
        {
            assert_eq!(shells.first(), Some(&login));
        }
        let mut dedup = shells.clone();
        dedup.dedup();
        assert_eq!(dedup, shells);
    }
}
