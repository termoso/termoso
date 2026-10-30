//! Process-wide application state owned by Rust.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use termoso_core::secrets::{self, MasterKeySource};
use termoso_core::store::Store;
use termoso_core::sync::ConflictPolicy;

use crate::account::AccountRuntime;
use crate::edits::Edits;
use crate::error::{DesktopError, Result};
use crate::forwarding::Forwards;
use crate::multiplayer::Multiplayer;
use crate::prompts::PromptBroker;
use crate::sessions::Sessions;
use crate::sftp::SftpSessions;
use crate::sync::Syncs;

pub const PROFILE_ENV: &str = "TERMOSO_PROFILE_DIR";
pub const PROFILE_NAME: &str = "default";
const DB_FILE: &str = "vault.db";
const LOGS_DIR: &str = "logs";
const SETTINGS_META: &str = "desktop.settings";

pub struct AppState {
    pub profile_dir: PathBuf,
    pub master_source: std::sync::Mutex<MasterKeySource>,
    /// `None` while the vault is locked: the master key and every decrypted
    /// row live only inside `Store`, so dropping it is what "locked" means.
    store: RwLock<Option<Arc<Store>>>,
    pub lock: LockRuntime,
    pub sessions: Sessions,
    pub sftp: SftpSessions,
    pub edits: Edits,
    pub syncs: Syncs,
    pub forwards: Forwards,
    pub prompts: PromptBroker,
    pub account: AccountRuntime,
    pub multiplayer: Multiplayer,
    pub agent: crate::agent_server::AgentRuntime,
}

/// App Lock bookkeeping that outlives the store.
#[derive(Default)]
pub struct LockRuntime {
    /// Last user interaction reported by the webview (inactivity relock).
    last_activity: std::sync::Mutex<Option<Instant>>,
    /// Once-per-process start-up work (update check, cloud sync scheduler)
    /// has run; later unlocks skip it.
    pub first_startup_done: AtomicBool,
    /// A lock is tearing the runtime down; unlock and further locks wait.
    pub locking: AtomicBool,
}

impl LockRuntime {
    pub fn touch(&self) {
        self.touch_at(Instant::now());
    }

    pub fn touch_at(&self, at: Instant) {
        *self.last_activity.lock().expect("activity poisoned") = Some(at);
    }

    pub fn idle_for_at(&self, now: Instant) -> Option<Duration> {
        self.last_activity
            .lock()
            .expect("activity poisoned")
            .map(|t| now.saturating_duration_since(t))
    }

    /// `true` once the idle time reaches `lock_after_minutes` (0 = never).
    pub fn idle_expired(&self, lock_after_minutes: u32, now: Instant) -> bool {
        if lock_after_minutes == 0 {
            return false;
        }
        let limit = Duration::from_secs(u64::from(lock_after_minutes) * 60);
        self.idle_for_at(now).is_some_and(|idle| idle >= limit)
    }
}

impl AppState {
    /// Prepare the profile. Without a master password the key is read from
    /// the OS keychain (falling back to an owner-only file) and the store
    /// opens right away; with one, the store stays closed until
    /// [`AppState::unlock_with_password`].
    pub fn open() -> Result<Self> {
        let profile_dir = std::env::var_os(PROFILE_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| secrets::default_profile_dir(PROFILE_NAME));
        Self::open_at(profile_dir)
    }

    pub fn open_at(profile_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&profile_dir)?;
        std::fs::create_dir_all(profile_dir.join(LOGS_DIR))?;
        let (source, store) = if secrets::password_protected(&profile_dir) {
            (MasterKeySource::Password, None)
        } else {
            let master = secrets::load_or_create(&profile_dir, PROFILE_NAME, true)?;
            let store = Store::open(&profile_dir.join(DB_FILE), master.key)?;
            (master.source, Some(Arc::new(store)))
        };
        let lock = LockRuntime::default();
        lock.touch();
        Ok(Self {
            profile_dir,
            master_source: std::sync::Mutex::new(source),
            store: RwLock::new(store),
            lock,
            sessions: Sessions::default(),
            sftp: SftpSessions::default(),
            edits: Edits::default(),
            syncs: Syncs::default(),
            forwards: Forwards::default(),
            prompts: PromptBroker::default(),
            account: AccountRuntime::default(),
            multiplayer: Multiplayer::default(),
            agent: Default::default(),
        })
    }

    /// Throwaway state over an in-memory store for unit tests.
    #[cfg(test)]
    pub fn in_memory(profile_dir: PathBuf) -> Self {
        use termoso_core::termoso_crypto::keys::SymmetricKey;
        std::fs::create_dir_all(profile_dir.join(LOGS_DIR)).expect("profile dir");
        Self {
            profile_dir,
            master_source: std::sync::Mutex::new(MasterKeySource::File),
            store: RwLock::new(Some(Arc::new(
                Store::open_in_memory(SymmetricKey::generate()).expect("store"),
            ))),
            lock: LockRuntime::default(),
            sessions: Sessions::default(),
            sftp: SftpSessions::default(),
            edits: Edits::default(),
            syncs: Syncs::default(),
            forwards: Forwards::default(),
            prompts: PromptBroker::default(),
            account: AccountRuntime::default(),
            multiplayer: Multiplayer::default(),
            agent: Default::default(),
        }
    }

    /// The open store, or `locked` when the vault is locked. Every command
    /// that touches vault data goes through here, so a locked vault refuses
    /// them uniformly instead of each command checking.
    pub fn store(&self) -> Result<Arc<Store>> {
        self.store
            .read()
            .expect("store poisoned")
            .clone()
            .ok_or_else(|| DesktopError::new("locked", "the vault is locked"))
    }

    pub fn is_locked(&self) -> bool {
        self.store.read().expect("store poisoned").is_none()
    }

    pub fn password_protected(&self) -> bool {
        secrets::password_protected(&self.profile_dir)
    }

    /// Open the store with the master key unwrapped by `password`. A wrong
    /// password leaves the on-disk record untouched.
    pub fn unlock_with_password(&self, password: &str) -> Result<()> {
        let mut slot = self.store.write().expect("store poisoned");
        if slot.is_some() {
            return Ok(());
        }
        let master = secrets::unlock_with_password(&self.profile_dir, PROFILE_NAME, password)?;
        let store = Store::open(&self.profile_dir.join(DB_FILE), master.key)?;
        *slot = Some(Arc::new(store));
        *self.master_source.lock().expect("master source poisoned") = master.source;
        self.lock.touch();
        Ok(())
    }

    /// Drop the store (and with it the master key and every cached vault
    /// key). Returns whether anything was open. Callers must have shut down
    /// the runtimes that hold their own `Arc<Store>` first.
    pub fn close_store(&self) -> bool {
        let taken = self.store.write().expect("store poisoned").take();
        if let Some(store) = &taken
            && Arc::strong_count(store) > 1
        {
            tracing::warn!(
                refs = Arc::strong_count(store) - 1,
                "store still referenced after lock; key stays in memory until released"
            );
        }
        taken.is_some()
    }

    pub fn master_source(&self) -> MasterKeySource {
        *self.master_source.lock().expect("master source poisoned")
    }

    /// Move a file-based master key into the OS keychain.
    pub fn migrate_master_key(&self) -> Result<MasterKeySource> {
        if self.master_source() == MasterKeySource::Password {
            return Err(DesktopError::invalid(
                "the master key is protected by a password; remove it first",
            ));
        }
        if secrets::migrate_file_to_keychain(&self.profile_dir, PROFILE_NAME)? {
            *self.master_source.lock().expect("master source poisoned") = MasterKeySource::Keychain;
        }
        Ok(self.master_source())
    }

    /// Wrap the master key under `password` (enable or change). With a
    /// password already set, `current` must unlock it first.
    pub fn set_master_password(&self, current: Option<&str>, password: &str) -> Result<()> {
        let store = self.store()?;
        if self.password_protected() {
            secrets::verify_password(&self.profile_dir, current.unwrap_or_default())?;
        }
        secrets::set_password(
            &self.profile_dir,
            PROFILE_NAME,
            store.master_key(),
            password,
        )?;
        *self.master_source.lock().expect("master source poisoned") = MasterKeySource::Password;
        Ok(())
    }

    /// Go back to keychain / file storage after proving `current`.
    pub fn remove_master_password(&self, current: &str) -> Result<MasterKeySource> {
        let store = self.store()?;
        if !self.password_protected() {
            return Ok(self.master_source());
        }
        secrets::verify_password(&self.profile_dir, current)?;
        let source =
            secrets::remove_password(&self.profile_dir, PROFILE_NAME, store.master_key(), true)?;
        *self.master_source.lock().expect("master source poisoned") = source;
        Ok(source)
    }

    /// Where encrypted session recordings live.
    pub fn logs_dir(&self) -> PathBuf {
        self.profile_dir.join(LOGS_DIR)
    }

    pub fn settings(&self) -> Result<Settings> {
        Ok(match self.store()?.meta(SETTINGS_META)? {
            Some(raw) => serde_json::from_str(&raw)?,
            None => Settings::default(),
        })
    }

    pub fn save_settings(&self, settings: &Settings) -> Result<()> {
        settings.validate()?;
        self.store()?
            .set_meta(SETTINGS_META, &serde_json::to_string(settings)?)?;
        Ok(())
    }
}

/// A regex watched on terminal output (SecureCRT/iTerm-style trigger).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct Trigger {
    pub id: uuid::Uuid,
    pub name: String,
    /// JavaScript regular expression source, tested against the ANSI-stripped output.
    pub pattern: String,
    pub enabled: bool,
    /// Desktop notification with the matching line.
    pub notify: bool,
    /// Highlight the matching row in the terminal.
    pub highlight: bool,
    /// Text typed into the session on a match (`\n` for Enter), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<String>,
}

/// UI preferences. Stored in the (encrypted-at-rest) local database, never
/// leaves the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    /// `dark` | `light` | `system`.
    pub theme: String,
    /// UI language: `system` (follow the OS) or a locale from [`LANGUAGES`].
    pub language: String,
    /// `grid` | `list`.
    pub hosts_view: String,
    /// `grid` | `list` for the Port Forwarding page.
    pub forwarding_view: String,
    /// `grid` | `list` for the Keychain page.
    pub keychain_view: String,
    pub terminal_font_size: u16,
    pub terminal_font_family: String,
    /// Line height multiplier (1.0 = font's natural height).
    pub terminal_line_height: f32,
    /// Colour scheme id from the client's theme registry; `auto` follows
    /// `theme` with the Termoso Dark / Light schemes.
    pub terminal_theme: String,
    pub cursor_blink: bool,
    /// `block` | `underline` | `bar`.
    pub cursor_style: String,
    pub scrollback: u32,
    pub copy_on_select: bool,
    pub paste_on_right_click: bool,
    pub confirm_close_tab: bool,
    pub confirm_paste_multiline: bool,
    pub autocomplete: bool,
    /// Install the OSC 133 prompt markers into bash / zsh / fish after
    /// connecting: powers command history, autocomplete and prompt navigation.
    pub shell_integration: bool,
    /// Output triggers: a regex watched on every terminal, with what to do on a match.
    #[serde(default)]
    pub triggers: Vec<Trigger>,
    /// What to do with the command a workspace pane was running when it was
    /// saved: `type` puts it on the prompt for the user to confirm, `run`
    /// executes it, `never` restores only the working directory.
    pub restore_commands: String,
    pub terminal_bell: bool,
    /// Render bold text with the bright ANSI colours.
    pub bright_bold: bool,
    /// `TERM` advertised to remote shells and the local PTY.
    pub term_type: String,
    /// Re-establish SSH / Telnet sessions that drop unexpectedly.
    pub auto_reconnect: bool,
    /// Colour error / warning / ok / info / debug words and IP / MAC addresses
    /// in terminal output (client-side, foreground only).
    pub keyword_highlight: bool,
    /// Program for local terminals (`/bin/zsh`, `pwsh.exe`, `wsl.exe -d Ubuntu`);
    /// empty = the user's login shell.
    pub local_shell: String,
    pub keep_alive_seconds: u32,
    /// Probe a host's OS after the first successful connection to pick its icon.
    pub detect_os: bool,
    /// Offer the hybrid ML-KEM-768 + X25519 key exchange (servers without it
    /// fall back to classical algorithms).
    pub post_quantum_kex: bool,
    /// Offer keys held by the system SSH agent (`SSH_AUTH_SOCK`, Windows
    /// OpenSSH agent or Pageant) when authenticating.
    pub use_ssh_agent: bool,
    /// Run our own SSH agent (socket / named pipe) serving the vault's keys
    /// to local `ssh`, `git` and IDEs.
    pub serve_ssh_agent: bool,
    /// Claim and execute team automations on this computer.
    #[serde(default)]
    pub run_automations: bool,
    /// Ask in the UI before each signature our agent makes.
    pub agent_confirm: bool,
    /// Record terminal output of every session into the encrypted log store.
    pub record_sessions: bool,
    /// Delete local recordings older than this many days (0 = keep).
    pub log_retention_days: u32,
    /// Start `auto_start` forwarding rules when the app launches.
    pub autostart_forwarding: bool,
    /// Closing the window hides it to the system tray; sessions and
    /// forwards keep running until Quit.
    pub minimize_to_tray: bool,
    /// `newest_wins` | `local_wins` | `server_wins`.
    pub sync_conflict: String,
    /// Background sync period in seconds (0 = manual + realtime only).
    pub sync_interval_seconds: u32,
    /// Upload finished recordings to the account server.
    pub upload_logs: bool,
    /// Sync identities, keys and certificates of the Personal vault. Off
    /// keeps them on this device only (hosts etc. still sync); they are
    /// removed together with the account on sign-out.
    pub sync_credentials: bool,
    /// `manual` (never contacts the feed unless asked) | `startup`.
    pub update_check: String,
    /// Release feed URL; empty = project default. Point it at your own server
    /// to keep updates fully self-hosted.
    pub update_url: String,
    /// Lock the vault after this many minutes without keyboard / mouse input
    /// in the app (0 = never). Only meaningful with a master password.
    pub lock_after_minutes: u32,
    /// The start-up sign-in screen was dismissed with "Continue offline";
    /// signing in stays one click away in the account menu.
    pub welcome_seen: bool,
    /// Master switch for system notifications.
    pub notifications: bool,
    /// A command finished in a tab that was not in front (shell integration).
    pub notify_commands: bool,
    /// Only commands that ran at least this long are reported; 0 = every one.
    pub notify_command_seconds: u32,
    /// A file transfer finished or failed while the SFTP tab was not in front.
    pub notify_transfers: bool,
    /// SFTP transfer speed limit in KiB/s per transfer; 0 is unlimited.
    #[serde(default)]
    pub sftp_rate_limit_kib: u32,
    /// A live session was dropped by the network / server.
    pub notify_sessions: bool,
    /// Team and account: access to a shared vault, someone joined a shared
    /// terminal, this device was signed out remotely.
    pub notify_account: bool,
    /// Keyboard shortcut overrides: command id → chord (`ctrl+shift+k`), or
    /// an empty string to unbind. Commands not listed keep their defaults.
    pub shortcuts: BTreeMap<String, String>,
    /// SFTP "Open with" associations: lower-case extension (`""` = files
    /// without one) → application name or path.
    pub sftp_open_with: BTreeMap<String, String>,
}

/// Terminal emulation types offered in Settings; all have terminfo entries on
/// every mainstream distribution.
pub const TERM_TYPES: &[&str] = &[
    "xterm-256color",
    "xterm",
    "vt100",
    "vt220",
    "linux",
    "screen-256color",
    "tmux-256color",
];

/// Values accepted for [`Settings::language`]; `system` plus every bundled UI locale.
pub const LANGUAGES: &[&str] = &["system", "en", "ru"];

const MAX_SHORTCUTS: usize = 256;
const MAX_SHORTCUT_LEN: usize = 48;
const MAX_OPEN_WITH: usize = 256;

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: "dark".into(),
            language: "system".into(),
            hosts_view: "grid".into(),
            forwarding_view: "grid".into(),
            keychain_view: "grid".into(),
            terminal_font_size: 14,
            terminal_font_family: "JetBrains Mono".into(),
            terminal_line_height: 1.0,
            terminal_theme: "auto".into(),
            cursor_blink: true,
            cursor_style: "block".into(),
            scrollback: 10_000,
            copy_on_select: false,
            paste_on_right_click: false,
            confirm_close_tab: true,
            confirm_paste_multiline: true,
            autocomplete: true,
            shell_integration: true,
            triggers: Vec::new(),
            restore_commands: "type".into(),
            terminal_bell: false,
            bright_bold: false,
            term_type: "xterm-256color".into(),
            auto_reconnect: true,
            keyword_highlight: true,
            local_shell: String::new(),
            keep_alive_seconds: 30,
            detect_os: true,
            post_quantum_kex: true,
            use_ssh_agent: true,
            record_sessions: false,
            log_retention_days: 0,
            autostart_forwarding: true,
            serve_ssh_agent: false,
            run_automations: false,
            agent_confirm: true,
            minimize_to_tray: false,
            sync_conflict: "newest_wins".into(),
            sync_interval_seconds: 300,
            upload_logs: false,
            sync_credentials: true,
            update_check: "manual".into(),
            update_url: String::new(),
            lock_after_minutes: 0,
            welcome_seen: false,
            notifications: true,
            notify_commands: true,
            notify_command_seconds: 5,
            notify_transfers: true,
            sftp_rate_limit_kib: 0,
            notify_sessions: true,
            notify_account: true,
            shortcuts: BTreeMap::new(),
            sftp_open_with: BTreeMap::new(),
        }
    }
}

impl Settings {
    fn validate(&self) -> Result<()> {
        if !matches!(self.theme.as_str(), "dark" | "light" | "system") {
            return Err(DesktopError::invalid("theme must be dark, light or system"));
        }
        if !LANGUAGES.contains(&self.language.as_str()) {
            return Err(DesktopError::invalid(format!(
                "language must be one of {}",
                LANGUAGES.join(", ")
            )));
        }
        if !matches!(self.hosts_view.as_str(), "grid" | "list") {
            return Err(DesktopError::invalid("hostsView must be grid or list"));
        }
        if !matches!(self.forwarding_view.as_str(), "grid" | "list") {
            return Err(DesktopError::invalid("forwardingView must be grid or list"));
        }
        if !matches!(self.keychain_view.as_str(), "grid" | "list") {
            return Err(DesktopError::invalid("keychainView must be grid or list"));
        }
        if !matches!(self.cursor_style.as_str(), "block" | "underline" | "bar") {
            return Err(DesktopError::invalid(
                "cursorStyle must be block, underline or bar",
            ));
        }
        if !(6..=72).contains(&self.terminal_font_size) {
            return Err(DesktopError::invalid("terminalFontSize out of range"));
        }
        if !(0.8..=2.0).contains(&self.terminal_line_height) {
            return Err(DesktopError::invalid(
                "terminalLineHeight must be between 0.8 and 2.0",
            ));
        }
        if self.terminal_theme.is_empty() || self.terminal_theme.len() > 64 {
            return Err(DesktopError::invalid("terminalTheme must be 1-64 chars"));
        }
        if self.scrollback > 1_000_000 {
            return Err(DesktopError::invalid("scrollback too large"));
        }
        if self.sftp_rate_limit_kib > 1 << 20 {
            return Err(DesktopError::invalid("sftpRateLimitKib too large"));
        }
        if !TERM_TYPES.contains(&self.term_type.as_str()) {
            return Err(DesktopError::invalid(format!(
                "termType must be one of {}",
                TERM_TYPES.join(", ")
            )));
        }
        if self.local_shell.len() > 512 || self.local_shell.contains(['\0', '\n']) {
            return Err(DesktopError::invalid("localShell is invalid"));
        }
        if self.keep_alive_seconds > 3600 {
            return Err(DesktopError::invalid("keepAliveSeconds too large"));
        }
        if self.log_retention_days > 3650 {
            return Err(DesktopError::invalid("logRetentionDays too large"));
        }
        self.conflict_policy()?;
        if self.sync_interval_seconds != 0 && !(30..=86_400).contains(&self.sync_interval_seconds) {
            return Err(DesktopError::invalid(
                "syncIntervalSeconds must be 0 or between 30 and 86400",
            ));
        }
        if !matches!(self.restore_commands.as_str(), "type" | "run" | "never") {
            return Err(DesktopError::invalid(
                "restoreCommands must be type, run or never",
            ));
        }
        if !matches!(self.update_check.as_str(), "manual" | "startup") {
            return Err(DesktopError::invalid(
                "updateCheck must be manual or startup",
            ));
        }
        crate::update::feed_url(&self.update_url)?;
        if self.lock_after_minutes > 7 * 24 * 60 {
            return Err(DesktopError::invalid("lockAfterMinutes too large"));
        }
        if self.notify_command_seconds > 3600 {
            return Err(DesktopError::invalid("notifyCommandSeconds too large"));
        }
        if self.shortcuts.len() > MAX_SHORTCUTS {
            return Err(DesktopError::invalid("too many shortcut overrides"));
        }
        for (command, chord) in &self.shortcuts {
            let ok = |s: &str, max: usize| {
                !s.is_empty()
                    && s.len() <= max
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-' | '_'))
            };
            if !ok(command, 64) || !(chord.is_empty() || ok(chord, MAX_SHORTCUT_LEN)) {
                return Err(DesktopError::invalid("invalid shortcut entry"));
            }
        }
        if self.sftp_open_with.len() > MAX_OPEN_WITH {
            return Err(DesktopError::invalid("too many Open with associations"));
        }
        for (ext, app) in &self.sftp_open_with {
            if ext.len() > 32
                || ext.contains(['/', '\\', '.'])
                || app.trim().is_empty()
                || app.len() > 512
                || app.contains(['\0', '\n'])
            {
                return Err(DesktopError::invalid("invalid Open with association"));
            }
        }
        Ok(())
    }

    pub fn conflict_policy(&self) -> Result<ConflictPolicy> {
        match self.sync_conflict.as_str() {
            "newest_wins" => Ok(ConflictPolicy::NewestWins),
            "local_wins" => Ok(ConflictPolicy::LocalWins),
            "server_wins" => Ok(ConflictPolicy::ServerWins),
            _ => Err(DesktopError::invalid(
                "syncConflict must be newest_wins, local_wins or server_wins",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoso_core::model::Group;

    fn state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::open_at(dir.path().to_path_buf()).unwrap();
        (dir, state)
    }

    fn group(state: &AppState, name: &str) -> uuid::Uuid {
        let store = state.store().unwrap();
        let vault = store.local_vault().unwrap().id;
        store
            .insert(
                vault,
                &Group {
                    label: name.into(),
                    ..Group::default()
                },
            )
            .unwrap()
    }

    #[test]
    fn lock_cycle_keeps_data_and_refuses_wrong_password() {
        let (dir, state) = state();
        assert!(!state.is_locked());
        assert!(!state.password_protected());
        let id = group(&state, "before");
        let db_before = std::fs::read(dir.path().join(DB_FILE)).unwrap();

        state.set_master_password(None, "correct horse").unwrap();
        assert!(state.password_protected());
        assert_eq!(state.master_source(), MasterKeySource::Password);
        assert!(!dir.path().join("master.key").exists());
        // Wrapping the key does not touch the database.
        assert_eq!(std::fs::read(dir.path().join(DB_FILE)).unwrap(), db_before);

        assert!(state.close_store());
        assert!(state.is_locked());
        assert_eq!(state.store().unwrap_err().kind, "locked");
        assert_eq!(state.settings().unwrap_err().kind, "locked");

        assert_eq!(
            state
                .unlock_with_password("wrong password")
                .unwrap_err()
                .kind,
            "wrong_password"
        );
        assert!(state.is_locked());

        state.unlock_with_password("correct horse").unwrap();
        assert!(!state.is_locked());
        let g: Group = state.store().unwrap().require::<Group>(id).unwrap().data;
        assert_eq!(g.label, "before");
    }

    #[test]
    fn fresh_start_on_protected_profile_is_locked() {
        let (dir, state) = state();
        state.set_master_password(None, "correct horse").unwrap();
        drop(state);

        let state = AppState::open_at(dir.path().to_path_buf()).unwrap();
        assert!(state.is_locked());
        assert_eq!(state.master_source(), MasterKeySource::Password);
        state.unlock_with_password("correct horse").unwrap();
        assert!(!state.is_locked());
    }

    #[test]
    fn change_and_remove_password_need_the_current_one() {
        let (dir, state) = state();
        let id = group(&state, "kept");
        state.set_master_password(None, "first password").unwrap();
        assert_eq!(
            state
                .set_master_password(Some("nope nope"), "second password")
                .unwrap_err()
                .kind,
            "wrong_password"
        );
        assert_eq!(
            state
                .set_master_password(None, "second password")
                .unwrap_err()
                .kind,
            "wrong_password"
        );
        state
            .set_master_password(Some("first password"), "second password")
            .unwrap();
        state.close_store();
        assert_eq!(
            state
                .unlock_with_password("first password")
                .unwrap_err()
                .kind,
            "wrong_password"
        );
        state.unlock_with_password("second password").unwrap();

        assert_eq!(
            state
                .remove_master_password("first password")
                .unwrap_err()
                .kind,
            "wrong_password"
        );
        assert!(state.password_protected());
        let source = state.remove_master_password("second password").unwrap();
        assert_ne!(source, MasterKeySource::Password);
        assert!(!state.password_protected());
        assert!(!dir.path().join("master.pw").exists());
        drop(state);

        // Plain storage again: opens without a prompt and the data is there.
        let state = AppState::open_at(dir.path().to_path_buf()).unwrap();
        assert!(!state.is_locked());
        let g: Group = state.store().unwrap().require::<Group>(id).unwrap().data;
        assert_eq!(g.label, "kept");
    }

    #[test]
    fn lock_without_password_is_not_locked_on_restart() {
        let (dir, state) = state();
        assert!(state.close_store());
        assert!(state.is_locked());
        drop(state);
        let state = AppState::open_at(dir.path().to_path_buf()).unwrap();
        assert!(!state.is_locked());
    }

    #[test]
    fn idle_timeout_is_deterministic() {
        let lock = LockRuntime::default();
        let t0 = Instant::now();
        assert!(!lock.idle_expired(5, t0), "no activity yet → never lock");
        lock.touch_at(t0);
        assert!(
            !lock.idle_expired(0, t0 + Duration::from_secs(3600)),
            "0 = disabled"
        );
        assert!(!lock.idle_expired(5, t0 + Duration::from_secs(299)));
        assert!(lock.idle_expired(5, t0 + Duration::from_secs(300)));
        lock.touch_at(t0 + Duration::from_secs(290));
        assert!(
            !lock.idle_expired(5, t0 + Duration::from_secs(300)),
            "activity resets"
        );
        assert!(lock.idle_expired(5, t0 + Duration::from_secs(590)));
    }

    #[test]
    fn locked_state_rejects_vault_access_and_password_changes() {
        let (dir, state) = state();
        state.set_master_password(None, "correct horse").unwrap();
        assert!(state.close_store());
        let err = state.store().unwrap_err();
        assert_eq!(err.kind, "locked");
        assert_eq!(state.settings().unwrap_err().kind, "locked");
        assert_eq!(
            state
                .set_master_password(Some("correct horse"), "another one")
                .unwrap_err()
                .kind,
            "locked"
        );
        assert_eq!(
            state
                .remove_master_password("correct horse")
                .unwrap_err()
                .kind,
            "locked"
        );
        assert!(state.password_protected(), "wrapper untouched while locked");
        drop(dir);
    }

    #[test]
    fn defaults_validate_and_old_blobs_still_load() {
        Settings::default().validate().unwrap();
        // A blob written by an older build (fewer fields) must still parse.
        let s: Settings = serde_json::from_str(r#"{"theme":"light","scrollback":500}"#).unwrap();
        assert_eq!(s.theme, "light");
        assert_eq!(s.scrollback, 500);
        assert_eq!(s.cursor_style, "block");
        assert!(!s.record_sessions);
        assert!(s.shortcuts.is_empty());
        s.validate().unwrap();
    }

    #[test]
    fn shortcut_overrides_are_checked() {
        let mut s = Settings::default();
        s.shortcuts
            .insert("palette.commands".into(), "ctrl+k".into());
        s.shortcuts.insert("tab.new".into(), String::new());
        s.validate().unwrap();
        s.shortcuts
            .insert("tab.close".into(), "ctrl+<script>".into());
        assert!(s.validate().is_err());
        s.shortcuts.remove("tab.close");
        s.shortcuts.insert("bad id!".into(), "ctrl+w".into());
        assert!(s.validate().is_err());
    }

    #[test]
    fn open_with_associations_are_checked() {
        let mut s = Settings::default();
        s.sftp_open_with.insert("conf".into(), "code".into());
        s.sftp_open_with.insert("".into(), "/usr/bin/gedit".into());
        s.validate().unwrap();
        s.sftp_open_with.insert("tar.gz".into(), "code".into());
        assert!(s.validate().is_err());
        s.sftp_open_with.remove("tar.gz");
        s.sftp_open_with.insert("txt".into(), "ed\ncat".into());
        assert!(s.validate().is_err());
        s.sftp_open_with.remove("txt");
        s.sftp_open_with.insert("a/b".into(), "code".into());
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_bad_values() {
        let s = Settings {
            cursor_style: "blink".into(),
            ..Settings::default()
        };
        assert!(s.validate().is_err());
        let s = Settings {
            sync_conflict: "coin_flip".into(),
            ..Settings::default()
        };
        assert!(s.validate().is_err());
        let mut s = Settings {
            sync_interval_seconds: 5,
            ..Settings::default()
        };
        assert!(s.validate().is_err());
        s.sync_interval_seconds = 0;
        assert!(s.validate().is_ok());
        let s = Settings {
            log_retention_days: 100_000,
            ..Settings::default()
        };
        assert!(s.validate().is_err());
    }
}
