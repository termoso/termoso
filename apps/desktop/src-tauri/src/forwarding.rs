//! Port forwarding: stored rules (`pf_rule` entities) plus the runtime
//! registry of tunnels currently open. Connections reuse the same SSH path
//! as terminals (jump hosts, prompts, stored credentials); the webview only
//! sees rule metadata and traffic counters.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, Runtime};
use termoso_core::error::CoreError;
use termoso_core::forward::{Forward, ForwardSpec};
use termoso_core::model::{Host, PfRule};
use termoso_core::ssh::SshClient;
use termoso_core::store::{LocalVaultKind, Store};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::error::{DesktopError, Result};
use crate::hosts;
use crate::sessions;
use crate::state::AppState;

pub const FORWARD_EVENT: &str = "forward";

/// Retries after the SSH transport of a running tunnel drops (when the
/// `autoReconnect` setting is on). Delays: 2, 4, 8, 16, 32, 60 seconds.
const RECONNECT_ATTEMPTS: u32 = 6;
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(60);

fn reconnect_delay(attempt: u32) -> Duration {
    Duration::from_secs(2u64 << attempt.saturating_sub(1).min(8)).min(RECONNECT_MAX_DELAY)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PfKind {
    Local,
    Remote,
    Dynamic,
}

impl From<termoso_core::import::PfKind> for PfKind {
    fn from(k: termoso_core::import::PfKind) -> Self {
        match k {
            termoso_core::import::PfKind::Local => Self::Local,
            termoso_core::import::PfKind::Remote => Self::Remote,
            termoso_core::import::PfKind::Dynamic => Self::Dynamic,
        }
    }
}

impl PfKind {
    fn as_str(self) -> &'static str {
        match self {
            PfKind::Local => "local",
            PfKind::Remote => "remote",
            PfKind::Dynamic => "dynamic",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "local" => Ok(PfKind::Local),
            "remote" => Ok(PfKind::Remote),
            "dynamic" => Ok(PfKind::Dynamic),
            other => Err(DesktopError::invalid(format!(
                "unknown forwarding kind {other:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PfState {
    Stopped,
    Starting,
    Running,
    /// Transport dropped; a retry is scheduled (`attempt`, `next_retry_at`).
    Reconnecting,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PfRuntime {
    pub state: PfState,
    pub started_at: Option<DateTime<Utc>>,
    /// Address actually bound (local/dynamic) or the port the server opened
    /// (remote).
    pub bound: Option<String>,
    pub connections: u64,
    pub active: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub last_error: Option<String>,
    /// Reconnect attempt number (0 unless `state == Reconnecting`).
    pub attempt: u32,
    pub next_retry_at: Option<DateTime<Utc>>,
}

impl PfRuntime {
    fn stopped(last_error: Option<String>) -> Self {
        Self {
            state: PfState::Stopped,
            started_at: None,
            bound: None,
            connections: 0,
            active: 0,
            bytes_in: 0,
            bytes_out: 0,
            last_error,
            attempt: 0,
            next_retry_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PfRuleCard {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub label: String,
    pub host_id: Uuid,
    pub host_label: String,
    pub kind: PfKind,
    pub bound_address: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub auto_start: bool,
    pub updated_at: DateTime<Utc>,
    pub runtime: PfRuntime,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PfRuleForm {
    pub id: Option<Uuid>,
    pub vault_id: Uuid,
    pub label: String,
    pub host_id: Uuid,
    pub kind: PfKind,
    #[serde(default)]
    pub bound_address: String,
    pub local_port: u16,
    #[serde(default)]
    pub remote_host: String,
    #[serde(default)]
    pub remote_port: u16,
    #[serde(default)]
    pub auto_start: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ForwardEvent {
    Changed { id: Uuid, runtime: PfRuntime },
}

struct LiveForward {
    forward: Forward,
    started_at: DateTime<Utc>,
    /// Transport (+ jump hosts) kept alive for the tunnel's lifetime.
    #[allow(dead_code)]
    client: Arc<SshClient>,
    #[allow(dead_code)]
    jumps: Vec<Arc<SshClient>>,
    watcher: JoinHandle<()>,
}

struct Reconnecting {
    /// Identifies the retry loop that owns this entry.
    generation: u64,
    attempt: u32,
    next_at: DateTime<Utc>,
    reason: String,
    cancel: CancellationToken,
}

#[derive(Default)]
pub struct Forwards {
    live: Mutex<HashMap<Uuid, Arc<LiveForward>>>,
    pending: Mutex<HashMap<Uuid, CancellationToken>>,
    reconnecting: Mutex<HashMap<Uuid, Reconnecting>>,
    errors: Mutex<HashMap<Uuid, String>>,
}

impl Forwards {
    /// Register a manual / scheduled start. Supersedes a pending retry.
    fn begin(&self, id: Uuid) -> Result<CancellationToken> {
        if self
            .live
            .lock()
            .expect("forwards poisoned")
            .contains_key(&id)
        {
            return Err(DesktopError::invalid("forwarding rule is already running"));
        }
        let mut pending = self.pending.lock().expect("forwards poisoned");
        if pending.contains_key(&id) {
            return Err(DesktopError::invalid("forwarding rule is already starting"));
        }
        let tok = CancellationToken::new();
        pending.insert(id, tok.clone());
        self.cancel_reconnect(id);
        self.errors.lock().expect("forwards poisoned").remove(&id);
        Ok(tok)
    }

    fn set_reconnecting(&self, id: Uuid, entry: Reconnecting) {
        self.reconnecting
            .lock()
            .expect("forwards poisoned")
            .insert(id, entry);
    }

    /// Remove the retry entry if it still belongs to loop `generation`.
    fn take_reconnecting(&self, id: Uuid, generation: u64) -> bool {
        let mut map = self.reconnecting.lock().expect("forwards poisoned");
        match map.get(&id) {
            Some(r) if r.generation == generation => {
                map.remove(&id);
                true
            }
            _ => false,
        }
    }

    fn cancel_reconnect(&self, id: Uuid) -> bool {
        match self
            .reconnecting
            .lock()
            .expect("forwards poisoned")
            .remove(&id)
        {
            Some(r) => {
                r.cancel.cancel();
                true
            }
            None => false,
        }
    }

    /// Running, starting and retrying rules.
    pub fn all_ids(&self) -> Vec<Uuid> {
        let mut ids = self.running_ids();
        ids.extend(self.pending.lock().expect("forwards poisoned").keys());
        ids.extend(self.reconnecting.lock().expect("forwards poisoned").keys());
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    fn cancel_pending(&self, id: Uuid) {
        if let Some(tok) = self.pending.lock().expect("forwards poisoned").remove(&id) {
            tok.cancel();
        }
    }

    fn finish_pending(&self, id: Uuid) -> bool {
        self.pending
            .lock()
            .expect("forwards poisoned")
            .remove(&id)
            .is_some()
    }

    fn remove(&self, id: Uuid) -> Option<Arc<LiveForward>> {
        if let Some(tok) = self.pending.lock().expect("forwards poisoned").remove(&id) {
            tok.cancel();
        }
        self.cancel_reconnect(id);
        self.live.lock().expect("forwards poisoned").remove(&id)
    }

    fn set_error(&self, id: Uuid, message: String) {
        self.errors
            .lock()
            .expect("forwards poisoned")
            .insert(id, message);
    }

    pub fn runtime(&self, id: Uuid) -> PfRuntime {
        if let Some(live) = self.live.lock().expect("forwards poisoned").get(&id) {
            let stats = live.forward.stats();
            let bound = match live.forward.spec() {
                ForwardSpec::Remote { bind, .. } => {
                    live.forward.remote_port().map(|p| format!("{bind}:{p}"))
                }
                _ => live.forward.local_addr().map(|a| a.to_string()),
            };
            return PfRuntime {
                state: PfState::Running,
                started_at: Some(live.started_at),
                bound,
                connections: stats.connections.load(Ordering::Relaxed),
                active: stats.active.load(Ordering::Relaxed),
                bytes_in: stats.bytes_in.load(Ordering::Relaxed),
                bytes_out: stats.bytes_out.load(Ordering::Relaxed),
                last_error: None,
                attempt: 0,
                next_retry_at: None,
            };
        }
        if self
            .pending
            .lock()
            .expect("forwards poisoned")
            .contains_key(&id)
        {
            return PfRuntime {
                state: PfState::Starting,
                ..PfRuntime::stopped(None)
            };
        }
        if let Some(r) = self
            .reconnecting
            .lock()
            .expect("forwards poisoned")
            .get(&id)
        {
            return PfRuntime {
                state: PfState::Reconnecting,
                attempt: r.attempt,
                next_retry_at: Some(r.next_at),
                ..PfRuntime::stopped(Some(r.reason.clone()))
            };
        }
        PfRuntime::stopped(
            self.errors
                .lock()
                .expect("forwards poisoned")
                .get(&id)
                .cloned(),
        )
    }

    pub fn running_ids(&self) -> Vec<Uuid> {
        self.live
            .lock()
            .expect("forwards poisoned")
            .keys()
            .copied()
            .collect()
    }

    /// Running tunnels with the time each came up.
    pub fn running_since(&self) -> Vec<(Uuid, DateTime<Utc>)> {
        self.live
            .lock()
            .expect("forwards poisoned")
            .iter()
            .map(|(id, l)| (*id, l.started_at))
            .collect()
    }
}

// ───────────────────────────── rules (store) ─────────────────────────────

/// Labels are optional (an unlabelled card shows its route instead).
fn validate(form: &PfRuleForm) -> Result<PfRule> {
    let label = form.label.trim();
    if form.local_port == 0 {
        return Err(DesktopError::invalid(match form.kind {
            PfKind::Remote => "local port is required",
            _ => "port to listen on is required",
        }));
    }
    let bound_address = form.bound_address.trim().to_string();
    let remote_host = form.remote_host.trim().to_string();
    match form.kind {
        PfKind::Local => {
            if remote_host.is_empty() {
                return Err(DesktopError::invalid("destination host is required"));
            }
            if form.remote_port == 0 {
                return Err(DesktopError::invalid("destination port is required"));
            }
        }
        PfKind::Remote => {
            if form.remote_port == 0 {
                return Err(DesktopError::invalid("remote port is required"));
            }
        }
        PfKind::Dynamic => {}
    }
    Ok(PfRule {
        label: label.to_string(),
        host_id: form.host_id,
        kind: form.kind.as_str().to_string(),
        bound_address,
        local_port: form.local_port,
        remote_host,
        remote_port: form.remote_port,
        auto_start: form.auto_start,
    })
}

fn card(
    forwards: &Forwards,
    e: &termoso_core::model::Entity<PfRule>,
    hosts: &HashMap<Uuid, String>,
) -> Result<PfRuleCard> {
    Ok(PfRuleCard {
        id: e.id,
        vault_id: e.vault_id,
        label: e.data.label.clone(),
        host_id: e.data.host_id,
        host_label: hosts
            .get(&e.data.host_id)
            .cloned()
            .unwrap_or_else(|| "(missing host)".into()),
        kind: PfKind::parse(&e.data.kind)?,
        bound_address: e.data.bound_address.clone(),
        local_port: e.data.local_port,
        remote_host: e.data.remote_host.clone(),
        remote_port: e.data.remote_port,
        auto_start: e.data.auto_start,
        updated_at: e.updated_at,
        runtime: forwards.runtime(e.id),
    })
}

fn host_labels(store: &Store, vault_id: Option<Uuid>) -> Result<HashMap<Uuid, String>> {
    Ok(store
        .list::<Host>(vault_id)?
        .into_iter()
        .map(|h| (h.id, h.data.label))
        .collect())
}

pub fn rules(state: &AppState, vault_id: Option<Uuid>) -> Result<Vec<PfRuleCard>> {
    let hosts = host_labels(&*state.store()?, vault_id)?;
    let mut out = Vec::new();
    for e in state.store()?.list::<PfRule>(vault_id)? {
        out.push(card(&state.forwards, &e, &hosts)?);
    }
    out.sort_by_key(|a| a.label.to_lowercase());
    Ok(out)
}

pub fn rule(state: &AppState, id: Uuid) -> Result<PfRuleCard> {
    let e = state.store()?.require::<PfRule>(id)?;
    let hosts = host_labels(&*state.store()?, Some(e.vault_id))?;
    card(&state.forwards, &e, &hosts)
}

pub fn save(state: &AppState, form: &PfRuleForm) -> Result<PfRuleCard> {
    let data = validate(form)?;
    let host = state.store()?.require::<Host>(form.host_id)?;
    if host.vault_id != form.vault_id {
        return Err(DesktopError::invalid("host belongs to another vault"));
    }
    if host.data.ssh_config_id.is_none() && host.data.telnet_config_id.is_some() {
        return Err(DesktopError::invalid("telnet hosts cannot forward ports"));
    }
    let id = match form.id {
        Some(id) => {
            state.store()?.require::<PfRule>(id)?;
            state.store()?.update(id, &data)?;
            id
        }
        None => state.store()?.insert(form.vault_id, &data)?,
    };
    rule(state, id)
}

/// Duplicate a rule next to the original ("<label> copy"), not running.
pub fn duplicate(state: &AppState, id: Uuid) -> Result<PfRuleCard> {
    let src = state.store()?.require::<PfRule>(id)?;
    let mut data = src.data.clone();
    if !data.label.is_empty() {
        data.label = format!("{} copy", data.label);
    }
    let new_id = state.store()?.insert(src.vault_id, &data)?;
    rule(state, new_id)
}

/// Copy a rule into another (unlocked) vault. The host it goes through is
/// reused when the target vault already has one with the same label and
/// address, otherwise copied along with the rule. Into a team vault the host
/// arrives without credentials: sharing them is an explicit choice made on the
/// Hosts page, never a side effect of copying a rule.
pub fn copy_to_vault(state: &AppState, id: Uuid, vault_id: Uuid) -> Result<PfRuleCard> {
    let src = state.store()?.require::<PfRule>(id)?;
    if src.vault_id == vault_id {
        return Err(DesktopError::invalid("rule is already in that vault"));
    }
    let vault = state.store()?.vault(vault_id)?;
    if !vault.unlocked {
        return Err(DesktopError::invalid("target vault is locked"));
    }
    let creds = if vault.kind == LocalVaultKind::Team {
        hosts::CopyCredentials::Personal
    } else {
        hosts::CopyCredentials::Shared
    };
    let host = state.store()?.require::<Host>(src.data.host_id)?;
    let host_id = match state
        .store()?
        .list::<Host>(Some(vault_id))?
        .into_iter()
        .find(|h| h.data.label == host.data.label && h.data.address == host.data.address)
    {
        Some(h) => h.id,
        None => hosts::copy_to_vault(&*state.store()?, &[host.id], vault_id, creds)?
            .into_iter()
            .next()
            .ok_or_else(|| DesktopError::not_found(format!("host {}", host.id)))?,
    };
    let data = PfRule {
        host_id,
        ..src.data.clone()
    };
    let new_id = state.store()?.insert(vault_id, &data)?;
    rule(state, new_id)
}

/// Move a rule into another vault: copy, stop and delete the original.
pub async fn move_to_vault<R: Runtime>(
    app: &AppHandle<R>,
    id: Uuid,
    vault_id: Uuid,
) -> Result<PfRuleCard> {
    let state = app.state::<AppState>();
    let copied = copy_to_vault(&state, id, vault_id)?;
    delete(app, id).await?;
    Ok(copied)
}

pub async fn delete<R: Runtime>(app: &AppHandle<R>, id: Uuid) -> Result<()> {
    stop(app, id).await?;
    let state = app.state::<AppState>();
    state.store()?.require::<PfRule>(id)?;
    state.store()?.delete(id)?;
    state
        .forwards
        .errors
        .lock()
        .expect("forwards poisoned")
        .remove(&id);
    Ok(())
}

// ───────────────────────────── runtime ─────────────────────────────

fn emit<R: Runtime>(app: &AppHandle<R>, id: Uuid) {
    let state = app.state::<AppState>();
    let runtime = state.forwards.runtime(id);
    let _ = app.emit(FORWARD_EVENT, ForwardEvent::Changed { id, runtime });
    crate::presence::refresh(app);
}

/// Open the tunnel for rule `id`. Prompts (host key, password…) are routed
/// under the rule id, so the UI can answer or cancel them like a session.
pub async fn start<R: Runtime>(app: &AppHandle<R>, id: Uuid) -> Result<PfRuleCard> {
    let state = app.state::<AppState>();
    let e = state.store()?.require::<PfRule>(id)?;
    if let Some(d) = termoso_core::policy::check_forward(
        &*state.store()?,
        e.vault_id,
        &e.data.kind,
        e.data.remote_port,
    ) {
        return Err(DesktopError::invalid(d.message()));
    }
    let spec = ForwardSpec::from_rule(&e.data)?;
    let cancel = state.forwards.begin(id)?;
    emit(app, id);

    // A rule only ever tunnels through a host of its own vault.
    let result = tokio::select! {
        r = sessions::connect_host(app, id, e.data.host_id, Some(e.vault_id)) => r,
        _ = cancel.cancelled() => Err(CoreError::Cancelled.into()),
    };
    state.prompts.cancel_session(id);
    let still_wanted = state.forwards.finish_pending(id);
    let conn = match result {
        Ok(c) if still_wanted => c,
        Ok(_) => {
            emit(app, id);
            return Err(CoreError::Cancelled.into());
        }
        Err(err) => {
            state.forwards.set_error(id, err.message.clone());
            emit(app, id);
            return Err(err);
        }
    };

    let forward = match Forward::start(conn.client.clone(), spec).await {
        Ok(f) => f,
        Err(err) => {
            let err: DesktopError = err.into();
            let _ = conn.client.disconnect().await;
            state.forwards.set_error(id, err.message.clone());
            emit(app, id);
            return Err(err);
        }
    };

    let watcher = {
        let app = app.clone();
        let client = conn.client.clone();
        tokio::spawn(async move {
            let reason = client.closed().await;
            let state = app.state::<AppState>();
            if state.forwards.remove(id).is_some() {
                let reason = format!("connection lost: {reason}");
                let retry = state.settings().map(|s| s.auto_reconnect).unwrap_or(false);
                if retry {
                    schedule_reconnect(&app, id, reason);
                } else {
                    state.forwards.set_error(id, reason);
                    emit(&app, id);
                }
            }
        })
    };

    state
        .forwards
        .live
        .lock()
        .expect("forwards poisoned")
        .insert(
            id,
            Arc::new(LiveForward {
                forward,
                started_at: Utc::now(),
                client: conn.client,
                jumps: conn.jumps,
                watcher,
            }),
        );
    emit(app, id);
    rule(&state, id)
}

static RECONNECT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Retry `start` with exponential backoff after the transport dropped. The
/// loop ends when the tunnel is back, when `stop` / `delete` / a manual start
/// supersede it, or after `RECONNECT_ATTEMPTS` failures (the rule is then left
/// stopped with the last error).
fn schedule_reconnect<R: Runtime>(app: &AppHandle<R>, id: Uuid, reason: String) {
    let app = app.clone();
    let generation = RECONNECT_GENERATION.fetch_add(1, Ordering::Relaxed);
    let cancel = CancellationToken::new();
    tokio::spawn(async move {
        let state = app.state::<AppState>();
        let mut reason = reason;
        for attempt in 1..=RECONNECT_ATTEMPTS {
            let delay = reconnect_delay(attempt);
            let next_at =
                Utc::now() + chrono::Duration::from_std(delay).unwrap_or(chrono::Duration::zero());
            state.forwards.set_reconnecting(
                id,
                Reconnecting {
                    generation,
                    attempt,
                    next_at,
                    reason: reason.clone(),
                    cancel: cancel.clone(),
                },
            );
            emit(&app, id);
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = cancel.cancelled() => return,
            }
            if !state.forwards.take_reconnecting(id, generation) {
                return;
            }
            match start(&app, id).await {
                Ok(_) => return,
                Err(err) if err.kind == "cancelled" || err.kind == "not_found" => return,
                Err(err) => reason = err.message,
            }
        }
        state.forwards.set_error(
            id,
            format!("{reason} (gave up after {RECONNECT_ATTEMPTS} attempts)"),
        );
        emit(&app, id);
    });
}

/// Stop every tunnel, abort starts in flight and drop retry loops.
pub async fn stop_all<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<AppState>();
    let ids = state.forwards.all_ids();
    for id in ids {
        state.forwards.cancel_pending(id);
        if let Err(e) = stop(app, id).await {
            tracing::debug!(rule = %id, "stop on lock: {e}");
        }
    }
}

pub async fn stop<R: Runtime>(app: &AppHandle<R>, id: Uuid) -> Result<()> {
    let state = app.state::<AppState>();
    state.prompts.cancel_session(id);
    let retrying = state.forwards.cancel_reconnect(id);
    if let Some(live) = state.forwards.remove(id) {
        live.watcher.abort();
        live.forward.stop().await;
        let _ = live.client.disconnect().await;
        emit(app, id);
    } else if retrying {
        emit(app, id);
    }
    Ok(())
}

/// Start every rule flagged `auto_start` that is not already running.
/// Failures are recorded per rule and do not abort the others.
pub async fn autostart<R: Runtime>(app: &AppHandle<R>) -> Result<Vec<Uuid>> {
    let state = app.state::<AppState>();
    let running = state.forwards.running_ids();
    let mut started = Vec::new();
    for e in state.store()?.list::<PfRule>(None)? {
        if e.data.auto_start && !running.contains(&e.id) && start(app, e.id).await.is_ok() {
            started.push(e.id);
        }
    }
    Ok(started)
}

/// Snapshot of every rule's runtime counters (cheap; polled by the UI).
pub fn runtimes(state: &AppState) -> Result<HashMap<Uuid, PfRuntime>> {
    Ok(state
        .store()?
        .list::<PfRule>(None)?
        .into_iter()
        .map(|e| (e.id, state.forwards.runtime(e.id)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(kind: PfKind) -> PfRuleForm {
        PfRuleForm {
            id: None,
            vault_id: Uuid::new_v4(),
            label: "db".into(),
            host_id: Uuid::new_v4(),
            kind,
            bound_address: String::new(),
            local_port: 5432,
            remote_host: "127.0.0.1".into(),
            remote_port: 5432,
            auto_start: false,
        }
    }

    #[test]
    fn validation_per_kind() {
        assert!(validate(&form(PfKind::Local)).is_ok());
        assert!(validate(&form(PfKind::Remote)).is_ok());
        assert!(validate(&form(PfKind::Dynamic)).is_ok());

        let mut f = form(PfKind::Local);
        f.remote_host.clear();
        assert!(validate(&f).is_err());
        let mut f = form(PfKind::Local);
        f.remote_port = 0;
        assert!(validate(&f).is_err());
        let mut f = form(PfKind::Dynamic);
        f.remote_host.clear();
        f.remote_port = 0;
        assert!(validate(&f).is_ok());
        let mut f = form(PfKind::Dynamic);
        f.local_port = 0;
        assert!(validate(&f).is_err());
        let mut f = form(PfKind::Remote);
        f.label = "  ".into();
        assert_eq!(validate(&f).unwrap().label, "");
    }

    #[test]
    fn stored_rule_converts_to_core_spec() {
        let rule = validate(&form(PfKind::Local)).unwrap();
        assert_eq!(rule.kind, "local");
        let spec = ForwardSpec::from_rule(&rule).unwrap();
        assert!(matches!(
            spec,
            ForwardSpec::Local {
                port: 5432,
                remote_port: 5432,
                ..
            }
        ));
        let rule = validate(&form(PfKind::Dynamic)).unwrap();
        assert!(matches!(
            ForwardSpec::from_rule(&rule).unwrap(),
            ForwardSpec::Dynamic { port: 5432, .. }
        ));
    }

    #[test]
    fn runtime_reports_stopped_with_last_error() {
        let f = Forwards::default();
        let id = Uuid::new_v4();
        assert_eq!(f.runtime(id).state, PfState::Stopped);
        let tok = f.begin(id).unwrap();
        assert_eq!(f.runtime(id).state, PfState::Starting);
        assert!(f.begin(id).is_err());
        assert!(f.finish_pending(id));
        assert!(!tok.is_cancelled());
        f.set_error(id, "nope".into());
        let rt = f.runtime(id);
        assert_eq!(rt.state, PfState::Stopped);
        assert_eq!(rt.last_error.as_deref(), Some("nope"));
        assert!(f.begin(id).is_ok());
        assert!(f.runtime(id).last_error.is_none());
    }

    #[test]
    fn reconnect_backoff_is_capped() {
        let secs: Vec<u64> = (1..=RECONNECT_ATTEMPTS)
            .map(|a| reconnect_delay(a).as_secs())
            .collect();
        assert_eq!(secs, vec![2, 4, 8, 16, 32, 60]);
        assert_eq!(reconnect_delay(40), RECONNECT_MAX_DELAY);
    }

    #[test]
    fn reconnecting_state_is_reported_and_superseded() {
        let f = Forwards::default();
        let id = Uuid::new_v4();
        let cancel = CancellationToken::new();
        f.set_reconnecting(
            id,
            Reconnecting {
                generation: 7,
                attempt: 2,
                next_at: Utc::now(),
                reason: "connection lost: eof".into(),
                cancel: cancel.clone(),
            },
        );
        let rt = f.runtime(id);
        assert_eq!(rt.state, PfState::Reconnecting);
        assert_eq!(rt.attempt, 2);
        assert!(rt.next_retry_at.is_some());
        assert_eq!(rt.last_error.as_deref(), Some("connection lost: eof"));

        // Another loop's generation cannot take the entry.
        assert!(!f.take_reconnecting(id, 8));
        // A manual start cancels the scheduled retry.
        assert!(f.begin(id).is_ok());
        assert!(cancel.is_cancelled());
        assert_eq!(f.runtime(id).state, PfState::Starting);
        assert!(!f.take_reconnecting(id, 7));
        assert!(f.finish_pending(id));

        let cancel = CancellationToken::new();
        f.set_reconnecting(
            id,
            Reconnecting {
                generation: 9,
                attempt: 1,
                next_at: Utc::now(),
                reason: String::new(),
                cancel: cancel.clone(),
            },
        );
        assert!(f.take_reconnecting(id, 9));
        assert!(!cancel.is_cancelled());
        assert_eq!(f.runtime(id).state, PfState::Stopped);
        assert!(!f.cancel_reconnect(id));
    }
}
