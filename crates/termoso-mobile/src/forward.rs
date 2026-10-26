//! Port forwarding: stored rules (`PfRule` entities, shared with desktop and
//! synced like hosts) and live tunnels. A [`PfTunnel`] owns one SSH
//! connection for the lifetime of one rule's tunnel, connects through the
//! same [`Connector`] as terminals and SFTP (stored credentials, host keys,
//! prompts), and reconnects with backoff when the transport drops.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use termoso_core::forward::{Forward, ForwardSpec};
use termoso_core::model::{Entity, Host, PfRule, ResolvedHost};
use termoso_core::ssh::{SshClient, SshTarget};
use termoso_core::store::Store;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::connect::{
    ConnectStage, ConnectUi, Connector, PromptAnswer, PromptRequest, SecretCache, connect_resolved,
    stage_label,
};
use crate::dto::{millis, parse_id, parse_opt_id};
use crate::error::{MobileError, Result};
use crate::presence::Slot;
use crate::settings::MobileSettings;

/// Retries after the transport of a running tunnel drops: 2, 4, 8, 16, 32, 60 s.
const RECONNECT_ATTEMPTS: u32 = 6;
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(60);

fn reconnect_delay(attempt: u32) -> Duration {
    Duration::from_secs(2u64 << attempt.saturating_sub(1).min(8)).min(RECONNECT_MAX_DELAY)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PfKind {
    Local,
    Remote,
    Dynamic,
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
            other => Err(MobileError::invalid(format!(
                "unknown forwarding kind {other:?}"
            ))),
        }
    }
}

/// A stored rule, ready to display.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PfRuleItem {
    pub id: String,
    pub vault_id: String,
    /// May be empty: the UI shows the route instead.
    pub label: String,
    pub host_id: String,
    pub host_label: String,
    /// `true` when the host the rule points at is gone.
    pub host_missing: bool,
    pub kind: PfKind,
    /// Bind address; empty = `127.0.0.1` (local / dynamic) or the server default (remote).
    pub bound_address: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub auto_start: bool,
    pub updated_at: i64,
    /// `ssh -L/-R/-D` style route for cards.
    pub route: String,
}

/// Editor payload; `id == None` creates.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PfRuleDraft {
    pub id: Option<String>,
    pub vault_id: String,
    pub label: String,
    pub host_id: String,
    pub kind: PfKind,
    pub bound_address: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub auto_start: bool,
}

/// Where a tunnel is in its life.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TunnelState {
    /// Connecting; `stage` is what to show (localised by the UI), `hop` the
    /// jump host it belongs to, `detail` the English rendering of both.
    Connecting {
        detail: String,
        stage: ConnectStage,
        hop: Option<String>,
    },
    /// Listening. `bound` is the local socket (local / dynamic) or the port
    /// the server opened (remote).
    Running {
        bound: String,
    },
    /// Transport dropped; retrying after `retry_in_secs`.
    Reconnecting {
        attempt: u32,
        retry_in_secs: u32,
        reason: String,
    },
    Failed {
        kind: String,
        message: String,
    },
    Stopped,
}

/// Live counters.
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct TunnelStats {
    pub connections: u64,
    pub active: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Callbacks into Kotlin, from Rust worker threads.
#[uniffi::export(with_foreign)]
pub trait TunnelListener: Send + Sync {
    fn on_state(&self, state: TunnelState);
    /// Answer with [`PfTunnel::answer`] using the same `prompt_id`.
    fn on_prompt(&self, prompt_id: u64, request: PromptRequest);
}

struct TunnelUi {
    listener: Arc<dyn TunnelListener>,
    state: Arc<Mutex<TunnelState>>,
}

impl TunnelState {
    fn connecting(stage: ConnectStage, hop: Option<String>) -> Self {
        Self::Connecting {
            detail: stage_label(&stage, hop.as_deref()),
            stage,
            hop,
        }
    }
}

impl ConnectUi for TunnelUi {
    fn phase(&self, stage: ConnectStage, hop: Option<String>) {
        let state = TunnelState::connecting(stage, hop);
        *self.state.lock().expect("state poisoned") = state.clone();
        self.listener.on_state(state);
    }

    fn prompt(&self, prompt_id: u64, request: PromptRequest) {
        self.listener.on_prompt(prompt_id, request);
    }
}

struct Live {
    forward: Forward,
    client: Arc<SshClient>,
    /// Kept alive for the duration of `client`.
    _jumps: Vec<Arc<SshClient>>,
}

struct Inner {
    conn: Arc<Connector>,
    listener: Arc<dyn TunnelListener>,
    state: Arc<Mutex<TunnelState>>,
    live: Mutex<Option<Arc<Live>>>,
    /// Fired by `stop`: aborts the connect, the tunnel and any retry.
    stopped: CancellationToken,
    /// Team presence registration for the rule's host.
    presence: Slot,
}

/// One rule's tunnel. Drop-safe: dropping the last reference stops it.
#[derive(uniffi::Object)]
pub struct PfTunnel {
    rule_id: Uuid,
    inner: Arc<Inner>,
    runtime: tokio::runtime::Handle,
}

pub(crate) struct TunnelLaunch {
    pub store: Arc<Store>,
    pub secrets: Arc<SecretCache>,
    pub rule: Entity<PfRule>,
    pub settings: MobileSettings,
    pub listener: Arc<dyn TunnelListener>,
    pub presence: Slot,
}

impl PfTunnel {
    pub(crate) fn launch(runtime: tokio::runtime::Handle, launch: TunnelLaunch) -> Arc<Self> {
        let TunnelLaunch {
            store,
            secrets,
            rule,
            settings,
            listener,
            presence,
        } = launch;
        let state = Arc::new(Mutex::new(TunnelState::connecting(
            ConnectStage::Connecting,
            None,
        )));
        let conn = Arc::new(Connector::new(
            store.clone(),
            secrets.clone(),
            Arc::new(TunnelUi {
                listener: listener.clone(),
                state: state.clone(),
            }),
        ));
        let inner = Arc::new(Inner {
            conn,
            listener,
            state,
            live: Mutex::new(None),
            stopped: CancellationToken::new(),
            presence,
        });
        let tunnel = Arc::new(Self {
            rule_id: rule.id,
            inner: inner.clone(),
            runtime: runtime.clone(),
        });
        runtime.spawn(run(inner, store, rule, settings));
        tunnel
    }
}

#[uniffi::export]
impl PfTunnel {
    /// Id of the rule this tunnel serves.
    pub fn rule_id(&self) -> String {
        self.rule_id.to_string()
    }

    pub fn state(&self) -> TunnelState {
        self.inner.state.lock().expect("state poisoned").clone()
    }

    pub fn stats(&self) -> TunnelStats {
        match self.inner.live.lock().expect("live poisoned").as_ref() {
            Some(live) => {
                let s = live.forward.stats();
                TunnelStats {
                    connections: s.connections.load(Ordering::Relaxed),
                    active: s.active.load(Ordering::Relaxed),
                    bytes_in: s.bytes_in.load(Ordering::Relaxed),
                    bytes_out: s.bytes_out.load(Ordering::Relaxed),
                }
            }
            None => TunnelStats::default(),
        }
    }

    /// Reply to a prompt raised through the listener.
    pub fn answer(&self, prompt_id: u64, answer: PromptAnswer) -> bool {
        self.inner.conn.answer(prompt_id, answer)
    }

    /// Close the tunnel and its connection; the object stays usable for `state()`.
    pub fn stop(&self) {
        self.inner.conn.cancel_prompts();
        self.inner.stopped.cancel();
        let live = self.inner.live.lock().expect("live poisoned").take();
        if let Some(live) = live {
            self.runtime.spawn(async move {
                live.forward.stop().await;
                let _ = live.client.disconnect().await;
            });
        }
    }
}

impl Drop for PfTunnel {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Inner {
    fn set_state(&self, state: TunnelState) {
        match state {
            TunnelState::Running { .. } => self.presence.connected(),
            TunnelState::Connecting { .. }
            | TunnelState::Reconnecting { .. }
            | TunnelState::Failed { .. }
            | TunnelState::Stopped => self.presence.gone(),
        }
        *self.state.lock().expect("state poisoned") = state.clone();
        self.listener.on_state(state);
    }
}

fn bound_label(forward: &Forward, spec: &ForwardSpec) -> String {
    match spec {
        ForwardSpec::Remote { bind, .. } => {
            let port = forward.remote_port().unwrap_or_default();
            let host = if bind.is_empty() { "localhost" } else { bind };
            format!("{host}:{port} on server")
        }
        _ => forward
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default(),
    }
}

async fn open_once(
    inner: &Arc<Inner>,
    store: &Store,
    rule: &Entity<PfRule>,
    settings: &MobileSettings,
) -> Result<Live> {
    // A rule only ever tunnels through a host of its own vault.
    let resolved = store.resolve_host_in(rule.data.host_id, Some(rule.vault_id))?;
    if resolved.protocol() != "ssh" {
        return Err(MobileError::invalid("telnet hosts cannot forward ports"));
    }
    let target = SshTarget {
        host: resolved.host.data.address.clone(),
        port: resolved.port(),
        username: resolved.username().unwrap_or_default(),
    };
    let spec = ForwardSpec::from_rule(&rule.data)?;
    let (client, jumps) = connect_resolved(&inner.conn, settings, target, Some(&resolved)).await?;
    inner.set_state(TunnelState::connecting(ConnectStage::OpeningTunnel, None));
    let forward = match Forward::start(client.clone(), spec).await {
        Ok(f) => f,
        Err(e) => {
            let _ = client.disconnect().await;
            return Err(e.into());
        }
    };
    Ok(Live {
        forward,
        client,
        _jumps: jumps,
    })
}

async fn run(inner: Arc<Inner>, store: Arc<Store>, rule: Entity<PfRule>, settings: MobileSettings) {
    let mut attempt = 0u32;
    loop {
        let live = tokio::select! {
            r = open_once(&inner, &store, &rule, &settings) => r,
            _ = inner.stopped.cancelled() => Err(MobileError::Cancelled),
        };
        let live = match live {
            Ok(l) => l,
            Err(e) => {
                if inner.stopped.is_cancelled() {
                    inner.set_state(TunnelState::Stopped);
                    return;
                }
                let e = inner.conn.map_error(e);
                if attempt == 0 || matches!(e, MobileError::Cancelled) {
                    // First attempt (or the user gave up on a prompt): report and stop.
                    inner.set_state(TunnelState::Failed {
                        kind: e.kind(),
                        message: e.to_string(),
                    });
                    return;
                }
                if attempt >= RECONNECT_ATTEMPTS {
                    inner.set_state(TunnelState::Failed {
                        kind: e.kind(),
                        message: format!("{e} (gave up after {RECONNECT_ATTEMPTS} attempts)"),
                    });
                    return;
                }
                attempt += 1;
                if !wait_retry(&inner, attempt, e.to_string()).await {
                    return;
                }
                continue;
            }
        };
        if inner.stopped.is_cancelled() {
            live.forward.stop().await;
            let _ = live.client.disconnect().await;
            inner.set_state(TunnelState::Stopped);
            return;
        }
        let bound = bound_label(&live.forward, live.forward.spec());
        let client = live.client.clone();
        *inner.live.lock().expect("live poisoned") = Some(Arc::new(live));
        inner.set_state(TunnelState::Running { bound });

        let reason = tokio::select! {
            r = client.closed() => r,
            _ = inner.stopped.cancelled() => {
                inner.set_state(TunnelState::Stopped);
                return;
            }
        };
        // Transport dropped underneath a running tunnel.
        let dropped = inner.live.lock().expect("live poisoned").take();
        if let Some(d) = dropped {
            d.forward.stop().await;
        }
        if inner.stopped.is_cancelled() {
            inner.set_state(TunnelState::Stopped);
            return;
        }
        attempt = 1;
        if !wait_retry(&inner, attempt, format!("connection lost: {reason}")).await {
            return;
        }
    }
}

/// Publish `Reconnecting` and sleep; `false` when stopped meanwhile.
async fn wait_retry(inner: &Arc<Inner>, attempt: u32, reason: String) -> bool {
    let delay = reconnect_delay(attempt);
    inner.set_state(TunnelState::Reconnecting {
        attempt,
        retry_in_secs: delay.as_secs() as u32,
        reason,
    });
    tokio::select! {
        _ = tokio::time::sleep(delay) => true,
        _ = inner.stopped.cancelled() => {
            inner.set_state(TunnelState::Stopped);
            false
        }
    }
}

// ───────────────────────────── rules ─────────────────────────────

fn route(rule: &PfRule) -> String {
    let bind = |default: &str| {
        if rule.bound_address.is_empty() {
            default.to_string()
        } else {
            rule.bound_address.clone()
        }
    };
    match rule.kind.as_str() {
        "local" => format!(
            "{}:{} → {}:{}",
            bind("127.0.0.1"),
            rule.local_port,
            rule.remote_host,
            rule.remote_port
        ),
        "remote" => format!(
            "server {}:{} → {}:{}",
            bind("localhost"),
            rule.remote_port,
            if rule.remote_host.is_empty() {
                "127.0.0.1"
            } else {
                rule.remote_host.as_str()
            },
            rule.local_port
        ),
        _ => format!("SOCKS5 on {}:{}", bind("127.0.0.1"), rule.local_port),
    }
}

fn item(e: &Entity<PfRule>, hosts: &[Entity<Host>]) -> Result<PfRuleItem> {
    let host = hosts.iter().find(|h| h.id == e.data.host_id);
    Ok(PfRuleItem {
        id: e.id.to_string(),
        vault_id: e.vault_id.to_string(),
        label: e.data.label.clone(),
        host_id: e.data.host_id.to_string(),
        host_label: host
            .map(|h| {
                if h.data.label.is_empty() {
                    h.data.address.clone()
                } else {
                    h.data.label.clone()
                }
            })
            .unwrap_or_else(|| "(missing host)".into()),
        host_missing: host.is_none(),
        kind: PfKind::parse(&e.data.kind)?,
        bound_address: e.data.bound_address.clone(),
        local_port: e.data.local_port,
        remote_host: e.data.remote_host.clone(),
        remote_port: e.data.remote_port,
        auto_start: e.data.auto_start,
        updated_at: millis(e.updated_at),
        route: route(&e.data),
    })
}

fn validate(draft: &PfRuleDraft) -> Result<(PfRule, Uuid)> {
    let host_id = parse_id(&draft.host_id).map_err(|_| MobileError::invalid("choose a host"))?;
    if draft.local_port == 0 {
        return Err(MobileError::invalid(match draft.kind {
            PfKind::Remote => "local port is required",
            _ => "port to listen on is required",
        }));
    }
    let remote_host = draft.remote_host.trim().to_string();
    match draft.kind {
        PfKind::Local => {
            if remote_host.is_empty() {
                return Err(MobileError::invalid("destination host is required"));
            }
            if draft.remote_port == 0 {
                return Err(MobileError::invalid("destination port is required"));
            }
        }
        PfKind::Remote => {
            if draft.remote_port == 0 {
                return Err(MobileError::invalid("remote port is required"));
            }
        }
        PfKind::Dynamic => {}
    }
    Ok((
        PfRule {
            label: draft.label.trim().to_string(),
            host_id,
            kind: draft.kind.as_str().to_string(),
            bound_address: draft.bound_address.trim().to_string(),
            local_port: draft.local_port,
            remote_host,
            remote_port: draft.remote_port,
            auto_start: draft.auto_start,
        },
        host_id,
    ))
}

pub(crate) fn rules(store: &Store, vault_id: &Option<String>) -> Result<Vec<PfRuleItem>> {
    let vault = parse_opt_id(vault_id)?;
    let hosts = store.list::<Host>(vault)?;
    let mut out = store
        .list::<PfRule>(vault)?
        .iter()
        .map(|e| item(e, &hosts))
        .collect::<Result<Vec<_>>>()?;
    out.sort_by_key(|r| {
        (
            r.label.is_empty(),
            r.label.to_lowercase(),
            r.route.to_lowercase(),
        )
    });
    Ok(out)
}

pub(crate) fn rule(store: &Store, id: Uuid) -> Result<PfRuleItem> {
    let e = store.require::<PfRule>(id)?;
    let hosts = store.list::<Host>(Some(e.vault_id))?;
    item(&e, &hosts)
}

pub(crate) fn save(store: &Store, draft: &PfRuleDraft) -> Result<PfRuleItem> {
    let (data, host_id) = validate(draft)?;
    let vault_id = parse_id(&draft.vault_id)?;
    let host = store.require::<Host>(host_id)?;
    if host.vault_id != vault_id {
        return Err(MobileError::invalid("host belongs to another vault"));
    }
    if host.data.ssh_config_id.is_none() && host.data.telnet_config_id.is_some() {
        return Err(MobileError::invalid("telnet hosts cannot forward ports"));
    }
    let id = match &draft.id {
        Some(id) => {
            let id = parse_id(id)?;
            store.require::<PfRule>(id)?;
            store.update(id, &data)?;
            id
        }
        None => store.insert(vault_id, &data)?,
    };
    rule(store, id)
}

pub(crate) fn duplicate(store: &Store, id: Uuid) -> Result<PfRuleItem> {
    let src = store.require::<PfRule>(id)?;
    let mut data = src.data.clone();
    if !data.label.is_empty() {
        data.label = format!("{} copy", data.label);
    }
    let new_id = store.insert(src.vault_id, &data)?;
    rule(store, new_id)
}

pub(crate) fn delete(store: &Store, id: Uuid) -> Result<()> {
    store.require::<PfRule>(id)?;
    store.delete(id)?;
    Ok(())
}

pub(crate) fn resolve_for_tunnel(store: &Store, id: Uuid) -> Result<Entity<PfRule>> {
    let e = store.require::<PfRule>(id)?;
    if let Some(d) =
        termoso_core::policy::check_forward(store, e.vault_id, &e.data.kind, e.data.remote_port)
    {
        return Err(MobileError::Invalid {
            detail: d.message(),
        });
    }
    let _: ResolvedHost = store.resolve_host_in(e.data.host_id, Some(e.vault_id))?;
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(kind: PfKind) -> PfRuleDraft {
        PfRuleDraft {
            id: None,
            vault_id: Uuid::nil().to_string(),
            label: String::new(),
            host_id: Uuid::new_v4().to_string(),
            kind,
            bound_address: String::new(),
            local_port: 8080,
            remote_host: "db.internal".into(),
            remote_port: 5432,
            auto_start: false,
        }
    }

    #[test]
    fn validation_per_kind() {
        assert!(validate(&draft(PfKind::Local)).is_ok());
        let mut d = draft(PfKind::Local);
        d.remote_host.clear();
        assert!(validate(&d).is_err());
        let mut d = draft(PfKind::Dynamic);
        d.remote_host.clear();
        d.remote_port = 0;
        assert!(validate(&d).is_ok());
        let mut d = draft(PfKind::Remote);
        d.remote_port = 0;
        assert!(validate(&d).is_err());
        let mut d = draft(PfKind::Local);
        d.local_port = 0;
        assert!(validate(&d).is_err());
        let mut d = draft(PfKind::Local);
        d.host_id = "nope".into();
        assert!(validate(&d).is_err());
    }

    #[test]
    fn routes() {
        let (local, _) = validate(&draft(PfKind::Local)).unwrap();
        assert_eq!(route(&local), "127.0.0.1:8080 → db.internal:5432");
        let (remote, _) = validate(&draft(PfKind::Remote)).unwrap();
        assert_eq!(route(&remote), "server localhost:5432 → db.internal:8080");
        let mut d = draft(PfKind::Dynamic);
        d.bound_address = "0.0.0.0".into();
        let (dynamic, _) = validate(&d).unwrap();
        assert_eq!(route(&dynamic), "SOCKS5 on 0.0.0.0:8080");
    }

    #[test]
    fn reconnect_backoff_is_capped() {
        assert_eq!(reconnect_delay(1), Duration::from_secs(2));
        assert_eq!(reconnect_delay(3), Duration::from_secs(8));
        assert_eq!(reconnect_delay(6), RECONNECT_MAX_DELAY);
        assert_eq!(reconnect_delay(40), RECONNECT_MAX_DELAY);
    }
}
