//! Shared SSH connection path for terminals and SFTP: jump hosts, proxy,
//! saved credentials, and prompts for anything missing. The UI end is a
//! [`ConnectUi`]; each session kind wraps its own listener in one so the
//! prompt/answer protocol is identical for every connection.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use termoso_core::error::CoreError;
use termoso_core::fido2::{self, Fido2Error};
use termoso_core::hostkey::{
    HostKeyDecision, HostKeyInfo, HostKeyPrompt, HostKeyVerdict, KnownHosts,
};
use termoso_core::model::{Identity, ResolvedHost, SshConfig};
use termoso_core::ssh::proxy::{ProxyConfig, ProxyKind};
use termoso_core::ssh::totp::TotpResponder;
use termoso_core::ssh::{
    AuthMethod, ConnectOptions, ConnectPhase, ConnectProgress, InteractivePrompt,
    InteractiveQuestion, IpVersion, SshClient, SshTarget,
};
use termoso_core::store::Store;
use tokio::sync::oneshot;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{MobileError, Result};
use crate::settings::MobileSettings;

const MAX_PASSWORD_ATTEMPTS: u32 = 3;

/// Something only the user can answer.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum PromptRequest {
    /// First contact with this host: show the fingerprint, ask to trust.
    HostKeyUnknown {
        host: String,
        key_type: String,
        fingerprint: String,
    },
    /// The pinned key differs. Loud warning.
    HostKeyChanged {
        host: String,
        key_type: String,
        old_fingerprint: String,
        new_fingerprint: String,
    },
    /// The host has no username configured: ask which account to log in
    /// as. Answered with [`PromptAnswer::Secret`] (`remember` saves it on
    /// the host's identity).
    Username {
        host: String,
        retry: bool,
    },
    Password {
        username: String,
        retry: bool,
    },
    Passphrase {
        key_label: String,
        retry: bool,
    },
    /// The security key wants its PIN before it signs. `retries` is what
    /// the token reports after a wrong PIN, when it does.
    SecurityKeyPin {
        key_label: String,
        retry: bool,
        retries: Option<i32>,
    },
    /// No security key is attached (or the attached one does not hold this
    /// credential when `wrong_device`). The UI waits for a USB plug / NFC
    /// tap, registers it, and answers [`PromptAnswer::Retry`].
    SecurityKeyInsert {
        key_label: String,
        wrong_device: bool,
    },
    /// Server-driven keyboard-interactive dialog.
    KeyboardInteractive {
        name: String,
        instructions: String,
        questions: Vec<InteractiveQuestionInfo>,
    },
    /// A WebDAV server's TLS certificate is not trusted by the system
    /// roots (self-signed / private CA): show the fingerprint, ask to
    /// trust. Answered with [`PromptAnswer::HostKey`].
    Certificate {
        host: String,
        fingerprint: String,
    },
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct InteractiveQuestionInfo {
    pub prompt: String,
    /// Input may be shown while typing.
    pub echo: bool,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum PromptAnswer {
    Cancel,
    /// Host key: reject / accept once / accept and save.
    HostKey {
        decision: HostKeyChoice,
    },
    /// Username, password or passphrase; `remember` stores it in the vault.
    Secret {
        value: String,
        remember: bool,
    },
    /// One answer per keyboard-interactive question, in order.
    Answers {
        values: Vec<String>,
    },
    /// Try again (a security key is now attached).
    Retry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HostKeyChoice {
    Reject,
    AcceptOnce,
    AcceptAndSave,
}

/// Where a connection attempt is, for the UI to render in its own language.
/// `SessionState::Connecting::detail` carries the English rendering from
/// [`stage_label`] for clients that do not localise it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectStage {
    /// Nothing reported yet.
    Connecting,
    Resolving,
    /// TCP connect to `target` (`host:port`, a proxy, or a WebDAV share).
    ConnectingTo {
        target: String,
    },
    Handshake,
    HostKey,
    Auth {
        method: String,
    },
    SecurityKeyTouch,
    Authenticated,
    MoshServer,
    MoshWaiting {
        port: u16,
    },
    OpeningShell,
    StartingShell,
    OpeningSftp,
    OpeningTunnel,
}

impl From<&ConnectPhase> for ConnectStage {
    fn from(p: &ConnectPhase) -> Self {
        match p {
            ConnectPhase::Resolving => Self::Resolving,
            ConnectPhase::Connecting { via } => Self::ConnectingTo {
                target: via.clone(),
            },
            ConnectPhase::Handshake => Self::Handshake,
            ConnectPhase::HostKey => Self::HostKey,
            ConnectPhase::Auth { method } => Self::Auth {
                method: method.clone(),
            },
            ConnectPhase::SecurityKeyTouch { .. } => Self::SecurityKeyTouch,
            ConnectPhase::Authenticated => Self::Authenticated,
            ConnectPhase::MoshServer => Self::MoshServer,
        }
    }
}

/// The UI side of a connection attempt.
pub(crate) trait ConnectUi: Send + Sync {
    /// A new connect stage; `hop` names the jump host it belongs to.
    fn phase(&self, stage: ConnectStage, hop: Option<String>);
    /// Ask the user; the answer comes back through [`Connector::answer`].
    fn prompt(&self, prompt_id: u64, request: PromptRequest);
}

type PromptTx = oneshot::Sender<PromptAnswer>;

pub(crate) struct PromptBroker {
    next: AtomicU64,
    pending: Mutex<HashMap<u64, PromptTx>>,
}

impl PromptBroker {
    fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
        }
    }

    async fn ask(&self, ui: &dyn ConnectUi, request: PromptRequest) -> Option<PromptAnswer> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .expect("prompts poisoned")
            .insert(id, tx);
        ui.prompt(id, request);
        match rx.await {
            Ok(PromptAnswer::Cancel) | Err(_) => None,
            Ok(a) => Some(a),
        }
    }

    fn answer(&self, id: u64, answer: PromptAnswer) -> bool {
        match self.pending.lock().expect("prompts poisoned").remove(&id) {
            Some(tx) => tx.send(answer).is_ok(),
            None => false,
        }
    }

    fn cancel_all(&self) {
        self.pending.lock().expect("prompts poisoned").clear();
    }
}

/// Key passphrases the user typed without saving them, kept only in RAM
/// for the lifetime of the open profile (`MobileSettings::cache_passphrases`).
/// Never serialised; zeroised when forgotten or when the profile closes.
#[derive(Default)]
pub struct SecretCache {
    passphrases: Mutex<HashMap<Uuid, Zeroizing<String>>>,
}

impl SecretCache {
    pub fn passphrase(&self, key: Uuid) -> Option<Zeroizing<String>> {
        self.passphrases
            .lock()
            .expect("secret cache poisoned")
            .get(&key)
            .cloned()
    }

    pub fn remember_passphrase(&self, key: Uuid, value: Zeroizing<String>) {
        self.passphrases
            .lock()
            .expect("secret cache poisoned")
            .insert(key, value);
    }

    pub fn forget_passphrase(&self, key: Uuid) {
        self.passphrases
            .lock()
            .expect("secret cache poisoned")
            .remove(&key);
    }

    pub fn clear(&self) {
        self.passphrases
            .lock()
            .expect("secret cache poisoned")
            .clear();
    }

    pub fn len(&self) -> usize {
        self.passphrases
            .lock()
            .expect("secret cache poisoned")
            .len()
    }
}

/// Everything one connection attempt needs from its owner: the store for
/// credentials and known hosts, the UI for prompts, the prompt broker and
/// the "user gave up" flag.
pub(crate) struct Connector {
    pub store: Arc<Store>,
    pub ui: Arc<dyn ConnectUi>,
    pub secrets: Arc<SecretCache>,
    prompts: PromptBroker,
    /// Set when the user dismissed a prompt; turns the resulting connect
    /// error into `Cancelled`.
    cancelled: AtomicBool,
}

impl Connector {
    pub fn new(store: Arc<Store>, secrets: Arc<SecretCache>, ui: Arc<dyn ConnectUi>) -> Self {
        Self {
            store,
            ui,
            secrets,
            prompts: PromptBroker::new(),
            cancelled: AtomicBool::new(false),
        }
    }

    pub fn answer(&self, id: u64, answer: PromptAnswer) -> bool {
        self.prompts.answer(id, answer)
    }

    pub fn cancel_prompts(&self) {
        self.prompts.cancel_all();
    }

    pub fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Map a connect error to `Cancelled` when the user dismissed a prompt.
    pub fn map_error(&self, e: MobileError) -> MobileError {
        if self.cancelled() {
            MobileError::Cancelled
        } else {
            e
        }
    }

    pub(crate) async fn ask(&self, request: PromptRequest) -> Option<PromptAnswer> {
        self.prompts.ask(self.ui.as_ref(), request).await
    }

    pub(crate) fn give_up(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

/// English rendering of a stage, `hop: ` prefixed for jump hosts.
pub(crate) fn stage_label(stage: &ConnectStage, hop: Option<&str>) -> String {
    let base = match stage {
        ConnectStage::Connecting => "Connecting…".to_string(),
        ConnectStage::Resolving => "Resolving host…".into(),
        ConnectStage::ConnectingTo { target } => format!("Connecting to {target}…"),
        ConnectStage::Handshake => "Handshake…".into(),
        ConnectStage::HostKey => "Checking host key…".into(),
        ConnectStage::Auth { method } => format!("Authenticating ({method})…"),
        ConnectStage::SecurityKeyTouch => "Touch your security key…".into(),
        ConnectStage::Authenticated => "Authenticated…".into(),
        ConnectStage::MoshServer => "Starting mosh-server…".into(),
        ConnectStage::MoshWaiting { port } => format!("Mosh: waiting for udp/{port}…"),
        ConnectStage::OpeningShell => "Opening shell…".into(),
        ConnectStage::StartingShell => "Starting shell…".into(),
        ConnectStage::OpeningSftp => "Opening SFTP…".into(),
        ConnectStage::OpeningTunnel => "Opening tunnel…".into(),
    };
    match hop {
        Some(h) => format!("{h}: {base}"),
        None => base,
    }
}

struct Progress {
    conn: Arc<Connector>,
    hop: Option<String>,
}

impl ConnectProgress for Progress {
    fn phase(&self, phase: ConnectPhase) {
        self.conn
            .ui
            .phase(ConnectStage::from(&phase), self.hop.clone());
    }
}

struct HostKeyAsk {
    conn: Arc<Connector>,
}

fn key_host(info: &HostKeyInfo) -> String {
    info.host.clone()
}

impl HostKeyPrompt for HostKeyAsk {
    fn decide(
        &self,
        verdict: HostKeyVerdict,
    ) -> Pin<Box<dyn Future<Output = HostKeyDecision> + Send + '_>> {
        Box::pin(async move {
            let request = match &verdict {
                HostKeyVerdict::Known => return HostKeyDecision::AcceptOnce,
                HostKeyVerdict::Unknown { key } => PromptRequest::HostKeyUnknown {
                    host: key_host(key),
                    key_type: key.key_type.clone(),
                    fingerprint: key.fingerprint.clone(),
                },
                HostKeyVerdict::Changed { old, new } => PromptRequest::HostKeyChanged {
                    host: key_host(new),
                    key_type: new.key_type.clone(),
                    old_fingerprint: old.fingerprint.clone(),
                    new_fingerprint: new.fingerprint.clone(),
                },
            };
            match self.conn.ask(request).await {
                Some(PromptAnswer::HostKey { decision }) => match decision {
                    HostKeyChoice::Reject => HostKeyDecision::Reject,
                    HostKeyChoice::AcceptOnce => HostKeyDecision::AcceptOnce,
                    HostKeyChoice::AcceptAndSave => HostKeyDecision::AcceptAndSave,
                },
                _ => {
                    self.conn.give_up();
                    HostKeyDecision::Reject
                }
            }
        })
    }
}

struct InteractiveAsk {
    conn: Arc<Connector>,
}

impl InteractivePrompt for InteractiveAsk {
    fn respond(
        &self,
        name: String,
        instructions: String,
        prompts: Vec<InteractiveQuestion>,
    ) -> Pin<Box<dyn Future<Output = Option<Vec<String>>> + Send + '_>> {
        Box::pin(async move {
            let n = prompts.len();
            // PAM commonly follows a successful password with an empty round;
            // there is nothing to type, so answer it without bothering the user.
            if n == 0 {
                return Some(Vec::new());
            }
            let request = PromptRequest::KeyboardInteractive {
                name,
                instructions,
                questions: prompts
                    .into_iter()
                    .map(|q| InteractiveQuestionInfo {
                        prompt: q.prompt,
                        echo: q.echo,
                    })
                    .collect(),
            };
            match self.conn.ask(request).await {
                Some(PromptAnswer::Answers { values }) if values.len() == n => Some(values),
                Some(PromptAnswer::Secret { value, .. }) if n == 1 => Some(vec![value]),
                _ => {
                    self.conn.give_up();
                    None
                }
            }
        })
    }
}

pub(crate) fn proxy_config(store: &Store, p: &termoso_core::model::Proxy) -> Result<ProxyConfig> {
    let kind = ProxyKind::parse(&p.kind)
        .ok_or_else(|| MobileError::invalid(format!("unsupported proxy type {}", p.kind)))?;
    let (username, password) = match p.identity_id {
        Some(id) => {
            let ident = store.get::<Identity>(id)?;
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
/// host's SSH config. `username` is the login the connection is using;
/// `edit` applies the remembered value to the identity.
fn remember_on_identity(
    store: &Store,
    resolved: &ResolvedHost,
    username: &str,
    what: &str,
    edit: impl Fn(&mut Identity),
) {
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
                        ..SshConfig::default()
                    },
                )?;
                let mut host = resolved.host.data.clone();
                host.ssh_config_id = Some(cfg_id);
                store.update(resolved.host.id, &host)
            }
        }
    })();
    if let Err(e) = result {
        tracing::warn!("remember {what}: {e}");
    }
}

fn remember_password(store: &Store, resolved: &ResolvedHost, username: &str, value: &str) {
    remember_on_identity(store, resolved, username, "password", |i| {
        i.password = Some(value.to_string())
    });
}

fn remember_username(store: &Store, resolved: &ResolvedHost, username: &str) {
    remember_on_identity(store, resolved, username, "username", |i| {
        i.username = username.to_string()
    });
}

/// Ask for the login name when the target has none; an empty answer asks
/// again, backing out cancels the connection.
async fn ask_username(
    conn: &Arc<Connector>,
    target: &SshTarget,
    resolved: Option<&ResolvedHost>,
) -> Result<String> {
    let host = resolved
        .map(|r| r.host.data.label.clone())
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| target.host.clone());
    let mut retry = false;
    loop {
        let answer = conn
            .ask(PromptRequest::Username {
                host: host.clone(),
                retry,
            })
            .await;
        match answer {
            Some(PromptAnswer::Secret { value, remember }) => {
                let value = value.trim().to_string();
                if value.is_empty() {
                    retry = true;
                    continue;
                }
                if remember && let Some(r) = resolved {
                    remember_username(&conn.store, r, &value);
                }
                return Ok(value);
            }
            _ => return Err(MobileError::Cancelled),
        }
    }
}

fn keepalive(settings: &MobileSettings, cfg: &SshConfig) -> Option<Duration> {
    let secs = cfg
        .keep_alive_interval
        .unwrap_or(settings.keep_alive_seconds);
    (secs > 0).then(|| Duration::from_secs(secs as u64))
}

/// Connect to `target` through the host's jump chain (each hop with its own
/// credentials, proxy and known-host entry), prompting for a password /
/// passphrase when the saved credentials are not enough. The returned jump
/// clients must be kept alive as long as the main client is.
pub(crate) async fn connect_resolved(
    conn: &Arc<Connector>,
    settings: &MobileSettings,
    target: SshTarget,
    resolved: Option<&ResolvedHost>,
) -> Result<(Arc<SshClient>, Vec<Arc<SshClient>>)> {
    let chain = resolved.map(|r| r.chain.clone()).unwrap_or_default();
    if let Some(r) = resolved
        && chain.is_empty()
        && termoso_core::policy::jump_required(&conn.store, r.host.vault_id)
    {
        return Err(MobileError::Invalid {
            detail: termoso_core::policy::Denied::DirectConnection.message(),
        });
    }
    ssh_connect(conn, settings, target, resolved, &chain, None, None).await
}

async fn ssh_connect(
    conn: &Arc<Connector>,
    settings: &MobileSettings,
    target: SshTarget,
    resolved: Option<&ResolvedHost>,
    chain: &[termoso_core::model::Entity<termoso_core::model::Host>],
    jump: Option<Arc<SshClient>>,
    hop: Option<String>,
) -> Result<(Arc<SshClient>, Vec<Arc<SshClient>>)> {
    let store = &conn.store;
    let mut target = target;
    if target.username.trim().is_empty() {
        target.username = ask_username(conn, &target, resolved).await?;
    }
    let mut jumps: Vec<Arc<SshClient>> = Vec::new();
    let mut via = jump;
    for link in chain {
        let hop_resolved = store.resolve_host_in(link.id, Some(link.vault_id))?;
        let hop_target = SshTarget {
            host: hop_resolved.host.data.address.clone(),
            port: hop_resolved.port(),
            username: hop_resolved.username().unwrap_or_default(),
        };
        let (client, _) = Box::pin(ssh_connect(
            conn,
            settings,
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

    let known_hosts = KnownHosts::new(store.clone(), store.local_vault()?.id);
    let ssh_cfg = resolved.map(|r| r.ssh.clone()).unwrap_or_default();
    let identity = resolved.and_then(|r| r.identity.clone());
    let mut password: Option<Zeroizing<String>> = identity
        .as_ref()
        .and_then(|i| i.data.password.clone())
        .filter(|p| !p.is_empty())
        .map(Zeroizing::new);
    let key_id = resolved.and_then(|r| r.key.as_ref()).map(|k| k.id);
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
    let cache_passphrases = settings.cache_passphrases && key_id.is_some();
    let mut cached_passphrase = false;
    if passphrase.is_none()
        && cache_passphrases
        && let Some(id) = key_id
        && let Some(p) = conn.secrets.passphrase(id)
    {
        passphrase = Some(p);
        cached_passphrase = true;
    }
    let mut typed_passphrase: Option<Zeroizing<String>> = None;
    let totp = identity
        .as_ref()
        .and_then(|i| i.data.totp_secret.as_deref())
        .filter(|t| !t.is_empty())
        .map(|t| TotpResponder::parse(t).map_err(MobileError::from))
        .transpose()?;
    let proxy = match resolved.and_then(|r| r.proxy.as_ref()) {
        Some(p) => Some(proxy_config(store, &p.data)?),
        None => None,
    };
    let key_label = resolved
        .and_then(|r| r.key.as_ref())
        .map(|k| k.data.label.clone())
        .or_else(|| {
            resolved
                .and_then(|r| r.ssh_id_handle.as_deref())
                .map(|h| format!("SSH ID @{h}"))
        })
        .unwrap_or_default();
    let mut pin: Option<Zeroizing<String>> = None;

    let mut attempts = 0;
    let mut inserts = 0;
    let mut asked_password = false;
    let mut asked_passphrase = false;
    loop {
        let mut auth: Vec<AuthMethod> = Vec::new();
        if let Some(key) = resolved.and_then(|r| r.key.as_ref()) {
            let certificate = resolved
                .and_then(|r| r.certificate.as_ref())
                .map(|c| c.data.certificate.clone());
            if key.data.is_agent_backed() {
                return Err(MobileError::Key {
                    detail: format!(
                        "key \"{}\" is signed by a desktop SSH agent; import its private key to use it here",
                        key.data.label
                    ),
                });
            }
            if fido2::is_sk_type(&key.data.key_type) {
                auth.push(AuthMethod::SecurityKey {
                    private_key: Zeroizing::new(key.data.private_key.clone()),
                    passphrase: passphrase.clone(),
                    pin: pin.clone(),
                    backend: Arc::new(crate::fido2::PhoneBackend::default()),
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
        // Team CA certificate first (hosts in a team vault; cached by the
        // account sync, see `termoso_core::ca`).
        if let Some(m) =
            resolved.and_then(|r| termoso_core::ca::auth_method(store, r.host.vault_id))
        {
            auth.push(m);
        }
        if let Some(i) = identity.as_ref().filter(|i| i.data.ssh_id) {
            auth.extend(crate::sshid::auth_methods(
                store,
                i.data.ssh_id_key_type,
                pin.clone(),
            )?);
        }
        // Team policy `auth = keys_only`: no password-class methods at all.
        let keys_only =
            resolved.is_some_and(|r| termoso_core::policy::keys_only(store, r.host.vault_id));
        if keys_only {
            if auth.is_empty() {
                return Err(MobileError::Invalid {
                    detail: termoso_core::policy::Denied::PasswordAuth.message(),
                });
            }
        } else {
            if let Some(pw) = &password {
                auth.push(AuthMethod::Password(pw.clone()));
            }
            auth.push(AuthMethod::KeyboardInteractive);
        }

        let ask: Arc<dyn InteractivePrompt> = Arc::new(InteractiveAsk { conn: conn.clone() });
        let interactive: Option<Arc<dyn InteractivePrompt>> = match (&totp, &password) {
            (Some(t), _) => Some(Arc::new(TotpResponder::new(
                t.clone(),
                password.clone(),
                Some(ask),
            ))),
            (None, Some(_)) => None,
            (None, None) => Some(ask),
        };
        let opts = ConnectOptions {
            target: target.clone(),
            auth,
            known_hosts: known_hosts.clone(),
            host_key_prompt: Arc::new(HostKeyAsk { conn: conn.clone() }),
            interactive,
            keepalive: keepalive(settings, &ssh_cfg),
            timeout: Duration::from_secs(ssh_cfg.timeout.unwrap_or(20).clamp(1, 600) as u64),
            proxy: proxy.clone(),
            gateway: None,
            env: ssh_cfg.env_variables.clone(),
            agent_forwarding: ssh_cfg.agent_forwarding,
            // No local X server on a phone: the flag only travels with the
            // synced host for desktop clients.
            x11: None,
            agent_socket: None,
            post_quantum_kex: settings.post_quantum_kex,
            progress: Some(Arc::new(Progress {
                conn: conn.clone(),
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
            Ok(client) => {
                if let Some((id, p)) = key_id.zip(typed_passphrase.take())
                    && cache_passphrases
                {
                    conn.secrets.remember_passphrase(id, p);
                }
                return Ok((Arc::new(client), jumps));
            }
            Err(CoreError::AuthFailed { remaining })
                if attempts < MAX_PASSWORD_ATTEMPTS
                    && !conn.cancelled()
                    && (remaining.is_empty()
                        || remaining
                            .iter()
                            .any(|m| m == "password" || m == "keyboard-interactive")) =>
            {
                attempts += 1;
                let answer = conn
                    .ask(PromptRequest::Password {
                        username: target.username.clone(),
                        retry: asked_password || password.is_some(),
                    })
                    .await;
                asked_password = true;
                match answer {
                    Some(PromptAnswer::Secret { value, remember }) => {
                        let value = Zeroizing::new(value);
                        if remember && let Some(r) = resolved {
                            remember_password(store, r, &target.username, &value);
                        }
                        password = Some(value);
                    }
                    _ => return Err(MobileError::Cancelled),
                }
            }
            Err(CoreError::Key(msg))
                if attempts < MAX_PASSWORD_ATTEMPTS && msg.contains("passphrase") =>
            {
                attempts += 1;
                if cached_passphrase && let Some(id) = key_id {
                    conn.secrets.forget_passphrase(id);
                    cached_passphrase = false;
                }
                let answer = conn
                    .ask(PromptRequest::Passphrase {
                        key_label: key_label.clone(),
                        retry: asked_passphrase || passphrase.is_some(),
                    })
                    .await;
                asked_passphrase = true;
                match answer {
                    Some(PromptAnswer::Secret { value, remember }) => {
                        let value = Zeroizing::new(value);
                        if remember && let Some(key) = resolved.and_then(|r| r.key.as_ref()) {
                            let mut data = key.data.clone();
                            data.passphrase = Some(value.to_string());
                            if let Err(e) = store.update(key.id, &data) {
                                tracing::warn!("remember passphrase: {e}");
                            }
                            typed_passphrase = None;
                        } else {
                            typed_passphrase = Some(value.clone());
                        }
                        passphrase = Some(value);
                    }
                    _ => return Err(MobileError::Cancelled),
                }
            }
            Err(CoreError::Fido2(
                e @ (Fido2Error::PinRequired | Fido2Error::PinInvalid { .. }),
            )) if attempts < MAX_PASSWORD_ATTEMPTS && !conn.cancelled() => {
                attempts += 1;
                let retries = match e {
                    Fido2Error::PinInvalid { retries } => retries,
                    _ => None,
                };
                let answer = conn
                    .ask(PromptRequest::SecurityKeyPin {
                        key_label: key_label.clone(),
                        retry: pin.is_some(),
                        retries,
                    })
                    .await;
                match answer {
                    Some(PromptAnswer::Secret { value, .. }) => pin = Some(Zeroizing::new(value)),
                    _ => return Err(MobileError::Cancelled),
                }
            }
            Err(CoreError::Fido2(e @ (Fido2Error::NoDevice | Fido2Error::WrongDevice)))
                if inserts < MAX_PASSWORD_ATTEMPTS && !conn.cancelled() =>
            {
                inserts += 1;
                let answer = conn
                    .ask(PromptRequest::SecurityKeyInsert {
                        key_label: key_label.clone(),
                        wrong_device: matches!(e, Fido2Error::WrongDevice),
                    })
                    .await;
                if !matches!(answer, Some(PromptAnswer::Retry)) {
                    return Err(MobileError::Cancelled);
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}
