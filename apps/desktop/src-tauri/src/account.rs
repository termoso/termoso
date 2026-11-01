//! Account and sync runtime. Sign-in flows, the session token, account keys
//! and vault keys live in Rust; the webview sees profile data, sync status
//! and a step machine for MFA / device approval. The recovery phrase is
//! returned exactly once, from `register`, so the UI can show it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, Runtime};
use termoso_core::account::{
    self as core, LoginFlow, LoginStep, ReauthFlow, ReauthStep, RegisterInput,
};
use termoso_core::api::ApiClient;
use termoso_core::store::{EntityFilter, LocalVault, StoredAccount};
use termoso_core::sync::{SyncEngine, SyncEvent, SyncOptions, SyncReport};
use termoso_proto::account::ServerInfo;
use termoso_proto::auth::{Device, MfaCredential, MfaMethod, SsoResult};
use termoso_proto::entities::is_credential_kind;
use termoso_proto::vault::VaultMember;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{DesktopError, Result};
use crate::state::AppState;

pub const SYNC_EVENT: &str = "sync";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountCard {
    pub server_url: String,
    pub user_id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
    pub is_admin: bool,
    pub device_id: Uuid,
    pub signed_in_at: DateTime<Utc>,
}

impl From<StoredAccount> for AccountCard {
    fn from(a: StoredAccount) -> Self {
        Self {
            server_url: a.server_url,
            user_id: a.user_id,
            email: a.email,
            display_name: a.display_name,
            avatar: a.avatar,
            is_admin: a.is_admin,
            device_id: a.device_id,
            signed_in_at: a.signed_in_at,
        }
    }
}

/// Where an interactive sign-in currently stands.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(
    tag = "step",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum LoginOutcome {
    Done { account: AccountCard },
    MfaRequired { methods: Vec<MfaMethod> },
    DeviceApprovalRequired { email_hint: String },
}

/// Where a step-up (re-authentication for sensitive account changes) stands.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(
    tag = "step",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ReauthOutcome {
    Done { expires_at: DateTime<Utc> },
    MfaRequired { methods: Vec<MfaMethod> },
    EmailCodeRequired { email_hint: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Registered {
    pub account: AccountCard,
    /// Shown once; never stored by the UI.
    pub recovery_phrase: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum SyncState {
    #[default]
    Idle,
    Syncing,
    Offline,
    Error,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    pub state: SyncState,
    pub realtime: bool,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub pushed: usize,
    pub pulled: usize,
    pub conflicts: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountStatus {
    pub account: Option<AccountCard>,
    /// A sign-in waiting for a second factor / device code.
    pub pending: Option<LoginOutcome>,
    pub sync: SyncStatus,
    pub vaults: Vec<LocalVault>,
    /// Identities, keys and certificates of the Personal vault that exist
    /// only on this device because credential sync is off (0 when it is on).
    pub local_credentials: usize,
}

/// Emitted on `SYNC_EVENT`.
#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SyncNotice {
    Status {
        status: SyncStatus,
    },
    EntitiesChanged {
        vault_id: Uuid,
    },
    VaultsChanged,
    HistoryChanged,
    LogsChanged,
    AccountChanged,
    /// Who is connected to what changed in a team.
    PresenceChanged {
        team_id: Uuid,
    },
    /// The server revoked this device; the account was signed out locally.
    SignedOut,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginForm {
    pub server_url: String,
    pub email: String,
    pub password: String,
    /// Bind the identity verified by the SSO round trip started with
    /// [`sso_start`] (the server then skips new-device approval).
    #[serde(default)]
    pub sso: bool,
    /// Cloudflare Turnstile token from the server's `/captcha` page, sent when
    /// the previous attempt failed with `turnstile_required`.
    #[serde(default)]
    pub captcha: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterForm {
    pub server_url: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub invite_token: Option<String>,
    /// Bind the identity verified by the SSO round trip started with
    /// [`sso_start`].
    #[serde(default)]
    pub sso: bool,
    /// Cloudflare Turnstile token from the server's `/captcha` page, sent when
    /// the previous attempt failed with `turnstile_required`.
    #[serde(default)]
    pub captcha: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoStartForm {
    pub server_url: String,
    pub provider: String,
}

/// Deep link the server sends the browser back to once the IdP is done.
pub const SSO_CALLBACK: &str = "termoso://sso";

/// Where a browser-based SSO sign-in stands. The verified `sso_session`
/// itself never reaches the webview: it stays in Rust until `login` /
/// `register` bind it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(
    tag = "step",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SsoOutcome {
    /// Browser round trip not finished yet.
    Pending,
    /// Known account: unlock with the Termoso password.
    LoginRequired {
        email: String,
    },
    /// New identity: create an account (and its keys) with a password.
    RegistrationRequired {
        email: String,
        display_name: Option<String>,
    },
    Failed {
        message: String,
    },
}

struct SsoFlow {
    api: Arc<ApiClient>,
    server_url: String,
    flow_id: String,
    /// Terminal outcome once collected — the server hands it out only once.
    outcome: Option<SsoOutcome>,
    session: Option<Zeroizing<String>>,
}

struct Engine {
    engine: Arc<SyncEngine>,
    cancel: CancellationToken,
    runner: JoinHandle<()>,
    watcher: JoinHandle<()>,
}

impl Engine {
    fn stop(self) {
        self.cancel.cancel();
        self.runner.abort();
        self.watcher.abort();
    }
}

#[derive(Default)]
struct Inner {
    api: Option<Arc<ApiClient>>,
    flow: Option<LoginFlow>,
    pending: Option<LoginOutcome>,
    reauth: Option<ReauthFlow>,
    sso: Option<SsoFlow>,
    engine: Option<Engine>,
}

#[derive(Default)]
pub struct AccountRuntime {
    inner: tokio::sync::Mutex<Inner>,
    /// Serialises SSO polls: the server hands a terminal result out once, so
    /// two concurrent polls must not both go to the network.
    sso_poll: tokio::sync::Mutex<()>,
    status: Mutex<SyncStatus>,
}

impl AccountRuntime {
    pub fn sync_status(&self) -> SyncStatus {
        self.status.lock().expect("sync status poisoned").clone()
    }

    fn update_status(&self, f: impl FnOnce(&mut SyncStatus)) -> SyncStatus {
        let mut s = self.status.lock().expect("sync status poisoned");
        f(&mut s);
        s.clone()
    }
}

fn device_name() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .filter(|h| !h.trim().is_empty())
        .unwrap_or_else(|| "Termoso Desktop".into())
}

fn device(state: &AppState) -> Result<termoso_proto::auth::DeviceInfo> {
    Ok(core::device_info(
        &*state.store()?,
        &device_name(),
        core::current_platform(),
        env!("CARGO_PKG_VERSION"),
    )?)
}

fn sync_options(state: &AppState) -> Result<SyncOptions> {
    let settings = state.settings()?;
    let interval = match settings.sync_interval_seconds {
        0 => Duration::from_secs(365 * 24 * 3600),
        s => Duration::from_secs(u64::from(s)),
    };
    Ok(SyncOptions {
        conflict: settings.conflict_policy()?,
        log_dir: Some(state.logs_dir()),
        upload_logs: settings.upload_logs,
        sync_credentials: settings.sync_credentials,
        interval,
        ..SyncOptions::default()
    })
}

fn local_credentials(state: &AppState) -> Result<usize> {
    if state.settings()?.sync_credentials {
        return Ok(0);
    }
    let Some(vault) = state.store()?.personal_vault()? else {
        return Ok(0);
    };
    Ok(state
        .store()?
        .rows(&EntityFilter {
            vault_id: Some(vault.id),
            ..EntityFilter::default()
        })?
        .iter()
        .filter(|r| is_credential_kind(&r.kind))
        .count())
}

fn outcome(step: &LoginStep) -> LoginOutcome {
    match step {
        LoginStep::Done(s) => LoginOutcome::Done {
            account: s.account.clone().into(),
        },
        LoginStep::MfaRequired { methods } => LoginOutcome::MfaRequired {
            methods: methods.clone(),
        },
        LoginStep::DeviceApprovalRequired { email_hint } => LoginOutcome::DeviceApprovalRequired {
            email_hint: email_hint.clone(),
        },
    }
}

fn reauth_outcome(step: &ReauthStep) -> ReauthOutcome {
    match step {
        ReauthStep::Done { expires_at } => ReauthOutcome::Done {
            expires_at: *expires_at,
        },
        ReauthStep::MfaRequired { methods } => ReauthOutcome::MfaRequired {
            methods: methods.clone(),
        },
        ReauthStep::EmailCodeRequired { email_hint } => ReauthOutcome::EmailCodeRequired {
            email_hint: email_hint.clone(),
        },
    }
}

fn normalize_url(url: &str) -> Result<String> {
    let url = url.trim().trim_end_matches('/');
    if url.is_empty() {
        return Err(DesktopError::invalid("server URL is required"));
    }
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(DesktopError::invalid(
            "server URL must start with https:// or http://",
        ));
    }
    Ok(url.to_string())
}

pub fn status(state: &AppState, pending: Option<LoginOutcome>) -> Result<AccountStatus> {
    Ok(AccountStatus {
        account: state.store()?.account()?.map(Into::into),
        pending,
        sync: state.account.sync_status(),
        vaults: state.store()?.vaults()?,
        local_credentials: local_credentials(state)?,
    })
}

pub async fn current<R: Runtime>(app: &AppHandle<R>) -> Result<AccountStatus> {
    let state = app.state::<AppState>();
    let pending = state.account.inner.lock().await.pending.clone();
    status(&state, pending)
}

pub async fn server_info(url: &str) -> Result<ServerInfo> {
    let api = ApiClient::new(&normalize_url(url)?)?;
    Ok(api.server_info().await?)
}

// ───────────────────────────── sign in ─────────────────────────────

pub async fn login<R: Runtime>(app: &AppHandle<R>, form: LoginForm) -> Result<LoginOutcome> {
    let state = app.state::<AppState>();
    if state.store()?.account()?.is_some() {
        return Err(DesktopError::invalid("already signed in"));
    }
    if form.password.is_empty() {
        return Err(DesktopError::invalid("password is required"));
    }
    let server_url = normalize_url(&form.server_url)?;
    let device = device(&state)?;
    let mut inner = state.account.inner.lock().await;
    let (api, sso_session) = if form.sso {
        take_sso_session(&mut inner, &server_url, &form.email)?
    } else {
        (Arc::new(ApiClient::new(&server_url)?), None)
    };
    let started = LoginFlow::start(
        api.clone(),
        state.store()?.clone(),
        &form.email,
        &form.password,
        device,
        sso_session.map(|s| s.to_string()),
        form.captcha,
    )
    .await;
    // The SSO session is single-use on the server; keep it only for the
    // captcha retry, which repeats this very request.
    if form.sso
        && !matches!(&started, Err(e) if e.is_api_code(termoso_proto::error::codes::TURNSTILE_REQUIRED))
    {
        inner.sso = None;
    }
    let (flow, step) = started?;
    inner.api = Some(api);
    finish_step(app, &state, &mut inner, flow, step).await
}

// ───────────────────────────── single sign-on ─────────────────────────────

/// Ask the server for the IdP authorization URL and open it in the system
/// browser; the browser is sent back to [`SSO_CALLBACK`] and the result is
/// collected with [`sso_poll`]. Replaces any earlier unfinished SSO attempt.
/// Home-realm discovery before sign-in: which provider (if any) owns the e-mail domain.
pub async fn sso_discover(
    server_url: &str,
    email: &str,
) -> Result<termoso_proto::auth::SsoDiscoverResponse> {
    let server_url = normalize_url(server_url)?;
    let api = ApiClient::new(&server_url)?;
    Ok(api.sso_discover(email.trim()).await?)
}

pub async fn sso_start<R: Runtime>(app: &AppHandle<R>, form: SsoStartForm) -> Result<String> {
    let state = app.state::<AppState>();
    if state.store()?.account()?.is_some() {
        return Err(DesktopError::invalid("already signed in"));
    }
    let provider = form.provider.trim();
    if provider.is_empty() {
        return Err(DesktopError::invalid("provider is required"));
    }
    let server_url = normalize_url(&form.server_url)?;
    let api = Arc::new(ApiClient::new(&server_url)?);
    if !api
        .server_info()
        .await?
        .sso_providers
        .iter()
        .any(|p| p.id == provider)
    {
        return Err(DesktopError::invalid(
            "this server has no such sign-in provider",
        ));
    }
    let started = api.sso_start(provider, Some(SSO_CALLBACK)).await?;
    if !(started.authorization_url.starts_with("https://")
        || started.authorization_url.starts_with("http://"))
    {
        return Err(DesktopError::invalid(
            "server returned a non-web authorization URL",
        ));
    }
    if started.flow_id.is_empty() {
        return Err(DesktopError::invalid("server returned an empty SSO flow"));
    }
    let mut inner = state.account.inner.lock().await;
    if inner.flow.is_some() {
        return Err(DesktopError::invalid(
            "another sign-in is in progress; cancel it first",
        ));
    }
    inner.sso = Some(SsoFlow {
        api,
        server_url,
        flow_id: started.flow_id.clone(),
        outcome: None,
        session: None,
    });
    drop(inner);
    tauri_plugin_opener::open_url(&started.authorization_url, None::<&str>)
        .map_err(|e| DesktopError::new("io", format!("could not open the browser: {e}")))?;
    Ok(started.flow_id)
}

/// Where the SSO round trip stands. Terminal outcomes are fetched from the
/// server once and then answered from memory, so the browser callback and
/// the UI's polling may both call this freely.
pub async fn sso_poll<R: Runtime>(app: &AppHandle<R>) -> Result<SsoOutcome> {
    let state = app.state::<AppState>();
    let _serial = state.account.sso_poll.lock().await;
    // The account lock is not held across the network round trip so that
    // cancelling or a stuck server never blocks the rest of the account UI.
    let (api, flow_id) = {
        let inner = state.account.inner.lock().await;
        let flow = inner
            .sso
            .as_ref()
            .ok_or_else(|| DesktopError::invalid("no single sign-on in progress"))?;
        if let Some(out) = &flow.outcome {
            return Ok(out.clone());
        }
        (flow.api.clone(), flow.flow_id.clone())
    };
    let result = api.sso_poll(&flow_id).await?;
    let mut inner = state.account.inner.lock().await;
    let flow = inner
        .sso
        .as_mut()
        .filter(|f| f.flow_id == flow_id)
        .ok_or_else(|| DesktopError::invalid("single sign-on was cancelled"))?;
    let out = match result {
        SsoResult::Pending => return Ok(SsoOutcome::Pending),
        SsoResult::LoginRequired { sso_session, email } => {
            flow.session = Some(Zeroizing::new(sso_session));
            SsoOutcome::LoginRequired { email }
        }
        SsoResult::RegistrationRequired {
            sso_session,
            email,
            display_name,
        } => {
            flow.session = Some(Zeroizing::new(sso_session));
            SsoOutcome::RegistrationRequired {
                email,
                display_name,
            }
        }
        SsoResult::Linked { .. } => SsoOutcome::Failed {
            message: "This was an account-linking flow; finish it in the web cabinet".into(),
        },
        SsoResult::Failed { message } => SsoOutcome::Failed { message },
    };
    flow.outcome = Some(out.clone());
    Ok(out)
}

/// The browser came back through the `termoso://sso` deep link. Only the
/// flow this app started is accepted; the link carries no secrets, the
/// result is still fetched from the server.
pub async fn sso_callback<R: Runtime>(app: &AppHandle<R>, flow_id: &str) -> Result<SsoOutcome> {
    let state = app.state::<AppState>();
    let inner = state.account.inner.lock().await;
    match &inner.sso {
        Some(f) if f.flow_id == flow_id => {}
        _ => {
            return Err(DesktopError::invalid(
                "this sign-in link does not belong to a sign-in started here",
            ));
        }
    }
    drop(inner);
    sso_poll(app).await
}

pub async fn sso_cancel<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let state = app.state::<AppState>();
    state.account.inner.lock().await.sso = None;
    Ok(())
}

/// Hand the verified SSO session to a login / registration on the same
/// server for the same email. One-shot: the flow is dropped either way.
fn take_sso_session(
    inner: &mut Inner,
    server_url: &str,
    email: &str,
) -> Result<(Arc<ApiClient>, Option<Zeroizing<String>>)> {
    // Borrowed, not taken: a successful hand-over leaves the flow in place so
    // the caller can repeat the very same request after a captcha; the caller
    // drops it once the attempt settles. A rejected hand-over drops it here.
    let Some(flow) = inner.sso.as_ref() else {
        return Err(DesktopError::invalid("no single sign-on in progress"));
    };
    let handed = (|| {
        if flow.server_url != server_url {
            return Err(DesktopError::invalid(
                "single sign-on was started against a different server",
            ));
        }
        let verified = match &flow.outcome {
            Some(SsoOutcome::LoginRequired { email: e })
            | Some(SsoOutcome::RegistrationRequired { email: e, .. }) => e,
            _ => {
                return Err(DesktopError::invalid(
                    "single sign-on has not completed yet",
                ));
            }
        };
        if !verified.eq_ignore_ascii_case(email.trim()) {
            return Err(DesktopError::invalid(
                "email does not match the single sign-on identity",
            ));
        }
        let session = flow
            .session
            .clone()
            .ok_or_else(|| DesktopError::invalid("single sign-on session is missing"))?;
        Ok((flow.api.clone(), Some(session)))
    })();
    if handed.is_err() {
        inner.sso = None;
    }
    handed
}

async fn finish_step<R: Runtime>(
    app: &AppHandle<R>,
    state: &AppState,
    inner: &mut Inner,
    flow: LoginFlow,
    step: LoginStep,
) -> Result<LoginOutcome> {
    let out = outcome(&step);
    match step {
        LoginStep::Done(_) => {
            inner.flow = None;
            inner.pending = None;
            start_engine(app, state, inner)?;
        }
        _ => {
            inner.flow = Some(flow);
            inner.pending = Some(out.clone());
        }
    }
    Ok(out)
}

pub async fn mfa<R: Runtime>(
    app: &AppHandle<R>,
    credential: MfaCredential,
) -> Result<LoginOutcome> {
    let state = app.state::<AppState>();
    let mut inner = state.account.inner.lock().await;
    let mut flow = inner
        .flow
        .take()
        .ok_or_else(|| DesktopError::invalid("no sign-in in progress"))?;
    match flow.mfa(credential).await {
        Ok(step) => finish_step(app, &state, &mut inner, flow, step).await,
        Err(e) => {
            inner.flow = Some(flow);
            Err(e.into())
        }
    }
}

pub async fn mfa_email_send<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let state = app.state::<AppState>();
    let inner = state.account.inner.lock().await;
    let flow = inner
        .flow
        .as_ref()
        .ok_or_else(|| DesktopError::invalid("no sign-in in progress"))?;
    Ok(flow.send_mfa_email().await?)
}

pub async fn webauthn_challenge<R: Runtime>(app: &AppHandle<R>) -> Result<serde_json::Value> {
    let state = app.state::<AppState>();
    let inner = state.account.inner.lock().await;
    let flow = inner
        .flow
        .as_ref()
        .ok_or_else(|| DesktopError::invalid("no sign-in in progress"))?;
    Ok(flow.webauthn_challenge().await?)
}

pub async fn approve_device<R: Runtime>(app: &AppHandle<R>, code: &str) -> Result<LoginOutcome> {
    let state = app.state::<AppState>();
    let mut inner = state.account.inner.lock().await;
    let mut flow = inner
        .flow
        .take()
        .ok_or_else(|| DesktopError::invalid("no sign-in in progress"))?;
    match flow.approve_device(code).await {
        Ok(step) => finish_step(app, &state, &mut inner, flow, step).await,
        Err(e) => {
            inner.flow = Some(flow);
            Err(e.into())
        }
    }
}

pub async fn resend_device_code<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let state = app.state::<AppState>();
    let inner = state.account.inner.lock().await;
    let flow = inner
        .flow
        .as_ref()
        .ok_or_else(|| DesktopError::invalid("no sign-in in progress"))?;
    Ok(flow.resend_device_code().await?)
}

pub async fn cancel_login<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let state = app.state::<AppState>();
    let mut inner = state.account.inner.lock().await;
    inner.flow = None;
    inner.pending = None;
    inner.sso = None;
    if state.store()?.account()?.is_none() {
        inner.api = None;
    }
    Ok(())
}

pub async fn register<R: Runtime>(app: &AppHandle<R>, form: RegisterForm) -> Result<Registered> {
    let state = app.state::<AppState>();
    if state.store()?.account()?.is_some() {
        return Err(DesktopError::invalid("already signed in"));
    }
    if form.password.chars().count() < 12 {
        return Err(DesktopError::invalid(
            "password must be at least 12 characters",
        ));
    }
    let server_url = normalize_url(&form.server_url)?;
    let device = device(&state)?;
    let mut inner = state.account.inner.lock().await;
    let (api, sso_session) = if form.sso {
        take_sso_session(&mut inner, &server_url, &form.email)?
    } else {
        (Arc::new(ApiClient::new(&server_url)?), None)
    };
    let attempt = core::register(
        api.clone(),
        state.store()?.clone(),
        RegisterInput {
            email: form.email,
            password: form.password,
            display_name: form
                .display_name
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            device,
            invite_token: form.invite_token,
            sso_session: sso_session.map(|s| s.to_string()),
            turnstile_token: form.captcha,
        },
    )
    .await;
    // The SSO session is single-use on the server; keep it only for the
    // captcha retry, which repeats this very request.
    if form.sso
        && !matches!(&attempt, Err(e) if e.is_api_code(termoso_proto::error::codes::TURNSTILE_REQUIRED))
    {
        inner.sso = None;
    }
    let registered = attempt?;
    inner.api = Some(api);
    inner.flow = None;
    inner.pending = None;
    start_engine(app, &state, &mut inner)?;
    let phrase: Zeroizing<String> = registered.recovery_phrase;
    Ok(Registered {
        account: registered.signed_in.account.into(),
        recovery_phrase: phrase.to_string(),
    })
}

/// Restore the persisted session at startup and start syncing. Offline
/// servers are not an error: the engine will retry in the background.
pub async fn resume<R: Runtime>(app: &AppHandle<R>) -> Result<Option<AccountCard>> {
    let state = app.state::<AppState>();
    let Some(stored) = state.store()?.account()? else {
        return Ok(None);
    };
    let api = Arc::new(ApiClient::new(&stored.server_url)?);
    let mut inner = state.account.inner.lock().await;
    match core::resume(&api, &*state.store()?).await {
        Ok(Some(signed)) => {
            inner.api = Some(api);
            start_engine(app, &state, &mut inner)?;
            Ok(Some(signed.account.into()))
        }
        Ok(None) => Ok(None),
        Err(e) if e.is_unauthorized() => {
            core::sign_out_local(&api, &*state.store()?)?;
            state.account.update_status(|s| {
                s.state = SyncState::Error;
                s.last_error = Some("session revoked by the server".into());
            });
            Ok(None)
        }
        Err(e) => {
            // Offline: keep the stored token, run the engine so it reconnects.
            let secrets = state.store()?.account_secrets()?;
            api.set_token(Some(secrets.token));
            inner.api = Some(api);
            start_engine(app, &state, &mut inner)?;
            state.account.update_status(|s| {
                s.state = SyncState::Offline;
                s.last_error = Some(e.to_string());
            });
            Ok(Some(stored.into()))
        }
    }
}

/// Stop the sync engine and forget the in-memory API client and login
/// flows without touching the stored account: the device stays signed in
/// and [`resume`] picks it up again after unlock.
pub async fn suspend<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<AppState>();
    let mut inner = state.account.inner.lock().await;
    stop_engine(&mut inner).await;
    inner.flow = None;
    inner.pending = None;
    inner.reauth = None;
    inner.sso = None;
    if let Some(api) = inner.api.take() {
        api.set_token(None);
    }
    drop(inner);
    state.account.update_status(|s| *s = SyncStatus::default());
}

pub async fn sign_out<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let state = app.state::<AppState>();
    let mut inner = state.account.inner.lock().await;
    stop_engine(&mut inner).await;
    inner.flow = None;
    inner.pending = None;
    inner.reauth = None;
    let api = match inner.api.take() {
        Some(api) => api,
        None => match state.store()?.account()? {
            Some(a) => {
                let api = Arc::new(ApiClient::new(&a.server_url)?);
                api.set_token(Some(state.store()?.account_secrets()?.token));
                api
            }
            None => return Ok(()),
        },
    };
    core::sign_out(&api, &*state.store()?).await?;
    crate::avatars::clear_cache(&state);
    if let Ok(store) = state.store() {
        let _ = store.clear_file_cache(None);
    }
    let _ = std::fs::remove_dir_all(state.profile_dir.join(crate::sftp::FCACHE_DIR));
    state.account.update_status(|s| *s = SyncStatus::default());
    let _ = app.emit(SYNC_EVENT, SyncNotice::SignedOut);
    Ok(())
}

// ───────────────────────────── sync engine ─────────────────────────────

fn start_engine<R: Runtime>(app: &AppHandle<R>, state: &AppState, inner: &mut Inner) -> Result<()> {
    if inner.engine.is_some() {
        return Ok(());
    }
    let api = inner
        .api
        .clone()
        .ok_or_else(|| DesktopError::invalid("no API client"))?;
    let engine = SyncEngine::new(api, state.store()?.clone(), sync_options(state)?);
    let cancel = CancellationToken::new();
    let mut rx = engine.subscribe();
    let watcher_app = app.clone();
    let watcher = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    if on_event(&watcher_app, ev).await {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    let runner = tokio::spawn(engine.clone().run(cancel.clone()));
    let sshid_app = app.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::sshid::refresh(&sshid_app).await {
            tracing::debug!("sshid refresh skipped: {e}");
        }
    });
    inner.engine = Some(Engine {
        engine,
        cancel,
        runner,
        watcher,
    });
    crate::presence::refresh(app);
    Ok(())
}

/// The running sync engine, if signed in.
pub(crate) async fn engine<R: Runtime>(app: &AppHandle<R>) -> Option<Arc<SyncEngine>> {
    let state = app.state::<AppState>();
    let inner = state.account.inner.lock().await;
    inner.engine.as_ref().map(|e| e.engine.clone())
}

async fn stop_engine(inner: &mut Inner) {
    if let Some(e) = inner.engine.take() {
        e.stop();
    }
}

/// Apply a sync-engine event to the status and forward it. Returns `true`
/// when the engine has stopped for good.
async fn on_event<R: Runtime>(app: &AppHandle<R>, ev: SyncEvent) -> bool {
    let state = app.state::<AppState>();
    let notice = match ev {
        SyncEvent::Started => SyncNotice::Status {
            status: state
                .account
                .update_status(|s| s.state = SyncState::Syncing),
        },
        SyncEvent::Finished(report) => SyncNotice::Status {
            status: state.account.update_status(|s| apply_report(s, &report)),
        },
        SyncEvent::Failed(msg) => SyncNotice::Status {
            status: state.account.update_status(|s| {
                s.state = SyncState::Error;
                s.last_error = Some(msg);
            }),
        },
        SyncEvent::Connected => SyncNotice::Status {
            status: state.account.update_status(|s| {
                s.realtime = true;
                if s.state == SyncState::Offline {
                    s.state = SyncState::Idle;
                }
            }),
        },
        SyncEvent::Disconnected => SyncNotice::Status {
            status: state.account.update_status(|s| {
                s.realtime = false;
                if s.state == SyncState::Idle {
                    s.state = SyncState::Offline;
                }
            }),
        },
        SyncEvent::VaultsChanged => SyncNotice::VaultsChanged,
        SyncEvent::EntitiesChanged { vault_id } => SyncNotice::EntitiesChanged { vault_id },
        SyncEvent::HistoryChanged => SyncNotice::HistoryChanged,
        SyncEvent::LogsChanged => SyncNotice::LogsChanged,
        SyncEvent::AccountChanged => SyncNotice::AccountChanged,
        SyncEvent::PresenceChanged { team_id } => SyncNotice::PresenceChanged { team_id },
        SyncEvent::SessionRevoked => {
            let mut inner = state.account.inner.lock().await;
            // We are the watcher task: stop the runner, let ourselves return.
            if let Some(e) = inner.engine.take() {
                e.cancel.cancel();
                e.runner.abort();
            }
            if let Some(api) = inner.api.take() {
                api.set_token(None);
            }
            if let Err(e) = state.store().and_then(|s| Ok(s.clear_account()?)) {
                tracing::warn!("clearing revoked account failed: {e}");
            }
            state.account.update_status(|s| {
                *s = SyncStatus::default();
                s.state = SyncState::Error;
                s.last_error = Some("this device was signed out by the server".into());
            });
            let _ = app.emit(SYNC_EVENT, SyncNotice::SignedOut);
            return true;
        }
    };
    let _ = app.emit(SYNC_EVENT, notice);
    false
}

fn apply_report(s: &mut SyncStatus, r: &SyncReport) {
    s.state = if s.realtime {
        SyncState::Idle
    } else {
        SyncState::Offline
    };
    s.last_sync_at = Some(Utc::now());
    s.last_error = r.errors.first().map(|(id, code)| format!("{code} ({id})"));
    s.pushed = r.pushed;
    s.pulled = r.pulled;
    s.conflicts = r.conflicts;
}

pub async fn sync_now<R: Runtime>(app: &AppHandle<R>) -> Result<SyncStatus> {
    let state = app.state::<AppState>();
    let engine = {
        let inner = state.account.inner.lock().await;
        inner
            .engine
            .as_ref()
            .map(|e| e.engine.clone())
            .ok_or_else(|| DesktopError::invalid("not signed in"))?
    };
    state
        .account
        .update_status(|s| s.state = SyncState::Syncing);
    let result = engine.sync_once().await;
    let status = match &result {
        Ok(report) => state.account.update_status(|s| apply_report(s, report)),
        Err(e) => state.account.update_status(|s| {
            s.state = SyncState::Error;
            s.last_error = Some(e.to_string());
        }),
    };
    let _ = app.emit(
        SYNC_EVENT,
        SyncNotice::Status {
            status: status.clone(),
        },
    );
    if let Ok(report) = &result
        && report.changed_locally()
    {
        let _ = app.emit(SYNC_EVENT, SyncNotice::VaultsChanged);
    }
    result?;
    Ok(status)
}

/// Restart the engine with fresh options (after settings change).
pub async fn reconfigure<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let state = app.state::<AppState>();
    let mut inner = state.account.inner.lock().await;
    if inner.engine.is_none() {
        return Ok(());
    }
    stop_engine(&mut inner).await;
    start_engine(app, &state, &mut inner)
}

/// Switch credential sync for the Personal vault. Turning it off takes the
/// identities, keys and certificates off the server (they stay here);
/// turning it on pushes the local ones and pulls what other devices have.
/// Works offline too: the setting is saved and the engine picks it up.
pub async fn set_credential_sync<R: Runtime>(
    app: &AppHandle<R>,
    on: bool,
) -> Result<AccountStatus> {
    let state = app.state::<AppState>();
    let mut settings = state.settings()?;
    if settings.sync_credentials != on {
        settings.sync_credentials = on;
        state.save_settings(&settings)?;
    }
    reconfigure(app).await?;
    if let Some(engine) = engine(app).await {
        state
            .account
            .update_status(|s| s.state = SyncState::Syncing);
        let result = if on {
            engine.resync_credentials().await.map(Some)
        } else {
            engine.purge_credentials().await.map(|_| None)
        };
        let status = match &result {
            Ok(Some(report)) => state.account.update_status(|s| apply_report(s, report)),
            Ok(None) => state.account.update_status(|s| {
                s.state = SyncState::Idle;
                s.last_sync_at = Some(Utc::now());
            }),
            Err(e) => state.account.update_status(|s| {
                s.state = SyncState::Error;
                s.last_error = Some(e.to_string());
            }),
        };
        let _ = app.emit(SYNC_EVENT, SyncNotice::Status { status });
        let _ = app.emit(SYNC_EVENT, SyncNotice::VaultsChanged);
        result?;
    }
    current(app).await
}

// ───────────────────────────── devices ─────────────────────────────

/// The signed-in API client, or "not signed in".
pub(crate) async fn api<R: Runtime>(app: &AppHandle<R>) -> Result<Arc<ApiClient>> {
    let state = app.state::<AppState>();
    let inner = state.account.inner.lock().await;
    inner
        .api
        .clone()
        .filter(|a| a.token().is_some())
        .ok_or_else(|| DesktopError::invalid("not signed in"))
}

// ───────────────────────────── step-up ─────────────────────────────

/// Prove the password again so the session may perform sensitive changes
/// (the server answers `reauth_required` otherwise).
pub async fn reauth_start<R: Runtime>(
    app: &AppHandle<R>,
    password: Zeroizing<String>,
) -> Result<ReauthOutcome> {
    let state = app.state::<AppState>();
    let account = state
        .store()?
        .account()?
        .ok_or_else(|| DesktopError::invalid("not signed in"))?;
    let api = api(app).await?;
    let mut inner = state.account.inner.lock().await;
    inner.reauth = None;
    let (flow, step) = ReauthFlow::start(api, &account.email, &password).await?;
    Ok(keep_reauth(&mut inner, flow, step))
}

fn keep_reauth(inner: &mut Inner, flow: ReauthFlow, step: ReauthStep) -> ReauthOutcome {
    let out = reauth_outcome(&step);
    inner.reauth = match step {
        ReauthStep::Done { .. } => None,
        _ => Some(flow),
    };
    out
}

enum ReauthAnswer {
    Mfa(MfaCredential),
    EmailCode(String),
}

async fn continue_reauth<R: Runtime>(
    app: &AppHandle<R>,
    answer: ReauthAnswer,
) -> Result<ReauthOutcome> {
    let state = app.state::<AppState>();
    let mut inner = state.account.inner.lock().await;
    let mut flow = inner
        .reauth
        .take()
        .ok_or_else(|| DesktopError::invalid("no re-authentication in progress"))?;
    let result = match answer {
        ReauthAnswer::Mfa(credential) => flow.mfa(credential).await,
        ReauthAnswer::EmailCode(code) => flow.email_code(&code).await,
    };
    match result {
        Ok(step) => Ok(keep_reauth(&mut inner, flow, step)),
        Err(e) => {
            inner.reauth = Some(flow);
            Err(e.into())
        }
    }
}

pub async fn reauth_mfa<R: Runtime>(
    app: &AppHandle<R>,
    credential: MfaCredential,
) -> Result<ReauthOutcome> {
    continue_reauth(app, ReauthAnswer::Mfa(credential)).await
}

pub async fn reauth_email_code<R: Runtime>(
    app: &AppHandle<R>,
    code: String,
) -> Result<ReauthOutcome> {
    continue_reauth(app, ReauthAnswer::EmailCode(code)).await
}

pub async fn reauth_mfa_email_send<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let state = app.state::<AppState>();
    let inner = state.account.inner.lock().await;
    let flow = inner
        .reauth
        .as_ref()
        .ok_or_else(|| DesktopError::invalid("no re-authentication in progress"))?;
    Ok(flow.send_mfa_email().await?)
}

pub async fn reauth_webauthn_challenge<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<serde_json::Value> {
    let state = app.state::<AppState>();
    let inner = state.account.inner.lock().await;
    let flow = inner
        .reauth
        .as_ref()
        .ok_or_else(|| DesktopError::invalid("no re-authentication in progress"))?;
    Ok(flow.webauthn_challenge().await?)
}

pub async fn reauth_cancel<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let state = app.state::<AppState>();
    state.account.inner.lock().await.reauth = None;
    Ok(())
}

pub async fn devices<R: Runtime>(app: &AppHandle<R>) -> Result<Vec<Device>> {
    Ok(api(app).await?.devices().await?)
}

pub async fn vault_members<R: Runtime>(
    app: &AppHandle<R>,
    vault_id: Uuid,
) -> Result<Vec<VaultMember>> {
    Ok(api(app).await?.vault_members(vault_id).await?.members)
}

pub async fn revoke_device<R: Runtime>(app: &AppHandle<R>, id: Uuid) -> Result<()> {
    let state = app.state::<AppState>();
    if state.store()?.account()?.map(|a| a.device_id) == Some(id) {
        return Err(DesktopError::invalid(
            "use sign out to remove the current device",
        ));
    }
    Ok(api(app).await?.revoke_device(id).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_normalisation() {
        assert_eq!(
            normalize_url(" https://termoso.example.com/ ").unwrap(),
            "https://termoso.example.com"
        );
        assert!(normalize_url("termoso.example.com").is_err());
        assert!(normalize_url("").is_err());
    }

    #[test]
    fn report_updates_status() {
        let mut s = SyncStatus {
            realtime: true,
            ..SyncStatus::default()
        };
        apply_report(
            &mut s,
            &SyncReport {
                pushed: 2,
                pulled: 3,
                conflicts: 1,
                errors: vec![(Uuid::nil(), "too_large".into())],
                ..SyncReport::default()
            },
        );
        assert_eq!(s.state, SyncState::Idle);
        assert_eq!((s.pushed, s.pulled, s.conflicts), (2, 3, 1));
        assert!(s.last_error.as_deref().unwrap().starts_with("too_large"));
        assert!(s.last_sync_at.is_some());
    }

    #[test]
    fn outcome_serialises_step_tag() {
        let v = serde_json::to_value(LoginOutcome::MfaRequired {
            methods: vec![MfaMethod::Totp],
        })
        .unwrap();
        assert_eq!(v["step"], "mfaRequired");
        assert_eq!(v["methods"][0], "totp");
    }

    const SERVER: &str = "https://termoso.example.com";

    fn sso_inner(outcome: Option<SsoOutcome>, session: Option<&str>) -> Inner {
        Inner {
            sso: Some(SsoFlow {
                api: Arc::new(ApiClient::new(SERVER).unwrap()),
                server_url: SERVER.into(),
                flow_id: "flow-1".into(),
                outcome,
                session: session.map(|s| Zeroizing::new(s.to_string())),
            }),
            ..Inner::default()
        }
    }

    fn verified(email: &str) -> Option<SsoOutcome> {
        Some(SsoOutcome::LoginRequired {
            email: email.into(),
        })
    }

    #[test]
    fn sso_session_is_handed_over_once() {
        let mut inner = sso_inner(verified("ann@example.com"), Some("sess"));
        let (_, session) = take_sso_session(&mut inner, SERVER, " Ann@Example.com ").unwrap();
        assert_eq!(session.as_deref().map(String::as_str), Some("sess"));
        // The flow stays for a captcha retry of the same request; the caller
        // drops it once the attempt settles.
        assert!(inner.sso.is_some());
        inner.sso = None;
        assert!(take_sso_session(&mut inner, SERVER, "ann@example.com").is_err());
    }

    #[test]
    fn sso_session_refuses_other_server_or_email() {
        let mut inner = sso_inner(verified("ann@example.com"), Some("sess"));
        let err = take_sso_session(&mut inner, "https://other.example.com", "ann@example.com")
            .unwrap_err();
        assert!(err.to_string().contains("different server"), "{err}");
        assert!(inner.sso.is_none(), "a rejected hand-over drops the flow");

        let mut inner = sso_inner(verified("ann@example.com"), Some("sess"));
        let err = take_sso_session(&mut inner, SERVER, "bob@example.com").unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    #[test]
    fn sso_session_requires_a_verified_result() {
        for outcome in [
            None,
            Some(SsoOutcome::Pending),
            Some(SsoOutcome::Failed {
                message: "denied".into(),
            }),
        ] {
            let mut inner = sso_inner(outcome, Some("sess"));
            assert!(take_sso_session(&mut inner, SERVER, "ann@example.com").is_err());
        }
        let mut inner = sso_inner(verified("ann@example.com"), None);
        assert!(take_sso_session(&mut inner, SERVER, "ann@example.com").is_err());
    }

    #[test]
    fn sso_outcome_never_carries_the_session() {
        let v = serde_json::to_value(SsoOutcome::RegistrationRequired {
            email: "ann@example.com".into(),
            display_name: None,
        })
        .unwrap();
        assert_eq!(v["step"], "registrationRequired");
        assert_eq!(v["email"], "ann@example.com");
        assert!(v.get("ssoSession").is_none() && v.get("session").is_none());
        assert_eq!(v.as_object().unwrap().len(), 3);
    }
}
