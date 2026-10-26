//! Account and sync runtime for the mobile façade. Mirrors the desktop
//! runtime: OPAQUE sign-in, MFA / device-approval step machine, session
//! resume, sign-out and the background [`SyncEngine`] all live in Rust;
//! Kotlin sees profile data, sync status and change notifications.
//!
//! Secrets policy: the password only feeds OPAQUE and is dropped when the
//! call returns; the session token, account keys and vault keys stay in the
//! encrypted store. The recovery phrase is returned exactly once, from
//! [`AccountRuntime::register`].

use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use termoso_core::account::{
    self as core, LoginFlow, LoginStep, ReauthFlow, ReauthStep, RegisterInput,
};
use termoso_core::api::ApiClient;
use termoso_core::fido2::webauthn;
use termoso_core::store::{EntityFilter, Store, StoredAccount};
use termoso_core::sync::{SyncEngine, SyncEvent, SyncOptions, SyncReport};
use termoso_proto::account::ServerInfo;
use termoso_proto::auth::{
    Device, MfaCredential, MfaStatus, SsoKind, SsoResult, WebauthnCredentialInfo,
};
use termoso_proto::entities::is_credential_kind;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::dto::{VaultInfo, parse_id};
use crate::error::{MobileError, Result};
use crate::fido2::{self, Fido2Listener};
use crate::settings::MobileSettings;

/// Signed-in account as shown in the UI (no keys, no token).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountCard {
    pub server_url: String,
    pub user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    /// Content tag of the profile picture (see `TermosoApp::user_avatar`).
    pub avatar: Option<String>,
    pub is_admin: bool,
    pub device_id: String,
    /// RFC 3339.
    pub signed_in_at: String,
}

impl From<StoredAccount> for AccountCard {
    fn from(a: StoredAccount) -> Self {
        Self {
            server_url: a.server_url,
            user_id: a.user_id.to_string(),
            email: a.email,
            display_name: a.display_name,
            avatar: a.avatar,
            is_admin: a.is_admin,
            device_id: a.device_id.to_string(),
            signed_in_at: a.signed_in_at.to_rfc3339(),
        }
    }
}

/// What a server tells about itself before sign-in.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ServerCard {
    pub url: String,
    pub name: String,
    pub version: String,
    pub registration_open: bool,
    /// The server can send email (device approval / email MFA work).
    pub email: bool,
    /// A closed registration still lets identities verified by SSO sign up.
    pub sso_registration: bool,
    /// Single sign-on providers to offer on the sign-in screen.
    pub sso_providers: Vec<SsoProviderCard>,
    /// Corporate mode: only single sign-on is accepted.
    pub sso_only: bool,
    /// Teams may configure their own IdP on this server.
    pub team_idp: bool,
    /// Corporate mode: the team every account joins.
    pub home_team_name: Option<String>,
    /// `false` hides the personal vault.
    pub personal_vaults: bool,
}

impl ServerCard {
    fn new(url: String, info: ServerInfo) -> Self {
        Self {
            url,
            name: info.name,
            version: info.version,
            registration_open: info.registration_open,
            email: info.features.email,
            sso_registration: info.sso_registration,
            sso_providers: info
                .sso_providers
                .into_iter()
                .map(|p| SsoProviderCard {
                    id: p.id,
                    name: p.name,
                    saml: p.kind == SsoKind::Saml,
                })
                .collect(),
            sso_only: info.sso_only,
            team_idp: info.team_idp,
            home_team_name: info.home_team.as_ref().map(|t| t.name.clone()),
            personal_vaults: info.features.personal_vaults,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SsoProviderCard {
    /// Slug used in `sso_start`.
    pub id: String,
    pub name: String,
    /// SAML 2.0 rather than OpenID Connect.
    pub saml: bool,
}

/// Deep link the server sends the browser back to once the IdP is done.
pub const SSO_CALLBACK: &str = "termoso://sso";

/// What [`AccountRuntime::sso_start`] hands the UI: the page to open in a
/// Custom Tab and the flow the callback must name.
/// Result of e-mail domain discovery before sign-in.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SsoDiscoverCard {
    pub provider_id: Option<String>,
    pub provider_name: Option<String>,
    pub team_name: Option<String>,
    /// Password sign-in is refused for this domain.
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SsoStarted {
    pub flow_id: String,
    pub authorization_url: String,
}

/// Where a browser-based SSO sign-in stands. The verified `sso_session`
/// itself never crosses the FFI: it stays in Rust until `login` /
/// `register` bind it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MfaMethod {
    Totp,
    Webauthn,
    BackupCode,
    Email,
}

impl From<termoso_proto::auth::MfaMethod> for MfaMethod {
    fn from(m: termoso_proto::auth::MfaMethod) -> Self {
        use termoso_proto::auth::MfaMethod as M;
        match m {
            M::Totp => Self::Totp,
            M::Webauthn => Self::Webauthn,
            M::BackupCode => Self::BackupCode,
            M::Email => Self::Email,
        }
    }
}

/// Where an interactive sign-in stands.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum LoginOutcome {
    Done { account: AccountCard },
    MfaRequired { methods: Vec<MfaMethod> },
    DeviceApprovalRequired { email_hint: String },
}

impl From<&LoginStep> for LoginOutcome {
    fn from(step: &LoginStep) -> Self {
        match step {
            LoginStep::Done(s) => Self::Done {
                account: s.account.clone().into(),
            },
            LoginStep::MfaRequired { methods } => Self::MfaRequired {
                methods: methods.iter().copied().map(Into::into).collect(),
            },
            LoginStep::DeviceApprovalRequired { email_hint } => Self::DeviceApprovalRequired {
                email_hint: email_hint.clone(),
            },
        }
    }
}

/// Where a step-up (re-authentication) stands. Sensitive account changes —
/// revoking devices, removing security keys, SSH ID changes — answer
/// [`MobileError::ReauthRequired`] until the signed-in session proves the
/// password (and second factor) again through `reauth_*`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ReauthOutcome {
    /// Sensitive changes are allowed until `expires_at` (Unix millis).
    Done {
        expires_at: i64,
    },
    MfaRequired {
        methods: Vec<MfaMethod>,
    },
    /// The account has no password; a code went to the masked address.
    EmailCodeRequired {
        email_hint: String,
    },
}

impl From<&ReauthStep> for ReauthOutcome {
    fn from(step: &ReauthStep) -> Self {
        match step {
            ReauthStep::Done { expires_at } => Self::Done {
                expires_at: expires_at.timestamp_millis(),
            },
            ReauthStep::MfaRequired { methods } => Self::MfaRequired {
                methods: methods.iter().copied().map(Into::into).collect(),
            },
            ReauthStep::EmailCodeRequired { email_hint } => Self::EmailCodeRequired {
                email_hint: email_hint.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Registered {
    pub account: AccountCard,
    /// 24 words. Shown once; never stored by the UI.
    pub recovery_phrase: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, uniffi::Enum)]
pub enum SyncState {
    #[default]
    Idle,
    Syncing,
    Offline,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, uniffi::Record)]
pub struct SyncStatus {
    pub state: SyncState,
    /// Realtime channel connected: changes from other devices arrive at once.
    pub realtime: bool,
    /// RFC 3339.
    pub last_sync_at: Option<String>,
    pub last_error: Option<String>,
    pub pushed: u32,
    pub pulled: u32,
    pub conflicts: u32,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AccountStatus {
    pub account: Option<AccountCard>,
    /// A sign-in waiting for a second factor / device code.
    pub pending: Option<LoginOutcome>,
    pub sync: SyncStatus,
    pub vaults: Vec<VaultInfo>,
    /// Identities, keys and certificates of the Personal vault that exist
    /// only on this device because credential sync is off (0 when it is on).
    pub local_credentials: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceCard {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub app_version: String,
    /// RFC 3339.
    pub created_at: String,
    /// RFC 3339.
    pub last_seen_at: String,
    pub current: bool,
}

impl From<Device> for DeviceCard {
    fn from(d: Device) -> Self {
        Self {
            current: d.current,
            id: d.id.to_string(),
            name: d.name,
            platform: format!("{:?}", d.platform).to_lowercase(),
            app_version: d.app_version,
            created_at: d.created_at.to_rfc3339(),
            last_seen_at: d.last_seen_at.to_rfc3339(),
        }
    }
}

/// A security key registered as a second factor (`GET /account/mfa`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityKeyCredential {
    pub id: String,
    pub name: String,
    /// RFC 3339.
    pub created_at: String,
    /// RFC 3339.
    pub last_used_at: Option<String>,
}

impl From<WebauthnCredentialInfo> for SecurityKeyCredential {
    fn from(c: WebauthnCredentialInfo) -> Self {
        Self {
            id: c.id.to_string(),
            name: c.name,
            created_at: c.created_at.to_rfc3339(),
            last_used_at: c.last_used_at.map(|t| t.to_rfc3339()),
        }
    }
}

/// Second-factor setup of the signed-in account.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MfaCard {
    pub totp_enabled: bool,
    pub security_keys: Vec<SecurityKeyCredential>,
    pub backup_codes_remaining: u32,
}

impl From<MfaStatus> for MfaCard {
    fn from(s: MfaStatus) -> Self {
        Self {
            totp_enabled: s.totp_enabled,
            security_keys: s.webauthn_credentials.into_iter().map(Into::into).collect(),
            backup_codes_remaining: s.backup_codes_remaining,
        }
    }
}

/// Which attached security key to use for a WebAuthn ceremony, and its
/// PIN when the token has one set.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SecurityKeyRequest {
    /// Token from [`crate::Fido2Devices::list`]; `None` = whichever
    /// attached one recognises the credential (sign-in) or the only one
    /// attached (registration).
    pub device_id: Option<String>,
    pub pin: Option<String>,
}

/// Local data changed because of a sync pull; list screens should reload.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SyncChange {
    Vaults,
    Entities {
        vault_id: String,
    },
    History,
    Logs,
    Account,
    /// Who is connected to what changed in this team.
    Presence {
        team_id: String,
    },
}

/// Callbacks into Kotlin. Invoked from Rust worker threads; keep them quick
/// (post to the main thread, do not block).
#[uniffi::export(with_foreign)]
pub trait SyncListener: Send + Sync {
    fn on_status(&self, status: SyncStatus);
    fn on_changed(&self, change: SyncChange);
    /// The account is gone (sign-out or revoked by the server).
    fn on_signed_out(&self, reason: Option<String>);
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LoginForm {
    pub server_url: String,
    pub email: String,
    pub password: String,
    /// Bind the identity verified by the SSO round trip started with
    /// [`AccountRuntime::sso_start`] (the server then skips new-device
    /// approval).
    #[uniffi(default = false)]
    pub sso: bool,
    /// Cloudflare Turnstile token from the server's `/captcha` page, sent when
    /// the previous attempt failed with `turnstile_required`.
    #[uniffi(default = None)]
    pub captcha: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RegisterForm {
    pub server_url: String,
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
    pub invite_token: Option<String>,
    /// Bind the identity verified by the SSO round trip started with
    /// [`AccountRuntime::sso_start`].
    #[uniffi(default = false)]
    pub sso: bool,
    /// Cloudflare Turnstile token from the server's `/captcha` page, sent when
    /// the previous attempt failed with `turnstile_required`.
    #[uniffi(default = None)]
    pub captcha: Option<String>,
}

const MIN_PASSWORD_CHARS: usize = 12;

/// Trim, drop trailing slashes, require an http(s) scheme.
pub fn normalize_server_url(url: &str) -> Result<String> {
    let url = url.trim().trim_end_matches('/');
    if url.is_empty() {
        return Err(MobileError::invalid("server URL is required"));
    }
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(MobileError::invalid(
            "server URL must start with https:// or http://",
        ));
    }
    if url[url.find("://").unwrap_or(0) + 3..].is_empty() {
        return Err(MobileError::invalid("server URL has no host"));
    }
    Ok(url.to_string())
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
        return Err(MobileError::invalid("no single sign-on in progress"));
    };
    let handed = (|| {
        if flow.server_url != server_url {
            return Err(MobileError::invalid(
                "single sign-on was started against a different server",
            ));
        }
        let verified = match &flow.outcome {
            Some(SsoOutcome::LoginRequired { email: e })
            | Some(SsoOutcome::RegistrationRequired { email: e, .. }) => e,
            _ => {
                return Err(MobileError::invalid("single sign-on has not completed yet"));
            }
        };
        if !verified.eq_ignore_ascii_case(email.trim()) {
            return Err(MobileError::invalid(
                "email does not match the single sign-on identity",
            ));
        }
        let session = flow
            .session
            .clone()
            .ok_or_else(|| MobileError::invalid("single sign-on session is missing"))?;
        Ok((flow.api.clone(), Some(session)))
    })();
    if handed.is_err() {
        inner.sso = None;
    }
    handed
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

/// One store's account state. Held by [`crate::TermosoApp`]; background
/// tasks only hold a [`Weak`] so an unlocked vault can be dropped.
pub struct AccountRuntime {
    store: Arc<Store>,
    presence: Arc<crate::presence::Tracker>,
    logs_dir: PathBuf,
    device_name: Mutex<String>,
    inner: tokio::sync::Mutex<Inner>,
    /// Serialises SSO polls: the server hands a terminal result out once, so
    /// two concurrent polls must not both go to the network.
    sso_poll: tokio::sync::Mutex<()>,
    status: Mutex<SyncStatus>,
    listener: Mutex<Option<Arc<dyn SyncListener>>>,
}

const DEFAULT_DEVICE_NAME: &str = if cfg!(target_os = "ios") {
    "iPhone"
} else {
    "Android"
};

impl AccountRuntime {
    pub(crate) fn new(
        store: Arc<Store>,
        presence: Arc<crate::presence::Tracker>,
        logs_dir: PathBuf,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            presence,
            logs_dir,
            device_name: Mutex::new(DEFAULT_DEVICE_NAME.into()),
            inner: tokio::sync::Mutex::new(Inner::default()),
            sso_poll: tokio::sync::Mutex::new(()),
            status: Mutex::new(SyncStatus::default()),
            listener: Mutex::new(None),
        })
    }

    /// Facts the platform shell knows about the device (Android: storage
    /// encryption, keyguard, StrongBox). Sent with the next sign-in / refresh.
    pub fn set_posture(
        &self,
        os_version: String,
        disk_encryption: Option<bool>,
        screen_lock: Option<bool>,
        secure_key_storage: Option<bool>,
    ) {
        termoso_core::posture::set_reported(termoso_core::posture::Posture {
            os_version,
            disk_encryption,
            screen_lock,
            secure_key_storage,
        });
    }

    pub fn set_device_name(&self, name: String) {
        let name = name.trim().to_string();
        if !name.is_empty() {
            *self.device_name.lock().unwrap_or_else(|p| p.into_inner()) = name;
        }
    }

    pub fn set_listener(&self, listener: Option<Arc<dyn SyncListener>>) {
        *self.listener.lock().unwrap_or_else(|p| p.into_inner()) = listener;
    }

    fn listener(&self) -> Option<Arc<dyn SyncListener>> {
        self.listener
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub(crate) fn store(&self) -> &Store {
        &self.store
    }

    pub(crate) fn store_arc(&self) -> Arc<Store> {
        self.store.clone()
    }

    pub(crate) fn notify_changed(&self, change: SyncChange) {
        if let Some(l) = self.listener() {
            l.on_changed(change);
        }
    }

    /// Run one sync round on the runtime without waiting for it (after a
    /// vault-list change that may have queued re-encrypted rows).
    pub(crate) fn sync_in_background(self: &Arc<Self>) {
        let rt = self.clone();
        tokio::spawn(async move {
            if let Err(e) = rt.sync_now().await {
                tracing::debug!("sync after vault change: {e}");
            }
        });
    }

    pub fn sync_status(&self) -> SyncStatus {
        self.status
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn update_status(&self, f: impl FnOnce(&mut SyncStatus)) -> SyncStatus {
        let mut s = self.status.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut s);
        s.clone()
    }

    fn publish_status(&self, f: impl FnOnce(&mut SyncStatus)) {
        let status = self.update_status(f);
        if let Some(l) = self.listener() {
            l.on_status(status);
        }
    }

    fn device(&self) -> Result<termoso_proto::auth::DeviceInfo> {
        let name = self
            .device_name
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        Ok(core::device_info(
            &self.store,
            &name,
            core::current_platform(),
            env!("CARGO_PKG_VERSION"),
        )?)
    }

    pub async fn status(&self) -> Result<AccountStatus> {
        let pending = self.inner.lock().await.pending.clone();
        Ok(AccountStatus {
            account: self.store.account()?.map(Into::into),
            pending,
            sync: self.sync_status(),
            vaults: self
                .store
                .vaults()?
                .into_iter()
                .map(VaultInfo::from)
                .collect(),
            local_credentials: self.local_credentials()?,
        })
    }

    /// Personal-vault credentials that only this device has (credential
    /// sync off); 0 while the sync is on.
    fn local_credentials(&self) -> Result<u32> {
        if MobileSettings::load(&self.store)?.sync_credentials {
            return Ok(0);
        }
        let Some(vault) = self.store.personal_vault()? else {
            return Ok(0);
        };
        Ok(self
            .store
            .rows(&EntityFilter {
                vault_id: Some(vault.id),
                ..EntityFilter::default()
            })?
            .iter()
            .filter(|r| is_credential_kind(&r.kind))
            .count() as u32)
    }

    pub async fn server_info(url: &str) -> Result<ServerCard> {
        let url = normalize_server_url(url)?;
        let api = ApiClient::new(&url)?;
        Ok(ServerCard::new(url, api.server_info().await?))
    }

    // ---- sign in ------------------------------------------------------

    pub async fn login(self: &Arc<Self>, form: LoginForm) -> Result<LoginOutcome> {
        if self.store.account()?.is_some() {
            return Err(MobileError::invalid("already signed in"));
        }
        if form.email.trim().is_empty() {
            return Err(MobileError::invalid("email is required"));
        }
        if form.password.is_empty() {
            return Err(MobileError::invalid("password is required"));
        }
        let server_url = normalize_server_url(&form.server_url)?;
        let device = self.device()?;
        let mut inner = self.inner.lock().await;
        let (api, sso_session) = if form.sso {
            take_sso_session(&mut inner, &server_url, &form.email)?
        } else {
            (Arc::new(ApiClient::new(&server_url)?), None)
        };
        let started = LoginFlow::start(
            api.clone(),
            self.store.clone(),
            form.email.trim(),
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
        self.finish_step(&mut inner, flow, step)
    }

    // ---- single sign-on -----------------------------------------------

    /// Home-realm discovery: which provider (if any) owns the e-mail domain,
    /// and whether the matching team policy forbids password sign-in.
    pub async fn sso_discover(&self, server_url: &str, email: &str) -> Result<SsoDiscoverCard> {
        let server_url = normalize_server_url(server_url)?;
        let api = ApiClient::new(&server_url)?;
        let r = api.sso_discover(email.trim()).await?;
        Ok(SsoDiscoverCard {
            provider_id: r.provider.as_ref().map(|p| p.id.clone()),
            provider_name: r.provider.as_ref().map(|p| p.name.clone()),
            team_name: r.team_name,
            required: r.required,
        })
    }

    /// Ask the server for the IdP authorization URL. The UI opens it in a
    /// Custom Tab; the browser is sent back to [`SSO_CALLBACK`] and the
    /// result is collected with [`Self::sso_poll`]. Replaces any earlier
    /// unfinished SSO attempt.
    pub async fn sso_start(&self, server_url: &str, provider: &str) -> Result<SsoStarted> {
        if self.store.account()?.is_some() {
            return Err(MobileError::invalid("already signed in"));
        }
        let provider = provider.trim();
        if provider.is_empty() {
            return Err(MobileError::invalid("provider is required"));
        }
        let server_url = normalize_server_url(server_url)?;
        let api = Arc::new(ApiClient::new(&server_url)?);
        if !api
            .server_info()
            .await?
            .sso_providers
            .iter()
            .any(|p| p.id == provider)
        {
            return Err(MobileError::invalid(
                "this server has no such sign-in provider",
            ));
        }
        let started = api.sso_start(provider, Some(SSO_CALLBACK)).await?;
        if !(started.authorization_url.starts_with("https://")
            || started.authorization_url.starts_with("http://"))
        {
            return Err(MobileError::invalid(
                "server returned a non-web authorization URL",
            ));
        }
        if started.flow_id.is_empty() {
            return Err(MobileError::invalid("server returned an empty SSO flow"));
        }
        let mut inner = self.inner.lock().await;
        if inner.flow.is_some() {
            return Err(MobileError::invalid(
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
        Ok(SsoStarted {
            flow_id: started.flow_id,
            authorization_url: started.authorization_url,
        })
    }

    /// Where the SSO round trip stands. Terminal outcomes are fetched from
    /// the server once and then answered from memory, so the deep-link
    /// callback and the UI's polling may both call this freely.
    pub async fn sso_poll(&self) -> Result<SsoOutcome> {
        let _serial = self.sso_poll.lock().await;
        // The account lock is not held across the network round trip so
        // that cancelling or a stuck server never blocks the rest of the UI.
        let (api, flow_id) = {
            let inner = self.inner.lock().await;
            let flow = inner
                .sso
                .as_ref()
                .ok_or_else(|| MobileError::invalid("no single sign-on in progress"))?;
            if let Some(out) = &flow.outcome {
                return Ok(out.clone());
            }
            (flow.api.clone(), flow.flow_id.clone())
        };
        let result = api.sso_poll(&flow_id).await?;
        let mut inner = self.inner.lock().await;
        let flow = inner
            .sso
            .as_mut()
            .filter(|f| f.flow_id == flow_id)
            .ok_or_else(|| MobileError::invalid("single sign-on was cancelled"))?;
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

    /// The browser came back through the `termoso://sso` deep link. Only
    /// the flow this app started is accepted; the link carries no secrets,
    /// the result is still fetched from the server.
    pub async fn sso_callback(&self, flow_id: &str) -> Result<SsoOutcome> {
        let inner = self.inner.lock().await;
        match &inner.sso {
            Some(f) if f.flow_id == flow_id => {}
            _ => {
                return Err(MobileError::invalid(
                    "this sign-in link does not belong to a sign-in started here",
                ));
            }
        }
        drop(inner);
        self.sso_poll().await
    }

    pub async fn sso_cancel(&self) -> Result<()> {
        self.inner.lock().await.sso = None;
        Ok(())
    }

    fn finish_step(
        self: &Arc<Self>,
        inner: &mut Inner,
        flow: LoginFlow,
        step: LoginStep,
    ) -> Result<LoginOutcome> {
        let out = LoginOutcome::from(&step);
        match step {
            LoginStep::Done(_) => {
                inner.flow = None;
                inner.pending = None;
                self.start_engine(inner)?;
            }
            _ => {
                inner.flow = Some(flow);
                inner.pending = Some(out.clone());
            }
        }
        Ok(out)
    }

    pub async fn mfa(self: &Arc<Self>, method: MfaMethod, code: String) -> Result<LoginOutcome> {
        let code = code.trim().to_string();
        if code.is_empty() {
            return Err(MobileError::invalid("code is required"));
        }
        let credential = match method {
            MfaMethod::Totp => MfaCredential::Totp { code },
            MfaMethod::BackupCode => MfaCredential::BackupCode { code },
            MfaMethod::Email => MfaCredential::Email { code },
            MfaMethod::Webauthn => {
                return Err(MobileError::invalid(
                    "security keys sign a challenge instead of entering a code",
                ));
            }
        };
        let mut inner = self.inner.lock().await;
        let mut flow = inner
            .flow
            .take()
            .ok_or_else(|| MobileError::invalid("no sign-in in progress"))?;
        match flow.mfa(credential).await {
            Ok(step) => self.finish_step(&mut inner, flow, step),
            Err(e) => {
                inner.flow = Some(flow);
                Err(e.into())
            }
        }
    }

    /// Second factor with an attached security key (USB or NFC, see
    /// [`crate::Fido2Devices`]): fetches the WebAuthn challenge, has the
    /// token sign it and submits the assertion. Blocks until the token is
    /// touched; the sign-in stays pending when the ceremony fails, so the
    /// user can retry or switch method. `listener.on_touch` fires just
    /// before the token is asked.
    pub async fn mfa_security_key(
        self: &Arc<Self>,
        req: SecurityKeyRequest,
        listener: Option<Arc<dyn Fido2Listener>>,
    ) -> Result<LoginOutcome> {
        let (mut flow, api) = {
            let mut inner = self.inner.lock().await;
            let flow = inner
                .flow
                .take()
                .ok_or_else(|| MobileError::invalid("no sign-in in progress"))?;
            let api = inner
                .api
                .clone()
                .ok_or_else(|| MobileError::invalid("no sign-in in progress"))?;
            (flow, api)
        };
        // The token may take a while to be touched; other account calls
        // keep working meanwhile and `cancel_login` can drop the step.
        let result = self.security_key_step(&mut flow, &api, req, listener).await;
        let mut inner = self.inner.lock().await;
        if inner.pending.is_none() {
            return Err(MobileError::invalid("sign-in was cancelled"));
        }
        match result {
            Ok(step) => self.finish_step(&mut inner, flow, step),
            Err(e) => {
                inner.flow = Some(flow);
                Err(e)
            }
        }
    }

    async fn security_key_step(
        &self,
        flow: &mut LoginFlow,
        api: &ApiClient,
        req: SecurityKeyRequest,
        listener: Option<Arc<dyn Fido2Listener>>,
    ) -> Result<LoginStep> {
        let options = flow.webauthn_challenge().await?;
        let credential = Self::assert_security_key(api, options, req, listener).await?;
        Ok(flow.mfa(MfaCredential::Webauthn { credential }).await?)
    }

    /// Have the attached token sign the server's WebAuthn `options`.
    async fn assert_security_key(
        api: &ApiClient,
        options: serde_json::Value,
        req: SecurityKeyRequest,
        listener: Option<Arc<dyn Fido2Listener>>,
    ) -> Result<serde_json::Value> {
        let origin = webauthn::origin_for(api.server_url());
        let pin = req.pin.filter(|p| !p.is_empty()).map(Zeroizing::new);
        if let Some(l) = &listener {
            l.on_touch();
        }
        tokio::task::spawn_blocking(move || {
            fido2::registry().webauthn_assert(
                req.device_id.as_deref(),
                &options,
                &origin,
                pin.as_deref().map(|p| p.as_str()),
            )
        })
        .await
        .map_err(|e| MobileError::invalid(e.to_string()))?
        .map_err(Into::into)
    }

    pub async fn mfa_email_send(&self) -> Result<()> {
        let inner = self.inner.lock().await;
        let flow = inner
            .flow
            .as_ref()
            .ok_or_else(|| MobileError::invalid("no sign-in in progress"))?;
        Ok(flow.send_mfa_email().await?)
    }

    pub async fn approve_device(self: &Arc<Self>, code: String) -> Result<LoginOutcome> {
        let code = code.trim().to_string();
        if code.is_empty() {
            return Err(MobileError::invalid("code is required"));
        }
        let mut inner = self.inner.lock().await;
        let mut flow = inner
            .flow
            .take()
            .ok_or_else(|| MobileError::invalid("no sign-in in progress"))?;
        match flow.approve_device(&code).await {
            Ok(step) => self.finish_step(&mut inner, flow, step),
            Err(e) => {
                inner.flow = Some(flow);
                Err(e.into())
            }
        }
    }

    pub async fn resend_device_code(&self) -> Result<()> {
        let inner = self.inner.lock().await;
        let flow = inner
            .flow
            .as_ref()
            .ok_or_else(|| MobileError::invalid("no sign-in in progress"))?;
        Ok(flow.resend_device_code().await?)
    }

    pub async fn cancel_login(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.flow = None;
        inner.pending = None;
        inner.sso = None;
        if self.store.account()?.is_none() {
            inner.api = None;
        }
        Ok(())
    }

    // ---- step-up ------------------------------------------------------

    /// Prove the password again so the session may perform sensitive
    /// changes. The password only feeds the OPAQUE client, as at sign-in.
    pub async fn reauth_start(&self, password: String) -> Result<ReauthOutcome> {
        let password = Zeroizing::new(password);
        let account = self
            .store
            .account()?
            .ok_or_else(|| MobileError::invalid("not signed in"))?;
        let api = self.api().await?;
        let mut inner = self.inner.lock().await;
        inner.reauth = None;
        let (flow, step) = ReauthFlow::start(api, &account.email, &password).await?;
        Ok(Self::keep_reauth(&mut inner, flow, step))
    }

    fn keep_reauth(inner: &mut Inner, flow: ReauthFlow, step: ReauthStep) -> ReauthOutcome {
        let out = ReauthOutcome::from(&step);
        inner.reauth = match step {
            ReauthStep::Done { .. } => None,
            _ => Some(flow),
        };
        out
    }

    fn take_reauth(inner: &mut Inner) -> Result<ReauthFlow> {
        inner
            .reauth
            .take()
            .ok_or_else(|| MobileError::invalid("no re-authentication in progress"))
    }

    /// Answer the second factor of a step-up with a typed code.
    pub async fn reauth_mfa(&self, method: MfaMethod, code: String) -> Result<ReauthOutcome> {
        let code = code.trim().to_string();
        if code.is_empty() {
            return Err(MobileError::invalid("code is required"));
        }
        let credential = match method {
            MfaMethod::Totp => MfaCredential::Totp { code },
            MfaMethod::BackupCode => MfaCredential::BackupCode { code },
            MfaMethod::Email => MfaCredential::Email { code },
            MfaMethod::Webauthn => {
                return Err(MobileError::invalid(
                    "security keys sign a challenge instead of entering a code",
                ));
            }
        };
        let mut inner = self.inner.lock().await;
        let mut flow = Self::take_reauth(&mut inner)?;
        match flow.mfa(credential).await {
            Ok(step) => Ok(Self::keep_reauth(&mut inner, flow, step)),
            Err(e) => {
                inner.reauth = Some(flow);
                Err(e.into())
            }
        }
    }

    /// Second factor of a step-up with an attached security key; see
    /// [`Self::mfa_security_key`] for the ceremony.
    pub async fn reauth_security_key(
        &self,
        req: SecurityKeyRequest,
        listener: Option<Arc<dyn Fido2Listener>>,
    ) -> Result<ReauthOutcome> {
        let (mut flow, api) = {
            let mut inner = self.inner.lock().await;
            let flow = Self::take_reauth(&mut inner)?;
            let api = inner
                .api
                .clone()
                .ok_or_else(|| MobileError::invalid("not signed in"))?;
            (flow, api)
        };
        let result = async {
            let options = flow.webauthn_challenge().await?;
            let credential = Self::assert_security_key(&api, options, req, listener).await?;
            Ok::<_, MobileError>(flow.mfa(MfaCredential::Webauthn { credential }).await?)
        }
        .await;
        let mut inner = self.inner.lock().await;
        match result {
            Ok(step) => Ok(Self::keep_reauth(&mut inner, flow, step)),
            Err(e) => {
                inner.reauth = Some(flow);
                Err(e)
            }
        }
    }

    /// Submit the emailed code of a password-less step-up.
    pub async fn reauth_email_code(&self, code: String) -> Result<ReauthOutcome> {
        let code = code.trim().to_string();
        if code.is_empty() {
            return Err(MobileError::invalid("code is required"));
        }
        let mut inner = self.inner.lock().await;
        let mut flow = Self::take_reauth(&mut inner)?;
        match flow.email_code(&code).await {
            Ok(step) => Ok(Self::keep_reauth(&mut inner, flow, step)),
            Err(e) => {
                inner.reauth = Some(flow);
                Err(e.into())
            }
        }
    }

    /// Ask for a one-time MFA code by email during a step-up.
    pub async fn reauth_mfa_email_send(&self) -> Result<()> {
        let inner = self.inner.lock().await;
        let flow = inner
            .reauth
            .as_ref()
            .ok_or_else(|| MobileError::invalid("no re-authentication in progress"))?;
        Ok(flow.send_mfa_email().await?)
    }

    pub async fn reauth_cancel(&self) -> Result<()> {
        self.inner.lock().await.reauth = None;
        Ok(())
    }

    pub async fn register(self: &Arc<Self>, form: RegisterForm) -> Result<Registered> {
        if self.store.account()?.is_some() {
            return Err(MobileError::invalid("already signed in"));
        }
        if form.email.trim().is_empty() {
            return Err(MobileError::invalid("email is required"));
        }
        if form.password.chars().count() < MIN_PASSWORD_CHARS {
            return Err(MobileError::invalid(format!(
                "password must be at least {MIN_PASSWORD_CHARS} characters"
            )));
        }
        let server_url = normalize_server_url(&form.server_url)?;
        let device = self.device()?;
        let mut inner = self.inner.lock().await;
        let (api, sso_session) = if form.sso {
            take_sso_session(&mut inner, &server_url, &form.email)?
        } else {
            (Arc::new(ApiClient::new(&server_url)?), None)
        };
        let attempt = core::register(
            api.clone(),
            self.store.clone(),
            RegisterInput {
                email: form.email.trim().to_string(),
                password: form.password,
                display_name: form
                    .display_name
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                device,
                invite_token: form
                    .invite_token
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
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
        self.start_engine(&mut inner)?;
        Ok(Registered {
            account: registered.signed_in.account.into(),
            recovery_phrase: registered.recovery_phrase.to_string(),
        })
    }

    /// Restore the persisted session and start syncing. An unreachable
    /// server is not an error: the engine retries in the background.
    pub async fn resume(self: &Arc<Self>) -> Result<Option<AccountCard>> {
        let Some(stored) = self.store.account()? else {
            return Ok(None);
        };
        let api = Arc::new(ApiClient::new(&stored.server_url)?);
        let mut inner = self.inner.lock().await;
        if inner.engine.is_some() {
            return Ok(Some(stored.into()));
        }
        match core::resume(&api, &self.store).await {
            Ok(Some(signed)) => {
                inner.api = Some(api);
                self.start_engine(&mut inner)?;
                Ok(Some(signed.account.into()))
            }
            Ok(None) => Ok(None),
            Err(e) if e.is_unauthorized() => {
                core::sign_out_local(&api, &self.store)?;
                self.publish_status(|s| {
                    *s = SyncStatus::default();
                    s.state = SyncState::Error;
                    s.last_error = Some("session revoked by the server".into());
                });
                if let Some(l) = self.listener() {
                    l.on_signed_out(Some("This device was signed out by the server.".into()));
                }
                Ok(None)
            }
            Err(e) => {
                let secrets = self.store.account_secrets()?;
                api.set_token(Some(secrets.token));
                inner.api = Some(api);
                self.start_engine(&mut inner)?;
                self.publish_status(|s| {
                    s.state = SyncState::Offline;
                    s.last_error = Some(e.to_string());
                });
                Ok(Some(stored.into()))
            }
        }
    }

    pub async fn sign_out(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        if let Some(e) = inner.engine.take() {
            e.stop();
        }
        inner.flow = None;
        inner.pending = None;
        inner.sso = None;
        let api = match inner.api.take() {
            Some(api) => api,
            None => match self.store.account()? {
                Some(a) => {
                    let api = Arc::new(ApiClient::new(&a.server_url)?);
                    api.set_token(Some(self.store.account_secrets()?.token));
                    api
                }
                None => return Ok(()),
            },
        };
        core::sign_out(&api, &self.store).await?;
        self.update_status(|s| *s = SyncStatus::default());
        if let Some(l) = self.listener() {
            l.on_signed_out(None);
        }
        Ok(())
    }

    // ---- sync engine --------------------------------------------------

    fn start_engine(self: &Arc<Self>, inner: &mut Inner) -> Result<()> {
        if inner.engine.is_some() {
            return Ok(());
        }
        let api = inner
            .api
            .clone()
            .ok_or_else(|| MobileError::invalid("no API client"))?;
        let opts = SyncOptions {
            log_dir: Some(self.logs_dir.clone()),
            upload_logs: false,
            sync_credentials: MobileSettings::load(&self.store)?.sync_credentials,
            interval: Duration::from_secs(15 * 60),
            ..SyncOptions::default()
        };
        let engine = SyncEngine::new(api, self.store.clone(), opts);
        let cancel = CancellationToken::new();
        let mut rx = engine.subscribe();
        let weak: Weak<Self> = Arc::downgrade(self);
        let watcher = tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        let Some(rt) = weak.upgrade() else { break };
                        if rt.on_event(ev).await {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        let runner = tokio::spawn(engine.clone().run(cancel.clone()));
        self.presence.attach(&engine);
        let sshid: Weak<Self> = Arc::downgrade(self);
        tokio::spawn(async move {
            let Some(rt) = sshid.upgrade() else { return };
            if let Err(e) = rt.sshid_refresh().await {
                tracing::debug!("sshid refresh skipped: {e}");
            }
        });
        inner.engine = Some(Engine {
            engine,
            cancel,
            runner,
            watcher,
        });
        Ok(())
    }

    /// Apply an engine event to the status and forward it. Returns `true`
    /// when the engine has stopped for good.
    async fn on_event(&self, ev: SyncEvent) -> bool {
        let listener = self.listener();
        let notify = |change: SyncChange| {
            if let Some(l) = &listener {
                l.on_changed(change);
            }
        };
        match ev {
            SyncEvent::Started => self.publish_status(|s| s.state = SyncState::Syncing),
            SyncEvent::Finished(report) => {
                let changed = report.changed_locally();
                self.publish_status(|s| apply_report(s, &report));
                if changed {
                    notify(SyncChange::Vaults);
                }
            }
            SyncEvent::Failed(msg) => self.publish_status(|s| {
                s.state = SyncState::Error;
                s.last_error = Some(msg);
            }),
            SyncEvent::Connected => self.publish_status(|s| {
                s.realtime = true;
                if s.state == SyncState::Offline {
                    s.state = SyncState::Idle;
                }
            }),
            SyncEvent::Disconnected => self.publish_status(|s| {
                s.realtime = false;
                if s.state == SyncState::Idle {
                    s.state = SyncState::Offline;
                }
            }),
            SyncEvent::VaultsChanged => notify(SyncChange::Vaults),
            SyncEvent::EntitiesChanged { vault_id } => notify(SyncChange::Entities {
                vault_id: vault_id.to_string(),
            }),
            SyncEvent::HistoryChanged => notify(SyncChange::History),
            SyncEvent::LogsChanged => notify(SyncChange::Logs),
            SyncEvent::AccountChanged => notify(SyncChange::Account),
            SyncEvent::PresenceChanged { team_id } => notify(SyncChange::Presence {
                team_id: team_id.to_string(),
            }),
            SyncEvent::SessionRevoked => {
                let mut inner = self.inner.lock().await;
                // We are the watcher task: stop the runner, let ourselves return.
                if let Some(e) = inner.engine.take() {
                    e.cancel.cancel();
                    e.runner.abort();
                }
                if let Some(api) = inner.api.take() {
                    api.set_token(None);
                }
                if let Err(e) = self.store.clear_account() {
                    tracing::warn!("clearing revoked account failed: {e}");
                }
                self.publish_status(|s| {
                    *s = SyncStatus::default();
                    s.state = SyncState::Error;
                    s.last_error = Some("this device was signed out by the server".into());
                });
                if let Some(l) = &listener {
                    l.on_signed_out(Some("This device was signed out by the server.".into()));
                }
                return true;
            }
        }
        false
    }

    /// Fetch a teammate's recording body into the local log cache.
    /// Pin / annotate a recording on the server (team or synced personal log).
    pub async fn annotate_log(
        &self,
        id: Uuid,
        pinned: Option<bool>,
        note: Option<String>,
    ) -> Result<()> {
        let engine = {
            let inner = self.inner.lock().await;
            inner
                .engine
                .as_ref()
                .map(|e| e.engine.clone())
                .ok_or_else(|| MobileError::invalid("not signed in"))?
        };
        engine.annotate_log(id, pinned, note).await?;
        Ok(())
    }

    pub async fn fetch_log(&self, id: Uuid) -> Result<()> {
        let engine = {
            let inner = self.inner.lock().await;
            inner
                .engine
                .as_ref()
                .map(|e| e.engine.clone())
                .ok_or_else(|| MobileError::invalid("not signed in"))?
        };
        engine.download_log(id).await?;
        Ok(())
    }

    pub async fn sync_now(&self) -> Result<SyncStatus> {
        let engine = {
            let inner = self.inner.lock().await;
            inner
                .engine
                .as_ref()
                .map(|e| e.engine.clone())
                .ok_or_else(|| MobileError::invalid("not signed in"))?
        };
        self.publish_status(|s| s.state = SyncState::Syncing);
        let result = engine.sync_once().await;
        let status = match &result {
            Ok(report) => self.update_status(|s| apply_report(s, report)),
            Err(e) => self.update_status(|s| {
                s.state = SyncState::Error;
                s.last_error = Some(e.to_string());
            }),
        };
        if let Some(l) = self.listener() {
            l.on_status(status.clone());
            if matches!(&result, Ok(r) if r.changed_locally()) {
                l.on_changed(SyncChange::Vaults);
            }
        }
        result?;
        Ok(status)
    }

    /// Switch credential sync for the Personal vault. Off takes identities,
    /// keys and certificates off the server (they stay on this device); on
    /// pushes the local ones and pulls what other devices have. Works
    /// offline too: the setting is saved and the engine picks it up.
    pub async fn set_credential_sync(self: &Arc<Self>, on: bool) -> Result<AccountStatus> {
        let mut settings = MobileSettings::load(&self.store)?;
        if settings.sync_credentials != on {
            settings.sync_credentials = on;
            settings.save(&self.store)?;
        }
        let engine = {
            let mut inner = self.inner.lock().await;
            if let Some(e) = inner.engine.take() {
                e.stop();
                self.start_engine(&mut inner)?;
            }
            inner.engine.as_ref().map(|e| e.engine.clone())
        };
        if let Some(engine) = engine {
            self.publish_status(|s| s.state = SyncState::Syncing);
            let result = if on {
                engine.resync_credentials().await.map(Some)
            } else {
                engine.purge_credentials().await.map(|_| None)
            };
            let status = match &result {
                Ok(Some(report)) => self.update_status(|s| apply_report(s, report)),
                Ok(None) => self.update_status(|s| {
                    s.state = SyncState::Idle;
                    s.last_sync_at = Some(chrono::Utc::now().to_rfc3339());
                }),
                Err(e) => self.update_status(|s| {
                    s.state = SyncState::Error;
                    s.last_error = Some(e.to_string());
                }),
            };
            if let Some(l) = self.listener() {
                l.on_status(status);
                l.on_changed(SyncChange::Vaults);
            }
            result?;
        }
        self.status().await
    }

    // ---- devices ------------------------------------------------------

    pub(crate) async fn api(&self) -> Result<Arc<ApiClient>> {
        let inner = self.inner.lock().await;
        inner
            .api
            .clone()
            .filter(|a| a.token().is_some())
            .ok_or_else(|| MobileError::invalid("not signed in"))
    }

    pub async fn devices(&self) -> Result<Vec<DeviceCard>> {
        Ok(self
            .api()
            .await?
            .devices()
            .await?
            .into_iter()
            .map(DeviceCard::from)
            .collect())
    }

    pub async fn revoke_device(&self, id: String) -> Result<()> {
        let id = parse_id(&id)?;
        if self.store.account()?.map(|a| a.device_id) == Some(id) {
            return Err(MobileError::invalid(
                "use sign out to remove the current device",
            ));
        }
        Ok(self.api().await?.revoke_device(id).await?)
    }

    // ---- second factor ------------------------------------------------

    pub async fn mfa_status(&self) -> Result<MfaCard> {
        Ok(self.api().await?.mfa_status().await?.into())
    }

    /// Register an attached security key as a second factor under `name`.
    /// Blocks until the token is touched. Registration needs user
    /// verification when the token has a PIN, so pass it in `req`.
    pub async fn register_security_key(
        &self,
        name: String,
        req: SecurityKeyRequest,
        listener: Option<Arc<dyn Fido2Listener>>,
    ) -> Result<SecurityKeyCredential> {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(MobileError::invalid("name is required"));
        }
        let api = self.api().await?;
        let options = api.webauthn_register_start().await?;
        let origin = webauthn::origin_for(api.server_url());
        let pin = req.pin.filter(|p| !p.is_empty()).map(Zeroizing::new);
        if let Some(l) = &listener {
            l.on_touch();
        }
        let credential = tokio::task::spawn_blocking(move || {
            fido2::registry().webauthn_register(
                req.device_id.as_deref(),
                &options,
                &origin,
                pin.as_deref().map(|p| p.as_str()),
            )
        })
        .await
        .map_err(|e| MobileError::invalid(e.to_string()))??;
        Ok(api
            .webauthn_register_finish(&name, credential)
            .await?
            .into())
    }

    pub async fn remove_security_key(&self, id: String) -> Result<()> {
        Ok(self.api().await?.webauthn_delete(parse_id(&id)?).await?)
    }

    /// Stop background work. Called when the vault is closed.
    pub fn shutdown(self: &Arc<Self>, handle: &tokio::runtime::Handle) {
        match self.inner.try_lock() {
            Ok(mut inner) => {
                if let Some(e) = inner.engine.take() {
                    e.stop();
                }
            }
            Err(_) => {
                let rt = self.clone();
                handle.spawn(async move {
                    let mut inner = rt.inner.lock().await;
                    if let Some(e) = inner.engine.take() {
                        e.stop();
                    }
                });
            }
        }
        self.set_listener(None);
    }
}

fn apply_report(s: &mut SyncStatus, r: &SyncReport) {
    s.state = if s.realtime {
        SyncState::Idle
    } else {
        SyncState::Offline
    };
    s.last_sync_at = Some(chrono::Utc::now().to_rfc3339());
    s.last_error = r.errors.first().map(|(id, code)| format!("{code} ({id})"));
    s.pushed = u32::try_from(r.pushed).unwrap_or(u32::MAX);
    s.pulled = u32::try_from(r.pulled).unwrap_or(u32::MAX);
    s.conflicts = u32::try_from(r.conflicts).unwrap_or(u32::MAX);
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn normalizes_server_url() {
        assert_eq!(
            normalize_server_url("  https://termoso.example/// ").unwrap(),
            "https://termoso.example"
        );
        assert_eq!(
            normalize_server_url("http://10.0.2.2:8080").unwrap(),
            "http://10.0.2.2:8080"
        );
        assert!(normalize_server_url("").is_err());
        assert!(normalize_server_url("termoso.example").is_err());
        assert!(normalize_server_url("https://").is_err());
    }

    #[test]
    fn report_updates_status() {
        let mut s = SyncStatus {
            realtime: true,
            ..SyncStatus::default()
        };
        let r = SyncReport {
            pushed: 3,
            pulled: 5,
            conflicts: 1,
            errors: vec![(Uuid::nil(), "too_large".into())],
            history: (0, 0),
            logs: (0, 0),
        };
        apply_report(&mut s, &r);
        assert_eq!(s.state, SyncState::Idle);
        assert_eq!((s.pushed, s.pulled, s.conflicts), (3, 5, 1));
        assert!(s.last_error.as_deref().unwrap().starts_with("too_large"));
        assert!(s.last_sync_at.is_some());

        s.realtime = false;
        apply_report(&mut s, &SyncReport::default());
        assert_eq!(s.state, SyncState::Offline);
        assert_eq!(s.last_error, None);
    }

    const SERVER: &str = "https://termoso.example";

    fn sso_inner(outcome: Option<SsoOutcome>, session: Option<&str>) -> Inner {
        Inner {
            sso: Some(SsoFlow {
                api: Arc::new(ApiClient::new(SERVER).unwrap()),
                server_url: SERVER.to_string(),
                flow_id: "flow".to_string(),
                outcome,
                session: session.map(|s| Zeroizing::new(s.to_string())),
            }),
            ..Inner::default()
        }
    }

    fn verified(email: &str) -> Option<SsoOutcome> {
        Some(SsoOutcome::LoginRequired {
            email: email.to_string(),
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
        assert!(take_sso_session(&mut inner, "https://other.example", "ann@example.com").is_err());
        assert!(inner.sso.is_none(), "a rejected hand-over drops the flow");

        let mut inner = sso_inner(verified("ann@example.com"), Some("sess"));
        assert!(take_sso_session(&mut inner, SERVER, "bob@example.com").is_err());
    }

    #[test]
    fn sso_session_requires_a_verified_result() {
        for outcome in [
            None,
            Some(SsoOutcome::Pending),
            Some(SsoOutcome::Failed {
                message: "nope".into(),
            }),
        ] {
            let mut inner = sso_inner(outcome, Some("sess"));
            assert!(take_sso_session(&mut inner, SERVER, "ann@example.com").is_err());
        }
        let mut inner = sso_inner(verified("ann@example.com"), None);
        assert!(take_sso_session(&mut inner, SERVER, "ann@example.com").is_err());
    }

    #[test]
    fn server_card_lists_sso_providers() {
        let info: ServerInfo = serde_json::from_value(serde_json::json!({
            "name": "t", "version": "1", "registration_open": false,
            "sso_registration": true,
            "sso_providers": [{"id": "okta", "name": "Okta", "kind": "saml"}],
            "features": {"session_logs": false, "email": false, "webauthn": false, "teams": false},
            "max_entity_bytes": 1, "max_log_bytes": 1,
        }))
        .unwrap();
        let card = ServerCard::new(SERVER.into(), info);
        assert!(card.sso_registration);
        assert_eq!(
            card.sso_providers,
            vec![SsoProviderCard {
                id: "okta".into(),
                name: "Okta".into(),
                saml: true,
            }]
        );
    }
}
