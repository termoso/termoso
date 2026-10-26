//! Typed HTTP client for the Termoso server (`/api/v1`).
//!
//! Thin and deliberately dumb: every method maps 1:1 onto a route and speaks
//! the `termoso_proto` types. Cryptography, key handling and persistence live
//! in [`crate::account`] and [`crate::sync`]; nothing here ever sees a
//! password, a private key or a vault key.
//!
//! Failures come back as [`CoreError::Api`] carrying the server's machine
//! readable `code`, or [`CoreError::Http`] for transport problems.

use std::sync::RwLock;
use std::time::Duration;

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use termoso_proto::account::{
    AccountKeys, PresenceVisibilityRequest, ServerInfo, SettingsBlob, UpdateProfileRequest,
    UserProfile,
};
use termoso_proto::ai::{AiCommandRequest, AiCommandResponse, AiSettingsRequest, AiStatus};
use termoso_proto::auth::{
    AuthResponse, Device, DeviceApproveRequest, DeviceApproveResendRequest, DeviceList,
    LoginFinishRequest, LoginStartRequest, LoginStartResponse, MfaCredential, MfaStatus,
    MfaVerifyRequest, ReauthFinishRequest, ReauthStartRequest, ReauthStartResponse,
    RegisterFinishRequest, RegisterStartRequest, RegisterStartResponse, SsoResult,
    SsoStartResponse, WebauthnChallengeRequest, WebauthnCredentialInfo,
    WebauthnRegisterFinishRequest,
};
use termoso_proto::automation::{
    Automation, AutomationList, AutomationRun, AutomationRunList, ClaimRunsRequest,
    ClaimRunsResponse, CreateAutomationRequest, FinishRunRequest, UpdateAutomationRequest,
};
use termoso_proto::ca::{
    IssueCertificateRequest, IssueCertificateResponse, IssuedCertificate, IssuedCertificateList,
    RotateTeamCaRequest, TeamCa, UpdateTeamCaRequest,
};
use termoso_proto::error::ApiError;
use termoso_proto::live::{CreateLiveSessionRequest, LiveSession, LiveSessionList};
use termoso_proto::logs::{
    CreateLogRequest, CreateLogResponse, DownloadLogResponse, LogListResponse, SessionLog,
    UpdateLogRequest,
};
use termoso_proto::sshid::{
    AddFido2KeyRequest, AddPublicKeyRequest, CreateSshIdRequest, PutDeviceKeysRequest, SshIdKey,
    SshIdProfile,
};
use termoso_proto::sync::{
    HistoryClearRequest, HistoryKind, HistoryPullResponse, HistoryPushRequest, PullRequest,
    PullResponse, PushRequest, PushResponse,
};
use termoso_proto::team::{
    AuditEventList, CreateInviteRequest, CreateRoleRequest, CreateTeamRequest,
    CreateWebhookRequest, CreatedInvite, InviteList, PendingVaultKeys, PermissionCatalog,
    RoleMappingList, SetDefaultRoleRequest, Team, TeamList, TeamMemberList, TeamPoliciesResponse,
    TeamPresence, TeamRoleDef, TeamRoleList, UpdateRoleRequest, UpdateTeamMemberRequest,
    UpdateTeamPoliciesRequest, UpdateTeamRequest, UpdateWebhookRequest, Webhook,
    WebhookDeliveryList, WebhookList,
};
use termoso_proto::vault::{
    CreateVaultRequest, ResealMyKeyRequest, RotateVaultKeyRequest, RotateVaultKeyResponse,
    UpdateVaultRequest, Vault, VaultList, VaultMemberList, VaultMemberUpsert,
};
use url::Url;
use uuid::Uuid;

use crate::error::{CoreError, Result};

/// Filters for [`ApiClient::team_audit`]; `None` fields are omitted from the
/// query string.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditQuery {
    /// Only events with an id below this (cursor for older pages).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<i64>,
    /// Page size (server caps it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Exact action, or a prefix ending in `.` (e.g. `vault.`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Only events by this user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<Uuid>,
    /// Only events touching this vault.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<Uuid>,
}

/// `GET /account` body (profile + public key material).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AccountResponse {
    /// Profile.
    pub user: UserProfile,
    /// Public key and wrapped private key.
    pub keys: AccountKeys,
}

/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Client for one server. Cheap to clone the `Arc` it usually lives in; the
/// bearer token can be swapped at runtime (sign-in / sign-out).
pub struct ApiClient {
    http: reqwest::Client,
    base: Url,
    token: RwLock<Option<String>>,
    user_agent: String,
}

impl std::fmt::Debug for ApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiClient")
            .field("base", &self.base.as_str())
            .field("signed_in", &self.token().is_some())
            .finish()
    }
}

impl ApiClient {
    /// Connect to `server_url` (scheme + host, optional path prefix; the
    /// `/api/v1` segment is added here).
    pub fn new(server_url: &str) -> Result<Self> {
        Self::with_timeout(server_url, DEFAULT_TIMEOUT)
    }

    /// Like [`ApiClient::new`] with a custom request timeout.
    pub fn with_timeout(server_url: &str, timeout: Duration) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(default_user_agent())
            .build()?;
        Self::with_http(server_url, http)
    }

    /// Use a caller-configured `reqwest::Client` (proxy, custom roots,
    /// extra headers). The bearer token is still managed here.
    pub fn with_http(server_url: &str, http: reqwest::Client) -> Result<Self> {
        Ok(Self {
            http,
            base: normalize_server_url(server_url)?,
            token: RwLock::new(None),
            user_agent: default_user_agent(),
        })
    }

    /// Server base URL (normalised, trailing slash).
    pub fn server_url(&self) -> &Url {
        &self.base
    }

    /// `User-Agent` sent with every request.
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    /// Current bearer token.
    pub fn token(&self) -> Option<String> {
        self.token.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Install (or clear) the bearer token.
    pub fn set_token(&self, token: Option<String>) {
        *self.token.write().unwrap_or_else(|p| p.into_inner()) = token;
    }

    /// WebSocket endpoint (`ws[s]://…/api/v1/ws`).
    pub fn ws_url(&self) -> Result<Url> {
        self.ws_url_for("ws")
    }

    /// Multiplayer relay endpoint (`ws[s]://…/api/v1/live/{id}/ws`).
    pub fn live_ws_url(&self, id: Uuid) -> Result<Url> {
        self.ws_url_for(&format!("live/{id}/ws"))
    }

    /// Gateway tunnel endpoint (`ws[s]://…/api/v1/gateways/{id}/connect`).
    pub fn gateway_ws_url(&self, gateway_id: Uuid) -> Result<Url> {
        self.ws_url_for(&format!("gateways/{gateway_id}/connect"))
    }

    fn ws_url_for(&self, path: &str) -> Result<Url> {
        let mut u = self.api_url(path);
        let scheme = match u.scheme() {
            "https" => "wss",
            "http" => "ws",
            other => return Err(CoreError::Invalid(format!("unsupported scheme {other}"))),
        };
        u.set_scheme(scheme)
            .map_err(|_| CoreError::Invalid("cannot set ws scheme".into()))?;
        Ok(u)
    }

    fn api_url(&self, path: &str) -> Url {
        // `base` always ends with `/`, so joining a relative path keeps any
        // prefix the operator mounted the server under.
        self.base
            .join(&format!("api/v1/{}", path.trim_start_matches('/')))
            .expect("relative api path")
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        let mut rb = self.http.request(method, self.api_url(path));
        if let Some(t) = self.token() {
            rb = rb.bearer_auth(t);
        }
        rb
    }

    async fn send<T: DeserializeOwned>(rb: RequestBuilder) -> Result<T> {
        let resp = rb.send().await?;
        let resp = check(resp).await?;
        Ok(resp.json().await?)
    }

    async fn send_empty(rb: RequestBuilder) -> Result<()> {
        let resp = rb.send().await?;
        check(resp).await?;
        Ok(())
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        Self::send(self.request(Method::GET, path)).await
    }

    async fn get_query<T: DeserializeOwned, Q: Serialize + ?Sized>(
        &self,
        path: &str,
        query: &Q,
    ) -> Result<T> {
        Self::send(self.request(Method::GET, path).query(query)).await
    }

    async fn post<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        Self::send(self.request(Method::POST, path).json(body)).await
    }

    async fn post_empty<B: Serialize + ?Sized>(&self, path: &str, body: &B) -> Result<()> {
        Self::send_empty(self.request(Method::POST, path).json(body)).await
    }

    async fn patch<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        Self::send(self.request(Method::PATCH, path).json(body)).await
    }

    async fn patch_empty<B: Serialize + ?Sized>(&self, path: &str, body: &B) -> Result<()> {
        Self::send_empty(self.request(Method::PATCH, path).json(body)).await
    }

    async fn put_empty<B: Serialize + ?Sized>(&self, path: &str, body: &B) -> Result<()> {
        Self::send_empty(self.request(Method::PUT, path).json(body)).await
    }

    async fn put<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        Self::send(self.request(Method::PUT, path).json(body)).await
    }

    async fn delete_query<Q: Serialize + ?Sized>(&self, path: &str, q: &Q) -> Result<()> {
        Self::send_empty(self.request(Method::DELETE, path).query(q)).await
    }

    async fn delete(&self, path: &str) -> Result<()> {
        Self::send_empty(self.request(Method::DELETE, path)).await
    }

    // ───────────────────────────── server ─────────────────────────────

    /// `GET /server/info` — unauthenticated capability probe.
    pub async fn server_info(&self) -> Result<ServerInfo> {
        self.get("server/info").await
    }

    // ───────────────────────────── auth ─────────────────────────────

    /// `GET /auth/sso/{provider}/start` — begin a browser-based SSO round
    /// trip. `redirect` is where the server sends the browser afterwards
    /// (an app deep link); without it the browser lands on a "return to the
    /// app" page and the client picks the result up via [`Self::sso_poll`].
    pub async fn sso_start(
        &self,
        provider: &str,
        redirect: Option<&str>,
    ) -> Result<SsoStartResponse> {
        let path = format!("auth/sso/{}/start", pct(provider));
        match redirect {
            Some(r) => self.get_query(&path, &[("redirect", r)]).await,
            None => self.get(&path).await,
        }
    }

    /// `GET /auth/sso/flow/{flow_id}` — outcome of an SSO round trip.
    pub async fn sso_poll(&self, flow_id: &str) -> Result<SsoResult> {
        self.get(&format!("auth/sso/flow/{}", pct(flow_id))).await
    }

    /// `POST /auth/register/start`.
    pub async fn register_start(
        &self,
        req: &RegisterStartRequest,
    ) -> Result<RegisterStartResponse> {
        self.post("auth/register/start", req).await
    }

    /// `POST /auth/register/finish`.
    pub async fn register_finish(&self, req: &RegisterFinishRequest) -> Result<AuthResponse> {
        self.post("auth/register/finish", req).await
    }

    /// `POST /auth/login/start`.
    pub async fn login_start(&self, req: &LoginStartRequest) -> Result<LoginStartResponse> {
        self.post("auth/login/start", req).await
    }

    /// `POST /auth/login/finish`.
    pub async fn login_finish(&self, req: &LoginFinishRequest) -> Result<AuthResponse> {
        self.post("auth/login/finish", req).await
    }

    /// `POST /auth/mfa/verify`.
    pub async fn mfa_verify(
        &self,
        mfa_token: &str,
        credential: MfaCredential,
    ) -> Result<AuthResponse> {
        self.post(
            "auth/mfa/verify",
            &MfaVerifyRequest {
                mfa_token: mfa_token.into(),
                credential,
            },
        )
        .await
    }

    /// `POST /auth/reauth/start` — step-up for the current session; sensitive
    /// account mutations answer `reauth_required` until this succeeds.
    pub async fn reauth_start(&self, req: &ReauthStartRequest) -> Result<ReauthStartResponse> {
        self.post("auth/reauth/start", req).await
    }

    /// `POST /auth/reauth/finish`. `MfaRequired` means the second factor is
    /// still pending: verify it with the returned `mfa_token` as for login.
    pub async fn reauth_finish(&self, req: &ReauthFinishRequest) -> Result<AuthResponse> {
        self.post("auth/reauth/finish", req).await
    }

    /// `POST /auth/mfa/webauthn/challenge` — raw options for the platform
    /// authenticator.
    pub async fn mfa_webauthn_challenge(&self, mfa_token: &str) -> Result<serde_json::Value> {
        self.post(
            "auth/mfa/webauthn/challenge",
            &WebauthnChallengeRequest {
                mfa_token: mfa_token.into(),
            },
        )
        .await
    }

    /// `POST /auth/mfa/email/send`.
    pub async fn mfa_email_send(&self, mfa_token: &str) -> Result<()> {
        self.post_empty(
            "auth/mfa/email/send",
            &WebauthnChallengeRequest {
                mfa_token: mfa_token.into(),
            },
        )
        .await
    }

    /// `POST /auth/device/approve`.
    pub async fn device_approve(&self, approval_token: &str, code: &str) -> Result<AuthResponse> {
        self.post(
            "auth/device/approve",
            &DeviceApproveRequest {
                approval_token: approval_token.into(),
                code: code.into(),
            },
        )
        .await
    }

    /// `POST /auth/device/approve/resend`.
    pub async fn device_approve_resend(&self, approval_token: &str) -> Result<()> {
        self.post_empty(
            "auth/device/approve/resend",
            &DeviceApproveResendRequest {
                approval_token: approval_token.into(),
            },
        )
        .await
    }

    /// `POST /auth/logout` — revokes the current session server-side.
    pub async fn logout(&self) -> Result<()> {
        Self::send_empty(self.request(Method::POST, "auth/logout")).await
    }

    // ───────────────────────────── account ─────────────────────────────

    /// `GET /account`.
    pub async fn account(&self) -> Result<AccountResponse> {
        self.get("account").await
    }

    /// `PATCH /account/profile`.
    pub async fn update_profile(&self, display_name: Option<String>) -> Result<UserProfile> {
        self.patch("account/profile", &UpdateProfileRequest { display_name })
            .await
    }

    /// `PUT /account/avatar` — replace the profile picture with `image`
    /// (any common raster format; the server shrinks it).
    pub async fn put_avatar(&self, image: Vec<u8>, content_type: &str) -> Result<UserProfile> {
        Self::send(
            self.request(Method::PUT, "account/avatar")
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(image),
        )
        .await
    }

    /// `DELETE /account/avatar`.
    pub async fn delete_avatar(&self) -> Result<UserProfile> {
        Self::send(self.request(Method::DELETE, "account/avatar")).await
    }

    /// `GET /users/{id}/avatar` — the normalised WebP, or `None` when the
    /// user has no picture.
    pub async fn user_avatar(&self, user_id: Uuid) -> Result<Option<Vec<u8>>> {
        let resp = self
            .request(Method::GET, &format!("users/{user_id}/avatar"))
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = check(resp).await?;
        Ok(Some(resp.bytes().await?.to_vec()))
    }

    /// `PUT /account/presence` — hide / show this account in team presence.
    pub async fn set_presence_hidden(&self, hidden: bool) -> Result<UserProfile> {
        Self::send(
            self.request(Method::PUT, "account/presence")
                .json(&PresenceVisibilityRequest { hidden }),
        )
        .await
    }

    // ───────────────────────────── ai ─────────────────────────────

    /// `GET /account/ai` — provider on offer, opt-in state and today's quota.
    pub async fn ai_status(&self) -> Result<AiStatus> {
        self.get("account/ai").await
    }

    /// `PUT /account/ai` — opt in to (or out of) AI command suggestions.
    pub async fn set_ai_enabled(&self, enabled: bool) -> Result<AiStatus> {
        Self::send(
            self.request(Method::PUT, "account/ai")
                .json(&AiSettingsRequest { enabled }),
        )
        .await
    }

    /// `POST /ai/command` — one shell command for a short request. Only the
    /// request text and the OS/shell labels leave the machine; the caller
    /// decides what (if anything) to do with the answer.
    pub async fn ai_command(&self, req: &AiCommandRequest) -> Result<AiCommandResponse> {
        self.post("ai/command", req).await
    }

    /// `GET /account/settings` — encrypted settings blob.
    pub async fn settings(&self) -> Result<SettingsBlob> {
        self.get("account/settings").await
    }

    /// `GET /account/devices`.
    pub async fn devices(&self) -> Result<Vec<Device>> {
        let l: DeviceList = self.get("account/devices").await?;
        Ok(l.devices)
    }

    /// `DELETE /account/devices/{id}`.
    pub async fn revoke_device(&self, id: Uuid) -> Result<()> {
        self.delete(&format!("account/devices/{id}")).await
    }

    // ─────────────────────────────── MFA ──────────────────────────────

    /// `GET /account/mfa`.
    pub async fn mfa_status(&self) -> Result<MfaStatus> {
        self.get("account/mfa").await
    }

    /// `POST /account/mfa/webauthn/register/start` — WebAuthn
    /// `PublicKeyCredentialCreationOptions` (`{"publicKey": …}`).
    pub async fn webauthn_register_start(&self) -> Result<serde_json::Value> {
        self.post(
            "account/mfa/webauthn/register/start",
            &serde_json::json!({}),
        )
        .await
    }

    /// `POST /account/mfa/webauthn/register/finish` with the
    /// `RegisterPublicKeyCredential` the authenticator produced.
    pub async fn webauthn_register_finish(
        &self,
        name: &str,
        credential: serde_json::Value,
    ) -> Result<WebauthnCredentialInfo> {
        self.post(
            "account/mfa/webauthn/register/finish",
            &WebauthnRegisterFinishRequest {
                name: name.into(),
                credential,
            },
        )
        .await
    }

    /// `DELETE /account/mfa/webauthn/{id}`.
    pub async fn webauthn_delete(&self, id: Uuid) -> Result<()> {
        self.delete(&format!("account/mfa/webauthn/{id}")).await
    }

    // ───────────────────────────── SSH ID ─────────────────────────────

    /// `GET /account/sshid` — the account's SSH ID, `None` until claimed.
    pub async fn sshid(&self) -> Result<Option<SshIdProfile>> {
        self.get("account/sshid").await
    }

    /// `POST /account/sshid` — claim `handle`.
    pub async fn create_sshid(&self, handle: &str) -> Result<SshIdProfile> {
        self.post(
            "account/sshid",
            &CreateSshIdRequest {
                handle: handle.to_string(),
            },
        )
        .await
    }

    /// `DELETE /account/sshid` — drop the handle and every published key.
    pub async fn delete_sshid(&self) -> Result<()> {
        self.delete("account/sshid").await
    }

    /// `PUT /account/sshid/keys/device` — replace this device's public keys.
    pub async fn put_sshid_device_keys(&self, req: &PutDeviceKeysRequest) -> Result<SshIdProfile> {
        Self::send(
            self.request(Method::PUT, "account/sshid/keys/device")
                .json(req),
        )
        .await
    }

    /// `POST /account/sshid/keys` — publish a public key the user already has.
    pub async fn add_sshid_public_key(&self, req: &AddPublicKeyRequest) -> Result<SshIdKey> {
        self.post("account/sshid/keys", req).await
    }

    /// `POST /account/sshid/keys/fido2` — publish a security-key public key.
    pub async fn add_sshid_fido2_key(&self, req: &AddFido2KeyRequest) -> Result<SshIdKey> {
        self.post("account/sshid/keys/fido2", req).await
    }

    /// `DELETE /account/sshid/keys/{id}`.
    pub async fn remove_sshid_key(&self, id: Uuid) -> Result<()> {
        self.delete(&format!("account/sshid/keys/{id}")).await
    }

    // ───────────────────────────── vaults / teams ─────────────────────────────

    /// `GET /vaults` — every vault we are a member of, with our sealed key.
    pub async fn vaults(&self) -> Result<Vec<Vault>> {
        let l: VaultList = self.get("vaults").await?;
        Ok(l.vaults)
    }

    /// `GET /vaults/{id}`.
    pub async fn vault(&self, id: Uuid) -> Result<Vault> {
        self.get(&format!("vaults/{id}")).await
    }

    /// `GET /vaults/{id}/members`.
    pub async fn vault_members(&self, id: Uuid) -> Result<VaultMemberList> {
        self.get(&format!("vaults/{id}/members")).await
    }

    /// `PUT /vaults/{id}/members/{user_id}` — grant / reseal a key.
    pub async fn upsert_vault_member(&self, id: Uuid, member: &VaultMemberUpsert) -> Result<()> {
        self.put_empty(&format!("vaults/{id}/members/{}", member.user_id), member)
            .await
    }

    /// `DELETE /vaults/{id}/members/{user_id}` — revoke access (rotate the key afterwards).
    pub async fn remove_vault_member(&self, id: Uuid, user_id: Uuid) -> Result<()> {
        self.delete(&format!("vaults/{id}/members/{user_id}")).await
    }

    /// `PATCH /vaults/{id}` — rename.
    pub async fn update_vault(&self, id: Uuid, req: &UpdateVaultRequest) -> Result<Vault> {
        self.patch(&format!("vaults/{id}"), req).await
    }

    /// `DELETE /vaults/{id}` — delete a team vault with everything in it.
    pub async fn delete_vault(&self, id: Uuid) -> Result<()> {
        self.delete(&format!("vaults/{id}")).await
    }

    /// `POST /vaults/{id}/rotate-key`.
    pub async fn rotate_vault_key(
        &self,
        id: Uuid,
        req: &RotateVaultKeyRequest,
    ) -> Result<RotateVaultKeyResponse> {
        self.post(&format!("vaults/{id}/rotate-key"), req).await
    }

    /// `PUT /vaults/{id}/my-key` — replace our own sealed copy of the current key.
    pub async fn reseal_my_key(&self, id: Uuid, req: &ResealMyKeyRequest) -> Result<()> {
        self.put_empty(&format!("vaults/{id}/my-key"), req).await
    }

    /// `GET /teams`.
    pub async fn teams(&self) -> Result<TeamList> {
        self.get("teams").await
    }

    /// `POST /teams`.
    pub async fn create_team(&self, req: &CreateTeamRequest) -> Result<Team> {
        self.post("teams", req).await
    }

    /// `GET /teams/{id}`.
    pub async fn team(&self, id: Uuid) -> Result<Team> {
        self.get(&format!("teams/{id}")).await
    }

    /// `PATCH /teams/{id}` — rename.
    pub async fn update_team(&self, id: Uuid, req: &UpdateTeamRequest) -> Result<Team> {
        self.patch(&format!("teams/{id}"), req).await
    }

    /// `DELETE /teams/{id}` — owner only; removes the team and its vaults.
    pub async fn delete_team(&self, id: Uuid) -> Result<()> {
        self.delete(&format!("teams/{id}")).await
    }

    /// `POST /teams/{id}/leave`.
    pub async fn leave_team(&self, id: Uuid) -> Result<()> {
        self.post_empty(&format!("teams/{id}/leave"), &()).await
    }

    /// `GET /teams/{id}/members`.
    pub async fn team_members(&self, id: Uuid) -> Result<TeamMemberList> {
        self.get(&format!("teams/{id}/members")).await
    }

    /// `PATCH /teams/{id}/members/{user_id}` — change a member's team role.
    pub async fn update_team_member(
        &self,
        id: Uuid,
        user_id: Uuid,
        req: &UpdateTeamMemberRequest,
    ) -> Result<()> {
        self.patch_empty(&format!("teams/{id}/members/{user_id}"), req)
            .await
    }

    /// `DELETE /teams/{id}/members/{user_id}`.
    pub async fn remove_team_member(&self, id: Uuid, user_id: Uuid) -> Result<()> {
        self.delete(&format!("teams/{id}/members/{user_id}")).await
    }

    /// Owner-only: delete the account of a member the team created
    /// (sign-up through its invitation). Requires a fresh step-up.
    pub async fn delete_team_member_account(&self, id: Uuid, user_id: Uuid) -> Result<()> {
        self.delete(&format!("teams/{id}/members/{user_id}/account"))
            .await
    }

    /// `GET /teams/{id}/invites` — pending invitations.
    pub async fn team_invites(&self, id: Uuid) -> Result<InviteList> {
        self.get(&format!("teams/{id}/invites")).await
    }

    /// `POST /teams/{id}/invites`.
    pub async fn create_invite(
        &self,
        id: Uuid,
        req: &CreateInviteRequest,
    ) -> Result<CreatedInvite> {
        self.post(&format!("teams/{id}/invites"), req).await
    }

    /// `DELETE /teams/{id}/invites/{invite_id}` — revoke.
    pub async fn delete_invite(&self, id: Uuid, invite_id: Uuid) -> Result<()> {
        self.delete(&format!("teams/{id}/invites/{invite_id}"))
            .await
    }

    /// `POST /teams/{id}/vaults` — create a team vault with pre-sealed member keys.
    pub async fn create_team_vault(&self, id: Uuid, req: &CreateVaultRequest) -> Result<Vault> {
        self.post(&format!("teams/{id}/vaults"), req).await
    }

    /// `POST /invites/{token}/accept` — join the team behind an invitation link.
    pub async fn accept_invite(&self, token: &str) -> Result<Team> {
        let token = token.trim();
        if token.is_empty()
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(CoreError::Invalid("malformed invitation token".into()));
        }
        self.post(&format!("invites/{token}/accept"), &()).await
    }

    /// `GET /teams/{id}/pending-keys`.
    pub async fn team_pending_keys(&self, team_id: Uuid) -> Result<PendingVaultKeys> {
        self.get(&format!("teams/{team_id}/pending-keys")).await
    }

    /// `GET /teams/{id}/presence` — who is connected to which team-vault host.
    pub async fn team_presence(&self, team_id: Uuid) -> Result<TeamPresence> {
        self.get(&format!("teams/{team_id}/presence")).await
    }

    /// `GET /teams/{id}/audit` — team activity log, newest first.
    pub async fn team_audit(&self, team_id: Uuid, q: &AuditQuery) -> Result<AuditEventList> {
        self.get_query(&format!("teams/{team_id}/audit"), q).await
    }

    // ───────────────── roles, policies, webhooks (0.9.0) ─────────────────

    /// `GET /teams/{id}/permissions` — the permission catalog.
    pub async fn team_permissions(&self, team_id: Uuid) -> Result<PermissionCatalog> {
        self.get(&format!("teams/{team_id}/permissions")).await
    }

    /// `GET /teams/{id}/roles`.
    pub async fn team_roles(&self, team_id: Uuid) -> Result<TeamRoleList> {
        self.get(&format!("teams/{team_id}/roles")).await
    }

    /// `POST /teams/{id}/roles`.
    pub async fn team_role_create(
        &self,
        team_id: Uuid,
        req: &CreateRoleRequest,
    ) -> Result<TeamRoleDef> {
        self.post(&format!("teams/{team_id}/roles"), req).await
    }

    /// `PATCH /teams/{id}/roles/{role}`.
    pub async fn team_role_update(
        &self,
        team_id: Uuid,
        role_id: Uuid,
        req: &UpdateRoleRequest,
    ) -> Result<TeamRoleDef> {
        self.patch(&format!("teams/{team_id}/roles/{role_id}"), req)
            .await
    }

    /// `DELETE /teams/{id}/roles/{role}?reassign_to=` — members move to `reassign_to`
    /// (the default role when `None`).
    pub async fn team_role_delete(
        &self,
        team_id: Uuid,
        role_id: Uuid,
        reassign_to: Option<Uuid>,
    ) -> Result<()> {
        let q: Vec<(&str, String)> = reassign_to
            .into_iter()
            .map(|r| ("reassign_to", r.to_string()))
            .collect();
        self.delete_query(&format!("teams/{team_id}/roles/{role_id}"), &q)
            .await
    }

    /// `PUT /teams/{id}/default-role`.
    pub async fn team_set_default_role(&self, team_id: Uuid, role_id: Uuid) -> Result<()> {
        self.put_empty(
            &format!("teams/{team_id}/default-role"),
            &SetDefaultRoleRequest { role_id },
        )
        .await
    }

    /// `GET /teams/{id}/role-mappings` — IdP group → role.
    pub async fn team_role_mappings(&self, team_id: Uuid) -> Result<RoleMappingList> {
        self.get(&format!("teams/{team_id}/role-mappings")).await
    }

    /// `PUT /teams/{id}/role-mappings` — replaces the whole list.
    pub async fn team_set_role_mappings(
        &self,
        team_id: Uuid,
        req: &RoleMappingList,
    ) -> Result<RoleMappingList> {
        self.put(&format!("teams/{team_id}/role-mappings"), req)
            .await
    }

    // ───────────────────────────── automations ─────────────────────────────

    /// `GET /teams/{id}/automations`.
    pub async fn team_automations(&self, team_id: Uuid) -> Result<AutomationList> {
        self.get(&format!("teams/{team_id}/automations")).await
    }

    /// `POST /teams/{id}/automations`.
    pub async fn create_automation(
        &self,
        team_id: Uuid,
        req: &CreateAutomationRequest,
    ) -> Result<Automation> {
        self.post(&format!("teams/{team_id}/automations"), req)
            .await
    }

    /// `PUT /teams/{id}/automations/{aid}`.
    pub async fn update_automation(
        &self,
        team_id: Uuid,
        id: Uuid,
        req: &UpdateAutomationRequest,
    ) -> Result<Automation> {
        self.put(&format!("teams/{team_id}/automations/{id}"), req)
            .await
    }

    /// `DELETE /teams/{id}/automations/{aid}`.
    pub async fn delete_automation(&self, team_id: Uuid, id: Uuid) -> Result<()> {
        self.delete(&format!("teams/{team_id}/automations/{id}"))
            .await
    }

    /// `POST /teams/{id}/automations/{aid}/run` — queue a run now.
    pub async fn run_automation_now(&self, team_id: Uuid, id: Uuid) -> Result<AutomationRun> {
        self.post(&format!("teams/{team_id}/automations/{id}/run"), &())
            .await
    }

    /// `GET /teams/{id}/automations/{aid}/runs`.
    pub async fn automation_runs(&self, team_id: Uuid, id: Uuid) -> Result<AutomationRunList> {
        self.get(&format!("teams/{team_id}/automations/{id}/runs"))
            .await
    }

    /// `POST /teams/{id}/automations/runs/claim` — executor side.
    pub async fn claim_automation_runs(
        &self,
        team_id: Uuid,
        req: &ClaimRunsRequest,
    ) -> Result<ClaimRunsResponse> {
        self.post(&format!("teams/{team_id}/automations/runs/claim"), req)
            .await
    }

    /// `PATCH /teams/{id}/automations/runs/{rid}` — executor side.
    pub async fn finish_automation_run(
        &self,
        team_id: Uuid,
        run_id: Uuid,
        req: &FinishRunRequest,
    ) -> Result<AutomationRun> {
        self.patch(&format!("teams/{team_id}/automations/runs/{run_id}"), req)
            .await
    }

    // ───────────────────────────── team SSH CA ─────────────────────────────

    /// `GET /teams/{id}/ca` — `None` when the team has no CA yet.
    pub async fn team_ca(&self, team_id: Uuid) -> Result<Option<TeamCa>> {
        match self.get(&format!("teams/{team_id}/ca")).await {
            Ok(ca) => Ok(Some(ca)),
            Err(e) if e.status() == Some(404) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `PUT /teams/{id}/ca` — create the CA or change its settings.
    pub async fn update_team_ca(&self, team_id: Uuid, req: &UpdateTeamCaRequest) -> Result<TeamCa> {
        self.put(&format!("teams/{team_id}/ca"), req).await
    }

    /// `DELETE /teams/{id}/ca`.
    pub async fn delete_team_ca(&self, team_id: Uuid) -> Result<()> {
        self.delete(&format!("teams/{team_id}/ca")).await
    }

    /// `POST /teams/{id}/ca/rotate`.
    pub async fn rotate_team_ca(&self, team_id: Uuid, req: &RotateTeamCaRequest) -> Result<TeamCa> {
        self.post(&format!("teams/{team_id}/ca/rotate"), req).await
    }

    /// `POST /teams/{id}/ca/issue` — certify this device's public key.
    pub async fn issue_team_certificate(
        &self,
        team_id: Uuid,
        req: &IssueCertificateRequest,
    ) -> Result<IssueCertificateResponse> {
        self.post(&format!("teams/{team_id}/ca/issue"), req).await
    }

    /// `GET /teams/{id}/ca/certificates`.
    pub async fn team_certificates(&self, team_id: Uuid) -> Result<IssuedCertificateList> {
        self.get(&format!("teams/{team_id}/ca/certificates")).await
    }

    /// `POST /teams/{id}/ca/certificates/{cid}/revoke`.
    pub async fn revoke_team_certificate(
        &self,
        team_id: Uuid,
        certificate_id: Uuid,
    ) -> Result<IssuedCertificate> {
        self.post(
            &format!("teams/{team_id}/ca/certificates/{certificate_id}/revoke"),
            &(),
        )
        .await
    }

    /// `GET /teams/{id}/policies`.
    pub async fn team_policies(&self, team_id: Uuid) -> Result<TeamPoliciesResponse> {
        self.get(&format!("teams/{team_id}/policies")).await
    }

    /// `PUT /teams/{id}/policies` — partial update.
    pub async fn team_update_policies(
        &self,
        team_id: Uuid,
        req: &UpdateTeamPoliciesRequest,
    ) -> Result<TeamPoliciesResponse> {
        self.put(&format!("teams/{team_id}/policies"), req).await
    }

    /// `GET /teams/{id}/webhooks`.
    pub async fn team_webhooks(&self, team_id: Uuid) -> Result<WebhookList> {
        self.get(&format!("teams/{team_id}/webhooks")).await
    }

    /// `POST /teams/{id}/webhooks`.
    pub async fn team_webhook_create(
        &self,
        team_id: Uuid,
        req: &CreateWebhookRequest,
    ) -> Result<Webhook> {
        self.post(&format!("teams/{team_id}/webhooks"), req).await
    }

    /// `PATCH /teams/{id}/webhooks/{hook}`.
    pub async fn team_webhook_update(
        &self,
        team_id: Uuid,
        hook_id: Uuid,
        req: &UpdateWebhookRequest,
    ) -> Result<Webhook> {
        self.patch(&format!("teams/{team_id}/webhooks/{hook_id}"), req)
            .await
    }

    /// `DELETE /teams/{id}/webhooks/{hook}`.
    pub async fn team_webhook_delete(&self, team_id: Uuid, hook_id: Uuid) -> Result<()> {
        self.delete(&format!("teams/{team_id}/webhooks/{hook_id}"))
            .await
    }

    /// `POST /teams/{id}/webhooks/{hook}/test` — sends a test event, returns its deliveries.
    pub async fn team_webhook_test(
        &self,
        team_id: Uuid,
        hook_id: Uuid,
    ) -> Result<WebhookDeliveryList> {
        self.post(&format!("teams/{team_id}/webhooks/{hook_id}/test"), &())
            .await
    }

    /// `GET /teams/{id}/webhooks/{hook}/deliveries` — last 100.
    pub async fn team_webhook_deliveries(
        &self,
        team_id: Uuid,
        hook_id: Uuid,
    ) -> Result<WebhookDeliveryList> {
        self.get(&format!("teams/{team_id}/webhooks/{hook_id}/deliveries"))
            .await
    }

    // ───────────────────────────── sync ─────────────────────────────

    /// `POST /sync/push`.
    pub async fn sync_push(&self, req: &PushRequest) -> Result<PushResponse> {
        self.post("sync/push", req).await
    }

    /// `POST /sync/pull`.
    pub async fn sync_pull(&self, req: &PullRequest) -> Result<PullResponse> {
        self.post("sync/pull", req).await
    }

    /// `POST /history/push`.
    pub async fn history_push(&self, req: &HistoryPushRequest) -> Result<HistoryPullResponse> {
        self.post("history/push", req).await
    }

    /// `GET /history/pull?since=&limit=`.
    pub async fn history_pull(&self, since: i64, limit: u32) -> Result<HistoryPullResponse> {
        self.get_query(
            "history/pull",
            &[("since", since.to_string()), ("limit", limit.to_string())],
        )
        .await
    }

    /// `POST /history/clear`.
    pub async fn history_clear(&self, kind: Option<HistoryKind>) -> Result<()> {
        self.post_empty("history/clear", &HistoryClearRequest { kind })
            .await
    }

    // ───────────────────────────── session logs ─────────────────────────────

    /// `GET /logs?since=&limit=` — metadata only.
    pub async fn logs(&self, since: i64, limit: u32) -> Result<LogListResponse> {
        self.get_query(
            "logs",
            &[("since", since.to_string()), ("limit", limit.to_string())],
        )
        .await
    }

    /// `GET /vaults/{id}/logs?since=&limit=` — every member's logs in a
    /// (team) vault, paged by the vault counter.
    pub async fn vault_logs(
        &self,
        vault_id: Uuid,
        since: i64,
        limit: u32,
    ) -> Result<LogListResponse> {
        self.get_query(
            &format!("vaults/{vault_id}/logs"),
            &[("since", since.to_string()), ("limit", limit.to_string())],
        )
        .await
    }

    /// `POST /logs` — register a log and get a presigned upload URL.
    pub async fn create_log(&self, req: &CreateLogRequest) -> Result<CreateLogResponse> {
        self.post("logs", req).await
    }

    /// `PATCH /logs/{id}` — mark uploaded (with the exact byte size) or
    /// update metadata.
    pub async fn update_log(&self, id: Uuid, req: &UpdateLogRequest) -> Result<SessionLog> {
        self.patch(&format!("logs/{id}"), req).await
    }

    /// `GET /logs/{id}/download` — presigned download URL.
    pub async fn log_download_url(&self, id: Uuid) -> Result<DownloadLogResponse> {
        self.get(&format!("logs/{id}/download")).await
    }

    /// `DELETE /logs/{id}`.
    pub async fn delete_log(&self, id: Uuid) -> Result<()> {
        self.delete(&format!("logs/{id}")).await
    }

    // ---- multiplayer ------------------------------------------------------

    /// `POST /live` — register a live terminal session. The server only ever
    /// sees the join token (and stores its hash), never the link secret.
    pub async fn create_live_session(&self, join_token: String) -> Result<LiveSession> {
        self.post("live", &CreateLiveSessionRequest { join_token })
            .await
    }

    /// `GET /live` — sessions this account is hosting.
    pub async fn live_sessions(&self) -> Result<LiveSessionList> {
        self.get("live").await
    }

    /// `POST /live/{id}/stop`.
    pub async fn stop_live_session(&self, id: Uuid) -> Result<()> {
        self.post_empty(&format!("live/{id}/stop"), &()).await
    }

    /// PUT an already-encrypted log body to the presigned URL from
    /// [`ApiClient::create_log`]. No bearer token is sent (object storage
    /// authenticates via the URL).
    pub async fn upload_log_object(&self, target: &CreateLogResponse, body: Vec<u8>) -> Result<()> {
        let mut rb = self.http.put(&target.upload_url).body(body);
        for (k, v) in &target.upload_headers {
            rb = rb.header(k.as_str(), v.as_str());
        }
        let resp = rb.send().await?;
        if !resp.status().is_success() {
            return Err(CoreError::Api {
                status: resp.status().as_u16(),
                code: "storage_upload_failed".into(),
                message: format!("object storage answered {}", resp.status()),
            });
        }
        Ok(())
    }

    /// Fetch the encrypted body from a presigned download URL.
    pub async fn download_log_object(&self, target: &DownloadLogResponse) -> Result<Vec<u8>> {
        let resp = self.http.get(&target.download_url).send().await?;
        if !resp.status().is_success() {
            return Err(CoreError::Api {
                status: resp.status().as_u16(),
                code: "storage_download_failed".into(),
                message: format!("object storage answered {}", resp.status()),
            });
        }
        Ok(resp.bytes().await?.to_vec())
    }

    /// Authenticated GET returning the raw body (exports).
    async fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let resp = self.request(Method::GET, path).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let parsed: std::result::Result<ApiError, _> = serde_json::from_str(&body);
            return Err(match parsed {
                Ok(e) => CoreError::Api {
                    status,
                    code: e.code,
                    message: e.message,
                },
                Err(_) => CoreError::Api {
                    status,
                    code: "http_error".into(),
                    message: body,
                },
            });
        }
        Ok(resp.bytes().await?.to_vec())
    }

    // ───────────────────────── 0.9.1 enterprise ─────────────────────────

    /// `GET /auth/sso/discover?email=` — home-realm discovery (no auth needed).
    pub async fn sso_discover(
        &self,
        email: &str,
    ) -> Result<termoso_proto::auth::SsoDiscoverResponse> {
        self.get_query("auth/sso/discover", &[("email", email)])
            .await
    }

    /// Enterprise API: team idp.
    pub async fn team_idp(&self, team_id: Uuid) -> Result<termoso_proto::team::TeamIdpResponse> {
        self.get(&format!("teams/{team_id}/idp")).await
    }

    /// Enterprise API: team update idp.
    pub async fn team_update_idp(
        &self,
        team_id: Uuid,
        req: &termoso_proto::team::UpdateTeamIdpRequest,
    ) -> Result<termoso_proto::team::TeamIdpResponse> {
        self.put(&format!("teams/{team_id}/idp"), req).await
    }

    /// Enterprise API: team test idp.
    pub async fn team_test_idp(
        &self,
        team_id: Uuid,
        req: &termoso_proto::team::UpdateTeamIdpRequest,
    ) -> Result<termoso_proto::team::TeamIdpResponse> {
        self.post(&format!("teams/{team_id}/idp/test"), req).await
    }

    /// Enterprise API: team delete idp.
    pub async fn team_delete_idp(&self, team_id: Uuid) -> Result<()> {
        self.delete(&format!("teams/{team_id}/idp")).await
    }

    /// Enterprise API: team acl.
    pub async fn team_acl(
        &self,
        team_id: Uuid,
        vault_id: Uuid,
    ) -> Result<termoso_proto::team::EntityAclResponse> {
        self.get(&format!("teams/{team_id}/vaults/{vault_id}/acl"))
            .await
    }

    /// Enterprise API: team upsert acl.
    pub async fn team_upsert_acl(
        &self,
        team_id: Uuid,
        vault_id: Uuid,
        req: &termoso_proto::team::UpsertEntityAclRequest,
    ) -> Result<termoso_proto::team::EntityAclResponse> {
        self.put(&format!("teams/{team_id}/vaults/{vault_id}/acl"), req)
            .await
    }

    /// Enterprise API: team delete acl.
    pub async fn team_delete_acl(
        &self,
        team_id: Uuid,
        vault_id: Uuid,
        rule_id: Uuid,
    ) -> Result<()> {
        self.delete(&format!("teams/{team_id}/vaults/{vault_id}/acl/{rule_id}"))
            .await
    }

    /// `GET /acl/me` — rules that apply to the caller across all team vaults.
    pub async fn acl_me(&self) -> Result<termoso_proto::team::MyAclResponse> {
        self.get("acl/me").await
    }

    /// `GET /teams/{id}/logs` — recordings of every member (`logs.view_team`).
    pub async fn team_logs(
        &self,
        team_id: Uuid,
        vault_id: Option<Uuid>,
    ) -> Result<LogListResponse> {
        match vault_id {
            Some(v) => {
                self.get_query(
                    &format!("teams/{team_id}/logs"),
                    &[("vault_id", v.to_string())],
                )
                .await
            }
            None => self.get(&format!("teams/{team_id}/logs")).await,
        }
    }

    /// `GET /teams/{id}/logs/export` — NDJSON with signed download links.
    pub async fn team_logs_export(&self, team_id: Uuid) -> Result<Vec<u8>> {
        self.get_bytes(&format!("teams/{team_id}/logs/export"))
            .await
    }

    /// Enterprise API: team rotation.
    pub async fn team_rotation(
        &self,
        team_id: Uuid,
    ) -> Result<termoso_proto::team::RotationOverview> {
        self.get(&format!("teams/{team_id}/rotation")).await
    }

    /// Enterprise API: team create rotation jobs.
    pub async fn team_create_rotation_jobs(
        &self,
        team_id: Uuid,
        req: &termoso_proto::team::CreateRotationJobsRequest,
    ) -> Result<termoso_proto::team::RotationJobList> {
        self.post(&format!("teams/{team_id}/rotation/jobs"), req)
            .await
    }

    /// `GET /rotation/jobs` — jobs the caller's client may execute.
    pub async fn rotation_jobs(&self) -> Result<termoso_proto::team::RotationJobList> {
        self.get("rotation/jobs").await
    }

    /// Enterprise API: rotation update job.
    pub async fn rotation_update_job(
        &self,
        job_id: Uuid,
        req: &termoso_proto::team::UpdateRotationJobRequest,
    ) -> Result<termoso_proto::team::RotationJob> {
        self.patch(&format!("rotation/jobs/{job_id}"), req).await
    }

    /// Enterprise API: rotation cancel job.
    pub async fn rotation_cancel_job(&self, job_id: Uuid) -> Result<()> {
        self.delete(&format!("rotation/jobs/{job_id}")).await
    }

    /// Enterprise API: team access requests.
    pub async fn team_access_requests(
        &self,
        team_id: Uuid,
    ) -> Result<termoso_proto::team::AccessRequestList> {
        self.get(&format!("teams/{team_id}/access-requests")).await
    }

    /// Enterprise API: team create access request.
    pub async fn team_create_access_request(
        &self,
        team_id: Uuid,
        req: &termoso_proto::team::CreateAccessRequest,
    ) -> Result<termoso_proto::team::AccessRequest> {
        self.post(&format!("teams/{team_id}/access-requests"), req)
            .await
    }

    /// Enterprise API: team cancel access request.
    pub async fn team_cancel_access_request(&self, team_id: Uuid, rid: Uuid) -> Result<()> {
        self.delete(&format!("teams/{team_id}/access-requests/{rid}"))
            .await
    }

    /// `action` is `approve`, `deny` or `revoke`.
    pub async fn team_decide_access_request(
        &self,
        team_id: Uuid,
        rid: Uuid,
        action: &str,
        req: &termoso_proto::team::DecideAccessRequest,
    ) -> Result<termoso_proto::team::AccessRequest> {
        self.post(
            &format!("teams/{team_id}/access-requests/{rid}/{action}"),
            req,
        )
        .await
    }

    /// Enterprise API: team data.
    pub async fn team_data(&self, team_id: Uuid) -> Result<termoso_proto::team::TeamDataStatus> {
        self.get(&format!("teams/{team_id}/data")).await
    }

    /// `GET /teams/{id}/export` — full GDPR export (JSON bytes).
    pub async fn team_export(&self, team_id: Uuid) -> Result<Vec<u8>> {
        self.get_bytes(&format!("teams/{team_id}/export")).await
    }

    /// Enterprise API: team schedule deletion.
    pub async fn team_schedule_deletion(
        &self,
        team_id: Uuid,
        req: &termoso_proto::team::ScheduleTeamDeletionRequest,
    ) -> Result<termoso_proto::team::TeamDataStatus> {
        self.post(&format!("teams/{team_id}/deletion"), req).await
    }

    /// Enterprise API: team cancel deletion.
    pub async fn team_cancel_deletion(
        &self,
        team_id: Uuid,
    ) -> Result<termoso_proto::team::TeamDataStatus> {
        Self::send(self.request(Method::DELETE, &format!("teams/{team_id}/deletion"))).await
    }

    /// Enterprise API: team devices.
    pub async fn team_devices(&self, team_id: Uuid) -> Result<termoso_proto::team::TeamDeviceList> {
        self.get(&format!("teams/{team_id}/devices")).await
    }

    /// Enterprise API: team approve device.
    pub async fn team_approve_device(&self, team_id: Uuid, device_id: Uuid) -> Result<()> {
        self.post_empty(&format!("teams/{team_id}/devices/{device_id}/approve"), &())
            .await
    }

    /// Enterprise API: team reject device.
    pub async fn team_reject_device(&self, team_id: Uuid, device_id: Uuid) -> Result<()> {
        self.post_empty(&format!("teams/{team_id}/devices/{device_id}/reject"), &())
            .await
    }
}

pub(crate) fn default_user_agent() -> String {
    format!("termoso-core/{}", env!("CARGO_PKG_VERSION"))
}

/// Percent-encode a caller-supplied path segment.
fn pct(segment: &str) -> String {
    utf8_percent_encode(segment, NON_ALPHANUMERIC).to_string()
}

/// Turn a user-typed server address into a base URL with a trailing slash.
/// Bare hosts get `https://`.
pub fn normalize_server_url(input: &str) -> Result<Url> {
    let s = input.trim();
    if s.is_empty() {
        return Err(CoreError::Invalid("empty server url".into()));
    }
    let with_scheme = if s.contains("://") {
        s.to_string()
    } else {
        format!("https://{s}")
    };
    let mut u =
        Url::parse(&with_scheme).map_err(|e| CoreError::Invalid(format!("server url: {e}")))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(CoreError::Invalid(format!(
            "unsupported scheme {}",
            u.scheme()
        )));
    }
    if u.host_str().is_none() {
        return Err(CoreError::Invalid("server url has no host".into()));
    }
    u.set_query(None);
    u.set_fragment(None);
    let mut path = u.path().trim_end_matches('/').to_string();
    if path.ends_with("/api/v1") {
        path.truncate(path.len() - "/api/v1".len());
    }
    path.push('/');
    u.set_path(&path);
    Ok(u)
}

async fn check(resp: Response) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    Err(api_error(status, &body))
}

fn api_error(status: StatusCode, body: &str) -> CoreError {
    match serde_json::from_str::<ApiError>(body) {
        Ok(e) => CoreError::Api {
            status: status.as_u16(),
            code: e.code,
            message: e.message,
        },
        Err(_) => CoreError::Api {
            status: status.as_u16(),
            code: if status == StatusCode::UNAUTHORIZED {
                termoso_proto::error::codes::UNAUTHORIZED.into()
            } else {
                "http_error".into()
            },
            message: if body.trim().is_empty() {
                status.to_string()
            } else {
                body.chars().take(200).collect()
            },
        },
    }
}

impl CoreError {
    /// Server error with this code?
    pub fn is_api_code(&self, wanted: &str) -> bool {
        matches!(self, CoreError::Api { code, .. } if code == wanted)
    }

    /// The session token was rejected — the caller should sign out.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, CoreError::Api { status: 401, .. })
            || self.is_api_code(termoso_proto::error::codes::UNAUTHORIZED)
            || self.is_api_code(termoso_proto::error::codes::TOKEN_EXPIRED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_server_urls() {
        assert_eq!(
            normalize_server_url("termoso.example").unwrap().as_str(),
            "https://termoso.example/"
        );
        assert_eq!(
            normalize_server_url("http://localhost:8080/api/v1/")
                .unwrap()
                .as_str(),
            "http://localhost:8080/"
        );
        assert_eq!(
            normalize_server_url("https://host/prefix?x=1#f")
                .unwrap()
                .as_str(),
            "https://host/prefix/"
        );
        assert!(normalize_server_url("ftp://x").is_err());
        assert!(normalize_server_url("").is_err());
    }

    #[test]
    fn api_paths_keep_prefix() {
        let c = ApiClient::new("https://host/prefix").unwrap();
        assert_eq!(
            c.api_url("sync/push").as_str(),
            "https://host/prefix/api/v1/sync/push"
        );
        assert_eq!(c.ws_url().unwrap().as_str(), "wss://host/prefix/api/v1/ws");
        let c = ApiClient::new("http://127.0.0.1:1234").unwrap();
        assert_eq!(
            c.ws_url().unwrap().as_str(),
            "ws://127.0.0.1:1234/api/v1/ws"
        );
    }

    #[test]
    fn maps_error_bodies() {
        let e = api_error(
            StatusCode::CONFLICT,
            r#"{"code":"conflict","message":"Version mismatch"}"#,
        );
        assert!(e.is_api_code("conflict"));
        assert!(!e.is_unauthorized());
        let e = api_error(StatusCode::UNAUTHORIZED, "<html>nope</html>");
        assert!(e.is_unauthorized());
        let e = api_error(StatusCode::BAD_GATEWAY, "");
        assert!(matches!(e, CoreError::Api { status: 502, .. }));
    }
}
