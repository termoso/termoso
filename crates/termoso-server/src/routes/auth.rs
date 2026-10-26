//! Registration, login (OPAQUE), MFA, device approval, recovery, password change, SSO.

use std::time::Duration;

use axum::Json;
use axum::extract::{Form, Path, Query, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};
use termoso_crypto::encoding::{b64, unb64, unb64_array};
use termoso_crypto::opaque;
use termoso_proto::auth::*;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PublicKeyCredential, RequestChallengeResponse,
};

use crate::codes;
use crate::error::{ApiResult, Error, NoContent};
use crate::extract::{Auth, Client, Json as Body};
use crate::ratelimit;
use crate::session;
use crate::sso;
use crate::state::AppState;
use crate::turnstile;
use crate::users::{self, UserRow};
use crate::util::{hash_token, mask_email, normalize_code, normalize_email};

const LOGIN_TTL: Duration = Duration::from_secs(120);
const MFA_TTL: Duration = Duration::from_secs(600);
const APPROVAL_TTL: Duration = Duration::from_secs(900);
const RECOVERY_TTL: Duration = Duration::from_secs(900);
pub const EMAIL_VERIFY_TTL: Duration = Duration::from_secs(1800);

const P_LOGIN: &str = "login";
const P_MFA: &str = "mfa";
const P_MFA_EMAIL: &str = "mfa_email";
const P_WEBAUTHN_AUTH: &str = "webauthn_auth";
const P_APPROVE: &str = "device_approve";
const P_RECOVERY: &str = "recovery";
const P_REAUTH: &str = "reauth";
const P_REAUTH_EMAIL: &str = "reauth_email";
pub const P_EMAIL_VERIFY: &str = "email_verify";

// ───────────────────────────── helpers ─────────────────────────────

fn valid_display_name(name: &Option<String>) -> ApiResult<Option<String>> {
    match name {
        None => Ok(None),
        Some(n) => {
            let n = n.trim();
            if n.is_empty() {
                return Ok(None);
            }
            if n.chars().count() > 100 {
                return Err(Error::bad_request("Display name is too long"));
            }
            Ok(Some(n.to_string()))
        }
    }
}

pub(crate) fn validate_keys(k: &AccountKeysUpload) -> ApiResult<()> {
    unb64_array::<32>(&k.public_key)
        .map_err(|_| Error::bad_request("public_key must be 32 bytes"))?;
    unb64_array::<32>(&k.recovery_verifier)
        .map_err(|_| Error::bad_request("recovery_verifier must be 32 bytes"))?;
    for (name, v) in [
        ("wrapped_private_key", &k.wrapped_private_key),
        (
            "recovery_wrapped_private_key",
            &k.recovery_wrapped_private_key,
        ),
        ("personal_vault_sealed_key", &k.personal_vault_sealed_key),
    ] {
        let bytes =
            unb64(v).map_err(|_| Error::bad_request(format!("{name} is not valid base64")))?;
        if bytes.len() < 32 || bytes.len() > 4096 {
            return Err(Error::bad_request(format!(
                "{name} has an unexpected length"
            )));
        }
    }
    Ok(())
}

/// Oldest client allowed in: the operator's `TERMOSO_MIN_CLIENT_VERSION`,
/// else this server's own version.
pub(crate) fn min_client_version(cfg: &crate::config::Config) -> &str {
    cfg.min_client_version
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(crate::state::VERSION)
}

/// `1.2.3[-pre][+build]` → (1, 2, 3); anything else is `None`. `0.0.0-*` is
/// the conventional "unreleased" version of dev and test builds and is also
/// `None`, so such clients are never gated.
fn semver_tuple(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let (a, b, c) = (it.next()??, it.next()??, it.next()??);
    Some((a, b, c)).filter(|t| *t != (0, 0, 0))
}

/// Refuse clients older than [`min_client_version`]: an old client against a
/// newer server breaks in confusing ways, so it is told to update instead.
/// Clients whose version string is not semver (dev builds, tests) pass.
pub(crate) fn check_client_version(cfg: &crate::config::Config, d: &DeviceInfo) -> ApiResult<()> {
    // The web cabinet ships inside the server image, so it can never be
    // "older" in a way an update would fix; gating it would only lock
    // operators out of their own console.
    if d.platform == Platform::Web {
        return Ok(());
    }
    let required = min_client_version(cfg);
    let (Some(client), Some(min)) = (semver_tuple(&d.app_version), semver_tuple(required)) else {
        return Ok(());
    };
    if client < min {
        return Err(Error::new(
            axum::http::StatusCode::UPGRADE_REQUIRED,
            termoso_proto::error::codes::CLIENT_UPDATE_REQUIRED,
            format!(
                "This server requires Termoso {required} or newer; you are on {}. Please update the app.",
                d.app_version
            ),
        )
        .with_details(serde_json::json!({
            "required_version": required,
            "client_version": d.app_version,
            "server_version": crate::state::VERSION,
        })));
    }
    Ok(())
}

pub(crate) fn validate_device(d: &DeviceInfo) -> ApiResult<()> {
    if d.name.trim().is_empty() || d.name.chars().count() > 120 {
        return Err(Error::bad_request("Invalid device name"));
    }
    if d.app_version.chars().count() > 64 {
        return Err(Error::bad_request("Invalid app version"));
    }
    Ok(())
}

pub(crate) async fn build_session(
    state: &AppState,
    user: &UserRow,
    device_id: Uuid,
) -> ApiResult<Session> {
    let (token, expires_at) = session::issue(state, user.id, device_id).await?;
    let mfa = users::mfa_enabled(state, user).await?;
    let is_owner = state.owner_user_id().await? == Some(user.id);
    Ok(Session {
        token,
        expires_at,
        device_id,
        user: users::profile(user, mfa, is_owner),
        keys: users::keys(user),
    })
}

pub(crate) async fn send_code_email(
    state: &AppState,
    to: &str,
    purpose: &str,
    code: &str,
    ttl: Duration,
) -> ApiResult<()> {
    let Some(mailer) = &state.mailer else {
        return Err(Error::feature_disabled("Email"));
    };
    ratelimit::check(state, ratelimit::EMAIL, to).await?;
    let email = mailer.code_email(purpose, code, ttl.as_secs() / 60);
    mailer
        .send(to, &email)
        .await
        .map_err(|e| Error::Internal(e.context("sending email")))?;
    Ok(())
}

pub async fn send_email_verification(state: &AppState, user: &UserRow) -> ApiResult<()> {
    if state.mailer.is_none() || user.email_verified {
        return Ok(());
    }
    let code = codes::issue_for(
        state,
        P_EMAIL_VERIFY,
        &user.id.to_string(),
        &user.email,
        EMAIL_VERIFY_TTL,
    )
    .await?;
    send_code_email(
        state,
        &user.email,
        "email verification",
        &code,
        EMAIL_VERIFY_TTL,
    )
    .await
}

// ───────────────────────────── registration ─────────────────────────────

#[derive(Serialize, Deserialize)]
struct InviteRow {
    id: Uuid,
    team_id: Uuid,
    email: String,
    role: String,
    vault_ids: Vec<Uuid>,
    role_id: Option<Uuid>,
}

async fn load_invite(state: &AppState, token: &str) -> ApiResult<Option<InviteRow>> {
    let row: Option<(Uuid, Uuid, String, String, Vec<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, team_id, email, role, vault_ids, role_id FROM team_invites
         WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now()",
    )
    .bind(hash_token(token))
    .fetch_optional(&state.db)
    .await?;
    Ok(
        row.map(|(id, team_id, email, role, vault_ids, role_id)| InviteRow {
            id,
            team_id,
            email,
            role,
            vault_ids,
            role_id,
        }),
    )
}

/// Sign-up policy: the bootstrap admin and invited addresses always get in;
/// everyone else needs open registration (or an IdP-verified identity when
/// `sso_registration` is on) and an address in `allowed_domains`.
async fn registration_allowed(
    state: &AppState,
    email: &str,
    invite: Option<&InviteRow>,
    sso_verified: bool,
    team_jit: bool,
) -> ApiResult<()> {
    if state.is_bootstrap_admin(email) {
        return Ok(());
    }
    if let Some(inv) = invite
        && inv.email.eq_ignore_ascii_case(email)
    {
        return Ok(());
    }
    let settings = state.settings().await?;
    if settings.sso_only && !sso_verified {
        return Err(crate::enterprise::sso_required(state, email).await);
    }
    crate::enterprise::require_team_sso(state, sso_verified, email).await?;
    if !(settings.registration_open || (sso_verified && settings.sso_registration) || team_jit) {
        return Err(Error::registration_closed());
    }
    if !settings.allowed_domains.is_empty() {
        let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
        if !settings
            .allowed_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain))
        {
            return Err(Error::forbidden(
                "Sign-up is limited to approved email domains on this server",
            ));
        }
    }
    Ok(())
}

#[utoipa::path(post, path = "/api/v1/auth/register/start", tag = "auth",
    request_body = RegisterStartRequest, responses((status = 200, body = RegisterStartResponse)))]
pub async fn register_start(
    State(state): State<AppState>,
    client: Client,
    Body(req): Body<RegisterStartRequest>,
) -> ApiResult<Json<RegisterStartResponse>> {
    ratelimit::check_ip(&state, ratelimit::AUTH_IP, client.ip.as_deref()).await?;
    turnstile::require(&state, req.turnstile_token.as_deref(), client.ip.as_deref()).await?;
    let email = normalize_email(&req.email).ok_or_else(|| Error::bad_request("Invalid email"))?;
    // Closed registration is enforced at `register_finish`, where the invite
    // token (which may still allow sign-up) is available. A domain claimed by
    // a team for SSO is refused right away: no invite overrides that.
    crate::enterprise::require_team_sso(&state, false, &email).await?;
    if users::by_email(&state.db, &email).await?.is_some() {
        return Err(Error::email_taken());
    }
    let opaque_response = state
        .opaque
        .registration_start(&email, &req.opaque_request)?;
    Ok(Json(RegisterStartResponse { opaque_response }))
}

#[utoipa::path(post, path = "/api/v1/auth/register/finish", tag = "auth",
    request_body = RegisterFinishRequest, responses((status = 200, body = AuthResponse)))]
pub async fn register_finish(
    State(state): State<AppState>,
    client: Client,
    Body(req): Body<RegisterFinishRequest>,
) -> ApiResult<Json<AuthResponse>> {
    ratelimit::check_ip(&state, ratelimit::AUTH_IP, client.ip.as_deref()).await?;
    let email = normalize_email(&req.email).ok_or_else(|| Error::bad_request("Invalid email"))?;
    validate_keys(&req.keys)?;
    validate_device(&req.device)?;
    check_client_version(&state.cfg, &req.device)?;
    let display_name = valid_display_name(&req.display_name)?;

    let invite = match &req.invite_token {
        Some(t) => Some(
            load_invite(&state, t)
                .await?
                .ok_or_else(Error::token_expired)?,
        ),
        None => None,
    };
    let sso_sess = match &req.sso_session {
        Some(t) => Some(sso::consume_session(&state, t, &email).await?),
        None => None,
    };
    registration_allowed(
        &state,
        &email,
        invite.as_ref(),
        sso_sess.is_some(),
        sso_sess.as_ref().is_some_and(|s| s.team_id.is_some()),
    )
    .await?;
    let invite_matches = invite
        .as_ref()
        .is_some_and(|i| i.email.eq_ignore_ascii_case(&email));
    let email_verified = sso_sess.is_some() || invite_matches || state.mailer.is_none();

    let record = opaque::Server::registration_finish(&req.opaque_upload)?;
    let user_id = Uuid::new_v4();
    // A SCIM-provisioned account (no password yet) is completed in place when
    // the IdP or an invitation vouches for the email, keeping its id.
    let provisioned: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE lower(email) = $1 AND opaque_record IS NULL
           AND provisioned_at IS NOT NULL AND NOT disabled",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;
    let takeover = provisioned.is_some() && (sso_sess.is_some() || invite_matches);
    let user_id = provisioned
        .filter(|_| takeover)
        .map(|p| p.0)
        .unwrap_or(user_id);
    let is_admin = state.is_bootstrap_admin(&email);

    let mut tx = state.db.begin().await?;
    let managed_by = invite
        .as_ref()
        .filter(|_| invite_matches)
        .map(|i| i.team_id);
    let inserted = sqlx::query(if takeover {
        USERS_TAKEOVER_SQL
    } else {
        USERS_INSERT_SQL
    })
    .bind(user_id)
    .bind(&email)
    .bind(email_verified)
    .bind(&display_name)
    .bind(&record)
    .bind(&req.keys.public_key)
    .bind(&req.keys.wrapped_private_key)
    .bind(&req.keys.recovery_wrapped_private_key)
    .bind(hash_token(&req.keys.recovery_verifier))
    .bind(is_admin)
    .bind(managed_by)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(Error::email_taken());
    }
    users::create_personal_vault(&mut tx, user_id, &req.keys.personal_vault_sealed_key).await?;
    if let Some(inv) = &invite
        && invite_matches
    {
        crate::routes::teams::apply_invite(
            &mut tx,
            inv.id,
            inv.team_id,
            &inv.role,
            inv.role_id,
            &inv.vault_ids,
            user_id,
            None,
        )
        .await?;
    }
    tx.commit().await?;
    crate::enterprise::ensure_home_team(&state, user_id).await?;

    let user = users::by_id(&state.db, user_id).await?;
    if let Some(s) = &sso_sess {
        sso::link_identity(&state, s, user_id).await?;
    }
    let (device_id, _) =
        session::upsert_device(&state.db, user_id, &req.device, client.ip.as_deref()).await?;
    let sess = build_session(&state, &user, device_id).await?;
    users::security_event(
        &state,
        user_id,
        "registered",
        Some(device_id),
        client.ip.as_deref(),
        client.user_agent.as_deref(),
        None,
    )
    .await?;
    if let Err(e) = send_email_verification(&state, &user).await {
        tracing::warn!(error = %e, "could not send verification email");
    }
    if invite.is_some() {
        crate::events::publish(
            &state,
            crate::events::Event::TeamsUpdated {
                user_ids: vec![user_id],
            },
        )
        .await?;
    }
    metrics::counter!("termoso_registrations_total").increment(1);
    Ok(Json(AuthResponse::Authenticated(sess)))
}

// ───────────────────────────── login ─────────────────────────────

#[derive(Serialize, Deserialize)]
struct LoginFlow {
    email: String,
    user_id: Option<Uuid>,
    server_state: String,
    device: DeviceInfo,
    sso_verified: bool,
    /// The IdP identity that vouched for this sign-in; linked to the account
    /// once the password checks out.
    #[serde(default)]
    sso: Option<sso::SsoSession>,
}

#[derive(Serialize, Deserialize)]
struct MfaFlow {
    user_id: Uuid,
    /// Device signing in; `None` for a step-up of an existing session.
    #[serde(default)]
    device: Option<DeviceInfo>,
    sso_verified: bool,
    /// Step-up: the session to mark re-authenticated once the factor passes.
    #[serde(default)]
    reauth_session: Option<Uuid>,
}

#[derive(Serialize, Deserialize)]
struct ApprovalFlow {
    user_id: Uuid,
    device_id: Uuid,
}

#[utoipa::path(post, path = "/api/v1/auth/login/start", tag = "auth",
    request_body = LoginStartRequest, responses((status = 200, body = LoginStartResponse)))]
pub async fn login_start(
    State(state): State<AppState>,
    client: Client,
    Body(req): Body<LoginStartRequest>,
) -> ApiResult<Json<LoginStartResponse>> {
    ratelimit::check_ip(&state, ratelimit::AUTH_IP, client.ip.as_deref()).await?;
    if turnstile::login_needs_captcha(&state, client.ip.as_deref()).await {
        turnstile::require(&state, req.turnstile_token.as_deref(), client.ip.as_deref()).await?;
    }
    let email = normalize_email(&req.email).ok_or_else(|| Error::bad_request("Invalid email"))?;
    ratelimit::check(&state, ratelimit::AUTH_ACCOUNT, &email).await?;
    validate_device(&req.device)?;
    check_client_version(&state.cfg, &req.device)?;
    let sso_sess = match &req.sso_session {
        Some(t) => Some(sso::consume_session(&state, t, &email).await?),
        None => None,
    };
    let sso_verified = sso_sess.is_some();
    crate::enterprise::require_sso(&state, sso_verified, &email).await?;
    crate::enterprise::require_team_sso(&state, sso_verified, &email).await?;
    let user = users::by_email(&state.db, &email).await?;
    if let (Some(u), false) = (&user, sso_verified)
        && let Some(provider) = crate::policy::sso_required(&state.db, u.id, &email).await?
    {
        return Err(Error::new(
            axum::http::StatusCode::UNAUTHORIZED,
            termoso_proto::error::codes::SSO_REQUIRED,
            "Your team requires signing in through its identity provider",
        )
        .with_details(serde_json::json!({ "provider": provider })));
    }
    let record = user.as_ref().and_then(|u| u.opaque_record.as_deref());
    let (opaque_response, server_state) =
        state
            .opaque
            .login_start(&email, record, &req.opaque_request)?;
    let login_id = codes::put_flow(
        &state,
        P_LOGIN,
        &LoginFlow {
            email,
            user_id: user.map(|u| u.id),
            server_state: b64(&server_state),
            device: req.device,
            sso_verified,
            sso: sso_sess,
        },
        LOGIN_TTL,
    )
    .await?;
    Ok(Json(LoginStartResponse {
        login_id,
        opaque_response,
    }))
}

#[utoipa::path(post, path = "/api/v1/auth/login/finish", tag = "auth",
    request_body = LoginFinishRequest, responses((status = 200, body = AuthResponse)))]
pub async fn login_finish(
    State(state): State<AppState>,
    client: Client,
    Body(req): Body<LoginFinishRequest>,
) -> ApiResult<Json<AuthResponse>> {
    ratelimit::check_ip(&state, ratelimit::AUTH_IP, client.ip.as_deref()).await?;
    let flow: LoginFlow = codes::take_flow(&state, P_LOGIN, &req.login_id).await?;
    let Some(user_id) = flow.user_id else {
        metrics::counter!("termoso_logins_total", "result" => "unknown_user").increment(1);
        turnstile::note_login_failure(&state, client.ip.as_deref()).await;
        return Err(Error::invalid_credentials());
    };
    let server_state = unb64(&flow.server_state)?;
    if opaque::Server::login_finish(&flow.email, &server_state, &req.opaque_finalization).is_err() {
        users::security_event(
            &state,
            user_id,
            "login_failed",
            None,
            client.ip.as_deref(),
            client.user_agent.as_deref(),
            None,
        )
        .await?;
        metrics::counter!("termoso_logins_total", "result" => "bad_password").increment(1);
        turnstile::note_login_failure(&state, client.ip.as_deref()).await;
        return Err(Error::invalid_credentials());
    }
    let user = users::by_id(&state.db, user_id).await?;
    if user.disabled {
        return Err(Error::account_disabled());
    }
    if let Some(s) = &flow.sso {
        sso::link_identity(&state, s, user.id).await?;
    }
    let resp = continue_login(
        &state,
        &client,
        &user,
        flow.device,
        flow.sso_verified,
        false,
    )
    .await?;
    Ok(Json(resp))
}

/// Shared tail of login: MFA → device approval → session.
async fn continue_login(
    state: &AppState,
    client: &Client,
    user: &UserRow,
    device: DeviceInfo,
    sso_verified: bool,
    mfa_done: bool,
) -> ApiResult<AuthResponse> {
    crate::enterprise::ensure_home_team(state, user.id).await?;
    if !mfa_done && users::mfa_enabled(state, user).await? {
        let methods = available_mfa_methods(state, user).await?;
        let mfa_token = codes::put_flow(
            state,
            P_MFA,
            &MfaFlow {
                user_id: user.id,
                device: Some(device),
                sso_verified,
                reauth_session: None,
            },
            MFA_TTL,
        )
        .await?;
        return Ok(AuthResponse::MfaRequired { mfa_token, methods });
    }

    let (device_id, is_new) =
        session::upsert_device(&state.db, user.id, &device, client.ip.as_deref()).await?;
    crate::trust::gate(state, user.id, device_id, &device, client.ip.as_deref()).await?;
    let approved: (bool,) =
        sqlx::query_as("SELECT approved_at IS NOT NULL FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_one(&state.db)
            .await?;
    let settings = state.settings().await?;
    let forced = crate::policy::mandatory_device_approval(&state.db, user.id).await?;
    let needs_approval = (is_new || !approved.0)
        && (settings.new_device_email_approval || forced)
        && state.mailer.is_some()
        && user.email_verified
        && !sso_verified;
    if needs_approval {
        let (approval_token, code) = codes::issue(
            state,
            P_APPROVE,
            &ApprovalFlow {
                user_id: user.id,
                device_id,
            },
            APPROVAL_TTL,
        )
        .await?;
        send_code_email(
            state,
            &user.email,
            "new device sign-in",
            &code,
            APPROVAL_TTL,
        )
        .await?;
        users::security_event(
            state,
            user.id,
            "device_approval_requested",
            Some(device_id),
            client.ip.as_deref(),
            client.user_agent.as_deref(),
            Some(serde_json::json!({ "device_name": device.name })),
        )
        .await?;
        return Ok(AuthResponse::DeviceApprovalRequired {
            approval_token,
            email_hint: mask_email(&user.email),
        });
    }

    let sess = build_session(state, user, device_id).await?;
    users::security_event(
        state,
        user.id,
        "login",
        Some(device_id),
        client.ip.as_deref(),
        client.user_agent.as_deref(),
        None,
    )
    .await?;
    metrics::counter!("termoso_logins_total", "result" => "ok").increment(1);
    Ok(AuthResponse::Authenticated(sess))
}

async fn available_mfa_methods(state: &AppState, user: &UserRow) -> ApiResult<Vec<MfaMethod>> {
    let mut methods = Vec::new();
    if user.totp_enabled {
        methods.push(MfaMethod::Totp);
    }
    let (wa,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM webauthn_credentials WHERE user_id = $1")
            .bind(user.id)
            .fetch_one(&state.db)
            .await?;
    if wa > 0 && state.webauthn.is_some() {
        methods.push(MfaMethod::Webauthn);
    }
    let (bc,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM backup_codes WHERE user_id = $1 AND used_at IS NULL")
            .bind(user.id)
            .fetch_one(&state.db)
            .await?;
    if bc > 0 {
        methods.push(MfaMethod::BackupCode);
    }
    if state.mailer.is_some() && user.email_verified {
        methods.push(MfaMethod::Email);
    }
    Ok(methods)
}

// ───────────────────────────── MFA ─────────────────────────────

pub fn totp_for(state: &AppState, user: &UserRow, secret: &[u8]) -> ApiResult<totp_rs::Totp> {
    totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret.to_vec())
        .with_issuer(Some(state.cfg.server_name.as_str()))
        .with_account_name(user.email.as_str())
        .build()
        .map_err(|e| Error::Internal(anyhow::anyhow!("totp: {e}")))
}

pub fn decrypt_totp_secret(state: &AppState, user: &UserRow) -> ApiResult<Option<Vec<u8>>> {
    match &user.totp_secret {
        Some(enc) => Ok(Some(state.decrypt_secret("totp", enc)?)),
        None => Ok(None),
    }
}

/// Verifies a TOTP code with ±1 step skew and rejects replays of the matched
/// time step (RFC 6238 §5.2) within the window.
pub async fn check_totp(state: &AppState, user: &UserRow, code: &str) -> ApiResult<bool> {
    let Some(secret) = decrypt_totp_secret(state, user)? else {
        return Ok(false);
    };
    let code = normalize_code(code);
    let totp = totp_for(state, user, &secret)?;
    let Some(step) = totp.check_current(&code) else {
        return Ok(false);
    };
    let replay_key = format!("totp_used:{}:{step}", user.id);
    let (n, _) = state
        .cache
        .incr_window(&replay_key, Duration::from_secs(95))
        .await?;
    Ok(n == 1)
}

pub async fn consume_backup_code(state: &AppState, user_id: Uuid, code: &str) -> ApiResult<bool> {
    let h = hash_token(&normalize_code(code));
    let res = sqlx::query("UPDATE backup_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL")
        .bind(user_id)
        .bind(&h)
        .execute(&state.db)
        .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn load_passkeys(state: &AppState, user_id: Uuid) -> ApiResult<Vec<(Uuid, Passkey)>> {
    let rows: Vec<(Uuid, serde_json::Value)> =
        sqlx::query_as("SELECT id, credential FROM webauthn_credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&state.db)
            .await?;
    rows.into_iter()
        .map(|(id, v)| Ok((id, serde_json::from_value::<Passkey>(v)?)))
        .collect()
}

#[utoipa::path(post, path = "/api/v1/auth/mfa/webauthn/challenge", tag = "auth",
    request_body = WebauthnChallengeRequest, responses((status = 200, body = serde_json::Value)))]
pub async fn mfa_webauthn_challenge(
    State(state): State<AppState>,
    Body(req): Body<WebauthnChallengeRequest>,
) -> ApiResult<Json<RequestChallengeResponse>> {
    let webauthn = state
        .webauthn
        .as_ref()
        .ok_or_else(|| Error::feature_disabled("WebAuthn"))?;
    let flow: MfaFlow = codes::get_flow(&state, P_MFA, &req.mfa_token).await?;
    let keys: Vec<Passkey> = load_passkeys(&state, flow.user_id)
        .await?
        .into_iter()
        .map(|(_, k)| k)
        .collect();
    if keys.is_empty() {
        return Err(Error::invalid_mfa());
    }
    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&keys)
        .map_err(|e| Error::Internal(anyhow::anyhow!("webauthn: {e}")))?;
    codes::set_flow(
        &state,
        P_WEBAUTHN_AUTH,
        &req.mfa_token,
        &auth_state,
        MFA_TTL,
    )
    .await?;
    Ok(Json(rcr))
}

#[utoipa::path(post, path = "/api/v1/auth/mfa/email/send", tag = "auth",
    request_body = WebauthnChallengeRequest, responses((status = 204)))]
pub async fn mfa_email_send(
    State(state): State<AppState>,
    Body(req): Body<WebauthnChallengeRequest>,
) -> ApiResult<NoContent> {
    let flow: MfaFlow = codes::get_flow(&state, P_MFA, &req.mfa_token).await?;
    let user = users::by_id(&state.db, flow.user_id).await?;
    if !user.email_verified {
        return Err(Error::email_unverified());
    }
    let code = codes::issue_for(&state, P_MFA_EMAIL, &req.mfa_token, &user.id, MFA_TTL).await?;
    send_code_email(&state, &user.email, "sign-in verification", &code, MFA_TTL)
        .await
        .map(NoContent::from)
}

#[utoipa::path(post, path = "/api/v1/auth/mfa/verify", tag = "auth",
    request_body = MfaVerifyRequest, responses((status = 200, body = AuthResponse)))]
pub async fn mfa_verify(
    State(state): State<AppState>,
    client: Client,
    Body(req): Body<MfaVerifyRequest>,
) -> ApiResult<Json<AuthResponse>> {
    ratelimit::check(
        &state,
        ratelimit::CODE_GUESS,
        &format!("mfa:{}", hash_token(&req.mfa_token)),
    )
    .await?;
    let flow: MfaFlow = codes::get_flow(&state, P_MFA, &req.mfa_token).await?;
    let user = users::by_id(&state.db, flow.user_id).await?;
    if user.disabled {
        return Err(Error::account_disabled());
    }
    let ok = match &req.credential {
        MfaCredential::Totp { code } => check_totp(&state, &user, code).await?,
        MfaCredential::BackupCode { code } => consume_backup_code(&state, user.id, code).await?,
        MfaCredential::Email { code } => {
            codes::verify::<Uuid>(&state, P_MFA_EMAIL, &req.mfa_token, code)
                .await
                .map(|_| true)
                .or_else(|e| match e {
                    Error::Status(..) => Ok(false),
                    other => Err(other),
                })?
        }
        MfaCredential::Webauthn { credential } => {
            let webauthn = state
                .webauthn
                .as_ref()
                .ok_or_else(|| Error::feature_disabled("WebAuthn"))?;
            let auth_state: PasskeyAuthentication =
                codes::take_flow(&state, P_WEBAUTHN_AUTH, &req.mfa_token).await?;
            let cred: PublicKeyCredential =
                serde_json::from_value(credential.clone()).map_err(|_| Error::invalid_mfa())?;
            match webauthn.finish_passkey_authentication(&cred, &auth_state) {
                Ok(result) => {
                    for (id, mut pk) in load_passkeys(&state, user.id).await? {
                        if pk.cred_id() == result.cred_id() {
                            pk.update_credential(&result);
                            sqlx::query("UPDATE webauthn_credentials SET credential = $2, last_used_at = now() WHERE id = $1")
                                .bind(id)
                                .bind(serde_json::to_value(&pk)?)
                                .execute(&state.db)
                                .await?;
                        }
                    }
                    true
                }
                Err(e) => {
                    tracing::debug!(error = %e, "webauthn assertion rejected");
                    false
                }
            }
        }
    };
    if !ok {
        users::security_event(
            &state,
            user.id,
            "mfa_failed",
            None,
            client.ip.as_deref(),
            client.user_agent.as_deref(),
            None,
        )
        .await?;
        return Err(Error::invalid_mfa());
    }
    codes::del_flow(&state, P_MFA, &req.mfa_token).await?;
    if let Some(session_id) = flow.reauth_session {
        let resp = complete_step_up(&state, &client, &user, session_id).await?;
        return Ok(Json(resp));
    }
    let device = flow
        .device
        .ok_or_else(|| Error::bad_request("Invalid MFA flow"))?;
    let resp = continue_login(&state, &client, &user, device, flow.sso_verified, true).await?;
    Ok(Json(resp))
}

// ───────────────────────────── step-up ─────────────────────────────

#[derive(Serialize, Deserialize)]
struct ReauthFlow {
    session_id: Uuid,
    user_id: Uuid,
    method: ReauthMethod,
    /// OPAQUE server login state (`method == password`).
    server_state: Option<String>,
}

async fn complete_step_up(
    state: &AppState,
    client: &Client,
    user: &UserRow,
    session_id: Uuid,
) -> ApiResult<AuthResponse> {
    let reauth_expires_at = session::mark_step_up(state, session_id).await?;
    users::security_event(
        state,
        user.id,
        "reauth",
        None,
        client.ip.as_deref(),
        client.user_agent.as_deref(),
        None,
    )
    .await?;
    Ok(AuthResponse::Reauthenticated { reauth_expires_at })
}

#[utoipa::path(post, path = "/api/v1/auth/reauth/start", tag = "auth",
    request_body = ReauthStartRequest, responses((status = 200, body = ReauthStartResponse)))]
pub async fn reauth_start(
    State(state): State<AppState>,
    auth: Auth,
    Body(req): Body<ReauthStartRequest>,
) -> ApiResult<Json<ReauthStartResponse>> {
    let user = users::by_id(&state.db, auth.user_id()).await?;
    ratelimit::check(&state, ratelimit::AUTH_ACCOUNT, &user.email).await?;
    let mut flow = ReauthFlow {
        session_id: auth.session.session_id,
        user_id: user.id,
        method: ReauthMethod::None,
        server_state: None,
    };
    let mut opaque_response = None;
    let mut email_hint = None;
    if let Some(record) = user.opaque_record.as_deref() {
        let request = req
            .opaque_request
            .as_deref()
            .ok_or_else(|| Error::bad_request("opaque_request is required"))?;
        let (resp, server_state) = state
            .opaque
            .login_start(&user.email, Some(record), request)?;
        flow.method = ReauthMethod::Password;
        flow.server_state = Some(b64(&server_state));
        opaque_response = Some(resp);
    } else if state.mailer.is_some() && user.email_verified {
        flow.method = ReauthMethod::Email;
        email_hint = Some(mask_email(&user.email));
    } else if !users::mfa_enabled(&state, &user).await? {
        // Nothing this account could prove ownership with; refusing beats
        // letting a bare bearer token perform destructive changes.
        return Err(Error::bad_request(
            "Re-authentication is not available: this account has no password, \
             no verified email and no second factor",
        ));
    }
    let reauth_id = codes::put_flow(&state, P_REAUTH, &flow, MFA_TTL).await?;
    if flow.method == ReauthMethod::Email {
        let code = codes::issue_for(&state, P_REAUTH_EMAIL, &reauth_id, &user.id, MFA_TTL).await?;
        send_code_email(&state, &user.email, "confirm it's you", &code, MFA_TTL).await?;
    }
    Ok(Json(ReauthStartResponse {
        reauth_id,
        method: flow.method,
        opaque_response,
        email_hint,
    }))
}

#[utoipa::path(post, path = "/api/v1/auth/reauth/finish", tag = "auth",
    request_body = ReauthFinishRequest, responses((status = 200, body = AuthResponse)))]
pub async fn reauth_finish(
    State(state): State<AppState>,
    auth: Auth,
    client: Client,
    Body(req): Body<ReauthFinishRequest>,
) -> ApiResult<Json<AuthResponse>> {
    ratelimit::check(
        &state,
        ratelimit::CODE_GUESS,
        &format!("reauth:{}", hash_token(&req.reauth_id)),
    )
    .await?;
    let flow: ReauthFlow = codes::get_flow(&state, P_REAUTH, &req.reauth_id).await?;
    if flow.session_id != auth.session.session_id || flow.user_id != auth.user_id() {
        return Err(Error::unauthorized());
    }
    let user = users::by_id(&state.db, auth.user_id()).await?;
    let ok = match flow.method {
        ReauthMethod::Password => {
            // OPAQUE server state is single-use: a wrong password restarts.
            codes::del_flow(&state, P_REAUTH, &req.reauth_id).await?;
            let (Some(st), Some(fin)) = (&flow.server_state, &req.opaque_finalization) else {
                return Err(Error::bad_request("opaque_finalization is required"));
            };
            opaque::Server::login_finish(&user.email, &unb64(st)?, fin).is_ok()
        }
        ReauthMethod::Email => {
            let code = req
                .code
                .as_deref()
                .ok_or_else(|| Error::bad_request("code is required"))?;
            // A wrong code keeps the flow alive for another attempt (rate limited).
            codes::verify::<Uuid>(&state, P_REAUTH_EMAIL, &req.reauth_id, code).await?;
            codes::del_flow(&state, P_REAUTH, &req.reauth_id).await?;
            true
        }
        ReauthMethod::None => {
            codes::del_flow(&state, P_REAUTH, &req.reauth_id).await?;
            true
        }
    };
    if !ok {
        users::security_event(
            &state,
            user.id,
            "reauth_failed",
            Some(auth.device_id()),
            client.ip.as_deref(),
            client.user_agent.as_deref(),
            None,
        )
        .await?;
        return Err(Error::invalid_credentials());
    }
    if users::mfa_enabled(&state, &user).await? {
        let methods = available_mfa_methods(&state, &user).await?;
        let mfa_token = codes::put_flow(
            &state,
            P_MFA,
            &MfaFlow {
                user_id: user.id,
                device: None,
                sso_verified: false,
                reauth_session: Some(auth.session.session_id),
            },
            MFA_TTL,
        )
        .await?;
        return Ok(Json(AuthResponse::MfaRequired { mfa_token, methods }));
    }
    let resp = complete_step_up(&state, &client, &user, auth.session.session_id).await?;
    Ok(Json(resp))
}

// ───────────────────────────── device approval ─────────────────────────────

#[utoipa::path(post, path = "/api/v1/auth/device/approve", tag = "auth",
    request_body = DeviceApproveRequest, responses((status = 200, body = AuthResponse)))]
pub async fn device_approve(
    State(state): State<AppState>,
    client: Client,
    Body(req): Body<DeviceApproveRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let flow: ApprovalFlow =
        codes::verify(&state, P_APPROVE, &req.approval_token, &req.code).await?;
    let user = users::by_id(&state.db, flow.user_id).await?;
    if user.disabled {
        return Err(Error::account_disabled());
    }
    let sess = build_session(&state, &user, flow.device_id).await?;
    users::security_event(
        &state,
        user.id,
        "device_approved",
        Some(flow.device_id),
        client.ip.as_deref(),
        client.user_agent.as_deref(),
        None,
    )
    .await?;
    metrics::counter!("termoso_logins_total", "result" => "ok").increment(1);
    Ok(Json(AuthResponse::Authenticated(sess)))
}

#[utoipa::path(post, path = "/api/v1/auth/device/approve/resend", tag = "auth",
    request_body = DeviceApproveResendRequest, responses((status = 204)))]
pub async fn device_approve_resend(
    State(state): State<AppState>,
    Body(req): Body<DeviceApproveResendRequest>,
) -> ApiResult<NoContent> {
    let (flow, code): (ApprovalFlow, String) =
        codes::reissue(&state, P_APPROVE, &req.approval_token, APPROVAL_TTL).await?;
    let user = users::by_id(&state.db, flow.user_id).await?;
    send_code_email(
        &state,
        &user.email,
        "new device sign-in",
        &code,
        APPROVAL_TTL,
    )
    .await
    .map(NoContent::from)
}

// ───────────────────────────── recovery & password ─────────────────────────────

#[derive(Serialize, Deserialize)]
struct RecoveryFlow {
    user_id: Uuid,
}

#[utoipa::path(post, path = "/api/v1/auth/recovery/start", tag = "auth",
    request_body = RecoveryStartRequest, responses((status = 200, body = RecoveryStartResponse)))]
pub async fn recovery_start(
    State(state): State<AppState>,
    client: Client,
    Body(req): Body<RecoveryStartRequest>,
) -> ApiResult<Json<RecoveryStartResponse>> {
    ratelimit::check_ip(&state, ratelimit::AUTH_IP, client.ip.as_deref()).await?;
    turnstile::require(&state, req.turnstile_token.as_deref(), client.ip.as_deref()).await?;
    let email = normalize_email(&req.email).ok_or_else(|| Error::bad_request("Invalid email"))?;
    ratelimit::check(&state, ratelimit::AUTH_ACCOUNT, &email).await?;
    unb64_array::<32>(&req.recovery_verifier)
        .map_err(|_| Error::bad_request("recovery_verifier must be 32 bytes"))?;
    let user = users::by_email(&state.db, &email).await?;
    let Some(user) = user else {
        return Err(Error::invalid_credentials());
    };
    if !crate::util::constant_time_eq(
        &user.recovery_verifier_hash,
        &hash_token(&req.recovery_verifier),
    ) {
        users::security_event(
            &state,
            user.id,
            "recovery_failed",
            None,
            client.ip.as_deref(),
            client.user_agent.as_deref(),
            None,
        )
        .await?;
        return Err(Error::invalid_credentials());
    }
    if user.disabled {
        return Err(Error::account_disabled());
    }
    let recovery_token = codes::put_flow(
        &state,
        P_RECOVERY,
        &RecoveryFlow { user_id: user.id },
        RECOVERY_TTL,
    )
    .await?;
    users::security_event(
        &state,
        user.id,
        "recovery_started",
        None,
        client.ip.as_deref(),
        client.user_agent.as_deref(),
        None,
    )
    .await?;
    Ok(Json(RecoveryStartResponse {
        recovery_token,
        recovery_wrapped_private_key: user.recovery_wrapped_private_key,
        public_key: user.public_key,
    }))
}

async fn resolve_password_subject(
    state: &AppState,
    auth: &Option<Auth>,
    recovery_token: &Option<String>,
) -> ApiResult<UserRow> {
    match (auth, recovery_token) {
        (_, Some(token)) => {
            let flow: RecoveryFlow = codes::get_flow(state, P_RECOVERY, token).await?;
            users::by_id(&state.db, flow.user_id).await
        }
        (Some(auth), None) => {
            auth.require_step_up()?;
            users::by_id(&state.db, auth.user_id()).await
        }
        (None, None) => Err(Error::unauthorized()),
    }
}

#[utoipa::path(post, path = "/api/v1/auth/password/start", tag = "auth",
    request_body = PasswordSetupStartRequest, responses((status = 200, body = PasswordSetupStartResponse)))]
pub async fn password_start(
    State(state): State<AppState>,
    auth: Option<Auth>,
    Body(req): Body<PasswordSetupStartRequest>,
) -> ApiResult<Json<PasswordSetupStartResponse>> {
    let user = resolve_password_subject(&state, &auth, &req.recovery_token).await?;
    let opaque_response = state
        .opaque
        .registration_start(&user.email, &req.opaque_request)?;
    Ok(Json(PasswordSetupStartResponse { opaque_response }))
}

#[utoipa::path(post, path = "/api/v1/auth/password/finish", tag = "auth",
    request_body = PasswordSetupFinishRequest, responses((status = 200, body = AuthResponse)))]
pub async fn password_finish(
    State(state): State<AppState>,
    auth: Option<Auth>,
    client: Client,
    Body(req): Body<PasswordSetupFinishRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let user = resolve_password_subject(&state, &auth, &req.recovery_token).await?;
    unb64(&req.wrapped_private_key)
        .map_err(|_| Error::bad_request("wrapped_private_key is not valid base64"))?;
    if let Some(r) = &req.new_recovery {
        unb64_array::<32>(&r.recovery_verifier)
            .map_err(|_| Error::bad_request("recovery_verifier must be 32 bytes"))?;
        unb64(&r.recovery_wrapped_private_key)
            .map_err(|_| Error::bad_request("recovery_wrapped_private_key is not valid base64"))?;
    }
    let record = opaque::Server::registration_finish(&req.opaque_upload)?;

    let device = match (&auth, &req.device) {
        (Some(a), _) => Some(a.device_id()),
        (None, Some(_)) => None,
        (None, None) => return Err(Error::bad_request("device is required for recovery")),
    };

    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET opaque_record = $2, wrapped_private_key = $3, updated_at = now() WHERE id = $1")
        .bind(user.id)
        .bind(&record)
        .bind(&req.wrapped_private_key)
        .execute(&mut *tx)
        .await?;
    if let Some(r) = &req.new_recovery {
        sqlx::query("UPDATE users SET recovery_wrapped_private_key = $2, recovery_verifier_hash = $3 WHERE id = $1")
            .bind(user.id)
            .bind(&r.recovery_wrapped_private_key)
            .bind(hash_token(&r.recovery_verifier))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    if let Some(t) = &req.recovery_token {
        codes::del_flow(&state, P_RECOVERY, t).await?;
    }
    let kind = if req.recovery_token.is_some() {
        "password_recovered"
    } else {
        "password_changed"
    };

    let device_id = match device {
        Some(id) => id,
        None => {
            let info = req
                .device
                .as_ref()
                .ok_or_else(|| Error::bad_request("device is required"))?;
            validate_device(info)?;
            check_client_version(&state.cfg, info)?;
            session::upsert_device(&state.db, user.id, info, client.ip.as_deref())
                .await?
                .0
        }
    };
    // A new password always signs every other session out: the caller may be
    // reclaiming a compromised account. `revoke_other_sessions` is kept in the
    // protocol for compatibility; it cannot opt out.
    session::revoke_all(&state, user.id, None).await?;
    let user = users::by_id(&state.db, user.id).await?;
    let sess = build_session(&state, &user, device_id).await?;
    users::security_event(
        &state,
        user.id,
        kind,
        Some(device_id),
        client.ip.as_deref(),
        client.user_agent.as_deref(),
        None,
    )
    .await?;
    let what = if req.recovery_token.is_some() {
        "Your password was reset with the recovery phrase"
    } else {
        "Your password was changed"
    };
    let mut text = format!("{what}. Every other device and browser was signed out.");
    if req.new_recovery.is_some() {
        text.push_str(" A new recovery phrase was generated; the previous one no longer works.");
    }
    users::notify(&state, &user.email, "password changed", &text).await;
    crate::events::publish(
        &state,
        crate::events::Event::AccountUpdated { user_id: user.id },
    )
    .await?;
    Ok(Json(AuthResponse::Authenticated(sess)))
}

#[utoipa::path(post, path = "/api/v1/auth/logout", tag = "auth", responses((status = 204)))]
pub async fn logout(State(state): State<AppState>, auth: Auth) -> ApiResult<NoContent> {
    session::revoke_session(&state, auth.session.session_id)
        .await
        .map(NoContent::from)
}

// ───────────────────────────── SSO ─────────────────────────────

#[utoipa::path(get, path = "/api/v1/auth/sso/providers", tag = "auth", responses((status = 200, body = Vec<SsoProvider>)))]
pub async fn sso_providers(State(state): State<AppState>) -> Json<Vec<SsoProvider>> {
    Json(state.sso.list())
}

#[derive(Deserialize)]
pub struct SsoStartQuery {
    pub redirect: Option<String>,
}

#[utoipa::path(get, path = "/api/v1/auth/sso/{provider}/start", tag = "auth",
    params(("provider" = String, Path), ("redirect" = Option<String>, Query)),
    responses((status = 200, body = SsoStartResponse)))]
pub async fn sso_start(
    State(state): State<AppState>,
    client: Client,
    Path(provider): Path<String>,
    Query(q): Query<SsoStartQuery>,
) -> ApiResult<Json<SsoStartResponse>> {
    ratelimit::check_ip(&state, ratelimit::AUTH_IP, client.ip.as_deref()).await?;
    let (authorization_url, flow_id) = sso::start(&state, &provider, q.redirect, None).await?;
    Ok(Json(SsoStartResponse {
        authorization_url,
        flow_id,
    }))
}

#[derive(Deserialize)]
pub struct SsoCallbackQuery {
    pub state: Option<String>,
    pub code: Option<String>,
    pub error: Option<String>,
}

pub async fn sso_callback(
    State(state): State<AppState>,
    client: Client,
    Query(q): Query<SsoCallbackQuery>,
) -> ApiResult<Response> {
    ratelimit::check_ip(&state, ratelimit::ANON_IP, client.ip.as_deref()).await?;
    let flow_id = q.state.ok_or_else(|| Error::bad_request("missing state"))?;
    let (redirect, flow_id) =
        sso::callback(&state, &flow_id, q.code.as_deref(), q.error.as_deref()).await?;
    Ok(sso_done(&state, redirect, &flow_id))
}

fn sso_done(state: &AppState, redirect: Option<String>, flow_id: &str) -> Response {
    if let Some(target) = redirect {
        let sep = if target.contains('?') { '&' } else { '?' };
        return Redirect::to(&format!("{target}{sep}flow={flow_id}")).into_response();
    }
    Html(SSO_DONE_HTML.replace("{name}", &html_escape(&state.cfg.server_name))).into_response()
}

/// SP metadata for a SAML provider — hand this URL (or its output) to the IdP.
#[utoipa::path(get, path = "/api/v1/auth/sso/{provider}/saml/metadata", tag = "auth",
    params(("provider" = String, Path)),
    responses((status = 200, description = "SAML SP EntityDescriptor", content_type = "application/samlmetadata+xml")))]
pub async fn sso_saml_metadata(
    State(state): State<AppState>,
    Path(provider): Path<String>,
) -> ApiResult<Response> {
    let xml = state.sso.saml_metadata(&provider)?;
    Ok((
        [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
        xml,
    )
        .into_response())
}

/// SAML HTTP-POST binding: auto-submitting form carrying the `AuthnRequest`.
pub async fn sso_saml_post(
    State(state): State<AppState>,
    client: Client,
    Path(flow_id): Path<String>,
) -> ApiResult<Html<String>> {
    ratelimit::check_ip(&state, ratelimit::ANON_IP, client.ip.as_deref()).await?;
    let form = sso::saml_post_form(&state, &flow_id).await?;
    Ok(Html(
        SAML_POST_HTML
            .replace("{action}", &html_escape(&form.action))
            .replace("{request}", &html_escape(&form.saml_request))
            .replace("{relay}", &html_escape(&flow_id)),
    ))
}

#[derive(Deserialize)]
pub struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// SAML Assertion Consumer Service (HTTP-POST binding).
pub async fn sso_saml_acs(
    State(state): State<AppState>,
    client: Client,
    Form(form): Form<SamlAcsForm>,
) -> ApiResult<Response> {
    ratelimit::check_ip(&state, ratelimit::AUTH_IP, client.ip.as_deref()).await?;
    let relay = form
        .relay_state
        .filter(|r| !r.is_empty())
        .ok_or_else(|| Error::bad_request("missing RelayState"))?;
    let (redirect, flow_id) = sso::saml_acs(&state, &relay, &form.saml_response).await?;
    Ok(sso_done(&state, redirect, &flow_id))
}

#[utoipa::path(get, path = "/api/v1/auth/sso/flow/{flow_id}", tag = "auth",
    params(("flow_id" = String, Path)), responses((status = 200, body = SsoResult)))]
pub async fn sso_poll(
    State(state): State<AppState>,
    client: Client,
    Path(flow_id): Path<String>,
) -> ApiResult<Json<SsoResult>> {
    ratelimit::check_ip(&state, ratelimit::ANON_IP, client.ip.as_deref()).await?;
    Ok(Json(sso::poll(&state, &flow_id).await?))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const SAML_POST_HTML: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Signing in…</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#12151F;color:#E6E8F0;font-family:system-ui,sans-serif}
button{background:#3DDC84;color:#0B1F14;border:0;border-radius:8px;padding:10px 18px;font-size:15px;cursor:pointer}</style></head>
<body><form method="post" action="{action}"><input type="hidden" name="SAMLRequest" value="{request}"><input type="hidden" name="RelayState" value="{relay}">
<noscript><button type="submit">Continue to your identity provider</button></noscript></form>
<script>document.forms[0].submit()</script></body></html>"#;

const SSO_DONE_HTML: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#12151F;color:#E6E8F0;font-family:system-ui,sans-serif}
.card{background:#1A1E2B;border:1px solid #2D3345;border-radius:12px;padding:32px 40px;text-align:center;max-width:420px}
h1{font-size:20px;margin:0 0 8px;color:#5FD0A4}p{margin:0;color:#8E93A8}</style></head>
<body><div class="card"><h1>Signed in</h1><p>You can close this window and return to {name}.</p></div></body></html>"#;

const USERS_INSERT_SQL: &str =
    "INSERT INTO users (id, email, email_verified, display_name, opaque_record, public_key,
            wrapped_private_key, recovery_wrapped_private_key, recovery_verifier_hash, is_admin,
            managed_by_team_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT DO NOTHING";
const USERS_TAKEOVER_SQL: &str = "UPDATE users SET email = $2, email_verified = $3, display_name = COALESCE($4, display_name),
        opaque_record = $5, public_key = $6, wrapped_private_key = $7, recovery_wrapped_private_key = $8,
        recovery_verifier_hash = $9, is_admin = $10, managed_by_team_id = COALESCE($11, managed_by_team_id)
     WHERE id = $1 AND opaque_record IS NULL";

#[cfg(test)]
mod client_version_tests {
    use super::*;

    fn dev(v: &str) -> DeviceInfo {
        DeviceInfo {
            name: "t".into(),
            platform: termoso_proto::auth::Platform::Windows,
            app_version: v.into(),
            client_device_id: None,
            posture: None,
        }
    }

    #[test]
    fn web_cabinet_is_never_gated() {
        let cfg = crate::config::Config {
            min_client_version: Some("9.9.9".into()),
            ..Default::default()
        };
        let d = DeviceInfo {
            name: "browser".into(),
            platform: Platform::Web,
            app_version: "0.1.0".into(),
            client_device_id: None,
            posture: None,
        };
        assert!(check_client_version(&cfg, &d).is_ok());
    }

    #[test]
    fn older_client_is_refused_newer_or_equal_passes() {
        let cfg = crate::config::Config {
            min_client_version: Some("0.9.1".into()),
            ..Default::default()
        };
        assert!(check_client_version(&cfg, &dev("0.9.0")).is_err());
        assert!(check_client_version(&cfg, &dev("0.9.1")).is_ok());
        assert!(check_client_version(&cfg, &dev("0.10.0")).is_ok());
        assert!(check_client_version(&cfg, &dev("1.0.0-beta.1")).is_ok());
        // Non-semver builds (dev, tests) are not blocked.
        assert!(check_client_version(&cfg, &dev("dev")).is_ok());
        assert!(check_client_version(&cfg, &dev("0.0.0-test")).is_ok());
        assert!(check_client_version(&cfg, &dev("")).is_ok());
    }

    #[test]
    fn default_minimum_is_the_server_version() {
        let cfg = crate::config::Config::default();
        assert_eq!(min_client_version(&cfg), crate::state::VERSION);
        assert!(check_client_version(&cfg, &dev(crate::state::VERSION)).is_ok());
        assert!(check_client_version(&cfg, &dev("0.0.1")).is_err());
    }
}
