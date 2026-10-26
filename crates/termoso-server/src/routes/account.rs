//! Account: profile, email verification/change, encrypted settings blob,
//! devices, security events, recovery-key rotation, deletion.

use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use termoso_crypto::encoding::{unb64, unb64_array};
use termoso_proto::account::*;
use termoso_proto::auth::{Device, DeviceList, RecoveryRotate, SsoIdentity, SsoStartResponse};
use uuid::Uuid;

use crate::avatar;
use crate::codes;
use crate::error::{ApiResult, Error, NoContent};
use crate::events::{self, Event};
use crate::extract::{Auth, Json as Body, StepUp};
use crate::presence;
use crate::ratelimit;
use crate::routes::auth::{P_EMAIL_VERIFY, send_email_verification};
use crate::session;
use crate::state::AppState;
use crate::users;
use crate::util::{hash_token, normalize_email};

const EMAIL_CHANGE_TTL: Duration = Duration::from_secs(1800);
const P_EMAIL_CHANGE: &str = "email_change";
const P_DELETE: &str = "account_delete";

#[derive(Serialize)]
pub struct AccountResponse {
    pub user: UserProfile,
    pub keys: AccountKeys,
}

#[utoipa::path(get, path = "/api/v1/account", tag = "account", responses((status = 200)))]
pub async fn get(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<AccountResponse>> {
    let u = users::by_id(&state.db, auth.user_id()).await?;
    let mfa = users::mfa_enabled(&state, &u).await?;
    let is_owner = state.owner_user_id().await? == Some(u.id);
    Ok(Json(AccountResponse {
        user: users::profile(&u, mfa, is_owner),
        keys: users::keys(&u),
    }))
}

#[utoipa::path(patch, path = "/api/v1/account/profile", tag = "account",
    request_body = UpdateProfileRequest, responses((status = 200, body = UserProfile)))]
pub async fn update_profile(
    State(state): State<AppState>,
    auth: Auth,
    Body(req): Body<UpdateProfileRequest>,
) -> ApiResult<Json<UserProfile>> {
    let name = req
        .display_name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());
    if name.as_ref().is_some_and(|n| n.chars().count() > 100) {
        return Err(Error::bad_request("Display name is too long"));
    }
    sqlx::query("UPDATE users SET display_name = $2, updated_at = now() WHERE id = $1")
        .bind(auth.user_id())
        .bind(&name)
        .execute(&state.db)
        .await?;
    let u = users::by_id(&state.db, auth.user_id()).await?;
    let mfa = users::mfa_enabled(&state, &u).await?;
    let is_owner = state.owner_user_id().await? == Some(u.id);
    events::publish(&state, Event::AccountUpdated { user_id: u.id }).await?;
    Ok(Json(users::profile(&u, mfa, is_owner)))
}

#[utoipa::path(put, path = "/api/v1/account/presence", tag = "account",
    request_body = PresenceVisibilityRequest, responses((status = 200, body = UserProfile)))]
pub async fn put_presence(
    State(state): State<AppState>,
    auth: Auth,
    Body(req): Body<PresenceVisibilityRequest>,
) -> ApiResult<Json<UserProfile>> {
    sqlx::query("UPDATE users SET presence_hidden = $2, updated_at = now() WHERE id = $1")
        .bind(auth.user_id())
        .bind(req.hidden)
        .execute(&state.db)
        .await?;
    if req.hidden {
        presence::clear_user(&state, auth.user_id()).await?;
    }
    let u = users::by_id(&state.db, auth.user_id()).await?;
    let mfa = users::mfa_enabled(&state, &u).await?;
    let is_owner = state.owner_user_id().await? == Some(u.id);
    events::publish(&state, Event::AccountUpdated { user_id: u.id }).await?;
    Ok(Json(users::profile(&u, mfa, is_owner)))
}

// ───────────────────────────── avatar ─────────────────────────────

#[utoipa::path(put, path = "/api/v1/account/avatar", tag = "account",
    request_body(content_type = "image/*"), responses((status = 200, body = UserProfile)))]
pub async fn put_avatar(
    State(state): State<AppState>,
    auth: Auth,
    body: Bytes,
) -> ApiResult<Json<UserProfile>> {
    if body.len() > avatar::MAX_UPLOAD {
        return Err(Error::too_large("Image is too large (4 MiB max)"));
    }
    let webp = tokio::task::spawn_blocking(move || avatar::normalize(&body))
        .await
        .map_err(|e| Error::Internal(e.into()))??;
    avatar::store(&state.db, auth.user_id(), &webp).await?;
    let u = users::by_id(&state.db, auth.user_id()).await?;
    let mfa = users::mfa_enabled(&state, &u).await?;
    let is_owner = state.owner_user_id().await? == Some(u.id);
    events::publish(&state, Event::AccountUpdated { user_id: u.id }).await?;
    Ok(Json(users::profile(&u, mfa, is_owner)))
}

#[utoipa::path(delete, path = "/api/v1/account/avatar", tag = "account", responses((status = 200, body = UserProfile)))]
pub async fn delete_avatar(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<UserProfile>> {
    avatar::clear(&state.db, auth.user_id()).await?;
    let u = users::by_id(&state.db, auth.user_id()).await?;
    let mfa = users::mfa_enabled(&state, &u).await?;
    let is_owner = state.owner_user_id().await? == Some(u.id);
    events::publish(&state, Event::AccountUpdated { user_id: u.id }).await?;
    Ok(Json(users::profile(&u, mfa, is_owner)))
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct AvatarQuery {
    /// Content tag the client expects (`UserProfile.avatar`). When it matches
    /// the stored picture the response is cacheable forever, because the URL
    /// then changes together with the picture.
    pub v: Option<String>,
}

/// Anyone signed in may see anyone's picture: it is the same information a
/// teammate sees next to your name. Responses carry the tag as `ETag`;
/// requests pinned to the current tag via `?v=` are marked immutable, others
/// must revalidate so a replaced picture never sticks in an HTTP cache.
#[utoipa::path(get, path = "/api/v1/users/{id}/avatar", tag = "account", params(AvatarQuery),
    responses((status = 200, content_type = "image/webp"), (status = 304), (status = 404)))]
pub async fn user_avatar(
    State(state): State<AppState>,
    _auth: Auth,
    Path(id): Path<Uuid>,
    Query(q): Query<AvatarQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let (bytes, tag) = avatar::load(&state.db, id)
        .await?
        .ok_or_else(|| Error::not_found("Avatar"))?;
    let etag = format!("\"{tag}\"");
    let cache = if q.v.as_deref() == Some(tag.as_str()) {
        "private, max-age=31536000, immutable"
    } else {
        "private, no-cache"
    };
    let common = [
        (
            header::ETAG,
            HeaderValue::from_str(&etag).map_err(|e| Error::Internal(e.into()))?,
        ),
        (header::CACHE_CONTROL, HeaderValue::from_static(cache)),
    ];
    let unchanged = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag));
    if unchanged {
        return Ok((StatusCode::NOT_MODIFIED, common).into_response());
    }
    Ok((
        common,
        [(header::CONTENT_TYPE, HeaderValue::from_static("image/webp"))],
        bytes,
    )
        .into_response())
}

// ───────────────────────────── email ─────────────────────────────

#[utoipa::path(post, path = "/api/v1/account/email/verify/send", tag = "account", responses((status = 204)))]
pub async fn email_verify_send(State(state): State<AppState>, auth: Auth) -> ApiResult<NoContent> {
    if state.mailer.is_none() {
        return Err(Error::feature_disabled("Email"));
    }
    let u = users::by_id(&state.db, auth.user_id()).await?;
    if u.email_verified {
        return Ok(NoContent);
    }
    send_email_verification(&state, &u)
        .await
        .map(NoContent::from)
}

#[utoipa::path(post, path = "/api/v1/account/email/verify/confirm", tag = "account",
    request_body = CodeRequest, responses((status = 204)))]
pub async fn email_verify_confirm(
    State(state): State<AppState>,
    auth: Auth,
    Body(req): Body<CodeRequest>,
) -> ApiResult<NoContent> {
    let email: String = codes::verify(
        &state,
        P_EMAIL_VERIFY,
        &auth.user_id().to_string(),
        &req.code,
    )
    .await?;
    let res = sqlx::query("UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1 AND lower(email) = $2")
        .bind(auth.user_id())
        .bind(email.to_lowercase())
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(Error::invalid_code());
    }
    session::invalidate_user_cache(&state, auth.user_id()).await?;
    crate::enterprise::ensure_home_team(&state, auth.user_id()).await?;
    users::security_event(
        &state,
        auth.user_id(),
        "email_verified",
        Some(auth.device_id()),
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        None,
    )
    .await?;
    events::publish(
        &state,
        Event::AccountUpdated {
            user_id: auth.user_id(),
        },
    )
    .await?;
    Ok(NoContent)
}

#[utoipa::path(post, path = "/api/v1/account/email/change", tag = "account",
    request_body = ChangeEmailRequest, responses((status = 204)))]
pub async fn email_change(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    Body(req): Body<ChangeEmailRequest>,
) -> ApiResult<NoContent> {
    let new_email =
        normalize_email(&req.new_email).ok_or_else(|| Error::bad_request("Invalid email"))?;
    if users::by_email(&state.db, &new_email).await?.is_some() {
        return Err(Error::email_taken());
    }
    let u = users::by_id(&state.db, auth.user_id()).await?;
    if u.opaque_record.is_none() {
        return Err(Error::bad_request("Account has no password"));
    }
    match &state.mailer {
        None => {
            // No email on this server: change directly (nothing to verify against).
            apply_email_change(&state, &auth, &new_email)
                .await
                .map(NoContent::from)
        }
        Some(mailer) => {
            ratelimit::check(&state, ratelimit::EMAIL, &new_email).await?;
            let code = codes::issue_for(
                &state,
                P_EMAIL_CHANGE,
                &auth.user_id().to_string(),
                &new_email,
                EMAIL_CHANGE_TTL,
            )
            .await?;
            let email = mailer.code_email("email change", &code, EMAIL_CHANGE_TTL.as_secs() / 60);
            mailer
                .send(&new_email, &email)
                .await
                .map_err(|e| Error::Internal(e.context("sending email")))?;
            Ok(NoContent)
        }
    }
}

#[utoipa::path(post, path = "/api/v1/account/email/change/confirm", tag = "account",
    request_body = CodeRequest, responses((status = 204)))]
pub async fn email_change_confirm(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    Body(req): Body<CodeRequest>,
) -> ApiResult<NoContent> {
    let new_email: String = codes::verify(
        &state,
        P_EMAIL_CHANGE,
        &auth.user_id().to_string(),
        &req.code,
    )
    .await?;
    if users::by_email(&state.db, &new_email).await?.is_some() {
        return Err(Error::email_taken());
    }
    apply_email_change(&state, &auth, &new_email)
        .await
        .map(NoContent::from)
}

async fn apply_email_change(state: &AppState, auth: &Auth, new_email: &str) -> ApiResult<()> {
    // The OPAQUE record is bound to the email (identifier), so a fresh
    // registration is needed. Clear the record and let the client re-register
    // its password via /auth/password/* while still authenticated.
    let old = users::by_id(&state.db, auth.user_id()).await?;
    sqlx::query(
        "UPDATE users SET email = $2, email_verified = $3, opaque_record = NULL, updated_at = now() WHERE id = $1",
    )
    .bind(auth.user_id())
    .bind(new_email)
    .bind(state.mailer.is_some())
    .execute(&state.db)
    .await?;
    session::invalidate_user_cache(state, auth.user_id()).await?;
    users::security_event(
        state,
        auth.user_id(),
        "email_changed",
        Some(auth.device_id()),
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        Some(serde_json::json!({ "from": old.email, "to": new_email })),
    )
    .await?;
    users::notify(
        state,
        &old.email,
        "email changed",
        &format!("The email address of your account was changed to {new_email}."),
    )
    .await;
    events::publish(
        state,
        Event::AccountUpdated {
            user_id: auth.user_id(),
        },
    )
    .await
}

// ───────────────────────────── settings blob ─────────────────────────────

#[utoipa::path(get, path = "/api/v1/account/settings", tag = "account", responses((status = 200, body = SettingsBlob)))]
pub async fn get_settings(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<SettingsBlob>> {
    let row: Option<(String, i64, DateTime<Utc>)> =
        sqlx::query_as("SELECT data, version, updated_at FROM user_settings WHERE user_id = $1")
            .bind(auth.user_id())
            .fetch_optional(&state.db)
            .await?;
    let (data, version, updated_at) = row.unwrap_or_else(|| (String::new(), 0, Utc::now()));
    Ok(Json(SettingsBlob {
        data,
        version,
        updated_at,
    }))
}

#[utoipa::path(put, path = "/api/v1/account/settings", tag = "account",
    request_body = PutSettingsRequest, responses((status = 200, body = SettingsBlob)))]
pub async fn put_settings(
    State(state): State<AppState>,
    auth: Auth,
    Body(req): Body<PutSettingsRequest>,
) -> ApiResult<Json<SettingsBlob>> {
    let max = state.settings().await?.max_entity_bytes as usize;
    if req.data.len() > max {
        return Err(Error::too_large("Settings blob too large"));
    }
    let row: Option<(i64, DateTime<Utc>)> = sqlx::query_as(
        "INSERT INTO user_settings (user_id, data, version, updated_at) VALUES ($1, $2, 1, now())
         ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data, version = user_settings.version + 1, updated_at = now()
         WHERE user_settings.version = $3
         RETURNING version, updated_at",
    )
    .bind(auth.user_id())
    .bind(&req.data)
    .bind(req.base_version)
    .fetch_optional(&state.db)
    .await?;
    let Some((version, updated_at)) = row else {
        return Err(Error::conflict("Settings were modified by another device"));
    };
    events::publish(
        &state,
        Event::AccountUpdated {
            user_id: auth.user_id(),
        },
    )
    .await?;
    Ok(Json(SettingsBlob {
        data: req.data,
        version,
        updated_at,
    }))
}

// ───────────────────────────── devices ─────────────────────────────

#[utoipa::path(get, path = "/api/v1/account/devices", tag = "account", responses((status = 200, body = DeviceList)))]
pub async fn devices(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<DeviceList>> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        Uuid,
        String,
        String,
        Option<String>,
        DateTime<Utc>,
        DateTime<Utc>,
        Option<String>,
        Option<serde_json::Value>,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        "SELECT d.id, d.name, d.platform, d.app_version, d.created_at, d.last_seen_at, d.last_ip, d.posture, d.posture_at
         FROM devices d
         WHERE d.user_id = $1
           AND EXISTS (SELECT 1 FROM sessions s WHERE s.device_id = d.id AND s.revoked_at IS NULL AND s.expires_at > now())
           AND NOT EXISTS (SELECT 1 FROM bridges b WHERE b.device_id = d.id)
         ORDER BY d.last_seen_at DESC",
    )
    .bind(auth.user_id())
    .fetch_all(&state.db)
    .await?;
    let devices = rows
        .into_iter()
        .map(
            |(
                id,
                name,
                platform,
                app_version,
                created_at,
                last_seen_at,
                last_ip,
                posture,
                posture_at,
            )| Device {
                id,
                name,
                platform: session::parse_platform(&platform),
                app_version: app_version.unwrap_or_default(),
                created_at,
                last_seen_at,
                last_ip,
                current: id == auth.device_id(),
                posture: posture.and_then(|v| serde_json::from_value(v).ok()),
                posture_at,
            },
        )
        .collect();
    Ok(Json(DeviceList { devices }))
}

#[utoipa::path(delete, path = "/api/v1/account/devices/{id}", tag = "account",
    params(("id" = Uuid, Path)), responses((status = 204)))]
pub async fn revoke_device(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    Path(id): Path<Uuid>,
) -> ApiResult<NoContent> {
    session::revoke_device(&state, auth.user_id(), id).await?;
    users::security_event(
        &state,
        auth.user_id(),
        "device_revoked",
        Some(auth.device_id()),
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        Some(serde_json::json!({ "revoked_device_id": id })),
    )
    .await
    .map(NoContent::from)
}

// ───────────────────────────── security events ─────────────────────────────

#[derive(Deserialize)]
pub struct SecurityEventsQuery {
    /// Only events strictly older than this instant (pagination cursor).
    pub before: Option<DateTime<Utc>>,
    /// Page size, 1–200 (default 50).
    pub limit: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/account/security-events", tag = "account", responses((status = 200, body = SecurityEventList)))]
pub async fn security_events(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<SecurityEventsQuery>,
) -> ApiResult<Json<SecurityEventList>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let rows: Vec<(
        Uuid,
        String,
        Option<Uuid>,
        Option<String>,
        Option<String>,
        Option<serde_json::Value>,
        DateTime<Utc>,
    )> = sqlx::query_as(
        "SELECT id, kind, device_id, ip, user_agent, details, created_at FROM security_events
             WHERE user_id = $1 AND ($2::timestamptz IS NULL OR created_at < $2)
             ORDER BY created_at DESC LIMIT $3",
    )
    .bind(auth.user_id())
    .bind(q.before)
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await?;
    let has_more = rows.len() as i64 > limit;
    let events: Vec<SecurityEvent> = rows
        .into_iter()
        .take(limit as usize)
        .map(
            |(id, kind, device_id, ip, user_agent, details, created_at)| SecurityEvent {
                id,
                kind,
                device_id,
                ip,
                user_agent,
                details,
                created_at,
            },
        )
        .collect();
    Ok(Json(SecurityEventList { events, has_more }))
}

// ───────────────────────────── recovery key rotation ─────────────────────────────

#[utoipa::path(post, path = "/api/v1/account/recovery/rotate", tag = "account",
    request_body = RecoveryRotate, responses((status = 204)))]
pub async fn rotate_recovery(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    Body(req): Body<RecoveryRotate>,
) -> ApiResult<NoContent> {
    unb64_array::<32>(&req.recovery_verifier)
        .map_err(|_| Error::bad_request("recovery_verifier must be 32 bytes"))?;
    unb64(&req.recovery_wrapped_private_key)
        .map_err(|_| Error::bad_request("recovery_wrapped_private_key is not valid base64"))?;
    let u = users::by_id(&state.db, auth.user_id()).await?;
    sqlx::query("UPDATE users SET recovery_wrapped_private_key = $2, recovery_verifier_hash = $3, updated_at = now() WHERE id = $1")
        .bind(u.id)
        .bind(&req.recovery_wrapped_private_key)
        .bind(hash_token(&req.recovery_verifier))
        .execute(&state.db)
        .await?;
    users::security_event(
        &state,
        u.id,
        "recovery_key_rotated",
        Some(auth.device_id()),
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        None,
    )
    .await?;
    users::notify(
        &state,
        &u.email,
        "recovery phrase replaced",
        "A new recovery phrase was generated for your account. The previous phrase no longer works.",
    )
    .await;
    Ok(NoContent)
}

// ───────────────────────────── deletion ─────────────────────────────

#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    /// Confirmation code sent by email (required when email is configured).
    #[serde(default)]
    pub code: Option<String>,
}

/// `DELETE /account` — first call (no code) sends a confirmation code when email
/// is configured; the second call with the code deletes the account. Teams owned
/// by the user must be deleted or transferred first.
#[utoipa::path(delete, path = "/api/v1/account", tag = "account",
    responses((status = 202, description = "Confirmation code sent"), (status = 204, description = "Deleted")))]
pub async fn delete_account(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    body: Option<Body<DeleteAccountRequest>>,
) -> ApiResult<axum::http::StatusCode> {
    let u = users::by_id(&state.db, auth.user_id()).await?;
    let code = body.and_then(|Body(b)| b.code);
    if let Some(mailer) = &state.mailer
        && u.email_verified
    {
        match code {
            None => {
                ratelimit::check(&state, ratelimit::EMAIL, &u.email).await?;
                let code = codes::issue_for(
                    &state,
                    P_DELETE,
                    &u.id.to_string(),
                    &u.id,
                    Duration::from_secs(900),
                )
                .await?;
                let email = mailer.code_email("account deletion", &code, 15);
                mailer
                    .send(&u.email, &email)
                    .await
                    .map_err(|e| Error::Internal(e.context("sending email")))?;
                return Ok(axum::http::StatusCode::ACCEPTED);
            }
            Some(c) => {
                codes::verify::<Uuid>(&state, P_DELETE, &u.id.to_string(), &c).await?;
            }
        }
    }
    let (owned,): (i64,) = sqlx::query_as("SELECT count(*) FROM teams WHERE owner_id = $1")
        .bind(u.id)
        .fetch_one(&state.db)
        .await?;
    if owned > 0 {
        return Err(Error::conflict(
            "Transfer or delete the teams you own first",
        ));
    }
    users::delete(&state, u.id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ───────────────────────────── connected SSO accounts ─────────────────────────

#[utoipa::path(get, path = "/api/v1/account/sso", tag = "account", responses((status = 200, body = Vec<SsoIdentity>)))]
pub async fn sso_identities(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<Vec<SsoIdentity>>> {
    Ok(Json(crate::sso::identities(&state, auth.user_id()).await?))
}

#[derive(Deserialize)]
pub struct SsoLinkQuery {
    pub redirect: Option<String>,
}

/// Starts an identity-provider round-trip that attaches the identity to the
/// signed-in account instead of signing in; the flow ends with `SsoResult::Linked`.
#[utoipa::path(get, path = "/api/v1/account/sso/{provider}/link/start", tag = "account",
    params(("provider" = String, Path)), responses((status = 200, body = SsoStartResponse)))]
pub async fn sso_link_start(
    State(state): State<AppState>,
    auth: Auth,
    Path(provider): Path<String>,
    Query(q): Query<SsoLinkQuery>,
) -> ApiResult<Json<SsoStartResponse>> {
    let (authorization_url, flow_id) =
        crate::sso::start(&state, &provider, q.redirect, Some(auth.user_id())).await?;
    Ok(Json(SsoStartResponse {
        authorization_url,
        flow_id,
    }))
}

#[utoipa::path(delete, path = "/api/v1/account/sso/{provider}", tag = "account",
    params(("provider" = String, Path)), responses((status = 204)))]
pub async fn sso_unlink(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    Path(provider): Path<String>,
) -> ApiResult<NoContent> {
    if !crate::sso::unlink(&state, auth.user_id(), &provider).await? {
        return Err(Error::not_found("linked account"));
    }
    users::security_event(
        &state,
        auth.user_id(),
        "sso_unlinked",
        Some(auth.device_id()),
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        Some(serde_json::json!({ "provider": provider })),
    )
    .await?;
    Ok(NoContent::from(()))
}
