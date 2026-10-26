//! Bearer sessions: issue, validate (Redis-cached), touch, revoke.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use termoso_proto::auth::{DeviceInfo, Platform};
use uuid::Uuid;

use crate::error::{ApiResult, Error};
use crate::events;
use crate::state::AppState;
use crate::util::{hash_token, random_token};

const CACHE_TTL: Duration = Duration::from_secs(60);

/// How long a step-up (`reauth_at`) authorizes sensitive operations.
pub const STEP_UP_TTL: chrono::Duration = chrono::Duration::minutes(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub is_admin: bool,
    pub disabled: bool,
    pub email_verified: bool,
    pub last_used_at: DateTime<Utc>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub reauth_at: Option<DateTime<Utc>>,
    /// Set for API-bridge sessions, which are confined to sync.
    #[serde(default)]
    pub bridge_id: Option<Uuid>,
}

impl SessionInfo {
    pub fn step_up_fresh(&self) -> bool {
        self.reauth_at.is_some_and(|t| Utc::now() - t < STEP_UP_TTL)
    }
}

/// Bridge sessions do not slide: they live until revoked from the cabinet.
const BRIDGE_TTL: chrono::Duration = chrono::Duration::days(365 * 20);

fn cache_key(token_hash: &str) -> String {
    format!("sess:{token_hash}")
}

/// Posture as stored in `devices.posture`; `None` leaves the stored value alone.
pub(crate) fn posture_json(info: &DeviceInfo) -> Option<serde_json::Value> {
    info.posture
        .as_ref()
        .and_then(|p| serde_json::to_value(p).ok())
}

pub fn platform_str(p: Platform) -> &'static str {
    match p {
        Platform::Windows => "windows",
        Platform::Linux => "linux",
        Platform::Macos => "macos",
        Platform::Android => "android",
        Platform::Ios => "ios",
        Platform::Web => "web",
        Platform::Cli => "cli",
    }
}

pub fn parse_platform(s: &str) -> Platform {
    match s {
        "windows" => Platform::Windows,
        "linux" => Platform::Linux,
        "macos" => Platform::Macos,
        "android" => Platform::Android,
        "ios" => Platform::Ios,
        "cli" => Platform::Cli,
        _ => Platform::Web,
    }
}

/// Find an existing device for this user by client id, or create a new one.
/// Returns `(device_id, is_new)`.
pub async fn upsert_device(
    db: &PgPool,
    user_id: Uuid,
    info: &DeviceInfo,
    ip: Option<&str>,
) -> ApiResult<(Uuid, bool)> {
    // A client id owned by another user is not reused: each account gets its own device row.
    let mut id = Uuid::new_v4();
    if let Some(cid) = info.client_device_id {
        let owner: Option<(Uuid,)> = sqlx::query_as("SELECT user_id FROM devices WHERE id = $1")
            .bind(cid)
            .fetch_optional(db)
            .await?;
        match owner {
            Some((owner,)) if owner == user_id => {
                sqlx::query(
                    "UPDATE devices SET name = $2, platform = $3, app_version = $4, last_seen_at = now(), last_ip = $5,
                            posture = COALESCE($6, posture),
                            posture_at = CASE WHEN $6::jsonb IS NULL THEN posture_at ELSE now() END
                     WHERE id = $1",
                )
                .bind(cid)
                .bind(&info.name)
                .bind(platform_str(info.platform))
                .bind(&info.app_version)
                .bind(ip)
                .bind(posture_json(info))
                .execute(db)
                .await?;
                return Ok((cid, false));
            }
            Some(_) => {}
            None => id = cid,
        }
    }
    sqlx::query(
        "INSERT INTO devices (id, user_id, name, platform, app_version, last_ip, posture, posture_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $7::jsonb IS NULL THEN NULL ELSE now() END)",
    )
    .bind(id)
    .bind(user_id)
    .bind(&info.name)
    .bind(platform_str(info.platform))
    .bind(&info.app_version)
    .bind(ip)
    .bind(posture_json(info))
    .execute(db)
    .await?;
    Ok((id, true))
}

/// Create a session for an (already approved) device. Returns the bearer token.
/// Every session is issued right after a full proof (password + MFA, recovery
/// phrase, or a confirmed reset), so it starts inside the step-up window.
pub async fn issue(
    state: &AppState,
    user_id: Uuid,
    device_id: Uuid,
) -> ApiResult<(String, DateTime<Utc>)> {
    let settings = state.settings().await?;
    let token = random_token();
    let expires_at = Utc::now()
        + crate::policy::session_ttl(&state.db, user_id, settings.session_ttl_days).await?;
    // A device holds one live session: signing in again replaces the previous
    // token instead of leaving it valid until it expires.
    sqlx::query(
        "UPDATE sessions SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL",
    )
    .bind(device_id)
    .execute(&state.db)
    .await?;
    sqlx::query(
        "INSERT INTO sessions (id, user_id, device_id, token_hash, expires_at, reauth_at)
         VALUES ($1, $2, $3, $4, $5, now())",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(device_id)
    .bind(hash_token(&token))
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    sqlx::query("UPDATE devices SET approved_at = COALESCE(approved_at, now()), last_seen_at = now() WHERE id = $1")
        .bind(device_id)
        .execute(&state.db)
        .await?;
    Ok((token, expires_at))
}

/// Create the session behind an API bridge. Never inside the step-up window
/// (a bridge cannot touch account settings anyway).
pub async fn issue_bridge(
    state: &AppState,
    user_id: Uuid,
    device_id: Uuid,
    bridge_id: Uuid,
) -> ApiResult<String> {
    let token = random_token();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, device_id, token_hash, expires_at, bridge_id)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(device_id)
    .bind(hash_token(&token))
    .bind(Utc::now() + BRIDGE_TTL)
    .bind(bridge_id)
    .execute(&state.db)
    .await?;
    sqlx::query("UPDATE devices SET approved_at = now(), last_seen_at = now() WHERE id = $1")
        .bind(device_id)
        .execute(&state.db)
        .await?;
    Ok(token)
}

pub async fn validate(state: &AppState, token: &str) -> ApiResult<SessionInfo> {
    let h = hash_token(token);
    let key = cache_key(&h);
    if let Some(info) = state.cache.get_json::<SessionInfo>(&key).await?
        && info.expires_at > Utc::now()
    {
        return Ok(info);
    }
    type Row = (
        Uuid,
        Uuid,
        Uuid,
        DateTime<Utc>,
        bool,
        bool,
        bool,
        DateTime<Utc>,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
        Option<Uuid>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT s.id, s.user_id, s.device_id, s.expires_at, u.is_admin, u.disabled, u.email_verified,
                s.last_used_at, s.created_at, s.reauth_at, s.bridge_id
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now()",
    )
    .bind(&h)
    .fetch_optional(&state.db)
    .await?;
    let Some((
        session_id,
        user_id,
        device_id,
        expires_at,
        is_admin,
        disabled,
        email_verified,
        last_used_at,
        created_at,
        reauth_at,
        bridge_id,
    )) = row
    else {
        return Err(Error::unauthorized());
    };
    let info = SessionInfo {
        session_id,
        user_id,
        device_id,
        expires_at,
        is_admin,
        disabled,
        email_verified,
        last_used_at,
        created_at: Some(created_at),
        reauth_at,
        bridge_id,
    };
    state.cache.set_json(&key, &info, CACHE_TTL).await?;
    Ok(info)
}

/// Sliding expiry + last-seen bookkeeping, at most every 5 minutes per session.
/// A bridge's first request is recorded immediately so its cabinet entry
/// switches from "never used" as soon as the container comes up.
pub async fn touch(state: &AppState, info: &SessionInfo, ip: Option<&str>) -> ApiResult<()> {
    let first_bridge_use =
        info.bridge_id.is_some() && info.created_at.is_some_and(|c| info.last_used_at <= c);
    if !first_bridge_use && Utc::now() - info.last_used_at < chrono::Duration::minutes(5) {
        return Ok(());
    }
    let new_exp = if info.bridge_id.is_some() {
        info.expires_at
    } else {
        let settings = state.settings().await?;
        Utc::now()
            + crate::policy::session_ttl(&state.db, info.user_id, settings.session_ttl_days).await?
    };
    sqlx::query("UPDATE sessions SET last_used_at = now(), expires_at = $2 WHERE id = $1")
        .bind(info.session_id)
        .bind(new_exp)
        .execute(&state.db)
        .await?;
    sqlx::query(
        "UPDATE devices SET last_seen_at = now(), last_ip = COALESCE($2, last_ip) WHERE id = $1",
    )
    .bind(info.device_id)
    .bind(ip)
    .execute(&state.db)
    .await?;
    sqlx::query("UPDATE users SET last_seen_at = now() WHERE id = $1")
        .bind(info.user_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// Record a completed step-up on the session; returns when it expires.
pub async fn mark_step_up(state: &AppState, session_id: Uuid) -> ApiResult<DateTime<Utc>> {
    let row: Option<(String, DateTime<Utc>)> = sqlx::query_as(
        "UPDATE sessions SET reauth_at = now() WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()
         RETURNING token_hash, reauth_at",
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((h, at)) = row else {
        return Err(Error::unauthorized());
    };
    state.cache.del(&cache_key(&h)).await?;
    Ok(at + STEP_UP_TTL)
}

pub async fn revoke_session(state: &AppState, session_id: Uuid) -> ApiResult<()> {
    let row: Option<(String, Uuid, Uuid)> = sqlx::query_as(
        "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL RETURNING token_hash, user_id, device_id",
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await?;
    if let Some((h, user_id, device_id)) = row {
        state.cache.del(&cache_key(&h)).await?;
        let (live,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM sessions WHERE device_id = $1 AND revoked_at IS NULL AND expires_at > now()",
        )
        .bind(device_id)
        .fetch_one(&state.db)
        .await?;
        if live == 0 {
            crate::routes::sshid::forget_device(state, device_id).await?;
            crate::routes::ca::forget_device(state, device_id).await?;
        }
        events::publish(
            state,
            events::Event::SessionRevoked {
                user_id,
                session_id,
            },
        )
        .await?;
    }
    Ok(())
}

/// Revoke all sessions of a device.
pub async fn revoke_device(state: &AppState, user_id: Uuid, device_id: Uuid) -> ApiResult<()> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "UPDATE sessions SET revoked_at = now() WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL RETURNING id, token_hash",
    )
    .bind(device_id)
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    crate::routes::sshid::forget_device(state, device_id).await?;
    crate::routes::ca::forget_device(state, device_id).await?;
    for (session_id, h) in rows {
        state.cache.del(&cache_key(&h)).await?;
        events::publish(
            state,
            events::Event::SessionRevoked {
                user_id,
                session_id,
            },
        )
        .await?;
    }
    Ok(())
}

/// Revoke every interactive session of the user except `keep`. API bridges
/// are separate credentials with their own revocation in the cabinet and
/// stay untouched.
pub async fn revoke_all(state: &AppState, user_id: Uuid, keep: Option<Uuid>) -> ApiResult<()> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "UPDATE sessions SET revoked_at = now()
         WHERE user_id = $1 AND revoked_at IS NULL AND bridge_id IS NULL
           AND ($2::uuid IS NULL OR id <> $2)
         RETURNING id, token_hash",
    )
    .bind(user_id)
    .bind(keep)
    .fetch_all(&state.db)
    .await?;
    for (session_id, h) in rows {
        state.cache.del(&cache_key(&h)).await?;
        events::publish(
            state,
            events::Event::SessionRevoked {
                user_id,
                session_id,
            },
        )
        .await?;
    }
    Ok(())
}

pub async fn is_revoked(state: &AppState, session_id: Uuid) -> ApiResult<bool> {
    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT revoked_at IS NOT NULL OR expires_at <= now() FROM sessions WHERE id = $1",
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(|(r,)| r).unwrap_or(true))
}

/// Invalidate the cached copy (e.g. after the user was disabled / promoted).
pub async fn invalidate_user_cache(state: &AppState, user_id: Uuid) -> ApiResult<()> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT token_hash FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()")
            .bind(user_id)
            .fetch_all(&state.db)
            .await?;
    for (h,) in rows {
        state.cache.del(&cache_key(&h)).await?;
    }
    Ok(())
}
