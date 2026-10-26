//! Break-glass: a sealed one-time secret that lets one designated member
//! become a team admin for a bounded time when the owner is unreachable.
//! Loud by design — every owner and admin is e-mailed, the use is audited
//! with its reason (so webhooks / SIEM see it), and the role reverts on its own.

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use termoso_proto::team::{BreakGlass, ConfigureBreakGlassRequest, TeamRole, UseBreakGlassRequest};
use uuid::Uuid;

use crate::audit;
use crate::error::{ApiResult, Error, NoContent};
use crate::extract::{Auth, StepUp};
use crate::state::AppState;
use crate::util::{constant_time_eq, hash_token, random_token};

const MAX_ATTEMPTS: i32 = 5;
const LOCK_MINUTES: i32 = 15;
const REASON_MAX: usize = 500;
const EXPIRY_EVERY: std::time::Duration = std::time::Duration::from_secs(300);

type Row = (
    Uuid,
    Option<String>,
    i32,
    Option<Uuid>,
    DateTime<Utc>,
    i32,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

async fn load(state: &AppState, team_id: Uuid) -> ApiResult<Option<BreakGlass>> {
    let row: Option<Row> = sqlx::query_as(
        "SELECT b.user_id, u.email, b.duration_hours, b.created_by, b.created_at, b.attempts,
                b.used_at, b.expires_at, b.ended_at
         FROM team_break_glass b LEFT JOIN users u ON u.id = b.user_id WHERE b.team_id = $1",
    )
    .bind(team_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(
        |(
            user_id,
            email,
            duration_hours,
            created_by,
            created_at,
            attempts,
            used_at,
            expires_at,
            ended_at,
        )| {
            let status = match (used_at, ended_at) {
                (None, _) => "ready",
                (Some(_), None) => "active",
                (Some(_), Some(_)) => "used",
            };
            BreakGlass {
                user_id,
                email,
                duration_hours,
                created_by,
                created_at,
                status: status.into(),
                used_at,
                expires_at,
                attempts,
                secret: None,
            }
        },
    ))
}

async fn require_owner(state: &AppState, team_id: Uuid, user_id: Uuid) -> ApiResult<()> {
    let role = super::teams::my_role(&state.db, team_id, user_id)
        .await
        .map_err(|_| Error::not_found("Team"))?;
    if role != TeamRole::Owner {
        return Err(Error::forbidden("Only the owner can set up break-glass"));
    }
    Ok(())
}

/// `GET /teams/{id}/break-glass` — status, no secret (`members.view`).
#[utoipa::path(get, path = "/api/v1/teams/{id}/break-glass", tag = "teams",
    params(("id" = Uuid, Path)), responses((status = 200, body = BreakGlass), (status = 404)))]
pub async fn get(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
) -> ApiResult<Json<BreakGlass>> {
    crate::authz::require(&state, team_id, auth.user_id(), "members.view").await?;
    load(&state, team_id)
        .await?
        .map(Json)
        .ok_or_else(|| Error::not_found("Break-glass"))
}

/// `PUT /teams/{id}/break-glass` — (re)issue the secret (owner, step-up).
/// Replaces any previous set-up; an active emergency role is ended first.
#[utoipa::path(put, path = "/api/v1/teams/{id}/break-glass", tag = "teams",
    params(("id" = Uuid, Path)), request_body = ConfigureBreakGlassRequest,
    responses((status = 200, body = BreakGlass)))]
pub async fn configure(
    State(state): State<AppState>,
    auth: StepUp,
    Path(team_id): Path<Uuid>,
    Json(req): Json<ConfigureBreakGlassRequest>,
) -> ApiResult<Json<BreakGlass>> {
    require_owner(&state, team_id, auth.user_id()).await?;
    if !(1..=72).contains(&req.duration_hours) {
        return Err(Error::bad_request("duration_hours must be 1..=72"));
    }
    if req.user_id == auth.user_id() {
        return Err(Error::bad_request("Designate someone other than the owner"));
    }
    super::teams::my_role(&state.db, team_id, req.user_id)
        .await
        .map_err(|_| Error::bad_request("The designated user is not a member of this team"))?;
    if let Some(active) = active(&state, team_id).await? {
        restore(
            &state,
            team_id,
            &active,
            "break_glass.ended",
            Some(auth.user_id()),
        )
        .await?;
    }
    let secret = random_token();
    sqlx::query(
        "INSERT INTO team_break_glass (team_id, user_id, secret_hash, duration_hours, created_by)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (team_id) DO UPDATE SET user_id = EXCLUDED.user_id, secret_hash = EXCLUDED.secret_hash,
             duration_hours = EXCLUDED.duration_hours, created_by = EXCLUDED.created_by, created_at = now(),
             attempts = 0, locked_until = NULL, used_at = NULL, expires_at = NULL, ended_at = NULL,
             prev_role = NULL, prev_role_id = NULL, prev_role_source = NULL",
    )
    .bind(team_id)
    .bind(req.user_id)
    .bind(hash_token(&secret))
    .bind(req.duration_hours)
    .bind(auth.user_id())
    .execute(&state.db)
    .await?;
    audit::record(
        &state.db,
        audit::Entry::new(team_id, &auth, "break_glass.configured")
            .user(req.user_id)
            .details(serde_json::json!({ "duration_hours": req.duration_hours })),
    )
    .await;
    let mut bg = load(&state, team_id)
        .await?
        .ok_or_else(|| Error::not_found("Break-glass"))?;
    bg.secret = Some(secret);
    Ok(Json(bg))
}

/// `DELETE /teams/{id}/break-glass` (owner, step-up). Ends an active emergency role.
#[utoipa::path(delete, path = "/api/v1/teams/{id}/break-glass", tag = "teams",
    params(("id" = Uuid, Path)), responses((status = 204)))]
pub async fn remove(
    State(state): State<AppState>,
    auth: StepUp,
    Path(team_id): Path<Uuid>,
) -> ApiResult<NoContent> {
    require_owner(&state, team_id, auth.user_id()).await?;
    if let Some(active) = active(&state, team_id).await? {
        restore(
            &state,
            team_id,
            &active,
            "break_glass.ended",
            Some(auth.user_id()),
        )
        .await?;
    }
    let n = sqlx::query("DELETE FROM team_break_glass WHERE team_id = $1")
        .bind(team_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(Error::not_found("Break-glass"));
    }
    audit::record(
        &state.db,
        audit::Entry::new(team_id, &auth, "break_glass.removed"),
    )
    .await;
    Ok(NoContent)
}

/// `POST /teams/{id}/break-glass/use` — the designated member redeems the secret.
#[utoipa::path(post, path = "/api/v1/teams/{id}/break-glass/use", tag = "teams",
    params(("id" = Uuid, Path)), request_body = UseBreakGlassRequest,
    responses((status = 200, body = BreakGlass), (status = 403), (status = 409), (status = 429)))]
pub async fn use_secret(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
    Json(req): Json<UseBreakGlassRequest>,
) -> ApiResult<Json<BreakGlass>> {
    let reason = req.reason.trim();
    if reason.is_empty() || reason.chars().count() > REASON_MAX {
        return Err(Error::bad_request("reason is required (≤ 500 characters)"));
    }
    let row: Option<(
        Uuid,
        String,
        i32,
        i32,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        "SELECT user_id, secret_hash, duration_hours, attempts, locked_until, used_at
             FROM team_break_glass WHERE team_id = $1",
    )
    .bind(team_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((user_id, secret_hash, hours, attempts, locked_until, used_at)) = row else {
        return Err(Error::not_found("Break-glass"));
    };
    if user_id != auth.user_id() {
        audit::record(
            &state.db,
            audit::Entry::new(team_id, &auth, "break_glass.denied")
                .details(serde_json::json!({ "why": "not_designated" })),
        )
        .await;
        return Err(Error::forbidden(
            "You are not the designated break-glass user",
        ));
    }
    if locked_until.is_some_and(|t| t > Utc::now()) {
        return Err(Error::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "break_glass_locked",
            format!("Too many wrong secrets; try again in {LOCK_MINUTES} minutes"),
        ));
    }
    if used_at.is_some() {
        return Err(Error::conflict(
            "This secret has already been used; the owner must issue a new one",
        ));
    }
    if !constant_time_eq(&hash_token(req.secret.trim()), &secret_hash) {
        let attempts = attempts + 1;
        sqlx::query(
            "UPDATE team_break_glass SET attempts = $2,
                locked_until = CASE WHEN $2 >= $3 THEN now() + make_interval(mins => $4) ELSE locked_until END
             WHERE team_id = $1",
        )
        .bind(team_id)
        .bind(attempts)
        .bind(MAX_ATTEMPTS)
        .bind(LOCK_MINUTES)
        .execute(&state.db)
        .await?;
        audit::record(
            &state.db,
            audit::Entry::new(team_id, &auth, "break_glass.denied")
                .details(serde_json::json!({ "why": "wrong_secret", "attempts": attempts })),
        )
        .await;
        return Err(Error::forbidden("Wrong secret"));
    }
    // Still a member, not the owner.
    let role = super::teams::my_role(&state.db, team_id, user_id)
        .await
        .map_err(|_| Error::forbidden("You are no longer a member of this team"))?;
    if role == TeamRole::Owner {
        return Err(Error::conflict("You already own this team"));
    }
    let admin_role = crate::authz::builtin_role_id(&state.db, team_id, "admin").await?;
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE team_break_glass b SET used_at = now(), expires_at = now() + make_interval(hours => $2),
                attempts = 0, locked_until = NULL,
                prev_role = m.role, prev_role_id = m.role_id, prev_role_source = m.role_source
         FROM team_members m WHERE b.team_id = $1 AND m.team_id = $1 AND m.user_id = b.user_id",
    )
    .bind(team_id)
    .bind(hours)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE team_members SET role = 'admin', role_id = $3, role_source = 'break_glass'
         WHERE team_id = $1 AND user_id = $2",
    )
    .bind(team_id)
    .bind(user_id)
    .bind(admin_role)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    audit::record(
        &state.db,
        audit::Entry::new(team_id, &auth, "break_glass.used")
            .user(user_id)
            .details(serde_json::json!({ "reason": reason, "duration_hours": hours })),
    )
    .await;
    let team = super::teams::team_name(&state.db, team_id)
        .await
        .unwrap_or_default();
    let who = crate::users::by_id(&state.db, user_id)
        .await
        .map(|u| u.email)
        .unwrap_or_else(|_| user_id.to_string());
    notify_team(
        &state,
        team_id,
        &format!("Break-glass used in {team}"),
        &format!(
            "{who} redeemed the break-glass secret of the team \"{team}\" and is an admin for the next {hours} hours.\n\nReason: {reason}\n\nIf this is unexpected, end it now: Team → Break-glass → End."
        ),
    )
    .await;
    load(&state, team_id)
        .await?
        .map(Json)
        .ok_or_else(|| Error::not_found("Break-glass"))
}

/// `POST /teams/{id}/break-glass/end` — owner or the member ends the emergency role early.
#[utoipa::path(post, path = "/api/v1/teams/{id}/break-glass/end", tag = "teams",
    params(("id" = Uuid, Path)), responses((status = 200, body = BreakGlass), (status = 409)))]
pub async fn end(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
) -> ApiResult<Json<BreakGlass>> {
    let Some(active) = active(&state, team_id).await? else {
        return Err(Error::conflict("No emergency role is active"));
    };
    let role = super::teams::my_role(&state.db, team_id, auth.user_id())
        .await
        .map_err(|_| Error::not_found("Team"))?;
    if role != TeamRole::Owner && auth.user_id() != active.user_id {
        return Err(Error::forbidden(
            "Only the owner or the emergency admin can end it",
        ));
    }
    restore(
        &state,
        team_id,
        &active,
        "break_glass.ended",
        Some(auth.user_id()),
    )
    .await?;
    load(&state, team_id)
        .await?
        .map(Json)
        .ok_or_else(|| Error::not_found("Break-glass"))
}

struct Active {
    user_id: Uuid,
    prev_role: String,
    prev_role_id: Option<Uuid>,
    prev_role_source: String,
}

async fn active(state: &AppState, team_id: Uuid) -> ApiResult<Option<Active>> {
    let row: Option<(Uuid, Option<String>, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT user_id, prev_role, prev_role_id, prev_role_source FROM team_break_glass
         WHERE team_id = $1 AND used_at IS NOT NULL AND ended_at IS NULL",
    )
    .bind(team_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(|(user_id, r, rid, src)| Active {
        user_id,
        prev_role: r.unwrap_or_else(|| "member".into()),
        prev_role_id: rid,
        prev_role_source: src.unwrap_or_else(|| "manual".into()),
    }))
}

/// Put the member back where they were (if they are still a member and still
/// hold the emergency role) and close the record.
async fn restore(
    state: &AppState,
    team_id: Uuid,
    a: &Active,
    action: &'static str,
    by: Option<Uuid>,
) -> ApiResult<()> {
    let prev_role_id = match a.prev_role_id {
        Some(id) => id,
        None => crate::authz::builtin_role_id(&state.db, team_id, &a.prev_role).await?,
    };
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE team_members SET role = $3, role_id = $4, role_source = $5
         WHERE team_id = $1 AND user_id = $2 AND role_source = 'break_glass'",
    )
    .bind(team_id)
    .bind(a.user_id)
    .bind(&a.prev_role)
    .bind(prev_role_id)
    .bind(&a.prev_role_source)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE team_break_glass SET ended_at = now() WHERE team_id = $1 AND ended_at IS NULL",
    )
    .bind(team_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let entry = match by {
        Some(u) => audit::Entry::by(team_id, u, None, action),
        None => audit::Entry::system(team_id, action),
    };
    audit::record(
        &state.db,
        entry
            .user(a.user_id)
            .details(serde_json::json!({ "restored_role": a.prev_role })),
    )
    .await;
    Ok(())
}

async fn notify_team(state: &AppState, team_id: Uuid, subject: &str, text: &str) {
    let to: Vec<(String,)> = sqlx::query_as(
        "SELECT u.email FROM team_members m JOIN users u ON u.id = m.user_id
         WHERE m.team_id = $1 AND m.role IN ('owner', 'admin') LIMIT 50",
    )
    .bind(team_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    for (email,) in to {
        crate::users::notify(state, &email, subject, text).await;
    }
}

/// Every 5 minutes: revert emergency roles whose time is up.
pub async fn run_expiry(state: AppState) {
    crate::jobs::exclusive(state, "break-glass-expiry", EXPIRY_EVERY, |s| async move {
        expire_pass(&s).await
    })
    .await
}

pub async fn expire_pass(state: &AppState) -> anyhow::Result<u64> {
    let due: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT team_id FROM team_break_glass
         WHERE used_at IS NOT NULL AND ended_at IS NULL AND expires_at < now()",
    )
    .fetch_all(&state.db)
    .await?;
    let mut n = 0;
    for (team_id,) in due {
        if let Some(a) = active(state, team_id)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
        {
            restore(state, team_id, &a, "break_glass.expired", None)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            n += 1;
        }
    }
    Ok(n)
}
