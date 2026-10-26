//! Operator API. Admins see accounts and metadata, never vault contents.

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::AssertSqlSafe;
use termoso_proto::admin::*;
use uuid::Uuid;

use crate::audit;
use crate::error::{ApiResult, Error, NoContent};
use crate::events::{self, Event};
use crate::extract::{Admin, Json as Body};
use crate::session;
use crate::state::AppState;
use crate::users;

#[utoipa::path(get, path = "/api/v1/admin/stats", tag = "admin", responses((status = 200, body = AdminStats)))]
pub async fn stats(State(state): State<AppState>, _admin: Admin) -> ApiResult<Json<AdminStats>> {
    let (users, active_users_30d, teams, vaults, entities, active_sessions, log_storage_bytes): (i64, i64, i64, i64, i64, i64, i64) =
        sqlx::query_as(
            "SELECT
                (SELECT count(*) FROM users),
                (SELECT count(*) FROM users WHERE last_seen_at > now() - interval '30 days'),
                (SELECT count(*) FROM teams),
                (SELECT count(*) FROM vaults WHERE deleted_at IS NULL),
                (SELECT count(*) FROM entities WHERE deleted = false),
                (SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > now()),
                (SELECT COALESCE(sum(size_bytes), 0)::bigint FROM session_logs WHERE deleted = false)",
        )
        .fetch_one(&state.db)
        .await?;
    Ok(Json(AdminStats {
        users,
        active_users_30d,
        teams,
        vaults,
        entities,
        active_sessions,
        log_storage_bytes,
    }))
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct ListQuery {
    /// Only members of this team.
    pub team: Option<Uuid>,
    /// `created` (default), `last_seen`, `email` or `devices`.
    pub sort: Option<String>,
    /// Substring match on email / display name.
    pub q: Option<String>,
    #[serde(default)]
    pub offset: i64,
    pub limit: Option<i64>,
}

type UserRow = (
    Uuid,
    String,
    bool,
    Option<String>,
    Option<String>,
    bool,
    bool,
    bool,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    i64,
    serde_json::Value,
    String,
);

fn to_admin_user(r: UserRow, owner: Option<Uuid>) -> AdminUser {
    let (
        id,
        email,
        email_verified,
        display_name,
        avatar,
        is_admin,
        disabled,
        mfa_enabled,
        created_at,
        last_seen_at,
        devices,
        teams,
        source,
    ) = r;
    AdminUser {
        id,
        email,
        email_verified,
        display_name,
        avatar,
        is_admin,
        is_owner: owner == Some(id),
        disabled,
        mfa_enabled,
        created_at,
        last_seen_at,
        devices,
        teams: serde_json::from_value(teams).unwrap_or_default(),
        source,
    }
}

const USER_SELECT: &str = "SELECT u.id, u.email, u.email_verified, u.display_name, u.avatar_tag, u.is_admin, u.disabled,
        (u.totp_enabled OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id)),
        u.created_at, u.last_seen_at,
        (SELECT count(*) FROM devices d WHERE d.user_id = u.id
           AND EXISTS (SELECT 1 FROM sessions s WHERE s.device_id = d.id AND s.revoked_at IS NULL AND s.expires_at > now())),
        COALESCE((SELECT json_agg(json_build_object('id', t.id, 'name', t.name, 'role', r.slug) ORDER BY t.name)
                  FROM team_members m JOIN teams t ON t.id = m.team_id JOIN team_roles r ON r.id = m.role_id
                  WHERE m.user_id = u.id), '[]'::json),
        CASE WHEN u.managed_by_team_id IS NOT NULL THEN 'scim'
             WHEN EXISTS (SELECT 1 FROM sso_identities i WHERE i.user_id = u.id) THEN 'sso'
             ELSE 'password' END
     FROM users u";

const USER_FILTER: &str = "($1::text IS NULL OR lower(u.email) LIKE $1 OR lower(COALESCE(u.display_name, '')) LIKE $1)
         AND ($4::uuid IS NULL OR EXISTS (SELECT 1 FROM team_members tm WHERE tm.team_id = $4 AND tm.user_id = u.id))";

fn user_order(sort: Option<&str>) -> &'static str {
    match sort {
        Some("last_seen") => "u.last_seen_at DESC NULLS LAST",
        Some("email") => "lower(u.email)",
        Some("devices") => "11 DESC, u.created_at DESC",
        _ => "u.created_at DESC",
    }
}

#[utoipa::path(get, path = "/api/v1/admin/users", tag = "admin", params(ListQuery), responses((status = 200, body = AdminUserList)))]
pub async fn users(
    State(state): State<AppState>,
    _admin: Admin,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<AdminUserList>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let pattern =
        q.q.as_deref()
            .map(|s| format!("%{}%", s.trim().to_lowercase()));
    let order = user_order(q.sort.as_deref());
    let rows: Vec<UserRow> = sqlx::query_as(AssertSqlSafe(format!(
        "{USER_SELECT} WHERE {USER_FILTER} ORDER BY {order} OFFSET $2 LIMIT $3"
    )))
    .bind(&pattern)
    .bind(q.offset.max(0))
    .bind(limit)
    .bind(q.team)
    .fetch_all(&state.db)
    .await?;
    let (total,): (i64,) = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT count(*) FROM users u WHERE {USER_FILTER}"
    )))
    .bind(&pattern)
    .bind(0i64)
    .bind(0i64)
    .bind(q.team)
    .fetch_one(&state.db)
    .await?;
    let owner = state.owner_user_id().await?;
    Ok(Json(AdminUserList {
        users: rows.into_iter().map(|r| to_admin_user(r, owner)).collect(),
        total,
    }))
}

#[utoipa::path(get, path = "/api/v1/admin/users/{id}", tag = "admin", params(("id" = Uuid, Path)), responses((status = 200, body = AdminUser)))]
pub async fn user(
    State(state): State<AppState>,
    _admin: Admin,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<AdminUser>> {
    let row: Option<UserRow> =
        sqlx::query_as(AssertSqlSafe(format!("{USER_SELECT} WHERE u.id = $1")))
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let owner = state.owner_user_id().await?;
    row.map(|r| to_admin_user(r, owner))
        .map(Json)
        .ok_or_else(|| Error::not_found("User"))
}

#[utoipa::path(patch, path = "/api/v1/admin/users/{id}", tag = "admin", params(("id" = Uuid, Path)),
    request_body = AdminUpdateUserRequest, responses((status = 200, body = AdminUser)))]
pub async fn update_user(
    State(state): State<AppState>,
    Admin(auth): Admin,
    Path(id): Path<Uuid>,
    Body(req): Body<AdminUpdateUserRequest>,
) -> ApiResult<Json<AdminUser>> {
    let target = users::by_id(&state.db, id).await?;
    if id == auth.user_id() && (req.disabled == Some(true) || req.is_admin == Some(false)) {
        return Err(Error::bad_request("You cannot disable or demote yourself"));
    }
    let owner = state.owner_user_id().await?;
    if req.is_admin.is_some() && owner != Some(auth.user_id()) {
        return Err(Error::forbidden(
            "Only the server owner can grant or revoke the admin role",
        ));
    }
    if owner == Some(id) && (req.disabled == Some(true) || req.is_admin == Some(false)) {
        return Err(Error::forbidden(
            "The server owner cannot be disabled or demoted",
        ));
    }
    if req.is_admin == Some(false) && state.cfg.is_bootstrap_admin(&target.email) {
        return Err(Error::bad_request(
            "This admin is configured in TERMOSO_ADMIN_EMAILS",
        ));
    }
    sqlx::query(
        "UPDATE users SET disabled = COALESCE($2, disabled), is_admin = COALESCE($3, is_admin),
                email_verified = COALESCE($4, email_verified), updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(req.disabled)
    .bind(req.is_admin)
    .bind(req.email_verified)
    .execute(&state.db)
    .await?;
    if req.disabled == Some(true) {
        session::revoke_all(&state, id, None).await?;
    }
    session::invalidate_user_cache(&state, id).await?;
    users::security_event(
        &state,
        id,
        "admin_update",
        None,
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        Some(serde_json::json!({ "by": auth.user_id(), "disabled": req.disabled, "is_admin": req.is_admin, "email_verified": req.email_verified })),
    )
    .await?;
    events::publish(&state, Event::AccountUpdated { user_id: id }).await?;
    user(State(state), Admin(auth), Path(id)).await
}

#[utoipa::path(delete, path = "/api/v1/admin/users/{id}", tag = "admin", params(("id" = Uuid, Path)), responses((status = 204)))]
pub async fn delete_user(
    State(state): State<AppState>,
    Admin(auth): Admin,
    Path(id): Path<Uuid>,
) -> ApiResult<NoContent> {
    if id == auth.user_id() {
        return Err(Error::bad_request(
            "Delete your own account through /account",
        ));
    }
    let target = users::by_id(&state.db, id).await?;
    if state.owner_user_id().await? == Some(id) {
        return Err(Error::forbidden("The server owner cannot be deleted"));
    }
    let (owned,): (i64,) = sqlx::query_as("SELECT count(*) FROM teams WHERE owner_id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await?;
    if owned > 0 {
        return Err(Error::conflict(
            "User owns teams; transfer or delete them first",
        ));
    }
    let log_keys: Vec<(String,)> =
        sqlx::query_as("SELECT object_key FROM session_logs WHERE user_id = $1")
            .bind(id)
            .fetch_all(&state.db)
            .await?;
    session::revoke_all(&state, id, None).await?;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    if let Some(storage) = &state.storage {
        for (k,) in log_keys {
            if let Err(e) = storage.delete(&k).await {
                tracing::warn!(error = %e, key = %k, "could not delete log object");
            }
        }
    }
    users::security_event(
        &state,
        auth.user_id(),
        "admin_deleted_user",
        Some(auth.device_id()),
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        Some(serde_json::json!({ "user_id": id, "email": target.email })),
    )
    .await
    .map(NoContent::from)
}

#[utoipa::path(post, path = "/api/v1/admin/users/{id}/revoke-sessions", tag = "admin", params(("id" = Uuid, Path)), responses((status = 204)))]
pub async fn revoke_sessions(
    State(state): State<AppState>,
    Admin(auth): Admin,
    Path(id): Path<Uuid>,
) -> ApiResult<NoContent> {
    users::by_id(&state.db, id).await?;
    session::revoke_all(&state, id, None).await?;
    users::security_event(
        &state,
        id,
        "admin_revoked_sessions",
        None,
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        Some(serde_json::json!({ "by": auth.user_id() })),
    )
    .await
    .map(NoContent::from)
}

/// Reset a user's second factors (support case: lost authenticator *and* backup codes).
#[utoipa::path(post, path = "/api/v1/admin/users/{id}/reset-mfa", tag = "admin", params(("id" = Uuid, Path)), responses((status = 204)))]
pub async fn reset_mfa(
    State(state): State<AppState>,
    Admin(auth): Admin,
    Path(id): Path<Uuid>,
) -> ApiResult<NoContent> {
    users::by_id(&state.db, id).await?;
    if id != auth.user_id() && state.owner_user_id().await? == Some(id) {
        return Err(Error::forbidden(
            "Only the server owner can reset their own MFA",
        ));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET totp_secret = NULL, totp_enabled = false, updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM webauthn_credentials WHERE user_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM backup_codes WHERE user_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    session::revoke_all(&state, id, None).await?;
    users::security_event(
        &state,
        id,
        "admin_reset_mfa",
        None,
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        Some(serde_json::json!({ "by": auth.user_id() })),
    )
    .await?;
    events::publish(&state, Event::AccountUpdated { user_id: id })
        .await
        .map(NoContent::from)
}

// ───────────────────────────── teams ─────────────────────────────

type TeamRow = (
    Uuid,
    String,
    String,
    i64,
    i64,
    DateTime<Utc>,
    Option<String>,
    Option<DateTime<Utc>>,
    i64,
    bool,
    bool,
    i64,
);

const TEAM_SELECT: &str = "SELECT t.id, t.name, u.email,
        (SELECT count(*) FROM team_members m WHERE m.team_id = t.id),
        (SELECT count(*) FROM vaults v WHERE v.team_id = t.id AND v.deleted_at IS NULL),
        t.created_at, t.region, t.deletion_scheduled_at,
        (SELECT COALESCE(sum(l.size_bytes), 0)::bigint FROM session_logs l JOIN vaults v ON v.id = l.vault_id
          WHERE v.team_id = t.id AND l.deleted = false),
        EXISTS (SELECT 1 FROM team_idp i WHERE i.team_id = t.id AND i.enabled),
        EXISTS (SELECT 1 FROM scim_tokens k WHERE k.team_id = t.id AND k.revoked_at IS NULL
                  AND (k.expires_at IS NULL OR k.expires_at > now())),
        (SELECT count(*) FROM team_webhooks w WHERE w.team_id = t.id AND w.enabled)
     FROM teams t JOIN users u ON u.id = t.owner_id";

fn to_admin_team(r: TeamRow, home: Option<Uuid>) -> AdminTeam {
    AdminTeam {
        id: r.0,
        name: r.1,
        owner_email: r.2,
        member_count: r.3,
        vault_count: r.4,
        created_at: r.5,
        region: r.6,
        deletion_scheduled_at: r.7,
        log_bytes: r.8,
        is_home: home == Some(r.0),
        idp: r.9,
        scim: r.10,
        webhooks: r.11,
    }
}

#[utoipa::path(get, path = "/api/v1/admin/teams", tag = "admin", params(ListQuery), responses((status = 200, body = AdminTeamList)))]
pub async fn teams(
    State(state): State<AppState>,
    _admin: Admin,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<AdminTeamList>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let pattern =
        q.q.as_deref()
            .map(|s| format!("%{}%", s.trim().to_lowercase()));
    let order = match q.sort.as_deref() {
        Some("name") => "lower(t.name)",
        Some("members") => "4 DESC, t.created_at DESC",
        Some("storage") => "9 DESC, t.created_at DESC",
        _ => "t.created_at DESC",
    };
    let rows: Vec<TeamRow> = sqlx::query_as(AssertSqlSafe(format!(
        "{TEAM_SELECT} WHERE ($1::text IS NULL OR lower(t.name) LIKE $1 OR lower(u.email) LIKE $1)
         ORDER BY {order} OFFSET $2 LIMIT $3"
    )))
    .bind(&pattern)
    .bind(q.offset.max(0))
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    let (total,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM teams t JOIN users u ON u.id = t.owner_id
         WHERE ($1::text IS NULL OR lower(t.name) LIKE $1 OR lower(u.email) LIKE $1)",
    )
    .bind(&pattern)
    .fetch_one(&state.db)
    .await?;
    let home = state.settings().await?.home_team_id;
    Ok(Json(AdminTeamList {
        teams: rows.into_iter().map(|r| to_admin_team(r, home)).collect(),
        total,
    }))
}

/// One team: summary, members, policies and the last 50 audit events.
#[utoipa::path(get, path = "/api/v1/admin/teams/{id}", tag = "admin", params(("id" = Uuid, Path)), responses((status = 200, body = AdminTeamDetail)))]
pub async fn team_detail(
    State(state): State<AppState>,
    _admin: Admin,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<AdminTeamDetail>> {
    let row: Option<TeamRow> =
        sqlx::query_as(AssertSqlSafe(format!("{TEAM_SELECT} WHERE t.id = $1")))
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let row = row.ok_or_else(|| Error::not_found("Team"))?;
    let home = state.settings().await?.home_team_id;
    let members: Vec<(
        Uuid,
        String,
        String,
        String,
        String,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        "SELECT m.user_id, u.email, m.role, r.slug, m.role_source, m.joined_at, u.last_seen_at
         FROM team_members m JOIN users u ON u.id = m.user_id JOIN team_roles r ON r.id = m.role_id
         WHERE m.team_id = $1 ORDER BY m.role = 'owner' DESC, m.role = 'admin' DESC, u.email",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    let policies = crate::policy::load(&state.db, id).await?;
    let (audit,): (serde_json::Value,) = sqlx::query_as(
        "SELECT COALESCE(json_agg(row_to_json(x)), '[]'::json) FROM (
            SELECT e.id, e.action, e.actor_id, u.email AS actor_email, e.device_id, e.vault_id, e.target_user, e.details, e.created_at
            FROM team_audit_events e LEFT JOIN users u ON u.id = e.actor_id
            WHERE e.team_id = $1 ORDER BY e.created_at DESC LIMIT 50) x",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(AdminTeamDetail {
        team: to_admin_team(row, home),
        members: members
            .into_iter()
            .map(
                |(user_id, email, level, role, role_source, joined_at, last_seen_at)| {
                    AdminTeamMember {
                        user_id,
                        email,
                        level,
                        role,
                        role_source,
                        joined_at,
                        last_seen_at,
                    }
                },
            )
            .collect(),
        policies,
        audit,
    }))
}

/// Add an existing account to a team (default role unless `role` is given).
#[utoipa::path(post, path = "/api/v1/admin/teams/{id}/members", tag = "admin", params(("id" = Uuid, Path)),
    request_body = AdminAddMemberRequest, responses((status = 200, body = AdminTeamDetail)))]
pub async fn add_member(
    State(state): State<AppState>,
    admin: Admin,
    Path(id): Path<Uuid>,
    Body(req): Body<AdminAddMemberRequest>,
) -> ApiResult<Json<AdminTeamDetail>> {
    let role_id: Uuid = match req.role.as_deref().map(str::trim).filter(|r| !r.is_empty()) {
        Some("owner") => {
            return Err(Error::bad_request(
                "Use ownership transfer for the owner role",
            ));
        }
        Some(slug) => {
            let r: Option<(Uuid,)> =
                sqlx::query_as("SELECT id FROM team_roles WHERE team_id = $1 AND slug = $2")
                    .bind(id)
                    .bind(slug)
                    .fetch_optional(&state.db)
                    .await?;
            r.ok_or_else(|| Error::not_found("Role"))?.0
        }
        None => crate::authz::default_role_id(&state.db, id).await?,
    };
    let (exists,): (bool,) = sqlx::query_as("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
        .bind(req.user_id)
        .fetch_one(&state.db)
        .await?;
    if !exists {
        return Err(Error::not_found("User"));
    }
    let n = sqlx::query(
        "INSERT INTO team_members (team_id, user_id, role, role_id, role_source)
         VALUES ($1, $2, CASE WHEN (SELECT slug FROM team_roles WHERE id = $3) = 'admin' THEN 'admin' ELSE 'member' END, $3, 'admin')
         ON CONFLICT (team_id, user_id) DO NOTHING",
    )
    .bind(id)
    .bind(req.user_id)
    .bind(role_id)
    .execute(&state.db)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(Error::conflict("Already a member"));
    }
    audit::record(
        &state.db,
        audit::Entry::system(id, "member.joined")
            .user(req.user_id)
            .details(
                serde_json::json!({ "by_server_admin": admin.0.user_id(), "role_id": role_id }),
            ),
    )
    .await;
    let _ = state.events.send(crate::events::Event::TeamsUpdated {
        user_ids: vec![req.user_id],
    });
    team_detail(State(state), admin, Path(id)).await
}

/// Remove a member (not the owner).
#[utoipa::path(delete, path = "/api/v1/admin/teams/{id}/members/{user_id}", tag = "admin",
    params(("id" = Uuid, Path), ("user_id" = Uuid, Path)), responses((status = 204)))]
pub async fn remove_member(
    State(state): State<AppState>,
    admin: Admin,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<NoContent> {
    let role: Option<(String,)> =
        sqlx::query_as("SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    let (role,) = role.ok_or_else(|| Error::not_found("Member"))?;
    if role == "owner" {
        return Err(Error::conflict(
            "Transfer ownership before removing the owner",
        ));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "DELETE FROM vault_members vm USING vaults v WHERE vm.vault_id = v.id AND v.team_id = $1 AND vm.user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    crate::routes::ca::forget_member(&mut *tx, id, user_id).await?;
    tx.commit().await?;
    audit::record(
        &state.db,
        audit::Entry::system(id, "member.removed")
            .user(user_id)
            .details(serde_json::json!({ "by_server_admin": admin.0.user_id() })),
    )
    .await;
    let _ = state.events.send(crate::events::Event::TeamsUpdated {
        user_ids: vec![user_id],
    });
    let _ = state.events.send(crate::events::Event::VaultsUpdated {
        user_ids: vec![user_id],
    });
    Ok(NoContent)
}

/// Background jobs and their last pass.
#[utoipa::path(get, path = "/api/v1/admin/jobs", tag = "admin", responses((status = 200, body = AdminJobList)))]
pub async fn jobs(State(state): State<AppState>, _admin: Admin) -> ApiResult<Json<AdminJobList>> {
    let rows: Vec<(String, DateTime<Utc>, Option<DateTime<Utc>>, Option<i64>, Option<String>)> =
        sqlx::query_as(
            "SELECT name, last_started_at, last_finished_at, last_result, last_error FROM job_runs ORDER BY name",
        )
        .fetch_all(&state.db)
        .await?;
    Ok(Json(AdminJobList {
        jobs: rows
            .into_iter()
            .map(
                |(name, last_started_at, last_finished_at, last_result, last_error)| AdminJob {
                    name,
                    last_started_at,
                    last_finished_at,
                    last_result,
                    last_error,
                },
            )
            .collect(),
    }))
}

#[utoipa::path(delete, path = "/api/v1/admin/teams/{id}", tag = "admin", params(("id" = Uuid, Path)), responses((status = 204)))]
pub async fn delete_team(
    State(state): State<AppState>,
    Admin(auth): Admin,
    Path(id): Path<Uuid>,
) -> ApiResult<NoContent> {
    let members = crate::routes::teams::member_ids(&state.db, id).await?;
    let res = sqlx::query("DELETE FROM teams WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(Error::not_found("Team"));
    }
    events::publish(
        &state,
        Event::TeamsUpdated {
            user_ids: members.clone(),
        },
    )
    .await?;
    events::publish(&state, Event::VaultsUpdated { user_ids: members }).await?;
    users::security_event(
        &state,
        auth.user_id(),
        "admin_deleted_team",
        Some(auth.device_id()),
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        Some(serde_json::json!({ "team_id": id })),
    )
    .await
    .map(NoContent::from)
}

// ───────────────────────────── settings / email ─────────────────────────────

#[utoipa::path(get, path = "/api/v1/admin/settings", tag = "admin", responses((status = 200, body = ServerSettings)))]
pub async fn get_settings(
    State(state): State<AppState>,
    _admin: Admin,
) -> ApiResult<Json<ServerSettings>> {
    Ok(Json(state.settings().await?))
}

#[utoipa::path(put, path = "/api/v1/admin/settings", tag = "admin",
    request_body = ServerSettings, responses((status = 200, body = ServerSettings)))]
pub async fn put_settings(
    State(state): State<AppState>,
    Admin(auth): Admin,
    Body(s): Body<ServerSettings>,
) -> ApiResult<Json<ServerSettings>> {
    if s.session_ttl_days == 0 || s.session_ttl_days > 3650 {
        return Err(Error::bad_request("session_ttl_days must be 1..=3650"));
    }
    if s.max_entity_bytes < 1024 || s.max_entity_bytes > 4 * 1024 * 1024 {
        return Err(Error::bad_request(
            "max_entity_bytes must be between 1 KiB and 4 MiB",
        ));
    }
    if s.max_log_bytes < 1024 {
        return Err(Error::bad_request("max_log_bytes is too small"));
    }
    if s.audit_retention_days > 3650 {
        return Err(Error::bad_request("audit_retention_days must be 0..=3650"));
    }
    crate::enterprise::validate_settings(&state, &s).await?;
    let mut s = s;
    s.allowed_domains = s
        .allowed_domains
        .iter()
        .map(|d| d.trim().trim_start_matches('@').to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    state.save_settings(&s, Some(auth.user_id())).await?;
    users::security_event(
        &state,
        auth.user_id(),
        "admin_settings_changed",
        Some(auth.device_id()),
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        None,
    )
    .await?;
    Ok(Json(s))
}

#[utoipa::path(post, path = "/api/v1/admin/email/test", tag = "admin", request_body = TestEmailRequest, responses((status = 204)))]
pub async fn test_email(
    State(state): State<AppState>,
    _admin: Admin,
    Body(req): Body<TestEmailRequest>,
) -> ApiResult<NoContent> {
    let mailer = state
        .mailer
        .as_ref()
        .ok_or_else(|| Error::feature_disabled("Email"))?;
    let to =
        crate::util::normalize_email(&req.to).ok_or_else(|| Error::bad_request("Invalid email"))?;
    let email = crate::mail::Email::new(
        format!("{}: test email", state.cfg.server_name),
        "Outgoing email works",
    )
    .paragraph("If you can read this, outgoing email from your Termoso server works.")
    .outro("This message was requested from the admin settings; nothing else is configured by it.");
    mailer
        .send(&to, &email)
        .await
        .map_err(|e| Error::bad_request(format!("Sending failed: {e}")))
        .map(NoContent::from)
}

// ───────────────────────────── effective configuration ────

/// `scheme://host:port/path` with user info and query removed.
fn masked_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(u) => {
            let mut out = format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""));
            if let Some(p) = u.port() {
                out.push_str(&format!(":{p}"));
            }
            if u.path() != "/" {
                out.push_str(u.path());
            }
            out
        }
        Err(_) => "<unparseable>".into(),
    }
}

async fn probe<F, T>(f: F) -> (String, Option<u64>, Option<String>)
where
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    let t0 = std::time::Instant::now();
    match tokio::time::timeout(std::time::Duration::from_secs(3), f).await {
        Ok(Ok(_)) => ("ok".into(), Some(t0.elapsed().as_millis() as u64), None),
        Ok(Err(e)) => (
            "error".into(),
            Some(t0.elapsed().as_millis() as u64),
            Some(e.to_string()),
        ),
        Err(_) => ("error".into(), None, Some("timed out after 3 s".into())),
    }
}

fn split_list(s: &str) -> Vec<String> {
    s.split([',', ' '])
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_owned)
        .collect()
}

#[utoipa::path(get, path = "/api/v1/admin/config", tag = "admin", responses((status = 200, body = AdminConfig)))]
pub async fn config(State(state): State<AppState>, _admin: Admin) -> ApiResult<Json<AdminConfig>> {
    let cfg = &state.cfg;

    let (db_status, db_latency, db_error) = probe(async {
        sqlx::query("SELECT 1").execute(&state.db).await?;
        anyhow::Ok(())
    })
    .await;
    let (redis_status, redis_latency, redis_error) = probe(state.cache.ping()).await;

    let storage = match (&cfg.s3, &state.storage) {
        (Some(s3), Some(st)) => {
            let (status, latency_ms, error) = probe(st.ping()).await;
            Some(AdminConfigStorage {
                bucket: s3.bucket.clone(),
                region: s3.region.clone(),
                endpoint: s3.endpoint.clone(),
                public_endpoint: s3.public_endpoint.clone(),
                force_path_style: s3.force_path_style,
                presign_secs: s3.presign_secs,
                status,
                latency_ms,
                error,
            })
        }
        _ => None,
    };

    let smtp = cfg.smtp.as_ref().map(|m| AdminConfigSmtp {
        host: m.host.clone(),
        port: m.port,
        security: match m.security {
            crate::config::SmtpSecurity::Starttls => "starttls",
            crate::config::SmtpSecurity::Tls => "tls",
            crate::config::SmtpSecurity::None => "none",
        }
        .into(),
        from: m.from.clone(),
        auth: m.username.is_some(),
    });

    let sso = cfg
        .sso
        .iter()
        .map(|(id, p)| AdminConfigSso {
            id: id.clone(),
            name: p.name.clone().unwrap_or_else(|| id.clone()),
            kind: match p.kind {
                crate::config::SsoKindConfig::Oidc => "oidc",
                crate::config::SsoKindConfig::Saml => "saml",
            }
            .into(),
            issuer: p.issuer.clone().or_else(|| p.saml_idp_entity_id.clone()),
            allowed_domains: p
                .allowed_domains
                .as_deref()
                .map(split_list)
                .unwrap_or_default(),
        })
        .collect();

    let webauthn = cfg.webauthn.as_ref().map(|w| AdminConfigWebauthn {
        rp_id: w.rp_id.clone(),
        rp_name: w.rp_name.clone(),
        origins: split_list(&w.origins),
    });

    let ai = cfg.ai.as_ref().map(|a| AdminConfigAi {
        provider: a.provider.clone(),
        model: a.model.clone(),
        endpoint: masked_url(&a.url),
        confidential: a.confidential,
        daily_quota: a.daily_quota,
        max_prompt_chars: a.max_prompt_chars as u64,
        timeout_secs: a.timeout_secs,
    });

    let meta = state.settings_meta().await?;
    let min_client = crate::routes::auth::min_client_version(cfg).to_owned();

    Ok(Json(AdminConfig {
        server: AdminConfigServer {
            version: crate::state::VERSION.into(),
            started_at: state.started_at,
            uptime_secs: (Utc::now() - state.started_at).num_seconds().max(0) as u64,
            name: cfg.server_name.clone(),
            public_url: cfg.public_url.clone(),
            web_url: cfg.web_url().to_owned(),
            bind: cfg.bind.to_string(),
            trust_proxy: cfg.trust_proxy,
            cors_origins: cfg.cors_origins(),
            log: cfg.log.clone(),
            log_format: match cfg.log_format {
                crate::config::LogFormat::Text => "text",
                crate::config::LogFormat::Json => "json",
            }
            .into(),
            data_region: cfg.data_region.clone(),
            min_client_version_overridden: min_client != crate::state::VERSION,
            min_client_version: min_client,
            start_over_delay_secs: cfg.start_over_delay_secs,
            team_deletion_grace_days: cfg.team_deletion_grace_days,
            team_audit_retention_days_max: cfg.audit_retention_days_max,
            audit_sink: cfg.audit_sink,
            swagger_ui: cfg.swagger_ui,
            bridges: cfg.bridges,
            team_idp: cfg.team_idp,
            landing: cfg.landing,
            docs: cfg.docs,
            metrics_bind: cfg.metrics.enabled.then(|| cfg.metrics.bind.to_string()),
            webhooks_allow_private: cfg.webhooks_allow_private,
            webhooks_syslog_ca: cfg.webhooks_syslog_ca.is_some(),
            turnstile: cfg.turnstile.is_some(),
            admin_emails: cfg.admin_emails(),
            owner_email: Some(cfg.owner_email.trim().to_lowercase()).filter(|e| !e.is_empty()),
        },
        database: AdminConfigService {
            endpoint: masked_url(&cfg.database_url),
            detail: Some(format!("pool max {}", cfg.database_max_connections)),
            status: db_status,
            latency_ms: db_latency,
            error: db_error,
        },
        redis: AdminConfigService {
            endpoint: masked_url(&cfg.redis_url),
            detail: Some(format!("prefix {}", cfg.redis_prefix)),
            status: redis_status,
            latency_ms: redis_latency,
            error: redis_error,
        },
        storage,
        smtp,
        sso,
        webauthn,
        ai,
        settings: AdminSettingsMeta {
            defaults: ServerSettings::default(),
            limits: AdminSettingsLimits {
                session_ttl_days_min: 1,
                session_ttl_days_max: 3650,
                max_entity_bytes_min: 1024,
                max_entity_bytes_max: 4 * 1024 * 1024,
                max_log_bytes_min: 1024,
                audit_retention_days_max: 3650,
            },
            updated_at: meta.as_ref().map(|(t, _)| *t),
            updated_by: meta.and_then(|(_, e)| e),
        },
    }))
}
