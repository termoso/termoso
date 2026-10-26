//! Just-in-time access requests. Approval creates a *pending* vault
//! membership with an expiry; a manager's client seals the vault key to the
//! requester exactly like for invited members (the server never holds it),
//! and the expiry job removes the membership when the window closes.

use axum::Json;
use axum::extract::{Path, Query, State};

use super::paging::PageQuery;
use chrono::{DateTime, Duration, Utc};
use termoso_proto::team::{
    AccessRequest, AccessRequestList, CreateAccessRequest, DecideAccessRequest,
};
use uuid::Uuid;

use crate::audit;
use crate::error::{ApiResult, Error, NoContent};
use crate::events::{self, Event};
use crate::extract::{Auth, Json as Body};
use crate::state::AppState;

pub const ROLES: &[&str] = &["viewer", "editor"];
pub const MAX_HOURS: i32 = 720;
pub const PERM: &str = "access.approve";

type Row = (
    Uuid,
    Uuid,
    Uuid,
    String,
    Uuid,
    String,
    String,
    i32,
    String,
    String,
    Option<Uuid>,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
);

const COLS: &str =
    "r.id, r.team_id, r.vault_id, v.name, r.user_id, u.email, r.role, r.hours, r.reason, r.status,
        r.decided_by, r.decided_at, r.decision_note, r.expires_at, r.created_at
    FROM access_requests r JOIN vaults v ON v.id = r.vault_id JOIN users u ON u.id = r.user_id";

fn to_req(r: Row) -> AccessRequest {
    AccessRequest {
        id: r.0,
        team_id: r.1,
        vault_id: r.2,
        vault_name: r.3,
        user_id: r.4,
        user_email: r.5,
        role: r.6,
        hours: r.7,
        reason: r.8,
        status: r.9,
        decided_by: r.10,
        decided_at: r.11,
        decision_note: r.12,
        expires_at: r.13,
        created_at: r.14,
    }
}

async fn load(state: &AppState, team_id: Uuid, id: Uuid) -> ApiResult<AccessRequest> {
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLS} WHERE r.id = $1 AND r.team_id = $2"
    )))
    .bind(id)
    .bind(team_id)
    .fetch_optional(&state.db)
    .await?;
    row.map(to_req)
        .ok_or_else(|| Error::not_found("Access request"))
}

fn clean(note: Option<String>, max: usize) -> ApiResult<Option<String>> {
    let Some(n) = note else { return Ok(None) };
    let n = n.trim();
    if n.chars().count() > max {
        return Err(Error::too_large(format!(
            "Text is limited to {max} characters"
        )));
    }
    Ok((!n.is_empty()).then(|| n.to_owned()))
}

async fn notify_approvers(state: &AppState, team_id: Uuid, req: &AccessRequest) {
    let Some(mailer) = &state.mailer else { return };
    let approvers: Vec<(String,)> = match sqlx::query_as(
        "SELECT u.email FROM team_members m JOIN users u ON u.id = m.user_id
         WHERE m.team_id = $1 AND m.role IN ('owner', 'admin') AND u.id <> $2 LIMIT 20",
    )
    .bind(team_id)
    .bind(req.user_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, "approver lookup");
            return;
        }
    };
    let url = format!(
        "{}/team?tab=access",
        state.cfg.public_url.trim_end_matches('/')
    );
    for (email,) in approvers {
        let msg = crate::mail::Email::new(
            format!("Access request: {}", req.vault_name),
            "Someone asks for temporary vault access",
        )
        .paragraph(format!(
            "{} requests {} access to the vault “{}” for {} hour(s).",
            req.user_email, req.role, req.vault_name, req.hours
        ))
        .row(
            "Reason",
            if req.reason.is_empty() {
                "—".to_string()
            } else {
                req.reason.clone()
            },
        )
        .button("Review request", &url);
        if let Err(e) = mailer.send(&email, &msg).await {
            tracing::warn!(error = %e, "access request email");
        }
    }
}

async fn notify_requester(state: &AppState, req: &AccessRequest, approved: bool) {
    let Some(mailer) = &state.mailer else { return };
    let url = format!(
        "{}/team?tab=access",
        state.cfg.public_url.trim_end_matches('/')
    );
    let mut msg = crate::mail::Email::new(
        format!(
            "Access {}: {}",
            if approved { "granted" } else { "denied" },
            req.vault_name
        ),
        if approved {
            "Your temporary access was approved"
        } else {
            "Your access request was denied"
        },
    );
    if approved && let Some(until) = req.expires_at {
        msg = msg.paragraph(format!(
            "You have {} access to “{}” until {}. Open Termoso: the vault appears once a manager's client has shared the key with you.",
            req.role,
            req.vault_name,
            until.format("%Y-%m-%d %H:%M UTC")
        ));
    } else {
        msg = msg.paragraph(format!("Request for “{}” was declined.", req.vault_name));
    }
    if let Some(n) = &req.decision_note {
        msg = msg.row("Note", n.clone());
    }
    if let Err(e) = mailer
        .send(&req.user_email, &msg.button("Open Termoso", &url))
        .await
    {
        tracing::warn!(error = %e, "access decision email");
    }
}

/// Ask for temporary access to a team vault you are not a member of.
#[utoipa::path(post, path = "/api/v1/teams/{id}/access-requests", tag = "teams",
    params(("id" = Uuid, Path)), request_body = CreateAccessRequest,
    responses((status = 200, body = AccessRequest)))]
pub async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
    Body(req): Body<CreateAccessRequest>,
) -> ApiResult<Json<AccessRequest>> {
    crate::authz::membership(&state.db, team_id, auth.user_id())
        .await
        .map_err(|_| Error::not_found("Team"))?;
    if !ROLES.contains(&req.role.as_str()) {
        return Err(Error::bad_request("role must be viewer or editor"));
    }
    if !(1..=MAX_HOURS).contains(&req.hours) {
        return Err(Error::bad_request(format!("hours must be 1..={MAX_HOURS}")));
    }
    let reason = clean(Some(req.reason), 500)?.unwrap_or_default();
    let (vault_ok,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM vaults WHERE id = $1 AND team_id = $2 AND kind = 'team' AND deleted_at IS NULL)",
    )
    .bind(req.vault_id)
    .bind(team_id)
    .fetch_one(&state.db)
    .await?;
    if !vault_ok {
        return Err(Error::not_found("Team vault"));
    }
    let (member,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM vault_members WHERE vault_id = $1 AND user_id = $2)",
    )
    .bind(req.vault_id)
    .bind(auth.user_id())
    .fetch_one(&state.db)
    .await?;
    if member {
        return Err(Error::conflict("You already have access to this vault"));
    }
    let row: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO access_requests (team_id, vault_id, user_id, role, hours, reason)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(team_id)
    .bind(req.vault_id)
    .bind(auth.user_id())
    .bind(&req.role)
    .bind(req.hours)
    .bind(&reason)
    .fetch_optional(&state.db)
    .await?;
    let Some((id,)) = row else {
        return Err(Error::conflict(
            "You already have a pending request for this vault",
        ));
    };
    let out = load(&state, team_id, id).await?;
    audit::record(
        &state.db,
        audit::Entry::new(team_id, &auth, "access.requested")
            .vault(req.vault_id)
            .details(serde_json::json!({ "request_id": id, "role": req.role, "hours": req.hours })),
    )
    .await;
    notify_approvers(&state, team_id, &out).await;
    Ok(Json(out))
}

/// Requests of the team: everything for `access.approve` holders, your own
/// otherwise.
#[derive(serde::Deserialize, utoipa::IntoParams)]
pub struct AccessListQuery {
    /// `open` (pending or approved) or `closed`; omit for both.
    pub status: Option<String>,
    /// Rows to skip.
    #[serde(default)]
    pub offset: i64,
    /// Rows per page; omit for the whole list.
    pub limit: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/teams/{id}/access-requests", tag = "teams",
    params(("id" = Uuid, Path), AccessListQuery), responses((status = 200, body = AccessRequestList)))]
pub async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
    Query(q): Query<AccessListQuery>,
) -> ApiResult<Json<AccessRequestList>> {
    let open: Option<bool> = match q.status.as_deref().map(str::trim) {
        None | Some("") => None,
        Some("open") => Some(true),
        Some("closed") => Some(false),
        Some(_) => return Err(Error::bad_request("status must be open or closed")),
    };
    let pq = PageQuery::new(q.offset, q.limit);
    let (offset, limit) = pq.window(500);
    crate::authz::membership(&state.db, team_id, auth.user_id())
        .await
        .map_err(|_| Error::not_found("Team"))?;
    let all = crate::authz::require(&state, team_id, auth.user_id(), PERM)
        .await
        .is_ok();
    // Expire eagerly so the list never shows a grant that is already over.
    if let Err(e) = expiry_pass(state.clone()).await {
        tracing::warn!(error = %e, "access expiry");
    }
    let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLS} WHERE r.team_id = $1 AND ($2 OR r.user_id = $3)
           AND ($4::bool IS NULL OR (r.status IN ('pending', 'approved')) = $4)
         ORDER BY (r.status = 'pending') DESC, r.created_at DESC LIMIT $5 OFFSET $6"
    )))
    .bind(team_id)
    .bind(all)
    .bind(auth.user_id())
    .bind(open)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    let total = if pq.limit.is_some() {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM access_requests r WHERE r.team_id = $1 AND ($2 OR r.user_id = $3)
               AND ($4::bool IS NULL OR (r.status IN ('pending', 'approved')) = $4)",
        )
        .bind(team_id)
        .bind(all)
        .bind(auth.user_id())
        .bind(open)
        .fetch_one(&state.db)
        .await?;
        n
    } else {
        offset + rows.len() as i64
    };
    Ok(Json(AccessRequestList {
        can_approve: all,
        requests: rows.into_iter().map(to_req).collect(),
        total,
    }))
}

/// Grant the request (optionally trimming hours/role). Creates a pending
/// vault membership that expires automatically.
#[utoipa::path(post, path = "/api/v1/teams/{id}/access-requests/{rid}/approve", tag = "teams",
    params(("id" = Uuid, Path), ("rid" = Uuid, Path)), request_body = DecideAccessRequest,
    responses((status = 200, body = AccessRequest)))]
pub async fn approve(
    State(state): State<AppState>,
    auth: Auth,
    Path((team_id, rid)): Path<(Uuid, Uuid)>,
    Body(req): Body<DecideAccessRequest>,
) -> ApiResult<Json<AccessRequest>> {
    crate::authz::require(&state, team_id, auth.user_id(), PERM).await?;
    let cur = load(&state, team_id, rid).await?;
    if cur.status != "pending" {
        return Err(Error::conflict("Request already decided"));
    }
    if cur.user_id == auth.user_id() {
        return Err(Error::forbidden("You cannot approve your own request"));
    }
    let hours = req.hours.unwrap_or(cur.hours);
    if !(1..=MAX_HOURS).contains(&hours) {
        return Err(Error::bad_request(format!("hours must be 1..={MAX_HOURS}")));
    }
    let role = req.role.unwrap_or_else(|| cur.role.clone());
    if !ROLES.contains(&role.as_str()) {
        return Err(Error::bad_request("role must be viewer or editor"));
    }
    let note = clean(req.note, 500)?;
    let until = Utc::now() + Duration::hours(hours as i64);
    let mut tx = state.db.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO vault_members (vault_id, user_id, role, sealed_key, key_version, added_by, expires_at)
         SELECT id, $2, $3, NULL, key_version, $4, $5 FROM vaults WHERE id = $1
         ON CONFLICT (vault_id, user_id) DO NOTHING",
    )
    .bind(cur.vault_id)
    .bind(cur.user_id)
    .bind(&role)
    .bind(auth.user_id())
    .bind(until)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(Error::conflict(
            "The member already has access to this vault",
        ));
    }
    sqlx::query(
        "UPDATE access_requests SET status = 'approved', role = $2, hours = $3, decided_by = $4,
                decided_at = now(), decision_note = $5, expires_at = $6, updated_at = now() WHERE id = $1",
    )
    .bind(rid)
    .bind(&role)
    .bind(hours)
    .bind(auth.user_id())
    .bind(&note)
    .bind(until)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let out = load(&state, team_id, rid).await?;
    audit::record(
        &state.db,
        audit::Entry::new(team_id, &auth, "access.approved")
            .vault(cur.vault_id)
            .user(cur.user_id)
            .details(serde_json::json!({
                "request_id": rid, "role": role, "hours": hours, "expires_at": until,
            })),
    )
    .await;
    events::publish(
        &state,
        Event::VaultsUpdated {
            user_ids: vec![cur.user_id, auth.user_id()],
        },
    )
    .await?;
    notify_requester(&state, &out, true).await;
    Ok(Json(out))
}

#[utoipa::path(post, path = "/api/v1/teams/{id}/access-requests/{rid}/deny", tag = "teams",
    params(("id" = Uuid, Path), ("rid" = Uuid, Path)), request_body = DecideAccessRequest,
    responses((status = 200, body = AccessRequest)))]
pub async fn deny(
    State(state): State<AppState>,
    auth: Auth,
    Path((team_id, rid)): Path<(Uuid, Uuid)>,
    Body(req): Body<DecideAccessRequest>,
) -> ApiResult<Json<AccessRequest>> {
    crate::authz::require(&state, team_id, auth.user_id(), PERM).await?;
    let cur = load(&state, team_id, rid).await?;
    if cur.status != "pending" {
        return Err(Error::conflict("Request already decided"));
    }
    let note = clean(req.note, 500)?;
    sqlx::query(
        "UPDATE access_requests SET status = 'denied', decided_by = $2, decided_at = now(),
                decision_note = $3, updated_at = now() WHERE id = $1",
    )
    .bind(rid)
    .bind(auth.user_id())
    .bind(&note)
    .execute(&state.db)
    .await?;
    let out = load(&state, team_id, rid).await?;
    audit::record(
        &state.db,
        audit::Entry::new(team_id, &auth, "access.denied")
            .vault(cur.vault_id)
            .user(cur.user_id)
            .details(serde_json::json!({ "request_id": rid, "note": note })),
    )
    .await;
    notify_requester(&state, &out, false).await;
    Ok(Json(out))
}

/// End an approved grant early.
#[utoipa::path(post, path = "/api/v1/teams/{id}/access-requests/{rid}/revoke", tag = "teams",
    params(("id" = Uuid, Path), ("rid" = Uuid, Path)), responses((status = 200, body = AccessRequest)))]
pub async fn revoke(
    State(state): State<AppState>,
    auth: Auth,
    Path((team_id, rid)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<AccessRequest>> {
    crate::authz::require(&state, team_id, auth.user_id(), PERM).await?;
    let cur = load(&state, team_id, rid).await?;
    if cur.status != "approved" {
        return Err(Error::conflict("Only approved requests can be revoked"));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2 AND expires_at IS NOT NULL",
    )
    .bind(cur.vault_id)
    .bind(cur.user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE access_requests SET status = 'revoked', decided_by = $2, decided_at = now(), updated_at = now() WHERE id = $1",
    )
    .bind(rid)
    .bind(auth.user_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    audit::record(
        &state.db,
        audit::Entry::new(team_id, &auth, "access.revoked")
            .vault(cur.vault_id)
            .user(cur.user_id)
            .details(serde_json::json!({ "request_id": rid })),
    )
    .await;
    events::publish(
        &state,
        Event::VaultsUpdated {
            user_ids: vec![cur.user_id, auth.user_id()],
        },
    )
    .await?;
    Ok(Json(load(&state, team_id, rid).await?))
}

/// Withdraw your own pending request.
#[utoipa::path(delete, path = "/api/v1/teams/{id}/access-requests/{rid}", tag = "teams",
    params(("id" = Uuid, Path), ("rid" = Uuid, Path)), responses((status = 204)))]
pub async fn cancel(
    State(state): State<AppState>,
    auth: Auth,
    Path((team_id, rid)): Path<(Uuid, Uuid)>,
) -> ApiResult<NoContent> {
    let cur = load(&state, team_id, rid).await?;
    if cur.user_id != auth.user_id() {
        return Err(Error::forbidden(
            "Only the requester can withdraw a request",
        ));
    }
    if cur.status != "pending" {
        return Err(Error::conflict("Request already decided"));
    }
    sqlx::query(
        "UPDATE access_requests SET status = 'cancelled', updated_at = now() WHERE id = $1",
    )
    .bind(rid)
    .execute(&state.db)
    .await?;
    Ok(NoContent)
}

/// Every 5 minutes drop vault memberships whose window closed and mark the
/// matching requests expired (audited as `access.expired`).
pub async fn run_expiry(state: AppState) {
    crate::jobs::exclusive(
        state,
        "access-expiry",
        std::time::Duration::from_secs(300),
        expiry_pass,
    )
    .await
}

pub async fn expiry_pass(state: AppState) -> anyhow::Result<u64> {
    let rows: Vec<(Uuid, Uuid, Option<Uuid>)> = sqlx::query_as(
        "DELETE FROM vault_members vm USING vaults v
         WHERE vm.vault_id = v.id AND vm.expires_at IS NOT NULL AND vm.expires_at < now()
         RETURNING vm.vault_id, vm.user_id, v.team_id",
    )
    .fetch_all(&state.db)
    .await?;
    sqlx::query(
        "UPDATE access_requests SET status = 'expired', updated_at = now()
         WHERE status = 'approved' AND expires_at < now()",
    )
    .execute(&state.db)
    .await?;
    let mut users = Vec::new();
    for (vault_id, user_id, team_id) in &rows {
        users.push(*user_id);
        if let Some(team_id) = team_id {
            audit::record(
                &state.db,
                audit::Entry::system(*team_id, "access.expired")
                    .vault(*vault_id)
                    .user(*user_id),
            )
            .await;
        }
    }
    if !users.is_empty() {
        let _ = events::publish(&state, Event::VaultsUpdated { user_ids: users }).await;
    }
    Ok(rows.len() as u64)
}
