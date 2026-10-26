//! Admin-approved devices of a team (`devices.approve`).

use axum::Json;
use axum::extract::{Path, Query, State};

use super::paging::PageQuery;
use chrono::{DateTime, Utc};
use termoso_proto::team::{TeamDevice, TeamDeviceList};
use uuid::Uuid;

use crate::audit;
use crate::error::{ApiResult, Error};
use crate::extract::Auth;
use crate::state::AppState;

pub const PERM: &str = "devices.approve";

type Row = (
    Uuid,
    Uuid,
    String,
    String,
    String,
    Option<String>,
    DateTime<Utc>,
    Option<String>,
    String,
    Option<Uuid>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
);

const SELECT: &str = "SELECT a.device_id, a.user_id, u.email, d.name, d.platform, d.app_version, d.last_seen_at, d.last_ip,
        a.status, a.decided_by, a.decided_at, a.created_at
    FROM team_device_approvals a JOIN devices d ON d.id = a.device_id JOIN users u ON u.id = a.user_id";

fn to_dev(r: Row) -> TeamDevice {
    TeamDevice {
        device_id: r.0,
        user_id: r.1,
        user_email: r.2,
        name: r.3,
        platform: r.4,
        app_version: r.5,
        last_seen_at: r.6,
        last_ip: r.7,
        status: r.8,
        decided_by: r.9,
        decided_at: r.10,
        requested_at: r.11,
    }
}

/// Pending first, then approved/rejected, newest first.
#[derive(serde::Deserialize, utoipa::IntoParams)]
pub struct DeviceListQuery {
    /// `pending` (awaiting a decision) or `decided`; omit for both.
    pub status: Option<String>,
    /// Rows to skip.
    #[serde(default)]
    pub offset: i64,
    /// Rows per page; omit for the whole list.
    pub limit: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/teams/{id}/devices", tag = "teams",
    params(("id" = Uuid, Path), DeviceListQuery), responses((status = 200, body = TeamDeviceList)))]
pub async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
    Query(q): Query<DeviceListQuery>,
) -> ApiResult<Json<TeamDeviceList>> {
    crate::authz::require(&state, team_id, auth.user_id(), PERM).await?;
    let pending: Option<bool> = match q.status.as_deref().map(str::trim) {
        None | Some("") => None,
        Some("pending") => Some(true),
        Some("decided") => Some(false),
        Some(_) => return Err(Error::bad_request("status must be pending or decided")),
    };
    let pq = PageQuery::new(q.offset, q.limit);
    let (offset, limit) = pq.window(1000);
    let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE a.team_id = $1 AND ($2::bool IS NULL OR (a.status = 'pending') = $2)
         ORDER BY (a.status = 'pending') DESC, a.created_at DESC LIMIT $3 OFFSET $4"
    )))
    .bind(team_id)
    .bind(pending)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    let total = if pq.limit.is_some() {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM team_device_approvals a
             WHERE a.team_id = $1 AND ($2::bool IS NULL OR (a.status = 'pending') = $2)",
        )
        .bind(team_id)
        .bind(pending)
        .fetch_one(&state.db)
        .await?;
        n
    } else {
        offset + rows.len() as i64
    };
    let p = crate::policy::load(&state.db, team_id).await?;
    Ok(Json(TeamDeviceList {
        admin_approval: p.device_admin_approval,
        devices: rows.into_iter().map(to_dev).collect(),
        total,
    }))
}

async fn decide(
    state: &AppState,
    auth: &Auth,
    team_id: Uuid,
    device_id: Uuid,
    status: &'static str,
) -> ApiResult<Json<TeamDevice>> {
    crate::authz::require(state, team_id, auth.user_id(), PERM).await?;
    let owner: Option<(Uuid,)> = sqlx::query_as(
        "SELECT d.user_id FROM devices d JOIN team_members m ON m.user_id = d.user_id AND m.team_id = $1 WHERE d.id = $2",
    )
    .bind(team_id)
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;
    let (user_id,) = owner.ok_or_else(|| Error::not_found("Device"))?;
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO team_device_approvals (team_id, device_id, user_id, status, decided_by, decided_at)
         VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (team_id, device_id) DO UPDATE SET status = EXCLUDED.status,
             decided_by = EXCLUDED.decided_by, decided_at = now()",
    )
    .bind(team_id)
    .bind(device_id)
    .bind(user_id)
    .bind(status)
    .bind(auth.user_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if status == "rejected" {
        crate::session::revoke_device(state, user_id, device_id).await?;
    }
    audit::record(
        &state.db,
        audit::Entry::new(
            team_id,
            auth,
            if status == "approved" {
                "device.approved"
            } else {
                "device.rejected"
            },
        )
        .user(user_id)
        .details(serde_json::json!({ "device_id": device_id })),
    )
    .await;
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE a.team_id = $1 AND a.device_id = $2"
    )))
    .bind(team_id)
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(Json(to_dev(row.ok_or_else(|| Error::not_found("Device"))?)))
}

#[utoipa::path(post, path = "/api/v1/teams/{id}/devices/{device_id}/approve", tag = "teams",
    params(("id" = Uuid, Path), ("device_id" = Uuid, Path)), responses((status = 200, body = TeamDevice)))]
pub async fn approve(
    State(state): State<AppState>,
    auth: Auth,
    Path((team_id, device_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<TeamDevice>> {
    decide(&state, &auth, team_id, device_id, "approved").await
}

/// Rejecting also ends the device's live sessions.
#[utoipa::path(post, path = "/api/v1/teams/{id}/devices/{device_id}/reject", tag = "teams",
    params(("id" = Uuid, Path), ("device_id" = Uuid, Path)), responses((status = 200, body = TeamDevice)))]
pub async fn reject(
    State(state): State<AppState>,
    auth: Auth,
    Path((team_id, device_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<TeamDevice>> {
    decide(&state, &auth, team_id, device_id, "rejected").await
}
