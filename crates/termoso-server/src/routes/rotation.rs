//! Credential rotation bookkeeping. Secrets never leave the vault key: clients
//! report `secret_rotated_at` per identity/key/host when they push, the server
//! only compares those timestamps with the team's max-age policy and tracks
//! rotation jobs that a client holding the vault key executes.

use axum::Json;
use axum::extract::{Path, Query, State};

use super::paging::PageQuery;
use chrono::{DateTime, Utc};
use termoso_proto::team::{
    CreateRotationJobsRequest, RotationDue, RotationJob, RotationJobList, RotationOverview,
    UpdateRotationJobRequest,
};
use uuid::Uuid;

use crate::audit;
use crate::error::{ApiResult, Error, NoContent};
use crate::extract::{Auth, Json as Body};
use crate::routes::vaults;
use crate::state::AppState;

/// Kinds whose age is governed by `key_max_age_days`.
pub const KEY_KINDS: &[&str] = &["ssh_key", "ssh_certificate"];
/// Kinds whose age is governed by `password_max_age_days`.
pub const PASSWORD_KINDS: &[&str] = &["identity", "host"];
pub const STATUSES: &[&str] = &["pending", "running", "done", "failed", "cancelled"];

type JobRow = (
    Uuid,
    Uuid,
    Uuid,
    Uuid,
    String,
    String,
    String,
    Option<String>,
    Uuid,
    String,
    Option<Uuid>,
    DateTime<Utc>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
);

const JOBS_BY_TEAM: &str =
    "SELECT j.id, j.team_id, j.vault_id, j.entity_id, j.entity_kind, j.status, j.note, j.error,
        j.requested_by, u.email, j.claimed_by, j.created_at, j.updated_at, j.finished_at
    FROM rotation_jobs j JOIN users u ON u.id = j.requested_by
    WHERE j.team_id = $1 ORDER BY j.created_at DESC LIMIT 500";

const JOBS_PAGE: &str =
    "SELECT j.id, j.team_id, j.vault_id, j.entity_id, j.entity_kind, j.status, j.note, j.error,
        j.requested_by, u.email, j.claimed_by, j.created_at, j.updated_at, j.finished_at
    FROM rotation_jobs j JOIN users u ON u.id = j.requested_by
    WHERE j.team_id = $1 ORDER BY j.created_at DESC LIMIT $2 OFFSET $3";

const JOBS_BY_ID: &str =
    "SELECT j.id, j.team_id, j.vault_id, j.entity_id, j.entity_kind, j.status, j.note, j.error,
        j.requested_by, u.email, j.claimed_by, j.created_at, j.updated_at, j.finished_at
    FROM rotation_jobs j JOIN users u ON u.id = j.requested_by
    WHERE j.id = $1";

/// Open jobs in team vaults the user can write to.
const JOBS_FOR_USER: &str =
    "SELECT j.id, j.team_id, j.vault_id, j.entity_id, j.entity_kind, j.status, j.note, j.error,
        j.requested_by, u.email, j.claimed_by, j.created_at, j.updated_at, j.finished_at
    FROM rotation_jobs j JOIN users u ON u.id = j.requested_by
    JOIN vault_members vm ON vm.vault_id = j.vault_id AND vm.user_id = $1
        AND vm.role IN ('manager', 'editor') AND vm.sealed_key IS NOT NULL
    WHERE j.status IN ('pending', 'running') ORDER BY j.created_at";

fn job(r: JobRow) -> RotationJob {
    RotationJob {
        id: r.0,
        team_id: r.1,
        vault_id: r.2,
        entity_id: r.3,
        entity_kind: r.4,
        status: r.5,
        note: r.6,
        error: r.7,
        requested_by: r.8,
        requested_by_email: r.9,
        claimed_by: r.10,
        created_at: r.11,
        updated_at: r.12,
        finished_at: r.13,
    }
}

type DueRow = (
    Uuid,
    Uuid,
    String,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
    Option<Uuid>,
);

/// Entities past the team's max age. `secret_rotated_at` falls back to the
/// entity's creation time, so never-reported secrets age from creation.
pub async fn due(
    db: &sqlx::PgPool,
    team_id: Uuid,
    key_days: i32,
    password_days: i32,
) -> ApiResult<Vec<RotationDue>> {
    if key_days <= 0 && password_days <= 0 {
        return Ok(Vec::new());
    }
    let rows: Vec<DueRow> = sqlx::query_as(
        "SELECT e.id, e.vault_id, e.kind, e.secret_rotated_at, e.created_at,
                (SELECT j.id FROM rotation_jobs j WHERE j.entity_id = e.id AND j.status IN ('pending', 'running') LIMIT 1)
         FROM entities e JOIN vaults v ON v.id = e.vault_id
         WHERE v.team_id = $1 AND v.kind = 'team' AND e.deleted = false AND (
               (e.kind = ANY($2) AND $3 > 0 AND COALESCE(e.secret_rotated_at, e.created_at) < now() - make_interval(days => $3))
            OR (e.kind = ANY($4) AND $5 > 0 AND COALESCE(e.secret_rotated_at, e.created_at) < now() - make_interval(days => $5)))
         ORDER BY COALESCE(e.secret_rotated_at, e.created_at) LIMIT 5000",
    )
    .bind(team_id)
    .bind(KEY_KINDS)
    .bind(key_days)
    .bind(PASSWORD_KINDS)
    .bind(password_days)
    .fetch_all(db)
    .await?;
    let now = Utc::now();
    Ok(rows
        .into_iter()
        .map(
            |(entity_id, vault_id, kind, rotated, created, job_id)| RotationDue {
                entity_id,
                vault_id,
                kind,
                secret_rotated_at: rotated,
                age_days: (now - rotated.unwrap_or(created)).num_days().max(0) as i32,
                job_id,
            },
        )
        .collect())
}

/// Max-age policy, overdue secrets and recent jobs of a team (`rotation.manage`).
#[utoipa::path(get, path = "/api/v1/teams/{id}/rotation", tag = "teams",
    params(("id" = Uuid, Path), PageQuery), responses((status = 200, body = RotationOverview)))]
pub async fn overview(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
    Query(pq): Query<PageQuery>,
) -> ApiResult<Json<RotationOverview>> {
    crate::authz::require(&state, team_id, auth.user_id(), "rotation.manage").await?;
    let (offset, limit) = pq.window(500);
    let p = crate::policy::load(&state.db, team_id).await?;
    let due = due(
        &state.db,
        team_id,
        p.key_max_age_days,
        p.password_max_age_days,
    )
    .await?;
    let jobs: Vec<JobRow> = sqlx::query_as(JOBS_PAGE)
        .bind(team_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;
    let jobs_total = pq
        .total(
            jobs.len(),
            &state.db,
            "SELECT count(*) FROM rotation_jobs WHERE team_id = $1",
            team_id,
        )
        .await?;
    Ok(Json(RotationOverview {
        jobs_total,
        key_max_age_days: p.key_max_age_days,
        password_max_age_days: p.password_max_age_days,
        due,
        jobs: jobs.into_iter().map(job).collect(),
    }))
}

/// Queue rotation of the given entities; a client with write access to the
/// vault picks the jobs up (`rotation.manage`).
#[utoipa::path(post, path = "/api/v1/teams/{id}/rotation/jobs", tag = "teams",
    params(("id" = Uuid, Path)), request_body = CreateRotationJobsRequest,
    responses((status = 200, body = RotationJobList)))]
pub async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
    Body(req): Body<CreateRotationJobsRequest>,
) -> ApiResult<Json<RotationJobList>> {
    crate::authz::require(&state, team_id, auth.user_id(), "rotation.manage").await?;
    if req.entity_ids.is_empty() || req.entity_ids.len() > 1000 {
        return Err(Error::bad_request("entity_ids must hold 1..=1000 ids"));
    }
    let note = req.note.trim();
    if note.chars().count() > 500 {
        return Err(Error::too_large("Notes are limited to 500 characters"));
    }
    let (owned,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM vaults WHERE id = $1 AND team_id = $2 AND kind = 'team')",
    )
    .bind(req.vault_id)
    .bind(team_id)
    .fetch_one(&state.db)
    .await?;
    if !owned {
        return Err(Error::not_found("Team vault"));
    }
    let rotatable: Vec<&str> = KEY_KINDS.iter().chain(PASSWORD_KINDS).copied().collect();
    let targets: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, kind FROM entities WHERE vault_id = $1 AND id = ANY($2) AND deleted = false AND kind = ANY($3)",
    )
    .bind(req.vault_id)
    .bind(&req.entity_ids)
    .bind(&rotatable)
    .fetch_all(&state.db)
    .await?;
    if targets.len() != req.entity_ids.len() {
        return Err(Error::bad_request(
            "Every entity must be a live identity, key, certificate or host of that vault",
        ));
    }
    let mut ids = Vec::with_capacity(targets.len());
    let mut tx = state.db.begin().await?;
    for (entity_id, kind) in &targets {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "INSERT INTO rotation_jobs (team_id, vault_id, entity_id, entity_kind, note, requested_by)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING RETURNING id",
        )
        .bind(team_id)
        .bind(req.vault_id)
        .bind(entity_id)
        .bind(kind)
        .bind(note)
        .bind(auth.user_id())
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((id,)) = row {
            ids.push(id);
        }
    }
    tx.commit().await?;
    if !ids.is_empty() {
        audit::record(
            &state.db,
            audit::Entry::new(team_id, &auth, "rotation.requested")
                .vault(req.vault_id)
                .details(serde_json::json!({ "jobs": ids.len(), "entities": targets.len() })),
        )
        .await;
    }
    let jobs: Vec<JobRow> = sqlx::query_as(JOBS_BY_TEAM)
        .bind(team_id)
        .fetch_all(&state.db)
        .await?;
    Ok(Json(RotationJobList {
        jobs: jobs
            .into_iter()
            .filter(|j| ids.contains(&j.0))
            .map(job)
            .collect(),
    }))
}

/// Open rotation jobs in vaults the caller can write to — what a client
/// should execute.
#[utoipa::path(get, path = "/api/v1/rotation/jobs", tag = "teams",
    responses((status = 200, body = RotationJobList)))]
pub async fn mine(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<RotationJobList>> {
    let jobs: Vec<JobRow> = sqlx::query_as(JOBS_FOR_USER)
        .bind(auth.user_id())
        .fetch_all(&state.db)
        .await?;
    Ok(Json(RotationJobList {
        jobs: jobs.into_iter().map(job).collect(),
    }))
}

/// Advance a job: `running` (claim), `done` or `failed` by a vault writer;
/// `cancelled` by `rotation.manage`. `done` also stamps the entity's
/// `secret_rotated_at` in case the client's push did not carry it.
#[utoipa::path(patch, path = "/api/v1/rotation/jobs/{id}", tag = "teams",
    params(("id" = Uuid, Path)), request_body = UpdateRotationJobRequest,
    responses((status = 200, body = RotationJob)))]
pub async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<UpdateRotationJobRequest>,
) -> ApiResult<Json<RotationJob>> {
    let row: Option<JobRow> = sqlx::query_as(JOBS_BY_ID)
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    let cur = job(row.ok_or_else(|| Error::not_found("Rotation job"))?);
    let status = req.status.as_str();
    if !STATUSES.contains(&status) || status == "pending" {
        return Err(Error::bad_request(
            "status must be running, done, failed or cancelled",
        ));
    }
    if matches!(cur.status.as_str(), "done" | "failed" | "cancelled") {
        return Err(Error::conflict("Rotation job already finished"));
    }
    if status == "cancelled" {
        crate::authz::require(&state, cur.team_id, auth.user_id(), "rotation.manage").await?;
    } else {
        vaults::require_write(&state, cur.vault_id, auth.user_id()).await?;
    }
    if status == "running" && cur.status == "running" && cur.claimed_by != Some(auth.user_id()) {
        return Err(Error::conflict(
            "Another member is already rotating this secret",
        ));
    }
    let error = req
        .error
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|e| e.chars().take(1000).collect::<String>());
    let finished = status != "running";
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE rotation_jobs SET status = $2, claimed_by = COALESCE(claimed_by, $3), error = $4,
                updated_at = now(), finished_at = CASE WHEN $5 THEN now() ELSE NULL END
         WHERE id = $1",
    )
    .bind(id)
    .bind(status)
    .bind(auth.user_id())
    .bind(&error)
    .bind(finished)
    .execute(&mut *tx)
    .await?;
    if status == "done" {
        sqlx::query(
            "UPDATE entities SET secret_rotated_at = GREATEST(COALESCE(secret_rotated_at, 'epoch'), now()) WHERE id = $1",
        )
        .bind(cur.entity_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    let action = match status {
        "done" => Some("rotation.completed"),
        "failed" => Some("rotation.failed"),
        "cancelled" => Some("rotation.cancelled"),
        _ => None,
    };
    if let Some(action) = action {
        audit::record(
            &state.db,
            audit::Entry::new(cur.team_id, &auth, action)
                .vault(cur.vault_id)
                .details(serde_json::json!({
                    "job_id": id, "entity_id": cur.entity_id, "kind": cur.entity_kind, "error": error,
                })),
        )
        .await;
    }
    let row: Option<JobRow> = sqlx::query_as(JOBS_BY_ID)
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    Ok(Json(job(
        row.ok_or_else(|| Error::not_found("Rotation job"))?
    )))
}

/// Drop a finished job from the list (`rotation.manage`).
#[utoipa::path(delete, path = "/api/v1/rotation/jobs/{id}", tag = "teams",
    params(("id" = Uuid, Path)), responses((status = 204)))]
pub async fn delete(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<NoContent> {
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT team_id, status FROM rotation_jobs WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let (team_id, status) = row.ok_or_else(|| Error::not_found("Rotation job"))?;
    crate::authz::require(&state, team_id, auth.user_id(), "rotation.manage").await?;
    if matches!(status.as_str(), "pending" | "running") {
        return Err(Error::conflict("Cancel the job before deleting it"));
    }
    sqlx::query("DELETE FROM rotation_jobs WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(NoContent)
}

/// Daily reminder: one `rotation.due` audit event (and so webhook) per team
/// that has overdue secrets, at most once per 24 h.
pub async fn run_reminders(state: AppState) {
    crate::jobs::exclusive(
        state,
        "rotation-reminders",
        std::time::Duration::from_secs(3600),
        reminder_pass,
    )
    .await
}

pub async fn reminder_pass(state: AppState) -> anyhow::Result<u64> {
    let teams: Vec<(Uuid, i32, i32)> = sqlx::query_as(
        "SELECT p.team_id, p.key_max_age_days, p.password_max_age_days FROM team_policies p
         WHERE (p.key_max_age_days > 0 OR p.password_max_age_days > 0)
           AND NOT EXISTS (SELECT 1 FROM team_audit_events e WHERE e.team_id = p.team_id
                           AND e.action = 'rotation.due' AND e.created_at > now() - interval '23 hours')",
    )
    .fetch_all(&state.db)
    .await?;
    let mut sent = 0;
    for (team_id, key_days, password_days) in teams {
        let due = due(&state.db, team_id, key_days, password_days).await?;
        if due.is_empty() {
            continue;
        }
        let keys = due
            .iter()
            .filter(|d| KEY_KINDS.contains(&d.kind.as_str()))
            .count();
        audit::record(
            &state.db,
            audit::Entry::system(team_id, "rotation.due").details(serde_json::json!({
                "overdue": due.len(), "keys": keys, "passwords": due.len() - keys,
                "oldest_days": due.first().map(|d| d.age_days),
            })),
        )
        .await;
        sent += 1;
    }
    Ok(sent)
}
