//! Team automations: scheduled snippet runs (`automations.manage` /
//! `automations.view` / `automations.run`).
//!
//! The server never sees snippet text or host addresses: it stores opaque
//! entity ids and the schedule, turns due schedules into `pending` runs, and
//! lets executors holding the vault key (API bridge, opted-in desktops)
//! claim, execute and report them. Failures become audit events (so
//! webhooks fire) and e-mail alerts.

use std::time::Duration as StdDuration;

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Duration, Utc};
use sqlx::PgExecutor;
use termoso_proto::automation::*;
use uuid::Uuid;

use crate::audit;
use crate::cron::{Schedule, parse_timezone};
use crate::error::{ApiResult, Error, NoContent};
use crate::extract::{Auth, Json as Body};
use crate::state::AppState;

pub const MANAGE: &str = "automations.manage";
pub const VIEW: &str = "automations.view";
pub const RUN: &str = "automations.run";
const TICK: StdDuration = StdDuration::from_secs(30);
const RUNS_LIMIT: i64 = 200;

#[derive(sqlx::FromRow)]
struct AutoRow {
    id: Uuid,
    team_id: Uuid,
    vault_id: Uuid,
    snippet_id: Uuid,
    name: String,
    host_ids: Vec<Uuid>,
    group_id: Option<Uuid>,
    schedule: String,
    timezone: String,
    enabled: bool,
    timeout_secs: i32,
    alert_on: String,
    alert_emails: Vec<String>,
    alert_admins: bool,
    last_run_at: Option<DateTime<Utc>>,
    last_status: Option<String>,
    next_run_at: Option<DateTime<Utc>>,
    created_by: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

macro_rules! select_auto {
    ($tail:literal) => {
        concat!(
            "SELECT id, team_id, vault_id, snippet_id, name, host_ids, group_id, schedule, timezone, enabled,
                timeout_secs, alert_on, alert_emails, alert_admins, last_run_at, last_status, next_run_at,
                created_by, created_at, updated_at
             FROM team_automations",
            $tail
        )
    };
}

fn to_auto(r: AutoRow) -> Automation {
    Automation {
        id: r.id,
        team_id: r.team_id,
        vault_id: r.vault_id,
        snippet_id: r.snippet_id,
        name: r.name,
        host_ids: r.host_ids,
        group_id: r.group_id,
        schedule: r.schedule,
        timezone: r.timezone,
        enabled: r.enabled,
        timeout_secs: r.timeout_secs,
        alert_on: r.alert_on,
        alert_emails: r.alert_emails,
        alert_admins: r.alert_admins,
        last_run_at: r.last_run_at,
        last_status: r.last_status,
        next_run_at: r.next_run_at,
        created_by: r.created_by,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

#[derive(sqlx::FromRow)]
struct RunRow {
    id: Uuid,
    automation_id: Uuid,
    team_id: Uuid,
    vault_id: Uuid,
    status: String,
    scheduled_for: DateTime<Utc>,
    manual: bool,
    claimed_by_device: Option<Uuid>,
    claimed_by_name: Option<String>,
    claimed_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    hosts_total: i32,
    hosts_failed: i32,
    outcomes: serde_json::Value,
    sealed: Option<String>,
    key_version: Option<i32>,
    error: Option<String>,
    created_at: DateTime<Utc>,
}

macro_rules! select_run {
    ($tail:literal) => {
        concat!(
            "SELECT r.id, r.automation_id, r.team_id, a.vault_id, r.status, r.scheduled_for, r.manual,
                r.claimed_by_device, d.name AS claimed_by_name, r.claimed_at, r.finished_at, r.hosts_total, r.hosts_failed,
                r.outcomes, r.sealed, r.key_version, r.error, r.created_at
             FROM team_automation_runs r
             JOIN team_automations a ON a.id = r.automation_id
             LEFT JOIN devices d ON d.id = r.claimed_by_device",
            $tail
        )
    };
}

fn to_run(r: RunRow) -> AutomationRun {
    AutomationRun {
        id: r.id,
        automation_id: r.automation_id,
        team_id: r.team_id,
        vault_id: r.vault_id,
        status: r.status,
        scheduled_for: r.scheduled_for,
        manual: r.manual,
        claimed_by_device: r.claimed_by_device,
        claimed_by_name: r.claimed_by_name,
        claimed_at: r.claimed_at,
        finished_at: r.finished_at,
        hosts_total: r.hosts_total,
        hosts_failed: r.hosts_failed,
        outcomes: serde_json::from_value(r.outcomes).unwrap_or_default(),
        sealed: r.sealed,
        key_version: r.key_version,
        results: Vec::new(),
        error: r.error,
        created_at: r.created_at,
    }
}

async fn load<'e, E: PgExecutor<'e>>(db: E, team_id: Uuid, id: Uuid) -> ApiResult<Automation> {
    let row: Option<AutoRow> = sqlx::query_as(select_auto!(" WHERE team_id = $1 AND id = $2"))
        .bind(team_id)
        .bind(id)
        .fetch_optional(db)
        .await?;
    row.map(to_auto)
        .ok_or_else(|| Error::not_found("automation"))
}

fn clean_name(name: &str) -> ApiResult<String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 80 {
        return Err(Error::bad_request("name must be 1–80 characters"));
    }
    Ok(n.to_string())
}

fn clean_schedule(expr: &str, tz: &str) -> ApiResult<(String, String, DateTime<Utc>)> {
    let expr = expr.trim();
    let s = Schedule::parse(expr).map_err(|e| Error::bad_request(format!("schedule: {e}")))?;
    let tz_name = if tz.trim().is_empty() {
        "UTC".to_string()
    } else {
        tz.trim().to_string()
    };
    let off = parse_timezone(&tz_name)
        .ok_or_else(|| Error::bad_request("timezone must be UTC or a fixed offset like +03:00"))?;
    let next = s
        .next_after(Utc::now(), off)
        .ok_or_else(|| Error::bad_request("schedule never fires"))?;
    Ok((expr.to_string(), tz_name, next))
}

fn clean_hosts(ids: &[Uuid]) -> ApiResult<Vec<Uuid>> {
    let mut out: Vec<Uuid> = Vec::with_capacity(ids.len());
    for id in ids {
        if !out.contains(id) {
            out.push(*id);
        }
    }
    if out.len() > HOSTS_MAX {
        return Err(Error::bad_request(format!("At most {HOSTS_MAX} hosts")));
    }
    Ok(out)
}

fn clean_timeout(t: i32) -> ApiResult<i32> {
    if (TIMEOUT_SECS_MIN..=TIMEOUT_SECS_MAX).contains(&t) {
        Ok(t)
    } else {
        Err(Error::bad_request(format!(
            "timeout_secs must be {TIMEOUT_SECS_MIN}..={TIMEOUT_SECS_MAX}"
        )))
    }
}

fn clean_alert_on(s: &str) -> ApiResult<String> {
    if ALERT_ON.contains(&s) {
        Ok(s.to_string())
    } else {
        Err(Error::bad_request(
            "alert_on must be never, failure or always",
        ))
    }
}

fn clean_emails(list: &[String]) -> ApiResult<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for e in list {
        let e = e.trim().to_ascii_lowercase();
        let ok = e.len() <= 254
            && e.split_once('@')
                .is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.ends_with('.'));
        if !ok {
            return Err(Error::bad_request(format!(
                "`{e}` is not an e-mail address"
            )));
        }
        if !out.contains(&e) {
            out.push(e);
        }
    }
    if out.len() > ALERT_EMAILS_MAX {
        return Err(Error::bad_request(format!(
            "At most {ALERT_EMAILS_MAX} alert recipients"
        )));
    }
    Ok(out)
}

async fn vault_in_team(state: &AppState, team_id: Uuid, vault_id: Uuid) -> ApiResult<()> {
    let ok: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM vaults WHERE id = $1 AND team_id = $2 AND kind = 'team'")
            .bind(vault_id)
            .bind(team_id)
            .fetch_optional(&state.db)
            .await?;
    ok.map(|_| ())
        .ok_or_else(|| Error::bad_request("vault_id is not a vault of this team"))
}

#[utoipa::path(get, path = "/api/v1/teams/{id}/automations", tag = "teams", params(("id" = Uuid, Path)),
    responses((status = 200, body = AutomationList)))]
pub async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<AutomationList>> {
    crate::authz::require(&state, id, auth.user_id(), VIEW).await?;
    let rows: Vec<AutoRow> = sqlx::query_as(select_auto!(
        " WHERE team_id = $1 ORDER BY name, created_at"
    ))
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(AutomationList {
        automations: rows.into_iter().map(to_auto).collect(),
    }))
}

#[utoipa::path(post, path = "/api/v1/teams/{id}/automations", tag = "teams", params(("id" = Uuid, Path)),
    request_body = CreateAutomationRequest, responses((status = 200, body = Automation)))]
pub async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<CreateAutomationRequest>,
) -> ApiResult<Json<Automation>> {
    crate::authz::require(&state, id, auth.user_id(), MANAGE).await?;
    vault_in_team(&state, id, req.vault_id).await?;
    let name = clean_name(&req.name)?;
    let (schedule, timezone, next) =
        clean_schedule(&req.schedule, req.timezone.as_deref().unwrap_or(""))?;
    let host_ids = clean_hosts(&req.host_ids)?;
    if host_ids.is_empty() && req.group_id.is_none() {
        return Err(Error::bad_request("Pick at least one host or a group"));
    }
    let timeout = clean_timeout(req.timeout_secs.unwrap_or(TIMEOUT_SECS_DEFAULT))?;
    let alert_on = clean_alert_on(req.alert_on.as_deref().unwrap_or("failure"))?;
    let emails = clean_emails(&req.alert_emails)?;
    let enabled = req.enabled.unwrap_or(true);
    let aid = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO team_automations (id, team_id, vault_id, snippet_id, name, host_ids, group_id, schedule,
            timezone, enabled, timeout_secs, alert_on, alert_emails, alert_admins, next_run_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
    )
    .bind(aid)
    .bind(id)
    .bind(req.vault_id)
    .bind(req.snippet_id)
    .bind(&name)
    .bind(&host_ids)
    .bind(req.group_id)
    .bind(&schedule)
    .bind(&timezone)
    .bind(enabled)
    .bind(timeout)
    .bind(&alert_on)
    .bind(&emails)
    .bind(req.alert_admins.unwrap_or(true))
    .bind(enabled.then_some(next))
    .bind(auth.user_id())
    .execute(&state.db)
    .await?;
    let a = load(&state.db, id, aid).await?;
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "automation.created")
            .vault(req.vault_id)
            .details(serde_json::json!({
                "automation_id": aid, "name": name, "schedule": schedule, "timezone": timezone,
                "hosts": host_ids.len(), "group": req.group_id.is_some(), "enabled": enabled,
            })),
    )
    .await;
    Ok(Json(a))
}

#[utoipa::path(get, path = "/api/v1/teams/{id}/automations/{aid}", tag = "teams",
    params(("id" = Uuid, Path), ("aid" = Uuid, Path)), responses((status = 200, body = Automation)))]
pub async fn get(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, aid)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<Automation>> {
    crate::authz::require(&state, id, auth.user_id(), VIEW).await?;
    Ok(Json(load(&state.db, id, aid).await?))
}

#[utoipa::path(put, path = "/api/v1/teams/{id}/automations/{aid}", tag = "teams",
    params(("id" = Uuid, Path), ("aid" = Uuid, Path)), request_body = UpdateAutomationRequest,
    responses((status = 200, body = Automation)))]
pub async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, aid)): Path<(Uuid, Uuid)>,
    Body(req): Body<UpdateAutomationRequest>,
) -> ApiResult<Json<Automation>> {
    crate::authz::require(&state, id, auth.user_id(), MANAGE).await?;
    let cur = load(&state.db, id, aid).await?;
    let name = match &req.name {
        Some(n) => clean_name(n)?,
        None => cur.name.clone(),
    };
    let tz = req.timezone.clone().unwrap_or(cur.timezone.clone());
    let (schedule, timezone, next) =
        clean_schedule(req.schedule.as_deref().unwrap_or(&cur.schedule), &tz)?;
    let host_ids = match &req.host_ids {
        Some(h) => clean_hosts(h)?,
        None => cur.host_ids.clone(),
    };
    let group_id = match req.group_id {
        Some(g) => g,
        None => cur.group_id,
    };
    if host_ids.is_empty() && group_id.is_none() {
        return Err(Error::bad_request("Pick at least one host or a group"));
    }
    let timeout = clean_timeout(req.timeout_secs.unwrap_or(cur.timeout_secs))?;
    let alert_on = clean_alert_on(req.alert_on.as_deref().unwrap_or(&cur.alert_on))?;
    let emails = match &req.alert_emails {
        Some(e) => clean_emails(e)?,
        None => cur.alert_emails.clone(),
    };
    let enabled = req.enabled.unwrap_or(cur.enabled);
    // Keep the pending slot when the schedule did not change and the
    // automation stays on; otherwise reschedule from now.
    let next_run = if !enabled {
        None
    } else if schedule == cur.schedule && timezone == cur.timezone && cur.enabled {
        cur.next_run_at.or(Some(next))
    } else {
        Some(next)
    };
    sqlx::query(
        "UPDATE team_automations SET snippet_id = $3, name = $4, host_ids = $5, group_id = $6, schedule = $7,
            timezone = $8, enabled = $9, timeout_secs = $10, alert_on = $11, alert_emails = $12,
            alert_admins = $13, next_run_at = $14, updated_at = now()
         WHERE team_id = $1 AND id = $2",
    )
    .bind(id)
    .bind(aid)
    .bind(req.snippet_id.unwrap_or(cur.snippet_id))
    .bind(&name)
    .bind(&host_ids)
    .bind(group_id)
    .bind(&schedule)
    .bind(&timezone)
    .bind(enabled)
    .bind(timeout)
    .bind(&alert_on)
    .bind(&emails)
    .bind(req.alert_admins.unwrap_or(cur.alert_admins))
    .bind(next_run)
    .execute(&state.db)
    .await?;
    if !enabled {
        sqlx::query(
            "UPDATE team_automation_runs SET status = 'cancelled', finished_at = now()
             WHERE automation_id = $1 AND status = 'pending'",
        )
        .bind(aid)
        .execute(&state.db)
        .await?;
    }
    let a = load(&state.db, id, aid).await?;
    audit::record(
        &state.db,
        audit::Entry::new(
            id,
            &auth,
            if enabled != cur.enabled && !enabled {
                "automation.paused"
            } else {
                "automation.updated"
            },
        )
        .vault(cur.vault_id)
        .details(serde_json::json!({
            "automation_id": aid, "name": name, "schedule": schedule, "timezone": timezone,
            "hosts": host_ids.len(), "group": group_id.is_some(), "enabled": enabled,
        })),
    )
    .await;
    Ok(Json(a))
}

#[utoipa::path(delete, path = "/api/v1/teams/{id}/automations/{aid}", tag = "teams",
    params(("id" = Uuid, Path), ("aid" = Uuid, Path)), responses((status = 204)))]
pub async fn delete(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, aid)): Path<(Uuid, Uuid)>,
) -> ApiResult<NoContent> {
    crate::authz::require(&state, id, auth.user_id(), MANAGE).await?;
    let cur = load(&state.db, id, aid).await?;
    sqlx::query("DELETE FROM team_automations WHERE team_id = $1 AND id = $2")
        .bind(id)
        .bind(aid)
        .execute(&state.db)
        .await?;
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "automation.deleted")
            .vault(cur.vault_id)
            .details(serde_json::json!({ "automation_id": aid, "name": cur.name })),
    )
    .await;
    Ok(NoContent)
}

/// Queue a run right away (an executor still has to pick it up).
#[utoipa::path(post, path = "/api/v1/teams/{id}/automations/{aid}/run", tag = "teams",
    params(("id" = Uuid, Path), ("aid" = Uuid, Path)), responses((status = 200, body = AutomationRun)))]
pub async fn run_now(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, aid)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<AutomationRun>> {
    crate::authz::require(&state, id, auth.user_id(), MANAGE).await?;
    let a = load(&state.db, id, aid).await?;
    let open: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM team_automation_runs WHERE automation_id = $1 AND status IN ('pending', 'running') LIMIT 1",
    )
    .bind(aid)
    .fetch_optional(&state.db)
    .await?;
    if open.is_some() {
        return Err(Error::conflict("A run is already pending or running"));
    }
    let rid = insert_run(&state.db, aid, id, Utc::now(), true).await?;
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "automation.run_requested")
            .vault(a.vault_id)
            .details(serde_json::json!({ "automation_id": aid, "run_id": rid, "name": a.name })),
    )
    .await;
    let row: RunRow = sqlx::query_as(select_run!(" WHERE r.id = $1"))
        .bind(rid)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(to_run(row)))
}

async fn insert_run<'e, E: PgExecutor<'e>>(
    db: E,
    automation_id: Uuid,
    team_id: Uuid,
    scheduled_for: DateTime<Utc>,
    manual: bool,
) -> ApiResult<Uuid> {
    let rid = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO team_automation_runs (id, automation_id, team_id, scheduled_for, manual)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(rid)
    .bind(automation_id)
    .bind(team_id)
    .bind(scheduled_for)
    .bind(manual)
    .execute(db)
    .await?;
    Ok(rid)
}

#[utoipa::path(get, path = "/api/v1/teams/{id}/automations/{aid}/runs", tag = "teams",
    params(("id" = Uuid, Path), ("aid" = Uuid, Path)), responses((status = 200, body = AutomationRunList)))]
pub async fn runs(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, aid)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<AutomationRunList>> {
    crate::authz::require(&state, id, auth.user_id(), VIEW).await?;
    load(&state.db, id, aid).await?;
    let rows: Vec<RunRow> = sqlx::query_as(select_run!(
        " WHERE r.automation_id = $1 ORDER BY r.created_at DESC LIMIT $2"
    ))
    .bind(aid)
    .bind(RUNS_LIMIT)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(AutomationRunList {
        runs: rows.into_iter().map(to_run).collect(),
    }))
}

#[utoipa::path(get, path = "/api/v1/teams/{id}/automations/runs/{rid}", tag = "teams",
    params(("id" = Uuid, Path), ("rid" = Uuid, Path)), responses((status = 200, body = AutomationRun)))]
pub async fn run(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, rid)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<AutomationRun>> {
    crate::authz::require(&state, id, auth.user_id(), VIEW).await?;
    let row: Option<RunRow> = sqlx::query_as(select_run!(" WHERE r.team_id = $1 AND r.id = $2"))
        .bind(id)
        .bind(rid)
        .fetch_optional(&state.db)
        .await?;
    Ok(Json(to_run(row.ok_or_else(|| Error::not_found("run"))?)))
}

/// Executors: take ownership of pending runs whose vault they can open.
#[utoipa::path(post, path = "/api/v1/teams/{id}/automations/runs/claim", tag = "teams",
    params(("id" = Uuid, Path)), request_body = ClaimRunsRequest, responses((status = 200, body = ClaimRunsResponse)))]
pub async fn claim(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<ClaimRunsRequest>,
) -> ApiResult<Json<ClaimRunsResponse>> {
    crate::authz::require(&state, id, auth.user_id(), RUN).await?;
    let limit = req.limit.unwrap_or(5).clamp(1, 20) as i64;
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "UPDATE team_automation_runs r SET status = 'running', claimed_by_device = $2, claimed_at = now()
         WHERE r.id IN (
             SELECT r2.id FROM team_automation_runs r2 JOIN team_automations a ON a.id = r2.automation_id
             WHERE r2.team_id = $1 AND r2.status = 'pending' AND a.enabled
               AND (cardinality($3::uuid[]) = 0 OR a.vault_id = ANY($3))
             ORDER BY r2.scheduled_for LIMIT $4 FOR UPDATE SKIP LOCKED)
         RETURNING r.id",
    )
    .bind(id)
    .bind(auth.device_id())
    .bind(&req.vault_ids)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (rid,) in rows {
        let run: RunRow = sqlx::query_as(select_run!(" WHERE r.id = $1"))
            .bind(rid)
            .fetch_one(&state.db)
            .await?;
        let run = to_run(run);
        let a = load(&state.db, id, run.automation_id).await?;
        out.push(ClaimedRun {
            run,
            vault_id: a.vault_id,
            snippet_id: a.snippet_id,
            host_ids: a.host_ids,
            group_id: a.group_id,
            timeout_secs: a.timeout_secs,
            name: a.name,
        });
    }
    Ok(Json(ClaimRunsResponse { runs: out }))
}

fn cap(s: &str) -> String {
    if s.len() <= OUTPUT_CAP {
        return s.to_string();
    }
    let mut end = OUTPUT_CAP;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n… [truncated]", &s[..end])
}

/// Executors: report the outcome of a run they claimed.
#[utoipa::path(patch, path = "/api/v1/teams/{id}/automations/runs/{rid}", tag = "teams",
    params(("id" = Uuid, Path), ("rid" = Uuid, Path)), request_body = FinishRunRequest,
    responses((status = 200, body = AutomationRun)))]
pub async fn finish(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, rid)): Path<(Uuid, Uuid)>,
    Body(req): Body<FinishRunRequest>,
) -> ApiResult<Json<AutomationRun>> {
    let m = crate::authz::require(&state, id, auth.user_id(), RUN).await?;
    let row: Option<RunRow> = sqlx::query_as(select_run!(" WHERE r.team_id = $1 AND r.id = $2"))
        .bind(id)
        .bind(rid)
        .fetch_optional(&state.db)
        .await?;
    let cur = to_run(row.ok_or_else(|| Error::not_found("run"))?);
    if cur.status != "running" {
        return Err(Error::conflict("Run is not running"));
    }
    if cur.claimed_by_device != Some(auth.device_id()) && !m.has(MANAGE) {
        return Err(Error::forbidden(
            "Only the device that claimed the run may finish it",
        ));
    }
    if req.sealed.as_ref().is_some_and(|s| s.len() > SEALED_CAP) {
        return Err(Error::bad_request("sealed results exceed the size limit"));
    }
    let total = req.outcomes.len() as i32;
    let failed = req.outcomes.iter().filter(|o| !o.ok).count() as i32;
    let status = if req.error.is_some() || failed > 0 || total == 0 {
        "failed"
    } else {
        "done"
    };
    let a = load(&state.db, id, cur.automation_id).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE team_automation_runs SET status = $2, finished_at = now(), hosts_total = $3, hosts_failed = $4,
            outcomes = $5, sealed = $6, key_version = $7, error = $8
         WHERE id = $1",
    )
    .bind(rid)
    .bind(status)
    .bind(total)
    .bind(failed)
    .bind(serde_json::to_value(&req.outcomes)?)
    .bind(&req.sealed)
    .bind(req.key_version)
    .bind(req.error.as_deref().map(cap))
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE team_automations SET last_run_at = now(), last_status = $2 WHERE id = $1")
        .bind(cur.automation_id)
        .bind(status)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit::record(
        &state.db,
        audit::Entry::new(
            id,
            &auth,
            if status == "done" {
                "automation.succeeded"
            } else {
                "automation.failed"
            },
        )
        .vault(a.vault_id)
        .details(serde_json::json!({
            "automation_id": a.id, "run_id": rid, "name": a.name,
            "hosts_total": total, "hosts_failed": failed, "error": req.error,
        })),
    )
    .await;
    metrics::counter!("termoso_automation_runs_total", "status" => status.to_string()).increment(1);
    let row: RunRow = sqlx::query_as(select_run!(" WHERE r.id = $1"))
        .bind(rid)
        .fetch_one(&state.db)
        .await?;
    let run = to_run(row);
    if a.alert_on == "always" || (a.alert_on == "failure" && status == "failed") {
        alert(&state, &a, &run).await;
    }
    Ok(Json(run))
}

/// E-mail the team admins and the extra recipients about a run.
async fn alert(state: &AppState, a: &Automation, run: &AutomationRun) {
    let Some(mailer) = &state.mailer else { return };
    let mut to: Vec<String> = a.alert_emails.clone();
    if a.alert_admins {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT u.email FROM team_members m JOIN users u ON u.id = m.user_id
             WHERE m.team_id = $1 AND m.role IN ('owner', 'admin') LIMIT 20",
        )
        .bind(a.team_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
        for (e,) in rows {
            if !to.contains(&e) {
                to.push(e);
            }
        }
    }
    let (team_name,): (String,) = sqlx::query_as("SELECT name FROM teams WHERE id = $1")
        .bind(a.team_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or_else(|_| (String::from("team"),));
    let url = format!(
        "{}/team?tab=automations",
        state.cfg.public_url.trim_end_matches('/')
    );
    let (subject, title) = match run.status.as_str() {
        "done" => (
            format!("Automation ran: {} ({team_name})", a.name),
            "Scheduled run finished".to_string(),
        ),
        "missed" => (
            format!("Automation missed: {} ({team_name})", a.name),
            "Nobody picked up a scheduled run".to_string(),
        ),
        _ => (
            format!("Automation failed: {} ({team_name})", a.name),
            "Scheduled run failed".to_string(),
        ),
    };
    let mut msg = crate::mail::Email::new(subject, title)
        .row("Automation", &a.name)
        .row("Team", &team_name)
        .row("Scheduled for", run.scheduled_for.to_rfc3339())
        .row("Status", &run.status);
    if run.status == "missed" {
        msg = msg.paragraph(
            "No executor (API bridge or a desktop with “run team automations” on) claimed the run within 15 minutes. Check that one is online and can open the vault.",
        );
    } else {
        // Only counts: which hosts and why is in the sealed results, which
        // the server cannot (and must not) read.
        msg = msg.row(
            "Hosts",
            format!("{} failed of {}", run.hosts_failed, run.hosts_total),
        );
        if let Some(e) = &run.error {
            msg = msg.paragraph(format!("Run error: {e}"));
        }
    }
    msg = msg.button("Open automations", &url);
    for rcpt in to {
        if let Err(e) = mailer.send(&rcpt, &msg).await {
            tracing::warn!(error = %e, "automation alert e-mail");
        }
    }
}

/// Background scheduler: due schedules become `pending` runs; `pending` runs
/// nobody claimed in time become `missed`.
pub async fn run_scheduler(state: AppState) {
    crate::jobs::exclusive(state, "automations", TICK, |s| async move {
        let n = tick(&s).await?;
        Ok(n)
    })
    .await
}

pub async fn tick(state: &AppState) -> anyhow::Result<u64> {
    let now = Utc::now();
    let due: Vec<(Uuid, Uuid, String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, team_id, schedule, timezone, next_run_at FROM team_automations
         WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= $1
         ORDER BY next_run_at LIMIT 500",
    )
    .bind(now)
    .fetch_all(&state.db)
    .await?;
    let mut n = 0u64;
    for (aid, team_id, schedule, tz, next_run_at) in due {
        let next = Schedule::parse(&schedule)
            .ok()
            .zip(parse_timezone(&tz))
            .and_then(|(s, off)| s.next_after(now, off));
        // Advance first so a crash between the two statements never
        // double-fires; a schedule that cannot be parsed any more is paused.
        let advanced = sqlx::query(
            "UPDATE team_automations SET next_run_at = $2, enabled = enabled AND $3
             WHERE id = $1 AND next_run_at = $4",
        )
        .bind(aid)
        .bind(next)
        .bind(next.is_some())
        .bind(next_run_at)
        .execute(&state.db)
        .await?
        .rows_affected();
        if advanced == 0 {
            continue;
        }
        let open: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM team_automation_runs WHERE automation_id = $1 AND status IN ('pending', 'running') LIMIT 1",
        )
        .bind(aid)
        .fetch_optional(&state.db)
        .await?;
        if open.is_some() {
            // Previous run still open: skip this slot rather than pile up.
            continue;
        }
        insert_run(&state.db, aid, team_id, next_run_at, false).await?;
        n += 1;
    }

    let missed: Vec<(Uuid, Uuid, Uuid)> = sqlx::query_as(
        "UPDATE team_automation_runs SET status = 'missed', finished_at = now()
         WHERE status = 'pending' AND created_at < $1
         RETURNING id, automation_id, team_id",
    )
    .bind(now - Duration::minutes(MISSED_AFTER_MINUTES))
    .fetch_all(&state.db)
    .await?;
    for (rid, aid, team_id) in missed {
        let Ok(a) = load(&state.db, team_id, aid).await else {
            continue;
        };
        sqlx::query(
            "UPDATE team_automations SET last_run_at = now(), last_status = 'missed' WHERE id = $1",
        )
        .bind(aid)
        .execute(&state.db)
        .await?;
        audit::record(
            &state.db,
            audit::Entry::system(team_id, "automation.missed")
                .vault(a.vault_id)
                .details(
                    serde_json::json!({ "automation_id": aid, "run_id": rid, "name": a.name }),
                ),
        )
        .await;
        if a.alert_on != "never" {
            let row: Result<RunRow, _> = sqlx::query_as(select_run!(" WHERE r.id = $1"))
                .bind(rid)
                .fetch_one(&state.db)
                .await;
            if let Ok(row) = row {
                alert(state, &a, &to_run(row)).await;
            }
        }
        n += 1;
    }
    Ok(n)
}
