//! Team activity log. Every team-scoped mutation records *who* did *what* to
//! *which* object; payloads are never inspected (they are ciphertext), so an
//! entity entry carries only its kind and id.

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::{PgExecutor, PgPool};
use termoso_proto::team::{AuditEvent, AuditEventList};
use uuid::Uuid;

use crate::error::{ApiResult, Error};
use crate::extract::Auth;
use crate::state::AppState;

const PAGE: usize = 100;
const MAX_PAGE: usize = 500;

/// A pending log entry; `record` writes it.
#[derive(Debug, Clone)]
pub struct Entry {
    pub team_id: Uuid,
    pub actor: Option<(Uuid, Uuid)>,
    pub action: &'static str,
    pub vault_id: Option<Uuid>,
    pub target_user: Option<Uuid>,
    pub details: serde_json::Value,
}

impl Entry {
    pub fn new(team_id: Uuid, auth: &Auth, action: &'static str) -> Self {
        Self {
            team_id,
            actor: Some((auth.user_id(), auth.device_id())),
            action,
            vault_id: None,
            target_user: None,
            details: serde_json::json!({}),
        }
    }

    /// Same as `new` for code paths without an `Auth` (registration with an
    /// invite token, relay cleanup).
    /// An entry without an actor (background jobs).
    pub fn system(team_id: Uuid, action: &'static str) -> Self {
        Self {
            team_id,
            actor: None,
            action,
            vault_id: None,
            target_user: None,
            details: serde_json::Value::Object(Default::default()),
        }
    }

    pub fn by(team_id: Uuid, user_id: Uuid, device_id: Option<Uuid>, action: &'static str) -> Self {
        Self {
            team_id,
            actor: Some((user_id, device_id.unwrap_or(Uuid::nil()))),
            action,
            vault_id: None,
            target_user: None,
            details: serde_json::json!({}),
        }
    }

    pub fn vault(mut self, vault_id: Uuid) -> Self {
        self.vault_id = Some(vault_id);
        self
    }

    pub fn user(mut self, user_id: Uuid) -> Self {
        self.target_user = Some(user_id);
        self
    }

    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

/// Insert one entry. Failures are logged, never propagated: the audit trail
/// must not turn a successful mutation into an error for the caller.
/// Mirror every event to the log as JSON (`TERMOSO_AUDIT_SINK=true`).
static SINK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn enable_sink(on: bool) {
    SINK.store(on, std::sync::atomic::Ordering::Relaxed);
}

pub async fn record<'e, E: PgExecutor<'e>>(db: E, e: Entry) {
    let (actor_id, device_id) = match e.actor {
        Some((u, d)) => (Some(u), (!d.is_nil()).then_some(d)),
        None => (None, None),
    };
    // One statement: the event plus an outbox row for every enabled webhook
    // of the team whose filter matches the action.
    let res = sqlx::query(
        "WITH ev AS (
             INSERT INTO team_audit_events (team_id, actor_id, device_id, action, vault_id, target_user, details)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, team_id, action)
         INSERT INTO audit_deliveries (webhook_id, event_id)
         SELECT w.id, ev.id FROM ev JOIN team_webhooks w ON w.team_id = ev.team_id AND w.enabled
         WHERE w.actions IS NULL OR ev.action = ANY(w.actions)
            OR EXISTS (SELECT 1 FROM unnest(w.actions) a WHERE right(a, 1) = '.' AND ev.action LIKE a || '%')",
    )
    .bind(e.team_id)
    .bind(actor_id)
    .bind(device_id)
    .bind(e.action)
    .bind(e.vault_id)
    .bind(e.target_user)
    .bind(&e.details)
    .execute(db)
    .await;
    match res {
        Ok(_) => {
            metrics::counter!("termoso_team_audit_events_total", "action" => e.action).increment(1);
            if SINK.load(std::sync::atomic::Ordering::Relaxed) {
                let line = serde_json::json!({
                    "ts": chrono::Utc::now(), "team_id": e.team_id, "actor_id": actor_id,
                    "device_id": device_id, "action": e.action, "vault_id": e.vault_id,
                    "target_user": e.target_user, "details": e.details,
                });
                tracing::info!(target: "termoso_audit", event = %line);
            }
        }
        Err(err) => tracing::warn!(error = %err, action = e.action, "could not write audit event"),
    }
}

/// Team of a vault (`None` for personal vaults, which are not audited).
pub async fn team_of_vault<'e, E: PgExecutor<'e>>(db: E, vault_id: Uuid) -> Option<Uuid> {
    sqlx::query_as::<_, (Option<Uuid>,)>("SELECT team_id FROM vaults WHERE id = $1")
        .bind(vault_id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .and_then(|(t,)| t)
}

/// Drop entries older than the configured retention (called opportunistically
/// from the list endpoint so no background job is needed).
async fn purge(state: &AppState, team_id: Uuid, days: u32) -> ApiResult<()> {
    if days == 0 {
        return Ok(());
    }
    sqlx::query(
        "WITH doomed AS (
             SELECT id, team_id, hash FROM team_audit_events
             WHERE team_id = $1 AND created_at < now() - make_interval(days => $2)),
         anchor AS (
             INSERT INTO audit_checkpoints (team_id, kind, last_id, hash)
             SELECT team_id, 'retention', id, hash FROM doomed WHERE hash IS NOT NULL
             ORDER BY id DESC LIMIT 1)
         DELETE FROM team_audit_events WHERE id IN (SELECT id FROM doomed)",
    )
    .bind(team_id)
    .bind(days as i32)
    .execute(&state.db)
    .await?;
    Ok(())
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct AuditQuery {
    /// Return entries with `id < before` (older page).
    pub before: Option<i64>,
    /// Page size (default 100, max 500).
    pub limit: Option<u32>,
    /// Only this action (exact) or action family (`vault.` prefix).
    pub action: Option<String>,
    /// Only this actor.
    pub actor: Option<Uuid>,
    /// Only this vault.
    pub vault: Option<Uuid>,
}

type Row = (
    i64,
    Uuid,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    String,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    serde_json::Value,
    DateTime<Utc>,
    Option<String>,
    Option<String>,
);

/// Team admins see everything; members see the log too (the whole point is
/// that the software reports *to* the team, not on it) but not other members'
/// device ids.
#[utoipa::path(get, path = "/api/v1/teams/{id}/audit", tag = "teams",
    params(("id" = Uuid, Path), AuditQuery), responses((status = 200, body = AuditEventList)))]
pub async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<AuditEventList>> {
    let role = crate::authz::require(&state, team_id, auth.user_id(), "audit.view").await?;
    let retention = state.settings().await?.audit_retention_days;
    purge(&state, team_id, retention).await?;
    let limit = q
        .limit
        .map(|l| l as usize)
        .unwrap_or(PAGE)
        .clamp(1, MAX_PAGE);
    let action_exact = q.action.as_deref().filter(|a| !a.ends_with('.'));
    let action_prefix = q
        .action
        .as_deref()
        .filter(|a| a.ends_with('.'))
        .map(|a| format!("{a}%"));
    if q.action.as_deref().is_some_and(|a| a.len() > 64) {
        return Err(Error::bad_request("action filter too long"));
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT e.id, e.team_id, e.actor_id, a.email, a.display_name, a.avatar_tag, e.device_id, e.action,
                e.vault_id, e.target_user, t.email, e.details, e.created_at,
                encode(e.hash, 'hex'), encode(e.prev_hash, 'hex')
         FROM team_audit_events e
         LEFT JOIN users a ON a.id = e.actor_id
         LEFT JOIN users t ON t.id = e.target_user
         WHERE e.team_id = $1
           AND ($2::bigint IS NULL OR e.id < $2)
           AND ($3::text IS NULL OR e.action = $3)
           AND ($4::text IS NULL OR e.action LIKE $4)
           AND ($5::uuid IS NULL OR e.actor_id = $5)
           AND ($6::uuid IS NULL OR e.vault_id = $6)
         ORDER BY e.id DESC LIMIT $7",
    )
    .bind(team_id)
    .bind(q.before)
    .bind(action_exact)
    .bind(action_prefix)
    .bind(q.actor)
    .bind(q.vault)
    .bind((limit + 1) as i64)
    .fetch_all(&state.db)
    .await?;
    let has_more = rows.len() > limit;
    let me = auth.user_id();
    let events: Vec<AuditEvent> = rows
        .into_iter()
        .take(limit)
        .map(
            |(
                id,
                team_id,
                actor_id,
                actor_email,
                actor_name,
                actor_avatar,
                device_id,
                action,
                vault_id,
                target_user,
                target_email,
                details,
                created_at,
                hash,
                prev_hash,
            )| AuditEvent {
                id,
                team_id,
                actor_id,
                actor_email,
                actor_name,
                actor_avatar,
                device_id: device_id.filter(|_| role.has("audit.view_ips") || actor_id == Some(me)),
                action,
                vault_id,
                target_user,
                target_email,
                details,
                created_at,
                hash,
                prev_hash,
            },
        )
        .collect();
    let next_before = if has_more {
        events.last().map(|e| e.id)
    } else {
        None
    };
    Ok(Json(AuditEventList {
        events,
        next_before,
    }))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ExportQuery {
    /// Oldest event to include (inclusive).
    pub from: Option<DateTime<Utc>>,
    /// Newest event to include (exclusive).
    pub to: Option<DateTime<Utc>>,
    /// Only this action (exact) or family (`vault.` prefix).
    pub action: Option<String>,
    /// Only this actor.
    pub actor: Option<Uuid>,
    /// Only this vault.
    pub vault: Option<Uuid>,
    /// `csv` (default) or `jsonl`.
    pub format: Option<String>,
}

const EXPORT_PAGE: i64 = 1000;
const EXPORT_MAX_ROWS: usize = 1_000_000;
const CSV_HEADER: &str = "\u{feff}id,created_at,team_id,action,actor_id,actor_email,actor_name,device_id,vault_id,target_user,target_email,details,hash,prev_hash\n";

fn csv_field(v: &str) -> String {
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

fn csv_line(e: &AuditEvent) -> String {
    let o = |v: &Option<String>| csv_field(v.as_deref().unwrap_or(""));
    let u = |v: &Option<Uuid>| v.map(|x| x.to_string()).unwrap_or_default();
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
        e.id,
        e.created_at.to_rfc3339(),
        e.team_id,
        csv_field(&e.action),
        u(&e.actor_id),
        o(&e.actor_email),
        o(&e.actor_name),
        u(&e.device_id),
        u(&e.vault_id),
        u(&e.target_user),
        o(&e.target_email),
        csv_field(&e.details.to_string()),
        o(&e.hash),
        o(&e.prev_hash),
    )
}

struct ExportCursor {
    after: i64,
    rows: usize,
    done: bool,
    header: bool,
}

/// `GET /teams/{id}/audit/export` — the log (within the filters) as a streamed
/// CSV or JSONL download; `audit.export`, 10 exports per hour per team.
#[utoipa::path(get, path = "/api/v1/teams/{id}/audit/export", tag = "teams",
    params(("id" = Uuid, Path), ExportQuery), responses((status = 200, description = "CSV or JSONL stream")))]
pub async fn export(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
    Query(q): Query<ExportQuery>,
) -> ApiResult<axum::response::Response> {
    let role = crate::authz::require(&state, team_id, auth.user_id(), "audit.export").await?;
    crate::ratelimit::check(&state, crate::ratelimit::AUDIT_EXPORT, &team_id.to_string()).await?;
    let jsonl = match q.format.as_deref().unwrap_or("csv") {
        "csv" => false,
        "jsonl" => true,
        _ => return Err(Error::bad_request("format must be csv or jsonl")),
    };
    let see_devices = role.has("audit.view_ips");
    let me = auth.user_id();
    let (exact, prefix) = match q.action.as_deref().map(str::trim) {
        None | Some("") => (None, None),
        Some(a) if a.ends_with('.') => (None, Some(format!("{a}%"))),
        Some(a) => (Some(a.to_string()), None),
    };
    record(
        &state.db,
        Entry::new(team_id, &auth, "audit.exported").details(serde_json::json!({
            "from": q.from, "to": q.to, "action": q.action, "format": if jsonl { "jsonl" } else { "csv" }
        })),
    )
    .await;
    let db = state.db.clone();
    let init = ExportCursor {
        after: 0,
        rows: 0,
        done: false,
        header: !jsonl,
    };
    let (from, to, actor, vault) = (q.from, q.to, q.actor, q.vault);
    let stream = futures::stream::unfold(init, move |mut c| {
        let db = db.clone();
        let (exact, prefix) = (exact.clone(), prefix.clone());
        async move {
            if c.header {
                c.header = false;
                return Some((
                    Ok::<_, std::io::Error>(bytes::Bytes::from_static(CSV_HEADER.as_bytes())),
                    c,
                ));
            }
            if c.done {
                return None;
            }
            let remaining = EXPORT_MAX_ROWS.saturating_sub(c.rows);
            if remaining == 0 {
                return None;
            }
            let page: Vec<Row> = match sqlx::query_as(
                "SELECT e.id, e.team_id, e.actor_id, a.email, a.display_name, a.avatar_tag, e.device_id, e.action,
                        e.vault_id, e.target_user, t.email, e.details, e.created_at,
                encode(e.hash, 'hex'), encode(e.prev_hash, 'hex')
                 FROM team_audit_events e
                 LEFT JOIN users a ON a.id = e.actor_id
                 LEFT JOIN users t ON t.id = e.target_user
                 WHERE e.team_id = $1 AND e.id > $2
                   AND ($3::timestamptz IS NULL OR e.created_at >= $3)
                   AND ($4::timestamptz IS NULL OR e.created_at < $4)
                   AND ($5::text IS NULL OR e.action = $5)
                   AND ($6::text IS NULL OR e.action LIKE $6)
                   AND ($7::uuid IS NULL OR e.actor_id = $7)
                   AND ($8::uuid IS NULL OR e.vault_id = $8)
                 ORDER BY e.id ASC LIMIT $9",
            )
            .bind(team_id)
            .bind(c.after)
            .bind(from)
            .bind(to)
            .bind(&exact)
            .bind(&prefix)
            .bind(actor)
            .bind(vault)
            .bind((remaining as i64).min(EXPORT_PAGE))
            .fetch_all(&db)
            .await
            {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "audit export page failed");
                    c.done = true;
                    return Some((Err(std::io::Error::other(e.to_string())), c));
                }
            };
            if page.is_empty() {
                return None;
            }
            c.after = page.last().map(|r| r.0).unwrap_or(c.after);
            c.rows += page.len();
            let mut out = String::new();
            for (
                id,
                team_id,
                actor_id,
                actor_email,
                actor_name,
                actor_avatar,
                device_id,
                action,
                vault_id,
                target_user,
                target_email,
                details,
                created_at,
                hash,
                prev_hash,
            ) in page
            {
                let ev = AuditEvent {
                    id,
                    team_id,
                    actor_id,
                    actor_email,
                    actor_name,
                    actor_avatar,
                    device_id: device_id.filter(|_| see_devices || actor_id == Some(me)),
                    action,
                    vault_id,
                    target_user,
                    target_email,
                    details,
                    created_at,
                    hash,
                    prev_hash,
                };
                if jsonl {
                    out.push_str(&serde_json::to_string(&ev).unwrap_or_default());
                    out.push('\n');
                } else {
                    out.push_str(&csv_line(&ev));
                }
            }
            Some((Ok(bytes::Bytes::from(out)), c))
        }
    });
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let (ctype, ext) = if jsonl {
        ("application/x-ndjson; charset=utf-8", "jsonl")
    } else {
        ("text/csv; charset=utf-8", "csv")
    };
    let resp = axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, ctype)
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"termoso-audit-{team_id}-{stamp}.{ext}\""),
        )
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        // hyper may poll the body once more after the final chunk; a bare
        // `unfold` panics on that, which killed the response mid-stream.
        .body(axum::body::Body::from_stream(futures::StreamExt::fuse(
            stream,
        )))
        .map_err(|e| anyhow::anyhow!("response: {e}"))?;
    Ok(resp)
}

/// Retention: every 6 hours delete events older than each team's
/// `audit_retention_days`, 10k rows per statement.
pub async fn run_retention(state: AppState) {
    crate::jobs::exclusive(
        state,
        "audit-retention",
        std::time::Duration::from_secs(6 * 3600),
        |s| async move { retention_pass(&s.db).await },
    )
    .await
}

pub async fn retention_pass(db: &PgPool) -> anyhow::Result<u64> {
    let mut total = 0u64;
    loop {
        let n = sqlx::query(
            "WITH doomed AS (
                 SELECT e.id, e.team_id, e.hash FROM team_audit_events e
                 JOIN team_policies p ON p.team_id = e.team_id
                 WHERE e.created_at < now() - make_interval(days => p.audit_retention_days)
                 ORDER BY e.id LIMIT 10000),
             anchor AS (
                 INSERT INTO audit_checkpoints (team_id, kind, last_id, hash)
                 SELECT DISTINCT ON (team_id) team_id, 'retention', id, hash FROM doomed
                 WHERE hash IS NOT NULL ORDER BY team_id, id DESC)
             DELETE FROM team_audit_events WHERE id IN (SELECT id FROM doomed)",
        )
        .execute(db)
        .await?
        .rows_affected();
        total += n;
        if n < 10000 {
            return Ok(total);
        }
    }
}
