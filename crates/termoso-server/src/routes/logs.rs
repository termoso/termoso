//! Session logs: metadata in Postgres, encrypted recordings in S3 via
//! pre-signed URLs (the server never proxies log bytes).
//!
//! Every log belongs to the vault whose key encrypts it. In a team vault the
//! recording is therefore readable by everyone holding the vault key, and the
//! server lets those members list and download it; pins and notes are shared
//! team state, while the encrypted metadata and body stay author-controlled.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::AssertSqlSafe;
use termoso_crypto::encoding::unb64;
use termoso_proto::logs::*;
use termoso_proto::sync::MAX_BATCH;
use termoso_proto::vault::VaultKind;
use uuid::Uuid;

use crate::audit;
use crate::error::{ApiResult, Error, NoContent};
use crate::events::{self, Event};
use crate::extract::{Auth, Json as Body};
use crate::ratelimit;
use crate::routes::vaults::{self, Access};
use crate::state::AppState;
use crate::storage::Storage;

#[derive(sqlx::FromRow)]
struct Row {
    id: Uuid,
    user_id: Uuid,
    vault_id: Uuid,
    meta: String,
    key_version: i32,
    size_bytes: i64,
    completed: bool,
    created_at: DateTime<Utc>,
    seq: i64,
    vault_seq: i64,
    deleted: bool,
    pinned: bool,
    note: String,
    note_by: Option<Uuid>,
    email: String,
    display_name: Option<String>,
    avatar_tag: Option<String>,
    team: bool,
}

/// One row plus the bits only the server needs.
struct Stored {
    log: SessionLog,
    vault_seq: i64,
    team: bool,
}

fn stored(r: Row) -> Stored {
    let Row {
        id,
        user_id,
        vault_id,
        meta,
        key_version,
        size_bytes,
        completed,
        created_at,
        seq,
        vault_seq,
        deleted,
        pinned,
        note,
        note_by,
        email,
        display_name,
        avatar_tag,
        team,
    } = r;
    let author = (!deleted).then_some(LogAuthor {
        user_id,
        email,
        display_name,
        avatar_tag,
    });
    Stored {
        log: SessionLog {
            id,
            vault_id,
            user_id,
            author,
            meta,
            key_version,
            size_bytes,
            completed,
            created_at,
            seq,
            deleted,
            pinned,
            note,
            note_by,
        },
        vault_seq,
        team,
    }
}

/// Which counter a listing is paged by.
#[derive(Clone, Copy)]
enum Cursor {
    Author,
    Vault,
}

fn to_log(r: Row, cursor: Cursor) -> SessionLog {
    let s = stored(r);
    match cursor {
        Cursor::Author => s.log,
        Cursor::Vault => SessionLog {
            seq: s.vault_seq,
            ..s.log
        },
    }
}

const SELECT: &str =
    "SELECT s.id, s.user_id, s.vault_id, s.meta, s.key_version, s.size_bytes, s.completed,
        s.created_at, s.seq, s.vault_seq, s.deleted, s.pinned, s.note, s.note_by,
        u.email, u.display_name, u.avatar_tag, v.kind = 'team' AS team
    FROM session_logs s JOIN users u ON u.id = s.user_id JOIN vaults v ON v.id = s.vault_id";

const RETURNING: &str = "RETURNING id, user_id, vault_id, meta, key_version, size_bytes, completed,
        created_at, seq, vault_seq, deleted, pinned, note, note_by";

fn storage(state: &AppState) -> ApiResult<&Storage> {
    state
        .storage
        .as_ref()
        .ok_or_else(|| Error::feature_disabled("Session logs (object storage)"))
}

fn object_key(user_id: Uuid, id: Uuid) -> String {
    format!("logs/{user_id}/{id}.bin")
}

/// Advance both counters a change is published under: the author's (for
/// `GET /logs`) and the vault's (for `GET /vaults/{id}/logs`).
async fn next_seqs(
    tx: &mut sqlx::PgConnection,
    user_id: Uuid,
    vault_id: Uuid,
) -> ApiResult<(i64, i64)> {
    let (seq,): (i64,) =
        sqlx::query_as("UPDATE users SET logs_seq = logs_seq + 1 WHERE id = $1 RETURNING logs_seq")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    let (vseq,): (i64,) = sqlx::query_as(
        "UPDATE vaults SET logs_seq = logs_seq + 1 WHERE id = $1 RETURNING logs_seq",
    )
    .bind(vault_id)
    .fetch_one(&mut *tx)
    .await?;
    Ok((seq, vseq))
}

async fn notify(state: &AppState, s: &Stored) -> ApiResult<()> {
    events::publish(
        state,
        Event::LogsChanged {
            user_id: s.log.user_id,
            seq: s.log.seq,
        },
    )
    .await?;
    if s.team {
        events::publish(
            state,
            Event::VaultLogsChanged {
                vault_id: s.log.vault_id,
                seq: s.vault_seq,
            },
        )
        .await?;
    }
    Ok(())
}

async fn load(state: &AppState, id: Uuid) -> ApiResult<Stored> {
    let row: Option<Row> = sqlx::query_as(AssertSqlSafe(format!("{SELECT} WHERE s.id = $1")))
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    row.map(stored).ok_or_else(|| Error::not_found("Log"))
}

/// What the caller may do with a log: the author owns it outright; other
/// members of a team vault act through their vault role.
struct Grant {
    stored: Stored,
    owner: bool,
    access: Option<Access>,
}

impl Grant {
    fn can_write(&self) -> bool {
        self.owner || self.access.as_ref().is_some_and(|a| a.role.can_write())
    }
    fn can_manage(&self) -> bool {
        self.owner || self.access.as_ref().is_some_and(|a| a.role.can_manage())
    }
    fn team_id(&self) -> Option<Uuid> {
        self.access.as_ref().and_then(|a| a.team_id)
    }
}

/// Load a log the caller may at least read. Teammates need a sealed vault key
/// (a pending member could not decrypt anything anyway); anyone else gets the
/// same 404 as for a log that does not exist.
async fn readable(state: &AppState, auth: &Auth, id: Uuid) -> ApiResult<Grant> {
    let s = load(state, id).await?;
    let owner = s.log.user_id == auth.user_id();
    let access = match vaults::access(&state.db, s.log.vault_id, auth.user_id()).await {
        Ok(a) => Some(a),
        Err(Error::Status(StatusCode::NOT_FOUND, ..)) if owner => None,
        Err(e) => return Err(e),
    };
    let teammate = access
        .as_ref()
        .is_some_and(|a| a.kind == VaultKind::Team && !a.pending);
    if !owner && !teammate {
        return Err(Error::not_found("Log"));
    }
    Ok(Grant {
        stored: s,
        owner,
        access,
    })
}

fn validate_meta(meta: &str, max: usize) -> ApiResult<()> {
    if meta.len() > max || unb64(meta).is_err() {
        return Err(Error::too_large("Log metadata too large"));
    }
    Ok(())
}

fn clean_note(note: &str) -> ApiResult<String> {
    let note = note.trim();
    if note.chars().count() > MAX_NOTE_CHARS {
        return Err(Error::too_large(format!(
            "Notes are limited to {MAX_NOTE_CHARS} characters"
        )));
    }
    if note
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(Error::bad_request("Note contains control characters"));
    }
    Ok(note.to_owned())
}

#[utoipa::path(post, path = "/api/v1/logs", tag = "logs",
    request_body = CreateLogRequest, responses((status = 200, body = CreateLogResponse)))]
pub async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Body(req): Body<CreateLogRequest>,
) -> ApiResult<Json<CreateLogResponse>> {
    let storage = storage(&state)?;
    ratelimit::check(&state, ratelimit::SYNC_PUSH, &auth.user_id().to_string()).await?;
    let settings = state.settings().await?;
    validate_meta(&req.meta, settings.max_entity_bytes as usize)?;
    let max_log = settings.max_log_bytes as i64;
    if req.size_bytes <= 0 || req.size_bytes > max_log {
        return Err(Error::too_large(format!(
            "Logs are limited to {max_log} bytes"
        )));
    }
    let a = vaults::require_write(&state, req.vault_id, auth.user_id()).await?;
    if a.key_version != req.key_version {
        return Err(Error::conflict("Stale vault key version"));
    }
    let (used,): (i64,) = sqlx::query_as("SELECT COALESCE(sum(size_bytes), 0)::bigint FROM session_logs WHERE user_id = $1 AND deleted = false")
        .bind(auth.user_id())
        .fetch_one(&state.db)
        .await?;
    let quota = settings.log_quota_bytes as i64;
    if quota > 0 && used + req.size_bytes > quota {
        return Err(Error::quota_exceeded("Session log storage quota exceeded"));
    }
    let key = object_key(auth.user_id(), req.id);
    let mut tx = state.db.begin().await?;
    let (seq, vseq) = next_seqs(&mut tx, auth.user_id(), req.vault_id).await?;
    let inserted = sqlx::query(
        "INSERT INTO session_logs (id, user_id, vault_id, object_key, meta, key_version, size_bytes, completed, seq, vault_seq)
         VALUES ($1, $2, $3, $4, $5, $6, $7, false, $8, $9) ON CONFLICT (id) DO NOTHING",
    )
    .bind(req.id)
    .bind(auth.user_id())
    .bind(req.vault_id)
    .bind(&key)
    .bind(&req.meta)
    .bind(req.key_version)
    .bind(req.size_bytes)
    .bind(seq)
    .bind(vseq)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(Error::conflict("Log already exists"));
    }
    tx.commit().await?;
    let p = storage
        .presign_put(&key, req.size_bytes)
        .await
        .map_err(|e| Error::Internal(e.context("presigning upload")))?;
    Ok(Json(CreateLogResponse {
        upload_url: p.url,
        upload_headers: p.headers,
        expires_in: p.expires_in,
    }))
}

#[utoipa::path(patch, path = "/api/v1/logs/{id}", tag = "logs", params(("id" = Uuid, Path)),
    request_body = UpdateLogRequest, responses((status = 200, body = SessionLog)))]
pub async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<UpdateLogRequest>,
) -> ApiResult<Json<SessionLog>> {
    let grant = readable(&state, &auth, id).await?;
    let log = &grant.stored.log;
    if log.deleted {
        return Err(Error::not_found("Log"));
    }
    if (req.meta.is_some() || req.size_bytes.is_some()) && !grant.owner {
        return Err(Error::forbidden("Only the author can change a recording"));
    }
    if (req.pinned.is_some() || req.note.is_some()) && !grant.can_write() {
        return Err(Error::forbidden("Editor role required to pin or annotate"));
    }
    let settings = state.settings().await?;
    if let Some(m) = &req.meta {
        validate_meta(m, settings.max_entity_bytes as usize)?;
    }
    let note = req.note.as_deref().map(clean_note).transpose()?;
    let mut size = log.size_bytes;
    let mut completed = log.completed;
    if let Some(declared) = req.size_bytes {
        let storage = storage(&state)?;
        let key = object_key(log.user_id, id);
        let actual = storage
            .object_size(&key)
            .await
            .map_err(|e| Error::Internal(e.context("checking object")))?;
        let Some(actual) = actual else {
            return Err(Error::bad_request("Upload not found in storage"));
        };
        if actual != declared {
            return Err(Error::bad_request(
                "Declared size does not match the uploaded object",
            ));
        }
        if actual > settings.max_log_bytes as i64 {
            storage.delete(&key).await.ok();
            return Err(Error::too_large("Uploaded object exceeds the limit"));
        }
        size = actual;
        completed = true;
    }
    let pinned = req.pinned.unwrap_or(log.pinned);
    let note_by = match &note {
        Some(n) if n.is_empty() => None,
        Some(_) => Some(auth.user_id()),
        None => log.note_by,
    };
    let mut tx = state.db.begin().await?;
    let (seq, vseq) = next_seqs(&mut tx, log.user_id, log.vault_id).await?;
    let row: Row = sqlx::query_as(AssertSqlSafe(format!(
        "WITH upd AS (UPDATE session_logs SET meta = COALESCE($2, meta), size_bytes = $3, completed = $4,
                seq = $5, vault_seq = $6, pinned = $7, note = COALESCE($8, note), note_by = $9
             WHERE id = $1 {RETURNING})
         {SELECT_FROM_UPD}"
    )))
    .bind(id)
    .bind(&req.meta)
    .bind(size)
    .bind(completed)
    .bind(seq)
    .bind(vseq)
    .bind(pinned)
    .bind(&note)
    .bind(note_by)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let updated = stored(row);
    if let Some(team_id) = grant.team_id() {
        let mut changes = Vec::new();
        if let Some(p) = req.pinned.filter(|p| *p != log.pinned) {
            changes.push(if p { "pinned" } else { "unpinned" });
        }
        if note.as_deref().is_some_and(|n| n != log.note) {
            changes.push("note");
        }
        if !changes.is_empty() {
            audit::record(
                &state.db,
                audit::Entry::new(team_id, &auth, "log.updated")
                    .vault(log.vault_id)
                    .details(serde_json::json!({
                        "log_id": id,
                        "author_id": log.user_id,
                        "changes": changes,
                    })),
            )
            .await;
        }
    }
    notify(&state, &updated).await?;
    if completed && !log.completed {
        metrics::counter!("termoso_logs_uploaded_total").increment(1);
        metrics::counter!("termoso_logs_uploaded_bytes_total").increment(size as u64);
    }
    Ok(Json(updated.log))
}

/// Re-select the updated row with its author/vault columns.
const SELECT_FROM_UPD: &str =
    "SELECT s.id, s.user_id, s.vault_id, s.meta, s.key_version, s.size_bytes, s.completed,
        s.created_at, s.seq, s.vault_seq, s.deleted, s.pinned, s.note, s.note_by,
        u.email, u.display_name, u.avatar_tag, v.kind = 'team' AS team
    FROM upd s JOIN users u ON u.id = s.user_id JOIN vaults v ON v.id = s.vault_id";

#[utoipa::path(get, path = "/api/v1/logs/{id}/download", tag = "logs", params(("id" = Uuid, Path)),
    responses((status = 200, body = DownloadLogResponse)))]
pub async fn download(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<DownloadLogResponse>> {
    let storage = storage(&state)?;
    let grant = readable(&state, &auth, id).await?;
    let log = &grant.stored.log;
    if log.deleted || !log.completed {
        return Err(Error::not_found("Log"));
    }
    let p = storage
        .presign_get(&object_key(log.user_id, id))
        .await
        .map_err(|e| Error::Internal(e.context("presigning download")))?;
    Ok(Json(DownloadLogResponse {
        download_url: p.url,
        expires_in: p.expires_in,
    }))
}

#[utoipa::path(delete, path = "/api/v1/logs/{id}", tag = "logs", params(("id" = Uuid, Path)), responses((status = 204)))]
pub async fn delete(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<NoContent> {
    let grant = readable(&state, &auth, id).await?;
    let log = &grant.stored.log;
    if log.deleted {
        return Ok(NoContent);
    }
    if !grant.can_manage() {
        return Err(Error::forbidden(
            "Only the author or a vault manager can delete a recording",
        ));
    }
    if let Some(team_id) = grant.team_id()
        && crate::policy::recording_required(&state.db, team_id).await?
        && crate::authz::require(&state, team_id, auth.user_id(), "logs.delete")
            .await
            .is_err()
    {
        return Err(Error::forbidden(
            "Recording is mandatory in this team; logs.delete permission required",
        ));
    }
    if let Some(storage) = &state.storage
        && let Err(e) = storage.delete(&object_key(log.user_id, id)).await
    {
        tracing::warn!(error = %e, "could not delete log object");
    }
    let mut tx = state.db.begin().await?;
    let (seq, vseq) = next_seqs(&mut tx, log.user_id, log.vault_id).await?;
    sqlx::query(
        "UPDATE session_logs SET deleted = true, meta = '', size_bytes = 0, pinned = false, note = '',
                note_by = NULL, seq = $2, vault_seq = $3 WHERE id = $1",
    )
    .bind(id)
    .bind(seq)
    .bind(vseq)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if let Some(team_id) = grant.team_id() {
        audit::record(
            &state.db,
            audit::Entry::new(team_id, &auth, "log.deleted")
                .vault(log.vault_id)
                .details(serde_json::json!({ "log_id": id, "author_id": log.user_id })),
        )
        .await;
    }
    let deleted = Stored {
        log: SessionLog {
            seq,
            deleted: true,
            ..grant.stored.log
        },
        vault_seq: vseq,
        team: grant.stored.team,
    };
    notify(&state, &deleted).await.map(NoContent::from)
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct ListQuery {
    #[serde(default)]
    pub since: i64,
    pub limit: Option<u32>,
}

fn page(rows: Vec<Row>, limit: usize, since: i64, cursor: Cursor) -> LogListResponse {
    let has_more = rows.len() > limit;
    let logs: Vec<SessionLog> = rows
        .into_iter()
        .take(limit)
        .map(|r| to_log(r, cursor))
        .collect();
    let since = logs.last().map(|l| l.seq).unwrap_or(since);
    LogListResponse {
        total: 0,
        logs,
        since,
        has_more,
    }
}

fn clamp(limit: Option<u32>) -> usize {
    limit
        .map(|l| l as usize)
        .unwrap_or(MAX_BATCH)
        .clamp(1, MAX_BATCH)
}

#[utoipa::path(get, path = "/api/v1/logs", tag = "logs", params(ListQuery), responses((status = 200, body = LogListResponse)))]
pub async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<LogListResponse>> {
    let limit = clamp(q.limit);
    let rows: Vec<Row> = sqlx::query_as(AssertSqlSafe(format!(
        "{SELECT} WHERE s.user_id = $1 AND s.seq > $2 ORDER BY s.seq LIMIT $3"
    )))
    .bind(auth.user_id())
    .bind(q.since)
    .bind((limit + 1) as i64)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(page(rows, limit, q.since, Cursor::Author)))
}

/// Every member's recordings in a vault, paged by the vault counter. Team
/// vaults only make sense here; a personal vault simply yields the owner's
/// logs.
#[utoipa::path(get, path = "/api/v1/vaults/{id}/logs", tag = "logs",
    params(("id" = Uuid, Path), ListQuery), responses((status = 200, body = LogListResponse)))]
pub async fn list_vault(
    State(state): State<AppState>,
    auth: Auth,
    Path(vault_id): Path<Uuid>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<LogListResponse>> {
    let a = vaults::access(&state.db, vault_id, auth.user_id()).await?;
    if a.pending {
        return Err(Error::forbidden("No key for this vault yet"));
    }
    let limit = clamp(q.limit);
    let rows: Vec<Row> = sqlx::query_as(AssertSqlSafe(format!(
        "{SELECT} WHERE s.vault_id = $1 AND s.vault_seq > $2 ORDER BY s.vault_seq LIMIT $3"
    )))
    .bind(vault_id)
    .bind(q.since)
    .bind((limit + 1) as i64)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(page(rows, limit, q.since, Cursor::Vault)))
}

/// Retention: every 6 hours delete unpinned recordings in team vaults that
/// are older than the team's `log_retention_days` (0 = keep forever).
pub async fn run_retention(state: AppState) {
    crate::jobs::exclusive(
        state,
        "log-retention",
        std::time::Duration::from_secs(6 * 3600),
        retention_pass,
    )
    .await
}

pub async fn retention_pass(state: AppState) -> anyhow::Result<u64> {
    const BATCH: i64 = 500;
    let mut total = 0u64;
    loop {
        let rows: Vec<(Uuid, Uuid, Uuid)> = sqlx::query_as(
            "SELECT s.id, s.user_id, s.vault_id
             FROM session_logs s
             JOIN vaults v ON v.id = s.vault_id
             JOIN team_policies p ON p.team_id = v.team_id
             WHERE v.kind = 'team' AND p.log_retention_days > 0
               AND s.deleted = false AND s.pinned = false
               AND s.created_at < now() - make_interval(days => p.log_retention_days)
             ORDER BY s.created_at
             LIMIT $1",
        )
        .bind(BATCH)
        .fetch_all(&state.db)
        .await?;
        let n = rows.len() as i64;
        for (id, user_id, vault_id) in rows {
            if let Some(storage) = &state.storage
                && let Err(e) = storage.delete(&object_key(user_id, id)).await
            {
                tracing::warn!(error = %e, log = %id, "could not delete expired log object");
            }
            let mut tx = state.db.begin().await?;
            let (seq, vseq) = next_seqs(&mut tx, user_id, vault_id).await?;
            sqlx::query(
                "UPDATE session_logs SET deleted = true, meta = '', size_bytes = 0, note = '',
                        note_by = NULL, seq = $2, vault_seq = $3 WHERE id = $1",
            )
            .bind(id)
            .bind(seq)
            .bind(vseq)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            let _ = events::publish(&state, Event::LogsChanged { user_id, seq }).await;
            let _ = events::publish(
                &state,
                Event::VaultLogsChanged {
                    vault_id,
                    seq: vseq,
                },
            )
            .await;
            total += 1;
        }
        if n < BATCH {
            return Ok(total);
        }
    }
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct TeamLogsQuery {
    /// Only recordings started at or after this instant.
    pub from: Option<DateTime<Utc>>,
    /// Only recordings started before this instant.
    pub to: Option<DateTime<Utc>>,
    /// Restrict to one team vault.
    pub vault_id: Option<Uuid>,
    /// Rows per page (the whole list when omitted; capped).
    pub limit: Option<u32>,
    /// Rows to skip.
    #[serde(default)]
    pub offset: i64,
}

const TEAM_LIMIT_MAX: i64 = 10_000;

async fn team_rows(
    state: &AppState,
    team_id: Uuid,
    q: &TeamLogsQuery,
    max: i64,
) -> ApiResult<Vec<Row>> {
    let limit = q.limit.map_or(max, |l| (l as i64).clamp(1, max));
    Ok(sqlx::query_as(AssertSqlSafe(format!(
        "{SELECT} WHERE v.team_id = $1 AND v.kind = 'team' AND s.deleted = false
            AND ($2::uuid IS NULL OR s.vault_id = $2)
            AND ($3::timestamptz IS NULL OR s.created_at >= $3)
            AND ($4::timestamptz IS NULL OR s.created_at < $4)
         ORDER BY s.created_at DESC LIMIT $5 OFFSET $6"
    )))
    .bind(team_id)
    .bind(q.vault_id)
    .bind(q.from)
    .bind(q.to)
    .bind(limit)
    .bind(q.offset.max(0))
    .fetch_all(&state.db)
    .await?)
}

/// Recordings matching the same filter, regardless of `limit`/`offset`.
async fn team_total(state: &AppState, team_id: Uuid, q: &TeamLogsQuery) -> ApiResult<i64> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM session_logs s JOIN users u ON u.id = s.user_id JOIN vaults v ON v.id = s.vault_id WHERE v.team_id = $1 AND v.kind = 'team' AND s.deleted = false
            AND ($2::uuid IS NULL OR s.vault_id = $2)
            AND ($3::timestamptz IS NULL OR s.created_at >= $3)
            AND ($4::timestamptz IS NULL OR s.created_at < $4)",
    )
    .bind(team_id)
    .bind(q.vault_id)
    .bind(q.from)
    .bind(q.to)
    .fetch_one(&state.db)
    .await?;
    Ok(n)
}

/// Every recording in the team's vaults, newest first (`logs.view_team`).
/// Same envelope as the vault listing (that is what the clients parse);
/// `total` counts every recording matching the filter, `offset`/`limit`
/// pick the page.
#[utoipa::path(get, path = "/api/v1/teams/{id}/logs", tag = "logs",
    params(("id" = Uuid, Path), TeamLogsQuery), responses((status = 200, body = LogListResponse)))]
pub async fn team_list(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
    Query(q): Query<TeamLogsQuery>,
) -> ApiResult<Json<LogListResponse>> {
    crate::authz::require(&state, team_id, auth.user_id(), "logs.view_team").await?;
    let rows = team_rows(&state, team_id, &q, MAX_BATCH as i64).await?;
    let total = team_total(&state, team_id, &q).await?;
    let logs: Vec<SessionLog> = rows.into_iter().map(|r| stored(r).log).collect();
    let has_more = q.offset.max(0) + (logs.len() as i64) < total;
    Ok(Json(LogListResponse {
        since: 0,
        has_more,
        total,
        logs,
    }))
}

/// Compliance export: one JSON object per recording (metadata as stored,
/// still encrypted with the vault key) plus a short-lived download URL for
/// the body. `logs.export`; audited as `logs.exported`.
#[utoipa::path(get, path = "/api/v1/teams/{id}/logs/export", tag = "logs",
    params(("id" = Uuid, Path), TeamLogsQuery),
    responses((status = 200, description = "application/x-ndjson", body = String)))]
pub async fn team_export(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
    Query(q): Query<TeamLogsQuery>,
) -> ApiResult<impl axum::response::IntoResponse> {
    crate::authz::require(&state, team_id, auth.user_id(), "logs.export").await?;
    ratelimit::check(&state, ratelimit::SYNC_PUSH, &auth.user_id().to_string()).await?;
    let rows = team_rows(&state, team_id, &q, TEAM_LIMIT_MAX).await?;
    let mut out = String::new();
    let mut count = 0usize;
    for r in rows {
        let s = stored(r);
        let mut v = serde_json::to_value(&s.log).unwrap_or_default();
        if let (Some(storage), true, Some(obj)) =
            (&state.storage, s.log.completed, v.as_object_mut())
        {
            match storage
                .presign_get(&object_key(s.log.user_id, s.log.id))
                .await
            {
                Ok(p) => {
                    obj.insert("download_url".into(), p.url.into());
                    obj.insert("download_expires_in".into(), p.expires_in.into());
                }
                Err(e) => tracing::warn!(error = %e, log = %s.log.id, "presign for export"),
            }
        }
        out.push_str(&v.to_string());
        out.push('\n');
        count += 1;
    }
    audit::record(
        &state.db,
        audit::Entry::new(team_id, &auth, "logs.exported").details(serde_json::json!({
            "count": count, "from": q.from, "to": q.to, "vault_id": q.vault_id,
        })),
    )
    .await;
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/x-ndjson".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"termoso-recordings-{team_id}.jsonl\""),
            ),
        ],
        out,
    ))
}

// ───────────────────────── local blob store ─────────────────────────

fn io_err(e: std::io::Error, what: &str) -> Error {
    Error::Internal(anyhow::Error::from(e).context(what.to_string()))
}

/// `PUT /logs/blob/{token}` — upload for the local storage backend. The token
/// (sealed with the master key, 15 min) names the object and caps its size.
#[utoipa::path(put, path = "/api/v1/logs/blob/{token}", tag = "logs",
    params(("token" = String, Path)), responses((status = 204), (status = 403), (status = 413)))]
pub async fn blob_put(
    State(state): State<AppState>,
    Path(token): Path<String>,
    body: axum::body::Body,
) -> ApiResult<crate::error::NoContent> {
    let storage = storage(&state)?;
    let grant = storage
        .open_grant(&token)
        .map_err(|_| Error::forbidden("Invalid or expired upload token"))?;
    if grant.method != "put" {
        return Err(Error::forbidden("Not an upload token"));
    }
    let path = storage
        .local_file(&grant.key)
        .map_err(|e| Error::Internal(e.context("blob path")))?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| io_err(e, "creating log directory"))?;
    }
    let tmp = path.with_extension("part");
    let mut file = tokio::fs::File::create(&tmp)
        .await
        .map_err(|e| io_err(e, "creating log file"))?;
    let mut stream = body.into_data_stream();
    let mut written: i64 = 0;
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| Error::Internal(anyhow::anyhow!("upload stream: {e}")))?;
        written += chunk.len() as i64;
        if written > grant.max_len {
            drop(file);
            tokio::fs::remove_file(&tmp).await.ok();
            return Err(Error::quota_exceeded("Upload exceeds the declared size"));
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| io_err(e, "writing log file"))?;
    }
    file.flush()
        .await
        .map_err(|e| io_err(e, "flushing log file"))?;
    drop(file);
    tokio::fs::rename(&tmp, &path)
        .await
        .map_err(|e| io_err(e, "placing log file"))?;
    Ok(crate::error::NoContent)
}

/// `GET /logs/blob/{token}` — download for the local storage backend.
#[utoipa::path(get, path = "/api/v1/logs/blob/{token}", tag = "logs",
    params(("token" = String, Path)), responses((status = 200, description = "octet-stream"), (status = 403)))]
pub async fn blob_get(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> ApiResult<axum::response::Response> {
    use axum::response::IntoResponse;
    let storage = storage(&state)?;
    let grant = storage
        .open_grant(&token)
        .map_err(|_| Error::forbidden("Invalid or expired download token"))?;
    if grant.method != "get" {
        return Err(Error::forbidden("Not a download token"));
    }
    let path = storage
        .local_file(&grant.key)
        .map_err(|e| Error::Internal(e.context("blob path")))?;
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::not_found("Log data"));
        }
        Err(e) => return Err(io_err(e, "opening log file")),
    };
    let len = file
        .metadata()
        .await
        .map_err(|e| io_err(e, "log file metadata"))?
        .len();
    let stream = futures::stream::unfold(file, |mut file| async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 64 * 1024];
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok::<_, std::io::Error>(bytes::Bytes::from(buf)), file))
            }
            Err(e) => Some((Err(e), file)),
        }
    });
    let body = axum::body::Body::from_stream(stream);
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/octet-stream".to_string(),
            ),
            (axum::http::header::CONTENT_LENGTH, len.to_string()),
        ],
        body,
    )
        .into_response())
}

// ───────────────────────────── comments ─────────────────────────────

#[derive(sqlx::FromRow)]
struct CommentRow {
    id: Uuid,
    log_id: Uuid,
    user_id: Uuid,
    body: String,
    offset_ms: Option<i64>,
    created_at: DateTime<Utc>,
    email: String,
    display_name: Option<String>,
    avatar_tag: Option<String>,
}

const COMMENT_SELECT: &str = "SELECT c.id, c.log_id, c.user_id, c.body, c.offset_ms, c.created_at,
        u.email, u.display_name, u.avatar_tag
    FROM session_log_comments c JOIN users u ON u.id = c.user_id";

fn comment(r: CommentRow) -> LogComment {
    LogComment {
        id: r.id,
        log_id: r.log_id,
        user_id: r.user_id,
        author: Some(LogAuthor {
            user_id: r.user_id,
            email: r.email,
            display_name: r.display_name,
            avatar_tag: r.avatar_tag,
        }),
        body: r.body,
        offset_ms: r.offset_ms,
        created_at: r.created_at,
    }
}

fn clean_comment(body: &str) -> ApiResult<String> {
    let body = body.trim();
    if body.is_empty() {
        return Err(Error::bad_request("Comment is empty"));
    }
    if body.chars().count() > MAX_COMMENT_CHARS {
        return Err(Error::too_large(format!(
            "Comments are limited to {MAX_COMMENT_CHARS} characters"
        )));
    }
    if body
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(Error::bad_request("Comment contains control characters"));
    }
    Ok(body.to_owned())
}

/// Everyone who can read the recording can read its thread.
#[utoipa::path(get, path = "/api/v1/logs/{id}/comments", tag = "logs", params(("id" = Uuid, Path)),
    responses((status = 200, body = LogCommentList)))]
pub async fn comments_list(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<LogCommentList>> {
    let grant = readable(&state, &auth, id).await?;
    if grant.stored.log.deleted {
        return Err(Error::not_found("Log"));
    }
    let rows: Vec<CommentRow> = sqlx::query_as(AssertSqlSafe(format!(
        "{COMMENT_SELECT} WHERE c.log_id = $1 ORDER BY c.created_at, c.id"
    )))
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(LogCommentList {
        comments: rows.into_iter().map(comment).collect(),
    }))
}

/// Editors (and the author) comment; viewers read.
#[utoipa::path(post, path = "/api/v1/logs/{id}/comments", tag = "logs", params(("id" = Uuid, Path)),
    request_body = CreateLogCommentRequest, responses((status = 200, body = LogComment)))]
pub async fn comment_create(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<CreateLogCommentRequest>,
) -> ApiResult<Json<LogComment>> {
    let grant = readable(&state, &auth, id).await?;
    let log = &grant.stored.log;
    if log.deleted {
        return Err(Error::not_found("Log"));
    }
    if !grant.can_write() {
        return Err(Error::forbidden("Editor role required to comment"));
    }
    let body = clean_comment(&req.body)?;
    if req.offset_ms.is_some_and(|o| o < 0) {
        return Err(Error::bad_request("offset_ms must not be negative"));
    }
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM session_log_comments WHERE log_id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await?;
    if count >= MAX_COMMENTS_PER_LOG {
        return Err(Error::too_large(format!(
            "A recording holds at most {MAX_COMMENTS_PER_LOG} comments"
        )));
    }
    let cid = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO session_log_comments (id, log_id, user_id, body, offset_ms) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(cid)
    .bind(id)
    .bind(auth.user_id())
    .bind(&body)
    .bind(req.offset_ms)
    .execute(&state.db)
    .await?;
    let row: CommentRow =
        sqlx::query_as(AssertSqlSafe(format!("{COMMENT_SELECT} WHERE c.id = $1")))
            .bind(cid)
            .fetch_one(&state.db)
            .await?;
    if let Some(team_id) = grant.team_id() {
        audit::record(
            &state.db,
            audit::Entry::new(team_id, &auth, "log.commented")
                .vault(log.vault_id)
                .details(serde_json::json!({
                    "log_id": id,
                    "author_id": log.user_id,
                    "comment_id": cid,
                })),
        )
        .await;
    }
    Ok(Json(comment(row)))
}

/// Your own comment, or any comment if you manage the vault (the recording's
/// author gets no extra say over the thread).
#[utoipa::path(delete, path = "/api/v1/logs/{id}/comments/{comment_id}", tag = "logs",
    params(("id" = Uuid, Path), ("comment_id" = Uuid, Path)), responses((status = 204)))]
pub async fn comment_delete(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, comment_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<NoContent> {
    let grant = readable(&state, &auth, id).await?;
    let owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM session_log_comments WHERE id = $1 AND log_id = $2",
    )
    .bind(comment_id)
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    let Some(owner) = owner else {
        return Err(Error::not_found("Comment"));
    };
    // Recording authors do not moderate other people's comments; vault managers do.
    let manages_vault = grant.access.as_ref().is_some_and(|a| a.role.can_manage());
    if owner != auth.user_id() && !manages_vault {
        return Err(Error::forbidden(
            "Only the author or a vault manager can delete a comment",
        ));
    }
    sqlx::query("DELETE FROM session_log_comments WHERE id = $1")
        .bind(comment_id)
        .execute(&state.db)
        .await?;
    if let Some(team_id) = grant.team_id() {
        audit::record(
            &state.db,
            audit::Entry::new(team_id, &auth, "log.comment_deleted")
                .vault(grant.stored.log.vault_id)
                .details(serde_json::json!({ "log_id": id, "comment_id": comment_id })),
        )
        .await;
    }
    Ok(NoContent)
}
