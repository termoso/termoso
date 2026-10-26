//! Tamper evidence for the team activity log.
//!
//! The database chains every `team_audit_events` row to the team's previous
//! one (`hash = sha256(fields || prev_hash)`, trigger in migration 0034), so
//! editing or deleting an entry breaks the chain. This module adds what the
//! database cannot: signed checkpoints (the head of the chain at a point in
//! time, signed with a server Ed25519 key sealed by the master key) and the
//! verification walk exposed at `GET /teams/{id}/audit/verify`.
//!
//! Retention anchors the newest row it removes in `audit_checkpoints`
//! (`kind = 'retention'`), so a chain whose first surviving entry points at an
//! anchor is still intact.

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::Serialize;
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};
use uuid::Uuid;

use crate::error::ApiResult;
use crate::extract::Auth;
use crate::state::AppState;

const KEY_PURPOSE: &str = "audit-signing";
/// sshsig namespace (`ssh-keygen -Y verify -n termoso-audit …`).
const NAMESPACE: &str = "termoso-audit";
const CHECKPOINT_EVERY: std::time::Duration = std::time::Duration::from_secs(3600);

/// What a checkpoint signature covers.
fn signed_message(team_id: Uuid, last_id: i64, hash: &[u8]) -> Vec<u8> {
    format!(
        "termoso-audit-checkpoint-v1|{team_id}|{last_id}|{}",
        hex::encode(hash)
    )
    .into_bytes()
}

/// The server's audit signing key, created on first use and sealed with the
/// master key.
async fn signing_key(state: &AppState) -> ApiResult<PrivateKey> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT private_key_enc FROM server_keys WHERE purpose = $1")
            .bind(KEY_PURPOSE)
            .fetch_optional(&state.db)
            .await?;
    if let Some((sealed,)) = row {
        let pem = state.decrypt_secret(KEY_PURPOSE, &sealed)?;
        return PrivateKey::from_openssh(&pem)
            .map_err(|e| anyhow::anyhow!("audit signing key: {e}").into());
    }
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    termoso_crypto::random_bytes(&mut seed[..]);
    let mut key = PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&seed));
    key.set_comment("termoso-audit");
    let public = key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("audit public key: {e}"))?;
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("audit private key: {e}"))?;
    let sealed = state.encrypt_secret(KEY_PURPOSE, pem.as_bytes())?;
    // Two servers racing on first use: the first insert wins, the other reads it back.
    sqlx::query(
        "INSERT INTO server_keys (purpose, public_key, private_key_enc) VALUES ($1, $2, $3)
         ON CONFLICT (purpose) DO NOTHING",
    )
    .bind(KEY_PURPOSE)
    .bind(&public)
    .bind(&sealed)
    .execute(&state.db)
    .await?;
    let (sealed,): (Vec<u8>,) =
        sqlx::query_as("SELECT private_key_enc FROM server_keys WHERE purpose = $1")
            .bind(KEY_PURPOSE)
            .fetch_one(&state.db)
            .await?;
    let pem = state.decrypt_secret(KEY_PURPOSE, &sealed)?;
    PrivateKey::from_openssh(&pem).map_err(|e| anyhow::anyhow!("audit signing key: {e}").into())
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AuditKey {
    /// `ssh-ed25519 AAAA… termoso-audit` — verify checkpoint signatures with it.
    pub public_key: String,
    /// Bytes a signature covers: `termoso-audit-checkpoint-v1|<team_id>|<last_id>|<hex hash>`.
    pub message_format: &'static str,
    /// sshsig namespace to pass to `ssh-keygen -Y verify -n`.
    pub namespace: &'static str,
}

/// `GET /audit/key` — the public half of the audit signing key (no auth).
#[utoipa::path(get, path = "/audit/key", tag = "teams", responses((status = 200, body = AuditKey)))]
pub async fn public_key(State(state): State<AppState>) -> ApiResult<Json<AuditKey>> {
    let key = signing_key(&state).await?;
    Ok(Json(AuditKey {
        public_key: key
            .public_key()
            .to_openssh()
            .map_err(|e| anyhow::anyhow!("audit public key: {e}"))?,
        message_format: "termoso-audit-checkpoint-v1|<team_id>|<last_id>|<hex sha256>",
        namespace: NAMESPACE,
    }))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Checkpoint {
    pub id: i64,
    pub last_id: i64,
    pub hash: String,
    /// OpenSSH sshsig PEM over `termoso-audit-checkpoint-v1|<team_id>|<last_id>|<hex hash>`,
    /// namespace `termoso-audit`; check with `ssh-keygen -Y verify` and `GET /audit/key`.
    pub signature: String,
    pub created_at: DateTime<Utc>,
}

/// Sign the current head of `team_id`'s chain. `None` when the team has no
/// events or the head is already checkpointed.
pub async fn write_checkpoint(state: &AppState, team_id: Uuid) -> ApiResult<Option<Checkpoint>> {
    let head: Option<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT id, hash FROM team_audit_events WHERE team_id = $1 AND hash IS NOT NULL
         ORDER BY id DESC LIMIT 1",
    )
    .bind(team_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((last_id, hash)) = head else {
        return Ok(None);
    };
    let last: Option<(i64,)> = sqlx::query_as(
        "SELECT last_id FROM audit_checkpoints WHERE team_id = $1 AND kind = 'checkpoint'
         ORDER BY id DESC LIMIT 1",
    )
    .bind(team_id)
    .fetch_optional(&state.db)
    .await?;
    if last.is_some_and(|(l,)| l == last_id) {
        return Ok(None);
    }
    let key = signing_key(state).await?;
    let sig = key
        .sign(
            NAMESPACE,
            HashAlg::Sha256,
            &signed_message(team_id, last_id, &hash),
        )
        .and_then(|s| s.to_pem(LineEnding::LF))
        .map_err(|e| anyhow::anyhow!("audit checkpoint signature: {e}"))?;
    let (id, created_at): (i64, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO audit_checkpoints (team_id, kind, last_id, hash, signature)
         VALUES ($1, 'checkpoint', $2, $3, $4) RETURNING id, created_at",
    )
    .bind(team_id)
    .bind(last_id)
    .bind(&hash)
    .bind(&sig)
    .fetch_one(&state.db)
    .await?;
    Ok(Some(Checkpoint {
        id,
        last_id,
        hash: hex::encode(hash),
        signature: sig,
        created_at,
    }))
}

/// `POST /teams/{id}/audit/checkpoint` — sign the head now (`audit.export`).
#[utoipa::path(post, path = "/api/v1/teams/{id}/audit/checkpoint", tag = "teams",
    params(("id" = Uuid, Path)), responses((status = 200, body = Option<Checkpoint>)))]
pub async fn checkpoint(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
) -> ApiResult<Json<Option<Checkpoint>>> {
    crate::authz::require(&state, team_id, auth.user_id(), "audit.export").await?;
    Ok(Json(write_checkpoint(&state, team_id).await?))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Verification {
    /// Every entry re-hashes, links to its predecessor, the first surviving
    /// entry is genesis or a retention anchor, and the latest signed checkpoint
    /// matches an entry and verifies.
    pub ok: bool,
    /// Entries checked.
    pub events: i64,
    pub first_id: Option<i64>,
    pub last_id: Option<i64>,
    /// Hex hash of the newest entry.
    pub head_hash: Option<String>,
    /// First entry that fails, with why (`hash`, `link`, `anchor`, `unhashed`).
    pub broken_at: Option<i64>,
    pub reason: Option<&'static str>,
    /// The latest signed checkpoint, if any, and whether it checks out.
    pub checkpoint: Option<Checkpoint>,
    pub checkpoint_ok: Option<bool>,
}

/// `GET /teams/{id}/audit/verify` — walk the chain (`audit.view`).
#[utoipa::path(get, path = "/api/v1/teams/{id}/audit/verify", tag = "teams",
    params(("id" = Uuid, Path)), responses((status = 200, body = Verification)))]
pub async fn verify(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
) -> ApiResult<Json<Verification>> {
    crate::authz::require(&state, team_id, auth.user_id(), "audit.view").await?;
    Ok(Json(run_verify(&state, team_id).await?))
}

pub async fn run_verify(state: &AppState, team_id: Uuid) -> ApiResult<Verification> {
    // One pass in SQL: recompute each hash and compare with the stored one and
    // with the next row's prev_hash. Rows written before migration 0034 have no
    // hash and are reported as `unhashed`.
    let (events, first_id, last_id, head_hash): (i64, Option<i64>, Option<i64>, Option<Vec<u8>>) =
        sqlx::query_as(
            "SELECT count(*), min(id), max(id),
                    (SELECT hash FROM team_audit_events WHERE team_id = $1 ORDER BY id DESC LIMIT 1)
             FROM team_audit_events WHERE team_id = $1",
        )
        .bind(team_id)
        .fetch_one(&state.db)
        .await?;
    let broken: Option<(i64, String)> = sqlx::query_as(
        "SELECT id, reason FROM (
             SELECT e.id,
                    CASE
                      WHEN e.hash IS NULL THEN 'unhashed'
                      WHEN e.hash <> audit_event_hash(e.prev_hash, e.id, e.team_id, e.actor_id, e.device_id,
                                                      e.action, e.vault_id, e.target_user, e.details, e.created_at)
                           THEN 'hash'
                      WHEN lag(e.hash) OVER (ORDER BY e.id) IS NOT NULL
                           AND e.prev_hash IS DISTINCT FROM lag(e.hash) OVER (ORDER BY e.id) THEN 'link'
                      WHEN lag(e.hash) OVER (ORDER BY e.id) IS NULL AND e.prev_hash IS NOT NULL
                           AND NOT EXISTS (SELECT 1 FROM audit_checkpoints c
                                           WHERE c.team_id = e.team_id AND c.hash = e.prev_hash)
                           THEN 'anchor'
                      ELSE NULL
                    END AS reason
             FROM team_audit_events e WHERE e.team_id = $1) x
         WHERE reason IS NOT NULL ORDER BY id LIMIT 1",
    )
    .bind(team_id)
    .fetch_optional(&state.db)
    .await?;
    let reason = broken.as_ref().map(|(_, r)| match r.as_str() {
        "hash" => "hash",
        "link" => "link",
        "anchor" => "anchor",
        _ => "unhashed",
    });

    let cp: Option<(i64, i64, Vec<u8>, Option<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, last_id, hash, signature, created_at FROM audit_checkpoints
         WHERE team_id = $1 AND kind = 'checkpoint' ORDER BY id DESC LIMIT 1",
    )
    .bind(team_id)
    .fetch_optional(&state.db)
    .await?;
    let mut checkpoint = None;
    let mut checkpoint_ok = None;
    if let Some((id, cp_last, hash, sig, created_at)) = cp {
        let stored: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT hash FROM team_audit_events WHERE id = $1 AND team_id = $2")
                .bind(cp_last)
                .bind(team_id)
                .fetch_optional(&state.db)
                .await?;
        let anchored: Option<(i64,)> = sqlx::query_as(
            "SELECT 1::bigint FROM audit_checkpoints WHERE team_id = $1 AND kind = 'retention'
             AND last_id >= $2 LIMIT 1",
        )
        .bind(team_id)
        .bind(cp_last)
        .fetch_optional(&state.db)
        .await?;
        let entry_ok = match stored {
            Some((h,)) => h == hash,
            // The checkpointed entry was removed by retention: fine if an anchor covers it.
            None => anchored.is_some(),
        };
        let pk = signing_public_key(state).await?;
        let sig_ok = sig.as_deref().is_some_and(|pem| {
            SshSig::from_pem(pem).is_ok_and(|s| {
                pk.verify(NAMESPACE, &signed_message(team_id, cp_last, &hash), &s)
                    .is_ok()
            })
        });
        checkpoint_ok = Some(entry_ok && sig_ok);
        checkpoint = Some(Checkpoint {
            id,
            last_id: cp_last,
            hash: hex::encode(&hash),
            signature: sig.unwrap_or_default(),
            created_at,
        });
    }
    Ok(Verification {
        ok: broken.is_none() && checkpoint_ok != Some(false),
        events,
        first_id,
        last_id,
        head_hash: head_hash.map(hex::encode),
        broken_at: broken.map(|(id, _)| id),
        reason,
        checkpoint,
        checkpoint_ok,
    })
}

async fn signing_public_key(state: &AppState) -> ApiResult<PublicKey> {
    Ok(signing_key(state).await?.public_key().clone())
}

/// Hourly: sign the head of every team whose log moved since its last checkpoint.
pub async fn run_checkpoints(state: AppState) {
    crate::jobs::exclusive(
        state,
        "audit-checkpoints",
        CHECKPOINT_EVERY,
        |s| async move { checkpoint_pass(&s).await },
    )
    .await
}

pub async fn checkpoint_pass(state: &AppState) -> anyhow::Result<u64> {
    let teams: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT DISTINCT e.team_id FROM team_audit_events e
         WHERE e.id > coalesce((SELECT max(c.last_id) FROM audit_checkpoints c
                                WHERE c.team_id = e.team_id AND c.kind = 'checkpoint'), 0)",
    )
    .fetch_all(&state.db)
    .await?;
    let mut n = 0;
    for (team_id,) in teams {
        if write_checkpoint(state, team_id)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .is_some()
        {
            n += 1;
        }
    }
    Ok(n)
}
