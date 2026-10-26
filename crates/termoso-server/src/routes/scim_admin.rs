//! Team-side SCIM administration: bearer tokens, group overview, group → vault grants.

use axum::Json;
use axum::extract::{Path, Query, State};

use super::paging::PageQuery;
use chrono::{DateTime, Utc};
use termoso_proto::team::{
    CreateScimTokenRequest, CreatedScimToken, ScimGroupInfo, ScimGroupList, ScimGroupVault,
    ScimToken, ScimTokenList, SetScimGroupVaultsRequest,
};
use uuid::Uuid;

use crate::audit;
use crate::error::{ApiResult, Error, NoContent};
use crate::extract::{Auth, Json as Body};
use crate::state::AppState;
use crate::util::{hash_token, random_token};

fn base_url(state: &AppState) -> String {
    format!("{}/scim/v2", state.cfg.public_url.trim_end_matches('/'))
}

type TokenRow = (
    Uuid,
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

fn to_token(r: TokenRow) -> ScimToken {
    ScimToken {
        id: r.0,
        name: r.1,
        created_at: r.2,
        expires_at: r.3,
        last_used_at: r.4,
    }
}

#[utoipa::path(get, path = "/api/v1/teams/{id}/scim/tokens", tag = "teams", params(("id" = Uuid, Path)),
    responses((status = 200, body = ScimTokenList)))]
pub async fn list_tokens(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ScimTokenList>> {
    crate::authz::require(&state, id, auth.user_id(), "scim.manage").await?;
    let rows: Vec<TokenRow> = sqlx::query_as(
        "SELECT id, name, created_at, expires_at, last_used_at FROM scim_tokens
         WHERE team_id = $1 AND revoked_at IS NULL ORDER BY created_at",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(ScimTokenList {
        tokens: rows.into_iter().map(to_token).collect(),
        base_url: base_url(&state),
    }))
}

#[utoipa::path(post, path = "/api/v1/teams/{id}/scim/tokens", tag = "teams", params(("id" = Uuid, Path)),
    request_body = CreateScimTokenRequest, responses((status = 200, body = CreatedScimToken)))]
pub async fn create_token(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<CreateScimTokenRequest>,
) -> ApiResult<Json<CreatedScimToken>> {
    crate::authz::require(&state, id, auth.user_id(), "scim.tokens").await?;
    let name = req.name.trim();
    if name.is_empty() || name.len() > 60 {
        return Err(Error::bad_request("name must be 1..=60 characters"));
    }
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM scim_tokens WHERE team_id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await?;
    if count >= crate::scim::MAX_TOKENS {
        return Err(Error::bad_request("At most 3 active SCIM tokens per team"));
    }
    let expires_at = match req.expires_in_days {
        Some(0) | None => None,
        Some(d) if d <= 3650 => Some(Utc::now() + chrono::Duration::days(d as i64)),
        Some(_) => return Err(Error::bad_request("expires_in_days must be 1..=3650")),
    };
    let secret = format!("tsk_{}", random_token());
    let tid = Uuid::new_v4();
    let row: TokenRow = sqlx::query_as(
        "INSERT INTO scim_tokens (id, team_id, name, token_hash, created_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, created_at, expires_at, last_used_at",
    )
    .bind(tid)
    .bind(id)
    .bind(name)
    .bind(hash_token(&secret))
    .bind(auth.user_id())
    .bind(expires_at)
    .fetch_one(&state.db)
    .await?;
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "scim.token_created").details(
            serde_json::json!({ "token_id": tid, "name": name, "expires_at": expires_at }),
        ),
    )
    .await;
    Ok(Json(CreatedScimToken {
        token: to_token(row),
        secret,
        base_url: base_url(&state),
    }))
}

#[utoipa::path(delete, path = "/api/v1/teams/{id}/scim/tokens/{tid}", tag = "teams",
    params(("id" = Uuid, Path), ("tid" = Uuid, Path)), responses((status = 204)))]
pub async fn revoke_token(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, tid)): Path<(Uuid, Uuid)>,
) -> ApiResult<NoContent> {
    crate::authz::require(&state, id, auth.user_id(), "scim.tokens").await?;
    let n = sqlx::query("UPDATE scim_tokens SET revoked_at = now() WHERE team_id = $1 AND id = $2 AND revoked_at IS NULL")
        .bind(id)
        .bind(tid)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(Error::not_found("SCIM token"));
    }
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "scim.token_revoked")
            .details(serde_json::json!({ "token_id": tid })),
    )
    .await;
    Ok(NoContent)
}

#[utoipa::path(get, path = "/api/v1/teams/{id}/scim/groups", tag = "teams", params(("id" = Uuid, Path), PageQuery),
    responses((status = 200, body = ScimGroupList)))]
pub async fn list_groups(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Query(pq): Query<PageQuery>,
) -> ApiResult<Json<ScimGroupList>> {
    crate::authz::require(&state, id, auth.user_id(), "scim.manage").await?;
    let (offset, limit) = pq.window(10_000);
    let rows: Vec<(Uuid, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT g.id, g.display_name, g.external_id, (SELECT count(*) FROM scim_group_members m WHERE m.group_id = g.id)
         FROM scim_groups g WHERE g.team_id = $1 ORDER BY g.display_name LIMIT $2 OFFSET $3",
    )
    .bind(id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    let total = pq
        .total(
            rows.len(),
            &state.db,
            "SELECT count(*) FROM scim_groups WHERE team_id = $1",
            id,
        )
        .await?;
    let grants: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT gv.group_id, gv.vault_id, gv.vault_role FROM scim_group_vaults gv JOIN scim_groups g ON g.id = gv.group_id WHERE g.team_id = $1",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(ScimGroupList {
        total,
        groups: rows
            .into_iter()
            .map(
                |(gid, display_name, external_id, member_count)| ScimGroupInfo {
                    id: gid,
                    display_name,
                    external_id,
                    member_count,
                    vaults: grants
                        .iter()
                        .filter(|g| g.0 == gid)
                        .map(|g| ScimGroupVault {
                            vault_id: g.1,
                            role: g.2.clone(),
                        })
                        .collect(),
                },
            )
            .collect(),
    }))
}

#[utoipa::path(put, path = "/api/v1/teams/{id}/scim/groups/{gid}/vaults", tag = "teams",
    params(("id" = Uuid, Path), ("gid" = Uuid, Path)), request_body = SetScimGroupVaultsRequest, responses((status = 204)))]
pub async fn set_group_vaults(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, gid)): Path<(Uuid, Uuid)>,
    Body(req): Body<SetScimGroupVaultsRequest>,
) -> ApiResult<NoContent> {
    crate::authz::require(&state, id, auth.user_id(), "scim.manage").await?;
    crate::authz::require(&state, id, auth.user_id(), "vaults.members").await?;
    let exists: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM scim_groups WHERE team_id = $1 AND id = $2")
            .bind(id)
            .bind(gid)
            .fetch_optional(&state.db)
            .await?;
    if exists.is_none() {
        return Err(Error::not_found("SCIM group"));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM scim_group_vaults WHERE group_id = $1")
        .bind(gid)
        .execute(&mut *tx)
        .await?;
    for g in &req.vaults {
        if !["viewer", "editor", "manager"].contains(&g.role.as_str()) {
            return Err(Error::bad_request("role must be viewer, editor or manager"));
        }
        let ok: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM vaults WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL",
        )
        .bind(g.vault_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        if ok.is_none() {
            return Err(Error::bad_request(format!(
                "vault {} is not a vault of this team",
                g.vault_id
            )));
        }
        sqlx::query("INSERT INTO scim_group_vaults (group_id, vault_id, vault_role) VALUES ($1, $2, $3) ON CONFLICT (group_id, vault_id) DO UPDATE SET vault_role = EXCLUDED.vault_role")
            .bind(gid)
            .bind(g.vault_id)
            .bind(&g.role)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    let members: Vec<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM scim_group_members WHERE group_id = $1")
            .bind(gid)
            .fetch_all(&state.db)
            .await?;
    for (uid,) in members {
        crate::scim::resync_user(&state, id, uid).await?;
    }
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "scim.group_vaults_updated")
            .details(serde_json::json!({ "group_id": gid, "vaults": req.vaults.len() })),
    )
    .await;
    Ok(NoContent)
}
