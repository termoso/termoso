//! Group/host access rules of team vaults (`/teams/{id}/vaults/{vault_id}/acl`)
//! and the caller's resolved rules (`/acl/me`).

use crate::acl::{self, ENTITY_KINDS, MODES, PRINCIPAL_KINDS};
use crate::audit;
use crate::error::{ApiResult, Error};
use crate::extract::{Auth, Json as Body};
use crate::state::AppState;
use axum::Json;
use axum::extract::{Path, Query, State};

use super::paging::PageQuery;
use termoso_proto::team::{
    EntityAclResponse, EntityAclRule, MyAclResponse, MyAclRule, UpsertEntityAclRequest,
};
use uuid::Uuid;

type Row = (
    Uuid,
    Uuid,
    Uuid,
    String,
    String,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    String,
    chrono::DateTime<chrono::Utc>,
);

const SELECT_BY_VAULT: &str =
    "SELECT a.id, a.vault_id, a.entity_id, a.entity_kind, a.principal_kind, a.role_id, a.user_id,
            a.group_name,
            COALESCE(r.name, u.email, a.group_name) AS principal_name,
            a.mode, a.updated_at
     FROM entity_acl a
     LEFT JOIN team_roles r ON r.id = a.role_id
     LEFT JOIN users u ON u.id = a.user_id
     WHERE a.vault_id = $1
     ORDER BY a.entity_kind, a.entity_id, a.principal_kind, a.updated_at";

fn to_rule(r: Row) -> EntityAclRule {
    let (
        id,
        vault_id,
        entity_id,
        entity_kind,
        principal_kind,
        role_id,
        user_id,
        group_name,
        principal_name,
        mode,
        updated_at,
    ) = r;
    EntityAclRule {
        id,
        vault_id,
        entity_id,
        entity_kind,
        principal_kind,
        role_id,
        user_id,
        group_name,
        principal_name: principal_name.unwrap_or_default(),
        mode,
        updated_at,
    }
}

/// The vault must be a vault of this team; personal vaults never carry rules.
async fn team_vault(state: &AppState, team_id: Uuid, vault_id: Uuid) -> ApiResult<()> {
    let owner: Option<(Option<Uuid>,)> = sqlx::query_as("SELECT team_id FROM vaults WHERE id = $1")
        .bind(vault_id)
        .fetch_optional(&state.db)
        .await?;
    match owner {
        Some((Some(t),)) if t == team_id => Ok(()),
        Some(_) => Err(Error::bad_request(
            "Access rules apply to team vaults of this team only",
        )),
        None => Err(Error::not_found("Vault")),
    }
}

async fn list_rules(
    state: &AppState,
    vault_id: Uuid,
    pq: &PageQuery,
) -> ApiResult<Json<EntityAclResponse>> {
    let (offset, limit) = pq.window(10_000);
    let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT_BY_VAULT} LIMIT $2 OFFSET $3"
    )))
    .bind(vault_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    let total = pq
        .total(
            rows.len(),
            &state.db,
            "SELECT count(*) FROM entity_acl WHERE vault_id = $1",
            vault_id,
        )
        .await?;
    Ok(Json(EntityAclResponse {
        rules: rows.into_iter().map(to_rule).collect(),
        total,
    }))
}

#[utoipa::path(get, path = "/api/v1/teams/{id}/vaults/{vault_id}/acl", tag = "teams",
    params(("id" = Uuid, Path), ("vault_id" = Uuid, Path), PageQuery),
    responses((status = 200, body = EntityAclResponse)))]
pub async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, vault_id)): Path<(Uuid, Uuid)>,
    Query(pq): Query<PageQuery>,
) -> ApiResult<Json<EntityAclResponse>> {
    crate::authz::require(&state, id, auth.user_id(), "acl.manage").await?;
    team_vault(&state, id, vault_id).await?;
    list_rules(&state, vault_id, &pq).await
}

#[utoipa::path(put, path = "/api/v1/teams/{id}/vaults/{vault_id}/acl", tag = "teams",
    params(("id" = Uuid, Path), ("vault_id" = Uuid, Path)),
    request_body = UpsertEntityAclRequest, responses((status = 200, body = EntityAclResponse)))]
pub async fn upsert(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, vault_id)): Path<(Uuid, Uuid)>,
    Body(req): Body<UpsertEntityAclRequest>,
) -> ApiResult<Json<EntityAclResponse>> {
    crate::authz::require(&state, id, auth.user_id(), "acl.manage").await?;
    team_vault(&state, id, vault_id).await?;
    let entity_kind = req.entity_kind.trim().to_lowercase();
    if !ENTITY_KINDS.contains(&entity_kind.as_str()) {
        return Err(Error::bad_request("entity_kind must be group or host"));
    }
    let mode = req.mode.trim().to_lowercase();
    if !MODES.contains(&mode.as_str()) {
        return Err(Error::bad_request(
            "mode must be none, connect, read or edit",
        ));
    }
    let principal_kind = req.principal_kind.trim().to_lowercase();
    if !PRINCIPAL_KINDS.contains(&principal_kind.as_str()) {
        return Err(Error::bad_request(
            "principal_kind must be role, member or group",
        ));
    }
    let (mut role_id, mut user_id, mut group_name) = (None, None, None);
    match principal_kind.as_str() {
        "role" => {
            let rid = req
                .role_id
                .ok_or_else(|| Error::bad_request("role_id is required"))?;
            let ok: Option<(String,)> =
                sqlx::query_as("SELECT slug FROM team_roles WHERE id = $1 AND team_id = $2")
                    .bind(rid)
                    .bind(id)
                    .fetch_optional(&state.db)
                    .await?;
            match ok {
                None => return Err(Error::not_found("Team role")),
                Some((slug,)) if slug == "owner" || slug == "admin" => {
                    return Err(Error::bad_request(
                        "Owners and admins are never restricted by access rules",
                    ));
                }
                Some(_) => {}
            }
            role_id = Some(rid);
        }
        "member" => {
            let uid = req
                .user_id
                .ok_or_else(|| Error::bad_request("user_id is required"))?;
            let m = crate::authz::membership(&state.db, id, uid)
                .await
                .map_err(|_| Error::not_found("Team member"))?;
            if m.is_admin() {
                return Err(Error::bad_request(
                    "Owners and admins are never restricted by access rules",
                ));
            }
            user_id = Some(uid);
        }
        _ => {
            let g = req
                .group_name
                .map(|g| g.trim().to_string())
                .filter(|g| !g.is_empty())
                .ok_or_else(|| Error::bad_request("group_name is required"))?;
            group_name = Some(g.chars().take(200).collect::<String>());
        }
    }
    let (rule_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO entity_acl (team_id, vault_id, entity_id, entity_kind, principal_kind, role_id, user_id, group_name, mode, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (vault_id, entity_id, principal_kind,
                      COALESCE(role_id, '00000000-0000-0000-0000-000000000000'::uuid),
                      COALESCE(user_id, '00000000-0000-0000-0000-000000000000'::uuid),
                      COALESCE(group_name, ''))
         DO UPDATE SET entity_kind = EXCLUDED.entity_kind, mode = EXCLUDED.mode, updated_at = now()
         RETURNING id",
    )
    .bind(id)
    .bind(vault_id)
    .bind(req.entity_id)
    .bind(&entity_kind)
    .bind(&principal_kind)
    .bind(role_id)
    .bind(user_id)
    .bind(&group_name)
    .bind(&mode)
    .bind(auth.user_id())
    .fetch_one(&state.db)
    .await?;
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "acl.updated")
            .vault(vault_id)
            .details(serde_json::json!({
                "rule_id": rule_id,
                "entity_id": req.entity_id,
                "entity_kind": entity_kind,
                "principal_kind": principal_kind,
                "role_id": role_id,
                "user_id": user_id,
                "group_name": group_name,
                "mode": mode,
            })),
    )
    .await;
    list_rules(&state, vault_id, &PageQuery::default()).await
}

#[utoipa::path(delete, path = "/api/v1/teams/{id}/vaults/{vault_id}/acl/{rule_id}", tag = "teams",
    params(("id" = Uuid, Path), ("vault_id" = Uuid, Path), ("rule_id" = Uuid, Path)),
    responses((status = 200, body = EntityAclResponse)))]
pub async fn delete(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, vault_id, rule_id)): Path<(Uuid, Uuid, Uuid)>,
) -> ApiResult<Json<EntityAclResponse>> {
    crate::authz::require(&state, id, auth.user_id(), "acl.manage").await?;
    team_vault(&state, id, vault_id).await?;
    let n = sqlx::query("DELETE FROM entity_acl WHERE id = $1 AND vault_id = $2 AND team_id = $3")
        .bind(rule_id)
        .bind(vault_id)
        .bind(id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(Error::not_found("Access rule"));
    }
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "acl.removed")
            .vault(vault_id)
            .details(serde_json::json!({ "rule_id": rule_id })),
    )
    .await;
    list_rules(&state, vault_id, &PageQuery::default()).await
}

/// Rules that apply to the caller across all team vaults.
#[utoipa::path(get, path = "/api/v1/acl/me", tag = "teams",
    responses((status = 200, body = MyAclResponse)))]
pub async fn me(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<MyAclResponse>> {
    let rules = acl::rules_for_user(&state.db, auth.user_id(), None).await?;
    Ok(Json(MyAclResponse {
        rules: rules
            .into_iter()
            .map(|r| MyAclRule {
                vault_id: r.vault_id,
                entity_id: r.entity_id,
                entity_kind: r.entity_kind,
                mode: r.mode,
            })
            .collect(),
    }))
}
