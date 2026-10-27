//! Vaults: personal and team containers for encrypted entities. The server
//! stores each member's *sealed* copy of the vault key and never the key itself.

use axum::Json;
use axum::extract::{Path, Query, State};

use super::paging::PageQuery;
use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use termoso_crypto::encoding::unb64;
use termoso_proto::vault::*;
use uuid::Uuid;

use crate::audit;
use crate::error::{ApiResult, Error, NoContent};
use crate::events::{self, Event};
use crate::extract::{Auth, Json as Body};
use crate::routes::teams::{self, parse_vault_role, vault_role_str};
use crate::state::AppState;
use crate::users;

/// Access info for one user in one vault.
#[derive(Debug, Clone)]
pub struct Access {
    pub vault_id: Uuid,
    pub kind: VaultKind,
    pub team_id: Option<Uuid>,
    pub role: VaultRole,
    pub key_version: i32,
    /// Member row exists but the key has not been sealed to them yet.
    pub pending: bool,
}

/// Look up `user_id`'s membership in `vault_id`. Team admins get implicit
/// manager rights on team vaults (needed to seal keys for new members) but no
/// data access unless they hold a sealed key. Team vaults whose team requires
/// two-factor authentication are unreachable for members without it.
pub async fn access<'e, E: PgExecutor<'e>>(
    db: E,
    vault_id: Uuid,
    user_id: Uuid,
) -> ApiResult<Access> {
    let row: Option<(
        String,
        Option<Uuid>,
        i32,
        Option<String>,
        Option<bool>,
        Option<Vec<String>>,
        Option<String>,
        bool,
        bool,
    )> = sqlx::query_as(
        "SELECT v.kind, v.team_id, v.key_version, vm.role, vm.sealed_key IS NULL,
                (SELECT r.permissions FROM team_roles r WHERE r.id = tm.role_id),
                (SELECT p.mfa FROM team_policies p WHERE p.team_id = v.team_id),
                EXISTS (SELECT 1 FROM users u WHERE u.id = $2 AND u.totp_enabled),
                EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = $2)
         FROM vaults v
         LEFT JOIN vault_members vm ON vm.vault_id = v.id AND vm.user_id = $2
         LEFT JOIN team_members tm ON tm.team_id = v.team_id AND tm.user_id = $2
         LEFT JOIN teams t ON t.id = v.team_id
         WHERE v.id = $1 AND v.deleted_at IS NULL",
    )
    .bind(vault_id)
    .bind(user_id)
    .fetch_optional(db)
    .await?;
    let Some((kind, team_id, key_version, vrole, pending, trole, mfa_level, has_totp, has_passkey)) =
        row
    else {
        return Err(Error::not_found("Vault"));
    };
    let level = mfa_level.as_deref().unwrap_or("off");
    if !crate::policy::satisfies(level, has_totp, has_passkey)
        && (vrole.is_some() || trole.is_some())
    {
        return Err(Error::mfa_required()
            .with_details(serde_json::json!({ "team_id": team_id, "level": level })));
    }
    let kind = if kind == "team" {
        VaultKind::Team
    } else {
        VaultKind::Personal
    };
    // A role holding `vaults.members` (or `*`) acts as manager on every
    // team vault, like team admins did before fine-grained roles.
    let team_admin = trole
        .as_ref()
        .map(|p| p.iter().any(|x| x == "*" || x == "vaults.members"))
        .unwrap_or(false);
    let role = match (vrole, team_admin) {
        (Some(r), true) => parse_vault_role(&r).max(VaultRole::Manager),
        (Some(r), false) => parse_vault_role(&r),
        (None, true) => VaultRole::Manager,
        (None, false) => return Err(Error::not_found("Vault")),
    };
    Ok(Access {
        vault_id,
        kind,
        team_id,
        role,
        key_version,
        pending: pending.unwrap_or(true),
    })
}

pub async fn require_write(state: &AppState, vault_id: Uuid, user_id: Uuid) -> ApiResult<Access> {
    let a = access(&state.db, vault_id, user_id).await?;
    if !a.role.can_write() || a.pending {
        return Err(Error::forbidden("No write access to this vault"));
    }
    Ok(a)
}

pub async fn require_manage(state: &AppState, vault_id: Uuid, user_id: Uuid) -> ApiResult<Access> {
    let a = access(&state.db, vault_id, user_id).await?;
    if !a.role.can_manage() {
        return Err(Error::forbidden("Vault manager role required"));
    }
    Ok(a)
}

pub async fn member_ids<'e, E: PgExecutor<'e>>(db: E, vault_id: Uuid) -> ApiResult<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM vault_members WHERE vault_id = $1")
            .bind(vault_id)
            .fetch_all(db)
            .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

fn validate_name(name: &str) -> ApiResult<String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 100 {
        return Err(Error::bad_request("Invalid vault name"));
    }
    Ok(n.to_string())
}

fn validate_sealed(sealed: &str) -> ApiResult<()> {
    let b = unb64(sealed).map_err(|_| Error::bad_request("sealed_key is not valid base64"))?;
    if b.len() < 48 || b.len() > 512 {
        return Err(Error::bad_request("sealed_key has an unexpected length"));
    }
    Ok(())
}

// ───────────────────────────── list / get ─────────────────────────────

#[utoipa::path(get, path = "/api/v1/vaults", tag = "vaults", responses((status = 200, body = VaultList)))]
pub async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<VaultList>> {
    let rows: Vec<(Uuid, String, Option<Uuid>, String, DateTime<Utc>, String, Option<String>, i32, bool, bool)> = sqlx::query_as(
        "SELECT v.id, v.kind, v.team_id, v.name, v.created_at, vm.role, vm.sealed_key, v.key_version, v.session_logging, v.is_default
         FROM vaults v JOIN vault_members vm ON vm.vault_id = v.id
         WHERE vm.user_id = $1 AND v.deleted_at IS NULL
         ORDER BY v.kind, v.created_at",
    )
    .bind(auth.user_id())
    .fetch_all(&state.db)
    .await?;
    Ok(Json(VaultList {
        vaults: rows
            .into_iter()
            .map(
                |(
                    id,
                    kind,
                    team_id,
                    name,
                    created_at,
                    role,
                    sealed_key,
                    key_version,
                    session_logging,
                    is_default,
                )| Vault {
                    id,
                    kind: if kind == "team" {
                        VaultKind::Team
                    } else {
                        VaultKind::Personal
                    },
                    team_id,
                    name,
                    created_at,
                    my_role: parse_vault_role(&role),
                    sealed_key,
                    key_version,
                    session_logging,
                    is_default,
                },
            )
            .collect(),
    }))
}

#[utoipa::path(get, path = "/api/v1/vaults/{id}", tag = "vaults", params(("id" = Uuid, Path)), responses((status = 200, body = Vault)))]
pub async fn get(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vault>> {
    let a = access(&state.db, id, auth.user_id()).await?;
    let (name, created_at, sealed_key, session_logging, is_default): (
        String,
        DateTime<Utc>,
        Option<String>,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT v.name, v.created_at, vm.sealed_key, v.session_logging, v.is_default FROM vaults v
         LEFT JOIN vault_members vm ON vm.vault_id = v.id AND vm.user_id = $2 WHERE v.id = $1",
    )
    .bind(id)
    .bind(auth.user_id())
    .fetch_one(&state.db)
    .await?;
    Ok(Json(Vault {
        id,
        kind: a.kind,
        team_id: a.team_id,
        name,
        created_at,
        my_role: a.role,
        sealed_key,
        key_version: a.key_version,
        session_logging,
        is_default,
    }))
}

// ───────────────────────────── create / update / delete ─────────────────────────────

#[utoipa::path(post, path = "/api/v1/teams/{id}/vaults", tag = "vaults", params(("id" = Uuid, Path)),
    request_body = CreateVaultRequest, responses((status = 200, body = Vault)))]
pub async fn create_team_vault(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
    Body(req): Body<CreateVaultRequest>,
) -> ApiResult<Json<Vault>> {
    crate::authz::require(&state, team_id, auth.user_id(), "vaults.create").await?;
    let name = validate_name(&req.name)?;
    let me = req
        .members
        .iter()
        .find(|m| m.user_id == auth.user_id())
        .ok_or_else(|| {
            Error::bad_request("The creator must be included in members with a sealed key")
        })?;
    if me.role != VaultRole::Manager {
        return Err(Error::bad_request("The creator must be a manager"));
    }
    for m in &req.members {
        validate_sealed(&m.sealed_key)?;
        teams::my_role(&state.db, team_id, m.user_id)
            .await
            .map_err(|_| Error::bad_request("All members must belong to the team"))?;
    }
    let id = Uuid::new_v4();
    let mut tx = state.db.begin().await?;
    // Serialise per team so exactly one vault becomes the default.
    sqlx::query("SELECT 1 FROM teams WHERE id = $1 FOR UPDATE")
        .bind(team_id)
        .execute(&mut *tx)
        .await?;
    let (created_at, is_default): (DateTime<Utc>, bool) = sqlx::query_as(
        "INSERT INTO vaults (id, kind, team_id, name, is_default)
         VALUES ($1, 'team', $2, $3, NOT EXISTS (
             SELECT 1 FROM vaults WHERE team_id = $2 AND kind = 'team' AND is_default AND deleted_at IS NULL))
         RETURNING created_at, is_default",
    )
    .bind(id)
    .bind(team_id)
    .bind(&name)
    .fetch_one(&mut *tx)
    .await?;
    for m in &req.members {
        sqlx::query(
            "INSERT INTO vault_members (vault_id, user_id, role, sealed_key, key_version, added_by) VALUES ($1, $2, $3, $4, 1, $5)",
        )
        .bind(id)
        .bind(m.user_id)
        .bind(vault_role_str(m.role))
        .bind(&m.sealed_key)
        .bind(auth.user_id())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    let ids: Vec<Uuid> = req.members.iter().map(|m| m.user_id).collect();
    events::publish(&state, Event::VaultsUpdated { user_ids: ids }).await?;
    metrics::counter!("termoso_vaults_created_total").increment(1);
    audit::record(
        &state.db,
        audit::Entry::new(team_id, &auth, "vault.created")
            .vault(id)
            .details(serde_json::json!({
                "name": name,
                "default": is_default,
                "members": req.members.iter().map(|m| serde_json::json!({
                    "user_id": m.user_id,
                    "role": vault_role_str(m.role),
                })).collect::<Vec<_>>(),
            })),
    )
    .await;
    Ok(Json(Vault {
        id,
        kind: VaultKind::Team,
        team_id: Some(team_id),
        name,
        created_at,
        my_role: VaultRole::Manager,
        sealed_key: Some(me.sealed_key.clone()),
        key_version: 1,
        session_logging: false,
        is_default,
    }))
}

#[utoipa::path(patch, path = "/api/v1/vaults/{id}", tag = "vaults", params(("id" = Uuid, Path)),
    request_body = UpdateVaultRequest, responses((status = 200, body = Vault)))]
pub async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<UpdateVaultRequest>,
) -> ApiResult<Json<Vault>> {
    let a = require_manage(&state, id, auth.user_id()).await?;
    let mut changed = false;
    if let Some(name) = &req.name {
        let name = validate_name(name)?;
        sqlx::query("UPDATE vaults SET name = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(&name)
            .execute(&state.db)
            .await?;
        if let Some(team_id) = a.team_id {
            audit::record(
                &state.db,
                audit::Entry::new(team_id, &auth, "vault.renamed")
                    .vault(id)
                    .details(serde_json::json!({ "name": name })),
            )
            .await;
        }
        changed = true;
    }
    if let Some(on) = req.session_logging {
        let Some(team_id) = a.team_id else {
            return Err(Error::forbidden("Session logging is a team vault setting"));
        };
        if !on && crate::policy::recording_required(&state.db, team_id).await? {
            return Err(Error::forbidden(
                "Team policy makes session recording mandatory",
            ));
        }
        let r = sqlx::query(
            "UPDATE vaults SET session_logging = $2, updated_at = now() WHERE id = $1 AND session_logging <> $2",
        )
        .bind(id)
        .bind(on)
        .execute(&state.db)
        .await?;
        if r.rows_affected() > 0 {
            audit::record(
                &state.db,
                audit::Entry::new(team_id, &auth, "vault.session_logging")
                    .vault(id)
                    .details(serde_json::json!({ "enabled": on })),
            )
            .await;
            changed = true;
        }
    }
    if changed {
        events::publish(
            &state,
            Event::VaultsUpdated {
                user_ids: member_ids(&state.db, id).await?,
            },
        )
        .await?;
    }
    get(State(state), auth, Path(id)).await
}

#[utoipa::path(delete, path = "/api/v1/vaults/{id}", tag = "vaults", params(("id" = Uuid, Path)), responses((status = 204)))]
pub async fn delete(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<NoContent> {
    let a = require_manage(&state, id, auth.user_id()).await?;
    if a.kind == VaultKind::Personal {
        return Err(Error::forbidden("The personal vault cannot be deleted"));
    }
    let members = member_ids(&state.db, id).await?;
    let (name, is_default): (String, bool) =
        sqlx::query_as("SELECT name, is_default FROM vaults WHERE id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await?;
    if is_default {
        return Err(Error::forbidden(
            "The team's default vault cannot be deleted; rename it instead",
        ));
    }
    let log_keys: Vec<(String,)> =
        sqlx::query_as("SELECT object_key FROM session_logs WHERE vault_id = $1")
            .bind(id)
            .fetch_all(&state.db)
            .await?;
    sqlx::query("DELETE FROM vaults WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    if let Some(team_id) = a.team_id {
        audit::record(
            &state.db,
            audit::Entry::new(team_id, &auth, "vault.deleted")
                .vault(id)
                .details(serde_json::json!({ "name": name, "members": members.len() })),
        )
        .await;
    }
    if let Some(storage) = &state.storage {
        for (k,) in log_keys {
            if let Err(e) = storage.delete(&k).await {
                tracing::warn!(error = %e, key = %k, "could not delete log object");
            }
        }
    }
    events::publish(&state, Event::VaultsUpdated { user_ids: members }).await?;
    users::security_event(
        &state,
        auth.user_id(),
        "vault_deleted",
        Some(auth.device_id()),
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        Some(serde_json::json!({ "vault_id": id })),
    )
    .await
    .map(NoContent::from)
}

// ───────────────────────────── members ─────────────────────────────

#[utoipa::path(get, path = "/api/v1/vaults/{id}/members", tag = "vaults", params(("id" = Uuid, Path), PageQuery),
    responses((status = 200, body = VaultMemberList)))]
pub async fn members(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Query(pq): Query<PageQuery>,
) -> ApiResult<Json<VaultMemberList>> {
    access(&state.db, id, auth.user_id()).await?;
    let (offset, limit) = pq.window(10_000);
    type Row = (
        Uuid,
        String,
        Option<String>,
        Option<String>,
        String,
        i32,
        bool,
        String,
        DateTime<Utc>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT u.id, u.email, u.display_name, u.avatar_tag, vm.role, vm.key_version, vm.sealed_key IS NULL, u.public_key, vm.added_at
         FROM vault_members vm JOIN users u ON u.id = vm.user_id WHERE vm.vault_id = $1
         ORDER BY vm.added_at LIMIT $2 OFFSET $3",
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
            "SELECT count(*) FROM vault_members WHERE vault_id = $1",
            id,
        )
        .await?;
    Ok(Json(VaultMemberList {
        total,
        members: rows
            .into_iter()
            .map(
                |(
                    user_id,
                    email,
                    display_name,
                    avatar,
                    role,
                    key_version,
                    pending,
                    public_key,
                    added_at,
                )| VaultMember {
                    user_id,
                    email,
                    display_name,
                    avatar,
                    role: parse_vault_role(&role),
                    key_version,
                    pending,
                    public_key,
                    added_at,
                },
            )
            .collect(),
    }))
}

/// Add a member or update their role / sealed key.
#[utoipa::path(put, path = "/api/v1/vaults/{id}/members/{user_id}", tag = "vaults",
    params(("id" = Uuid, Path), ("user_id" = Uuid, Path)),
    request_body = VaultMemberUpsert, responses((status = 204)))]
pub async fn upsert_member(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Body(req): Body<VaultMemberUpsert>,
) -> ApiResult<NoContent> {
    let a = require_manage(&state, id, auth.user_id()).await?;
    if a.kind == VaultKind::Personal {
        return Err(Error::forbidden("The personal vault cannot be shared"));
    }
    if req.user_id != user_id {
        return Err(Error::bad_request("user_id mismatch"));
    }
    validate_sealed(&req.sealed_key)?;
    let team_id = a
        .team_id
        .ok_or_else(|| Error::Internal(anyhow::anyhow!("team vault without team")))?;
    teams::my_role(&state.db, team_id, user_id)
        .await
        .map_err(|_| Error::bad_request("User is not a member of the team"))?;
    if user_id == auth.user_id() && req.role != VaultRole::Manager {
        // A manager may not demote themselves if they are the last manager.
        let (managers,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM vault_members WHERE vault_id = $1 AND role = 'manager' AND user_id <> $2")
                .bind(id)
                .bind(user_id)
                .fetch_one(&state.db)
                .await?;
        if managers == 0 {
            return Err(Error::conflict("A vault needs at least one manager"));
        }
    }
    let previous: Option<(String, bool)> = sqlx::query_as(
        "SELECT role, sealed_key IS NULL FROM vault_members WHERE vault_id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    sqlx::query(
        "INSERT INTO vault_members (vault_id, user_id, role, sealed_key, key_version, added_by)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (vault_id, user_id) DO UPDATE SET role = EXCLUDED.role, sealed_key = EXCLUDED.sealed_key, key_version = EXCLUDED.key_version",
    )
    .bind(id)
    .bind(user_id)
    .bind(vault_role_str(req.role))
    .bind(&req.sealed_key)
    .bind(a.key_version)
    .bind(auth.user_id())
    .execute(&state.db)
    .await?;
    let (action, previous_role) = match previous {
        // Sealing a pending (invited) member's key is a grant, not a change.
        None | Some((_, true)) => ("vault.access_granted", None),
        Some((r, false)) => ("vault.access_changed", Some(r)),
    };
    audit::record(
        &state.db,
        audit::Entry::new(team_id, &auth, action)
            .vault(id)
            .user(user_id)
            .details(serde_json::json!({
                "role": vault_role_str(req.role),
                "previous_role": previous_role,
                "key_version": a.key_version,
            })),
    )
    .await;
    events::publish(
        &state,
        Event::VaultsUpdated {
            user_ids: vec![user_id, auth.user_id()],
        },
    )
    .await
    .map(NoContent::from)
}

#[utoipa::path(delete, path = "/api/v1/vaults/{id}/members/{user_id}", tag = "vaults",
    params(("id" = Uuid, Path), ("user_id" = Uuid, Path)), responses((status = 204)))]
pub async fn remove_member(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<NoContent> {
    let a = if user_id == auth.user_id() {
        access(&state.db, id, auth.user_id()).await?
    } else {
        require_manage(&state, id, auth.user_id()).await?
    };
    if a.kind == VaultKind::Personal {
        return Err(Error::forbidden(
            "The personal vault has a fixed membership",
        ));
    }
    let (managers,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM vault_members WHERE vault_id = $1 AND role = 'manager' AND user_id <> $2 AND sealed_key IS NOT NULL")
            .bind(id)
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    if managers == 0 {
        let team_admin_exists = match a.team_id {
            Some(t) => {
                let (n,): (i64,) = sqlx::query_as(
                    "SELECT count(*) FROM team_members WHERE team_id = $1 AND role IN ('owner','admin') AND user_id <> $2",
                )
                .bind(t)
                .bind(user_id)
                .fetch_one(&state.db)
                .await?;
                n > 0
            }
            None => false,
        };
        if !team_admin_exists {
            return Err(Error::conflict("A vault needs at least one manager"));
        }
    }
    let res: Option<(String,)> = sqlx::query_as(
        "DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2 RETURNING role",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((previous_role,)) = res else {
        return Err(Error::not_found("Member"));
    };
    if let Some(team_id) = a.team_id {
        audit::record(
            &state.db,
            audit::Entry::new(team_id, &auth, "vault.access_revoked")
                .vault(id)
                .user(user_id)
                .details(serde_json::json!({
                    "previous_role": previous_role,
                    "self": user_id == auth.user_id(),
                })),
        )
        .await;
    }
    events::publish(
        &state,
        Event::VaultsUpdated {
            user_ids: vec![user_id, auth.user_id()],
        },
    )
    .await
    .map(NoContent::from)
}

// ───────────────────────────── key rotation ─────────────────────────────

/// Replace the caller's own sealed copy of the current key. The key and its
/// version do not change, so this never grants or extends access; it lets a
/// client swap an anonymous sealed box for a self-authenticated one so its
/// other devices can tell the key came from the account holder.
#[utoipa::path(put, path = "/api/v1/vaults/{id}/my-key", tag = "vaults", params(("id" = Uuid, Path)),
    request_body = ResealMyKeyRequest, responses((status = 204)))]
pub async fn reseal_my_key(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<ResealMyKeyRequest>,
) -> ApiResult<NoContent> {
    validate_sealed(&req.sealed_key)?;
    let a = access(&state.db, id, auth.user_id()).await?;
    if a.pending {
        return Err(Error::forbidden("You do not hold a key for this vault"));
    }
    if a.key_version != req.key_version {
        return Err(Error::conflict("Vault key was rotated"));
    }
    let updated = sqlx::query(
        "UPDATE vault_members SET sealed_key = $3
         WHERE vault_id = $1 AND user_id = $2 AND key_version = $4 AND sealed_key IS NOT NULL",
    )
    .bind(id)
    .bind(auth.user_id())
    .bind(&req.sealed_key)
    .bind(req.key_version)
    .execute(&state.db)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(Error::conflict("Vault key was rotated"));
    }
    Ok(NoContent)
}

/// Rotate the vault key: the client generates a new key, re-seals it to every
/// remaining member and re-encrypts entities client-side afterwards (entities
/// carry `key_version`, so old and new can coexist during the migration).
#[utoipa::path(post, path = "/api/v1/vaults/{id}/rotate-key", tag = "vaults", params(("id" = Uuid, Path)),
    request_body = RotateVaultKeyRequest, responses((status = 200, body = RotateVaultKeyResponse)))]
pub async fn rotate_key(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<RotateVaultKeyRequest>,
) -> ApiResult<Json<RotateVaultKeyResponse>> {
    let a = require_manage(&state, id, auth.user_id()).await?;
    if a.key_version != req.base_key_version {
        return Err(Error::conflict("Vault key was rotated by someone else"));
    }
    let current = member_ids(&state.db, id).await?;
    let provided: std::collections::HashSet<Uuid> = req.members.iter().map(|m| m.user_id).collect();
    for m in &req.members {
        validate_sealed(&m.sealed_key)?;
        if !current.contains(&m.user_id) {
            return Err(Error::bad_request("Unknown member in rotation set"));
        }
    }
    if !provided.contains(&auth.user_id()) && a.kind == VaultKind::Team {
        let is_member = current.contains(&auth.user_id());
        if is_member {
            return Err(Error::bad_request("Include your own sealed key"));
        }
    }
    let new_version = a.key_version + 1;
    let mut tx = state.db.begin().await?;
    let updated = sqlx::query(
        "UPDATE vaults SET key_version = $2, updated_at = now() WHERE id = $1 AND key_version = $3",
    )
    .bind(id)
    .bind(new_version)
    .bind(req.base_key_version)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(Error::conflict("Vault key was rotated by someone else"));
    }
    // Members without a new sealed key lose access (this is how a removed
    // member's stale copy of the key is made useless).
    sqlx::query("UPDATE vault_members SET sealed_key = NULL, key_version = $2 WHERE vault_id = $1")
        .bind(id)
        .bind(new_version)
        .execute(&mut *tx)
        .await?;
    // Same for API bridges: their owner re-seals the new key from the cabinet.
    sqlx::query("UPDATE bridge_vaults SET sealed_key = NULL, key_version = $2 WHERE vault_id = $1")
        .bind(id)
        .bind(new_version)
        .execute(&mut *tx)
        .await?;
    for m in &req.members {
        sqlx::query("UPDATE vault_members SET sealed_key = $3, key_version = $4 WHERE vault_id = $1 AND user_id = $2")
            .bind(id)
            .bind(m.user_id)
            .bind(&m.sealed_key)
            .bind(new_version)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    if let Some(team_id) = a.team_id {
        let dropped: Vec<Uuid> = current
            .iter()
            .copied()
            .filter(|u| !provided.contains(u))
            .collect();
        audit::record(
            &state.db,
            audit::Entry::new(team_id, &auth, "vault.key_rotated")
                .vault(id)
                .details(serde_json::json!({
                    "key_version": new_version,
                    "resealed_for": req.members.iter().map(|m| m.user_id).collect::<Vec<_>>(),
                    "access_dropped": dropped,
                })),
        )
        .await;
    }
    events::publish(&state, Event::VaultsUpdated { user_ids: current }).await?;
    users::security_event(
        &state,
        auth.user_id(),
        "vault_key_rotated",
        Some(auth.device_id()),
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        Some(serde_json::json!({ "vault_id": id, "key_version": new_version })),
    )
    .await?;
    Ok(Json(RotateVaultKeyResponse {
        key_version: new_version,
    }))
}
