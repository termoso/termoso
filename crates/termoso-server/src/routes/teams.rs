//! Teams: membership, roles, invitations and pending vault-key requests.

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, Postgres, Transaction};
use termoso_proto::team::*;
use termoso_proto::vault::VaultRole;
use uuid::Uuid;

use crate::audit;
use crate::error::{ApiResult, Error, NoContent};
use crate::events::{self, Event};
use crate::extract::{Auth, Client, Json as Body, StepUp};
use crate::presence;
use crate::ratelimit;
use crate::state::AppState;
use crate::users;
use crate::util::{hash_token, normalize_email, random_token};

const INVITE_DAYS: i64 = 14;

pub fn team_role_str(r: TeamRole) -> &'static str {
    match r {
        TeamRole::Member => "member",
        TeamRole::Admin => "admin",
        TeamRole::Owner => "owner",
    }
}

pub fn parse_team_role(s: &str) -> TeamRole {
    match s {
        "owner" => TeamRole::Owner,
        "admin" => TeamRole::Admin,
        _ => TeamRole::Member,
    }
}

pub fn vault_role_str(r: VaultRole) -> &'static str {
    match r {
        VaultRole::Viewer => "viewer",
        VaultRole::Editor => "editor",
        VaultRole::Manager => "manager",
    }
}

pub fn parse_vault_role(s: &str) -> VaultRole {
    match s {
        "manager" => VaultRole::Manager,
        "editor" => VaultRole::Editor,
        _ => VaultRole::Viewer,
    }
}

/// Role of `user_id` in `team_id`, or 404 if not a member.
pub async fn my_role<'e, E: PgExecutor<'e>>(
    db: E,
    team_id: Uuid,
    user_id: Uuid,
) -> ApiResult<TeamRole> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2")
            .bind(team_id)
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    row.map(|(r,)| parse_team_role(&r))
        .ok_or_else(|| Error::not_found("Team"))
}

pub async fn member_ids<'e, E: PgExecutor<'e>>(db: E, team_id: Uuid) -> ApiResult<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> = sqlx::query_as("SELECT user_id FROM team_members WHERE team_id = $1")
        .bind(team_id)
        .fetch_all(db)
        .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

fn validate_name(name: &str) -> ApiResult<String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 100 {
        return Err(Error::bad_request("Invalid team name"));
    }
    Ok(n.to_string())
}

// ───────────────────────────── teams ─────────────────────────────

#[utoipa::path(get, path = "/api/v1/teams", tag = "teams", responses((status = 200, body = TeamList)))]
pub async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<TeamList>> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        Uuid,
        String,
        DateTime<Utc>,
        String,
        i64,
        bool,
        bool,
        bool,
        Uuid,
        String,
        String,
        Vec<String>,
    )> = sqlx::query_as(
        "SELECT t.id, t.name, t.created_at, m.role,
                (SELECT count(*) FROM team_members x WHERE x.team_id = t.id),
                t.multiplayer_enabled, t.require_mfa, t.presence_enabled,
                r.id, r.slug, r.name, r.permissions
         FROM teams t JOIN team_members m ON m.team_id = t.id
         JOIN team_roles r ON r.id = m.role_id
         WHERE m.user_id = $1 ORDER BY t.created_at",
    )
    .bind(auth.user_id())
    .fetch_all(&state.db)
    .await?;
    let mut out = TeamList {
        teams: rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    created_at,
                    role,
                    member_count,
                    multiplayer_enabled,
                    require_mfa,
                    presence_enabled,
                    role_id,
                    role_slug,
                    role_name,
                    role_perms,
                )| {
                    let level = parse_team_role(&role);
                    let (my_role_ref, my_permissions) =
                        crate::authz::role_parts(level, role_id, role_slug, role_name, role_perms);
                    Team {
                        id,
                        name,
                        created_at,
                        my_role: parse_team_role(&role),
                        my_role_ref: Some(my_role_ref),
                        my_permissions,
                        member_count,
                        multiplayer_enabled,
                        require_mfa,
                        presence_enabled,
                        policies: None,
                    }
                },
            )
            .collect(),
    };
    crate::policy::attach(&state.db, &mut out.teams).await?;
    Ok(Json(out))
}

#[utoipa::path(post, path = "/api/v1/teams", tag = "teams",
    request_body = CreateTeamRequest, responses((status = 200, body = Team)))]
pub async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Body(req): Body<CreateTeamRequest>,
) -> ApiResult<Json<Team>> {
    let name = validate_name(&req.name)?;
    if !auth.session.is_admin && !state.settings().await?.users_can_create_teams {
        return Err(Error::forbidden("Team creation is disabled on this server"));
    }
    if !auth.session.email_verified && state.mailer.is_some() {
        return Err(Error::email_unverified());
    }
    let id = Uuid::new_v4();
    let mut tx = state.db.begin().await?;
    let (created_at,): (DateTime<Utc>,) = sqlx::query_as(
        "INSERT INTO teams (id, name, owner_id, region) VALUES ($1, $2, $3, $4) RETURNING created_at",
    )
    .bind(id)
    .bind(&name)
    .bind(auth.user_id())
    .bind(&state.cfg.data_region)
    .fetch_one(&mut *tx)
    .await?;
    let owner_role_id = crate::authz::seed_builtin_roles(&mut tx, id).await?;
    sqlx::query(
        "INSERT INTO team_members (team_id, user_id, role, role_id) VALUES ($1, $2, 'owner', $3)",
    )
    .bind(id)
    .bind(auth.user_id())
    .bind(owner_role_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    metrics::counter!("termoso_teams_created_total").increment(1);
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "team.created").details(serde_json::json!({ "name": name })),
    )
    .await;
    Ok(Json(Team {
        id,
        name,
        created_at,
        my_role: TeamRole::Owner,
        my_role_ref: Some(RoleRef {
            id: owner_role_id,
            slug: "owner".into(),
            name: "Owner".into(),
        }),
        my_permissions: vec!["*".to_string()],
        member_count: 1,
        multiplayer_enabled: true,
        require_mfa: false,
        presence_enabled: false,
        policies: None,
    }))
}

#[utoipa::path(get, path = "/api/v1/teams/{id}", tag = "teams", params(("id" = Uuid, Path)), responses((status = 200, body = Team)))]
pub async fn get(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Team>> {
    let membership = crate::authz::membership(&state.db, id, auth.user_id()).await?;
    let role = membership.level;
    let (name, created_at, member_count, multiplayer_enabled, require_mfa, presence_enabled): (
        String,
        DateTime<Utc>,
        i64,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT name, created_at, (SELECT count(*) FROM team_members WHERE team_id = $1),
                multiplayer_enabled, require_mfa, presence_enabled
         FROM teams WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(Team {
        id,
        name,
        created_at,
        my_role: role,
        my_role_ref: Some(membership.role.clone()),
        my_permissions: membership.permission_list(),
        member_count,
        multiplayer_enabled,
        require_mfa,
        presence_enabled,
        policies: Some(crate::policy::load(&state.db, id).await?),
    }))
}

#[utoipa::path(patch, path = "/api/v1/teams/{id}", tag = "teams", params(("id" = Uuid, Path)),
    request_body = UpdateTeamRequest, responses((status = 200, body = Team)))]
pub async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<UpdateTeamRequest>,
) -> ApiResult<Json<Team>> {
    crate::authz::require(&state, id, auth.user_id(), "team.rename").await?;
    if let Some(name) = &req.name {
        let name = validate_name(name)?;
        sqlx::query("UPDATE teams SET name = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(&name)
            .execute(&state.db)
            .await?;
        audit::record(
            &state.db,
            audit::Entry::new(id, &auth, "team.renamed")
                .details(serde_json::json!({ "name": name })),
        )
        .await;
    }
    if let Some(on) = req.multiplayer_enabled {
        sqlx::query("UPDATE teams SET multiplayer_enabled = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(on)
            .execute(&state.db)
            .await?;
        audit::record(
            &state.db,
            audit::Entry::new(id, &auth, "team.settings")
                .details(serde_json::json!({ "multiplayer_enabled": on })),
        )
        .await;
    }
    if let Some(on) = req.require_mfa {
        if on && !users::mfa_enabled_for(&state, auth.user_id()).await? {
            return Err(Error::forbidden(
                "Turn on two-factor authentication for your own account first",
            ));
        }
        sqlx::query("UPDATE teams SET require_mfa = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(on)
            .execute(&state.db)
            .await?;
        sqlx::query(
            "INSERT INTO team_policies (team_id, mfa, updated_by) VALUES ($1, $2, $3)
             ON CONFLICT (team_id) DO UPDATE SET
                 mfa = CASE WHEN EXCLUDED.mfa = 'off' THEN 'off'
                            WHEN team_policies.mfa = 'passkey' THEN 'passkey' ELSE 'any' END,
                 updated_by = $3, updated_at = now()",
        )
        .bind(id)
        .bind(if on { "any" } else { "off" })
        .bind(auth.user_id())
        .execute(&state.db)
        .await?;
        audit::record(
            &state.db,
            audit::Entry::new(id, &auth, "team.settings")
                .details(serde_json::json!({ "require_mfa": on })),
        )
        .await;
    }
    if let Some(on) = req.presence_enabled {
        sqlx::query("UPDATE teams SET presence_enabled = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(on)
            .execute(&state.db)
            .await?;
        audit::record(
            &state.db,
            audit::Entry::new(id, &auth, "team.settings")
                .details(serde_json::json!({ "presence_enabled": on })),
        )
        .await;
        if !on {
            presence::clear_team(&state, id).await?;
        }
        events::publish(&state, Event::PresenceChanged { team_id: id }).await?;
    }
    events::publish(
        &state,
        Event::TeamsUpdated {
            user_ids: member_ids(&state.db, id).await?,
        },
    )
    .await?;
    get(State(state), auth, Path(id)).await
}

/// Hard-delete a team: rows cascade, log objects are removed from storage,
/// members are told to refresh. Returns the former member ids.
pub async fn purge(state: &AppState, id: Uuid) -> ApiResult<Vec<Uuid>> {
    let members = member_ids(&state.db, id).await?;
    let log_keys: Vec<(String,)> =
        sqlx::query_as("SELECT l.object_key FROM session_logs l JOIN vaults v ON v.id = l.vault_id WHERE v.team_id = $1")
            .bind(id)
            .fetch_all(&state.db)
            .await?;
    sqlx::query("DELETE FROM teams WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    if let Some(storage) = &state.storage {
        for (k,) in log_keys {
            if let Err(e) = storage.delete(&k).await {
                tracing::warn!(error = %e, key = %k, "could not delete log object");
            }
        }
    }
    events::publish(
        state,
        Event::TeamsUpdated {
            user_ids: members.clone(),
        },
    )
    .await?;
    events::publish(
        state,
        Event::VaultsUpdated {
            user_ids: members.clone(),
        },
    )
    .await?;
    Ok(members)
}

#[utoipa::path(delete, path = "/api/v1/teams/{id}", tag = "teams", params(("id" = Uuid, Path)), responses((status = 204)))]
pub async fn delete(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<NoContent> {
    let role = my_role(&state.db, id, auth.user_id()).await?;
    if role != TeamRole::Owner && !auth.session.is_admin {
        return Err(Error::forbidden("Only the owner can delete a team"));
    }
    purge(&state, id).await?;
    users::security_event(
        &state,
        auth.user_id(),
        "team_deleted",
        Some(auth.device_id()),
        auth.ip.as_deref(),
        auth.user_agent.as_deref(),
        Some(serde_json::json!({ "team_id": id })),
    )
    .await
    .map(NoContent::from)
}

// ───────────────────────────── members ─────────────────────────────

#[utoipa::path(get, path = "/api/v1/teams/{id}/members", tag = "teams", params(("id" = Uuid, Path)),
    responses((status = 200, body = TeamMemberList)))]
pub async fn members(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TeamMemberList>> {
    let me = crate::authz::membership(&state.db, id, auth.user_id()).await?;
    // Whether a member has a second factor is visible to roles holding
    // `members.view_mfa` (they enforce `require_mfa`) and to the member
    // themself; other members do not learn each other's security posture.
    let sees_mfa = me.has("members.view_mfa") || auth.session.is_admin;
    type Row = (
        Uuid,
        String,
        Option<String>,
        Option<String>,
        String,
        String,
        DateTime<Utc>,
        Uuid,
        String,
        String,
        String,
        bool,
        bool,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT u.id, u.email, u.display_name, u.avatar_tag, m.role, u.public_key, m.joined_at,
                r.id, r.slug, r.name, m.role_source,
                u.totp_enabled
                OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id),
                u.managed_by_team_id IS NOT DISTINCT FROM m.team_id
         FROM team_members m JOIN users u ON u.id = m.user_id
         JOIN team_roles r ON r.id = m.role_id
         WHERE m.team_id = $1 ORDER BY m.joined_at",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(TeamMemberList {
        members: rows
            .into_iter()
            .map(
                |(
                    user_id,
                    email,
                    display_name,
                    avatar,
                    role,
                    public_key,
                    joined_at,
                    role_id,
                    role_slug,
                    role_name,
                    role_source,
                    mfa,
                    managed,
                )| {
                    TeamMember {
                        role_ref: Some(RoleRef {
                            id: role_id,
                            slug: role_slug,
                            name: role_name,
                        }),
                        role_source: Some(role_source),
                        user_id,
                        email,
                        display_name,
                        avatar,
                        role: parse_team_role(&role),
                        public_key,
                        joined_at,
                        mfa_enabled: (sees_mfa || user_id == auth.user_id()).then_some(mfa),
                        managed,
                    }
                },
            )
            .collect(),
    }))
}

#[utoipa::path(patch, path = "/api/v1/teams/{id}/members/{user_id}", tag = "teams",
    params(("id" = Uuid, Path), ("user_id" = Uuid, Path)),
    request_body = UpdateTeamMemberRequest, responses((status = 204)))]
pub async fn update_member(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Body(req): Body<UpdateTeamMemberRequest>,
) -> ApiResult<NoContent> {
    let me = crate::authz::membership(&state.db, id, auth.user_id()).await?;
    let target = crate::authz::membership(&state.db, id, user_id)
        .await
        .map_err(|_| Error::not_found("Member"))?;
    // Resolve the requested role: `role_id` (0.9.0 clients) wins over the
    // coarse `role` level.
    let (new_role_id, new_slug, new_level): (Uuid, String, TeamRole) = match req.role_id {
        Some(rid) => {
            let row: Option<(String,)> =
                sqlx::query_as("SELECT slug FROM team_roles WHERE team_id = $1 AND id = $2")
                    .bind(id)
                    .bind(rid)
                    .fetch_optional(&state.db)
                    .await?;
            let (slug,) = row.ok_or_else(|| Error::not_found("Role"))?;
            let level = match slug.as_str() {
                "owner" => TeamRole::Owner,
                "admin" => TeamRole::Admin,
                _ => TeamRole::Member,
            };
            (rid, slug, level)
        }
        None => {
            let rid = crate::authz::role_id_for_level(&state.db, id, req.role).await?;
            (rid, team_role_str(req.role).to_string(), req.role)
        }
    };
    if new_level == TeamRole::Owner {
        if me.level != TeamRole::Owner {
            return Err(Error::forbidden("Only the owner can transfer ownership"));
        }
        if user_id == auth.user_id() {
            return Err(Error::bad_request("You already own this team"));
        }
        let admin_role = crate::authz::builtin_role_id(&state.db, id, "admin").await?;
        let mut tx = state.db.begin().await?;
        sqlx::query(
            "UPDATE team_members SET role = 'admin', role_id = $3, role_source = 'manual'
             WHERE team_id = $1 AND user_id = $2",
        )
        .bind(id)
        .bind(auth.user_id())
        .bind(admin_role)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE team_members SET role = 'owner', role_id = $3, role_source = 'manual'
             WHERE team_id = $1 AND user_id = $2",
        )
        .bind(id)
        .bind(user_id)
        .bind(new_role_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE teams SET owner_id = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        // An owner answers to nobody: the account stops being managed.
        sqlx::query(
            "UPDATE users SET managed_by_team_id = NULL WHERE id = $1 AND managed_by_team_id = $2",
        )
        .bind(user_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    } else {
        if !me.has("members.role") {
            return Err(me.denied("members.role"));
        }
        if target.level == TeamRole::Owner {
            return Err(Error::forbidden("Transfer ownership first"));
        }
        // Nobody hands out permissions they do not hold themselves.
        if me.level != TeamRole::Owner {
            let (perms,): (Vec<String>,) =
                sqlx::query_as("SELECT permissions FROM team_roles WHERE id = $1")
                    .bind(new_role_id)
                    .fetch_one(&state.db)
                    .await?;
            if let Some(p) = perms.iter().find(|p| !me.has(p)) {
                return Err(Error::forbidden(format!(
                    "You cannot assign `{new_slug}`: it grants `{p}`, which you do not hold"
                )));
            }
        }
        sqlx::query(
            "UPDATE team_members SET role = $3, role_id = $4, role_source = 'manual'
             WHERE team_id = $1 AND user_id = $2",
        )
        .bind(id)
        .bind(user_id)
        .bind(team_role_str(new_level))
        .bind(new_role_id)
        .execute(&state.db)
        .await?;
    }
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "member.role")
            .user(user_id)
            .details(serde_json::json!({
                "role": new_slug,
                "role_id": new_role_id,
                "previous_role": target.role.slug,
                "previous_role_id": target.role.id,
                "source": "manual",
            })),
    )
    .await;
    events::publish(
        &state,
        Event::TeamsUpdated {
            user_ids: member_ids(&state.db, id).await?,
        },
    )
    .await
    .map(NoContent::from)
}

/// Remove a member: drops their team membership and access to every team
/// vault. An account the team created keeps existing as an individual one;
/// returns whether that conversion happened.
pub(crate) async fn remove(state: &AppState, team_id: Uuid, user_id: Uuid) -> ApiResult<bool> {
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2")
        .bind(team_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    crate::routes::ca::forget_member(&mut *tx, team_id, user_id).await?;
    let converted = sqlx::query(
        "UPDATE users SET managed_by_team_id = NULL WHERE id = $1 AND managed_by_team_id = $2",
    )
    .bind(user_id)
    .bind(team_id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    sqlx::query(
        "DELETE FROM vault_members vm USING vaults v WHERE vm.vault_id = v.id AND v.team_id = $1 AND vm.user_id = $2",
    )
    .bind(team_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    presence::clear_user_in_team(state, team_id, user_id).await?;
    let mut ids = member_ids(&state.db, team_id).await?;
    ids.push(user_id);
    events::publish(
        state,
        Event::TeamsUpdated {
            user_ids: ids.clone(),
        },
    )
    .await?;
    events::publish(state, Event::VaultsUpdated { user_ids: ids }).await?;
    Ok(converted)
}

#[utoipa::path(delete, path = "/api/v1/teams/{id}/members/{user_id}", tag = "teams",
    params(("id" = Uuid, Path), ("user_id" = Uuid, Path)), responses((status = 204)))]
pub async fn remove_member(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<NoContent> {
    crate::authz::require(&state, id, auth.user_id(), "members.remove").await?;
    let target = my_role(&state.db, id, user_id)
        .await
        .map_err(|_| Error::not_found("Member"))?;
    if target == TeamRole::Owner {
        return Err(Error::forbidden("The owner cannot be removed"));
    }
    let converted = remove(&state, id, user_id).await?;
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "member.removed")
            .user(user_id)
            .details(serde_json::json!({
                "role": team_role_str(target),
                "account": if converted { "converted" } else { "kept" },
            })),
    )
    .await;
    if converted {
        notify_conversion(&state, id, user_id).await;
    }
    Ok(NoContent)
}

/// Tell a former managed member that the account is now theirs alone.
async fn notify_conversion(state: &AppState, team_id: Uuid, user_id: Uuid) {
    let (Ok(u), Ok(team)) = (
        users::by_id(&state.db, user_id).await,
        team_name(&state.db, team_id).await,
    ) else {
        return;
    };
    users::notify(
        state,
        &u.email,
        "account converted to individual",
        &format!(
            "You were removed from the team \"{team}\". The account was created through that \
             team's invitation; it is now an individual account that only you control."
        ),
    )
    .await;
}

pub(crate) async fn team_name<'e, E: PgExecutor<'e>>(db: E, team_id: Uuid) -> ApiResult<String> {
    let (name,): (String,) = sqlx::query_as("SELECT name FROM teams WHERE id = $1")
        .bind(team_id)
        .fetch_one(db)
        .await?;
    Ok(name)
}

/// `DELETE /teams/{id}/members/{user_id}/account` — the owner deletes an
/// account the team created (sign-up through its invitation). Everything the
/// user has — devices, personal vault, logs — goes with it; accounts that
/// existed before joining can only be removed from the team.
#[utoipa::path(delete, path = "/api/v1/teams/{id}/members/{user_id}/account", tag = "teams",
    params(("id" = Uuid, Path), ("user_id" = Uuid, Path)),
    responses((status = 204), (status = 409, description = "Not a team-created account, or it owns teams")))]
pub async fn delete_member_account(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<NoContent> {
    if my_role(&state.db, id, auth.user_id()).await? != TeamRole::Owner {
        return Err(Error::forbidden(
            "Only the owner can delete a member's account",
        ));
    }
    let target = my_role(&state.db, id, user_id)
        .await
        .map_err(|_| Error::not_found("Member"))?;
    if target == TeamRole::Owner {
        return Err(Error::forbidden("The owner cannot be removed"));
    }
    let u = users::by_id(&state.db, user_id).await?;
    if u.managed_by_team_id != Some(id) {
        return Err(Error::conflict(
            "This account was not created by the team; remove the member instead",
        ));
    }
    let (owned,): (i64,) = sqlx::query_as("SELECT count(*) FROM teams WHERE owner_id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
    if owned > 0 {
        return Err(Error::conflict(
            "The member owns other teams; they must transfer or delete them first",
        ));
    }
    let team = team_name(&state.db, id).await?;
    // Written before the row disappears so the entry keeps the user reference.
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "member.account_deleted")
            .user(user_id)
            .details(serde_json::json!({ "role": team_role_str(target), "email": u.email })),
    )
    .await;
    users::delete(&state, user_id).await?;
    presence::clear_user_in_team(&state, id, user_id).await?;
    users::notify(
        &state,
        &u.email,
        "account deleted",
        &format!(
            "The owner of the team \"{team}\" deleted your Termoso account, which was created \
             through that team's invitation. All its data and devices were removed."
        ),
    )
    .await;
    Ok(NoContent)
}

#[utoipa::path(post, path = "/api/v1/teams/{id}/leave", tag = "teams", params(("id" = Uuid, Path)), responses((status = 204)))]
pub async fn leave(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<NoContent> {
    let role = my_role(&state.db, id, auth.user_id()).await?;
    if role == TeamRole::Owner {
        return Err(Error::forbidden("Transfer ownership before leaving"));
    }
    let converted = remove(&state, id, auth.user_id()).await?;
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "member.left").details(serde_json::json!({
            "role": team_role_str(role),
            "account": if converted { "converted" } else { "kept" },
        })),
    )
    .await;
    Ok(NoContent)
}

// ───────────────────────────── presence ─────────────────────────────

#[utoipa::path(get, path = "/api/v1/teams/{id}/presence", tag = "teams", params(("id" = Uuid, Path)),
    responses((status = 200, body = TeamPresence)))]
pub async fn get_presence(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TeamPresence>> {
    my_role(&state.db, id, auth.user_id()).await?;
    let (enabled,): (bool,) = sqlx::query_as("SELECT presence_enabled FROM teams WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(
        presence::snapshot(&state, id, auth.user_id(), enabled).await?,
    ))
}

// ───────────────────────────── invites ─────────────────────────────

#[utoipa::path(get, path = "/api/v1/teams/{id}/invites", tag = "teams", params(("id" = Uuid, Path)),
    responses((status = 200, body = InviteList)))]
pub async fn invites(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<InviteList>> {
    crate::authz::require(&state, id, auth.user_id(), "members.invite").await?;
    let rows: Vec<(Uuid, String, String, Uuid, DateTime<Utc>, DateTime<Utc>, Option<Uuid>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT i.id, i.email, i.role, i.invited_by, i.created_at, i.expires_at, r.id, r.slug, r.name
         FROM team_invites i LEFT JOIN team_roles r ON r.id = i.role_id
         WHERE i.team_id = $1 AND i.accepted_at IS NULL AND i.expires_at > now() ORDER BY i.created_at",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(InviteList {
        invites: rows
            .into_iter()
            .map(
                |(id, email, role, invited_by, created_at, expires_at, rid, slug, name)| Invite {
                    id,
                    email,
                    role: parse_team_role(&role),
                    invited_by,
                    created_at,
                    expires_at,
                    role_ref: rid.map(|id| RoleRef {
                        id,
                        slug: slug.unwrap_or_default(),
                        name: name.unwrap_or_default(),
                    }),
                },
            )
            .collect(),
    }))
}

#[utoipa::path(post, path = "/api/v1/teams/{id}/invites", tag = "teams", params(("id" = Uuid, Path)),
    request_body = CreateInviteRequest, responses((status = 200, body = CreatedInvite)))]
pub async fn create_invite(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<CreateInviteRequest>,
) -> ApiResult<Json<CreatedInvite>> {
    let me = crate::authz::require(&state, id, auth.user_id(), "members.invite").await?;
    if req.role == TeamRole::Owner {
        return Err(Error::bad_request("Cannot invite as owner"));
    }
    let (role_ref, role_level) =
        crate::authz::assignable_role(&state.db, &me, req.role_id, req.role).await?;
    let email = normalize_email(&req.email).ok_or_else(|| Error::bad_request("Invalid email"))?;
    let pol = crate::policy::load(&state.db, id).await?;
    if !crate::policy::domain_allowed(&pol.sso_domains, &email) {
        return Err(Error::new(
            axum::http::StatusCode::BAD_REQUEST,
            termoso_proto::error::codes::DOMAIN_NOT_ALLOWED,
            "This team only accepts members from its SSO domains",
        )
        .with_details(serde_json::json!({ "domains": pol.sso_domains })));
    }
    let already: Option<(Uuid,)> = sqlx::query_as(
        "SELECT u.id FROM users u JOIN team_members m ON m.user_id = u.id WHERE m.team_id = $1 AND lower(u.email) = $2",
    )
    .bind(id)
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;
    if already.is_some() {
        return Err(Error::conflict("Already a member"));
    }
    for vid in &req.vault_ids {
        let ok: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM vaults WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL",
        )
        .bind(vid)
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
        if ok.is_none() {
            return Err(Error::bad_request("Vault does not belong to this team"));
        }
    }
    let token = random_token();
    let invite_id = Uuid::new_v4();
    let expires_at = Utc::now() + chrono::Duration::days(INVITE_DAYS);
    sqlx::query(
        "DELETE FROM team_invites WHERE team_id = $1 AND lower(email) = $2 AND accepted_at IS NULL",
    )
    .bind(id)
    .bind(&email)
    .execute(&state.db)
    .await?;
    let (created_at,): (DateTime<Utc>,) = sqlx::query_as(
        "INSERT INTO team_invites (id, team_id, email, role, token_hash, invited_by, vault_ids, expires_at, role_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING created_at",
    )
    .bind(invite_id)
    .bind(id)
    .bind(&email)
    .bind(team_role_str(role_level))
    .bind(hash_token(&token))
    .bind(auth.user_id())
    .bind(&req.vault_ids)
    .bind(expires_at)
    .bind(role_ref.id)
    .fetch_one(&state.db)
    .await?;
    let url = format!(
        "{}/invite/{}",
        state.cfg.web_url().trim_end_matches('/'),
        token
    );
    if let Some(mailer) = &state.mailer
        && ratelimit::check(&state, ratelimit::EMAIL, &email)
            .await
            .is_ok()
    {
        let (team_name,): (String,) = sqlx::query_as("SELECT name FROM teams WHERE id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await?;
        let inviter = users::by_id(&state.db, auth.user_id()).await?;
        let inviter = inviter
            .display_name
            .clone()
            .unwrap_or(inviter.email.clone());
        let email_msg = crate::mail::Email::new(
            format!("Invitation to {team_name}"),
            format!("Join \"{team_name}\""),
        )
        .preheader(format!("{inviter} invited you to {team_name} on {}.", state.cfg.server_name))
        .paragraph(format!(
            "{inviter} invited you to join the team \"{team_name}\" on {}. Accept to get access to the team's shared vaults and hosts.",
            state.cfg.server_name
        ))
        .button("Accept invitation", &url)
        .outro(format!("The invitation expires in {INVITE_DAYS} days."))
        .note(format!(
            "Not expecting this? You can ignore the email — nothing is shared with you until you accept, and {inviter} is not notified."
        ));
        if let Err(e) = mailer.send(&email, &email_msg).await {
            tracing::warn!(error = %e, "could not send invite email");
        }
    }
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "invite.created").details(serde_json::json!({
            "invite_id": invite_id,
            "email": email,
            "role": team_role_str(req.role),
            "vault_ids": req.vault_ids,
        })),
    )
    .await;
    Ok(Json(CreatedInvite {
        invite: Invite {
            id: invite_id,
            email,
            role: role_level,
            invited_by: auth.user_id(),
            created_at,
            expires_at,
            role_ref: Some(role_ref),
        },
        url,
    }))
}

#[utoipa::path(delete, path = "/api/v1/teams/{id}/invites/{invite_id}", tag = "teams",
    params(("id" = Uuid, Path), ("invite_id" = Uuid, Path)), responses((status = 204)))]
pub async fn delete_invite(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, invite_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<NoContent> {
    crate::authz::require(&state, id, auth.user_id(), "members.invite").await?;
    let res: Option<(String,)> = sqlx::query_as(
        "DELETE FROM team_invites WHERE id = $1 AND team_id = $2 AND accepted_at IS NULL RETURNING email",
    )
    .bind(invite_id)
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    let Some((email,)) = res else {
        return Err(Error::not_found("Invite"));
    };
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "invite.revoked")
            .details(serde_json::json!({ "invite_id": invite_id, "email": email })),
    )
    .await;
    Ok(NoContent)
}

#[utoipa::path(get, path = "/api/v1/invites/{token}", tag = "teams", params(("token" = String, Path)),
    responses((status = 200, body = InvitePreview)))]
pub async fn invite_preview(
    State(state): State<AppState>,
    client: Client,
    Path(token): Path<String>,
) -> ApiResult<Json<InvitePreview>> {
    ratelimit::check_ip(&state, ratelimit::ANON_IP, client.ip.as_deref()).await?;
    let row: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT t.name, COALESCE(u.display_name, u.email), i.email, i.role
         FROM team_invites i JOIN teams t ON t.id = i.team_id JOIN users u ON u.id = i.invited_by
         WHERE i.token_hash = $1 AND i.accepted_at IS NULL AND i.expires_at > now()",
    )
    .bind(hash_token(&token))
    .fetch_optional(&state.db)
    .await?;
    let Some((team_name, inviter, email, role)) = row else {
        return Err(Error::token_expired());
    };
    let account_exists = users::by_email(&state.db, &email).await?.is_some();
    Ok(Json(InvitePreview {
        team_name,
        inviter,
        email,
        role: parse_team_role(&role),
        account_exists,
    }))
}

/// Join the team and create pending (unsealed) vault memberships. Used by
/// `accept_invite` and by registration with an invite token.
#[allow(clippy::too_many_arguments)]
pub async fn apply_invite(
    tx: &mut Transaction<'_, Postgres>,
    invite_id: Uuid,
    team_id: Uuid,
    role: &str,
    role_id: Option<Uuid>,
    vault_ids: &[Uuid],
    user_id: Uuid,
    device_id: Option<Uuid>,
) -> ApiResult<NoContent> {
    let role = if role == "owner" { "member" } else { role };
    sqlx::query(
        "INSERT INTO team_members (team_id, user_id, role, role_id)
         VALUES ($1, $2, $3, COALESCE(
             (SELECT id FROM team_roles WHERE team_id = $1 AND id = $4 AND slug <> 'owner'),
             (SELECT id FROM team_roles WHERE team_id = $1 AND slug = $3 AND builtin),
             (SELECT default_role_id FROM teams WHERE id = $1)))
         ON CONFLICT (team_id, user_id) DO NOTHING",
    )
    .bind(team_id)
    .bind(user_id)
    .bind(role)
    .bind(role_id)
    .execute(&mut **tx)
    .await?;
    for vid in vault_ids {
        sqlx::query(
            "INSERT INTO vault_members (vault_id, user_id, role, sealed_key, key_version)
             SELECT id, $2, 'viewer', NULL, key_version FROM vaults WHERE id = $1 AND team_id = $3 AND deleted_at IS NULL
             ON CONFLICT (vault_id, user_id) DO NOTHING",
        )
        .bind(vid)
        .bind(user_id)
        .bind(team_id)
        .execute(&mut **tx)
        .await?;
    }
    sqlx::query("UPDATE team_invites SET accepted_at = now(), accepted_by = $2 WHERE id = $1")
        .bind(invite_id)
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    audit::record(
        &mut **tx,
        audit::Entry::by(team_id, user_id, device_id, "invite.accepted")
            .user(user_id)
            .details(serde_json::json!({
                "invite_id": invite_id,
                "role": role,
                "vault_ids": vault_ids,
            })),
    )
    .await;
    Ok(NoContent)
}

#[utoipa::path(post, path = "/api/v1/invites/{token}/accept", tag = "teams", params(("token" = String, Path)),
    responses((status = 200, body = Team)))]
pub async fn accept_invite(
    State(state): State<AppState>,
    auth: Auth,
    Path(token): Path<String>,
) -> ApiResult<Json<Team>> {
    let row: Option<(Uuid, Uuid, String, String, Vec<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, team_id, email, role, vault_ids, role_id FROM team_invites
         WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now()",
    )
    .bind(hash_token(&token))
    .fetch_optional(&state.db)
    .await?;
    let Some((invite_id, team_id, email, role, vault_ids, role_id)) = row else {
        return Err(Error::token_expired());
    };
    let me = users::by_id(&state.db, auth.user_id()).await?;
    if !me.email.eq_ignore_ascii_case(&email) {
        return Err(Error::forbidden(
            "This invitation was sent to a different email address",
        ));
    }
    let mut tx = state.db.begin().await?;
    // The token reached this mailbox, so accepting proves it is theirs —
    // the same proof sign-up with a matching invite relies on. Team
    // policies that need a reachable mailbox (device approval, email
    // step-up) must not stay silently off for an unverified member.
    if !me.email_verified {
        sqlx::query("UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1")
            .bind(me.id)
            .execute(&mut *tx)
            .await?;
    }
    apply_invite(
        &mut tx,
        invite_id,
        team_id,
        &role,
        role_id,
        &vault_ids,
        me.id,
        Some(auth.device_id()),
    )
    .await?;
    tx.commit().await?;
    if !me.email_verified {
        crate::session::invalidate_user_cache(&state, me.id).await?;
        crate::enterprise::ensure_home_team(&state, me.id).await?;
        users::security_event(
            &state,
            me.id,
            "email_verified",
            Some(auth.device_id()),
            None,
            None,
            Some(serde_json::json!({ "via": "invite", "team_id": team_id })),
        )
        .await?;
    }
    let mut ids = member_ids(&state.db, team_id).await?;
    ids.push(me.id);
    events::publish(
        &state,
        Event::TeamsUpdated {
            user_ids: ids.clone(),
        },
    )
    .await?;
    if !vault_ids.is_empty() {
        events::publish(&state, Event::VaultsUpdated { user_ids: ids }).await?;
    }
    get(State(state), auth, Path(team_id)).await
}

// ───────────────────────────── pending vault keys ─────────────────────────────

/// Members of team vaults who still need the vault key sealed to their public
/// key. Only vault managers (or team admins) get to see them.
#[utoipa::path(get, path = "/api/v1/teams/{id}/pending-keys", tag = "teams", params(("id" = Uuid, Path)),
    responses((status = 200, body = PendingVaultKeys)))]
pub async fn pending_keys(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<PendingVaultKeys>> {
    let me = crate::authz::membership(&state.db, id, auth.user_id()).await?;
    let rows: Vec<(Uuid, Uuid, String, String)> = sqlx::query_as(
        "SELECT vm.vault_id, vm.user_id, u.public_key, vm.role
         FROM vault_members vm
         JOIN vaults v ON v.id = vm.vault_id
         JOIN users u ON u.id = vm.user_id
         WHERE v.team_id = $1 AND v.deleted_at IS NULL AND vm.sealed_key IS NULL
           AND ($3 OR EXISTS (SELECT 1 FROM vault_members me WHERE me.vault_id = v.id AND me.user_id = $2
                              AND me.role = 'manager' AND me.sealed_key IS NOT NULL))",
    )
    .bind(id)
    .bind(auth.user_id())
    .bind(me.has("vaults.members"))
    .fetch_all(&state.db)
    .await?;
    Ok(Json(PendingVaultKeys {
        items: rows
            .into_iter()
            .map(|(vault_id, user_id, public_key, role)| PendingVaultKey {
                vault_id,
                user_id,
                public_key,
                role: parse_vault_role(&role),
            })
            .collect(),
    }))
}
