//! Fine-grained team permissions. A member holds exactly one role; a role is a
//! set of `domain.action` keys (see `termoso_proto::team::PERMISSIONS`). The
//! owner always has everything regardless of role contents.

use std::collections::HashSet;

use sqlx::PgExecutor;
use termoso_proto::error::codes;
use termoso_proto::team::{
    CLIENT_ENFORCED_PERMISSIONS, PERMISSIONS, PermissionInfo, RoleRef, TeamRole,
};
use uuid::Uuid;

use crate::error::{ApiResult, Error};
use crate::state::AppState;

/// A user's standing in a team.
#[derive(Debug, Clone)]
pub struct Membership {
    pub team_id: Uuid,
    pub user_id: Uuid,
    /// Coarse level kept for older clients and for owner checks.
    pub level: TeamRole,
    pub role: RoleRef,
    pub role_source: String,
    permissions: HashSet<String>,
    wildcard: bool,
}

impl Membership {
    /// Whether the member holds `perm`.
    pub fn has(&self, perm: &str) -> bool {
        self.level == TeamRole::Owner || self.wildcard || self.permissions.contains(perm)
    }

    /// Effective permission list for API responses (`*` for the owner).
    pub fn permission_list(&self) -> Vec<String> {
        if self.level == TeamRole::Owner || self.wildcard {
            return vec!["*".to_string()];
        }
        let mut v: Vec<String> = self.permissions.iter().cloned().collect();
        v.sort();
        v
    }

    /// Admin-or-owner, the pre-0.9.0 notion; prefer `has`.
    pub fn is_admin(&self) -> bool {
        self.level.is_admin()
    }

    /// `permission_denied` for `perm`.
    pub fn denied(&self, perm: &str) -> Error {
        denied(perm)
    }
}

/// `403 permission_denied` naming the missing permission.
pub fn denied(perm: &str) -> Error {
    Error::new(
        axum::http::StatusCode::FORBIDDEN,
        codes::PERMISSION_DENIED,
        format!("This needs the `{perm}` permission in the team"),
    )
    .with_details(serde_json::json!({ "permission": perm }))
}

/// Load the membership, `404 Team` when the user is not a member.
pub async fn membership<'e, E: PgExecutor<'e>>(
    db: E,
    team_id: Uuid,
    user_id: Uuid,
) -> ApiResult<Membership> {
    let row: Option<(String, Uuid, String, String, Vec<String>, String)> = sqlx::query_as(
        "SELECT m.role, r.id, r.slug, r.name, r.permissions, m.role_source
         FROM team_members m JOIN team_roles r ON r.id = m.role_id
         WHERE m.team_id = $1 AND m.user_id = $2",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_optional(db)
    .await?;
    let (level, id, slug, name, perms, source) = row.ok_or_else(|| Error::not_found("Team"))?;
    Ok(Membership {
        team_id,
        user_id,
        level: crate::routes::teams::parse_team_role(&level),
        role: RoleRef { id, slug, name },
        role_source: source,
        wildcard: perms.iter().any(|p| p == "*"),
        permissions: perms.into_iter().collect(),
    })
}

/// Membership that holds `perm`, or `403 permission_denied`.
pub async fn require(
    state: &AppState,
    team_id: Uuid,
    user_id: Uuid,
    perm: &str,
) -> ApiResult<Membership> {
    let m = membership(&state.db, team_id, user_id).await?;
    if !m.has(perm) {
        return Err(denied(perm));
    }
    Ok(m)
}

/// Validate a permission set for a custom/admin role: known keys only, no
/// owner-only keys, deduplicated and sorted.
pub fn normalize_permissions(perms: &[String]) -> ApiResult<Vec<String>> {
    use termoso_proto::team::{OWNER_ONLY_PERMISSIONS, is_permission};
    let mut set = HashSet::new();
    for p in perms {
        let p = p.trim();
        if p == "*" || OWNER_ONLY_PERMISSIONS.contains(&p) {
            return Err(Error::bad_request(format!(
                "`{p}` belongs to the owner only"
            )));
        }
        if !is_permission(p) {
            return Err(Error::bad_request(format!("Unknown permission `{p}`")));
        }
        set.insert(p.to_string());
    }
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort();
    Ok(v)
}

/// Human-readable catalog for the cabinet.
pub fn catalog() -> Vec<PermissionInfo> {
    PERMISSIONS
        .iter()
        .map(|&key| {
            let (title, description, dangerous) = describe(key);
            PermissionInfo {
                key: key.to_string(),
                group: key.split('.').next().unwrap_or("").to_string(),
                title: title.to_string(),
                description: description.to_string(),
                dangerous,
                enforced_by: if CLIENT_ENFORCED_PERMISSIONS.contains(&key) {
                    "client"
                } else {
                    "server"
                }
                .to_string(),
            }
        })
        .collect()
}

fn describe(key: &str) -> (&'static str, &'static str, bool) {
    match key {
        "team.view" => ("View team", "See the team, its name and settings.", false),
        "team.rename" => ("Rename team", "Change the team name.", false),
        "team.settings" => (
            "Team settings",
            "Change presence, multiplayer and other team-wide switches.",
            false,
        ),
        "team.delete" => ("Delete team", "Owner only.", true),
        "devices.approve" => (
            "Approve devices",
            "Vet members' new devices when the team requires admin approval; reject ends their sessions.",
            true,
        ),
        "team.export" => (
            "Export team data",
            "Download everything the server stores for the team (GDPR export).",
            true,
        ),
        "team.transfer" => ("Transfer ownership", "Owner only.", true),
        "members.view" => ("View members", "See who is in the team.", false),
        "members.view_mfa" => (
            "View MFA status",
            "See which members have MFA or a passkey enabled.",
            false,
        ),
        "members.invite" => (
            "Invite members",
            "Create, list and revoke invitations.",
            false,
        ),
        "invites.view" => (
            "View invitations",
            "See pending invitations without creating them.",
            false,
        ),
        "members.remove" => ("Remove members", "Remove a member from the team.", true),
        "members.suspend" => (
            "Suspend members",
            "Temporarily block a member without removing them.",
            true,
        ),
        "members.role" => (
            "Change roles",
            "Assign roles to members (never above your own permissions).",
            true,
        ),
        "roles.manage" => (
            "Manage roles",
            "Create, edit and delete custom roles and group mappings.",
            true,
        ),
        "vaults.create" => ("Create vaults", "Create team vaults and folders.", false),
        "vaults.rename" => ("Rename vaults", "Rename a vault or folder.", false),
        "vaults.archive" => ("Archive vaults", "Archive and restore vaults.", false),
        "vaults.delete" => (
            "Delete vaults",
            "Permanently delete a vault and its contents.",
            true,
        ),
        "vaults.transfer" => (
            "Move vaults",
            "Move a vault or folder to another parent or team.",
            true,
        ),
        "vaults.members" => (
            "Manage vault access",
            "Grant and revoke vault membership.",
            true,
        ),
        "acl.manage" => (
            "Manage group and host access",
            "Set per-group/per-host access rules (hidden, connect only, read, edit) for roles, members and IdP groups inside team vaults.",
            true,
        ),
        "rotation.manage" => (
            "Manage credential rotation",
            "See overdue keys and passwords, queue and cancel rotation jobs.",
            true,
        ),
        "access.approve" => (
            "Approve access requests",
            "Grant, deny and revoke temporary (just-in-time) access to team vaults.",
            true,
        ),
        "vaults.rotate_key" => (
            "Rotate vault keys",
            "Rotate a vault key after access changes.",
            true,
        ),
        "vaults.history" => (
            "Vault history",
            "See change history and roll back entities.",
            false,
        ),
        "entities.read" => (
            "Read entities",
            "See hosts, snippets, keys and identities.",
            false,
        ),
        "entities.write" => (
            "Edit entities",
            "Create and edit hosts, snippets, keys and identities.",
            false,
        ),
        "entities.delete" => (
            "Delete entities",
            "Delete hosts, snippets, keys and identities.",
            true,
        ),
        "entities.move" => (
            "Move entities",
            "Move entities between vaults and folders.",
            false,
        ),
        "entities.share_link" => (
            "Share links",
            "Create share links for hosts and snippets.",
            false,
        ),
        "secrets.reveal" => (
            "Reveal secrets",
            "Show passwords, keys and passphrases in clear text.",
            true,
        ),
        "secrets.copy" => (
            "Copy secrets",
            "Copy passwords and keys to the clipboard without showing them.",
            false,
        ),
        "keys.generate" => (
            "Generate keys",
            "Generate SSH keys inside team vaults.",
            false,
        ),
        "keys.export" => ("Export keys", "Export private keys from team vaults.", true),
        "snippets.run" => ("Run snippets", "Run snippets on hosts.", false),
        "connect.ssh" => ("SSH", "Open SSH sessions to team hosts.", false),
        "connect.sftp" => ("SFTP", "Open SFTP sessions to team hosts.", false),
        "connect.port_forward" => (
            "Port forwarding",
            "Create local, remote and dynamic forwards.",
            false,
        ),
        "connect.telnet" => ("Telnet", "Open Telnet sessions.", false),
        "connect.serial" => ("Serial", "Open serial sessions.", false),
        "connect.mosh" => ("Mosh", "Open Mosh sessions.", false),
        "connect.local_terminal" => (
            "Local terminal",
            "Use the local terminal and on-device Linux.",
            false,
        ),
        "connect.record" => (
            "Record sessions",
            "Record terminal sessions to team logs.",
            false,
        ),
        "connect.bridge" => (
            "Connect via bridge",
            "Use team bridges and connect-only access.",
            false,
        ),
        "live.start" => ("Start multiplayer", "Share a session with others.", false),
        "live.join" => ("Join multiplayer", "Join a shared session.", false),
        "live.control" => (
            "Control multiplayer",
            "Give and take control in a shared session.",
            false,
        ),
        "logs.view_own" => ("View own logs", "See your own session logs.", false),
        "logs.view_team" => ("View team logs", "See session logs of every member.", true),
        "logs.export" => ("Export logs", "Download session logs.", true),
        "logs.delete" => ("Delete logs", "Delete session logs.", true),
        "export.vault" => ("Export vaults", "Export vault contents.", true),
        "import.vault" => ("Import", "Import hosts and keys into team vaults.", false),
        "bridges.manage" => (
            "Manage bridges",
            "Enrol, configure and remove team bridges.",
            true,
        ),
        "bridges.use" => ("Use bridges", "Connect through team bridges.", false),
        "sshid.manage" => (
            "Manage SSH ID",
            "Manage the team SSH identity and agent.",
            true,
        ),
        "ai.use" => ("Use AI", "Use the AI assistant with team context.", false),
        "mcp.use" => ("Use MCP", "Expose team data to MCP clients.", false),
        "digest.manage" => (
            "Activity digest",
            "Configure the team activity digest.",
            false,
        ),
        "audit.view" => ("View audit log", "Read the team audit log.", false),
        "audit.view_ips" => (
            "View IPs in audit",
            "See IP addresses in audit entries.",
            true,
        ),
        "audit.export" => (
            "Export audit log",
            "Download the audit log as CSV or JSONL.",
            true,
        ),
        "webhooks.manage" => (
            "Manage webhooks",
            "Configure audit webhooks and SIEM delivery.",
            true,
        ),
        "tokens.manage" => (
            "Manage API tokens",
            "Create and revoke team API tokens.",
            true,
        ),
        "ca.manage" => (
            "Manage SSH CA",
            "Create, configure, rotate and disable the team certificate authority; revoke certificates.",
            true,
        ),
        "ca.issue" => (
            "Get SSH certificates",
            "Receive short-lived certificates for this device's keys from the team CA.",
            false,
        ),
        "automations.manage" => (
            "Manage automations",
            "Create, edit, pause and delete scheduled snippet runs; see every run.",
            true,
        ),
        "automations.view" => (
            "View automations",
            "See the team's scheduled runs and their results.",
            false,
        ),
        "automations.run" => (
            "Execute automations",
            "Let this member's devices (and bridges) claim and execute due runs.",
            false,
        ),
        "policies.manage" => (
            "Manage policies",
            "Set MFA, key, session and SSO policies.",
            true,
        ),
        "sso.manage" => (
            "Manage SSO",
            "Configure identity providers and domains.",
            true,
        ),
        "scim.manage" => (
            "Manage SCIM",
            "Configure SCIM provisioning and group mappings.",
            true,
        ),
        "scim.tokens" => ("SCIM tokens", "Issue and revoke SCIM bearer tokens.", true),
        _ => ("", "", false),
    }
}

/// Built-in roles every team gets: `(slug, name, description, permissions, position)`.
pub const BUILTIN_ROLES: &[(&str, &str, &str, &[&str], i32)] = &[
    (
        "owner",
        "Owner",
        "Everything, including deleting the team and transferring ownership.",
        &["*"],
        0,
    ),
    (
        "admin",
        "Admin",
        "Manages members, roles, vaults, policies, audit and integrations.",
        &[
            "team.view",
            "team.rename",
            "team.settings",
            "members.view",
            "members.view_mfa",
            "members.invite",
            "invites.view",
            "members.remove",
            "members.suspend",
            "members.role",
            "roles.manage",
            "vaults.create",
            "vaults.rename",
            "vaults.archive",
            "vaults.delete",
            "vaults.transfer",
            "vaults.members",
            "acl.manage",
            "rotation.manage",
            "access.approve",
            "team.export",
            "devices.approve",
            "vaults.rotate_key",
            "vaults.history",
            "entities.read",
            "entities.write",
            "entities.delete",
            "entities.move",
            "entities.share_link",
            "secrets.reveal",
            "secrets.copy",
            "keys.generate",
            "keys.export",
            "snippets.run",
            "connect.ssh",
            "connect.sftp",
            "connect.port_forward",
            "connect.telnet",
            "connect.serial",
            "connect.mosh",
            "connect.local_terminal",
            "connect.record",
            "connect.bridge",
            "live.start",
            "live.join",
            "live.control",
            "logs.view_own",
            "logs.view_team",
            "logs.export",
            "logs.delete",
            "export.vault",
            "import.vault",
            "bridges.manage",
            "bridges.use",
            "sshid.manage",
            "ai.use",
            "mcp.use",
            "digest.manage",
            "audit.view",
            "audit.view_ips",
            "audit.export",
            "webhooks.manage",
            "tokens.manage",
            "policies.manage",
            "sso.manage",
            "scim.manage",
            "scim.tokens",
            "ca.manage",
            "ca.issue",
            "automations.manage",
            "automations.view",
            "automations.run",
        ],
        10,
    ),
    (
        "member",
        "Member",
        "Works with the vaults they are given access to.",
        &[
            "team.view",
            "members.view",
            "invites.view",
            "entities.read",
            "entities.write",
            "entities.delete",
            "entities.move",
            "entities.share_link",
            "secrets.reveal",
            "secrets.copy",
            "keys.generate",
            "snippets.run",
            "connect.ssh",
            "connect.sftp",
            "connect.port_forward",
            "connect.telnet",
            "connect.serial",
            "connect.mosh",
            "connect.local_terminal",
            "connect.record",
            "connect.bridge",
            "live.start",
            "live.join",
            "live.control",
            "logs.view_own",
            "import.vault",
            "bridges.use",
            "ai.use",
            "mcp.use",
            "audit.view",
            "vaults.history",
            "ca.issue",
            "automations.view",
            "automations.run",
        ],
        20,
    ),
    (
        "viewer",
        "Viewer",
        "Connects to hosts but cannot change anything or see secrets.",
        &[
            "team.view",
            "members.view",
            "entities.read",
            "secrets.copy",
            "connect.ssh",
            "connect.sftp",
            "connect.port_forward",
            "connect.telnet",
            "connect.mosh",
            "connect.local_terminal",
            "connect.bridge",
            "bridges.use",
            "live.join",
            "logs.view_own",
            "ca.issue",
            "automations.view",
        ],
        30,
    ),
    (
        "auditor",
        "Auditor",
        "Reads the audit log and team session logs; no vault access.",
        &[
            "team.view",
            "members.view",
            "members.view_mfa",
            "invites.view",
            "audit.view",
            "audit.view_ips",
            "audit.export",
            "logs.view_team",
            "automations.view",
        ],
        40,
    ),
];

/// Create the built-in roles for a new team and set `member` as default.
/// Returns the owner role id.
pub async fn seed_builtin_roles(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    team_id: Uuid,
) -> ApiResult<Uuid> {
    let mut owner = Uuid::nil();
    for (slug, name, desc, perms, pos) in BUILTIN_ROLES {
        let id = Uuid::new_v4();
        let perms: Vec<String> = perms.iter().map(|s| s.to_string()).collect();
        sqlx::query(
            "INSERT INTO team_roles (id, team_id, slug, name, description, permissions, builtin, position)
             VALUES ($1, $2, $3, $4, $5, $6, true, $7)",
        )
        .bind(id).bind(team_id).bind(slug).bind(name).bind(desc).bind(&perms).bind(pos)
        .execute(&mut **tx)
        .await?;
        if *slug == "owner" {
            owner = id;
        }
        if *slug == "member" {
            sqlx::query("UPDATE teams SET default_role_id = $2 WHERE id = $1")
                .bind(team_id)
                .bind(id)
                .execute(&mut **tx)
                .await?;
        }
    }
    Ok(owner)
}

/// Id of a built-in role by slug.
pub async fn builtin_role_id<'e, E: PgExecutor<'e>>(
    db: E,
    team_id: Uuid,
    slug: &str,
) -> ApiResult<Uuid> {
    let (id,): (Uuid,) =
        sqlx::query_as("SELECT id FROM team_roles WHERE team_id = $1 AND slug = $2 AND builtin")
            .bind(team_id)
            .bind(slug)
            .fetch_one(db)
            .await?;
    Ok(id)
}

/// Role for a coarse level, used by pre-0.9.0 request bodies.
pub async fn role_id_for_level<'e, E: PgExecutor<'e>>(
    db: E,
    team_id: Uuid,
    level: TeamRole,
) -> ApiResult<Uuid> {
    let slug = match level {
        TeamRole::Owner => "owner",
        TeamRole::Admin => "admin",
        TeamRole::Member => "member",
    };
    builtin_role_id(db, team_id, slug).await
}

/// Default role for new members (falls back to built-in `member`).
pub async fn default_role_id<'e, E: PgExecutor<'e>>(db: E, team_id: Uuid) -> ApiResult<Uuid> {
    let row: Option<(Option<Uuid>,)> =
        sqlx::query_as("SELECT default_role_id FROM teams WHERE id = $1")
            .bind(team_id)
            .fetch_optional(db)
            .await?;
    if let Some((Some(id),)) = row {
        return Ok(id);
    }
    Err(Error::not_found("Team"))
}

/// `RoleRef` + effective permissions from a joined row.
/// Resolve the role an actor wants to hand out (`role_id` wins over the
/// coarse `level`). Owner is never assignable here; a non-owner may only
/// grant permissions they hold themselves.
pub async fn assignable_role<'e, E: PgExecutor<'e> + Copy>(
    db: E,
    actor: &Membership,
    role_id: Option<Uuid>,
    level: TeamRole,
) -> ApiResult<(RoleRef, TeamRole)> {
    let team_id = actor.team_id;
    let rid = match role_id {
        Some(rid) => rid,
        None => role_id_for_level(db, team_id, level).await?,
    };
    let row: Option<(String, String, Vec<String>)> = sqlx::query_as(
        "SELECT slug, name, permissions FROM team_roles WHERE team_id = $1 AND id = $2",
    )
    .bind(team_id)
    .bind(rid)
    .fetch_optional(db)
    .await?;
    let (slug, name, perms) = row.ok_or_else(|| Error::not_found("Role"))?;
    if slug == "owner" || perms.iter().any(|p| p == "*") {
        return Err(Error::bad_request("The owner role cannot be assigned"));
    }
    if let Some(missing) = perms.iter().find(|p| !actor.has(p)) {
        return Err(denied(missing));
    }
    let lvl = match slug.as_str() {
        "admin" => TeamRole::Admin,
        _ => TeamRole::Member,
    };
    Ok((
        RoleRef {
            id: rid,
            slug,
            name,
        },
        lvl,
    ))
}

/// Apply the team group → role mappings for a user who just signed in
/// through an IdP with `groups` (OIDC `groups` claim, SAML `memberOf`).
/// Per team: the matching mapping with the lowest `priority` wins and the
/// member becomes `role_source = 'idp'`; a member the IdP previously placed
/// who now matches nothing falls back to the team default role; manual
/// assignments and the owner are never touched.
pub async fn apply_group_mappings(
    db: &sqlx::PgPool,
    user_id: Uuid,
    groups: &[String],
) -> ApiResult<Vec<Uuid>> {
    apply_group_mappings_scoped(db, user_id, groups, None, "idp").await
}

/// Same as [`apply_group_mappings`], optionally limited to one team and
/// with a different `role_source` (`scim` for SCIM group sync).
pub async fn apply_group_mappings_scoped(
    db: &sqlx::PgPool,
    user_id: Uuid,
    groups: &[String],
    only_team: Option<Uuid>,
    new_source: &str,
) -> ApiResult<Vec<Uuid>> {
    let lowered: Vec<String> = groups
        .iter()
        .map(|g| g.trim().to_lowercase())
        .filter(|g| !g.is_empty())
        .collect();
    let rows: Vec<(
        Uuid,
        String,
        Uuid,
        Option<Uuid>,
        Option<Uuid>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT m.team_id, m.role_source, m.role_id,
                (SELECT x.role_id FROM team_role_mappings x
                  WHERE x.team_id = m.team_id AND lower(x.group_name) = ANY($2)
                  ORDER BY x.priority, x.group_name LIMIT 1),
                t.default_role_id,
                (SELECT slug FROM team_roles WHERE id = m.role_id)
         FROM team_members m JOIN teams t ON t.id = m.team_id
         WHERE m.user_id = $1 AND m.role <> 'owner' AND ($3::uuid IS NULL OR m.team_id = $3)",
    )
    .bind(user_id)
    .bind(&lowered)
    .bind(only_team)
    .fetch_all(db)
    .await?;
    let mut changed = Vec::new();
    for (team_id, source, current, mapped, default_role, _slug) in rows {
        let target = match (mapped, source.as_str()) {
            (Some(r), _) => r,
            (None, "idp" | "scim") => match default_role {
                Some(d) => d,
                None => continue,
            },
            (None, _) => continue,
        };
        if target == current && source == new_source {
            continue;
        }
        let done = sqlx::query(
            "UPDATE team_members SET role_id = $3, role_source = $4,
                 role = CASE WHEN (SELECT slug FROM team_roles WHERE id = $3) = 'admin' THEN 'admin' ELSE 'member' END
             WHERE team_id = $1 AND user_id = $2 AND role <> 'owner'
               AND EXISTS (SELECT 1 FROM team_roles r WHERE r.id = $3 AND r.team_id = $1 AND r.slug <> 'owner')",
        )
        .bind(team_id)
        .bind(user_id)
        .bind(target)
        .bind(new_source)
        .execute(db)
        .await?
        .rows_affected();
        if done > 0 {
            changed.push(team_id);
        }
    }
    Ok(changed)
}

pub fn role_parts(
    level: TeamRole,
    id: Uuid,
    slug: String,
    name: String,
    perms: Vec<String>,
) -> (RoleRef, Vec<String>) {
    let list = if level == TeamRole::Owner || perms.iter().any(|p| p == "*") {
        vec!["*".to_string()]
    } else {
        let mut v = perms;
        v.sort();
        v
    };
    (RoleRef { id, slug, name }, list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_permission_is_described_and_builtins_are_known() {
        for key in PERMISSIONS {
            let (title, _, _) = describe(key);
            assert!(!title.is_empty(), "{key} has no title");
        }
        for (slug, _, _, perms, _) in BUILTIN_ROLES {
            for p in *perms {
                assert!(
                    *p == "*" || termoso_proto::team::is_permission(p),
                    "{slug}: unknown {p}"
                );
            }
        }
        assert!(PERMISSIONS.len() >= 60);
    }

    #[test]
    fn builtin_roles_only_use_known_permissions() {
        for (slug, _, _, perms, _) in BUILTIN_ROLES {
            for p in *perms {
                assert!(
                    *p == "*" || termoso_proto::team::is_permission(p),
                    "{slug}: {p}"
                );
            }
        }
        assert_eq!(catalog().len(), PERMISSIONS.len());
    }

    #[test]
    fn normalize_rejects_owner_only_and_unknown() {
        assert!(normalize_permissions(&["team.delete".into()]).is_err());
        assert!(normalize_permissions(&["*".into()]).is_err());
        assert!(normalize_permissions(&["nope.x".into()]).is_err());
        let v = normalize_permissions(&[
            "vaults.create".into(),
            " vaults.create ".into(),
            "audit.view".into(),
        ])
        .unwrap();
        assert_eq!(v, vec!["audit.view", "vaults.create"]);
    }

    #[test]
    fn owner_has_everything() {
        let m = Membership {
            team_id: Uuid::nil(),
            user_id: Uuid::nil(),
            level: TeamRole::Owner,
            role: RoleRef {
                id: Uuid::nil(),
                slug: "owner".into(),
                name: "Owner".into(),
            },
            role_source: "manual".into(),
            permissions: HashSet::new(),
            wildcard: false,
        };
        assert!(m.has("scim.manage"));
        assert_eq!(m.permission_list(), vec!["*"]);
        let v = Membership {
            level: TeamRole::Member,
            permissions: ["team.view".to_string()].into_iter().collect(),
            ..m
        };
        assert!(v.has("team.view") && !v.has("vaults.create"));
    }
}
