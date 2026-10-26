//! Team and team-vault management. Vault keys are generated, opened and sealed
//! here with the account keypair from the store; the webview only sees teams,
//! members, roles, invitation links and pending states.

use std::collections::HashMap;
use termoso_proto::team as proto;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, Runtime};
use termoso_core::account as core;
use termoso_core::api::{ApiClient, AuditQuery};
use termoso_core::store::LocalVaultKind;
use termoso_core::termoso_crypto::keys::{SymmetricKey, public_key_from_b64};
use termoso_core::termoso_crypto::sealed;
use termoso_proto::team::{
    AuditEvent, CreateInviteRequest, CreateTeamRequest, Invite, Team, TeamRole,
    UpdateTeamMemberRequest, UpdateTeamRequest,
};
use termoso_proto::vault::{
    CreateVaultRequest, RotateVaultKeyRequest, SealedKeyFor, UpdateVaultRequest, VaultMemberUpsert,
    VaultRole,
};
use uuid::Uuid;

use crate::account::{SYNC_EVENT, SyncNotice, api};
use crate::error::{DesktopError, Result};
use crate::state::AppState;

type CoreError = termoso_core::error::CoreError;

/// Team member as shown in the Team page (public key stays in Rust).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TeamMemberCard {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
    pub role: TeamRole,
    pub joined_at: DateTime<Utc>,
    /// Second factor enrolled; `None` when the server keeps it private.
    pub mfa_enabled: Option<bool>,
    /// Account was created through this team's invitation; the owner may delete it.
    pub managed: bool,
}

/// Team-vault member still waiting for their sealed copy of the vault key.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PendingKeyCard {
    pub vault_id: Uuid,
    pub user_id: Uuid,
    pub role: VaultRole,
}

/// One page of the team activity log (server order: newest first).
#[derive(Debug, Clone, Serialize)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
    pub next_before: Option<i64>,
}

/// Filters for [`audit`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditFilter {
    pub before: Option<i64>,
    pub limit: Option<u32>,
    pub action: Option<String>,
    pub actor: Option<Uuid>,
    pub vault: Option<Uuid>,
}

/// Outcome of one invitation in a batch.
#[derive(Debug, Clone, Serialize)]
pub struct InviteResult {
    pub email: String,
    pub invite: Option<Invite>,
    /// Share link (also emailed when the server has SMTP).
    pub url: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VaultAccess {
    pub user_id: Uuid,
    pub role: VaultRole,
}

/// Pull the vault list again (new vault, key granted, rotation, removal),
/// tell the webview and push any re-encrypted rows.
async fn refresh<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let state = app.state::<AppState>();
    let api = api(app).await?;
    core::refresh_vaults(&api, &*state.store()?).await?;
    let _ = app.emit(SYNC_EVENT, SyncNotice::VaultsChanged);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(e) = crate::account::sync_now(&app).await {
            tracing::debug!("sync after vault change: {e}");
        }
    });
    Ok(())
}

fn clean_name(name: &str) -> Result<String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 80 {
        return Err(DesktopError::invalid("name must be 1–80 characters"));
    }
    Ok(n.to_string())
}

// ───────────────────────────── teams ─────────────────────────────

pub async fn list<R: Runtime>(app: &AppHandle<R>) -> Result<Vec<Team>> {
    Ok(api(app).await?.teams().await?.teams)
}

/// Create a team and its first vault (named after the team) with us as manager.
pub async fn create<R: Runtime>(app: &AppHandle<R>, name: &str) -> Result<Team> {
    let name = clean_name(name)?;
    let api = api(app).await?;
    let team = api
        .create_team(&CreateTeamRequest { name: name.clone() })
        .await?;
    let state = app.state::<AppState>();
    let secrets = state.store()?.account_secrets()?;
    let me = state
        .store()?
        .account()?
        .ok_or_else(|| DesktopError::invalid("not signed in"))?;
    let key = SymmetricKey::generate();
    let req = CreateVaultRequest {
        name,
        members: vec![VaultMemberUpsert {
            user_id: me.user_id,
            role: VaultRole::Manager,
            sealed_key: sealed::seal_vault_key(secrets.private_key.public(), &key)
                .map_err(CoreError::from)?,
        }],
    };
    if let Err(e) = api.create_team_vault(team.id, &req).await {
        tracing::warn!(team = %team.id, "team created without a vault: {e}");
    }
    refresh(app).await?;
    Ok(team)
}

pub async fn rename<R: Runtime>(app: &AppHandle<R>, team_id: Uuid, name: &str) -> Result<Team> {
    let name = clean_name(name)?;
    let team = api(app)
        .await?
        .update_team(
            team_id,
            &UpdateTeamRequest {
                name: Some(name),
                ..Default::default()
            },
        )
        .await?;
    refresh(app).await?;
    Ok(team)
}

/// Settings → Team → Security: multiplayer / require-2FA / presence switches
/// (admins only).
pub async fn set_security<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    multiplayer_enabled: Option<bool>,
    require_mfa: Option<bool>,
    presence_enabled: Option<bool>,
) -> Result<Team> {
    let team = api(app)
        .await?
        .update_team(
            team_id,
            &UpdateTeamRequest {
                name: None,
                multiplayer_enabled,
                require_mfa,
                presence_enabled,
            },
        )
        .await?;
    refresh(app).await?;
    Ok(team)
}

pub async fn delete<R: Runtime>(app: &AppHandle<R>, team_id: Uuid) -> Result<()> {
    api(app).await?.delete_team(team_id).await?;
    refresh(app).await
}

pub async fn leave<R: Runtime>(app: &AppHandle<R>, team_id: Uuid) -> Result<()> {
    api(app).await?.leave_team(team_id).await?;
    refresh(app).await
}

/// Token from an invitation link (`…/invite/<token>`) or a bare token.
fn invite_token(link: &str) -> &str {
    let path = link.trim().split(['?', '#']).next().unwrap_or_default();
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default()
}

/// Join the team behind an invitation link (or bare token).
pub async fn accept_invite<R: Runtime>(app: &AppHandle<R>, link: &str) -> Result<Team> {
    let team = api(app).await?.accept_invite(invite_token(link)).await?;
    refresh(app).await?;
    Ok(team)
}

// ───────────────────────────── members ─────────────────────────────

async fn members_raw(
    api: &ApiClient,
    team_id: Uuid,
) -> Result<Vec<termoso_proto::team::TeamMember>> {
    Ok(api.team_members(team_id).await?.members)
}

pub async fn members<R: Runtime>(app: &AppHandle<R>, team_id: Uuid) -> Result<Vec<TeamMemberCard>> {
    let api = api(app).await?;
    Ok(members_raw(&api, team_id)
        .await?
        .into_iter()
        .map(|m| TeamMemberCard {
            user_id: m.user_id,
            email: m.email,
            display_name: m.display_name,
            avatar: m.avatar,
            role: m.role,
            joined_at: m.joined_at,
            mfa_enabled: m.mfa_enabled,
            managed: m.managed,
        })
        .collect())
}

pub async fn set_member_role<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    user_id: Uuid,
    role: TeamRole,
) -> Result<()> {
    api(app)
        .await?
        .update_team_member(
            team_id,
            user_id,
            &UpdateTeamMemberRequest {
                role,
                role_id: None,
            },
        )
        .await?;
    Ok(())
}

/// Remove a teammate, then rotate the key of every team vault we manage and
/// hold a key for, so their stale copy stops working.
pub async fn remove_member<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<()> {
    let api = api(app).await?;
    api.remove_team_member(team_id, user_id).await?;
    rotate_after_removal(app, &api, team_id).await
}

/// Owner-only: delete the whole account of a member this team created, then
/// rotate the team-vault keys they held like a plain removal does.
pub async fn delete_member_account<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<()> {
    let api = api(app).await?;
    api.delete_team_member_account(team_id, user_id).await?;
    rotate_after_removal(app, &api, team_id).await
}

async fn rotate_after_removal<R: Runtime>(
    app: &AppHandle<R>,
    api: &ApiClient,
    team_id: Uuid,
) -> Result<()> {
    let state = app.state::<AppState>();
    let vaults = state.store()?.vaults()?;
    for v in vaults
        .iter()
        .filter(|v| v.team_id == Some(team_id) && v.unlocked && v.role.can_manage())
    {
        if let Err(e) = rotate_with(api, &state, v.id).await {
            tracing::warn!(vault = %v.id, "rotate after member removal: {e}");
        }
    }
    refresh(app).await
}

// ───────────────────────────── invites ─────────────────────────────

pub async fn invites<R: Runtime>(app: &AppHandle<R>, team_id: Uuid) -> Result<Vec<Invite>> {
    Ok(api(app).await?.team_invites(team_id).await?.invites)
}

pub async fn invite<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    emails: Vec<String>,
    role: TeamRole,
    vault_ids: Vec<Uuid>,
) -> Result<Vec<InviteResult>> {
    if role == TeamRole::Owner {
        return Err(DesktopError::invalid("cannot invite as owner"));
    }
    let api = api(app).await?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for raw in emails {
        let email = raw.trim().to_ascii_lowercase();
        if email.is_empty() || !seen.insert(email.clone()) {
            continue;
        }
        let req = CreateInviteRequest {
            email: email.clone(),
            role,
            role_id: None,
            vault_ids: vault_ids.clone(),
        };
        out.push(match api.create_invite(team_id, &req).await {
            Ok(c) => InviteResult {
                email,
                invite: Some(c.invite),
                url: Some(c.url),
                error: None,
            },
            Err(e) => InviteResult {
                email,
                invite: None,
                url: None,
                error: Some(e.to_string()),
            },
        });
    }
    if out.is_empty() {
        return Err(DesktopError::invalid("enter at least one email address"));
    }
    Ok(out)
}

pub async fn revoke_invite<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    invite_id: Uuid,
) -> Result<()> {
    api(app).await?.delete_invite(team_id, invite_id).await?;
    Ok(())
}

pub async fn audit<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    f: AuditFilter,
) -> Result<AuditPage> {
    let q = AuditQuery {
        before: f.before,
        limit: f.limit,
        action: f.action.filter(|a| !a.is_empty()),
        actor: f.actor,
        vault: f.vault,
    };
    let page = api(app).await?.team_audit(team_id, &q).await?;
    Ok(AuditPage {
        events: page.events,
        next_before: page.next_before,
    })
}

// ───────────────── roles, policies, webhooks (0.9.0) ─────────────────

pub async fn permissions<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::PermissionCatalog> {
    Ok(api(app).await?.team_permissions(team_id).await?)
}

pub async fn roles<R: Runtime>(app: &AppHandle<R>, team_id: Uuid) -> Result<proto::TeamRoleList> {
    Ok(api(app).await?.team_roles(team_id).await?)
}

pub async fn role_create<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    req: proto::CreateRoleRequest,
) -> Result<proto::TeamRoleDef> {
    Ok(api(app).await?.team_role_create(team_id, &req).await?)
}

pub async fn role_update<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    role_id: Uuid,
    req: proto::UpdateRoleRequest,
) -> Result<proto::TeamRoleDef> {
    Ok(api(app)
        .await?
        .team_role_update(team_id, role_id, &req)
        .await?)
}

pub async fn role_delete<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    role_id: Uuid,
    reassign_to: Option<Uuid>,
) -> Result<()> {
    Ok(api(app)
        .await?
        .team_role_delete(team_id, role_id, reassign_to)
        .await?)
}

pub async fn set_default_role<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    role_id: Uuid,
) -> Result<()> {
    Ok(api(app)
        .await?
        .team_set_default_role(team_id, role_id)
        .await?)
}

pub async fn role_mappings<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<Vec<proto::RoleMapping>> {
    Ok(api(app).await?.team_role_mappings(team_id).await?.mappings)
}

pub async fn set_role_mappings<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    mappings: Vec<proto::RoleMapping>,
) -> Result<Vec<proto::RoleMapping>> {
    let req = proto::RoleMappingList { mappings };
    Ok(api(app)
        .await?
        .team_set_role_mappings(team_id, &req)
        .await?
        .mappings)
}

// ───────────────────────────── SSH CA ─────────────────────────────

pub async fn ca<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<Option<termoso_proto::ca::TeamCa>> {
    Ok(api(app).await?.team_ca(team_id).await?)
}

pub async fn update_ca<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    patch: termoso_proto::ca::UpdateTeamCaRequest,
) -> Result<termoso_proto::ca::TeamCa> {
    let ca = api(app).await?.update_team_ca(team_id, &patch).await?;
    refresh_local_certificates(app).await;
    Ok(ca)
}

pub async fn delete_ca<R: Runtime>(app: &AppHandle<R>, team_id: Uuid) -> Result<()> {
    api(app).await?.delete_team_ca(team_id).await?;
    let state = app.state::<AppState>();
    let _ = termoso_core::ca::forget_certificates(&*state.store()?);
    let _ = termoso_core::policy::clear(&*state.store()?);
    Ok(())
}

pub async fn rotate_ca<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    grace_hours: Option<i32>,
) -> Result<termoso_proto::ca::TeamCa> {
    let ca = api(app)
        .await?
        .rotate_team_ca(
            team_id,
            &termoso_proto::ca::RotateTeamCaRequest { grace_hours },
        )
        .await?;
    refresh_local_certificates(app).await;
    Ok(ca)
}

pub async fn ca_certificates<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<termoso_proto::ca::IssuedCertificateList> {
    Ok(api(app).await?.team_certificates(team_id).await?)
}

pub async fn ca_revoke<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    certificate_id: Uuid,
) -> Result<termoso_proto::ca::IssuedCertificate> {
    Ok(api(app)
        .await?
        .revoke_team_certificate(team_id, certificate_id)
        .await?)
}

/// This device's cached certificate for the team, after asking the server
/// for a fresh one when the cache is stale.
pub async fn ca_local<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<Option<termoso_core::ca::CachedCert>> {
    refresh_local_certificates(app).await;
    let state = app.state::<AppState>();
    let store = state.store()?;
    Ok(termoso_core::ca::cached(&store)?
        .into_iter()
        .find(|c| c.team_id == team_id))
}

async fn refresh_local_certificates<R: Runtime>(app: &AppHandle<R>) {
    let Ok(api) = api(app).await else { return };
    let state = app.state::<AppState>();
    let Ok(store) = state.store() else { return };
    if let Err(e) = termoso_core::ca::refresh_all(&api, &store).await {
        tracing::debug!("team CA refresh: {e}");
    }
    if let Err(e) = termoso_core::policy::refresh(&api, &store).await {
        tracing::debug!("team policy refresh: {e}");
    }
}

pub async fn policies<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::TeamPoliciesResponse> {
    Ok(api(app).await?.team_policies(team_id).await?)
}

pub async fn update_policies<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    patch: proto::UpdateTeamPoliciesRequest,
) -> Result<proto::TeamPoliciesResponse> {
    Ok(api(app)
        .await?
        .team_update_policies(team_id, &patch)
        .await?)
}

pub async fn webhooks<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<Vec<proto::Webhook>> {
    Ok(api(app).await?.team_webhooks(team_id).await?.webhooks)
}

pub async fn webhook_create<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    req: proto::CreateWebhookRequest,
) -> Result<proto::Webhook> {
    Ok(api(app).await?.team_webhook_create(team_id, &req).await?)
}

pub async fn webhook_update<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    hook_id: Uuid,
    req: proto::UpdateWebhookRequest,
) -> Result<proto::Webhook> {
    Ok(api(app)
        .await?
        .team_webhook_update(team_id, hook_id, &req)
        .await?)
}

pub async fn webhook_delete<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    hook_id: Uuid,
) -> Result<()> {
    Ok(api(app)
        .await?
        .team_webhook_delete(team_id, hook_id)
        .await?)
}

pub async fn webhook_test<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    hook_id: Uuid,
) -> Result<Vec<proto::WebhookDelivery>> {
    Ok(api(app)
        .await?
        .team_webhook_test(team_id, hook_id)
        .await?
        .deliveries)
}

pub async fn webhook_deliveries<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    hook_id: Uuid,
) -> Result<Vec<proto::WebhookDelivery>> {
    Ok(api(app)
        .await?
        .team_webhook_deliveries(team_id, hook_id)
        .await?
        .deliveries)
}

// ───────────────────────────── vaults ─────────────────────────────

pub async fn pending_keys<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<Vec<PendingKeyCard>> {
    Ok(api(app)
        .await?
        .team_pending_keys(team_id)
        .await?
        .items
        .into_iter()
        .map(|p| PendingKeyCard {
            vault_id: p.vault_id,
            user_id: p.user_id,
            role: p.role,
        })
        .collect())
}

/// Public keys of team members, by user id.
async fn public_keys(api: &ApiClient, team_id: Uuid) -> Result<HashMap<Uuid, String>> {
    Ok(members_raw(api, team_id)
        .await?
        .into_iter()
        .map(|m| (m.user_id, m.public_key))
        .collect())
}

fn seal_for(public_key_b64: &str, key: &SymmetricKey) -> Result<String> {
    let pk = public_key_from_b64(public_key_b64).map_err(CoreError::from)?;
    Ok(sealed::seal_vault_key(&pk, key).map_err(CoreError::from)?)
}

/// Create a team vault; we are always included as a manager.
pub async fn create_vault<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    name: &str,
    access: Vec<VaultAccess>,
) -> Result<()> {
    let name = clean_name(name)?;
    let api = api(app).await?;
    let state = app.state::<AppState>();
    let secrets = state.store()?.account_secrets()?;
    let me = state
        .store()?
        .account()?
        .ok_or_else(|| DesktopError::invalid("not signed in"))?;
    let keys = public_keys(&api, team_id).await?;
    let key = SymmetricKey::generate();
    let mut members = vec![VaultMemberUpsert {
        user_id: me.user_id,
        role: VaultRole::Manager,
        sealed_key: sealed::seal_vault_key(secrets.private_key.public(), &key)
            .map_err(CoreError::from)?,
    }];
    for a in access.into_iter().filter(|a| a.user_id != me.user_id) {
        let pk = keys
            .get(&a.user_id)
            .ok_or_else(|| DesktopError::not_found("user is not a member of this team"))?;
        members.push(VaultMemberUpsert {
            user_id: a.user_id,
            role: a.role,
            sealed_key: seal_for(pk, &key)?,
        });
    }
    api.create_team_vault(team_id, &CreateVaultRequest { name, members })
        .await?;
    refresh(app).await
}

pub async fn rename_vault<R: Runtime>(
    app: &AppHandle<R>,
    vault_id: Uuid,
    name: &str,
) -> Result<()> {
    let name = clean_name(name)?;
    api(app)
        .await?
        .update_vault(
            vault_id,
            &UpdateVaultRequest {
                name: Some(name),
                session_logging: None,
            },
        )
        .await?;
    refresh(app).await
}

pub async fn delete_vault<R: Runtime>(app: &AppHandle<R>, vault_id: Uuid) -> Result<()> {
    api(app).await?.delete_vault(vault_id).await?;
    refresh(app).await
}

/// Grant (or change) a teammate's access: seal our copy of the vault key to
/// their account public key. Works for pending members and role changes alike.
pub async fn set_vault_access<R: Runtime>(
    app: &AppHandle<R>,
    vault_id: Uuid,
    user_id: Uuid,
    role: VaultRole,
) -> Result<()> {
    let api = api(app).await?;
    let state = app.state::<AppState>();
    let vault = state.store()?.vault(vault_id)?;
    let team_id = vault
        .team_id
        .ok_or_else(|| DesktopError::invalid("not a team vault"))?;
    let key = state.store()?.vault_key(vault_id)?;
    let keys = public_keys(&api, team_id).await?;
    let pk = keys
        .get(&user_id)
        .ok_or_else(|| DesktopError::not_found("user is not a member of this team"))?;
    api.upsert_vault_member(
        vault_id,
        &VaultMemberUpsert {
            user_id,
            role,
            sealed_key: seal_for(pk, &key)?,
        },
    )
    .await?;
    Ok(())
}

/// Revoke access and rotate the vault key for everyone who remains.
pub async fn remove_vault_access<R: Runtime>(
    app: &AppHandle<R>,
    vault_id: Uuid,
    user_id: Uuid,
) -> Result<()> {
    let api = api(app).await?;
    api.remove_vault_member(vault_id, user_id).await?;
    let state = app.state::<AppState>();
    let me = state.store()?.account()?.map(|a| a.user_id);
    if me != Some(user_id) {
        rotate_with(&api, &state, vault_id).await?;
    }
    refresh(app).await
}

pub async fn rotate_vault_key<R: Runtime>(app: &AppHandle<R>, vault_id: Uuid) -> Result<()> {
    let api = api(app).await?;
    let state = app.state::<AppState>();
    rotate_with(&api, &state, vault_id).await?;
    refresh(app).await
}

/// New vault key sealed to every member who already holds one; pending members
/// keep waiting for a manager to grant the new key. Local rows are re-encrypted
/// by the vault refresh that follows.
async fn rotate_with(api: &ApiClient, state: &AppState, vault_id: Uuid) -> Result<()> {
    let vault = state.store()?.vault(vault_id)?;
    if !vault.unlocked {
        return Err(DesktopError::invalid("you need the vault key to rotate it"));
    }
    let members = api.vault_members(vault_id).await?.members;
    let key = SymmetricKey::generate();
    // Personal vault: only we hold it, and only a self-authenticated envelope
    // is accepted back by our own devices.
    let me = if vault.kind == LocalVaultKind::Personal {
        Some(state.store()?.account_secrets()?.private_key)
    } else {
        None
    };
    let sealed_for = members
        .iter()
        .filter(|m| !m.pending)
        .map(|m| {
            Ok(SealedKeyFor {
                user_id: m.user_id,
                sealed_key: match &me {
                    Some(pair) => {
                        sealed::seal_vault_key_self(pair, &key).map_err(CoreError::from)?
                    }
                    None => seal_for(&m.public_key, &key)?,
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    api.rotate_vault_key(
        vault_id,
        &RotateVaultKeyRequest {
            base_key_version: vault.key_version,
            members: sealed_for,
        },
    )
    .await?;
    Ok(())
}

// ───────────────────────── 0.9.1 enterprise ─────────────────────────

pub async fn idp<R: Runtime>(app: &AppHandle<R>, team_id: Uuid) -> Result<proto::TeamIdpResponse> {
    Ok(api(app).await?.team_idp(team_id).await?)
}

pub async fn update_idp<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    req: proto::UpdateTeamIdpRequest,
) -> Result<proto::TeamIdpResponse> {
    Ok(api(app).await?.team_update_idp(team_id, &req).await?)
}

pub async fn test_idp<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    req: proto::UpdateTeamIdpRequest,
) -> Result<proto::TeamIdpResponse> {
    Ok(api(app).await?.team_test_idp(team_id, &req).await?)
}

pub async fn delete_idp<R: Runtime>(app: &AppHandle<R>, team_id: Uuid) -> Result<()> {
    Ok(api(app).await?.team_delete_idp(team_id).await?)
}

pub async fn acl<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    vault_id: Uuid,
) -> Result<Vec<proto::EntityAclRule>> {
    Ok(api(app).await?.team_acl(team_id, vault_id).await?.rules)
}

pub async fn upsert_acl<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    vault_id: Uuid,
    req: proto::UpsertEntityAclRequest,
) -> Result<Vec<proto::EntityAclRule>> {
    Ok(api(app)
        .await?
        .team_upsert_acl(team_id, vault_id, &req)
        .await?
        .rules)
}

pub async fn delete_acl<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    vault_id: Uuid,
    rule_id: Uuid,
) -> Result<()> {
    Ok(api(app)
        .await?
        .team_delete_acl(team_id, vault_id, rule_id)
        .await?)
}

pub async fn acl_me<R: Runtime>(app: &AppHandle<R>) -> Result<Vec<proto::MyAclRule>> {
    Ok(api(app).await?.acl_me().await?.rules)
}

pub async fn logs<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    vault_id: Option<Uuid>,
) -> Result<termoso_proto::logs::LogListResponse> {
    Ok(api(app).await?.team_logs(team_id, vault_id).await?)
}

pub async fn logs_export<R: Runtime>(app: &AppHandle<R>, team_id: Uuid) -> Result<String> {
    let bytes = api(app).await?.team_logs_export(team_id).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub async fn rotation<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::RotationOverview> {
    Ok(api(app).await?.team_rotation(team_id).await?)
}

pub async fn create_rotation_jobs<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    req: proto::CreateRotationJobsRequest,
) -> Result<Vec<proto::RotationJob>> {
    Ok(api(app)
        .await?
        .team_create_rotation_jobs(team_id, &req)
        .await?
        .jobs)
}

pub async fn rotation_jobs<R: Runtime>(app: &AppHandle<R>) -> Result<Vec<proto::RotationJob>> {
    Ok(api(app).await?.rotation_jobs().await?.jobs)
}

pub async fn rotation_update_job<R: Runtime>(
    app: &AppHandle<R>,
    job_id: Uuid,
    req: proto::UpdateRotationJobRequest,
) -> Result<proto::RotationJob> {
    Ok(api(app).await?.rotation_update_job(job_id, &req).await?)
}

pub async fn rotation_cancel_job<R: Runtime>(app: &AppHandle<R>, job_id: Uuid) -> Result<()> {
    Ok(api(app).await?.rotation_cancel_job(job_id).await?)
}

pub async fn access_requests<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::AccessRequestList> {
    Ok(api(app).await?.team_access_requests(team_id).await?)
}

pub async fn create_access_request<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    req: proto::CreateAccessRequest,
) -> Result<proto::AccessRequest> {
    Ok(api(app)
        .await?
        .team_create_access_request(team_id, &req)
        .await?)
}

pub async fn cancel_access_request<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    rid: Uuid,
) -> Result<()> {
    Ok(api(app)
        .await?
        .team_cancel_access_request(team_id, rid)
        .await?)
}

pub async fn decide_access_request<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    rid: Uuid,
    action: String,
    req: proto::DecideAccessRequest,
) -> Result<proto::AccessRequest> {
    Ok(api(app)
        .await?
        .team_decide_access_request(team_id, rid, &action, &req)
        .await?)
}

pub async fn data<R: Runtime>(app: &AppHandle<R>, team_id: Uuid) -> Result<proto::TeamDataStatus> {
    Ok(api(app).await?.team_data(team_id).await?)
}

pub async fn export<R: Runtime>(app: &AppHandle<R>, team_id: Uuid) -> Result<String> {
    let bytes = api(app).await?.team_export(team_id).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub async fn schedule_deletion<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    confirm_name: String,
) -> Result<proto::TeamDataStatus> {
    let req = proto::ScheduleTeamDeletionRequest { confirm_name };
    Ok(api(app)
        .await?
        .team_schedule_deletion(team_id, &req)
        .await?)
}

pub async fn cancel_deletion<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::TeamDataStatus> {
    Ok(api(app).await?.team_cancel_deletion(team_id).await?)
}

pub async fn devices<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::TeamDeviceList> {
    Ok(api(app).await?.team_devices(team_id).await?)
}

pub async fn approve_device<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    device_id: Uuid,
) -> Result<()> {
    Ok(api(app)
        .await?
        .team_approve_device(team_id, device_id)
        .await?)
}

pub async fn reject_device<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    device_id: Uuid,
) -> Result<()> {
    Ok(api(app)
        .await?
        .team_reject_device(team_id, device_id)
        .await?)
}
// ───────────── compliance: access reviews, break-glass, audit chain ─────────────

pub async fn access_reviews<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::AccessReviewList> {
    Ok(api(app).await?.access_reviews(team_id).await?)
}

pub async fn access_review<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    review_id: Uuid,
) -> Result<proto::AccessReviewDetail> {
    Ok(api(app).await?.access_review(team_id, review_id).await?)
}

pub async fn open_access_review<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::AccessReviewDetail> {
    Ok(api(app).await?.open_access_review(team_id).await?)
}

pub async fn decide_access_review_item<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    review_id: Uuid,
    item_id: Uuid,
    req: proto::DecideAccessReviewItemRequest,
) -> Result<proto::AccessReviewItem> {
    Ok(api(app)
        .await?
        .decide_access_review_item(team_id, review_id, item_id, &req)
        .await?)
}

pub async fn complete_access_review<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    review_id: Uuid,
    req: proto::CompleteAccessReviewRequest,
) -> Result<proto::AccessReviewDetail> {
    Ok(api(app)
        .await?
        .complete_access_review(team_id, review_id, &req)
        .await?)
}

pub async fn cancel_access_review<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    review_id: Uuid,
) -> Result<proto::AccessReview> {
    Ok(api(app)
        .await?
        .cancel_access_review(team_id, review_id)
        .await?)
}

pub async fn break_glass<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<Option<proto::BreakGlass>> {
    Ok(api(app).await?.break_glass(team_id).await?)
}

pub async fn configure_break_glass<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    req: proto::ConfigureBreakGlassRequest,
) -> Result<proto::BreakGlass> {
    Ok(api(app).await?.configure_break_glass(team_id, &req).await?)
}

pub async fn delete_break_glass<R: Runtime>(app: &AppHandle<R>, team_id: Uuid) -> Result<()> {
    Ok(api(app).await?.delete_break_glass(team_id).await?)
}

pub async fn use_break_glass<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    req: proto::UseBreakGlassRequest,
) -> Result<proto::BreakGlass> {
    Ok(api(app).await?.use_break_glass(team_id, &req).await?)
}

pub async fn end_break_glass<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::BreakGlass> {
    Ok(api(app).await?.end_break_glass(team_id).await?)
}

pub async fn verify_audit<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::AuditVerification> {
    Ok(api(app).await?.verify_audit(team_id).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_token_is_last_path_segment() {
        assert_eq!(invite_token("https://x.io/invite/abc_-9?x=1"), "abc_-9");
        assert_eq!(invite_token("abc"), "abc");
        assert_eq!(invite_token(" https://x.io/invite/abc/ "), "abc");
        assert_eq!(invite_token(""), "");
    }
}
