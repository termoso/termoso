//! Teams, members and invitations.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::schema;

schema! {
    /// Role inside a team.
    #[derive(Copy, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(rename_all = "snake_case")]
    pub enum TeamRole {
        /// Regular member; vault access is granted per vault.
        Member,
        /// Can manage members, invites and vaults.
        Admin,
        /// Exactly one per team; can delete the team and transfer ownership.
        Owner,
    }
}

impl TeamRole {
    /// Whether this role may administer the team.
    pub fn is_admin(self) -> bool {
        matches!(self, TeamRole::Admin | TeamRole::Owner)
    }
}

schema! {
    /// A team.
    pub struct Team {
        /// Id.
        pub id: Uuid,
        /// Name.
        pub name: String,
        /// Created.
        pub created_at: DateTime<Utc>,
        /// Requesting user's role.
        pub my_role: TeamRole,
        /// Requesting user's fine-grained role (0.9.0+).
        #[serde(default)]
        pub my_role_ref: Option<RoleRef>,
        /// Requesting user's effective permissions (`*` for the owner).
        #[serde(default)]
        pub my_permissions: Vec<String>,
        /// Number of members.
        pub member_count: i64,
        /// Members may share live terminal sessions with each other.
        #[serde(default = "default_true")]
        pub multiplayer_enabled: bool,
        /// Members without two-factor authentication cannot open team vaults.
        #[serde(default)]
        pub require_mfa: bool,
        /// Members see who is connected to which team-vault host right now.
        #[serde(default)]
        pub presence_enabled: bool,
        /// Team policies (0.9.0+; `None` from older servers).
        #[serde(default)]
        pub policies: Option<TeamPolicies>,
    }
}

fn default_true() -> bool {
    true
}

schema! {
    /// `GET /teams`
    pub struct TeamList {
        /// Teams.
        pub teams: Vec<Team>,
    }
}

schema! {
    /// `POST /teams`
    pub struct CreateTeamRequest {
        /// Name.
        pub name: String,
    }
}

schema! {
    /// `PATCH /teams/{id}`
    #[derive(Default)]
    pub struct UpdateTeamRequest {
        /// New name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// Allow live terminal sharing between members.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub multiplayer_enabled: Option<bool>,
        /// Require two-factor authentication to open team vaults.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub require_mfa: Option<bool>,
        /// Show members who is connected to which team-vault host.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub presence_enabled: Option<bool>,
    }
}

schema! {
    /// Team member with public key (needed to seal vault keys to them).
    pub struct TeamMember {
        /// User id.
        pub user_id: Uuid,
        /// Email.
        pub email: String,
        /// Display name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        /// Profile picture tag (see `UserProfile::avatar`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub avatar: Option<String>,
        /// Role.
        pub role: TeamRole,
        /// Fine-grained role (0.9.0+).
        #[serde(default)]
        pub role_ref: Option<RoleRef>,
        /// `manual`, `idp` or `scim` — who assigned the role.
        #[serde(default)]
        pub role_source: Option<String>,
        /// X25519 public key (base64).
        pub public_key: String,
        /// Joined.
        pub joined_at: DateTime<Utc>,
        /// Whether the member has a second factor (TOTP or a security key).
        /// Present for team admins and for the caller's own row; other
        /// members get `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mfa_enabled: Option<bool>,
        /// The account was created through this team's invitation and can be
        /// deleted by the owner (`DELETE /teams/{id}/members/{user_id}/account`);
        /// removing such a member instead converts it into an individual account.
        #[serde(default)]
        pub managed: bool,
    }
}

schema! {
    /// `GET /teams/{id}/members`
    pub struct TeamMemberList {
        /// Members.
        pub members: Vec<TeamMember>,
    }
}

schema! {
    /// One live connection of a team member to a host in a team vault, as
    /// reported by their device. Only routing metadata: the server never
    /// learns the host's name or address.
    #[derive(PartialEq, Eq, Hash)]
    pub struct PresenceSession {
        /// Team vault the host lives in.
        pub vault_id: Uuid,
        /// Host entity id.
        pub host_id: Uuid,
        /// `ssh` | `sftp` | `mosh` | `telnet` | `forwarding`.
        pub protocol: String,
        /// When the connection was established.
        pub since: DateTime<Utc>,
    }
}

schema! {
    /// Everything one device of one member is connected to right now.
    pub struct PresenceEntry {
        /// Member.
        pub user_id: Uuid,
        /// Email.
        pub email: String,
        /// Display name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        /// Profile picture tag (see `UserProfile::avatar`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub avatar: Option<String>,
        /// Device.
        pub device_id: Uuid,
        /// Device name as registered at login.
        pub device_name: String,
        /// `linux` | `windows` | `macos` | `android` | `ios` | `web`.
        pub platform: String,
        /// Live connections (only those in vaults the requester can see).
        pub sessions: Vec<PresenceSession>,
        /// Last heartbeat from the device.
        pub seen_at: DateTime<Utc>,
    }
}

schema! {
    /// `GET /teams/{id}/presence`
    pub struct TeamPresence {
        /// Whether the team has presence turned on; `entries` is empty otherwise.
        pub enabled: bool,
        /// Devices with at least one live connection.
        pub entries: Vec<PresenceEntry>,
    }
}

schema! {
    /// `PATCH /teams/{id}/members/{user_id}`
    pub struct UpdateTeamMemberRequest {
        /// New role (`owner` transfers ownership; only the owner may do that).
        pub role: TeamRole,
            /// Fine-grained role to assign (preferred over `role`).
        #[serde(default)]
        pub role_id: Option<Uuid>,
}
}

schema! {
    /// `POST /teams/{id}/invites`
    pub struct CreateInviteRequest {
        /// Invitee email.
        pub email: String,
        /// Role on acceptance (coarse level; `role_id` wins when set).
        pub role: TeamRole,
        /// Fine-grained role on acceptance (0.9.0+).
        #[serde(default)]
        pub role_id: Option<Uuid>,
        /// Vaults to grant on acceptance (keys are sealed later by an admin
        /// once the invitee's public key is known).
        #[serde(default)]
        pub vault_ids: Vec<Uuid>,
    }
}

schema! {
    /// Pending invitation.
    pub struct Invite {
        /// Id.
        pub id: Uuid,
        /// Email.
        pub email: String,
        /// Role.
        pub role: TeamRole,
        /// Invited by.
        pub invited_by: Uuid,
        /// Created.
        pub created_at: DateTime<Utc>,
        /// Expires.
        pub expires_at: DateTime<Utc>,
        /// Fine-grained role on acceptance (0.9.0+).
        #[serde(default)]
        pub role_ref: Option<RoleRef>,
    }
}

schema! {
    /// `POST /teams/{id}/invites` response: the invite plus its share link.
    pub struct CreatedInvite {
        /// The pending invitation.
        #[serde(flatten)]
        pub invite: Invite,
        /// Share this link with the invitee (also emailed when SMTP is configured).
        pub url: String,
    }
}

schema! {
    /// `GET /teams/{id}/invites`
    pub struct InviteList {
        /// Invites.
        pub invites: Vec<Invite>,
    }
}

schema! {
    /// `GET /invites/{token}` – public preview.
    pub struct InvitePreview {
        /// Team name.
        pub team_name: String,
        /// Inviter display name or email.
        pub inviter: String,
        /// Invitee email.
        pub email: String,
        /// Role.
        pub role: TeamRole,
        /// Whether an account with that email already exists.
        pub account_exists: bool,
    }
}

schema! {
    /// Members whose vault keys still need to be sealed (`GET /teams/{id}/pending-keys`).
    pub struct PendingVaultKeys {
        /// Items.
        pub items: Vec<PendingVaultKey>,
    }
}

schema! {
    /// A (vault, user) pair lacking a sealed key.
    pub struct PendingVaultKey {
        /// Vault.
        pub vault_id: Uuid,
        /// User.
        pub user_id: Uuid,
        /// Their public key.
        pub public_key: String,
        /// Role that was granted.
        pub role: crate::vault::VaultRole,
    }
}

schema! {
    /// One entry of the team activity log (`GET /teams/{id}/audit`). The
    /// server never sees vault payloads, so entries name kinds and ids — the
    /// client resolves them to labels where it holds the vault key.
    pub struct AuditEvent {
        /// Monotonic id; also the paging cursor.
        pub id: i64,
        /// Team.
        pub team_id: Uuid,
        /// Who did it (`None` once the account is gone).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actor_id: Option<Uuid>,
        /// Actor email at query time.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actor_email: Option<String>,
        /// Actor display name at query time.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actor_name: Option<String>,
        /// Actor profile picture tag at query time (see `UserProfile::avatar`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actor_avatar: Option<String>,
        /// Device the request came from.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device_id: Option<Uuid>,
        /// What happened: `team.created`, `team.renamed`, `team.settings`,
        /// `member.role`, `member.removed`, `member.account_deleted`,
        /// `member.left`, `invite.created`,
        /// `invite.revoked`, `invite.accepted`, `vault.created`, `vault.renamed`,
        /// `vault.deleted`, `vault.key_rotated`, `vault.access_granted`,
        /// `vault.access_changed`, `vault.access_revoked`, `entity.created`,
        /// `entity.updated`, `entity.deleted`, `multiplayer.started`,
        /// `multiplayer.joined`, `multiplayer.stopped`, `vault.session_logging`,
        /// `log.updated`, `log.deleted`.
        pub action: String,
        /// Vault involved, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub vault_id: Option<Uuid>,
        /// Other user involved (member, invitee), if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target_user: Option<Uuid>,
        /// Target user's email at query time.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target_email: Option<String>,
        /// Action-specific metadata (entity kind/id, role, name, counts).
        #[serde(default)]
        pub details: serde_json::Value,
        /// When.
        pub created_at: DateTime<Utc>,
    }
}

schema! {
    /// A page of the team activity log, newest first.
    pub struct AuditEventList {
        /// Events.
        pub events: Vec<AuditEvent>,
        /// Pass as `before` to fetch the next (older) page.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next_before: Option<i64>,
    }
}

schema! {
    /// How often an admin receives the team activity digest by e-mail.
    #[derive(Copy, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum DigestCadence {
        /// Every morning (07:00 UTC) for the previous UTC day.
        Daily,
        /// Every Monday morning (07:00 UTC) for the previous week.
        Weekly,
    }
}

impl DigestCadence {
    /// Storage / wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            DigestCadence::Daily => "daily",
            DigestCadence::Weekly => "weekly",
        }
    }

    /// Inverse of [`Self::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "daily" => Some(DigestCadence::Daily),
            "weekly" => Some(DigestCadence::Weekly),
            _ => None,
        }
    }
}

schema! {
    /// `GET /teams/{id}/digest` — the caller's own digest subscription.
    /// Digests are opt-in per admin; nobody else receives them.
    pub struct DigestSubscription {
        /// `None` when the caller has not subscribed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cadence: Option<DigestCadence>,
        /// End of the last period that was mailed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_sent_at: Option<DateTime<Utc>>,
    }
}

schema! {
    /// `PUT /teams/{id}/digest` — subscribe (`cadence` set) or unsubscribe
    /// (`cadence` null).
    pub struct UpdateDigestRequest {
        /// Desired cadence, or `None` to stop receiving digests.
        #[serde(default)]
        pub cadence: Option<DigestCadence>,
    }
}

schema! {
    /// `POST /teams/{id}/digest/send` — mail the caller the digest for the
    /// most recent period right away.
    pub struct SendDigestRequest {
        /// Period length; defaults to the subscription's cadence, then daily.
        #[serde(default)]
        pub cadence: Option<DigestCadence>,
    }
}

schema! {
    /// `POST /teams/{id}/digest/send` result.
    pub struct SendDigestResponse {
        /// Number of events in the mailed period. Nothing is sent when zero.
        pub events: u32,
        /// Whether an e-mail went out.
        pub sent: bool,
    }
}

// ───────────────────────────── roles & permissions ─────────────────────────────

/// Every team permission the server understands, as `domain.action`. The
/// built-in `owner` role holds `*`; everything else is an explicit subset.
pub const PERMISSIONS: &[&str] = &[
    // team
    "team.view",
    "team.rename",
    "team.settings",
    "team.delete",
    "team.transfer",
    // members
    "members.view",
    "members.view_mfa",
    "members.invite",
    "members.remove",
    "members.suspend",
    "members.role",
    // invites
    "invites.view",
    // roles
    "roles.manage",
    // vaults
    "vaults.create",
    "vaults.rename",
    "vaults.archive",
    "vaults.delete",
    "vaults.transfer",
    "vaults.members",
    "vaults.rotate_key",
    // acl
    "acl.manage",
    "rotation.manage",
    "access.approve",
    "team.export",
    "devices.approve",
    "vaults.history",
    // entities
    "entities.read",
    "entities.write",
    "entities.delete",
    "entities.move",
    "entities.share_link",
    // secrets
    "secrets.reveal",
    "secrets.copy",
    // keys
    "keys.generate",
    "keys.export",
    // snippets
    "snippets.run",
    // connect
    "connect.ssh",
    "connect.sftp",
    "connect.port_forward",
    "connect.telnet",
    "connect.serial",
    "connect.mosh",
    "connect.local_terminal",
    "connect.record",
    "connect.bridge",
    // live
    "live.start",
    "live.join",
    "live.control",
    // logs
    "logs.view_own",
    "logs.view_team",
    "logs.export",
    "logs.delete",
    // export
    "export.vault",
    // import
    "import.vault",
    // bridges
    "bridges.manage",
    "bridges.use",
    // sshid
    "sshid.manage",
    // ca
    "ca.manage",
    "ca.issue",
    // automations
    "automations.manage",
    "automations.view",
    "automations.run",
    // ai
    "ai.use",
    // mcp
    "mcp.use",
    // digest
    "digest.manage",
    // audit
    "audit.view",
    "audit.view_ips",
    "audit.export",
    // webhooks
    "webhooks.manage",
    // tokens
    "tokens.manage",
    // policies
    "policies.manage",
    // sso
    "sso.manage",
    // scim
    "scim.manage",
    "scim.tokens",
];

/// Permissions the server cannot enforce on its own: zero-knowledge clients
/// hold the secrets, so these are honoured by Termoso clients and listed as
/// such in the catalog (`enforced_by = "client"`).
pub const CLIENT_ENFORCED_PERMISSIONS: &[&str] = &[
    "secrets.reveal",
    "secrets.copy",
    "keys.export",
    "snippets.run",
    "connect.serial",
    "connect.local_terminal",
];

/// Permissions only the owner may hold; they cannot be put on any role.
pub const OWNER_ONLY_PERMISSIONS: &[&str] = &["team.delete", "team.transfer"];

/// Whether `key` is a known permission.
pub fn is_permission(key: &str) -> bool {
    PERMISSIONS.contains(&key)
}

schema! {
    /// A permission in the catalog (`GET /teams/{id}/permissions`).
    pub struct PermissionInfo {
        /// `domain.action`.
        pub key: String,
        /// Group for display (`team`, `members`, `vaults`, …).
        pub group: String,
        /// Short title.
        pub title: String,
        /// One-line description.
        pub description: String,
        /// Granting this widens access to secrets or administration.
        pub dangerous: bool,
        /// `server` (checked on every request) or `client` (honoured by Termoso
        /// clients; the server cannot see the secret).
        pub enforced_by: String,
    }
}

schema! {
    /// `GET /teams/{id}/permissions`
    pub struct PermissionCatalog {
        /// All permissions.
        pub permissions: Vec<PermissionInfo>,
    }
}

schema! {
    /// Short reference to a role, embedded in members and the team.
    pub struct RoleRef {
        /// Role id.
        pub id: Uuid,
        /// Stable slug (`owner`, `admin`, `member`, `viewer`, `auditor`, or custom).
        pub slug: String,
        /// Display name.
        pub name: String,
    }
}

schema! {
    /// A team role (`GET /teams/{id}/roles`).
    pub struct TeamRoleDef {
        /// Id.
        pub id: Uuid,
        /// Slug.
        pub slug: String,
        /// Name.
        pub name: String,
        /// Description.
        pub description: String,
        /// Permissions (`*` for the owner role).
        pub permissions: Vec<String>,
        /// Seeded by the server; cannot be deleted.
        pub builtin: bool,
        /// Sort position (lower first).
        pub position: i32,
        /// Members holding this role.
        pub member_count: i64,
        /// Created.
        pub created_at: DateTime<Utc>,
        /// Updated.
        pub updated_at: DateTime<Utc>,
    }
}

schema! {
    /// `GET /teams/{id}/roles`
    pub struct TeamRoleList {
        /// Roles, by position.
        pub roles: Vec<TeamRoleDef>,
        /// Role new members get (invites, IdP users without a mapping).
        pub default_role_id: Option<Uuid>,
    }
}

schema! {
    /// `POST /teams/{id}/roles`
    pub struct CreateRoleRequest {
        /// Name, 1..40 characters.
        pub name: String,
        /// Description, up to 200 characters.
        #[serde(default)]
        pub description: String,
        /// Permissions; unknown or owner-only keys are rejected.
        pub permissions: Vec<String>,
        /// Copy permissions from this role when `permissions` is empty.
        #[serde(default)]
        pub copy_from: Option<Uuid>,
    }
}

schema! {
    /// `PATCH /teams/{id}/roles/{role_id}`
    pub struct UpdateRoleRequest {
        /// New name.
        #[serde(default)]
        pub name: Option<String>,
        /// New description.
        #[serde(default)]
        pub description: Option<String>,
        /// Replace the permission set (not allowed for `owner`).
        #[serde(default)]
        pub permissions: Option<Vec<String>>,
        /// New position.
        #[serde(default)]
        pub position: Option<i32>,
    }
}

schema! {
    /// `PUT /teams/{id}/default-role`
    pub struct SetDefaultRoleRequest {
        /// Role new members get.
        pub role_id: Uuid,
    }
}

schema! {
    /// Group (IdP claim / SCIM group) → role mapping.
    pub struct RoleMapping {
        /// Group name as the IdP sends it.
        pub group_name: String,
        /// Role granted.
        pub role_id: Uuid,
        /// Lower wins when several groups match.
        pub priority: i32,
    }
}

schema! {
    /// `GET`/`PUT /teams/{id}/role-mappings`
    pub struct RoleMappingList {
        /// Mappings.
        pub mappings: Vec<RoleMapping>,
    }
}

// ───────────────────────────── policies ─────────────────────────────

fn default_auth() -> String {
    "any".into()
}

fn default_export() -> String {
    "allow".into()
}

schema! {
    /// Team policies (`GET/PUT /teams/{id}/policies`). Server-enforced unless
    /// noted; the strictest value across a user's teams applies to them.
    pub struct TeamPolicies {
        /// `off` | `any` (TOTP, email or passkey) | `passkey` (WebAuthn only).
        pub mfa: String,
        /// `allow` | `deny` — forbid device-only SSH keys in this team's
        /// vaults. Client-enforced: the server never sees keys.
        pub local_keys: String,
        /// Sessions of members expire after this many hours (1..=2160).
        pub session_ttl_hours: Option<i32>,
        /// Members with an email in `sso_domains` cannot sign in with a
        /// password (owner excepted).
        pub sso_only: bool,
        /// Provider id members are sent to when `sso_only` applies.
        pub sso_provider: Option<String>,
        /// Allow-list of email domains for invitations and SSO-only.
        pub sso_domains: Vec<String>,
        /// New devices of members always need email approval.
        pub device_approval: bool,
        /// Audit log retention in days (30..=3650; the server may cap it).
        #[serde(default = "default_audit_retention_days")]
        pub audit_retention_days: i32,
        /// `optional` (vault managers decide per vault) or `required`
        /// (every team vault records, authors cannot delete recordings).
        #[serde(default = "default_session_recording")]
        pub session_recording: String,
        /// Days to keep unpinned team recordings; 0 = forever.
        #[serde(default)]
        pub log_retention_days: i32,
        /// Rotate SSH keys/certificates older than this many days; 0 = off.
        #[serde(default)]
        pub key_max_age_days: i32,
        /// Rotate identity/host passwords older than this many days; 0 = off.
        #[serde(default)]
        pub password_max_age_days: i32,
        /// Networks members may sign in from (CIDRs); empty = anywhere.
        #[serde(default)]
        pub ip_allowlist: Vec<String>,
        /// New devices of members must be approved by a team admin
        /// (`devices.approve`) before they can sign in.
        #[serde(default)]
        pub device_admin_approval: bool,
        /// `any` or `keys_only`: whether hosts in team vaults may be opened
        /// with a password or keyboard-interactive authentication.
        #[serde(default = "default_auth")]
        pub auth: String,
        /// Hosts in team vaults must be reached through a jump host.
        #[serde(default)]
        pub jump_host_required: bool,
        /// `allow` or `deny`: local export/backup of team vault data.
        #[serde(default = "default_export")]
        pub export: String,
        /// Remote ports (`22`, `8000-8999`) members may forward from team
        /// hosts; empty means any port.
        #[serde(default)]
        pub forward_ports: Vec<String>,
        /// Members may sign in only from devices whose disk is encrypted.
        #[serde(default)]
        pub posture_disk_encryption: bool,
        /// Members may sign in only from devices with a screen lock.
        #[serde(default)]
        pub posture_screen_lock: bool,
        /// Members may sign in only from devices whose key is in hardware (TPM / Secure Enclave / StrongBox).
        #[serde(default)]
        pub posture_secure_key: bool,
        /// Last change.
        pub updated_at: DateTime<Utc>,
    }
}

fn default_session_recording() -> String {
    "optional".into()
}

schema! {
    /// `PUT /teams/{id}/policies` — only the given fields change.
    pub struct UpdateTeamPoliciesRequest {
        /// See [`TeamPolicies::mfa`].
        #[serde(default)]
        pub mfa: Option<String>,
        /// See [`TeamPolicies::local_keys`].
        #[serde(default)]
        pub local_keys: Option<String>,
        /// Hours (1..=2160); `0` clears the limit.
        #[serde(default)]
        pub session_ttl_hours: Option<i32>,
        /// See [`TeamPolicies::sso_only`].
        #[serde(default)]
        pub sso_only: Option<bool>,
        /// Provider id; an empty string clears it.
        #[serde(default)]
        pub sso_provider: Option<String>,
        /// See [`TeamPolicies::sso_domains`].
        #[serde(default)]
        pub sso_domains: Option<Vec<String>>,
        /// See [`TeamPolicies::device_approval`].
        #[serde(default)]
        pub device_approval: Option<bool>,
        /// See [`TeamPolicies::audit_retention_days`].
        #[serde(default)]
        pub audit_retention_days: Option<i32>,
        /// See [`TeamPolicies::session_recording`].
        #[serde(default)]
        pub session_recording: Option<String>,
        /// See [`TeamPolicies::log_retention_days`].
        #[serde(default)]
        pub log_retention_days: Option<i32>,
        /// See [`TeamPolicies::key_max_age_days`].
        #[serde(default)]
        pub key_max_age_days: Option<i32>,
        /// See [`TeamPolicies::password_max_age_days`].
        #[serde(default)]
        pub password_max_age_days: Option<i32>,
        /// See [`TeamPolicies::ip_allowlist`].
        #[serde(default)]
        pub ip_allowlist: Option<Vec<String>>,
        /// See [`TeamPolicies::device_admin_approval`].
        #[serde(default)]
        pub device_admin_approval: Option<bool>,
        /// `any` or `keys_only`.
        pub auth: Option<String>,
        /// Hosts in team vaults must go through a jump host.
        pub jump_host_required: Option<bool>,
        /// `allow` or `deny`.
        pub export: Option<String>,
        /// Port allowlist (`22`, `8000-8999`); empty = any.
        pub forward_ports: Option<Vec<String>>,
        /// Require disk encryption on members' devices.
        #[serde(default)]
        pub posture_disk_encryption: Option<bool>,
        /// Require a screen lock on members' devices.
        #[serde(default)]
        pub posture_screen_lock: Option<bool>,
        /// Require a hardware-backed device key.
        #[serde(default)]
        pub posture_secure_key: Option<bool>,
    }
}

schema! {
    /// A member's device as seen by team admins.
    pub struct TeamDevice {
        /// Device id.
        pub device_id: Uuid,
        /// Owner.
        pub user_id: Uuid,
        /// Owner's e-mail.
        pub user_email: String,
        /// Device name chosen by the client.
        pub name: String,
        /// Platform.
        pub platform: String,
        /// App version at last sign-in.
        pub app_version: Option<String>,
        /// Last activity.
        pub last_seen_at: DateTime<Utc>,
        /// Last client address.
        pub last_ip: Option<String>,
        /// `pending`, `approved` or `rejected`.
        pub status: String,
        /// Admin who decided.
        pub decided_by: Option<Uuid>,
        /// When.
        pub decided_at: Option<DateTime<Utc>>,
        /// First sign-in attempt from this device.
        pub requested_at: DateTime<Utc>,
    }
}

schema! {
    /// `GET /teams/{id}/devices`.
    pub struct TeamDeviceList {
        /// Whether the policy currently requires admin approval.
        pub admin_approval: bool,
        /// Devices, pending first.
        pub devices: Vec<TeamDevice>,
    }
}

schema! {
    /// A secret past the team's max age.
    pub struct RotationDue {
        /// Entity the secret lives in.
        pub entity_id: Uuid,
        /// Team vault holding the entity.
        pub vault_id: Uuid,
        /// Entity kind (`ssh_key`, `ssh_certificate`, `identity`, `host`).
        pub kind: String,
        /// Last rotation the owning client reported; `None` = never.
        pub secret_rotated_at: Option<DateTime<Utc>>,
        /// Days since the last rotation (or since creation).
        pub age_days: i32,
        /// Open rotation job for this entity, if any.
        pub job_id: Option<Uuid>,
    }
}

schema! {
    /// A queued rotation; executed by a client with write access to the vault.
    pub struct RotationJob {
        /// Job id.
        pub id: Uuid,
        /// Owning team.
        pub team_id: Uuid,
        /// Team vault holding the entity.
        pub vault_id: Uuid,
        /// Entity the secret lives in.
        pub entity_id: Uuid,
        /// Entity kind (`ssh_key`, `ssh_certificate`, `identity`, `host`).
        pub entity_kind: String,
        /// `pending`, `running`, `done`, `failed` or `cancelled`.
        pub status: String,
        /// Free-form note from the requester.
        pub note: String,
        /// Failure reason reported by the executing client.
        pub error: Option<String>,
        /// Who queued the job.
        pub requested_by: Uuid,
        /// E-mail of the requester.
        pub requested_by_email: String,
        /// Member whose client is executing (or executed) the job.
        pub claimed_by: Option<Uuid>,
        /// Queued at.
        pub created_at: DateTime<Utc>,
        /// Last status change.
        pub updated_at: DateTime<Utc>,
        /// When the job reached a final state.
        pub finished_at: Option<DateTime<Utc>>,
    }
}

schema! {
    /// `GET /teams/{id}/rotation`: policy, overdue secrets and recent jobs.
    pub struct RotationOverview {
        /// Current key max-age policy (0 = off).
        pub key_max_age_days: i32,
        /// Current password max-age policy (0 = off).
        pub password_max_age_days: i32,
        /// Secrets past their max age.
        pub due: Vec<RotationDue>,
        /// Jobs, newest first.
        pub jobs: Vec<RotationJob>,
    }
}

schema! {
    /// A list of rotation jobs.
    pub struct RotationJobList {
        /// Jobs, newest first.
        pub jobs: Vec<RotationJob>,
    }
}

schema! {
    /// Queue rotation jobs for entities of one team vault.
    pub struct CreateRotationJobsRequest {
        /// Team vault holding the entity.
        pub vault_id: Uuid,
        /// Entities of `vault_id` to rotate (1..=1000).
        pub entity_ids: Vec<Uuid>,
        /// Free-form note shown to whoever executes the jobs.
        #[serde(default)]
        pub note: String,
    }
}

schema! {
    /// A just-in-time request for temporary access to a team vault.
    pub struct AccessRequest {
        /// Request id.
        pub id: Uuid,
        /// Owning team.
        pub team_id: Uuid,
        /// Vault the access is for.
        pub vault_id: Uuid,
        /// Vault name at the time of reading.
        pub vault_name: String,
        /// Requester.
        pub user_id: Uuid,
        /// Requester's e-mail.
        pub user_email: String,
        /// `viewer` or `editor`.
        pub role: String,
        /// Requested (or granted) window in hours.
        pub hours: i32,
        /// Why access is needed.
        pub reason: String,
        /// `pending`, `approved`, `denied`, `cancelled`, `revoked` or `expired`.
        pub status: String,
        /// Approver / denier.
        pub decided_by: Option<Uuid>,
        /// When the decision was made.
        pub decided_at: Option<DateTime<Utc>>,
        /// Approver's note.
        pub decision_note: Option<String>,
        /// When the granted access ends.
        pub expires_at: Option<DateTime<Utc>>,
        /// Requested at.
        pub created_at: DateTime<Utc>,
    }
}

schema! {
    /// `GET /teams/{id}/access-requests`.
    pub struct AccessRequestList {
        /// Whether the caller may approve/deny/revoke.
        pub can_approve: bool,
        /// Requests, pending first.
        pub requests: Vec<AccessRequest>,
    }
}

schema! {
    /// Ask for temporary access.
    pub struct CreateAccessRequest {
        /// Team vault.
        pub vault_id: Uuid,
        /// `viewer` (default) or `editor`.
        #[serde(default = "default_viewer")]
        pub role: String,
        /// Window in hours (1..=720, default 8).
        #[serde(default = "default_hours")]
        pub hours: i32,
        /// Why access is needed.
        #[serde(default)]
        pub reason: String,
    }
}

fn default_viewer() -> String {
    "viewer".into()
}

fn default_hours() -> i32 {
    8
}

schema! {
    /// Approve (optionally trimming the grant) or deny a request.
    pub struct DecideAccessRequest {
        /// Override the granted hours.
        #[serde(default)]
        pub hours: Option<i32>,
        /// Override the granted role.
        #[serde(default)]
        pub role: Option<String>,
        /// Note for the requester.
        #[serde(default)]
        pub note: Option<String>,
    }
}

schema! {
    /// `GET /teams/{id}/data`: residency and pending deletion.
    pub struct TeamDataStatus {
        /// Region the team's data was created in (server-defined label).
        pub region: Option<String>,
        /// Region label of the server answering.
        pub server_region: Option<String>,
        /// Team creation time.
        pub created_at: DateTime<Utc>,
        /// When the team will be purged, if deletion is scheduled.
        pub deletion_scheduled_at: Option<DateTime<Utc>>,
        /// Owner who scheduled it.
        pub deletion_requested_by: Option<Uuid>,
        /// Grace period of this server in days (0 = immediate).
        pub deletion_grace_days: i32,
    }
}

schema! {
    /// Schedule team deletion; the name must match to confirm.
    pub struct ScheduleTeamDeletionRequest {
        /// Exact team name.
        pub confirm_name: String,
    }
}

schema! {
    /// Advance a rotation job.
    pub struct UpdateRotationJobRequest {
        /// `running`, `done`, `failed` or `cancelled`.
        pub status: String,
        /// Failure reason (for `failed`).
        #[serde(default)]
        pub error: Option<String>,
    }
}

schema! {
    /// What applies to the calling user across all their teams (strictest wins).
    pub struct EffectivePolicies {
        /// `off` | `any` | `passkey`.
        pub mfa: String,
        /// Team that requires it.
        pub mfa_team_id: Option<Uuid>,
        /// Whether the user currently satisfies `mfa`.
        pub mfa_satisfied: bool,
        /// Shortest session TTL in hours, if any team sets one.
        pub session_ttl_hours: Option<i32>,
        /// Teams forbidding device-only keys.
        pub local_keys_denied_by: Vec<Uuid>,
        /// Teams forcing device approval.
        pub device_approval_by: Vec<Uuid>,
        /// Provider the user must sign in through, if a team requires SSO for them.
        pub sso_provider: Option<String>,
        /// Teams whose policy makes session recording mandatory: clients
        /// record every session on hosts of those teams' vaults.
        #[serde(default)]
        pub recording_required_by: Vec<Uuid>,
    }
}

schema! {
    /// `GET /teams/{id}/policies`
    pub struct TeamPoliciesResponse {
        /// The team's policies.
        pub policies: TeamPolicies,
        /// What applies to the caller across all their teams.
        pub effective_for_me: EffectivePolicies,
    }
}

fn default_audit_retention_days() -> i32 {
    365
}

// ───────────────────────────── audit webhooks ─────────────────────────────

/// Delivery formats for audit webhooks.
pub const WEBHOOK_KINDS: &[&str] = &["generic", "splunk_hec", "elastic", "datadog", "syslog_tls"];

schema! {
    /// An audit webhook (`/teams/{id}/webhooks`). The secret is write-only.
    pub struct Webhook {
        /// Id.
        pub id: Uuid,
        /// Destination.
        pub url: String,
        /// `generic` (HMAC-signed JSON) | `splunk_hec` | `elastic` | `datadog`.
        pub kind: String,
        /// Actions to send (`vault.` = family); `None` = everything.
        pub actions: Option<Vec<String>>,
        /// Disabled hooks keep their history but receive nothing.
        pub enabled: bool,
        /// Created.
        pub created_at: DateTime<Utc>,
        /// HTTP status of the last attempt.
        pub last_status: Option<i32>,
        /// Error of the last failed attempt.
        pub last_error: Option<String>,
        /// Last successful delivery.
        pub last_delivered_at: Option<DateTime<Utc>>,
        /// Consecutive failures (50 disables the hook).
        pub failures: i32,
    }
}

schema! {
    /// `GET /teams/{id}/webhooks`
    pub struct WebhookList {
        /// Hooks.
        pub webhooks: Vec<Webhook>,
    }
}

schema! {
    /// `POST /teams/{id}/webhooks`
    pub struct CreateWebhookRequest {
        /// `https://` URL (plain http / private addresses only when the server allows it).
        pub url: String,
        /// HMAC secret (`generic`) or the destination's token (`splunk_hec`, `elastic`, `datadog`).
        pub secret: String,
        /// See [`Webhook::kind`]; default `generic`.
        #[serde(default)]
        pub kind: Option<String>,
        /// See [`Webhook::actions`].
        #[serde(default)]
        pub actions: Option<Vec<String>>,
    }
}

schema! {
    /// `PATCH /teams/{id}/webhooks/{wid}` — only given fields change.
    pub struct UpdateWebhookRequest {
        /// New URL.
        #[serde(default)]
        pub url: Option<String>,
        /// New secret / token.
        #[serde(default)]
        pub secret: Option<String>,
        /// New kind.
        #[serde(default)]
        pub kind: Option<String>,
        /// New action filter (`Some(vec![])` = everything).
        #[serde(default)]
        pub actions: Option<Vec<String>>,
        /// Enable / disable (re-enabling resets the failure counter).
        #[serde(default)]
        pub enabled: Option<bool>,
    }
}

schema! {
    /// One delivery attempt record.
    pub struct WebhookDelivery {
        /// Id.
        pub id: i64,
        /// Audit event.
        pub event_id: i64,
        /// Event action.
        pub action: String,
        /// Attempts made so far.
        pub attempt: i32,
        /// `pending` | `sending` | `ok` | `dead`.
        pub status: String,
        /// HTTP status of the last attempt.
        pub response_status: Option<i32>,
        /// First KiB of the last response body.
        pub response_body: Option<String>,
        /// Next attempt (for pending).
        pub next_at: DateTime<Utc>,
        /// When it succeeded.
        pub delivered_at: Option<DateTime<Utc>>,
    }
}

schema! {
    /// `GET /teams/{id}/webhooks/{wid}/deliveries`
    pub struct WebhookDeliveryList {
        /// Newest first, at most 100.
        pub deliveries: Vec<WebhookDelivery>,
    }
}

// ───────────────────────────── SCIM ─────────────────────────────

schema! {
    /// A SCIM bearer token of a team (`/teams/{id}/scim/tokens`); the secret
    /// is shown once at creation.
    pub struct ScimToken {
        /// Id.
        pub id: Uuid,
        /// Label (e.g. "Okta").
        pub name: String,
        /// Created.
        pub created_at: DateTime<Utc>,
        /// Expiry, if any.
        pub expires_at: Option<DateTime<Utc>>,
        /// Last request with this token.
        pub last_used_at: Option<DateTime<Utc>>,
    }
}

schema! {
    /// `GET /teams/{id}/scim/tokens`
    pub struct ScimTokenList {
        /// Active tokens (at most 3).
        pub tokens: Vec<ScimToken>,
        /// SCIM base URL to paste into the IdP.
        pub base_url: String,
    }
}

schema! {
    /// `POST /teams/{id}/scim/tokens`
    pub struct CreateScimTokenRequest {
        /// Label.
        pub name: String,
        /// Days until expiry (omit = never).
        #[serde(default)]
        pub expires_in_days: Option<u32>,
    }
}

schema! {
    /// Response of token creation.
    pub struct CreatedScimToken {
        /// The token record.
        pub token: ScimToken,
        /// Bearer secret — shown once.
        pub secret: String,
        /// SCIM base URL.
        pub base_url: String,
    }
}

schema! {
    /// A SCIM group as seen by the team (`GET /teams/{id}/scim/groups`).
    pub struct ScimGroupInfo {
        /// Id.
        pub id: Uuid,
        /// IdP display name (matches `team_role_mappings.group_name`).
        pub display_name: String,
        /// IdP id.
        pub external_id: Option<String>,
        /// Members.
        pub member_count: i64,
        /// Vault grants.
        pub vaults: Vec<ScimGroupVault>,
    }
}

schema! {
    /// Vault granted to every member of a SCIM group.
    pub struct ScimGroupVault {
        /// Vault.
        pub vault_id: Uuid,
        /// `viewer` | `editor` | `manager`.
        pub role: String,
    }
}

schema! {
    /// `GET /teams/{id}/scim/groups`
    pub struct ScimGroupList {
        /// Groups.
        pub groups: Vec<ScimGroupInfo>,
    }
}

schema! {
    /// `PUT /teams/{id}/scim/groups/{gid}/vaults`
    pub struct SetScimGroupVaultsRequest {
        /// Full replacement list.
        pub vaults: Vec<ScimGroupVault>,
    }
}

schema! {
    /// A team's own identity provider (`GET /teams/{id}/idp`). The client
    /// secret is never returned.
    pub struct TeamIdp {
        /// `oidc` | `saml`.
        pub kind: String,
        /// Button label shown at sign-in.
        pub name: String,
        /// OIDC issuer URL (discovery).
        #[serde(default)]
        pub issuer: Option<String>,
        /// OIDC client id.
        #[serde(default)]
        pub client_id: Option<String>,
        /// Whether a client secret is stored.
        pub has_client_secret: bool,
        /// Extra OIDC scopes (space separated).
        #[serde(default)]
        pub scopes: Option<String>,
        /// SAML IdP metadata: `https://` URL or inline XML.
        #[serde(default)]
        pub saml_metadata: Option<String>,
        /// IdP `entityID` inside aggregate metadata.
        #[serde(default)]
        pub saml_idp_entity_id: Option<String>,
        /// Email domains routed to this IdP at sign-in.
        pub domains: Vec<String>,
        /// Whether sign-in through this IdP is on.
        pub enabled: bool,
        /// A verified sign-in may create the account and join the team.
        pub jit_join: bool,
        /// Provider id to use with `/auth/sso/{provider}/start`.
        pub provider_id: String,
        /// SP metadata URL (SAML) / redirect URI (OIDC) to register at the IdP.
        pub callback_url: String,
        /// Updated at.
        pub updated_at: DateTime<Utc>,
    }
}

schema! {
    /// `PUT /teams/{id}/idp`. Absent fields keep their value; a new
    /// `client_secret` replaces the stored one.
    pub struct UpdateTeamIdpRequest {
        /// `oidc` | `saml`.
        #[serde(default)]
        pub kind: Option<String>,
        /// Button label.
        #[serde(default)]
        pub name: Option<String>,
        /// OIDC issuer URL.
        #[serde(default)]
        pub issuer: Option<String>,
        /// OIDC client id.
        #[serde(default)]
        pub client_id: Option<String>,
        /// OIDC client secret (write-only).
        #[serde(default)]
        pub client_secret: Option<String>,
        /// Extra OIDC scopes.
        #[serde(default)]
        pub scopes: Option<String>,
        /// SAML IdP metadata (URL or XML).
        #[serde(default)]
        pub saml_metadata: Option<String>,
        /// IdP `entityID` inside aggregate metadata.
        #[serde(default)]
        pub saml_idp_entity_id: Option<String>,
        /// Email domains routed to this IdP.
        #[serde(default)]
        pub domains: Option<Vec<String>>,
        /// Whether sign-in through this IdP is on.
        #[serde(default)]
        pub enabled: Option<bool>,
        /// Verified sign-ins may join the team.
        #[serde(default)]
        pub jit_join: Option<bool>,
    }
}

schema! {
    /// `GET`/`PUT /teams/{id}/idp`.
    pub struct TeamIdpResponse {
        /// `None` when the team has no IdP configured.
        #[serde(default)]
        pub idp: Option<TeamIdp>,
        /// Whether this server allows per-team IdPs (`TERMOSO_TEAM_IDP`).
        pub available: bool,
    }
}

schema! {
    /// One access rule on a group or host of a team vault.
    pub struct EntityAclRule {
        /// Rule id.
        pub id: Uuid,
        /// Team vault the entity lives in.
        pub vault_id: Uuid,
        /// Group or host entity id (client-encrypted entity).
        pub entity_id: Uuid,
        /// `group` | `host`.
        pub entity_kind: String,
        /// `role` | `member` | `group` (IdP/SCIM group name).
        pub principal_kind: String,
        /// Team role (principal_kind = role).
        #[serde(default)]
        pub role_id: Option<Uuid>,
        /// Team member (principal_kind = member).
        #[serde(default)]
        pub user_id: Option<Uuid>,
        /// IdP/SCIM group display name (principal_kind = group).
        #[serde(default)]
        pub group_name: Option<String>,
        /// Human-readable principal (role name / member e-mail / group).
        pub principal_name: String,
        /// `none` (hidden) | `connect` (no secrets) | `read` | `edit`.
        pub mode: String,
        /// Last change.
        pub updated_at: DateTime<Utc>,
    }
}

schema! {
    /// `PUT /teams/{id}/vaults/{vault_id}/acl` — create or replace a rule for
    /// (entity, principal).
    pub struct UpsertEntityAclRequest {
        /// Group or host entity id.
        pub entity_id: Uuid,
        /// `group` | `host`.
        pub entity_kind: String,
        /// `role` | `member` | `group`.
        pub principal_kind: String,
        /// Team role id.
        #[serde(default)]
        pub role_id: Option<Uuid>,
        /// Team member id.
        #[serde(default)]
        pub user_id: Option<Uuid>,
        /// IdP/SCIM group name.
        #[serde(default)]
        pub group_name: Option<String>,
        /// `none` | `connect` | `read` | `edit`.
        pub mode: String,
    }
}

schema! {
    /// Rules of one team vault.
    pub struct EntityAclResponse {
        /// All rules, most recent last.
        pub rules: Vec<EntityAclRule>,
    }
}

schema! {
    /// A rule resolved for the caller (`GET /acl/me`). Clients apply group →
    /// host inheritance; a host rule beats the nearest group rule. Entities
    /// without a rule keep vault-level access.
    pub struct MyAclRule {
        /// Team vault.
        pub vault_id: Uuid,
        /// Group or host entity id.
        pub entity_id: Uuid,
        /// `group` | `host`.
        pub entity_kind: String,
        /// `none` | `connect` | `read` | `edit`.
        pub mode: String,
    }
}

schema! {
    /// `GET /acl/me`.
    pub struct MyAclResponse {
        /// Rules that apply to the caller across all team vaults.
        pub rules: Vec<MyAclRule>,
    }
}
