//! Administration API (server operators).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::schema;

schema! {
    /// `GET /admin/stats`
    pub struct AdminStats {
        /// Registered users.
        pub users: i64,
        /// Users active in the last 30 days.
        pub active_users_30d: i64,
        /// Teams.
        pub teams: i64,
        /// Vaults.
        pub vaults: i64,
        /// Live entities (non-deleted).
        pub entities: i64,
        /// Devices with a valid session.
        pub active_sessions: i64,
        /// Session logs stored (bytes).
        pub log_storage_bytes: i64,
    }
}

schema! {
    /// User as seen by an administrator (no secrets, no content).
    pub struct AdminUser {
        /// Id.
        pub id: Uuid,
        /// Email.
        pub email: String,
        /// Verified.
        pub email_verified: bool,
        /// Display name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        /// Profile picture tag (see `UserProfile::avatar`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub avatar: Option<String>,
        /// Admin.
        pub is_admin: bool,
        /// Owner (see `UserProfile::is_owner`).
        #[serde(default)]
        pub is_owner: bool,
        /// Disabled.
        pub disabled: bool,
        /// MFA on.
        pub mfa_enabled: bool,
        /// Created.
        pub created_at: DateTime<Utc>,
        /// Last activity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_seen_at: Option<DateTime<Utc>>,
        /// Device count.
        pub devices: i64,
        /// Teams the user belongs to.
        #[serde(default)]
        pub teams: Vec<AdminUserTeam>,
        /// How the account came to be: `password`, `sso` or `scim`.
        #[serde(default)]
        pub source: String,
    }
}

schema! {
    /// Team membership shown in the admin user list.
    pub struct AdminUserTeam {
        /// Team id.
        pub id: Uuid,
        /// Team name.
        pub name: String,
        /// Role slug in that team.
        pub role: String,
    }
}

schema! {
    /// Paginated user list.
    pub struct AdminUserList {
        /// Users.
        pub users: Vec<AdminUser>,
        /// Total matching.
        pub total: i64,
    }
}

schema! {
    /// `PATCH /admin/users/{id}`
    pub struct AdminUpdateUserRequest {
        /// Disable / enable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub disabled: Option<bool>,
        /// Grant / revoke admin.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub is_admin: Option<bool>,
        /// Force email verified.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub email_verified: Option<bool>,
    }
}

schema! {
    /// Runtime-editable server settings (`GET`/`PUT /admin/settings`).
    pub struct ServerSettings {
        /// Allow new sign-ups.
        pub registration_open: bool,
        /// Only emails in `allowed_domains` may register (empty = any).
        #[serde(default)]
        pub allowed_domains: Vec<String>,
        /// Users verified by a configured SSO provider may sign up even while
        /// `registration_open` is off (domain filter still applies).
        #[serde(default)]
        pub sso_registration: bool,
        /// Require verified email before syncing.
        pub require_email_verification: bool,
        /// Require approval code when logging in from a new device.
        pub new_device_email_approval: bool,
        /// Regular users may create teams.
        pub users_can_create_teams: bool,
        /// Session lifetime in days.
        pub session_ttl_days: u32,
        /// Maximum entity payload size in bytes.
        pub max_entity_bytes: u32,
        /// Maximum session log size in bytes.
        pub max_log_bytes: u64,
        /// Per-user total log storage quota in bytes (0 = unlimited).
        pub log_quota_bytes: u64,
        /// Keep team activity-log entries this many days (0 = forever).
        #[serde(default = "default_audit_retention_days")]
        pub audit_retention_days: u32,
        /// Corporate mode: every account on this server joins this team
        /// automatically (default role of the team).
        #[serde(default)]
        pub home_team_id: Option<Uuid>,
        /// Corporate mode: password sign-in and e-mail sign-up are off;
        /// only SSO (server providers or the home team's IdP).
        #[serde(default)]
        pub sso_only: bool,
        /// Show personal vaults in clients. `false` = team vaults only
        /// (the personal vault still exists, it is just hidden).
        #[serde(default = "default_true")]
        pub personal_vaults: bool,
    }
}

fn default_true() -> bool {
    true
}

fn default_audit_retention_days() -> u32 {
    365
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            registration_open: true,
            allowed_domains: Vec::new(),
            sso_registration: false,
            require_email_verification: false,
            new_device_email_approval: true,
            users_can_create_teams: true,
            session_ttl_days: 90,
            max_entity_bytes: 256 * 1024,
            max_log_bytes: 512 * 1024 * 1024,
            log_quota_bytes: 0,
            audit_retention_days: default_audit_retention_days(),
            home_team_id: None,
            sso_only: false,
            personal_vaults: true,
        }
    }
}

schema! {
    /// `POST /admin/email/test`
    pub struct TestEmailRequest {
        /// Recipient.
        pub to: String,
    }
}

schema! {
    /// Team as seen by an administrator.
    pub struct AdminTeam {
        /// Id.
        pub id: Uuid,
        /// Name.
        pub name: String,
        /// Owner email.
        pub owner_email: String,
        /// Members.
        pub member_count: i64,
        /// Vaults.
        pub vault_count: i64,
        /// Created.
        pub created_at: DateTime<Utc>,
        /// Data-residency label stamped at creation.
        #[serde(default)]
        pub region: Option<String>,
        /// Pending GDPR deletion.
        #[serde(default)]
        pub deletion_scheduled_at: Option<DateTime<Utc>>,
        /// Bytes of session recordings stored for the team.
        #[serde(default)]
        pub log_bytes: i64,
        /// This is the server's home team (corporate mode).
        #[serde(default)]
        pub is_home: bool,
        /// A team IdP is configured and enabled.
        #[serde(default)]
        pub idp: bool,
        /// SCIM provisioning has a live token.
        #[serde(default)]
        pub scim: bool,
        /// Enabled webhooks.
        #[serde(default)]
        pub webhooks: i64,
    }
}

schema! {
    /// Member row in the admin team card.
    pub struct AdminTeamMember {
        /// User id.
        pub user_id: Uuid,
        /// E-mail.
        pub email: String,
        /// Coarse level (`owner`, `admin`, `member`).
        pub level: String,
        /// Role slug.
        pub role: String,
        /// How the role was assigned (`manual`, `idp`, `scim`, `server`, `admin`).
        pub role_source: String,
        /// Joined.
        pub joined_at: DateTime<Utc>,
        /// Last activity of the account.
        pub last_seen_at: Option<DateTime<Utc>>,
    }
}

schema! {
    /// `GET /admin/teams/{id}`
    pub struct AdminTeamDetail {
        /// Summary row.
        pub team: AdminTeam,
        /// Members.
        pub members: Vec<AdminTeamMember>,
        /// Team policies.
        pub policies: crate::team::TeamPolicies,
        /// Last 50 audit events (same shape as the team audit log).
        pub audit: serde_json::Value,
    }
}

schema! {
    /// `POST /admin/teams/{id}/members`
    pub struct AdminAddMemberRequest {
        /// Account to add.
        pub user_id: Uuid,
        /// Role slug; the team's default role when omitted.
        #[serde(default)]
        pub role: Option<String>,
    }
}

schema! {
    /// Background job as seen in the admin console.
    pub struct AdminJob {
        /// Job name.
        pub name: String,
        /// Last start.
        pub last_started_at: DateTime<Utc>,
        /// Last finish (`None` while running or after a crash).
        pub last_finished_at: Option<DateTime<Utc>>,
        /// Rows handled by the last pass.
        pub last_result: Option<i64>,
        /// Error of the last pass.
        pub last_error: Option<String>,
    }
}

schema! {
    /// `GET /admin/jobs`
    pub struct AdminJobList {
        /// Jobs.
        pub jobs: Vec<AdminJob>,
    }
}

schema! {
    /// `GET /admin/teams`
    pub struct AdminTeamList {
        /// Teams.
        pub teams: Vec<AdminTeam>,
        /// Total.
        pub total: i64,
    }
}

schema! {
    /// `GET /admin/config` — the configuration this server is actually running
    /// with (environment + defaults), secrets masked, plus a live health probe
    /// of every backing service.
    pub struct AdminConfig {
        /// Process, URLs and feature switches.
        pub server: AdminConfigServer,
        /// PostgreSQL.
        pub database: AdminConfigService,
        /// Redis.
        pub redis: AdminConfigService,
        /// S3-compatible storage for session logs (`None` = not configured).
        pub storage: Option<AdminConfigStorage>,
        /// Outgoing e-mail (`None` = not configured).
        pub smtp: Option<AdminConfigSmtp>,
        /// Server-wide SSO providers.
        pub sso: Vec<AdminConfigSso>,
        /// WebAuthn / passkeys (`None` = off).
        pub webauthn: Option<AdminConfigWebauthn>,
        /// AI assistant backend (`None` = off).
        pub ai: Option<AdminConfigAi>,
        /// Defaults, bounds and provenance of the editable settings.
        pub settings: AdminSettingsMeta,
    }
}

schema! {
    /// Process-level configuration.
    pub struct AdminConfigServer {
        /// Server version.
        pub version: String,
        /// Process start time.
        pub started_at: DateTime<Utc>,
        /// Seconds since start.
        pub uptime_secs: u64,
        /// Display name (`TERMOSO_SERVER_NAME`).
        pub name: String,
        /// API base URL as seen by clients (`TERMOSO_PUBLIC_URL`).
        pub public_url: String,
        /// Cabinet URL (`TERMOSO_WEB_URL`).
        pub web_url: String,
        /// Listen address (`TERMOSO_BIND`).
        pub bind: String,
        /// Client IPs taken from `X-Forwarded-For` (`TERMOSO_TRUST_PROXY`).
        pub trust_proxy: bool,
        /// Extra CORS origins.
        pub cors_origins: Vec<String>,
        /// Log filter (`TERMOSO_LOG`).
        pub log: String,
        /// `text` | `json`.
        pub log_format: String,
        /// Advertised data region.
        pub data_region: Option<String>,
        /// Oldest client allowed to sign in.
        pub min_client_version: String,
        /// `true` when `TERMOSO_MIN_CLIENT_VERSION` overrides the default (= server version).
        pub min_client_version_overridden: bool,
        /// Delay before a start-over (account reset) completes.
        pub start_over_delay_secs: u64,
        /// Days a deleted team can still be restored.
        pub team_deletion_grace_days: u32,
        /// Upper bound teams may set for their audit-log retention.
        pub team_audit_retention_days_max: u32,
        /// Audit events are also written to the process log.
        pub audit_sink: bool,
        /// Swagger UI served at `/api/docs`.
        pub swagger_ui: bool,
        /// API bridges may be created.
        pub bridges: bool,
        /// Teams may configure their own IdP.
        pub team_idp: bool,
        /// Landing page served by this process.
        pub landing: bool,
        /// Docs served by this process.
        pub docs: bool,
        /// Prometheus listen address when metrics are on.
        pub metrics_bind: Option<String>,
        /// Webhooks may target private/internal addresses.
        pub webhooks_allow_private: bool,
        /// A custom CA is configured for syslog-TLS webhooks.
        pub webhooks_syslog_ca: bool,
        /// Cloudflare Turnstile protects sign-up.
        pub turnstile: bool,
        /// Bootstrap administrators (`TERMOSO_ADMIN_EMAILS`).
        pub admin_emails: Vec<String>,
        /// Fixed owner (`TERMOSO_OWNER_EMAIL`); `None` = first registered account.
        pub owner_email: Option<String>,
    }
}

schema! {
    /// A backing service and the result of a live probe.
    pub struct AdminConfigService {
        /// Endpoint with credentials removed.
        pub endpoint: String,
        /// Extra detail (pool size, key prefix…).
        pub detail: Option<String>,
        /// `ok` | `error`.
        pub status: String,
        /// Probe round-trip in milliseconds.
        pub latency_ms: Option<u64>,
        /// Probe error.
        pub error: Option<String>,
    }
}

schema! {
    /// S3-compatible storage.
    pub struct AdminConfigStorage {
        /// Bucket.
        pub bucket: String,
        /// Region.
        pub region: Option<String>,
        /// Custom endpoint.
        pub endpoint: Option<String>,
        /// Endpoint clients use for presigned URLs.
        pub public_endpoint: Option<String>,
        /// Path-style addressing.
        pub force_path_style: bool,
        /// Presigned URL lifetime.
        pub presign_secs: u64,
        /// `ok` | `error`.
        pub status: String,
        /// Probe round-trip in milliseconds.
        pub latency_ms: Option<u64>,
        /// Probe error.
        pub error: Option<String>,
    }
}

schema! {
    /// Outgoing e-mail.
    pub struct AdminConfigSmtp {
        /// Host.
        pub host: String,
        /// Port.
        pub port: u16,
        /// `starttls` | `tls` | `none`.
        pub security: String,
        /// From address.
        pub from: String,
        /// Authenticates with a username/password.
        pub auth: bool,
    }
}

schema! {
    /// Server-wide SSO provider.
    pub struct AdminConfigSso {
        /// Slug.
        pub id: String,
        /// Display name.
        pub name: String,
        /// `oidc` | `saml`.
        pub kind: String,
        /// OIDC issuer / SAML IdP entity id.
        pub issuer: Option<String>,
        /// E-mail domains accepted from this provider (empty = any).
        pub allowed_domains: Vec<String>,
    }
}

schema! {
    /// WebAuthn relying party.
    pub struct AdminConfigWebauthn {
        /// RP id.
        pub rp_id: String,
        /// RP display name.
        pub rp_name: String,
        /// Allowed origins.
        pub origins: Vec<String>,
    }
}

schema! {
    /// AI assistant backend.
    pub struct AdminConfigAi {
        /// Provider.
        pub provider: String,
        /// Model.
        pub model: String,
        /// Endpoint host.
        pub endpoint: String,
        /// Prompts are not retained by the provider.
        pub confidential: bool,
        /// Requests per user per day.
        pub daily_quota: u32,
        /// Prompt size limit.
        pub max_prompt_chars: u64,
        /// Request timeout.
        pub timeout_secs: u64,
    }
}

schema! {
    /// Defaults, bounds and provenance of `ServerSettings`.
    pub struct AdminSettingsMeta {
        /// Values a fresh server starts with.
        pub defaults: ServerSettings,
        /// Accepted ranges.
        pub limits: AdminSettingsLimits,
        /// Last change.
        pub updated_at: Option<DateTime<Utc>>,
        /// E-mail of the admin who made the last change.
        pub updated_by: Option<String>,
    }
}

schema! {
    /// Accepted ranges for `ServerSettings`.
    pub struct AdminSettingsLimits {
        /// Minimum session lifetime (days).
        pub session_ttl_days_min: u32,
        /// Maximum session lifetime (days).
        pub session_ttl_days_max: u32,
        /// Minimum record size (bytes).
        pub max_entity_bytes_min: u32,
        /// Maximum record size (bytes).
        pub max_entity_bytes_max: u32,
        /// Minimum session-log size (bytes).
        pub max_log_bytes_min: u64,
        /// Maximum audit retention (days); 0 = forever.
        pub audit_retention_days_max: u32,
    }
}

schema! {
    /// `GET /admin/teams/{id}/members`
    pub struct AdminTeamMemberList {
        /// One page of members.
        pub members: Vec<AdminTeamMember>,
        /// Members matching the filter.
        pub total: i64,
    }
}

schema! {
    /// `GET /admin/teams/{id}/audit`
    pub struct AdminTeamAuditList {
        /// One page of events (same shape as the team audit log).
        pub events: serde_json::Value,
        /// Events in the team.
        pub total: i64,
    }
}
