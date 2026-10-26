/** Wire types mirroring `crates/termoso-proto`. Dates are RFC 3339 strings. */

export type Platform = "windows" | "linux" | "macos" | "android" | "ios" | "web" | "cli";

export interface DeviceInfo {
  name: string;
  platform: Platform;
  app_version: string;
  client_device_id?: string;
}

export interface ApiErrorBody {
  code: string;
  message: string;
  details?: unknown;
}

// ── server ──────────────────────────────────────────────────────────────

export interface ServerFeatures {
  /** `false` hides personal vaults (corporate mode). */
  personal_vaults?: boolean;
  session_logs: boolean;
  email: boolean;
  webauthn: boolean;
  teams: boolean;
  /** API bridges can be created; absent on older servers (always offered). */
  bridges?: boolean;
}

export type SsoKind = "oidc" | "saml";

export interface SsoProvider {
  id: string;
  name: string;
  kind: SsoKind;
}

export interface ServerInfo {
  /** Ceiling for per-team audit retention (days). */
  audit_retention_days_max: number;
  /** Teams may configure their own IdP (`TERMOSO_TEAM_IDP`). */
  team_idp?: boolean;
  /** Corporate mode: password sign-in and e-mail sign-up are refused. */
  sso_only?: boolean;
  /** Data-residency label of this server. */
  region?: string | null;
  /** Corporate mode: every account is a member of this team. */
  home_team?: HomeTeam | null;
  name: string;
  version: string;
  registration_open: boolean;
  /** SSO-verified identities may sign up even while registration is closed. */
  sso_registration: boolean;
  sso_providers: SsoProvider[];
  /** Set when the server requires a Cloudflare Turnstile token (sign-up, start over, recovery, repeated failed logins). */
  turnstile_site_key?: string | null;
  features: ServerFeatures;
  max_entity_bytes: number;
  max_log_bytes: number;
  /** Base under which SSH ID handles are published (`<sshid_url>/<handle>`). */
  sshid_url: string;
  /** Public URL of the web cabinet; where the landing sends people when it has its own origin. */
  web_url: string;
  /** `/` on this origin is the landing page (`false`: it goes to `/login`). */
  landing: boolean;
  /** This origin serves only the landing; the cabinet lives at `web_url`. */
  landing_only: boolean;
  /** Documentation is served (`TERMOSO_DOCS`); absent on older servers. */
  docs?: boolean;
  /** Dedicated docs origin (`TERMOSO_DOCS_URL`), empty when docs live at `/docs` here. */
  docs_url?: string;
}

// ── account ─────────────────────────────────────────────────────────────

export interface UserProfile {
  id: string;
  email: string;
  email_verified: boolean;
  display_name?: string;
  created_at: string;
  is_admin: boolean;
  is_owner: boolean;
  mfa_enabled: boolean;
  /** A destructive "start over" reset is scheduled for this moment (cancellable until then). */
  reset_scheduled_for?: string | null;
  /** Content tag of the profile picture (`GET /users/{id}/avatar`); absent when none. */
  avatar?: string;
}

export interface AccountKeys {
  public_key: string;
  wrapped_private_key: string;
  key_version: number;
}

export interface AccountResponse {
  user: UserProfile;
  keys: AccountKeys;
}

export interface UpdateProfileRequest {
  display_name: string | null;
}

export interface SecurityEvent {
  id: string;
  kind: string;
  device_id?: string;
  ip?: string;
  user_agent?: string;
  details?: unknown;
  created_at: string;
}

export interface SettingsBlob {
  data: string;
  version: number;
  updated_at: string;
}

// ── auth ────────────────────────────────────────────────────────────────

export interface AccountKeysUpload {
  public_key: string;
  wrapped_private_key: string;
  recovery_wrapped_private_key: string;
  recovery_verifier: string;
  personal_vault_sealed_key: string;
}

export interface RegisterFinishRequest {
  email: string;
  opaque_upload: string;
  display_name?: string;
  device: DeviceInfo;
  keys: AccountKeysUpload;
  invite_token?: string;
  sso_session?: string;
}

export interface LoginStartResponse {
  login_id: string;
  opaque_response: string;
}

export type MfaMethod = "totp" | "webauthn" | "backup_code" | "email";

export type MfaCredential =
  | { method: "totp"; code: string }
  | { method: "backup_code"; code: string }
  | { method: "email"; code: string }
  | { method: "webauthn"; credential: unknown };

export interface Session {
  token: string;
  expires_at: string;
  device_id: string;
  user: UserProfile;
  keys: AccountKeys;
}

export type AuthResponse =
  | ({ status: "authenticated" } & Session)
  | { status: "mfa_required"; mfa_token: string; methods: MfaMethod[] }
  | { status: "device_approval_required"; approval_token: string; email_hint: string }
  | { status: "reauthenticated"; reauth_expires_at: string };

export const REAUTH_REQUIRED = "reauth_required";

export type ReauthMethod = "password" | "email" | "none";

export interface ReauthStartResponse {
  reauth_id: string;
  method: ReauthMethod;
  opaque_response?: string | null;
  email_hint?: string | null;
}

export interface StartOverRequestResponse {
  request_token: string;
  email_hint: string;
}

export interface StartOverScheduled {
  scheduled_for: string;
  email_hint: string;
}

export interface StartOverStatus {
  email_hint: string;
  email: string;
  scheduled_for: string;
  ready: boolean;
}

export interface StartOverFinishRequest {
  token: string;
  opaque_upload: string;
  keys: AccountKeysUpload;
  device: DeviceInfo;
}

export interface RecoveryRotate {
  recovery_wrapped_private_key: string;
  recovery_verifier: string;
}

export interface PasswordSetupFinishRequest {
  recovery_token?: string;
  opaque_upload: string;
  wrapped_private_key: string;
  new_recovery?: RecoveryRotate;
  revoke_other_sessions: boolean;
  device?: DeviceInfo;
}

export interface RecoveryStartResponse {
  recovery_token: string;
  recovery_wrapped_private_key: string;
  public_key: string;
}

export interface Device {
  id: string;
  name: string;
  platform: Platform;
  app_version: string;
  created_at: string;
  last_seen_at: string;
  last_ip?: string;
  current: boolean;
}

export interface WebauthnCredentialInfo {
  id: string;
  name: string;
  created_at: string;
  last_used_at?: string;
}

export interface MfaStatus {
  totp_enabled: boolean;
  webauthn_credentials: WebauthnCredentialInfo[];
  backup_codes_remaining: number;
}

export interface TotpSetupResponse {
  secret: string;
  otpauth_url: string;
}

export interface SsoStartResponse {
  authorization_url: string;
  flow_id: string;
}

export type SsoResult =
  | { status: "pending" }
  | { status: "login_required"; sso_session: string; email: string }
  | { status: "registration_required"; sso_session: string; email: string; display_name?: string }
  | { status: "linked"; provider: string; email: string }
  | { status: "failed"; message: string };

export interface SsoIdentity {
  provider: string;
  name: string;
  email?: string;
  linked_at: string;
}

// ── teams ───────────────────────────────────────────────────────────────

export type TeamRole = "member" | "admin" | "owner";

export interface Team {
  id: string;
  name: string;
  created_at: string;
  my_role: TeamRole;
  /** Fine-grained role (0.9.0+). */
  my_role_ref?: RoleRef | null;
  /** Permission keys the caller holds in this team; `*` for the owner. */
  my_permissions?: string[];
  member_count: number;
  require_mfa?: boolean;
  policies?: TeamPolicies | null;
}

export interface RoleRef {
  id: string;
  slug: string;
  name: string;
}

export interface PermissionInfo {
  key: string;
  group: string;
  title: string;
  description: string;
  dangerous: boolean;
  /** `server` or `client` (honoured by clients, not a security boundary). */
  enforced_by: "server" | "client";
}

export interface TeamRoleDef {
  id: string;
  slug: string;
  name: string;
  description: string;
  permissions: string[];
  builtin: boolean;
  position: number;
  member_count: number;
  created_at: string;
  updated_at: string;
}

export interface TeamRoleList {
  roles: TeamRoleDef[];
  default_role_id: string | null;
}

export interface RoleMapping {
  group_name: string;
  role_id: string;
  priority: number;
}

export type MfaPolicy = "off" | "any" | "passkey";
export type LocalKeysPolicy = "allow" | "deny";

export interface TeamPolicies {
  mfa: MfaPolicy;
  local_keys: LocalKeysPolicy;
  session_ttl_hours: number | null;
  sso_only: boolean;
  sso_provider: string | null;
  sso_domains: string[];
  device_approval: boolean;
  audit_retention_days: number;
  /** `optional` | `required` — required forces recording in every team vault. */
  session_recording: SessionRecordingPolicy;
  /** Days session recordings are kept; 0 = forever. */
  log_retention_days: number;
  /** Max age of SSH keys/certificates before rotation is due; 0 = off. */
  key_max_age_days: number;
  /** Max age of passwords before rotation is due; 0 = off. */
  password_max_age_days: number;
  /** CIDR allow-list for member sign-in; empty = everywhere. */
  ip_allowlist: string[];
  /** New member devices wait for an admin's approval. */
  device_admin_approval: boolean;
  updated_at: string;
}

export type UpdateTeamPolicies = Partial<Omit<TeamPolicies, "updated_at">>;

export interface EffectivePolicies {
  mfa: MfaPolicy;
  mfa_team_id: string | null;
  mfa_satisfied: boolean;
  session_ttl_hours: number | null;
  local_keys_denied_by: string[];
  device_approval_by: string[];
  sso_provider: string | null; /** Teams whose policy forces session recording. */
  recording_required_by?: string[];
}

export interface TeamPoliciesResponse {
  policies: TeamPolicies;
  effective_for_me: EffectivePolicies;
}

export type WebhookKind = "generic" | "splunk_hec" | "elastic" | "datadog" | "syslog_tls";

export interface Webhook {
  id: string;
  url: string;
  kind: WebhookKind;
  actions: string[] | null;
  enabled: boolean;
  created_at: string;
  last_status: number | null;
  last_error: string | null;
  last_delivered_at: string | null;
  failures: number;
}

export interface WebhookDelivery {
  id: number;
  event_id: number;
  action: string;
  attempt: number;
  status: "pending" | "sending" | "ok" | "dead";
  response_status: number | null;
  response_body: string | null;
  next_at: string;
  delivered_at: string | null;
}

export interface ScimToken {
  id: string;
  name: string;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
}

export interface CreatedScimToken {
  token: ScimToken;
  secret: string;
  base_url: string;
}

export interface ScimGroupVault {
  vault_id: string;
  role: VaultRole;
}

export interface ScimGroupInfo {
  id: string;
  display_name: string;
  external_id: string | null;
  member_count: number;
  vaults: ScimGroupVault[];
}

export interface AuditEvent {
  id: number;
  team_id: string;
  actor_id?: string;
  actor_email?: string;
  actor_name?: string;
  actor_avatar?: string;
  device_id?: string;
  action: string;
  vault_id?: string;
  target_user?: string;
  target_email?: string;
  details: unknown;
  created_at: string;
}

export interface AuditEventList {
  events: AuditEvent[];
  next_before?: number;
}

/** How often an admin receives the team activity digest by e-mail. */
export type DigestCadence = "daily" | "weekly";

/** The caller's own digest subscription; nobody else receives it. */
export interface DigestSubscription {
  cadence?: DigestCadence;
  /** End of the last period that was mailed. */
  last_sent_at?: string;
}

export interface SendDigestResponse {
  events: number;
  sent: boolean;
}

export interface TeamMember {
  user_id: string;
  email: string;
  display_name?: string;
  avatar?: string;
  role: TeamRole;
  /** Fine-grained role (0.9.0+). */
  role_ref?: RoleRef | null;
  /** `manual`, `idp` or `scim` — who assigned the role. */
  role_source?: "manual" | "idp" | "scim" | null;
  public_key: string;
  joined_at: string;
  /** Second factor enrolled; only disclosed to team admins and the member themself. */
  mfa_enabled?: boolean | null;
  /** Account was created by accepting this team's invitation; the owner may delete it. */
  managed?: boolean;
}

export interface Invite {
  id: string;
  email: string;
  role: TeamRole;
  invited_by: string;
  created_at: string;
  expires_at: string;
}

export interface InvitePreview {
  team_name: string;
  inviter: string;
  email: string;
  role: TeamRole;
  account_exists: boolean;
}

export interface PendingVaultKey {
  vault_id: string;
  user_id: string;
  public_key: string;
  role: VaultRole;
}

// ── vaults ──────────────────────────────────────────────────────────────

export type VaultKind = "personal" | "team";
export type VaultRole = "viewer" | "editor" | "manager";

export interface Vault {
  id: string;
  kind: VaultKind;
  team_id?: string;
  name: string;
  created_at: string;
  my_role: VaultRole;
  sealed_key?: string;
  key_version: number;
  /** Team vault: a manager turned on recording of every member's sessions. */
  session_logging: boolean;
  /** Team vault: the team's first vault. It can be renamed but not deleted. */
  is_default: boolean;
}

/** Who recorded a session log, as the server shows it to vault members. */
export interface LogAuthor {
  user_id: string;
  email: string;
  display_name?: string;
  avatar_tag?: string;
}

/** A session recording as listed by the server; `meta` and the body are vault-key ciphertext. */
export interface SessionLog {
  id: string;
  vault_id: string;
  user_id: string;
  author?: LogAuthor;
  meta: string;
  key_version: number;
  size_bytes: number;
  completed: boolean;
  created_at: string;
  seq: number;
  deleted: boolean;
  pinned: boolean;
  note: string;
  note_by?: string;
}

export interface LogListResponse {
  logs: SessionLog[];
  since: number;
  has_more: boolean;
}

/** Plaintext of `SessionLog.meta` once decrypted with the vault key. */
export interface LogMeta {
  host_id?: string;
  label: string;
  target: string;
  protocol: string;
  started_at: string;
  ended_at?: string;
  cols: number;
  rows: number;
}

export interface VaultMember {
  user_id: string;
  email: string;
  display_name?: string;
  avatar?: string;
  role: VaultRole;
  key_version: number;
  pending: boolean;
  public_key: string;
  added_at: string;
}

export interface VaultMemberUpsert {
  user_id: string;
  role: VaultRole;
  sealed_key: string;
}

export interface SealedKeyFor {
  user_id: string;
  sealed_key: string;
}

// ── admin ───────────────────────────────────────────────────────────────

export interface AdminStats {
  users: number;
  active_users_30d: number;
  teams: number;
  vaults: number;
  entities: number;
  active_sessions: number;
  log_storage_bytes: number;
}

export interface AdminUser {
  id: string;
  email: string;
  email_verified: boolean;
  display_name?: string;
  avatar?: string;
  is_admin: boolean;
  is_owner: boolean;
  disabled: boolean;
  mfa_enabled: boolean;
  created_at: string;
  last_seen_at?: string;
  devices: number; /** Teams the user belongs to, with the team-role slug. */
  teams?: AdminUserTeam[];
  /** `password` | `sso` | `scim`. */
  source?: string;
}

export interface AdminUserTeam {
  id: string;
  name: string;
  role: string;
}

export interface AdminUpdateUserRequest {
  disabled?: boolean;
  is_admin?: boolean;
  email_verified?: boolean;
}

export interface ServerSettings {
  registration_open: boolean;
  allowed_domains: string[];
  sso_registration: boolean;
  require_email_verification: boolean;
  new_device_email_approval: boolean;
  users_can_create_teams: boolean;
  session_ttl_days: number;
  max_entity_bytes: number;
  max_log_bytes: number;
  log_quota_bytes: number;
  audit_retention_days: number; /** Corporate mode: every account joins this team automatically. */
  home_team_id?: string | null;
  /** Corporate mode: only SSO sign-in (bootstrap admin keeps password). */
  sso_only?: boolean;
  /** `false` hides personal vaults in clients. */
  personal_vaults?: boolean;
}

/** `GET /admin/config` — effective runtime configuration (secrets masked) plus live probes. */
export interface AdminConfig {
  server: AdminConfigServer;
  database: AdminConfigService;
  redis: AdminConfigService;
  storage: AdminConfigStorage | null;
  smtp: AdminConfigSmtp | null;
  sso: AdminConfigSso[];
  webauthn: AdminConfigWebauthn | null;
  ai: AdminConfigAi | null;
  settings: AdminSettingsMeta;
}

export interface AdminConfigServer {
  version: string;
  started_at: string;
  uptime_secs: number;
  name: string;
  public_url: string;
  web_url: string;
  bind: string;
  trust_proxy: boolean;
  cors_origins: string[];
  log: string;
  log_format: string;
  data_region: string | null;
  min_client_version: string;
  min_client_version_overridden: boolean;
  start_over_delay_secs: number;
  team_deletion_grace_days: number;
  team_audit_retention_days_max: number;
  audit_sink: boolean;
  swagger_ui: boolean;
  bridges: boolean;
  team_idp: boolean;
  landing: boolean;
  docs: boolean;
  metrics_bind: string | null;
  webhooks_allow_private: boolean;
  webhooks_syslog_ca: boolean;
  turnstile: boolean;
  admin_emails: string[];
  owner_email: string | null;
}

export interface AdminConfigService {
  endpoint: string;
  detail: string | null;
  status: "ok" | "error";
  latency_ms: number | null;
  error: string | null;
}

export interface AdminConfigStorage {
  bucket: string;
  region: string | null;
  endpoint: string | null;
  public_endpoint: string | null;
  force_path_style: boolean;
  presign_secs: number;
  status: "ok" | "error";
  latency_ms: number | null;
  error: string | null;
}

export interface AdminConfigSmtp {
  host: string;
  port: number;
  security: "starttls" | "tls" | "none";
  from: string;
  auth: boolean;
}

export interface AdminConfigSso {
  id: string;
  name: string;
  kind: "oidc" | "saml";
  issuer: string | null;
  allowed_domains: string[];
}

export interface AdminConfigWebauthn {
  rp_id: string;
  rp_name: string;
  origins: string[];
}

export interface AdminConfigAi {
  provider: string;
  model: string;
  endpoint: string;
  confidential: boolean;
  daily_quota: number;
  max_prompt_chars: number;
  timeout_secs: number;
}

export interface AdminSettingsMeta {
  defaults: ServerSettings;
  limits: AdminSettingsLimits;
  updated_at: string | null;
  updated_by: string | null;
}

export interface AdminSettingsLimits {
  session_ttl_days_min: number;
  session_ttl_days_max: number;
  max_entity_bytes_min: number;
  max_entity_bytes_max: number;
  max_log_bytes_min: number;
  audit_retention_days_max: number;
}

export interface AdminTeam {
  id: string;
  name: string;
  owner_email: string;
  member_count: number;
  vault_count: number;
  created_at: string;
  region?: string | null;
  deletion_scheduled_at?: string | null;
  log_bytes?: number;
  is_home?: boolean;
  idp?: boolean;
  scim?: boolean;
  webhooks?: number;
}

export interface AdminTeamMember {
  user_id: string;
  email: string;
  level: string;
  role: string;
  role_source: string;
  joined_at: string;
  last_seen_at?: string | null;
}

/** `offset` / `limit` for a server-paged list; omit both for the whole list. */
export interface PageParams {
  offset?: number;
  limit?: number;
}

export interface AdminTeamMemberList {
  members: AdminTeamMember[];
  total: number;
}

export interface AdminTeamAuditList {
  events: AuditEvent[];
  total: number;
}

export interface AdminTeamDetail {
  team: AdminTeam;
  members: AdminTeamMember[];
  policies: TeamPolicies;
  audit: AuditEvent[];
}

export interface AdminJob {
  name: string;
  last_started_at: string;
  last_finished_at?: string | null;
  last_result?: number | null;
  last_error?: string | null;
}

export interface Page<T> {
  items: T[];
  total: number;
}

// ── API bridges ─────────────────────────────────────────────────────────

/** A vault an API bridge may write to; `sealed_key` is absent after a key rotation until re-sealed. */
export interface BridgeVault {
  vault_id: string;
  name: string;
  kind: VaultKind;
  team_id?: string;
  role: VaultRole;
  key_version: number;
  sealed_key?: string;
}

export interface Bridge {
  id: string;
  name: string;
  device_id: string;
  public_key: string;
  vaults: BridgeVault[];
  created_at: string;
  last_used_at?: string;
  last_ip?: string;
}

export interface BridgeVaultKey {
  vault_id: string;
  sealed_key: string;
}

export interface CreateBridgeResponse {
  bridge: Bridge;
  /** Shown once; the server keeps only a hash. */
  token: string;
}

/** `termoso-bridge.json` mounted into the bridge container. */
export interface BridgeCredentials {
  version: 1;
  server: string;
  bridge_id: string;
  private_key: string;
  token: string;
}

// ── 0.9.1 enterprise ──

export interface HomeTeam {
  id: string;
  name: string;
}

export type SessionRecordingPolicy = "optional" | "required";

export interface SsoDiscoverResponse {
  provider?: SsoProvider | null;
  team_name?: string | null;
  /** The matching policy forbids password sign-in. */
  required: boolean;
}

export type TeamIdpKind = "oidc" | "saml";

export interface TeamIdp {
  kind: TeamIdpKind;
  name: string;
  issuer?: string | null;
  client_id?: string | null;
  has_client_secret: boolean;
  scopes?: string | null;
  saml_metadata?: string | null;
  saml_idp_entity_id?: string | null;
  domains: string[];
  enabled: boolean;
  jit_join: boolean;
  provider_id: string;
  callback_url: string;
  updated_at: string;
}

export interface UpdateTeamIdp {
  kind?: TeamIdpKind;
  name?: string;
  issuer?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string;
  saml_metadata?: string;
  saml_idp_entity_id?: string;
  domains?: string[];
  enabled?: boolean;
  jit_join?: boolean;
}

export interface TeamIdpResponse {
  idp: TeamIdp | null;
  /** Feature is enabled on this server. */
  available: boolean;
}

export type AclMode = "none" | "connect" | "read" | "edit";
export type AclPrincipalKind = "role" | "member" | "group";
export type AclEntityKind = "host" | "group";

export interface EntityAclRule {
  id: string;
  vault_id: string;
  entity_id: string;
  entity_kind: AclEntityKind;
  principal_kind: AclPrincipalKind;
  role_id?: string | null;
  user_id?: string | null;
  group_name?: string | null;
  principal_name: string;
  mode: AclMode;
  updated_at: string;
}

export interface UpsertEntityAcl {
  entity_id: string;
  entity_kind: AclEntityKind;
  principal_kind: AclPrincipalKind;
  role_id?: string;
  user_id?: string;
  group_name?: string;
  mode: AclMode;
}

export type TeamDeviceStatus = "pending" | "approved" | "rejected";

export interface TeamDevice {
  device_id: string;
  user_id: string;
  user_email: string;
  name: string;
  platform: string;
  app_version?: string | null;
  last_seen_at: string;
  last_ip?: string | null;
  status: TeamDeviceStatus;
  decided_by?: string | null;
  decided_at?: string | null;
  requested_at: string;
}

export interface TeamDeviceList {
  admin_approval: boolean;
  devices: TeamDevice[];
  total: number;
}

export interface RotationDue {
  entity_id: string;
  vault_id: string;
  kind: string;
  secret_rotated_at?: string | null;
  age_days: number;
  job_id?: string | null;
}

export type RotationJobStatus = "pending" | "running" | "done" | "failed" | "cancelled";

export interface RotationJob {
  id: string;
  team_id: string;
  vault_id: string;
  entity_id: string;
  entity_kind: string;
  status: RotationJobStatus;
  note: string;
  error?: string | null;
  requested_by: string;
  requested_by_email: string;
  claimed_by?: string | null;
  created_at: string;
  updated_at: string;
  finished_at?: string | null;
}

export interface RotationOverview {
  key_max_age_days: number;
  password_max_age_days: number;
  due: RotationDue[];
  jobs: RotationJob[];
  jobs_total: number;
}

export type AccessRole = "viewer" | "editor";
export type AccessRequestStatus =
  "pending" | "approved" | "denied" | "revoked" | "expired" | "cancelled";

export interface AccessRequest {
  id: string;
  team_id: string;
  vault_id: string;
  vault_name: string;
  user_id: string;
  user_email: string;
  role: AccessRole;
  hours: number;
  reason: string;
  status: AccessRequestStatus;
  decided_by?: string | null;
  decided_at?: string | null;
  decision_note?: string | null;
  expires_at?: string | null;
  created_at: string;
}

export interface AccessRequestList {
  can_approve: boolean;
  requests: AccessRequest[];
  total: number;
}

export interface TeamDataStatus {
  region?: string | null;
  server_region?: string | null;
  created_at: string;
  deletion_scheduled_at?: string | null;
  deletion_requested_by?: string | null;
  deletion_grace_days: number;
}
