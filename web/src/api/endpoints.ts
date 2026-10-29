import { fetchBlob, http, requestWithStatus, upload } from "./client";
import type {
  AdminConfig,
  AccountResponse,
  AdminStats,
  AdminTeam,
  AdminUpdateUserRequest,
  AdminUser,
  AuditEventList,
  AuthResponse,
  Bridge,
  BridgeVaultKey,
  CreateBridgeResponse,
  CreatedScimToken,
  Device,
  DeviceInfo,
  DigestCadence,
  DigestSubscription,
  Invite,
  InvitePreview,
  LoginStartResponse,
  LogListResponse,
  MfaCredential,
  MfaStatus,
  Page,
  PasswordSetupFinishRequest,
  PendingVaultKey,
  PermissionInfo,
  ReauthStartResponse,
  RecoveryRotate,
  RecoveryStartResponse,
  RegisterFinishRequest,
  RoleMapping,
  ScimGroupInfo,
  ScimGroupVault,
  ScimToken,
  SealedKeyFor,
  SecurityEvent,
  SendDigestResponse,
  ServerInfo,
  ServerSettings,
  SessionLog,
  SettingsBlob,
  SsoIdentity,
  SsoProvider,
  SsoResult,
  SsoStartResponse,
  StartOverFinishRequest,
  StartOverRequestResponse,
  StartOverScheduled,
  StartOverStatus,
  Team,
  TeamMember,
  TeamPoliciesResponse,
  TeamRole,
  TeamRoleDef,
  TeamRoleList,
  TotpSetupResponse,
  UpdateTeamPolicies,
  UserProfile,
  Vault,
  VaultMember,
  VaultMemberUpsert,
  VaultRole,
  WebauthnCredentialInfo,
  Webhook,
  WebhookDelivery,
  WebhookKind,
  AdminTeamAuditList,
  AdminTeamMemberList,
  PageParams,
} from "./types";
import type {
  AccessRequest,
  AdminJob,
  AdminTeamDetail,
  AccessRequestList,
  AccessRole,
  EntityAclRule,
  RotationJob,
  RotationOverview,
  SsoDiscoverResponse,
  TeamDataStatus,
  TeamDeviceList,
  TeamIdpResponse,
  UpdateTeamIdp,
  UpsertEntityAcl,
} from "./types";

const anon = { anonymous: true } as const;

export const serverApi = {
  info: () => http.get<ServerInfo>("/server/info", anon),
};

export const authApi = {
  ssoDiscover: (email: string) =>
    http.get<SsoDiscoverResponse>("/auth/sso/discover", { query: { email } }),
  registerStart: (email: string, opaque_request: string, turnstile_token?: string) =>
    http.post<{ opaque_response: string }>(
      "/auth/register/start",
      { email, opaque_request, turnstile_token },
      anon,
    ),
  registerFinish: (req: RegisterFinishRequest) =>
    http.post<AuthResponse>("/auth/register/finish", req, anon),

  loginStart: (
    email: string,
    opaque_request: string,
    device: DeviceInfo,
    sso_session?: string,
    turnstile_token?: string,
  ) =>
    http.post<LoginStartResponse>(
      "/auth/login/start",
      { email, opaque_request, device, sso_session, turnstile_token },
      anon,
    ),
  loginFinish: (login_id: string, opaque_finalization: string) =>
    http.post<AuthResponse>("/auth/login/finish", { login_id, opaque_finalization }, anon),

  mfaVerify: (mfa_token: string, credential: MfaCredential) =>
    http.post<AuthResponse>("/auth/mfa/verify", { mfa_token, credential }, anon),
  mfaWebauthnChallenge: (mfa_token: string) =>
    http.post<unknown>("/auth/mfa/webauthn/challenge", { mfa_token }, anon),
  mfaEmailSend: (mfa_token: string) =>
    http.post<undefined>("/auth/mfa/email/send", { mfa_token }, anon),

  deviceApprove: (approval_token: string, code: string) =>
    http.post<AuthResponse>("/auth/device/approve", { approval_token, code }, anon),
  deviceApproveResend: (approval_token: string) =>
    http.post<undefined>("/auth/device/approve/resend", { approval_token }, anon),

  recoveryStart: (email: string, recovery_verifier: string, turnstile_token?: string) =>
    http.post<RecoveryStartResponse>(
      "/auth/recovery/start",
      { email, recovery_verifier, turnstile_token },
      anon,
    ),
  passwordStart: (opaque_request: string, recovery_token?: string) =>
    http.post<{ opaque_response: string }>(
      "/auth/password/start",
      { opaque_request, recovery_token },
      recovery_token ? anon : undefined,
    ),
  passwordFinish: (req: PasswordSetupFinishRequest) =>
    http.post<AuthResponse>("/auth/password/finish", req, req.recovery_token ? anon : undefined),

  logout: () => http.post<undefined>("/auth/logout"),

  reauthStart: (opaque_request?: string) =>
    http.post<ReauthStartResponse>("/auth/reauth/start", { opaque_request }),
  reauthFinish: (reauth_id: string, proof: { opaque_finalization?: string; code?: string }) =>
    http.post<AuthResponse>("/auth/reauth/finish", { reauth_id, ...proof }),

  startOverRequest: (email: string, turnstile_token?: string) =>
    http.post<StartOverRequestResponse>(
      "/auth/start-over/request",
      { email, turnstile_token },
      anon,
    ),
  startOverConfirm: (request_token: string, code: string, mfa_code?: string) =>
    http.post<StartOverScheduled>(
      "/auth/start-over/confirm",
      { request_token, code, mfa_code },
      anon,
    ),
  startOverStatus: (token: string) =>
    http.get<StartOverStatus>(`/auth/start-over/${encodeURIComponent(token)}`, anon),
  startOverCancel: (cancel_token: string) =>
    http.post<undefined>("/auth/start-over/cancel", { cancel_token }, anon),
  startOverPasswordStart: (token: string, opaque_request: string) =>
    http.post<{ opaque_response: string }>(
      "/auth/start-over/password/start",
      { token, opaque_request },
      anon,
    ),
  startOverFinish: (req: StartOverFinishRequest) =>
    http.post<AuthResponse>("/auth/start-over/finish", req, anon),

  ssoProviders: () => http.get<SsoProvider[]>("/auth/sso/providers", anon),
  ssoStart: (provider: string, redirect: string) =>
    http.get<SsoStartResponse>(`/auth/sso/${encodeURIComponent(provider)}/start`, {
      ...anon,
      query: { redirect },
    }),
  ssoPoll: (flow_id: string) =>
    http.get<SsoResult>(`/auth/sso/flow/${encodeURIComponent(flow_id)}`, anon),
};

export const accountApi = {
  get: (token?: string) => http.get<AccountResponse>("/account", token ? { token } : undefined),
  updateProfile: (display_name: string | null) =>
    http.patch<UserProfile>("/account/profile", { display_name }),
  putAvatar: (image: Blob) => upload<UserProfile>("PUT", "/account/avatar", image),
  deleteAvatar: () => http.delete<UserProfile>("/account/avatar"),
  /** `GET /users/{id}/avatar?v={tag}` — the tag pins the URL so the browser's HTTP cache never serves a replaced picture. */
  avatar: (user_id: string, tag: string) =>
    fetchBlob(`/users/${encodeURIComponent(user_id)}/avatar?v=${encodeURIComponent(tag)}`),
  emailVerifySend: () => http.post<undefined>("/account/email/verify/send"),
  emailVerifyConfirm: (code: string) =>
    http.post<undefined>("/account/email/verify/confirm", { code }),
  emailChange: (new_email: string) => http.post<undefined>("/account/email/change", { new_email }),
  emailChangeConfirm: (code: string) =>
    http.post<undefined>("/account/email/change/confirm", { code }),
  settings: () => http.get<SettingsBlob>("/account/settings"),
  putSettings: (data: string, base_version: number) =>
    http.put<SettingsBlob>("/account/settings", { data, base_version }),
  devices: () => http.get<{ devices: Device[] }>("/account/devices"),
  revokeDevice: (id: string) => http.delete<undefined>(`/account/devices/${id}`),
  securityEvents: (before?: string, limit = 10) =>
    http.get<{ events: SecurityEvent[]; has_more: boolean }>("/account/security-events", {
      query: before ? { before, limit: String(limit) } : { limit: String(limit) },
    }),
  rotateRecovery: (req: RecoveryRotate) => http.post<undefined>("/account/recovery/rotate", req),
  cancelStartOver: () => http.post<undefined>("/account/start-over/cancel"),
  /** Resolves to `"code_sent"` (202: a confirmation code was mailed) or `"deleted"` (204). */
  delete: async (code?: string): Promise<"code_sent" | "deleted"> => {
    const r = await requestWithStatus<undefined>(
      "DELETE",
      "/account",
      code === undefined ? undefined : { code },
    );
    return r.status === 202 ? "code_sent" : "deleted";
  },

  ssoIdentities: () => http.get<SsoIdentity[]>("/account/sso"),
  ssoLinkStart: (provider: string, redirect: string) =>
    http.get<SsoStartResponse>(`/account/sso/${encodeURIComponent(provider)}/link/start`, {
      query: { redirect },
    }),
  ssoUnlink: (provider: string) =>
    http.delete<undefined>(`/account/sso/${encodeURIComponent(provider)}`),
  mfa: () => http.get<MfaStatus>("/account/mfa"),
  totpSetup: () => http.post<TotpSetupResponse>("/account/mfa/totp/setup"),
  totpConfirm: (code: string) =>
    http.post<{ codes: string[] }>("/account/mfa/totp/confirm", { code }),
  totpDisable: (code: string) => http.delete<undefined>("/account/mfa/totp", { code }),
  backupCodes: () => http.post<{ codes: string[] }>("/account/mfa/backup-codes"),
  webauthnRegisterStart: () => http.post<unknown>("/account/mfa/webauthn/register/start"),
  webauthnRegisterFinish: (name: string, credential: unknown) =>
    http.post<WebauthnCredentialInfo>("/account/mfa/webauthn/register/finish", {
      name,
      credential,
    }),
  webauthnDelete: (id: string) => http.delete<undefined>(`/account/mfa/webauthn/${id}`),
};

export const teamsApi = {
  list: () => http.get<{ teams: Team[] }>("/teams"),
  create: (name: string) => http.post<Team>("/teams", { name }),
  get: (id: string) => http.get<Team>(`/teams/${id}`),
  update: (id: string, name: string) => http.patch<Team>(`/teams/${id}`, { name }),
  delete: (id: string) => http.delete<undefined>(`/teams/${id}`),
  leave: (id: string) => http.post<undefined>(`/teams/${id}/leave`),
  members: (id: string, p: PageParams = {}) =>
    http.get<{ members: TeamMember[]; total: number }>(`/teams/${id}/members`, { query: p }),
  updateMember: (id: string, userId: string, role: TeamRole) =>
    http.patch<TeamMember>(`/teams/${id}/members/${userId}`, { role }),
  removeMember: (id: string, userId: string) =>
    http.delete<undefined>(`/teams/${id}/members/${userId}`),
  /** Owner-only: delete the whole account of a member created by this team's invitation. */
  deleteMemberAccount: (id: string, userId: string) =>
    http.delete<undefined>(`/teams/${id}/members/${userId}/account`),
  digest: (id: string) => http.get<DigestSubscription>(`/teams/${id}/digest`),
  updateDigest: (id: string, cadence: DigestCadence | null) =>
    http.put<DigestSubscription>(`/teams/${id}/digest`, { cadence }),
  sendDigest: (id: string, cadence: DigestCadence) =>
    http.post<SendDigestResponse>(`/teams/${id}/digest/send`, { cadence }),
  invites: (id: string, p: PageParams = {}) =>
    http.get<{ invites: Invite[]; total: number }>(`/teams/${id}/invites`, { query: p }),
  createInvite: (id: string, email: string, role: TeamRole, vault_ids: string[]) =>
    http.post<Invite & { url: string }>(`/teams/${id}/invites`, { email, role, vault_ids }),
  deleteInvite: (id: string, inviteId: string) =>
    http.delete<undefined>(`/teams/${id}/invites/${inviteId}`),
  pendingKeys: (id: string) => http.get<{ items: PendingVaultKey[] }>(`/teams/${id}/pending-keys`),
  // ── roles & permissions (0.9.0) ──
  permissions: (id: string) =>
    http.get<{ permissions: PermissionInfo[] }>(`/teams/${id}/permissions`),
  roles: (id: string) => http.get<TeamRoleList>(`/teams/${id}/roles`),
  createRole: (
    id: string,
    body: { name: string; description?: string; permissions: string[]; copy_from?: string },
  ) => http.post<TeamRoleDef>(`/teams/${id}/roles`, body),
  updateRole: (
    id: string,
    roleId: string,
    body: { name?: string; description?: string; permissions?: string[]; position?: number },
  ) => http.patch<TeamRoleDef>(`/teams/${id}/roles/${roleId}`, body),
  deleteRole: (id: string, roleId: string, reassign_to?: string) =>
    http.delete<undefined>(`/teams/${id}/roles/${roleId}`, undefined, {
      query: reassign_to ? { reassign_to } : undefined,
    }),
  setDefaultRole: (id: string, role_id: string) =>
    http.put<undefined>(`/teams/${id}/default-role`, { role_id }),
  setMemberRole: (id: string, userId: string, role: TeamRole, role_id: string) =>
    http.patch<TeamMember>(`/teams/${id}/members/${userId}`, { role, role_id }),
  roleMappings: (id: string) => http.get<{ mappings: RoleMapping[] }>(`/teams/${id}/role-mappings`),
  setRoleMappings: (id: string, mappings: RoleMapping[]) =>
    http.put<{ mappings: RoleMapping[] }>(`/teams/${id}/role-mappings`, { mappings }),
  // ── 0.9.1 enterprise ──
  idp: (id: string) => http.get<TeamIdpResponse>(`/teams/${id}/idp`),
  updateIdp: (id: string, patch: UpdateTeamIdp) =>
    http.put<TeamIdpResponse>(`/teams/${id}/idp`, patch),
  deleteIdp: (id: string) => http.delete<undefined>(`/teams/${id}/idp`),
  testIdp: (id: string, patch: UpdateTeamIdp) =>
    http.post<TeamIdpResponse>(`/teams/${id}/idp/test`, patch),
  acl: (id: string, vaultId: string, p: PageParams = {}) =>
    http.get<{ rules: EntityAclRule[]; total: number }>(`/teams/${id}/vaults/${vaultId}/acl`, {
      query: p,
    }),
  upsertAcl: (id: string, vaultId: string, rule: UpsertEntityAcl) =>
    http.put<{ rules: EntityAclRule[] }>(`/teams/${id}/vaults/${vaultId}/acl`, rule),
  deleteAcl: (id: string, vaultId: string, ruleId: string) =>
    http.delete<undefined>(`/teams/${id}/vaults/${vaultId}/acl/${ruleId}`),
  logs: (id: string, q: { vault_id?: string; from?: string; to?: string } & PageParams = {}) =>
    http.get<{ logs: SessionLog[]; total: number }>(`/teams/${id}/logs`, { query: q }),
  logsExport: (id: string) => fetchBlob(`/teams/${id}/logs/export`),
  rotation: (id: string, p: PageParams = {}) =>
    http.get<RotationOverview>(`/teams/${id}/rotation`, { query: p }),
  createRotationJobs: (
    id: string,
    body: { vault_id: string; entity_ids: string[]; note: string },
  ) => http.post<{ jobs: RotationJob[] }>(`/teams/${id}/rotation/jobs`, body),
  cancelRotationJob: (jobId: string) => http.delete<undefined>(`/rotation/jobs/${jobId}`),
  accessRequests: (id: string, q: { status?: "open" | "closed" } & PageParams = {}) =>
    http.get<AccessRequestList>(`/teams/${id}/access-requests`, { query: q }),
  createAccessRequest: (
    id: string,
    body: { vault_id: string; role: AccessRole; hours: number; reason: string },
  ) => http.post<AccessRequest>(`/teams/${id}/access-requests`, body),
  cancelAccessRequest: (id: string, rid: string) =>
    http.delete<undefined>(`/teams/${id}/access-requests/${rid}`),
  approveAccessRequest: (
    id: string,
    rid: string,
    body: { hours?: number; role?: AccessRole; note?: string },
  ) => http.post<AccessRequest>(`/teams/${id}/access-requests/${rid}/approve`, body),
  denyAccessRequest: (id: string, rid: string, note?: string) =>
    http.post<AccessRequest>(`/teams/${id}/access-requests/${rid}/deny`, { note }),
  revokeAccessRequest: (id: string, rid: string, note?: string) =>
    http.post<AccessRequest>(`/teams/${id}/access-requests/${rid}/revoke`, { note }),
  data: (id: string) => http.get<TeamDataStatus>(`/teams/${id}/data`),
  exportData: (id: string) => fetchBlob(`/teams/${id}/export`),
  scheduleDeletion: (id: string, confirmName: string) =>
    http.post<TeamDataStatus>(`/teams/${id}/deletion`, { confirm_name: confirmName }),
  cancelDeletion: (id: string) => http.delete<TeamDataStatus>(`/teams/${id}/deletion`),
  devices: (id: string, q: { status?: "pending" | "decided" } & PageParams = {}) =>
    http.get<TeamDeviceList>(`/teams/${id}/devices`, { query: q }),
  approveDevice: (id: string, deviceId: string) =>
    http.post<undefined>(`/teams/${id}/devices/${deviceId}/approve`),
  rejectDevice: (id: string, deviceId: string) =>
    http.post<undefined>(`/teams/${id}/devices/${deviceId}/reject`),
  // ── policies ──
  policies: (id: string) => http.get<TeamPoliciesResponse>(`/teams/${id}/policies`),
  updatePolicies: (id: string, patch: UpdateTeamPolicies) =>
    http.put<TeamPoliciesResponse>(`/teams/${id}/policies`, patch),
  // ── audit ──
  audit: (
    id: string,
    q: {
      before?: number;
      offset?: number;
      limit?: number;
      action?: string;
      actor?: string;
      vault?: string;
    },
  ) => http.get<AuditEventList>(`/teams/${id}/audit`, { query: q }),
  auditExport: (
    id: string,
    q: { format: "csv" | "jsonl"; from?: string; to?: string; action?: string; actor?: string },
  ) => {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(q)) if (v) params.set(k, v);
    return fetchBlob(`/teams/${id}/audit/export?${params.toString()}`);
  },
  // ── webhooks ──
  webhooks: (id: string) => http.get<{ webhooks: Webhook[] }>(`/teams/${id}/webhooks`),
  createWebhook: (
    id: string,
    body: { url: string; secret: string; kind: WebhookKind; actions?: string[] | null },
  ) => http.post<Webhook>(`/teams/${id}/webhooks`, body),
  updateWebhook: (
    id: string,
    wid: string,
    body: {
      url?: string;
      secret?: string;
      kind?: WebhookKind;
      actions?: string[] | null;
      enabled?: boolean;
    },
  ) => http.patch<Webhook>(`/teams/${id}/webhooks/${wid}`, body),
  deleteWebhook: (id: string, wid: string) =>
    http.delete<undefined>(`/teams/${id}/webhooks/${wid}`),
  testWebhook: (id: string, wid: string) =>
    http.post<{ deliveries: WebhookDelivery[] }>(`/teams/${id}/webhooks/${wid}/test`),
  webhookDeliveries: (id: string, wid: string) =>
    http.get<{ deliveries: WebhookDelivery[] }>(`/teams/${id}/webhooks/${wid}/deliveries`),
  // ── SCIM ──
  scimTokens: (id: string) =>
    http.get<{ tokens: ScimToken[]; base_url: string }>(`/teams/${id}/scim/tokens`),
  createScimToken: (id: string, body: { name: string; expires_in_days?: number }) =>
    http.post<CreatedScimToken>(`/teams/${id}/scim/tokens`, body),
  revokeScimToken: (id: string, tid: string) =>
    http.delete<undefined>(`/teams/${id}/scim/tokens/${tid}`),
  scimGroups: (id: string, p: PageParams = {}) =>
    http.get<{ groups: ScimGroupInfo[]; total: number }>(`/teams/${id}/scim/groups`, { query: p }),
  setScimGroupVaults: (id: string, gid: string, vaults: ScimGroupVault[]) =>
    http.put<ScimGroupInfo>(`/teams/${id}/scim/groups/${gid}/vaults`, { vaults }),
  createVault: (id: string, name: string, members: VaultMemberUpsert[]) =>
    http.post<Vault>(`/teams/${id}/vaults`, { name, members }),
  invitePreview: (token: string) =>
    http.get<InvitePreview>(`/invites/${encodeURIComponent(token)}`, anon),
  acceptInvite: (token: string) => http.post<Team>(`/invites/${encodeURIComponent(token)}/accept`),
};

export const logsApi = {
  /** Pin / comment (editors), or fix up one's own recording (author). */
  update: (id: string, patch: { pinned?: boolean; note?: string }) =>
    http.patch<SessionLog>(`/logs/${id}`, patch),
  delete: (id: string) => http.delete<undefined>(`/logs/${id}`),
};

export const bridgesApi = {
  list: () => http.get<{ bridges: Bridge[] }>("/account/bridges"),
  create: (name: string, public_key: string, vaults: BridgeVaultKey[]) =>
    http.post<CreateBridgeResponse>("/account/bridges", { name, public_key, vaults }),
  setVaults: (id: string, vaults: BridgeVaultKey[]) =>
    http.put<Bridge>(`/account/bridges/${id}/vaults`, vaults),
  revoke: (id: string) => http.delete<undefined>(`/account/bridges/${id}`),
};

export const vaultsApi = {
  list: () => http.get<{ vaults: Vault[] }>("/vaults"),
  get: (id: string) => http.get<Vault>(`/vaults/${id}`),
  update: (id: string, patch: { name?: string; session_logging?: boolean }) =>
    http.patch<Vault>(`/vaults/${id}`, patch),
  delete: (id: string) => http.delete<undefined>(`/vaults/${id}`),
  /** Recordings every member of a team vault shares, oldest first from `since`. */
  logs: (id: string, since = 0, limit = 100) =>
    http.get<LogListResponse>(`/vaults/${id}/logs?since=${since}&limit=${limit}`),
  members: (id: string, p: PageParams = {}) =>
    http.get<{ members: VaultMember[]; total: number }>(`/vaults/${id}/members`, { query: p }),
  upsertMember: (id: string, userId: string, role: VaultRole, sealed_key: string) =>
    http.put<VaultMember>(`/vaults/${id}/members/${userId}`, { user_id: userId, role, sealed_key }),
  removeMember: (id: string, userId: string) =>
    http.delete<undefined>(`/vaults/${id}/members/${userId}`),
  rotateKey: (id: string, base_key_version: number, members: SealedKeyFor[]) =>
    http.post<{ key_version: number }>(`/vaults/${id}/rotate-key`, { base_key_version, members }),
  /** Replaces the caller's own sealed copy of the current key (same version, same key). */
  resealMyKey: (id: string, key_version: number, sealed_key: string) =>
    http.put<undefined>(`/vaults/${id}/my-key`, { key_version, sealed_key }),
};

export interface ListParams {
  q?: string;
  offset?: number;
  limit?: number;
  team?: string;
  sort?: string;
}

export const adminApi = {
  stats: () => http.get<AdminStats>("/admin/stats"),
  config: () => http.get<AdminConfig>("/admin/config"),
  users: async (p: ListParams): Promise<Page<AdminUser>> => {
    const r = await http.get<{ users: AdminUser[]; total: number }>("/admin/users", { query: p });
    return { items: r.users, total: r.total };
  },
  user: (id: string) => http.get<AdminUser>(`/admin/users/${id}`),
  updateUser: (id: string, req: AdminUpdateUserRequest) =>
    http.patch<AdminUser>(`/admin/users/${id}`, req),
  deleteUser: (id: string) => http.delete<undefined>(`/admin/users/${id}`),
  revokeSessions: (id: string) => http.post<undefined>(`/admin/users/${id}/revoke-sessions`),
  resetMfa: (id: string) => http.post<undefined>(`/admin/users/${id}/reset-mfa`),
  teams: async (p: ListParams): Promise<Page<AdminTeam>> => {
    const r = await http.get<{ teams: AdminTeam[]; total: number }>("/admin/teams", { query: p });
    return { items: r.teams, total: r.total };
  },
  deleteTeam: (id: string) => http.delete<undefined>(`/admin/teams/${id}`),
  teamDetail: (id: string) => http.get<AdminTeamDetail>(`/admin/teams/${id}`),
  teamMembers: (id: string, q: { q?: string } & PageParams = {}) =>
    http.get<AdminTeamMemberList>(`/admin/teams/${id}/members`, { query: q }),
  teamAudit: (id: string, p: PageParams = {}) =>
    http.get<AdminTeamAuditList>(`/admin/teams/${id}/audit`, { query: p }),
  addTeamMember: (id: string, userId: string, role?: string) =>
    http.post<undefined>(`/admin/teams/${id}/members`, { user_id: userId, role }),
  removeTeamMember: (id: string, userId: string) =>
    http.delete<undefined>(`/admin/teams/${id}/members/${userId}`),
  jobs: () => http.get<{ jobs: AdminJob[] }>("/admin/jobs"),
  settings: () => http.get<ServerSettings>("/admin/settings"),
  putSettings: (s: ServerSettings) => http.put<ServerSettings>("/admin/settings", s),
  testEmail: (to: string) => http.post<undefined>("/admin/email/test", { to }),
};
