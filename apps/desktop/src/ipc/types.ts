import { msg, type Language } from "@/i18n";
// Mirrors of the Rust IPC types (apps/desktop/src-tauri/src/*.rs). These are
// shapes only; all validation and domain logic lives in Rust.

export type Uuid = string;

export interface DesktopError {
  kind: string;
  message: string;
}

export function isDesktopError(e: unknown): e is DesktopError {
  return (
    typeof e === "object" &&
    e !== null &&
    typeof (e as DesktopError).kind === "string" &&
    typeof (e as DesktopError).message === "string"
  );
}

/** The server wants a fresh re-authentication before this sensitive change. */
export function isReauthRequired(e: unknown): boolean {
  return isDesktopError(e) && e.kind === "reauth_required";
}

export function errorMessage(e: unknown): string {
  if (isDesktopError(e)) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}

export type MasterKeySource = "keychain" | "file" | "password";

/** Master password / App Lock state (`vault_status`). */
export interface VaultStatus {
  locked: boolean;
  passwordProtected: boolean;
  masterSource: MasterKeySource;
  minPasswordChars: number;
}

export type VaultEvent = { type: "locked" } | { type: "unlocked" };

export interface AppInfo {
  version: string;
  profileDir: string;
  deviceId: Uuid;
  masterKeySource: MasterKeySource;
  signedIn: boolean;
  platform: string;
}

export type ThemeMode = "dark" | "light" | "system";
export type HostsView = "grid" | "list";
export type CursorStyle = "block" | "underline" | "bar";
export const TERM_TYPES = [
  "xterm-256color",
  "xterm",
  "vt100",
  "vt220",
  "linux",
  "screen-256color",
  "tmux-256color",
] as const;
export type TermType = (typeof TERM_TYPES)[number];
export type SyncConflict = "newest_wins" | "local_wins" | "server_wins";

/** A regex watched on terminal output with what to do on a match. */
export interface Trigger {
  id: Uuid;
  name: string;
  /** JavaScript regex source, tested against ANSI-stripped output. */
  pattern: string;
  enabled: boolean;
  notify: boolean;
  highlight: boolean;
  /** Typed into the session on a match (`\n` = Enter). */
  reply?: string | null;
}

export interface Settings {
  theme: ThemeMode;
  /** UI language; `system` follows the OS locale. */
  language: Language;
  hostsView: HostsView;
  forwardingView: HostsView;
  keychainView: HostsView;
  terminalFontSize: number;
  terminalFontFamily: string;
  /** Line height multiplier (1.0 = natural). */
  terminalLineHeight: number;
  /** Colour scheme id; `auto` follows `theme` with Termoso Dark / Light. */
  terminalTheme: string;
  cursorBlink: boolean;
  cursorStyle: CursorStyle;
  scrollback: number;
  copyOnSelect: boolean;
  pasteOnRightClick: boolean;
  confirmCloseTab: boolean;
  confirmPasteMultiline: boolean;
  autocomplete: boolean;
  /** Install OSC 133 prompt markers into bash / zsh / fish after connecting. */
  shellIntegration: boolean;
  /** Output triggers: regexes watched on every terminal. */
  triggers: Trigger[];
  /** Command a workspace pane was running when saved: put on the prompt, run, or dropped. */
  restoreCommands: RestoreCommands;
  terminalBell: boolean;
  brightBold: boolean;
  termType: TermType;
  autoReconnect: boolean;
  keywordHighlight: boolean;
  /** Program (+ args) for local terminals; empty = login shell. */
  localShell: string;
  keepAliveSeconds: number;
  /** Probe the OS after the first successful connection to pick the host icon. */
  detectOs: boolean;
  /** Offer hybrid ML-KEM-768 + X25519 key exchange. */
  postQuantumKex: boolean;
  /** Offer keys from the system SSH agent (SSH_AUTH_SOCK / Pageant) when authenticating. */
  useSshAgent: boolean;
  /** Run Termoso's own SSH agent serving vault keys to local ssh/git. */
  serveSshAgent: boolean;
  /** Confirm every signature the agent makes. */
  agentConfirm: boolean;
  /** Claim and execute team automations on this computer. */
  runAutomations: boolean;
  recordSessions: boolean;
  logRetentionDays: number;
  /** Relock a password-protected vault after this many idle minutes; 0 = never. */
  lockAfterMinutes: number;
  autostartForwarding: boolean;
  /** Closing the window hides it to the tray; sessions and forwards keep running. */
  minimizeToTray: boolean;
  syncConflict: SyncConflict;
  syncIntervalSeconds: number;
  uploadLogs: boolean;
  /** Sync identities, keys and certificates of the Personal vault; off keeps them on this device. */
  syncCredentials: boolean;
  updateCheck: UpdateCheck;
  /** Release feed URL; empty = project default. */
  updateUrl: string;
  /** Start-up sign-in screen was dismissed with "Continue offline". */
  welcomeSeen: boolean;
  /** Master switch for system notifications. */
  notifications: boolean;
  /** A command finished in a tab that was not in front. */
  notifyCommands: boolean;
  /** Only commands that ran at least this long are reported; 0 = every one. */
  notifyCommandSeconds: number;
  /** A transfer finished or failed while the SFTP tab was not in front. */
  notifyTransfers: boolean;
  /** SFTP transfer speed limit in KiB/s per transfer; 0 is unlimited. */
  sftpRateLimitKib: number;
  /** A live session was dropped by the network / server. */
  notifySessions: boolean;
  /** Shared vault access, someone joined a shared terminal, remote sign-out. */
  notifyAccount: boolean;
  /** Shortcut overrides: command id → chord (`ctrl+shift+k`), `""` = unbound. */
  shortcuts: Record<string, string>;
  /** SFTP “Open with” associations: lower-case extension (`""` = none) → app. */
  sftpOpenWith: Record<string, string>;
}

export type UpdateCheck = "manual" | "startup";

export type RestoreCommands = "type" | "run" | "never";

export interface UpdateInfo {
  currentVersion: string;
  version: string;
  notes: string | null;
  publishedAt: string | null;
  downloadUrl: string;
  target: string;
}

export type UpdateEvent =
  | { type: "available"; info: UpdateInfo }
  | { type: "progress"; downloaded: number; total: number | null }
  | { type: "installed"; version: string }
  | { type: "failed"; message: string };

export type LocalVaultKind = "local" | "personal" | "team";
export type VaultRole = "viewer" | "editor" | "manager";

export interface LocalVault {
  id: Uuid;
  kind: LocalVaultKind;
  name: string;
  team_id: Uuid | null;
  role: VaultRole;
  unlocked: boolean;
  key_version: number;
  cursor: number;
  /** Team vault: the manager turned on recording of every member's sessions. */
  session_logging: boolean;
  logs_cursor: number;
  /** Team vault: the team's first vault. It can be renamed but not deleted. */
  is_default: boolean;
}

/** Member of a team vault as the server sees it. */
export interface VaultMember {
  user_id: Uuid;
  email: string;
  display_name?: string | null;
  avatar?: string | null;
  role: VaultRole;
  key_version: number;
  pending: boolean;
}

export type TeamRole = "member" | "admin" | "owner";

export interface Team {
  id: Uuid;
  name: string;
  created_at: string;
  my_role: TeamRole;
  member_count: number;
  multiplayer_enabled: boolean;
  require_mfa: boolean;
  /** Members can see who is connected to which team-vault host right now. */
  presence_enabled: boolean;
  /** Fine-grained role (0.9.0+ servers). */
  my_role_ref?: { id: Uuid; slug: string; name: string } | null;
  /** Permission keys the caller holds; `*` for the owner. Absent on 0.8 servers. */
  my_permissions?: string[];
  policies?: TeamPolicies | null;
}

export interface TeamPolicies {
  mfa: "off" | "any" | "passkey";
  /** `deny` = device-local identities must not be used for this team's hosts (client-enforced). */
  local_keys: "allow" | "deny";
  session_ttl_hours: number | null;
  sso_only: boolean;
  sso_provider: string | null;
  sso_domains: string[];
  device_approval: boolean;
  audit_retention_days: number;
  /** `required` forces recording in every team vault. */
  session_recording: "optional" | "required";
  /** Days recordings are kept; 0 = forever. */
  log_retention_days: number;
  key_max_age_days: number;
  password_max_age_days: number;
  ip_allowlist: string[];
  device_admin_approval: boolean;
  /** `keys_only` = no password / keyboard-interactive auth for team hosts (client-enforced). */
  auth: "any" | "keys_only";
  /** Team hosts must be reached through a jump host (client-enforced). */
  jump_host_required: boolean;
  /** `deny` = no local export/backup of team vault data (client-enforced). */
  export: "allow" | "deny";
  /** `deny` = no offline copies of files read from team hosts (client-enforced). */
  offline_cache: "allow" | "deny";
  /** Remote ports members may forward from team hosts (`22`, `8000-8999`); empty = any. */
  forward_ports: string[];
  /** Sign-in requires the device to prove disk encryption / a screen lock / a hardware-backed key. */
  posture_disk_encryption: boolean;
  posture_screen_lock: boolean;
  posture_secure_key: boolean;
  updated_at: string;
}

/** What a client reported about its own device; `null` facts could not be determined. */
export interface Posture {
  os_version: string;
  disk_encryption?: boolean | null;
  screen_lock?: boolean | null;
  secure_key_storage?: boolean | null;
}

/** One open connection of a device to a team-vault host (routing metadata only). */
export interface PresenceSession {
  vault_id: Uuid;
  host_id: Uuid;
  /** `ssh`, `mosh`, `telnet`, `sftp` or `forward`. */
  protocol: string;
  since: string;
}

/** One device of one teammate and what it is connected to. */
export interface PresenceEntry {
  user_id: Uuid;
  email: string;
  display_name?: string | null;
  avatar?: string | null;
  device_id: Uuid;
  device_name: string;
  platform: string;
  sessions: PresenceSession[];
  seen_at: string;
}

export interface TeamPresence {
  enabled: boolean;
  entries: PresenceEntry[];
}

/** Server-side account profile (`GET /account`). */
export interface UserProfile {
  id: Uuid;
  email: string;
  email_verified: boolean;
  display_name?: string | null;
  created_at: string;
  is_admin: boolean;
  mfa_enabled: boolean;
  reset_scheduled_for?: string | null;
  /** Teammates never see which hosts this user is connected to. */
  presence_hidden: boolean;
  avatar?: string | null;
}

/** `GET /account/ai`: what the server offers and whether this account opted in. */
export interface AiStatus {
  /** The server has a model configured at all. */
  available: boolean;
  /** This account opted in. */
  enabled: boolean;
  provider: string | null;
  model: string | null;
  /** The model runs in confidential compute (TEE): the operator cannot read prompts. */
  confidential: boolean;
  daily_quota: number;
  used_today: number;
}

/** One suggestion; text for the user to read and paste, never executed here. */
export interface AiCommandResponse {
  /** Empty when the model declined (see `explanation`). */
  command: string;
  explanation: string | null;
  remaining_today: number;
}

export interface TeamMember {
  user_id: Uuid;
  email: string;
  display_name: string | null;
  avatar?: string | null;
  role: TeamRole;
  joined_at: string;
  /** Second factor enrolled; only admins and the member themself see it. */
  mfa_enabled?: boolean | null;
  /** Account was created through this team's invitation; the owner may delete it. */
  managed: boolean;
}

export interface TeamInvite {
  id: Uuid;
  email: string;
  role: TeamRole;
  invited_by: Uuid;
  created_at: string;
  expires_at: string;
}

export interface InviteResult {
  email: string;
  invite: TeamInvite | null;
  url: string | null;
  error: string | null;
}

/** Team-vault member still waiting for a manager to hand them the key. */
export interface PendingVaultKey {
  vault_id: Uuid;
  user_id: Uuid;
  role: VaultRole;
}

export interface VaultAccess {
  userId: Uuid;
  role: VaultRole;
}

/** One row of the team activity log (metadata only, never secrets). */
export interface AuditEvent {
  id: number;
  team_id: Uuid;
  actor_id?: Uuid;
  actor_email?: string;
  actor_name?: string;
  actor_avatar?: string;
  device_id?: Uuid;
  action: string;
  vault_id?: Uuid;
  target_user?: Uuid;
  target_email?: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface AuditPage {
  events: AuditEvent[];
  next_before: number | null;
}

export interface AuditFilter {
  before?: number;
  limit?: number;
  /** Exact action, or a prefix ending in `.` (e.g. `vault.`). */
  action?: string;
  actor?: Uuid;
  vault?: Uuid;
}

export interface HostCard {
  id: Uuid;
  vaultId: Uuid;
  label: string;
  address: string;
  groupId: Uuid | null;
  groupPath: string[];
  /** Primary protocol: `ssh` unless the host is Telnet-only. */
  protocol: HostProtocol;
  /** Effective username of the primary protocol. */
  username: string;
  /** Effective port of the primary protocol. */
  port: number;
  /** Effective Telnet port when the host also has a Telnet section. */
  telnetPort: number | null;
  /** Collection URL when the host has a WebDAV section. */
  webdavUrl: string | null;
  /** The SSH section connects over Mosh by default. */
  useMosh: boolean;
  tags: string[];
  osName: string | null;
  /** User-chosen icon id or `custom:data:`; overrides `osName`. */
  icon: string | null;
  ipVersion: IpVersion;
  notes: string;
  sortOrder: number;
  updatedAt: string;
  lastConnected: string | null;
  /** Provider the host was imported from (`Amazon AWS`, `DigitalOcean`, `azure`). */
  cloudProvider: string | null;
  dirty: boolean;
}

export interface HostForm {
  id: Uuid | null;
  vaultId: Uuid;
  label: string;
  address: string;
  groupId: Uuid | null;
  /** The host has an SSH section (the SSH fields below belong to it). */
  ssh: boolean;
  port: number | null;
  username: string;
  password: string | null;
  /** TOTP secret (otpauth URI or base32); null keeps the stored one, "" clears it. */
  totpSecret: string | null;
  sshKeyId: Uuid | null;
  /** Certificate pinned here; null = the key's own certificate, if any. */
  sshCertificateId: Uuid | null;
  identityId: Uuid | null;
  /** Log in with the account's SSH ID passkeys. */
  sshId: boolean;
  /** Preferred SSH ID key type; null = ED25519 first. */
  sshIdKeyType: SshIdKeyType | null;
  tagIds: Uuid[];
  notes: string;
  osName: string | null;
  /** User-chosen icon id or `custom:data:`; null follows OS detection. */
  icon: string | null;
  ipVersion: IpVersion;
  agentForwarding: boolean;
  /** Trusted X11 forwarding to the local display. */
  forwardX11: boolean;
  startupSnippetId: Uuid | null;
  /** Shell integration override; null follows Settings → Terminal → Shell integration. */
  shellIntegration: boolean | null;
  hostChainId: Uuid | null;
  proxyId: Uuid | null;
  /** Gateway (API bridge in `termoso-bridge gateway` mode) to tunnel through; null = direct. */
  gatewayId: Uuid | null;
  /** MAC address for Wake-on-LAN; null = unknown. */
  macAddress: string | null;
  /** Telnet section, when the host is also (or only) reachable over Telnet. */
  telnet: TelnetForm | null;
  /** WebDAV section: a file share browsed from Files, next to or instead of SSH. */
  webdav: WebDavForm | null;
  envVariables: [string, string][];
  keepAliveInterval: number | null;
  timeout: number | null;
  /** Terminal colour scheme id; null follows the app setting. */
  colorScheme: string | null;
  /** Connect with Mosh (mosh-client bootstrapped over this SSH section). */
  useMosh: boolean;
  /** Custom `mosh-server` command; null runs the default. */
  moshServerCommand: string | null;
  hasPassword: boolean;
  hasTotp: boolean;
}

export interface TelnetForm {
  port: number | null;
  username: string;
  /** null keeps the stored password when editing; "" clears it. */
  password: string | null;
  identityId: Uuid | null;
  colorScheme: string | null;
  hasPassword: boolean;
}

export function emptyTelnetForm(): TelnetForm {
  return {
    port: null,
    username: "",
    password: null,
    identityId: null,
    colorScheme: null,
    hasPassword: false,
  };
}

export interface WebDavForm {
  /** TCP port; null = 443 (80 with `http`). */
  port: number | null;
  /** Collection path below the host's address (`/remote.php/dav/files/alice/`); "" = `/`. */
  path: string;
  /** Plain HTTP instead of HTTPS. */
  http: boolean;
  /** TLS name (SNI + certificate check) when it differs from the address. */
  tlsServerName: string | null;
  /** PEM bundle of a private CA to trust instead of the system roots. */
  caCertificate: string | null;
  username: string;
  /** null keeps the stored password when editing; "" clears it. */
  password: string | null;
  identityId: Uuid | null;
  /** Pinned SHA-256 of the server certificate (self-signed / private CA). */
  certificateFingerprint: string | null;
  hasPassword: boolean;
  /** `password` (Basic / Digest, negotiated) or `token` (Bearer). */
  auth: WebDavAuth;
  /** null keeps the stored token when editing; "" clears it. */
  bearerToken: string | null;
  hasBearerToken: boolean;
  /** PEM certificate chain for mTLS; null keeps the stored pair, "" clears it. */
  clientCertificate: string | null;
  /** PEM private key for `clientCertificate`; null keeps the stored one. */
  clientKey: string | null;
  /** SHA-256 of the stored client certificate (read-only). */
  clientCertificateFingerprint: string | null;
}

export type WebDavAuth = "password" | "token";

export function emptyWebDavForm(): WebDavForm {
  return {
    port: null,
    path: "",
    http: false,
    tlsServerName: null,
    caCertificate: null,
    username: "",
    password: null,
    identityId: null,
    certificateFingerprint: null,
    hasPassword: false,
    auth: "password",
    bearerToken: null,
    hasBearerToken: false,
    clientCertificate: null,
    clientKey: null,
    clientCertificateFingerprint: null,
  };
}

/** Protocol of a host section. `webdav` is a file share, not a terminal. */
export type HostProtocol = "ssh" | "telnet" | "webdav";

/** Terminal protocols. */
export type TerminalProtocol = "ssh" | "telnet";

/** What `Connect ▸` offers: the sections plus Mosh, which rides on the SSH one. */
export type ConnectProtocol = TerminalProtocol | "mosh";

/** Terminal protocols a saved host can be opened with (empty for WebDAV-only hosts). */
export function hostProtocols(h: Pick<HostCard, "protocol" | "telnetPort">): TerminalProtocol[] {
  if (h.protocol === "telnet") return ["telnet"];
  if (h.protocol === "webdav") return [];
  return h.telnetPort === null ? ["ssh"] : ["ssh", "telnet"];
}

/** `hostProtocols` with Mosh slotted after SSH when the host has it enabled. */
export function connectProtocols(
  h: Pick<HostCard, "protocol" | "telnetPort" | "useMosh">,
): ConnectProtocol[] {
  return hostProtocols(h).flatMap((p) => (p === "ssh" && h.useMosh ? ["ssh", "mosh"] : [p]));
}

/** The host has an SSH section (so SFTP and port forwarding apply). */
export function hasSsh(h: Pick<HostCard, "protocol">): boolean {
  return h.protocol === "ssh";
}

/** The host has a WebDAV section browsable from Files. */
export function hasWebDav(h: Pick<HostCard, "protocol" | "webdavUrl">): boolean {
  return h.protocol === "webdav" || h.webdavUrl !== null;
}

export type IpVersion = "auto" | "4" | "6";

export type SerialParity = "none" | "odd" | "even";
export type SerialFlowControl = "none" | "software" | "hardware";

export interface SerialLine {
  baudRate: number;
  dataBits: 5 | 6 | 7 | 8;
  stopBits: 1 | 2;
  parity: SerialParity;
  flowControl: SerialFlowControl;
  /** WHATWG encoding label (`utf-8`, `koi8-r`, …); decoded/encoded in the core. */
  charset: string;
}

export const SERIAL_BAUD_RATES = [
  115200, 9600, 19200, 38400, 57600, 230400, 460800, 921600, 1200, 2400, 4800,
] as const;

/** Mirrors `termoso_core::serial::COMMON_CHARSETS`. */
export const SERIAL_CHARSETS: readonly { value: string; label: string }[] = [
  { value: "utf-8", label: "UTF-8" },
  { value: "iso-8859-1", label: "ISO-8859-1 (Latin-1)" },
  { value: "iso-8859-2", label: "ISO-8859-2 (Latin-2)" },
  { value: "iso-8859-15", label: "ISO-8859-15 (Latin-9)" },
  { value: "windows-1250", label: "Windows-1250" },
  { value: "windows-1251", label: "Windows-1251" },
  { value: "windows-1252", label: "Windows-1252" },
  { value: "koi8-r", label: "KOI8-R" },
  { value: "koi8-u", label: "KOI8-U" },
  { value: "gbk", label: "GBK" },
  { value: "gb18030", label: "GB18030" },
  { value: "big5", label: msg("Big5") },
  { value: "shift_jis", label: msg("Shift_JIS") },
  { value: "euc-jp", label: "EUC-JP" },
  { value: "euc-kr", label: "EUC-KR" },
];

export function defaultSerialLine(): SerialLine {
  return {
    baudRate: 115200,
    dataBits: 8,
    stopBits: 1,
    parity: "none",
    flowControl: "none",
    charset: "utf-8",
  };
}

/** A serial device found on this machine. */
export interface SerialPortInfo {
  path: string;
  kind: "usb" | "pci" | "bluetooth" | "unknown";
  manufacturer: string | null;
  product: string | null;
  serialNumber: string | null;
}

/** Raw `proxy` entity payload. */
/** `color_scheme` entity payload: a user colour scheme synced through the vault. */
export interface ColorSchemeData {
  name: string;
  background: string;
  foreground: string;
  cursor: string;
  /** `#rrggbbaa`; derived from the foreground when absent. */
  selection?: string | null;
  /** 16 ANSI colours in xterm order. */
  ansi: string[];
}

export interface ThemeImport {
  schemes: ColorSchemeData[];
  warnings: string[];
}

export interface ProxyData {
  kind: "socks4" | "socks5" | "http";
  host: string;
  port: number;
  /** Identity for proxy auth; wins over the inline username/password. */
  identity_id?: Uuid | null;
  username?: string | null;
  /** Not sent for SOCKS4 (the protocol has no password). */
  password?: string | null;
}

/** Raw `host_chain` entity payload. */
export interface HostChainData {
  label: string;
  host_ids: Uuid[];
}

export function emptyHostForm(vaultId: Uuid, groupId: Uuid | null): HostForm {
  return {
    id: null,
    vaultId,
    label: "",
    address: "",
    groupId,
    ssh: true,
    port: null,
    username: "",
    password: null,
    totpSecret: null,
    sshKeyId: null,
    sshCertificateId: null,
    identityId: null,
    sshId: false,
    sshIdKeyType: null,
    tagIds: [],
    notes: "",
    osName: null,
    icon: null,
    ipVersion: "auto",
    agentForwarding: false,
    forwardX11: false,
    startupSnippetId: null,
    shellIntegration: null,
    hostChainId: null,
    proxyId: null,
    gatewayId: null,
    macAddress: null,
    telnet: null,
    webdav: null,
    envVariables: [],
    keepAliveInterval: null,
    timeout: null,
    colorScheme: null,
    useMosh: false,
    moshServerCommand: null,
    hasPassword: false,
    hasTotp: false,
  };
}

export interface GroupNode {
  id: Uuid;
  vaultId: Uuid;
  label: string;
  parentId: Uuid | null;
  sortOrder: number;
  hostCount: number;
  groupCount: number;
  hasConfig: boolean;
  /** User-chosen icon id or `custom:data:`; null shows the default folder. */
  icon: string | null;
}

/** Group editor model: name, parent and the SSH defaults its hosts inherit. */
export interface GroupForm {
  id: Uuid | null;
  vaultId: Uuid;
  label: string;
  parentId: Uuid | null;
  /** User-chosen icon id or `custom:data:`; null shows the default folder. */
  icon: string | null;
  port: number | null;
  username: string;
  password: string | null;
  /** TOTP secret (otpauth URI or base32); null keeps the stored one, "" clears it. */
  totpSecret: string | null;
  sshKeyId: Uuid | null;
  /** Certificate pinned here; null = the key's own certificate, if any. */
  sshCertificateId: Uuid | null;
  identityId: Uuid | null;
  sshId: boolean;
  sshIdKeyType: SshIdKeyType | null;
  hasPassword: boolean;
  hasTotp: boolean;
  agentForwarding: boolean;
  forwardX11: boolean;
  hostChainId: Uuid | null;
  proxyId: Uuid | null;
  envVariables: [string, string][];
  keepAliveInterval: number | null;
  timeout: number | null;
}

export function emptyGroupForm(vaultId: Uuid, parentId: Uuid | null): GroupForm {
  return {
    id: null,
    vaultId,
    label: "",
    parentId,
    icon: null,
    port: null,
    username: "",
    password: null,
    totpSecret: null,
    sshKeyId: null,
    sshCertificateId: null,
    identityId: null,
    sshId: false,
    sshIdKeyType: null,
    hasPassword: false,
    hasTotp: false,
    agentForwarding: false,
    forwardX11: false,
    hostChainId: null,
    proxyId: null,
    envVariables: [],
    keepAliveInterval: null,
    timeout: null,
  };
}

/** What a host inherits from its group chain (placeholders in the editor). */
export interface Inherited {
  groupPath: string[];
  port: number | null;
  username: string | null;
  hasPassword: boolean;
  /** A TOTP secret is inherited (codes typed automatically). */
  hasTotp: boolean;
  sshKeyId: Uuid | null;
  sshKeyLabel: string | null;
  identityId: Uuid | null;
  identityLabel: string | null;
  sshId: boolean;
  agentForwarding: boolean;
  forwardX11: boolean;
  hostChainId: Uuid | null;
  proxyId: Uuid | null;
  keepAliveInterval: number | null;
  timeout: number | null;
  envVariables: [string, string][];
}

export interface TagInfo {
  id: Uuid;
  vaultId: Uuid;
  label: string;
  color: string | null;
  /** Hosts carrying the tag. */
  hosts: number;
}

export interface Entity<T> {
  id: Uuid;
  vault_id: Uuid;
  version: number;
  updated_at: string;
  dirty: boolean;
  data: T;
}

// ───────────────────────────── keychain ─────────────────────────────

/** Public metadata of an OpenSSH certificate attached to a key. */
export interface CertificateCard {
  /** `null` for an unsaved preview. */
  id: Uuid | null;
  certType: string;
  kind: string;
  keyId: string;
  serial: number;
  principals: string[];
  validAfter: string | null;
  validBefore: string | null;
  fingerprint: string;
  caFingerprint: string;
  caKeyType: string;
  validNow: boolean;
}

/** Public view of a stored key. Never carries private material. */
export interface KeyCard {
  id: Uuid;
  vaultId: Uuid;
  label: string;
  keyType: string;
  bits: number;
  fingerprint: string;
  publicKey: string;
  comment: string;
  encrypted: boolean;
  hasPassphrase: boolean;
  unreadable: boolean;
  /** Public half only: the system SSH agent holds the private key and signs. */
  agentBacked: boolean;
  usedBy: number;
  certificate: CertificateCard | null;
  certificateUnreadable: boolean;
  /** Set for FIDO2 security keys: the token signs, the vault keeps only the handle. */
  securityKey: SecurityKeyInfo | null;
  updatedAt: string;
  dirty: boolean;
}

export interface SkFlags {
  resident: boolean;
  userPresence: boolean;
  userVerification: boolean;
}

/** Public facts about a stored security-key handle; nothing here is secret. */
export interface SecurityKeyInfo {
  application: string;
  /** `null` while the handle is passphrase-protected and locked. */
  flags: SkFlags | null;
  credentialId: string | null;
}

export type SkAlgorithm = "ed25519" | "ecdsa_p256";

/** A FIDO2 authenticator plugged in right now. */
export interface Fido2Device {
  path: string;
  product: string;
  vendorId: number;
  productId: number;
  aaguid: string | null;
  pinSet: boolean | null;
  residentKeys: boolean;
  algorithms: SkAlgorithm[];
  versions: string[];
}

export interface Fido2GenerateForm {
  vaultId: Uuid;
  label: string;
  device: string | null;
  algorithm: SkAlgorithm;
  resident: boolean;
  userPresence: boolean;
  userVerification: boolean;
  pin: string | null;
  user: string | null;
  comment: string;
  passphrase: string | null;
  rememberPassphrase: boolean;
}

export interface Fido2LoadForm {
  vaultId: Uuid;
  device: string | null;
  pin: string;
  passphrase: string | null;
  rememberPassphrase: boolean;
}

/** Public half of pasted/picked private key text (editor preview; not stored). */
export interface KeyPreview {
  keyType: string;
  bits: number;
  fingerprint: string;
  publicKey: string;
  comment: string;
  /** A passphrase is required to import. */
  encrypted: boolean;
  /** PuTTY .ppk; converted to OpenSSH on import. */
  putty: boolean;
}

export type KeyAlgorithm =
  "ed25519" | { rsa: { bits: number } } | "ecdsa_p256" | "ecdsa_p384" | "ecdsa_p521";

export type ExportOutcome = "added" | "already_present";

export interface ExportToHostResult {
  outcome: ExportOutcome;
  hostLabel: string;
  /** `user@host:port` the key was installed for. */
  target: string;
}

/** A key held by the system SSH agent (public half only). */
export interface AgentKey {
  keyType: string;
  fingerprint: string;
  publicKey: string;
  comment: string;
  /** The agent holds a certificate for this key rather than the bare key. */
  certificate: boolean;
}

/** Public-only key whose private half lives in the SSH agent (KeePassXC, 1Password, ssh-add…). */
export interface AgentImportForm {
  vaultId: Uuid;
  /** Empty: the key's comment, else its fingerprint. */
  label: string;
  /** `type base64 [comment]` line. */
  publicKey: string;
  /** OpenSSH certificate for this key (`*-cert.pub`), verified before saving. */
  certificate: string | null;
}

/** Like `AgentImportForm`, but the `.pub` (and certificate) are read from disk inside Rust. */
export interface AgentImportFileForm {
  vaultId: Uuid;
  label: string;
  path: string;
  certificatePath: string | null;
}

export interface AgentKeys {
  available: boolean;
  error: string | null;
  keys: AgentKey[];
}

export interface GenerateKeyForm {
  vaultId: Uuid;
  label: string;
  algorithm: KeyAlgorithm;
  comment: string;
  passphrase: string | null;
  rememberPassphrase: boolean;
}

export interface ImportKeyForm {
  vaultId: Uuid;
  label: string;
  /** OpenSSH / PEM / PKCS#8 / PuTTY .ppk text. */
  privateKey: string;
  passphrase: string | null;
  rememberPassphrase: boolean;
  /** OpenSSH certificate for this key (`*-cert.pub`), verified before saving. */
  certificate: string | null;
}

/** Like `ImportKeyForm`, but the private key is read from `path` inside Rust. */
export interface ImportKeyFileForm {
  vaultId: Uuid;
  label: string;
  path: string;
  passphrase: string | null;
  rememberPassphrase: boolean;
  /** Pasted certificate text; ignored when `certificatePath` is set. */
  certificate: string | null;
  certificatePath: string | null;
}

export interface IdentityCard {
  id: Uuid;
  vaultId: Uuid;
  label: string;
  username: string;
  hasPassword: boolean;
  /** A TOTP secret is stored; one-time codes are typed automatically. */
  hasTotp: boolean;
  sshKeyId: Uuid | null;
  sshKeyLabel: string | null;
  /** Certificate pinned on the identity itself (`null` = the key's own). */
  sshCertificateId: Uuid | null;
  hasCertificate: boolean;
  sshId: boolean;
  sshIdKeyType: SshIdKeyType | null;
  updatedAt: string;
}

export interface IdentityForm {
  id: Uuid | null;
  vaultId: Uuid;
  label: string;
  username: string;
  /** `null` keeps the stored password; `""` clears it. */
  password: string | null;
  /** TOTP secret; `null` keeps the stored one, `""` clears it. */
  totpSecret: string | null;
  sshKeyId: Uuid | null;
  /** Explicit certificate; `null` falls back to the key's own certificate. */
  sshCertificateId: Uuid | null;
  sshId: boolean;
  sshIdKeyType: SshIdKeyType | null;
}

// ───────────────────────────── SSH ID ─────────────────────────────

/** Passkey families an SSH ID publishes (wire form of `SshIdKeyType`). */
export type SshIdKeyType = "ed25519" | "ecdsa" | "rsa" | "ecdsa_sk" | "ed25519_sk";

export const SSH_ID_KEY_TYPES: {
  value: SshIdKeyType;
  label: string;
  hint: string;
  hardware: boolean;
  /** Algorithm token of an `authorized_keys` line. */
  wire: string;
}[] = [
  {
    value: "ecdsa_sk",
    label: "ECDSA-SK",
    hint: "OpenSSH 8.4+",
    hardware: true,
    wire: "sk-ecdsa-sha2-nistp256@openssh.com",
  },
  {
    value: "ed25519_sk",
    label: "ED25519-SK",
    hint: "OpenSSH 8.2+",
    hardware: true,
    wire: "sk-ssh-ed25519@openssh.com",
  },
  {
    value: "ed25519",
    label: "ED25519",
    hint: "OpenSSH 6.5+",
    hardware: false,
    wire: "ssh-ed25519",
  },
  {
    value: "ecdsa",
    label: "ECDSA",
    hint: msg("OpenSSH 5.7+"),
    hardware: false,
    wire: "ecdsa-sha2-nistp256",
  },
  { value: "rsa", label: "RSA", hint: msg("Legacy devices"), hardware: false, wire: "ssh-rsa" },
];

export const SSH_ID_DEFAULT_TYPE: SshIdKeyType = "ed25519";

export function sshIdTypeLabel(t: SshIdKeyType): string {
  return SSH_ID_KEY_TYPES.find((k) => k.value === t)?.label ?? t.toUpperCase();
}

/** One published key as the server lists it (snake_case: proto DTO). */
export interface SshIdKey {
  id: Uuid;
  key_type: SshIdKeyType;
  public_key: string;
  device_id: Uuid | null;
  label: string;
  current_device: boolean;
  updated_at: string;
}

export interface SshIdProfile {
  handle: string;
  url: string;
  created_at: string;
  keys: SshIdKey[];
}

export interface DeviceKeyCard {
  keyType: SshIdKeyType;
  fingerprint: string;
  publicKey: string;
  published: boolean;
}

export interface SshIdView {
  signedIn: boolean;
  profile: SshIdProfile | null;
  deviceKeys: DeviceKeyCard[];
  provisionCommand: string | null;
  /** Handles are published at `<baseUrl>/<handle>`; known before one is claimed. */
  baseUrl: string | null;
}

export interface SshIdFido2Form {
  label: string;
  device: string | null;
  algorithm: SkAlgorithm;
  resident: boolean;
  userPresence: boolean;
  userVerification: boolean;
  pin: string | null;
  user: string | null;
  comment: string;
}

// ───────────────────────────── port forwarding ─────────────────────────────

export type PfKind = "local" | "remote" | "dynamic";
export type PfState = "stopped" | "starting" | "running" | "reconnecting";

export interface PfRuntime {
  state: PfState;
  startedAt: string | null;
  bound: string | null;
  connections: number;
  active: number;
  bytesIn: number;
  bytesOut: number;
  lastError: string | null;
  /** Reconnect attempt number while `state === "reconnecting"`. */
  attempt: number;
  nextRetryAt: string | null;
}

export interface PfRuleCard {
  id: Uuid;
  vaultId: Uuid;
  label: string;
  hostId: Uuid;
  hostLabel: string;
  kind: PfKind;
  boundAddress: string;
  localPort: number;
  remoteHost: string;
  remotePort: number;
  autoStart: boolean;
  updatedAt: string;
  runtime: PfRuntime;
}

export interface PfRuleForm {
  id: Uuid | null;
  vaultId: Uuid;
  label: string;
  hostId: Uuid;
  kind: PfKind;
  boundAddress: string;
  localPort: number;
  remoteHost: string;
  remotePort: number;
  autoStart: boolean;
}

export interface ForwardEvent {
  type: "changed";
  id: Uuid;
  runtime: PfRuntime;
}

// ───────────────────────────── snippets ─────────────────────────────

export interface SnippetCard {
  id: Uuid;
  vaultId: Uuid;
  label: string;
  script: string;
  packageId: Uuid | null;
  closeAfterRun: boolean;
  sortOrder: number;
  variables: string[];
  /** Hosts the snippet is configured to run on, in execution order. */
  targetHostIds: Uuid[];
  updatedAt: string;
  dirty: boolean;
}

export interface SnippetForm {
  id: Uuid | null;
  vaultId: Uuid;
  label: string;
  script: string;
  packageId: Uuid | null;
  closeAfterRun: boolean;
  sortOrder: number;
}

export interface PackageNode {
  id: Uuid;
  vaultId: Uuid;
  label: string;
  parentId: Uuid | null;
  snippetCount: number;
}

export interface RunResult {
  sessionIds: Uuid[];
  closeAfterRun: boolean;
}

// ───────────────────────────── known hosts ─────────────────────────────

export interface KnownHostCard {
  id: Uuid;
  vaultId: Uuid;
  hostname: string;
  keyType: string;
  fingerprint: string;
  publicKey: string;
  updatedAt: string;
}

export interface ImportReport {
  added: number;
}

/** A server key pinned for one `host:port`; team-vault pins sync to every member. */
export interface HostKeyPin {
  id: Uuid;
  vaultId: Uuid;
  keyType: string;
  fingerprint: string;
  /** `<type> <base64>` */
  publicKey: string;
}

// ───────────────────────────── import (ssh_config / PuTTY / CSV) ─────────────────────────────

export type ImportSource =
  | "ssh_config"
  | "putty"
  | "csv"
  | "mobaxterm"
  | "securecrt"
  | "zoc"
  | "winscp"
  | "royalts"
  | "iterm2"
  | "tabby"
  | "xshell";

export interface ImportedProxy {
  kind: string;
  host: string;
  port: number;
  username: string;
  /** The password itself never reaches the UI. */
  hasPassword: boolean;
}

export interface ImportedHost {
  label: string;
  address: string;
  protocol: string;
  port: number | null;
  username: string;
  hasPassword: boolean;
  groupPath: string[];
  tags: string[];
  keyPath: string | null;
  jumpHosts: string[];
  proxy: ImportedProxy | null;
  agentForwarding: boolean;
  forwardX11: boolean;
  envVariables: [string, string][];
  keepAliveInterval: number | null;
  timeout: number | null;
  notes: string;
  warnings: string[];
}

export interface ImportedKey {
  path: string;
  name: string;
  keyType: string;
  bits: number;
  fingerprint: string;
  encrypted: boolean;
  publicKey: string;
  /** A lone `.pub`: stored as an agent-backed key, no private material. */
  agentBacked: boolean;
}

export interface ImportedKnownHost {
  hostname: string;
  keyType: string;
  fingerprint: string;
  line: string;
}

export interface ImportedPfRule {
  hostLabel: string;
  kind: PfKind;
  boundAddress: string;
  localPort: number;
  remoteHost: string;
  remotePort: number;
}

/** Parsed source; nothing is written until `importApply` with a selection. */
export interface ImportPreview {
  id: Uuid;
  source: ImportSource;
  origin: string;
  hosts: ImportedHost[];
  keys: ImportedKey[];
  knownHosts: ImportedKnownHost[];
  pfRules: ImportedPfRule[];
  warnings: string[];
}

/** Indexes into the preview lists. */
export interface ImportSelection {
  hosts: number[];
  keys: number[];
  knownHosts: number[];
  pfRules: number[];
}

// ───────────────────────────── cloud integration ─────────────────────────────

export type CloudProvider = "aws" | "digital_ocean" | "azure";
export type AwsService = "ec2" | "lightsail";
export type CloudAddressType = "public" | "private";

/**
 * Provider credentials for a single discovery call. They travel to Rust once,
 * are used for the API request and dropped; nothing in them is stored or
 * echoed back.
 */
export type CloudConfig =
  | {
      provider: "aws";
      region: string;
      access_key_id: string;
      secret_access_key: string;
      service: AwsService;
      address_type: CloudAddressType;
    }
  | { provider: "digital_ocean"; token: string }
  | { provider: "azure"; tenant_id: string; client_id: string; client_secret: string };

/** What would happen to a discovered machine on import. */
export type CloudAction = "new" | "update" | "no_address";

export interface CloudInstance {
  instanceId: string;
  label: string;
  address: string | null;
  state: string | null;
  region: string | null;
  size: string | null;
  os: string | null;
  osName: string | null;
  action: CloudAction;
  /** Host already linked to this machine (`action === "update"`). */
  hostId: Uuid | null;
}

export interface CloudPreview {
  id: Uuid;
  provider: CloudProvider;
  providerName: string;
  service: AwsService | null;
  addressType: CloudAddressType | null;
  instances: CloudInstance[];
}

export interface CloudSelection {
  /** Indexes into `CloudPreview.instances`. */
  instances: number[];
  groupId: Uuid | null;
  tagIds: Uuid[];
  /** SSH username for newly created hosts. */
  username: string;
  port: number | null;
  /** Delete hosts previously imported from this provider that are gone. */
  removeMissing: boolean;
}

export interface CloudImportReport {
  created: number;
  updated: number;
  unchanged: number;
  removed: number;
  skipped: number;
  warnings: string[];
}

// ───────────────────────────── cloud sync groups ─────────────────────────────

/**
 * What a group remembers about its cloud account. No secrets: those are
 * encrypted into local metadata by `cloud_sync_save` and never come back.
 */
export interface CloudSyncConfig {
  provider: CloudProvider;
  region?: string;
  service?: AwsService;
  addressType?: CloudAddressType;
  /** AWS key id — not secret, shown so the user knows which key is in use. */
  accessKeyId?: string;
  tenantId?: string;
  clientId?: string;
  username: string;
  port: number | null;
  tagIds: Uuid[];
  removeMissing: boolean;
  /** Background refresh period in minutes; `0` = only on “Sync now”. */
  intervalMinutes: number;
  enabled: boolean;
}

/** Provider secret for `cloud_sync_save`; `null` keeps the stored one. */
export interface CloudSyncSecret {
  secretAccessKey?: string;
  token?: string;
  clientSecret?: string;
}

export interface CloudSyncStatus {
  lastRun?: string;
  lastSuccess?: string;
  errorKind?: string;
  error?: string;
  report?: CloudImportReport;
  instances: number;
}

export interface CloudSyncGroup {
  groupId: Uuid;
  vaultId: Uuid;
  label: string;
  config: CloudSyncConfig;
  status: CloudSyncStatus;
  /** A secret is stored on this device; synced groups elsewhere show as plain groups. */
  hasSecret: boolean;
  running: boolean;
  nextRun?: string;
}

export const CLOUD_SYNC_MIN_INTERVAL = 5;
export const CLOUD_SYNC_MAX_INTERVAL = 7 * 24 * 60;

// ───────────────────────────── local discovery (mDNS) ─────────────────────────────

export type LocalService = "ssh" | "sftp";

/** An SSH server advertised on the LAN. A candidate only — nothing is stored. */
export interface LocalDevice {
  name: string;
  hostname: string;
  /** IPv4 first, link-local last. */
  addresses: string[];
  port: number;
  services: LocalService[];
  txt?: Record<string, string>;
}

export type TailnetProvider = "tailscale" | "netbird" | "zerotier";

/** A machine the local Tailscale / NetBird / ZeroTier client knows. A candidate only. */
export interface TailnetDevice {
  provider: TailnetProvider;
  name: string;
  /** MagicDNS / NetBird FQDN, without trailing dot. */
  dnsName: string | null;
  /** Overlay addresses, IPv4 first. */
  addresses: string[];
  os: string | null;
  online: boolean;
  tags: string[];
  /** This machine itself. */
  thisDevice: boolean;
}

export interface TailnetProviderStatus {
  id: TailnetProvider;
  installed: boolean;
  /** CLI found but it failed (daemon down, logged out…). */
  error: string | null;
}

export interface TailnetScan {
  providers: TailnetProviderStatus[];
  devices: TailnetDevice[];
}

/** One host of a quiet snippet run (no terminal; `exec` channel). */
export interface QuietHostResult {
  hostId: Uuid;
  label: string;
  /** `user@host:port` the command ran on; empty when connecting failed. */
  target: string;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  /** Connection or transport error — the command never ran. */
  error: string | null;
  ms: number;
}

export interface QuietRun {
  runId: Uuid;
  command: string;
  results: QuietHostResult[];
}

export interface QuietProgress {
  runId: Uuid;
  result: QuietHostResult;
}

// ───────────────────────────── export / backup ─────────────────────────────

/** A bridge in `gateway` mode the account can tunnel through (`GET /gateways`). */
export interface GatewayInfo {
  id: Uuid;
  name: string;
  online: boolean;
  seen_at?: string | null;
  vault_ids: Uuid[];
}

export interface AccessReviewItem {
  id: Uuid;
  kind: string;
  user_id: Uuid;
  email?: string | null;
  display_name?: string | null;
  vault_id?: Uuid | null;
  vault_name?: string | null;
  role: string;
  last_seen_at?: string | null;
  decision?: "keep" | "remove" | null;
  decided_by?: Uuid | null;
  decided_at?: string | null;
  note?: string | null;
}

export interface AccessReview {
  id: Uuid;
  team_id: Uuid;
  status: string;
  opened_by?: Uuid | null;
  opened_at: string;
  due_at: string;
  closed_by?: Uuid | null;
  closed_at?: string | null;
  items: number;
  decided: number;
  kept: number;
  removed: number;
}

export interface AccessReviewList {
  reviews: AccessReview[];
}

export interface AccessReviewDetail {
  review: AccessReview;
  items: AccessReviewItem[];
}

export interface BreakGlass {
  user_id: Uuid;
  email?: string | null;
  duration_hours: number;
  created_by?: Uuid | null;
  created_at: string;
  status: string;
  used_at?: string | null;
  expires_at?: string | null;
  attempts: number;
  /** Only in the response to configuring: the one-time secret. */
  secret?: string | null;
}

export interface AuditVerification {
  ok: boolean;
  events: number;
  first_id?: number | null;
  last_id?: number | null;
  head_hash?: string | null;
  broken_at?: number | null;
  reason?: string | null;
  checkpoint_ok?: boolean | null;
}

export interface CsvExportReport {
  hosts: number;
  /** True when the file contains plaintext passwords. */
  passwordsIncluded: boolean;
  path: string;
}

export interface BackupVaultSummary {
  id: Uuid;
  kind: LocalVaultKind;
  name: string;
  entities: number;
  /** Count per entity kind, only kinds that are present. */
  counts: Record<string, number>;
}

export interface BackupSummary {
  /** Token for `backupRestore`; nil UUID when describing a fresh export. */
  previewId: Uuid;
  createdAt: string;
  appVersion: string;
  vaults: BackupVaultSummary[];
  path: string | null;
}

export interface RestoreReport {
  added: number;
  replaced: number;
  /** Entities whose id already lives in another vault; left untouched. */
  skipped: number;
  warnings: string[];
}

export interface ImportApplyReport {
  hosts: number;
  groups: number;
  tags: number;
  keys: number;
  knownHosts: number;
  pfRules: number;
  hostChains: number;
  proxies: number;
  /** Hosts already in the vault whose empty fields were filled in. */
  updatedHosts: number;
  skippedHosts: number;
  skippedKeys: number;
  warnings: string[];
}

// ───────────────────────────── session logs ─────────────────────────────

export interface LogCard {
  id: Uuid;
  vaultId: Uuid;
  hostId: Uuid | null;
  label: string;
  target: string;
  protocol: string;
  startedAt: string;
  endedAt: string | null;
  durationSecs: number | null;
  cols: number;
  rows: number;
  sizeBytes: number;
  cached: boolean;
  uploaded: boolean;
  completed: boolean;
  createdAt: string;
  bookmarks: number;
  /** Recorded by this account / device. */
  mine: boolean;
  /** Lives in a team vault (teammates see it too). */
  team: boolean;
  author: LogAuthor | null;
  pinned: boolean;
  note: string;
  noteBy: Uuid | null;
  canAnnotate: boolean;
  canDelete: boolean;
}

export interface LogAuthor {
  userId: Uuid;
  email: string;
  displayName: string | null;
  /** Picture tag for `userAvatar`. */
  avatar: string | null;
}

export interface BookmarkCard {
  id: Uuid;
  logId: Uuid;
  offset: number;
  note: string;
  updatedAt: string;
}

export interface LogBody {
  id: Uuid;
  text: string;
  bytes: number;
}

// ───────────────────────────── account / sync ─────────────────────────────

export interface AccountCard {
  serverUrl: string;
  userId: Uuid;
  email: string;
  displayName: string | null;
  /** Content tag of the profile picture; `null` when none. */
  avatar: string | null;
  isAdmin: boolean;
  deviceId: Uuid;
  signedInAt: string;
}

export type MfaMethod = "totp" | "webauthn" | "email" | "backup_code";

export type MfaCredential =
  | { method: "totp"; code: string }
  | { method: "backup_code"; code: string }
  | { method: "webauthn"; credential: unknown }
  | { method: "email"; code: string };

export type LoginOutcome =
  | { step: "done"; account: AccountCard }
  | { step: "mfaRequired"; methods: MfaMethod[] }
  | { step: "deviceApprovalRequired"; emailHint: string };

/** Step-up (`account_reauth_*`): the session is confirmed until `expiresAt`. */
export type ReauthOutcome =
  | { step: "done"; expiresAt: string }
  | { step: "mfaRequired"; methods: MfaMethod[] }
  | { step: "emailCodeRequired"; emailHint: string };

export interface Registered {
  account: AccountCard;
  /** Shown once; Rust never stores it. */
  recoveryPhrase: string;
}

export type SyncState = "idle" | "syncing" | "offline" | "error";

export interface SyncStatus {
  state: SyncState;
  realtime: boolean;
  lastSyncAt: string | null;
  lastError: string | null;
  pushed: number;
  pulled: number;
  conflicts: number;
}

export interface AccountStatus {
  account: AccountCard | null;
  pending: LoginOutcome | null;
  sync: SyncStatus;
  vaults: LocalVault[];
  /** Personal-vault credentials that exist only on this device (0 while credential sync is on). */
  localCredentials: number;
}

export type SyncNotice =
  | { kind: "status"; status: SyncStatus }
  | { kind: "entitiesChanged"; vaultId: Uuid }
  | { kind: "vaultsChanged" }
  | { kind: "historyChanged" }
  | { kind: "logsChanged" }
  | { kind: "accountChanged" }
  | { kind: "presenceChanged"; teamId: Uuid }
  | { kind: "signedOut" };

export interface LoginForm {
  serverUrl: string;
  email: string;
  password: string;
  /** Bind the identity verified by the SSO round trip started with `accountSsoStart`. */
  sso?: boolean;
  /** Turnstile token from the server's `/captcha` page after a `turnstile_required` error. */
  captcha?: string | null;
}

export interface RegisterForm {
  serverUrl: string;
  email: string;
  password: string;
  displayName: string | null;
  inviteToken: string | null;
  /** Bind the identity verified by the SSO round trip started with `accountSsoStart`. */
  sso?: boolean;
  /** Turnstile token from the server's `/captcha` page after a `turnstile_required` error. */
  captcha?: string | null;
}

export interface SsoStartForm {
  serverUrl: string;
  provider: string;
}

/** Where a browser-based SSO sign-in stands; the verified session itself stays in Rust. */
export type SsoOutcome =
  | { step: "pending" }
  | { step: "loginRequired"; email: string }
  | { step: "registrationRequired"; email: string; displayName: string | null }
  | { step: "failed"; message: string };

export type Platform = "windows" | "linux" | "macos" | "android" | "ios" | "web" | "cli";

export interface Device {
  id: Uuid;
  name: string;
  platform: Platform;
  app_version: string;
  created_at: string;
  last_seen_at: string;
  last_ip?: string | null;
  current: boolean;
  posture?: Posture | null;
  posture_at?: string | null;
}

export interface SsoProvider {
  id: string;
  name: string;
  kind: "oidc" | "saml";
}

export interface ServerInfo {
  /** Teams may configure their own IdP. */
  team_idp?: boolean;
  /** Corporate mode: password sign-in and sign-up are refused. */
  sso_only?: boolean;
  region?: string | null;
  home_team?: { id: Uuid; name: string } | null;
  name: string;
  version: string;
  registration_open: boolean;
  /** SSO-verified users may create an account even while registration is closed. */
  sso_registration: boolean;
  sso_providers: SsoProvider[];
  features: {
    personal_vaults?: boolean;
    session_logs: boolean;
    email: boolean;
    webauthn: boolean;
    teams: boolean;
  };
  max_entity_bytes: number;
  max_log_bytes: number;
  sshid_url: string;
}

export interface ConnectionHistory {
  host_id: Uuid | null;
  label: string;
  target: string;
  protocol: string;
  duration_secs: number | null;
  error: string | null;
}

/**
 * A past connection with the vault its saved host lives in today. `vault_id`
 * is `null` for quick connects, local shells and deleted hosts, which belong
 * to the local vault only.
 */
export interface VaultConnection extends HistoryItem<ConnectionHistory> {
  vault_id: Uuid | null;
}

/** A command line typed in a terminal (encrypted at rest; never the output). */
export interface CommandHistory {
  host_id: Uuid | null;
  command: string;
}

export interface HistoryItem<T> {
  id: Uuid;
  created_at: string;
  data: T;
}

export interface DirEntry {
  name: string;
  dir: boolean;
}

export type SessionState = "connecting" | "connected";

export interface SessionInfo {
  id: Uuid;
  protocol: "ssh" | "mosh" | "telnet" | "serial" | "local" | "multiplayer";
  title: string;
  target: string;
  hostId: Uuid | null;
  startedAt: string;
  state: SessionState;
  /** Negotiated SSH algorithms (null for telnet/local or before key exchange). */
  algorithms: SshAlgorithms | null;
  /** Jump hosts the connection went through, outermost first (`user@host:port`). */
  via: string[];
  /** Colour scheme configured on the host (or inherited); null follows the app setting. */
  colorScheme: string | null;
  /** Base name of the user's shell (`bash`, `zsh`, …) once known. */
  shell: string | null;
  /** The host's shell integration override; null follows the app setting. */
  shellIntegration: boolean | null;
}

export interface SshAlgorithms {
  kex: string;
  hostKey: string;
  cipher: string;
  mac: string;
}

/** Hybrid / post-quantum key exchanges announce themselves in the name. */
export function isPostQuantumKex(a: SshAlgorithms | null): boolean {
  return !!a && (a.kex.includes("mlkem") || a.kex.includes("sntrup"));
}

/** Stage of an SSH connection attempt (see `ConnectPhase` in termoso-core). */
export type ConnectPhase =
  | { kind: "resolving" }
  | { kind: "connecting"; via: string }
  | { kind: "handshake" }
  | { kind: "host_key" }
  | { kind: "auth"; method: string }
  | { kind: "security_key_touch"; key: string }
  | { kind: "authenticated" }
  | { kind: "mosh_server" };

export type SessionEvent =
  | { type: "connecting"; id: Uuid; info: SessionInfo }
  | { type: "connected"; id: Uuid; info: SessionInfo }
  | { type: "progress"; id: Uuid; hop: string | null; phase: ConnectPhase }
  | { type: "notice"; id: Uuid; message: string }
  | { type: "exit"; id: Uuid; code: number | null; signal: string | null }
  | { type: "error"; id: Uuid; message: string }
  | { type: "shell"; id: Uuid; shell: string }
  | { type: "closed"; id: Uuid }
  /** The remote started `sz` (receive) or `rz` (send); pick a folder / files. */
  | { type: "zmodem"; id: Uuid; kind: ZmodemKind }
  | {
      type: "zmodem_progress";
      id: Uuid;
      kind: ZmodemKind;
      name: string;
      done: number;
      total: number | null;
      files: number;
    }
  | { type: "zmodem_done"; id: Uuid; ok: boolean; files: number; error: string | null };

export type ZmodemKind = "receive" | "send";

export type OpenTarget =
  | {
      kind: "host";
      host_id: Uuid;
      /** Vault the host is expected to live in; the open fails if it lives elsewhere. */
      vault_id?: Uuid | null;
      /** Which section to open; defaults to SSH (or Mosh when enabled) when the host has one. */
      protocol?: ConnectProtocol | null;
    }
  | { kind: "serial"; path: string; line: SerialLine }
  | {
      kind: "quick";
      address: string;
      username?: string | null;
      port?: number | null;
      /** `ssh` (default) or `telnet`. */
      protocol?: "ssh" | "telnet" | null;
    }
  | { kind: "local" }
  /** Someone else's terminal, from a `termoso://join/…` multiplayer link. */
  | { kind: "live"; link: string };

// ───────────────────────────── multiplayer ─────────────────────────────

export interface LiveParticipant {
  userId: Uuid;
  email: string;
  displayName: string | null;
  avatar: string | null;
  isHost: boolean;
  /** Keystrokes of this person reach the shared terminal. */
  canWrite: boolean;
  isMe: boolean;
}

/** A shared (host) or watched (viewer) terminal tab. */
export interface ShareInfo {
  /** Local session (pane) id. */
  id: Uuid;
  liveId: Uuid;
  role: "host" | "viewer";
  /** Host only: the link to hand out. */
  link: string | null;
  participants: LiveParticipant[];
  /** Viewer: whether our keystrokes reach the host terminal. */
  canWrite: boolean;
}

export type LiveEvent =
  | { type: "participants"; id: Uuid; participants: LiveParticipant[] }
  | { type: "typing"; id: Uuid; user_id: Uuid }
  | { type: "control"; id: Uuid; canWrite: boolean }
  | { type: "resize"; id: Uuid; cols: number; rows: number }
  | { type: "title"; id: Uuid; title: string }
  | { type: "ended"; id: Uuid; reason: "stopped" | "disconnected" | "error"; message: string };

/** Split tree of a saved tab; leaves are connection targets. */
export type LayoutTemplate =
  | {
      kind: "leaf";
      target: OpenTarget;
      /** Working directory the shell reported (OSC 7) when the layout was saved. */
      cwd?: string | null;
      /** Command running (between the OSC 133 `C` and `D` marks) when saved. */
      command?: string | null;
    }
  | {
      kind: "split";
      direction: "row" | "column";
      ratio: number;
      first: LayoutTemplate;
      second: LayoutTemplate;
    };

export type TabViewMode = "split" | "list";

export interface WorkspaceTemplate {
  id: Uuid;
  name: string;
  viewMode: TabViewMode;
  layout: LayoutTemplate;
  createdAt: string;
  updatedAt: string;
}

export interface SnapshotTab {
  /** Workspace name; `null` for a plain session tab. */
  name: string | null;
  viewMode: TabViewMode;
  templateId: Uuid | null;
  layout: LayoutTemplate;
}

export interface SessionSnapshot {
  savedAt: string;
  tabs: SnapshotTab[];
}

export interface WorkspacesState {
  templates: WorkspaceTemplate[];
  lastSession: SessionSnapshot | null;
}

export interface HostKeyInfo {
  host: string;
  key_type: string;
  fingerprint: string;
  public_key: string;
}

export type HostKeyVerdict =
  | { status: "known" }
  | { status: "unknown"; key: HostKeyInfo }
  | { status: "changed"; old: HostKeyInfo; new: HostKeyInfo };

export interface Question {
  prompt: string;
  echo: boolean;
}

export type PromptRequest =
  | { kind: "host_key"; verdict: HostKeyVerdict }
  | { kind: "certificate"; host: string; fingerprint: string }
  | { kind: "username"; host: string; retry: boolean }
  | { kind: "password"; username: string; retry: boolean }
  | { kind: "passphrase"; key_label: string }
  | { kind: "pin"; key_label: string; retry: boolean; retries: number | null }
  | { kind: "interactive"; name: string; instructions: string; questions: Question[] }
  | { kind: "agent_sign"; key_label: string; fingerprint: string; process: string | null };

export type PromptEvent = { id: Uuid; session_id: Uuid; target: string } & PromptRequest;

export interface PromptClosedEvent {
  id: Uuid;
  session_id: Uuid;
}

export type PromptAnswer =
  | { kind: "host_key"; decision: "reject" | "accept_once" | "accept_and_save" }
  | { kind: "secret"; value: string; remember: boolean }
  | { kind: "interactive"; answers: string[] }
  | { kind: "confirm" }
  | { kind: "cancel" };

// ───────────────────────────── SFTP ─────────────────────────────

export type EntryKind = "dir" | "file" | "symlink" | "other";

/** A file on either side (Rust fills the same shape for local and remote). */
export interface FsEntry {
  name: string;
  path: string;
  kind: EntryKind;
  size: number | null;
  mode: number | null;
  uid: number | null;
  gid: number | null;
  user: string | null;
  group: string | null;
  mtime: number | null;
  atime: number | null;
  link_target: string | null;
  /** What a symlink points at; `null` for non-links and dangling links. */
  target_kind: EntryKind | null;
}

export interface Listing {
  path: string;
  parent: string | null;
  entries: FsEntry[];
}

export type SftpTarget =
  | { kind: "host"; host_id: Uuid; vault_id?: Uuid | null; sudo_password?: string | null }
  | { kind: "session"; session_id: Uuid }
  | { kind: "webdav"; host_id: Uuid; vault_id?: Uuid | null }
  /** Read-only view of the host's offline copies; no connection is made. */
  | { kind: "offline"; host_id: Uuid };

/** Per-host offline-copy settings (device-local). */
export interface FileCacheSettings {
  /** False when the team policy forbids offline copies for this host. */
  allowed: boolean;
  enabled: boolean;
  maxFileMib: number;
  maxTotalMib: number;
  includePaths: string[];
  excludePaths: string[];
}

export interface FileCacheHost {
  hostId: Uuid;
  label: string;
  files: number;
  bytes: number;
}

export interface FileCacheOverview {
  files: number;
  bytes: number;
  hosts: FileCacheHost[];
}

export type RemoteProtocol = "sftp" | "webdav";

/** What the remote side supports; the panel hides controls it cannot honour. */
export interface RemoteCapabilities {
  permissions: boolean;
  symlinks: boolean;
  ownership: boolean;
  serverCopy: boolean;
  resumeUpload: boolean;
}

export const SFTP_CAPABILITIES: RemoteCapabilities = {
  permissions: true,
  symlinks: true,
  ownership: true,
  serverCopy: false,
  resumeUpload: true,
};

export interface SftpInfo {
  id: Uuid;
  title: string;
  target: string;
  hostId: Uuid | null;
  protocol: RemoteProtocol;
  capabilities: RemoteCapabilities;
  home: string;
  startedAt: string;
}

export type SftpEvent = { type: "opened"; id: Uuid; info: SftpInfo } | { type: "closed"; id: Uuid };

export type Direction = "upload" | "download" | "relay";

/** What to do with files that already exist at the destination. */
export type Conflict = "replace" | "skip" | "rename" | "resume";

export interface TransferInfo {
  id: Uuid;
  sftpId: Uuid;
  /** Destination connection of a relay; `null` for uploads and downloads. */
  toSftpId: Uuid | null;
  direction: Direction;
  local: string;
  remote: string;
  conflict: Conflict;
  startedAt: string;
}

export type TransferEvent =
  | { type: "started"; id: Uuid; info: TransferInfo }
  | { type: "queued"; id: Uuid }
  | { type: "running"; id: Uuid }
  | { type: "paused"; id: Uuid }
  | {
      type: "progress";
      id: Uuid;
      done: number;
      total: number | null;
      files_done: number;
      files_total: number;
      files_skipped: number;
      current: string;
    }
  | { type: "finished"; id: Uuid; bytes: number; files_skipped: number }
  | { type: "failed"; id: Uuid; message: string }
  | { type: "cancelled"; id: Uuid };

/** A local folder watched; every save under it is uploaded to `remote` on `sftpId`. */
export interface SyncInfo {
  id: Uuid;
  sftpId: Uuid;
  local: string;
  remote: string;
  ignore: string[];
  deleteRemote: boolean;
  /** Also download files that change on the server. */
  twoWay: boolean;
  startedAt: string;
}

export interface SyncStats {
  uploaded: number;
  downloaded: number;
  bytes: number;
  removed: number;
  failed: number;
  pending: number;
  lastPath: string | null;
  lastAt: string | null;
  lastError: string | null;
}

/** One side of a file comparison; `sftpId: null` is this machine. */
export interface DiffSide {
  sftpId: Uuid | null;
  path: string;
}

export interface DiffLine {
  kind: "equal" | "insert" | "delete" | "skip";
  old: number | null;
  new: number | null;
  /** For `skip`: the number of unchanged lines left out. */
  text: string;
}

export interface DiffResult {
  same: boolean;
  binary: boolean;
  truncated: boolean;
  leftSize: number;
  rightSize: number;
  lines: DiffLine[];
}

export interface SyncCard {
  info: SyncInfo;
  stats: SyncStats;
}

export type SyncEvent =
  | { type: "started"; info: SyncInfo }
  | { type: "progress"; id: Uuid; stats: SyncStats }
  | { type: "stopped"; id: Uuid; reason: string | null };

/** A remote file opened locally; saves are uploaded back while it is open. */
export interface EditInfo {
  id: Uuid;
  sftpId: Uuid;
  remote: string;
  local: string;
  name: string;
  app: string | null;
  size: number | null;
  startedAt: string;
}

export type EditEvent =
  | { type: "opened"; id: Uuid; info: EditInfo }
  | { type: "uploading"; id: Uuid }
  | { type: "uploaded"; id: Uuid; bytes: number; at: string }
  | { type: "failed"; id: Uuid; message: string }
  | { type: "closed"; id: Uuid };

// ── team roles, policies, webhooks (0.9.0) ──

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

export type UpdateTeamPolicies = Partial<Omit<TeamPolicies, "updated_at">>;

export interface EffectivePolicies {
  mfa: MfaPolicy;
  mfa_team_id: string | null;
  mfa_satisfied: boolean;
  session_ttl_hours: number | null;
  local_keys_denied_by: string[];
  device_approval_by: string[];
  sso_provider: string | null; /** Teams whose policy forces session recording. */
  recording_required_by?: Uuid[];
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

// ── 0.9.1 enterprise ──

export interface SsoDiscoverResponse {
  provider?: SsoProvider | null;
  team_name?: string | null;
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
  available: boolean;
}

export type AclMode = "none" | "connect" | "read" | "edit";
export type AclPrincipalKind = "role" | "member" | "group";
export type AclEntityKind = "host" | "group";

export interface EntityAclRule {
  id: Uuid;
  vault_id: Uuid;
  entity_id: Uuid;
  entity_kind: AclEntityKind;
  principal_kind: AclPrincipalKind;
  role_id?: Uuid | null;
  user_id?: Uuid | null;
  group_name?: string | null;
  principal_name: string;
  mode: AclMode;
  updated_at: string;
}

export interface UpsertEntityAcl {
  entity_id: Uuid;
  entity_kind: AclEntityKind;
  principal_kind: AclPrincipalKind;
  role_id?: Uuid;
  user_id?: Uuid;
  group_name?: string;
  mode: AclMode;
}

export interface MyAclRule {
  vault_id: Uuid;
  entity_id: Uuid;
  entity_kind: AclEntityKind;
  mode: AclMode;
}

export type TeamDeviceStatus = "pending" | "approved" | "rejected";

export interface TeamDevice {
  device_id: Uuid;
  user_id: Uuid;
  user_email: string;
  name: string;
  platform: string;
  app_version?: string | null;
  last_seen_at: string;
  last_ip?: string | null;
  status: TeamDeviceStatus;
  decided_by?: Uuid | null;
  decided_at?: string | null;
  requested_at: string;
}

export interface TeamDeviceList {
  admin_approval: boolean;
  devices: TeamDevice[];
}

// ───────────────────────────── team SSH CA ─────────────────────────────

export interface TeamCa {
  team_id: Uuid;
  key_type: string;
  public_key: string;
  fingerprint: string;
  principals: string[];
  ttl_hours: number;
  extensions: string[];
  enabled: boolean;
  retired_public_key?: string | null;
  retired_until?: string | null;
  trusted_keys_url: string;
  active_certificates: number;
  created_at: string;
  rotated_at?: string | null;
  updated_at: string;
}

export interface UpdateTeamCaRequest {
  principals?: string[] | null;
  ttl_hours?: number | null;
  extensions?: string[] | null;
  enabled?: boolean | null;
}

export interface IssuedCertificate {
  id: Uuid;
  team_id: Uuid;
  user_id: Uuid;
  user_email: string;
  device_id?: Uuid | null;
  device_name?: string | null;
  serial: number;
  key_type: SshIdKeyType;
  key_fingerprint: string;
  key_id: string;
  principals: string[];
  valid_after: string;
  valid_before: string;
  revoked_at?: string | null;
  active: boolean;
  current_device: boolean;
  created_at: string;
}

export interface IssuedCertificateList {
  certificates: IssuedCertificate[];
}

/** This device's cached certificate for a team (termoso_core::ca::CachedCert). */
export interface LocalTeamCertificate {
  team_id: Uuid;
  certificate?: string | null;
  ca_public_key?: string | null;
  principals?: string[] | null;
  valid_after?: string | null;
  valid_before?: string | null;
  checked_at: string;
  refusal?: "no_ca" | "disabled" | "forbidden" | "error" | null;
}

export const CA_EXTENSIONS = [
  "permit-pty",
  "permit-port-forwarding",
  "permit-agent-forwarding",
  "permit-X11-forwarding",
  "permit-user-rc",
] as const;

export interface RotationDue {
  entity_id: Uuid;
  vault_id: Uuid;
  kind: string;
  secret_rotated_at?: string | null;
  age_days: number;
  job_id?: Uuid | null;
}

export type RotationJobStatus = "pending" | "running" | "done" | "failed" | "cancelled";

export interface RotationJob {
  id: Uuid;
  team_id: Uuid;
  vault_id: Uuid;
  entity_id: Uuid;
  entity_kind: string;
  status: RotationJobStatus;
  note: string;
  error?: string | null;
  requested_by: Uuid;
  requested_by_email: string;
  claimed_by?: Uuid | null;
  created_at: string;
  updated_at: string;
  finished_at?: string | null;
}

export interface RotationOverview {
  key_max_age_days: number;
  password_max_age_days: number;
  due: RotationDue[];
  jobs: RotationJob[];
}

export type AccessRole = "viewer" | "editor";
export type AccessRequestStatus =
  "pending" | "approved" | "denied" | "revoked" | "expired" | "cancelled";

export interface AccessRequest {
  id: Uuid;
  team_id: Uuid;
  vault_id: Uuid;
  vault_name: string;
  user_id: Uuid;
  user_email: string;
  role: AccessRole;
  hours: number;
  reason: string;
  status: AccessRequestStatus;
  decided_by?: Uuid | null;
  decided_at?: string | null;
  decision_note?: string | null;
  expires_at?: string | null;
  created_at: string;
}

export interface AccessRequestList {
  can_approve: boolean;
  requests: AccessRequest[];
}

export interface TeamDataStatus {
  region?: string | null;
  server_region?: string | null;
  created_at: string;
  deletion_scheduled_at?: string | null;
  deletion_requested_by?: Uuid | null;
  deletion_grace_days: number;
}

/** One server-side session recording row as stored (meta is ciphertext). */
export interface TeamSessionLog {
  id: Uuid;
  vault_id: Uuid;
  user_id: Uuid;
  author?: LogAuthor | null;
  meta: string;
  key_version: number;
  size_bytes: number;
  completed: boolean;
  created_at: string;
  seq: number;
  deleted: boolean;
  pinned: boolean;
  note: string;
  note_by?: Uuid | null;
}

export interface TeamLogList {
  logs: TeamSessionLog[];
  since: number;
  has_more: boolean;
}

export interface RotationRunResult {
  jobId: Uuid;
  status: "done" | "failed";
  hostsUpdated: string[];
  hostsFailed: [string, string][];
}

// ───────────────────────────── SSH agent (ours) ─────────────────────────────

export interface AgentServedKey {
  label: string;
  keyType: string;
  fingerprint: string;
}

export interface AgentSkippedKey {
  label: string;
  reason: string;
}

/** `agent_server_status`: Termoso's own agent serving vault keys. */
export interface AgentServerStatus {
  running: boolean;
  /** Socket path (Unix) or pipe name (Windows). */
  endpoint: string | null;
  /** Shell line pointing SSH_AUTH_SOCK at the agent. */
  exportHint: string | null;
  keys: AgentServedKey[];
  skipped: AgentSkippedKey[];
}

// ---- team automations ----------------------------------------------------

export const AUTOMATION_ALERT_ON = ["never", "failure", "always"] as const;
export type AutomationAlertOn = (typeof AUTOMATION_ALERT_ON)[number];
export const AUTOMATION_TIMEOUT_MIN = 10;
export const AUTOMATION_TIMEOUT_MAX = 3600;
export const AUTOMATION_HOSTS_MAX = 200;

export interface Automation {
  id: Uuid;
  team_id: Uuid;
  vault_id: Uuid;
  snippet_id: Uuid;
  name: string;
  host_ids: Uuid[];
  group_id: Uuid | null;
  schedule: string;
  timezone: string;
  enabled: boolean;
  timeout_secs: number;
  alert_on: AutomationAlertOn;
  alert_emails: string[];
  alert_admins: boolean;
  last_run_at: string | null;
  last_status: string | null;
  next_run_at: string | null;
  created_by: Uuid | null;
  created_at: string;
  updated_at: string;
}

export interface CreateAutomationRequest {
  vault_id: Uuid;
  snippet_id: Uuid;
  name: string;
  host_ids: Uuid[];
  group_id?: Uuid | null;
  schedule: string;
  timezone?: string | null;
  enabled?: boolean | null;
  timeout_secs?: number | null;
  alert_on?: AutomationAlertOn | null;
  alert_emails: string[];
  alert_admins?: boolean | null;
}

export interface UpdateAutomationRequest {
  snippet_id?: Uuid | null;
  name?: string | null;
  host_ids?: Uuid[] | null;
  /** `null` leaves the group alone; `[null]`-style clearing is not needed: pass `group_id: null` inside an object to clear. */
  group_id?: Uuid | null;
  schedule?: string | null;
  timezone?: string | null;
  enabled?: boolean | null;
  timeout_secs?: number | null;
  alert_on?: AutomationAlertOn | null;
  alert_emails?: string[] | null;
  alert_admins?: boolean | null;
}

export interface AutomationList {
  automations: Automation[];
}

export interface HostRunResult {
  host_id: Uuid;
  label: string;
  target: string;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  error: string | null;
  ms: number;
}

export type AutomationRunStatus =
  "pending" | "running" | "done" | "failed" | "missed" | "cancelled";

export interface HostOutcome {
  host_id: Uuid;
  ok: boolean;
}

export interface AutomationRun {
  id: Uuid;
  automation_id: Uuid;
  team_id: Uuid;
  vault_id: Uuid;
  status: AutomationRunStatus;
  scheduled_for: string;
  manual: boolean;
  claimed_by_device: Uuid | null;
  claimed_by_name: string | null;
  claimed_at: string | null;
  finished_at: string | null;
  hosts_total: number;
  hosts_failed: number;
  outcomes: HostOutcome[];
  /** Encrypted per-host results; the desktop opens them when the vault is unlocked. */
  sealed?: string | null;
  key_version?: number | null;
  /** Filled in locally from `sealed`; the server never sends it. */
  results: HostRunResult[];
  error: string | null;
  created_at: string;
}

export interface AutomationRunList {
  runs: AutomationRun[];
}
