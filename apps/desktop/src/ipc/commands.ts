// Thin typed wrappers over Tauri `invoke`. One function per Rust command.

import { invoke, Channel } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AccountStatus,
  AgentImportFileForm,
  AgentImportForm,
  AgentKeys,
  AgentServerStatus,
  AiCommandResponse,
  AiStatus,
  AppInfo,
  AuditFilter,
  AuditPage,
  BackupSummary,
  BookmarkCard,
  CertificateCard,
  CloudConfig,
  CloudImportReport,
  CloudPreview,
  CloudSelection,
  CloudSyncConfig,
  CloudSyncGroup,
  CloudSyncSecret,
  CommandHistory,
  Conflict,
  CsvExportReport,
  Device,
  DirEntry,
  Direction,
  EditEvent,
  SyncCard,
  SyncEvent,
  SyncInfo,
  EditInfo,
  Entity,
  ExportToHostResult,
  Fido2Device,
  Fido2GenerateForm,
  Fido2LoadForm,
  ForwardEvent,
  FsEntry,
  GenerateKeyForm,
  GroupForm,
  GroupNode,
  HistoryItem,
  HostCard,
  HostForm,
  HostKeyPin,
  IdentityCard,
  IdentityForm,
  ImportApplyReport,
  ImportKeyFileForm,
  ImportKeyForm,
  ImportPreview,
  ImportReport,
  ImportSelection,
  ImportSource,
  Inherited,
  InviteResult,
  KeyCard,
  KeyPreview,
  KnownHostCard,
  Listing,
  LiveEvent,
  LocalDevice,
  TailnetScan,
  LocalVault,
  LogBody,
  LogCard,
  LoginForm,
  LoginOutcome,
  MasterKeySource,
  MfaCredential,
  OpenTarget,
  PackageNode,
  PendingVaultKey,
  PermissionInfo,
  PfRuleCard,
  PfRuleForm,
  PfRuntime,
  PromptAnswer,
  PromptClosedEvent,
  PromptEvent,
  ReauthOutcome,
  RegisterForm,
  Registered,
  RestoreReport,
  RoleMapping,
  RunResult,
  SerialPortInfo,
  ServerInfo,
  SessionEvent,
  SessionInfo,
  Settings,
  SftpEvent,
  SftpInfo,
  SftpTarget,
  ShareInfo,
  SnippetCard,
  SnippetForm,
  SshIdFido2Form,
  SshIdView,
  SsoOutcome,
  SsoStartForm,
  SyncNotice,
  SyncStatus,
  TagInfo,
  Team,
  TeamInvite,
  TeamMember,
  TeamPoliciesResponse,
  TeamPresence,
  TeamRole,
  TeamRoleDef,
  TeamRoleList,
  ThemeImport,
  TransferEvent,
  TransferInfo,
  UpdateEvent,
  UpdateInfo,
  UpdateTeamPolicies,
  UserProfile,
  Uuid,
  VaultAccess,
  VaultConnection,
  VaultEvent,
  VaultMember,
  VaultRole,
  VaultStatus,
  Webhook,
  WebhookDelivery,
  WebhookKind,
  WorkspacesState,
  QuietProgress,
  QuietRun,
  IssuedCertificate,
  IssuedCertificateList,
  LocalTeamCertificate,
  TeamCa,
  UpdateTeamCaRequest,
} from "./types";
import type {
  AccessRequest,
  AccessRequestList,
  AccessRole,
  EntityAclRule,
  MyAclRule,
  RotationJob,
  RotationOverview,
  RotationRunResult,
  SsoDiscoverResponse,
  TeamDataStatus,
  TeamDeviceList,
  TeamIdpResponse,
  TeamLogList,
  UpdateTeamIdp,
  UpsertEntityAcl,
} from "./types";

export const appInfo = () => invoke<AppInfo>("app_info");
export const appQuit = () => invoke<null>("app_quit");

export const settingsGet = () => invoke<Settings>("settings_get");

// ───────────────────────────── master password / App Lock ─────────────────────────────

export const vaultStatus = () => invoke<VaultStatus>("vault_status");
export const vaultUnlock = (password: string) => invoke<VaultStatus>("vault_unlock", { password });
export const vaultLock = () => invoke<VaultStatus>("vault_lock");
export const vaultActivity = () => invoke<null>("vault_activity");
export const masterPasswordSet = (current: string | null, password: string) =>
  invoke<VaultStatus>("master_password_set", { current, password });
export const masterPasswordRemove = (current: string) =>
  invoke<VaultStatus>("master_password_remove", { current });
export const onVaultEvent = (cb: (e: VaultEvent) => void): Promise<UnlistenFn> =>
  listen<VaultEvent>("vault", (ev) => cb(ev.payload));
export const settingsSet = (settings: Settings) => invoke<Settings>("settings_set", { settings });

export const workspacesGet = () => invoke<WorkspacesState>("workspaces_get");
export const workspacesSet = (workspaces: WorkspacesState) =>
  invoke<WorkspacesState>("workspaces_set", { workspaces });

export const vaultsList = () => invoke<LocalVault[]>("vaults_list");
export const vaultDefault = () => invoke<LocalVault>("vault_default");

export const entitiesList = <T>(kind: string, vaultId?: Uuid | null) =>
  invoke<Entity<T>[]>("entities_list", { kind, vaultId: vaultId ?? null });
export const entitySave = <T>(kind: string, vaultId: Uuid, id: Uuid | null, data: T) =>
  invoke<Entity<T>>("entity_save", { kind, vaultId, id, data });
export const entityDelete = (id: Uuid) => invoke<null>("entity_delete", { id });

export const hostsList = (vaultId?: Uuid | null) =>
  invoke<HostCard[]>("hosts_list", { vaultId: vaultId ?? null });
export const hostForm = (id: Uuid) => invoke<HostForm>("host_form", { id });
export const hostSave = (form: HostForm) => invoke<HostCard>("host_save", { form });
export const webdavPemFile = (path: string) =>
  invoke<{ certificate: string; privateKey: string }>("webdav_pem_file", { path });
export const webdavClientIdentityInspect = (certificate: string, privateKey: string) =>
  invoke<string>("webdav_client_identity_inspect", { certificate, privateKey });
export const hostDelete = (id: Uuid) => invoke<null>("host_delete", { id });
export const hostsDelete = (ids: Uuid[]) => invoke<null>("hosts_delete", { ids });
export const hostDuplicate = (id: Uuid) => invoke<HostCard>("host_duplicate", { id });
export const hostsMove = (ids: Uuid[], groupId: Uuid | null) =>
  invoke<null>("hosts_move", { ids, groupId });
export const hostsCopyToVault = (
  ids: Uuid[],
  vaultId: Uuid,
  moveHosts: boolean,
  withCredentials = true,
) => invoke<Uuid[]>("hosts_copy_to_vault", { ids, vaultId, moveHosts, withCredentials });
export const hostInherited = (groupId: Uuid | null) =>
  invoke<Inherited>("host_inherited", { groupId });

export const groupsList = (vaultId?: Uuid | null) =>
  invoke<GroupNode[]>("groups_list", { vaultId: vaultId ?? null });
export const groupSave = (args: {
  vaultId: Uuid;
  id: Uuid | null;
  label: string;
  parentId: Uuid | null;
}) => invoke<GroupNode>("group_save", args);
export const groupForm = (id: Uuid) => invoke<GroupForm>("group_form", { id });
export const groupSaveForm = (form: GroupForm) => invoke<GroupNode>("group_save_form", { form });
export const groupDuplicate = (id: Uuid) => invoke<GroupNode>("group_duplicate", { id });
export const groupDelete = (id: Uuid, recursive = false) =>
  invoke<null>("group_delete", { id, recursive });

export const tagsList = (vaultId?: Uuid | null) =>
  invoke<TagInfo[]>("tags_list", { vaultId: vaultId ?? null });
export const tagUpdate = (id: Uuid, label: string, color: string | null) =>
  invoke<TagInfo>("tag_update", { id, label, color });
export const tagDelete = (id: Uuid) => invoke<null>("tag_delete", { id });
export const tagsMerge = (sources: Uuid[], target: Uuid) =>
  invoke<TagInfo>("tags_merge", { sources, target });

export const serialPorts = () => invoke<SerialPortInfo[]>("serial_ports");
export const localShells = () => invoke<string[]>("local_shells");

/** Register `termoso://` / `ssh://` / `telnet://` handlers for this user; returns the schemes now registered. */
export const deepLinksRegister = () => invoke<string[]>("deep_links_register");
/** Files passed on the command line at launch (file associations), reported once. */
export const launchFiles = () => invoke<string[]>("launch_files");
export const launchLinks = () => invoke<string[]>("launch_links");
export const zmodemReceive = (id: Uuid, dir: string) => invoke<null>("zmodem_receive", { id, dir });
export const zmodemSend = (id: Uuid, paths: string[]) => invoke<null>("zmodem_send", { id, paths });
export const zmodemCancel = (id: Uuid) => invoke<null>("zmodem_cancel", { id });

export const historyConnections = (limit = 50) =>
  invoke<VaultConnection[]>("history_connections", { limit });
export const historyCommands = (limit = 500) =>
  invoke<HistoryItem<CommandHistory>[]>("history_commands", { limit });
export const historyRecordCommand = (hostId: Uuid | null, command: string) =>
  invoke<Uuid | null>("history_record_command", { hostId, command });
export const historyDelete = (id: Uuid) => invoke<null>("history_delete", { id });
export const historyClearCommands = () => invoke<null>("history_clear_commands");
export const historyClearConnections = () => invoke<null>("history_clear_connections");

/** Directory listing as the session sees it (path completion). */
export const terminalListDir = (id: Uuid, cwd: string | null, path: string) =>
  invoke<DirEntry[]>("terminal_list_dir", { id, cwd, path });
/** Type a stored password (+ Enter) into the session; `null` = the host's own identity. */
export const terminalInsertPassword = (id: Uuid, identityId: Uuid | null) =>
  invoke<null>("terminal_insert_password", { id, identityId });
/** Label of the identity a saved-host session has a password for, if any. */
export const terminalHostIdentity = (id: Uuid) =>
  invoke<string | null>("terminal_host_identity", { id });

export const sessionsList = () => invoke<SessionInfo[]>("sessions_list");

function outputChannel(onOutput: (bytes: Uint8Array) => void) {
  const output = new Channel<ArrayBuffer | number[]>();
  output.onmessage = (msg) =>
    onOutput(msg instanceof ArrayBuffer ? new Uint8Array(msg) : Uint8Array.from(msg));
  return output;
}

export function terminalOpen(
  id: Uuid,
  target: OpenTarget,
  cols: number,
  rows: number,
  onOutput: (bytes: Uint8Array) => void,
) {
  const output = outputChannel(onOutput);
  return invoke<SessionInfo>("terminal_open", { id, target, cols, rows, output });
}

export const terminalAttach = (id: Uuid, onOutput: (bytes: Uint8Array) => void) =>
  invoke<null>("terminal_attach", { id, output: outputChannel(onOutput) });

export const terminalWrite = (id: Uuid, data: string) =>
  invoke<null>("terminal_write", { id, data });
export const terminalResize = (id: Uuid, cols: number, rows: number) =>
  invoke<null>("terminal_resize", { id, cols, rows });
export const terminalClose = (id: Uuid) => invoke<null>("terminal_close", { id });

export const promptAnswer = (id: Uuid, answer: PromptAnswer) =>
  invoke<boolean>("prompt_answer", { id, answer });

export const onSessionEvent = (cb: (e: SessionEvent) => void): Promise<UnlistenFn> =>
  listen<SessionEvent>("session", (ev) => cb(ev.payload));
export const onPrompt = (cb: (e: PromptEvent) => void): Promise<UnlistenFn> =>
  listen<PromptEvent>("prompt", (ev) => cb(ev.payload));
export const onPromptClosed = (cb: (e: PromptClosedEvent) => void): Promise<UnlistenFn> =>
  listen<PromptClosedEvent>("prompt-closed", (ev) => cb(ev.payload));

// ───────────────────────────── SFTP ─────────────────────────────

export const sftpSessionsList = () => invoke<SftpInfo[]>("sftp_sessions_list");
export const sftpOpen = (id: Uuid, target: SftpTarget) =>
  invoke<SftpInfo>("sftp_open", { id, target });
export const sftpClose = (id: Uuid) => invoke<null>("sftp_close", { id });
export const sftpList = (id: Uuid, path: string | null) =>
  invoke<Listing>("sftp_list", { id, path });
export const sftpStat = (id: Uuid, path: string) => invoke<FsEntry>("sftp_stat", { id, path });
export const sftpMkdir = (id: Uuid, path: string) => invoke<null>("sftp_mkdir", { id, path });
export const sftpRename = (id: Uuid, from: string, to: string) =>
  invoke<null>("sftp_rename", { id, from, to });
export const sftpRemove = (id: Uuid, path: string, recursive: boolean) =>
  invoke<null>("sftp_remove", { id, path, recursive });
export const sftpChmod = (id: Uuid, path: string, mode: number) =>
  invoke<null>("sftp_chmod", { id, path, mode });
/** Server-side copy (WebDAV `COPY`); only when `capabilities.serverCopy`. */
export const sftpCopy = (id: Uuid, from: string, to: string) =>
  invoke<null>("sftp_copy", { id, from, to });

export const localHome = () => invoke<string>("local_home");
export const localList = (path: string | null) => invoke<Listing>("local_list", { path });
export const localDrives = () => invoke<string[]>("local_drives");
export const localStat = (path: string) => invoke<FsEntry>("local_stat", { path });
export const localMkdir = (path: string) => invoke<null>("local_mkdir", { path });
export const localRename = (from: string, to: string) => invoke<null>("local_rename", { from, to });
export const localRemove = (path: string, recursive: boolean) =>
  invoke<null>("local_remove", { path, recursive });

export const transferStart = (args: {
  sftpId: Uuid;
  toSftpId?: Uuid | null;
  direction: Direction;
  local: string;
  remote: string;
  conflict?: Conflict;
  temp?: boolean;
}) => invoke<TransferInfo>("transfer_start", args);
export const transferProbe = (args: {
  sftpId: Uuid;
  toSftpId?: Uuid | null;
  direction: Direction;
  local: string;
  remote: string;
}) => invoke<FsEntry | null>("transfer_probe", args);
export const transferCancel = (id: Uuid) => invoke<boolean>("transfer_cancel", { id });
export const transferPause = (id: Uuid) => invoke<boolean>("transfer_pause", { id });
export const transferResume = (id: Uuid) => invoke<null>("transfer_resume", { id });
export const transferForget = (id: Uuid) => invoke<null>("transfer_forget", { id });
export const localOpen = (path: string, withApp: string | null) =>
  invoke<null>("local_open", { path, with: withApp });

const b64 = (s: string) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));

/** Staging area for files dropped from the OS (webviews hand over blobs). */
export const dropBegin = () => invoke<string>("drop_begin");
export const dropWrite = (dir: string, rel: string, chunk: Uint8Array, append: boolean) =>
  invoke<null>("drop_write", chunk, {
    headers: {
      "x-drop-dir": b64(dir),
      "x-drop-path": b64(rel),
      "x-drop-append": append ? "1" : "0",
    },
  });
export const dropMkdir = (dir: string, rel: string) => invoke<null>("drop_mkdir", { dir, rel });
export const dropAbort = (dir: string) => invoke<null>("drop_abort", { dir });

export const syncsList = () => invoke<SyncCard[]>("syncs_list");
export const syncStart = (args: {
  sftpId: Uuid;
  local: string;
  remote: string;
  ignore: string[];
  deleteRemote: boolean;
  uploadExisting: boolean;
}) => invoke<SyncInfo>("sync_start", args);
export const syncStop = (id: Uuid) => invoke<null>("sync_stop", { id });
export const onSyncEvent = (cb: (e: SyncEvent) => void): Promise<UnlistenFn> =>
  listen<SyncEvent>("sftp_sync", (ev) => cb(ev.payload));
export const editsList = () => invoke<EditInfo[]>("edits_list");
export const editOpen = (sftpId: Uuid, remote: string, withApp: string | null) =>
  invoke<EditInfo>("edit_open", { sftpId, remote, with: withApp });
export const editUploadNow = (id: Uuid) => invoke<null>("edit_upload_now", { id });
export const editClose = (id: Uuid) => invoke<null>("edit_close", { id });

export const onSftpEvent = (cb: (e: SftpEvent) => void): Promise<UnlistenFn> =>
  listen<SftpEvent>("sftp", (ev) => cb(ev.payload));
export const onTransferEvent = (cb: (e: TransferEvent) => void): Promise<UnlistenFn> =>
  listen<TransferEvent>("transfer", (ev) => cb(ev.payload));
export const onEditEvent = (cb: (e: EditEvent) => void): Promise<UnlistenFn> =>
  listen<EditEvent>("sftp_edit", (ev) => cb(ev.payload));

// ───────────────────────────── keychain ─────────────────────────────

export const keysList = (vaultId?: Uuid | null) =>
  invoke<KeyCard[]>("keys_list", { vaultId: vaultId ?? null });
export const keyGenerate = (form: GenerateKeyForm) => invoke<KeyCard>("key_generate", { form });
export const keyImport = (form: ImportKeyForm) => invoke<KeyCard>("key_import", { form });
/** USB HID enumeration of FIDO2 authenticators; local only. */
export const fido2Devices = () => invoke<Fido2Device[]>("fido2_devices");
/** Resolves after the token has been touched (or the operation timed out). */
export const fido2Generate = (form: Fido2GenerateForm) =>
  invoke<KeyCard>("fido2_generate", { form });
export const fido2LoadResident = (form: Fido2LoadForm) =>
  invoke<KeyCard[]>("fido2_load_resident", { form });
/** Private material is read from `path` inside Rust and never crosses IPC. */
export const keyImportFile = (form: ImportKeyFileForm) =>
  invoke<KeyCard>("key_import_file", { form });
/** Public-only key signed by the system SSH agent; no private material is ever stored. */
export const keyImportAgent = (form: AgentImportForm) =>
  invoke<KeyCard>("key_import_agent", { form });
export const keyImportAgentFile = (form: AgentImportFileForm) =>
  invoke<KeyCard>("key_import_agent_file", { form });
/** Public half of pasted private key text; nothing is stored. */
export const keyInspect = (text: string) => invoke<KeyPreview>("key_inspect", { text });
export const keyInspectFile = (path: string) => invoke<KeyPreview>("key_inspect_file", { path });
/** Parse + verify a certificate for preview; nothing is stored. */
export const certificateInspect = (text: string) =>
  invoke<CertificateCard>("certificate_inspect", { text });
export const certificateInspectFile = (path: string) =>
  invoke<CertificateCard>("certificate_inspect_file", { path });
export const keyCertificate = (id: Uuid) => invoke<string | null>("key_certificate", { id });
/** `null` detaches the certificate. */
export const keySetCertificate = (id: Uuid, certificate: string | null) =>
  invoke<KeyCard>("key_set_certificate", { id, certificate });
export const keySetCertificateFile = (id: Uuid, path: string) =>
  invoke<KeyCard>("key_set_certificate_file", { id, path });
export const keyCopyToVault = (id: Uuid, vaultId: Uuid, moveKey: boolean) =>
  invoke<KeyCard>("key_copy_to_vault", { id, vaultId, moveKey });
export const keyRename = (id: Uuid, label: string) => invoke<KeyCard>("key_rename", { id, label });
export const keyChangePassphrase = (args: {
  id: Uuid;
  current: string | null;
  next: string | null;
  remember: boolean;
}) => invoke<KeyCard>("key_change_passphrase", args);
export const keyRememberPassphrase = (id: Uuid, passphrase: string | null) =>
  invoke<KeyCard>("key_remember_passphrase", { id, passphrase });
export const keyPublic = (id: Uuid) => invoke<string>("key_public", { id });
/** Returns private key text; only call on explicit user action. */
export const keyExport = (args: {
  id: Uuid;
  passphrase: string | null;
  exportPassphrase: string | null;
}) => invoke<string>("key_export", args);
export const keyExportFile = (args: {
  id: Uuid;
  path: string;
  passphrase: string | null;
  exportPassphrase: string | null;
}) => invoke<null>("key_export_file", args);
/** ssh-copy-id: append the public key to ~/.ssh/authorized_keys on a saved host. */
export const keyExportToHost = (id: Uuid, hostId: Uuid) =>
  invoke<ExportToHostResult>("key_export_to_host", { id, hostId });
export const agentKeys = () => invoke<AgentKeys>("agent_keys");
/** Our own agent (serves vault keys to local tools). */
export const agentServerStatus = () => invoke<AgentServerStatus>("agent_server_status");
export const agentServerRefresh = () => invoke<AgentServerStatus>("agent_server_refresh");
export const keyDelete = (id: Uuid) => invoke<null>("key_delete", { id });

export const identitiesList = (vaultId?: Uuid | null) =>
  invoke<IdentityCard[]>("identities_list", { vaultId: vaultId ?? null });
export const identitySave = (form: IdentityForm) => invoke<IdentityCard>("identity_save", { form });
export const identityDelete = (id: Uuid) => invoke<null>("identity_delete", { id });
export const identityCopyToVault = (id: Uuid, vaultId: Uuid, moveIdentity: boolean) =>
  invoke<IdentityCard>("identity_copy_to_vault", { id, vaultId, moveIdentity });

export const masterKeyMigrate = () => invoke<MasterKeySource>("master_key_migrate");

// ───────────────────────────── port forwarding ─────────────────────────────

export const pfRules = (vaultId?: Uuid | null) =>
  invoke<PfRuleCard[]>("pf_rules", { vaultId: vaultId ?? null });
export const pfRuntimes = () => invoke<Record<Uuid, PfRuntime>>("pf_runtimes");
export const pfSave = (form: PfRuleForm) => invoke<PfRuleCard>("pf_save", { form });
export const pfStart = (id: Uuid) => invoke<PfRuleCard>("pf_start", { id });
export const pfStop = (id: Uuid) => invoke<null>("pf_stop", { id });
export const pfDelete = (id: Uuid) => invoke<null>("pf_delete", { id });
export const pfDuplicate = (id: Uuid) => invoke<PfRuleCard>("pf_duplicate", { id });
export const pfCopyToVault = (id: Uuid, vaultId: Uuid, moveRule: boolean) =>
  invoke<PfRuleCard>("pf_copy_to_vault", { id, vaultId, moveRule });
export const onForwardEvent = (cb: (e: ForwardEvent) => void): Promise<UnlistenFn> =>
  listen<ForwardEvent>("forward", (ev) => cb(ev.payload));

// ───────────────────────────── snippets ─────────────────────────────

export const snippetsList = (vaultId?: Uuid | null) =>
  invoke<SnippetCard[]>("snippets_list", { vaultId: vaultId ?? null });
export const snippetSave = (form: SnippetForm) => invoke<SnippetCard>("snippet_save", { form });
export const snippetDelete = (id: Uuid) => invoke<null>("snippet_delete", { id });
export const snippetSetTargets = (id: Uuid, hostIds: Uuid[]) =>
  invoke<SnippetCard>("snippet_set_targets", { id, hostIds });
/** `paste` types the script without the final newline so it can be edited first. */
export const snippetRun = (
  id: Uuid,
  sessionIds: Uuid[],
  vars: Record<string, string>,
  paste = false,
) => invoke<RunResult>("snippet_run", { id, sessionIds, vars, paste });
export const snippetRunQuiet = (id: Uuid, hostIds: Uuid[], vars: Record<string, string>) =>
  invoke<QuietRun>("snippet_run_quiet", { id, hostIds, vars });
export const onSnippetQuietProgress = (cb: (p: QuietProgress) => void): Promise<UnlistenFn> =>
  listen<QuietProgress>("snippet-quiet-progress", (e) => cb(e.payload));
export const snippetPackages = (vaultId?: Uuid | null) =>
  invoke<PackageNode[]>("snippet_packages", { vaultId: vaultId ?? null });
export const snippetPackageSave = (args: {
  vaultId: Uuid;
  id: Uuid | null;
  label: string;
  parentId: Uuid | null;
}) => invoke<PackageNode>("snippet_package_save", args);
export const snippetPackageDelete = (id: Uuid) => invoke<null>("snippet_package_delete", { id });
export const snippetCopyToVault = (id: Uuid, vaultId: Uuid, moveSnippet: boolean) =>
  invoke<SnippetCard>("snippet_copy_to_vault", { id, vaultId, moveSnippet });
export const snippetPackageCopyToVault = (id: Uuid, vaultId: Uuid, movePackage: boolean) =>
  invoke<PackageNode>("snippet_package_copy_to_vault", { id, vaultId, movePackage });

// ───────────────────────────── known hosts ─────────────────────────────

export const knownHostsList = () => invoke<KnownHostCard[]>("known_hosts_list");
export const knownHostForget = (id: Uuid) => invoke<null>("known_host_forget", { id });
export const knownHostForgetHost = (hostname: string) =>
  invoke<number>("known_host_forget_host", { hostname });
export const knownHostsImportText = (contents: string) =>
  invoke<ImportReport>("known_hosts_import_text", { contents });
export const knownHostsImportFile = (path: string) =>
  invoke<ImportReport>("known_hosts_import_file", { path });
export const knownHostsExportText = () => invoke<string>("known_hosts_export_text");
export const knownHostsExportFile = (path: string) =>
  invoke<number>("known_hosts_export_file", { path });
export const knownHostsDefaultPath = () => invoke<string | null>("known_hosts_default_path");
export const hostKeyPins = (host: string, port: number) =>
  invoke<HostKeyPin[]>("host_key_pins", { host, port });
export const hostKeyPin = (args: {
  vaultId: Uuid;
  host: string;
  port: number;
  publicKey: string | null;
}) => invoke<HostKeyPin[]>("host_key_pin", args);
export const hostKeyUnpin = (id: Uuid) => invoke<null>("host_key_unpin", { id });

// import from other tools
export const importScanSsh = (dir: string | null) =>
  invoke<ImportPreview>("import_scan_ssh", { dir });
export const importParseFile = (source: ImportSource, path: string) =>
  invoke<ImportPreview>("import_parse_file", { source, path });
export const importScanPuttyRegistry = () => invoke<ImportPreview>("import_scan_putty_registry");
export const importScanSecurecrtDir = (path: string) =>
  invoke<ImportPreview>("import_scan_securecrt_dir", { path });
export const themeImportFile = (path: string) => invoke<ThemeImport>("theme_import_file", { path });
export const importSshDirDefault = () => invoke<string | null>("import_ssh_dir_default");
export const importCsvTemplate = () => invoke<string>("import_csv_template");
export const importCsvTemplateSave = (path: string) =>
  invoke<null>("import_csv_template_save", { path });
export const importApply = (vaultId: Uuid, previewId: Uuid, selection: ImportSelection) =>
  invoke<ImportApplyReport>("import_apply", { vaultId, previewId, selection });
export const importDiscard = (previewId: Uuid) => invoke<null>("import_discard", { previewId });

// ───────────────────────────── cloud integration ─────────────────────────────

/** Lists machines at the provider; `config` is used for this call only. */
export const cloudDiscover = (vaultId: Uuid, config: CloudConfig) =>
  invoke<CloudPreview>("cloud_discover", { vaultId, config });
export const cloudImport = (vaultId: Uuid, previewId: Uuid, selection: CloudSelection) =>
  invoke<CloudImportReport>("cloud_import", { vaultId, previewId, selection });
export const cloudDiscard = (previewId: Uuid) => invoke<null>("cloud_discard", { previewId });

// ───────────────────────────── cloud sync groups ─────────────────────────────

export const cloudSyncList = (vaultId: Uuid | null) =>
  invoke<CloudSyncGroup[]>("cloud_sync_list", { vaultId });
export const cloudSyncGet = (groupId: Uuid) =>
  invoke<CloudSyncGroup | null>("cloud_sync_get", { groupId });
/** `secret === null` keeps the one already stored for the group. */
export const cloudSyncSave = (
  groupId: Uuid,
  config: CloudSyncConfig,
  secret: CloudSyncSecret | null,
) => invoke<CloudSyncGroup>("cloud_sync_save", { groupId, config, secret });
export const cloudSyncForget = (groupId: Uuid) => invoke<null>("cloud_sync_forget", { groupId });
export const cloudSyncRun = (groupId: Uuid) =>
  invoke<CloudSyncGroup>("cloud_sync_run", { groupId });
export const onCloudSync = (cb: (g: CloudSyncGroup) => void): Promise<UnlistenFn> =>
  listen<CloudSyncGroup>("cloud-sync", (ev) => cb(ev.payload));

// ───────────────────────────── local discovery ─────────────────────────────

/** Browse the LAN over mDNS; returns candidates, creates nothing. */
export const mdnsBrowse = (timeoutMs?: number) =>
  invoke<LocalDevice[]>("mdns_browse", { timeoutMs: timeoutMs ?? null });

export const tailnetScan = () => invoke<TailnetScan>("tailnet_scan");

// ───────────────────────────── export / backup ─────────────────────────────

export const hostsExportCsv = (vaultId: Uuid | null, includePasswords: boolean, path: string) =>
  invoke<CsvExportReport>("hosts_export_csv", { vaultId, includePasswords, path });
export const backupExport = (vaultIds: Uuid[], password: string, path: string) =>
  invoke<BackupSummary>("backup_export", { vaultIds, password, path });
export const backupInspect = (path: string, password: string) =>
  invoke<BackupSummary>("backup_inspect", { path, password });
export const backupDiscard = (previewId: Uuid) => invoke<null>("backup_discard", { previewId });
export const backupRestore = (previewId: Uuid, source: number, vaultId: Uuid) =>
  invoke<RestoreReport>("backup_restore", { previewId, source, vaultId });

// ───────────────────────────── logs ─────────────────────────────

export const logsList = () => invoke<LogCard[]>("logs_list");
export const logRead = (id: Uuid) => invoke<LogBody>("log_read", { id });
export const logExport = (id: Uuid, path: string) => invoke<number>("log_export", { id, path });
export const logDelete = (id: Uuid) => invoke<null>("log_delete", { id });
/** Pin / annotate for the team; `undefined` leaves a field as it is. */
export const logAnnotate = (id: Uuid, patch: { pinned?: boolean; note?: string }) =>
  invoke<LogCard>("log_annotate", { id, pinned: patch.pinned ?? null, note: patch.note ?? null });
export const vaultSessionLoggingSet = (vaultId: Uuid, on: boolean) =>
  invoke<null>("vault_session_logging_set", { vaultId, on });
export const logBookmarks = (logId: Uuid) => invoke<BookmarkCard[]>("log_bookmarks", { logId });
export const logBookmarkAdd = (logId: Uuid, offset: number, note: string) =>
  invoke<BookmarkCard>("log_bookmark_add", { logId, offset, note });
export const logBookmarkDelete = (id: Uuid) => invoke<null>("log_bookmark_delete", { id });

// ───────────────────────────── account / sync ─────────────────────────────

export const accountStatus = () => invoke<AccountStatus>("account_status");
export const accountServerInfo = (serverUrl: string) =>
  invoke<ServerInfo>("account_server_info", { serverUrl });
export const accountLogin = (form: LoginForm) => invoke<LoginOutcome>("account_login", { form });
export const accountMfa = (credential: MfaCredential) =>
  invoke<LoginOutcome>("account_mfa", { credential });
export const accountMfaEmailSend = () => invoke<null>("account_mfa_email_send");
export const accountWebauthnChallenge = () => invoke<unknown>("account_webauthn_challenge");
export const accountDeviceApprove = (code: string) =>
  invoke<LoginOutcome>("account_device_approve", { code });
export const accountDeviceResend = () => invoke<null>("account_device_resend");
export const accountCancelLogin = () => invoke<null>("account_cancel_login");
/** Opens the identity provider in the system browser; resolves with the flow id. */
export const accountSsoStart = (form: SsoStartForm) =>
  invoke<string>("account_sso_start", { form });
export const accountSsoPoll = () => invoke<SsoOutcome>("account_sso_poll");
/** The browser came back through `termoso://sso?flow=…`. */
export const accountSsoCallback = (flowId: string) =>
  invoke<SsoOutcome>("account_sso_callback", { flowId });
export const accountSsoCancel = () => invoke<null>("account_sso_cancel");
export const accountRegister = (form: RegisterForm) =>
  invoke<Registered>("account_register", { form });
export const accountSignOut = () => invoke<null>("account_sign_out");
export const accountSyncNow = () => invoke<SyncStatus>("account_sync_now");
/** Turn Personal-vault credential sync on (push + re-pull) or off (server tombstones, local rows kept). */
export const accountSetCredentialSync = (on: boolean) =>
  invoke<AccountStatus>("account_set_credential_sync", { on });
export const accountDevices = () => invoke<Device[]>("account_devices");
export const accountDeviceRevoke = (id: Uuid) => invoke<null>("account_device_revoke", { id });
export const accountReauthStart = (password: string) =>
  invoke<ReauthOutcome>("account_reauth_start", { password });
export const accountReauthMfa = (credential: MfaCredential) =>
  invoke<ReauthOutcome>("account_reauth_mfa", { credential });
export const accountReauthEmailCode = (code: string) =>
  invoke<ReauthOutcome>("account_reauth_email_code", { code });
export const accountReauthMfaEmailSend = () => invoke<null>("account_reauth_mfa_email_send");
export const accountReauthWebauthnChallenge = () =>
  invoke<unknown>("account_reauth_webauthn_challenge");
export const accountReauthCancel = () => invoke<null>("account_reauth_cancel");
export const accountVaultMembers = (vaultId: Uuid) =>
  invoke<VaultMember[]>("account_vault_members", { vaultId });
export const onSyncNotice = (cb: (e: SyncNotice) => void): Promise<UnlistenFn> =>
  listen<SyncNotice>("sync", (ev) => cb(ev.payload));

// ───────────────────────────── SSH ID ─────────────────────────────

export const sshidView = () => invoke<SshIdView>("sshid_view");
export const sshidCreate = (handle: string) => invoke<SshIdView>("sshid_create", { handle });
export const sshidDelete = () => invoke<SshIdView>("sshid_delete");
export const sshidPublish = () => invoke<SshIdView>("sshid_publish");
export const sshidRotate = () => invoke<SshIdView>("sshid_rotate");
export const sshidAddFido2 = (form: SshIdFido2Form) =>
  invoke<SshIdView>("sshid_add_fido2", { form });
export const sshidAddPublicKey = (form: { label: string; publicKey: string }) =>
  invoke<SshIdView>("sshid_add_public_key", form);
export const sshidRemoveKey = (id: Uuid) => invoke<SshIdView>("sshid_remove_key", { id });
export const sshidRemoveDevice = (deviceId: Uuid) =>
  invoke<SshIdView>("sshid_remove_device", { deviceId });

// ───────────────────────────── multiplayer ─────────────────────────────

export const multiplayerStart = (id: Uuid) => invoke<ShareInfo>("multiplayer_start", { id });
export const multiplayerStop = (id: Uuid) => invoke<null>("multiplayer_stop", { id });
export const multiplayerInfo = (id: Uuid) => invoke<ShareInfo | null>("multiplayer_info", { id });
export const multiplayerSetControl = (id: Uuid, userId: Uuid, enabled: boolean) =>
  invoke<null>("multiplayer_set_control", { id, userId, enabled });
export const onLiveEvent = (cb: (e: LiveEvent) => void): Promise<UnlistenFn> =>
  listen<LiveEvent>("multiplayer", (ev) => cb(ev.payload));

// ───────────────────────────── teams ─────────────────────────────

export const teamsList = () => invoke<Team[]>("teams_list");
export const teamCreate = (name: string) => invoke<Team>("team_create", { name });
export const teamRename = (teamId: Uuid, name: string) =>
  invoke<Team>("team_rename", { teamId, name });
export const teamSetSecurity = (
  teamId: Uuid,
  patch: { multiplayerEnabled?: boolean; requireMfa?: boolean; presenceEnabled?: boolean },
) => invoke<Team>("team_set_security", { teamId, ...patch });
/** Who is connected to the team's hosts right now (empty when presence is off). */
export const teamPermissions = (teamId: Uuid) =>
  invoke<{ permissions: PermissionInfo[] }>("team_permissions", { teamId });
export const teamRoles = (teamId: Uuid) => invoke<TeamRoleList>("team_roles", { teamId });
export const teamRoleCreate = (
  teamId: Uuid,
  req: { name: string; description?: string; permissions: string[]; copy_from?: Uuid },
) => invoke<TeamRoleDef>("team_role_create", { teamId, req });
export const teamRoleUpdate = (
  teamId: Uuid,
  roleId: Uuid,
  req: { name?: string; description?: string; permissions?: string[]; position?: number },
) => invoke<TeamRoleDef>("team_role_update", { teamId, roleId, req });
export const teamRoleDelete = (teamId: Uuid, roleId: Uuid, reassignTo?: Uuid) =>
  invoke<null>("team_role_delete", { teamId, roleId, reassignTo: reassignTo ?? null });
export const teamSetDefaultRole = (teamId: Uuid, roleId: Uuid) =>
  invoke<null>("team_set_default_role", { teamId, roleId });
export const teamRoleMappings = (teamId: Uuid) =>
  invoke<RoleMapping[]>("team_role_mappings", { teamId });
export const teamSetRoleMappings = (teamId: Uuid, mappings: RoleMapping[]) =>
  invoke<RoleMapping[]>("team_set_role_mappings", { teamId, mappings });
export const teamPolicies = (teamId: Uuid) =>
  invoke<TeamPoliciesResponse>("team_policies", { teamId });
export const teamUpdatePolicies = (teamId: Uuid, patch: UpdateTeamPolicies) =>
  invoke<TeamPoliciesResponse>("team_update_policies", { teamId, patch });
export const teamWebhooks = (teamId: Uuid) => invoke<Webhook[]>("team_webhooks", { teamId });
export const teamWebhookCreate = (
  teamId: Uuid,
  req: { url: string; secret: string; kind?: WebhookKind; actions?: string[] | null },
) => invoke<Webhook>("team_webhook_create", { teamId, req });
export const teamWebhookUpdate = (
  teamId: Uuid,
  hookId: Uuid,
  req: {
    url?: string;
    secret?: string;
    kind?: WebhookKind;
    actions?: string[] | null;
    enabled?: boolean;
  },
) => invoke<Webhook>("team_webhook_update", { teamId, hookId, req });
export const teamWebhookDelete = (teamId: Uuid, hookId: Uuid) =>
  invoke<null>("team_webhook_delete", { teamId, hookId });
export const teamWebhookTest = (teamId: Uuid, hookId: Uuid) =>
  invoke<WebhookDelivery[]>("team_webhook_test", { teamId, hookId });
export const teamWebhookDeliveries = (teamId: Uuid, hookId: Uuid) =>
  invoke<WebhookDelivery[]>("team_webhook_deliveries", { teamId, hookId });
export const teamPresence = (teamId: Uuid) => invoke<TeamPresence>("team_presence", { teamId });
export const accountProfile = () => invoke<UserProfile>("account_profile");
/** `data:` URL of a user's picture (disk-cached by tag), or `null` when the server has none. */
/** WebP bytes of a profile picture; empty when the user has none. */
export const userAvatar = (userId: Uuid, tag: string) =>
  invoke<ArrayBuffer>("user_avatar", { userId, tag });
export const accountSetPresenceHidden = (hidden: boolean) =>
  invoke<UserProfile>("account_set_presence_hidden", { hidden });
export const aiStatus = () => invoke<AiStatus>("ai_status");
export const aiSetEnabled = (enabled: boolean) => invoke<AiStatus>("ai_set_enabled", { enabled });
/**
 * One command for a short request. Rust attaches only the session's OS and
 * shell labels; the answer is shown, never run.
 */
export const aiAsk = (prompt: string, sessionId: Uuid | null) =>
  invoke<AiCommandResponse>("ai_ask", { form: { prompt, sessionId } });
export const teamDelete = (teamId: Uuid) => invoke<null>("team_delete", { teamId });
export const teamLeave = (teamId: Uuid) => invoke<null>("team_leave", { teamId });
export const teamAcceptInvite = (link: string) => invoke<Team>("team_accept_invite", { link });
export const teamMembers = (teamId: Uuid) => invoke<TeamMember[]>("team_members", { teamId });
export const teamMemberSetRole = (teamId: Uuid, userId: Uuid, role: TeamRole) =>
  invoke<null>("team_member_set_role", { teamId, userId, role });
export const teamMemberRemove = (teamId: Uuid, userId: Uuid) =>
  invoke<null>("team_member_remove", { teamId, userId });
/** Owner-only; the server asks for a fresh re-authentication. */
export const teamMemberDeleteAccount = (teamId: Uuid, userId: Uuid) =>
  invoke<null>("team_member_delete_account", { teamId, userId });
export const teamInvites = (teamId: Uuid) => invoke<TeamInvite[]>("team_invites", { teamId });
export const teamInvite = (teamId: Uuid, emails: string[], role: TeamRole, vaultIds: Uuid[]) =>
  invoke<InviteResult[]>("team_invite", { teamId, emails, role, vaultIds });
export const teamInviteRevoke = (teamId: Uuid, inviteId: Uuid) =>
  invoke<null>("team_invite_revoke", { teamId, inviteId });
export const teamPendingKeys = (teamId: Uuid) =>
  invoke<PendingVaultKey[]>("team_pending_keys", { teamId });
export const teamAudit = (teamId: Uuid, filter: AuditFilter = {}) =>
  invoke<AuditPage>("team_audit", { teamId, filter });
export const teamVaultCreate = (teamId: Uuid, name: string, access: VaultAccess[]) =>
  invoke<null>("team_vault_create", { teamId, name, access });
export const teamVaultRename = (vaultId: Uuid, name: string) =>
  invoke<null>("team_vault_rename", { vaultId, name });
export const teamVaultDelete = (vaultId: Uuid) => invoke<null>("team_vault_delete", { vaultId });
export const teamVaultSetAccess = (vaultId: Uuid, userId: Uuid, role: VaultRole) =>
  invoke<null>("team_vault_set_access", { vaultId, userId, role });
export const teamVaultRemoveAccess = (vaultId: Uuid, userId: Uuid) =>
  invoke<null>("team_vault_remove_access", { vaultId, userId });
export const teamVaultRotateKey = (vaultId: Uuid) =>
  invoke<null>("team_vault_rotate_key", { vaultId });

// ───────────────────────────── updates ─────────────────────────────

export const updateCheck = () => invoke<UpdateInfo | null>("update_check");
export const updateInstall = () => invoke<UpdateInfo>("update_install");
export const updateRestart = () => invoke<null>("update_restart");
export const onUpdateEvent = (cb: (e: UpdateEvent) => void): Promise<UnlistenFn> =>
  listen<UpdateEvent>("update", (ev) => cb(ev.payload));

// ── 0.9.1 enterprise ──
export const ssoDiscover = (serverUrl: string, email: string) =>
  invoke<SsoDiscoverResponse>("account_sso_discover", { serverUrl, email });
export const teamIdp = (teamId: Uuid) => invoke<TeamIdpResponse>("team_idp", { teamId });
export const teamUpdateIdp = (teamId: Uuid, patch: UpdateTeamIdp) =>
  invoke<TeamIdpResponse>("team_update_idp", { teamId, patch });
export const teamTestIdp = (teamId: Uuid, patch: UpdateTeamIdp) =>
  invoke<TeamIdpResponse>("team_test_idp", { teamId, patch });
export const teamDeleteIdp = (teamId: Uuid) => invoke<null>("team_delete_idp", { teamId });
export const teamAcl = (teamId: Uuid, vaultId: Uuid) =>
  invoke<EntityAclRule[]>("team_acl", { teamId, vaultId });
export const teamUpsertAcl = (teamId: Uuid, vaultId: Uuid, rule: UpsertEntityAcl) =>
  invoke<EntityAclRule[]>("team_upsert_acl", { teamId, vaultId, rule });
export const teamDeleteAcl = (teamId: Uuid, vaultId: Uuid, ruleId: Uuid) =>
  invoke<null>("team_delete_acl", { teamId, vaultId, ruleId });
export const aclMe = () => invoke<MyAclRule[]>("acl_me");
export const teamLogs = (teamId: Uuid, vaultId?: Uuid) =>
  invoke<TeamLogList>("team_logs", { teamId, vaultId: vaultId ?? null });
export const teamLogsExport = (teamId: Uuid) => invoke<string>("team_logs_export", { teamId });
export const teamRotation = (teamId: Uuid) => invoke<RotationOverview>("team_rotation", { teamId });
export const teamCreateRotationJobs = (
  teamId: Uuid,
  req: { vault_id: Uuid; entity_ids: Uuid[]; note: string },
) => invoke<RotationJob[]>("team_create_rotation_jobs", { teamId, req });
export const rotationJobs = () => invoke<RotationJob[]>("rotation_jobs");
export const rotationUpdateJob = (jobId: Uuid, req: { status: string; error?: string | null }) =>
  invoke<RotationJob>("rotation_update_job", { jobId, req });
export const rotationCancelJob = (jobId: Uuid) => invoke<null>("rotation_cancel_job", { jobId });
export const teamAccessRequests = (teamId: Uuid) =>
  invoke<AccessRequestList>("team_access_requests", { teamId });
export const teamCreateAccessRequest = (
  teamId: Uuid,
  req: { vault_id: Uuid; role: AccessRole; hours: number; reason: string },
) => invoke<AccessRequest>("team_create_access_request", { teamId, req });
export const teamCancelAccessRequest = (teamId: Uuid, rid: Uuid) =>
  invoke<null>("team_cancel_access_request", { teamId, rid });
export const teamDecideAccessRequest = (
  teamId: Uuid,
  rid: Uuid,
  action: "approve" | "deny" | "revoke",
  req: { hours?: number; role?: AccessRole; note?: string },
) => invoke<AccessRequest>("team_decide_access_request", { teamId, rid, action, req });
export const teamData = (teamId: Uuid) => invoke<TeamDataStatus>("team_data", { teamId });
export const teamExport = (teamId: Uuid) => invoke<string>("team_export", { teamId });
export const teamScheduleDeletion = (teamId: Uuid, confirmName: string) =>
  invoke<TeamDataStatus>("team_schedule_deletion", { teamId, confirmName });
export const teamCancelDeletion = (teamId: Uuid) =>
  invoke<TeamDataStatus>("team_cancel_deletion", { teamId });
export const teamCa = (teamId: Uuid) => invoke<TeamCa | null>("team_ca", { teamId });
export const teamUpdateCa = (teamId: Uuid, patch: UpdateTeamCaRequest) =>
  invoke<TeamCa>("team_update_ca", { teamId, patch });
export const teamDeleteCa = (teamId: Uuid) => invoke<null>("team_delete_ca", { teamId });
export const teamRotateCa = (teamId: Uuid, graceHours: number | null) =>
  invoke<TeamCa>("team_rotate_ca", { teamId, graceHours });
export const teamCaCertificates = (teamId: Uuid) =>
  invoke<IssuedCertificateList>("team_ca_certificates", { teamId });
export const teamCaRevoke = (teamId: Uuid, certificateId: Uuid) =>
  invoke<IssuedCertificate>("team_ca_revoke", { teamId, certificateId });
export const teamCaLocal = (teamId: Uuid) =>
  invoke<LocalTeamCertificate | null>("team_ca_local", { teamId });
export const teamDevices = (teamId: Uuid) => invoke<TeamDeviceList>("team_devices", { teamId });
export const teamApproveDevice = (teamId: Uuid, deviceId: Uuid) =>
  invoke<null>("team_approve_device", { teamId, deviceId });
export const teamRejectDevice = (teamId: Uuid, deviceId: Uuid) =>
  invoke<null>("team_reject_device", { teamId, deviceId });
export const saveTextFile = (path: string, contents: string) =>
  invoke<null>("save_text_file", { path, contents });
export const rotationRunJob = (jobId: Uuid) =>
  invoke<RotationRunResult>("rotation_run_job", { jobId });
export const rotationMarkDone = (jobId: Uuid) =>
  invoke<RotationJob>("rotation_mark_done", { jobId });
