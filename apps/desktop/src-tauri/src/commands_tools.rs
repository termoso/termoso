//! IPC surface for keychain, port forwarding, snippets, known hosts, logs
//! and account/sync. Thin adapters; the façades own validation and secrets.

use std::collections::HashMap;
use termoso_proto::team as proto;

use serde::Deserialize;

use tauri::{AppHandle, Emitter, Manager, Runtime, State};
use termoso_client::trust::HostKeyPin;
use termoso_core::model::SshKey;
use termoso_core::secrets::MasterKeySource;
use termoso_proto::account::{ServerInfo, UserProfile};
use termoso_proto::ai::{AiCommandResponse, AiStatus};
use termoso_proto::auth::{Device, MfaCredential};
use termoso_proto::team::{Invite, Team, TeamPresence, TeamRole};
use termoso_proto::vault::{VaultMember, VaultRole};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::account::{
    self, AccountStatus, LoginForm, LoginOutcome, ReauthOutcome, RegisterForm, Registered,
    SYNC_EVENT, SyncNotice, SyncStatus,
};
use crate::ai::{self, AskForm};
use crate::avatars;
use crate::backup::{self, BackupSummary};
use crate::cloud::{self, CloudImportReport, CloudPreview, CloudSelection};
use crate::cloud_sync::{self, CloudSyncConfig, CloudSyncGroup, CloudSyncSecret};
use crate::error::{DesktopError, Result};
use crate::forwarding::{self, PfRuleCard, PfRuleForm, PfRuntime};
use crate::import::{self, ImportPreview, ImportSelection, ImportSource};
use crate::keychain::{
    self, AgentImportForm, CertificateCard, ExportOutcome, Fido2GenerateForm, Fido2LoadForm,
    GenerateForm, IdentityCard, IdentityForm, ImportForm, KeyCard, KeyPreview,
};
use crate::logs::{self, BookmarkCard, LogBody, LogCard};
use crate::multiplayer::{self, ShareInfo};
use crate::presence;
use crate::sessions;
use crate::snippets::{self, PackageNode, RunResult, SnippetCard, SnippetForm};
use crate::sshid::{self, SshIdFido2Form, SshIdView};
use crate::state::AppState;
use crate::team::{self, InviteResult, PendingKeyCard, TeamMemberCard, VaultAccess};
use crate::trust::{self, ImportReport, KnownHostCard};
use crate::update::{self, UpdateInfo};

// ───────────────────────────── keychain ─────────────────────────────

#[tauri::command]
pub async fn keys_list<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    vault_id: Option<Uuid>,
) -> Result<Vec<KeyCard>> {
    let cards = keychain::keys_list(&*state.store()?, vault_id)?;
    // The keychain page lists after every change: keep the agent in step.
    if state.settings().map(|s| s.serve_ssh_agent).unwrap_or(false) {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(e) = crate::agent_server::reconcile(&app).await {
                tracing::warn!("ssh-agent refresh failed: {e}");
            }
        });
    }
    Ok(cards)
}

#[tauri::command]
pub async fn key_generate(state: State<'_, AppState>, form: GenerateForm) -> Result<KeyCard> {
    keychain::generate(&*state.store()?, &form)
}

#[tauri::command]
pub async fn key_import(state: State<'_, AppState>, form: ImportForm) -> Result<KeyCard> {
    keychain::import(&*state.store()?, &form)
}

fn blocking_err(e: tokio::task::JoinError) -> DesktopError {
    DesktopError::new("internal", e.to_string())
}

/// FIDO2 authenticators plugged in right now (USB HID enumeration; local only).
#[tauri::command]
pub async fn fido2_devices() -> Result<Vec<termoso_core::fido2::Fido2Device>> {
    tokio::task::spawn_blocking(keychain::fido2_devices)
        .await
        .map_err(blocking_err)
}

/// Make a credential on the token and store the `sk-*` key. Blocks until
/// the user touches the token (or it times out), so it runs off-runtime.
#[tauri::command]
pub async fn fido2_generate(
    state: State<'_, AppState>,
    form: Fido2GenerateForm,
) -> Result<KeyCard> {
    let store = state.store()?.clone();
    tokio::task::spawn_blocking(move || keychain::fido2_generate(&store, &form))
        .await
        .map_err(blocking_err)?
}

/// Import the resident SSH credentials of a token into a vault.
#[tauri::command]
pub async fn fido2_load_resident(
    state: State<'_, AppState>,
    form: Fido2LoadForm,
) -> Result<Vec<KeyCard>> {
    let store = state.store()?.clone();
    tokio::task::spawn_blocking(move || keychain::fido2_load_resident(&store, &form))
        .await
        .map_err(blocking_err)?
}

/// Import request for a private key file on disk.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportFileForm {
    pub vault_id: Uuid,
    pub label: String,
    pub path: String,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub remember_passphrase: bool,
    /// Pasted certificate text; ignored when `certificate_path` is set.
    #[serde(default)]
    pub certificate: Option<String>,
    /// Path to a `*-cert.pub` to attach.
    #[serde(default)]
    pub certificate_path: Option<String>,
}

/// Import from a file on disk; the private material is read here and never
/// crosses the IPC boundary.
#[tauri::command]
pub async fn key_import_file(state: State<'_, AppState>, form: ImportFileForm) -> Result<KeyCard> {
    let private_key = std::fs::read_to_string(&form.path)?;
    let certificate = match form.certificate_path {
        Some(p) => Some(std::fs::read_to_string(&p)?),
        None => form.certificate,
    };
    keychain::import(
        &*state.store()?,
        &ImportForm {
            vault_id: form.vault_id,
            label: form.label,
            private_key,
            passphrase: form.passphrase,
            remember_passphrase: form.remember_passphrase,
            certificate,
        },
    )
}

/// Store a public-only key that the system SSH agent signs with (pasted
/// `.pub` line or an entry picked from `agent_keys`).
#[tauri::command]
pub async fn key_import_agent(
    state: State<'_, AppState>,
    form: AgentImportForm,
) -> Result<KeyCard> {
    keychain::import_agent(&*state.store()?, &form)
}

/// `.pub` file variant of `key_import_agent`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentImportFileForm {
    pub vault_id: Uuid,
    #[serde(default)]
    pub label: String,
    pub path: String,
    #[serde(default)]
    pub certificate_path: Option<String>,
}

#[tauri::command]
pub async fn key_import_agent_file(
    state: State<'_, AppState>,
    form: AgentImportFileForm,
) -> Result<KeyCard> {
    let public_key = std::fs::read_to_string(&form.path)?;
    if public_key.contains("PRIVATE KEY-----") {
        return Err(DesktopError::invalid(
            "this is a private key file; pick the .pub file (or use Import key to store the private key)",
        ));
    }
    let certificate = match form.certificate_path {
        Some(p) => Some(std::fs::read_to_string(&p)?),
        None => None,
    };
    keychain::import_agent(
        &*state.store()?,
        &AgentImportForm {
            vault_id: form.vault_id,
            label: form.label,
            public_key,
            certificate,
        },
    )
}

/// Public half + format of pasted private key text; nothing is stored.
#[tauri::command]
pub async fn key_inspect(text: String) -> Result<KeyPreview> {
    keychain::inspect_private(&text)
}

/// Same for a file on disk; the private material stays in Rust.
#[tauri::command]
pub async fn key_inspect_file(path: String) -> Result<KeyPreview> {
    keychain::inspect_private(&std::fs::read_to_string(&path)?)
}

/// Parse + verify a certificate for the editor preview; nothing is stored.
#[tauri::command]
pub async fn certificate_inspect(text: String) -> Result<CertificateCard> {
    keychain::inspect_certificate(&text)
}

#[tauri::command]
pub async fn certificate_inspect_file(path: String) -> Result<CertificateCard> {
    keychain::inspect_certificate(&std::fs::read_to_string(&path)?)
}

/// Certificate text attached to a key (public data), for display/copy.
#[tauri::command]
pub async fn key_certificate(state: State<'_, AppState>, id: Uuid) -> Result<Option<String>> {
    keychain::certificate_text(&*state.store()?, id)
}

/// Attach (`Some(text)`) or detach (`None`) the certificate of a key.
#[tauri::command]
pub async fn key_set_certificate(
    state: State<'_, AppState>,
    id: Uuid,
    certificate: Option<String>,
) -> Result<KeyCard> {
    keychain::set_certificate(&*state.store()?, id, certificate)
}

#[tauri::command]
pub async fn key_set_certificate_file(
    state: State<'_, AppState>,
    id: Uuid,
    path: String,
) -> Result<KeyCard> {
    let text = std::fs::read_to_string(&path)?;
    keychain::set_certificate(&*state.store()?, id, Some(text))
}

/// Copy or move a key (with its certificate) into another vault.
#[tauri::command]
pub async fn key_copy_to_vault(
    state: State<'_, AppState>,
    id: Uuid,
    vault_id: Uuid,
    move_key: bool,
) -> Result<KeyCard> {
    keychain::copy_to_vault(&*state.store()?, id, vault_id, move_key)
}

#[tauri::command]
pub async fn key_rename(state: State<'_, AppState>, id: Uuid, label: String) -> Result<KeyCard> {
    keychain::rename(&*state.store()?, id, &label)
}

#[tauri::command]
pub async fn key_change_passphrase(
    state: State<'_, AppState>,
    id: Uuid,
    current: Option<String>,
    next: Option<String>,
    remember: bool,
) -> Result<KeyCard> {
    keychain::change_passphrase(&*state.store()?, id, current, next, remember)
}

#[tauri::command]
pub async fn key_remember_passphrase(
    state: State<'_, AppState>,
    id: Uuid,
    passphrase: Option<String>,
) -> Result<KeyCard> {
    keychain::remember_passphrase(&*state.store()?, id, passphrase)
}

#[tauri::command]
pub async fn key_public(state: State<'_, AppState>, id: Uuid) -> Result<String> {
    keychain::public_key(&*state.store()?, id)
}

/// Explicit export of private material. `export_passphrase` re-encrypts the
/// exported copy; `None` writes it unencrypted (the UI warns first).
#[tauri::command]
pub async fn key_export(
    state: State<'_, AppState>,
    id: Uuid,
    passphrase: Option<String>,
    export_passphrase: Option<String>,
) -> Result<String> {
    key_export_allowed(&*state.store()?, id)?;
    Ok(keychain::export(&*state.store()?, id, passphrase, export_passphrase)?.to_string())
}

/// Team policy `export = deny` covers private keys of the team vault.
fn key_export_allowed(store: &termoso_core::store::Store, id: Uuid) -> Result<()> {
    let e = store.require::<termoso_core::model::SshKey>(id)?;
    if termoso_core::policy::export_denied(store, e.vault_id) {
        return Err(DesktopError::invalid(
            termoso_core::policy::Denied::Export.message(),
        ));
    }
    Ok(())
}

#[tauri::command]
pub async fn key_export_file(
    state: State<'_, AppState>,
    id: Uuid,
    path: String,
    passphrase: Option<String>,
    export_passphrase: Option<String>,
) -> Result<()> {
    key_export_allowed(&*state.store()?, id)?;
    let text = keychain::export(&*state.store()?, id, passphrase, export_passphrase)?;
    write_private(&path, text.as_bytes())?;
    let public = keychain::public_key(&*state.store()?, id)?;
    std::fs::write(format!("{path}.pub"), format!("{public}\n"))?;
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &str, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

/// Result of `key_export_to_host`.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportToHostResult {
    pub outcome: ExportOutcome,
    pub host_label: String,
    /// `user@host:port` the key was installed for.
    pub target: String,
}

/// `ssh-copy-id`: connect to a saved host with its current credentials and
/// append the key's public half to `~/.ssh/authorized_keys` there. Prompts
/// (password, host key) are routed under a throw-away session id; the
/// transport is closed as soon as the command returns.
#[tauri::command]
pub async fn key_export_to_host<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    id: Uuid,
    host_id: Uuid,
) -> Result<ExportToHostResult> {
    let key_vault = state.store()?.require::<SshKey>(id)?.vault_id;
    let public = keychain::public_key(&*state.store()?, id)?;
    let conn = sessions::connect_host(&app, Uuid::new_v4(), host_id, Some(key_vault)).await?;
    let out = conn
        .client
        .exec(
            keychain::EXPORT_COMMAND,
            Some(bytes::Bytes::from(format!("{public}\n"))),
        )
        .await;
    let (host_label, target) = (conn.label.clone(), conn.display.clone());
    conn.close().await;
    let out = out?;
    let outcome = keychain::export_outcome(out.exit_code, &out.stdout, &out.stderr)?;
    Ok(ExportToHostResult {
        outcome,
        host_label,
        target,
    })
}

/// Keys the system SSH agent currently holds (public halves only). Empty
/// with `available: false` when no agent is reachable.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentKeys {
    pub available: bool,
    /// Why the agent is unavailable (never contains secrets).
    pub error: Option<String>,
    pub keys: Vec<termoso_core::agent::AgentKey>,
}

#[tauri::command]
pub async fn agent_keys() -> Result<AgentKeys> {
    let mut agent = match termoso_core::agent::connect_system_agent().await {
        Ok(a) => a,
        Err(e) => {
            return Ok(AgentKeys {
                available: false,
                error: Some(e.to_string()),
                keys: Vec::new(),
            });
        }
    };
    match termoso_core::agent::list_keys(&mut agent).await {
        Ok(keys) => Ok(AgentKeys {
            available: true,
            error: None,
            keys,
        }),
        Err(e) => Ok(AgentKeys {
            available: false,
            error: Some(e.to_string()),
            keys: Vec::new(),
        }),
    }
}

#[tauri::command]
pub async fn key_delete(state: State<'_, AppState>, id: Uuid) -> Result<()> {
    keychain::delete(&*state.store()?, id)
}

#[tauri::command]
pub async fn identities_list(
    state: State<'_, AppState>,
    vault_id: Option<Uuid>,
) -> Result<Vec<IdentityCard>> {
    keychain::identities(&*state.store()?, vault_id)
}

#[tauri::command]
pub async fn identity_save(state: State<'_, AppState>, form: IdentityForm) -> Result<IdentityCard> {
    keychain::save_identity(&*state.store()?, &form)
}

#[tauri::command]
pub async fn identity_delete(state: State<'_, AppState>, id: Uuid) -> Result<()> {
    keychain::delete_identity(&*state.store()?, id)
}

/// Copy or move an identity (with its key and certificate) into another vault.
#[tauri::command]
pub async fn identity_copy_to_vault(
    state: State<'_, AppState>,
    id: Uuid,
    vault_id: Uuid,
    move_identity: bool,
) -> Result<IdentityCard> {
    keychain::copy_identity_to_vault(&*state.store()?, id, vault_id, move_identity)
}

#[tauri::command]
pub fn master_key_migrate(state: State<'_, AppState>) -> Result<MasterKeySource> {
    state.migrate_master_key()
}

// ───────────────────────────── port forwarding ─────────────────────────────

#[tauri::command]
pub async fn pf_rules(
    state: State<'_, AppState>,
    vault_id: Option<Uuid>,
) -> Result<Vec<PfRuleCard>> {
    forwarding::rules(&state, vault_id)
}

#[tauri::command]
pub async fn pf_save(state: State<'_, AppState>, form: PfRuleForm) -> Result<PfRuleCard> {
    forwarding::save(&state, &form)
}

#[tauri::command]
pub fn pf_runtimes(state: State<'_, AppState>) -> Result<HashMap<Uuid, PfRuntime>> {
    forwarding::runtimes(&state)
}

#[tauri::command]
pub async fn pf_start<R: Runtime>(app: AppHandle<R>, id: Uuid) -> Result<PfRuleCard> {
    forwarding::start(&app, id).await
}

#[tauri::command]
pub async fn pf_stop<R: Runtime>(app: AppHandle<R>, id: Uuid) -> Result<()> {
    forwarding::stop(&app, id).await
}

#[tauri::command]
pub async fn pf_delete<R: Runtime>(app: AppHandle<R>, id: Uuid) -> Result<()> {
    forwarding::delete(&app, id).await
}

#[tauri::command]
pub async fn pf_duplicate(state: State<'_, AppState>, id: Uuid) -> Result<PfRuleCard> {
    forwarding::duplicate(&state, id)
}

#[tauri::command]
pub async fn pf_copy_to_vault<R: Runtime>(
    app: AppHandle<R>,
    id: Uuid,
    vault_id: Uuid,
    move_rule: bool,
) -> Result<PfRuleCard> {
    if move_rule {
        forwarding::move_to_vault(&app, id, vault_id).await
    } else {
        forwarding::copy_to_vault(&app.state::<AppState>(), id, vault_id)
    }
}

// ───────────────────────────── snippets ─────────────────────────────

#[tauri::command]
pub async fn snippets_list(
    state: State<'_, AppState>,
    vault_id: Option<Uuid>,
) -> Result<Vec<SnippetCard>> {
    snippets::list(&*state.store()?, vault_id)
}

#[tauri::command]
pub async fn snippet_save(state: State<'_, AppState>, form: SnippetForm) -> Result<SnippetCard> {
    snippets::save(&*state.store()?, &form)
}

#[tauri::command]
pub async fn snippet_delete(state: State<'_, AppState>, id: Uuid) -> Result<()> {
    snippets::delete(&*state.store()?, id)
}

#[tauri::command]
pub async fn snippet_copy_to_vault(
    state: State<'_, AppState>,
    id: Uuid,
    vault_id: Uuid,
    move_snippet: bool,
) -> Result<SnippetCard> {
    snippets::copy_to_vault(&*state.store()?, id, vault_id, move_snippet)
}

#[tauri::command]
pub async fn snippet_set_targets(
    state: State<'_, AppState>,
    id: Uuid,
    host_ids: Vec<Uuid>,
) -> Result<SnippetCard> {
    snippets::set_targets(&*state.store()?, id, &host_ids)
}

/// Run a snippet on saved hosts without opening terminals; see
/// [`snippets::run_quiet`].
#[tauri::command]
pub async fn snippet_run_quiet<R: Runtime>(
    app: AppHandle<R>,
    id: Uuid,
    host_ids: Vec<Uuid>,
    vars: HashMap<String, String>,
) -> Result<snippets::QuietRun> {
    snippets::run_quiet(&app, id, &host_ids, &vars).await
}

#[tauri::command]
pub async fn snippet_run(
    state: State<'_, AppState>,
    id: Uuid,
    session_ids: Vec<Uuid>,
    vars: HashMap<String, String>,
    paste: Option<bool>,
) -> Result<RunResult> {
    snippets::run(&state, id, &session_ids, &vars, paste.unwrap_or(false)).await
}

#[tauri::command]
pub async fn snippet_packages(
    state: State<'_, AppState>,
    vault_id: Option<Uuid>,
) -> Result<Vec<PackageNode>> {
    snippets::packages(&*state.store()?, vault_id)
}

#[tauri::command]
pub async fn snippet_package_save(
    state: State<'_, AppState>,
    vault_id: Uuid,
    id: Option<Uuid>,
    label: String,
    parent_id: Option<Uuid>,
) -> Result<PackageNode> {
    snippets::save_package(&*state.store()?, vault_id, id, &label, parent_id)
}

#[tauri::command]
pub async fn snippet_package_delete(state: State<'_, AppState>, id: Uuid) -> Result<()> {
    snippets::delete_package(&*state.store()?, id)
}

#[tauri::command]
pub async fn snippet_package_copy_to_vault(
    state: State<'_, AppState>,
    id: Uuid,
    vault_id: Uuid,
    move_package: bool,
) -> Result<PackageNode> {
    snippets::copy_package_to_vault(&*state.store()?, id, vault_id, move_package)
}

// ───────────────────────────── known hosts ─────────────────────────────

#[tauri::command]
pub async fn known_hosts_list(state: State<'_, AppState>) -> Result<Vec<KnownHostCard>> {
    trust::list(&*state.store()?)
}

#[tauri::command]
pub async fn known_host_forget(state: State<'_, AppState>, id: Uuid) -> Result<()> {
    trust::forget(&*state.store()?, id)
}

#[tauri::command]
pub async fn known_host_forget_host(state: State<'_, AppState>, hostname: String) -> Result<usize> {
    trust::forget_host(&*state.store()?, &hostname)
}

#[tauri::command]
pub async fn host_key_pins(
    state: State<'_, AppState>,
    host: String,
    port: u16,
) -> Result<Vec<HostKeyPin>> {
    termoso_client::trust::pins(&state.store()?, &host, port)
}

#[tauri::command]
pub async fn host_key_pin(
    state: State<'_, AppState>,
    vault_id: Uuid,
    host: String,
    port: u16,
    public_key: Option<String>,
) -> Result<Vec<HostKeyPin>> {
    termoso_client::trust::pin(
        &state.store()?,
        vault_id,
        &host,
        port,
        public_key.as_deref(),
    )
}

#[tauri::command]
pub async fn host_key_unpin(state: State<'_, AppState>, id: Uuid) -> Result<()> {
    termoso_client::trust::unpin(&state.store()?, id)
}

#[tauri::command]
pub async fn known_hosts_import_text(
    state: State<'_, AppState>,
    contents: String,
) -> Result<ImportReport> {
    trust::import_openssh(&state, &contents)
}

#[tauri::command]
pub async fn known_hosts_import_file(
    state: State<'_, AppState>,
    path: String,
) -> Result<ImportReport> {
    trust::import_file(&state, &path)
}

#[tauri::command]
pub async fn known_hosts_export_text(state: State<'_, AppState>) -> Result<String> {
    trust::export_openssh(&state)
}

#[tauri::command]
pub async fn known_hosts_export_file(state: State<'_, AppState>, path: String) -> Result<usize> {
    trust::export_file(&state, &path)
}

#[tauri::command]
pub fn known_hosts_default_path() -> Option<String> {
    trust::default_openssh_path()
}

// ───────────────────────────── import ─────────────────────────────

/// Parse everything in `~/.ssh` (or `dir`) without touching the vault.
#[tauri::command]
pub async fn import_scan_ssh(dir: Option<String>) -> Result<ImportPreview> {
    tauri::async_runtime::spawn_blocking(move || import::scan_ssh_dir(dir.as_deref()))
        .await
        .map_err(|e| crate::error::DesktopError::new("import", e.to_string()))?
        .map(import::remember)
}

#[tauri::command]
pub async fn import_parse_file(source: ImportSource, path: String) -> Result<ImportPreview> {
    tauri::async_runtime::spawn_blocking(move || import::parse_file(source, &path))
        .await
        .map_err(|e| crate::error::DesktopError::new("import", e.to_string()))?
        .map(import::remember)
}

/// Parse a colour scheme file (iTerm2, Windows Terminal, Alacritty, Kitty,
/// Ghostty, Gogh) into vault-ready payloads; nothing is saved here.
#[tauri::command]
pub async fn theme_import_file(path: String) -> Result<crate::theme_import::ThemeImport> {
    tauri::async_runtime::spawn_blocking(move || crate::theme_import::import_file(&path))
        .await
        .map_err(|e| crate::error::DesktopError::new("import", e.to_string()))?
}

#[tauri::command]
pub async fn import_scan_securecrt_dir(path: String) -> Result<ImportPreview> {
    tauri::async_runtime::spawn_blocking(move || import::scan_securecrt_dir(&path))
        .await
        .map_err(|e| crate::error::DesktopError::new("import", e.to_string()))?
        .map(import::remember)
}

#[tauri::command]
pub async fn import_scan_xshell_dir(path: String) -> Result<ImportPreview> {
    tauri::async_runtime::spawn_blocking(move || import::scan_xshell_dir(&path))
        .await
        .map_err(|e| crate::error::DesktopError::new("import", e.to_string()))?
        .map(import::remember)
}

#[tauri::command]
pub async fn import_scan_putty_registry() -> Result<ImportPreview> {
    tauri::async_runtime::spawn_blocking(import::scan_putty_registry)
        .await
        .map_err(|e| crate::error::DesktopError::new("import", e.to_string()))?
        .map(import::remember)
}

#[tauri::command]
pub fn import_ssh_dir_default() -> Option<String> {
    import::default_ssh_dir()
        .filter(|p| p.is_dir())
        .map(|p| p.to_string_lossy().into_owned())
}

#[tauri::command]
pub fn import_csv_template() -> String {
    import::csv_template()
}

#[tauri::command]
pub fn import_csv_template_save(path: String) -> Result<()> {
    std::fs::write(&path, import::csv_template())?;
    Ok(())
}

#[tauri::command]
pub async fn import_apply(
    state: State<'_, AppState>,
    vault_id: Uuid,
    preview_id: Uuid,
    selection: ImportSelection,
) -> Result<import::ImportReport> {
    import::apply_cached(&state, vault_id, preview_id, &selection)
}

#[tauri::command]
pub fn import_discard(preview_id: Uuid) {
    import::discard(preview_id)
}

// ───────────────────────────── cloud integration ─────────────────────────────

/// List machines at a provider. `config` carries the credentials for this
/// call only; nothing of it is kept or returned.
#[tauri::command]
pub async fn cloud_discover(
    state: State<'_, AppState>,
    vault_id: Uuid,
    config: termoso_core::cloud::CloudConfig,
) -> Result<CloudPreview> {
    cloud::discover(&*state.store()?, vault_id, config).await
}

#[tauri::command]
pub async fn cloud_import(
    state: State<'_, AppState>,
    vault_id: Uuid,
    preview_id: Uuid,
    selection: CloudSelection,
) -> Result<CloudImportReport> {
    cloud::apply_cached(&*state.store()?, vault_id, preview_id, &selection)
}

#[tauri::command]
pub fn cloud_discard(preview_id: Uuid) {
    cloud::discard(preview_id)
}

// ───────────────────────────── cloud sync groups ─────────────────────────────

#[tauri::command]
pub fn cloud_sync_list(
    state: State<'_, AppState>,
    vault_id: Option<Uuid>,
) -> Result<Vec<CloudSyncGroup>> {
    cloud_sync::list(&*state.store()?, vault_id)
}

#[tauri::command]
pub fn cloud_sync_get(
    state: State<'_, AppState>,
    group_id: Uuid,
) -> Result<Option<CloudSyncGroup>> {
    cloud_sync::get(&*state.store()?, group_id)
}

/// Create or update a group's cloud sync. `secret` is encrypted into local
/// metadata and never returned; pass `None` to keep the stored one.
#[tauri::command]
pub fn cloud_sync_save(
    state: State<'_, AppState>,
    group_id: Uuid,
    config: CloudSyncConfig,
    secret: Option<CloudSyncSecret>,
) -> Result<CloudSyncGroup> {
    cloud_sync::save(&*state.store()?, group_id, config, secret)
}

#[tauri::command]
pub fn cloud_sync_forget(state: State<'_, AppState>, group_id: Uuid) -> Result<()> {
    cloud_sync::forget(&*state.store()?, group_id)
}

/// "Sync now": list machines with the stored credentials and reconcile the
/// group's hosts. Emits the same `cloud-sync` event the scheduler does.
#[tauri::command]
pub async fn cloud_sync_run(
    app: AppHandle,
    state: State<'_, AppState>,
    group_id: Uuid,
) -> Result<CloudSyncGroup> {
    let group = cloud_sync::run(&*state.store()?, group_id).await?;
    let _ = app.emit(cloud_sync::EVENT, &group);
    Ok(group)
}

// ───────────────────────────── local discovery ─────────────────────────────

/// Browse the LAN for SSH servers advertised over mDNS/DNS-SD. Candidates
/// only; nothing is stored until the user imports one.
#[tauri::command]
pub async fn mdns_browse(timeout_ms: Option<u64>) -> Result<Vec<termoso_core::mdns::LocalDevice>> {
    let timeout = timeout_ms
        .map(std::time::Duration::from_millis)
        .unwrap_or(termoso_core::mdns::DEFAULT_TIMEOUT);
    Ok(termoso_core::mdns::browse(timeout).await?)
}

/// Machines known to the local Tailscale / NetBird / ZeroTier client.
#[tauri::command]
pub async fn tailnet_scan() -> Result<crate::tailnet::TailnetScan> {
    crate::tailnet::scan().await
}

// ───────────────────────────── export / backup ─────────────────────────────

/// Write hosts as CSV. Passwords are left blank unless `include_passwords`.
#[tauri::command]
pub async fn hosts_export_csv(
    state: State<'_, AppState>,
    vault_id: Option<Uuid>,
    include_passwords: bool,
    path: String,
) -> Result<backup::CsvExportReport> {
    backup::export_hosts_csv(&*state.store()?, vault_id, include_passwords, &path)
}

/// Write SSH hosts as an OpenSSH `ssh_config` fragment or an Ansible INI
/// inventory (`format`: `ssh_config` | `ansible`). Never includes secrets.
#[tauri::command]
pub async fn hosts_export_as(
    state: State<'_, AppState>,
    vault_id: Option<Uuid>,
    format: String,
    path: String,
) -> Result<backup::CsvExportReport> {
    backup::export_hosts_as(&*state.store()?, vault_id, &format, &path)
}

/// Wake-on-LAN: send the magic packet for the host's MAC (optionally to a
/// specific broadcast address). Returns how many datagrams went out.
#[tauri::command]
pub async fn wake_host(mac: String, broadcast: Option<String>) -> Result<usize> {
    let target = match broadcast
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(b) => Some(
            b.parse()
                .map_err(|_| DesktopError::invalid(format!("not an IP address: {b}")))?,
        ),
        None => None,
    };
    Ok(termoso_core::wol::wake(&mac, target).await?)
}

/// Encrypt the given vaults (all unlocked when empty) into a `.termoso` file.
#[tauri::command]
pub async fn backup_export(
    state: State<'_, AppState>,
    vault_ids: Vec<Uuid>,
    password: String,
    path: String,
) -> Result<BackupSummary> {
    let store = state.store()?.clone();
    tauri::async_runtime::spawn_blocking(move || {
        backup::export_file(&store, &vault_ids, &password, &path)
    })
    .await
    .map_err(|e| crate::error::DesktopError::new("backup", e.to_string()))?
}

/// Decrypt a backup and describe its contents; nothing is written yet.
#[tauri::command]
pub async fn backup_inspect(path: String, password: String) -> Result<BackupSummary> {
    tauri::async_runtime::spawn_blocking(move || backup::inspect_file(&path, &password))
        .await
        .map_err(|e| crate::error::DesktopError::new("backup", e.to_string()))?
}

#[tauri::command]
pub fn backup_discard(preview_id: Uuid) {
    backup::discard(preview_id)
}

/// Restore vault `source` of an inspected backup into `vault_id`.
#[tauri::command]
pub async fn backup_restore<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    preview_id: Uuid,
    source: usize,
    vault_id: Uuid,
) -> Result<backup::RestoreReport> {
    let report = backup::apply(&*state.store()?, preview_id, source, vault_id)?;
    let _ = app.emit(SYNC_EVENT, SyncNotice::EntitiesChanged { vault_id });
    Ok(report)
}

// ───────────────────────────── logs ─────────────────────────────

#[tauri::command]
pub async fn logs_list(state: State<'_, AppState>) -> Result<Vec<LogCard>> {
    logs::list(&*state.store()?)
}

/// Fetch the encrypted body from the server when it is not on this device
/// yet (a teammate's recording, or our own from another device).
async fn ensure_body<R: Runtime>(app: &AppHandle<R>, id: Uuid) -> Result<()> {
    let state = app.state::<AppState>();
    let card = logs::list(&*state.store()?)?
        .into_iter()
        .find(|l| l.id == id)
        .ok_or_else(|| DesktopError::not_found(format!("log {id}")))?;
    if card.cached || !card.uploaded {
        return Ok(());
    }
    let engine = account::engine(app)
        .await
        .ok_or_else(|| DesktopError::invalid("sign in to download this recording"))?;
    engine.download_log(id).await?;
    Ok(())
}

#[tauri::command]
pub async fn log_read<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<LogBody> {
    ensure_body(&app, id).await?;
    logs::read(&*state.store()?, id)
}

#[tauri::command]
pub async fn log_export<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    id: Uuid,
    path: String,
) -> Result<usize> {
    ensure_body(&app, id).await?;
    logs::export(&*state.store()?, id, &path)
}

/// Pin / annotate for the team. Goes through the server when it knows the
/// recording (so teammates see it); otherwise stays local.
#[tauri::command]
pub async fn log_annotate<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    id: Uuid,
    pinned: Option<bool>,
    note: Option<String>,
) -> Result<LogCard> {
    let card = logs::list(&*state.store()?)?
        .into_iter()
        .find(|l| l.id == id)
        .ok_or_else(|| DesktopError::not_found(format!("log {id}")))?;
    let note = note.map(|n| n.trim().to_string());
    if let Some(n) = &note {
        logs::check_note(n)?;
    }
    match account::engine(&app).await {
        Some(engine) if card.uploaded => {
            if !card.can_annotate {
                return Err(DesktopError::forbidden(
                    "Editor role required to pin or annotate",
                ));
            }
            engine.annotate_log(id, pinned, note).await?;
            logs::list(&*state.store()?)?
                .into_iter()
                .find(|l| l.id == id)
                .ok_or_else(|| DesktopError::not_found(format!("log {id}")))
        }
        _ => logs::annotate_local(&*state.store()?, id, pinned, note.as_deref()),
    }
}

/// Turn recording of every member's sessions in a team vault on or off
/// (vault manager).
#[tauri::command]
pub async fn vault_session_logging_set<R: Runtime>(
    app: AppHandle<R>,
    vault_id: Uuid,
    on: bool,
) -> Result<()> {
    let engine = account::engine(&app)
        .await
        .ok_or_else(|| DesktopError::invalid("sign in to change team vault settings"))?;
    engine.set_vault_session_logging(vault_id, on).await?;
    let _ = app.emit(SYNC_EVENT, SyncNotice::VaultsChanged);
    Ok(())
}

#[tauri::command]
pub async fn log_delete<R: Runtime>(app: AppHandle<R>, id: Uuid) -> Result<()> {
    logs::delete(&*app.state::<AppState>().store()?, id)?;
    if let Some(engine) = account::engine(&app).await {
        engine.request_sync();
    }
    Ok(())
}

#[tauri::command]
pub async fn log_bookmarks(state: State<'_, AppState>, log_id: Uuid) -> Result<Vec<BookmarkCard>> {
    logs::bookmarks(&*state.store()?, log_id)
}

#[tauri::command]
pub async fn log_bookmark_add(
    state: State<'_, AppState>,
    log_id: Uuid,
    offset: u64,
    note: String,
) -> Result<BookmarkCard> {
    logs::add_bookmark(&*state.store()?, log_id, offset, &note)
}

#[tauri::command]
pub async fn log_bookmark_delete(state: State<'_, AppState>, id: Uuid) -> Result<()> {
    logs::delete_bookmark(&*state.store()?, id)
}

// ───────────────────────────── account / sync ─────────────────────────────

#[tauri::command]
pub async fn account_status<R: Runtime>(app: AppHandle<R>) -> Result<AccountStatus> {
    account::current(&app).await
}

#[tauri::command]
pub async fn account_server_info(server_url: String) -> Result<ServerInfo> {
    account::server_info(&server_url).await
}

#[tauri::command]
pub async fn account_login<R: Runtime>(app: AppHandle<R>, form: LoginForm) -> Result<LoginOutcome> {
    account::login(&app, form).await
}

#[tauri::command]
pub async fn account_mfa<R: Runtime>(
    app: AppHandle<R>,
    credential: MfaCredential,
) -> Result<LoginOutcome> {
    account::mfa(&app, credential).await
}

#[tauri::command]
pub async fn account_mfa_email_send<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    account::mfa_email_send(&app).await
}

#[tauri::command]
pub async fn account_webauthn_challenge<R: Runtime>(
    app: AppHandle<R>,
) -> Result<serde_json::Value> {
    account::webauthn_challenge(&app).await
}

#[tauri::command]
pub async fn account_device_approve<R: Runtime>(
    app: AppHandle<R>,
    code: String,
) -> Result<LoginOutcome> {
    account::approve_device(&app, &code).await
}

#[tauri::command]
pub async fn account_device_resend<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    account::resend_device_code(&app).await
}

#[tauri::command]
pub async fn account_cancel_login<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    account::cancel_login(&app).await
}

/// Write UTF-8 text to a path the user picked in a save dialog (exports).
#[tauri::command]
pub async fn save_text_file(path: String, contents: String) -> Result<()> {
    tokio::fs::write(&path, contents.as_bytes())
        .await
        .map_err(|e| DesktopError::invalid(format!("cannot write {path}: {e}")))?;
    Ok(())
}

#[tauri::command]
pub async fn account_sso_discover(
    server_url: String,
    email: String,
) -> Result<termoso_proto::auth::SsoDiscoverResponse> {
    account::sso_discover(&server_url, &email).await
}

#[tauri::command]
pub async fn account_sso_start<R: Runtime>(
    app: AppHandle<R>,
    form: account::SsoStartForm,
) -> Result<String> {
    account::sso_start(&app, form).await
}

#[tauri::command]
pub async fn account_sso_poll<R: Runtime>(app: AppHandle<R>) -> Result<account::SsoOutcome> {
    account::sso_poll(&app).await
}

#[tauri::command]
pub async fn account_sso_callback<R: Runtime>(
    app: AppHandle<R>,
    flow_id: String,
) -> Result<account::SsoOutcome> {
    account::sso_callback(&app, &flow_id).await
}

#[tauri::command]
pub async fn account_sso_cancel<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    account::sso_cancel(&app).await
}

#[tauri::command]
pub async fn account_register<R: Runtime>(
    app: AppHandle<R>,
    form: RegisterForm,
) -> Result<Registered> {
    account::register(&app, form).await
}

#[tauri::command]
pub async fn account_sign_out<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    account::sign_out(&app).await
}

#[tauri::command]
pub async fn account_sync_now<R: Runtime>(app: AppHandle<R>) -> Result<SyncStatus> {
    account::sync_now(&app).await
}

#[tauri::command]
pub async fn account_set_credential_sync<R: Runtime>(
    app: AppHandle<R>,
    on: bool,
) -> Result<AccountStatus> {
    account::set_credential_sync(&app, on).await
}

#[tauri::command]
pub async fn account_devices<R: Runtime>(app: AppHandle<R>) -> Result<Vec<Device>> {
    account::devices(&app).await
}

#[tauri::command]
pub async fn account_device_revoke<R: Runtime>(app: AppHandle<R>, id: Uuid) -> Result<()> {
    account::revoke_device(&app, id).await
}

#[tauri::command]
pub async fn account_reauth_start<R: Runtime>(
    app: AppHandle<R>,
    password: Zeroizing<String>,
) -> Result<ReauthOutcome> {
    account::reauth_start(&app, password).await
}

#[tauri::command]
pub async fn account_reauth_mfa<R: Runtime>(
    app: AppHandle<R>,
    credential: MfaCredential,
) -> Result<ReauthOutcome> {
    account::reauth_mfa(&app, credential).await
}

#[tauri::command]
pub async fn account_reauth_email_code<R: Runtime>(
    app: AppHandle<R>,
    code: String,
) -> Result<ReauthOutcome> {
    account::reauth_email_code(&app, code).await
}

#[tauri::command]
pub async fn account_reauth_mfa_email_send<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    account::reauth_mfa_email_send(&app).await
}

#[tauri::command]
pub async fn account_reauth_webauthn_challenge<R: Runtime>(
    app: AppHandle<R>,
) -> Result<serde_json::Value> {
    account::reauth_webauthn_challenge(&app).await
}

#[tauri::command]
pub async fn account_reauth_cancel<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    account::reauth_cancel(&app).await
}

#[tauri::command]
pub async fn account_vault_members<R: Runtime>(
    app: AppHandle<R>,
    vault_id: Uuid,
) -> Result<Vec<VaultMember>> {
    account::vault_members(&app, vault_id).await
}

// ───────────────────────────── SSH ID ─────────────────────────────

#[tauri::command]
pub async fn sshid_view<R: Runtime>(app: AppHandle<R>) -> Result<SshIdView> {
    sshid::view(&app).await
}

#[tauri::command]
pub async fn sshid_create<R: Runtime>(app: AppHandle<R>, handle: String) -> Result<SshIdView> {
    sshid::create(&app, &handle).await
}

#[tauri::command]
pub async fn sshid_delete<R: Runtime>(app: AppHandle<R>) -> Result<SshIdView> {
    sshid::delete(&app).await
}

#[tauri::command]
pub async fn sshid_publish<R: Runtime>(app: AppHandle<R>) -> Result<SshIdView> {
    sshid::publish_now(&app).await
}

#[tauri::command]
pub async fn sshid_rotate<R: Runtime>(app: AppHandle<R>) -> Result<SshIdView> {
    sshid::rotate(&app).await
}

/// Blocks until the token is touched; the generation runs off-runtime.
#[tauri::command]
pub async fn sshid_add_fido2<R: Runtime>(
    app: AppHandle<R>,
    form: SshIdFido2Form,
) -> Result<SshIdView> {
    sshid::add_fido2(&app, form).await
}

#[tauri::command]
pub async fn sshid_add_public_key<R: Runtime>(
    app: AppHandle<R>,
    label: String,
    public_key: String,
) -> Result<SshIdView> {
    sshid::add_public_key(&app, label, public_key).await
}

#[tauri::command]
pub async fn sshid_remove_key<R: Runtime>(app: AppHandle<R>, id: Uuid) -> Result<SshIdView> {
    sshid::remove_key(&app, id).await
}

#[tauri::command]
pub async fn sshid_remove_device<R: Runtime>(
    app: AppHandle<R>,
    device_id: Uuid,
) -> Result<SshIdView> {
    sshid::remove_device(&app, device_id).await
}

// ───────────────────────────── teams ─────────────────────────────

#[tauri::command]
pub async fn teams_list<R: Runtime>(app: AppHandle<R>) -> Result<Vec<Team>> {
    team::list(&app).await
}

#[tauri::command]
pub async fn team_create<R: Runtime>(app: AppHandle<R>, name: String) -> Result<Team> {
    team::create(&app, &name).await
}

#[tauri::command]
pub async fn team_rename<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    name: String,
) -> Result<Team> {
    team::rename(&app, team_id, &name).await
}

#[tauri::command]
pub async fn team_set_security<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    multiplayer_enabled: Option<bool>,
    require_mfa: Option<bool>,
    presence_enabled: Option<bool>,
) -> Result<Team> {
    team::set_security(
        &app,
        team_id,
        multiplayer_enabled,
        require_mfa,
        presence_enabled,
    )
    .await
}

#[tauri::command]
pub async fn team_delete<R: Runtime>(app: AppHandle<R>, team_id: Uuid) -> Result<()> {
    team::delete(&app, team_id).await
}

#[tauri::command]
pub async fn team_leave<R: Runtime>(app: AppHandle<R>, team_id: Uuid) -> Result<()> {
    team::leave(&app, team_id).await
}

#[tauri::command]
pub async fn team_accept_invite<R: Runtime>(app: AppHandle<R>, link: String) -> Result<Team> {
    team::accept_invite(&app, &link).await
}

#[tauri::command]
pub async fn team_members<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<Vec<TeamMemberCard>> {
    team::members(&app, team_id).await
}

#[tauri::command]
pub async fn team_member_set_role<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    user_id: Uuid,
    role: TeamRole,
) -> Result<()> {
    team::set_member_role(&app, team_id, user_id, role).await
}

#[tauri::command]
pub async fn team_member_remove<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<()> {
    team::remove_member(&app, team_id, user_id).await
}

#[tauri::command]
pub async fn team_member_delete_account<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<()> {
    team::delete_member_account(&app, team_id, user_id).await
}

#[tauri::command]
pub async fn team_invites<R: Runtime>(app: AppHandle<R>, team_id: Uuid) -> Result<Vec<Invite>> {
    team::invites(&app, team_id).await
}

#[tauri::command]
pub async fn team_invite<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    emails: Vec<String>,
    role: TeamRole,
    vault_ids: Vec<Uuid>,
) -> Result<Vec<InviteResult>> {
    team::invite(&app, team_id, emails, role, vault_ids).await
}

#[tauri::command]
pub async fn team_invite_revoke<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    invite_id: Uuid,
) -> Result<()> {
    team::revoke_invite(&app, team_id, invite_id).await
}

#[tauri::command]
pub async fn team_pending_keys<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<Vec<PendingKeyCard>> {
    team::pending_keys(&app, team_id).await
}

#[tauri::command]
pub async fn team_audit<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    filter: Option<team::AuditFilter>,
) -> Result<team::AuditPage> {
    team::audit(&app, team_id, filter.unwrap_or_default()).await
}

#[tauri::command]
pub async fn team_permissions<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::PermissionCatalog> {
    team::permissions(&app, team_id).await
}

#[tauri::command]
pub async fn team_roles<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::TeamRoleList> {
    team::roles(&app, team_id).await
}

#[tauri::command]
pub async fn team_role_create<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    req: proto::CreateRoleRequest,
) -> Result<proto::TeamRoleDef> {
    team::role_create(&app, team_id, req).await
}

#[tauri::command]
pub async fn team_role_update<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    role_id: Uuid,
    req: proto::UpdateRoleRequest,
) -> Result<proto::TeamRoleDef> {
    team::role_update(&app, team_id, role_id, req).await
}

#[tauri::command]
pub async fn team_role_delete<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    role_id: Uuid,
    reassign_to: Option<Uuid>,
) -> Result<()> {
    team::role_delete(&app, team_id, role_id, reassign_to).await
}

#[tauri::command]
pub async fn team_set_default_role<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    role_id: Uuid,
) -> Result<()> {
    team::set_default_role(&app, team_id, role_id).await
}

#[tauri::command]
pub async fn team_role_mappings<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<Vec<proto::RoleMapping>> {
    team::role_mappings(&app, team_id).await
}

#[tauri::command]
pub async fn team_set_role_mappings<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    mappings: Vec<proto::RoleMapping>,
) -> Result<Vec<proto::RoleMapping>> {
    team::set_role_mappings(&app, team_id, mappings).await
}

#[tauri::command]
pub async fn team_policies<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::TeamPoliciesResponse> {
    team::policies(&app, team_id).await
}

#[tauri::command]
pub async fn team_ca<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<Option<termoso_proto::ca::TeamCa>> {
    team::ca(&app, team_id).await
}

#[tauri::command]
pub async fn team_update_ca<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    patch: termoso_proto::ca::UpdateTeamCaRequest,
) -> Result<termoso_proto::ca::TeamCa> {
    team::update_ca(&app, team_id, patch).await
}

#[tauri::command]
pub async fn team_delete_ca<R: Runtime>(app: AppHandle<R>, team_id: Uuid) -> Result<()> {
    team::delete_ca(&app, team_id).await
}

#[tauri::command]
pub async fn team_rotate_ca<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    grace_hours: Option<i32>,
) -> Result<termoso_proto::ca::TeamCa> {
    team::rotate_ca(&app, team_id, grace_hours).await
}

#[tauri::command]
pub async fn team_ca_certificates<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<termoso_proto::ca::IssuedCertificateList> {
    team::ca_certificates(&app, team_id).await
}

#[tauri::command]
pub async fn team_ca_revoke<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    certificate_id: Uuid,
) -> Result<termoso_proto::ca::IssuedCertificate> {
    team::ca_revoke(&app, team_id, certificate_id).await
}

#[tauri::command]
pub async fn team_ca_local<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<Option<termoso_core::ca::CachedCert>> {
    team::ca_local(&app, team_id).await
}

#[tauri::command]
pub async fn team_update_policies<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    patch: proto::UpdateTeamPoliciesRequest,
) -> Result<proto::TeamPoliciesResponse> {
    team::update_policies(&app, team_id, patch).await
}

#[tauri::command]
pub async fn team_idp<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::TeamIdpResponse> {
    team::idp(&app, team_id).await
}

#[tauri::command]
pub async fn team_update_idp<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    patch: proto::UpdateTeamIdpRequest,
) -> Result<proto::TeamIdpResponse> {
    team::update_idp(&app, team_id, patch).await
}

#[tauri::command]
pub async fn team_test_idp<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    patch: proto::UpdateTeamIdpRequest,
) -> Result<proto::TeamIdpResponse> {
    team::test_idp(&app, team_id, patch).await
}

#[tauri::command]
pub async fn team_delete_idp<R: Runtime>(app: AppHandle<R>, team_id: Uuid) -> Result<()> {
    team::delete_idp(&app, team_id).await
}

#[tauri::command]
pub async fn team_acl<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    vault_id: Uuid,
) -> Result<Vec<proto::EntityAclRule>> {
    team::acl(&app, team_id, vault_id).await
}

#[tauri::command]
pub async fn team_upsert_acl<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    vault_id: Uuid,
    rule: proto::UpsertEntityAclRequest,
) -> Result<Vec<proto::EntityAclRule>> {
    team::upsert_acl(&app, team_id, vault_id, rule).await
}

#[tauri::command]
pub async fn team_delete_acl<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    vault_id: Uuid,
    rule_id: Uuid,
) -> Result<()> {
    team::delete_acl(&app, team_id, vault_id, rule_id).await
}

#[tauri::command]
pub async fn acl_me<R: Runtime>(app: AppHandle<R>) -> Result<Vec<proto::MyAclRule>> {
    team::acl_me(&app).await
}

#[tauri::command]
pub async fn team_logs<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    vault_id: Option<Uuid>,
) -> Result<termoso_proto::logs::LogListResponse> {
    team::logs(&app, team_id, vault_id).await
}

#[tauri::command]
pub async fn team_logs_export<R: Runtime>(app: AppHandle<R>, team_id: Uuid) -> Result<String> {
    team::logs_export(&app, team_id).await
}

#[tauri::command]
pub async fn team_rotation<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::RotationOverview> {
    team::rotation(&app, team_id).await
}

#[tauri::command]
pub async fn team_create_rotation_jobs<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    req: proto::CreateRotationJobsRequest,
) -> Result<Vec<proto::RotationJob>> {
    team::create_rotation_jobs(&app, team_id, req).await
}

#[tauri::command]
pub async fn rotation_jobs<R: Runtime>(app: AppHandle<R>) -> Result<Vec<proto::RotationJob>> {
    team::rotation_jobs(&app).await
}

#[tauri::command]
pub async fn rotation_update_job<R: Runtime>(
    app: AppHandle<R>,
    job_id: Uuid,
    req: proto::UpdateRotationJobRequest,
) -> Result<proto::RotationJob> {
    team::rotation_update_job(&app, job_id, req).await
}

#[tauri::command]
pub async fn rotation_run_job<R: Runtime>(
    app: AppHandle<R>,
    job_id: Uuid,
) -> Result<crate::rotation::RotationRunResult> {
    crate::rotation::run_job(&app, job_id).await
}

#[tauri::command]
pub async fn rotation_mark_done<R: Runtime>(
    app: AppHandle<R>,
    job_id: Uuid,
) -> Result<termoso_proto::team::RotationJob> {
    crate::rotation::mark_done(&app, job_id).await
}

#[tauri::command]
pub async fn rotation_cancel_job<R: Runtime>(app: AppHandle<R>, job_id: Uuid) -> Result<()> {
    team::rotation_cancel_job(&app, job_id).await
}

#[tauri::command]
pub async fn team_access_requests<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::AccessRequestList> {
    team::access_requests(&app, team_id).await
}

#[tauri::command]
pub async fn team_create_access_request<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    req: proto::CreateAccessRequest,
) -> Result<proto::AccessRequest> {
    team::create_access_request(&app, team_id, req).await
}

#[tauri::command]
pub async fn team_cancel_access_request<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    rid: Uuid,
) -> Result<()> {
    team::cancel_access_request(&app, team_id, rid).await
}

#[tauri::command]
pub async fn team_decide_access_request<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    rid: Uuid,
    action: String,
    req: proto::DecideAccessRequest,
) -> Result<proto::AccessRequest> {
    team::decide_access_request(&app, team_id, rid, action, req).await
}

#[tauri::command]
pub async fn team_data<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::TeamDataStatus> {
    team::data(&app, team_id).await
}

#[tauri::command]
pub async fn team_export<R: Runtime>(app: AppHandle<R>, team_id: Uuid) -> Result<String> {
    team::export(&app, team_id).await
}

#[tauri::command]
pub async fn team_schedule_deletion<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    confirm_name: String,
) -> Result<proto::TeamDataStatus> {
    team::schedule_deletion(&app, team_id, confirm_name).await
}

#[tauri::command]
pub async fn team_cancel_deletion<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::TeamDataStatus> {
    team::cancel_deletion(&app, team_id).await
}

#[tauri::command]
pub async fn team_devices<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<proto::TeamDeviceList> {
    team::devices(&app, team_id).await
}

#[tauri::command]
pub async fn team_approve_device<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    device_id: Uuid,
) -> Result<()> {
    team::approve_device(&app, team_id, device_id).await
}

#[tauri::command]
pub async fn team_reject_device<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    device_id: Uuid,
) -> Result<()> {
    team::reject_device(&app, team_id, device_id).await
}

#[tauri::command]
pub async fn team_webhooks<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<Vec<proto::Webhook>> {
    team::webhooks(&app, team_id).await
}

#[tauri::command]
pub async fn team_webhook_create<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    req: proto::CreateWebhookRequest,
) -> Result<proto::Webhook> {
    team::webhook_create(&app, team_id, req).await
}

#[tauri::command]
pub async fn team_webhook_update<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    hook_id: Uuid,
    req: proto::UpdateWebhookRequest,
) -> Result<proto::Webhook> {
    team::webhook_update(&app, team_id, hook_id, req).await
}

#[tauri::command]
pub async fn team_webhook_delete<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    hook_id: Uuid,
) -> Result<()> {
    team::webhook_delete(&app, team_id, hook_id).await
}

#[tauri::command]
pub async fn team_webhook_test<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    hook_id: Uuid,
) -> Result<Vec<proto::WebhookDelivery>> {
    team::webhook_test(&app, team_id, hook_id).await
}

#[tauri::command]
pub async fn team_webhook_deliveries<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    hook_id: Uuid,
) -> Result<Vec<proto::WebhookDelivery>> {
    team::webhook_deliveries(&app, team_id, hook_id).await
}

#[tauri::command]
pub async fn team_presence<R: Runtime>(app: AppHandle<R>, team_id: Uuid) -> Result<TeamPresence> {
    presence::team(&app, team_id).await
}

#[tauri::command]
pub async fn account_profile<R: Runtime>(app: AppHandle<R>) -> Result<UserProfile> {
    presence::profile(&app).await
}

/// Raw WebP bytes (empty when there is no picture) so the webview can build
/// a blob URL without a base64 round trip.
#[tauri::command]
pub async fn user_avatar<R: Runtime>(
    app: AppHandle<R>,
    user_id: Uuid,
    tag: String,
) -> Result<tauri::ipc::Response> {
    let bytes = avatars::user_avatar(&app, user_id, tag).await?;
    Ok(tauri::ipc::Response::new(bytes.unwrap_or_default()))
}

#[tauri::command]
pub async fn account_set_presence_hidden<R: Runtime>(
    app: AppHandle<R>,
    hidden: bool,
) -> Result<UserProfile> {
    presence::set_hidden(&app, hidden).await
}

#[tauri::command]
pub async fn ai_status<R: Runtime>(app: AppHandle<R>) -> Result<AiStatus> {
    ai::status(&app).await
}

#[tauri::command]
pub async fn ai_set_enabled<R: Runtime>(app: AppHandle<R>, enabled: bool) -> Result<AiStatus> {
    ai::set_enabled(&app, enabled).await
}

#[tauri::command]
pub async fn ai_ask<R: Runtime>(app: AppHandle<R>, form: AskForm) -> Result<AiCommandResponse> {
    ai::ask(&app, form).await
}

#[tauri::command]
pub async fn team_vault_create<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    name: String,
    access: Vec<VaultAccess>,
) -> Result<()> {
    team::create_vault(&app, team_id, &name, access).await
}

#[tauri::command]
pub async fn team_vault_rename<R: Runtime>(
    app: AppHandle<R>,
    vault_id: Uuid,
    name: String,
) -> Result<()> {
    team::rename_vault(&app, vault_id, &name).await
}

#[tauri::command]
pub async fn team_vault_delete<R: Runtime>(app: AppHandle<R>, vault_id: Uuid) -> Result<()> {
    team::delete_vault(&app, vault_id).await
}

#[tauri::command]
pub async fn team_vault_set_access<R: Runtime>(
    app: AppHandle<R>,
    vault_id: Uuid,
    user_id: Uuid,
    role: VaultRole,
) -> Result<()> {
    team::set_vault_access(&app, vault_id, user_id, role).await
}

#[tauri::command]
pub async fn team_vault_remove_access<R: Runtime>(
    app: AppHandle<R>,
    vault_id: Uuid,
    user_id: Uuid,
) -> Result<()> {
    team::remove_vault_access(&app, vault_id, user_id).await
}

#[tauri::command]
pub async fn team_vault_rotate_key<R: Runtime>(app: AppHandle<R>, vault_id: Uuid) -> Result<()> {
    team::rotate_vault_key(&app, vault_id).await
}

// ───────────────────────────── multiplayer ─────────────────────────────

#[tauri::command]
pub async fn multiplayer_start<R: Runtime>(app: AppHandle<R>, id: Uuid) -> Result<ShareInfo> {
    multiplayer::start(&app, id).await
}

#[tauri::command]
pub async fn multiplayer_stop<R: Runtime>(app: AppHandle<R>, id: Uuid) -> Result<()> {
    multiplayer::stop(&app, id).await
}

#[tauri::command]
pub fn multiplayer_info(state: State<'_, AppState>, id: Uuid) -> Option<ShareInfo> {
    state.multiplayer.info(id)
}

#[tauri::command]
pub fn multiplayer_set_control<R: Runtime>(
    app: AppHandle<R>,
    id: Uuid,
    user_id: Uuid,
    enabled: bool,
) -> Result<()> {
    multiplayer::set_control(&app, id, user_id, enabled)
}

// ───────────────────────────── updates ─────────────────────────────

#[tauri::command]
pub async fn update_check<R: Runtime>(app: AppHandle<R>) -> Result<Option<UpdateInfo>> {
    update::check(&app).await
}

#[tauri::command]
pub async fn update_install<R: Runtime>(app: AppHandle<R>) -> Result<UpdateInfo> {
    update::install(&app).await
}

#[tauri::command]
pub fn update_restart<R: Runtime>(app: AppHandle<R>) {
    app.restart()
}

#[tauri::command]
pub async fn team_automations<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<termoso_proto::automation::AutomationList> {
    crate::automations::list(&app, team_id).await
}

#[tauri::command]
pub async fn team_automation_create<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    req: termoso_proto::automation::CreateAutomationRequest,
) -> Result<termoso_proto::automation::Automation> {
    crate::automations::create(&app, team_id, req).await
}

#[tauri::command]
pub async fn team_automation_update<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    id: Uuid,
    req: termoso_proto::automation::UpdateAutomationRequest,
) -> Result<termoso_proto::automation::Automation> {
    crate::automations::update(&app, team_id, id, req).await
}

#[tauri::command]
pub async fn team_automation_delete<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    id: Uuid,
) -> Result<()> {
    crate::automations::delete(&app, team_id, id).await
}

#[tauri::command]
pub async fn team_automation_run_now<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    id: Uuid,
) -> Result<termoso_proto::automation::AutomationRun> {
    crate::automations::run_now(&app, team_id, id).await
}

#[tauri::command]
pub async fn team_automation_runs<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    id: Uuid,
) -> Result<termoso_proto::automation::AutomationRunList> {
    crate::automations::runs(&app, team_id, id).await
}

/// Run due automations right now (the executor also polls every minute).
#[tauri::command]
pub async fn team_automations_execute<R: Runtime>(app: AppHandle<R>) -> Result<usize> {
    crate::automations::pass(&app).await
}

/// Gateways (API bridges in `gateway` mode) this account can tunnel through.
#[tauri::command]
pub async fn gateways_list<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> Result<Vec<termoso_proto::bridge::GatewayInfo>> {
    Ok(crate::account::api(&app).await?.gateways().await?.gateways)
}

#[tauri::command]
pub async fn team_access_reviews<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<termoso_proto::team::AccessReviewList> {
    team::access_reviews(&app, team_id).await
}

#[tauri::command]
pub async fn team_access_review<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    review_id: Uuid,
) -> Result<termoso_proto::team::AccessReviewDetail> {
    team::access_review(&app, team_id, review_id).await
}

#[tauri::command]
pub async fn team_access_review_open<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<termoso_proto::team::AccessReviewDetail> {
    team::open_access_review(&app, team_id).await
}

#[tauri::command]
pub async fn team_access_review_decide<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    review_id: Uuid,
    item_id: Uuid,
    req: termoso_proto::team::DecideAccessReviewItemRequest,
) -> Result<termoso_proto::team::AccessReviewItem> {
    team::decide_access_review_item(&app, team_id, review_id, item_id, req).await
}

#[tauri::command]
pub async fn team_access_review_complete<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    review_id: Uuid,
    req: termoso_proto::team::CompleteAccessReviewRequest,
) -> Result<termoso_proto::team::AccessReviewDetail> {
    team::complete_access_review(&app, team_id, review_id, req).await
}

#[tauri::command]
pub async fn team_access_review_cancel<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    review_id: Uuid,
) -> Result<termoso_proto::team::AccessReview> {
    team::cancel_access_review(&app, team_id, review_id).await
}

#[tauri::command]
pub async fn team_break_glass<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<Option<termoso_proto::team::BreakGlass>> {
    team::break_glass(&app, team_id).await
}

#[tauri::command]
pub async fn team_break_glass_configure<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    req: termoso_proto::team::ConfigureBreakGlassRequest,
) -> Result<termoso_proto::team::BreakGlass> {
    team::configure_break_glass(&app, team_id, req).await
}

#[tauri::command]
pub async fn team_break_glass_delete<R: Runtime>(app: AppHandle<R>, team_id: Uuid) -> Result<()> {
    team::delete_break_glass(&app, team_id).await
}

#[tauri::command]
pub async fn team_break_glass_use<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
    req: termoso_proto::team::UseBreakGlassRequest,
) -> Result<termoso_proto::team::BreakGlass> {
    team::use_break_glass(&app, team_id, req).await
}

#[tauri::command]
pub async fn team_break_glass_end<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<termoso_proto::team::BreakGlass> {
    team::end_break_glass(&app, team_id).await
}

#[tauri::command]
pub async fn team_audit_verify<R: Runtime>(
    app: AppHandle<R>,
    team_id: Uuid,
) -> Result<termoso_proto::team::AuditVerification> {
    team::verify_audit(&app, team_id).await
}
