//! The one object Kotlin holds: an open encrypted profile. Everything is
//! synchronous and cheap except key generation and connecting, which the
//! caller runs off the main thread (generation) or which run on the Rust
//! runtime and report back through the listener (sessions).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use termoso_client::hosts::{self, CopyCredentials};
use termoso_client::keychain;
use termoso_core::hostkey::KnownHosts;
use termoso_core::model::ResolvedHost;
use termoso_core::ssh::{IpVersion, SshTarget};
use termoso_core::store::Store;
use termoso_crypto::keys::SymmetricKey;
use zeroize::Zeroizing;

use crate::account::{
    AccountCard, AccountRuntime, AccountStatus, DeviceCard, LoginForm, LoginOutcome, MfaCard,
    MfaMethod, ReauthOutcome, RegisterForm, Registered, SecurityKeyCredential, SecurityKeyRequest,
    ServerCard, SsoDiscoverCard, SsoOutcome, SsoStarted, SyncListener, SyncStatus,
};
use crate::ai::{AiStatusCard, AiSuggestionCard, AiTarget};
use crate::connect::SecretCache;
use crate::dto::*;
use crate::error::{MobileError, Result};
use crate::fido2::{self, Fido2GenerateDraft, Fido2Listener, Fido2LoadDraft, SecurityKeyCard};
use crate::forward::{self, PfRuleDraft, PfRuleItem, PfTunnel, TunnelLaunch, TunnelListener};
use crate::import::{self as host_import, ImportPreviewItem};
use crate::keyexport::{KeyExport, KeyExportLaunch, KeyExportListener};
use crate::live::{LiveListener, LiveShare};
use crate::presence::{self, TeamPresenceCard};
use crate::quiet::{QuietLaunch, QuietRun, QuietRunListener};
use crate::serial::{PipeTerminal, SerialLine, SerialLink, SerialPipe, SerialSession};
use crate::session::{
    Launch, LaunchTarget, SessionListener, SshSession, TerminalOptions, Transport, ViewerLaunch,
};
use crate::settings::MobileSettings;
use crate::sftp::{Backend as FileBackend, SftpLaunch, SftpListener, SftpSession};
use crate::snippets::{self, SnippetDraft, SnippetItem, SnippetPackageItem, SnippetRun};
use crate::sshid::SshIdView;
use crate::team::{
    AccessRequestCard, AccessRequestsCard, AclRuleCard, AuditPage, InviteCard, InviteSent,
    PendingKeyCard, PermissionCard, RotationCard, TeamCard, TeamDataCard, TeamDevicesCard,
    TeamMemberCard, TeamPoliciesCard, TeamRole, TeamRoleCard, VaultAccessDraft, VaultMemberCard,
};
use crate::themes::TerminalTheme;

const DB_FILE: &str = "vault.db";
const AVATARS_DIR: &str = "avatars";

pub(crate) static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("termoso-rt")
        .enable_all()
        .build()
        .expect("tokio runtime")
});

/// Route Rust `tracing` output to logcat (tag `termoso`) on Android, the
/// unified log (subsystem `com.termoso`) on iOS, stderr elsewhere.
/// Idempotent. Never logs secrets: the core masks them.
#[uniffi::export]
pub fn init_logging(verbose: bool) {
    use tracing_subscriber::prelude::*;
    let level = if verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    let filter = tracing_subscriber::filter::LevelFilter::from_level(level);
    #[cfg(target_os = "android")]
    let layer = tracing_android::layer("termoso").ok();
    #[cfg(target_os = "ios")]
    let layer = Some(tracing_oslog::OsLogger::new("com.termoso", "core"));
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let layer = Some(tracing_subscriber::fmt::layer().with_target(false));
    if let Some(layer) = layer {
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(layer)
            .try_init();
    }
}

/// Crate version (`CARGO_PKG_VERSION`).
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The `mosh-server` command line used when a host sets none.
#[uniffi::export]
pub fn mosh_default_server_command() -> String {
    termoso_core::mosh::DEFAULT_SERVER_COMMAND.to_string()
}

/// A fresh 32-byte master key for a new profile. The caller wraps it with
/// the Android Keystore and hands it back to [`TermosoApp::open`] on every
/// launch; Rust never persists it.
#[uniffi::export]
pub fn generate_master_key() -> Vec<u8> {
    SymmetricKey::generate().as_bytes().to_vec()
}

/// Whether `profile_dir` already contains a vault.
#[uniffi::export]
pub fn profile_exists(profile_dir: String) -> bool {
    Path::new(&profile_dir).join(DB_FILE).is_file()
}

/// Parse `user@host:port`, `ssh://user@host:port`, `telnet://host:port` or
/// plain `host` into a target (defaults: port 22, telnet 23; the username
/// stays empty and is asked for on connect). Errors on an empty host.
#[uniffi::export]
pub fn parse_target(input: String) -> Result<QuickTarget> {
    let s = input.trim();
    let (protocol, s) = if let Some(rest) = s.strip_prefix("telnet://") {
        ("telnet", rest)
    } else {
        ("ssh", s.trim_start_matches("ssh://"))
    };
    let s = s.trim_end_matches('/');
    let (user, rest) = match s.rsplit_once('@') {
        Some((u, r)) if !u.is_empty() => (Some(u.to_string()), r),
        _ => (None, s),
    };
    let (host, port) = if let Some(stripped) = rest.strip_prefix('[') {
        // [v6]:port
        match stripped.split_once(']') {
            Some((h, p)) => (h.to_string(), p.trim_start_matches(':').parse::<u16>().ok()),
            None => (stripped.to_string(), None),
        }
    } else if rest.matches(':').count() == 1 {
        let (h, p) = rest.split_once(':').unwrap_or((rest, ""));
        (h.to_string(), p.parse::<u16>().ok())
    } else {
        (rest.to_string(), None)
    };
    if host.is_empty() {
        return Err(MobileError::invalid("host is empty"));
    }
    Ok(QuickTarget {
        host,
        port: port.unwrap_or(if protocol == "telnet" { 23 } else { 22 }),
        username: user.unwrap_or_default(),
        protocol: protocol.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct QuickTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// `ssh` | `telnet`.
    pub protocol: String,
}

/// What [`App::connect_local`] starts. Everything empty → the platform's
/// shell (`/system/bin/sh` on Android, `/bin/sh` on iOS, `$SHELL` elsewhere)
/// in `home`.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct LocalShell {
    /// Program and arguments.
    pub argv: Vec<String>,
    /// Working directory and `HOME`.
    pub home: String,
    /// Extra environment (`NAME=value`).
    pub env: Vec<String>,
}

/// Probe a server before sign-in. Nothing is contacted until the user
/// picked it.
#[uniffi::export]
pub fn server_info(url: String) -> Result<ServerCard> {
    RUNTIME.block_on(AccountRuntime::server_info(&url))
}

/// An open profile.
#[derive(uniffi::Object)]
pub struct TermosoApp {
    store: Arc<Store>,
    secrets: Arc<SecretCache>,
    profile_dir: PathBuf,
    account: Arc<AccountRuntime>,
    presence: Arc<presence::Tracker>,
}

impl Drop for TermosoApp {
    fn drop(&mut self) {
        self.account.shutdown(RUNTIME.handle());
    }
}

#[uniffi::export]
impl TermosoApp {
    /// Open (or create) the encrypted vault in `profile_dir` with the
    /// 32-byte master key from the Keystore.
    #[uniffi::constructor]
    pub fn open(profile_dir: String, master_key: Vec<u8>) -> Result<Arc<Self>> {
        let key: [u8; 32] = master_key
            .as_slice()
            .try_into()
            .map_err(|_| MobileError::invalid("master key must be 32 bytes"))?;
        let master = SymmetricKey::from_bytes(key);
        let dir = PathBuf::from(profile_dir);
        std::fs::create_dir_all(&dir)?;
        let store = Arc::new(Store::open(&dir.join(DB_FILE), master)?);
        let presence = presence::Tracker::new(store.clone());
        Ok(Arc::new(Self {
            account: AccountRuntime::new(store.clone(), presence.clone(), dir.join("logs")),
            store,
            secrets: Arc::new(SecretCache::default()),
            profile_dir: dir,
            presence,
        }))
    }

    pub fn profile_dir(&self) -> String {
        self.profile_dir.to_string_lossy().into_owned()
    }

    /// Stable per-install id (not sent anywhere in phase 1).
    pub fn device_id(&self) -> Result<String> {
        Ok(self.store.device_id()?.to_string())
    }

    // ---- vaults -------------------------------------------------------

    pub fn vaults(&self) -> Result<Vec<VaultInfo>> {
        Ok(self
            .store
            .vaults()?
            .into_iter()
            .map(VaultInfo::from)
            .collect())
    }

    pub fn local_vault(&self) -> Result<VaultInfo> {
        Ok(self.store.local_vault()?.into())
    }

    // ---- hosts --------------------------------------------------------

    /// Hosts of one vault, or of all vaults when `vault_id` is `None`.
    pub fn hosts(&self, vault_id: Option<String>) -> Result<Vec<HostItem>> {
        let vault = parse_opt_id(&vault_id)?;
        Ok(hosts::cards(&self.store, vault)?
            .into_iter()
            .map(HostItem::from)
            .collect())
    }

    pub fn host(&self, id: String) -> Result<HostItem> {
        let id = parse_id(&id)?;
        hosts::cards(&self.store, None)?
            .into_iter()
            .find(|c| c.id == id)
            .map(HostItem::from)
            .ok_or_else(|| MobileError::not_found("host"))
    }

    pub fn groups(&self, vault_id: Option<String>) -> Result<Vec<GroupItem>> {
        let vault = parse_opt_id(&vault_id)?;
        Ok(hosts::groups(&self.store, vault)?
            .into_iter()
            .map(GroupItem::from)
            .collect())
    }

    pub fn tags(&self, vault_id: Option<String>) -> Result<Vec<TagItem>> {
        let vault = parse_opt_id(&vault_id)?;
        Ok(hosts::tags(&self.store, vault)?
            .into_iter()
            .map(TagItem::from)
            .collect())
    }

    /// Editor model for an existing host (no password: `has_password` says
    /// whether one is stored).
    pub fn host_draft(&self, id: String) -> Result<HostDraft> {
        Ok(hosts::form(&self.store, parse_id(&id)?)?.into())
    }

    /// Empty editor model for a new host.
    pub fn new_host_draft(&self, vault_id: String, group_id: Option<String>) -> Result<HostDraft> {
        Ok(HostDraft::blank(
            parse_id(&vault_id)?,
            parse_opt_id(&group_id)?,
        ))
    }

    /// What a host in `group_id` inherits (placeholders for the editor).
    pub fn inherited(&self, group_id: Option<String>) -> Result<InheritedInfo> {
        Ok(hosts::inherited(&self.store, parse_opt_id(&group_id)?)?.into())
    }

    /// Create or update a host. Sections the mobile editor does not show
    /// are preserved on update.
    pub fn save_host(&self, draft: HostDraft) -> Result<HostItem> {
        if draft.label.trim().is_empty() && draft.address.trim().is_empty() {
            return Err(MobileError::invalid("address is required"));
        }
        let base = match parse_opt_id(&draft.id)? {
            Some(id) => hosts::form(&self.store, id)?,
            None => blank_form(parse_id(&draft.vault_id)?),
        };
        let form = draft.apply(base)?;
        Ok(hosts::save(&self.store, &form)?.into())
    }

    pub fn delete_host(&self, id: String) -> Result<()> {
        Ok(hosts::delete(&self.store, parse_id(&id)?)?)
    }

    pub fn delete_hosts(&self, ids: Vec<String>) -> Result<()> {
        for id in parse_ids(&ids)? {
            hosts::delete(&self.store, id)?;
        }
        Ok(())
    }

    pub fn duplicate_host(&self, id: String) -> Result<HostItem> {
        Ok(hosts::duplicate(&self.store, parse_id(&id)?)?.into())
    }

    pub fn move_hosts(&self, ids: Vec<String>, group_id: Option<String>) -> Result<()> {
        Ok(hosts::move_hosts(
            &self.store,
            &parse_ids(&ids)?,
            parse_opt_id(&group_id)?,
        )?)
    }

    // ---- proxies & jump chains -----------------------------------------

    /// Proxies of one vault, or of all vaults when `vault_id` is `None`.
    pub fn proxies(&self, vault_id: Option<String>) -> Result<Vec<ProxyItem>> {
        let vault = parse_opt_id(&vault_id)?;
        let identities = keychain::identities(&self.store, None)?;
        let label = |id: Option<uuid::Uuid>| {
            id.and_then(|i| {
                identities
                    .iter()
                    .find(|c| c.id == i)
                    .map(|c| c.label.clone())
            })
        };
        Ok(self
            .store
            .list::<termoso_core::model::Proxy>(vault)?
            .into_iter()
            .map(|e| ProxyItem {
                id: e.id.to_string(),
                vault_id: e.vault_id.to_string(),
                kind: e.data.kind.clone(),
                host: e.data.host.clone(),
                port: e.data.port,
                identity_id: e.data.identity_id.map(|i| i.to_string()),
                identity_label: label(e.data.identity_id),
                username: e.data.username.clone(),
                password: e.data.password.clone(),
            })
            .collect())
    }

    /// Create or update a proxy; returns its id.
    pub fn save_proxy(&self, draft: ProxyDraft) -> Result<String> {
        use termoso_core::ssh::proxy::ProxyKind;
        let kind = draft.kind.trim().to_ascii_lowercase();
        if ProxyKind::parse(&kind).is_none() {
            return Err(MobileError::invalid(format!(
                "unsupported proxy type {kind}"
            )));
        }
        let host = draft.host.trim().to_string();
        if host.is_empty() {
            return Err(MobileError::invalid("proxy host is required"));
        }
        let data = termoso_core::model::Proxy {
            kind,
            host,
            port: draft.port,
            identity_id: parse_opt_id(&draft.identity_id)?,
            username: draft
                .username
                .map(|u| u.trim().to_string())
                .filter(|u| !u.is_empty()),
            password: draft.password.filter(|p| !p.is_empty()),
        };
        Ok(match parse_opt_id(&draft.id)? {
            Some(id) => {
                self.store.update(id, &data)?;
                id
            }
            None => self.store.insert(parse_id(&draft.vault_id)?, &data)?,
        }
        .to_string())
    }

    pub fn delete_proxy(&self, id: String) -> Result<()> {
        Ok(self.store.delete(parse_id(&id)?)?)
    }

    /// Jump chains of one vault, or of all vaults when `vault_id` is `None`.
    pub fn host_chains(&self, vault_id: Option<String>) -> Result<Vec<HostChainItem>> {
        let vault = parse_opt_id(&vault_id)?;
        let cards = hosts::cards(&self.store, None)?;
        Ok(self
            .store
            .list::<termoso_core::model::HostChain>(vault)?
            .into_iter()
            .map(|e| HostChainItem {
                id: e.id.to_string(),
                vault_id: e.vault_id.to_string(),
                label: e.data.label.clone(),
                host_ids: e.data.host_ids.iter().map(ToString::to_string).collect(),
                host_labels: e
                    .data
                    .host_ids
                    .iter()
                    .filter_map(|h| cards.iter().find(|c| c.id == *h).map(|c| c.label.clone()))
                    .collect(),
            })
            .collect())
    }

    /// Create or update a jump chain; returns its id.
    pub fn save_host_chain(&self, draft: HostChainDraft) -> Result<String> {
        let host_ids = parse_ids(&draft.host_ids)?;
        if host_ids.is_empty() {
            return Err(MobileError::invalid("a chain needs at least one host"));
        }
        let data = termoso_core::model::HostChain {
            label: draft.label.trim().to_string(),
            host_ids,
        };
        Ok(match parse_opt_id(&draft.id)? {
            Some(id) => {
                self.store.update(id, &data)?;
                id
            }
            None => self.store.insert(parse_id(&draft.vault_id)?, &data)?,
        }
        .to_string())
    }

    pub fn delete_host_chain(&self, id: String) -> Result<()> {
        Ok(self.store.delete(parse_id(&id)?)?)
    }

    /// Copy hosts into another vault. `with_credentials` copies keys /
    /// passwords along (team vault sharing); otherwise only the address book.
    /// Move hosts into another vault (copy, then delete the originals).
    pub fn move_hosts_to_vault(
        &self,
        ids: Vec<String>,
        vault_id: String,
        with_credentials: bool,
    ) -> Result<Vec<String>> {
        let creds = if with_credentials {
            CopyCredentials::Shared
        } else {
            CopyCredentials::Personal
        };
        Ok(
            hosts::move_to_vault(&self.store, &parse_ids(&ids)?, parse_id(&vault_id)?, creds)?
                .into_iter()
                .map(|u| u.to_string())
                .collect(),
        )
    }

    pub fn copy_hosts_to_vault(
        &self,
        ids: Vec<String>,
        vault_id: String,
        with_credentials: bool,
    ) -> Result<Vec<String>> {
        let creds = if with_credentials {
            CopyCredentials::Shared
        } else {
            CopyCredentials::Personal
        };
        Ok(
            hosts::copy_to_vault(&self.store, &parse_ids(&ids)?, parse_id(&vault_id)?, creds)?
                .into_iter()
                .map(|u| u.to_string())
                .collect(),
        )
    }

    pub fn save_group(
        &self,
        vault_id: String,
        id: Option<String>,
        label: String,
        parent_id: Option<String>,
    ) -> Result<GroupItem> {
        Ok(hosts::save_group(
            &self.store,
            parse_id(&vault_id)?,
            parse_opt_id(&id)?,
            &label,
            parse_opt_id(&parent_id)?,
        )?
        .into())
    }

    /// Delete a group; hosts and sub-groups move up one level.
    pub fn delete_group(&self, id: String) -> Result<()> {
        Ok(hosts::delete_group(&self.store, parse_id(&id)?)?)
    }

    /// Find-or-create a tag by label in `vault_id`.
    pub fn create_tag(&self, vault_id: String, label: String) -> Result<TagItem> {
        let vault = parse_id(&vault_id)?;
        let label = label.trim();
        if label.is_empty() {
            return Err(MobileError::invalid("tag label is empty"));
        }
        if let Some(existing) = hosts::tags(&self.store, Some(vault))?
            .into_iter()
            .find(|t| t.label.eq_ignore_ascii_case(label))
        {
            return Ok(existing.into());
        }
        let id = self.store.insert(
            vault,
            &termoso_core::model::Tag {
                label: label.to_string(),
                color: None,
            },
        )?;
        hosts::tags(&self.store, Some(vault))?
            .into_iter()
            .find(|t| t.id == id)
            .map(TagItem::from)
            .ok_or_else(|| MobileError::not_found("tag"))
    }

    pub fn save_tag(&self, id: String, label: String) -> Result<TagItem> {
        Ok(hosts::tag_update(&self.store, parse_id(&id)?, label, None)?.into())
    }

    pub fn delete_tag(&self, id: String) -> Result<()> {
        Ok(hosts::tag_delete(&self.store, parse_id(&id)?)?)
    }

    // ---- keychain -----------------------------------------------------

    pub fn keys(&self, vault_id: Option<String>) -> Result<Vec<KeyItem>> {
        let vault = parse_opt_id(&vault_id)?;
        Ok(keychain::keys_list(&self.store, vault)?
            .into_iter()
            .map(KeyItem::from)
            .collect())
    }

    /// Generate a key pair into the vault. RSA 4096 takes a few seconds on
    /// a phone: call off the main thread.
    pub fn generate_key(&self, draft: KeyGenerateDraft) -> Result<KeyItem> {
        let form = keychain::GenerateForm {
            vault_id: parse_id(&draft.vault_id)?,
            label: draft.label,
            algorithm: draft.algorithm.into(),
            comment: draft.comment,
            passphrase: draft.passphrase,
            remember_passphrase: draft.remember_passphrase,
        };
        Ok(keychain::generate(&self.store, &form)?.into())
    }

    /// Inspect pasted private-key text before importing.
    pub fn inspect_private_key(&self, text: String) -> Result<KeyPreview> {
        Ok(keychain::inspect_private(&text)?.into())
    }

    /// Split a pasted / picked PEM file into the WebDAV editor's certificate
    /// and private-key fields (either may come back empty).
    pub fn split_client_pem(&self, text: String) -> Result<PemParts> {
        let p = termoso_core::webdav::split_client_pem(&text)?;
        Ok(PemParts {
            certificate: p.certificate,
            private_key: p.private_key,
        })
    }

    /// Validate a WebDAV client certificate + key pair; returns the leaf
    /// SHA-256 fingerprint.
    pub fn inspect_client_certificate(
        &self,
        certificate: String,
        private_key: String,
    ) -> Result<String> {
        Ok(
            termoso_core::webdav::ClientIdentity::from_pem(&certificate, &private_key)?
                .fingerprint(),
        )
    }

    /// Parse pasted text or a picked file (ssh_config, PuTTY .reg, MobaXterm,
    /// SecureCRT, ZOC, CSV) into a host preview; `source` overrides detection.
    pub fn import_parse(
        &self,
        text: String,
        file_name: String,
        source: Option<String>,
    ) -> Result<ImportPreviewItem> {
        host_import::parse(&text, &file_name, source)
    }

    pub fn import_key(&self, draft: KeyImportDraft) -> Result<KeyItem> {
        let form = keychain::ImportForm {
            vault_id: parse_id(&draft.vault_id)?,
            label: draft.label,
            private_key: draft.private_key,
            passphrase: draft.passphrase,
            remember_passphrase: draft.remember_passphrase,
            certificate: draft.certificate,
        };
        Ok(keychain::import(&self.store, &form)?.into())
    }

    pub fn rename_key(&self, id: String, label: String) -> Result<KeyItem> {
        Ok(keychain::rename(&self.store, parse_id(&id)?, &label)?.into())
    }

    /// `authorized_keys` line for the key.
    pub fn public_key(&self, id: String) -> Result<String> {
        Ok(keychain::public_key(&self.store, parse_id(&id)?)?)
    }

    /// Export the private key as OpenSSH text — the only call that returns
    /// private material; the UI asks for confirmation first. `passphrase`
    /// unlocks the stored key when it is not remembered; `export_passphrase`
    /// re-encrypts the export (`None` = plain).
    pub fn export_private_key(
        &self,
        id: String,
        passphrase: Option<String>,
        export_passphrase: Option<String>,
    ) -> Result<String> {
        let id = parse_id(&id)?;
        let key = self.store.require::<termoso_core::model::SshKey>(id)?;
        if termoso_core::policy::export_denied(&self.store, key.vault_id) {
            return Err(MobileError::Invalid {
                detail: termoso_core::policy::Denied::Export.message(),
            });
        }
        let text: Zeroizing<String> =
            keychain::export(&self.store, id, passphrase, export_passphrase)?;
        Ok(text.to_string())
    }

    pub fn change_key_passphrase(
        &self,
        id: String,
        current: Option<String>,
        next: Option<String>,
        remember: bool,
    ) -> Result<KeyItem> {
        let id = parse_id(&id)?;
        self.secrets.forget_passphrase(id);
        Ok(keychain::change_passphrase(&self.store, id, current, next, remember)?.into())
    }

    pub fn set_key_certificate(&self, id: String, certificate: Option<String>) -> Result<KeyItem> {
        Ok(keychain::set_certificate(&self.store, parse_id(&id)?, certificate)?.into())
    }

    pub fn delete_key(&self, id: String) -> Result<()> {
        let id = parse_id(&id)?;
        self.secrets.forget_passphrase(id);
        Ok(keychain::delete(&self.store, id)?)
    }

    // ---- FIDO2 security keys ------------------------------------------

    /// Create a credential on an attached security key (see
    /// [`crate::Fido2Devices`]) and store the `sk-*` handle. Blocks until
    /// the token is touched: call off the main thread.
    pub fn fido2_generate(
        &self,
        draft: Fido2GenerateDraft,
        listener: Option<Arc<dyn Fido2Listener>>,
    ) -> Result<KeyItem> {
        fido2::generate(&fido2::registry(), &self.store, draft, listener)
    }

    /// Import the resident SSH credentials of an attached token
    /// (`ssh-keygen -K`). Blocking; needs the token PIN.
    pub fn fido2_load_resident(
        &self,
        draft: Fido2LoadDraft,
        listener: Option<Arc<dyn Fido2Listener>>,
    ) -> Result<Vec<KeyItem>> {
        fido2::load_resident(&fido2::registry(), &self.store, draft, listener)
    }

    /// Security-key facts about a stored key; `None` for ordinary keys.
    pub fn security_key_info(&self, id: String) -> Result<Option<SecurityKeyCard>> {
        fido2::describe(&self.store, parse_id(&id)?)
    }

    pub fn identities(&self, vault_id: Option<String>) -> Result<Vec<IdentityItem>> {
        let vault = parse_opt_id(&vault_id)?;
        Ok(keychain::identities(&self.store, vault)?
            .into_iter()
            .map(IdentityItem::from)
            .collect())
    }

    pub fn save_identity(&self, draft: IdentityDraft) -> Result<IdentityItem> {
        let mut form = draft.into_form()?;
        if let Some(id) = form.id {
            // Keep the certificate the mobile editor does not show.
            if let Some(existing) = keychain::identities(&self.store, None)?
                .into_iter()
                .find(|i| i.id == id)
            {
                form.ssh_certificate_id = existing.ssh_certificate_id;
            }
        }
        Ok(keychain::save_identity(&self.store, &form)?.into())
    }

    pub fn delete_identity(&self, id: String) -> Result<()> {
        Ok(keychain::delete_identity(&self.store, parse_id(&id)?)?)
    }

    // ---- known hosts --------------------------------------------------

    pub fn known_hosts(&self) -> Result<Vec<KnownHostItem>> {
        let kh = KnownHosts::new(self.store.clone(), self.store.local_vault()?.id);
        Ok(kh
            .all()?
            .into_iter()
            .map(|e| KnownHostItem {
                id: e.id.to_string(),
                hostname: e.data.hostname,
                key_type: e.data.key_type,
                fingerprint: e.data.fingerprint,
                updated_at: millis(e.updated_at),
            })
            .collect())
    }

    pub fn forget_known_host(&self, id: String) -> Result<()> {
        Ok(self.store.delete(parse_id(&id)?)?)
    }

    /// Server keys pinned for `host:port` across all unlocked vaults.
    pub fn host_key_pins(&self, host: String, port: u16) -> Result<Vec<HostKeyPinItem>> {
        Ok(termoso_client::trust::pins(&self.store, &host, port)?
            .into_iter()
            .map(HostKeyPinItem::from)
            .collect())
    }

    /// Pin a server key into `vault_id`: a pasted OpenSSH public-key line, or
    /// (with `public_key` empty) the keys already trusted in other vaults.
    pub fn pin_host_key(
        &self,
        vault_id: String,
        host: String,
        port: u16,
        public_key: Option<String>,
    ) -> Result<Vec<HostKeyPinItem>> {
        Ok(termoso_client::trust::pin(
            &self.store,
            parse_id(&vault_id)?,
            &host,
            port,
            public_key.as_deref().filter(|s| !s.trim().is_empty()),
        )?
        .into_iter()
        .map(HostKeyPinItem::from)
        .collect())
    }

    pub fn unpin_host_key(&self, id: String) -> Result<()> {
        Ok(termoso_client::trust::unpin(&self.store, parse_id(&id)?)?)
    }

    // ---- history ------------------------------------------------------

    /// Past connections, newest first. `vault_id` is the vault the saved
    /// host lives in today (locked or not); quick connects, local shells and
    /// deleted hosts have none and belong to the local vault.
    pub fn history(&self, limit: u32) -> Result<Vec<HistoryItem>> {
        Ok(self
            .store
            .connections_by_vault(limit.clamp(1, 1000) as usize)?
            .into_iter()
            .map(|c| (c.vault_id.map(|u| u.to_string()), c.item))
            .map(|(vault_id, h)| HistoryItem {
                id: h.id.to_string(),
                vault_id,
                host_id: h.data.host_id.map(|u| u.to_string()),
                label: h.data.label,
                target: h.data.target,
                protocol: h.data.protocol,
                started_at: millis(h.created_at),
                duration_secs: h.data.duration_secs,
                error: h.data.error,
            })
            .collect())
    }

    pub fn clear_history(&self) -> Result<()> {
        Ok(self
            .store
            .clear_history(Some(termoso_proto::sync::HistoryKind::Connection))?)
    }

    /// Commands entered at shell prompts, newest first. Lines that carried
    /// an inline credential were never stored (see the session module).
    pub fn command_history(&self, limit: u32) -> Result<Vec<CommandHistoryItem>> {
        Ok(self
            .store
            .commands(limit.clamp(1, 1000) as usize)?
            .into_iter()
            .map(|h| CommandHistoryItem {
                id: h.id.to_string(),
                host_id: h.data.host_id.map(|u| u.to_string()),
                command: h.data.command,
                at: millis(h.created_at),
            })
            .collect())
    }

    pub fn delete_command_history(&self, id: String) -> Result<()> {
        Ok(self.store.delete_history(parse_id(&id)?)?)
    }

    pub fn clear_command_history(&self) -> Result<()> {
        Ok(self
            .store
            .clear_history(Some(termoso_proto::sync::HistoryKind::Command))?)
    }

    // ---- session logs -------------------------------------------------

    /// Recordings this device can read: its own and, for team vaults with
    /// session logging on, teammates' (once synced). Newest first.
    pub fn session_logs(&self) -> Result<Vec<SessionLogCard>> {
        let mut out: Vec<SessionLogCard> = self
            .store
            .logs()?
            .into_iter()
            .map(|item| SessionLogCard {
                id: item.id.to_string(),
                vault_id: item.vault_id.to_string(),
                host_id: item.meta.host_id.map(|u| u.to_string()),
                label: item.meta.label,
                target: item.meta.target,
                protocol: item.meta.protocol,
                started_at: millis(item.meta.started_at),
                ended_at: item.meta.ended_at.map(millis),
                bytes: item.size_bytes.max(0) as u64,
                mine: item.mine,
                author: item.author.map(|a| a.display_name.unwrap_or(a.email)),
                completed: item.completed,
                downloaded: item.cached,
                pinned: item.pinned,
                note: item.note,
            })
            .collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.started_at));
        Ok(out)
    }

    /// Decrypted recording as text (invalid UTF-8 replaced). Fetches a
    /// teammate's body from the server when it is not on this device yet.
    pub fn session_log_text(&self, id: String) -> Result<String> {
        let id = parse_id(&id)?;
        let body = match self.store.read_log(id) {
            Ok(b) => b,
            Err(e) => {
                RUNTIME
                    .block_on(self.account.fetch_log(id))
                    .map_err(|_| e)?;
                self.store.read_log(id)?
            }
        };
        Ok(String::from_utf8_lossy(&body).into_owned())
    }

    /// Pin a recording so it survives per-host overwrite / cleanup, or leave a
    /// note on it. Synced logs go through the server (editor role); local-only
    /// logs are updated in the store.
    pub fn annotate_session_log(
        &self,
        id: String,
        pinned: Option<bool>,
        note: Option<String>,
    ) -> Result<SessionLogCard> {
        let uuid = parse_id(&id)?;
        let item = self
            .store
            .logs()?
            .into_iter()
            .find(|l| l.id == uuid)
            .ok_or_else(|| MobileError::not_found("recording"))?;
        let note = note.map(|n| n.trim().to_string());
        let synced = item.uploaded
            && RUNTIME
                .block_on(self.account.annotate_log(uuid, pinned, note.clone()))
                .is_ok();
        if !synced {
            let pinned = pinned.unwrap_or(item.pinned);
            let (note, note_by) = match note {
                Some(n) if n != item.note => (n, None),
                _ => (item.note.clone(), item.note_by),
            };
            self.store.annotate_log(uuid, pinned, &note, note_by)?;
            if item.uploaded {
                self.account.sync_in_background();
            }
        }
        self.session_logs()?
            .into_iter()
            .find(|c| c.id == id)
            .ok_or_else(|| MobileError::not_found("recording"))
    }

    pub fn delete_session_log(&self, id: String) -> Result<()> {
        let id = parse_id(&id)?;
        let item = self
            .store
            .logs()?
            .into_iter()
            .find(|l| l.id == id)
            .ok_or_else(|| MobileError::not_found("recording"))?;
        if !item.mine {
            return Err(MobileError::invalid(
                "Only the author can delete this recording from here",
            ));
        }
        self.store.delete_log(id)?;
        self.account.sync_in_background();
        Ok(())
    }

    /// Forget the connections shown under one vault: those of its hosts,
    /// plus the vault-less ones (quick connect, local shell, deleted host)
    /// when it is the local vault.
    pub fn clear_vault_history(&self, vault_id: String) -> Result<()> {
        let vault = vault_id.clone();
        let is_local = self.store.local_vault()?.id == parse_id(&vault_id)?;
        for item in self.history(1000)? {
            let mine = match &item.vault_id {
                Some(v) => *v == vault,
                None => is_local,
            };
            if mine {
                self.store.delete_history(parse_id(&item.id)?)?;
            }
        }
        Ok(())
    }

    // ---- settings -----------------------------------------------------

    pub fn settings(&self) -> Result<MobileSettings> {
        MobileSettings::load(&self.store)
    }

    pub fn save_settings(&self, settings: MobileSettings) -> Result<()> {
        if !settings.cache_passphrases {
            self.secrets.clear();
        }
        settings.save(&self.store)
    }

    /// Drop every key passphrase held in memory (see
    /// `MobileSettings::cache_passphrases`). Called before the vault is
    /// locked; closing the profile clears them as well.
    pub fn forget_cached_passphrases(&self) {
        self.secrets.clear();
    }

    /// How many key passphrases are currently held in memory.
    pub fn cached_passphrase_count(&self) -> u32 {
        self.secrets.len() as u32
    }

    // ---- account & sync -----------------------------------------------

    /// Receive sync status / change notifications. Replace with `None` to
    /// stop.
    pub fn set_sync_listener(&self, listener: Option<Arc<dyn SyncListener>>) {
        self.account.set_listener(listener);
    }

    /// Name this installation registers under (shown in the devices list).
    pub fn set_device_name(&self, name: String) {
        self.account.set_device_name(name);
    }

    /// Security facts about this device, sent with every sign-in / refresh so
    /// team posture policies can be checked server-side.
    pub fn set_posture(
        &self,
        os_version: String,
        disk_encryption: Option<bool>,
        screen_lock: Option<bool>,
        secure_key_storage: Option<bool>,
    ) {
        self.account
            .set_posture(os_version, disk_encryption, screen_lock, secure_key_storage);
    }

    pub fn account_status(&self) -> Result<AccountStatus> {
        RUNTIME.block_on(self.account.status())
    }

    /// Restore a persisted session and start syncing. Returns the account
    /// even when the server is unreachable (the engine reconnects).
    pub fn account_resume(&self) -> Result<Option<AccountCard>> {
        RUNTIME.block_on(self.account.resume())
    }

    pub fn account_login(&self, form: LoginForm) -> Result<LoginOutcome> {
        RUNTIME.block_on(self.account.login(form))
    }

    pub fn account_register(&self, form: RegisterForm) -> Result<Registered> {
        RUNTIME.block_on(self.account.register(form))
    }

    /// Second factor for a pending sign-in.
    pub fn account_mfa(&self, method: MfaMethod, code: String) -> Result<LoginOutcome> {
        RUNTIME.block_on(self.account.mfa(method, code))
    }

    /// Second factor with an attached security key (no code). Blocks until
    /// the token is touched: call off the main thread.
    pub fn account_mfa_security_key(
        &self,
        req: SecurityKeyRequest,
        listener: Option<Arc<dyn Fido2Listener>>,
    ) -> Result<LoginOutcome> {
        RUNTIME.block_on(self.account.mfa_security_key(req, listener))
    }

    pub fn account_mfa_email_send(&self) -> Result<()> {
        RUNTIME.block_on(self.account.mfa_email_send())
    }

    /// Code from the device-approval email for a pending sign-in.
    pub fn account_approve_device(&self, code: String) -> Result<LoginOutcome> {
        RUNTIME.block_on(self.account.approve_device(code))
    }

    pub fn account_resend_device_code(&self) -> Result<()> {
        RUNTIME.block_on(self.account.resend_device_code())
    }

    pub fn account_cancel_login(&self) -> Result<()> {
        RUNTIME.block_on(self.account.cancel_login())
    }

    /// Start a browser-based single sign-on; the UI opens
    /// `authorization_url` in a Custom Tab.
    pub fn account_sso_start(&self, server_url: String, provider: String) -> Result<SsoStarted> {
        RUNTIME.block_on(self.account.sso_start(&server_url, &provider))
    }

    pub fn account_sso_discover(
        &self,
        server_url: String,
        email: String,
    ) -> Result<SsoDiscoverCard> {
        RUNTIME.block_on(self.account.sso_discover(&server_url, &email))
    }

    pub fn account_sso_poll(&self) -> Result<SsoOutcome> {
        RUNTIME.block_on(self.account.sso_poll())
    }

    /// `termoso://sso?flow=<id>` came back from the browser.
    pub fn account_sso_callback(&self, flow_id: String) -> Result<SsoOutcome> {
        RUNTIME.block_on(self.account.sso_callback(&flow_id))
    }

    pub fn account_sso_cancel(&self) -> Result<()> {
        RUNTIME.block_on(self.account.sso_cancel())
    }

    /// Step-up for sensitive account changes: prove the password again
    /// (the server answered `ReauthRequired`). Continues with
    /// `reauth_mfa` / `reauth_security_key` / `reauth_email_code`.
    pub fn reauth_start(&self, password: String) -> Result<ReauthOutcome> {
        RUNTIME.block_on(self.account.reauth_start(password))
    }

    pub fn reauth_mfa(&self, method: MfaMethod, code: String) -> Result<ReauthOutcome> {
        RUNTIME.block_on(self.account.reauth_mfa(method, code))
    }

    pub fn reauth_security_key(
        &self,
        req: SecurityKeyRequest,
        listener: Option<Arc<dyn Fido2Listener>>,
    ) -> Result<ReauthOutcome> {
        RUNTIME.block_on(self.account.reauth_security_key(req, listener))
    }

    pub fn reauth_email_code(&self, code: String) -> Result<ReauthOutcome> {
        RUNTIME.block_on(self.account.reauth_email_code(code))
    }

    pub fn reauth_mfa_email_send(&self) -> Result<()> {
        RUNTIME.block_on(self.account.reauth_mfa_email_send())
    }

    pub fn reauth_cancel(&self) -> Result<()> {
        RUNTIME.block_on(self.account.reauth_cancel())
    }

    /// Revoke this device on the server and forget the account, synced
    /// vaults and keys locally. The local vault stays.
    pub fn account_sign_out(&self) -> Result<()> {
        self.secrets.clear();
        let _ = std::fs::remove_dir_all(self.profile_dir.join(AVATARS_DIR));
        RUNTIME.block_on(self.account.sign_out())
    }

    pub fn sync_now(&self) -> Result<SyncStatus> {
        RUNTIME.block_on(self.account.sync_now())
    }

    /// Turn Personal-vault credential sync on (push + re-pull) or off
    /// (server tombstones, local rows kept). Also persisted in settings.
    pub fn set_credential_sync(&self, on: bool) -> Result<AccountStatus> {
        RUNTIME.block_on(self.account.set_credential_sync(on))
    }

    pub fn sync_status(&self) -> SyncStatus {
        self.account.sync_status()
    }

    pub fn account_devices(&self) -> Result<Vec<DeviceCard>> {
        RUNTIME.block_on(self.account.devices())
    }

    pub fn account_revoke_device(&self, id: String) -> Result<()> {
        RUNTIME.block_on(self.account.revoke_device(id))
    }

    /// Second-factor setup of the signed-in account (security keys, TOTP,
    /// backup codes left).
    pub fn account_mfa_status(&self) -> Result<MfaCard> {
        RUNTIME.block_on(self.account.mfa_status())
    }

    /// Register an attached security key as a second factor. Blocks until
    /// the token is touched: call off the main thread.
    pub fn account_register_security_key(
        &self,
        name: String,
        req: SecurityKeyRequest,
        listener: Option<Arc<dyn Fido2Listener>>,
    ) -> Result<SecurityKeyCredential> {
        RUNTIME.block_on(self.account.register_security_key(name, req, listener))
    }

    pub fn account_remove_security_key(&self, id: String) -> Result<()> {
        RUNTIME.block_on(self.account.remove_security_key(id))
    }

    // ---- SSH ID -------------------------------------------------------

    /// Handle, published keys and this device's passkeys. Signed in, it
    /// also (re)publishes the device keys when the server is behind and
    /// the session is allowed to; otherwise they show as not published.
    pub fn sshid(&self) -> Result<SshIdView> {
        RUNTIME.block_on(self.account.sshid_view())
    }

    /// (Re)publish this device's passkeys under the handle. Unlike
    /// [`Self::sshid`], a `ReauthRequired` answer is surfaced.
    pub fn sshid_publish(&self) -> Result<SshIdView> {
        RUNTIME.block_on(self.account.sshid_publish())
    }

    /// Claim `handle` (`@` and case are tolerated) and publish this device's
    /// passkeys under it.
    pub fn sshid_create(&self, handle: String) -> Result<SshIdView> {
        RUNTIME.block_on(self.account.sshid_create(handle))
    }

    /// Replace this device's passkeys with fresh ones.
    pub fn sshid_rotate(&self) -> Result<SshIdView> {
        RUNTIME.block_on(self.account.sshid_rotate())
    }

    /// Remove one published key (another device's, or a FIDO2 key).
    pub fn sshid_remove_key(&self, id: String) -> Result<SshIdView> {
        RUNTIME.block_on(self.account.sshid_remove_key(id))
    }

    /// Publish a keychain security key under the SSH ID (see
    /// [`AccountRuntime::sshid_attach_security_key`]).
    pub fn sshid_attach_security_key(&self, key_id: String) -> Result<SshIdView> {
        RUNTIME.block_on(self.account.sshid_attach_security_key(key_id))
    }

    /// Publish a public key generated elsewhere under the SSH ID (see
    /// [`AccountRuntime::sshid_add_public_key`]).
    pub fn sshid_add_public_key(&self, label: String, public_key: String) -> Result<SshIdView> {
        RUNTIME.block_on(self.account.sshid_add_public_key(label, public_key))
    }

    /// Create a credential on an attached security key and publish it
    /// under the SSH ID in one go. The handle is kept unencrypted in the
    /// personal vault (the local one when signed out of sync) so it
    /// follows the account like the desktop does. Blocks until the token
    /// is touched: call off the main thread.
    pub fn sshid_add_fido2(
        &self,
        mut draft: Fido2GenerateDraft,
        listener: Option<Arc<dyn Fido2Listener>>,
    ) -> Result<SshIdView> {
        let view = RUNTIME.block_on(self.account.sshid_view())?;
        let handle = match (&view.signed_in, &view.handle) {
            (true, Some(h)) => h.clone(),
            (false, _) => return Err(MobileError::invalid("sign in to use SSH ID")),
            (true, None) => return Err(MobileError::invalid("SSH ID is not set up")),
        };
        draft.vault_id = match self.store.personal_vault()? {
            Some(v) => v.id.to_string(),
            None => self.store.local_vault()?.id.to_string(),
        };
        draft.passphrase = None;
        draft.remember_passphrase = false;
        if draft.comment.trim().is_empty() {
            draft.comment = format!("{handle}@termoso");
        }
        let key = fido2::generate(&fido2::registry(), &self.store, draft, listener)?;
        RUNTIME.block_on(self.account.sshid_attach_security_key(key.id))
    }

    /// Delete the SSH ID and every key published under it; identities that
    /// used it fall back to their other credentials.
    pub fn sshid_delete(&self) -> Result<SshIdView> {
        RUNTIME.block_on(self.account.sshid_delete())
    }

    // ---- teams --------------------------------------------------------

    pub fn teams(&self) -> Result<Vec<TeamCard>> {
        RUNTIME.block_on(self.account.teams())
    }

    pub fn create_team(&self, name: String) -> Result<TeamCard> {
        RUNTIME.block_on(self.account.create_team(name))
    }

    pub fn rename_team(&self, team_id: String, name: String) -> Result<TeamCard> {
        RUNTIME.block_on(self.account.rename_team(team_id, name))
    }

    pub fn set_team_security(
        &self,
        team_id: String,
        multiplayer_enabled: Option<bool>,
        require_mfa: Option<bool>,
        presence_enabled: Option<bool>,
    ) -> Result<TeamCard> {
        RUNTIME.block_on(self.account.set_team_security(
            team_id,
            multiplayer_enabled,
            require_mfa,
            presence_enabled,
        ))
    }

    pub fn delete_team(&self, team_id: String) -> Result<()> {
        RUNTIME.block_on(self.account.delete_team(team_id))
    }

    /// Who is connected to the team's hosts right now.
    pub fn team_presence(&self, team_id: String) -> Result<TeamPresenceCard> {
        RUNTIME.block_on(self.account.team_presence(team_id))
    }

    /// Profile picture `tag` of `user_id` as WebP bytes, from the on-disk
    /// cache or the server; `None` when the server no longer has one. The
    /// tag changes with the picture, so a cached file is never stale.
    pub fn user_avatar(&self, user_id: String, tag: String) -> Result<Option<Vec<u8>>> {
        if tag.is_empty() || !tag.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Ok(None);
        }
        let dir = self.profile_dir.join(AVATARS_DIR);
        let path = dir.join(format!("{user_id}-{tag}.webp"));
        if let Ok(bytes) = std::fs::read(&path) {
            return Ok(Some(bytes));
        }
        let Some(bytes) = RUNTIME.block_on(self.account.user_avatar(user_id.clone()))? else {
            return Ok(None);
        };
        std::fs::create_dir_all(&dir)?;
        std::fs::write(&path, &bytes)?;
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let prefix = format!("{user_id}-");
            for e in entries.flatten() {
                let name = e.file_name();
                if name.to_string_lossy().starts_with(&prefix) && e.path() != path {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        Ok(Some(bytes))
    }

    /// Whether the server offers AI command suggestions and whether this
    /// account turned them on.
    pub fn ai_status(&self) -> Result<AiStatusCard> {
        RUNTIME.block_on(self.account.ai_status())
    }

    /// Opt in to (or out of) AI command suggestions for this account.
    pub fn set_ai_enabled(&self, enabled: bool) -> Result<AiStatusCard> {
        RUNTIME.block_on(self.account.set_ai_enabled(enabled))
    }

    /// One shell command for a short request. Sends the request text and the
    /// target's OS label only; the answer is returned, never typed.
    pub fn ai_ask(&self, prompt: String, target: AiTarget) -> Result<AiSuggestionCard> {
        RUNTIME.block_on(self.account.ai_ask(prompt, target))
    }

    /// Whether this account hides itself from teammates' presence views.
    pub fn presence_hidden(&self) -> Result<bool> {
        RUNTIME.block_on(self.account.presence_hidden())
    }

    /// Hide (or show again) this account in teammates' presence views.
    pub fn set_presence_hidden(&self, hidden: bool) -> Result<bool> {
        RUNTIME.block_on(self.account.set_presence_hidden(hidden))
    }

    pub fn leave_team(&self, team_id: String) -> Result<()> {
        RUNTIME.block_on(self.account.leave_team(team_id))
    }

    /// Join a team from an invitation link or token.
    pub fn accept_team_invite(&self, link: String) -> Result<TeamCard> {
        RUNTIME.block_on(self.account.accept_invite(link))
    }

    pub fn team_members(&self, team_id: String) -> Result<Vec<TeamMemberCard>> {
        RUNTIME.block_on(self.account.team_members(team_id))
    }

    pub fn set_team_member_role(
        &self,
        team_id: String,
        user_id: String,
        role: TeamRole,
    ) -> Result<()> {
        RUNTIME.block_on(self.account.set_team_member_role(team_id, user_id, role))
    }

    pub fn remove_team_member(&self, team_id: String, user_id: String) -> Result<()> {
        RUNTIME.block_on(self.account.remove_team_member(team_id, user_id))
    }

    pub fn team_invites(&self, team_id: String) -> Result<Vec<InviteCard>> {
        RUNTIME.block_on(self.account.team_invites(team_id))
    }

    pub fn team_invite(
        &self,
        team_id: String,
        emails: Vec<String>,
        role: TeamRole,
        vault_ids: Vec<String>,
    ) -> Result<Vec<InviteSent>> {
        RUNTIME.block_on(self.account.invite(team_id, emails, role, vault_ids))
    }

    pub fn revoke_team_invite(&self, team_id: String, invite_id: String) -> Result<()> {
        RUNTIME.block_on(self.account.revoke_invite(team_id, invite_id))
    }

    pub fn team_audit(
        &self,
        team_id: String,
        before: Option<i64>,
        limit: Option<u32>,
    ) -> Result<AuditPage> {
        RUNTIME.block_on(self.account.team_audit(team_id, before, limit))
    }

    pub fn team_roles(&self, team_id: String) -> Result<Vec<TeamRoleCard>> {
        RUNTIME.block_on(self.account.team_roles(team_id))
    }

    pub fn team_permissions(&self, team_id: String) -> Result<Vec<PermissionCard>> {
        RUNTIME.block_on(self.account.team_permissions(team_id))
    }

    pub fn team_policies(&self, team_id: String) -> Result<TeamPoliciesCard> {
        RUNTIME.block_on(self.account.team_policies(team_id))
    }

    pub fn team_devices(&self, team_id: String) -> Result<TeamDevicesCard> {
        RUNTIME.block_on(self.account.team_devices(team_id))
    }

    pub fn team_approve_device(&self, team_id: String, device_id: String) -> Result<()> {
        RUNTIME.block_on(self.account.team_approve_device(team_id, device_id))
    }

    pub fn team_reject_device(&self, team_id: String, device_id: String) -> Result<()> {
        RUNTIME.block_on(self.account.team_reject_device(team_id, device_id))
    }

    pub fn team_access_requests(&self, team_id: String) -> Result<AccessRequestsCard> {
        RUNTIME.block_on(self.account.team_access_requests(team_id))
    }

    pub fn team_request_access(
        &self,
        team_id: String,
        vault_id: String,
        role: String,
        hours: i32,
        reason: String,
    ) -> Result<AccessRequestCard> {
        RUNTIME.block_on(
            self.account
                .team_request_access(team_id, vault_id, role, hours, reason),
        )
    }

    pub fn team_cancel_access_request(&self, team_id: String, request_id: String) -> Result<()> {
        RUNTIME.block_on(self.account.team_cancel_access_request(team_id, request_id))
    }

    pub fn team_decide_access_request(
        &self,
        team_id: String,
        request_id: String,
        action: String,
        hours: Option<i32>,
        note: Option<String>,
    ) -> Result<AccessRequestCard> {
        RUNTIME.block_on(
            self.account
                .team_decide_access_request(team_id, request_id, action, hours, note),
        )
    }

    pub fn team_acl(&self, team_id: String, vault_id: String) -> Result<Vec<AclRuleCard>> {
        RUNTIME.block_on(self.account.team_acl(team_id, vault_id))
    }

    pub fn team_rotation(&self, team_id: String) -> Result<RotationCard> {
        RUNTIME.block_on(self.account.team_rotation(team_id))
    }

    pub fn team_data(&self, team_id: String) -> Result<TeamDataCard> {
        RUNTIME.block_on(self.account.team_data(team_id))
    }

    pub fn team_pending_keys(&self, team_id: String) -> Result<Vec<PendingKeyCard>> {
        RUNTIME.block_on(self.account.pending_keys(team_id))
    }

    pub fn create_team_vault(
        &self,
        team_id: String,
        name: String,
        access: Vec<VaultAccessDraft>,
    ) -> Result<()> {
        RUNTIME.block_on(self.account.create_team_vault(team_id, name, access))
    }

    pub fn rename_team_vault(&self, vault_id: String, name: String) -> Result<()> {
        RUNTIME.block_on(self.account.rename_team_vault(vault_id, name))
    }

    pub fn delete_team_vault(&self, vault_id: String) -> Result<()> {
        RUNTIME.block_on(self.account.delete_team_vault(vault_id))
    }

    pub fn team_vault_members(&self, vault_id: String) -> Result<Vec<VaultMemberCard>> {
        RUNTIME.block_on(self.account.team_vault_members(vault_id))
    }

    pub fn set_team_vault_access(
        &self,
        vault_id: String,
        user_id: String,
        access: VaultAccess,
    ) -> Result<()> {
        RUNTIME.block_on(self.account.set_vault_access(vault_id, user_id, access))
    }

    pub fn remove_team_vault_access(&self, vault_id: String, user_id: String) -> Result<()> {
        RUNTIME.block_on(self.account.remove_vault_access(vault_id, user_id))
    }

    pub fn rotate_team_vault_key(&self, vault_id: String) -> Result<()> {
        RUNTIME.block_on(self.account.rotate_team_vault_key(vault_id))
    }

    // ---- sessions -----------------------------------------------------

    /// Open a terminal to a saved host. Returns at once; progress, prompts
    /// and output arrive on `listener`. `vault_id` is the vault the caller
    /// took the host from; a host of any other vault is refused before any
    /// credential is read.
    pub fn connect_host(
        &self,
        host_id: String,
        vault_id: String,
        options: TerminalOptions,
        listener: Arc<dyn SessionListener>,
    ) -> Result<Arc<SshSession>> {
        let resolved = self.resolve_host_in(&host_id, &vault_id)?;
        let protocol = match (options.transport, resolved.telnet.is_some()) {
            (Transport::Telnet, true) => "telnet",
            (Transport::Telnet, false) => {
                return Err(MobileError::invalid("this host has no Telnet section"));
            }
            _ => resolved.protocol(),
        };
        let mosh = match options.transport {
            Transport::Mosh => true,
            Transport::Ssh | Transport::Telnet => false,
            Transport::Auto => resolved.ssh.use_mosh,
        };
        let presence = Some(self.presence.slot(
            resolved.host.id,
            match (protocol, mosh) {
                ("telnet", _) => "telnet",
                (_, true) => "mosh",
                (_, false) => "ssh",
            },
        ));
        let target = match protocol {
            "telnet" => LaunchTarget::Telnet {
                host: resolved.host.data.address.clone(),
                port: resolved.telnet.as_ref().and_then(|t| t.port).unwrap_or(23),
                ip_version: IpVersion::parse(&resolved.host.data.ip_version),
                host_id: Some(resolved.host.id),
                vault_id: Some(resolved.host.vault_id),
                label: resolved.host.data.label.clone(),
                proxy: match &resolved.proxy {
                    Some(p) => Some(crate::connect::proxy_config(&self.store, &p.data)?),
                    None => None,
                },
            },
            "ssh" => LaunchTarget::Ssh {
                target: ssh_target(&resolved),
                resolved: Some(Box::new(resolved)),
            },
            other => {
                return Err(MobileError::invalid(format!(
                    "{other} hosts are not supported on mobile yet"
                )));
            }
        };
        Ok(SshSession::launch(
            RUNTIME.handle().clone(),
            Launch {
                store: self.store.clone(),
                secrets: self.secrets.clone(),
                target,
                settings: MobileSettings::load(&self.store)?,
                options,
                listener,
                presence,
                logs_dir: self.profile_dir.join("logs"),
                account: Some(self.account.clone()),
            },
        ))
    }

    /// Open a shell on this device. Nothing is saved except the connection
    /// history.
    pub fn connect_local(
        &self,
        shell: LocalShell,
        options: TerminalOptions,
        listener: Arc<dyn SessionListener>,
    ) -> Result<Arc<SshSession>> {
        let argv = if shell.argv.is_empty() {
            vec![default_local_shell()]
        } else {
            shell.argv
        };
        let home = shell.home.trim();
        let mut env: Vec<(String, String)> = shell
            .env
            .iter()
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        if !home.is_empty() {
            env.push(("HOME".into(), home.to_string()));
        }
        Ok(SshSession::launch(
            RUNTIME.handle().clone(),
            Launch {
                store: self.store.clone(),
                secrets: self.secrets.clone(),
                target: LaunchTarget::Local {
                    argv,
                    cwd: (!home.is_empty()).then(|| home.into()),
                    env,
                },
                settings: MobileSettings::load(&self.store)?,
                options,
                listener,
                presence: None,
                logs_dir: self.profile_dir.join("logs"),
                account: Some(self.account.clone()),
            },
        ))
    }

    /// A serial console over a USB-UART adapter the app drives: Kotlin
    /// opens the device and moves bytes through the returned [`SerialPipe`]
    /// and the [`SerialLink`] it passes in.
    pub fn connect_serial(
        &self,
        device: String,
        label: String,
        line: SerialLine,
        link: Arc<dyn SerialLink>,
        options: TerminalOptions,
        listener: Arc<dyn SessionListener>,
    ) -> Result<SerialSession> {
        let (terminal, events) = PipeTerminal::open(&line, link)?;
        let session = SshSession::launch(
            RUNTIME.handle().clone(),
            Launch {
                store: self.store.clone(),
                secrets: self.secrets.clone(),
                target: LaunchTarget::Serial {
                    label,
                    device,
                    terminal: terminal.clone(),
                    events,
                },
                settings: MobileSettings::load(&self.store)?,
                options,
                listener,
                presence: None,
                logs_dir: self.profile_dir.join("logs"),
                account: Some(self.account.clone()),
            },
        );
        Ok(SerialSession {
            session,
            pipe: Arc::new(SerialPipe::new(terminal)),
        })
    }

    /// Open a terminal to an ad-hoc target (`user@host:port`); nothing is
    /// saved except the connection history and any trusted host key.
    pub fn connect_quick(
        &self,
        target: QuickTarget,
        options: TerminalOptions,
        listener: Arc<dyn SessionListener>,
    ) -> Result<Arc<SshSession>> {
        let launch = match target.protocol.as_str() {
            "telnet" => {
                let host = target.host.trim();
                if host.is_empty() {
                    return Err(MobileError::invalid("host is empty"));
                }
                LaunchTarget::Telnet {
                    host: host.to_string(),
                    port: target.port,
                    ip_version: IpVersion::Auto,
                    host_id: None,
                    vault_id: None,
                    label: host.to_string(),
                    proxy: None,
                }
            }
            _ => LaunchTarget::Ssh {
                target: quick_target(&target)?,
                resolved: None,
            },
        };
        Ok(SshSession::launch(
            RUNTIME.handle().clone(),
            Launch {
                store: self.store.clone(),
                secrets: self.secrets.clone(),
                target: launch,
                settings: MobileSettings::load(&self.store)?,
                options,
                listener,
                presence: None,
                logs_dir: self.profile_dir.join("logs"),
                account: Some(self.account.clone()),
            },
        ))
    }

    // ---- multiplayer --------------------------------------------------

    /// Share an open terminal with teammates. Needs a signed-in account;
    /// the link the returned handle exposes is what other people join with.
    /// `label` names the share until the remote sets a title.
    pub fn share_session(
        &self,
        session: Arc<SshSession>,
        label: String,
        listener: Arc<dyn LiveListener>,
    ) -> Result<Arc<LiveShare>> {
        RUNTIME.block_on(async {
            let api = self.account.api().await?;
            session.share(api, listener, label).await
        })
    }

    /// Join somebody's share from a `termoso://join/…` link. Returns a
    /// terminal that mirrors theirs; `live_listener` gets participants,
    /// control grants and the end of the share.
    pub fn join_live(
        &self,
        link: String,
        options: TerminalOptions,
        listener: Arc<dyn SessionListener>,
        live_listener: Arc<dyn LiveListener>,
    ) -> Result<Arc<SshSession>> {
        let parsed = termoso_core::live::LiveLink::parse(&link)?;
        let settings = MobileSettings::load(&self.store)?;
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let joined = RUNTIME.block_on(async {
            let api = self.account.api().await?;
            termoso_core::live::join(api, &parsed, tx)
                .await
                .map_err(MobileError::from)
        })?;
        Ok(SshSession::launch_viewer(
            RUNTIME.handle().clone(),
            ViewerLaunch {
                store: self.store.clone(),
                settings,
                options,
                listener,
                joined,
                live_events: rx,
                live_listener,
            },
        ))
    }

    /// Open SFTP to a saved host. Returns at once; state, prompts and
    /// transfers arrive on `listener`. `vault_id` as in [`Self::connect_host`].
    pub fn sftp_host(
        &self,
        host_id: String,
        vault_id: String,
        listener: Arc<dyn SftpListener>,
    ) -> Result<Arc<SftpSession>> {
        let (resolved, target) = self.ssh_host(&host_id, &vault_id)?;
        let presence = Some(self.presence.slot(resolved.host.id, "sftp"));
        Ok(SftpSession::launch(
            RUNTIME.handle().clone(),
            SftpLaunch {
                store: self.store.clone(),
                secrets: self.secrets.clone(),
                backend: FileBackend::Sftp {
                    target,
                    resolved: Some(resolved),
                },
                settings: MobileSettings::load(&self.store)?,
                listener,
                presence,
            },
        ))
    }

    /// Open the WebDAV share of a saved host (its WebDAV section). Same
    /// session type as SFTP; `capabilities()` tells the UI what to hide.
    /// Write-mode files spool under the profile directory before the PUT.
    /// `vault_id` as in [`Self::connect_host`].
    /// Open SFTP over the SSH connection of an open terminal — the same
    /// login, no prompts, like the desktop's "Open SFTP for this
    /// connection". `label`/`target` are what the files tab shows. Fails for
    /// Mosh, Telnet, local and shared-view terminals.
    pub fn sftp_session(
        &self,
        session: Arc<SshSession>,
        label: String,
        target: String,
        listener: Arc<dyn SftpListener>,
    ) -> Result<Arc<SftpSession>> {
        let client = session
            .ssh_client()
            .ok_or_else(|| MobileError::invalid("This terminal has no SSH connection to reuse"))?;
        let host_id = session.saved_host_id();
        let presence = host_id.map(|id| self.presence.slot(id, "sftp"));
        Ok(SftpSession::launch(
            RUNTIME.handle().clone(),
            SftpLaunch {
                store: self.store.clone(),
                secrets: self.secrets.clone(),
                backend: FileBackend::Session {
                    client,
                    host_id,
                    label,
                    target_display: target,
                },
                settings: MobileSettings::load(&self.store)?,
                listener,
                presence,
            },
        ))
    }

    pub fn webdav_host(
        &self,
        host_id: String,
        vault_id: String,
        listener: Arc<dyn SftpListener>,
    ) -> Result<Arc<SftpSession>> {
        let resolved = self.resolve_host_in(&host_id, &vault_id)?;
        if resolved.webdav.is_none() {
            return Err(MobileError::invalid("this host has no WebDAV section"));
        }
        let presence = Some(self.presence.slot(resolved.host.id, "webdav"));
        Ok(SftpSession::launch(
            RUNTIME.handle().clone(),
            SftpLaunch {
                store: self.store.clone(),
                secrets: self.secrets.clone(),
                backend: FileBackend::WebDav {
                    resolved,
                    spool_dir: self.profile_dir.join("webdav-spool"),
                },
                settings: MobileSettings::load(&self.store)?,
                listener,
                presence,
            },
        ))
    }

    /// Browse `root` — what the local shell sees as `/` (an installed Linux
    /// system's tree, or the Android shell's home) — as a file session that
    /// starts in `start`, a path inside it. Paths are relative to the root
    /// and never leave it (symlinks pointing out are dangling), so the rest
    /// of the app's private data stays private.
    pub fn local_files(
        &self,
        root: String,
        start: String,
        listener: Arc<dyn SftpListener>,
    ) -> Result<Arc<SftpSession>> {
        let home = root.trim();
        if home.is_empty() {
            return Err(MobileError::invalid("local root is empty"));
        }
        Ok(SftpSession::launch(
            RUNTIME.handle().clone(),
            SftpLaunch {
                store: self.store.clone(),
                secrets: self.secrets.clone(),
                backend: FileBackend::Local {
                    root: PathBuf::from(home),
                    home: start,
                },
                settings: MobileSettings::load(&self.store)?,
                listener,
                presence: None,
            },
        ))
    }

    /// Open SFTP to an ad-hoc target.
    pub fn sftp_quick(
        &self,
        target: QuickTarget,
        listener: Arc<dyn SftpListener>,
    ) -> Result<Arc<SftpSession>> {
        Ok(SftpSession::launch(
            RUNTIME.handle().clone(),
            SftpLaunch {
                store: self.store.clone(),
                secrets: self.secrets.clone(),
                backend: FileBackend::Sftp {
                    target: quick_target(&target)?,
                    resolved: None,
                },
                settings: MobileSettings::load(&self.store)?,
                listener,
                presence: None,
            },
        ))
    }

    // ── port forwarding ──

    /// Stored forwarding rules of one vault (all when `None`), labelled first.
    pub fn pf_rules(&self, vault_id: Option<String>) -> Result<Vec<PfRuleItem>> {
        forward::rules(&self.store, &vault_id)
    }

    pub fn pf_rule(&self, id: String) -> Result<PfRuleItem> {
        forward::rule(&self.store, parse_id(&id)?)
    }

    /// Create (`draft.id == None`) or update a rule after validating it.
    pub fn save_pf_rule(&self, draft: PfRuleDraft) -> Result<PfRuleItem> {
        forward::save(&self.store, &draft)
    }

    pub fn duplicate_pf_rule(&self, id: String) -> Result<PfRuleItem> {
        forward::duplicate(&self.store, parse_id(&id)?)
    }

    /// Remove a rule; the caller stops its tunnel first.
    pub fn delete_pf_rule(&self, id: String) -> Result<()> {
        forward::delete(&self.store, parse_id(&id)?)
    }

    /// Start a rule's tunnel. Returns at once; state and prompts arrive on
    /// `listener`. Fails synchronously only when the rule or its host is gone.
    /// `ssh-copy-id`: put the key's public half into `~/.ssh/authorized_keys`
    /// of a saved host. Keep the returned object until the listener fires.
    pub fn start_key_export(
        &self,
        key_id: String,
        host_id: String,
        vault_id: Option<String>,
        listener: Arc<dyn KeyExportListener>,
    ) -> Result<Arc<KeyExport>> {
        let vault_id = match vault_id {
            Some(v) => Some(parse_id(&v)?),
            None => None,
        };
        Ok(KeyExport::launch(
            RUNTIME.handle().clone(),
            KeyExportLaunch {
                store: self.store.clone(),
                secrets: self.secrets.clone(),
                settings: MobileSettings::load(&self.store)?,
                key_id: parse_id(&key_id)?,
                host_id: parse_id(&host_id)?,
                vault_id,
                listener,
            },
        ))
    }

    pub fn start_pf(
        &self,
        rule_id: String,
        listener: Arc<dyn TunnelListener>,
    ) -> Result<Arc<PfTunnel>> {
        let rule = forward::resolve_for_tunnel(&self.store, parse_id(&rule_id)?)?;
        let presence = self.presence.slot(rule.data.host_id, "forward");
        Ok(PfTunnel::launch(
            RUNTIME.handle().clone(),
            TunnelLaunch {
                store: self.store.clone(),
                secrets: self.secrets.clone(),
                rule,
                settings: MobileSettings::load(&self.store)?,
                listener,
                presence,
                account: Some(self.account.clone()),
            },
        ))
    }

    // ── snippets ──

    /// Snippets of one vault (all when `None`), in display order.
    pub fn snippets(&self, vault_id: Option<String>) -> Result<Vec<SnippetItem>> {
        snippets::list(&self.store, &vault_id)
    }

    pub fn snippet(&self, id: String) -> Result<SnippetItem> {
        snippets::get(&self.store, parse_id(&id)?)
    }

    /// Create (`draft.id == None`) or update a snippet and its target hosts.
    pub fn save_snippet(&self, draft: SnippetDraft) -> Result<SnippetItem> {
        snippets::save(&self.store, &draft)
    }

    pub fn duplicate_snippet(&self, id: String) -> Result<SnippetItem> {
        snippets::duplicate(&self.store, parse_id(&id)?)
    }

    /// Remove a snippet, its host targets and startup references.
    pub fn delete_snippet(&self, id: String) -> Result<()> {
        snippets::delete(&self.store, parse_id(&id)?)
    }

    /// Copy (or move) a snippet to another vault, at the top level.
    pub fn copy_snippet_to_vault(
        &self,
        id: String,
        vault_id: String,
        move_snippet: bool,
    ) -> Result<SnippetItem> {
        snippets::copy_to_vault(
            &self.store,
            parse_id(&id)?,
            parse_id(&vault_id)?,
            move_snippet,
        )
    }

    /// Packages of one vault (all when `None`), sorted by label.
    /// Built-in colour schemes followed by the user's own (`color_scheme`
    /// entities of `vault_id`, or of every unlocked vault when `None`).
    pub fn terminal_themes_all(&self, vault_id: Option<String>) -> Result<Vec<TerminalTheme>> {
        let mut all = crate::themes::terminal_themes();
        all.extend(crate::themes::custom_themes(
            &self.store,
            parse_opt_id(&vault_id)?,
        ));
        Ok(all)
    }

    /// Scheme by built-in id/name or by user-scheme entity id.
    pub fn terminal_theme_resolve(&self, key: String) -> Option<TerminalTheme> {
        crate::themes::resolve(&self.store, &key)
    }

    pub fn snippet_packages(&self, vault_id: Option<String>) -> Result<Vec<SnippetPackageItem>> {
        snippets::packages(&self.store, &vault_id)
    }

    pub fn save_snippet_package(
        &self,
        vault_id: String,
        id: Option<String>,
        label: String,
        parent_id: Option<String>,
    ) -> Result<SnippetPackageItem> {
        snippets::save_package(&self.store, &vault_id, &id, &label, &parent_id)
    }

    /// Remove a package; its snippets and sub-packages move to the parent.
    pub fn delete_snippet_package(&self, id: String) -> Result<()> {
        snippets::delete_package(&self.store, parse_id(&id)?)
    }

    /// Copy (or move) a package with its subtree to another vault.
    pub fn copy_snippet_package_to_vault(
        &self,
        id: String,
        vault_id: String,
        move_package: bool,
    ) -> Result<SnippetPackageItem> {
        snippets::copy_package_to_vault(
            &self.store,
            parse_id(&id)?,
            parse_id(&vault_id)?,
            move_package,
        )
    }

    /// `{{name}}` placeholders of a script being edited, in order.
    pub fn snippet_variables(&self, script: String) -> Vec<String> {
        termoso_client::snippets::variables(&script)
    }

    /// The text a run would type: variables expanded, line endings
    /// normalised, trailing newline present unless `paste`.
    pub fn preview_snippet(
        &self,
        id: String,
        vars: HashMap<String, String>,
        paste: bool,
    ) -> Result<String> {
        snippets::prepare(&self.store, parse_id(&id)?, &vars, paste).map(|(text, _)| text)
    }

    /// Run a snippet on hosts without opening terminals: one `exec` channel
    /// per host, stdout / stderr / exit code per host through `listener`.
    pub fn start_quiet_run(
        &self,
        id: String,
        host_ids: Vec<String>,
        vars: HashMap<String, String>,
        listener: Arc<dyn QuietRunListener>,
    ) -> Result<Arc<QuietRun>> {
        QuietRun::launch(
            RUNTIME.handle().clone(),
            QuietLaunch {
                store: self.store.clone(),
                secrets: self.secrets.clone(),
                snippet_id: parse_id(&id)?,
                host_ids: crate::quiet::parse_ids(&host_ids)?,
                vars,
                settings: MobileSettings::load(&self.store)?,
                listener,
            },
        )
    }

    /// Type a snippet into the given live sessions.
    pub fn run_snippet(
        &self,
        id: String,
        sessions: Vec<Arc<SshSession>>,
        vars: HashMap<String, String>,
        paste: bool,
    ) -> Result<SnippetRun> {
        snippets::run(&self.store, parse_id(&id)?, &sessions, &vars, paste)
    }
}

impl TermosoApp {
    /// [`Store::resolve_host_in`] for ids that came over the FFI.
    fn resolve_host_in(&self, host_id: &str, vault_id: &str) -> Result<ResolvedHost> {
        Ok(self
            .store
            .resolve_host_in(parse_id(host_id)?, Some(parse_id(vault_id)?))?)
    }

    fn ssh_host(&self, host_id: &str, vault_id: &str) -> Result<(ResolvedHost, SshTarget)> {
        let resolved = self.resolve_host_in(host_id, vault_id)?;
        if resolved.protocol() != "ssh" {
            return Err(MobileError::invalid(format!(
                "{} hosts are not supported here",
                resolved.protocol()
            )));
        }
        let target = ssh_target(&resolved);
        Ok((resolved, target))
    }
}

pub(crate) fn ssh_target(resolved: &ResolvedHost) -> SshTarget {
    SshTarget {
        host: resolved.host.data.address.clone(),
        port: resolved.port(),
        username: resolved.username().unwrap_or_default(),
    }
}

/// The shell [`App::connect_local`] starts when none is given.
fn default_local_shell() -> String {
    if cfg!(target_os = "android") {
        return "/system/bin/sh".into();
    }
    if cfg!(target_os = "ios") {
        return "/bin/sh".into();
    }
    std::env::var("SHELL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "/bin/sh".into())
}

fn quick_target(target: &QuickTarget) -> Result<SshTarget> {
    if target.host.trim().is_empty() {
        return Err(MobileError::invalid("host is empty"));
    }
    if target.protocol != "ssh" {
        return Err(MobileError::invalid(format!(
            "{} targets need a saved host",
            target.protocol
        )));
    }
    Ok(SshTarget {
        host: target.host.trim().to_string(),
        port: target.port,
        username: target.username.trim().to_string(),
    })
}
