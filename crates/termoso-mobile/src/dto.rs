//! Records crossing the FFI. Ids are UUID strings, timestamps are Unix
//! milliseconds. No DTO here carries a password, passphrase or private key:
//! those stay in the encrypted store and only travel in the explicit drafts
//! the UI submits.

use chrono::{DateTime, Utc};
use termoso_client::{hosts, keychain};
use termoso_core::store::{LocalVault, LocalVaultKind};
use termoso_proto::vault::VaultRole;
use uuid::Uuid;

use crate::error::{MobileError, Result};
use crate::sshid::SshIdKeyKind;

pub(crate) fn parse_id(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s.trim()).map_err(MobileError::from)
}

pub(crate) fn parse_opt_id(s: &Option<String>) -> Result<Option<Uuid>> {
    match s.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(v) => Ok(Some(parse_id(v)?)),
    }
}

pub(crate) fn parse_ids(ids: &[String]) -> Result<Vec<Uuid>> {
    ids.iter().map(|s| parse_id(s)).collect()
}

pub(crate) fn millis(t: DateTime<Utc>) -> i64 {
    t.timestamp_millis()
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum VaultKind {
    Local,
    Personal,
    Team,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum VaultAccess {
    View,
    Edit,
    Manage,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VaultInfo {
    pub id: String,
    pub kind: VaultKind,
    pub name: String,
    pub team_id: Option<String>,
    pub access: VaultAccess,
    pub locked: bool,
    /// The team's first vault: can be renamed but not deleted.
    #[uniffi(default = false)]
    pub is_default: bool,
}

impl From<LocalVault> for VaultInfo {
    fn from(v: LocalVault) -> Self {
        Self {
            id: v.id.to_string(),
            kind: match v.kind {
                LocalVaultKind::Local => VaultKind::Local,
                LocalVaultKind::Personal => VaultKind::Personal,
                LocalVaultKind::Team => VaultKind::Team,
            },
            name: v.name,
            team_id: v.team_id.map(|t| t.to_string()),
            access: match v.role {
                VaultRole::Viewer => VaultAccess::View,
                VaultRole::Editor => VaultAccess::Edit,
                VaultRole::Manager => VaultAccess::Manage,
            },
            locked: !v.unlocked,
            is_default: v.is_default,
        }
    }
}

/// One row of the hosts list. Effective values already include group
/// inheritance.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HostItem {
    pub id: String,
    pub vault_id: String,
    pub label: String,
    pub address: String,
    pub group_id: Option<String>,
    pub group_path: Vec<String>,
    /// `ssh` | `telnet` | `webdav` (the primary protocol; `webdav` only
    /// when the host has no SSH or Telnet section).
    pub protocol: String,
    /// The SSH section opens over Mosh by default.
    pub use_mosh: bool,
    pub username: String,
    /// Port of the primary protocol.
    pub port: u16,
    /// Set when the host also has a Telnet section.
    pub telnet_port: Option<u16>,
    /// Set when the host has a WebDAV section.
    pub webdav_url: Option<String>,
    pub tags: Vec<String>,
    pub os_name: Option<String>,
    pub icon: Option<String>,
    pub notes: String,
    /// Exposed to the system file picker (SAF) when the Files integration
    /// is on.
    pub files_provider: bool,
    pub updated_at: i64,
    pub last_connected: Option<i64>,
    pub dirty: bool,
}

impl From<hosts::HostCard> for HostItem {
    fn from(c: hosts::HostCard) -> Self {
        Self {
            id: c.id.to_string(),
            vault_id: c.vault_id.to_string(),
            label: c.label,
            address: c.address,
            group_id: c.group_id.map(|g| g.to_string()),
            group_path: c.group_path,
            protocol: c.protocol,
            telnet_port: c.telnet_port,
            webdav_url: c.webdav_url,
            use_mosh: c.use_mosh,
            username: c.username,
            port: c.port,
            tags: c.tags,
            os_name: c.os_name,
            icon: c.icon,
            notes: c.notes,
            files_provider: c.files_provider,
            updated_at: millis(c.updated_at),
            last_connected: c.last_connected.map(millis),
            dirty: c.dirty,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

/// What the host editor edits. `None` for optional fields means "inherit /
/// unset". Fields the mobile editor does not expose (proxy, jump chain,
/// colour scheme…) are preserved on save.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HostDraft {
    pub id: Option<String>,
    pub vault_id: String,
    pub label: String,
    pub address: String,
    pub group_id: Option<String>,
    pub port: Option<u16>,
    pub username: String,
    /// `None` keeps the stored password when editing; `Some("")` clears it.
    pub password: Option<String>,
    /// TOTP secret (`otpauth://` URI or base32) typed into one-time-code
    /// prompts; `None` keeps the stored one, `Some("")` clears it.
    pub totp_secret: Option<String>,
    pub ssh_key_id: Option<String>,
    /// Use an existing identity instead of the inline username/password/key.
    pub identity_id: Option<String>,
    /// Inline credentials log in with the account's SSH ID passkeys.
    pub ssh_id: bool,
    /// Passkey type to try first when `ssh_id` is set.
    pub ssh_id_key_type: Option<SshIdKeyKind>,
    /// Open terminals over Mosh (UDP) by default; SSH bootstraps the server.
    pub use_mosh: bool,
    /// Custom `mosh-server` command line; `None` = the built-in default.
    pub mosh_server_command: Option<String>,
    pub tag_ids: Vec<String>,
    pub notes: String,
    pub os_name: Option<String>,
    pub icon: Option<String>,
    /// `auto` | `4` | `6`.
    pub ip_version: String,
    pub agent_forwarding: bool,
    /// Trusted X11 forwarding; kept in sync for desktop, mobile has no local
    /// X server and skips the request.
    pub forward_x11: bool,
    /// Snippet typed into the shell right after connecting.
    pub startup_snippet_id: Option<String>,
    pub env_variables: Vec<EnvVar>,
    pub keep_alive_interval: Option<u32>,
    pub timeout: Option<u32>,
    /// Jump-host chain to go through; `None` connects directly.
    pub host_chain_id: Option<String>,
    /// SOCKS / HTTP proxy; `None` connects directly.
    pub proxy_id: Option<String>,
    /// Team gateway (API bridge) to reach a host behind NAT; `None` dials directly.
    pub gateway_id: Option<String>,
    /// MAC address for Wake-on-LAN, `aa:bb:cc:dd:ee:ff`.
    pub mac_address: Option<String>,
    /// Terminal colour scheme id; `None` follows the app setting.
    pub color_scheme: Option<String>,
    /// Terminal charset; `None` = UTF-8.
    pub charset: Option<String>,
    /// `ctrl-h` makes Backspace send ^H instead of DEL (Termius "Delete sends Ctrl-H").
    pub backspace: Option<String>,
    /// Set by the core when the stored inline identity has a password.
    pub has_password: bool,
    /// Set by the core when the stored inline identity has a TOTP secret.
    pub has_totp: bool,
    /// The host has an SSH section (the SSH fields above belong to it). A
    /// host needs this, `telnet` or `webdav`.
    pub ssh: bool,
    /// Telnet section; `None` = not reachable over Telnet.
    pub telnet: Option<TelnetDraft>,
    /// WebDAV section; `None` = no share on this host.
    pub webdav: Option<WebDavDraft>,
    /// Expose the SFTP / WebDAV share to the system file picker (SAF).
    pub files_provider: bool,
}

/// WebDAV section of the host editor. Credentials are the share's own,
/// never inherited from the SSH identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct WebDavDraft {
    /// TCP port; `None` = 443 (80 with `http`).
    pub port: Option<u16>,
    /// Collection path below the host's address (`/remote.php/dav/files/alice/`); empty = `/`.
    pub path: String,
    /// Plain HTTP instead of HTTPS.
    pub http: bool,
    /// TLS: name sent as SNI and checked against the certificate when it
    /// differs from the address (reverse proxy reached by IP, name not in DNS).
    pub tls_server_name: Option<String>,
    /// TLS: PEM bundle of a private CA to trust instead of the system roots.
    pub ca_certificate: Option<String>,
    pub username: String,
    /// `None` keeps the stored password when editing; `Some("")` clears it.
    pub password: Option<String>,
    pub identity_id: Option<String>,
    /// SHA-256 of the server certificate to trust instead of the system
    /// roots (`AA:BB:…` or bare hex); `None` = system roots.
    pub certificate_fingerprint: Option<String>,
    /// Set by the core when the stored inline identity has a password.
    pub has_password: bool,
    /// `password` (Basic / Digest, negotiated) or `token` (Bearer).
    pub auth: String,
    /// `None` keeps the stored token when editing; `Some("")` clears it.
    pub bearer_token: Option<String>,
    /// Set by the core when the stored inline identity has a token.
    pub has_bearer_token: bool,
    /// PEM client certificate chain for servers requiring mTLS; `None`
    /// keeps the stored pair, `Some("")` clears it.
    pub client_certificate: Option<String>,
    /// PEM private key for `client_certificate`; `None` keeps the stored one.
    pub client_key: Option<String>,
    /// Set by the core: SHA-256 of the stored client certificate.
    pub client_certificate_fingerprint: Option<String>,
}

impl From<hosts::WebDavForm> for WebDavDraft {
    fn from(w: hosts::WebDavForm) -> Self {
        Self {
            port: w.port,
            path: w.path,
            http: w.http,
            tls_server_name: w.tls_server_name,
            ca_certificate: w.ca_certificate,
            username: w.username,
            password: None,
            identity_id: w.identity_id.map(|i| i.to_string()),
            certificate_fingerprint: w.certificate_fingerprint,
            has_password: w.has_password,
            auth: w.auth,
            bearer_token: None,
            has_bearer_token: w.has_bearer_token,
            client_certificate: None,
            client_key: None,
            client_certificate_fingerprint: w.client_certificate_fingerprint,
        }
    }
}

/// Telnet section of the host editor.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct TelnetDraft {
    /// `None` = 23.
    pub port: Option<u16>,
    pub username: String,
    /// `None` keeps the stored password when editing; `Some("")` clears it.
    pub password: Option<String>,
    pub identity_id: Option<String>,
    /// Set by the core when the stored inline identity has a password.
    pub has_password: bool,
}

impl From<hosts::TelnetForm> for TelnetDraft {
    fn from(t: hosts::TelnetForm) -> Self {
        Self {
            port: t.port,
            username: t.username,
            password: None,
            identity_id: t.identity_id.map(|i| i.to_string()),
            has_password: t.has_password,
        }
    }
}

impl HostDraft {
    /// Empty draft for a new host in `vault_id`.
    pub fn blank(vault_id: Uuid, group_id: Option<Uuid>) -> Self {
        Self {
            id: None,
            vault_id: vault_id.to_string(),
            label: String::new(),
            address: String::new(),
            group_id: group_id.map(|g| g.to_string()),
            port: None,
            username: String::new(),
            password: None,
            ssh_key_id: None,
            identity_id: None,
            ssh_id: false,
            ssh_id_key_type: None,
            use_mosh: false,
            mosh_server_command: None,
            tag_ids: Vec::new(),
            notes: String::new(),
            os_name: None,
            icon: None,
            ip_version: "auto".into(),
            agent_forwarding: false,
            forward_x11: false,
            startup_snippet_id: None,
            env_variables: Vec::new(),
            keep_alive_interval: None,
            host_chain_id: None,
            proxy_id: None,
            gateway_id: None,
            mac_address: None,
            color_scheme: None,
            charset: None,
            backspace: None,
            timeout: None,
            has_password: false,
            has_totp: false,
            ssh: true,
            telnet: None,
            webdav: None,
            files_provider: false,
            totp_secret: None,
        }
    }
}

impl From<hosts::HostForm> for HostDraft {
    fn from(f: hosts::HostForm) -> Self {
        Self {
            id: f.id.map(|i| i.to_string()),
            vault_id: f.vault_id.to_string(),
            label: f.label,
            address: f.address,
            group_id: f.group_id.map(|g| g.to_string()),
            port: f.port,
            username: f.username,
            password: None,
            totp_secret: None,
            ssh_key_id: f.ssh_key_id.map(|k| k.to_string()),
            identity_id: f.identity_id.map(|i| i.to_string()),
            ssh_id: f.ssh_id,
            ssh_id_key_type: f.ssh_id_key_type.map(Into::into),
            use_mosh: f.use_mosh,
            mosh_server_command: f.mosh_server_command,
            tag_ids: f.tag_ids.iter().map(ToString::to_string).collect(),
            notes: f.notes,
            os_name: f.os_name,
            icon: f.icon,
            ip_version: f.ip_version,
            agent_forwarding: f.agent_forwarding,
            forward_x11: f.forward_x11,
            startup_snippet_id: f.startup_snippet_id.map(|s| s.to_string()),
            env_variables: f
                .env_variables
                .into_iter()
                .map(|(name, value)| EnvVar { name, value })
                .collect(),
            keep_alive_interval: f.keep_alive_interval,
            timeout: f.timeout,
            host_chain_id: f.host_chain_id.map(|i| i.to_string()),
            proxy_id: f.proxy_id.map(|i| i.to_string()),
            gateway_id: f.gateway_id.map(|i| i.to_string()),
            mac_address: f.mac_address,
            color_scheme: f.color_scheme,
            charset: f.charset,
            backspace: f.backspace,
            has_password: f.has_password,
            has_totp: f.has_totp,
            ssh: f.ssh,
            telnet: f.telnet.map(Into::into),
            webdav: f.webdav.map(Into::into),
            files_provider: f.files_provider,
        }
    }
}

impl HostDraft {
    /// Overlay this draft on `base` (the stored form for edits, a fresh SSH
    /// form for new hosts) so untouched sections survive the round trip.
    pub(crate) fn apply(self, mut base: hosts::HostForm) -> Result<hosts::HostForm> {
        base.id = parse_opt_id(&self.id)?;
        base.vault_id = parse_id(&self.vault_id)?;
        base.label = self.label;
        base.address = self.address;
        base.group_id = parse_opt_id(&self.group_id)?;
        base.ssh = self.ssh || (self.telnet.is_none() && self.webdav.is_none());
        base.port = self.port;
        base.username = self.username;
        base.password = self.password;
        base.totp_secret = self.totp_secret;
        base.ssh_key_id = parse_opt_id(&self.ssh_key_id)?;
        base.identity_id = parse_opt_id(&self.identity_id)?;
        base.ssh_id = self.ssh_id;
        base.ssh_id_key_type = self.ssh_id_key_type.map(Into::into);
        base.use_mosh = self.use_mosh;
        base.mosh_server_command = self
            .mosh_server_command
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        base.tag_ids = parse_ids(&self.tag_ids)?;
        base.notes = self.notes;
        base.os_name = self.os_name;
        base.icon = self.icon;
        base.ip_version = self.ip_version;
        base.agent_forwarding = self.agent_forwarding;
        base.forward_x11 = self.forward_x11;
        base.startup_snippet_id = parse_opt_id(&self.startup_snippet_id)?;
        base.env_variables = self
            .env_variables
            .into_iter()
            .map(|e| (e.name, e.value))
            .collect();
        base.keep_alive_interval = self.keep_alive_interval;
        base.timeout = self.timeout;
        base.host_chain_id = parse_opt_id(&self.host_chain_id)?;
        base.proxy_id = parse_opt_id(&self.proxy_id)?;
        base.gateway_id = parse_opt_id(&self.gateway_id)?;
        base.mac_address = self
            .mac_address
            .map(|m| m.trim().to_string())
            .filter(|m| !m.is_empty());
        base.color_scheme = self.color_scheme;
        base.charset = self.charset;
        base.backspace = self.backspace;
        base.files_provider = self.files_provider;
        base.telnet = match self.telnet {
            None => None,
            Some(t) => {
                let stored = base.telnet.take().unwrap_or_default();
                Some(hosts::TelnetForm {
                    port: t.port,
                    username: t.username,
                    password: t.password,
                    identity_id: parse_opt_id(&t.identity_id)?,
                    color_scheme: stored.color_scheme,
                    has_password: stored.has_password,
                })
            }
        };
        base.webdav = match self.webdav {
            None => None,
            Some(w) => {
                let stored = base.webdav.take().unwrap_or_default();
                Some(hosts::WebDavForm {
                    port: w.port,
                    path: w.path.trim().to_string(),
                    http: w.http,
                    tls_server_name: w
                        .tls_server_name
                        .map(|n| n.trim().to_string())
                        .filter(|n| !n.is_empty()),
                    ca_certificate: w
                        .ca_certificate
                        .map(|c| c.trim().to_string())
                        .filter(|c| !c.is_empty()),
                    username: w.username.trim().to_string(),
                    password: w.password,
                    identity_id: parse_opt_id(&w.identity_id)?,
                    certificate_fingerprint: w
                        .certificate_fingerprint
                        .map(|f| f.trim().to_string())
                        .filter(|f| !f.is_empty()),
                    has_password: stored.has_password,
                    auth: w.auth,
                    bearer_token: w.bearer_token,
                    has_bearer_token: stored.has_bearer_token,
                    client_certificate: w.client_certificate,
                    client_key: w.client_key,
                    client_certificate_fingerprint: stored.client_certificate_fingerprint,
                })
            }
        };
        Ok(base)
    }
}

pub(crate) fn blank_form(vault_id: Uuid) -> hosts::HostForm {
    hosts::HostForm {
        id: None,
        vault_id,
        label: String::new(),
        address: String::new(),
        group_id: None,
        ssh: true,
        port: None,
        username: String::new(),
        password: None,
        ssh_key_id: None,
        ssh_certificate_id: None,
        identity_id: None,
        ssh_id: false,
        ssh_id_key_type: None,
        use_mosh: false,
        mosh_server_command: None,
        tag_ids: Vec::new(),
        notes: String::new(),
        os_name: None,
        icon: None,
        ip_version: "auto".into(),
        agent_forwarding: false,
        forward_x11: false,
        startup_snippet_id: None,
        host_chain_id: None,
        proxy_id: None,
        gateway_id: None,
        mac_address: None,
        telnet: None,
        webdav: None,
        env_variables: Vec::new(),
        keep_alive_interval: None,
        timeout: None,
        color_scheme: None,
        charset: None,
        backspace: None,
        has_password: false,
        files_provider: false,
        totp_secret: None,
        has_totp: false,
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct GroupItem {
    pub id: String,
    pub vault_id: String,
    pub label: String,
    pub parent_id: Option<String>,
    pub host_count: u32,
    pub group_count: u32,
    pub has_config: bool,
}

impl From<hosts::GroupNode> for GroupItem {
    fn from(g: hosts::GroupNode) -> Self {
        Self {
            id: g.id.to_string(),
            vault_id: g.vault_id.to_string(),
            label: g.label,
            parent_id: g.parent_id.map(|p| p.to_string()),
            host_count: g.host_count as u32,
            group_count: g.group_count as u32,
            has_config: g.has_config,
        }
    }
}

/// What a host in `group_id` inherits from the group chain (placeholders in
/// the editor).
#[derive(Debug, Clone, uniffi::Record)]
pub struct InheritedInfo {
    pub group_path: Vec<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub has_password: bool,
    /// A TOTP secret is inherited (codes typed automatically).
    pub has_totp: bool,
    pub ssh_key_id: Option<String>,
    pub ssh_key_label: Option<String>,
    pub identity_id: Option<String>,
    pub identity_label: Option<String>,
    /// The inherited credentials log in with SSH ID.
    pub ssh_id: bool,
}

impl From<hosts::Inherited> for InheritedInfo {
    fn from(i: hosts::Inherited) -> Self {
        Self {
            group_path: i.group_path,
            port: i.port,
            username: i.username,
            has_password: i.has_password,
            has_totp: i.has_totp,
            ssh_key_id: i.ssh_key_id.map(|k| k.to_string()),
            ssh_key_label: i.ssh_key_label,
            identity_id: i.identity_id.map(|k| k.to_string()),
            identity_label: i.identity_label,
            ssh_id: i.ssh_id,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct TagItem {
    pub id: String,
    pub vault_id: String,
    pub label: String,
    pub hosts: u32,
}

impl From<hosts::TagInfo> for TagItem {
    fn from(t: hosts::TagInfo) -> Self {
        Self {
            id: t.id.to_string(),
            vault_id: t.vault_id.to_string(),
            label: t.label,
            hosts: t.hosts as u32,
        }
    }
}

/// A key as listed in the Keychain: public half and metadata only.
#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyItem {
    pub id: String,
    pub vault_id: String,
    pub label: String,
    pub key_type: String,
    pub bits: u32,
    pub fingerprint: String,
    pub public_key: String,
    pub comment: String,
    /// The private key is passphrase-protected.
    pub encrypted: bool,
    /// The passphrase is remembered in the vault.
    pub has_passphrase: bool,
    pub unreadable: bool,
    /// Identities using this key.
    pub used_by: u32,
    pub has_certificate: bool,
    /// FIDO2 security key: the stored handle needs the token to sign.
    pub security_key: bool,
    pub updated_at: i64,
}

impl From<keychain::KeyCard> for KeyItem {
    fn from(k: keychain::KeyCard) -> Self {
        Self {
            id: k.id.to_string(),
            vault_id: k.vault_id.to_string(),
            label: k.label,
            security_key: termoso_core::fido2::is_sk_type(&k.key_type),
            key_type: k.key_type,
            bits: k.bits as u32,
            fingerprint: k.fingerprint,
            public_key: k.public_key,
            comment: k.comment,
            encrypted: k.encrypted,
            has_passphrase: k.has_passphrase,
            unreadable: k.unreadable,
            used_by: k.used_by as u32,
            has_certificate: k.certificate.is_some(),
            updated_at: millis(k.updated_at),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum KeyAlgorithm {
    Ed25519,
    Rsa { bits: u32 },
    EcdsaP256,
    EcdsaP384,
}

impl From<KeyAlgorithm> for termoso_core::keys::KeyAlgorithm {
    fn from(a: KeyAlgorithm) -> Self {
        match a {
            KeyAlgorithm::Ed25519 => Self::Ed25519,
            KeyAlgorithm::Rsa { bits } => Self::Rsa {
                bits: bits as usize,
            },
            KeyAlgorithm::EcdsaP256 => Self::EcdsaP256,
            KeyAlgorithm::EcdsaP384 => Self::EcdsaP384,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyGenerateDraft {
    pub vault_id: String,
    pub label: String,
    pub algorithm: KeyAlgorithm,
    pub comment: String,
    pub passphrase: Option<String>,
    pub remember_passphrase: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyImportDraft {
    pub vault_id: String,
    pub label: String,
    /// OpenSSH / PKCS#8 / PEM / PuTTY `.ppk` text.
    pub private_key: String,
    pub passphrase: Option<String>,
    pub remember_passphrase: bool,
    pub certificate: Option<String>,
}

/// Certificate chain and private key found in one PEM text; either may be
/// empty.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PemParts {
    pub certificate: String,
    pub private_key: String,
}

/// What a pasted private key looks like before importing it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyPreview {
    pub key_type: String,
    pub bits: u32,
    pub fingerprint: String,
    pub public_key: String,
    pub comment: String,
    pub encrypted: bool,
    pub putty: bool,
}

impl From<keychain::KeyPreview> for KeyPreview {
    fn from(p: keychain::KeyPreview) -> Self {
        Self {
            key_type: p.key_type,
            bits: p.bits as u32,
            fingerprint: p.fingerprint,
            public_key: p.public_key,
            comment: p.comment,
            encrypted: p.encrypted,
            putty: p.putty,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct IdentityItem {
    pub id: String,
    pub vault_id: String,
    pub label: String,
    pub username: String,
    pub has_password: bool,
    /// A TOTP secret is stored: one-time codes are typed automatically.
    pub has_totp: bool,
    pub ssh_key_id: Option<String>,
    pub ssh_key_label: Option<String>,
    pub has_certificate: bool,
    /// Logs in with the account's SSH ID passkeys.
    pub ssh_id: bool,
    pub ssh_id_key_type: Option<SshIdKeyKind>,
    pub updated_at: i64,
}

impl From<keychain::IdentityCard> for IdentityItem {
    fn from(i: keychain::IdentityCard) -> Self {
        Self {
            id: i.id.to_string(),
            vault_id: i.vault_id.to_string(),
            label: i.label,
            username: i.username,
            has_password: i.has_password,
            ssh_key_id: i.ssh_key_id.map(|k| k.to_string()),
            ssh_key_label: i.ssh_key_label,
            has_certificate: i.has_certificate,
            ssh_id: i.ssh_id,
            ssh_id_key_type: i.ssh_id_key_type.map(Into::into),
            updated_at: millis(i.updated_at),
            has_totp: i.has_totp,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct IdentityDraft {
    pub id: Option<String>,
    pub vault_id: String,
    pub label: String,
    pub username: String,
    /// `None` keeps the stored password, `Some("")` clears it.
    pub password: Option<String>,
    /// `None` keeps the stored TOTP secret, `Some("")` clears it.
    pub totp_secret: Option<String>,
    pub ssh_key_id: Option<String>,
    pub ssh_id: bool,
    pub ssh_id_key_type: Option<SshIdKeyKind>,
}

impl IdentityDraft {
    pub(crate) fn into_form(self) -> Result<keychain::IdentityForm> {
        Ok(keychain::IdentityForm {
            id: parse_opt_id(&self.id)?,
            vault_id: parse_id(&self.vault_id)?,
            label: self.label,
            username: self.username,
            password: self.password,
            totp_secret: self.totp_secret,
            ssh_key_id: parse_opt_id(&self.ssh_key_id)?,
            ssh_certificate_id: None,
            ssh_id: self.ssh_id,
            ssh_id_key_type: self.ssh_id_key_type.map(Into::into),
        })
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct KnownHostItem {
    pub id: String,
    /// `host[:port]`.
    pub hostname: String,
    pub key_type: String,
    pub fingerprint: String,
    pub updated_at: i64,
}

/// A server key pinned for one `host:port`; team-vault pins sync to members.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HostKeyPinItem {
    pub id: String,
    pub vault_id: String,
    pub key_type: String,
    pub fingerprint: String,
    /// `<type> <base64>`
    pub public_key: String,
}

impl From<termoso_client::trust::HostKeyPin> for HostKeyPinItem {
    fn from(p: termoso_client::trust::HostKeyPin) -> Self {
        Self {
            id: p.id.to_string(),
            vault_id: p.vault_id.to_string(),
            key_type: p.key_type,
            fingerprint: p.fingerprint,
            public_key: p.public_key,
        }
    }
}

/// A command typed at a shell prompt, newest first.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CommandHistoryItem {
    pub id: String,
    pub host_id: Option<String>,
    pub command: String,
    pub at: i64,
}

/// A terminal recording known to this device.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SessionLogCard {
    pub id: String,
    pub vault_id: String,
    pub host_id: Option<String>,
    pub label: String,
    pub target: String,
    pub protocol: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub bytes: u64,
    pub mine: bool,
    pub author: Option<String>,
    pub completed: bool,
    /// Body is on this device (a teammate's is fetched on first open).
    pub downloaded: bool,
    pub pinned: bool,
    pub note: String,
}

/// A past connection, newest first.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HistoryItem {
    pub id: String,
    /// Vault of the saved host; `None` for quick connects, local shells
    /// and hosts that no longer exist.
    pub vault_id: Option<String>,
    pub host_id: Option<String>,
    pub label: String,
    /// `user@address:port`.
    pub target: String,
    pub protocol: String,
    pub started_at: i64,
    pub duration_secs: Option<u64>,
    pub error: Option<String>,
}

// ───────────────────────────── proxies & jump chains ─────────────────────────────

/// SOCKS / HTTP proxy a host can connect through.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ProxyItem {
    pub id: String,
    pub vault_id: String,
    /// `socks4`, `socks5` or `http`.
    pub kind: String,
    pub host: String,
    pub port: u16,
    /// Identity used for proxy authentication.
    pub identity_id: Option<String>,
    pub identity_label: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Editor model of a proxy; `id` is `None` for a new one.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ProxyDraft {
    pub id: Option<String>,
    pub vault_id: String,
    pub kind: String,
    pub host: String,
    pub port: u16,
    pub identity_id: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Ordered jump hosts a connection goes through before the target.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HostChainItem {
    pub id: String,
    pub vault_id: String,
    pub label: String,
    pub host_ids: Vec<String>,
    /// Labels of [`Self::host_ids`] in order (unknown hosts are skipped).
    pub host_labels: Vec<String>,
}

/// Editor model of a jump chain; `id` is `None` for a new one.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HostChainDraft {
    pub id: Option<String>,
    pub vault_id: String,
    pub label: String,
    pub host_ids: Vec<String>,
}
