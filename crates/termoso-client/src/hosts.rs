//! Host list / editor façade. The UI edits a flat `HostForm`; Rust maps it to
//! the `host` + inline `ssh_config` + inline `identity` entities (Termius
//! layout) and resolves group inheritance for display.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use termoso_core::model::{
    ClientCertificate, Entity, Group, Host, HostChain, HostSnippet, Identity, Proxy, SerialConfig,
    Snippet, SshCertificate, SshConfig, SshKey, Tag, TelnetConfig, WebDavConfig,
};
use termoso_core::store::Store;
use termoso_core::webdav::client_certificate_fingerprint;
use termoso_proto::sshid::SshIdKeyType;
use uuid::Uuid;

use crate::error::{ClientError, Result};
use crate::keychain;

/// What a host card / list row shows. Effective values already account for
/// group inheritance.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostCard {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub label: String,
    pub address: String,
    pub group_id: Option<Uuid>,
    pub group_path: Vec<String>,
    /// Primary protocol: `ssh`, or `telnet` / `webdav` when the host has no
    /// SSH section.
    pub protocol: String,
    /// Effective username of the primary protocol.
    pub username: String,
    /// Effective port of the primary protocol.
    pub port: u16,
    /// Effective Telnet port when the host also has a Telnet configuration.
    pub telnet_port: Option<u16>,
    /// Base URL of the host's WebDAV share, when it has one.
    pub webdav_url: Option<String>,
    /// The SSH section connects over Mosh by default.
    pub use_mosh: bool,
    pub tags: Vec<String>,
    pub os_name: Option<String>,
    /// User-chosen icon id; takes precedence over `os_name`.
    pub icon: Option<String>,
    /// `auto` | `4` | `6`.
    pub ip_version: String,
    pub notes: String,
    pub sort_order: i32,
    /// Shown to the system file picker (Android SAF).
    pub files_provider: bool,
    pub updated_at: DateTime<Utc>,
    /// Most recent connection to this host, if any.
    pub last_connected: Option<DateTime<Utc>>,
    /// Provider the host was imported from (`Host::cloud_instance_type`).
    pub cloud_provider: Option<String>,
    pub dirty: bool,
}

/// Flat editor model. `None` for optional fields means "inherit / unset".
/// A host carries an SSH configuration (`ssh`), a Telnet one (`telnet`) or
/// both, like Termius' protocol sections.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostForm {
    pub id: Option<Uuid>,
    pub vault_id: Uuid,
    pub label: String,
    pub address: String,
    pub group_id: Option<Uuid>,
    /// The host has an SSH section; the SSH fields below belong to it.
    #[serde(default = "default_true")]
    pub ssh: bool,
    pub port: Option<u16>,
    pub username: String,
    /// `None` keeps the stored password when editing; `Some("")` clears it.
    pub password: Option<String>,
    /// TOTP secret for keyboard-interactive logins; `None` keeps the stored
    /// one, `Some("")` clears it.
    #[serde(default)]
    pub totp_secret: Option<String>,
    pub ssh_key_id: Option<Uuid>,
    /// Certificate pinned on the host (`None` = the key's own, if any).
    #[serde(default)]
    pub ssh_certificate_id: Option<Uuid>,
    /// Reference an existing (visible) identity instead of the inline one.
    pub identity_id: Option<Uuid>,
    /// Log in with the account's SSH ID passkeys.
    #[serde(default)]
    pub ssh_id: bool,
    /// Passkey type to try first when `ssh_id` is set.
    #[serde(default)]
    pub ssh_id_key_type: Option<SshIdKeyType>,
    /// Connect with Mosh (bootstrapped over this SSH section).
    #[serde(default)]
    pub use_mosh: bool,
    /// Custom `mosh-server` command line; `None` = default.
    #[serde(default)]
    pub mosh_server_command: Option<String>,
    pub tag_ids: Vec<Uuid>,
    pub notes: String,
    pub os_name: Option<String>,
    /// User-chosen icon id (`None` = follow detection).
    #[serde(default)]
    pub icon: Option<String>,
    /// `auto` (default) | `4` | `6`.
    #[serde(default = "default_ip_version")]
    pub ip_version: String,
    pub agent_forwarding: bool,
    /// Trusted X11 forwarding to the local display (desktop only).
    #[serde(default)]
    pub forward_x11: bool,
    pub startup_snippet_id: Option<Uuid>,
    pub host_chain_id: Option<Uuid>,
    pub proxy_id: Option<Uuid>,
    /// Gateway (an API bridge in `gateway` mode) to tunnel through; `None` = direct.
    #[serde(default)]
    pub gateway_id: Option<Uuid>,
    /// MAC address for Wake-on-LAN.
    #[serde(default)]
    pub mac_address: Option<String>,
    /// Telnet section, when the host is also (or only) reachable over Telnet.
    #[serde(default)]
    pub telnet: Option<TelnetForm>,
    /// WebDAV section, when the host exposes a file share over HTTP(S).
    #[serde(default)]
    pub webdav: Option<WebDavForm>,
    #[serde(default)]
    pub env_variables: Vec<(String, String)>,
    #[serde(default)]
    pub keep_alive_interval: Option<u32>,
    #[serde(default)]
    pub timeout: Option<u32>,
    /// Terminal colour scheme id; `None` follows the app setting.
    #[serde(default)]
    pub color_scheme: Option<String>,
    /// Terminal charset (`UTF-8` when `None`).
    #[serde(default)]
    pub charset: Option<String>,
    /// Backspace mode: `None` (DEL) or `ctrl-h`.
    #[serde(default)]
    pub backspace: Option<String>,
    /// Set when the stored inline identity has a password (UI shows a mask).
    #[serde(default)]
    pub has_password: bool,
    /// Set when the stored inline identity has a TOTP secret.
    #[serde(default)]
    pub has_totp: bool,
    /// Expose the SFTP / WebDAV share to the system file picker (Android SAF).
    #[serde(default)]
    pub files_provider: bool,
    /// Shell integration override: `None` follows the app setting.
    #[serde(default)]
    pub shell_integration: Option<bool>,
}

fn default_true() -> bool {
    true
}

fn default_ip_version() -> String {
    "auto".to_string()
}

/// Telnet section of the host editor: port and login.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelnetForm {
    pub port: Option<u16>,
    #[serde(default)]
    pub username: String,
    /// `None` keeps the stored password when editing; `Some("")` clears it.
    #[serde(default)]
    pub password: Option<String>,
    /// Reference an existing (visible) identity instead of the inline one.
    #[serde(default)]
    pub identity_id: Option<Uuid>,
    #[serde(default)]
    pub color_scheme: Option<String>,
    #[serde(default)]
    pub has_password: bool,
}

/// WebDAV section of the host editor: share URL, login and the certificate
/// the user chose to trust.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebDavForm {
    /// Base URL of the share (`https://…/remote.php/dav/files/alice/`).
    /// TCP port; `None` = 443 (80 with `http`).
    #[serde(default)]
    pub port: Option<u16>,
    /// Collection path below the host (`/remote.php/dav/files/alice/`); empty = `/`.
    #[serde(default)]
    pub path: String,
    /// Plain HTTP instead of HTTPS.
    #[serde(default)]
    pub http: bool,
    /// TLS name (SNI + certificate check) when it differs from the address.
    #[serde(default)]
    pub tls_server_name: Option<String>,
    /// PEM bundle of a private CA to trust instead of the system roots.
    #[serde(default)]
    pub ca_certificate: Option<String>,
    #[serde(default)]
    pub username: String,
    /// `None` keeps the stored password when editing; `Some("")` clears it.
    #[serde(default)]
    pub password: Option<String>,
    /// Reference an existing (visible) identity instead of the inline one.
    #[serde(default)]
    pub identity_id: Option<Uuid>,
    /// Pinned SHA-256 fingerprint of a self-signed server certificate.
    #[serde(default)]
    pub certificate_fingerprint: Option<String>,
    #[serde(default)]
    pub has_password: bool,
    /// `password` (Basic / Digest, negotiated) or `token` (Bearer).
    #[serde(default = "default_webdav_auth")]
    pub auth: String,
    /// `None` keeps the stored token when editing; `Some("")` clears it.
    #[serde(default)]
    pub bearer_token: Option<String>,
    #[serde(default)]
    pub has_bearer_token: bool,
    /// PEM client certificate chain + key for servers requiring mTLS.
    /// `None` keeps the stored pair; an empty certificate clears it.
    #[serde(default)]
    pub client_certificate: Option<String>,
    #[serde(default)]
    pub client_key: Option<String>,
    /// SHA-256 fingerprint of the stored client certificate's leaf.
    #[serde(default)]
    pub client_certificate_fingerprint: Option<String>,
}

fn default_webdav_auth() -> String {
    WEBDAV_AUTH_PASSWORD.into()
}

pub const WEBDAV_AUTH_PASSWORD: &str = "password";
pub const WEBDAV_AUTH_TOKEN: &str = "token";

/// Serial line settings as edited in the Serial tab.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SerialLine {
    pub baud_rate: u32,
    pub data_bits: u8,
    pub stop_bits: u8,
    /// `none` | `odd` | `even`.
    pub parity: String,
    /// `none` | `software` | `hardware`.
    pub flow_control: String,
    /// WHATWG encoding label; empty = UTF-8.
    #[serde(default)]
    pub charset: String,
}

impl Default for SerialLine {
    fn default() -> Self {
        Self {
            baud_rate: 115_200,
            data_bits: 8,
            stop_bits: 1,
            parity: "none".into(),
            flow_control: "none".into(),
            charset: String::new(),
        }
    }
}

impl SerialLine {
    pub fn into_config(self, path: &str) -> SerialConfig {
        SerialConfig {
            path: path.to_string(),
            baud_rate: self.baud_rate,
            data_bits: self.data_bits,
            stop_bits: self.stop_bits,
            parity: self.parity,
            flow_control: self.flow_control,
            charset: self.charset,
        }
    }
}

/// Stored `ip_version` (`""`, `4`, `6`) → form value.
fn ip_version_of(stored: &str) -> String {
    match stored {
        "4" | "6" => stored.to_string(),
        _ => default_ip_version(),
    }
}

const MAX_CUSTOM_ICON_DATA_LENGTH: usize = 32 * 1024;

fn valid_custom_icon(value: &str) -> bool {
    let Some(data_url) = value.strip_prefix("custom:data:") else {
        return false;
    };
    if data_url.len() > MAX_CUSTOM_ICON_DATA_LENGTH {
        return false;
    }
    let Some((header, payload)) = data_url.split_once(',') else {
        return false;
    };
    let Some(mime) = header
        .strip_prefix("data:")
        .and_then(|h| h.strip_suffix(";base64"))
    else {
        return false;
    };
    if !matches!(
        mime.to_ascii_lowercase().as_str(),
        "image/png"
            | "image/jpeg"
            | "image/gif"
            | "image/webp"
            | "image/svg+xml"
            | "image/x-icon"
            | "image/avif"
    ) {
        return false;
    }
    !payload.is_empty()
        && payload
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

fn clean_icon(icon: &Option<String>) -> Result<Option<String>> {
    let value = icon
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "auto");
    let Some(value) = value else {
        return Ok(None);
    };
    if value.starts_with("custom:") && !valid_custom_icon(value) {
        return Err(ClientError::invalid("invalid custom icon"));
    }
    Ok(Some(value.to_string()))
}

/// Empty / whitespace scheme ids mean "follow the app setting".
fn clean_scheme(scheme: &Option<String>) -> Option<String> {
    scheme
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Telnet is the primary protocol only when the host has no SSH section.
fn is_telnet_only(h: &Host) -> bool {
    h.telnet_config_id.is_some() && h.ssh_config_id.is_none()
}

/// WebDAV is the primary protocol only when the host has neither SSH nor
/// Telnet.
fn is_webdav_only(h: &Host) -> bool {
    h.webdav_config_id.is_some() && h.ssh_config_id.is_none() && h.telnet_config_id.is_none()
}

/// Validate the WebDAV section's connection fields; identity and pin are
/// filled in by the caller.
fn clean_webdav_section(w: &WebDavForm) -> Result<WebDavConfig> {
    if w.port == Some(0) {
        return Err(ClientError::invalid("WebDAV port must be 1–65535"));
    }
    let name = w
        .tls_server_name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty() && !w.http);
    let tls_server_name = match name {
        Some(n) => Some(
            termoso_core::webdav::validate_server_name(n)
                .map_err(|e| ClientError::invalid(format!("WebDAV TLS: {e}")))?,
        ),
        None => None,
    };
    let ca = w
        .ca_certificate
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty() && !w.http);
    let ca_certificate = match ca {
        Some(pem) => {
            termoso_core::webdav::validate_ca_bundle(pem)
                .map_err(|e| ClientError::invalid(format!("WebDAV TLS: {e}")))?;
            Some(pem.to_string())
        }
        None => None,
    };
    Ok(WebDavConfig {
        url: String::new(),
        port: w.port,
        path: termoso_core::webdav::normalize_share_path(&w.path),
        http: w.http,
        tls_server_name,
        ca_certificate,
        identity_id: None,
        certificate_fingerprint: None,
    })
}

/// Per-field view of a stored section; older entries that still carry a
/// full URL are split so the form (and the next save) use the fields.
fn webdav_fields(w: &WebDavConfig) -> (Option<u16>, String, bool) {
    if w.url.trim().is_empty() {
        return (w.port, w.path.clone(), w.http);
    }
    match termoso_core::webdav::split_share_url(&w.url) {
        Ok(p) => (p.port, p.path, p.http),
        Err(_) => (w.port, w.path.clone(), w.http),
    }
}

/// `aa:bb:…` fingerprint the form may enter with or without separators.
fn clean_fingerprint(fp: &Option<String>) -> Result<Option<String>> {
    let Some(raw) = fp.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    termoso_core::webdav::normalize_fingerprint(raw)
        .map(Some)
        .map_err(|e| ClientError::invalid(format!("certificate fingerprint: {e}")))
}

/// Hidden inline identity flattened into a form section.
#[derive(Default)]
struct FlatIdentity {
    identity_id: Option<Uuid>,
    username: String,
    ssh_key_id: Option<Uuid>,
    ssh_certificate_id: Option<Uuid>,
    has_password: bool,
    has_totp: bool,
    ssh_id: bool,
    ssh_id_key_type: Option<SshIdKeyType>,
    has_bearer_token: bool,
    client_certificate_fingerprint: Option<String>,
}

fn flatten_identity(store: &Store, id: Option<Uuid>) -> Result<FlatIdentity> {
    let identity = match id {
        Some(i) => store.get::<Identity>(i)?,
        None => None,
    };
    Ok(match &identity {
        Some(i) if i.data.is_visible => FlatIdentity {
            identity_id: Some(i.id),
            ..FlatIdentity::default()
        },
        Some(i) => FlatIdentity {
            identity_id: None,
            username: i.data.username.clone(),
            ssh_key_id: i.data.ssh_key_id,
            ssh_certificate_id: i.data.ssh_certificate_id,
            has_password: i.data.password.as_deref().is_some_and(|p| !p.is_empty()),
            has_totp: i.data.totp_secret.as_deref().is_some_and(|t| !t.is_empty()),
            ssh_id: i.data.ssh_id,
            ssh_id_key_type: i.data.ssh_id_key_type,
            has_bearer_token: i
                .data
                .bearer_token
                .as_deref()
                .is_some_and(|t| !t.is_empty()),
            client_certificate_fingerprint: i
                .data
                .client_certificate
                .as_ref()
                .and_then(|c| client_certificate_fingerprint(&c.certificate).ok()),
        },
        None => FlatIdentity::default(),
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupNode {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub label: String,
    pub parent_id: Option<Uuid>,
    pub sort_order: i32,
    /// Hosts directly inside this group.
    pub host_count: usize,
    /// Sub-groups directly inside this group.
    pub group_count: usize,
    /// The group carries SSH defaults its hosts inherit.
    pub has_config: bool,
    /// User-chosen icon id (`None` = default folder).
    pub icon: Option<String>,
}

/// Editor model for a group: name, parent and the SSH defaults hosts inherit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupForm {
    pub id: Option<Uuid>,
    pub vault_id: Uuid,
    pub label: String,
    pub parent_id: Option<Uuid>,
    /// User-chosen icon id (`None` = default folder).
    #[serde(default)]
    pub icon: Option<String>,
    pub port: Option<u16>,
    pub username: String,
    /// `None` keeps the stored password when editing; `Some("")` clears it.
    pub password: Option<String>,
    /// TOTP secret; `None` keeps the stored one, `Some("")` clears it.
    #[serde(default)]
    pub totp_secret: Option<String>,
    pub ssh_key_id: Option<Uuid>,
    #[serde(default)]
    pub ssh_certificate_id: Option<Uuid>,
    pub identity_id: Option<Uuid>,
    #[serde(default)]
    pub has_password: bool,
    #[serde(default)]
    pub has_totp: bool,
    #[serde(default)]
    pub ssh_id: bool,
    #[serde(default)]
    pub ssh_id_key_type: Option<SshIdKeyType>,
    #[serde(default)]
    pub agent_forwarding: bool,
    #[serde(default)]
    pub forward_x11: bool,
    pub host_chain_id: Option<Uuid>,
    pub proxy_id: Option<Uuid>,
    #[serde(default)]
    pub env_variables: Vec<(String, String)>,
    #[serde(default)]
    pub keep_alive_interval: Option<u32>,
    #[serde(default)]
    pub timeout: Option<u32>,
}

/// What a host placed in a group inherits from the group chain. Shown as
/// placeholders / "Inherited" hints in the host editor.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inherited {
    /// Group path root → leaf.
    pub group_path: Vec<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub has_password: bool,
    /// A TOTP secret is inherited (codes typed automatically).
    pub has_totp: bool,
    pub ssh_key_id: Option<Uuid>,
    pub ssh_key_label: Option<String>,
    /// A visible (shared) identity is inherited.
    pub identity_id: Option<Uuid>,
    pub identity_label: Option<String>,
    /// The inherited credentials log in with SSH ID.
    pub ssh_id: bool,
    pub agent_forwarding: bool,
    pub forward_x11: bool,
    pub host_chain_id: Option<Uuid>,
    pub proxy_id: Option<Uuid>,
    pub keep_alive_interval: Option<u32>,
    pub timeout: Option<u32>,
    pub env_variables: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TagInfo {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub label: String,
    pub color: Option<String>,
    /// Hosts carrying the tag.
    pub hosts: usize,
}

/// Newest connection per saved host.
fn last_connections(store: &Store) -> Result<HashMap<Uuid, DateTime<Utc>>> {
    let mut out = HashMap::new();
    for item in store.connections(2000)? {
        if let Some(hid) = item.data.host_id {
            let e = out.entry(hid).or_insert(item.created_at);
            if item.created_at > *e {
                *e = item.created_at;
            }
        }
    }
    Ok(out)
}

pub fn cards(store: &Store, vault_id: Option<Uuid>) -> Result<Vec<HostCard>> {
    let hosts: Vec<Entity<Host>> = store.list(vault_id)?;
    let recent = last_connections(store)?;
    let mut out = Vec::with_capacity(hosts.len());
    for h in hosts {
        let r = store.resolve_host(h.id)?;
        let telnet_only = is_telnet_only(&h.data);
        let webdav_only = is_webdav_only(&h.data);
        let telnet_port = r.telnet.as_ref().map(|t| t.port.unwrap_or(23));
        let webdav_url = r
            .webdav
            .as_ref()
            .and_then(|w| termoso_core::webdav::share_url(&h.data.address, w).ok())
            .map(|u| u.to_string());
        let port = if telnet_only {
            telnet_port.unwrap_or(23)
        } else if webdav_only {
            webdav_url
                .as_deref()
                .and_then(|u| url::Url::parse(u).ok())
                .and_then(|u| u.port_or_known_default())
                .unwrap_or(443)
        } else {
            r.port()
        };
        let username = if webdav_only {
            r.webdav_identity
                .as_ref()
                .map(|i| i.data.username.clone())
                .unwrap_or_default()
        } else {
            r.username().unwrap_or_default()
        };
        let protocol = if telnet_only {
            "telnet"
        } else if webdav_only {
            "webdav"
        } else {
            "ssh"
        };
        out.push(HostCard {
            id: h.id,
            vault_id: h.vault_id,
            label: h.data.label.clone(),
            address: h.data.address.clone(),
            group_id: h.data.group_id,
            group_path: r.group_path,
            protocol: protocol.to_string(),
            username,
            port,
            telnet_port,
            webdav_url,
            use_mosh: protocol == "ssh" && r.ssh.use_mosh,
            tags: r.tags,
            os_name: h.data.os_name.clone(),
            icon: h.data.icon.clone(),
            ip_version: ip_version_of(&h.data.ip_version),
            notes: h.data.notes.clone(),
            sort_order: h.data.sort_order,
            files_provider: h.data.files_provider,
            updated_at: h.updated_at,
            last_connected: recent.get(&h.id).copied(),
            cloud_provider: h.data.cloud_instance_type.clone(),
            dirty: h.dirty,
        });
    }
    out.sort_by(|a, b| {
        a.sort_order
            .cmp(&b.sort_order)
            .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
    });
    Ok(out)
}

pub fn groups(store: &Store, vault_id: Option<Uuid>) -> Result<Vec<GroupNode>> {
    let groups: Vec<Entity<Group>> = store.list(vault_id)?;
    let hosts: Vec<Entity<Host>> = store.list(vault_id)?;
    let mut out: Vec<GroupNode> = groups
        .iter()
        .map(|g| GroupNode {
            host_count: hosts
                .iter()
                .filter(|h| h.data.group_id == Some(g.id))
                .count(),
            group_count: groups
                .iter()
                .filter(|c| c.data.parent_id == Some(g.id))
                .count(),
            has_config: g.data.ssh_config_id.is_some(),
            icon: g.data.icon.clone(),
            id: g.id,
            vault_id: g.vault_id,
            label: g.data.label.clone(),
            parent_id: g.data.parent_id,
            sort_order: g.data.sort_order,
        })
        .collect();
    out.sort_by(|a, b| {
        a.sort_order
            .cmp(&b.sort_order)
            .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
    });
    Ok(out)
}

pub fn tags(store: &Store, vault_id: Option<Uuid>) -> Result<Vec<TagInfo>> {
    let tags: Vec<Entity<Tag>> = store.list(vault_id)?;
    let hosts: Vec<Entity<Host>> = store.list(vault_id)?;
    let mut counts: HashMap<Uuid, usize> = HashMap::new();
    for h in &hosts {
        let mut seen = h.data.tag_ids.clone();
        seen.sort();
        seen.dedup();
        for t in seen {
            *counts.entry(t).or_default() += 1;
        }
    }
    let mut out: Vec<TagInfo> = tags
        .into_iter()
        .map(|t| TagInfo {
            id: t.id,
            vault_id: t.vault_id,
            hosts: counts.get(&t.id).copied().unwrap_or(0),
            label: t.data.label,
            color: t.data.color,
        })
        .collect();
    out.sort_by_key(|t| t.label.to_lowercase());
    Ok(out)
}

fn normalize_tag_color(color: Option<String>) -> Result<Option<String>> {
    let Some(c) = color.map(|c| c.trim().to_ascii_lowercase()) else {
        return Ok(None);
    };
    if c.is_empty() {
        return Ok(None);
    }
    let hex = c.strip_prefix('#').unwrap_or(&c);
    if !matches!(hex.len(), 3 | 6) || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ClientError::invalid("tag colour must be a hex value"));
    }
    Ok(Some(format!("#{hex}")))
}

/// Rename and/or recolour a tag. Renaming onto an existing label in the same
/// vault merges into that tag instead (Termius does the same).
pub fn tag_update(
    store: &Store,
    id: Uuid,
    label: String,
    color: Option<String>,
) -> Result<TagInfo> {
    let mut tag = store.require::<Tag>(id)?;
    let label = label.trim().to_string();
    if label.is_empty() {
        return Err(ClientError::invalid("tag label is empty"));
    }
    let color = normalize_tag_color(color)?;
    let siblings: Vec<Entity<Tag>> = store.list(Some(tag.vault_id))?;
    if let Some(other) = siblings
        .iter()
        .find(|t| t.id != id && t.data.label.eq_ignore_ascii_case(&label))
    {
        let target = other.id;
        tags_merge(store, &[id], target)?;
        let mut merged = store.require::<Tag>(target)?;
        if color.is_some() && merged.data.color != color {
            merged.data.color = color;
            store.update(target, &merged.data)?;
        }
        return tag_info(store, target);
    }
    if tag.data.label != label || tag.data.color != color {
        tag.data.label = label;
        tag.data.color = color;
        store.update(id, &tag.data)?;
    }
    tag_info(store, id)
}

fn tag_info(store: &Store, id: Uuid) -> Result<TagInfo> {
    let tag = store.require::<Tag>(id)?;
    tags(store, Some(tag.vault_id))?
        .into_iter()
        .find(|t| t.id == id)
        .ok_or_else(|| ClientError::not_found("tag"))
}

/// Remove a tag and unlink it from every host.
pub fn tag_delete(store: &Store, id: Uuid) -> Result<()> {
    let tag = store.require::<Tag>(id)?;
    let hosts: Vec<Entity<Host>> = store.list(Some(tag.vault_id))?;
    for mut h in hosts {
        if h.data.tag_ids.contains(&id) {
            h.data.tag_ids.retain(|t| *t != id);
            store.update(h.id, &h.data)?;
        }
    }
    Ok(store.delete(id)?)
}

/// Fold `sources` into `target`: hosts carrying any source tag get the target
/// tag instead, then the source tags are deleted.
pub fn tags_merge(store: &Store, sources: &[Uuid], target: Uuid) -> Result<TagInfo> {
    let target_tag = store.require::<Tag>(target)?;
    let sources: Vec<Uuid> = sources.iter().copied().filter(|s| *s != target).collect();
    for s in &sources {
        let src = store.require::<Tag>(*s)?;
        if src.vault_id != target_tag.vault_id {
            return Err(ClientError::invalid("tags belong to different vaults"));
        }
    }
    let hosts: Vec<Entity<Host>> = store.list(Some(target_tag.vault_id))?;
    for mut h in hosts {
        if !h.data.tag_ids.iter().any(|t| sources.contains(t)) {
            continue;
        }
        let mut ids: Vec<Uuid> = h
            .data
            .tag_ids
            .iter()
            .copied()
            .map(|t| if sources.contains(&t) { target } else { t })
            .collect();
        let mut seen = HashSet::new();
        ids.retain(|t| seen.insert(*t));
        h.data.tag_ids = ids;
        store.update(h.id, &h.data)?;
    }
    for s in sources {
        store.delete(s)?;
    }
    tag_info(store, target)
}

/// Load the editor model for an existing host. Inline (hidden) identities are
/// flattened into the form; visible ones are referenced by id.
pub fn form(store: &Store, id: Uuid) -> Result<HostForm> {
    let host = store.require::<Host>(id)?;
    let ssh = match host.data.ssh_config_id {
        Some(c) => store.get::<SshConfig>(c)?.map(|e| e.data),
        None => None,
    };
    let telnet_cfg = match host.data.telnet_config_id {
        Some(c) => store.get::<TelnetConfig>(c)?.map(|e| e.data),
        None => None,
    };
    let webdav_cfg = match host.data.webdav_config_id {
        Some(c) => store.get::<WebDavConfig>(c)?.map(|e| e.data),
        None => None,
    };
    let ssh_login = flatten_identity(store, ssh.as_ref().and_then(|s| s.identity_id))?;
    let webdav = match &webdav_cfg {
        Some(w) => {
            let login = flatten_identity(store, w.identity_id)?;
            let (port, path, http) = webdav_fields(w);
            Some(WebDavForm {
                port,
                path,
                http,
                tls_server_name: w.tls_server_name.clone(),
                ca_certificate: w.ca_certificate.clone(),
                username: login.username,
                password: None,
                identity_id: login.identity_id,
                certificate_fingerprint: w.certificate_fingerprint.clone(),
                has_password: login.has_password,
                auth: if login.has_bearer_token {
                    WEBDAV_AUTH_TOKEN.into()
                } else {
                    WEBDAV_AUTH_PASSWORD.into()
                },
                bearer_token: None,
                has_bearer_token: login.has_bearer_token,
                client_certificate: None,
                client_key: None,
                client_certificate_fingerprint: login.client_certificate_fingerprint,
            })
        }
        None => None,
    };
    let telnet = match &telnet_cfg {
        Some(t) => {
            let login = flatten_identity(store, t.identity_id)?;
            Some(TelnetForm {
                port: t.port,
                username: login.username,
                password: None,
                identity_id: login.identity_id,
                color_scheme: t.color_scheme.clone(),
                has_password: login.has_password,
            })
        }
        None => None,
    };
    Ok(HostForm {
        id: Some(host.id),
        vault_id: host.vault_id,
        label: host.data.label,
        address: host.data.address,
        group_id: host.data.group_id,
        // Hosts without any section (legacy rows) edit as SSH.
        ssh: ssh.is_some() || (telnet_cfg.is_none() && webdav_cfg.is_none()),
        port: ssh.as_ref().and_then(|s| s.port),
        username: ssh_login.username,
        password: None,
        totp_secret: None,
        ssh_key_id: ssh_login.ssh_key_id,
        ssh_certificate_id: ssh_login.ssh_certificate_id,
        identity_id: ssh_login.identity_id,
        ssh_id: ssh_login.ssh_id,
        ssh_id_key_type: ssh_login.ssh_id_key_type,
        use_mosh: ssh.as_ref().is_some_and(|s| s.use_mosh),
        mosh_server_command: ssh.as_ref().and_then(|s| s.mosh_server_command.clone()),
        tag_ids: host.data.tag_ids,
        notes: host.data.notes,
        os_name: host.data.os_name,
        mac_address: host.data.mac_address,
        icon: host.data.icon,
        ip_version: ip_version_of(&host.data.ip_version),
        agent_forwarding: ssh.as_ref().is_some_and(|s| s.agent_forwarding),
        forward_x11: ssh.as_ref().is_some_and(|s| s.forward_x11),
        startup_snippet_id: host.data.startup_snippet_id,
        host_chain_id: ssh.as_ref().and_then(|s| s.host_chain_id),
        proxy_id: ssh.as_ref().and_then(|s| s.proxy_id),
        gateway_id: ssh.as_ref().and_then(|s| s.gateway_id),
        telnet,
        webdav,
        env_variables: ssh
            .as_ref()
            .map(|s| s.env_variables.clone())
            .unwrap_or_default(),
        keep_alive_interval: ssh.as_ref().and_then(|s| s.keep_alive_interval),
        timeout: ssh.as_ref().and_then(|s| s.timeout),
        color_scheme: ssh.as_ref().and_then(|s| s.color_scheme.clone()),
        charset: ssh.as_ref().and_then(|s| s.charset.clone()),
        backspace: host.data.backspace.clone(),
        has_password: ssh_login.has_password,
        has_totp: ssh_login.has_totp,
        files_provider: host.data.files_provider,
        shell_integration: host.data.shell_integration,
    })
}

/// The hidden identity an inline config points at, if any.
fn inline_identity_of(
    store: &Store,
    identity_id: Option<Uuid>,
) -> Result<Option<Entity<Identity>>> {
    Ok(match identity_id {
        Some(i) => store.get::<Identity>(i)?.filter(|e| !e.data.is_visible),
        None => None,
    })
}

/// Create or update a host with its inline ssh_config / telnet_config /
/// webdav_config and their hidden identities.
pub fn save(store: &Store, f: &HostForm) -> Result<HostCard> {
    let label = f.label.trim();
    if !f.ssh && f.telnet.is_none() && f.webdav.is_none() {
        return Err(ClientError::invalid(
            "a host needs an SSH, Telnet or WebDAV section",
        ));
    }
    let webdav_section = match &f.webdav {
        Some(w) => Some(clean_webdav_section(w)?),
        None => None,
    };
    let address = f.address.trim();
    if address.is_empty() {
        return Err(ClientError::invalid("address is required"));
    }
    if let Some(w) = &webdav_section {
        termoso_core::webdav::share_url(address, w)
            .map_err(|e| ClientError::invalid(format!("WebDAV: {e}")))?;
    }
    if let Some(gid) = f.group_id {
        let g = store.require::<Group>(gid)?;
        if g.vault_id != f.vault_id {
            return Err(ClientError::invalid("group belongs to another vault"));
        }
    }
    let identity_label = if label.is_empty() { address } else { label };

    let existing = match f.id {
        Some(id) => store.get::<Host>(id)?,
        None => None,
    };
    let existing_ssh = match existing.as_ref().and_then(|h| h.data.ssh_config_id) {
        Some(c) => store.get::<SshConfig>(c)?,
        None => None,
    };
    let existing_telnet = match existing.as_ref().and_then(|h| h.data.telnet_config_id) {
        Some(c) => store.get::<TelnetConfig>(c)?,
        None => None,
    };
    let ssh_inline_identity = inline_identity_of(
        store,
        existing_ssh.as_ref().and_then(|s| s.data.identity_id),
    )?;
    let telnet_inline_identity = inline_identity_of(
        store,
        existing_telnet.as_ref().and_then(|t| t.data.identity_id),
    )?;
    let existing_webdav = match existing.as_ref().and_then(|h| h.data.webdav_config_id) {
        Some(c) => store.get::<WebDavConfig>(c)?,
        None => None,
    };
    let webdav_inline_identity = inline_identity_of(
        store,
        existing_webdav.as_ref().and_then(|w| w.data.identity_id),
    )?;
    // Serial consoles are no longer saved hosts; drop a leftover config.
    if let Some(cid) = existing.as_ref().and_then(|h| h.data.serial_config_id)
        && store.get::<SerialConfig>(cid)?.is_some()
    {
        store.delete(cid)?;
    }

    let ssh_config_id = if f.ssh {
        let identity_id = upsert_identity(
            store,
            f.vault_id,
            ssh_inline_identity.as_ref(),
            &Credentials {
                identity_id: f.identity_id,
                username: &f.username,
                password: f.password.as_deref(),
                totp_secret: f.totp_secret.as_deref(),
                ssh_key_id: f.ssh_key_id,
                ssh_certificate_id: f.ssh_certificate_id,
                ssh_id: f.ssh_id,
                ssh_id_key_type: f.ssh_id_key_type,
                label: identity_label,
                webdav: None,
            },
        )?;
        // Inline ssh_config, keeping fields the form does not edit.
        let mut ssh = existing_ssh
            .as_ref()
            .map(|e| e.data.clone())
            .unwrap_or_default();
        ssh.port = f.port.filter(|p| *p != 0);
        ssh.identity_id = identity_id;
        ssh.use_mosh = f.use_mosh;
        ssh.mosh_server_command = f
            .mosh_server_command
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(str::to_string);
        ssh.agent_forwarding = f.agent_forwarding;
        ssh.forward_x11 = f.forward_x11;
        ssh.host_chain_id = f.host_chain_id;
        ssh.proxy_id = f.proxy_id;
        ssh.gateway_id = f.gateway_id;
        ssh.env_variables = clean_env(&f.env_variables);
        ssh.keep_alive_interval = f.keep_alive_interval.filter(|s| *s > 0);
        ssh.timeout = f.timeout.filter(|s| *s > 0);
        ssh.color_scheme = clean_scheme(&f.color_scheme);
        ssh.charset = clean_scheme(&f.charset).filter(|c| !c.eq_ignore_ascii_case("utf-8"));
        Some(match &existing_ssh {
            Some(e) => {
                store.update(e.id, &ssh)?;
                e.id
            }
            None => store.insert(f.vault_id, &ssh)?,
        })
    } else {
        if let Some(i) = &ssh_inline_identity {
            store.delete(i.id)?;
        }
        if let Some(e) = &existing_ssh {
            store.delete(e.id)?;
        }
        None
    };

    let telnet_config_id = if let Some(tf) = &f.telnet {
        let identity_id = upsert_identity(
            store,
            f.vault_id,
            telnet_inline_identity.as_ref(),
            &Credentials {
                identity_id: tf.identity_id,
                username: &tf.username,
                password: tf.password.as_deref(),
                totp_secret: None,
                ssh_key_id: None,
                ssh_certificate_id: None,
                ssh_id: false,
                ssh_id_key_type: None,
                label: identity_label,
                webdav: None,
            },
        )?;
        let mut t = existing_telnet
            .as_ref()
            .map(|e| e.data.clone())
            .unwrap_or_default();
        t.port = tf.port.filter(|p| *p != 0);
        t.identity_id = identity_id;
        t.color_scheme = clean_scheme(&tf.color_scheme);
        Some(match &existing_telnet {
            Some(e) => {
                store.update(e.id, &t)?;
                e.id
            }
            None => store.insert(f.vault_id, &t)?,
        })
    } else {
        if let Some(i) = &telnet_inline_identity {
            store.delete(i.id)?;
        }
        if let Some(e) = &existing_telnet {
            store.delete(e.id)?;
        }
        None
    };

    let webdav_config_id = if let (Some(wf), Some(section)) = (&f.webdav, webdav_section) {
        let token_mode = match wf.auth.as_str() {
            WEBDAV_AUTH_TOKEN => true,
            WEBDAV_AUTH_PASSWORD | "" => false,
            other => {
                return Err(ClientError::invalid(format!(
                    "unknown WebDAV auth mode `{other}`"
                )));
            }
        };
        let identity_id = upsert_identity(
            store,
            f.vault_id,
            webdav_inline_identity.as_ref(),
            &Credentials {
                identity_id: wf.identity_id,
                totp_secret: None,
                // Switching modes drops the other mode's secret.
                username: if token_mode { "" } else { &wf.username },
                password: if token_mode {
                    Some("")
                } else {
                    wf.password.as_deref()
                },
                ssh_key_id: None,
                ssh_certificate_id: None,
                ssh_id: false,
                ssh_id_key_type: None,
                label: identity_label,
                webdav: Some(WebDavCredentials {
                    bearer_token: if token_mode {
                        wf.bearer_token.as_deref()
                    } else {
                        Some("")
                    },
                    client_certificate: wf.client_certificate.as_deref(),
                    client_key: wf.client_key.as_deref(),
                }),
            },
        )?;
        let w = WebDavConfig {
            identity_id,
            certificate_fingerprint: clean_fingerprint(&wf.certificate_fingerprint)?,
            ..section
        };
        Some(match &existing_webdav {
            Some(e) => {
                if e.data != w {
                    store.update(e.id, &w)?;
                }
                e.id
            }
            None => store.insert(f.vault_id, &w)?,
        })
    } else {
        if let Some(i) = &webdav_inline_identity {
            store.delete(i.id)?;
        }
        if let Some(e) = &existing_webdav {
            store.delete(e.id)?;
        }
        None
    };

    let mut host = existing
        .as_ref()
        .map(|e| e.data.clone())
        .unwrap_or_default();
    host.label = if label.is_empty() {
        address.to_string()
    } else {
        label.to_string()
    };
    host.address = address.to_string();
    host.group_id = f.group_id;
    host.ssh_config_id = ssh_config_id;
    host.telnet_config_id = telnet_config_id;
    host.webdav_config_id = webdav_config_id;
    host.serial_config_id = None;
    host.tag_ids = f.tag_ids.clone();
    host.notes = f.notes.clone();
    host.files_provider = f.files_provider;
    host.shell_integration = f.shell_integration;
    // Detection owns `os_name`; a form loaded before a connection must not
    // erase what the session learned meanwhile.
    if existing.is_none() {
        host.os_name = f.os_name.clone().filter(|s| !s.is_empty());
    }
    host.mac_address = f
        .mac_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    host.icon = clean_icon(&f.icon)?;
    host.backspace = clean_scheme(&f.backspace);
    host.ip_version = match f.ip_version.as_str() {
        "4" | "6" => f.ip_version.clone(),
        _ => String::new(),
    };
    host.startup_snippet_id = f.startup_snippet_id;
    let host_id = match &existing {
        Some(e) => {
            store.update(e.id, &host)?;
            e.id
        }
        None => store.insert(f.vault_id, &host)?,
    };

    cards(store, Some(f.vault_id))?
        .into_iter()
        .find(|c| c.id == host_id)
        .ok_or_else(|| ClientError::not_found(format!("host {host_id}")))
}

/// Delete a host together with its inline ssh_config and hidden identity.
pub fn delete(store: &Store, id: Uuid) -> Result<()> {
    let Some(host) = store.get::<Host>(id)? else {
        return Ok(());
    };
    let mut identity_refs = Vec::new();
    if let Some(cid) = host.data.ssh_config_id
        && let Some(cfg) = store.get::<SshConfig>(cid)?
    {
        identity_refs.extend(cfg.data.identity_id);
        store.delete(cfg.id)?;
    }
    if let Some(cid) = host.data.telnet_config_id
        && let Some(cfg) = store.get::<TelnetConfig>(cid)?
    {
        identity_refs.extend(cfg.data.identity_id);
        store.delete(cfg.id)?;
    }
    if let Some(cid) = host.data.webdav_config_id
        && let Some(cfg) = store.get::<WebDavConfig>(cid)?
    {
        identity_refs.extend(cfg.data.identity_id);
        store.delete(cfg.id)?;
    }
    if let Some(cid) = host.data.serial_config_id
        && store.get::<SerialConfig>(cid)?.is_some()
    {
        store.delete(cid)?;
    }
    for iid in identity_refs {
        if let Some(i) = store.get::<Identity>(iid)?
            && !i.data.is_visible
        {
            store.delete(i.id)?;
        }
    }
    for hs in store.list::<HostSnippet>(Some(host.vault_id))? {
        if hs.data.host_id == id {
            store.delete(hs.id)?;
        }
    }
    store.delete(id)?;
    Ok(())
}

/// Credentials as edited in a host / group form.
struct Credentials<'a> {
    identity_id: Option<Uuid>,
    username: &'a str,
    password: Option<&'a str>,
    /// `None` keeps the stored TOTP secret, `Some("")` clears it.
    totp_secret: Option<&'a str>,
    ssh_key_id: Option<Uuid>,
    ssh_certificate_id: Option<Uuid>,
    ssh_id: bool,
    ssh_id_key_type: Option<SshIdKeyType>,
    label: &'a str,
    /// WebDAV-only secrets; `None` for SSH / Telnet logins.
    webdav: Option<WebDavCredentials<'a>>,
}

/// Token and client certificate of a WebDAV login. Each `None` keeps the
/// stored value, `Some("")` clears it.
struct WebDavCredentials<'a> {
    bearer_token: Option<&'a str>,
    client_certificate: Option<&'a str>,
    client_key: Option<&'a str>,
}

impl WebDavCredentials<'_> {
    fn resolve(
        &self,
        existing: Option<&Identity>,
    ) -> Result<(Option<String>, Option<ClientCertificate>)> {
        let token = match self.bearer_token.map(str::trim) {
            Some("") => None,
            Some(t) => Some(t.to_string()),
            None => existing.and_then(|e| e.bearer_token.clone()),
        };
        let cert = match (self.client_certificate.map(str::trim), self.client_key) {
            (Some(""), _) => None,
            (Some(c), Some(k)) => {
                let k = k.trim();
                if k.is_empty() {
                    return Err(ClientError::invalid(
                        "client certificate: a private key is required",
                    ));
                }
                termoso_core::webdav::ClientIdentity::from_pem(c, k)
                    .map_err(|e| ClientError::invalid(e.to_string()))?;
                Some(ClientCertificate {
                    certificate: c.to_string(),
                    private_key: k.to_string(),
                })
            }
            (Some(c), None) => {
                // A new certificate for the stored key (renewal).
                let Some(k) = existing
                    .and_then(|e| e.client_certificate.as_ref())
                    .map(|c| c.private_key.clone())
                else {
                    return Err(ClientError::invalid(
                        "client certificate: a private key is required",
                    ));
                };
                termoso_core::webdav::ClientIdentity::from_pem(c, &k)
                    .map_err(|e| ClientError::invalid(e.to_string()))?;
                Some(ClientCertificate {
                    certificate: c.to_string(),
                    private_key: k,
                })
            }
            (None, _) => existing.and_then(|e| e.client_certificate.clone()),
        };
        Ok((token, cert))
    }
}

/// Check a TOTP secret (`otpauth://` URI or base32) before storing it.
pub fn normalize_totp_secret(raw: &str) -> Result<String> {
    termoso_core::ssh::totp::normalize_secret(raw).map_err(|e| ClientError::invalid(e.to_string()))
}

/// Point at a visible identity, or create / update / drop the inline hidden
/// one. Returns the identity the config should reference.
fn upsert_identity(
    store: &Store,
    vault_id: Uuid,
    existing_inline: Option<&Entity<Identity>>,
    c: &Credentials<'_>,
) -> Result<Option<Uuid>> {
    if let Some(vis) = c.identity_id {
        let i = store.require::<Identity>(vis)?;
        if !i.data.is_visible {
            return Err(ClientError::invalid("identity is not selectable"));
        }
        if i.vault_id != vault_id {
            return Err(ClientError::invalid("identity belongs to another vault"));
        }
        if let Some(old) = existing_inline {
            store.delete(old.id)?;
        }
        return Ok(Some(vis));
    }
    // A certificate implies its key; picking one without a key selects that key.
    let mut ssh_key_id = c.ssh_key_id;
    if let Some(cid) = c.ssh_certificate_id {
        let cert = store.require::<SshCertificate>(cid)?;
        if cert.vault_id != vault_id {
            return Err(ClientError::invalid("certificate belongs to another vault"));
        }
        match (cert.data.ssh_key_id, ssh_key_id) {
            (Some(ck), Some(k)) if ck != k => {
                return Err(ClientError::invalid(
                    "certificate was issued for a different key",
                ));
            }
            (Some(ck), None) => ssh_key_id = Some(ck),
            _ => {}
        }
    }
    if let Some(k) = ssh_key_id {
        let key = store.require::<SshKey>(k)?;
        if key.vault_id != vault_id {
            return Err(ClientError::invalid("SSH key belongs to another vault"));
        }
    }
    let username = c.username.trim().to_string();
    let password = match (c.password, existing_inline) {
        (Some(""), _) => None,
        (Some(p), _) => Some(p.to_string()),
        (None, Some(old)) => old.data.password.clone(),
        (None, None) => None,
    };
    let totp_secret = match (c.totp_secret, existing_inline) {
        (Some(""), _) => None,
        (Some(t), _) => Some(normalize_totp_secret(t)?),
        (None, Some(old)) => old.data.totp_secret.clone(),
        (None, None) => None,
    };
    let (bearer_token, client_certificate) = match &c.webdav {
        Some(w) => w.resolve(existing_inline.map(|e| &e.data))?,
        None => (None, None),
    };
    if username.is_empty()
        && password.is_none()
        && totp_secret.is_none()
        && ssh_key_id.is_none()
        && !c.ssh_id
        && bearer_token.is_none()
        && client_certificate.is_none()
    {
        if let Some(old) = existing_inline {
            store.delete(old.id)?;
        }
        return Ok(None);
    }
    let data = Identity {
        external_id: None,
        label: c.label.to_string(),
        username,
        password,
        ssh_key_id,
        ssh_certificate_id: c.ssh_certificate_id.filter(|_| ssh_key_id.is_some()),
        is_visible: false,
        ssh_id: c.ssh_id,
        ssh_id_key_type: c.ssh_id_key_type.filter(|_| c.ssh_id),
        bearer_token,
        client_certificate,
        totp_secret,
    };
    Ok(Some(match existing_inline {
        Some(old) => {
            store.update(old.id, &data)?;
            old.id
        }
        None => store.insert(vault_id, &data)?,
    }))
}

fn clean_env(env: &[(String, String)]) -> Vec<(String, String)> {
    env.iter()
        .map(|(k, v)| (k.trim().to_string(), v.clone()))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

fn require_same_vault<T: termoso_core::model::Payload>(
    store: &Store,
    id: Option<Uuid>,
    vault_id: Uuid,
    what: &str,
) -> Result<()> {
    if let Some(id) = id {
        let e = store.require::<T>(id)?;
        if e.vault_id != vault_id {
            return Err(ClientError::invalid(format!(
                "{what} belongs to another vault"
            )));
        }
    }
    Ok(())
}

/// Ancestors of `group_id` (excluding itself), nearest first.
fn ancestors(groups: &[Entity<Group>], group_id: Uuid) -> Vec<Uuid> {
    let mut out = Vec::new();
    let mut cursor = groups
        .iter()
        .find(|g| g.id == group_id)
        .and_then(|g| g.data.parent_id);
    while let Some(gid) = cursor {
        if out.len() > 64 || out.contains(&gid) {
            break;
        }
        out.push(gid);
        cursor = groups
            .iter()
            .find(|g| g.id == gid)
            .and_then(|g| g.data.parent_id);
    }
    out
}

fn check_parent(
    store: &Store,
    vault_id: Uuid,
    id: Option<Uuid>,
    parent_id: Option<Uuid>,
) -> Result<()> {
    let Some(pid) = parent_id else {
        return Ok(());
    };
    if Some(pid) == id {
        return Err(ClientError::invalid("a group cannot be its own parent"));
    }
    let parent = store.require::<Group>(pid)?;
    if parent.vault_id != vault_id {
        return Err(ClientError::invalid(
            "parent group belongs to another vault",
        ));
    }
    if let Some(id) = id {
        let all: Vec<Entity<Group>> = store.list(Some(vault_id))?;
        if ancestors(&all, pid).contains(&id) {
            return Err(ClientError::invalid(
                "cannot move a group inside its own sub-group",
            ));
        }
    }
    Ok(())
}

fn group_node(store: &Store, vault_id: Uuid, gid: Uuid) -> Result<GroupNode> {
    groups(store, Some(vault_id))?
        .into_iter()
        .find(|g| g.id == gid)
        .ok_or_else(|| ClientError::not_found(format!("group {gid}")))
}

/// Rename / re-parent a group, keeping its SSH defaults.
pub fn save_group(
    store: &Store,
    vault_id: Uuid,
    id: Option<Uuid>,
    label: &str,
    parent_id: Option<Uuid>,
) -> Result<GroupNode> {
    let label = label.trim();
    if label.is_empty() {
        return Err(ClientError::invalid("group name is required"));
    }
    check_parent(store, vault_id, id, parent_id)?;
    let mut data = match id {
        Some(id) => store.require::<Group>(id)?.data,
        None => Group::default(),
    };
    data.label = label.to_string();
    data.parent_id = parent_id;
    let gid = match id {
        Some(id) => {
            store.update(id, &data)?;
            id
        }
        None => store.insert(vault_id, &data)?,
    };
    group_node(store, vault_id, gid)
}

/// Group as the editor sees it: name, parent and its own SSH defaults
/// (not what it inherits from parents — see [`inherited`]).
pub fn group_form(store: &Store, id: Uuid) -> Result<GroupForm> {
    let g = store.require::<Group>(id)?;
    let ssh = match g.data.ssh_config_id {
        Some(c) => store.get::<SshConfig>(c)?.map(|e| e.data),
        None => None,
    }
    .unwrap_or_default();
    let identity = match ssh.identity_id {
        Some(i) => store.get::<Identity>(i)?,
        None => None,
    };
    let (identity_id, inline) = match identity {
        Some(i) if i.data.is_visible => (Some(i.id), None),
        Some(i) => (None, Some(i.data)),
        None => (None, None),
    };
    Ok(GroupForm {
        id: Some(g.id),
        vault_id: g.vault_id,
        label: g.data.label,
        parent_id: g.data.parent_id,
        icon: g.data.icon,
        port: ssh.port,
        username: inline
            .as_ref()
            .map(|i| i.username.clone())
            .unwrap_or_default(),
        password: None,
        totp_secret: None,
        has_password: inline.as_ref().is_some_and(|i| i.password.is_some()),
        has_totp: inline.as_ref().is_some_and(|i| i.totp_secret.is_some()),
        ssh_key_id: inline.as_ref().and_then(|i| i.ssh_key_id),
        ssh_certificate_id: inline.as_ref().and_then(|i| i.ssh_certificate_id),
        identity_id,
        ssh_id: inline.as_ref().is_some_and(|i| i.ssh_id),
        ssh_id_key_type: inline.as_ref().and_then(|i| i.ssh_id_key_type),
        agent_forwarding: ssh.agent_forwarding,
        forward_x11: ssh.forward_x11,
        host_chain_id: ssh.host_chain_id,
        proxy_id: ssh.proxy_id,
        env_variables: ssh.env_variables,
        keep_alive_interval: ssh.keep_alive_interval,
        timeout: ssh.timeout,
    })
}

/// Create or update a group together with the SSH defaults its hosts inherit.
pub fn save_group_form(store: &Store, f: &GroupForm) -> Result<GroupNode> {
    let label = f.label.trim();
    if label.is_empty() {
        return Err(ClientError::invalid("group name is required"));
    }
    check_parent(store, f.vault_id, f.id, f.parent_id)?;
    require_same_vault::<HostChain>(store, f.host_chain_id, f.vault_id, "host chain")?;
    require_same_vault::<Proxy>(store, f.proxy_id, f.vault_id, "proxy")?;

    let existing = match f.id {
        Some(id) => store.get::<Group>(id)?,
        None => None,
    };
    let existing_ssh = match existing.as_ref().and_then(|g| g.data.ssh_config_id) {
        Some(c) => store.get::<SshConfig>(c)?,
        None => None,
    };
    let existing_inline = match existing_ssh.as_ref().and_then(|s| s.data.identity_id) {
        Some(i) => store.get::<Identity>(i)?.filter(|e| !e.data.is_visible),
        None => None,
    };
    let identity_id = upsert_identity(
        store,
        f.vault_id,
        existing_inline.as_ref(),
        &Credentials {
            identity_id: f.identity_id,
            username: &f.username,
            password: f.password.as_deref(),
            totp_secret: f.totp_secret.as_deref(),
            ssh_key_id: f.ssh_key_id,
            ssh_certificate_id: f.ssh_certificate_id,
            ssh_id: f.ssh_id,
            ssh_id_key_type: f.ssh_id_key_type,
            label,
            webdav: None,
        },
    )?;

    let mut ssh = existing_ssh
        .as_ref()
        .map(|e| e.data.clone())
        .unwrap_or_default();
    ssh.port = f.port.filter(|p| *p != 0);
    ssh.identity_id = identity_id;
    ssh.agent_forwarding = f.agent_forwarding;
    ssh.forward_x11 = f.forward_x11;
    ssh.host_chain_id = f.host_chain_id;
    ssh.proxy_id = f.proxy_id;
    ssh.env_variables = clean_env(&f.env_variables);
    ssh.keep_alive_interval = f.keep_alive_interval.filter(|s| *s > 0);
    ssh.timeout = f.timeout.filter(|s| *s > 0);
    let empty = ssh == SshConfig::default();
    let ssh_config_id = match (&existing_ssh, empty) {
        (Some(e), true) => {
            store.delete(e.id)?;
            None
        }
        (Some(e), false) => {
            store.update(e.id, &ssh)?;
            Some(e.id)
        }
        (None, true) => None,
        (None, false) => Some(store.insert(f.vault_id, &ssh)?),
    };

    let mut data = existing
        .as_ref()
        .map(|e| e.data.clone())
        .unwrap_or_default();
    data.label = label.to_string();
    data.parent_id = f.parent_id;
    data.icon = clean_icon(&f.icon)?;
    data.ssh_config_id = ssh_config_id;
    let gid = match &existing {
        Some(e) => {
            store.update(e.id, &data)?;
            e.id
        }
        None => store.insert(f.vault_id, &data)?,
    };
    group_node(store, f.vault_id, gid)
}

/// Delete a group; its hosts and sub-groups move to the parent.
pub fn delete_group(store: &Store, id: Uuid) -> Result<()> {
    let Some(g) = store.get::<Group>(id)? else {
        return Ok(());
    };
    let hosts: Vec<Entity<Host>> = store.list(Some(g.vault_id))?;
    for mut h in hosts.into_iter().filter(|h| h.data.group_id == Some(id)) {
        h.data.group_id = g.data.parent_id;
        store.update(h.id, &h.data)?;
    }
    let groups: Vec<Entity<Group>> = store.list(Some(g.vault_id))?;
    for mut c in groups.into_iter().filter(|c| c.data.parent_id == Some(id)) {
        c.data.parent_id = g.data.parent_id;
        store.update(c.id, &c.data)?;
    }
    if let Some(cid) = g.data.ssh_config_id
        && let Some(cfg) = store.get::<SshConfig>(cid)?
    {
        if let Some(iid) = cfg.data.identity_id
            && let Some(i) = store.get::<Identity>(iid)?
            && !i.data.is_visible
        {
            store.delete(i.id)?;
        }
        store.delete(cfg.id)?;
    }
    store.delete(id)?;
    Ok(())
}

/// Delete a group with everything inside it (hosts and sub-groups).
pub fn delete_group_recursive(store: &Store, id: Uuid) -> Result<()> {
    let Some(g) = store.get::<Group>(id)? else {
        return Ok(());
    };
    let groups: Vec<Entity<Group>> = store.list(Some(g.vault_id))?;
    for c in groups.iter().filter(|c| c.data.parent_id == Some(id)) {
        delete_group_recursive(store, c.id)?;
    }
    let hosts: Vec<Entity<Host>> = store.list(Some(g.vault_id))?;
    for h in hosts.iter().filter(|h| h.data.group_id == Some(id)) {
        delete(store, h.id)?;
    }
    delete_group(store, id)
}

/// What hosts inside `group_id` inherit.
pub fn inherited(store: &Store, group_id: Option<Uuid>) -> Result<Inherited> {
    let Some(gid) = group_id else {
        return Ok(Inherited::default());
    };
    let (ssh, group_path) = store.resolve_group_ssh(gid)?;
    let identity = match ssh.identity_id {
        Some(i) => store.get::<Identity>(i)?,
        None => None,
    };
    let key_id = identity.as_ref().and_then(|i| i.data.ssh_key_id);
    let key_label = match key_id {
        Some(k) => store.get::<SshKey>(k)?.map(|k| k.data.label),
        None => None,
    };
    let (identity_id, identity_label) = match &identity {
        Some(i) if i.data.is_visible => (Some(i.id), Some(i.data.label.clone())),
        _ => (None, None),
    };
    Ok(Inherited {
        group_path,
        port: ssh.port,
        username: identity
            .as_ref()
            .map(|i| i.data.username.clone())
            .filter(|u| !u.is_empty()),
        has_password: identity.as_ref().is_some_and(|i| i.data.password.is_some()),
        has_totp: identity
            .as_ref()
            .is_some_and(|i| i.data.totp_secret.is_some()),
        ssh_key_id: key_id,
        ssh_key_label: key_label,
        identity_id,
        identity_label,
        ssh_id: identity.as_ref().is_some_and(|i| i.data.ssh_id),
        agent_forwarding: ssh.agent_forwarding,
        forward_x11: ssh.forward_x11,
        host_chain_id: ssh.host_chain_id,
        proxy_id: ssh.proxy_id,
        keep_alive_interval: ssh.keep_alive_interval,
        timeout: ssh.timeout,
        env_variables: ssh.env_variables,
    })
}

fn copy_label(label: &str) -> String {
    format!("{label} copy")
}

/// Ids of the referenced entities that exist in `vault_id`; the rest are
/// dropped so a copy never points at another vault's data.
fn keep_if_in_vault<T: termoso_core::model::Payload>(
    store: &Store,
    id: Option<Uuid>,
    vault_id: Uuid,
) -> Result<Option<Uuid>> {
    Ok(match id {
        Some(id) => store
            .get::<T>(id)?
            .filter(|e| e.vault_id == vault_id)
            .map(|e| e.id),
        None => None,
    })
}

/// Tags of the source host recreated (by label) in the target vault.
fn tags_in_vault(store: &Store, tag_ids: &[Uuid], vault_id: Uuid) -> Result<Vec<Uuid>> {
    let mut out = Vec::new();
    let mut existing: Vec<Entity<Tag>> = store.list(Some(vault_id))?;
    for tid in tag_ids {
        let Some(src) = store.get::<Tag>(*tid)? else {
            continue;
        };
        if src.vault_id == vault_id {
            out.push(src.id);
            continue;
        }
        let id = match existing
            .iter()
            .find(|t| t.data.label.eq_ignore_ascii_case(&src.data.label))
        {
            Some(t) => t.id,
            None => {
                let id = store.insert(vault_id, &src.data)?;
                existing.push(Entity {
                    id,
                    vault_id,
                    version: 0,
                    updated_at: Utc::now(),
                    dirty: false,
                    data: src.data.clone(),
                });
                id
            }
        };
        out.push(id);
    }
    Ok(out)
}

/// Copy a host (with its inline SSH / Telnet config and hidden identity) into
/// `vault_id` / `group_id`. Shared references (visible identity, key, chain,
/// proxy, snippet) are kept only when they live in the target vault; a visible
/// identity from another vault is flattened into an inline copy.
/// What travels with a host copied into another vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyCredentials {
    /// Username, password and key go along; keys missing from the target
    /// vault are copied there too (`copied_keys` dedupes across a batch).
    Shared,
    /// Address, settings and tags only — everyone supplies their own login.
    Personal,
}

fn copy_host(
    store: &Store,
    id: Uuid,
    vault_id: Uuid,
    group_id: Option<Uuid>,
    label: Option<String>,
) -> Result<Uuid> {
    copy_host_with(
        store,
        id,
        vault_id,
        group_id,
        label,
        CopyCredentials::Shared,
        &mut HashMap::new(),
    )
}

fn copy_host_with(
    store: &Store,
    id: Uuid,
    vault_id: Uuid,
    group_id: Option<Uuid>,
    label: Option<String>,
    creds: CopyCredentials,
    copied_keys: &mut HashMap<Uuid, Uuid>,
) -> Result<Uuid> {
    let src = store.require::<Host>(id)?;
    let mut f = form(store, id)?;
    let same_vault = src.vault_id == vault_id;
    f.id = None;
    f.vault_id = vault_id;
    f.group_id = group_id;
    f.label = label.unwrap_or_else(|| src.data.label.clone());
    f.password = None;

    // Inline credentials: read the stored identities so the passwords travel.
    let ssh = match src.data.ssh_config_id {
        Some(c) => store.get::<SshConfig>(c)?.map(|e| e.data),
        None => None,
    };
    let telnet = match src.data.telnet_config_id {
        Some(c) => store.get::<TelnetConfig>(c)?.map(|e| e.data),
        None => None,
    };
    let webdav = match src.data.webdav_config_id {
        Some(c) => store.get::<WebDavConfig>(c)?.map(|e| e.data),
        None => None,
    };
    if let Some(i) = load_identity(store, ssh.as_ref().and_then(|s| s.identity_id))? {
        if i.data.is_visible && i.vault_id == vault_id {
            f.identity_id = Some(i.id);
        } else if i.data.is_visible && creds == CopyCredentials::Shared {
            // A shared identity travels as a shared identity (its key too).
            let copied = keychain::copy_identity_to_vault(store, i.id, vault_id, false)?;
            if let (Some(src), Some(dst)) = (i.data.ssh_key_id, copied.ssh_key_id) {
                copied_keys.insert(src, dst);
            }
            f.identity_id = Some(copied.id);
        } else {
            f.identity_id = None;
            f.username = i.data.username.clone();
            f.password = i.data.password.clone();
            f.ssh_key_id = i.data.ssh_key_id;
            f.ssh_id = i.data.ssh_id;
            f.ssh_id_key_type = i.data.ssh_id_key_type;
        }
    }
    if let Some(tf) = f.telnet.as_mut()
        && let Some(i) = load_identity(store, telnet.as_ref().and_then(|t| t.identity_id))?
    {
        if i.data.is_visible && i.vault_id == vault_id {
            tf.identity_id = Some(i.id);
        } else {
            tf.identity_id = None;
            tf.username = i.data.username.clone();
            tf.password = i.data.password.clone();
        }
    }
    if let Some(wf) = f.webdav.as_mut()
        && let Some(i) = load_identity(store, webdav.as_ref().and_then(|w| w.identity_id))?
    {
        if i.data.is_visible && i.vault_id == vault_id {
            wf.identity_id = Some(i.id);
        } else {
            wf.identity_id = None;
            wf.username = i.data.username.clone();
            wf.password = i.data.password.clone();
        }
    }
    if creds == CopyCredentials::Personal {
        f.username = String::new();
        f.password = None;
        f.ssh_key_id = None;
        f.identity_id = None;
        f.ssh_id = false;
        f.ssh_id_key_type = None;
        if let Some(tf) = f.telnet.as_mut() {
            tf.username = String::new();
            tf.password = None;
            tf.identity_id = None;
        }
        if let Some(wf) = f.webdav.as_mut() {
            wf.username = String::new();
            wf.password = None;
            wf.identity_id = None;
        }
    }
    if !same_vault {
        f.ssh_key_id = match f.ssh_key_id {
            Some(kid) if creds == CopyCredentials::Shared => Some(
                match keep_if_in_vault::<SshKey>(store, Some(kid), vault_id)? {
                    Some(k) => k,
                    None => match copied_keys.get(&kid) {
                        Some(k) => *k,
                        None => {
                            let k = keychain::copy_to_vault(store, kid, vault_id, false)?.id;
                            copied_keys.insert(kid, k);
                            k
                        }
                    },
                },
            ),
            other => keep_if_in_vault::<SshKey>(store, other, vault_id)?,
        };
        f.host_chain_id = keep_if_in_vault::<HostChain>(store, f.host_chain_id, vault_id)?;
        f.proxy_id = keep_if_in_vault::<Proxy>(store, f.proxy_id, vault_id)?;
        f.startup_snippet_id = keep_if_in_vault::<Snippet>(store, f.startup_snippet_id, vault_id)?;
        f.tag_ids = tags_in_vault(store, &f.tag_ids, vault_id)?;
    }
    let card = save(store, &f)?;
    // Fields the form does not carry (charset, mosh, colours…) travel raw.
    if let Some(mut s) = ssh.filter(|_| f.ssh)
        && let Some(cid) = store.require::<Host>(card.id)?.data.ssh_config_id
        && let Some(saved) = store.get::<SshConfig>(cid)?
    {
        s.identity_id = saved.data.identity_id;
        s.host_chain_id = saved.data.host_chain_id;
        s.proxy_id = saved.data.proxy_id;
        if !same_vault {
            s.port_knocking_id = None;
        }
        store.update(cid, &s)?;
    }
    Ok(card.id)
}

fn load_identity(store: &Store, id: Option<Uuid>) -> Result<Option<Entity<Identity>>> {
    Ok(match id {
        Some(i) => store.get::<Identity>(i)?,
        None => None,
    })
}

/// Duplicate a host next to the original ("<label> copy").
pub fn duplicate(store: &Store, id: Uuid) -> Result<HostCard> {
    let src = store.require::<Host>(id)?;
    let new_id = copy_host(
        store,
        id,
        src.vault_id,
        src.data.group_id,
        Some(copy_label(&src.data.label)),
    )?;
    cards(store, Some(src.vault_id))?
        .into_iter()
        .find(|c| c.id == new_id)
        .ok_or_else(|| ClientError::not_found(format!("host {new_id}")))
}

/// Move hosts into a group (or to the top level) of the same vault.
pub fn move_hosts(store: &Store, ids: &[Uuid], group_id: Option<Uuid>) -> Result<()> {
    let group = match group_id {
        Some(g) => Some(store.require::<Group>(g)?),
        None => None,
    };
    for id in ids {
        let mut h = store.require::<Host>(*id)?;
        if let Some(g) = &group
            && g.vault_id != h.vault_id
        {
            return Err(ClientError::invalid("group belongs to another vault"));
        }
        if h.data.group_id != group_id {
            h.data.group_id = group_id;
            store.update(h.id, &h.data)?;
        }
    }
    Ok(())
}

/// Copy hosts into another vault (top level of that vault). Returns new ids.
pub fn copy_to_vault(
    store: &Store,
    ids: &[Uuid],
    vault_id: Uuid,
    creds: CopyCredentials,
) -> Result<Vec<Uuid>> {
    let vault = store.vault(vault_id)?;
    if !vault.unlocked {
        return Err(ClientError::invalid("target vault is locked"));
    }
    if !vault.role.can_write() {
        return Err(ClientError::invalid("you can only view this vault"));
    }
    let mut copied_keys = HashMap::new();
    ids.iter()
        .map(|id| copy_host_with(store, *id, vault_id, None, None, creds, &mut copied_keys))
        .collect()
}

/// Move hosts into another vault: copy, then delete the originals.
pub fn move_to_vault(
    store: &Store,
    ids: &[Uuid],
    vault_id: Uuid,
    creds: CopyCredentials,
) -> Result<Vec<Uuid>> {
    let new_ids = copy_to_vault(store, ids, vault_id, creds)?;
    for id in ids {
        delete(store, *id)?;
    }
    Ok(new_ids)
}

/// Deep-copy a group (SSH defaults, sub-groups and hosts) next to the original.
pub fn duplicate_group(store: &Store, id: Uuid) -> Result<GroupNode> {
    let src = store.require::<Group>(id)?;
    let new_id = copy_group_tree(
        store,
        id,
        src.data.parent_id,
        Some(copy_label(&src.data.label)),
    )?;
    group_node(store, src.vault_id, new_id)
}

fn copy_group_tree(
    store: &Store,
    id: Uuid,
    parent_id: Option<Uuid>,
    label: Option<String>,
) -> Result<Uuid> {
    let src = store.require::<Group>(id)?;
    let mut f = group_form(store, id)?;
    f.id = None;
    f.parent_id = parent_id;
    if let Some(l) = label {
        f.label = l;
    }
    if f.identity_id.is_none()
        && let Some(cid) = src.data.ssh_config_id
        && let Some(cfg) = store.get::<SshConfig>(cid)?
        && let Some(iid) = cfg.data.identity_id
        && let Some(i) = store.get::<Identity>(iid)?
    {
        f.password = i.data.password.clone();
    }
    let new_id = save_group_form(store, &f)?.id;
    let hosts: Vec<Entity<Host>> = store.list(Some(src.vault_id))?;
    for h in hosts.iter().filter(|h| h.data.group_id == Some(id)) {
        copy_host(store, h.id, src.vault_id, Some(new_id), None)?;
    }
    let groups: Vec<Entity<Group>> = store.list(Some(src.vault_id))?;
    for g in groups.iter().filter(|g| g.data.parent_id == Some(id)) {
        copy_group_tree(store, g.id, Some(new_id), None)?;
    }
    Ok(new_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoso_core::termoso_crypto::keys::SymmetricKey;

    fn store() -> Store {
        Store::open_in_memory(SymmetricKey::generate()).expect("store")
    }

    fn new_form(vault_id: Uuid) -> HostForm {
        HostForm {
            charset: None,
            backspace: None,
            id: None,
            vault_id,
            label: "prod".into(),
            address: "10.0.0.1".into(),
            group_id: None,
            ssh: true,
            port: Some(2222),
            username: "deploy".into(),
            password: Some("s3cret".into()),
            ssh_key_id: None,
            ssh_certificate_id: None,
            identity_id: None,
            ssh_id: false,
            ssh_id_key_type: None,
            use_mosh: false,
            mosh_server_command: None,
            tag_ids: vec![],
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
            env_variables: vec![],
            keep_alive_interval: None,
            timeout: None,
            color_scheme: None,
            has_password: false,
            has_totp: false,
            files_provider: false,
            shell_integration: None,
            totp_secret: None,
        }
    }

    #[test]
    fn shell_integration_override_round_trips_and_defaults_to_follow() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let card = save(&s, &new_form(vault)).unwrap();
        assert_eq!(form(&s, card.id).unwrap().shell_integration, None);

        let mut f = form(&s, card.id).unwrap();
        f.shell_integration = Some(false);
        save(&s, &f).unwrap();
        assert_eq!(form(&s, card.id).unwrap().shell_integration, Some(false));

        // Hosts serialized before the field existed follow the setting, and
        // a host that follows it does not carry the key.
        let stored = s.require::<Host>(card.id).unwrap();
        let mut json = serde_json::to_value(&stored.data).unwrap();
        assert_eq!(json["shell_integration"], serde_json::Value::Bool(false));
        json.as_object_mut().unwrap().remove("shell_integration");
        let legacy: Host = serde_json::from_value(json).unwrap();
        assert_eq!(legacy.shell_integration, None);
        assert!(
            !serde_json::to_string(&legacy)
                .unwrap()
                .contains("shell_integration")
        );
    }

    #[test]
    fn files_provider_round_trips_and_defaults_off() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let card = save(&s, &new_form(vault)).unwrap();
        assert!(!card.files_provider);

        let mut f = form(&s, card.id).unwrap();
        f.files_provider = true;
        let card = save(&s, &f).unwrap();
        assert!(card.files_provider);
        assert!(form(&s, card.id).unwrap().files_provider);

        // Hosts serialized before the field existed deserialize as hidden.
        let stored = s.require::<Host>(card.id).unwrap();
        let mut json = serde_json::to_value(&stored.data).unwrap();
        assert_eq!(json["files_provider"], serde_json::Value::Bool(true));
        json.as_object_mut().unwrap().remove("files_provider");
        let legacy: Host = serde_json::from_value(json).unwrap();
        assert!(!legacy.files_provider);
        assert!(
            !serde_json::to_string(&legacy)
                .unwrap()
                .contains("files_provider")
        );
    }

    #[test]
    fn save_creates_inline_config_and_identity() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let card = save(&s, &new_form(vault)).unwrap();
        assert_eq!(card.username, "deploy");
        assert_eq!(card.port, 2222);
        assert_eq!(card.protocol, "ssh");

        let f = form(&s, card.id).unwrap();
        assert!(f.has_password);
        assert!(f.password.is_none());
        assert_eq!(f.username, "deploy");

        let identities: Vec<Entity<Identity>> = s.list(Some(vault)).unwrap();
        assert_eq!(identities.len(), 1);
        assert!(!identities[0].data.is_visible);
    }

    #[test]
    fn edit_keeps_password_unless_cleared() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let card = save(&s, &new_form(vault)).unwrap();
        let mut f = form(&s, card.id).unwrap();
        f.username = "ops".into();
        save(&s, &f).unwrap();
        let r = s.resolve_host(card.id).unwrap();
        assert_eq!(r.identity.unwrap().data.password.as_deref(), Some("s3cret"));

        f.password = Some(String::new());
        save(&s, &f).unwrap();
        let r = s.resolve_host(card.id).unwrap();
        assert_eq!(r.identity.unwrap().data.password, None);
    }

    #[test]
    fn group_inheritance_shows_in_card() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let cfg_id = s
            .insert(
                vault,
                &SshConfig {
                    port: Some(2200),
                    ..Default::default()
                },
            )
            .unwrap();
        let g = save_group(&s, vault, None, "dc1", None).unwrap();
        let mut gdata = s.require::<Group>(g.id).unwrap().data;
        gdata.ssh_config_id = Some(cfg_id);
        s.update(g.id, &gdata).unwrap();

        let mut f = new_form(vault);
        f.group_id = Some(g.id);
        f.port = None;
        let card = save(&s, &f).unwrap();
        assert_eq!(card.port, 2200);
        assert_eq!(card.group_path, vec!["dc1".to_string()]);
        assert_eq!(groups(&s, Some(vault)).unwrap()[0].host_count, 1);

        delete_group(&s, g.id).unwrap();
        let card = cards(&s, Some(vault)).unwrap().remove(0);
        assert_eq!(card.group_id, None);
        assert_eq!(card.port, 22);
    }

    #[test]
    fn advanced_ssh_fields_round_trip() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let mut f = new_form(vault);
        f.env_variables = vec![
            ("TERM".into(), "xterm".into()),
            ("  ".into(), "dropped".into()),
        ];
        f.keep_alive_interval = Some(30);
        f.timeout = Some(0);
        let card = save(&s, &f).unwrap();
        let f = form(&s, card.id).unwrap();
        assert_eq!(
            f.env_variables,
            vec![("TERM".to_string(), "xterm".to_string())]
        );
        assert_eq!(f.keep_alive_interval, Some(30));
        assert_eq!(f.timeout, None);
        assert!(f.ssh);
        assert!(f.telnet.is_none());
    }

    #[test]
    fn telnet_section_lives_next_to_ssh() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let mut f = new_form(vault);
        f.telnet = Some(TelnetForm {
            port: None,
            username: "admin".into(),
            password: Some("tel".into()),
            ..TelnetForm::default()
        });
        let card = save(&s, &f).unwrap();
        assert_eq!(card.protocol, "ssh");
        assert_eq!(card.port, 2222);
        assert_eq!(card.username, "deploy");
        assert_eq!(card.telnet_port, Some(23));
        let identities: Vec<Entity<Identity>> = s.list(Some(vault)).unwrap();
        assert_eq!(identities.len(), 2, "one hidden identity per section");

        let f = form(&s, card.id).unwrap();
        assert!(f.ssh);
        let t = f.telnet.clone().expect("telnet section");
        assert_eq!(t.username, "admin");
        assert!(t.has_password);
        assert!(t.password.is_none());
        let r = s.resolve_host(card.id).unwrap();
        assert_eq!(r.protocol(), "ssh");
        assert!(r.telnet.is_some());

        // Removing the Telnet section drops its config and hidden identity.
        let mut f = f;
        f.telnet = None;
        let card = save(&s, &f).unwrap();
        assert_eq!(card.telnet_port, None);
        let telnets: Vec<Entity<TelnetConfig>> = s.list(Some(vault)).unwrap();
        assert!(telnets.is_empty());
        let identities: Vec<Entity<Identity>> = s.list(Some(vault)).unwrap();
        assert_eq!(identities.len(), 1);
    }

    #[test]
    fn telnet_only_hosts_resolve_as_telnet() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let mut f = new_form(vault);
        f.ssh = false;
        f.telnet = Some(TelnetForm {
            port: Some(2323),
            username: "admin".into(),
            ..TelnetForm::default()
        });
        let card = save(&s, &f).unwrap();
        assert_eq!(card.protocol, "telnet");
        assert_eq!(card.port, 2323);
        assert_eq!(card.telnet_port, Some(2323));
        assert_eq!(card.username, "admin");
        let sshs: Vec<Entity<SshConfig>> = s.list(Some(vault)).unwrap();
        assert!(sshs.is_empty());
        let identities: Vec<Entity<Identity>> = s.list(Some(vault)).unwrap();
        assert_eq!(identities.len(), 1, "the SSH login is not kept");

        let mut f = form(&s, card.id).unwrap();
        assert!(!f.ssh);
        assert_eq!(f.username, "");
        // Adding SSH back makes it the primary protocol again.
        f.ssh = true;
        f.username = "deploy".into();
        let card = save(&s, &f).unwrap();
        assert_eq!(card.protocol, "ssh");
        assert_eq!(card.port, 22);
        assert_eq!(card.username, "deploy");
        assert_eq!(card.telnet_port, Some(2323));

        // A host needs at least one section.
        f.ssh = false;
        f.telnet = None;
        assert!(save(&s, &f).is_err());
        delete(&s, card.id).unwrap();
        let telnets: Vec<Entity<TelnetConfig>> = s.list(Some(vault)).unwrap();
        assert!(telnets.is_empty());
    }

    #[test]
    fn webdav_section_lives_next_to_ssh() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let mut f = new_form(vault);
        f.webdav = Some(WebDavForm {
            path: "remote.php/dav/files/alice".into(),
            username: "alice".into(),
            password: Some("dav".into()),
            certificate_fingerprint: Some(
                "D6DCE0382A45B8F81F063B705DA84C3C232FEA47D23B6FD02B5A9ACD33F73D8A".into(),
            ),
            ..WebDavForm::default()
        });
        let card = save(&s, &f).unwrap();
        assert_eq!(card.protocol, "ssh");
        assert_eq!(card.username, "deploy");
        assert_eq!(
            card.webdav_url.as_deref(),
            Some("https://10.0.0.1/remote.php/dav/files/alice/")
        );
        let identities: Vec<Entity<Identity>> = s.list(Some(vault)).unwrap();
        assert_eq!(identities.len(), 2, "one hidden identity per section");

        let f = form(&s, card.id).unwrap();
        let w = f.webdav.clone().expect("webdav section");
        assert_eq!(w.username, "alice");
        assert!(w.has_password);
        assert!(w.password.is_none());
        assert_eq!(
            w.certificate_fingerprint.as_deref(),
            Some(
                "d6:dc:e0:38:2a:45:b8:f8:1f:06:3b:70:5d:a8:4c:3c:23:2f:ea:47:d2:3b:6f:d0:2b:5a:9a:cd:33:f7:3d:8a"
            )
        );
        let r = s.resolve_host(card.id).unwrap();
        assert_eq!(r.protocol(), "ssh");
        assert_eq!(
            r.webdav_identity.as_ref().unwrap().data.password.as_deref(),
            Some("dav")
        );

        // Removing the section drops its config and hidden identity.
        let mut f = f;
        f.webdav = None;
        let card = save(&s, &f).unwrap();
        assert_eq!(card.webdav_url, None);
        let davs: Vec<Entity<WebDavConfig>> = s.list(Some(vault)).unwrap();
        assert!(davs.is_empty());
        let identities: Vec<Entity<Identity>> = s.list(Some(vault)).unwrap();
        assert_eq!(identities.len(), 1);
    }

    #[test]
    fn webdav_only_hosts_take_the_address_from_the_url() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let mut f = new_form(vault);
        f.ssh = false;
        f.address = "nas.local".into();
        f.webdav = Some(WebDavForm {
            port: Some(8080),
            path: "dav".into(),
            http: true,
            username: "nas".into(),
            ..WebDavForm::default()
        });
        let card = save(&s, &f).unwrap();
        assert_eq!(card.protocol, "webdav");
        assert_eq!(card.address, "nas.local");
        assert_eq!(card.port, 8080);
        assert_eq!(
            card.webdav_url.as_deref(),
            Some("http://nas.local:8080/dav/")
        );
        assert_eq!(card.username, "nas");
        assert!(!card.use_mosh);
        let identities: Vec<Entity<Identity>> = s.list(Some(vault)).unwrap();
        assert_eq!(identities.len(), 1, "the SSH login is not kept");
        let r = s.resolve_host(card.id).unwrap();
        assert_eq!(r.protocol(), "webdav");

        let mut f = form(&s, card.id).unwrap();
        assert!(!f.ssh);
        assert!(f.telnet.is_none());
        let mut bad = f.clone();
        bad.webdav.as_mut().unwrap().port = Some(0);
        assert!(save(&s, &bad).is_err());
        bad.webdav.as_mut().unwrap().port = None;
        bad.webdav.as_mut().unwrap().certificate_fingerprint = Some("zz".into());
        assert!(save(&s, &bad).is_err());
        bad.webdav.as_mut().unwrap().certificate_fingerprint = None;
        bad.webdav.as_mut().unwrap().http = false;
        bad.webdav.as_mut().unwrap().tls_server_name = Some("not a name!".into());
        assert!(save(&s, &bad).is_err());
        bad.webdav.as_mut().unwrap().tls_server_name = None;
        bad.webdav.as_mut().unwrap().ca_certificate = Some("not pem".into());
        assert!(save(&s, &bad).is_err());
        bad.address = String::new();
        bad.webdav.as_mut().unwrap().ca_certificate = None;
        assert!(save(&s, &bad).is_err(), "the address is the share's host");

        // Adding SSH back makes it the primary protocol again.
        f.ssh = true;
        f.username = "deploy".into();
        let card = save(&s, &f).unwrap();
        assert_eq!(card.protocol, "ssh");
        assert_eq!(card.port, 22);
        assert!(card.webdav_url.is_some());

        delete(&s, card.id).unwrap();
        let davs: Vec<Entity<WebDavConfig>> = s.list(Some(vault)).unwrap();
        assert!(davs.is_empty());
        let identities: Vec<Entity<Identity>> = s.list(Some(vault)).unwrap();
        assert!(identities.is_empty());
    }

    #[test]
    fn duplicate_keeps_webdav_credentials() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let mut f = new_form(vault);
        f.webdav = Some(WebDavForm {
            path: "/dav/".into(),
            username: "alice".into(),
            password: Some("dav".into()),
            ..WebDavForm::default()
        });
        let card = save(&s, &f).unwrap();
        let copy = duplicate(&s, card.id).unwrap();
        assert_ne!(copy.id, card.id);
        let r = s.resolve_host(copy.id).unwrap();
        let w = r.webdav.expect("webdav travels");
        assert_eq!(w.path, "/dav/");
        let i = r.webdav_identity.expect("identity travels");
        assert_eq!(i.data.username, "alice");
        assert_eq!(i.data.password.as_deref(), Some("dav"));
        assert_ne!(
            i.id,
            s.resolve_host(card.id).unwrap().webdav_identity.unwrap().id
        );
    }

    #[test]
    fn webdav_token_and_client_certificate_live_in_the_identity() {
        const CERT: &str = include_str!("../../termoso-core/tests/fixtures/webdav-client.crt.pem");
        const KEY: &str = include_str!("../../termoso-core/tests/fixtures/webdav-client.key.pem");
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let mut f = new_form(vault);
        f.ssh = false;
        f.webdav = Some(WebDavForm {
            path: "/dav/".into(),
            auth: WEBDAV_AUTH_TOKEN.into(),
            bearer_token: Some(" tok-123 ".into()),
            client_certificate: Some(CERT.into()),
            client_key: Some(KEY.into()),
            ..WebDavForm::default()
        });
        let card = save(&s, &f).unwrap();
        let ident = s.resolve_host(card.id).unwrap().webdav_identity.unwrap();
        assert_eq!(ident.data.bearer_token.as_deref(), Some("tok-123"));
        assert_eq!(ident.data.username, "");
        let cert = ident.data.client_certificate.clone().unwrap();
        assert_eq!(cert.certificate, CERT.trim());
        assert_eq!(cert.private_key, KEY.trim());
        let cfg_id = s
            .require::<Host>(card.id)
            .unwrap()
            .data
            .webdav_config_id
            .unwrap();
        let cfg = s.require::<WebDavConfig>(cfg_id).unwrap().data;
        assert_eq!(cfg.identity_id, Some(ident.id));
        let cfg_json = serde_json::to_string(&cfg).unwrap();
        assert!(!cfg_json.contains("tok-123") && !cfg_json.contains("PRIVATE KEY"));

        // The form reports presence only; `None` keeps both secrets.
        let f = form(&s, card.id).unwrap();
        let w = f.webdav.clone().unwrap();
        assert_eq!(w.auth, WEBDAV_AUTH_TOKEN);
        assert!(w.has_bearer_token);
        assert!(w.bearer_token.is_none());
        assert!(w.client_certificate.is_none() && w.client_key.is_none());
        assert!(w.client_certificate_fingerprint.is_some());
        save(&s, &f).unwrap();
        let ident = s.resolve_host(card.id).unwrap().webdav_identity.unwrap();
        assert_eq!(ident.data.bearer_token.as_deref(), Some("tok-123"));
        assert!(ident.data.client_certificate.is_some());

        // Garbage PEM and a certificate without a key are rejected up front.
        let mut bad = f.clone();
        bad.webdav.as_mut().unwrap().client_certificate = Some("not pem".into());
        bad.webdav.as_mut().unwrap().client_key = Some(KEY.into());
        assert!(save(&s, &bad).is_err());
        let mut fresh = new_form(vault);
        fresh.address = "10.0.0.9".into();
        fresh.webdav = Some(WebDavForm {
            path: "/".into(),
            client_certificate: Some(CERT.into()),
            ..WebDavForm::default()
        });
        assert!(save(&s, &fresh).is_err());

        // Switching back to password auth drops the token; an empty
        // certificate clears the pair.
        let mut f = form(&s, card.id).unwrap();
        {
            let w = f.webdav.as_mut().unwrap();
            w.auth = WEBDAV_AUTH_PASSWORD.into();
            w.username = "alice".into();
            w.password = Some("pw".into());
            w.client_certificate = Some(String::new());
        }
        save(&s, &f).unwrap();
        let ident = s.resolve_host(card.id).unwrap().webdav_identity.unwrap();
        assert_eq!(ident.data.bearer_token, None);
        assert_eq!(ident.data.client_certificate, None);
        assert_eq!(ident.data.username, "alice");
        assert_eq!(ident.data.password.as_deref(), Some("pw"));
        let f = form(&s, card.id).unwrap();
        assert_eq!(f.webdav.unwrap().auth, WEBDAV_AUTH_PASSWORD);
    }

    #[test]
    fn icon_and_ip_version_round_trip() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let mut f = new_form(vault);
        f.icon = Some("debian".into());
        f.ip_version = "6".into();
        let card = save(&s, &f).unwrap();
        assert_eq!(card.icon.as_deref(), Some("debian"));
        assert_eq!(card.ip_version, "6");
        let stored = s.require::<Host>(card.id).unwrap().data;
        assert_eq!(stored.ip_version, "6");

        let mut f = form(&s, card.id).unwrap();
        f.icon = Some("auto".into());
        f.ip_version = "auto".into();
        let card = save(&s, &f).unwrap();
        assert_eq!(card.icon, None);
        assert_eq!(card.ip_version, "auto");
        assert_eq!(s.require::<Host>(card.id).unwrap().data.ip_version, "");
    }

    #[test]
    fn tags_rename_merge_and_delete() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let prod = s
            .insert(
                vault,
                &Tag {
                    label: "prod".into(),
                    color: None,
                },
            )
            .unwrap();
        let production = s
            .insert(
                vault,
                &Tag {
                    label: "Production".into(),
                    color: Some("#10b981".into()),
                },
            )
            .unwrap();
        let db = s
            .insert(
                vault,
                &Tag {
                    label: "db".into(),
                    color: None,
                },
            )
            .unwrap();
        let mut f = new_form(vault);
        f.tag_ids = vec![prod, db];
        let a = save(&s, &f).unwrap();
        let mut f = new_form(vault);
        f.address = "10.0.0.2".into();
        f.tag_ids = vec![prod, production];
        let b = save(&s, &f).unwrap();

        let list = tags(&s, Some(vault)).unwrap();
        assert_eq!(list.iter().find(|t| t.id == prod).unwrap().hosts, 2);
        assert_eq!(list.iter().find(|t| t.id == db).unwrap().hosts, 1);

        // Recolour + rename in place.
        let t = tag_update(&s, db, " database ".into(), Some("A81D33".into())).unwrap();
        assert_eq!(t.label, "database");
        assert_eq!(t.color.as_deref(), Some("#a81d33"));
        assert!(tag_update(&s, db, "x".into(), Some("red".into())).is_err());
        assert!(tag_update(&s, db, "  ".into(), None).is_err());

        // Renaming onto an existing label merges into it (case-insensitive).
        let merged = tag_update(&s, prod, "production".into(), None).unwrap();
        assert_eq!(merged.id, production);
        assert_eq!(merged.hosts, 2);
        assert!(s.get::<Tag>(prod).unwrap().is_none());
        let b_tags = s.require::<Host>(b.id).unwrap().data.tag_ids;
        assert_eq!(b_tags, vec![production]);
        let a_tags = s.require::<Host>(a.id).unwrap().data.tag_ids;
        assert_eq!(a_tags, vec![production, db]);

        // Explicit merge, then delete unlinks everywhere.
        let t = tags_merge(&s, &[db, production], production).unwrap();
        assert_eq!(t.hosts, 2);
        assert!(s.get::<Tag>(db).unwrap().is_none());
        tag_delete(&s, production).unwrap();
        assert!(s.require::<Host>(a.id).unwrap().data.tag_ids.is_empty());
        assert!(
            cards(&s, Some(vault))
                .unwrap()
                .iter()
                .all(|c| c.tags.is_empty())
        );
        assert!(tags(&s, Some(vault)).unwrap().is_empty());
    }

    #[test]
    fn group_icon_round_trips_and_survives_duplicate() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let base = save_group(&s, vault, None, "servers", None).unwrap();
        let mut f = group_form(&s, base.id).unwrap();
        f.icon = Some(" server ".into());
        let g = save_group_form(&s, &f).unwrap();
        assert_eq!(g.icon.as_deref(), Some("server"));
        assert_eq!(
            group_form(&s, g.id).unwrap().icon.as_deref(),
            Some("server")
        );
        let copy = duplicate_group(&s, g.id).unwrap();
        assert_eq!(copy.icon.as_deref(), Some("server"));
        // "auto" / blank clears it again.
        let mut f = group_form(&s, g.id).unwrap();
        f.icon = Some("auto".into());
        assert_eq!(save_group_form(&s, &f).unwrap().icon, None);
    }

    #[test]
    fn custom_icons_round_trip_and_reject_invalid_values() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let mut host = new_form(vault);
        host.icon = Some("custom:data:data:image/png;base64,AAECAw==".into());
        let card = save(&s, &host).unwrap();
        assert_eq!(
            form(&s, card.id).unwrap().icon.as_deref(),
            Some("custom:data:data:image/png;base64,AAECAw==")
        );

        host.icon = Some("custom:data:data:image/png;base64,AAECAw==".into());
        assert_eq!(
            save(&s, &host).unwrap().icon.as_deref(),
            Some("custom:data:data:image/png;base64,AAECAw==")
        );
        host.icon = Some("custom:unsupported:https://example.com/server.png".into());
        assert!(save(&s, &host).is_err());
        host.icon = Some(format!(
            "custom:data:data:image/png;base64,{}",
            "A".repeat(32 * 1024)
        ));
        assert!(save(&s, &host).is_err());
        host.icon = Some("custom:data:data:text/html;base64,PGh0bWw+".into());
        assert!(save(&s, &host).is_err());

        let group = save_group(&s, vault, None, "custom", None).unwrap();
        let mut group_form = group_form(&s, group.id).unwrap();
        group_form.icon = Some("custom:data:data:image/png;base64,AAECAw==".into());
        assert_eq!(
            save_group_form(&s, &group_form).unwrap().icon.as_deref(),
            Some("custom:data:data:image/png;base64,AAECAw==")
        );
    }

    #[test]
    fn group_defaults_are_inherited_and_editable() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let g = save_group_form(
            &s,
            &GroupForm {
                id: None,
                vault_id: vault,
                label: "dc1".into(),
                parent_id: None,
                icon: None,
                port: Some(2200),
                username: "ops".into(),
                password: Some("pw".into()),
                ssh_key_id: None,
                ssh_certificate_id: None,
                identity_id: None,
                has_password: false,
                has_totp: false,
                ssh_id: false,
                ssh_id_key_type: None,
                agent_forwarding: true,
                forward_x11: false,
                host_chain_id: None,
                proxy_id: None,
                env_variables: vec![("LANG".into(), "C".into())],
                keep_alive_interval: None,
                timeout: None,
                totp_secret: None,
            },
        )
        .unwrap();
        assert!(g.has_config);

        let inh = inherited(&s, Some(g.id)).unwrap();
        assert_eq!(inh.group_path, vec!["dc1".to_string()]);
        assert_eq!(inh.port, Some(2200));
        assert_eq!(inh.username.as_deref(), Some("ops"));
        assert!(inh.has_password && inh.agent_forwarding);

        // A host with nothing set resolves to the group's values.
        let mut f = new_form(vault);
        f.group_id = Some(g.id);
        f.port = None;
        f.username = String::new();
        f.password = None;
        let card = save(&s, &f).unwrap();
        assert_eq!(card.port, 2200);
        assert_eq!(card.username, "ops");

        // Editing the group keeps the stored password and can drop defaults.
        let mut gf = group_form(&s, g.id).unwrap();
        assert!(gf.has_password);
        assert_eq!(gf.username, "ops");
        gf.port = None;
        gf.username = String::new();
        gf.password = Some(String::new());
        gf.agent_forwarding = false;
        gf.env_variables.clear();
        let g2 = save_group_form(&s, &gf).unwrap();
        assert!(!g2.has_config);
        let ids: Vec<Entity<Identity>> = s.list(Some(vault)).unwrap();
        assert!(ids.iter().all(|i| i.data.username != "ops"));
        assert_eq!(cards(&s, Some(vault)).unwrap()[0].port, 22);
    }

    #[test]
    fn group_cannot_move_into_own_subtree() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let a = save_group(&s, vault, None, "a", None).unwrap();
        let b = save_group(&s, vault, None, "b", Some(a.id)).unwrap();
        assert!(save_group(&s, vault, Some(a.id), "a", Some(b.id)).is_err());
        assert!(save_group(&s, vault, Some(a.id), "a", Some(a.id)).is_err());
    }

    #[test]
    fn duplicate_copies_credentials_and_config() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let mut f = new_form(vault);
        f.env_variables = vec![("TERM".into(), "xterm".into())];
        let card = save(&s, &f).unwrap();
        let copy = duplicate(&s, card.id).unwrap();
        assert_ne!(copy.id, card.id);
        assert_eq!(copy.label, "prod copy");
        assert_eq!(copy.port, 2222);
        assert_eq!(copy.username, "deploy");
        let cf = form(&s, copy.id).unwrap();
        assert!(cf.has_password);
        assert_eq!(cf.env_variables.len(), 1);
        // Two hosts, two inline identities, two ssh configs.
        assert_eq!(cards(&s, Some(vault)).unwrap().len(), 2);
        let ids: Vec<Entity<Identity>> = s.list(Some(vault)).unwrap();
        assert_eq!(ids.len(), 2);
        let cfgs: Vec<Entity<SshConfig>> = s.list(Some(vault)).unwrap();
        assert_eq!(cfgs.len(), 2);
    }

    #[test]
    fn move_hosts_between_groups() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let g = save_group(&s, vault, None, "g", None).unwrap();
        let a = save(&s, &new_form(vault)).unwrap();
        let b = save(
            &s,
            &HostForm {
                label: "b".into(),
                address: "10.0.0.2".into(),
                ..new_form(vault)
            },
        )
        .unwrap();
        move_hosts(&s, &[a.id, b.id], Some(g.id)).unwrap();
        let cards = cards(&s, Some(vault)).unwrap();
        assert!(cards.iter().all(|c| c.group_id == Some(g.id)));
        assert_eq!(groups(&s, Some(vault)).unwrap()[0].host_count, 2);
        move_hosts(&s, &[a.id], None).unwrap();
        assert_eq!(groups(&s, Some(vault)).unwrap()[0].host_count, 1);
    }

    #[test]
    fn duplicate_group_deep_copies_tree() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let root = save_group(&s, vault, None, "root", None).unwrap();
        let child = save_group(&s, vault, None, "child", Some(root.id)).unwrap();
        let mut f = new_form(vault);
        f.group_id = Some(child.id);
        save(&s, &f).unwrap();
        let mut f2 = new_form(vault);
        f2.group_id = Some(root.id);
        f2.address = "10.0.0.9".into();
        save(&s, &f2).unwrap();

        let copy = duplicate_group(&s, root.id).unwrap();
        assert_eq!(copy.label, "root copy");
        assert_eq!(copy.host_count, 1);
        assert_eq!(copy.group_count, 1);
        let all = groups(&s, Some(vault)).unwrap();
        assert_eq!(all.len(), 4);
        let copied_child = all
            .iter()
            .find(|g| g.parent_id == Some(copy.id))
            .expect("copied child");
        assert_eq!(copied_child.label, "child");
        assert_eq!(copied_child.host_count, 1);
        assert_eq!(cards(&s, Some(vault)).unwrap().len(), 4);

        delete_group_recursive(&s, copy.id).unwrap();
        assert_eq!(groups(&s, Some(vault)).unwrap().len(), 2);
        assert_eq!(cards(&s, Some(vault)).unwrap().len(), 2);
    }

    #[test]
    fn last_connected_comes_from_history() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let card = save(&s, &new_form(vault)).unwrap();
        assert!(card.last_connected.is_none());
        s.record_connection(&termoso_core::store::ConnectionHistory {
            host_id: Some(card.id),
            label: "prod".into(),
            target: "deploy@10.0.0.1:2222".into(),
            protocol: "ssh".into(),
            duration_secs: None,
            error: None,
        })
        .unwrap();
        let card = &cards(&s, Some(vault)).unwrap()[0];
        assert!(card.last_connected.is_some());
    }

    #[test]
    fn delete_removes_inline_entities() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let card = save(&s, &new_form(vault)).unwrap();
        delete(&s, card.id).unwrap();
        assert!(cards(&s, Some(vault)).unwrap().is_empty());
        let cfgs: Vec<Entity<SshConfig>> = s.list(Some(vault)).unwrap();
        let ids: Vec<Entity<Identity>> = s.list(Some(vault)).unwrap();
        assert!(cfgs.is_empty() && ids.is_empty());
    }

    #[test]
    fn legacy_webdav_url_is_split_into_fields() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let mut f = new_form(vault);
        f.address = "cloud.example.com".into();
        f.webdav = Some(WebDavForm {
            path: "/remote.php/dav/".into(),
            ..WebDavForm::default()
        });
        let card = save(&s, &f).unwrap();
        // An entry written by an older client carries the whole URL.
        let r = s.resolve_host(card.id).unwrap();
        let cfg_id = r.host.data.webdav_config_id.unwrap();
        let old = WebDavConfig {
            url: "http://cloud.example.com:8080/remote.php/dav/".into(),
            port: None,
            path: String::new(),
            http: false,
            ..r.webdav.clone().unwrap()
        };
        s.update(cfg_id, &old).unwrap();
        let cards = cards(&s, Some(vault)).unwrap();
        let card = cards.iter().find(|c| c.id == card.id).unwrap();
        assert_eq!(
            card.webdav_url.as_deref(),
            Some("http://cloud.example.com:8080/remote.php/dav/")
        );
        let f = form(&s, card.id).unwrap();
        let w = f.webdav.clone().unwrap();
        assert_eq!(w.port, Some(8080));
        assert!(w.http);
        assert_eq!(w.path, "/remote.php/dav/");
        // Saving the form again moves the entry to the per-field form.
        save(&s, &f).unwrap();
        let r = s.resolve_host(card.id).unwrap();
        let w = r.webdav.unwrap();
        assert!(w.url.is_empty());
        assert_eq!(w.port, Some(8080));
        assert!(w.http);
    }
}
