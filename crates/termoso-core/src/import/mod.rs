//! Parsers for host lists other tools export — OpenSSH `ssh_config`, PuTTY
//! registry exports, MobaXterm bookmarks, SecureCRT settings, ZOC host
//! directories and plain CSV — into a neutral [`ImportPreview`] every client
//! can show and apply to its vault. File scanning and applying live with the
//! clients; this module only parses.

#![allow(missing_docs)]

pub mod csv;
pub mod iterm2;
pub mod mobaxterm;
pub mod putty;
pub mod royalts;
pub mod securecrt;
pub mod ssh_config;
pub mod tabby;
pub mod winscp;
pub mod xshell;
pub mod zoc;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};

pub(crate) fn invalid(msg: impl Into<String>) -> CoreError {
    CoreError::Invalid(msg.into())
}

/// Direction of a port forwarding rule found in an import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PfKind {
    Local,
    Remote,
    Dynamic,
}

pub const MAX_TEXT_FILE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportSource {
    SshConfig,
    Putty,
    Csv,
    Mobaxterm,
    Securecrt,
    Zoc,
    Winscp,
    Royalts,
    Iterm2,
    Tabby,
    Xshell,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedProxy {
    /// `socks4`, `socks5`, `http`.
    pub kind: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Never leaves Rust; lands in the encrypted vault at apply time.
    #[serde(skip_serializing)]
    pub password: Option<String>,
    pub has_password: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedHost {
    pub label: String,
    pub address: String,
    /// `ssh` or `telnet`.
    pub protocol: String,
    pub port: Option<u16>,
    pub username: String,
    /// Never leaves Rust; lands in the encrypted vault at apply time.
    #[serde(skip_serializing)]
    pub password: Option<String>,
    pub has_password: bool,
    pub group_path: Vec<String>,
    pub tags: Vec<String>,
    /// Private key file referenced by the source (`IdentityFile`,
    /// `PublicKeyFile`); resolved against the imported keys at apply time.
    pub key_path: Option<String>,
    /// `ProxyJump` entries as written (`alias`, `user@host:port`).
    pub jump_hosts: Vec<String>,
    pub proxy: Option<ImportedProxy>,
    pub agent_forwarding: bool,
    pub forward_x11: bool,
    pub env_variables: Vec<(String, String)>,
    pub keep_alive_interval: Option<u32>,
    pub timeout: Option<u32>,
    /// Free text from the source (SecureCRT description, ZOC memo).
    pub notes: String,
    /// Source-specific notes for the user (ignored directives etc.).
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedKey {
    pub path: String,
    pub name: String,
    pub key_type: String,
    pub bits: usize,
    pub fingerprint: String,
    pub encrypted: bool,
    /// `authorized_keys` line, used to skip keys already in the vault.
    pub public_key: String,
    /// A `.pub` without its private half: stored public-only, the SSH
    /// agent signs (OpenSSH `IdentityFile key.pub`).
    pub agent_backed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedKnownHost {
    pub hostname: String,
    pub key_type: String,
    pub fingerprint: String,
    /// Plain `known_hosts` line for this single host.
    pub line: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedPfRule {
    /// Label of the host (in this preview) that carries the tunnel.
    pub host_label: String,
    pub kind: PfKind,
    pub bound_address: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    /// Handle for `apply` / `discard`; the full preview lives in the cache.
    pub id: Uuid,
    pub source: ImportSource,
    /// Where the data came from (path, registry), for the dialog header.
    pub origin: String,
    pub hosts: Vec<ImportedHost>,
    pub keys: Vec<ImportedKey>,
    pub known_hosts: Vec<ImportedKnownHost>,
    pub pf_rules: Vec<ImportedPfRule>,
    /// Non-fatal problems: skipped files, ignored directives.
    pub warnings: Vec<String>,
}

impl ImportPreview {
    pub fn new(source: ImportSource, origin: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            source,
            origin: origin.into(),
            hosts: Vec::new(),
            keys: Vec::new(),
            known_hosts: Vec::new(),
            pf_rules: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
            && self.keys.is_empty()
            && self.known_hosts.is_empty()
            && self.pf_rules.is_empty()
    }

    /// Set the `has_password` flags the UI sees instead of the secrets.
    pub fn seal(mut self) -> Self {
        for h in &mut self.hosts {
            h.has_password = h.password.as_deref().is_some_and(|p| !p.is_empty());
            if let Some(p) = &mut h.proxy {
                p.has_password = p.password.as_deref().is_some_and(|s| !s.is_empty());
            }
        }
        self
    }
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// `~/.ssh` of the current user (may not exist).
pub fn default_ssh_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".ssh"))
}

pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    } else if path == "~"
        && let Some(home) = home_dir()
    {
        return home;
    }
    PathBuf::from(path)
}

pub fn display(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

pub fn read_text(path: &Path, max: u64) -> Result<String> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(invalid(format!("{} is not a file", display(path))));
    }
    if meta.len() > max {
        return Err(invalid(format!("{} is too large", display(path))));
    }
    let bytes = std::fs::read(path)?;
    Ok(decode_text(&bytes))
}

/// UTF-8, or UTF-16LE/BE with BOM (what `regedit` writes).
pub fn decode_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return utf16(&bytes[2..], true);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return utf16(&bytes[2..], false);
    }
    if bytes.len() >= 4 && bytes.iter().skip(1).step_by(2).take(64).all(|b| *b == 0) {
        return utf16(bytes, true);
    }
    let text = String::from_utf8_lossy(bytes);
    text.strip_prefix('\u{feff}')
        .map(str::to_owned)
        .unwrap_or_else(|| text.into_owned())
}

pub fn utf16(bytes: &[u8], little: bool) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| {
            if little {
                u16::from_le_bytes(*c)
            } else {
                u16::from_be_bytes(*c)
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

/// `host`, `host:port` or `[v6]:port`; a bad or zero port is dropped.
pub(super) fn split_host_port(s: &str) -> (&str, Option<u16>) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
        return (host, port);
    }
    match s.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => match port.parse::<u16>() {
            Ok(p) if p > 0 => (host, Some(p)),
            _ => (s, None),
        },
        _ => (s, None),
    }
}
