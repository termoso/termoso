//! REST payloads. Field names follow the Termius API Bridge so existing
//! automation can be pointed at Termoso with a URL change.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `POST|PUT /v1/host/{external_id}/`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequest {
    /// Vault name or id. Optional when `group` is given or the bridge has exactly one vault.
    #[serde(default)]
    pub vault: Option<String>,
    /// `external_id` of the group to place the host in (`null`/absent = vault root).
    #[serde(default)]
    pub group: Option<String>,
    pub address: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub ssh: Option<SshSection>,
    #[serde(default)]
    pub telnet: Option<TelnetSection>,
}

/// `POST|PUT /v1/group/{external_id}/`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRequest {
    #[serde(default)]
    pub vault: Option<String>,
    /// `external_id` of the parent group (extension; Termius groups are flat).
    #[serde(default)]
    pub parent: Option<String>,
    pub label: String,
    #[serde(default)]
    pub ssh: Option<SshSection>,
    #[serde(default)]
    pub telnet: Option<TelnetSection>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshSection {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub credentials: Option<Credentials>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelnetSection {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub credentials: Option<Credentials>,
}

/// Inline credentials. Never logged, never echoed back.
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    /// `external_id` of a shared identity (see `/v1/identity/{external_id}`);
    /// excludes the inline fields below.
    #[serde(default)]
    pub identity: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub key: Option<KeyInput>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("identity", &self.identity)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("key", &self.key.as_ref().map(|_| "***"))
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyInput {
    #[serde(default)]
    pub label: Option<String>,
    /// Private key (PEM / OpenSSH).
    pub private: String,
    #[serde(default)]
    pub public: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
}

impl Credentials {
    pub fn is_empty(&self) -> bool {
        self.identity.as_deref().unwrap_or("").trim().is_empty()
            && self.username.as_deref().unwrap_or("").trim().is_empty()
            && self.password.as_deref().unwrap_or("").is_empty()
            && self.key.is_none()
    }
}

/// Non-secret view of a bridge-managed host.
#[derive(Debug, Clone, Serialize)]
pub struct HostSummary {
    pub id: Uuid,
    pub external_id: String,
    pub vault: String,
    pub vault_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    pub label: String,
    pub address: String,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telnet_port: Option<u16>,
    pub has_credentials: bool,
}

/// Non-secret view of a bridge-managed group.
#[derive(Debug, Clone, Serialize)]
pub struct GroupSummary {
    pub id: Uuid,
    pub external_id: String,
    pub vault: String,
    pub vault_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub label: String,
    pub hosts: usize,
}

/// `GET /v1/vaults/`.
#[derive(Debug, Clone, Serialize)]
pub struct VaultSummary {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub role: String,
    pub key_version: i32,
    /// `false` while waiting for a re-seal after a key rotation.
    pub ready: bool,
    pub hosts: usize,
    pub groups: usize,
}

/// `GET /v1/bridge/me` (and `GET /`).
#[derive(Debug, Clone, Serialize)]
pub struct BridgeStatus {
    pub bridge_id: Uuid,
    pub name: String,
    pub server: String,
    pub version: &'static str,
    pub vaults: Vec<VaultSummary>,
}

/// `PUT /v1/snippet/{external_id}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnippetRequest {
    #[serde(default)]
    pub vault: Option<String>,
    pub label: String,
    pub script: String,
    #[serde(default)]
    pub close_after_run: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnippetSummary {
    pub id: Uuid,
    pub external_id: String,
    pub vault: String,
    pub vault_id: Uuid,
    pub label: String,
    pub script: String,
    pub close_after_run: bool,
}

/// `PUT /v1/identity/{external_id}`: a reusable credential set, visible in
/// the keychain and referenced from hosts as `credentials.identity`.
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRequest {
    #[serde(default)]
    pub vault: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// `external_id` of a key stored through `/v1/key/{external_id}`.
    #[serde(default)]
    pub key: Option<String>,
}

impl std::fmt::Debug for IdentityRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityRequest")
            .field("vault", &self.vault)
            .field("label", &self.label)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("key", &self.key)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentitySummary {
    pub id: Uuid,
    pub external_id: String,
    pub vault: String,
    pub vault_id: Uuid,
    pub label: String,
    pub username: String,
    pub has_password: bool,
    /// `external_id` of the key, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Hosts and groups using this identity.
    pub used_by: usize,
}

/// `PUT /v1/key/{external_id}`.
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRequest {
    #[serde(default)]
    pub vault: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    pub private: String,
    #[serde(default)]
    pub public: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
}

impl std::fmt::Debug for KeyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRequest")
            .field("vault", &self.vault)
            .field("label", &self.label)
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct KeySummary {
    pub id: Uuid,
    pub external_id: String,
    pub vault: String,
    pub vault_id: Uuid,
    pub label: String,
    pub key_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub has_passphrase: bool,
    /// Identities referencing this key.
    pub used_by: usize,
}
