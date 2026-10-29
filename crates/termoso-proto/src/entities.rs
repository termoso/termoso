//! Synced entity model.
//!
//! The server stores every entity as an opaque encrypted blob plus a small set
//! of plaintext routing fields (`id`, `kind`, `vault_id`, versions). The
//! *plaintext* schema of each kind (what is inside `data` once decrypted) is
//! defined here so all clients agree. Relations between entities are expressed
//! as UUIDs inside the encrypted payload.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::schema;

/// Known entity kinds. Servers accept any of these; unknown kinds are rejected
/// so a buggy client cannot pollute a vault.
pub const KINDS: &[&str] = &[
    "group",
    "host",
    "ssh_config",
    "telnet_config",
    "webdav_config",
    "serial_config",
    "identity",
    "ssh_key",
    "ssh_certificate",
    "known_host",
    "snippet",
    "snippet_package",
    "host_snippet",
    "pf_rule",
    "proxy",
    "host_chain",
    "tag",
    "tag_host",
    "port_knocking",
    "cloud_import",
    "workspace",
    "workspace_template",
    "log_bookmark",
    "color_scheme",
];

/// Whether `kind` is a known entity kind.
pub fn is_known_kind(kind: &str) -> bool {
    KINDS.contains(&kind)
}

/// Kinds that carry secrets a user may want to keep off the server entirely
/// (usernames, passwords, private keys, certificates). Clients can be told
/// to keep these device-local for the Personal vault; see
/// `SyncOptions::sync_credentials` in `termoso-core`.
pub const CREDENTIAL_KINDS: &[&str] = &["identity", "ssh_key", "ssh_certificate"];

/// Whether `kind` is one of [`CREDENTIAL_KINDS`].
pub fn is_credential_kind(kind: &str) -> bool {
    CREDENTIAL_KINDS.contains(&kind)
}

/// `SshKey::key_type` of a key whose private half is held by an SSH agent
/// (OpenSSH `IdentityFile key.pub` + `IdentitiesOnly`); the vault stores
/// only the public line.
pub const AGENT_KEY_TYPE: &str = "agent";

impl payload::SshKey {
    /// The private half is not in the vault; an SSH agent signs.
    pub fn is_agent_backed(&self) -> bool {
        self.key_type == AGENT_KEY_TYPE
    }
}

schema! {
    /// Entity as stored and returned by the server.
    pub struct SyncEntity {
        /// See `EntityChange::secret_rotated_at`.
        #[serde(default)]
        pub secret_rotated_at: Option<DateTime<Utc>>,
        /// Client-generated UUID (v4).
        pub id: Uuid,
        /// Kind (see [`KINDS`]).
        pub kind: String,
        /// Vault.
        pub vault_id: Uuid,
        /// Optimistic-concurrency version, starts at 1.
        pub version: i64,
        /// Per-vault monotonically increasing change sequence (pull cursor).
        pub seq: i64,
        /// Tombstone.
        pub deleted: bool,
        /// Vault key version `data` was encrypted with.
        pub key_version: i32,
        /// Encrypted payload (envelope, base64). AAD = `termoso/v1/entity/<kind>/<id>`.
        /// Empty for tombstones.
        pub data: String,
        /// Last modification.
        pub updated_at: DateTime<Utc>,
        /// Device that made the last change.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub updated_by_device: Option<Uuid>,
    }
}

/// Plaintext payload schemas (what `SyncEntity::data` decrypts to).
///
/// These mirror the feature set of the desktop client one-to-one. Optional
/// fields default so that old clients can read new payloads.
pub mod payload {
    use super::*;

    schema! {
        /// Folder in the host tree. `parent_id` → another group.
        #[derive(Default)]
        pub struct Group {
            /// Label.
            pub label: String,
            /// Parent group.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub parent_id: Option<Uuid>,
            /// Default ssh_config for hosts in this group.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub ssh_config_id: Option<Uuid>,
            /// Default telnet_config.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub telnet_config_id: Option<Uuid>,
            /// Sort order.
            #[serde(default)]
            pub sort_order: i32,
            /// Id of the group in the system that created it through an API
            /// bridge (CMDB, cloud inventory); lets the bridge find it again.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub external_id: Option<String>,
        }
    }

    schema! {
        /// A connection target.
        #[derive(Default)]
        pub struct Host {
            /// Label.
            pub label: String,
            /// Hostname or IP.
            pub address: String,
            /// MAC address for Wake-on-LAN (`aa:bb:cc:dd:ee:ff`), if the host sleeps.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub mac_address: Option<String>,
            /// Group.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub group_id: Option<Uuid>,
            /// SSH settings.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub ssh_config_id: Option<Uuid>,
            /// Telnet settings.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub telnet_config_id: Option<Uuid>,
            /// WebDAV settings (a file share on this host).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub webdav_config_id: Option<Uuid>,
            /// Serial settings (local hosts).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub serial_config_id: Option<Uuid>,
            /// Tags.
            #[serde(default)]
            pub tag_ids: Vec<Uuid>,
            /// Free-form notes.
            #[serde(default)]
            pub notes: String,
            /// Detected OS name.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub os_name: Option<String>,
            /// Icon chosen by the user (an OS id such as `ubuntu`); overrides
            /// the detected `os_name` for display.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub icon: Option<String>,
            /// Preferred IP version: `auto`, `4`, `6`.
            #[serde(default)]
            pub ip_version: String,
            /// Backspace mode.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub backspace: Option<String>,
            /// Cloud instance id (for imported hosts).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub cloud_instance_id: Option<String>,
            /// Cloud instance type.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub cloud_instance_type: Option<String>,
            /// Startup snippet.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub startup_snippet_id: Option<Uuid>,
            /// Sort order.
            #[serde(default)]
            pub sort_order: i32,
            /// Id of the host in the system that created it through an API
            /// bridge (CMDB, cloud inventory); lets the bridge find it again.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub external_id: Option<String>,
            /// Expose the host's SFTP / WebDAV share to the system file picker
            /// (Android Storage Access Framework). Off by default so a host
            /// never shows up in other apps unless the user opts in.
            #[serde(default, skip_serializing_if = "std::ops::Not::not")]
            pub files_provider: bool,
            /// Per-host override of the app's shell integration setting
            /// (typing the OSC 133 hooks into the shell after login):
            /// `None` follows the setting, `Some(false)` never types them
            /// (routers, jump hosts, hosts whose session is a program rather
            /// than a shell), `Some(true)` always does.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub shell_integration: Option<bool>,
        }
    }

    schema! {
        /// SSH connection settings; may be attached to a host or a group.
        #[derive(Default, PartialEq, Eq)]
        pub struct SshConfig {
            /// Port (default 22).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub port: Option<u16>,
            /// Identity used to authenticate.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub identity_id: Option<Uuid>,
            /// Jump host chain.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub host_chain_id: Option<Uuid>,
            /// Proxy.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub proxy_id: Option<Uuid>,
            /// Reach the host through this gateway (an API bridge running `termoso-bridge gateway`)
            /// instead of dialling it directly; the bridge id.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub gateway_id: Option<Uuid>,
            /// Port knocking sequence.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub port_knocking_id: Option<Uuid>,
            /// Terminal charset.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub charset: Option<String>,
            /// Color scheme name.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub color_scheme: Option<String>,
            /// Font size override.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub font_size: Option<u16>,
            /// Cursor blink.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub cursor_blink: Option<bool>,
            /// Agent forwarding.
            #[serde(default)]
            pub agent_forwarding: bool,
            /// X11 forwarding (trusted) to the local display; clients without
            /// an X server ignore it.
            #[serde(default, skip_serializing_if = "std::ops::Not::not")]
            pub forward_x11: bool,
            /// Use Mosh.
            #[serde(default)]
            pub use_mosh: bool,
            /// Mosh server command.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub mosh_server_command: Option<String>,
            /// Environment variables to send.
            #[serde(default)]
            pub env_variables: Vec<(String, String)>,
            /// Keep-alive interval seconds.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub keep_alive_interval: Option<u32>,
            /// Connection timeout seconds.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub timeout: Option<u32>,
            /// Extra raw options (`Key=Value`, OpenSSH style).
            #[serde(default)]
            pub extra_options: Vec<String>,
        }
    }

    schema! {
        /// Telnet settings.
        #[derive(Default)]
        pub struct TelnetConfig {
            /// Port (default 23).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub port: Option<u16>,
            /// Identity.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub identity_id: Option<Uuid>,
            /// Charset.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub charset: Option<String>,
            /// Color scheme.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub color_scheme: Option<String>,
        }
    }

    schema! {
        /// WebDAV share settings. Credentials live in the referenced identity
        /// (username + password, a bearer token or a TLS client certificate;
        /// SSH keys do not apply).
        #[derive(Default, PartialEq, Eq)]
        pub struct WebDavConfig {
            /// Base URL of the share as stored before 0.8.2
            /// (`https://cloud.example.com/remote.php/dav/files/alice/`).
            /// Empty once the section uses the host's address with
            /// `port` / `path` / `http` below; kept so older entries and
            /// older clients keep working.
            #[serde(default)]
            pub url: String,
            /// TCP port; `None` = 443 (or 80 with `http`).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub port: Option<u16>,
            /// Collection path below the host, e.g. `/remote.php/dav/files/alice/`;
            /// empty = `/`.
            #[serde(default, skip_serializing_if = "String::is_empty")]
            pub path: String,
            /// Plain HTTP instead of HTTPS.
            #[serde(default, skip_serializing_if = "std::ops::Not::not")]
            pub http: bool,
            /// TLS: name sent as SNI and checked against the certificate
            /// when it differs from the host's address (a share behind a
            /// reverse proxy reached by IP, or a hostname not in DNS).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub tls_server_name: Option<String>,
            /// TLS: PEM bundle of a private certificate authority the
            /// server certificate must chain to, instead of the system roots.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub ca_certificate: Option<String>,
            /// Identity.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub identity_id: Option<Uuid>,
            /// SHA-256 fingerprint (`aa:bb:…`) of a self-signed or private-CA
            /// server certificate the user chose to trust; `None` = system roots.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub certificate_fingerprint: Option<String>,
        }
    }

    schema! {
        /// Serial port settings.
        #[derive(Default)]
        pub struct SerialConfig {
            /// Device path or COM port.
            pub path: String,
            /// Baud rate.
            pub baud_rate: u32,
            /// Data bits (5–8).
            #[serde(default)]
            pub data_bits: u8,
            /// Stop bits (1 or 2).
            #[serde(default)]
            pub stop_bits: u8,
            /// Parity: `none`, `odd`, `even`.
            #[serde(default)]
            pub parity: String,
            /// Flow control: `none`, `software`, `hardware`.
            #[serde(default)]
            pub flow_control: String,
            /// Text encoding of the device (WHATWG label, e.g. `utf-8`, `koi8-r`); empty = UTF-8.
            #[serde(default)]
            pub charset: String,
        }
    }

    schema! {
        /// Credentials (username + password and/or key).
        #[derive(Default)]
        pub struct Identity {
            /// Label.
            pub label: String,
            /// Username.
            pub username: String,
            /// Password.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub password: Option<String>,
            /// SSH key.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub ssh_key_id: Option<Uuid>,
            /// SSH certificate.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub ssh_certificate_id: Option<Uuid>,
            /// Hidden from the identities list (inline identity of a host).
            #[serde(default)]
            pub is_visible: bool,
            /// Authenticate with the account's SSH ID passkeys (this device's
            /// keys plus the FIDO2 keys attached to the SSH ID). The username
            /// falls back to the SSH ID handle when empty.
            #[serde(default, skip_serializing_if = "std::ops::Not::not")]
            pub ssh_id: bool,
            /// Passkey type to try first (`None` = ED25519, then the rest).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub ssh_id_key_type: Option<crate::sshid::SshIdKeyType>,
            /// Access token sent as `Authorization: Bearer …` (WebDAV). Takes
            /// precedence over username + password.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub bearer_token: Option<String>,
            /// TLS client certificate presented to servers requiring mTLS (WebDAV).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub client_certificate: Option<ClientCertificate>,
            /// TOTP secret (`otpauth://` URI or base32) used to answer the
            /// one-time-code prompt of keyboard-interactive logins.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub totp_secret: Option<String>,
            /// Stable id assigned by an external system (API Bridge, importers)
            /// so repeated syncs update instead of duplicating.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub external_id: Option<String>,
        }
    }

    schema! {
        /// TLS client certificate + private key, both PEM.
        #[derive(Default, PartialEq, Eq)]
        pub struct ClientCertificate {
            /// Certificate chain, leaf first.
            pub certificate: String,
            /// Unencrypted private key (PKCS#8, RSA or SEC1).
            pub private_key: String,
        }
    }

    schema! {
        /// SSH key. Normally the private half lives here; for
        /// [`AGENT_KEY_TYPE`] keys only `public_key` is set and an SSH agent
        /// on the connecting device does the signing.
        #[derive(Default)]
        pub struct SshKey {
            /// Label.
            pub label: String,
            /// PEM / OpenSSH private key (empty for agent-backed keys).
            #[serde(default)]
            pub private_key: String,
            /// Public key line.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub public_key: Option<String>,
            /// Passphrase.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub passphrase: Option<String>,
            /// Key type (`ed25519`, `rsa`, `ecdsa`, `fido2`, `agent`…).
            #[serde(default)]
            pub key_type: String,
            /// For FIDO2 resident keys: the credential id.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub fido2_credential_id: Option<String>,
            /// FIDO2 key attached to the account's SSH ID (managed from
            /// Settings → SSH ID, not listed in the Keychain).
            #[serde(default, skip_serializing_if = "std::ops::Not::not")]
            pub ssh_id: bool,
            /// Stable id assigned by an external system (API Bridge, importers)
            /// so repeated syncs update instead of duplicating.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub external_id: Option<String>,
        }
    }

    schema! {
        /// SSH certificate paired with a key.
        #[derive(Default)]
        pub struct SshCertificate {
            /// Label.
            pub label: String,
            /// Certificate content.
            pub certificate: String,
            /// The key it certifies.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub ssh_key_id: Option<Uuid>,
        }
    }

    schema! {
        /// Pinned server host key.
        #[derive(Default)]
        pub struct KnownHost {
            /// `host[:port]`.
            pub hostname: String,
            /// Key type.
            pub key_type: String,
            /// Base64 key.
            pub public_key: String,
            /// Fingerprint (SHA256).
            #[serde(default)]
            pub fingerprint: String,
        }
    }

    schema! {
        /// Command snippet.
        #[derive(Default)]
        pub struct Snippet {
            /// Label.
            pub label: String,
            /// Script body; may contain `{{variables}}`.
            pub script: String,
            /// Package.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub package_id: Option<Uuid>,
            /// Close terminal after running.
            #[serde(default)]
            pub close_after_run: bool,
            /// Sort order.
            #[serde(default)]
            pub sort_order: i32,
            /// Stable id assigned by an external system (API Bridge, importers)
            /// so repeated syncs update instead of duplicating.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub external_id: Option<String>,
        }
    }

    schema! {
        /// Snippet folder.
        #[derive(Default)]
        pub struct SnippetPackage {
            /// Label.
            pub label: String,
            /// Parent package.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub parent_id: Option<Uuid>,
        }
    }

    schema! {
        /// Host a snippet is configured to run on (an execution target).
        #[derive(Default)]
        pub struct HostSnippet {
            /// Host.
            pub host_id: Uuid,
            /// Snippet.
            pub snippet_id: Uuid,
            /// Execution order.
            #[serde(default)]
            pub sort_order: i32,
        }
    }

    schema! {
        /// Port-forwarding rule.
        #[derive(Default)]
        pub struct PfRule {
            /// Label.
            pub label: String,
            /// Host providing the tunnel.
            pub host_id: Uuid,
            /// `local`, `remote`, `dynamic`.
            pub kind: String,
            /// Bind address (local side).
            #[serde(default)]
            pub bound_address: String,
            /// Local port.
            pub local_port: u16,
            /// Remote host (not used for dynamic).
            #[serde(default)]
            pub remote_host: String,
            /// Remote port.
            #[serde(default)]
            pub remote_port: u16,
            /// Auto-start when app launches.
            #[serde(default)]
            pub auto_start: bool,
        }
    }

    schema! {
        /// SOCKS / HTTP proxy.
        #[derive(Default)]
        pub struct Proxy {
            /// `socks4`, `socks5`, `http`.
            pub kind: String,
            /// Host.
            pub host: String,
            /// Port.
            pub port: u16,
            /// Identity for proxy auth; takes precedence over the inline
            /// username/password below.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub identity_id: Option<Uuid>,
            /// Inline proxy username (HTTP, SOCKS5; SOCKS4 sends it as the user id).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub username: Option<String>,
            /// Inline proxy password (HTTP, SOCKS5 only).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub password: Option<String>,
        }
    }

    schema! {
        /// Ordered list of jump hosts.
        #[derive(Default)]
        pub struct HostChain {
            /// Label.
            pub label: String,
            /// Hosts in order.
            pub host_ids: Vec<Uuid>,
        }
    }

    schema! {
        /// Tag.
        #[derive(Default)]
        pub struct Tag {
            /// Label.
            pub label: String,
            /// Color (hex).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub color: Option<String>,
        }
    }

    schema! {
        /// Host ↔ tag link.
        #[derive(Default)]
        pub struct TagHost {
            /// Host.
            pub host_id: Uuid,
            /// Tag.
            pub tag_id: Uuid,
        }
    }

    schema! {
        /// Port knocking sequence.
        #[derive(Default)]
        pub struct PortKnocking {
            /// Label.
            pub label: String,
            /// Ports in order.
            pub ports: Vec<u16>,
            /// Delay between knocks (ms).
            #[serde(default)]
            pub delay_ms: u32,
        }
    }

    schema! {
        /// Cloud provider import credentials.
        #[derive(Default)]
        pub struct CloudImport {
            /// Label.
            pub label: String,
            /// `aws`, `digitalocean`, `gcp`, `azure`, `hetzner`…
            pub provider: String,
            /// Provider-specific credentials JSON.
            pub credentials: serde_json::Value,
            /// Regions to scan.
            #[serde(default)]
            pub regions: Vec<String>,
            /// Target group for imported hosts.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub group_id: Option<Uuid>,
        }
    }

    schema! {
        /// Saved workspace (layout of tabs / splits).
        #[derive(Default)]
        pub struct Workspace {
            /// Label.
            pub label: String,
            /// Layout tree JSON (client-defined).
            pub layout: serde_json::Value,
        }
    }

    schema! {
        /// Bookmark inside a session log.
        #[derive(Default)]
        pub struct LogBookmark {
            /// Session log id.
            pub log_id: Uuid,
            /// Byte offset.
            pub offset: u64,
            /// Note.
            #[serde(default)]
            pub note: String,
        }
    }

    schema! {
        /// User-defined terminal colour scheme (imported or built in the
        /// editor). Referenced from `Host::color_scheme` / `Group::color_scheme`
        /// by entity id. Colours are `#rrggbb`; `selection` may carry alpha.
        #[derive(Default)]
        pub struct ColorScheme {
            /// Display name.
            pub name: String,
            /// Background.
            pub background: String,
            /// Default text.
            pub foreground: String,
            /// Cursor.
            pub cursor: String,
            /// Selection background (`#rrggbbaa`); derived from the foreground when absent.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub selection: Option<String>,
            /// The 16 ANSI colours in xterm order: black, red, green, yellow,
            /// blue, magenta, cyan, white, then the bright eight.
            pub ansi: Vec<String>,
        }
    }
}
