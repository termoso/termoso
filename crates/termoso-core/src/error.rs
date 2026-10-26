//! Error type shared by every module.

use termoso_crypto::CryptoError;

/// Everything that can go wrong in the core. Messages never contain secret
/// material (passwords, keys, tokens) so they can be shown in the UI and
/// written to local logs.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Local database failure.
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    /// Cryptographic failure (wrong key, tampered envelope…).
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    /// JSON (de)serialisation.
    #[error("serialization: {0}")]
    Json(#[from] serde_json::Error),
    /// Filesystem.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// OS keychain unavailable or refused.
    #[error("keychain: {0}")]
    Keychain(String),
    /// The requested record does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The caller passed something invalid.
    #[error("invalid: {0}")]
    Invalid(String),
    /// The vault key for this vault is not available locally.
    #[error("vault {0} is locked (no key)")]
    VaultLocked(uuid::Uuid),
    /// Our role in this vault only allows viewing.
    #[error("vault {0} is view-only for you")]
    VaultReadOnly(uuid::Uuid),
    /// Server API error (`code` is the machine-readable code from the server).
    #[error("server {status}: {code}: {message}")]
    Api {
        /// HTTP status.
        status: u16,
        /// Error code.
        code: String,
        /// Human message.
        message: String,
    },
    /// HTTP transport.
    #[error("network: {0}")]
    Http(#[from] reqwest::Error),
    /// WebSocket transport.
    #[error("websocket: {0}")]
    Ws(String),
    /// No account is signed in.
    #[error("not signed in")]
    NotSignedIn,
    /// SSH failure.
    #[error("ssh: {0}")]
    Ssh(String),
    /// The server presented an unknown or changed host key and the caller did
    /// not trust it.
    #[error("host key rejected for {host}")]
    HostKeyRejected {
        /// `host:port`.
        host: String,
    },
    /// Authentication with the remote host failed.
    #[error("authentication failed{}", if .remaining.is_empty() { String::new() } else { format!(" (server accepts: {})", .remaining.join(", ")) })]
    AuthFailed {
        /// Methods the server still accepts.
        remaining: Vec<String>,
    },
    /// SFTP failure.
    #[error("sftp: {0}")]
    Sftp(String),
    /// WebDAV failure; `status` is the HTTP status when the server answered.
    #[error("webdav: {message}")]
    WebDav {
        /// HTTP status of the failed request, if any.
        status: Option<u16>,
        /// Human message (never includes credentials).
        message: String,
    },
    /// The server presented a TLS certificate that is neither publicly trusted
    /// nor pinned for this host; `fingerprint` is its SHA-256 (`aa:bb:…`) so
    /// the caller can offer to pin it.
    #[error("untrusted certificate for {host} (sha256 {fingerprint})")]
    CertificateRejected {
        /// `host:port`.
        host: String,
        /// Colon-separated lowercase hex SHA-256 of the leaf certificate.
        fingerprint: String,
    },
    /// Terminal / PTY failure.
    #[error("terminal: {0}")]
    Terminal(String),
    /// SSH key parsing or generation.
    #[error("ssh key: {0}")]
    Key(String),
    /// FIDO2 security key (no device, PIN, touch…).
    #[error("security key: {0}")]
    Fido2(#[from] crate::fido2::Fido2Error),
    /// Mosh bootstrap or UDP session failure.
    #[error("{0}")]
    Mosh(#[from] crate::mosh::MoshError),
    /// The master password did not unlock the profile.
    #[error("wrong master password")]
    WrongPassword,
    /// Operation was cancelled.
    #[error("cancelled")]
    Cancelled,
    /// Session (terminal/sftp) is gone.
    #[error("session closed")]
    Closed,
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, CoreError>;

impl From<russh::Error> for CoreError {
    fn from(e: russh::Error) -> Self {
        CoreError::Ssh(e.to_string())
    }
}

impl From<russh::keys::Error> for CoreError {
    fn from(e: russh::keys::Error) -> Self {
        CoreError::Key(e.to_string())
    }
}

impl From<russh::keys::ssh_key::Error> for CoreError {
    fn from(e: russh::keys::ssh_key::Error) -> Self {
        CoreError::Key(e.to_string())
    }
}

impl From<russh::keys::ssh_encoding::Error> for CoreError {
    fn from(e: russh::keys::ssh_encoding::Error) -> Self {
        CoreError::Key(e.to_string())
    }
}

impl From<russh_sftp::client::error::Error> for CoreError {
    fn from(e: russh_sftp::client::error::Error) -> Self {
        CoreError::Sftp(e.to_string())
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for CoreError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        CoreError::Ws(e.to_string())
    }
}

impl CoreError {
    /// HTTP status of an API error, `None` for anything else.
    pub fn status(&self) -> Option<u16> {
        match self {
            CoreError::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Short machine-readable kind for the UI (`"db"`, `"host_key_rejected"`…).
    pub fn kind(&self) -> &'static str {
        match self {
            CoreError::Db(_) => "db",
            CoreError::Crypto(_) => "crypto",
            CoreError::Json(_) => "json",
            CoreError::Io(_) => "io",
            CoreError::Keychain(_) => "keychain",
            CoreError::NotFound(_) => "not_found",
            CoreError::Invalid(_) => "invalid",
            CoreError::VaultLocked(_) => "vault_locked",
            CoreError::VaultReadOnly(_) => "vault_read_only",
            CoreError::Api { .. } => "api",
            CoreError::Http(_) => "network",
            CoreError::Ws(_) => "websocket",
            CoreError::NotSignedIn => "not_signed_in",
            CoreError::Ssh(_) => "ssh",
            CoreError::HostKeyRejected { .. } => "host_key_rejected",
            CoreError::AuthFailed { .. } => "auth_failed",
            CoreError::Sftp(_) => "sftp",
            CoreError::WebDav { .. } => "webdav",
            CoreError::CertificateRejected { .. } => "certificate_rejected",
            CoreError::Terminal(_) => "terminal",
            CoreError::Key(_) => "key",
            CoreError::Fido2(e) => e.kind(),
            CoreError::Mosh(_) => "mosh",
            CoreError::WrongPassword => "wrong_password",
            CoreError::Cancelled => "cancelled",
            CoreError::Closed => "closed",
        }
    }
}
