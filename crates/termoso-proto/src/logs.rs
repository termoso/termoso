//! Session logs: terminal recordings encrypted client-side and stored in object storage.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::schema;

schema! {
    /// Who recorded a log, as shown to teammates.
    pub struct LogAuthor {
        /// User id.
        pub user_id: Uuid,
        /// Email.
        pub email: String,
        /// Display name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        /// Avatar tag (see `GET /users/{id}/avatar`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub avatar_tag: Option<String>,
    }
}

schema! {
    /// Session log metadata.
    pub struct SessionLog {
        /// Client-generated UUID.
        pub id: Uuid,
        /// Vault whose key encrypts `meta` and the object (personal or team).
        pub vault_id: Uuid,
        /// Who recorded it.
        #[serde(default)]
        pub user_id: Uuid,
        /// Author profile (absent for tombstones).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub author: Option<LogAuthor>,
        /// Encrypted metadata (host label, address, start/end time, size…).
        /// AAD = `termoso/v1/log/<id>`.
        pub meta: String,
        /// Vault key version.
        pub key_version: i32,
        /// Encrypted object size in bytes (0 until completed).
        pub size_bytes: i64,
        /// Upload finished.
        pub completed: bool,
        /// Created.
        pub created_at: DateTime<Utc>,
        /// Server sequence for incremental listing: the author's counter in
        /// `GET /logs`, the vault's counter in `GET /vaults/{id}/logs`.
        pub seq: i64,
        /// Tombstone.
        #[serde(default)]
        pub deleted: bool,
        /// Pinned by a teammate (kept at the top, exempt from retention).
        #[serde(default)]
        pub pinned: bool,
        /// Plaintext team note (never contains terminal output).
        #[serde(default)]
        pub note: String,
        /// Who wrote/edited the note last.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note_by: Option<Uuid>,
    }
}

/// Longest team note accepted by the server.
pub const MAX_NOTE_CHARS: usize = 2000;

schema! {
    /// `POST /logs` – reserve a log and get an upload URL.
    pub struct CreateLogRequest {
        /// Id.
        pub id: Uuid,
        /// Vault.
        pub vault_id: Uuid,
        /// Encrypted metadata.
        pub meta: String,
        /// Key version.
        pub key_version: i32,
        /// Expected size (server enforces the maximum).
        pub size_bytes: i64,
    }
}

schema! {
    /// Response to `CreateLogRequest`.
    pub struct CreateLogResponse {
        /// Pre-signed PUT URL (valid for a limited time).
        pub upload_url: String,
        /// Headers that must be sent with the PUT.
        #[serde(default)]
        pub upload_headers: Vec<(String, String)>,
        /// Seconds until the URL expires.
        pub expires_in: u64,
    }
}

schema! {
    /// `PATCH /logs/{id}` – update metadata (e.g. after the session ends).
    pub struct UpdateLogRequest {
        /// New encrypted metadata.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub meta: Option<String>,
        /// Final size (marks the upload as completed).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub size_bytes: Option<i64>,
        /// Pin / unpin (team vaults: editor or above; personal: owner).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pinned: Option<bool>,
        /// Replace the note (empty string clears it).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }
}

schema! {
    /// `GET /logs/{id}/download`
    pub struct DownloadLogResponse {
        /// Pre-signed GET URL.
        pub download_url: String,
        /// Seconds until the URL expires.
        pub expires_in: u64,
    }
}

schema! {
    /// `GET /logs?since=&limit=` and `GET /vaults/{id}/logs?since=&limit=`
    pub struct LogListResponse {
        /// Logs.
        pub logs: Vec<SessionLog>,
        /// New cursor.
        pub since: i64,
        /// More available.
        pub has_more: bool,
        /// Logs matching the filter (team listing only; 0 elsewhere).
        #[serde(default)]
        pub total: i64,
    }
}
