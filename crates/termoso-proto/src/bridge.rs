//! API Bridge: a headless client the user runs in their own infrastructure
//! (Docker) to create and delete hosts, groups and credentials from scripts.
//!
//! The bridge holds its own key pair; the cabinet seals the vault keys it may
//! use to that key. Everything the bridge writes is encrypted locally and
//! travels through the normal sync protocol, so the server keeps seeing
//! opaque blobs only. Its bearer token is a restricted session: sync plus
//! `GET /bridge/me`, nothing else.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::schema;
use crate::vault::{VaultKind, VaultRole};

/// Current on-disk format of the credentials file the cabinet hands out.
pub const CREDENTIALS_VERSION: u32 = 1;

schema! {
    /// A vault a bridge may write to.
    pub struct BridgeVault {
        /// Vault id.
        pub vault_id: Uuid,
        /// Vault name (plaintext, same as `GET /vaults`).
        pub name: String,
        /// Kind.
        pub kind: VaultKind,
        /// Owning team (team vaults only).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub team_id: Option<Uuid>,
        /// Role of the owning user in the vault (the bridge inherits it).
        pub role: VaultRole,
        /// Current key version of the vault.
        pub key_version: i32,
        /// Vault key sealed to the bridge's public key; `None` after a key
        /// rotation until someone with the new key re-seals it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sealed_key: Option<String>,
    }
}

schema! {
    /// A bridge as listed in the cabinet.
    pub struct Bridge {
        /// Id.
        pub id: Uuid,
        /// Label chosen when creating it.
        pub name: String,
        /// The device row the bridge's session belongs to.
        pub device_id: Uuid,
        /// Bridge public key (base64), needed to seal vault keys to it.
        pub public_key: String,
        /// Vaults it may write to.
        pub vaults: Vec<BridgeVault>,
        /// Created.
        pub created_at: DateTime<Utc>,
        /// Last request made with the bridge token.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_used_at: Option<DateTime<Utc>>,
        /// Last IP seen (for the owner's review only).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_ip: Option<String>,
    }
}

schema! {
    /// `GET /account/bridges`
    pub struct BridgeList {
        /// Bridges owned by the caller.
        pub bridges: Vec<Bridge>,
    }
}

schema! {
    /// A vault key sealed to a bridge.
    pub struct BridgeVaultKey {
        /// Vault.
        pub vault_id: Uuid,
        /// Vault key sealed to the bridge public key.
        pub sealed_key: String,
    }
}

schema! {
    /// `POST /account/bridges`
    pub struct CreateBridgeRequest {
        /// Label.
        pub name: String,
        /// Bridge public key (base64), generated client-side; the private
        /// half goes into the credentials file and never reaches the server.
        pub public_key: String,
        /// Vaults the bridge may write to, with the key sealed to it.
        pub vaults: Vec<BridgeVaultKey>,
    }
}

schema! {
    /// `POST /account/bridges` response. `token` is shown exactly once.
    pub struct CreateBridgeResponse {
        /// The bridge.
        pub bridge: Bridge,
        /// Bearer token for the bridge (only sync + `GET /bridge/me`).
        pub token: String,
    }
}

schema! {
    /// `GET /bridge/me` — what a bridge learns about itself.
    pub struct BridgeSelf {
        /// Bridge id.
        pub id: Uuid,
        /// Label.
        pub name: String,
        /// Owning user.
        pub user_id: Uuid,
        /// Device id the bridge session runs under (`updated_by_device`).
        pub device_id: Uuid,
        /// Vaults with keys sealed to the bridge.
        pub vaults: Vec<BridgeVault>,
    }
}

schema! {
    /// Credentials file (`termoso-bridge.json`) written by the cabinet and
    /// mounted into the bridge container.
    pub struct BridgeCredentials {
        /// File format version.
        pub version: u32,
        /// Server base URL.
        pub server: String,
        /// Bridge id.
        pub bridge_id: Uuid,
        /// Bridge private key (base64, X25519 secret).
        pub private_key: String,
        /// Bearer token.
        pub token: String,
    }
}

schema! {
    /// A bridge running in `gateway` mode that the caller can tunnel through
    /// (`GET /gateways`).
    pub struct GatewayInfo {
        /// The bridge.
        pub id: Uuid,
        /// Bridge name as shown in the cabinet.
        pub name: String,
        /// Pinged within the last 90 s.
        pub online: bool,
        /// Last gateway ping.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seen_at: Option<chrono::DateTime<chrono::Utc>>,
        /// Vaults the gateway holds that the caller can open too.
        pub vault_ids: Vec<Uuid>,
    }
}

schema! {
    /// `GET /gateways`.
    pub struct GatewayList {
        /// Gateways sharing a vault with the caller.
        pub gateways: Vec<GatewayInfo>,
    }
}
