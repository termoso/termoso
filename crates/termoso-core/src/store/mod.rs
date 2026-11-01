//! Encrypted local database.
//!
//! One SQLite file per profile. Layout (see `schema.sql`):
//!
//! * `vaults` – every vault this device knows: the always-present *local*
//!   vault (offline, never synced) plus personal/team vaults after sign-in.
//!   The vault key is stored wrapped with the device master key.
//! * `entities` – one row per entity, payload encrypted with the vault key in
//!   the exact envelope the server stores, so sync is a byte-for-byte copy.
//! * `history`, `session_logs` – same idea.
//! * `account` – the signed-in session (token and account private key wrapped
//!   with the master key).
//!
//! The master key never touches the database file; it comes from
//! [`crate::secrets`]. Losing it means losing the local database, which is why
//! the keychain fallback file is kept next to the database.

mod entities;
mod file_cache;
mod history;
mod logs;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use termoso_crypto::aead::{self, Aad};
use termoso_crypto::keys::{KeyPair, SymmetricKey};
use termoso_proto::vault::{VaultKind, VaultRole};
use uuid::Uuid;

use crate::error::{CoreError, Result};

pub use entities::EntityFilter;
pub use entities::EntityRow;
pub use file_cache::{CacheKind, CachedEntry, FileCacheConfig, FileCacheUsage, SafOfflineMode};
pub use history::{CommandHistory, ConnectionHistory, HistoryItem, VaultConnection};
pub use logs::{LogItem, LogMeta, LogRow, MAX_CAPTURE_BYTES, Recorder};

const SCHEMA: &str = include_str!("schema.sql");
const ACCOUNT_AVATAR: &str = "account_avatar";
const SCHEMA_VERSION: i64 = 4;

/// Schema 1 → 2: team session logs (per-vault logging flag and cursor,
/// author / pin / note on log rows).
const MIGRATE_V2: &str = "
BEGIN;
ALTER TABLE vaults ADD COLUMN session_logging INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vaults ADD COLUMN logs_cursor INTEGER NOT NULL DEFAULT 0;
ALTER TABLE session_logs ADD COLUMN author_id TEXT;
ALTER TABLE session_logs ADD COLUMN author TEXT;
ALTER TABLE session_logs ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0;
ALTER TABLE session_logs ADD COLUMN note TEXT NOT NULL DEFAULT '';
ALTER TABLE session_logs ADD COLUMN note_by TEXT;
COMMIT;";

/// Schema 2 → 3: the team's default (undeletable) vault flag.
const MIGRATE_V3: &str = "
BEGIN;
ALTER TABLE vaults ADD COLUMN is_default INTEGER NOT NULL DEFAULT 0;
COMMIT;";

/// v4 only adds tables; the `CREATE TABLE IF NOT EXISTS` schema covers it.
const MIGRATE_V4: &str = SCHEMA;

/// A vault as seen by this device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalVault {
    /// Id (server id for synced vaults, random for the local one).
    pub id: Uuid,
    /// Kind.
    pub kind: LocalVaultKind,
    /// Display name.
    pub name: String,
    /// Owning team for team vaults.
    pub team_id: Option<Uuid>,
    /// Our role.
    pub role: VaultRole,
    /// The vault key is available (unlocked).
    pub unlocked: bool,
    /// Key version of the key we hold.
    pub key_version: i32,
    /// Pull cursor.
    pub cursor: i64,
    /// Team vault records every member's sessions (manager setting).
    pub session_logging: bool,
    /// `GET /vaults/{id}/logs` cursor.
    pub logs_cursor: i64,
    /// The team's first vault: can be renamed but not deleted.
    pub is_default: bool,
}

/// Vault kind including the device-only local vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalVaultKind {
    /// Lives only on this device; never synced.
    Local,
    /// Personal vault of the signed-in account.
    Personal,
    /// Team vault.
    Team,
}

impl LocalVaultKind {
    fn as_str(self) -> &'static str {
        match self {
            LocalVaultKind::Local => "local",
            LocalVaultKind::Personal => "personal",
            LocalVaultKind::Team => "team",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "local" => LocalVaultKind::Local,
            "personal" => LocalVaultKind::Personal,
            "team" => LocalVaultKind::Team,
            other => return Err(CoreError::Invalid(format!("vault kind {other}"))),
        })
    }

    /// Whether this vault participates in sync.
    pub fn is_synced(self) -> bool {
        !matches!(self, LocalVaultKind::Local)
    }
}

impl From<VaultKind> for LocalVaultKind {
    fn from(k: VaultKind) -> Self {
        match k {
            VaultKind::Personal => LocalVaultKind::Personal,
            VaultKind::Team => LocalVaultKind::Team,
        }
    }
}

fn role_str(r: VaultRole) -> &'static str {
    match r {
        VaultRole::Manager => "manager",
        VaultRole::Editor => "editor",
        VaultRole::Viewer => "viewer",
    }
}

fn parse_role(s: &str) -> Result<VaultRole> {
    Ok(match s {
        "manager" => VaultRole::Manager,
        "editor" => VaultRole::Editor,
        "viewer" => VaultRole::Viewer,
        other => return Err(CoreError::Invalid(format!("vault role {other}"))),
    })
}

/// The signed-in account as persisted locally (never contains the password).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAccount {
    /// Server base URL (`https://termoso.example`).
    pub server_url: String,
    /// User id.
    pub user_id: Uuid,
    /// Email.
    pub email: String,
    /// Display name.
    pub display_name: Option<String>,
    /// Content tag of the profile picture (`UserProfile::avatar`).
    pub avatar: Option<String>,
    /// Server admin.
    pub is_admin: bool,
    /// Server-side device id of this installation.
    pub device_id: Uuid,
    /// X25519 public key (base64).
    pub public_key: String,
    /// Account key version.
    pub key_version: i32,
    /// History pull cursor.
    pub history_cursor: i64,
    /// Session-log pull cursor.
    pub logs_cursor: i64,
    /// When the session was established.
    pub signed_in_at: DateTime<Utc>,
}

/// Secret half of the account, only handed out to the sync/api layer.
pub struct AccountSecrets {
    /// Bearer token.
    pub token: String,
    /// Account private key.
    pub private_key: KeyPair,
}

/// Local database handle. Cheap to share behind an `Arc`.
pub struct Store {
    conn: Mutex<Connection>,
    master: SymmetricKey,
    keys: Mutex<HashMap<Uuid, SymmetricKey>>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Store")
    }
}

fn wrap_aad(vault_id: Uuid) -> Aad {
    Aad::label(&["local", "vault-key", &vault_id.to_string()])
}

fn token_aad() -> Aad {
    Aad::label(&["local", "session-token"])
}

fn private_key_aad() -> Aad {
    Aad::label(&["local", "account-private-key"])
}

impl Store {
    /// Open (or create) the database at `path` with the device master key.
    pub fn open(path: &Path, master: SymmetricKey) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Self::init(Connection::open(path)?, master)
    }

    /// The device master key this store was opened with (needed to re-wrap
    /// it, e.g. under a password). Never leaves the process.
    pub fn master_key(&self) -> &SymmetricKey {
        &self.master
    }

    /// In-memory database (tests, ephemeral profiles).
    pub fn open_in_memory(master: SymmetricKey) -> Result<Self> {
        Self::init(Connection::open_in_memory()?, master)
    }

    fn init(conn: Connection, master: SymmetricKey) -> Result<Self> {
        conn.execute_batch(SCHEMA)?;
        let store = Store {
            conn: Mutex::new(conn),
            master,
            keys: Mutex::new(HashMap::new()),
        };
        let version = store.meta("schema_version")?;
        match version.as_deref().map(|v| v.parse::<i64>().ok()) {
            None => store.set_meta("schema_version", &SCHEMA_VERSION.to_string())?,
            Some(Some(v)) if v == SCHEMA_VERSION => {}
            Some(Some(from)) if (1..SCHEMA_VERSION).contains(&from) => {
                if from < 2 {
                    store.conn().execute_batch(MIGRATE_V2)?;
                }
                if from < 3 {
                    store.conn().execute_batch(MIGRATE_V3)?;
                }
                if from < 4 {
                    store.conn().execute_batch(MIGRATE_V4)?;
                }
                store.set_meta("schema_version", &SCHEMA_VERSION.to_string())?;
            }
            Some(_) => {
                return Err(CoreError::Invalid(format!(
                    "database schema {} is newer than this client",
                    version.unwrap_or_default()
                )));
            }
        }
        if store.meta("device_id")?.is_none() {
            store.set_meta("device_id", &Uuid::new_v4().to_string())?;
        }
        store.ensure_local_vault()?;
        store.load_keys()?;
        Ok(store)
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Stable per-installation id, generated on first launch. Sent to the
    /// server as `client_device_id` so re-logins reuse the same device record.
    pub fn device_id(&self) -> Result<Uuid> {
        let s = self
            .meta("device_id")?
            .ok_or_else(|| CoreError::NotFound("device_id".into()))?;
        Uuid::parse_str(&s).map_err(|e| CoreError::Invalid(e.to_string()))
    }

    // ───────────────────────────── meta ─────────────────────────────

    /// Read a plaintext setting.
    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn()
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// Write a plaintext setting.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Read a setting that is encrypted with the master key.
    pub fn secret_meta(&self, key: &str) -> Result<Option<String>> {
        match self.meta(key)? {
            None => Ok(None),
            Some(ct) => Ok(Some(aead::decrypt_str(
                &self.master,
                &Aad::label(&["local", "meta", key]),
                &ct,
            )?)),
        }
    }

    /// Write a setting encrypted with the master key.
    pub fn set_secret_meta(&self, key: &str, value: &str) -> Result<()> {
        let ct = aead::encrypt_str(&self.master, &Aad::label(&["local", "meta", key]), value)?;
        self.set_meta(key, &ct)
    }

    /// Keys of every setting starting with `prefix`, sorted.
    pub fn meta_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut st =
            conn.prepare("SELECT key FROM meta WHERE substr(key, 1, ?2) = ?1 ORDER BY key")?;
        let rows = st.query_map(params![prefix, prefix.len() as i64], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Delete a setting.
    pub fn delete_meta(&self, key: &str) -> Result<()> {
        self.conn()
            .execute("DELETE FROM meta WHERE key = ?1", params![key])?;
        Ok(())
    }

    // ───────────────────────────── vaults ─────────────────────────────

    fn ensure_local_vault(&self) -> Result<()> {
        let exists: bool = self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM vaults WHERE kind = 'local')",
            [],
            |r| r.get(0),
        )?;
        if !exists {
            let id = Uuid::new_v4();
            let key = SymmetricKey::generate();
            let wrapped = aead::wrap_key(&self.master, &wrap_aad(id), &key)?;
            self.conn().execute(
                "INSERT INTO vaults (id, kind, name, team_id, role, wrapped_key, key_version, cursor, created_at)
                 VALUES (?1, 'local', 'Local', NULL, 'manager', ?2, 1, 0, ?3)",
                params![id.to_string(), wrapped, Utc::now().to_rfc3339()],
            )?;
        }
        Ok(())
    }

    fn load_keys(&self) -> Result<()> {
        let rows: Vec<(String, Option<String>)> = {
            let conn = self.conn();
            let mut st = conn.prepare("SELECT id, wrapped_key FROM vaults")?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut keys = self.keys.lock().unwrap_or_else(|p| p.into_inner());
        keys.clear();
        for (id, wrapped) in rows {
            let id = Uuid::parse_str(&id).map_err(|e| CoreError::Invalid(e.to_string()))?;
            if let Some(w) = wrapped {
                let key = aead::unwrap_key(&self.master, &wrap_aad(id), &w)?;
                keys.insert(id, key);
            }
        }
        Ok(())
    }

    /// Vault key, if unlocked.
    pub fn vault_key(&self, vault_id: Uuid) -> Result<SymmetricKey> {
        self.keys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&vault_id)
            .cloned()
            .ok_or(CoreError::VaultLocked(vault_id))
    }

    /// The device-local vault.
    pub fn local_vault(&self) -> Result<LocalVault> {
        self.vaults()?
            .into_iter()
            .find(|v| v.kind == LocalVaultKind::Local)
            .ok_or_else(|| CoreError::NotFound("local vault".into()))
    }

    /// Personal vault of the signed-in account, if any.
    pub fn personal_vault(&self) -> Result<Option<LocalVault>> {
        Ok(self
            .vaults()?
            .into_iter()
            .find(|v| v.kind == LocalVaultKind::Personal))
    }

    /// All vaults.
    pub fn vaults(&self) -> Result<Vec<LocalVault>> {
        let conn = self.conn();
        let mut st = conn.prepare(
            "SELECT id, kind, name, team_id, role, wrapped_key IS NOT NULL, key_version, cursor,
                    session_logging, logs_cursor, is_default
             FROM vaults ORDER BY kind = 'local' DESC, kind, name",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, bool>(5)?,
                r.get::<_, i32>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, bool>(8)?,
                r.get::<_, i64>(9)?,
                r.get::<_, bool>(10)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (
                id,
                kind,
                name,
                team_id,
                role,
                unlocked,
                key_version,
                cursor,
                session_logging,
                logs_cursor,
                is_default,
            ) = row?;
            out.push(LocalVault {
                id: parse_uuid(&id)?,
                kind: LocalVaultKind::parse(&kind)?,
                name,
                team_id: team_id.as_deref().map(parse_uuid).transpose()?,
                role: parse_role(&role)?,
                unlocked,
                key_version,
                cursor,
                session_logging,
                logs_cursor,
                is_default,
            });
        }
        Ok(out)
    }

    /// Single vault.
    pub fn vault(&self, id: Uuid) -> Result<LocalVault> {
        self.vaults()?
            .into_iter()
            .find(|v| v.id == id)
            .ok_or_else(|| CoreError::NotFound(format!("vault {id}")))
    }

    /// Insert or update a synced vault. `key` is `None` while our sealed key
    /// is pending; entities of such a vault stay ciphertext until a key
    /// arrives.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_vault(
        &self,
        id: Uuid,
        kind: LocalVaultKind,
        name: &str,
        team_id: Option<Uuid>,
        role: VaultRole,
        key: Option<&SymmetricKey>,
        key_version: i32,
    ) -> Result<()> {
        if kind == LocalVaultKind::Local {
            return Err(CoreError::Invalid("cannot upsert the local vault".into()));
        }
        let wrapped = key
            .map(|k| aead::wrap_key(&self.master, &wrap_aad(id), k))
            .transpose()?;
        self.conn().execute(
            "INSERT INTO vaults (id, kind, name, team_id, role, wrapped_key, key_version, cursor, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)
             ON CONFLICT(id) DO UPDATE SET
               kind = excluded.kind, name = excluded.name, team_id = excluded.team_id,
               role = excluded.role,
               wrapped_key = COALESCE(excluded.wrapped_key, vaults.wrapped_key),
               key_version = excluded.key_version",
            params![
                id.to_string(),
                kind.as_str(),
                name,
                team_id.map(|t| t.to_string()),
                role_str(role),
                wrapped,
                key_version,
                Utc::now().to_rfc3339(),
            ],
        )?;
        if let Some(k) = key {
            self.keys
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(id, k.clone());
        }
        Ok(())
    }

    /// Remove a synced vault and everything in it (we lost access).
    pub fn remove_vault(&self, id: Uuid) -> Result<()> {
        let v = self.vault(id)?;
        if v.kind == LocalVaultKind::Local {
            return Err(CoreError::Invalid("cannot remove the local vault".into()));
        }
        self.conn()
            .execute("DELETE FROM vaults WHERE id = ?1", params![id.to_string()])?;
        self.keys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id);
        Ok(())
    }

    /// Update the pull cursor for a vault.
    pub fn set_vault_cursor(&self, id: Uuid, cursor: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE vaults SET cursor = ?2 WHERE id = ?1",
            params![id.to_string(), cursor],
        )?;
        Ok(())
    }

    /// Update the team-logs pull cursor for a vault.
    pub fn set_vault_logs_cursor(&self, id: Uuid, cursor: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE vaults SET logs_cursor = ?2 WHERE id = ?1",
            params![id.to_string(), cursor],
        )?;
        Ok(())
    }

    /// Mirror the server's per-vault session logging flag.
    pub fn set_vault_session_logging(&self, id: Uuid, on: bool) -> Result<()> {
        self.conn().execute(
            "UPDATE vaults SET session_logging = ?2 WHERE id = ?1",
            params![id.to_string(), on],
        )?;
        Ok(())
    }

    /// Mirror the server's default-vault flag.
    pub fn set_vault_default(&self, id: Uuid, on: bool) -> Result<()> {
        self.conn().execute(
            "UPDATE vaults SET is_default = ?2 WHERE id = ?1",
            params![id.to_string(), on],
        )?;
        Ok(())
    }

    // ───────────────────────────── account ─────────────────────────────

    /// The signed-in account, if any.
    pub fn account(&self) -> Result<Option<StoredAccount>> {
        let avatar = self.meta(ACCOUNT_AVATAR)?;
        let conn = self.conn();
        conn.query_row(
            "SELECT server_url, user_id, email, display_name, is_admin, device_id, public_key,
                    key_version, history_cursor, logs_cursor, signed_in_at
             FROM account WHERE id = 1",
            [],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, bool>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i32>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, i64>(9)?,
                    r.get::<_, String>(10)?,
                ))
            },
        )
        .optional()?
        .map(
            |(
                server_url,
                user_id,
                email,
                display_name,
                is_admin,
                device_id,
                public_key,
                key_version,
                history_cursor,
                logs_cursor,
                signed_in_at,
            )| {
                Ok(StoredAccount {
                    server_url,
                    user_id: parse_uuid(&user_id)?,
                    email,
                    display_name,
                    avatar,
                    is_admin,
                    device_id: parse_uuid(&device_id)?,
                    public_key,
                    key_version,
                    history_cursor,
                    logs_cursor,
                    signed_in_at: parse_time(&signed_in_at)?,
                })
            },
        )
        .transpose()
    }

    /// Token and private key of the signed-in account.
    pub fn account_secrets(&self) -> Result<AccountSecrets> {
        let (token, wrapped): (String, String) = self
            .conn()
            .query_row(
                "SELECT token, wrapped_private_key FROM account WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(CoreError::NotSignedIn)?;
        let token = aead::decrypt_str(&self.master, &token_aad(), &token)?;
        let sk = aead::decrypt_b64(&self.master, &private_key_aad(), &wrapped)?;
        Ok(AccountSecrets {
            token,
            private_key: KeyPair::from_secret_bytes(&sk)?,
        })
    }

    /// Persist a freshly authenticated session.
    pub fn save_account(
        &self,
        account: &StoredAccount,
        token: &str,
        private_key: &KeyPair,
    ) -> Result<()> {
        let token_ct = aead::encrypt_str(&self.master, &token_aad(), token)?;
        let sk_ct = aead::encrypt_b64(
            &self.master,
            &private_key_aad(),
            &private_key.secret_bytes(),
        )?;
        self.conn().execute(
            "INSERT INTO account (id, server_url, user_id, email, display_name, is_admin, device_id, token,
                                  public_key, wrapped_private_key, key_version, history_cursor, logs_cursor, signed_in_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(id) DO UPDATE SET
               server_url = excluded.server_url, user_id = excluded.user_id, email = excluded.email,
               display_name = excluded.display_name, is_admin = excluded.is_admin, device_id = excluded.device_id,
               token = excluded.token, public_key = excluded.public_key,
               wrapped_private_key = excluded.wrapped_private_key, key_version = excluded.key_version,
               signed_in_at = excluded.signed_in_at",
            params![
                account.server_url,
                account.user_id.to_string(),
                account.email,
                account.display_name,
                account.is_admin,
                account.device_id.to_string(),
                token_ct,
                account.public_key,
                sk_ct,
                account.key_version,
                account.history_cursor,
                account.logs_cursor,
                account.signed_in_at.to_rfc3339(),
            ],
        )?;
        self.set_account_avatar(account.avatar.as_deref())
    }

    /// Update the profile fields after a `GET /account`.
    pub fn update_account_profile(
        &self,
        email: &str,
        display_name: Option<&str>,
        avatar: Option<&str>,
        is_admin: bool,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE account SET email = ?1, display_name = ?2, is_admin = ?3 WHERE id = 1",
            params![email, display_name, is_admin],
        )?;
        self.set_account_avatar(avatar)
    }

    fn set_account_avatar(&self, avatar: Option<&str>) -> Result<()> {
        match avatar {
            Some(tag) => self.set_meta(ACCOUNT_AVATAR, tag),
            None => self.delete_meta(ACCOUNT_AVATAR),
        }
    }

    /// Update the history / logs cursors.
    pub fn set_account_cursors(&self, history: Option<i64>, logs: Option<i64>) -> Result<()> {
        self.conn().execute(
            "UPDATE account SET history_cursor = COALESCE(?1, history_cursor),
                                logs_cursor = COALESCE(?2, logs_cursor) WHERE id = 1",
            params![history, logs],
        )?;
        Ok(())
    }

    /// Sign out: forget the session, account keys and every synced vault. The
    /// local vault is untouched.
    pub fn clear_account(&self) -> Result<()> {
        {
            let conn = self.conn();
            conn.execute("DELETE FROM account", [])?;
            conn.execute("DELETE FROM vaults WHERE kind <> 'local'", [])?;
        }
        self.delete_meta(ACCOUNT_AVATAR)?;
        self.load_keys()
    }

    /// Wipe every synced record but keep the account (used when the vault key
    /// version changed and everything must be re-pulled).
    pub fn reset_sync_state(&self) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM entities WHERE vault_id IN (SELECT id FROM vaults WHERE kind <> 'local')",
            [],
        )?;
        conn.execute(
            "UPDATE vaults SET cursor = 0, logs_cursor = 0 WHERE kind <> 'local'",
            [],
        )?;
        Ok(())
    }

    /// Re-encrypt every row with a new master key (keychain rotation).
    pub fn rekey(&mut self, new_master: SymmetricKey) -> Result<()> {
        let keys: Vec<(Uuid, SymmetricKey)> = self
            .keys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let account = self.account_secrets().ok();
        let secret_meta: Vec<(String, String)> = {
            let conn = self.conn();
            let mut st = conn.prepare("SELECT key, value FROM meta WHERE key LIKE 'secret:%'")?;
            st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let old = std::mem::replace(&mut self.master, new_master);
        let conn = self.conn();
        for (id, key) in keys {
            let wrapped = aead::wrap_key(&self.master, &wrap_aad(id), &key)?;
            conn.execute(
                "UPDATE vaults SET wrapped_key = ?2 WHERE id = ?1",
                params![id.to_string(), wrapped],
            )?;
        }
        if let Some(a) = account {
            let token_ct = aead::encrypt_str(&self.master, &token_aad(), &a.token)?;
            let sk_ct = aead::encrypt_b64(
                &self.master,
                &private_key_aad(),
                &a.private_key.secret_bytes(),
            )?;
            conn.execute(
                "UPDATE account SET token = ?1, wrapped_private_key = ?2 WHERE id = 1",
                params![token_ct, sk_ct],
            )?;
        }
        for (key, ct) in secret_meta {
            let aad = Aad::label(&["local", "meta", &key]);
            let pt = aead::decrypt_str(&old, &aad, &ct)?;
            let ct = aead::encrypt_str(&self.master, &aad, &pt)?;
            conn.execute(
                "UPDATE meta SET value = ?2 WHERE key = ?1",
                params![key, ct],
            )?;
        }
        Ok(())
    }
}

pub(crate) fn parse_uuid(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| CoreError::Invalid(format!("uuid: {e}")))
}

pub(crate) fn parse_time(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| CoreError::Invalid(format!("timestamp: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_local_vault_and_device_id() {
        let store = Store::open_in_memory(SymmetricKey::generate()).unwrap();
        let local = store.local_vault().unwrap();
        assert_eq!(local.kind, LocalVaultKind::Local);
        assert!(local.unlocked);
        assert!(store.vault_key(local.id).is_ok());
        assert_eq!(store.device_id().unwrap(), store.device_id().unwrap());
    }

    #[test]
    fn reopening_with_wrong_master_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let master = SymmetricKey::generate();
        {
            let store = Store::open(&path, master.clone()).unwrap();
            store.set_secret_meta("secret:x", "hello").unwrap();
        }
        let ok = Store::open(&path, master).unwrap();
        assert_eq!(
            ok.secret_meta("secret:x").unwrap().as_deref(),
            Some("hello")
        );
        assert!(Store::open(&path, SymmetricKey::generate()).is_err());
    }

    #[test]
    fn account_roundtrip_and_sign_out() {
        let store = Store::open_in_memory(SymmetricKey::generate()).unwrap();
        assert!(store.account().unwrap().is_none());
        assert!(matches!(
            store.account_secrets(),
            Err(CoreError::NotSignedIn)
        ));
        let kp = KeyPair::generate();
        let acc = StoredAccount {
            server_url: "https://t.example".into(),
            user_id: Uuid::new_v4(),
            email: "a@b.c".into(),
            display_name: None,
            avatar: None,
            is_admin: false,
            device_id: Uuid::new_v4(),
            public_key: kp.public_b64(),
            key_version: 1,
            history_cursor: 0,
            logs_cursor: 0,
            signed_in_at: Utc::now(),
        };
        store.save_account(&acc, "tok", &kp).unwrap();
        let vk = SymmetricKey::generate();
        let vid = Uuid::new_v4();
        store
            .upsert_vault(
                vid,
                LocalVaultKind::Personal,
                "Personal",
                None,
                VaultRole::Manager,
                Some(&vk),
                1,
            )
            .unwrap();
        let s = store.account_secrets().unwrap();
        assert_eq!(s.token, "tok");
        assert_eq!(s.private_key.public_b64(), kp.public_b64());
        assert_eq!(store.vault_key(vid).unwrap().as_bytes(), vk.as_bytes());
        assert_eq!(store.vaults().unwrap().len(), 2);
        // A credential that never reached the server (credential sync off)
        // lives and dies with the account like every other synced row.
        let local_only = store
            .insert(
                vid,
                &crate::model::Identity {
                    label: "local".into(),
                    username: "root".into(),
                    password: Some("secret".into()),
                    ..crate::model::Identity::default()
                },
            )
            .unwrap();
        assert_eq!(store.row(local_only).unwrap().unwrap().version, 0);

        store.clear_account().unwrap();
        assert!(store.account().unwrap().is_none());
        assert_eq!(store.vaults().unwrap().len(), 1);
        assert!(store.row(local_only).unwrap().is_none());
        assert!(matches!(
            store.vault_key(vid),
            Err(CoreError::VaultLocked(_))
        ));
    }

    #[test]
    fn migrates_schema_v1_databases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let master = SymmetricKey::generate();
        let local_id;
        let log_id;
        {
            let store = Store::open(&path, master.clone()).unwrap();
            local_id = store.local_vault().unwrap().id;
            log_id = store
                .begin_log(
                    local_id,
                    &crate::store::LogMeta {
                        host_id: None,
                        label: "old".into(),
                        target: "local".into(),
                        protocol: "local".into(),
                        started_at: Utc::now(),
                        ended_at: None,
                        cols: 80,
                        rows: 24,
                    },
                )
                .unwrap();
            // Strip everything schema 2 added, as a client from before it
            // would have left the file.
            store
                .conn()
                .execute_batch(
                    "ALTER TABLE vaults DROP COLUMN is_default;
                     ALTER TABLE vaults DROP COLUMN session_logging;
                     ALTER TABLE vaults DROP COLUMN logs_cursor;
                     ALTER TABLE session_logs DROP COLUMN author_id;
                     ALTER TABLE session_logs DROP COLUMN author;
                     ALTER TABLE session_logs DROP COLUMN pinned;
                     ALTER TABLE session_logs DROP COLUMN note;
                     ALTER TABLE session_logs DROP COLUMN note_by;",
                )
                .unwrap();
            store.set_meta("schema_version", "1").unwrap();
        }
        let store = Store::open(&path, master.clone()).unwrap();
        assert_eq!(
            store.meta("schema_version").unwrap().as_deref(),
            Some(&*SCHEMA_VERSION.to_string())
        );
        let local = store.local_vault().unwrap();
        assert_eq!(local.id, local_id);
        assert!(!local.session_logging);
        assert!(!local.is_default);
        assert_eq!(local.logs_cursor, 0);
        let logs = store.logs().unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].id, log_id);
        assert!(logs[0].mine && !logs[0].pinned && logs[0].note.is_empty());
        assert!(logs[0].author.is_none());
        // Reopening an already migrated file is a no-op.
        drop(store);
        Store::open(&path, master).unwrap();
    }

    #[test]
    fn rekey_preserves_everything() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let m1 = SymmetricKey::generate();
        let m2 = SymmetricKey::generate();
        let local_id;
        {
            let mut store = Store::open(&path, m1).unwrap();
            local_id = store.local_vault().unwrap().id;
            store.set_secret_meta("secret:a", "v").unwrap();
            store.rekey(m2.clone()).unwrap();
        }
        let store = Store::open(&path, m2).unwrap();
        assert_eq!(store.local_vault().unwrap().id, local_id);
        assert_eq!(store.secret_meta("secret:a").unwrap().as_deref(), Some("v"));
    }
}
