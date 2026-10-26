//! Entity CRUD and the raw rows the sync engine works with.

use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, params};
use serde::de::DeserializeOwned;
use termoso_crypto::aead::{self, Aad};
use termoso_proto::entities::SyncEntity;
use termoso_proto::entities::is_known_kind;
use termoso_proto::sync::{EntityChange, EntityDelete};
use termoso_proto::vault::VaultRole;
use uuid::Uuid;

use super::{LocalVault, Store, parse_time, parse_uuid};
use crate::error::{CoreError, Result};
use crate::model::{
    AnyEntity, Entity, Group, Host, Identity, Payload, Proxy, ResolvedHost, SerialConfig,
    SshCertificate, SshConfig, SshKey, Tag, TagHost, TelnetConfig, WebDavConfig,
};

/// Raw local row (ciphertext), as the sync engine sees it.
#[derive(Debug, Clone)]
pub struct EntityRow {
    /// Id.
    pub id: Uuid,
    /// Kind.
    pub kind: String,
    /// Vault.
    pub vault_id: Uuid,
    /// Server version (0 = never pushed).
    pub version: i64,
    /// Server seq.
    pub seq: i64,
    /// Tombstone.
    pub deleted: bool,
    /// Key version.
    pub key_version: i32,
    /// Envelope.
    pub data: String,
    /// Last change.
    pub updated_at: DateTime<Utc>,
    /// Local changes pending.
    pub dirty: bool,
}

impl EntityRow {
    /// Build the push item for this row.
    pub fn to_change(&self) -> EntityChange {
        EntityChange {
            secret_rotated_at: None,
            id: self.id,
            kind: self.kind.clone(),
            vault_id: self.vault_id,
            base_version: (self.version > 0).then_some(self.version),
            key_version: self.key_version,
            data: self.data.clone(),
            updated_at: self.updated_at,
        }
    }

    /// Build the delete item for this row (only meaningful when `version > 0`).
    pub fn to_delete(&self) -> EntityDelete {
        EntityDelete {
            id: self.id,
            base_version: self.version,
        }
    }
}

/// Listing filter.
#[derive(Debug, Clone, Default)]
pub struct EntityFilter {
    /// Restrict to a vault.
    pub vault_id: Option<Uuid>,
    /// Restrict to a kind.
    pub kind: Option<String>,
    /// Include tombstones.
    pub include_deleted: bool,
}

const SELECT: &str = "SELECT id, kind, vault_id, version, seq, deleted, key_version, data, updated_at, dirty FROM entities";

type RawRow = (
    String,
    String,
    String,
    i64,
    i64,
    bool,
    i32,
    String,
    String,
    bool,
);

fn row_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawRow> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
    ))
}

fn into_row(
    t: (
        String,
        String,
        String,
        i64,
        i64,
        bool,
        i32,
        String,
        String,
        bool,
    ),
) -> Result<EntityRow> {
    Ok(EntityRow {
        id: parse_uuid(&t.0)?,
        kind: t.1,
        vault_id: parse_uuid(&t.2)?,
        version: t.3,
        seq: t.4,
        deleted: t.5,
        key_version: t.6,
        data: t.7,
        updated_at: parse_time(&t.8)?,
        dirty: t.9,
    })
}

impl Store {
    /// The vault, provided our role there allows local edits. Viewers get
    /// `VaultReadOnly` before anything is written, so the store never holds
    /// changes the server would reject on push.
    fn writable_vault(&self, vault_id: Uuid) -> Result<LocalVault> {
        let vault = self.vault(vault_id)?;
        if vault.kind.is_synced() && vault.role == VaultRole::Viewer {
            return Err(CoreError::VaultReadOnly(vault_id));
        }
        Ok(vault)
    }

    fn encrypt_payload<T: serde::Serialize>(
        &self,
        vault_id: Uuid,
        kind: &str,
        id: Uuid,
        data: &T,
    ) -> Result<(String, i32)> {
        let key = self.vault_key(vault_id)?;
        let key_version = self.vault(vault_id)?.key_version;
        let plaintext = serde_json::to_string(data)?;
        let ct = aead::encrypt_str(&key, &Aad::entity(kind, &id.to_string()), &plaintext)?;
        Ok((ct, key_version))
    }

    fn decrypt_row<T: DeserializeOwned>(&self, row: &EntityRow) -> Result<Entity<T>> {
        let key = self.vault_key(row.vault_id)?;
        let plaintext = aead::decrypt_str(
            &key,
            &Aad::entity(&row.kind, &row.id.to_string()),
            &row.data,
        )?;
        Ok(Entity {
            id: row.id,
            vault_id: row.vault_id,
            version: row.version,
            updated_at: row.updated_at,
            dirty: row.dirty,
            data: serde_json::from_str(&plaintext)?,
        })
    }

    // ───────────────────────────── typed API ─────────────────────────────

    /// Create a new entity; returns its id.
    pub fn insert<T: Payload>(&self, vault_id: Uuid, data: &T) -> Result<Uuid> {
        let id = Uuid::new_v4();
        self.put_with_id(vault_id, id, data)?;
        Ok(id)
    }

    /// Create or replace an entity with a caller-chosen id.
    pub fn put_with_id<T: Payload>(&self, vault_id: Uuid, id: Uuid, data: &T) -> Result<()> {
        self.put_raw(vault_id, T::KIND, id, data)
    }

    /// Update an existing entity's payload (marks it dirty).
    pub fn update<T: Payload>(&self, id: Uuid, data: &T) -> Result<()> {
        let row = self
            .row(id)?
            .ok_or_else(|| CoreError::NotFound(format!("entity {id}")))?;
        if row.kind != T::KIND {
            return Err(CoreError::Invalid(format!(
                "entity {id} is a {}, not {}",
                row.kind,
                T::KIND
            )));
        }
        self.put_raw(row.vault_id, T::KIND, id, data)
    }

    /// Insert/update an entity whose payload is arbitrary JSON.
    pub fn put_raw<T: serde::Serialize>(
        &self,
        vault_id: Uuid,
        kind: &str,
        id: Uuid,
        data: &T,
    ) -> Result<()> {
        if !is_known_kind(kind) {
            return Err(CoreError::Invalid(format!("unknown entity kind {kind}")));
        }
        let (ct, key_version) = self.encrypt_payload(vault_id, kind, id, data)?;
        let dirty = self.writable_vault(vault_id)?.kind.is_synced();
        self.conn().execute(
            "INSERT INTO entities (id, kind, vault_id, version, seq, deleted, key_version, data, updated_at, dirty)
             VALUES (?1, ?2, ?3, 0, 0, 0, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
               kind = excluded.kind, vault_id = excluded.vault_id, deleted = 0,
               key_version = excluded.key_version, data = excluded.data,
               updated_at = excluded.updated_at, dirty = excluded.dirty",
            params![
                id.to_string(),
                kind,
                vault_id.to_string(),
                key_version,
                ct,
                Utc::now().to_rfc3339(),
                dirty,
            ],
        )?;
        Ok(())
    }

    /// Fetch one entity.
    pub fn get<T: Payload>(&self, id: Uuid) -> Result<Option<Entity<T>>> {
        match self.row(id)? {
            Some(row) if !row.deleted && row.kind == T::KIND => Ok(Some(self.decrypt_row(&row)?)),
            _ => Ok(None),
        }
    }

    /// Fetch one entity or fail.
    pub fn require<T: Payload>(&self, id: Uuid) -> Result<Entity<T>> {
        self.get::<T>(id)?
            .ok_or_else(|| CoreError::NotFound(format!("{} {id}", T::KIND)))
    }

    /// Follow a reference held by an entity of `vault_id`. Vaults are trust
    /// boundaries: a reference into another vault is refused, not followed,
    /// so a record can never borrow credentials, proxies or jump hosts that
    /// live elsewhere. The check reads plaintext metadata, so it also holds
    /// for locked vaults.
    pub fn get_in<T: Payload>(&self, id: Uuid, vault_id: Uuid) -> Result<Option<Entity<T>>> {
        match self.row(id)? {
            Some(row) if !row.deleted && row.kind == T::KIND => {
                if row.vault_id != vault_id {
                    return Err(CoreError::Invalid(format!(
                        "{} {id} belongs to another vault",
                        T::KIND
                    )));
                }
                Ok(Some(self.decrypt_row(&row)?))
            }
            _ => Ok(None),
        }
    }

    /// [`Self::get_in`] or fail.
    pub fn require_in<T: Payload>(&self, id: Uuid, vault_id: Uuid) -> Result<Entity<T>> {
        self.get_in::<T>(id, vault_id)?
            .ok_or_else(|| CoreError::NotFound(format!("{} {id}", T::KIND)))
    }

    /// Fetch a host that the caller expects to find in `vault_id`; a host
    /// from any other vault is refused. `None` skips the check.
    pub fn require_host_in(&self, host_id: Uuid, vault_id: Option<Uuid>) -> Result<Entity<Host>> {
        match vault_id {
            Some(v) => self.require_in::<Host>(host_id, v),
            None => self.require::<Host>(host_id),
        }
    }

    /// List entities of a kind. `vault_id = None` lists across all unlocked
    /// vaults; entities in locked vaults are skipped.
    pub fn list<T: Payload>(&self, vault_id: Option<Uuid>) -> Result<Vec<Entity<T>>> {
        let rows = self.rows(&EntityFilter {
            vault_id,
            kind: Some(T::KIND.to_string()),
            include_deleted: false,
        })?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            match self.decrypt_row::<T>(&row) {
                Ok(e) => out.push(e),
                Err(CoreError::VaultLocked(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Fetch one entity of any kind as a JSON payload.
    pub fn get_any(&self, id: Uuid) -> Result<Option<AnyEntity>> {
        match self.row(id)? {
            Some(row) if !row.deleted => Ok(Some(self.decrypt_row::<serde_json::Value>(&row)?)),
            _ => Ok(None),
        }
    }

    /// List entities of any kind as JSON payloads.
    pub fn list_any(&self, filter: &EntityFilter) -> Result<Vec<AnyEntity>> {
        let rows = self.rows(filter)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            if row.deleted {
                continue;
            }
            match self.decrypt_row::<serde_json::Value>(&row) {
                Ok(e) => out.push(e),
                Err(CoreError::VaultLocked(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Delete an entity. Synced entities become dirty tombstones until pushed;
    /// local-vault and never-pushed entities are removed immediately.
    pub fn delete(&self, id: Uuid) -> Result<()> {
        let Some(row) = self.row(id)? else {
            return Ok(());
        };
        let synced = self.writable_vault(row.vault_id)?.kind.is_synced();
        let conn = self.conn();
        if synced && row.version > 0 {
            conn.execute(
                "UPDATE entities SET deleted = 1, dirty = 1, data = '', updated_at = ?2 WHERE id = ?1",
                params![id.to_string(), Utc::now().to_rfc3339()],
            )?;
        } else {
            conn.execute(
                "DELETE FROM entities WHERE id = ?1",
                params![id.to_string()],
            )?;
        }
        Ok(())
    }

    /// Move an entity to another vault (re-encrypts; old copy becomes a tombstone).
    pub fn move_to_vault(&self, id: Uuid, vault_id: Uuid) -> Result<Uuid> {
        let row = self
            .row(id)?
            .ok_or_else(|| CoreError::NotFound(format!("entity {id}")))?;
        let value: Entity<serde_json::Value> = self.decrypt_row(&row)?;
        let new_id = Uuid::new_v4();
        self.put_raw(vault_id, &row.kind, new_id, &value.data)?;
        self.delete(id)?;
        Ok(new_id)
    }

    // ───────────────────────────── raw rows (sync) ─────────────────────────────

    /// Raw row by id.
    pub fn row(&self, id: Uuid) -> Result<Option<EntityRow>> {
        let conn = self.conn();
        conn.query_row(
            &format!("{SELECT} WHERE id = ?1"),
            params![id.to_string()],
            row_from,
        )
        .optional()?
        .map(into_row)
        .transpose()
    }

    /// Raw rows matching a filter.
    pub fn rows(&self, filter: &EntityFilter) -> Result<Vec<EntityRow>> {
        let mut sql = format!("{SELECT} WHERE 1 = 1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(v) = filter.vault_id {
            sql.push_str(" AND vault_id = ?");
            args.push(Box::new(v.to_string()));
        }
        if let Some(k) = &filter.kind {
            sql.push_str(" AND kind = ?");
            args.push(Box::new(k.clone()));
        }
        if !filter.include_deleted {
            sql.push_str(" AND deleted = 0");
        }
        sql.push_str(" ORDER BY updated_at DESC");
        let conn = self.conn();
        let mut st = conn.prepare(&sql)?;
        let rows = st.query_map(
            rusqlite::params_from_iter(args.iter().map(|a| a.as_ref())),
            row_from,
        )?;
        rows.map(|r| r.map_err(CoreError::from).and_then(into_row))
            .collect()
    }

    /// Rows with local changes to push, oldest first.
    pub fn dirty_rows(&self, vault_id: Uuid) -> Result<Vec<EntityRow>> {
        let conn = self.conn();
        let mut st = conn.prepare(&format!(
            "{SELECT} WHERE vault_id = ?1 AND dirty = 1 ORDER BY updated_at ASC"
        ))?;
        let rows = st.query_map(params![vault_id.to_string()], row_from)?;
        rows.map(|r| r.map_err(CoreError::from).and_then(into_row))
            .collect()
    }

    /// Record a successful push: adopt server version/seq, clear dirty.
    pub fn mark_pushed(&self, id: Uuid, version: i64, seq: i64) -> Result<()> {
        let conn = self.conn();
        let removed = conn.execute(
            "DELETE FROM entities WHERE id = ?1 AND deleted = 1",
            params![id.to_string()],
        )?;
        if removed == 0 {
            conn.execute(
                "UPDATE entities SET version = ?2, seq = ?3, dirty = 0 WHERE id = ?1",
                params![id.to_string(), version, seq],
            )?;
        }
        Ok(())
    }

    /// Overwrite the local row with the server copy (clears dirty). Tombstones
    /// are removed outright.
    pub fn apply_remote(&self, e: &SyncEntity) -> Result<()> {
        let conn = self.conn();
        if e.deleted {
            conn.execute(
                "DELETE FROM entities WHERE id = ?1",
                params![e.id.to_string()],
            )?;
            return Ok(());
        }
        conn.execute(
            "INSERT INTO entities (id, kind, vault_id, version, seq, deleted, key_version, data, updated_at, dirty)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, 0)
             ON CONFLICT(id) DO UPDATE SET
               kind = excluded.kind, vault_id = excluded.vault_id, version = excluded.version,
               seq = excluded.seq, deleted = 0, key_version = excluded.key_version,
               data = excluded.data, updated_at = excluded.updated_at, dirty = 0",
            params![
                e.id.to_string(),
                e.kind,
                e.vault_id.to_string(),
                e.version,
                e.seq,
                e.key_version,
                e.data,
                e.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Keep the local payload but rebase it on the server version so the next
    /// push succeeds (local wins in a conflict).
    pub fn rebase_local(&self, id: Uuid, server_version: i64, server_seq: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE entities SET version = ?2, seq = ?3, dirty = 1 WHERE id = ?1",
            params![id.to_string(), server_version, server_seq],
        )?;
        Ok(())
    }

    /// Number of dirty rows across synced vaults.
    pub fn pending_changes(&self) -> Result<u64> {
        let n: i64 =
            self.conn()
                .query_row("SELECT COUNT(*) FROM entities WHERE dirty = 1", [], |r| {
                    r.get(0)
                })?;
        Ok(n as u64)
    }

    /// Re-encrypt every entity of a vault under its current key (after a key
    /// rotation) and mark them dirty so they are re-pushed.
    pub fn reencrypt_vault(
        &self,
        vault_id: Uuid,
        old_key: &termoso_crypto::keys::SymmetricKey,
    ) -> Result<usize> {
        let new_key = self.vault_key(vault_id)?;
        let key_version = self.vault(vault_id)?.key_version;
        let rows = self.rows(&EntityFilter {
            vault_id: Some(vault_id),
            kind: None,
            include_deleted: false,
        })?;
        let conn = self.conn();
        let mut done = 0;
        for row in rows.iter().filter(|r| r.key_version != key_version) {
            let aad = Aad::entity(&row.kind, &row.id.to_string());
            // Rows we cannot open with the previous key are left untouched:
            // a peer may already have re-uploaded them and a later pull wins.
            let Ok(pt) = aead::decrypt(old_key, &aad, &termoso_crypto::encoding::unb64(&row.data)?)
            else {
                continue;
            };
            let ct = aead::encrypt_b64(&new_key, &aad, &pt)?;
            conn.execute(
                "UPDATE entities SET data = ?2, key_version = ?3, dirty = 1 WHERE id = ?1",
                params![row.id.to_string(), ct, key_version],
            )?;
            done += 1;
        }
        Ok(done)
    }

    // ───────────────────────────── host resolution ─────────────────────────────

    /// Effective SSH config a host placed in `group_id` inherits from its
    /// group chain (nearer groups win), plus the group path root → leaf.
    pub fn resolve_group_ssh(&self, group_id: Uuid) -> Result<(SshConfig, Vec<String>)> {
        let group = self.require::<Group>(group_id)?;
        let groups: Vec<Entity<Group>> = self.list(Some(group.vault_id))?;
        let mut path = Vec::new();
        let mut chain: Vec<Uuid> = Vec::new();
        let mut cursor = Some(group_id);
        let mut hops = 0;
        while let Some(gid) = cursor {
            hops += 1;
            if hops > 64 {
                break;
            }
            let Some(g) = groups.iter().find(|g| g.id == gid) else {
                break;
            };
            path.push(g.data.label.clone());
            chain.extend(g.data.ssh_config_id);
            cursor = g.data.parent_id;
        }
        path.reverse();
        let mut ssh = SshConfig::default();
        for cid in chain.iter().rev() {
            if let Some(c) = self.get_in::<SshConfig>(*cid, group.vault_id)? {
                merge_ssh(&mut ssh, &c.data);
            }
        }
        Ok((ssh, path))
    }

    /// Resolve everything needed to connect to a host. Every record the host
    /// points at (configs, identity, key, certificate, proxy, jump hosts)
    /// must live in the host's own vault; see [`Self::get_in`].
    pub fn resolve_host(&self, host_id: Uuid) -> Result<ResolvedHost> {
        self.resolve_host_in(host_id, None)
    }

    /// [`Self::resolve_host`] for a host the caller expects in `vault_id`.
    pub fn resolve_host_in(&self, host_id: Uuid, vault_id: Option<Uuid>) -> Result<ResolvedHost> {
        let host = self.require_host_in(host_id, vault_id)?;
        let vault = host.vault_id;
        let groups: Vec<Entity<Group>> = self.list(Some(vault))?;

        // Walk the group chain root-ward collecting configs.
        let mut group_path = Vec::new();
        let mut chain_ssh: Vec<Uuid> = Vec::new();
        let mut chain_telnet: Vec<Uuid> = Vec::new();
        let mut cursor = host.data.group_id;
        let mut hops = 0;
        while let Some(gid) = cursor {
            hops += 1;
            if hops > 64 {
                break;
            }
            let Some(g) = groups.iter().find(|g| g.id == gid) else {
                break;
            };
            group_path.push(g.data.label.clone());
            if let Some(c) = g.data.ssh_config_id {
                chain_ssh.push(c);
            }
            if let Some(c) = g.data.telnet_config_id {
                chain_telnet.push(c);
            }
            cursor = g.data.parent_id;
        }
        group_path.reverse();

        let mut ssh = SshConfig::default();
        // Apply from the root group down to the host so nearer configs win.
        for cid in chain_ssh.iter().rev().chain(host.data.ssh_config_id.iter()) {
            if let Some(c) = self.get_in::<SshConfig>(*cid, vault)? {
                merge_ssh(&mut ssh, &c.data);
            }
        }
        let telnet = if host.data.telnet_config_id.is_some() || !chain_telnet.is_empty() {
            let mut t = TelnetConfig::default();
            for cid in chain_telnet
                .iter()
                .rev()
                .chain(host.data.telnet_config_id.iter())
            {
                if let Some(c) = self.get_in::<TelnetConfig>(*cid, vault)? {
                    if c.data.port.is_some() {
                        t.port = c.data.port;
                    }
                    if c.data.identity_id.is_some() {
                        t.identity_id = c.data.identity_id;
                    }
                    if c.data.charset.is_some() {
                        t.charset = c.data.charset.clone();
                    }
                    if c.data.color_scheme.is_some() {
                        t.color_scheme = c.data.color_scheme.clone();
                    }
                }
            }
            Some(t)
        } else {
            None
        };

        let serial = match host.data.serial_config_id {
            Some(cid) if host.data.ssh_config_id.is_none() => {
                self.get_in::<SerialConfig>(cid, vault)?.map(|c| c.data)
            }
            _ => None,
        };

        let webdav = match host.data.webdav_config_id {
            Some(cid) => self.get_in::<WebDavConfig>(cid, vault)?.map(|c| c.data),
            None => None,
        };
        let webdav_identity = match webdav.as_ref().and_then(|w| w.identity_id) {
            Some(id) => self.get_in::<Identity>(id, vault)?,
            None => None,
        };

        let identity_id = ssh.identity_id.or_else(|| {
            if host.data.ssh_config_id.is_none() {
                telnet.as_ref().and_then(|t| t.identity_id)
            } else {
                None
            }
        });
        let identity = match identity_id {
            Some(id) => self.get_in::<Identity>(id, vault)?,
            None => None,
        };
        let key = match identity.as_ref().and_then(|i| i.data.ssh_key_id) {
            Some(id) => self.get_in::<SshKey>(id, vault)?,
            None => None,
        };
        // Certificates live next to their key: an explicit identity reference
        // wins, otherwise the certificate attached to the key is used.
        let certificate = match identity.as_ref().and_then(|i| i.data.ssh_certificate_id) {
            Some(id) => self.get_in::<SshCertificate>(id, vault)?,
            None => match &key {
                Some(k) => self
                    .list::<SshCertificate>(Some(vault))?
                    .into_iter()
                    .find(|c| c.data.ssh_key_id == Some(k.id)),
                None => None,
            },
        };
        let ssh_id_handle = match &identity {
            Some(i) if i.data.ssh_id => crate::sshid::handle(self)?,
            _ => None,
        };
        let proxy = match ssh.proxy_id {
            Some(id) => self.get_in::<Proxy>(id, vault)?,
            None => None,
        };
        let mut chain = Vec::new();
        if let Some(cid) = ssh.host_chain_id
            && let Some(hc) = self.get_in::<crate::model::HostChain>(cid, vault)?
        {
            for hid in hc.data.host_ids {
                if hid != host_id
                    && let Some(h) = self.get_in::<Host>(hid, vault)?
                {
                    chain.push(h);
                }
            }
        }

        let tag_links: Vec<Entity<TagHost>> = self.list(Some(vault))?;
        let tags_all: Vec<Entity<Tag>> = self.list(Some(vault))?;
        let mut tags: Vec<String> = host
            .data
            .tag_ids
            .iter()
            .chain(
                tag_links
                    .iter()
                    .filter(|l| l.data.host_id == host_id)
                    .map(|l| &l.data.tag_id),
            )
            .filter_map(|tid| tags_all.iter().find(|t| t.id == *tid))
            .map(|t| t.data.label.clone())
            .collect();
        tags.sort();
        tags.dedup();

        let gateway_id = ssh.gateway_id;
        Ok(ResolvedHost {
            host,
            ssh,
            identity,
            key,
            certificate,
            ssh_id_handle,
            proxy,
            gateway_id,
            chain,
            telnet,
            serial,
            webdav,
            webdav_identity,
            group_path,
            tags,
        })
    }
}

fn merge_ssh(into: &mut SshConfig, from: &SshConfig) {
    macro_rules! opt {
        ($($f:ident),*) => { $( if from.$f.is_some() { into.$f = from.$f.clone(); } )* };
    }
    opt!(
        port,
        identity_id,
        host_chain_id,
        proxy_id,
        port_knocking_id,
        charset,
        color_scheme,
        font_size,
        cursor_blink,
        mosh_server_command,
        keep_alive_interval,
        timeout
    );
    if from.agent_forwarding {
        into.agent_forwarding = true;
    }
    if from.forward_x11 {
        into.forward_x11 = true;
    }
    if from.use_mosh {
        into.use_mosh = true;
    }
    if !from.env_variables.is_empty() {
        into.env_variables = from.env_variables.clone();
    }
    if !from.extra_options.is_empty() {
        into.extra_options = from.extra_options.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoso_crypto::keys::SymmetricKey;
    use termoso_proto::vault::VaultRole;

    use crate::store::LocalVaultKind;

    fn store() -> Store {
        Store::open_in_memory(SymmetricKey::generate()).unwrap()
    }

    #[test]
    fn crud_in_local_vault_is_never_dirty() {
        let s = store();
        let v = s.local_vault().unwrap().id;
        let id = s
            .insert(
                v,
                &Host {
                    label: "web".into(),
                    address: "10.0.0.1".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let h = s.require::<Host>(id).unwrap();
        assert_eq!(h.data.address, "10.0.0.1");
        assert!(!h.dirty);
        assert_eq!(s.list::<Host>(None).unwrap().len(), 1);
        assert_eq!(s.pending_changes().unwrap(), 0);

        s.update(
            id,
            &Host {
                label: "web2".into(),
                ..h.data
            },
        )
        .unwrap();
        assert_eq!(s.require::<Host>(id).unwrap().data.label, "web2");

        s.delete(id).unwrap();
        assert!(s.get::<Host>(id).unwrap().is_none());
        assert!(s.row(id).unwrap().is_none());
    }

    #[test]
    fn ciphertext_is_bound_to_kind_and_id() {
        let s = store();
        let v = s.local_vault().unwrap().id;
        let id = s
            .insert(
                v,
                &Group {
                    label: "g".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        // Reading as another kind must fail rather than mis-decode.
        assert!(s.get::<Host>(id).unwrap().is_none());
        assert!(s.update(id, &Host::default()).is_err());
    }

    #[test]
    fn synced_vault_tracks_dirty_and_tombstones() {
        let s = store();
        let vk = SymmetricKey::generate();
        let v = Uuid::new_v4();
        s.upsert_vault(
            v,
            LocalVaultKind::Personal,
            "P",
            None,
            VaultRole::Manager,
            Some(&vk),
            1,
        )
        .unwrap();
        let id = s
            .insert(
                v,
                &Tag {
                    label: "prod".into(),
                    color: None,
                },
            )
            .unwrap();
        let rows = s.dirty_rows(v).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].to_change().base_version, None);

        s.mark_pushed(id, 1, 7).unwrap();
        assert!(s.dirty_rows(v).unwrap().is_empty());
        assert_eq!(s.require::<Tag>(id).unwrap().version, 1);

        s.delete(id).unwrap();
        let rows = s.dirty_rows(v).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].deleted);
        assert_eq!(rows[0].to_delete().base_version, 1);
        assert!(s.get::<Tag>(id).unwrap().is_none());
        s.mark_pushed(id, 2, 8).unwrap();
        assert!(s.row(id).unwrap().is_none());
    }

    #[test]
    fn apply_remote_uses_server_envelope_verbatim() {
        let s = store();
        let vk = SymmetricKey::generate();
        let v = Uuid::new_v4();
        s.upsert_vault(
            v,
            LocalVaultKind::Personal,
            "P",
            None,
            VaultRole::Manager,
            Some(&vk),
            1,
        )
        .unwrap();
        let id = Uuid::new_v4();
        let data = aead::encrypt_str(
            &vk,
            &Aad::entity("host", &id.to_string()),
            &serde_json::to_string(&Host {
                label: "remote".into(),
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();
        s.apply_remote(&SyncEntity {
            secret_rotated_at: None,
            id,
            kind: "host".into(),
            vault_id: v,
            version: 3,
            seq: 10,
            deleted: false,
            key_version: 1,
            data,
            updated_at: Utc::now(),
            updated_by_device: None,
        })
        .unwrap();
        let h = s.require::<Host>(id).unwrap();
        assert_eq!(h.data.label, "remote");
        assert_eq!(h.version, 3);
        assert!(!h.dirty);
    }

    #[test]
    fn locked_vault_entities_are_skipped_not_fatal() {
        let s = store();
        let v = Uuid::new_v4();
        s.upsert_vault(
            v,
            LocalVaultKind::Team,
            "T",
            Some(Uuid::new_v4()),
            VaultRole::Viewer,
            None,
            1,
        )
        .unwrap();
        s.apply_remote(&SyncEntity {
            secret_rotated_at: None,
            id: Uuid::new_v4(),
            kind: "host".into(),
            vault_id: v,
            version: 1,
            seq: 1,
            deleted: false,
            key_version: 1,
            data: "AAAA".into(),
            updated_at: Utc::now(),
            updated_by_device: None,
        })
        .unwrap();
        assert!(s.list::<Host>(None).unwrap().is_empty());
        assert!(matches!(
            s.insert(v, &Host::default()),
            Err(CoreError::VaultLocked(_))
        ));
    }

    #[test]
    fn resolve_host_inherits_group_config_and_identity() {
        let s = store();
        let v = s.local_vault().unwrap().id;
        let key = s
            .insert(
                v,
                &SshKey {
                    label: "k".into(),
                    key_type: "ed25519".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let ident = s
            .insert(
                v,
                &Identity {
                    label: "me".into(),
                    username: "deploy".into(),
                    ssh_key_id: Some(key),
                    ..Default::default()
                },
            )
            .unwrap();
        let root_cfg = s
            .insert(
                v,
                &SshConfig {
                    port: Some(2222),
                    identity_id: Some(ident),
                    ..Default::default()
                },
            )
            .unwrap();
        let root = s
            .insert(
                v,
                &Group {
                    label: "Prod".into(),
                    ssh_config_id: Some(root_cfg),
                    ..Default::default()
                },
            )
            .unwrap();
        let child = s
            .insert(
                v,
                &Group {
                    label: "EU".into(),
                    parent_id: Some(root),
                    ..Default::default()
                },
            )
            .unwrap();
        let host_cfg = s
            .insert(
                v,
                &SshConfig {
                    port: Some(22),
                    ..Default::default()
                },
            )
            .unwrap();
        let tag = s
            .insert(
                v,
                &Tag {
                    label: "db".into(),
                    color: None,
                },
            )
            .unwrap();
        let host = s
            .insert(
                v,
                &Host {
                    label: "pg".into(),
                    address: "pg.internal".into(),
                    group_id: Some(child),
                    ssh_config_id: Some(host_cfg),
                    tag_ids: vec![tag],
                    ..Default::default()
                },
            )
            .unwrap();
        let r = s.resolve_host(host).unwrap();
        assert_eq!(r.port(), 22, "host config overrides group");
        assert_eq!(
            r.username().as_deref(),
            Some("deploy"),
            "identity inherited from root group"
        );
        assert_eq!(r.key.as_ref().unwrap().id, key);
        assert!(r.certificate.is_none());
        assert_eq!(r.group_path, vec!["Prod", "EU"]);
        assert_eq!(r.tags, vec!["db"]);

        // A certificate attached to the key is picked up even when the
        // identity does not reference it explicitly.
        let cert = s
            .insert(
                v,
                &SshCertificate {
                    label: "k".into(),
                    certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".into(),
                    ssh_key_id: Some(key),
                },
            )
            .unwrap();
        assert_eq!(s.resolve_host(host).unwrap().certificate.unwrap().id, cert);
        // An explicit identity reference wins.
        let other = s
            .insert(
                v,
                &SshCertificate {
                    label: "other".into(),
                    certificate: "ssh-ed25519-cert-v01@openssh.com BBBB".into(),
                    ssh_key_id: None,
                },
            )
            .unwrap();
        let mut i = s.require::<Identity>(ident).unwrap();
        i.data.ssh_certificate_id = Some(other);
        s.update(ident, &i.data).unwrap();
        assert_eq!(s.resolve_host(host).unwrap().certificate.unwrap().id, other);
    }

    fn personal_vault(s: &Store) -> Uuid {
        let v = Uuid::new_v4();
        s.upsert_vault(
            v,
            LocalVaultKind::Personal,
            "P",
            None,
            VaultRole::Manager,
            Some(&SymmetricKey::generate()),
            1,
        )
        .unwrap();
        v
    }

    #[test]
    fn resolve_host_refuses_credentials_from_another_vault() {
        let s = store();
        let local = s.local_vault().unwrap().id;
        let personal = personal_vault(&s);
        let my_identity = s
            .insert(
                personal,
                &Identity {
                    label: "me".into(),
                    username: "root".into(),
                    password: Some("hunter2".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        // A host in another vault points at the personal identity.
        let cfg = s
            .insert(
                local,
                &SshConfig {
                    identity_id: Some(my_identity),
                    ..Default::default()
                },
            )
            .unwrap();
        let host = s
            .insert(
                local,
                &Host {
                    label: "evil".into(),
                    address: "evil.example".into(),
                    ssh_config_id: Some(cfg),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(matches!(
            s.resolve_host(host),
            Err(CoreError::Invalid(m)) if m.contains("another vault")
        ));

        // Same for a jump host and a proxy borrowed from elsewhere.
        let jump = s
            .insert(
                personal,
                &Host {
                    label: "bastion".into(),
                    address: "bastion.example".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let chain = s
            .insert(
                local,
                &crate::model::HostChain {
                    host_ids: vec![jump],
                    ..Default::default()
                },
            )
            .unwrap();
        s.update(
            cfg,
            &SshConfig {
                identity_id: None,
                host_chain_id: Some(chain),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(matches!(
            s.resolve_host(host),
            Err(CoreError::Invalid(m)) if m.contains("another vault")
        ));

        // The check also holds when the other vault is locked: the reference
        // is refused before any decryption is attempted.
        let locked = Uuid::new_v4();
        s.upsert_vault(
            locked,
            LocalVaultKind::Team,
            "T",
            Some(Uuid::new_v4()),
            VaultRole::Viewer,
            None,
            1,
        )
        .unwrap();
        let locked_identity = Uuid::new_v4();
        s.apply_remote(&SyncEntity {
            secret_rotated_at: None,
            id: locked_identity,
            kind: Identity::KIND.into(),
            vault_id: locked,
            version: 1,
            seq: 1,
            deleted: false,
            key_version: 1,
            data: "AAAA".into(),
            updated_at: Utc::now(),
            updated_by_device: None,
        })
        .unwrap();
        s.update(
            cfg,
            &SshConfig {
                identity_id: Some(locked_identity),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(matches!(
            s.resolve_host(host),
            Err(CoreError::Invalid(m)) if m.contains("another vault")
        ));
    }

    #[test]
    fn resolve_host_in_checks_the_expected_vault() {
        let s = store();
        let local = s.local_vault().unwrap().id;
        let personal = personal_vault(&s);
        let host = s
            .insert(
                personal,
                &Host {
                    label: "pg".into(),
                    address: "pg.internal".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(s.resolve_host_in(host, Some(personal)).is_ok());
        assert!(s.resolve_host_in(host, None).is_ok());
        assert!(matches!(
            s.resolve_host_in(host, Some(local)),
            Err(CoreError::Invalid(m)) if m.contains("another vault")
        ));
    }
}
