//! In-memory decrypted mirror of one vault, rebuilt from `/sync/pull`.

use std::collections::HashMap;

use serde::Serialize;
use serde::de::DeserializeOwned;
use termoso_crypto::aead::{self, Aad};
use termoso_crypto::keys::SymmetricKey;
use termoso_proto::entities::SyncEntity;
use termoso_proto::entities::payload::{Group, Host, Identity, Snippet, SshKey, Tag};
use termoso_proto::sync::EntityChange;
use termoso_proto::vault::{VaultKind, VaultRole};
use uuid::Uuid;

use crate::error::{BridgeError, Result};

/// One entity as the bridge sees it.
#[derive(Debug, Clone)]
pub struct Entity {
    pub kind: String,
    pub version: i64,
    /// Decrypted payload; `None` when the entity was written under a key
    /// version the bridge does not hold (still tracked for versioning).
    pub data: Option<serde_json::Value>,
}

pub struct VaultState {
    pub id: Uuid,
    pub name: String,
    pub kind: VaultKind,
    pub role: VaultRole,
    pub key_version: i32,
    /// `None` after a rotation until the cabinet re-seals the key.
    pub key: Option<SymmetricKey>,
    pub cursor: i64,
    pub entities: HashMap<Uuid, Entity>,
}

impl VaultState {
    pub fn new(id: Uuid, name: String, kind: VaultKind, role: VaultRole, key_version: i32) -> Self {
        Self {
            id,
            name,
            kind,
            role,
            key_version,
            key: None,
            cursor: 0,
            entities: HashMap::new(),
        }
    }

    pub fn ready(&self) -> bool {
        self.key.is_some()
    }

    pub fn require_key(&self) -> Result<&SymmetricKey> {
        self.key.as_ref().ok_or_else(|| {
            BridgeError::Pending(format!(
                "vault '{}' key is pending: re-seal it to this bridge in the cabinet",
                self.name
            ))
        })
    }

    /// Apply one pulled entity.
    pub fn apply(&mut self, e: &SyncEntity) {
        self.cursor = self.cursor.max(e.seq);
        if e.deleted {
            self.entities.remove(&e.id);
            return;
        }
        let data = match &self.key {
            Some(k) if e.key_version == self.key_version => {
                match aead::decrypt_str(k, &Aad::entity(&e.kind, &e.id.to_string()), &e.data)
                    .ok()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                {
                    Some(v) => Some(v),
                    None => {
                        tracing::warn!(vault = %self.id, id = %e.id, kind = %e.kind, "cannot decrypt entity");
                        None
                    }
                }
            }
            _ => None,
        };
        self.entities.insert(
            e.id,
            Entity {
                kind: e.kind.clone(),
                version: e.version,
                data,
            },
        );
    }

    /// Forget everything pulled so far (used when the key changes).
    pub fn reset(&mut self) {
        self.cursor = 0;
        self.entities.clear();
    }

    pub fn version_of(&self, id: Uuid) -> Option<i64> {
        self.entities.get(&id).map(|e| e.version)
    }

    pub fn get<T: DeserializeOwned>(&self, id: Uuid, kind: &str) -> Option<T> {
        let e = self.entities.get(&id)?;
        if e.kind != kind {
            return None;
        }
        serde_json::from_value(e.data.clone()?).ok()
    }

    pub fn iter_kind<T: DeserializeOwned>(
        &self,
        kind: &str,
    ) -> impl Iterator<Item = (Uuid, i64, T)> + '_ {
        let kind = kind.to_string();
        self.entities.iter().filter_map(move |(id, e)| {
            if e.kind != kind {
                return None;
            }
            let v = serde_json::from_value::<T>(e.data.clone()?).ok()?;
            Some((*id, e.version, v))
        })
    }

    pub fn host_by_external_id(&self, external_id: &str) -> Option<(Uuid, Host)> {
        self.iter_kind::<Host>("host")
            .find(|(_, _, h)| h.external_id.as_deref() == Some(external_id))
            .map(|(id, _, h)| (id, h))
    }

    pub fn snippet_by_external_id(&self, external_id: &str) -> Option<(Uuid, Snippet)> {
        self.iter_kind::<Snippet>("snippet")
            .find(|(_, _, s)| s.external_id.as_deref() == Some(external_id))
            .map(|(id, _, s)| (id, s))
    }
    pub fn identity_by_external_id(&self, external_id: &str) -> Option<(Uuid, Identity)> {
        self.iter_kind::<Identity>("identity")
            .find(|(_, _, i)| i.external_id.as_deref() == Some(external_id))
            .map(|(id, _, i)| (id, i))
    }
    pub fn key_by_external_id(&self, external_id: &str) -> Option<(Uuid, SshKey)> {
        self.iter_kind::<SshKey>("ssh_key")
            .find(|(_, _, k)| k.external_id.as_deref() == Some(external_id))
            .map(|(id, _, k)| (id, k))
    }
    pub fn group_by_external_id(&self, external_id: &str) -> Option<(Uuid, Group)> {
        self.iter_kind::<Group>("group")
            .find(|(_, _, g)| g.external_id.as_deref() == Some(external_id))
            .map(|(id, _, g)| (id, g))
    }

    pub fn tag_by_label(&self, label: &str) -> Option<Uuid> {
        let want = label.trim().to_lowercase();
        self.iter_kind::<Tag>("tag")
            .find(|(_, _, t)| t.label.trim().to_lowercase() == want)
            .map(|(id, _, _)| id)
    }

    /// Readable entities of `kind` (unreadable ones await re-encryption by
    /// the owner after a key rotation).
    pub fn count_kind(&self, kind: &str) -> usize {
        self.entities
            .values()
            .filter(|e| e.kind == kind && e.data.is_some())
            .count()
    }

    /// Encrypt `data` as an [`EntityChange`] for this vault. `base_version`
    /// is the version currently known locally (`None` for a new entity).
    pub fn change<T: Serialize>(&self, kind: &str, id: Uuid, data: &T) -> Result<EntityChange> {
        let key = self.require_key()?;
        let plaintext = serde_json::to_string(data)?;
        let ct = aead::encrypt_str(key, &Aad::entity(kind, &id.to_string()), &plaintext)?;
        Ok(EntityChange {
            secret_rotated_at: None,
            id,
            kind: kind.to_string(),
            vault_id: self.id,
            base_version: self.version_of(id),
            key_version: self.key_version,
            data: ct,
            updated_at: chrono::Utc::now(),
        })
    }
}
