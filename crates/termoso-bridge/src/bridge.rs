//! Bridge runtime: mirrors the sealed vaults, maps REST payloads onto vault
//! entities, encrypts and pushes them.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use serde::Serialize;
use termoso_crypto::keys::KeyPair;
use termoso_crypto::sealed;
use termoso_proto::bridge::BridgeSelf;
use termoso_proto::entities::payload::{
    Group, Host, Identity, Snippet, SshConfig, SshKey, Tag, TelnetConfig, WebDavConfig,
};
use termoso_proto::sync::{EntityChange, EntityDelete, PullRequest, PushRequest, PushResult};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::credentials::Credentials as FileCredentials;
use crate::error::{BridgeError, Result};
use crate::model::{
    BridgeStatus, Credentials, GroupRequest, GroupSummary, HostRequest, HostSummary,
    IdentityRequest, IdentitySummary, KeyRequest, KeySummary, SnippetRequest, SnippetSummary,
    SshSection, TelnetSection, VaultSummary,
};
use crate::server::ServerClient;
use crate::vault::VaultState;

const MAX_LABEL: usize = 200;
const MAX_ADDRESS: usize = 253;
const MAX_TAGS: usize = 32;
const MAX_NOTES: usize = 4096;
const MAX_KEY_BYTES: usize = 64 * 1024;
const MAX_EXTERNAL_ID: usize = 200;
const PUSH_ATTEMPTS: usize = 3;
/// How long the vault list / sealed keys from `/bridge/me` are trusted before
/// being re-read on the next write.
const ME_TTL: Duration = Duration::from_secs(30);

pub struct Bridge {
    server: ServerClient,
    key_pair: KeyPair,
    bridge_id: Uuid,
    inner: Mutex<Inner>,
}

struct Inner {
    me: BridgeSelf,
    vaults: HashMap<Uuid, VaultState>,
    me_at: Instant,
}

/// Plaintext changes for one vault, built against a fresh mirror.
#[derive(Default)]
struct Plan {
    changes: Vec<(String, Uuid, serde_json::Value)>,
    deletes: Vec<Uuid>,
}

impl Plan {
    fn put<T: Serialize>(&mut self, kind: &str, id: Uuid, data: &T) -> Result<()> {
        self.changes
            .push((kind.to_string(), id, serde_json::to_value(data)?));
        Ok(())
    }

    fn delete(&mut self, id: Uuid) {
        if !self.deletes.contains(&id) {
            self.deletes.push(id);
        }
    }

    fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.deletes.is_empty()
    }
}

impl Bridge {
    /// Authenticate against the server, open the sealed vault keys and mirror
    /// the vaults.
    pub async fn connect(creds: FileCredentials) -> Result<Self> {
        let server = ServerClient::new(&creds.server, creds.token)?;
        let me = server.me().await?;
        if me.id != creds.bridge_id {
            return Err(BridgeError::Credentials(format!(
                "credentials file is for bridge {}, server says {}",
                creds.bridge_id, me.id
            )));
        }
        let b = Self {
            server,
            key_pair: creds.key_pair,
            bridge_id: me.id,
            inner: Mutex::new(Inner {
                me: me.clone(),
                vaults: HashMap::new(),
                me_at: Instant::now(),
            }),
        };
        {
            let mut inner = b.inner.lock().await;
            b.reconcile(&mut inner, me);
            b.pull_all(&mut inner).await?;
        }
        Ok(b)
    }

    /// Address and port of `host_id` in `vault_id`, for the gateway.
    pub async fn gateway_target(&self, vault_id: Uuid, host_id: Uuid) -> Result<(String, u16)> {
        let inner = self.inner.lock().await;
        let v = inner
            .vaults
            .get(&vault_id)
            .ok_or_else(|| BridgeError::NotFound("vault".into()))?;
        let h: termoso_proto::entities::payload::Host = v
            .get(host_id, "host")
            .ok_or_else(|| BridgeError::NotFound("host".into()))?;
        let port = crate::exec::effective_ssh(v, &h)
            .and_then(|c| c.port)
            .unwrap_or(22);
        Ok((h.address, port))
    }

    pub fn bridge_id(&self) -> Uuid {
        self.bridge_id
    }

    pub fn server_url(&self) -> String {
        self.server.server_url().to_string()
    }

    // ───────────────────────────── refresh ─────────────────────────────

    /// Merge `/bridge/me` into the vault set: add/remove vaults, open new or
    /// rotated keys, drop mirrors whose key changed.
    fn reconcile(&self, inner: &mut Inner, me: BridgeSelf) {
        let ids: HashSet<Uuid> = me.vaults.iter().map(|v| v.vault_id).collect();
        inner.vaults.retain(|id, _| ids.contains(id));
        for bv in &me.vaults {
            let key = bv
                .sealed_key
                .as_deref()
                .and_then(|s| match sealed::open_vault_key(&self.key_pair, s) {
                    Ok(k) => Some(k),
                    Err(_) => {
                        tracing::error!(vault = %bv.vault_id, "sealed vault key does not open with the bridge key");
                        None
                    }
                });
            let v = inner.vaults.entry(bv.vault_id).or_insert_with(|| {
                VaultState::new(
                    bv.vault_id,
                    bv.name.clone(),
                    bv.kind,
                    bv.role,
                    bv.key_version,
                )
            });
            v.name = bv.name.clone();
            v.role = bv.role;
            let key_changed = v.key_version != bv.key_version
                || v.key.as_ref().map(|k| k.as_bytes()) != key.as_ref().map(|k| k.as_bytes());
            if key_changed {
                v.reset();
            }
            v.key_version = bv.key_version;
            v.key = key;
        }
        inner.me = me;
        inner.me_at = Instant::now();
    }

    async fn refresh_me(&self, inner: &mut Inner, force: bool) -> Result<()> {
        if !force && inner.me_at.elapsed() < ME_TTL {
            return Ok(());
        }
        let me = self.server.me().await?;
        self.reconcile(inner, me);
        Ok(())
    }

    /// Pull every ready vault up to the head.
    async fn pull_all(&self, inner: &mut Inner) -> Result<()> {
        loop {
            let cursors: HashMap<Uuid, i64> = inner
                .vaults
                .values()
                .filter(|v| v.ready())
                .map(|v| (v.id, v.cursor))
                .collect();
            if cursors.is_empty() {
                return Ok(());
            }
            let resp = self
                .server
                .pull(&PullRequest {
                    cursors,
                    limit: Some(1000),
                })
                .await?;
            for e in &resp.entities {
                if let Some(v) = inner.vaults.get_mut(&e.vault_id) {
                    v.apply(e);
                }
            }
            for (vid, c) in resp.cursors {
                if let Some(v) = inner.vaults.get_mut(&vid) {
                    v.cursor = v.cursor.max(c);
                }
            }
            if !resp.has_more {
                return Ok(());
            }
        }
    }

    async fn refresh(&self, inner: &mut Inner, force_me: bool) -> Result<()> {
        self.refresh_me(inner, force_me).await?;
        self.pull_all(inner).await
    }

    /// Re-read `/bridge/me` and pull. Used by the periodic loop and `POST /v1/sync/`.
    pub async fn sync(&self) -> Result<BridgeStatus> {
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, true).await?;
        Ok(status_of(self, &inner))
    }

    /// Server client (bridge token).
    pub fn server(&self) -> &ServerClient {
        &self.server
    }

    /// Read access to `/bridge/me` and the mirrored vaults (refreshing first).
    pub async fn with_inner<R>(
        &self,
        f: impl FnOnce(&BridgeSelf, &HashMap<Uuid, VaultState>) -> R,
    ) -> Result<R> {
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        Ok(f(&inner.me, &inner.vaults))
    }

    pub async fn status(&self) -> BridgeStatus {
        let inner = self.inner.lock().await;
        status_of(self, &inner)
    }

    // ───────────────────────────── commit ─────────────────────────────

    /// Build a plan against the fresh mirror of `vault_id`, encrypt, push;
    /// on a conflict re-pull and rebuild.
    async fn commit<F>(&self, inner: &mut Inner, vault_id: Uuid, build: F) -> Result<()>
    where
        F: Fn(&VaultState) -> Result<Plan>,
    {
        for attempt in 0..PUSH_ATTEMPTS {
            let vault = inner.vaults.get(&vault_id).ok_or_else(|| {
                BridgeError::NotFound("vault is not assigned to this bridge".into())
            })?;
            if !vault.role.can_write() {
                return Err(BridgeError::Invalid(format!(
                    "vault '{}' is read-only for the bridge owner",
                    vault.name
                )));
            }
            let plan = build(vault)?;
            if plan.is_empty() {
                return Ok(());
            }
            let mut changes: Vec<EntityChange> = Vec::with_capacity(plan.changes.len());
            for (kind, id, data) in &plan.changes {
                changes.push(vault.change(kind, *id, data)?);
            }
            let deletes: Vec<EntityDelete> = plan
                .deletes
                .iter()
                .filter_map(|id| {
                    vault.version_of(*id).map(|base| EntityDelete {
                        id: *id,
                        base_version: base,
                    })
                })
                .collect();
            let req = PushRequest { changes, deletes };
            let resp = self.server.push(&req).await?;
            let mut conflict = false;
            for r in &resp.results {
                match r {
                    PushResult::Ok { .. } => {}
                    PushResult::Conflict { id, .. } => {
                        tracing::info!(%id, attempt, "sync conflict, re-pulling");
                        conflict = true;
                    }
                    PushResult::Error { id, code } => {
                        return Err(BridgeError::Server {
                            status: 422,
                            code: code.clone(),
                            message: format!("server rejected entity {id}"),
                        });
                    }
                }
            }
            self.pull_all(inner).await?;
            if !conflict {
                return Ok(());
            }
            self.refresh_me(inner, true).await?;
        }
        Err(BridgeError::Conflict(vault_id.to_string()))
    }

    // ───────────────────────────── resolve ─────────────────────────────

    fn resolve_vault(inner: &Inner, vault: Option<&str>, group: Option<&str>) -> Result<Uuid> {
        if let Some(name) = vault.map(str::trim).filter(|s| !s.is_empty()) {
            if let Ok(id) = Uuid::parse_str(name)
                && inner.vaults.contains_key(&id)
            {
                return Ok(id);
            }
            let mut hits = inner
                .vaults
                .values()
                .filter(|v| v.name.eq_ignore_ascii_case(name));
            return match (hits.next(), hits.next()) {
                (Some(v), None) => Ok(v.id),
                (Some(_), Some(_)) => Err(BridgeError::Invalid(format!(
                    "vault name '{name}' is ambiguous; pass the vault id"
                ))),
                (None, _) => Err(BridgeError::NotFound(format!(
                    "vault '{name}' is not assigned to this bridge"
                ))),
            };
        }
        if let Some(g) = group.map(str::trim).filter(|s| !s.is_empty()) {
            let mut hits = inner
                .vaults
                .values()
                .filter(|v| v.group_by_external_id(g).is_some());
            return match (hits.next(), hits.next()) {
                (Some(v), None) => Ok(v.id),
                (Some(_), Some(_)) => Err(BridgeError::Invalid(format!(
                    "group '{g}' exists in several vaults; pass `vault`"
                ))),
                (None, _) => Err(BridgeError::NotFound(format!("group '{g}' not found"))),
            };
        }
        let mut all = inner.vaults.values();
        match (all.next(), all.next()) {
            (Some(v), None) => Ok(v.id),
            (None, _) => Err(BridgeError::NotFound(
                "no vaults are assigned to this bridge".into(),
            )),
            _ => Err(BridgeError::Invalid(
                "`vault` is required when the bridge has several vaults".into(),
            )),
        }
    }

    /// Vault holding the host/group with `external_id` (optionally narrowed by `vault`).
    fn locate(
        inner: &Inner,
        kind: &str,
        external_id: &str,
        vault: Option<&str>,
    ) -> Result<Option<Uuid>> {
        let has = |v: &VaultState| match kind {
            "host" => v.host_by_external_id(external_id).is_some(),
            "snippet" => v.snippet_by_external_id(external_id).is_some(),
            "identity" => v.identity_by_external_id(external_id).is_some(),
            "key" => v.key_by_external_id(external_id).is_some(),
            _ => v.group_by_external_id(external_id).is_some(),
        };
        if vault.is_some() {
            let vid = Self::resolve_vault(inner, vault, None)?;
            return Ok(inner.vaults.get(&vid).filter(|v| has(v)).map(|v| v.id));
        }
        let mut hits = inner.vaults.values().filter(|v| has(v));
        match (hits.next(), hits.next()) {
            (Some(v), None) => Ok(Some(v.id)),
            (Some(_), Some(_)) => Err(BridgeError::Invalid(format!(
                "{kind} '{external_id}' exists in several vaults; pass `?vault=`"
            ))),
            (None, _) => Ok(None),
        }
    }

    // ───────────────────────────── hosts ─────────────────────────────

    pub async fn upsert_host(&self, external_id: &str, req: HostRequest) -> Result<HostSummary> {
        let external_id = validate_external_id(external_id)?;
        validate_host(&req)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let vault_id = Self::resolve_vault(&inner, req.vault.as_deref(), req.group.as_deref())?;
        let eid = external_id.clone();
        self.commit(&mut inner, vault_id, move |v| plan_host(v, &eid, &req))
            .await?;
        let v = &inner.vaults[&vault_id];
        let (id, h) = v
            .host_by_external_id(&external_id)
            .ok_or_else(|| BridgeError::Conflict(external_id.clone()))?;
        Ok(host_summary(v, id, &h))
    }

    /// Returns `false` when no such host exists.
    pub async fn delete_host(&self, external_id: &str, vault: Option<&str>) -> Result<bool> {
        let external_id = validate_external_id(external_id)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let Some(vault_id) = Self::locate(&inner, "host", &external_id, vault)? else {
            return Ok(false);
        };
        let eid = external_id.clone();
        self.commit(&mut inner, vault_id, move |v| {
            let mut plan = Plan::default();
            if let Some((id, h)) = v.host_by_external_id(&eid) {
                plan_delete_host(v, &mut plan, id, &h);
            }
            Ok(plan)
        })
        .await?;
        Ok(true)
    }

    pub async fn get_host(
        &self,
        external_id: &str,
        vault: Option<&str>,
    ) -> Result<Option<HostSummary>> {
        let external_id = validate_external_id(external_id)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let Some(vault_id) = Self::locate(&inner, "host", &external_id, vault)? else {
            return Ok(None);
        };
        let v = &inner.vaults[&vault_id];
        Ok(v.host_by_external_id(&external_id)
            .map(|(id, h)| host_summary(v, id, &h)))
    }

    /// Read-only view of the mirrored vaults (refreshed first if stale).
    /// `vault` narrows the view to one vault by name or id.
    pub async fn with_vaults<R>(
        &self,
        vault: Option<&str>,
        f: impl FnOnce(&[&VaultState]) -> Result<R>,
    ) -> Result<R> {
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let only = match vault {
            Some(_) => Some(Self::resolve_vault(&inner, vault, None)?),
            None => None,
        };
        let mut views: Vec<&VaultState> = inner
            .vaults
            .values()
            .filter(|v| only.is_none_or(|id| id == v.id))
            .collect();
        views.sort_by(|a, b| a.name.cmp(&b.name));
        f(&views)
    }

    /// Hosts carrying an `external_id`, across all (or one) vault.
    pub async fn list_hosts(&self, vault: Option<&str>) -> Result<Vec<HostSummary>> {
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let only = match vault {
            Some(_) => Some(Self::resolve_vault(&inner, vault, None)?),
            None => None,
        };
        let mut out: Vec<HostSummary> = inner
            .vaults
            .values()
            .filter(|v| only.is_none_or(|id| id == v.id))
            .flat_map(|v| {
                v.iter_kind::<Host>("host")
                    .filter(|(_, _, h)| h.external_id.is_some())
                    .map(move |(id, _, h)| host_summary(v, id, &h))
            })
            .collect();
        out.sort_by(|a, b| (&a.vault, &a.external_id).cmp(&(&b.vault, &b.external_id)));
        Ok(out)
    }

    // ─────────────────── snippets / identities / keys ───────────────────

    pub async fn upsert_snippet(
        &self,
        external_id: &str,
        req: SnippetRequest,
    ) -> Result<SnippetSummary> {
        let external_id = validate_external_id(external_id)?;
        validate_snippet(&req)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let vault_id = Self::resolve_vault(&inner, req.vault.as_deref(), None)?;
        let eid = external_id.clone();
        self.commit(&mut inner, vault_id, move |v| plan_snippet(v, &eid, &req))
            .await?;
        let v = &inner.vaults[&vault_id];
        let (id, sn) = v
            .snippet_by_external_id(&external_id)
            .ok_or_else(|| BridgeError::Conflict(external_id.clone()))?;
        Ok(snippet_summary(v, id, &sn))
    }

    pub async fn get_snippet(
        &self,
        external_id: &str,
        vault: Option<&str>,
    ) -> Result<Option<SnippetSummary>> {
        let external_id = validate_external_id(external_id)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let Some(vault_id) = Self::locate(&inner, "snippet", &external_id, vault)? else {
            return Ok(None);
        };
        let v = &inner.vaults[&vault_id];
        Ok(v.snippet_by_external_id(&external_id)
            .map(|(id, sn)| snippet_summary(v, id, &sn)))
    }

    pub async fn list_snippets(&self, vault: Option<&str>) -> Result<Vec<SnippetSummary>> {
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let only = match vault {
            Some(_) => Some(Self::resolve_vault(&inner, vault, None)?),
            None => None,
        };
        let mut out: Vec<SnippetSummary> = inner
            .vaults
            .values()
            .filter(|v| only.is_none_or(|id| id == v.id))
            .flat_map(|v| {
                v.iter_kind::<Snippet>("snippet")
                    .filter(|(_, _, s)| s.external_id.is_some())
                    .map(move |(id, _, s)| snippet_summary(v, id, &s))
            })
            .collect();
        out.sort_by(|a, b| (&a.vault, &a.external_id).cmp(&(&b.vault, &b.external_id)));
        Ok(out)
    }

    /// Returns `false` when no such snippet exists.
    pub async fn delete_snippet(&self, external_id: &str, vault: Option<&str>) -> Result<bool> {
        let external_id = validate_external_id(external_id)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let Some(vault_id) = Self::locate(&inner, "snippet", &external_id, vault)? else {
            return Ok(false);
        };
        let eid = external_id.clone();
        self.commit(&mut inner, vault_id, move |v| {
            v.require_key()?;
            let mut plan = Plan::default();
            if let Some((id, _)) = v.snippet_by_external_id(&eid) {
                plan.delete(id);
            }
            Ok(plan)
        })
        .await?;
        Ok(true)
    }

    pub async fn upsert_identity(
        &self,
        external_id: &str,
        req: IdentityRequest,
    ) -> Result<IdentitySummary> {
        let external_id = validate_external_id(external_id)?;
        validate_identity(&req)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let vault_id = Self::resolve_vault(&inner, req.vault.as_deref(), None)?;
        let eid = external_id.clone();
        self.commit(&mut inner, vault_id, move |v| {
            plan_shared_identity(v, &eid, &req)
        })
        .await?;
        let v = &inner.vaults[&vault_id];
        let (id, i) = v
            .identity_by_external_id(&external_id)
            .ok_or_else(|| BridgeError::Conflict(external_id.clone()))?;
        Ok(identity_summary(v, id, &i))
    }

    pub async fn get_identity(
        &self,
        external_id: &str,
        vault: Option<&str>,
    ) -> Result<Option<IdentitySummary>> {
        let external_id = validate_external_id(external_id)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let Some(vault_id) = Self::locate(&inner, "identity", &external_id, vault)? else {
            return Ok(None);
        };
        let v = &inner.vaults[&vault_id];
        Ok(v.identity_by_external_id(&external_id)
            .map(|(id, i)| identity_summary(v, id, &i)))
    }

    pub async fn list_identities(&self, vault: Option<&str>) -> Result<Vec<IdentitySummary>> {
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let only = match vault {
            Some(_) => Some(Self::resolve_vault(&inner, vault, None)?),
            None => None,
        };
        let mut out: Vec<IdentitySummary> = inner
            .vaults
            .values()
            .filter(|v| only.is_none_or(|id| id == v.id))
            .flat_map(|v| {
                v.iter_kind::<Identity>("identity")
                    .filter(|(_, _, i)| i.external_id.is_some())
                    .map(move |(id, _, i)| identity_summary(v, id, &i))
            })
            .collect();
        out.sort_by(|a, b| (&a.vault, &a.external_id).cmp(&(&b.vault, &b.external_id)));
        Ok(out)
    }

    /// Refuses (`Conflict`) while hosts or groups still use the identity.
    pub async fn delete_identity(&self, external_id: &str, vault: Option<&str>) -> Result<bool> {
        let external_id = validate_external_id(external_id)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let Some(vault_id) = Self::locate(&inner, "identity", &external_id, vault)? else {
            return Ok(false);
        };
        let eid = external_id.clone();
        self.commit(&mut inner, vault_id, move |v| {
            v.require_key()?;
            let mut plan = Plan::default();
            if let Some((id, _)) = v.identity_by_external_id(&eid) {
                let users = identity_users(v, id);
                if users > 0 {
                    return Err(BridgeError::Conflict(format!(
                        "identity '{eid}' is used by {users} host(s)/group(s)"
                    )));
                }
                plan.delete(id);
            }
            Ok(plan)
        })
        .await?;
        Ok(true)
    }

    pub async fn upsert_key(&self, external_id: &str, req: KeyRequest) -> Result<KeySummary> {
        let external_id = validate_external_id(external_id)?;
        validate_key(&req)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let vault_id = Self::resolve_vault(&inner, req.vault.as_deref(), None)?;
        let eid = external_id.clone();
        self.commit(&mut inner, vault_id, move |v| plan_key(v, &eid, &req))
            .await?;
        let v = &inner.vaults[&vault_id];
        let (id, k) = v
            .key_by_external_id(&external_id)
            .ok_or_else(|| BridgeError::Conflict(external_id.clone()))?;
        Ok(key_summary(v, id, &k))
    }

    pub async fn get_key(
        &self,
        external_id: &str,
        vault: Option<&str>,
    ) -> Result<Option<KeySummary>> {
        let external_id = validate_external_id(external_id)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let Some(vault_id) = Self::locate(&inner, "key", &external_id, vault)? else {
            return Ok(None);
        };
        let v = &inner.vaults[&vault_id];
        Ok(v.key_by_external_id(&external_id)
            .map(|(id, k)| key_summary(v, id, &k)))
    }

    pub async fn list_keys(&self, vault: Option<&str>) -> Result<Vec<KeySummary>> {
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let only = match vault {
            Some(_) => Some(Self::resolve_vault(&inner, vault, None)?),
            None => None,
        };
        let mut out: Vec<KeySummary> = inner
            .vaults
            .values()
            .filter(|v| only.is_none_or(|id| id == v.id))
            .flat_map(|v| {
                v.iter_kind::<SshKey>("ssh_key")
                    .filter(|(_, _, k)| k.external_id.is_some())
                    .map(move |(id, _, k)| key_summary(v, id, &k))
            })
            .collect();
        out.sort_by(|a, b| (&a.vault, &a.external_id).cmp(&(&b.vault, &b.external_id)));
        Ok(out)
    }

    /// Refuses (`Conflict`) while identities still reference the key.
    pub async fn delete_key(&self, external_id: &str, vault: Option<&str>) -> Result<bool> {
        let external_id = validate_external_id(external_id)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let Some(vault_id) = Self::locate(&inner, "key", &external_id, vault)? else {
            return Ok(false);
        };
        let eid = external_id.clone();
        self.commit(&mut inner, vault_id, move |v| {
            v.require_key()?;
            let mut plan = Plan::default();
            if let Some((id, _)) = v.key_by_external_id(&eid) {
                let users = key_users(v, id);
                if users > 0 {
                    return Err(BridgeError::Conflict(format!(
                        "key '{eid}' is used by {users} identit(y/ies)"
                    )));
                }
                plan.delete(id);
            }
            Ok(plan)
        })
        .await?;
        Ok(true)
    }

    // ───────────────────────────── groups ─────────────────────────────

    pub async fn upsert_group(&self, external_id: &str, req: GroupRequest) -> Result<GroupSummary> {
        let external_id = validate_external_id(external_id)?;
        validate_group(&req)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let vault_id = Self::resolve_vault(&inner, req.vault.as_deref(), req.parent.as_deref())?;
        let eid = external_id.clone();
        self.commit(&mut inner, vault_id, move |v| plan_group(v, &eid, &req))
            .await?;
        let v = &inner.vaults[&vault_id];
        let (id, g) = v
            .group_by_external_id(&external_id)
            .ok_or_else(|| BridgeError::Conflict(external_id.clone()))?;
        Ok(group_summary(v, id, &g))
    }

    /// Deletes the group; its hosts and sub-groups move to the parent.
    pub async fn delete_group(&self, external_id: &str, vault: Option<&str>) -> Result<bool> {
        let external_id = validate_external_id(external_id)?;
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let Some(vault_id) = Self::locate(&inner, "group", &external_id, vault)? else {
            return Ok(false);
        };
        let eid = external_id.clone();
        self.commit(&mut inner, vault_id, move |v| {
            let mut plan = Plan::default();
            let Some((gid, g)) = v.group_by_external_id(&eid) else {
                return Ok(plan);
            };
            for (hid, _, mut h) in v.iter_kind::<Host>("host") {
                if h.group_id == Some(gid) {
                    h.group_id = g.parent_id;
                    plan.put("host", hid, &h)?;
                }
            }
            for (cid, _, mut c) in v.iter_kind::<Group>("group") {
                if c.parent_id == Some(gid) {
                    c.parent_id = g.parent_id;
                    plan.put("group", cid, &c)?;
                }
            }
            plan_delete_ssh(v, &mut plan, g.ssh_config_id);
            plan_delete_telnet(v, &mut plan, g.telnet_config_id);
            plan.delete(gid);
            Ok(plan)
        })
        .await?;
        Ok(true)
    }

    pub async fn list_groups(&self, vault: Option<&str>) -> Result<Vec<GroupSummary>> {
        let mut inner = self.inner.lock().await;
        self.refresh(&mut inner, false).await?;
        let only = match vault {
            Some(_) => Some(Self::resolve_vault(&inner, vault, None)?),
            None => None,
        };
        let mut out: Vec<GroupSummary> = inner
            .vaults
            .values()
            .filter(|v| only.is_none_or(|id| id == v.id))
            .flat_map(|v| {
                v.iter_kind::<Group>("group")
                    .filter(|(_, _, g)| g.external_id.is_some())
                    .map(move |(id, _, g)| group_summary(v, id, &g))
            })
            .collect();
        out.sort_by(|a, b| (&a.vault, &a.external_id).cmp(&(&b.vault, &b.external_id)));
        Ok(out)
    }
}

// ───────────────────────────── planning ─────────────────────────────

fn plan_host(v: &VaultState, external_id: &str, req: &HostRequest) -> Result<Plan> {
    v.require_key()?;
    let mut plan = Plan::default();
    let existing = v.host_by_external_id(external_id);
    let host_id = existing
        .as_ref()
        .map(|(id, _)| *id)
        .unwrap_or_else(Uuid::new_v4);
    let old = existing.map(|(_, h)| h).unwrap_or_default();

    let group_id = match req
        .group
        .as_deref()
        .map(str::trim)
        .filter(|g| !g.is_empty())
    {
        Some(g) => Some(v.group_by_external_id(g).map(|(id, _)| id).ok_or_else(|| {
            BridgeError::NotFound(format!("group '{g}' not found in vault '{}'", v.name))
        })?),
        None => None,
    };

    let label = req
        .label
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .unwrap_or(req.address.trim())
        .to_string();

    // SSH: present unless the host is telnet-only.
    let ssh_config_id = if req.ssh.is_some() || req.telnet.is_none() {
        Some(plan_ssh(
            v,
            &mut plan,
            old.ssh_config_id,
            req.ssh.as_ref(),
            &label,
        )?)
    } else {
        plan_delete_ssh(v, &mut plan, old.ssh_config_id);
        None
    };
    let telnet_config_id = match &req.telnet {
        Some(t) => Some(plan_telnet(v, &mut plan, old.telnet_config_id, t, &label)?),
        None => {
            plan_delete_telnet(v, &mut plan, old.telnet_config_id);
            None
        }
    };

    let mut tag_ids = Vec::new();
    let mut seen = HashSet::new();
    for t in &req.tags {
        let t = t.trim();
        if t.is_empty() || !seen.insert(t.to_lowercase()) {
            continue;
        }
        let id = match v.tag_by_label(t) {
            Some(id) => id,
            None => {
                let id = Uuid::new_v4();
                plan.put(
                    "tag",
                    id,
                    &Tag {
                        label: t.to_string(),
                        color: None,
                    },
                )?;
                id
            }
        };
        tag_ids.push(id);
    }

    let host = Host {
        mac_address: None,
        label,
        address: req.address.trim().to_string(),
        group_id,
        ssh_config_id,
        telnet_config_id,
        webdav_config_id: old.webdav_config_id,
        serial_config_id: old.serial_config_id,
        tag_ids,
        notes: req.notes.clone().unwrap_or(old.notes),
        os_name: req
            .os
            .clone()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or(old.os_name),
        icon: old.icon,
        ip_version: old.ip_version,
        backspace: old.backspace,
        cloud_instance_id: old.cloud_instance_id,
        cloud_instance_type: old.cloud_instance_type,
        startup_snippet_id: old.startup_snippet_id,
        sort_order: old.sort_order,
        external_id: Some(external_id.to_string()),
        files_provider: old.files_provider,
        shell_integration: old.shell_integration,
    };
    plan.put("host", host_id, &host)?;
    Ok(plan)
}

fn plan_group(v: &VaultState, external_id: &str, req: &GroupRequest) -> Result<Plan> {
    v.require_key()?;
    let mut plan = Plan::default();
    let existing = v.group_by_external_id(external_id);
    let group_id = existing
        .as_ref()
        .map(|(id, _)| *id)
        .unwrap_or_else(Uuid::new_v4);
    let old = existing.map(|(_, g)| g).unwrap_or_default();

    let parent_id = match req
        .parent
        .as_deref()
        .map(str::trim)
        .filter(|g| !g.is_empty())
    {
        Some(p) => {
            let (pid, _) = v.group_by_external_id(p).ok_or_else(|| {
                BridgeError::NotFound(format!(
                    "parent group '{p}' not found in vault '{}'",
                    v.name
                ))
            })?;
            if pid == group_id || ancestors(v, pid).contains(&group_id) {
                return Err(BridgeError::Invalid(
                    "group cannot be its own ancestor".into(),
                ));
            }
            Some(pid)
        }
        None => None,
    };
    let label = req.label.trim().to_string();

    let ssh_config_id = match &req.ssh {
        Some(s) => Some(plan_ssh(v, &mut plan, old.ssh_config_id, Some(s), &label)?),
        None => {
            plan_delete_ssh(v, &mut plan, old.ssh_config_id);
            None
        }
    };
    let telnet_config_id = match &req.telnet {
        Some(t) => Some(plan_telnet(v, &mut plan, old.telnet_config_id, t, &label)?),
        None => {
            plan_delete_telnet(v, &mut plan, old.telnet_config_id);
            None
        }
    };

    let group = Group {
        label,
        parent_id,
        ssh_config_id,
        telnet_config_id,
        sort_order: old.sort_order,
        external_id: Some(external_id.to_string()),
    };
    plan.put("group", group_id, &group)?;
    Ok(plan)
}

fn ancestors(v: &VaultState, mut id: Uuid) -> Vec<Uuid> {
    let mut out = Vec::new();
    while let Some(g) = v.get::<Group>(id, "group") {
        match g.parent_id {
            Some(p) if !out.contains(&p) && out.len() < 64 => {
                out.push(p);
                id = p;
            }
            _ => break,
        }
    }
    out
}

fn plan_ssh(
    v: &VaultState,
    plan: &mut Plan,
    old_id: Option<Uuid>,
    section: Option<&SshSection>,
    label: &str,
) -> Result<Uuid> {
    let old = old_id.and_then(|id| v.get::<SshConfig>(id, "ssh_config"));
    let id = old_id
        .filter(|_| old.is_some())
        .unwrap_or_else(Uuid::new_v4);
    let mut cfg = old.unwrap_or_default();
    cfg.port = section.and_then(|s| s.port);
    cfg.identity_id = plan_identity(
        v,
        plan,
        cfg.identity_id,
        section.and_then(|s| s.credentials.as_ref()),
        label,
    )?;
    plan.put("ssh_config", id, &cfg)?;
    Ok(id)
}

fn plan_telnet(
    v: &VaultState,
    plan: &mut Plan,
    old_id: Option<Uuid>,
    section: &TelnetSection,
    label: &str,
) -> Result<Uuid> {
    let old = old_id.and_then(|id| v.get::<TelnetConfig>(id, "telnet_config"));
    let id = old_id
        .filter(|_| old.is_some())
        .unwrap_or_else(Uuid::new_v4);
    let mut cfg = old.unwrap_or_default();
    cfg.port = section.port;
    cfg.identity_id = plan_identity(
        v,
        plan,
        cfg.identity_id,
        section.credentials.as_ref(),
        label,
    )?;
    plan.put("telnet_config", id, &cfg)?;
    Ok(id)
}

/// Inline (hidden) identity owned by the bridge-managed host/group.
fn plan_identity(
    v: &VaultState,
    plan: &mut Plan,
    old_id: Option<Uuid>,
    creds: Option<&Credentials>,
    label: &str,
) -> Result<Option<Uuid>> {
    let old = old_id.and_then(|id| v.get::<Identity>(id, "identity").map(|i| (id, i)));
    // Only identities the bridge created (hidden from the keychain) are ours to rewrite.
    let creds = creds.filter(|c| !c.is_empty());

    let Some(c) = creds else {
        return Ok(match old {
            Some((id, i)) if !i.is_visible => {
                plan_delete_key(v, plan, id, i.ssh_key_id);
                plan.delete(id);
                None
            }
            Some((id, _)) => Some(id),
            None => None,
        });
    };
    let inline = old.filter(|(_, i)| !i.is_visible);

    // A shared identity by external_id replaces whatever inline one we kept.
    if let Some(ext) = c
        .identity
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        let (shared, _) = v.identity_by_external_id(ext).ok_or_else(|| {
            BridgeError::NotFound(format!("identity '{ext}' not found in vault '{}'", v.name))
        })?;
        if let Some((id, i)) = inline {
            plan_delete_key(v, plan, id, i.ssh_key_id);
            plan.delete(id);
        }
        return Ok(Some(shared));
    }

    let (id, mut ident) = inline.unwrap_or_else(|| (Uuid::new_v4(), Identity::default()));
    ident.label = label.to_string();
    ident.username = c.username.clone().unwrap_or_default().trim().to_string();
    ident.password = c.password.clone().filter(|p| !p.is_empty());
    ident.is_visible = false;
    ident.ssh_id = false;
    ident.ssh_id_key_type = None;

    match &c.key {
        Some(k) => {
            let key_id = ident
                .ssh_key_id
                .filter(|kid| v.get::<SshKey>(*kid, "ssh_key").is_some())
                .unwrap_or_else(Uuid::new_v4);
            let private = k.private.trim().to_string();
            let public = k
                .public
                .as_deref()
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string);
            let key = SshKey {
                external_id: None,
                label: k
                    .label
                    .as_deref()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .unwrap_or(label)
                    .to_string(),
                key_type: infer_key_type(&private, public.as_deref()),
                private_key: format!("{private}\n"),
                public_key: public,
                passphrase: k.passphrase.clone().filter(|p| !p.is_empty()),
                fido2_credential_id: None,
                ssh_id: false,
            };
            plan.put("ssh_key", key_id, &key)?;
            ident.ssh_key_id = Some(key_id);
            ident.ssh_certificate_id = None;
        }
        None => {
            plan_delete_key(v, plan, id, ident.ssh_key_id);
            ident.ssh_key_id = None;
            ident.ssh_certificate_id = None;
        }
    }
    plan.put("identity", id, &ident)?;
    Ok(Some(id))
}

/// Drop a key that only `identity_id` referenced.
fn plan_delete_key(v: &VaultState, plan: &mut Plan, identity_id: Uuid, key_id: Option<Uuid>) {
    let Some(kid) = key_id else { return };
    let shared = v
        .iter_kind::<Identity>("identity")
        .any(|(id, _, i)| id != identity_id && i.ssh_key_id == Some(kid));
    if !shared && v.version_of(kid).is_some() {
        plan.delete(kid);
    }
}

fn plan_delete_ssh(v: &VaultState, plan: &mut Plan, id: Option<Uuid>) {
    let Some(id) = id else { return };
    if let Some(cfg) = v.get::<SshConfig>(id, "ssh_config") {
        if let Some(iid) = cfg.identity_id
            && let Some(i) = v.get::<Identity>(iid, "identity").filter(|i| !i.is_visible)
        {
            plan_delete_key(v, plan, iid, i.ssh_key_id);
            plan.delete(iid);
        }
        plan.delete(id);
    }
}

fn plan_delete_telnet(v: &VaultState, plan: &mut Plan, id: Option<Uuid>) {
    let Some(id) = id else { return };
    if let Some(cfg) = v.get::<TelnetConfig>(id, "telnet_config") {
        if let Some(iid) = cfg.identity_id
            && v.get::<Identity>(iid, "identity")
                .is_some_and(|i| !i.is_visible)
        {
            plan.delete(iid);
        }
        plan.delete(id);
    }
}

fn plan_delete_webdav(v: &VaultState, plan: &mut Plan, id: Option<Uuid>) {
    let Some(id) = id else { return };
    if let Some(cfg) = v.get::<WebDavConfig>(id, "webdav_config") {
        if let Some(iid) = cfg.identity_id
            && v.get::<Identity>(iid, "identity")
                .is_some_and(|i| !i.is_visible)
        {
            plan.delete(iid);
        }
        plan.delete(id);
    }
}

fn plan_delete_host(v: &VaultState, plan: &mut Plan, id: Uuid, h: &Host) {
    plan_delete_ssh(v, plan, h.ssh_config_id);
    plan_delete_telnet(v, plan, h.telnet_config_id);
    plan_delete_webdav(v, plan, h.webdav_config_id);
    plan.delete(id);
}

fn infer_key_type(private: &str, public: Option<&str>) -> String {
    if let Some(p) = public {
        let algo = p.split_whitespace().next().unwrap_or("");
        return match algo {
            "ssh-ed25519" => "ed25519",
            "ssh-rsa" => "rsa",
            a if a.starts_with("ecdsa-") => "ecdsa",
            _ => "",
        }
        .to_string();
    }
    let head = private.lines().next().unwrap_or("");
    match head {
        "-----BEGIN RSA PRIVATE KEY-----" => "rsa",
        "-----BEGIN EC PRIVATE KEY-----" => "ecdsa",
        _ => "",
    }
    .to_string()
}

fn plan_snippet(v: &VaultState, external_id: &str, req: &SnippetRequest) -> Result<Plan> {
    v.require_key()?;
    let mut plan = Plan::default();
    let existing = v.snippet_by_external_id(external_id);
    let id = existing
        .as_ref()
        .map(|(id, _)| *id)
        .unwrap_or_else(Uuid::new_v4);
    let old = existing.map(|(_, s)| s).unwrap_or_default();
    plan.put(
        "snippet",
        id,
        &Snippet {
            label: req.label.trim().to_string(),
            script: req.script.clone(),
            package_id: old.package_id,
            close_after_run: req.close_after_run,
            sort_order: old.sort_order,
            external_id: Some(external_id.to_string()),
        },
    )?;
    Ok(plan)
}

/// A keychain-visible identity owned by an external system.
fn plan_shared_identity(v: &VaultState, external_id: &str, req: &IdentityRequest) -> Result<Plan> {
    v.require_key()?;
    let mut plan = Plan::default();
    let existing = v.identity_by_external_id(external_id);
    let id = existing
        .as_ref()
        .map(|(id, _)| *id)
        .unwrap_or_else(Uuid::new_v4);
    let old = existing.map(|(_, i)| i).unwrap_or_default();
    let ssh_key_id = match req.key.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
        Some(k) => Some(v.key_by_external_id(k).map(|(id, _)| id).ok_or_else(|| {
            BridgeError::NotFound(format!("key '{k}' not found in vault '{}'", v.name))
        })?),
        None => None,
    };
    let username = req.username.as_deref().unwrap_or("").trim().to_string();
    let label = req
        .label
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if username.is_empty() {
                external_id.to_string()
            } else {
                username.clone()
            }
        });
    plan.put(
        "identity",
        id,
        &Identity {
            label,
            username,
            password: req.password.clone().filter(|p| !p.is_empty()),
            ssh_key_id,
            ssh_certificate_id: None,
            is_visible: true,
            ssh_id: false,
            ssh_id_key_type: None,
            bearer_token: old.bearer_token,
            client_certificate: old.client_certificate,
            totp_secret: old.totp_secret,
            external_id: Some(external_id.to_string()),
        },
    )?;
    Ok(plan)
}

fn plan_key(v: &VaultState, external_id: &str, req: &KeyRequest) -> Result<Plan> {
    v.require_key()?;
    let mut plan = Plan::default();
    let id = v
        .key_by_external_id(external_id)
        .map(|(id, _)| id)
        .unwrap_or_else(Uuid::new_v4);
    let private = req.private.trim().to_string();
    let public = req
        .public
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string);
    plan.put(
        "ssh_key",
        id,
        &SshKey {
            label: req
                .label
                .as_deref()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .unwrap_or(external_id)
                .to_string(),
            key_type: infer_key_type(&private, public.as_deref()),
            private_key: format!("{private}\n"),
            public_key: public,
            passphrase: req.passphrase.clone().filter(|p| !p.is_empty()),
            fido2_credential_id: None,
            ssh_id: false,
            external_id: Some(external_id.to_string()),
        },
    )?;
    Ok(plan)
}

/// SSH/telnet configs (hosts and groups) pointing at `identity_id`.
fn identity_users(v: &VaultState, identity_id: Uuid) -> usize {
    v.iter_kind::<SshConfig>("ssh_config")
        .filter(|(_, _, c)| c.identity_id == Some(identity_id))
        .count()
        + v.iter_kind::<TelnetConfig>("telnet_config")
            .filter(|(_, _, c)| c.identity_id == Some(identity_id))
            .count()
}

fn key_users(v: &VaultState, key_id: Uuid) -> usize {
    v.iter_kind::<Identity>("identity")
        .filter(|(_, _, i)| i.ssh_key_id == Some(key_id))
        .count()
}

fn snippet_summary(v: &VaultState, id: Uuid, s: &Snippet) -> SnippetSummary {
    SnippetSummary {
        id,
        external_id: s.external_id.clone().unwrap_or_default(),
        vault: v.name.clone(),
        vault_id: v.id,
        label: s.label.clone(),
        script: s.script.clone(),
        close_after_run: s.close_after_run,
    }
}

fn identity_summary(v: &VaultState, id: Uuid, i: &Identity) -> IdentitySummary {
    IdentitySummary {
        id,
        external_id: i.external_id.clone().unwrap_or_default(),
        vault: v.name.clone(),
        vault_id: v.id,
        label: i.label.clone(),
        username: i.username.clone(),
        has_password: i.password.as_deref().is_some_and(|p| !p.is_empty()),
        key: i
            .ssh_key_id
            .and_then(|k| v.get::<SshKey>(k, "ssh_key"))
            .and_then(|k| k.external_id),
        used_by: identity_users(v, id),
    }
}

fn key_summary(v: &VaultState, id: Uuid, k: &SshKey) -> KeySummary {
    KeySummary {
        id,
        external_id: k.external_id.clone().unwrap_or_default(),
        vault: v.name.clone(),
        vault_id: v.id,
        label: k.label.clone(),
        key_type: k.key_type.clone(),
        public_key: k.public_key.clone(),
        has_passphrase: k.passphrase.as_deref().is_some_and(|p| !p.is_empty()),
        used_by: key_users(v, id),
    }
}

// ───────────────────────────── validation ─────────────────────────────

const MAX_SCRIPT_BYTES: usize = 64 * 1024;

fn validate_snippet(req: &SnippetRequest) -> Result<()> {
    if req.label.trim().is_empty() {
        return Err(BridgeError::Invalid("snippet label is required".into()));
    }
    if req.script.trim().is_empty() {
        return Err(BridgeError::Invalid("snippet script is required".into()));
    }
    if req.script.len() > MAX_SCRIPT_BYTES {
        return Err(BridgeError::Invalid(format!(
            "snippet script exceeds {MAX_SCRIPT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_identity(req: &IdentityRequest) -> Result<()> {
    let has_user = req
        .username
        .as_deref()
        .is_some_and(|u| !u.trim().is_empty());
    let has_secret = req.password.as_deref().is_some_and(|p| !p.is_empty())
        || req.key.as_deref().is_some_and(|k| !k.trim().is_empty());
    if !has_user && !has_secret {
        return Err(BridgeError::Invalid(
            "identity needs a username, a password or a key".into(),
        ));
    }
    Ok(())
}

fn validate_key(req: &KeyRequest) -> Result<()> {
    let private = req.private.trim();
    if private.is_empty() {
        return Err(BridgeError::Invalid("private key is required".into()));
    }
    if !private.starts_with("-----BEGIN ") {
        return Err(BridgeError::Invalid(
            "private key must be PEM / OpenSSH format".into(),
        ));
    }
    if private.len() > MAX_KEY_BYTES {
        return Err(BridgeError::Invalid(format!(
            "private key exceeds {MAX_KEY_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_external_id(s: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty() {
        return Err(BridgeError::Invalid("external_id must not be empty".into()));
    }
    if s.chars().count() > MAX_EXTERNAL_ID {
        return Err(BridgeError::Invalid(format!(
            "external_id longer than {MAX_EXTERNAL_ID} characters"
        )));
    }
    if s.chars().any(char::is_control) {
        return Err(BridgeError::Invalid(
            "external_id contains control characters".into(),
        ));
    }
    Ok(s.to_string())
}

fn validate_text(what: &str, s: Option<&str>, max: usize) -> Result<()> {
    if let Some(s) = s {
        if s.chars().count() > max {
            return Err(BridgeError::Invalid(format!(
                "{what} longer than {max} characters"
            )));
        }
        if s.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
            return Err(BridgeError::Invalid(format!(
                "{what} contains control characters"
            )));
        }
    }
    Ok(())
}

fn validate_credentials(where_: &str, c: Option<&Credentials>) -> Result<()> {
    if let Some(c) = c
        && c.identity.as_deref().is_some_and(|i| !i.trim().is_empty())
        && (c.username.is_some() || c.password.is_some() || c.key.is_some())
    {
        return Err(BridgeError::Invalid(format!(
            "{where_}: credentials.identity cannot be combined with username/password/key"
        )));
    }
    let Some(c) = c else { return Ok(()) };
    validate_text(
        &format!("{where_}.credentials.username"),
        c.username.as_deref(),
        MAX_LABEL,
    )?;
    if c.password.as_deref().is_some_and(|p| p.len() > 4096) {
        return Err(BridgeError::Invalid(format!(
            "{where_}.credentials.password is too long"
        )));
    }
    if let Some(k) = &c.key {
        let p = k.private.trim();
        if p.len() > MAX_KEY_BYTES {
            return Err(BridgeError::Invalid(format!(
                "{where_}.credentials.key.private is too large"
            )));
        }
        if !(p.starts_with("-----BEGIN ") && p.contains("PRIVATE KEY-----")) {
            return Err(BridgeError::Invalid(format!(
                "{where_}.credentials.key.private must be a PEM/OpenSSH private key"
            )));
        }
        validate_text(
            &format!("{where_}.credentials.key.label"),
            k.label.as_deref(),
            MAX_LABEL,
        )?;
        if k.public.as_deref().is_some_and(|s| s.len() > MAX_KEY_BYTES) {
            return Err(BridgeError::Invalid(format!(
                "{where_}.credentials.key.public is too large"
            )));
        }
    }
    Ok(())
}

fn validate_port(where_: &str, p: Option<u16>) -> Result<()> {
    if p == Some(0) {
        return Err(BridgeError::Invalid(format!(
            "{where_}.port must be 1..65535"
        )));
    }
    Ok(())
}

fn validate_host(req: &HostRequest) -> Result<()> {
    let addr = req.address.trim();
    if addr.is_empty() {
        return Err(BridgeError::Invalid("address is required".into()));
    }
    if addr.chars().count() > MAX_ADDRESS
        || addr.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(BridgeError::Invalid(
            "address is not a valid host name or IP".into(),
        ));
    }
    validate_text("label", req.label.as_deref(), MAX_LABEL)?;
    validate_text("vault", req.vault.as_deref(), MAX_LABEL)?;
    validate_text("group", req.group.as_deref(), MAX_EXTERNAL_ID)?;
    validate_text("os", req.os.as_deref(), MAX_LABEL)?;
    validate_text("notes", req.notes.as_deref(), MAX_NOTES)?;
    if req.tags.len() > MAX_TAGS {
        return Err(BridgeError::Invalid(format!("at most {MAX_TAGS} tags")));
    }
    for t in &req.tags {
        validate_text("tags[]", Some(t), 64)?;
    }
    if let Some(s) = &req.ssh {
        validate_port("ssh", s.port)?;
        validate_credentials("ssh", s.credentials.as_ref())?;
    }
    if let Some(t) = &req.telnet {
        validate_port("telnet", t.port)?;
        validate_credentials("telnet", t.credentials.as_ref())?;
        if t.credentials.as_ref().is_some_and(|c| c.key.is_some()) {
            return Err(BridgeError::Invalid(
                "telnet.credentials.key is not supported".into(),
            ));
        }
    }
    Ok(())
}

fn validate_group(req: &GroupRequest) -> Result<()> {
    if req.label.trim().is_empty() {
        return Err(BridgeError::Invalid("label is required".into()));
    }
    validate_text("label", Some(&req.label), MAX_LABEL)?;
    validate_text("vault", req.vault.as_deref(), MAX_LABEL)?;
    validate_text("parent", req.parent.as_deref(), MAX_EXTERNAL_ID)?;
    if let Some(s) = &req.ssh {
        validate_port("ssh", s.port)?;
        validate_credentials("ssh", s.credentials.as_ref())?;
    }
    if let Some(t) = &req.telnet {
        validate_port("telnet", t.port)?;
        validate_credentials("telnet", t.credentials.as_ref())?;
        if t.credentials.as_ref().is_some_and(|c| c.key.is_some()) {
            return Err(BridgeError::Invalid(
                "telnet.credentials.key is not supported".into(),
            ));
        }
    }
    Ok(())
}

// ───────────────────────────── views ─────────────────────────────

fn host_summary(v: &VaultState, id: Uuid, h: &Host) -> HostSummary {
    let ssh = h
        .ssh_config_id
        .and_then(|c| v.get::<SshConfig>(c, "ssh_config"));
    let telnet = h
        .telnet_config_id
        .and_then(|c| v.get::<TelnetConfig>(c, "telnet_config"));
    let has_credentials = ssh.as_ref().is_some_and(|c| c.identity_id.is_some())
        || telnet.as_ref().is_some_and(|c| c.identity_id.is_some());
    HostSummary {
        id,
        external_id: h.external_id.clone().unwrap_or_default(),
        vault: v.name.clone(),
        vault_id: v.id,
        group: h
            .group_id
            .and_then(|g| v.get::<Group>(g, "group"))
            .and_then(|g| g.external_id),
        label: h.label.clone(),
        address: h.address.clone(),
        tags: h
            .tag_ids
            .iter()
            .filter_map(|t| v.get::<Tag>(*t, "tag").map(|t| t.label))
            .collect(),
        ssh_port: match &ssh {
            Some(c) => Some(c.port.unwrap_or(22)),
            None if h.telnet_config_id.is_none() => Some(22),
            None => None,
        },
        telnet_port: telnet.map(|c| c.port.unwrap_or(23)),
        has_credentials,
    }
}

fn group_summary(v: &VaultState, id: Uuid, g: &Group) -> GroupSummary {
    GroupSummary {
        id,
        external_id: g.external_id.clone().unwrap_or_default(),
        vault: v.name.clone(),
        vault_id: v.id,
        parent: g
            .parent_id
            .and_then(|p| v.get::<Group>(p, "group"))
            .and_then(|p| p.external_id),
        label: g.label.clone(),
        hosts: v
            .iter_kind::<Host>("host")
            .filter(|(_, _, h)| h.group_id == Some(id))
            .count(),
    }
}

fn status_of(b: &Bridge, inner: &Inner) -> BridgeStatus {
    let mut vaults: Vec<VaultSummary> = inner
        .vaults
        .values()
        .map(|v| VaultSummary {
            id: v.id,
            name: v.name.clone(),
            kind: enum_str(&v.kind),
            role: enum_str(&v.role),
            key_version: v.key_version,
            ready: v.ready(),
            hosts: v.count_kind("host"),
            groups: v.count_kind("group"),
        })
        .collect();
    vaults.sort_by(|a, b| a.name.cmp(&b.name));
    BridgeStatus {
        bridge_id: b.bridge_id,
        name: inner.me.name.clone(),
        server: b.server_url(),
        version: env!("CARGO_PKG_VERSION"),
        vaults,
    }
}

fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_string))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_type_inference() {
        assert_eq!(infer_key_type("x", Some("ssh-ed25519 AAAA c")), "ed25519");
        assert_eq!(infer_key_type("x", Some("ssh-rsa AAAA")), "rsa");
        assert_eq!(
            infer_key_type("x", Some("ecdsa-sha2-nistp256 AAAA")),
            "ecdsa"
        );
        assert_eq!(
            infer_key_type("-----BEGIN RSA PRIVATE KEY-----\n", None),
            "rsa"
        );
        assert_eq!(
            infer_key_type("-----BEGIN OPENSSH PRIVATE KEY-----\n", None),
            ""
        );
    }

    #[test]
    fn validation_rejects_garbage() {
        assert!(validate_external_id("  ").is_err());
        assert!(validate_external_id("a\u{0}b").is_err());
        assert!(validate_external_id(&"x".repeat(201)).is_err());
        assert_eq!(validate_external_id(" vm-1 ").unwrap(), "vm-1");

        let mut req = HostRequest {
            address: "10.0.0.1".into(),
            ..Default::default()
        };
        validate_host(&req).unwrap();
        req.address = "bad host".into();
        assert!(validate_host(&req).is_err());
        req.address = "ok".into();
        req.ssh = Some(SshSection {
            port: Some(0),
            credentials: None,
        });
        assert!(validate_host(&req).is_err());
        req.ssh = Some(SshSection {
            port: Some(22),
            credentials: Some(Credentials {
                key: Some(crate::model::KeyInput {
                    private: "not a key".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        });
        assert!(validate_host(&req).is_err());
        req.tags = (0..33).map(|i| i.to_string()).collect();
        req.ssh = None;
        assert!(validate_host(&req).is_err());
    }

    #[test]
    fn shared_entries_are_validated() {
        let mut req = HostRequest {
            address: "10.0.0.1".into(),
            ssh: Some(SshSection {
                port: None,
                credentials: Some(Credentials {
                    identity: Some("ops".into()),
                    ..Default::default()
                }),
            }),
            ..Default::default()
        };
        validate_host(&req).unwrap();
        req.ssh
            .as_mut()
            .unwrap()
            .credentials
            .as_mut()
            .unwrap()
            .username = Some("root".into());
        assert!(
            validate_host(&req).is_err(),
            "identity excludes inline fields"
        );

        assert!(validate_snippet(&SnippetRequest::default()).is_err());
        assert!(
            validate_snippet(&SnippetRequest {
                label: "uptime".into(),
                script: "uptime".into(),
                ..Default::default()
            })
            .is_ok()
        );
        assert!(
            validate_snippet(&SnippetRequest {
                label: "big".into(),
                script: "x".repeat(MAX_SCRIPT_BYTES + 1),
                ..Default::default()
            })
            .is_err()
        );

        assert!(validate_identity(&IdentityRequest::default()).is_err());
        assert!(
            validate_identity(&IdentityRequest {
                key: Some("k1".into()),
                ..Default::default()
            })
            .is_ok()
        );

        assert!(validate_key(&KeyRequest::default()).is_err());
        assert!(
            validate_key(&KeyRequest {
                private: "not a key".into(),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            validate_key(&KeyRequest {
                private:
                    "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
                        .into(),
                ..Default::default()
            })
            .is_ok()
        );
    }
}
