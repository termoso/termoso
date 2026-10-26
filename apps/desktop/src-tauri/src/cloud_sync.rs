//! Cloud sync groups: a host group that mirrors a cloud account. The group
//! remembers the provider, region and default SSH settings; the credentials
//! live only in this device's encrypted local metadata (never in a vault
//! entity, so they never sync or reach the server) and are decrypted for
//! the duration of one listing call. A refresh — manual "Sync now" or the
//! background scheduler — reuses the one-shot import reconciliation
//! ([`crate::cloud::apply_scoped`]): new machines appear as hosts, address /
//! provider label / OS follow the provider, hosts the provider no longer
//! lists are removed from the group (if asked), and everything the user set
//! on a host stays.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use termoso_core::cloud::{
    AddressType, AwsConfig, AwsService, AzureConfig, CloudClient, CloudConfig, CloudError,
    CloudProvider, DigitalOceanConfig, Endpoints,
};
use termoso_core::model::{Entity, Group};
use termoso_core::store::Store;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cloud::{self, CloudImportReport, CloudSelection};
use crate::error::{DesktopError, Result};
use crate::state::AppState;

const CONFIG_PREFIX: &str = "cloud_sync:";
const STATUS_PREFIX: &str = "cloud_sync_status:";
/// `secret:` prefix keeps the blob in the set the store re-encrypts when the
/// master key is rotated.
const SECRET_PREFIX: &str = "secret:cloud_sync:";

/// Name of the webview event carrying a [`CloudSyncGroup`] after a refresh.
pub const EVENT: &str = "cloud-sync";
/// How often the scheduler looks for due groups.
const TICK: Duration = Duration::from_secs(30);
/// Shortest interval we accept; provider APIs are rate limited and hosts do
/// not appear that often.
pub const MIN_INTERVAL_MINUTES: u32 = 5;
pub const MAX_INTERVAL_MINUTES: u32 = 7 * 24 * 60;

/// What a sync group remembers about its cloud account — without secrets.
/// Stored in local (non-synced) metadata keyed by group id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudSyncConfig {
    pub provider: CloudProvider,
    /// AWS region (`eu-central-1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// AWS: EC2 or Lightsail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<AwsService>,
    /// AWS: public or private address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_type: Option<AddressType>,
    /// AWS access key id (not secret; shown so the user knows which key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    /// Azure tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Azure service principal (application) id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Default SSH username for hosts the sync creates.
    #[serde(default)]
    pub username: String,
    /// Default SSH port for new hosts; `None` = 22.
    #[serde(default)]
    pub port: Option<u16>,
    /// Tags added to new hosts.
    #[serde(default)]
    pub tag_ids: Vec<Uuid>,
    /// Remove hosts in the group the provider no longer lists.
    #[serde(default = "default_true")]
    pub remove_missing: bool,
    /// Background refresh period; `0` = only on "Sync now".
    #[serde(default = "default_interval")]
    pub interval_minutes: u32,
    /// Paused groups keep their settings but never refresh in the background.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

fn default_interval() -> u32 {
    60
}

impl CloudSyncConfig {
    /// Check what can be checked without the secret.
    fn validate(&self) -> Result<()> {
        match self.provider {
            CloudProvider::Aws => {
                let region = self.region.as_deref().unwrap_or("").trim();
                if region.is_empty() {
                    return Err(DesktopError::invalid("region is required"));
                }
                if self
                    .access_key_id
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(DesktopError::invalid("access key id is required"));
                }
            }
            CloudProvider::DigitalOcean => {}
            CloudProvider::Azure => {
                if self.tenant_id.as_deref().unwrap_or("").trim().is_empty()
                    || self.client_id.as_deref().unwrap_or("").trim().is_empty()
                {
                    return Err(DesktopError::invalid(
                        "tenant id and client id are required",
                    ));
                }
            }
        }
        if self.interval_minutes != 0
            && !(MIN_INTERVAL_MINUTES..=MAX_INTERVAL_MINUTES).contains(&self.interval_minutes)
        {
            return Err(DesktopError::invalid(format!(
                "refresh interval must be 0 (manual) or {MIN_INTERVAL_MINUTES}–{MAX_INTERVAL_MINUTES} minutes"
            )));
        }
        Ok(())
    }

    /// Provider credentials joined with the settings. The result holds the
    /// secret and must not outlive the listing call.
    fn to_cloud_config(&self, secret: &CloudSyncSecret) -> Result<CloudConfig> {
        let cfg = match self.provider {
            CloudProvider::Aws => CloudConfig::Aws(AwsConfig {
                region: self.region.clone().unwrap_or_default().trim().to_string(),
                access_key_id: self
                    .access_key_id
                    .clone()
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                secret_access_key: Zeroizing::new(
                    secret
                        .secret_access_key
                        .as_deref()
                        .unwrap_or("")
                        .to_string(),
                ),
                service: self.service.unwrap_or(AwsService::Ec2),
                address_type: self.address_type.unwrap_or(AddressType::Public),
            }),
            CloudProvider::DigitalOcean => CloudConfig::DigitalOcean(DigitalOceanConfig {
                token: Zeroizing::new(secret.token.as_deref().unwrap_or("").to_string()),
            }),
            CloudProvider::Azure => CloudConfig::Azure(AzureConfig {
                tenant_id: self
                    .tenant_id
                    .clone()
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                client_id: self
                    .client_id
                    .clone()
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                client_secret: Zeroizing::new(
                    secret.client_secret.as_deref().unwrap_or("").to_string(),
                ),
            }),
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

/// The secret half of the provider credentials. Comes in from the webview
/// when the user types it, goes out only as ciphertext in local metadata.
#[derive(Clone, Default, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct CloudSyncSecret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_access_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

impl std::fmt::Debug for CloudSyncSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CloudSyncSecret { .. }")
    }
}

impl CloudSyncSecret {
    fn is_empty(&self) -> bool {
        [&self.secret_access_key, &self.token, &self.client_secret]
            .iter()
            .all(|s| s.as_deref().is_none_or(|v| v.trim().is_empty()))
    }
}

/// Outcome of the last refresh, kept locally so the group shows it after a
/// restart.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudSyncStatus {
    /// When the last refresh finished (success or failure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run: Option<DateTime<Utc>>,
    /// When the last *successful* refresh finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success: Option<DateTime<Utc>>,
    /// Error kind of the last failure (`cloud_invalid_credentials`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    /// Human-readable error of the last failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Counts of the last successful refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<CloudImportReport>,
    /// Machines the provider listed last time (including ones without an
    /// address).
    #[serde(default)]
    pub instances: usize,
}

/// A group with cloud sync configured — what the webview lists and edits.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudSyncGroup {
    pub group_id: Uuid,
    pub vault_id: Uuid,
    pub label: String,
    pub config: CloudSyncConfig,
    pub status: CloudSyncStatus,
    /// Whether a secret is stored for this group on this device. A synced
    /// group on another device shows up as a plain group there.
    pub has_secret: bool,
    /// A refresh is in flight right now.
    pub running: bool,
    /// When the scheduler will refresh next; `None` for manual/paused
    /// groups or when the secret is missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_run: Option<DateTime<Utc>>,
}

/// Viewers of a synced vault cannot create hosts, so a sync group there
/// would only ever fail.
fn vault_read_only(store: &Store, vault_id: Uuid) -> Result<bool> {
    let v = store.vault(vault_id)?;
    Ok(v.kind.is_synced() && !v.role.can_write())
}

fn config_key(group_id: Uuid) -> String {
    format!("{CONFIG_PREFIX}{group_id}")
}

fn status_key(group_id: Uuid) -> String {
    format!("{STATUS_PREFIX}{group_id}")
}

fn secret_key(group_id: Uuid) -> String {
    format!("{SECRET_PREFIX}{group_id}")
}

fn running() -> &'static Mutex<HashSet<Uuid>> {
    static RUNNING: OnceLock<Mutex<HashSet<Uuid>>> = OnceLock::new();
    RUNNING.get_or_init(Mutex::default)
}

fn is_running(group_id: Uuid) -> bool {
    running()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&group_id)
}

/// Marks a group as refreshing while alive.
struct RunGuard(Uuid);

impl RunGuard {
    fn acquire(group_id: Uuid) -> Option<Self> {
        running()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(group_id)
            .then_some(Self(group_id))
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        running()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

pub fn load_config(store: &Store, group_id: Uuid) -> Result<Option<CloudSyncConfig>> {
    Ok(match store.meta(&config_key(group_id))? {
        Some(raw) => Some(serde_json::from_str(&raw)?),
        None => None,
    })
}

fn load_status(store: &Store, group_id: Uuid) -> Result<CloudSyncStatus> {
    Ok(match store.meta(&status_key(group_id))? {
        Some(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        None => CloudSyncStatus::default(),
    })
}

fn save_status(store: &Store, group_id: Uuid, status: &CloudSyncStatus) -> Result<()> {
    Ok(store.set_meta(&status_key(group_id), &serde_json::to_string(status)?)?)
}

fn load_secret(store: &Store, group_id: Uuid) -> Result<Option<CloudSyncSecret>> {
    Ok(match store.secret_meta(&secret_key(group_id))? {
        Some(raw) => {
            let raw = Zeroizing::new(raw);
            Some(serde_json::from_str(raw.as_str())?)
        }
        None => None,
    })
}

fn has_secret(store: &Store, group_id: Uuid) -> Result<bool> {
    Ok(store.meta(&secret_key(group_id))?.is_some())
}

fn next_run(
    config: &CloudSyncConfig,
    status: &CloudSyncStatus,
    has_secret: bool,
) -> Option<DateTime<Utc>> {
    if !config.enabled || config.interval_minutes == 0 || !has_secret {
        return None;
    }
    let period = chrono::Duration::minutes(i64::from(config.interval_minutes));
    Some(match status.last_run {
        Some(t) => t + period,
        None => Utc::now(),
    })
}

fn describe(store: &Store, g: &Entity<Group>, config: CloudSyncConfig) -> Result<CloudSyncGroup> {
    let status = load_status(store, g.id)?;
    let has_secret = has_secret(store, g.id)?;
    Ok(CloudSyncGroup {
        group_id: g.id,
        vault_id: g.vault_id,
        label: g.data.label.clone(),
        next_run: next_run(&config, &status, has_secret),
        config,
        status,
        has_secret,
        running: is_running(g.id),
    })
}

/// Every group with a sync config, optionally only in one vault. Configs
/// whose group is gone are dropped on the way.
pub fn list(store: &Store, vault_id: Option<Uuid>) -> Result<Vec<CloudSyncGroup>> {
    let mut out = Vec::new();
    for key in store.meta_keys(CONFIG_PREFIX)? {
        let Ok(gid) = Uuid::parse_str(&key[CONFIG_PREFIX.len()..]) else {
            continue;
        };
        let Some(g) = store.get::<Group>(gid)? else {
            forget(store, gid)?;
            continue;
        };
        if vault_id.is_some_and(|v| v != g.vault_id) {
            continue;
        }
        let Some(config) = load_config(store, gid)? else {
            continue;
        };
        out.push(describe(store, &g, config)?);
    }
    out.sort_by_key(|a| a.label.to_lowercase());
    Ok(out)
}

pub fn get(store: &Store, group_id: Uuid) -> Result<Option<CloudSyncGroup>> {
    let Some(g) = store.get::<Group>(group_id)? else {
        return Ok(None);
    };
    let Some(config) = load_config(store, group_id)? else {
        return Ok(None);
    };
    Ok(Some(describe(store, &g, config)?))
}

/// Create or update the sync settings of a group. `secret` replaces the
/// stored credentials; `None` keeps them (required when none are stored
/// yet). Switching provider or key id without a new secret is refused so
/// a stale secret never gets paired with a different identity.
pub fn save(
    store: &Store,
    group_id: Uuid,
    config: CloudSyncConfig,
    secret: Option<CloudSyncSecret>,
) -> Result<CloudSyncGroup> {
    let g = store.require::<Group>(group_id)?;
    if vault_read_only(store, g.vault_id)? {
        return Err(DesktopError::new(
            "vault_read_only",
            "this vault is view-only for you; cloud sync cannot create hosts in it",
        ));
    }
    config.validate()?;
    let previous = load_config(store, group_id)?;
    let secret = secret.filter(|s| !s.is_empty());
    match (&secret, &previous) {
        (Some(s), _) => {
            // Full validation, including the secret, before anything is written.
            config.to_cloud_config(s)?;
        }
        (None, Some(p)) => {
            if !has_secret(store, group_id)? {
                return Err(DesktopError::invalid("credentials are required"));
            }
            let same_identity = p.provider == config.provider
                && p.access_key_id == config.access_key_id
                && p.tenant_id == config.tenant_id
                && p.client_id == config.client_id;
            if !same_identity {
                return Err(DesktopError::invalid(
                    "enter the credentials again when changing the provider or account",
                ));
            }
        }
        (None, None) => return Err(DesktopError::invalid("credentials are required")),
    }
    store.set_meta(&config_key(group_id), &serde_json::to_string(&config)?)?;
    if let Some(s) = &secret {
        let raw = Zeroizing::new(serde_json::to_string(s)?);
        store.set_secret_meta(&secret_key(group_id), &raw)?;
    }
    if previous
        .as_ref()
        .is_some_and(|p| p.provider != config.provider)
    {
        // A different provider: the old outcome no longer describes this group.
        store.delete_meta(&status_key(group_id))?;
    }
    describe(store, &g, config)
}

/// Drop sync settings, credentials and status of a group. Hosts stay as
/// they are (still linked to their provider, so a later one-shot import
/// refreshes rather than duplicates them).
pub fn forget(store: &Store, group_id: Uuid) -> Result<()> {
    store.delete_meta(&config_key(group_id))?;
    store.delete_meta(&secret_key(group_id))?;
    store.delete_meta(&status_key(group_id))?;
    Ok(())
}

/// Delete a group through `delete`, then [`forget`] the sync settings of
/// it and (for recursive deletes) of every group that was below it.
pub fn delete_group_with(
    store: &Store,
    group_id: Uuid,
    delete: impl FnOnce(&Store, Uuid) -> Result<()>,
) -> Result<()> {
    let ids = match store.get::<Group>(group_id)? {
        Some(g) => subtree(store, &g)?,
        None => HashSet::from([group_id]),
    };
    delete(store, group_id)?;
    for id in ids {
        if store.get::<Group>(id)?.is_none() {
            forget(store, id)?;
        }
    }
    Ok(())
}

/// The group and every group below it, for scoping removals.
fn subtree(store: &Store, g: &Entity<Group>) -> Result<HashSet<Uuid>> {
    let groups: Vec<Entity<Group>> = store.list(Some(g.vault_id))?;
    let mut children: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for c in &groups {
        if let Some(p) = c.data.parent_id {
            children.entry(p).or_default().push(c.id);
        }
    }
    let mut out = HashSet::from([g.id]);
    let mut stack = vec![g.id];
    while let Some(id) = stack.pop() {
        for c in children.get(&id).into_iter().flatten() {
            if out.insert(*c) {
                stack.push(*c);
            }
        }
    }
    Ok(out)
}

/// Refresh one group now: list machines with the stored credentials and
/// reconcile the group's hosts. Concurrent refreshes of the same group are
/// collapsed into one.
pub async fn run(store: &Store, group_id: Uuid) -> Result<CloudSyncGroup> {
    run_with(store, group_id, cloud::endpoints()).await
}

/// [`run`] against explicit provider endpoints.
pub async fn run_with(
    store: &Store,
    group_id: Uuid,
    endpoints: Endpoints,
) -> Result<CloudSyncGroup> {
    let g = store.require::<Group>(group_id)?;
    let config = load_config(store, group_id)?
        .ok_or_else(|| DesktopError::not_found("this group has no cloud sync"))?;
    let Some(_guard) = RunGuard::acquire(group_id) else {
        return describe(store, &g, config);
    };
    let mut status = load_status(store, group_id)?;
    let outcome = refresh(store, &g, &config, endpoints).await;
    status.last_run = Some(Utc::now());
    match outcome {
        Ok((report, instances)) => {
            status.last_success = status.last_run;
            status.error_kind = None;
            status.error = None;
            status.report = Some(report);
            status.instances = instances;
        }
        Err(e) => {
            status.error_kind = Some(e.kind.to_string());
            status.error = Some(e.message.clone());
        }
    }
    save_status(store, group_id, &status)?;
    drop(_guard);
    describe(store, &g, config)
}

async fn refresh(
    store: &Store,
    g: &Entity<Group>,
    config: &CloudSyncConfig,
    endpoints: Endpoints,
) -> Result<(CloudImportReport, usize)> {
    if vault_read_only(store, g.vault_id)? {
        return Err(DesktopError::new(
            "vault_read_only",
            "this vault is view-only for you",
        ));
    }
    let secret = load_secret(store, g.id)?.ok_or_else(|| {
        DesktopError::new(
            "cloud_sync_no_secret",
            "credentials for this group are not stored on this device",
        )
    })?;
    let cloud_config = config.to_cloud_config(&secret)?;
    drop(secret);
    tracing::info!(
        group = %g.id,
        provider = config.provider.name(),
        "cloud sync refresh"
    );
    let instances = CloudClient::new(endpoints)
        .discover(&cloud_config)
        .await
        .map_err(|e: CloudError| DesktopError::new(e.kind(), e.to_string()))?;
    drop(cloud_config);
    let selection = CloudSelection {
        instances: (0..instances.len()).collect(),
        group_id: Some(g.id),
        tag_ids: config.tag_ids.clone(),
        username: config.username.clone(),
        port: config.port,
        remove_missing: config.remove_missing,
    };
    let scope = subtree(store, g)?;
    let report = cloud::apply_scoped(
        store,
        g.vault_id,
        config.provider,
        &instances,
        &selection,
        Some(&scope),
    )?;
    Ok((report, instances.len()))
}

/// Groups whose next refresh is due.
pub fn due(store: &Store) -> Result<Vec<Uuid>> {
    Ok(list(store, None)?
        .into_iter()
        .filter(|g| !g.running)
        .filter(|g| g.next_run.is_some_and(|t| t <= Utc::now()))
        .map(|g| g.group_id)
        .collect())
}

/// Background scheduler: refresh due groups every [`TICK`] and tell the
/// webview about each outcome. Runs for the life of the app.
pub async fn scheduler(app: AppHandle) {
    // Let the window come up and the account resume first.
    tokio::time::sleep(Duration::from_secs(15)).await;
    loop {
        let state = app.state::<AppState>();
        let Ok(store) = state.store() else {
            tokio::time::sleep(TICK).await;
            continue;
        };
        match due(&store) {
            Ok(ids) => {
                for gid in ids {
                    match run(&store, gid).await {
                        Ok(group) => {
                            if let Some(err) = &group.status.error {
                                tracing::warn!(group = %gid, "cloud sync failed: {err}");
                            }
                            let _ = app.emit(EVENT, &group);
                        }
                        Err(e) => tracing::warn!(group = %gid, "cloud sync failed: {e}"),
                    }
                }
            }
            Err(e) => tracing::warn!("cloud sync scheduler: {e}"),
        }
        drop(store);
        tokio::time::sleep(TICK).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoso_core::cloud::CloudInstance;
    use termoso_core::model::Host;
    use termoso_core::termoso_crypto::keys::SymmetricKey;

    fn store() -> Store {
        Store::open_in_memory(SymmetricKey::generate()).expect("store")
    }

    fn group(store: &Store, vault: Uuid, label: &str, parent: Option<Uuid>) -> Uuid {
        crate::hosts::save_group(store, vault, None, label, parent)
            .unwrap()
            .id
    }

    fn aws_config(region: &str) -> CloudSyncConfig {
        CloudSyncConfig {
            provider: CloudProvider::Aws,
            region: Some(region.into()),
            service: Some(AwsService::Ec2),
            address_type: Some(AddressType::Public),
            access_key_id: Some("AKIAEXAMPLE".into()),
            tenant_id: None,
            client_id: None,
            username: "ec2-user".into(),
            port: None,
            tag_ids: vec![],
            remove_missing: true,
            interval_minutes: 60,
            enabled: true,
        }
    }

    fn secret(f: impl FnOnce(&mut CloudSyncSecret)) -> CloudSyncSecret {
        let mut s = CloudSyncSecret::default();
        f(&mut s);
        s
    }

    fn aws_secret() -> CloudSyncSecret {
        secret(|s| s.secret_access_key = Some("SUPERSECRETKEY".into()))
    }

    fn inst(id: &str, label: &str, addr: &str) -> CloudInstance {
        CloudInstance {
            instance_id: id.into(),
            label: label.into(),
            address: Some(addr.into()),
            state: Some("running".into()),
            region: None,
            size: None,
            os: None,
            os_name: None,
        }
    }

    #[test]
    fn save_stores_config_plain_and_secret_encrypted() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let gid = group(&s, vault, "AWS eu", None);
        let saved = save(&s, gid, aws_config("eu-central-1"), Some(aws_secret())).unwrap();
        assert!(saved.has_secret);
        assert!(!saved.running);
        assert_eq!(saved.next_run.map(|t| t <= Utc::now()), Some(true));
        assert_eq!(saved.label, "AWS eu");

        // Plain config is readable and carries no secret material.
        let raw = s.meta(&config_key(gid)).unwrap().unwrap();
        assert!(raw.contains("AKIAEXAMPLE"));
        assert!(!raw.contains("SUPERSECRETKEY"));
        // The secret row is ciphertext…
        let ct = s.meta(&secret_key(gid)).unwrap().unwrap();
        assert!(!ct.contains("SUPERSECRETKEY"));
        // …and round-trips through the store's master key.
        let sec = load_secret(&s, gid).unwrap().unwrap();
        assert_eq!(sec.secret_access_key.as_deref(), Some("SUPERSECRETKEY"));
        // Nothing the webview sees has the secret in it.
        let json = serde_json::to_string(&saved).unwrap();
        assert!(!json.contains("SUPERSECRETKEY"));
        assert!(!format!("{saved:?}").contains("SUPERSECRETKEY"));
        assert_eq!(list(&s, Some(vault)).unwrap().len(), 1);
        assert_eq!(list(&s, Some(Uuid::new_v4())).unwrap().len(), 0);
    }

    #[test]
    fn save_requires_secret_and_refuses_identity_change_without_it() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let gid = group(&s, vault, "AWS", None);
        let err = save(&s, gid, aws_config("eu-central-1"), None).unwrap_err();
        assert_eq!(err.kind, "invalid");
        let err = save(
            &s,
            gid,
            aws_config("eu-central-1"),
            Some(CloudSyncSecret::default()),
        )
        .unwrap_err();
        assert_eq!(err.kind, "invalid");

        save(&s, gid, aws_config("eu-central-1"), Some(aws_secret())).unwrap();
        // Region change keeps the key: fine without re-entering the secret.
        let updated = save(&s, gid, aws_config("us-east-1"), None).unwrap();
        assert_eq!(updated.config.region.as_deref(), Some("us-east-1"));
        assert!(updated.has_secret);
        // Another key id must come with its secret.
        let mut other = aws_config("us-east-1");
        other.access_key_id = Some("AKIAOTHER".into());
        let err = save(&s, gid, other.clone(), None).unwrap_err();
        assert!(err.message.contains("credentials"));
        save(&s, gid, other, Some(aws_secret())).unwrap();
        // Interval bounds.
        let mut bad = aws_config("us-east-1");
        bad.access_key_id = Some("AKIAOTHER".into());
        bad.interval_minutes = 1;
        assert!(save(&s, gid, bad, None).is_err());
    }

    #[test]
    fn save_validates_secret_against_provider_before_writing() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let gid = group(&s, vault, "DO", None);
        let cfg = CloudSyncConfig {
            provider: CloudProvider::DigitalOcean,
            username: "root".into(),
            ..aws_config("")
        };
        // AWS secret for a DigitalOcean group: token missing → rejected, nothing stored.
        let err = save(&s, gid, cfg.clone(), Some(aws_secret())).unwrap_err();
        assert_eq!(err.kind, "invalid");
        assert!(load_config(&s, gid).unwrap().is_none());
        assert!(!has_secret(&s, gid).unwrap());
        let ok = save(
            &s,
            gid,
            cfg,
            Some(secret(|s| s.token = Some("dop_v1_x".into()))),
        )
        .unwrap();
        assert_eq!(ok.config.provider, CloudProvider::DigitalOcean);
    }

    #[test]
    fn forget_removes_everything_and_list_drops_deleted_groups() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let gid = group(&s, vault, "AWS", None);
        save(&s, gid, aws_config("eu-central-1"), Some(aws_secret())).unwrap();
        save_status(
            &s,
            gid,
            &CloudSyncStatus {
                last_run: Some(Utc::now()),
                ..Default::default()
            },
        )
        .unwrap();
        forget(&s, gid).unwrap();
        assert!(s.meta(&config_key(gid)).unwrap().is_none());
        assert!(s.meta(&secret_key(gid)).unwrap().is_none());
        assert!(s.meta(&status_key(gid)).unwrap().is_none());
        assert!(get(&s, gid).unwrap().is_none());

        let gid2 = group(&s, vault, "Gone", None);
        save(&s, gid2, aws_config("eu-central-1"), Some(aws_secret())).unwrap();
        crate::hosts::delete_group(&s, gid2).unwrap();
        assert!(list(&s, None).unwrap().is_empty());
        assert!(s.meta(&secret_key(gid2)).unwrap().is_none());
    }

    #[test]
    fn recursive_group_delete_forgets_nested_sync_settings() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let parent = group(&s, vault, "clouds", None);
        let child = group(&s, vault, "AWS eu", Some(parent));
        let sibling = group(&s, vault, "other", None);
        save(&s, child, aws_config("eu-central-1"), Some(aws_secret())).unwrap();
        save(&s, sibling, aws_config("us-east-1"), Some(aws_secret())).unwrap();

        // A flat delete re-parents the child, which keeps its settings.
        delete_group_with(&s, parent, crate::hosts::delete_group).unwrap();
        assert!(s.meta(&secret_key(child)).unwrap().is_some());
        assert_eq!(list(&s, None).unwrap().len(), 2);

        let parent = group(&s, vault, "clouds", None);
        let mut c = s.require::<Group>(child).unwrap();
        c.data.parent_id = Some(parent);
        s.update(child, &c.data).unwrap();
        delete_group_with(&s, parent, crate::hosts::delete_group_recursive).unwrap();
        assert!(s.meta(&config_key(child)).unwrap().is_none());
        assert!(s.meta(&secret_key(child)).unwrap().is_none());
        assert!(s.meta(&secret_key(sibling)).unwrap().is_some());
        assert_eq!(list(&s, None).unwrap().len(), 1);
    }

    #[test]
    fn next_run_and_due_follow_interval_enabled_and_secret() {
        let cfg = aws_config("eu-central-1");
        let mut status = CloudSyncStatus::default();
        // Never ran: due now.
        assert!(next_run(&cfg, &status, true).is_some());
        assert!(next_run(&cfg, &status, false).is_none());
        let t0 = Utc::now() - chrono::Duration::minutes(30);
        status.last_run = Some(t0);
        assert_eq!(
            next_run(&cfg, &status, true),
            Some(t0 + chrono::Duration::minutes(60))
        );
        let mut manual = cfg.clone();
        manual.interval_minutes = 0;
        assert!(next_run(&manual, &status, true).is_none());
        let mut paused = cfg.clone();
        paused.enabled = false;
        assert!(next_run(&paused, &status, true).is_none());

        let s = store();
        let vault = s.local_vault().unwrap().id;
        let fresh = group(&s, vault, "fresh", None);
        save(&s, fresh, cfg.clone(), Some(aws_secret())).unwrap();
        let recent = group(&s, vault, "recent", None);
        save(&s, recent, cfg.clone(), Some(aws_secret())).unwrap();
        save_status(
            &s,
            recent,
            &CloudSyncStatus {
                last_run: Some(Utc::now()),
                ..Default::default()
            },
        )
        .unwrap();
        let stale = group(&s, vault, "stale", None);
        save(&s, stale, cfg.clone(), Some(aws_secret())).unwrap();
        save_status(
            &s,
            stale,
            &CloudSyncStatus {
                last_run: Some(Utc::now() - chrono::Duration::minutes(61)),
                ..Default::default()
            },
        )
        .unwrap();
        let mut ids = due(&s).unwrap();
        ids.sort();
        let mut want = vec![fresh, stale];
        want.sort();
        assert_eq!(ids, want);
        // A running group is not scheduled twice.
        let _guard = RunGuard::acquire(stale).unwrap();
        assert_eq!(due(&s).unwrap(), vec![fresh]);
    }

    #[test]
    fn scoped_apply_removes_only_inside_the_group_subtree() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let eu = group(&s, vault, "eu", None);
        let eu_child = group(&s, vault, "eu/db", Some(eu));
        let us = group(&s, vault, "us", None);
        // Setup imports do not remove: an unscoped one-shot import with
        // `remove_missing` would sweep the whole vault.
        let sel = |g: Uuid| CloudSelection {
            instances: vec![0],
            group_id: Some(g),
            tag_ids: vec![],
            username: "ec2-user".into(),
            port: None,
            remove_missing: false,
        };
        cloud::apply(
            &s,
            vault,
            CloudProvider::Aws,
            &[inst("i-eu", "eu-web", "1.1.1.1")],
            &sel(eu),
        )
        .unwrap();
        cloud::apply(
            &s,
            vault,
            CloudProvider::Aws,
            &[inst("i-us", "us-web", "2.2.2.2")],
            &sel(us),
        )
        .unwrap();
        // Also a one-shot import outside any group and a host moved into the sub-group.
        let mut none = sel(eu);
        none.group_id = None;
        cloud::apply(
            &s,
            vault,
            CloudProvider::Aws,
            &[inst("i-loose", "loose", "3.3.3.3")],
            &none,
        )
        .unwrap();
        cloud::apply(
            &s,
            vault,
            CloudProvider::Aws,
            &[inst("i-old", "old-db", "4.4.4.4")],
            &sel(eu_child),
        )
        .unwrap();
        let eu_group = s.require::<Group>(eu).unwrap();
        let scope = subtree(&s, &eu_group).unwrap();
        assert_eq!(scope, HashSet::from([eu, eu_child]));

        // eu refresh: i-eu still there, i-old gone from the provider, plus a new one.
        let listing = vec![
            inst("i-eu", "eu-web", "1.1.1.1"),
            inst("i-new", "eu-new", "5.5.5.5"),
        ];
        let selection = CloudSelection {
            instances: vec![0, 1],
            remove_missing: true,
            ..sel(eu)
        };
        let r = cloud::apply_scoped(
            &s,
            vault,
            CloudProvider::Aws,
            &listing,
            &selection,
            Some(&scope),
        )
        .unwrap();
        assert_eq!((r.created, r.unchanged, r.removed), (1, 1, 1));
        let hosts: Vec<Entity<Host>> = s.list(Some(vault)).unwrap();
        let mut ids: Vec<&str> = hosts
            .iter()
            .filter_map(|h| h.data.cloud_instance_id.as_deref())
            .collect();
        ids.sort();
        // us-region host and the loose one-shot import survive; the stale sub-group host is gone.
        assert_eq!(ids, vec!["i-eu", "i-loose", "i-new", "i-us"]);
        let new = hosts
            .iter()
            .find(|h| h.data.cloud_instance_id.as_deref() == Some("i-new"))
            .unwrap();
        assert_eq!(new.data.group_id, Some(eu));
    }

    #[tokio::test]
    async fn run_records_failure_without_leaking_secret_and_keeps_hosts() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let gid = group(&s, vault, "AWS", None);
        // Point the provider client at a closed port so the listing fails fast.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let endpoints = Endpoints {
            aws_ec2: Some(format!("http://127.0.0.1:{port}/")),
            ..Endpoints::default()
        };
        let existing = CloudSelection {
            instances: vec![0],
            group_id: Some(gid),
            tag_ids: vec![],
            username: "ec2-user".into(),
            port: None,
            remove_missing: true,
        };
        cloud::apply(
            &s,
            vault,
            CloudProvider::Aws,
            &[inst("i-1", "web", "1.1.1.1")],
            &existing,
        )
        .unwrap();
        save(&s, gid, aws_config("eu-central-1"), Some(aws_secret())).unwrap();

        let out = run_with(&s, gid, endpoints.clone()).await.unwrap();
        assert!(out.status.last_run.is_some());
        assert!(out.status.last_success.is_none());
        let err = out.status.error.clone().expect("error recorded");
        assert!(!err.contains("SUPERSECRETKEY"), "{err}");
        assert!(out.status.error_kind.is_some());
        assert!(!out.running);
        // Failure never touches hosts.
        let hosts: Vec<Entity<Host>> = s.list(Some(vault)).unwrap();
        assert_eq!(hosts.len(), 1);
        // Status persisted and shown on the next describe.
        let again = get(&s, gid).unwrap().unwrap();
        assert_eq!(again.status, out.status);
        assert!(again.next_run.unwrap() > Utc::now());

        // Missing secret is its own error kind and does not crash.
        s.delete_meta(&secret_key(gid)).unwrap();
        let out = run_with(&s, gid, endpoints).await.unwrap();
        assert_eq!(
            out.status.error_kind.as_deref(),
            Some("cloud_sync_no_secret")
        );
        assert!(!out.has_secret);
        assert!(out.next_run.is_none());
    }

    // ---- end-to-end refresh against in-process provider mocks -----------

    /// One machine as the mock provider currently reports it.
    #[derive(Clone)]
    struct Machine {
        id: &'static str,
        name: String,
        ip: &'static str,
    }

    fn m(id: &'static str, name: &str, ip: &'static str) -> Machine {
        Machine {
            id,
            name: name.into(),
            ip,
        }
    }

    /// Mutable fleet shared with the mock so a test can add, rename and
    /// delete machines between refreshes.
    type Fleet = std::sync::Arc<Mutex<Vec<Machine>>>;

    fn fleet(list: Vec<Machine>) -> Fleet {
        std::sync::Arc::new(Mutex::new(list))
    }

    async fn mock(fleet: Fleet) -> Endpoints {
        use axum::extract::{Path, State};
        use axum::http::HeaderMap;
        use axum::response::IntoResponse;
        use axum::routing::{get, post};

        async fn ec2(State(f): State<Fleet>, headers: HeaderMap) -> axum::response::Response {
            let auth = headers["authorization"].to_str().unwrap();
            assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/"));
            let items: String = f
                .lock()
                .unwrap()
                .iter()
                .map(|x| {
                    format!(
                        "<item><instanceId>{}</instanceId><instanceState><name>running</name></instanceState><ipAddress>{}</ipAddress><platformDetails>Linux/UNIX</platformDetails><tagSet><item><key>Name</key><value>{}</value></item></tagSet></item>",
                        x.id, x.ip, x.name
                    )
                })
                .collect();
            (
                [("content-type", "text/xml")],
                format!(
                    "<DescribeInstancesResponse><reservationSet><item><instancesSet>{items}</instancesSet></item></reservationSet></DescribeInstancesResponse>"
                ),
            )
                .into_response()
        }
        async fn lightsail(
            State(f): State<Fleet>,
            headers: HeaderMap,
        ) -> axum::Json<serde_json::Value> {
            assert_eq!(headers["x-amz-target"], "Lightsail_20161128.GetInstances");
            let list: Vec<_> = f
                .lock()
                .unwrap()
                .iter()
                .map(|x| {
                    serde_json::json!({"name": x.name, "arn": x.id, "publicIpAddress": x.ip,
                        "blueprintName": "Ubuntu", "state": {"name": "running"}})
                })
                .collect();
            axum::Json(serde_json::json!({"instances": list}))
        }
        async fn droplets(
            State(f): State<Fleet>,
            headers: HeaderMap,
        ) -> axum::Json<serde_json::Value> {
            assert_eq!(headers["authorization"], "Bearer dop_v1_validtoken");
            let list: Vec<_> = f
                .lock()
                .unwrap()
                .iter()
                .map(|x| {
                    serde_json::json!({"id": x.id.parse::<u64>().unwrap(), "name": x.name, "status": "active",
                        "image": {"distribution": "Ubuntu"},
                        "networks": {"v4": [{"ip_address": x.ip, "type": "public"}]}})
                })
                .collect();
            axum::Json(serde_json::json!({"droplets": list, "links": {"pages": {}}}))
        }
        async fn az_token(
            axum::Form(f): axum::Form<HashMap<String, String>>,
        ) -> axum::Json<serde_json::Value> {
            assert_eq!(f["client_secret"], "az-secret");
            axum::Json(
                serde_json::json!({"token_type": "Bearer", "expires_in": 3599, "access_token": "tok"}),
            )
        }
        async fn az_subs(headers: HeaderMap) -> axum::Json<serde_json::Value> {
            assert_eq!(headers["authorization"], "Bearer tok");
            axum::Json(
                serde_json::json!({"value": [{"subscriptionId": "sub", "displayName": "S"}]}),
            )
        }
        async fn az_vms(State(f): State<Fleet>) -> axum::Json<serde_json::Value> {
            let list: Vec<_> = f.lock().unwrap().iter().map(|x| serde_json::json!({
                "id": format!("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{}", x.id),
                "name": x.name, "location": "westeurope",
                "properties": {
                    "storageProfile": {"osDisk": {"osType": "Linux"}, "imageReference": {"offer": "debian-12"}},
                    "networkProfile": {"networkInterfaces": [{
                        "id": format!("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/{}", x.id),
                        "properties": {"primary": true}}]}}
            })).collect();
            axum::Json(serde_json::json!({"value": list}))
        }
        async fn az_nic(
            Path((_s, _rg, nic)): Path<(String, String, String)>,
        ) -> axum::Json<serde_json::Value> {
            axum::Json(
                serde_json::json!({"properties": {"ipConfigurations": [{"properties": {"primary": true,
                "publicIPAddress": {"id": format!("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/{nic}")}}}]}}),
            )
        }
        async fn az_pip(
            State(f): State<Fleet>,
            Path((_s, _rg, pip)): Path<(String, String, String)>,
        ) -> axum::Json<serde_json::Value> {
            let ip = f
                .lock()
                .unwrap()
                .iter()
                .find(|x| x.id == pip)
                .map(|x| x.ip)
                .unwrap();
            axum::Json(serde_json::json!({"properties": {"ipAddress": ip}}))
        }

        let app = axum::Router::new()
            .route("/aws/ec2/", post(ec2))
            .route("/aws/lightsail/", post(lightsail))
            .route("/do/v2/droplets", get(droplets))
            .route("/az/login/{tenant}/oauth2/v2.0/token", post(az_token))
            .route("/az/arm/subscriptions", get(az_subs))
            .route("/az/arm/subscriptions/{sub}/providers/Microsoft.Compute/virtualMachines", get(az_vms))
            .route("/az/arm/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/networkInterfaces/{nic}", get(az_nic))
            .route("/az/arm/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/publicIPAddresses/{pip}", get(az_pip))
            .with_state(fleet);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Endpoints {
            aws_ec2: Some(format!("http://{addr}/aws/ec2/")),
            aws_lightsail: Some(format!("http://{addr}/aws/lightsail/")),
            digitalocean: Some(format!("http://{addr}/do")),
            azure_login: Some(format!("http://{addr}/az/login")),
            azure_management: Some(format!("http://{addr}/az/arm")),
        }
    }

    fn hosts_in(s: &Store, vault: Uuid, group: Uuid) -> Vec<Entity<Host>> {
        let mut hs: Vec<Entity<Host>> = s.list(Some(vault)).unwrap();
        hs.retain(|h| h.data.group_id == Some(group));
        hs.sort_by(|a, b| a.data.label.cmp(&b.data.label));
        hs
    }

    /// Full lifecycle for every provider: create, provider rename, address
    /// change, user rename kept, customizations kept, deletion mirrored.
    async fn lifecycle(config: CloudSyncConfig, secret: CloudSyncSecret) {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let gid = group(&s, vault, "cloud", None);
        let f = fleet(vec![m("1", "web", "10.0.0.1"), m("2", "db", "10.0.0.2")]);
        let endpoints = mock(f.clone()).await;
        save(&s, gid, config, Some(secret)).unwrap();

        let out = run_with(&s, gid, endpoints.clone()).await.unwrap();
        assert_eq!(out.status.error, None, "{:?}", out.status);
        let r = out.status.report.clone().unwrap();
        assert_eq!((r.created, r.updated, r.removed), (2, 0, 0));
        assert_eq!(out.status.instances, 2);
        let hs = hosts_in(&s, vault, gid);
        assert_eq!(hs.len(), 2);
        assert_eq!(hs[0].data.label, "db");
        assert_eq!(hs[0].data.address, "10.0.0.2");
        assert_eq!(
            crate::hosts::form(&s, hs[0].id).unwrap().username,
            "ec2-user"
        );
        assert!(hs[0].data.os_name.is_some(), "os classified from image");
        let web = hs[1].clone();

        // User customizes `web` (port, notes) and renames `db`.
        let mut form = crate::hosts::form(&s, web.id).unwrap();
        form.port = Some(2222);
        form.notes = "prod".into();
        crate::hosts::save(&s, &form).unwrap();
        let db = hs[0].clone();
        let mut form = crate::hosts::form(&s, db.id).unwrap();
        form.label = "My database".into();
        crate::hosts::save(&s, &form).unwrap();

        // Provider: renames web → web-1, moves it to a new address, renames
        // db too (must not win over the user's name), adds cache, drops nothing.
        *f.lock().unwrap() = vec![
            m("1", "web-1", "10.0.0.11"),
            m("2", "db-2", "10.0.0.2"),
            m("3", "cache", "10.0.0.3"),
        ];
        let out = run_with(&s, gid, endpoints.clone()).await.unwrap();
        let r = out.status.report.clone().unwrap();
        assert_eq!((r.created, r.updated, r.unchanged, r.removed), (1, 1, 1, 0));
        let hs: Vec<Entity<Host>> = s.list(Some(vault)).unwrap();
        assert_eq!(hs.len(), 3);
        let web = crate::hosts::form(&s, web.id).unwrap();
        assert_eq!(web.label, "web-1");
        assert_eq!(web.address, "10.0.0.11");
        assert_eq!(web.port, Some(2222));
        assert_eq!(web.notes, "prod");
        let db = hs.iter().find(|h| h.id == db.id).unwrap();
        assert_eq!(db.data.label, "My database");
        assert!(
            hs.iter()
                .any(|h| h.data.label == "cache" && h.data.group_id == Some(gid))
        );

        // A manual host in the same group is never touched.
        let manual = crate::hosts::save(
            &s,
            &crate::hosts::HostForm {
                charset: None,
                backspace: None,
                id: None,
                vault_id: vault,
                label: "manual".into(),
                address: "192.168.0.1".into(),
                group_id: Some(gid),
                ssh: true,
                port: None,
                username: "root".into(),
                password: None,
                ssh_key_id: None,
                ssh_certificate_id: None,
                identity_id: None,
                ssh_id: false,
                ssh_id_key_type: None,
                use_mosh: false,
                mosh_server_command: None,
                tag_ids: vec![],
                notes: String::new(),
                os_name: None,
                icon: None,
                ip_version: "auto".into(),
                agent_forwarding: false,
                forward_x11: false,
                startup_snippet_id: None,
                host_chain_id: None,
                proxy_id: None,
                gateway_id: None,
                mac_address: None,
                telnet: None,
                webdav: None,
                env_variables: vec![],
                keep_alive_interval: None,
                timeout: None,
                color_scheme: None,
                has_password: false,
                files_provider: false,
                has_totp: false,
                totp_secret: None,
            },
        )
        .unwrap();

        // Provider deletes db and cache.
        *f.lock().unwrap() = vec![m("1", "web-1", "10.0.0.11")];
        let out = run_with(&s, gid, endpoints.clone()).await.unwrap();
        let r = out.status.report.clone().unwrap();
        assert_eq!((r.created, r.updated, r.unchanged, r.removed), (0, 0, 1, 2));
        let mut labels: Vec<String> = s
            .list::<Host>(Some(vault))
            .unwrap()
            .into_iter()
            .map(|h| h.data.label)
            .collect();
        labels.sort();
        assert_eq!(labels, vec!["manual", "web-1"]);
        assert!(s.get::<Host>(manual.id).unwrap().is_some());

        // With `remove_missing` off, a vanished machine keeps its host.
        let mut cfg = load_config(&s, gid).unwrap().unwrap();
        cfg.remove_missing = false;
        save(&s, gid, cfg, None).unwrap();
        f.lock().unwrap().clear();
        let out = run_with(&s, gid, endpoints).await.unwrap();
        assert_eq!(out.status.error, None);
        assert_eq!(out.status.instances, 0);
        assert_eq!(out.status.report.unwrap().removed, 0);
        assert_eq!(s.list::<Host>(Some(vault)).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn aws_ec2_group_lifecycle() {
        lifecycle(aws_config("eu-central-1"), aws_secret()).await;
    }

    #[tokio::test]
    async fn aws_lightsail_group_lifecycle() {
        let mut cfg = aws_config("eu-central-1");
        cfg.service = Some(AwsService::Lightsail);
        lifecycle(cfg, aws_secret()).await;
    }

    #[tokio::test]
    async fn digitalocean_group_lifecycle() {
        let cfg = CloudSyncConfig {
            provider: CloudProvider::DigitalOcean,
            region: None,
            service: None,
            address_type: None,
            access_key_id: None,
            tenant_id: None,
            client_id: None,
            ..aws_config("")
        };
        lifecycle(cfg, secret(|s| s.token = Some("dop_v1_validtoken".into()))).await;
    }

    #[tokio::test]
    async fn azure_group_lifecycle() {
        let cfg = CloudSyncConfig {
            provider: CloudProvider::Azure,
            region: None,
            service: None,
            address_type: None,
            access_key_id: None,
            tenant_id: Some("tenant-1".into()),
            client_id: Some("client-1".into()),
            ..aws_config("")
        };
        lifecycle(cfg, secret(|s| s.client_secret = Some("az-secret".into()))).await;
    }

    /// Two sync groups of the same provider in one vault (e.g. two AWS
    /// regions) never delete each other's hosts.
    #[tokio::test]
    async fn two_groups_same_provider_do_not_fight() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let eu = group(&s, vault, "eu", None);
        let us = group(&s, vault, "us", None);
        let eu_fleet = fleet(vec![m("eu-1", "eu-web", "10.1.0.1")]);
        let us_fleet = fleet(vec![m("us-1", "us-web", "10.2.0.1")]);
        let eu_ep = mock(eu_fleet.clone()).await;
        let us_ep = mock(us_fleet.clone()).await;
        save(&s, eu, aws_config("eu-central-1"), Some(aws_secret())).unwrap();
        save(&s, us, aws_config("us-east-1"), Some(aws_secret())).unwrap();

        run_with(&s, eu, eu_ep.clone()).await.unwrap();
        run_with(&s, us, us_ep.clone()).await.unwrap();
        assert_eq!(s.list::<Host>(Some(vault)).unwrap().len(), 2);

        // Refreshing eu again lists only eu machines; us-web must survive.
        let out = run_with(&s, eu, eu_ep).await.unwrap();
        assert_eq!(out.status.report.unwrap().removed, 0);
        // And when us really loses its machine, only us-web goes.
        us_fleet.lock().unwrap().clear();
        let out = run_with(&s, us, us_ep).await.unwrap();
        assert_eq!(out.status.report.unwrap().removed, 1);
        let hs = s.list::<Host>(Some(vault)).unwrap();
        assert_eq!(hs.len(), 1);
        assert_eq!(hs[0].data.label, "eu-web");
    }

    #[test]
    fn run_on_group_without_sync_is_not_found() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let gid = group(&s, vault, "plain", None);
        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(run(&s, gid))
            .unwrap_err();
        assert_eq!(err.kind, "not_found");
    }
}
