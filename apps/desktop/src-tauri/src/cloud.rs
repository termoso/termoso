//! Cloud integration (Termius "AWS / DigitalOcean / Azure Integration"):
//! discover machines with provider credentials and import them as hosts.
//!
//! Provider credentials are used once, for the listing call, and are then
//! dropped: they never become a host password, an identity, a sync record or
//! a log line, and the preview the webview receives carries only what the
//! provider said about each machine. Imported hosts are linked to their
//! provider by `Host::cloud_instance_type` + `cloud_instance_id`, which is
//! what a later "pull data from cloud" reconciles against: label, address
//! and OS follow the provider, everything the user configured (credentials,
//! port, keys, Mosh, tags they added…) stays untouched.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use termoso_core::cloud::{
    AddressType, AwsService, CloudClient, CloudConfig, CloudInstance, CloudProvider, Endpoints,
};
use termoso_core::model::{Entity, Group, Host, Tag};
use termoso_core::store::Store;
use uuid::Uuid;

use crate::error::{DesktopError, Result};
use crate::hosts::{self, HostForm};

/// What the webview gets after a discovery; no credentials inside.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudPreview {
    pub id: Uuid,
    pub provider: CloudProvider,
    /// `Amazon AWS` / `DigitalOcean` / `Microsoft Azure`.
    pub provider_name: String,
    /// AWS only: EC2 or Lightsail.
    pub service: Option<AwsService>,
    /// AWS only: which address was picked.
    pub address_type: Option<AddressType>,
    pub instances: Vec<CloudPreviewInstance>,
}

/// One discovered machine, annotated with what it would do on import.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudPreviewInstance {
    #[serde(flatten)]
    pub instance: CloudInstance,
    /// `new` — creates a host; `update` — a host with this provider id
    /// exists in the target vault and would be refreshed; `no_address` —
    /// cannot be imported (stopped, no public IP…).
    pub action: &'static str,
    /// Existing host that would be refreshed.
    pub host_id: Option<Uuid>,
}

/// Indexes into `CloudPreview::instances` plus where they go.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudSelection {
    #[serde(default)]
    pub instances: Vec<usize>,
    pub group_id: Option<Uuid>,
    #[serde(default)]
    pub tag_ids: Vec<Uuid>,
    /// Default SSH username for *new* hosts (`ec2-user`, `root`, `azureuser`).
    #[serde(default)]
    pub username: String,
    /// Default SSH port for new hosts; `None` = 22.
    #[serde(default)]
    pub port: Option<u16>,
    /// Delete hosts of this provider in the vault that the provider no
    /// longer lists (Termius removes them on pull).
    #[serde(default)]
    pub remove_missing: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudImportReport {
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub removed: usize,
    /// Machines skipped because they have no usable address.
    pub skipped: usize,
    pub warnings: Vec<String>,
}

struct Cached {
    provider: CloudProvider,
    instances: Vec<CloudInstance>,
}

fn cache() -> &'static Mutex<HashMap<Uuid, Cached>> {
    static CACHE: OnceLock<Mutex<HashMap<Uuid, Cached>>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

/// Endpoints for the provider client. `TERMOSO_CLOUD_ENDPOINTS` (JSON
/// [`Endpoints`]) lets tests and sovereign-cloud users point at other
/// hosts; production uses the public APIs.
pub fn endpoints() -> Endpoints {
    match std::env::var("TERMOSO_CLOUD_ENDPOINTS") {
        Ok(raw) if !raw.trim().is_empty() => match serde_json::from_str(&raw) {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!("TERMOSO_CLOUD_ENDPOINTS ignored: {err}");
                Endpoints::default()
            }
        },
        _ => Endpoints::default(),
    }
}

/// List instances with the given credentials and remember the result for
/// [`apply`]. The credentials are dropped when this returns.
pub async fn discover(store: &Store, vault_id: Uuid, config: CloudConfig) -> Result<CloudPreview> {
    let provider = config.provider();
    let (service, address_type) = match &config {
        CloudConfig::Aws(a) => (Some(a.service), Some(a.address_type)),
        _ => (None, None),
    };
    tracing::info!(provider = provider.name(), "cloud discovery");
    let instances = CloudClient::new(endpoints()).discover(&config).await?;
    drop(config);

    let existing = linked_hosts(store, vault_id, provider)?;
    let preview_instances = instances
        .iter()
        .map(|i| {
            let host_id = existing.get(&i.instance_id).map(|h| h.id);
            let action = match (i.address.as_deref(), host_id) {
                (None, _) => "no_address",
                (Some(_), Some(_)) => "update",
                (Some(_), None) => "new",
            };
            CloudPreviewInstance {
                instance: i.clone(),
                action,
                host_id,
            }
        })
        .collect();

    let id = Uuid::new_v4();
    let mut cache = cache().lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= 8 {
        cache.clear();
    }
    cache.insert(
        id,
        Cached {
            provider,
            instances,
        },
    );
    Ok(CloudPreview {
        id,
        provider,
        provider_name: provider.name().to_string(),
        service,
        address_type,
        instances: preview_instances,
    })
}

pub fn discard(id: Uuid) {
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);
}

fn take(id: Uuid) -> Result<Cached> {
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id)
        .ok_or_else(|| DesktopError::not_found("cloud preview expired — load the machines again"))
}

/// Hosts in `vault_id` that came from `provider`, by provider instance id.
fn linked_hosts(
    store: &Store,
    vault_id: Uuid,
    provider: CloudProvider,
) -> Result<HashMap<String, Entity<Host>>> {
    let hosts: Vec<Entity<Host>> = store.list(Some(vault_id))?;
    Ok(hosts
        .into_iter()
        .filter(|h| h.data.cloud_instance_type.as_deref() == Some(provider.instance_type()))
        .filter_map(|h| h.data.cloud_instance_id.clone().map(|id| (id, h)))
        .collect())
}

/// Import the selected machines of a cached preview.
pub fn apply_cached(
    store: &Store,
    vault_id: Uuid,
    preview_id: Uuid,
    selection: &CloudSelection,
) -> Result<CloudImportReport> {
    let cached = take(preview_id)?;
    apply(
        store,
        vault_id,
        cached.provider,
        &cached.instances,
        selection,
    )
}

/// Create / refresh hosts for the selected `instances`; missing hosts are
/// removed anywhere in the vault.
pub fn apply(
    store: &Store,
    vault_id: Uuid,
    provider: CloudProvider,
    instances: &[CloudInstance],
    selection: &CloudSelection,
) -> Result<CloudImportReport> {
    apply_scoped(store, vault_id, provider, instances, selection, None)
}

/// Like [`apply`], but with `remove_scope` set only linked hosts sitting in
/// one of those groups count as "missing": a sync group for one region
/// must not delete hosts another region's group (or a one-shot import
/// elsewhere in the vault) created. Matching for refresh stays vault-wide,
/// so a host the user moved out of the group keeps following the provider
/// instead of being duplicated.
pub fn apply_scoped(
    store: &Store,
    vault_id: Uuid,
    provider: CloudProvider,
    instances: &[CloudInstance],
    selection: &CloudSelection,
    remove_scope: Option<&HashSet<Uuid>>,
) -> Result<CloudImportReport> {
    if let Some(gid) = selection.group_id {
        let g = store.require::<Group>(gid)?;
        if g.vault_id != vault_id {
            return Err(DesktopError::invalid("group belongs to another vault"));
        }
    }
    for tid in &selection.tag_ids {
        let t = store.require::<Tag>(*tid)?;
        if t.vault_id != vault_id {
            return Err(DesktopError::invalid("tag belongs to another vault"));
        }
    }
    let username = selection.username.trim();
    let mut report = CloudImportReport::default();
    let mut existing = linked_hosts(store, vault_id, provider)?;

    let mut chosen: Vec<usize> = selection
        .instances
        .iter()
        .copied()
        .filter(|i| *i < instances.len())
        .collect();
    chosen.sort_unstable();
    chosen.dedup();

    let mut touched: HashSet<String> = HashSet::new();
    for i in chosen {
        let inst = &instances[i];
        let Some(address) = inst
            .address
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty())
        else {
            report.skipped += 1;
            report.warnings.push(format!(
                "{}: no {}address, not imported",
                inst.label,
                if provider == CloudProvider::Aws {
                    ""
                } else {
                    "public "
                }
            ));
            continue;
        };
        touched.insert(inst.instance_id.clone());
        match existing.remove(&inst.instance_id) {
            Some(h) => {
                if refresh(store, &h, inst, address)? {
                    report.updated += 1;
                } else {
                    report.unchanged += 1;
                }
            }
            None => {
                let form = HostForm {
                    charset: None,
                    backspace: None,
                    id: None,
                    vault_id,
                    label: inst.label.clone(),
                    address: address.to_string(),
                    group_id: selection.group_id,
                    ssh: true,
                    port: selection.port.filter(|p| *p != 0),
                    username: username.to_string(),
                    password: None,
                    ssh_key_id: None,
                    ssh_certificate_id: None,
                    identity_id: None,
                    ssh_id: false,
                    ssh_id_key_type: None,
                    use_mosh: false,
                    mosh_server_command: None,
                    tag_ids: selection.tag_ids.clone(),
                    notes: String::new(),
                    os_name: inst.os_name.clone(),
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
                    totp_secret: None,
                    has_totp: false,
                };
                let card = hosts::save(store, &form)?;
                let mut host = store.require::<Host>(card.id)?;
                host.data.cloud_instance_id = Some(inst.instance_id.clone());
                host.data.cloud_instance_type = Some(provider.instance_type().to_string());
                store.update(host.id, &host.data)?;
                store.set_meta(&label_key(host.id), &inst.label)?;
                report.created += 1;
            }
        }
    }

    if selection.remove_missing {
        let listed: HashSet<&str> = instances.iter().map(|i| i.instance_id.as_str()).collect();
        for (iid, h) in existing {
            if listed.contains(iid.as_str()) || touched.contains(&iid) {
                continue;
            }
            if let Some(scope) = remove_scope
                && !h.data.group_id.is_some_and(|g| scope.contains(&g))
            {
                continue;
            }
            hosts::delete(store, h.id)?;
            store.delete_meta(&label_key(h.id))?;
            report.removed += 1;
        }
    }
    Ok(report)
}

/// Local (device-only, non-synced) note of the name the provider last gave
/// a host, so a rename at the provider can be told apart from a rename by
/// the user.
fn label_key(host_id: Uuid) -> String {
    format!("cloud_label:{host_id}")
}

/// Bring a linked host in line with the provider. Only discovered facts
/// change; returns whether anything did.
fn refresh(store: &Store, h: &Entity<Host>, inst: &CloudInstance, address: &str) -> Result<bool> {
    let mut data = h.data.clone();
    let mut changed = false;
    if data.address != address {
        data.address = address.to_string();
        changed = true;
    }
    // Follow the provider's name unless the user renamed the host away
    // from what the provider called it last time.
    let last = store.meta(&label_key(h.id))?;
    let provider_named = match &last {
        Some(l) => *l == data.label,
        None => data.label == inst.label || data.label == h.data.address,
    };
    if provider_named && data.label != inst.label && !inst.label.trim().is_empty() {
        data.label = inst.label.clone();
        changed = true;
    }
    if last.as_deref() != Some(inst.label.as_str()) {
        store.set_meta(&label_key(h.id), &inst.label)?;
    }
    if data.os_name.is_none()
        && let Some(os) = &inst.os_name
    {
        data.os_name = Some(os.clone());
        changed = true;
    }
    if changed {
        store.update(h.id, &data)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoso_core::cloud::CloudError;
    use termoso_core::model::{Identity, SshConfig};
    use termoso_core::termoso_crypto::keys::SymmetricKey;

    fn store() -> Store {
        Store::open_in_memory(SymmetricKey::generate()).expect("store")
    }

    fn inst(id: &str, label: &str, addr: Option<&str>) -> CloudInstance {
        CloudInstance {
            instance_id: id.into(),
            label: label.into(),
            address: addr.map(str::to_string),
            state: Some("running".into()),
            region: Some("eu-central-1".into()),
            size: Some("t3.micro".into()),
            os: Some("Ubuntu 24.04".into()),
            os_name: Some("ubuntu".into()),
        }
    }

    fn selection(idx: &[usize]) -> CloudSelection {
        CloudSelection {
            instances: idx.to_vec(),
            group_id: None,
            tag_ids: vec![],
            username: "ec2-user".into(),
            port: None,
            remove_missing: false,
        }
    }

    #[test]
    fn creates_hosts_linked_to_provider() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let list = vec![inst("i-1", "web", Some("1.2.3.4")), inst("i-2", "db", None)];
        let r = apply(&s, vault, CloudProvider::Aws, &list, &selection(&[0, 1])).unwrap();
        assert_eq!((r.created, r.skipped, r.updated), (1, 1, 0));
        assert_eq!(r.warnings.len(), 1);
        let hosts: Vec<Entity<Host>> = s.list(Some(vault)).unwrap();
        assert_eq!(hosts.len(), 1);
        let h = &hosts[0].data;
        assert_eq!(h.label, "web");
        assert_eq!(h.address, "1.2.3.4");
        assert_eq!(h.cloud_instance_id.as_deref(), Some("i-1"));
        assert_eq!(h.cloud_instance_type.as_deref(), Some("Amazon AWS"));
        assert_eq!(h.os_name.as_deref(), Some("ubuntu"));
        let card = hosts::cards(&s, Some(vault)).unwrap().remove(0);
        assert_eq!(card.username, "ec2-user");
        assert_eq!(card.port, 22);
        assert_eq!(card.cloud_provider.as_deref(), Some("Amazon AWS"));
    }

    #[test]
    fn refresh_keeps_credentials_and_settings() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let list = vec![inst("d-1", "app", Some("10.0.0.1"))];
        apply(
            &s,
            vault,
            CloudProvider::DigitalOcean,
            &list,
            &selection(&[0]),
        )
        .unwrap();
        // User customises the host: password, port, Mosh.
        let hid = s.list::<Host>(Some(vault)).unwrap()[0].id;
        let mut form = hosts::form(&s, hid).unwrap();
        form.password = Some("hunter2".into());
        form.port = Some(2200);
        form.use_mosh = true;
        hosts::save(&s, &form).unwrap();

        // Provider now reports a new address and name.
        let list = vec![inst("d-1", "app-renamed", Some("10.0.0.9"))];
        let r = apply(
            &s,
            vault,
            CloudProvider::DigitalOcean,
            &list,
            &selection(&[0]),
        )
        .unwrap();
        assert_eq!((r.created, r.updated, r.unchanged), (0, 1, 0));
        let hosts: Vec<Entity<Host>> = s.list(Some(vault)).unwrap();
        assert_eq!(hosts.len(), 1, "no duplicate host");
        assert_eq!(hosts[0].data.address, "10.0.0.9");
        assert_eq!(hosts[0].data.label, "app-renamed");
        let ssh = s
            .require::<SshConfig>(hosts[0].data.ssh_config_id.unwrap())
            .unwrap();
        assert_eq!(ssh.data.port, Some(2200));
        assert!(ssh.data.use_mosh);
        let ident = s
            .require::<Identity>(ssh.data.identity_id.unwrap())
            .unwrap();
        assert!(ident.data.password.is_some(), "password survived refresh");

        // Same data again → unchanged.
        let r = apply(
            &s,
            vault,
            CloudProvider::DigitalOcean,
            &list,
            &selection(&[0]),
        )
        .unwrap();
        assert_eq!((r.updated, r.unchanged), (0, 1));
    }

    #[test]
    fn user_rename_is_not_overwritten() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let list = vec![inst("vm-1", "vm-1", Some("10.0.0.1"))];
        apply(&s, vault, CloudProvider::Azure, &list, &selection(&[0])).unwrap();
        let hid = s.list::<Host>(Some(vault)).unwrap()[0].id;
        let mut form = hosts::form(&s, hid).unwrap();
        form.label = "my favourite box".into();
        hosts::save(&s, &form).unwrap();

        let list = vec![inst("vm-1", "vm-1-renamed", Some("10.0.0.1"))];
        apply(&s, vault, CloudProvider::Azure, &list, &selection(&[0])).unwrap();
        let h = s.require::<Host>(hid).unwrap();
        assert_eq!(h.data.label, "my favourite box");
    }

    #[test]
    fn remove_missing_only_touches_this_provider() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        apply(
            &s,
            vault,
            CloudProvider::Aws,
            &[
                inst("i-1", "a", Some("1.1.1.1")),
                inst("i-2", "b", Some("2.2.2.2")),
            ],
            &selection(&[0, 1]),
        )
        .unwrap();
        apply(
            &s,
            vault,
            CloudProvider::DigitalOcean,
            &[inst("77", "do", Some("3.3.3.3"))],
            &selection(&[0]),
        )
        .unwrap();
        // Manual host is never touched.
        let mut manual = hosts::form(&s, s.list::<Host>(Some(vault)).unwrap()[0].id).unwrap();
        manual.id = None;
        manual.label = "manual".into();
        manual.address = "9.9.9.9".into();
        hosts::save(&s, &manual).unwrap();
        assert_eq!(s.list::<Host>(Some(vault)).unwrap().len(), 4);

        let mut sel = selection(&[0]);
        sel.remove_missing = true;
        let r = apply(
            &s,
            vault,
            CloudProvider::Aws,
            &[inst("i-1", "a", Some("1.1.1.1"))],
            &sel,
        )
        .unwrap();
        assert_eq!((r.removed, r.unchanged), (1, 1));
        let labels: Vec<String> = s
            .list::<Host>(Some(vault))
            .unwrap()
            .into_iter()
            .map(|h| h.data.label)
            .collect();
        assert!(labels.contains(&"a".to_string()));
        assert!(!labels.contains(&"b".to_string()));
        assert!(labels.contains(&"do".to_string()));
        assert!(labels.contains(&"manual".to_string()));
    }

    #[test]
    fn group_and_tags_must_be_in_vault() {
        let s = store();
        let vault = s.local_vault().unwrap().id;
        let mut sel = selection(&[0]);
        sel.group_id = Some(Uuid::new_v4());
        let err = apply(
            &s,
            vault,
            CloudProvider::Aws,
            &[inst("i-1", "a", Some("1.1.1.1"))],
            &sel,
        )
        .unwrap_err();
        assert_eq!(err.kind, "not_found");
    }

    #[test]
    fn preview_and_report_carry_no_secrets() {
        // The preview DTO is built from `CloudInstance`s only; make sure the
        // serialised shape has no credential-looking keys.
        let p = CloudPreview {
            id: Uuid::new_v4(),
            provider: CloudProvider::Aws,
            provider_name: "Amazon AWS".into(),
            service: Some(AwsService::Ec2),
            address_type: Some(AddressType::Public),
            instances: vec![CloudPreviewInstance {
                instance: inst("i-1", "a", Some("1.1.1.1")),
                action: "new",
                host_id: None,
            }],
        };
        let json = serde_json::to_string(&p).unwrap();
        for needle in ["secret", "token", "password", "Key\"", "credential"] {
            assert!(!json.contains(needle), "{needle} in {json}");
        }
        assert!(json.contains("\"action\":\"new\""));
        assert!(json.contains("\"instanceId\":\"i-1\""));
    }

    #[test]
    fn cloud_errors_map_to_stable_kinds() {
        let e: DesktopError = CloudError::InvalidCredentials("nope".into()).into();
        assert_eq!(e.kind, "cloud_invalid_credentials");
        let e: DesktopError = CloudError::Unavailable("down".into()).into();
        assert_eq!(e.kind, "cloud_unavailable");
    }
}
