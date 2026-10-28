//! Import of hosts from other tools: OpenSSH `~/.ssh` (config, keys,
//! known_hosts), PuTTY saved sessions (registry / `.reg` export), the
//! Termius CSV template, MobaXterm bookmarks, SecureCRT sessions and the
//! ZOC host directory. Parsing only produces a preview; nothing is written
//! until the user picks what to import and a target vault. Private keys are
//! read from disk only at apply time and never travel to the webview — the
//! preview carries path, type and fingerprint. Passwords found in the source
//! (CSV, PuTTY proxy) stay in the Rust-side preview cache and are redacted
//! from what the UI receives; the UI refers to a preview by id.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use termoso_core::keys;
use termoso_core::model::{Group, HostChain, Identity, PfRule, Proxy, SshKey, Tag};
use termoso_core::store::Store;
use uuid::Uuid;

use crate::error::{DesktopError, Result};
use crate::forwarding::{self, PfRuleForm};
use crate::hosts::{self, HostForm, TelnetForm};
use crate::keychain;
use crate::state::AppState;
use crate::trust;
pub use termoso_core::import::{
    ImportPreview, ImportSource, ImportedHost, ImportedKey, ImportedKnownHost, ImportedProxy,
    MAX_TEXT_FILE, PfKind, csv, default_ssh_dir, display, expand_tilde, mobaxterm, putty,
    read_text, securecrt, ssh_config, zoc,
};

const MAX_KEY_FILE: u64 = 64 * 1024;
fn cache() -> &'static Mutex<HashMap<Uuid, ImportPreview>> {
    static CACHE: OnceLock<Mutex<HashMap<Uuid, ImportPreview>>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

/// Keep the full preview for a later `apply`; returns the same preview for
/// the caller to hand to the UI (passwords are skipped by serialisation).
pub fn remember(preview: ImportPreview) -> ImportPreview {
    let preview = preview.seal();
    let mut cache = cache().lock().unwrap_or_else(|e| e.into_inner());
    // A dialog holds one preview at a time; keep a few in case of races.
    if cache.len() >= 8 {
        cache.clear();
    }
    cache.insert(preview.id, preview.clone());
    preview
}

pub fn discard(id: Uuid) {
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);
}

fn take(id: Uuid) -> Result<ImportPreview> {
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id)
        .ok_or_else(|| DesktopError::not_found("import preview expired — open the file again"))
}

/// Indexes into the preview lists chosen by the user.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSelection {
    #[serde(default)]
    pub hosts: Vec<usize>,
    #[serde(default)]
    pub keys: Vec<usize>,
    #[serde(default)]
    pub known_hosts: Vec<usize>,
    #[serde(default)]
    pub pf_rules: Vec<usize>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub hosts: usize,
    pub groups: usize,
    pub tags: usize,
    pub keys: usize,
    pub known_hosts: usize,
    pub pf_rules: usize,
    pub host_chains: usize,
    pub proxies: usize,
    /// Hosts already present in the vault (same address+port+user) whose
    /// empty fields were filled in from the import.
    pub updated_hosts: usize,
    /// Hosts / keys already present in the vault (same address+port+user,
    /// same public key) that were left untouched.
    pub skipped_hosts: usize,
    pub skipped_keys: usize,
    pub warnings: Vec<String>,
}

// ───────────────────────────── discovery ─────────────────────────────

fn inspect_key_file(path: &Path) -> Result<Option<ImportedKey>> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() || meta.len() > MAX_KEY_FILE {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Ok(None);
    };
    if !text.contains("PRIVATE KEY-----") {
        if text.starts_with("PuTTY-User-Key-File") {
            return Err(DesktopError::invalid(
                "PuTTY .ppk keys are not supported directly — export as OpenSSH in PuTTYgen (Conversions → Export OpenSSH key)",
            ));
        }
        return Ok(None);
    }
    let info = keys::inspect(text)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(Some(ImportedKey {
        path: display(path),
        name,
        key_type: info.key_type,
        bits: info.bits,
        fingerprint: info.fingerprint,
        encrypted: info.encrypted,
        public_key: info.public_key,
        agent_backed: false,
    }))
}

/// Inspect a `.pub` file. `None` when it is not a public key line.
fn inspect_public_file(path: &Path) -> Result<Option<ImportedKey>> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() || meta.len() > MAX_KEY_FILE {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path)?;
    let line = text.trim();
    if line.is_empty() || line.contains("PRIVATE KEY-----") || line.contains("-cert-v01@") {
        return Ok(None);
    }
    let info = keys::parse_public(line)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(Some(ImportedKey {
        path: display(path),
        name,
        key_type: info.key_type,
        bits: info.bits,
        fingerprint: info.fingerprint,
        encrypted: false,
        public_key: info.public_key,
        agent_backed: true,
    }))
}

fn add_public_key_file(preview: &mut ImportPreview, path: &Path) {
    let shown = display(path);
    if preview.keys.iter().any(|k| k.path == shown) {
        return;
    }
    match inspect_public_file(path) {
        Ok(Some(k)) => preview.keys.push(k),
        Ok(None) => {}
        Err(e) => preview
            .warnings
            .push(format!("Key {shown} skipped: {}", e.message)),
    }
}

/// The private key next to `key.pub`, when it exists (then ssh uses it
/// rather than the agent).
fn private_sibling(pub_path: &Path) -> Option<PathBuf> {
    let stem = PathBuf::from(pub_path.to_str()?.strip_suffix(".pub")?);
    let text = std::fs::read_to_string(&stem).ok()?;
    text.contains("PRIVATE KEY-----").then_some(stem)
}

/// `IdentityFile` target: a private key, or a `.pub` whose private half is
/// either next to it or only in the agent.
fn add_identity_file(preview: &mut ImportPreview, path: &Path) {
    if !path.extension().is_some_and(|e| e == "pub") {
        add_key_file(preview, path);
    } else if let Some(private) = private_sibling(path) {
        add_key_file(preview, &private);
    } else {
        add_public_key_file(preview, path);
    }
}

/// Add `path` to the preview's keys (once), recording unreadable files as
/// warnings instead of failing the whole import.
fn add_key_file(preview: &mut ImportPreview, path: &Path) {
    let shown = display(path);
    if preview.keys.iter().any(|k| k.path == shown) {
        return;
    }
    match inspect_key_file(path) {
        Ok(Some(k)) => preview.keys.push(k),
        Ok(None) => {}
        Err(e) => preview
            .warnings
            .push(format!("Key {shown} skipped: {}", e.message)),
    }
}

/// Returns the number of hashed (`|1|…`) lines, which carry no host name
/// and therefore can't be pinned to a host.
fn parse_known_hosts(contents: &str, out: &mut Vec<ImportedKnownHost>) -> usize {
    let mut hashed = 0;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(hosts), Some(algo), Some(blob)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if hosts.starts_with("|1|") {
            hashed += 1;
            continue;
        }
        let Ok(key) = termoso_core::hostkey::parse_public_key(&format!("{algo} {blob}")) else {
            continue;
        };
        if key.algorithm().as_str() != algo {
            continue;
        }
        let fingerprint = termoso_core::hostkey::fingerprint(&key);
        for h in hosts.split(',') {
            if h.is_empty() || h.contains('*') || h.contains('?') {
                continue;
            }
            if out
                .iter()
                .any(|k| k.hostname == h && k.fingerprint == fingerprint)
            {
                continue;
            }
            out.push(ImportedKnownHost {
                hostname: h.to_string(),
                key_type: algo.to_string(),
                fingerprint: fingerprint.clone(),
                line: format!("{h} {algo} {blob}"),
            });
        }
    }
    hashed
}

fn hashed_known_hosts_warning(name: &str, hashed: usize) -> Option<String> {
    (hashed > 0).then(|| {
        format!(
            "{name}: {hashed} hashed entr{} skipped (HashKnownHosts hides the host name; keys get pinned on first connect instead)",
            if hashed == 1 { "y" } else { "ies" }
        )
    })
}

/// Everything importable from an OpenSSH directory: `config` (with
/// `Include`s), `known_hosts` and private key files found next to them.
pub fn scan_ssh_dir(dir: Option<&str>) -> Result<ImportPreview> {
    let dir = match dir {
        Some(d) if !d.trim().is_empty() => expand_tilde(d.trim()),
        _ => default_ssh_dir().ok_or_else(|| DesktopError::not_found("home directory"))?,
    };
    if !dir.is_dir() {
        return Err(DesktopError::not_found(format!(
            "{} does not exist",
            display(&dir)
        )));
    }
    let mut preview = ImportPreview::new(ImportSource::SshConfig, display(&dir));

    let config = dir.join("config");
    if config.is_file() {
        let text = read_text(&config, MAX_TEXT_FILE)?;
        ssh_config::parse_into(&text, &config, &mut preview);
    }
    for name in ["known_hosts", "known_hosts2"] {
        let p = dir.join(name);
        if p.is_file() {
            match read_text(&p, MAX_TEXT_FILE) {
                Ok(text) => {
                    let hashed = parse_known_hosts(&text, &mut preview.known_hosts);
                    preview
                        .warnings
                        .extend(hashed_known_hosts_warning(name, hashed));
                }
                Err(e) => preview.warnings.push(format!("{name}: {e}")),
            }
        }
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    entries.sort();
    for p in entries {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == "config"
            || name.starts_with("known_hosts")
            || name.starts_with("authorized_keys")
            || name.ends_with("-cert.pub")
        {
            continue;
        }
        if name.ends_with(".pub") {
            // Public halves of private keys found here are implied; a lone
            // `.pub` is an agent-held key (KeePassXC, hardware tokens…).
            if private_sibling(&p).is_none() {
                add_public_key_file(&mut preview, &p);
            }
            continue;
        }
        add_key_file(&mut preview, &p);
    }
    referenced_keys(&mut preview);
    if preview.is_empty() && preview.warnings.is_empty() {
        preview
            .warnings
            .push("Nothing to import: no config, keys or known_hosts found".into());
    }
    Ok(preview)
}

/// Pull in keys referenced by hosts but living outside the scanned
/// directory (or `.pub`-only identities), so they can be selected too.
fn referenced_keys(preview: &mut ImportPreview) {
    let paths: Vec<PathBuf> = preview
        .hosts
        .iter()
        .filter_map(|h| h.key_path.as_deref())
        .map(expand_tilde)
        .collect();
    for p in paths {
        if p.is_file() {
            add_identity_file(preview, &p);
        }
    }
}

/// Parse a single file of the given kind (ssh_config, PuTTY `.reg`, CSV).
pub fn parse_file(source: ImportSource, path: &str) -> Result<ImportPreview> {
    let path = expand_tilde(path.trim());
    if !path.is_file() {
        return Err(DesktopError::not_found(format!(
            "{} does not exist",
            display(&path)
        )));
    }
    let text = read_text(&path, MAX_TEXT_FILE)?;
    let mut preview = ImportPreview::new(source, display(&path));
    match source {
        ImportSource::SshConfig => {
            ssh_config::parse_into(&text, &path, &mut preview);
            referenced_keys(&mut preview);
        }
        ImportSource::Putty => putty::parse_reg_into(&text, &mut preview)?,
        ImportSource::Csv => csv::parse_into(&text, &mut preview)?,
        ImportSource::Mobaxterm => mobaxterm::parse_into(&text, &mut preview)?,
        ImportSource::Securecrt => {
            if text.trim_start().starts_with('<') {
                securecrt::parse_xml_into(&text, &mut preview)?
            } else {
                securecrt::parse_ini_into(&text, &mut preview)?
            }
        }
        ImportSource::Zoc => zoc::parse_into(&text, &mut preview)?,
    }
    if preview.is_empty() {
        return Err(DesktopError::invalid(match source {
            ImportSource::SshConfig => "No hosts found — is this an OpenSSH config file?",
            ImportSource::Putty => {
                "No PuTTY sessions found — export HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions with regedit"
            }
            ImportSource::Csv => "No hosts found in the CSV",
            ImportSource::Mobaxterm => "No SSH or Telnet sessions found in the MobaXterm bookmarks",
            ImportSource::Securecrt => "No SSH or Telnet sessions found in the SecureCRT export",
            ImportSource::Zoc => "No SSH hosts found in the ZOC host directory",
        }));
    }
    Ok(preview)
}

/// Parse CSV text without touching the filesystem or the cache.
#[cfg(test)]
pub fn parse_csv_text(text: &str) -> Result<ImportPreview> {
    let mut preview = ImportPreview::new(ImportSource::Csv, "text");
    csv::parse_into(text, &mut preview)?;
    Ok(preview)
}

/// A SecureCRT `Config` (or `Config/Sessions`) directory: one `.ini` per
/// session, directories are groups.
pub fn scan_securecrt_dir(dir: &str) -> Result<ImportPreview> {
    let dir = expand_tilde(dir.trim());
    if !dir.is_dir() {
        return Err(DesktopError::not_found(format!(
            "{} is not a directory",
            display(&dir)
        )));
    }
    let mut preview = ImportPreview::new(ImportSource::Securecrt, display(&dir));
    securecrt::scan_dir(&dir, &mut preview)?;
    if preview.is_empty() {
        return Err(DesktopError::invalid(
            "No SecureCRT sessions found — pick the Config or Config/Sessions directory",
        ));
    }
    Ok(preview)
}

/// Saved sessions of the PuTTY installed on this machine (Windows registry).
pub fn scan_putty_registry() -> Result<ImportPreview> {
    let text = export_registry()?;
    let mut preview = ImportPreview::new(ImportSource::Putty, putty::REGISTRY_ORIGIN);
    putty::parse_reg_into(&text, &mut preview)?;
    if preview.is_empty() {
        return Err(DesktopError::not_found("No PuTTY saved sessions found"));
    }
    Ok(preview)
}

pub fn csv_template() -> String {
    csv::TEMPLATE.to_string()
}

// ───────────────────────────── apply ─────────────────────────────

struct Existing {
    hosts: Vec<hosts::HostCard>,
    groups: HashMap<(Option<Uuid>, String), Uuid>,
    tags: HashMap<String, Uuid>,
    keys: HashMap<String, Uuid>,
    proxies: HashMap<(String, String, u16), Uuid>,
    rules: HashSet<(Uuid, String, u16, String, u16)>,
}

impl Existing {
    fn load(store: &Store, vault_id: Uuid) -> Result<Self> {
        let groups = store
            .list::<Group>(Some(vault_id))?
            .into_iter()
            .map(|g| ((g.data.parent_id, g.data.label.to_lowercase()), g.id))
            .collect();
        let tags = store
            .list::<Tag>(Some(vault_id))?
            .into_iter()
            .map(|t| (t.data.label.to_lowercase(), t.id))
            .collect();
        let keys = store
            .list::<SshKey>(Some(vault_id))?
            .into_iter()
            .filter_map(|k| {
                let line = keys::inspect(&k.data.private_key)
                    .ok()
                    .map(|i| i.public_key)
                    .or(k.data.public_key)?;
                Some((key_blob(&line), k.id))
            })
            .collect();
        let proxies = store
            .list::<Proxy>(Some(vault_id))?
            .into_iter()
            .filter(|p| p.data.identity_id.is_none())
            .map(|p| {
                (
                    (p.data.kind.clone(), p.data.host.to_lowercase(), p.data.port),
                    p.id,
                )
            })
            .collect();
        let rules = store
            .list::<PfRule>(Some(vault_id))?
            .into_iter()
            .map(|r| {
                (
                    r.data.host_id,
                    r.data.kind,
                    r.data.local_port,
                    r.data.remote_host.to_lowercase(),
                    r.data.remote_port,
                )
            })
            .collect();
        Ok(Self {
            hosts: hosts::cards(store, Some(vault_id))?,
            groups,
            tags,
            keys,
            proxies,
            rules,
        })
    }
}

/// `<type> <base64>` — drop the comment so equal keys compare equal.
fn key_blob(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

fn host_key(address: &str, port: u16, username: &str) -> (String, u16, String) {
    (
        address.trim().to_lowercase(),
        port,
        username.trim().to_string(),
    )
}

fn default_port(protocol: &str) -> u16 {
    if protocol == "telnet" { 23 } else { 22 }
}

/// Split `user@host:port` (host may be `[v6]:port`) as written in
/// `ProxyJump`.
fn split_jump(spec: &str) -> (Option<String>, String, Option<u16>) {
    let (user, rest) = match spec.rsplit_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, spec),
    };
    if let Some(inner) = rest.strip_prefix('[')
        && let Some((host, port)) = inner.split_once(']')
    {
        let port = port.strip_prefix(':').and_then(|p| p.parse().ok());
        return (user, host.to_string(), port);
    }
    match rest.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => match port.parse() {
            Ok(p) => (user, host.to_string(), Some(p)),
            Err(_) => (user, rest.to_string(), None),
        },
        _ => (user, rest.to_string(), None),
    }
}

fn dedup_indexes(v: &[usize], len: usize) -> Vec<usize> {
    let mut seen = HashSet::new();
    v.iter()
        .copied()
        .filter(|i| *i < len && seen.insert(*i))
        .collect()
}

/// Write the selected parts of the cached preview `preview_id` into
/// `vault_id`. The preview is consumed; a failure leaves it discarded too.
pub fn apply_cached(
    state: &AppState,
    vault_id: Uuid,
    preview_id: Uuid,
    selection: &ImportSelection,
) -> Result<ImportReport> {
    let preview = take(preview_id)?;
    apply(state, vault_id, &preview, selection)
}

pub fn apply(
    state: &AppState,
    vault_id: Uuid,
    preview: &ImportPreview,
    selection: &ImportSelection,
) -> Result<ImportReport> {
    let store = &*state.store()?;
    let mut report = ImportReport::default();
    let mut existing = Existing::load(store, vault_id)?;

    // Keys first so hosts can reference them.
    let mut key_by_path: HashMap<String, Uuid> = HashMap::new();
    for i in dedup_indexes(&selection.keys, preview.keys.len()) {
        let k = &preview.keys[i];
        match import_key(store, vault_id, k, &existing) {
            Ok((id, fresh)) => {
                if fresh {
                    existing.keys.insert(key_blob(&k.public_key), id);
                    report.keys += 1;
                } else {
                    report.skipped_keys += 1;
                }
                key_by_path.insert(k.path.clone(), id);
            }
            Err(e) => report
                .warnings
                .push(format!("Key {}: {}", k.name, e.message)),
        }
    }
    // Unselected keys already in the vault still resolve for hosts.
    for k in &preview.keys {
        if !key_by_path.contains_key(&k.path)
            && let Some(id) = existing.keys.get(&key_blob(&k.public_key))
        {
            key_by_path.insert(k.path.clone(), *id);
        }
    }

    let mut imported: HashMap<String, Uuid> = HashMap::new(); // label → host
    let mut pending_chains: Vec<(Uuid, Vec<String>)> = Vec::new();
    for i in dedup_indexes(&selection.hosts, preview.hosts.len()) {
        let h = &preview.hosts[i];
        let port = h.port.unwrap_or_else(|| default_port(&h.protocol));
        let key = host_key(&h.address, port, &h.username);
        if let Some(host_id) = existing
            .hosts
            .iter()
            .find(|c| host_key(&c.address, c.port, &c.username) == key)
            .map(|c| c.id)
        {
            match fill_existing(
                store,
                vault_id,
                host_id,
                h,
                &key_by_path,
                &mut existing,
                &mut report,
            ) {
                Ok(Filled {
                    changed,
                    needs_chain,
                }) => {
                    if changed || needs_chain {
                        report.updated_hosts += 1;
                    } else {
                        report.skipped_hosts += 1;
                    }
                    if needs_chain {
                        pending_chains.push((host_id, h.jump_hosts.clone()));
                    }
                }
                Err(e) => report
                    .warnings
                    .push(format!("Host {}: {}", h.label, e.message)),
            }
            // Let tunnels / chains / forwarding rules resolve to the existing host.
            imported.entry(h.label.clone()).or_insert(host_id);
            continue;
        }
        let group_id =
            ensure_group_path(store, vault_id, &h.group_path, &mut existing, &mut report)?;
        let tag_ids = ensure_tags(store, vault_id, &h.tags, &mut existing, &mut report)?;
        let proxy_id = match &h.proxy {
            Some(p) => Some(ensure_proxy(
                store,
                vault_id,
                p,
                &mut existing,
                &mut report,
            )?),
            None => None,
        };
        let ssh_key_id = h
            .key_path
            .as_deref()
            .and_then(|p| resolve_key(p, &key_by_path));
        if h.key_path.is_some() && ssh_key_id.is_none() && h.protocol == "ssh" {
            report.warnings.push(format!(
                "{}: key {} was not imported, the host has no key",
                h.label,
                h.key_path.as_deref().unwrap_or_default()
            ));
        }
        let telnet = h.protocol == "telnet";
        let password = h.password.clone().filter(|p| !p.is_empty());
        let form = HostForm {
            charset: None,
            backspace: None,
            id: None,
            vault_id,
            label: h.label.clone(),
            address: h.address.trim().to_string(),
            group_id,
            ssh: !telnet,
            port: if telnet { None } else { h.port },
            username: if telnet {
                String::new()
            } else {
                h.username.clone()
            },
            password: if telnet { None } else { password.clone() },
            ssh_key_id,
            ssh_certificate_id: None,
            identity_id: None,
            ssh_id: false,
            ssh_id_key_type: None,
            use_mosh: false,
            mosh_server_command: None,
            tag_ids,
            notes: h.notes.clone(),
            os_name: None,
            icon: None,
            ip_version: "auto".into(),
            agent_forwarding: h.agent_forwarding,
            forward_x11: h.forward_x11,
            startup_snippet_id: None,
            host_chain_id: None,
            proxy_id,
            gateway_id: None,
            mac_address: None,
            telnet: telnet.then(|| TelnetForm {
                port: h.port,
                username: h.username.clone(),
                password,
                ..TelnetForm::default()
            }),
            webdav: None,
            env_variables: h.env_variables.clone(),
            keep_alive_interval: h.keep_alive_interval,
            timeout: h.timeout,
            color_scheme: None,
            has_password: false,
            files_provider: false,
            shell_integration: None,
            totp_secret: None,
            has_totp: false,
        };
        match hosts::save(store, &form) {
            Ok(card) => {
                report.hosts += 1;
                existing.hosts.push(card.clone());
                imported.entry(h.label.clone()).or_insert(card.id);
                if !h.jump_hosts.is_empty() {
                    pending_chains.push((card.id, h.jump_hosts.clone()));
                }
            }
            Err(e) => report
                .warnings
                .push(format!("Host {}: {}", h.label, e.message)),
        }
    }

    for (host_id, jumps) in pending_chains {
        match build_chain(store, vault_id, &jumps, &imported, &mut existing) {
            Ok((chain_id, created)) => {
                report.hosts += created;
                if created > 0 {
                    report.warnings.push(format!(
                        "Jump chain {}: {created} jump host{} not in the import were created as plain SSH hosts",
                        jumps.join(" → "),
                        if created == 1 { "" } else { "s" }
                    ));
                }
                let mut form = hosts::form(store, host_id)?;
                form.host_chain_id = Some(chain_id);
                if let Err(e) = hosts::save(store, &form) {
                    report.warnings.push(format!("Jump chain: {}", e.message));
                } else {
                    report.host_chains += 1;
                }
            }
            Err(e) => report.warnings.push(format!("Jump chain: {}", e.message)),
        }
    }

    for i in dedup_indexes(&selection.pf_rules, preview.pf_rules.len()) {
        let r = &preview.pf_rules[i];
        let host_id = imported.get(&r.host_label).copied().or_else(|| {
            existing
                .hosts
                .iter()
                .find(|c| c.label == r.host_label)
                .map(|c| c.id)
        });
        let Some(host_id) = host_id else {
            report.warnings.push(format!(
                "Forwarding {}:{} skipped: host {} was not imported",
                r.bound_address, r.local_port, r.host_label
            ));
            continue;
        };
        let kind = match r.kind {
            PfKind::Local => "local",
            PfKind::Remote => "remote",
            PfKind::Dynamic => "dynamic",
        };
        let sig = (
            host_id,
            kind.to_string(),
            r.local_port,
            r.remote_host.to_lowercase(),
            r.remote_port,
        );
        if existing.rules.contains(&sig) {
            continue;
        }
        let label = match r.kind {
            PfKind::Dynamic => format!("{} SOCKS :{}", r.host_label, r.local_port),
            PfKind::Local => format!(
                "{} :{} → {}:{}",
                r.host_label, r.local_port, r.remote_host, r.remote_port
            ),
            PfKind::Remote => format!(
                "{} remote :{} → {}:{}",
                r.host_label, r.local_port, r.remote_host, r.remote_port
            ),
        };
        let form = PfRuleForm {
            id: None,
            vault_id,
            label,
            host_id,
            kind: r.kind.into(),
            bound_address: r.bound_address.clone(),
            local_port: r.local_port,
            remote_host: r.remote_host.clone(),
            remote_port: r.remote_port,
            auto_start: false,
        };
        match forwarding::save(state, &form) {
            Ok(_) => {
                existing.rules.insert(sig);
                report.pf_rules += 1;
            }
            Err(e) => report
                .warnings
                .push(format!("Forwarding {}: {}", form.label, e.message)),
        }
    }

    let known: Vec<&str> = dedup_indexes(&selection.known_hosts, preview.known_hosts.len())
        .into_iter()
        .map(|i| preview.known_hosts[i].line.as_str())
        .collect();
    if !known.is_empty() {
        let text = known.join("\n");
        report.known_hosts = trust::import_openssh(state, &text)?.added;
    }

    Ok(report)
}

struct Filled {
    changed: bool,
    /// The import has jump hosts and the existing host no chain yet.
    needs_chain: bool,
}

/// Merge an imported entry into the host already in the vault: fill in what
/// the host leaves empty (group, tags, notes, password, key, proxy) and never
/// overwrite a value the user set. Credentials are only filled on an inline
/// SSH login; a host that references a shared identity or SSH ID keeps it.
fn fill_existing(
    store: &Store,
    vault_id: Uuid,
    host_id: Uuid,
    h: &ImportedHost,
    key_by_path: &HashMap<String, Uuid>,
    existing: &mut Existing,
    report: &mut ImportReport,
) -> Result<Filled> {
    let mut form = hosts::form(store, host_id)?;
    let mut changed = false;
    if form.group_id.is_none() && !h.group_path.is_empty() {
        form.group_id = ensure_group_path(store, vault_id, &h.group_path, existing, report)?;
        changed |= form.group_id.is_some();
    }
    for id in ensure_tags(store, vault_id, &h.tags, existing, report)? {
        if !form.tag_ids.contains(&id) {
            form.tag_ids.push(id);
            changed = true;
        }
    }
    if form.notes.trim().is_empty() && !h.notes.trim().is_empty() {
        form.notes = h.notes.clone();
        changed = true;
    }
    let ssh = form.ssh && h.protocol != "telnet";
    if ssh && form.identity_id.is_none() && !form.ssh_id {
        if !form.has_password
            && let Some(p) = h.password.as_deref().filter(|p| !p.is_empty())
        {
            form.password = Some(p.to_string());
            changed = true;
        }
        if form.ssh_key_id.is_none()
            && let Some(id) = h
                .key_path
                .as_deref()
                .and_then(|p| resolve_key(p, key_by_path))
        {
            form.ssh_key_id = Some(id);
            changed = true;
        }
    }
    if ssh
        && form.proxy_id.is_none()
        && let Some(p) = &h.proxy
    {
        form.proxy_id = Some(ensure_proxy(store, vault_id, p, existing, report)?);
        changed = true;
    }
    if changed {
        hosts::save(store, &form)?;
    }
    Ok(Filled {
        changed,
        needs_chain: ssh && form.host_chain_id.is_none() && !h.jump_hosts.is_empty(),
    })
}

/// Store the key file at `k.path`; returns `(id, freshly_inserted)`.
fn import_key(
    store: &Store,
    vault_id: Uuid,
    k: &ImportedKey,
    existing: &Existing,
) -> Result<(Uuid, bool)> {
    if let Some(id) = existing.keys.get(&key_blob(&k.public_key)) {
        return Ok((*id, false));
    }
    let path = expand_tilde(&k.path);
    let meta = std::fs::metadata(&path)?;
    if meta.len() > MAX_KEY_FILE {
        return Err(DesktopError::invalid("file is too large"));
    }
    let text = std::fs::read_to_string(&path)?;
    let label = if k.name.trim().is_empty() {
        "imported key".to_string()
    } else {
        k.name.trim().to_string()
    };
    if k.agent_backed {
        let key = keychain::agent_key(&label, &text)?;
        let id = store.insert(vault_id, &key)?;
        return Ok((id, true));
    }
    let info = keys::inspect(&text)?;
    let key = if info.encrypted {
        // Cannot normalise without the passphrase; store as-is, the
        // connection prompts for it.
        SshKey {
            external_id: None,
            label,
            private_key: text.trim().to_string(),
            public_key: Some(info.public_key.clone()).filter(|p| !p.is_empty()),
            passphrase: None,
            key_type: short_type(&info.key_type),
            fido2_credential_id: None,
            ssh_id: false,
        }
    } else {
        let material = keys::import(&text, None)?;
        SshKey {
            external_id: None,
            label,
            private_key: material.private_key.to_string(),
            public_key: Some(material.public_key.clone()),
            passphrase: None,
            key_type: short_type(&material.info.key_type),
            fido2_credential_id: None,
            ssh_id: false,
        }
    };
    let id = store.insert(vault_id, &key)?;
    Ok((id, true))
}

fn short_type(t: &str) -> String {
    match t {
        "ssh-ed25519" => "ed25519".into(),
        "ssh-rsa" => "rsa".into(),
        t if t.starts_with("ecdsa") => "ecdsa".into(),
        t => t.to_string(),
    }
}

fn resolve_key(path: &str, by_path: &HashMap<String, Uuid>) -> Option<Uuid> {
    if let Some(id) = by_path.get(path) {
        return Some(*id);
    }
    let expanded = display(&expand_tilde(path));
    if let Some(id) = by_path.get(&expanded) {
        return Some(*id);
    }
    // PuTTY / ssh_config may reference `key.pub`; the private key is next to it.
    if let Some(stem) = expanded.strip_suffix(".pub") {
        return by_path.get(stem).copied();
    }
    None
}

fn ensure_group_path(
    store: &Store,
    vault_id: Uuid,
    path: &[String],
    existing: &mut Existing,
    report: &mut ImportReport,
) -> Result<Option<Uuid>> {
    let mut parent: Option<Uuid> = None;
    for seg in path {
        let label = seg.trim();
        if label.is_empty() {
            continue;
        }
        let key = (parent, label.to_lowercase());
        let id = match existing.groups.get(&key) {
            Some(id) => *id,
            None => {
                let node = hosts::save_group(store, vault_id, None, label, parent)?;
                existing.groups.insert(key, node.id);
                report.groups += 1;
                node.id
            }
        };
        parent = Some(id);
    }
    Ok(parent)
}

fn ensure_tags(
    store: &Store,
    vault_id: Uuid,
    tags: &[String],
    existing: &mut Existing,
    report: &mut ImportReport,
) -> Result<Vec<Uuid>> {
    let mut out = Vec::new();
    for t in tags {
        let label = t.trim();
        if label.is_empty() {
            continue;
        }
        let key = label.to_lowercase();
        let id = match existing.tags.get(&key) {
            Some(id) => *id,
            None => {
                let id = store.insert(
                    vault_id,
                    &Tag {
                        label: label.to_string(),
                        color: None,
                    },
                )?;
                existing.tags.insert(key, id);
                report.tags += 1;
                id
            }
        };
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

fn ensure_proxy(
    store: &Store,
    vault_id: Uuid,
    p: &ImportedProxy,
    existing: &mut Existing,
    report: &mut ImportReport,
) -> Result<Uuid> {
    let has_creds =
        !p.username.trim().is_empty() || p.password.as_deref().is_some_and(|s| !s.is_empty());
    let key = (p.kind.clone(), p.host.to_lowercase(), p.port);
    if !has_creds && let Some(id) = existing.proxies.get(&key) {
        return Ok(*id);
    }
    let identity_id = if has_creds {
        Some(store.insert(
            vault_id,
            &Identity {
                external_id: None,
                label: format!("{}:{} proxy", p.host, p.port),
                username: p.username.trim().to_string(),
                password: p.password.clone().filter(|s| !s.is_empty()),
                ssh_key_id: None,
                ssh_certificate_id: None,
                is_visible: false,
                ssh_id: false,
                ssh_id_key_type: None,
                bearer_token: None,
                client_certificate: None,
                totp_secret: None,
            },
        )?)
    } else {
        None
    };
    let id = store.insert(
        vault_id,
        &Proxy {
            kind: p.kind.clone(),
            host: p.host.trim().to_string(),
            port: p.port,
            identity_id,
            username: None,
            password: None,
        },
    )?;
    if !has_creds {
        existing.proxies.insert(key, id);
    }
    report.proxies += 1;
    Ok(id)
}

/// Resolve `ProxyJump` entries to hosts (imported, existing, or created on
/// the fly) and store a chain. Returns `(chain_id, hosts_created)`.
fn build_chain(
    store: &Store,
    vault_id: Uuid,
    jumps: &[String],
    imported: &HashMap<String, Uuid>,
    existing: &mut Existing,
) -> Result<(Uuid, usize)> {
    let mut ids = Vec::new();
    let mut created = 0;
    for spec in jumps {
        let spec = spec.trim();
        if spec.is_empty() || spec.eq_ignore_ascii_case("none") {
            continue;
        }
        if let Some(id) = imported.get(spec) {
            ids.push(*id);
            continue;
        }
        let (user, host, port) = split_jump(spec);
        let found = imported.get(&host).copied().or_else(|| {
            existing
                .hosts
                .iter()
                .find(|c| {
                    (c.label == host || c.address.eq_ignore_ascii_case(&host))
                        && port.is_none_or(|p| p == c.port)
                        && user.as_deref().is_none_or(|u| u == c.username)
                })
                .map(|c| c.id)
        });
        let id = match found {
            Some(id) => id,
            None => {
                let form = HostForm {
                    charset: None,
                    backspace: None,
                    id: None,
                    vault_id,
                    label: host.clone(),
                    address: host.clone(),
                    group_id: None,
                    ssh: true,
                    port,
                    username: user.unwrap_or_default(),
                    password: None,
                    ssh_key_id: None,
                    ssh_certificate_id: None,
                    identity_id: None,
                    ssh_id: false,
                    ssh_id_key_type: None,
                    use_mosh: false,
                    mosh_server_command: None,
                    tag_ids: Vec::new(),
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
                    env_variables: Vec::new(),
                    keep_alive_interval: None,
                    timeout: None,
                    color_scheme: None,
                    has_password: false,
                    files_provider: false,
                    shell_integration: None,
                    totp_secret: None,
                    has_totp: false,
                };
                let card = hosts::save(store, &form)?;
                existing.hosts.push(card.clone());
                created += 1;
                card.id
            }
        };
        ids.push(id);
    }
    if ids.is_empty() {
        return Err(DesktopError::invalid("no jump hosts"));
    }
    let labels: Vec<String> = ids
        .iter()
        .filter_map(|id| existing.hosts.iter().find(|c| c.id == *id))
        .map(|c| c.label.clone())
        .collect();
    let chain = HostChain {
        label: format!("via {}", labels.join(" → ")),
        host_ids: ids,
    };
    // Reuse an identical chain when one exists.
    if let Some(e) = store
        .list::<HostChain>(Some(vault_id))?
        .into_iter()
        .find(|e| e.data.host_ids == chain.host_ids)
    {
        return Ok((e.id, created));
    }
    Ok((store.insert(vault_id, &chain)?, created))
}

// PuTTY sessions straight from the Windows registry (regedit export).
#[cfg(windows)]
pub fn export_registry() -> Result<String> {
    use std::process::Command;
    let dir = std::env::temp_dir().join(format!("termoso-putty-{}.reg", uuid::Uuid::new_v4()));
    let mut cmd = Command::new("reg");
    cmd.args([
        "export",
        putty::REGISTRY_ORIGIN,
        &dir.to_string_lossy(),
        "/y",
    ]);
    crate::sessions::hide_console_window(&mut cmd);
    let status = cmd.output()?;
    if !status.status.success() {
        let _ = std::fs::remove_file(&dir);
        return Err(DesktopError::invalid(
            "PuTTY has no saved sessions in the registry (or PuTTY is not installed)",
        ));
    }
    let bytes = std::fs::read(&dir)?;
    let _ = std::fs::remove_file(&dir);
    Ok(termoso_core::import::decode_text(&bytes))
}

#[cfg(not(windows))]
pub fn export_registry() -> Result<String> {
    Err(DesktopError::invalid(
        "Reading the PuTTY registry works on Windows only — import a .reg export instead",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoso_core::import::{ImportedHost, decode_text};

    #[test]
    fn jump_specs_split() {
        assert_eq!(
            split_jump("alice@bastion:2222"),
            (Some("alice".into()), "bastion".into(), Some(2222))
        );
        assert_eq!(split_jump("bastion"), (None, "bastion".into(), None));
        assert_eq!(
            split_jump("[2001:db8::1]:22"),
            (None, "2001:db8::1".into(), Some(22))
        );
        assert_eq!(
            split_jump("2001:db8::1"),
            (None, "2001:db8::1".into(), None)
        );
    }

    #[test]
    fn known_hosts_lines() {
        let text = "\
# comment
github.com,140.82.121.4 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
|1|hashed|hashed ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
broken line
";
        let mut out = Vec::new();
        assert_eq!(parse_known_hosts(text, &mut out), 1);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].hostname, "github.com");
        assert_eq!(out[1].hostname, "140.82.121.4");
        assert!(out[0].fingerprint.starts_with("SHA256:"));
        assert!(out[0].line.starts_with("github.com ssh-ed25519 "));
    }

    #[test]
    fn utf16_reg_decodes() {
        let mut bytes = vec![0xFF, 0xFE];
        for c in "Windows Registry Editor".encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        assert_eq!(decode_text(&bytes), "Windows Registry Editor");
        assert_eq!(decode_text("plain".as_bytes()), "plain");
    }

    #[test]
    fn preview_serialization_redacts_secrets_and_cache_keeps_them() {
        let mut preview = ImportPreview::new(ImportSource::Csv, "test.csv");
        preview.hosts.push(ImportedHost {
            label: "web".into(),
            address: "web.example.com".into(),
            protocol: "ssh".into(),
            password: Some("hunter2-host".into()),
            proxy: Some(ImportedProxy {
                kind: "socks5".into(),
                host: "proxy".into(),
                port: 1080,
                username: "pu".into(),
                password: Some("hunter2-proxy".into()),
                has_password: false,
            }),
            ..ImportedHost::default()
        });
        let sealed = remember(preview);
        let json = serde_json::to_string(&sealed).unwrap();
        assert!(!json.contains("hunter2"), "{json}");
        assert!(json.contains("\"hasPassword\":true"));
        assert!(!json.contains("\"password\""));

        let cached = take(sealed.id).unwrap();
        assert_eq!(cached.hosts[0].password.as_deref(), Some("hunter2-host"));
        assert_eq!(
            cached.hosts[0].proxy.as_ref().unwrap().password.as_deref(),
            Some("hunter2-proxy")
        );
        assert!(take(sealed.id).is_err(), "a preview is consumed once");

        let again = remember(cached);
        discard(again.id);
        assert!(take(again.id).is_err());
    }

    #[test]
    fn pub_only_identity_files_become_agent_backed_keys() {
        const PRIVATE: &str =
            include_str!("../../../../../crates/termoso-core/testdata/keys/ed25519_openssh");
        const PUBLIC: &str =
            include_str!("../../../../../crates/termoso-core/testdata/keys/ed25519_openssh.pub");
        const OTHER_PUBLIC: &str =
            include_str!("../../../../../crates/termoso-core/testdata/keys/rsa_openssh.pub");
        const CERT: &str =
            include_str!("../../../../../crates/termoso-core/testdata/keys/ed25519-cert.pub");

        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir(&ssh).unwrap();
        std::fs::write(ssh.join("id_ed25519"), PRIVATE).unwrap();
        std::fs::write(ssh.join("id_ed25519.pub"), PUBLIC).unwrap();
        std::fs::write(ssh.join("keepass.pub"), OTHER_PUBLIC).unwrap();
        std::fs::write(ssh.join("id_ed25519-cert.pub"), CERT).unwrap();
        let config = format!(
            "Host disk\n  HostName disk.example.com\n  IdentityFile {d}/id_ed25519.pub\n\
             Host agent\n  HostName agent.example.com\n  IdentityFile {d}/keepass.pub\n\
             Host bare\n  HostName bare.example.com\n",
            d = display(&ssh)
        );
        std::fs::write(ssh.join("config"), config).unwrap();

        let preview = scan_ssh_dir(Some(&display(&ssh))).unwrap();
        assert_eq!(preview.warnings, Vec::<String>::new());
        let mut names: Vec<(String, bool)> = preview
            .keys
            .iter()
            .map(|k| (k.name.clone(), k.agent_backed))
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                ("id_ed25519".to_string(), false),
                ("keepass.pub".to_string(), true)
            ],
            "the .pub next to a private key is implied; the lone one is agent-held"
        );
        let json = serde_json::to_string(&preview).unwrap();
        assert!(json.contains("\"agentBacked\":true") && !json.contains("PRIVATE KEY"));

        // A single referenced `.pub` file works the same way.
        let mut single = ImportPreview::new(ImportSource::SshConfig, "cfg");
        single.hosts.push(ImportedHost {
            label: "x".into(),
            address: "x".into(),
            protocol: "ssh".into(),
            key_path: Some(display(&ssh.join("keepass.pub"))),
            ..ImportedHost::default()
        });
        referenced_keys(&mut single);
        assert_eq!(single.keys.len(), 1);
        assert!(single.keys[0].agent_backed);

        let state = AppState::in_memory(dir.path().join("profile"));
        let store = &*state.store().unwrap();
        let vault = store.local_vault().unwrap().id;
        let report = apply(
            &state,
            vault,
            &preview,
            &ImportSelection {
                hosts: (0..preview.hosts.len()).collect(),
                keys: (0..preview.keys.len()).collect(),
                ..ImportSelection::default()
            },
        )
        .unwrap();
        assert_eq!((report.hosts, report.keys), (3, 2));

        let key_of = |label: &str| {
            let host = store
                .list::<termoso_core::model::Host>(Some(vault))
                .unwrap()
                .into_iter()
                .find(|h| h.data.label == label)
                .unwrap();
            store.resolve_host(host.id).unwrap().key
        };
        let disk = key_of("disk").expect("disk host has a key");
        assert!(!disk.data.is_agent_backed());
        assert_eq!(disk.data.label, "id_ed25519");
        assert!(disk.data.private_key.contains("PRIVATE KEY"));
        let agent = key_of("agent").expect("agent host has a key");
        assert!(agent.data.is_agent_backed());
        assert!(agent.data.private_key.is_empty());
        assert_eq!(agent.data.public_key.as_deref(), Some(OTHER_PUBLIC.trim()));
        assert!(key_of("bare").is_none());

        // Re-import: everything already there, nothing duplicated.
        let again = apply(
            &state,
            vault,
            &preview,
            &ImportSelection {
                keys: (0..preview.keys.len()).collect(),
                ..ImportSelection::default()
            },
        )
        .unwrap();
        assert_eq!((again.keys, again.skipped_keys), (0, 2));
        assert_eq!(store.list::<SshKey>(Some(vault)).unwrap().len(), 2);
    }

    #[test]
    fn reimport_fills_missing_fields_and_keeps_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::in_memory(dir.path().join("profile"));
        let store = &*state.store().unwrap();
        let vault = store.local_vault().unwrap().id;
        let every_host = |p: &ImportPreview| ImportSelection {
            hosts: (0..p.hosts.len()).collect(),
            ..ImportSelection::default()
        };
        const HEADER: &str = "Groups,Label,Tags,Hostname/IP,Protocol,Port,Username,Password\n";

        // First source knows only address and user, like an ssh_config.
        let mut bare = ImportPreview::new(ImportSource::SshConfig, "config");
        bare.hosts.push(ImportedHost {
            label: "web".into(),
            address: "web.example.com".into(),
            protocol: "ssh".into(),
            username: "deploy".into(),
            ..ImportedHost::default()
        });
        assert_eq!(
            apply(&state, vault, &bare, &every_host(&bare))
                .unwrap()
                .hosts,
            1
        );

        // Second source for the same host brings group, tag and password.
        let csv = parse_csv_text(&format!(
            "{HEADER}Prod/Web,web,nginx,web.example.com,ssh,,deploy,first-secret\n"
        ))
        .unwrap();
        let report = apply(&state, vault, &csv, &every_host(&csv)).unwrap();
        assert_eq!(
            (report.hosts, report.updated_hosts, report.skipped_hosts),
            (0, 1, 0)
        );
        let cards = hosts::cards(store, Some(vault)).unwrap();
        assert_eq!(cards.len(), 1, "no duplicate host");
        let id = cards[0].id;
        assert_eq!(cards[0].group_path, ["Prod", "Web"]);
        assert_eq!(cards[0].tags, ["nginx"]);
        let password = || {
            store
                .resolve_host(id)
                .unwrap()
                .identity
                .and_then(|i| i.data.password)
        };
        assert_eq!(password().as_deref(), Some("first-secret"));

        // A third source with different values changes nothing already set.
        let other = parse_csv_text(&format!(
            "{HEADER}Staging,web,nginx,web.example.com,ssh,,deploy,second-secret\n"
        ))
        .unwrap();
        let report = apply(&state, vault, &other, &every_host(&other)).unwrap();
        assert_eq!((report.updated_hosts, report.skipped_hosts), (0, 1));
        assert_eq!(
            hosts::cards(store, Some(vault)).unwrap()[0].group_path,
            ["Prod", "Web"]
        );
        assert_eq!(password().as_deref(), Some("first-secret"));
    }
}
