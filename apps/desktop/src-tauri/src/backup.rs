//! Portable data: hosts as Termius-style CSV and whole vaults as a
//! password-protected `.termoso` backup.
//!
//! Both leave the webview out of the loop: the frontend only passes a target
//! path (chosen through the native dialog) and, for backups, a password. The
//! plaintext never crosses IPC.
//!
//! Backup file layout (`.termoso`):
//!
//! ```text
//! magic "TERMOSO-BACKUP\n" · u32 LE header length · header JSON · AEAD envelope
//! ```
//!
//! The header carries only what is needed to derive the key (format version,
//! Argon2id parameters, salt). Vault names, counts and every entity live inside
//! the XChaCha20-Poly1305 envelope, which is bound to the header through the
//! associated data so the parameters cannot be swapped.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use termoso_core::model::{Entity, Identity};
use termoso_core::store::{EntityFilter, LocalVaultKind, Store};
use termoso_crypto::aead::{self, Aad};
use termoso_crypto::kdf::{self, PasswordParams};
use termoso_proto::entities::KINDS;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{DesktopError, Result};
use crate::hosts;

// ───────────────────────────── CSV ─────────────────────────────

/// Column order of the exported CSV; the same header the importer accepts, so
/// a file exported here re-imports without mapping.
pub const CSV_HEADER: [&str; 8] = [
    "Groups",
    "Label",
    "Tags",
    "Hostname/IP",
    "Protocol",
    "Port",
    "Username",
    "Password",
];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CsvExportReport {
    pub hosts: usize,
    /// True when the file contains plaintext passwords.
    pub passwords_included: bool,
    pub path: String,
}

fn csv_field(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    // Leading formula characters are neutralised so the file is safe to open
    // in a spreadsheet.
    let needs_prefix = matches!(s.chars().next(), Some('=' | '+' | '-' | '@'));
    let body = if needs_prefix {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if body.contains(['"', ',', ';', '\n', '\r']) || body != body.trim() {
        format!("\"{}\"", body.replace('"', "\"\""))
    } else {
        body
    }
}

/// Render the hosts of `vault_id` (or every unlocked vault) as CSV.
///
/// Field mapping: `Groups` = group path joined with `/`, `Label`, `Tags`
/// (comma separated), `Hostname/IP`, `Protocol` (`ssh` or `telnet`), `Port`
/// and `Username` are the effective values shown on the host card.
/// `Password` is written only when `include_passwords` is set and the host's
/// own or inherited identity carries one; keys, certificates, proxies and
/// jump chains are never exported.
pub fn hosts_csv(
    store: &Store,
    vault_id: Option<Uuid>,
    include_passwords: bool,
) -> Result<(String, usize)> {
    if let Some(v) = vault_id
        && termoso_core::policy::export_denied(store, v)
    {
        return Err(DesktopError::invalid(
            termoso_core::policy::Denied::Export.message(),
        ));
    }
    let mut cards = hosts::cards(store, vault_id)?;
    cards.retain(|c| !termoso_core::policy::export_denied(store, c.vault_id));
    let mut out = String::new();
    out.push_str(&CSV_HEADER.join(","));
    out.push('\n');
    for c in &cards {
        let password = if include_passwords {
            let r = store.resolve_host_in(c.id, Some(c.vault_id))?;
            r.identity
                .as_ref()
                .and_then(|i: &Entity<Identity>| i.data.password.clone())
                .unwrap_or_default()
        } else {
            String::new()
        };
        let row = [
            csv_field(&c.group_path.join("/")),
            csv_field(&c.label),
            csv_field(&c.tags.join(", ")),
            csv_field(&c.address),
            csv_field(&c.protocol),
            csv_field(&c.port.to_string()),
            csv_field(&c.username),
            csv_field(&password),
        ];
        out.push_str(&row.join(","));
        out.push('\n');
    }
    Ok((out, cards.len()))
}

/// Write the CSV to `path` (owner-only on Unix).
pub fn export_hosts_csv(
    store: &Store,
    vault_id: Option<Uuid>,
    include_passwords: bool,
    path: &str,
) -> Result<CsvExportReport> {
    let (text, hosts) = hosts_csv(store, vault_id, include_passwords)?;
    write_private(path, text.as_bytes())?;
    Ok(CsvExportReport {
        hosts,
        passwords_included: include_passwords,
        path: path.to_string(),
    })
}

fn write_private(path: &str, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.flush()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)?;
        Ok(())
    }
}

// ───────────────────────────── backup format ─────────────────────────────

const MAGIC: &[u8] = b"TERMOSO-BACKUP\n";
const FORMAT_VERSION: u32 = 1;
const MAX_HEADER: usize = 4096;
const MAX_FILE: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Header {
    version: u32,
    kdf: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Payload {
    created_at: DateTime<Utc>,
    app_version: String,
    vaults: Vec<VaultDump>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultDump {
    id: Uuid,
    kind: LocalVaultKind,
    name: String,
    entities: Vec<EntityDump>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EntityDump {
    id: Uuid,
    kind: String,
    updated_at: DateTime<Utc>,
    data: serde_json::Value,
}

fn aad(header_json: &[u8]) -> Aad {
    Aad::label(&["backup", "v1", &B64.encode(header_json)])
}

fn derive(password: &str, header: &Header) -> Result<termoso_crypto::keys::SymmetricKey> {
    if header.kdf != "argon2id" {
        return Err(DesktopError::invalid(format!(
            "unsupported backup key derivation {}",
            header.kdf
        )));
    }
    let salt = B64
        .decode(&header.salt)
        .map_err(|_| DesktopError::invalid("backup header is corrupted"))?;
    // Cap the parameters a file may request so a hostile backup cannot pin the
    // machine (4 GiB, 64 passes).
    if header.m_cost > 4 * 1024 * 1024 || header.t_cost > 64 || header.p_cost > 16 {
        return Err(DesktopError::invalid(
            "backup asks for unreasonable KDF cost",
        ));
    }
    let params = PasswordParams {
        m_cost: header.m_cost,
        t_cost: header.t_cost,
        p_cost: header.p_cost,
    };
    Ok(kdf::password_key(password.as_bytes(), &salt, params)
        .map_err(termoso_core::error::CoreError::from)?)
}

fn dump_vault(store: &Store, vault_id: Uuid) -> Result<VaultDump> {
    let v = store.vault(vault_id)?;
    if !v.unlocked {
        return Err(DesktopError::invalid(format!(
            "vault \"{}\" is locked and cannot be exported",
            v.name
        )));
    }
    let mut entities = Vec::new();
    for kind in KINDS {
        let filter = EntityFilter {
            vault_id: Some(vault_id),
            kind: Some((*kind).to_string()),
            include_deleted: false,
        };
        for e in store.list_any(&filter)? {
            entities.push(EntityDump {
                id: e.id,
                kind: (*kind).to_string(),
                updated_at: e.updated_at,
                data: e.data,
            });
        }
    }
    Ok(VaultDump {
        id: v.id,
        kind: v.kind,
        name: v.name,
        entities,
    })
}

fn collect(store: &Store, vault_ids: &[Uuid]) -> Result<Payload> {
    // Team policy `export = deny`: such vaults are skipped from "everything"
    // and refused when asked for by name.
    let ids: Vec<Uuid> = if vault_ids.is_empty() {
        store
            .vaults()?
            .into_iter()
            .filter(|v| v.unlocked && !termoso_core::policy::export_denied(store, v.id))
            .map(|v| v.id)
            .collect()
    } else {
        if let Some(id) = vault_ids
            .iter()
            .find(|id| termoso_core::policy::export_denied(store, **id))
        {
            let _ = id;
            return Err(DesktopError::invalid(
                termoso_core::policy::Denied::Export.message(),
            ));
        }
        vault_ids.to_vec()
    };
    if ids.is_empty() {
        return Err(DesktopError::invalid("no unlocked vault to export"));
    }
    let mut vaults = Vec::with_capacity(ids.len());
    for id in ids {
        vaults.push(dump_vault(store, id)?);
    }
    Ok(Payload {
        created_at: Utc::now(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        vaults,
    })
}

fn seal(payload: &Payload, password: &str) -> Result<Vec<u8>> {
    if password.chars().count() < 8 {
        return Err(DesktopError::invalid(
            "backup password must be at least 8 characters",
        ));
    }
    let plaintext = Zeroizing::new(serde_json::to_vec(payload)?);

    let mut salt = [0u8; kdf::PASSWORD_SALT_LEN];
    termoso_crypto::random_bytes(&mut salt);
    let params = PasswordParams::default();
    let header = Header {
        version: FORMAT_VERSION,
        kdf: "argon2id".to_string(),
        m_cost: params.m_cost,
        t_cost: params.t_cost,
        p_cost: params.p_cost,
        salt: B64.encode(salt),
    };
    let header_json = serde_json::to_vec(&header)?;
    let key = derive(password, &header)?;
    let envelope = aead::encrypt(&key, &aad(&header_json), &plaintext)
        .map_err(termoso_core::error::CoreError::from)?;

    let mut out = Vec::with_capacity(MAGIC.len() + 4 + header_json.len() + envelope.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_json);
    out.extend_from_slice(&envelope);
    Ok(out)
}

/// Encrypt `vault_ids` (every unlocked vault when empty) under `password`.
#[cfg(test)]
fn encode(store: &Store, vault_ids: &[Uuid], password: &str) -> Result<Vec<u8>> {
    seal(&collect(store, vault_ids)?, password)
}

fn decode(bytes: &[u8], password: &str) -> Result<Payload> {
    let corrupted = || DesktopError::invalid("not a Termoso backup file");
    let rest = bytes.strip_prefix(MAGIC).ok_or_else(corrupted)?;
    let (len, rest) = rest.split_at_checked(4).ok_or_else(corrupted)?;
    let len = u32::from_le_bytes([len[0], len[1], len[2], len[3]]) as usize;
    if len == 0 || len > MAX_HEADER {
        return Err(corrupted());
    }
    let (header_json, envelope) = rest.split_at_checked(len).ok_or_else(corrupted)?;
    let header: Header = serde_json::from_slice(header_json).map_err(|_| corrupted())?;
    if header.version != FORMAT_VERSION {
        return Err(DesktopError::invalid(format!(
            "backup format v{} is newer than this Termoso understands",
            header.version
        )));
    }
    let key = derive(password, &header)?;
    let plaintext = Zeroizing::new(
        aead::decrypt(&key, &aad(header_json), envelope)
            .map_err(|_| DesktopError::new("auth", "wrong password or damaged backup"))?,
    );
    Ok(serde_json::from_slice(&plaintext)?)
}

/// Write an encrypted backup to `path`.
pub fn export_file(
    store: &Store,
    vault_ids: &[Uuid],
    password: &str,
    path: &str,
) -> Result<BackupSummary> {
    let payload = collect(store, vault_ids)?;
    let bytes = seal(&payload, password)?;
    write_private(path, &bytes)?;
    Ok(summary(Uuid::nil(), &payload, Some(path.to_string())))
}

// ───────────────────────────── import ─────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupVaultSummary {
    pub id: Uuid,
    pub kind: LocalVaultKind,
    pub name: String,
    pub entities: usize,
    /// Count per entity kind, only kinds that are present.
    pub counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSummary {
    /// Token for `apply`; nil when this summary describes a fresh export.
    pub preview_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub app_version: String,
    pub vaults: Vec<BackupVaultSummary>,
    pub path: Option<String>,
}

fn summary(preview_id: Uuid, p: &Payload, path: Option<String>) -> BackupSummary {
    BackupSummary {
        preview_id,
        created_at: p.created_at,
        app_version: p.app_version.clone(),
        path,
        vaults: p
            .vaults
            .iter()
            .map(|v| {
                let mut counts = BTreeMap::new();
                for e in &v.entities {
                    *counts.entry(e.kind.clone()).or_insert(0) += 1;
                }
                BackupVaultSummary {
                    id: v.id,
                    kind: v.kind,
                    name: v.name.clone(),
                    entities: v.entities.len(),
                    counts,
                }
            })
            .collect(),
    }
}

fn cache() -> &'static Mutex<HashMap<Uuid, Payload>> {
    static CACHE: OnceLock<Mutex<HashMap<Uuid, Payload>>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

/// Decrypt a backup and keep it in memory for a following `apply`.
pub fn inspect_file(path: &str, password: &str) -> Result<BackupSummary> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_FILE {
        return Err(DesktopError::invalid("backup file is too large"));
    }
    let bytes = std::fs::read(path)?;
    let payload = decode(&bytes, password)?;
    let id = Uuid::new_v4();
    let s = summary(id, &payload, Some(path.to_string()));
    let mut cache = cache().lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= 4 {
        cache.clear();
    }
    cache.insert(id, payload);
    Ok(s)
}

pub fn discard(preview_id: Uuid) {
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&preview_id);
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreReport {
    pub added: usize,
    pub replaced: usize,
    /// Entities whose id already lives in another vault; left untouched.
    pub skipped: usize,
    pub warnings: Vec<String>,
}

/// Restore the vault at index `source` of the cached backup into
/// `target_vault_id`. Entities keep their ids so cross references (groups,
/// identities, keys, tags) survive; an entity already present in the target
/// vault is replaced, one that lives in a different vault is skipped.
pub fn apply(
    store: &Store,
    preview_id: Uuid,
    source: usize,
    target_vault_id: Uuid,
) -> Result<RestoreReport> {
    let payload = cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&preview_id)
        .ok_or_else(|| DesktopError::not_found("backup preview expired — open the file again"))?;
    let dump = payload
        .vaults
        .get(source)
        .ok_or_else(|| DesktopError::invalid("no such vault in the backup"))?;
    let target = store.vault(target_vault_id)?;
    if !target.unlocked {
        return Err(DesktopError::invalid(format!(
            "vault \"{}\" is locked",
            target.name
        )));
    }
    let mut report = RestoreReport::default();
    for e in &dump.entities {
        match store.row(e.id)? {
            Some(row) if row.vault_id != target_vault_id => {
                report.skipped += 1;
                continue;
            }
            Some(_) => report.replaced += 1,
            None => report.added += 1,
        }
        if let Err(err) = store.put_raw(target_vault_id, &e.kind, e.id, &e.data) {
            report.warnings.push(format!("{} {}: {err}", e.kind, e.id));
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoso_core::model::{Group, Host, SshConfig};
    use termoso_crypto::keys::SymmetricKey;

    fn store() -> (Store, Uuid) {
        let s = Store::open_in_memory(SymmetricKey::generate()).expect("store");
        let v = s.local_vault().unwrap().id;
        (s, v)
    }

    fn seed(s: &Store, v: Uuid) -> Uuid {
        let group = s
            .insert(
                v,
                &Group {
                    label: "Prod, EU".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let identity = s
            .insert(
                v,
                &Identity {
                    label: "deploy".into(),
                    username: "deploy".into(),
                    password: Some("s3cret".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let ssh = s
            .insert(
                v,
                &SshConfig {
                    port: Some(2222),
                    identity_id: Some(identity),
                    ..Default::default()
                },
            )
            .unwrap();
        s.insert(
            v,
            &Host {
                label: "=web \"1\"".into(),
                address: "web1.example.com".into(),
                group_id: Some(group),
                ssh_config_id: Some(ssh),
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn csv_omits_passwords_by_default_and_escapes() {
        let (s, v) = store();
        seed(&s, v);
        let (csv, n) = hosts_csv(&s, Some(v), false).unwrap();
        assert_eq!(n, 1);
        let mut lines = csv.lines();
        assert_eq!(lines.next().unwrap(), CSV_HEADER.join(","));
        let row = lines.next().unwrap();
        assert_eq!(
            row,
            "\"Prod, EU\",\"'=web \"\"1\"\"\",,web1.example.com,ssh,2222,deploy,"
        );
        assert!(!csv.contains("s3cret"));
        let (with, _) = hosts_csv(&s, Some(v), true).unwrap();
        assert!(with.lines().nth(1).unwrap().ends_with(",deploy,s3cret"));
    }

    #[test]
    fn csv_round_trips_through_importer() {
        let (s, v) = store();
        seed(&s, v);
        let (csv, _) = hosts_csv(&s, Some(v), false).unwrap();
        let preview = crate::import::parse_csv_text(&csv).unwrap();
        assert_eq!(preview.hosts.len(), 1);
        let h = &preview.hosts[0];
        assert_eq!(h.address, "web1.example.com");
        assert_eq!(h.port, Some(2222));
        assert_eq!(h.username, "deploy");
        assert_eq!(h.group_path, vec!["Prod, EU".to_string()]);
        assert!(h.password.is_none());
    }

    #[test]
    fn backup_round_trip_and_wrong_password() {
        let (s, v) = store();
        let host_id = seed(&s, v);
        let bytes = encode(&s, &[v], "correct horse battery").unwrap();
        assert!(bytes.starts_with(MAGIC));
        assert!(!bytes.windows(6).any(|w| w == b"s3cret"));
        assert!(!bytes.windows(16).any(|w| w == b"web1.example.com"));

        let err = decode(&bytes, "wrong password!").unwrap_err();
        assert_eq!(err.kind, "auth");

        let payload = decode(&bytes, "correct horse battery").unwrap();
        assert_eq!(payload.vaults.len(), 1);
        assert_eq!(payload.vaults[0].entities.len(), 4);

        // Restore into a fresh store.
        let (t, tv) = store();
        let id = Uuid::new_v4();
        cache().lock().unwrap().insert(id, payload);
        let rep = apply(&t, id, 0, tv).unwrap();
        assert_eq!(rep.added, 4);
        assert_eq!(rep.replaced, 0);
        let restored = t.resolve_host(host_id).unwrap();
        assert_eq!(restored.port(), 2222);
        assert_eq!(restored.username().as_deref(), Some("deploy"));
        assert_eq!(restored.group_path, vec!["Prod, EU".to_string()]);
        assert_eq!(
            restored.identity.unwrap().data.password.as_deref(),
            Some("s3cret")
        );

        // Restoring again replaces instead of duplicating.
        let payload = decode(&bytes, "correct horse battery").unwrap();
        cache().lock().unwrap().insert(id, payload);
        let rep = apply(&t, id, 0, tv).unwrap();
        assert_eq!(rep.replaced, 4);
        assert_eq!(t.list::<Host>(Some(tv)).unwrap().len(), 1);
    }

    #[test]
    fn rejects_short_password_and_garbage() {
        let (s, v) = store();
        assert!(encode(&s, &[v], "short").is_err());
        assert!(decode(b"nope", "x").is_err());
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&bytes, "x").is_err());
    }
}
