//! Keychain façade: SSH keys, their certificates and identities. Private key
//! text never leaves Rust except through the explicit `export` path; list
//! DTOs carry only the public half and metadata derived by
//! `termoso_core::keys`. A certificate is public data attached to exactly
//! one key (`SshCertificate.ssh_key_id`); identities pick it up through the
//! key.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use termoso_core::fido2;
#[cfg(feature = "fido2")]
use termoso_core::fido2::{Fido2Device, GenerateOptions, SecurityKeyInfo};
use termoso_core::keys::{self, CertificateInfo, KeyAlgorithm, KeyInfo};
use termoso_core::model::{Entity, Identity, SshCertificate, SshConfig, SshKey, TelnetConfig};
use termoso_core::store::Store;
use termoso_proto::entities::AGENT_KEY_TYPE;
use termoso_proto::sshid::SshIdKeyType;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{ClientError, Result};

/// Public metadata of an OpenSSH certificate (`*-cert.pub`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateCard {
    /// `None` for a preview that has not been stored yet.
    pub id: Option<Uuid>,
    /// `ssh-ed25519-cert-v01@openssh.com`, …
    pub cert_type: String,
    /// `user` or `host`.
    pub kind: String,
    pub key_id: String,
    pub serial: u64,
    pub principals: Vec<String>,
    pub valid_after: Option<chrono::DateTime<chrono::Utc>>,
    pub valid_before: Option<chrono::DateTime<chrono::Utc>>,
    /// Fingerprint of the certified key (equals the key's fingerprint).
    pub fingerprint: String,
    pub ca_fingerprint: String,
    pub ca_key_type: String,
    /// Inside the validity window right now.
    pub valid_now: bool,
}

impl CertificateCard {
    fn from_info(id: Option<Uuid>, i: CertificateInfo) -> Self {
        Self {
            id,
            cert_type: i.cert_type,
            kind: i.kind,
            key_id: i.key_id,
            serial: i.serial,
            principals: i.principals,
            valid_after: i.valid_after,
            valid_before: i.valid_before,
            fingerprint: i.fingerprint,
            ca_fingerprint: i.ca_fingerprint,
            ca_key_type: i.ca_key_type,
            valid_now: i.valid_now,
        }
    }
}

/// Metadata for one stored key. Never contains the private half.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyCard {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub label: String,
    /// `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`, … or the stored
    /// `key_type` when the material cannot be parsed.
    pub key_type: String,
    pub bits: usize,
    pub fingerprint: String,
    pub public_key: String,
    pub comment: String,
    /// Private key is passphrase-protected on disk.
    pub encrypted: bool,
    /// A passphrase is stored alongside the key (auto-unlock).
    pub has_passphrase: bool,
    /// The material is not parseable (foreign/broken import); only public
    /// data is shown and the key cannot be exported or re-encrypted.
    pub unreadable: bool,
    /// Only the public half is stored; the system SSH agent signs with
    /// exactly this key (no other agent keys are tried).
    pub agent_backed: bool,
    /// Identities (visible and inline) that reference this key.
    pub used_by: usize,
    /// Certificate attached to this key, if any.
    pub certificate: Option<CertificateCard>,
    /// A certificate is attached but cannot be parsed (foreign import).
    pub certificate_unreadable: bool,
    /// FIDO2 security key: the token signs, the vault holds only the
    /// public half and the credential handle.
    #[cfg(feature = "fido2")]
    pub security_key: Option<SecurityKeyInfo>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub dirty: bool,
}

#[cfg(feature = "fido2")]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fido2GenerateForm {
    pub vault_id: Uuid,
    pub label: String,
    #[serde(flatten)]
    pub options: GenerateOptions,
    /// Keep the passphrase in the vault so connections do not prompt.
    #[serde(default)]
    pub remember_passphrase: bool,
}

#[cfg(feature = "fido2")]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fido2LoadForm {
    pub vault_id: Uuid,
    #[serde(default)]
    pub device: Option<String>,
    pub pin: Zeroizing<String>,
    #[serde(default)]
    pub passphrase: Option<Zeroizing<String>>,
    #[serde(default)]
    pub remember_passphrase: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateForm {
    pub vault_id: Uuid,
    pub label: String,
    pub algorithm: KeyAlgorithm,
    #[serde(default)]
    pub comment: String,
    /// Encrypt the private key with this passphrase.
    #[serde(default)]
    pub passphrase: Option<String>,
    /// Keep the passphrase in the vault so connections do not prompt.
    #[serde(default)]
    pub remember_passphrase: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportForm {
    pub vault_id: Uuid,
    pub label: String,
    /// Private key text in any supported format (OpenSSH, PKCS#8, PEM,
    /// PuTTY .ppk v2/v3).
    pub private_key: String,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub remember_passphrase: bool,
    /// OpenSSH certificate issued for this key; validated and attached.
    #[serde(default)]
    pub certificate: Option<String>,
}

/// Public-only key whose private half lives in the SSH agent (KeePassXC,
/// ssh-add, a hardware token…): OpenSSH's `IdentityFile key.pub`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentImportForm {
    pub vault_id: Uuid,
    /// Empty → the key's comment, then its fingerprint.
    #[serde(default)]
    pub label: String,
    /// `<type> <base64> [comment]` line (`.pub` file contents).
    pub public_key: String,
    /// OpenSSH certificate issued for this key; validated and attached.
    #[serde(default)]
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityCard {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub label: String,
    pub username: String,
    pub has_password: bool,
    /// A TOTP secret is stored: one-time codes are typed automatically.
    pub has_totp: bool,
    pub ssh_key_id: Option<Uuid>,
    pub ssh_key_label: Option<String>,
    /// Certificate pinned on the identity itself (`None` = the key's own).
    pub ssh_certificate_id: Option<Uuid>,
    /// The selected key carries a certificate (or one is referenced
    /// explicitly), so connections authenticate with it.
    pub has_certificate: bool,
    /// Logs in with the account's SSH ID passkeys.
    pub ssh_id: bool,
    pub ssh_id_key_type: Option<SshIdKeyType>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityForm {
    pub id: Option<Uuid>,
    pub vault_id: Uuid,
    pub label: String,
    pub username: String,
    /// `None` keeps the stored password, `Some("")` clears it.
    #[serde(default)]
    pub password: Option<String>,
    /// TOTP secret (`otpauth://` URI or base32) for keyboard-interactive
    /// logins; `None` keeps the stored one, `Some("")` clears it.
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub ssh_key_id: Option<Uuid>,
    /// Explicit certificate; `None` falls back to the key's own certificate.
    #[serde(default)]
    pub ssh_certificate_id: Option<Uuid>,
    /// Log in with the account's SSH ID passkeys (username may be empty:
    /// the handle is used).
    #[serde(default)]
    pub ssh_id: bool,
    #[serde(default)]
    pub ssh_id_key_type: Option<SshIdKeyType>,
}

fn label_of(s: &str, what: &str) -> Result<String> {
    let label = s.trim();
    if label.is_empty() {
        return Err(ClientError::invalid(format!("{what} label is required")));
    }
    if label.chars().count() > 200 {
        return Err(ClientError::invalid(format!("{what} label is too long")));
    }
    Ok(label.to_string())
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|p| !p.is_empty())
}

fn key_usage(
    store: &Store,
    vault_id: Option<Uuid>,
) -> Result<std::collections::HashMap<Uuid, usize>> {
    let mut usage = std::collections::HashMap::new();
    for ident in store.list::<Identity>(vault_id)? {
        if let Some(k) = ident.data.ssh_key_id {
            *usage.entry(k).or_insert(0) += 1;
        }
    }
    Ok(usage)
}

/// Certificates of one vault indexed by the key they are attached to.
fn certificates_by_key(
    store: &Store,
    vault_id: Option<Uuid>,
) -> Result<HashMap<Uuid, Entity<SshCertificate>>> {
    Ok(store
        .list::<SshCertificate>(vault_id)?
        .into_iter()
        .filter_map(|c| c.data.ssh_key_id.map(|k| (k, c)))
        .collect())
}

fn certificate_of(store: &Store, key: &Entity<SshKey>) -> Result<Option<Entity<SshCertificate>>> {
    Ok(store
        .list::<SshCertificate>(Some(key.vault_id))?
        .into_iter()
        .find(|c| c.data.ssh_key_id == Some(key.id)))
}

fn card(
    entity: &Entity<SshKey>,
    used_by: usize,
    certificate: Option<&Entity<SshCertificate>>,
) -> KeyCard {
    let k = &entity.data;
    let cert_info = certificate.map(|c| {
        keys::inspect_certificate(&c.data.certificate)
            .map(|i| CertificateCard::from_info(Some(c.id), i))
    });
    let certificate_unreadable = matches!(cert_info, Some(Err(_)));
    let info = keys::inspect(&k.private_key).ok();
    let public_line = info
        .as_ref()
        .map(|i| i.public_key.clone())
        .or_else(|| k.public_key.clone())
        .unwrap_or_default();
    let (key_type, bits, fingerprint, comment, encrypted) = match &info {
        Some(i) => (
            i.key_type.clone(),
            i.bits,
            i.fingerprint.clone(),
            i.comment.clone(),
            i.encrypted,
        ),
        None => {
            let pk = k
                .public_key
                .as_deref()
                .and_then(|l| keys::parse_public(l).ok());
            (
                pk.as_ref()
                    .map(|p| p.key_type.clone())
                    .unwrap_or_else(|| k.key_type.clone()),
                pk.as_ref().map(|p| p.bits).unwrap_or(0),
                pk.as_ref()
                    .map(|p| p.fingerprint.clone())
                    .unwrap_or_default(),
                pk.as_ref().map(|p| p.comment.clone()).unwrap_or_default(),
                false,
            )
        }
    };
    KeyCard {
        id: entity.id,
        vault_id: entity.vault_id,
        label: k.label.clone(),
        key_type,
        bits,
        fingerprint,
        public_key: public_line,
        comment,
        encrypted,
        has_passphrase: k.passphrase.as_deref().is_some_and(|p| !p.is_empty()),
        unreadable: info.is_none() && !k.is_agent_backed(),
        agent_backed: k.is_agent_backed(),
        used_by,
        certificate: cert_info.and_then(|c| c.ok()),
        certificate_unreadable,
        #[cfg(feature = "fido2")]
        security_key: fido2::describe(&k.private_key, k.passphrase.as_deref()),
        updated_at: entity.updated_at,
        dirty: entity.dirty,
    }
}

pub fn keys_list(store: &Store, vault_id: Option<Uuid>) -> Result<Vec<KeyCard>> {
    let usage = key_usage(store, vault_id)?;
    let certs = certificates_by_key(store, vault_id)?;
    let mut out: Vec<KeyCard> = store
        .list::<SshKey>(vault_id)?
        .iter()
        .filter(|e| !e.data.ssh_id)
        .map(|e| card(e, usage.get(&e.id).copied().unwrap_or(0), certs.get(&e.id)))
        .collect();
    out.sort_by_key(|a| a.label.to_lowercase());
    Ok(out)
}

fn key_card(store: &Store, id: Uuid) -> Result<KeyCard> {
    let e = store.require::<SshKey>(id)?;
    let usage = key_usage(store, Some(e.vault_id))?;
    let cert = certificate_of(store, &e)?;
    Ok(card(
        &e,
        usage.get(&id).copied().unwrap_or(0),
        cert.as_ref(),
    ))
}

fn short_type(info: &KeyInfo) -> String {
    match info.key_type.as_str() {
        "ssh-ed25519" => "ed25519".into(),
        "ssh-rsa" => "rsa".into(),
        "sk-ssh-ed25519@openssh.com" => "sk-ed25519".into(),
        "sk-ecdsa-sha2-nistp256@openssh.com" => "sk-ecdsa".into(),
        t if t.starts_with("ecdsa") => "ecdsa".into(),
        t => t.to_string(),
    }
}

/// Connected FIDO2 authenticators. Blocking USB I/O; callers run it off
/// the async runtime.
#[cfg(feature = "fido2")]
pub fn fido2_devices() -> Vec<Fido2Device> {
    fido2::list_devices()
}

/// Persist a security-key handle. `passphrase` is what the handle is
/// encrypted with (if anything); it is remembered in the vault only when
/// `remember` is set. The stored block is public key + credential handle —
/// the token never releases the signing key.
pub fn store_security_key(
    store: &Store,
    vault_id: Uuid,
    label: String,
    material: &keys::KeyMaterial,
    passphrase: Option<&str>,
    remember: bool,
) -> Result<KeyCard> {
    let credential =
        fido2::describe(&material.private_key, passphrase).and_then(|s| s.credential_id);
    let key = SshKey {
        external_id: None,
        label,
        private_key: material.private_key.to_string(),
        public_key: Some(material.public_key.clone()),
        passphrase: passphrase.filter(|_| remember).map(str::to_string),
        key_type: short_type(&material.info),
        fido2_credential_id: credential,
        ssh_id: false,
    };
    let id = store.insert(vault_id, &key)?;
    key_card(store, id)
}

/// Create a credential on the token (waits for the touch) and store the
/// resulting `sk-*` key. The token keeps the private key.
#[cfg(feature = "fido2")]
pub fn fido2_generate(store: &Store, form: &Fido2GenerateForm) -> Result<KeyCard> {
    let label = label_of(&form.label, "key")?;
    let mut opts = form.options.clone();
    opts.passphrase = opts.passphrase.filter(|p| !p.is_empty());
    if opts.comment.trim().is_empty() {
        opts.comment = label.clone();
    }
    let material = fido2::generate(&opts)?;
    let passphrase = opts.passphrase.as_deref().map(|p| p.as_str());
    store_security_key(
        store,
        form.vault_id,
        label,
        &material,
        passphrase,
        form.remember_passphrase,
    )
}

/// Load the resident SSH credentials from a token (`ssh-keygen -K`) into
/// the vault. Credentials already present (same public key) are skipped.
#[cfg(feature = "fido2")]
pub fn fido2_load_resident(store: &Store, form: &Fido2LoadForm) -> Result<Vec<KeyCard>> {
    let passphrase = form
        .passphrase
        .as_deref()
        .map(|p| p.as_str())
        .filter(|p| !p.is_empty());
    let found = fido2::load_resident(form.device.as_deref(), &form.pin, passphrase)?;
    let existing: std::collections::HashSet<String> = store
        .list::<SshKey>(Some(form.vault_id))?
        .into_iter()
        .filter_map(|k| keys::inspect(&k.data.private_key).ok())
        .map(|i| i.fingerprint)
        .collect();
    let mut out = Vec::new();
    for (n, material) in found.iter().enumerate() {
        if existing.contains(&material.info.fingerprint) {
            continue;
        }
        let label = if material.info.comment.trim().is_empty() {
            format!("Resident key {}", n + 1)
        } else {
            material.info.comment.trim().to_string()
        };
        out.push(store_security_key(
            store,
            form.vault_id,
            label,
            material,
            passphrase,
            form.remember_passphrase,
        )?);
    }
    Ok(out)
}

pub fn generate(store: &Store, form: &GenerateForm) -> Result<KeyCard> {
    let label = label_of(&form.label, "key")?;
    let passphrase = non_empty(form.passphrase.clone());
    let material = keys::generate(form.algorithm, form.comment.trim(), passphrase.as_deref())?;
    let key = SshKey {
        external_id: None,
        label,
        private_key: material.private_key.to_string(),
        public_key: Some(material.public_key.clone()),
        passphrase: if form.remember_passphrase {
            passphrase
        } else {
            None
        },
        key_type: short_type(&material.info),
        fido2_credential_id: None,
        ssh_id: false,
    };
    let id = store.insert(form.vault_id, &key)?;
    key_card(store, id)
}

pub fn import(store: &Store, form: &ImportForm) -> Result<KeyCard> {
    let label = label_of(&form.label, "key")?;
    let passphrase = non_empty(form.passphrase.clone());
    let material = keys::import(&form.private_key, passphrase.as_deref())?;
    // Validate the certificate before anything is persisted.
    let certificate = match form.certificate.as_deref().map(str::trim) {
        Some(c) if !c.is_empty() => {
            keys::inspect_certificate(c)?;
            if !keys::certificate_matches(c, &material.public_key)? {
                return Err(certificate_mismatch(c));
            }
            Some(c.to_string())
        }
        _ => None,
    };
    let key = SshKey {
        external_id: None,
        label: label.clone(),
        private_key: material.private_key.to_string(),
        public_key: Some(material.public_key.clone()),
        passphrase: if form.remember_passphrase {
            passphrase
        } else {
            None
        },
        key_type: short_type(&material.info),
        fido2_credential_id: None,
        ssh_id: false,
    };
    let id = store.insert(form.vault_id, &key)?;
    if let Some(c) = certificate {
        store.insert(
            form.vault_id,
            &SshCertificate {
                label,
                certificate: c,
                ssh_key_id: Some(id),
            },
        )?;
    }
    key_card(store, id)
}

/// Public-key line an agent-backed record must carry.
pub fn agent_key(label: &str, public_key: &str) -> Result<SshKey> {
    let info = keys::parse_public(public_key.trim())?;
    let label = match label.trim() {
        "" if !info.comment.trim().is_empty() => info.comment.trim().to_string(),
        "" => info.fingerprint.clone(),
        l => label_of(l, "key")?,
    };
    Ok(SshKey {
        external_id: None,
        label,
        private_key: String::new(),
        public_key: Some(info.public_key),
        passphrase: None,
        key_type: AGENT_KEY_TYPE.to_string(),
        fido2_credential_id: None,
        ssh_id: false,
    })
}

/// Store a public-only, agent-signed key. Keys with the same public half
/// already in the vault (private or agent-backed) are reused, not doubled.
pub fn import_agent(store: &Store, form: &AgentImportForm) -> Result<KeyCard> {
    let key = agent_key(&form.label, &form.public_key)?;
    let public_line = key.public_key.clone().unwrap_or_default();
    let certificate = match form.certificate.as_deref().map(str::trim) {
        Some(c) if !c.is_empty() => {
            keys::inspect_certificate(c)?;
            if !keys::certificate_matches(c, &public_line)? {
                return Err(certificate_mismatch(c));
            }
            Some(c.to_string())
        }
        _ => None,
    };
    let wanted = key_blob(&public_line);
    if let Some(existing) = store
        .list::<SshKey>(Some(form.vault_id))?
        .into_iter()
        .filter(|k| !k.data.ssh_id)
        .find(|k| public_line_of(&k.data).is_some_and(|l| key_blob(&l) == wanted))
    {
        if let Some(c) = certificate {
            set_certificate(store, existing.id, Some(c))?;
        }
        return key_card(store, existing.id);
    }
    let label = key.label.clone();
    let id = store.insert(form.vault_id, &key)?;
    if let Some(c) = certificate {
        store.insert(
            form.vault_id,
            &SshCertificate {
                label,
                certificate: c,
                ssh_key_id: Some(id),
            },
        )?;
    }
    key_card(store, id)
}

/// `<type> <base64>` of a public-key line: what identifies a key
/// regardless of comment.
fn key_blob(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

fn public_line_of(k: &SshKey) -> Option<String> {
    keys::inspect(&k.private_key)
        .ok()
        .map(|i| i.public_key)
        .or_else(|| k.public_key.clone())
        .filter(|l| !l.is_empty())
}

fn needs_private(k: &SshKey) -> Result<()> {
    if k.is_agent_backed() {
        return Err(ClientError::invalid(
            "this key is signed by the SSH agent; its private half is not in the vault",
        ));
    }
    Ok(())
}

fn certificate_mismatch(cert: &str) -> ClientError {
    let fp = keys::inspect_certificate(cert)
        .map(|i| i.fingerprint)
        .unwrap_or_default();
    ClientError::invalid(format!("certificate was issued for a different key ({fp})"))
}

/// Public half of private key text the user pasted or picked, for the
/// editor preview. Nothing is stored; the private text is not echoed back.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPreview {
    pub key_type: String,
    pub bits: usize,
    pub fingerprint: String,
    pub public_key: String,
    pub comment: String,
    /// The private key needs a passphrase to be imported.
    pub encrypted: bool,
    /// PuTTY `.ppk` (v2/v3); converted to OpenSSH on import.
    pub putty: bool,
}

pub fn inspect_private(text: &str) -> Result<KeyPreview> {
    let text = Zeroizing::new(text.trim().to_string());
    if text.is_empty() {
        return Err(ClientError::invalid("empty private key"));
    }
    let info = keys::inspect(&text)?;
    Ok(KeyPreview {
        key_type: info.key_type,
        bits: info.bits,
        fingerprint: info.fingerprint,
        public_key: info.public_key,
        comment: info.comment,
        encrypted: info.encrypted,
        putty: text.starts_with("PuTTY-User-Key-File-"),
    })
}

/// Parse and verify a certificate without storing it (editor preview).
pub fn inspect_certificate(text: &str) -> Result<CertificateCard> {
    Ok(CertificateCard::from_info(
        None,
        keys::inspect_certificate(text)?,
    ))
}

/// Certificate text attached to a key (public data).
pub fn certificate_text(store: &Store, key_id: Uuid) -> Result<Option<String>> {
    let e = store.require::<SshKey>(key_id)?;
    Ok(certificate_of(store, &e)?.map(|c| c.data.certificate))
}

/// Attach (`Some`) or detach (`None`/empty) the certificate of a key. The
/// certificate must verify and be issued for this key's public half.
pub fn set_certificate(
    store: &Store,
    key_id: Uuid,
    certificate: Option<String>,
) -> Result<KeyCard> {
    let e = store.require::<SshKey>(key_id)?;
    let existing = certificate_of(store, &e)?;
    match certificate
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        Some(c) => {
            keys::inspect_certificate(c)?;
            if !keys::certificate_matches(c, &public_key(store, key_id)?)? {
                return Err(certificate_mismatch(c));
            }
            match existing {
                Some(mut cert) => {
                    cert.data.certificate = c.to_string();
                    cert.data.label = e.data.label.clone();
                    store.update(cert.id, &cert.data)?;
                }
                None => {
                    store.insert(
                        e.vault_id,
                        &SshCertificate {
                            label: e.data.label.clone(),
                            certificate: c.to_string(),
                            ssh_key_id: Some(key_id),
                        },
                    )?;
                }
            }
        }
        None => {
            if let Some(cert) = existing {
                delete_certificate(store, &cert)?;
            }
        }
    }
    key_card(store, key_id)
}

/// Remove a certificate and every explicit identity reference to it.
fn delete_certificate(store: &Store, cert: &Entity<SshCertificate>) -> Result<()> {
    for mut ident in store.list::<Identity>(Some(cert.vault_id))? {
        if ident.data.ssh_certificate_id == Some(cert.id) {
            ident.data.ssh_certificate_id = None;
            store.update(ident.id, &ident.data)?;
        }
    }
    store.delete(cert.id)?;
    Ok(())
}

/// Copy (or move) a key together with its certificate into another vault.
/// Moving detaches the original from its identities like `delete`.
pub fn copy_to_vault(store: &Store, id: Uuid, vault_id: Uuid, mv: bool) -> Result<KeyCard> {
    let e = store.require::<SshKey>(id)?;
    if e.vault_id == vault_id {
        return Err(ClientError::invalid("key is already in this vault"));
    }
    // The very same key already there (e.g. brought along by a shared host):
    // point at it instead of storing a second copy.
    let same = |k: &Entity<SshKey>| {
        if e.data.is_agent_backed() {
            k.data.is_agent_backed()
                && match (public_line_of(&k.data), public_line_of(&e.data)) {
                    (Some(a), Some(b)) => key_blob(&a) == key_blob(&b),
                    _ => false,
                }
        } else {
            k.data.private_key == e.data.private_key
        }
    };
    if let Some(existing) = store.list::<SshKey>(Some(vault_id))?.into_iter().find(same) {
        if mv {
            delete(store, id)?;
        }
        return key_card(store, existing.id);
    }
    let cert = certificate_of(store, &e)?;
    let new_id = store.insert(vault_id, &e.data)?;
    if let Some(c) = cert {
        store.insert(
            vault_id,
            &SshCertificate {
                ssh_key_id: Some(new_id),
                ..c.data
            },
        )?;
    }
    if mv {
        delete(store, id)?;
    }
    key_card(store, new_id)
}

pub fn rename(store: &Store, id: Uuid, label: &str) -> Result<KeyCard> {
    let mut e = store.require::<SshKey>(id)?;
    e.data.label = label_of(label, "key")?;
    store.update(id, &e.data)?;
    if let Some(mut c) = certificate_of(store, &e)? {
        c.data.label = e.data.label.clone();
        store.update(c.id, &c.data)?;
    }
    key_card(store, id)
}

/// Re-encrypt the private key. `current` is needed only when the key is
/// encrypted and no passphrase is stored; `next = None` removes encryption.
pub fn change_passphrase(
    store: &Store,
    id: Uuid,
    current: Option<String>,
    next: Option<String>,
    remember: bool,
) -> Result<KeyCard> {
    let mut e = store.require::<SshKey>(id)?;
    needs_private(&e.data)?;
    let current = non_empty(current).or_else(|| non_empty(e.data.passphrase.clone()));
    let next = non_empty(next);
    let material =
        keys::change_passphrase(&e.data.private_key, current.as_deref(), next.as_deref())?;
    e.data.private_key = material.private_key.to_string();
    e.data.public_key = Some(material.public_key.clone());
    e.data.passphrase = if remember { next } else { None };
    store.update(id, &e.data)?;
    key_card(store, id)
}

/// Forget (or set) the stored passphrase without touching the key material.
pub fn remember_passphrase(store: &Store, id: Uuid, passphrase: Option<String>) -> Result<KeyCard> {
    let mut e = store.require::<SshKey>(id)?;
    needs_private(&e.data)?;
    let passphrase = non_empty(passphrase);
    if let Some(p) = &passphrase {
        // Verify before storing so a typo does not get persisted.
        keys::export_openssh(&e.data.private_key, Some(p), None)?;
    }
    e.data.passphrase = passphrase;
    store.update(id, &e.data)?;
    key_card(store, id)
}

/// Public key line (`type base64 comment`).
pub fn public_key(store: &Store, id: Uuid) -> Result<String> {
    let e = store.require::<SshKey>(id)?;
    if let Ok(info) = keys::inspect(&e.data.private_key) {
        return Ok(info.public_key);
    }
    e.data
        .public_key
        .clone()
        .ok_or_else(|| ClientError::invalid("key has no public half"))
}

/// Private key in OpenSSH format. The only path that hands private material
/// to the webview; the caller decides whether to re-encrypt it on the way out.
pub fn export(
    store: &Store,
    id: Uuid,
    passphrase: Option<String>,
    export_passphrase: Option<String>,
) -> Result<Zeroizing<String>> {
    let e = store.require::<SshKey>(id)?;
    needs_private(&e.data)?;
    let passphrase = non_empty(passphrase).or_else(|| non_empty(e.data.passphrase.clone()));
    Ok(keys::export_openssh(
        &e.data.private_key,
        passphrase.as_deref(),
        non_empty(export_passphrase).as_deref(),
    )?)
}

/// Remote side of "Export to host" (`ssh-copy-id` semantics). The public key
/// line arrives on stdin — never inside the command string — so no part of
/// it is ever parsed by the remote shell. Idempotent: an existing entry with
/// the same type+blob is left alone. POSIX sh + coreutils/busybox only; one
/// line without single quotes so it survives `sh -c '…'` under any login
/// shell (fish, csh, …).
macro_rules! authorized_keys_script {
    () => {
        concat!(
            "umask 077; d=\"${HOME:?}/.ssh\"; f=\"$d/authorized_keys\"; ",
            "mkdir -p \"$d\" && chmod 700 \"$d\" && touch \"$f\" && chmod 600 \"$f\" || exit 2; ",
            "k=$(head -n 1); set -f; set -- $k; [ -n \"$2\" ] || exit 3; blob=\"$1 $2\"; ",
            "if grep -qF -- \"$blob\" \"$f\"; then echo EXISTS; else ",
            "{ [ -s \"$f\" ] && [ -n \"$(tail -c 1 \"$f\")\" ] && echo >> \"$f\"; ",
            "printf \"%s\\n\" \"$k\" >> \"$f\" && echo ADDED; }; fi",
        )
    };
}

#[cfg(test)]
const AUTHORIZED_KEYS_SCRIPT: &str = authorized_keys_script!();

/// Command sent over `exec`: forces POSIX sh regardless of the login shell.
pub const EXPORT_COMMAND: &str = concat!("exec sh -c '", authorized_keys_script!(), "'");

/// Remote side of key rotation: drop one public key (type+blob on stdin)
/// from `~/.ssh/authorized_keys`, leaving every other line untouched.
/// Prints `REMOVED` or `MISSING` (file or line absent). Same constraints as
/// [`EXPORT_COMMAND`]: POSIX sh, no single quotes, key never in argv.
pub const REMOVE_COMMAND: &str = concat!(
    "exec sh -c '",
    "f=\"${HOME:?}/.ssh/authorized_keys\"; [ -f \"$f\" ] || { echo MISSING; exit 0; }; ",
    "k=$(head -n 1); set -f; set -- $k; [ -n \"$2\" ] || exit 3; blob=\"$1 $2\"; ",
    "if grep -qF -- \"$blob\" \"$f\"; then t=\"$f.rotate.$$\"; umask 077; ",
    "grep -vF -- \"$blob\" \"$f\" > \"$t\"; chmod 600 \"$t\" && mv \"$t\" \"$f\" && echo REMOVED; ",
    "else echo MISSING; fi'"
);

/// What `EXPORT_COMMAND` reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportOutcome {
    Added,
    AlreadyPresent,
}

/// Interpret the script's exit status and output.
pub fn export_outcome(
    exit_code: Option<u32>,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<ExportOutcome> {
    let out = String::from_utf8_lossy(stdout);
    match (exit_code, out.trim()) {
        (Some(0), "ADDED") => Ok(ExportOutcome::Added),
        (Some(0), "EXISTS") => Ok(ExportOutcome::AlreadyPresent),
        (Some(2), _) => Err(ClientError::invalid(
            "could not create ~/.ssh/authorized_keys on the host (permissions?)",
        )),
        (Some(3), _) => Err(ClientError::invalid(
            "the host did not receive the key (stdin was empty)",
        )),
        (code, _) => {
            let err = String::from_utf8_lossy(stderr);
            let detail = err.trim();
            Err(ClientError::invalid(match (code, detail.is_empty()) {
                (Some(c), false) => format!("remote command failed (exit {c}): {detail}"),
                (Some(c), true) => format!("remote command failed (exit {c})"),
                (None, false) => format!("remote command failed: {detail}"),
                (None, true) => "remote command failed without an exit status".to_string(),
            }))
        }
    }
}

/// Delete a key (and its certificate) and detach it from every identity
/// that referenced it.
pub fn delete(store: &Store, id: Uuid) -> Result<()> {
    let e = store.require::<SshKey>(id)?;
    if let Some(cert) = certificate_of(store, &e)? {
        delete_certificate(store, &cert)?;
    }
    for mut ident in store.list::<Identity>(Some(e.vault_id))? {
        if ident.data.ssh_key_id == Some(id) {
            ident.data.ssh_key_id = None;
            store.update(ident.id, &ident.data)?;
        }
    }
    store.delete(id)?;
    Ok(())
}

// ───────────────────────────── identities ─────────────────────────────

pub fn identities(store: &Store, vault_id: Option<Uuid>) -> Result<Vec<IdentityCard>> {
    let labels: HashMap<Uuid, String> = store
        .list::<SshKey>(vault_id)?
        .into_iter()
        .map(|k| (k.id, k.data.label))
        .collect();
    let certs = certificates_by_key(store, vault_id)?;
    let mut out: Vec<IdentityCard> = store
        .list::<Identity>(vault_id)?
        .into_iter()
        .filter(|i| i.data.is_visible)
        .map(|i| IdentityCard {
            id: i.id,
            vault_id: i.vault_id,
            label: i.data.label,
            username: i.data.username,
            has_password: i.data.password.as_deref().is_some_and(|p| !p.is_empty()),
            has_totp: i.data.totp_secret.as_deref().is_some_and(|t| !t.is_empty()),
            ssh_key_id: i.data.ssh_key_id,
            ssh_key_label: i.data.ssh_key_id.and_then(|k| labels.get(&k).cloned()),
            ssh_certificate_id: i.data.ssh_certificate_id,
            has_certificate: i.data.ssh_certificate_id.is_some()
                || i.data.ssh_key_id.is_some_and(|k| certs.contains_key(&k)),
            ssh_id: i.data.ssh_id,
            ssh_id_key_type: i.data.ssh_id_key_type,
            updated_at: i.updated_at,
        })
        .collect();
    out.sort_by_key(|a| a.label.to_lowercase());
    Ok(out)
}

pub fn save_identity(store: &Store, form: &IdentityForm) -> Result<IdentityCard> {
    let label = label_of(&form.label, "identity")?;
    let username = form.username.trim().to_string();
    if username.is_empty() && !form.ssh_id {
        return Err(ClientError::invalid("username is required"));
    }
    // A certificate is only usable together with the key it certifies, so
    // picking one without a key selects that key implicitly.
    let mut ssh_key_id = form.ssh_key_id;
    if let Some(c) = form.ssh_certificate_id {
        let cert = store.require::<SshCertificate>(c)?;
        if cert.vault_id != form.vault_id {
            return Err(ClientError::invalid("certificate belongs to another vault"));
        }
        match (cert.data.ssh_key_id, ssh_key_id) {
            (Some(ck), Some(k)) if ck != k => {
                return Err(ClientError::invalid(
                    "certificate was issued for a different key",
                ));
            }
            (Some(ck), None) => ssh_key_id = Some(ck),
            _ => {}
        }
    }
    if let Some(k) = ssh_key_id {
        let key = store.require::<SshKey>(k)?;
        if key.vault_id != form.vault_id {
            return Err(ClientError::invalid("key belongs to another vault"));
        }
    }
    let existing = match form.id {
        Some(id) => Some(store.require::<Identity>(id)?),
        None => None,
    };
    let password = match &form.password {
        Some(p) if p.is_empty() => None,
        Some(p) => Some(p.clone()),
        None => existing.as_ref().and_then(|e| e.data.password.clone()),
    };
    let totp_secret = match &form.totp_secret {
        Some(t) if t.trim().is_empty() => None,
        Some(t) => Some(crate::hosts::normalize_totp_secret(t)?),
        None => existing.as_ref().and_then(|e| e.data.totp_secret.clone()),
    };
    let data = Identity {
        external_id: None,
        label,
        username,
        password,
        ssh_key_id,
        ssh_certificate_id: form.ssh_certificate_id,
        is_visible: true,
        ssh_id: form.ssh_id,
        ssh_id_key_type: form.ssh_id_key_type.filter(|_| form.ssh_id),
        bearer_token: existing.as_ref().and_then(|e| e.data.bearer_token.clone()),
        client_certificate: existing
            .as_ref()
            .and_then(|e| e.data.client_certificate.clone()),
        totp_secret,
    };
    let id = match existing {
        Some(e) => {
            store.update(e.id, &data)?;
            e.id
        }
        None => store.insert(form.vault_id, &data)?,
    };
    identities(store, Some(form.vault_id))?
        .into_iter()
        .find(|c| c.id == id)
        .ok_or_else(|| ClientError::not_found(format!("identity {id}")))
}

/// Copy (or move) a visible identity into `vault_id`. The key it points at is
/// brought along (deduplicated by material, certificate included) so the
/// identity works for everyone with access to the target vault; secrets never
/// leave the store. Moving keeps the source key when other entities still
/// reference it, and inlines the login into hosts that used the identity.
pub fn copy_identity_to_vault(
    store: &Store,
    id: Uuid,
    vault_id: Uuid,
    mv: bool,
) -> Result<IdentityCard> {
    let e = store.require::<Identity>(id)?;
    if !e.data.is_visible {
        return Err(ClientError::invalid(
            "inline identities are managed by their host",
        ));
    }
    if e.vault_id == vault_id {
        return Err(ClientError::invalid("identity is already in this vault"));
    }
    let src_key = match e.data.ssh_key_id {
        Some(k) => Some(store.require::<SshKey>(k)?),
        None => None,
    };
    let new_key = match &src_key {
        Some(k) => Some(copy_to_vault(store, k.id, vault_id, false)?.id),
        None => None,
    };
    let new_cert = match (e.data.ssh_certificate_id, new_key) {
        (Some(_), Some(nk)) => certificate_of(store, &store.require::<SshKey>(nk)?)?.map(|c| c.id),
        _ => None,
    };
    let same = |other: &Entity<Identity>| {
        other.data.is_visible
            && other.data.label == e.data.label
            && other.data.username == e.data.username
            && other.data.password == e.data.password
            && other.data.ssh_key_id == new_key
    };
    let new_id = match store
        .list::<Identity>(Some(vault_id))?
        .into_iter()
        .find(same)
    {
        Some(existing) => existing.id,
        None => store.insert(
            vault_id,
            &Identity {
                ssh_key_id: new_key,
                ssh_certificate_id: new_cert,
                ..e.data.clone()
            },
        )?,
    };
    if mv {
        detach_identity(store, &e)?;
        store.delete(id)?;
        if let Some(k) = src_key
            && !key_referenced(store, &k)?
        {
            delete(store, k.id)?;
        }
    }
    identities(store, Some(vault_id))?
        .into_iter()
        .find(|c| c.id == new_id)
        .ok_or_else(|| ClientError::not_found(format!("identity {new_id}")))
}

/// Turn every reference to `ident` from SSH / Telnet configs in its vault into
/// an inline (hidden) copy, so the hosts keep working after the identity goes.
fn detach_identity(store: &Store, ident: &Entity<Identity>) -> Result<()> {
    let inline = || Identity {
        is_visible: false,
        ..ident.data.clone()
    };
    for mut c in store.list::<SshConfig>(Some(ident.vault_id))? {
        if c.data.identity_id == Some(ident.id) {
            c.data.identity_id = Some(store.insert(ident.vault_id, &inline())?);
            store.update(c.id, &c.data)?;
        }
    }
    for mut c in store.list::<TelnetConfig>(Some(ident.vault_id))? {
        if c.data.identity_id == Some(ident.id) {
            c.data.identity_id = Some(store.insert(ident.vault_id, &inline())?);
            store.update(c.id, &c.data)?;
        }
    }
    Ok(())
}

/// Whether any identity (visible or inline) in the key's vault still points at it.
fn key_referenced(store: &Store, key: &Entity<SshKey>) -> Result<bool> {
    Ok(store
        .list::<Identity>(Some(key.vault_id))?
        .iter()
        .any(|i| i.data.ssh_key_id == Some(key.id)))
}

pub fn delete_identity(store: &Store, id: Uuid) -> Result<()> {
    let e = store.require::<Identity>(id)?;
    if !e.data.is_visible {
        return Err(ClientError::invalid(
            "inline identities are managed by their host",
        ));
    }
    store.delete(id)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoso_core::store::LocalVaultKind;
    use termoso_core::termoso_crypto::keys::SymmetricKey;
    use termoso_core::termoso_proto::vault::VaultRole;

    fn store() -> Store {
        Store::open_in_memory(SymmetricKey::generate()).expect("store")
    }

    fn make_key(store: &Store, vault: Uuid, passphrase: Option<&str>, remember: bool) -> KeyCard {
        generate(
            store,
            &GenerateForm {
                vault_id: vault,
                label: "laptop".into(),
                algorithm: KeyAlgorithm::Ed25519,
                comment: "me@laptop".into(),
                passphrase: passphrase.map(str::to_string),
                remember_passphrase: remember,
            },
        )
        .expect("generate")
    }

    #[test]
    fn export_outcome_maps_script_results() {
        assert_eq!(
            export_outcome(Some(0), b"ADDED\n", b"").unwrap(),
            ExportOutcome::Added
        );
        assert_eq!(
            export_outcome(Some(0), b"EXISTS\n", b"").unwrap(),
            ExportOutcome::AlreadyPresent
        );
        let e = export_outcome(Some(2), b"", b"").unwrap_err().to_string();
        assert!(e.contains("authorized_keys"), "{e}");
        let e = export_outcome(Some(127), b"", b"sh: awk: not found\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("exit 127") && e.contains("awk"), "{e}");
        assert!(export_outcome(None, b"", b"").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn authorized_keys_script_is_idempotent_and_keeps_key_out_of_argv() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let store = store();
        let vault = store.local_vault().unwrap().id;
        let card = make_key(&store, vault, None, false);
        let line = public_key(&store, card.id).unwrap();
        let home = tempfile::tempdir().unwrap();

        // Pre-existing file without a trailing newline must not get glued to.
        std::fs::create_dir(home.path().join(".ssh")).unwrap();
        let ak = home.path().join(".ssh/authorized_keys");
        std::fs::write(&ak, "ssh-ed25519 AAAAexisting old@box").unwrap();

        // Goes through the login-shell wrapper exactly like the remote side.
        let run = |input: &str| {
            let mut child = Command::new("sh")
                .arg("-c")
                .arg(EXPORT_COMMAND)
                .env_clear()
                .env("HOME", home.path())
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("{input}\n").as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            export_outcome(
                out.status.code().map(|c| c as u32),
                &out.stdout,
                &out.stderr,
            )
        };

        assert_eq!(run(&line).unwrap(), ExportOutcome::Added);
        assert_eq!(run(&line).unwrap(), ExportOutcome::AlreadyPresent);
        // Same key, different comment: still a duplicate.
        let mut parts: Vec<&str> = line.split_whitespace().collect();
        parts.truncate(2);
        let no_comment = parts.join(" ");
        assert_eq!(run(&no_comment).unwrap(), ExportOutcome::AlreadyPresent);
        // A different key is appended as a second line.
        let other = make_key(&store, vault, None, false);
        assert_eq!(
            run(&public_key(&store, other.id).unwrap()).unwrap(),
            ExportOutcome::Added
        );

        let text = std::fs::read_to_string(&ak).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert_eq!(text.lines().nth(1), Some(line.as_str()));
        assert!(text.ends_with('\n'));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&ak).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(home.path().join(".ssh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(!AUTHORIZED_KEYS_SCRIPT.contains("ssh-ed25519"));
        assert!(!AUTHORIZED_KEYS_SCRIPT.contains('\'') && !AUTHORIZED_KEYS_SCRIPT.contains('\n'));
        // Malformed input (no blob) is refused rather than matched as a prefix.
        assert!(run("ssh-ed25519").is_err());

        // Hostile input never reaches the shell as code.
        let evil = "ssh-ed25519 AAAA$(touch /tmp/pwned_termoso)`id` x";
        assert_eq!(run(evil).unwrap(), ExportOutcome::Added);
        assert!(!std::path::Path::new("/tmp/pwned_termoso").exists());
        assert!(std::fs::read_to_string(&ak).unwrap().contains(evil));
    }

    #[test]
    fn list_never_contains_private_material() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let card = make_key(&store, vault, None, false);
        let json = serde_json::to_string(&keys_list(&store, Some(vault)).unwrap()).unwrap();
        assert!(!json.contains("PRIVATE KEY"));
        assert!(json.contains(&card.fingerprint));
        assert_eq!(card.key_type, "ssh-ed25519");
        assert_eq!(card.comment, "me@laptop");
        assert!(!card.encrypted);
        assert!(!card.has_passphrase);
        assert_eq!(card.used_by, 0);
    }

    #[test]
    fn passphrase_lifecycle() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let card = make_key(&store, vault, Some("pw"), true);
        assert!(card.encrypted && card.has_passphrase);

        // Export uses the stored passphrase; re-encrypting on export works.
        let plain = export(&store, card.id, None, None).unwrap();
        assert!(plain.contains("OPENSSH PRIVATE KEY"));
        let info = keys::inspect(&plain).unwrap();
        assert!(!info.encrypted);
        let enc = export(&store, card.id, None, Some("other".into())).unwrap();
        assert!(keys::inspect(&enc).unwrap().encrypted);

        // Forget the passphrase: export without one must fail.
        let card = remember_passphrase(&store, card.id, None).unwrap();
        assert!(!card.has_passphrase);
        assert!(export(&store, card.id, None, None).is_err());
        assert!(remember_passphrase(&store, card.id, Some("wrong".into())).is_err());
        assert!(export(&store, card.id, Some("pw".into()), None).is_ok());

        // Remove encryption entirely.
        let card = change_passphrase(&store, card.id, Some("pw".into()), None, false).unwrap();
        assert!(!card.encrypted);
        assert!(export(&store, card.id, None, None).is_ok());
    }

    #[test]
    fn import_roundtrip_and_public_line() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let material = keys::generate(KeyAlgorithm::EcdsaP256, "c", None).unwrap();
        let card = import(
            &store,
            &ImportForm {
                vault_id: vault,
                label: " imported ".into(),
                private_key: material.private_key.to_string(),
                passphrase: None,
                remember_passphrase: false,
                certificate: None,
            },
        )
        .unwrap();
        assert_eq!(card.label, "imported");
        assert_eq!(card.fingerprint, material.info.fingerprint);
        assert_eq!(public_key(&store, card.id).unwrap(), material.public_key);
        assert!(
            import(
                &store,
                &ImportForm {
                    vault_id: vault,
                    label: "bad".into(),
                    private_key: "not a key".into(),
                    passphrase: None,
                    remember_passphrase: false,
                    certificate: None,
                },
            )
            .is_err()
        );
    }

    const PPK_ENC: &str = include_str!("../../termoso-core/testdata/keys/ed25519_v3_encrypted.ppk");
    const OPENSSH_KEY: &str = include_str!("../../termoso-core/testdata/keys/ed25519_openssh");
    const CERT: &str = include_str!("../../termoso-core/testdata/keys/ed25519-cert.pub");
    const RSA_CERT: &str = include_str!("../../termoso-core/testdata/keys/rsa-cert.pub");

    fn import_form(vault: Uuid, private_key: &str, certificate: Option<&str>) -> ImportForm {
        ImportForm {
            vault_id: vault,
            label: "ppk".into(),
            private_key: private_key.into(),
            passphrase: Some("pw".into()),
            remember_passphrase: true,
            certificate: certificate.map(str::to_string),
        }
    }

    #[test]
    fn imports_encrypted_ppk_into_openssh_storage() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let mut form = import_form(vault, PPK_ENC, None);
        form.passphrase = None;
        let err = import(&store, &form).unwrap_err().to_string();
        assert!(err.contains("passphrase required"), "{err}");
        form.passphrase = Some("bad".into());
        let err = import(&store, &form).unwrap_err().to_string();
        assert!(err.contains("wrong passphrase"), "{err}");
        assert!(
            keys_list(&store, Some(vault)).unwrap().is_empty(),
            "nothing persisted"
        );

        let card = import(&store, &import_form(vault, PPK_ENC, None)).unwrap();
        assert_eq!(card.key_type, "ssh-ed25519");
        assert!(card.encrypted && card.has_passphrase);
        assert!(card.certificate.is_none());
        let stored = store.require::<SshKey>(card.id).unwrap();
        assert!(
            stored
                .data
                .private_key
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert_eq!(stored.data.key_type, "ed25519");
        assert!(
            export(&store, card.id, None, None)
                .unwrap()
                .contains("OPENSSH PRIVATE KEY")
        );
    }

    #[test]
    fn certificate_lifecycle() {
        let store = store();
        let vault = store.local_vault().unwrap().id;

        // Wrong key: nothing persisted, not even the key.
        let err = import(&store, &import_form(vault, OPENSSH_KEY, Some(RSA_CERT)))
            .unwrap_err()
            .to_string();
        assert!(err.contains("different key"), "{err}");
        assert!(keys_list(&store, Some(vault)).unwrap().is_empty());
        assert!(import(&store, &import_form(vault, OPENSSH_KEY, Some("garbage"))).is_err());

        let card = import(&store, &import_form(vault, OPENSSH_KEY, Some(CERT))).unwrap();
        let cert = card.certificate.clone().expect("certificate attached");
        assert_eq!(cert.key_id, "user-cert");
        assert_eq!(cert.principals, vec!["root", "ubuntu"]);
        assert_eq!(cert.fingerprint, card.fingerprint);
        assert!(cert.valid_now);
        assert_eq!(
            certificate_text(&store, card.id).unwrap().as_deref(),
            Some(CERT.trim())
        );
        let json = serde_json::to_string(&keys_list(&store, Some(vault)).unwrap()).unwrap();
        assert!(!json.contains("PRIVATE KEY") && json.contains("user-cert"));

        // The identity inherits the certificate through the key.
        let ident = save_identity(
            &store,
            &IdentityForm {
                id: None,
                vault_id: vault,
                label: "ops".into(),
                username: "root".into(),
                password: None,
                ssh_key_id: Some(card.id),
                ssh_certificate_id: None,
                ssh_id: false,
                ssh_id_key_type: None,
                totp_secret: None,
            },
        )
        .unwrap();
        assert!(ident.has_certificate && ident.ssh_certificate_id.is_none());

        // Pinning the certificate explicitly selects its key implicitly…
        let pinned = save_identity(
            &store,
            &IdentityForm {
                id: None,
                vault_id: vault,
                label: "pinned".into(),
                username: "root".into(),
                password: None,
                ssh_key_id: None,
                ssh_certificate_id: cert.id,
                ssh_id: false,
                ssh_id_key_type: None,
                totp_secret: None,
            },
        )
        .unwrap();
        assert_eq!(pinned.ssh_key_id, Some(card.id));
        assert_eq!(pinned.ssh_certificate_id, cert.id);
        // …and refuses a key the certificate was not issued for.
        let rsa = generate(
            &store,
            &GenerateForm {
                vault_id: vault,
                label: "other".into(),
                algorithm: KeyAlgorithm::Ed25519,
                comment: String::new(),
                passphrase: None,
                remember_passphrase: false,
            },
        )
        .unwrap();
        assert!(
            save_identity(
                &store,
                &IdentityForm {
                    id: Some(pinned.id),
                    vault_id: vault,
                    label: "pinned".into(),
                    username: "root".into(),
                    password: None,
                    ssh_key_id: Some(rsa.id),
                    ssh_certificate_id: cert.id,
                    ssh_id: false,
                    ssh_id_key_type: None,
                    totp_secret: None,
                },
            )
            .is_err()
        );
        delete(&store, rsa.id).unwrap();

        // Renaming the key renames the certificate entity too.
        rename(&store, card.id, "prod").unwrap();
        let c = store.require::<SshCertificate>(cert.id.unwrap()).unwrap();
        assert_eq!(c.data.label, "prod");

        // Replace with a certificate for another key: refused, old one kept.
        assert!(set_certificate(&store, card.id, Some(RSA_CERT.into())).is_err());
        assert!(
            keys_list(&store, Some(vault)).unwrap()[0]
                .certificate
                .is_some()
        );

        // Detach.
        let card = set_certificate(&store, card.id, Some("  ".into())).unwrap();
        assert!(card.certificate.is_none());
        assert!(
            store
                .list::<SshCertificate>(Some(vault))
                .unwrap()
                .is_empty()
        );
        assert!(!identities(&store, Some(vault)).unwrap()[0].has_certificate);

        // Re-attach, then copy/move to another vault and delete cascade.
        let card = set_certificate(&store, card.id, Some(CERT.into())).unwrap();
        assert!(card.certificate.is_some());
        let other = Uuid::new_v4();
        store
            .upsert_vault(
                other,
                LocalVaultKind::Personal,
                "other",
                None,
                VaultRole::Manager,
                Some(&SymmetricKey::generate()),
                1,
            )
            .unwrap();
        let copied = copy_to_vault(&store, card.id, other, false).unwrap();
        assert_eq!(copied.vault_id, other);
        assert_eq!(copied.fingerprint, card.fingerprint);
        assert!(copied.certificate.is_some());
        assert_eq!(keys_list(&store, None).unwrap().len(), 2);
        assert!(copy_to_vault(&store, card.id, vault, false).is_err());

        delete(&store, card.id).unwrap();
        assert_eq!(store.list::<SshCertificate>(Some(vault)).unwrap().len(), 0);
        assert_eq!(store.list::<SshCertificate>(Some(other)).unwrap().len(), 1);
        let ident = &identities(&store, Some(vault)).unwrap()[0];
        assert!(ident.ssh_key_id.is_none() && !ident.has_certificate);
    }

    #[test]
    fn preview_does_not_persist() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let p = inspect_certificate(CERT).unwrap();
        assert!(p.id.is_none());
        assert_eq!(p.kind, "user");
        assert!(inspect_certificate("ssh-ed25519 AAAA").is_err());
        assert!(
            store
                .list::<SshCertificate>(Some(vault))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn identities_reference_keys_and_detach_on_delete() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let key = make_key(&store, vault, None, false);
        let ident = save_identity(
            &store,
            &IdentityForm {
                id: None,
                vault_id: vault,
                label: "deploy".into(),
                username: "deploy".into(),
                password: Some("pw".into()),
                ssh_key_id: Some(key.id),
                ssh_certificate_id: None,
                ssh_id: false,
                ssh_id_key_type: None,
                totp_secret: None,
            },
        )
        .unwrap();
        assert!(ident.has_password);
        assert_eq!(ident.ssh_key_label.as_deref(), Some("laptop"));
        assert_eq!(keys_list(&store, Some(vault)).unwrap()[0].used_by, 1);

        // Saving with password None keeps it, Some("") clears it.
        let ident2 = save_identity(
            &store,
            &IdentityForm {
                id: Some(ident.id),
                vault_id: vault,
                label: "deploy".into(),
                username: "deploy".into(),
                password: None,
                ssh_key_id: Some(key.id),
                ssh_certificate_id: None,
                ssh_id: false,
                ssh_id_key_type: None,
                totp_secret: None,
            },
        )
        .unwrap();
        assert!(ident2.has_password);
        let ident3 = save_identity(
            &store,
            &IdentityForm {
                id: Some(ident.id),
                vault_id: vault,
                label: "deploy".into(),
                username: "deploy".into(),
                password: Some(String::new()),
                ssh_key_id: Some(key.id),
                ssh_certificate_id: None,
                ssh_id: false,
                ssh_id_key_type: None,
                totp_secret: None,
            },
        )
        .unwrap();
        assert!(!ident3.has_password);

        delete(&store, key.id).unwrap();
        let after = identities(&store, Some(vault)).unwrap();
        assert_eq!(after.len(), 1);
        assert!(after[0].ssh_key_id.is_none());
        assert!(
            save_identity(
                &store,
                &IdentityForm {
                    id: None,
                    vault_id: vault,
                    label: "x".into(),
                    username: "".into(),
                    password: None,
                    ssh_key_id: None,
                    ssh_certificate_id: None,
                    ssh_id: false,
                    ssh_id_key_type: None,
                    totp_secret: None,
                },
            )
            .is_err()
        );
    }

    fn synced_vault(store: &Store, kind: LocalVaultKind, role: VaultRole) -> Uuid {
        let id = Uuid::new_v4();
        store
            .upsert_vault(
                id,
                kind,
                "shared",
                (kind == LocalVaultKind::Team).then(Uuid::new_v4),
                role,
                Some(&SymmetricKey::generate()),
                1,
            )
            .unwrap();
        id
    }

    fn identity_with(store: &Store, vault: Uuid, key: Option<Uuid>) -> IdentityCard {
        save_identity(
            store,
            &IdentityForm {
                id: None,
                vault_id: vault,
                label: "deploy".into(),
                username: "deploy".into(),
                password: Some("pw".into()),
                ssh_key_id: key,
                ssh_certificate_id: None,
                ssh_id: false,
                ssh_id_key_type: None,
                totp_secret: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn identity_copy_brings_its_key_and_dedups_on_repeat() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let team = synced_vault(&store, LocalVaultKind::Team, VaultRole::Editor);
        let key = make_key(&store, vault, None, false);
        let ident = identity_with(&store, vault, Some(key.id));

        let copied = copy_identity_to_vault(&store, ident.id, team, false).unwrap();
        assert_eq!(copied.vault_id, team);
        assert!(copied.has_password);
        let team_keys = keys_list(&store, Some(team)).unwrap();
        assert_eq!(team_keys.len(), 1);
        assert_eq!(team_keys[0].fingerprint, key.fingerprint);
        assert_eq!(copied.ssh_key_id, Some(team_keys[0].id));
        // Source untouched.
        assert_eq!(identities(&store, Some(vault)).unwrap().len(), 1);
        assert_eq!(keys_list(&store, Some(vault)).unwrap().len(), 1);

        // Copying again reuses the identical identity and key instead of duplicating.
        let again = copy_identity_to_vault(&store, ident.id, team, false).unwrap();
        assert_eq!(again.id, copied.id);
        assert_eq!(identities(&store, Some(team)).unwrap().len(), 1);
        assert_eq!(keys_list(&store, Some(team)).unwrap().len(), 1);

        assert!(copy_identity_to_vault(&store, ident.id, vault, false).is_err());
        let none = identity_with(&store, vault, None);
        let c = copy_identity_to_vault(&store, none.id, team, false).unwrap();
        assert!(c.ssh_key_id.is_none());
    }

    #[test]
    fn identity_move_keeps_hosts_working_and_drops_orphan_key() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let team = synced_vault(&store, LocalVaultKind::Team, VaultRole::Manager);
        let key = make_key(&store, vault, None, false);
        let ident = identity_with(&store, vault, Some(key.id));
        let cfg = store
            .insert(
                vault,
                &SshConfig {
                    identity_id: Some(ident.id),
                    ..Default::default()
                },
            )
            .unwrap();

        let moved = copy_identity_to_vault(&store, ident.id, team, true).unwrap();
        assert_eq!(moved.vault_id, team);
        assert!(store.get::<Identity>(ident.id).unwrap().is_none());
        // The host got a hidden inline identity with the same credentials...
        let inline_id = store
            .get::<SshConfig>(cfg)
            .unwrap()
            .unwrap()
            .data
            .identity_id
            .expect("host keeps an identity");
        let inline = store.require::<Identity>(inline_id).unwrap();
        assert!(!inline.data.is_visible);
        assert_eq!(inline.data.username, "deploy");
        assert_eq!(inline.data.ssh_key_id, Some(key.id));
        // ...so the source key is still referenced and stays.
        assert_eq!(keys_list(&store, Some(vault)).unwrap().len(), 1);
        assert!(identities(&store, Some(vault)).unwrap().is_empty());

        // An identity nobody else uses takes its key along and leaves nothing behind.
        let key2 = make_key(&store, vault, None, false);
        let lone = identity_with(&store, vault, Some(key2.id));
        copy_identity_to_vault(&store, lone.id, team, true).unwrap();
        assert!(store.get::<SshKey>(key2.id).unwrap().is_none());
        assert_eq!(keys_list(&store, Some(team)).unwrap().len(), 2);
    }

    #[test]
    fn viewer_vault_rejects_writes_but_allows_copying_out() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let viewer = synced_vault(&store, LocalVaultKind::Team, VaultRole::Viewer);
        let key = make_key(&store, vault, None, false);

        let err = copy_to_vault(&store, key.id, viewer, false).unwrap_err();
        assert_eq!(err.kind, "vault_read_only", "{err}");
        assert!(keys_list(&store, Some(viewer)).unwrap().is_empty());
        let err = generate(
            &store,
            &GenerateForm {
                vault_id: viewer,
                label: "nope".into(),
                algorithm: KeyAlgorithm::Ed25519,
                comment: String::new(),
                passphrase: None,
                remember_passphrase: false,
            },
        )
        .unwrap_err();
        assert_eq!(err.kind, "vault_read_only");

        // Something already in a view-only vault (synced down, or written back
        // when we were still an editor) can be copied elsewhere, but not
        // renamed, moved or deleted.
        let team_id = store.vault(viewer).unwrap().team_id;
        let vault_key = store.vault_key(viewer).unwrap();
        let set_role = |role: VaultRole| {
            store
                .upsert_vault(
                    viewer,
                    LocalVaultKind::Team,
                    "shared",
                    team_id,
                    role,
                    Some(&vault_key),
                    1,
                )
                .unwrap();
        };
        set_role(VaultRole::Editor);
        let shared = copy_to_vault(&store, key.id, viewer, false).unwrap().id;
        set_role(VaultRole::Viewer);
        let copied = copy_to_vault(&store, shared, vault, false).unwrap();
        assert_eq!(copied.vault_id, vault);
        assert_eq!(copied.id, key.id, "identical key is reused, not duplicated");
        let fresh = make_key(&store, vault, None, false);
        set_role(VaultRole::Editor);
        let fresh_shared = copy_to_vault(&store, fresh.id, viewer, true).unwrap().id;
        set_role(VaultRole::Viewer);
        assert_eq!(keys_list(&store, Some(vault)).unwrap().len(), 1);
        let back = copy_to_vault(&store, fresh_shared, vault, false).unwrap();
        assert_eq!(back.fingerprint, fresh.fingerprint);
        assert_eq!(keys_list(&store, Some(vault)).unwrap().len(), 2);
        assert_eq!(
            rename(&store, shared, "renamed").unwrap_err().kind,
            "vault_read_only"
        );
        assert_eq!(
            copy_to_vault(&store, shared, vault, true).unwrap_err().kind,
            "vault_read_only"
        );
        assert_eq!(delete(&store, shared).unwrap_err().kind, "vault_read_only");
        assert_eq!(keys_list(&store, Some(viewer)).unwrap().len(), 2);
    }

    #[test]
    fn agent_backed_keys_store_only_the_public_half() {
        const PUB: &str = include_str!("../../termoso-core/testdata/keys/ed25519_openssh.pub");
        let store = store();
        let vault = store.local_vault().unwrap().id;

        let card = import_agent(
            &store,
            &AgentImportForm {
                vault_id: vault,
                label: String::new(),
                public_key: PUB.into(),
                certificate: None,
            },
        )
        .unwrap();
        assert!(card.agent_backed && !card.unreadable);
        assert_eq!(card.label, "user@c5", "label falls back to the comment");
        assert_eq!(card.key_type, "ssh-ed25519");
        let raw = store.require::<SshKey>(card.id).unwrap().data;
        assert!(raw.private_key.is_empty() && raw.is_agent_backed());
        assert_eq!(public_key(&store, card.id).unwrap(), PUB.trim());

        // Private-key operations are refused rather than failing on an
        // empty string.
        for err in [
            export(&store, card.id, None, None)
                .err()
                .map(|e| e.to_string()),
            change_passphrase(&store, card.id, None, Some("x".into()), false)
                .err()
                .map(|e| e.to_string()),
            remember_passphrase(&store, card.id, Some("x".into()))
                .err()
                .map(|e| e.to_string()),
        ] {
            assert!(err.unwrap().contains("SSH agent"));
        }

        // Same key again (with a certificate this time): reused + cert attached.
        let again = import_agent(
            &store,
            &AgentImportForm {
                vault_id: vault,
                label: "other".into(),
                public_key: PUB.into(),
                certificate: Some(CERT.into()),
            },
        )
        .unwrap();
        assert_eq!(again.id, card.id);
        assert_eq!(
            again.certificate.as_ref().map(|c| c.key_id.as_str()),
            Some("user-cert")
        );
        assert_eq!(keys_list(&store, Some(vault)).unwrap().len(), 1);

        // Certificate for a different key is rejected.
        let err = import_agent(
            &store,
            &AgentImportForm {
                vault_id: vault,
                label: String::new(),
                public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl x".into(),
                certificate: Some(CERT.into()),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("different key"), "{err}");
        assert!(
            import_agent(
                &store,
                &AgentImportForm {
                    vault_id: vault,
                    label: String::new(),
                    public_key: OPENSSH_KEY.into(),
                    certificate: None,
                },
            )
            .is_err()
        );

        // Copying to another vault dedups by public blob.
        let other = Uuid::new_v4();
        store
            .upsert_vault(
                other,
                LocalVaultKind::Personal,
                "other",
                None,
                VaultRole::Manager,
                Some(&SymmetricKey::generate()),
                1,
            )
            .unwrap();
        let copied = copy_to_vault(&store, card.id, other, false).unwrap();
        assert!(copied.agent_backed && copied.certificate.is_some());
        let twice = copy_to_vault(&store, card.id, other, false).unwrap();
        assert_eq!(twice.id, copied.id);
        let json = serde_json::to_string(&keys_list(&store, None).unwrap()).unwrap();
        assert!(json.contains("\"agentBacked\":true"));
    }
}
