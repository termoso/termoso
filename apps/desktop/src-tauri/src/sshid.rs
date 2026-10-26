//! SSH ID for the desktop: the account handle, this device's passkeys and
//! the FIDO2 keys attached to the SSH ID. Private device keys are generated
//! and kept in the encrypted store (`termoso_core::sshid`); the server and
//! the webview only ever see public keys, fingerprints and metadata.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, Runtime};
use termoso_core::api::ApiClient;
use termoso_core::fido2::{self, GenerateOptions};
use termoso_core::keys;
use termoso_core::model::SshKey;
use termoso_core::ssh::AuthMethod;
use termoso_core::sshid as core;
use termoso_core::store::Store;
use termoso_proto::sshid::{
    AddFido2KeyRequest, AddPublicKeyRequest, SshIdKeyType, SshIdProfile, normalize_handle,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::account::api;
use crate::error::{DesktopError, Result};
use crate::state::AppState;

/// One of this device's passkeys as shown in Settings → SSH ID.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyCard {
    pub key_type: SshIdKeyType,
    pub fingerprint: String,
    /// `authorized_keys` line.
    pub public_key: String,
    /// The server currently lists this key for the device.
    pub published: bool,
}

/// Everything the SSH ID page needs.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshIdView {
    pub signed_in: bool,
    /// `None` until the account sets up a handle.
    pub profile: Option<SshIdProfile>,
    pub device_keys: Vec<DeviceKeyCard>,
    /// `curl -fs <url> >> ~/.ssh/authorized_keys`
    pub provision_command: Option<String>,
    /// Where a handle would be published (`<base>/<handle>`), known before
    /// the account has one.
    pub base_url: Option<String>,
}

/// Form for attaching a FIDO2 key to the SSH ID: a fresh credential is
/// made on the token, only its public key goes to the server.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshIdFido2Form {
    pub label: String,
    #[serde(flatten)]
    pub options: GenerateOptions,
}

fn provision_command(profile: &SshIdProfile) -> String {
    format!("curl -fs {} >> ~/.ssh/authorized_keys", profile.url)
}

fn view_of(store: &Store, profile: Option<SshIdProfile>) -> Result<SshIdView> {
    let local = core::device_keys(store)?;
    let device_keys = local
        .iter()
        .map(|k| DeviceKeyCard {
            key_type: k.key_type,
            fingerprint: k.fingerprint(),
            public_key: k.public_key.clone(),
            published: profile.as_ref().is_some_and(|p| {
                p.keys
                    .iter()
                    .any(|s| s.current_device && same_key(&s.public_key, &k.public_key))
            }),
        })
        .collect();
    Ok(SshIdView {
        signed_in: true,
        provision_command: profile.as_ref().map(provision_command),
        base_url: profile
            .as_ref()
            .and_then(|p| p.url.rsplit_once('/'))
            .map(|(base, _)| base.to_string()),
        profile,
        device_keys,
    })
}

fn signed_out(store: &Store) -> Result<SshIdView> {
    let mut v = view_of(store, None)?;
    v.signed_in = false;
    Ok(v)
}

/// Compare `authorized_keys` lines by type and blob, ignoring the comment.
fn same_key(a: &str, b: &str) -> bool {
    let head = |s: &str| {
        let mut it = s.split_whitespace();
        (it.next().map(str::to_string), it.next().map(str::to_string))
    };
    head(a) == head(b)
}

/// Generate any missing device key and publish the set when the server
/// does not list exactly what this device holds. Publishing is a sensitive
/// change: outside the step-up window after sign-in the server asks for a
/// re-authentication, and the keys stay unpublished until the user confirms
/// (see [`publish_now`]).
async fn publish(
    api: &Arc<ApiClient>,
    store: &Arc<Store>,
    profile: SshIdProfile,
) -> Result<SshIdProfile> {
    let handle = profile.handle.clone();
    let s = store.clone();
    let keys = tokio::task::spawn_blocking(move || core::ensure_device_keys(&s, &handle))
        .await
        .map_err(|e| DesktopError::invalid(e.to_string()))??;
    let mine: Vec<&str> = profile
        .keys
        .iter()
        .filter(|k| k.current_device)
        .map(|k| k.public_key.as_str())
        .collect();
    let in_sync = mine.len() == keys.len()
        && keys
            .iter()
            .all(|k| mine.iter().any(|m| same_key(m, &k.public_key)));
    if in_sync {
        return Ok(profile);
    }
    match api
        .put_sshid_device_keys(&core::upload_request(&keys))
        .await
    {
        Ok(p) => Ok(p),
        Err(e) if e.is_api_code(termoso_proto::error::codes::REAUTH_REQUIRED) => Ok(profile),
        Err(e) => Err(e.into()),
    }
}

/// Publish this device's keys explicitly (the UI runs this after a step-up).
pub async fn publish_now<R: Runtime>(app: &AppHandle<R>) -> Result<SshIdView> {
    let state = app.state::<AppState>();
    let api = api(app).await?;
    let profile = api
        .sshid()
        .await?
        .ok_or_else(|| DesktopError::invalid("SSH ID is not set up"))?;
    let handle = profile.handle.clone();
    let s = state.store()?.clone();
    let keys = tokio::task::spawn_blocking(move || core::ensure_device_keys(&s, &handle))
        .await
        .map_err(|e| DesktopError::invalid(e.to_string()))??;
    let profile = api
        .put_sshid_device_keys(&core::upload_request(&keys))
        .await?;
    view_of(&*state.store()?, Some(profile))
}

async fn load(api: &Arc<ApiClient>, store: &Arc<Store>) -> Result<Option<SshIdProfile>> {
    let profile = match api.sshid().await? {
        Some(p) => Some(publish(api, store, p).await?),
        None => None,
    };
    core::set_handle(store, profile.as_ref().map(|p| p.handle.as_str()))?;
    Ok(profile)
}

/// Current state; keeps the device keys published while at it.
pub async fn view<R: Runtime>(app: &AppHandle<R>) -> Result<SshIdView> {
    let state = app.state::<AppState>();
    let api = match api(app).await {
        Ok(api) => api,
        Err(_) => return signed_out(&*state.store()?),
    };
    let profile = load(&api, &state.store()?).await?;
    let mut v = view_of(&*state.store()?, profile)?;
    if v.profile.is_none() {
        v.base_url = api
            .server_info()
            .await
            .ok()
            .map(|i| i.sshid_url)
            .filter(|u| !u.is_empty());
    }
    Ok(v)
}

/// Re-publish this device's keys in the background (after sign-in).
pub async fn refresh<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let state = app.state::<AppState>();
    let api = api(app).await?;
    load(&api, &state.store()?).await?;
    Ok(())
}

/// Claim a handle and publish this device's keys under it.
pub async fn create<R: Runtime>(app: &AppHandle<R>, handle: &str) -> Result<SshIdView> {
    let state = app.state::<AppState>();
    let api = api(app).await?;
    let handle = normalize_handle(handle).ok_or_else(|| {
        DesktopError::invalid("username must be 3–32 characters: lowercase letters, digits, - or _")
    })?;
    let profile = api.create_sshid(&handle).await?;
    let profile = publish(&api, &state.store()?, profile).await?;
    core::set_handle(&*state.store()?, Some(&profile.handle))?;
    view_of(&*state.store()?, Some(profile))
}

/// Delete the SSH ID: every published key goes with it on the server, the
/// device keys and the FIDO2 handles are wiped here.
pub async fn delete<R: Runtime>(app: &AppHandle<R>) -> Result<SshIdView> {
    let state = app.state::<AppState>();
    let api = api(app).await?;
    api.delete_sshid().await?;
    core::forget(&*state.store()?)?;
    for k in state.store()?.list::<SshKey>(None)? {
        if k.data.ssh_id {
            state.store()?.delete(k.id)?;
        }
    }
    view_of(&*state.store()?, None)
}

/// Replace this device's passkeys with fresh ones and publish them.
pub async fn rotate<R: Runtime>(app: &AppHandle<R>) -> Result<SshIdView> {
    let state = app.state::<AppState>();
    let api = api(app).await?;
    let profile = api
        .sshid()
        .await?
        .ok_or_else(|| DesktopError::invalid("SSH ID is not set up"))?;
    let handle = profile.handle.clone();
    let keys = tokio::task::spawn_blocking(move || core::new_device_keys(&handle))
        .await
        .map_err(|e| DesktopError::invalid(e.to_string()))??;
    let profile = api
        .put_sshid_device_keys(&core::upload_request(&keys))
        .await?;
    core::save_device_keys(&*state.store()?, &keys)?;
    view_of(&*state.store()?, Some(profile))
}

/// Make a credential on the token, attach its public key to the SSH ID and
/// keep the key handle in the vault (personal when signed in, so it follows
/// the account; the token holds the private key either way).
pub async fn add_fido2<R: Runtime>(app: &AppHandle<R>, form: SshIdFido2Form) -> Result<SshIdView> {
    let state = app.state::<AppState>();
    let api = api(app).await?;
    let profile = api
        .sshid()
        .await?
        .ok_or_else(|| DesktopError::invalid("SSH ID is not set up"))?;
    let label = form.label.trim().to_string();
    if label.is_empty() {
        return Err(DesktopError::invalid("key label is required"));
    }
    let mut opts = form.options;
    opts.passphrase = None;
    if opts.comment.trim().is_empty() {
        opts.comment = format!("{}@termoso", profile.handle);
    }
    let material = tokio::task::spawn_blocking(move || fido2::generate(&opts))
        .await
        .map_err(|e| DesktopError::invalid(e.to_string()))??;
    let key_type = match material.info.key_type.as_str() {
        "sk-ssh-ed25519@openssh.com" => SshIdKeyType::Ed25519Sk,
        "sk-ecdsa-sha2-nistp256@openssh.com" => SshIdKeyType::EcdsaSk,
        t => return Err(DesktopError::invalid(format!("unexpected key type {t}"))),
    };
    let published = api
        .add_sshid_fido2_key(&AddFido2KeyRequest {
            label: label.clone(),
            key_type,
            public_key: material.public_key.clone(),
        })
        .await?;
    let vault_id = match state.store()?.personal_vault()? {
        Some(v) => v.id,
        None => state.store()?.local_vault()?.id,
    };
    let credential = fido2::describe(&material.private_key, None).and_then(|s| s.credential_id);
    state.store()?.insert(
        vault_id,
        &SshKey {
            external_id: None,
            label,
            private_key: material.private_key.to_string(),
            public_key: Some(material.public_key.clone()),
            passphrase: None,
            key_type: published.key_type.wire_name().to_string(),
            fido2_credential_id: credential,
            ssh_id: true,
        },
    )?;
    let profile = api.sshid().await?;
    view_of(&*state.store()?, profile)
}

/// Publish a public key the user already has (generated elsewhere). Nothing
/// is stored locally: only the public line goes to the server, bound to the
/// account rather than this device.
pub async fn add_public_key<R: Runtime>(
    app: &AppHandle<R>,
    label: String,
    public_key: String,
) -> Result<SshIdView> {
    let state = app.state::<AppState>();
    let api = api(app).await?;
    let label = label.trim().to_string();
    if label.is_empty() {
        return Err(DesktopError::invalid("key label is required"));
    }
    let public_key = public_key.trim().to_string();
    if public_key.is_empty() {
        return Err(DesktopError::invalid("public key is required"));
    }
    api.add_sshid_public_key(&AddPublicKeyRequest { label, public_key })
        .await?;
    let profile = api.sshid().await?;
    view_of(&*state.store()?, profile)
}

/// Remove a published key. A FIDO2 key handle stored for it is dropped too;
/// device keys of another device are just unlisted (that device re-publishes
/// them if it is still signed in, so revoke the device instead).
pub async fn remove_key<R: Runtime>(app: &AppHandle<R>, id: Uuid) -> Result<SshIdView> {
    let state = app.state::<AppState>();
    let api = api(app).await?;
    let before = api.sshid().await?;
    let removed = before
        .as_ref()
        .and_then(|p| p.keys.iter().find(|k| k.id == id))
        .map(|k| k.public_key.clone());
    api.remove_sshid_key(id).await?;
    if let Some(pk) = removed {
        for k in state.store()?.list::<SshKey>(None)? {
            if k.data.ssh_id
                && k.data
                    .public_key
                    .as_deref()
                    .is_some_and(|p| same_key(p, &pk))
            {
                state.store()?.delete(k.id)?;
            }
        }
    }
    let profile = api.sshid().await?;
    view_of(&*state.store()?, profile)
}

/// Unpublish another device's passkeys by signing that device out: its
/// server session is revoked (so it cannot re-publish) and the server drops
/// its SSH ID keys with the session. The current device uses sign out.
pub async fn remove_device<R: Runtime>(app: &AppHandle<R>, device_id: Uuid) -> Result<SshIdView> {
    let state = app.state::<AppState>();
    crate::account::revoke_device(app, device_id).await?;
    let api = api(app).await?;
    let profile = api.sshid().await?;
    view_of(&*state.store()?, profile)
}

/// Authentication methods for an identity that logs in with SSH ID: this
/// device's passkeys (preferred type first), then the FIDO2 keys attached to
/// the SSH ID. Empty when the device holds no SSH ID keys yet.
pub fn auth_methods(
    store: &Store,
    preferred: Option<SshIdKeyType>,
    pin: Option<Zeroizing<String>>,
) -> Result<Vec<AuthMethod>> {
    let mut out = Vec::new();
    let device = core::ordered(core::device_keys(store)?, preferred);
    let hardware: Vec<AuthMethod> = store
        .list::<SshKey>(None)?
        .into_iter()
        .filter(|k| k.data.ssh_id && fido2::is_sk_type(&k.data.key_type))
        .map(|k| AuthMethod::SecurityKey {
            private_key: Zeroizing::new(k.data.private_key),
            passphrase: None,
            pin: pin.clone(),
            backend: Arc::new(fido2::UsbBackend::default()),
            certificate: None,
        })
        .collect();
    let hardware_first = matches!(
        preferred,
        Some(SshIdKeyType::EcdsaSk | SshIdKeyType::Ed25519Sk)
    );
    let mut hardware = Some(hardware);
    if hardware_first {
        out.extend(hardware.take().into_iter().flatten());
    }
    for k in device {
        // Skip anything that stopped parsing (corrupted meta) rather than
        // failing the whole connection.
        if keys::inspect(&k.private_key).is_err() {
            continue;
        }
        out.push(AuthMethod::Key {
            private_key: k.private_key,
            passphrase: None,
            certificate: None,
        });
    }
    out.extend(hardware.into_iter().flatten());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoso_core::termoso_crypto::keys::SymmetricKey;

    #[test]
    fn same_key_ignores_comment() {
        assert!(same_key("ssh-ed25519 AAAA a@b", "ssh-ed25519 AAAA other"));
        assert!(!same_key("ssh-ed25519 AAAA", "ssh-ed25519 BBBB"));
        assert!(!same_key("ssh-rsa AAAA", "ssh-ed25519 AAAA"));
    }

    #[test]
    fn auth_methods_follow_device_keys() {
        let s = Store::open_in_memory(SymmetricKey::generate()).unwrap();
        assert!(auth_methods(&s, None, None).unwrap().is_empty());
        core::ensure_device_keys(&s, "alice").unwrap();
        let m = auth_methods(&s, Some(SshIdKeyType::Rsa), None).unwrap();
        assert_eq!(m.len(), 3);
        match &m[0] {
            AuthMethod::Key { private_key, .. } => {
                let info = keys::inspect(private_key).unwrap();
                assert_eq!(info.key_type, "ssh-rsa");
            }
            _ => panic!("expected a key"),
        }
        let v = view_of(&s, None).unwrap();
        assert_eq!(v.device_keys.len(), 3);
        assert!(v.device_keys.iter().all(|k| !k.published));
        assert!(
            v.device_keys
                .iter()
                .all(|k| k.fingerprint.starts_with("SHA256:"))
        );
    }
}
