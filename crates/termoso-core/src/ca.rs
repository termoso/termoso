//! Team SSH CA on the client: one device key per installation, certified by
//! each team's CA (`POST /teams/{id}/ca/issue`). Certificates are cached in
//! encrypted metadata and refreshed in the background with the account
//! sync, so connecting never waits on the server. Hosts in a team vault try
//! the certificate first; everything else about the identity stays as is.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use termoso_proto::ca::{IssueCertificateRequest, IssueCertificateResponse};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api::ApiClient;
use crate::error::Result;
use crate::keys::{self, KeyAlgorithm};
use crate::ssh::AuthMethod;
use crate::store::Store;

const KEY_META: &str = "team_ca.device_key";
const CERTS_META: &str = "team_ca.certificates";
/// Teams that answered "no CA" (404), "disabled" (409) or "not allowed"
/// (403) are not asked again before this passes.
const BACKOFF: Duration = Duration::minutes(15);
/// A certificate is renewed once less than this share of its lifetime is
/// left (and at least five minutes before it expires).
const RENEW_FRACTION: f64 = 0.25;

/// The installation's CA-facing key (never leaves the device unsigned).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKey {
    /// OpenSSH private key PEM, unencrypted (the store is encrypted).
    pub private_key: Zeroizing<String>,
    /// `authorized_keys` line.
    pub public_key: String,
    /// Generation time.
    pub created_at: DateTime<Utc>,
}

/// One team's certificate for the device key, or the reason none exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCert {
    /// Team whose CA signed (or refused) it.
    pub team_id: Uuid,
    /// `ssh-ed25519-cert-v01@openssh.com AAAA…`; `None` after a refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `TrustedUserCAKeys` line of the signing key.
    pub ca_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Login names in the certificate.
    pub principals: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Start of validity.
    pub valid_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Expiry.
    pub valid_before: Option<DateTime<Utc>>,
    /// Last time the server was asked (success or refusal).
    pub checked_at: DateTime<Utc>,
    /// Why the last request yielded no certificate (`no_ca`, `disabled`,
    /// `forbidden`, `error`), for the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
}

impl CachedCert {
    /// Usable right now.
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        self.certificate.is_some()
            && self.valid_after.is_some_and(|a| a <= now)
            && self.valid_before.is_some_and(|b| b > now)
    }

    /// Worth asking the server again.
    fn is_stale(&self) -> bool {
        let now = Utc::now();
        match (self.valid_after, self.valid_before, &self.certificate) {
            (Some(a), Some(b), Some(_)) => {
                let life = (b - a).num_seconds().max(1) as f64;
                let left = (b - now).num_seconds() as f64;
                left < (life * RENEW_FRACTION).max(300.0)
            }
            _ => now - self.checked_at > BACKOFF,
        }
    }
}

/// The device key, generated on first use. CPU-cheap (ed25519).
pub fn device_key(store: &Store) -> Result<DeviceKey> {
    if let Some(json) = store.secret_meta(KEY_META)? {
        return Ok(serde_json::from_str(&json)?);
    }
    let material = keys::generate(KeyAlgorithm::Ed25519, "termoso-team-ca@device", None)?;
    let key = DeviceKey {
        private_key: material.private_key,
        public_key: material.public_key,
        created_at: Utc::now(),
    };
    store.set_secret_meta(KEY_META, &serde_json::to_string(&key)?)?;
    Ok(key)
}

/// Every cached entry (valid or not), for the UI.
pub fn cached(store: &Store) -> Result<Vec<CachedCert>> {
    Ok(match store.secret_meta(CERTS_META)? {
        Some(json) => serde_json::from_str(&json).unwrap_or_default(),
        None => Vec::new(),
    })
}

fn save(store: &Store, certs: &[CachedCert]) -> Result<()> {
    store.set_secret_meta(CERTS_META, &serde_json::to_string(certs)?)
}

/// The valid certificate for `team_id`, if any.
pub fn certificate(store: &Store, team_id: Uuid) -> Result<Option<CachedCert>> {
    Ok(cached(store)?
        .into_iter()
        .find(|c| c.team_id == team_id && c.is_valid()))
}

/// Team of the vault a host lives in, when it is a team vault.
pub fn team_of_vault(store: &Store, vault_id: Uuid) -> Option<Uuid> {
    store.vault(vault_id).ok().and_then(|v| v.team_id)
}

/// `AuthMethod::Key` carrying the team certificate for a host in `vault_id`,
/// or `None` when the vault is personal or no valid certificate is cached.
/// Put it first: sshd answers a rejected certificate instantly.
pub fn auth_method(store: &Store, vault_id: Uuid) -> Option<AuthMethod> {
    let team_id = team_of_vault(store, vault_id)?;
    let cert = certificate(store, team_id).ok().flatten()?;
    let key = device_key(store).ok()?;
    Some(AuthMethod::Key {
        private_key: key.private_key,
        passphrase: None,
        certificate: cert.certificate,
    })
}

/// Ask the server for a fresh certificate of every team whose cache is
/// stale. Refusals are remembered for [`BACKOFF`]. Network errors are
/// logged, never fatal: the next sync tries again.
pub async fn refresh_all(api: &ApiClient, store: &Store) -> Result<()> {
    let mut teams: Vec<Uuid> = store
        .vaults()?
        .into_iter()
        .filter_map(|v| v.team_id)
        .collect();
    teams.sort();
    teams.dedup();
    let mut certs = cached(store)?;
    certs.retain(|c| teams.contains(&c.team_id));
    let key = device_key(store)?;
    let mut changed = false;
    for team_id in teams {
        let stale = certs
            .iter()
            .find(|c| c.team_id == team_id)
            .is_none_or(CachedCert::is_stale);
        if !stale {
            continue;
        }
        let entry = match api
            .issue_team_certificate(
                team_id,
                &IssueCertificateRequest {
                    public_key: key.public_key.clone(),
                    principals: Vec::new(),
                },
            )
            .await
        {
            Ok(IssueCertificateResponse {
                certificate,
                ca_public_key,
                issued,
            }) => CachedCert {
                team_id,
                certificate: Some(certificate),
                ca_public_key: Some(ca_public_key),
                principals: Some(issued.principals),
                valid_after: Some(issued.valid_after),
                valid_before: Some(issued.valid_before),
                checked_at: Utc::now(),
                refusal: None,
            },
            Err(e) => {
                let refusal = match e.status() {
                    Some(404) => "no_ca",
                    Some(409) => "disabled",
                    Some(403) => "forbidden",
                    Some(_) => "error",
                    None => {
                        tracing::debug!("team {team_id}: certificate refresh failed: {e}");
                        continue;
                    }
                };
                CachedCert {
                    team_id,
                    certificate: None,
                    ca_public_key: None,
                    principals: None,
                    valid_after: None,
                    valid_before: None,
                    checked_at: Utc::now(),
                    refusal: Some(refusal.into()),
                }
            }
        };
        certs.retain(|c| c.team_id != team_id);
        certs.push(entry);
        changed = true;
    }
    if changed {
        save(store, &certs)?;
    }
    Ok(())
}

/// Drop the cached certificates (sign-out). The device key stays so a
/// returning sign-in keeps its identity with the CA records.
pub fn forget_certificates(store: &Store) -> Result<()> {
    store.delete_meta(CERTS_META)
}

/// Drop everything, device key included (account removed from this device).
pub fn forget(store: &Store) -> Result<()> {
    store.delete_meta(CERTS_META)?;
    store.delete_meta(KEY_META)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(life_h: i64, left_h: i64) -> CachedCert {
        let now = Utc::now();
        CachedCert {
            team_id: Uuid::new_v4(),
            certificate: Some("ssh-ed25519-cert-v01@openssh.com AAAA".into()),
            ca_public_key: None,
            principals: None,
            valid_after: Some(now - Duration::hours(life_h - left_h)),
            valid_before: Some(now + Duration::hours(left_h)),
            checked_at: now,
            refusal: None,
        }
    }

    #[test]
    fn staleness_follows_remaining_lifetime() {
        assert!(cert(8, 7).is_valid());
        assert!(!cert(8, 7).is_stale());
        assert!(cert(8, 1).is_stale(), "under a quarter left");
        assert!(cert(8, -1).is_stale());
        assert!(!cert(8, -1).is_valid());
        let refused = CachedCert {
            certificate: None,
            valid_after: None,
            valid_before: None,
            refusal: Some("no_ca".into()),
            ..cert(8, 8)
        };
        assert!(!refused.is_stale(), "refusals back off");
        let old = CachedCert {
            checked_at: Utc::now() - Duration::hours(1),
            ..refused
        };
        assert!(old.is_stale());
    }
}
