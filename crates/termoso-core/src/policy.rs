//! Client-side copy of team policies that clients enforce themselves
//! (`auth = keys_only`, `jump_host_required`, `export = deny`,
//! `forward_ports`). The server is the source of truth; the copy lives in
//! the encrypted store metadata so the rules hold offline and is refreshed
//! with every sync pass alongside the team CA certificates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use termoso_proto::team::TeamPolicies;
use uuid::Uuid;

use crate::api::ApiClient;
use crate::error::Result;
use crate::store::Store;

const META: &str = "team_policies";

/// Policies of one team as last seen from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPolicies {
    /// Team the policies belong to.
    pub team_id: Uuid,
    /// The policies.
    pub policies: TeamPolicies,
    /// When they were fetched.
    pub fetched_at: DateTime<Utc>,
}

/// Every cached entry.
pub fn cached(store: &Store) -> Result<Vec<CachedPolicies>> {
    Ok(match store.secret_meta(META)? {
        Some(json) => serde_json::from_str(&json).unwrap_or_default(),
        None => Vec::new(),
    })
}

/// Replace the cache with the policies of `teams` (as returned by `GET /teams`).
pub fn remember(store: &Store, teams: &[termoso_proto::team::Team]) -> Result<()> {
    let now = Utc::now();
    let list: Vec<CachedPolicies> = teams
        .iter()
        .filter_map(|t| {
            t.policies.clone().map(|p| CachedPolicies {
                team_id: t.id,
                policies: p,
                fetched_at: now,
            })
        })
        .collect();
    store.set_secret_meta(META, &serde_json::to_string(&list)?)
}

/// Pull `GET /teams` and refresh the cache. Network errors are returned so
/// the caller can log them; the previous copy stays in place.
pub async fn refresh(api: &ApiClient, store: &Store) -> Result<()> {
    let teams = api.teams().await?;
    remember(store, &teams.teams)
}

/// Drop the cache (sign-out).
pub fn clear(store: &Store) -> Result<()> {
    store.delete_meta(META)
}

/// Policies of `team_id`, if cached.
pub fn for_team(store: &Store, team_id: Uuid) -> Option<TeamPolicies> {
    cached(store)
        .ok()?
        .into_iter()
        .find(|c| c.team_id == team_id)
        .map(|c| c.policies)
}

/// Policies that apply to entities living in `vault_id`: `None` for a
/// personal vault or when nothing is cached for the team.
pub fn for_vault(store: &Store, vault_id: Uuid) -> Option<TeamPolicies> {
    let team_id = store.vault(vault_id).ok()?.team_id?;
    for_team(store, team_id)
}

/// Whether `port` is covered by a `forward_ports` allowlist (empty = any).
pub fn port_allowed(allowlist: &[String], port: u16) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    allowlist.iter().any(|e| match e.split_once('-') {
        Some((a, b)) => matches!(
            (a.trim().parse::<u16>(), b.trim().parse::<u16>()),
            (Ok(a), Ok(b)) if a <= port && port <= b
        ),
        None => e.trim().parse::<u16>().is_ok_and(|p| p == port),
    })
}

/// Why an operation on `vault_id` is refused by its team policy, if it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// `auth = keys_only`: no password / keyboard-interactive methods.
    PasswordAuth,
    /// `jump_host_required`: the host has no jump chain.
    DirectConnection,
    /// `export = deny`.
    Export,
    /// `forward_ports`: the remote port is not on the allowlist.
    ForwardPort(u16),
    /// `forward_ports` set: dynamic (SOCKS) forwarding can reach any port.
    DynamicForward,
}

impl Denied {
    /// Human-readable reason shown to the user.
    pub fn message(&self) -> String {
        match self {
            Denied::PasswordAuth => {
                "team policy allows key-based authentication only for this host".into()
            }
            Denied::DirectConnection => {
                "team policy requires a jump host for this host; add one to its chain".into()
            }
            Denied::Export => "team policy forbids exporting data of this team vault".into(),
            Denied::ForwardPort(p) => {
                format!("team policy does not allow forwarding port {p} on this host")
            }
            Denied::DynamicForward => {
                "team policy restricts forwarded ports; dynamic (SOCKS) forwarding is not allowed"
                    .into()
            }
        }
    }
}

/// `auth = keys_only` for the vault?
pub fn keys_only(store: &Store, vault_id: Uuid) -> bool {
    for_vault(store, vault_id).is_some_and(|p| p.auth == "keys_only")
}

/// `jump_host_required` for the vault?
pub fn jump_required(store: &Store, vault_id: Uuid) -> bool {
    for_vault(store, vault_id).is_some_and(|p| p.jump_host_required)
}

/// `export = deny` for the vault?
pub fn export_denied(store: &Store, vault_id: Uuid) -> bool {
    for_vault(store, vault_id).is_some_and(|p| p.export == "deny")
}

/// `offline_cache = deny` for the vault: no local copies of files read from
/// its hosts.
pub fn offline_cache_denied(store: &Store, vault_id: Uuid) -> bool {
    for_vault(store, vault_id).is_some_and(|p| p.offline_cache == "deny")
}

/// Check a port-forwarding rule of kind `kind` (`local` / `remote` /
/// `dynamic`) reaching `remote_port` on a host of `vault_id`.
pub fn check_forward(
    store: &Store,
    vault_id: Uuid,
    kind: &str,
    remote_port: u16,
) -> Option<Denied> {
    let p = for_vault(store, vault_id)?;
    if p.forward_ports.is_empty() {
        return None;
    }
    if kind == "dynamic" {
        return Some(Denied::DynamicForward);
    }
    (!port_allowed(&p.forward_ports, remote_port)).then_some(Denied::ForwardPort(remote_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_matching() {
        assert!(port_allowed(&[], 1));
        let l = vec!["22".to_string(), "8000-8999".to_string()];
        assert!(port_allowed(&l, 22));
        assert!(port_allowed(&l, 8000));
        assert!(port_allowed(&l, 8999));
        assert!(!port_allowed(&l, 80));
        assert!(!port_allowed(&l, 9000));
    }
}
