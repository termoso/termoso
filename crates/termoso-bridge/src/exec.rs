//! Run one command on a vault host over SSH, with the credentials stored in
//! the vault. Used by the MCP `ssh_exec` tool; never exposed over REST.
//!
//! Host keys: the vault's own `known_host` pins are loaded into an in-memory
//! store, so a key that changed since a desktop/mobile client pinned it is
//! rejected. Unknown hosts are accepted on first use unless strict mode is
//! on (then they are rejected and must be pinned from a client first).

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use termoso_core::hostkey::{FixedPrompt, HostKeyDecision, KnownHosts, StrictPrompt};
use termoso_core::ssh::{AuthMethod, ConnectOptions, SshClient, SshTarget};
use termoso_core::store::Store;
use termoso_crypto::keys::SymmetricKey;
use termoso_proto::entities::payload::{Group, Host, Identity, KnownHost, SshConfig, SshKey};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{BridgeError, Result};
use crate::vault::VaultState;

/// Hard cap on one command (seconds).
pub const MAX_TIMEOUT: u64 = 600;
/// Default per-command budget (seconds).
pub const DEFAULT_TIMEOUT: u64 = 60;
/// Captured output is truncated beyond this many bytes per stream.
pub const MAX_OUTPUT: usize = 64 * 1024;

/// Everything needed to open the connection, resolved from vault entities.
pub struct Target {
    pub vault: String,
    pub host_id: Uuid,
    pub label: String,
    pub target: SshTarget,
    pub auth: Vec<AuthMethod>,
    pub timeout: Duration,
    pub known_hosts: String,
}

/// Result of [`run`].
#[derive(Debug, Serialize)]
pub struct Output {
    pub host: String,
    pub address: String,
    pub exit_code: Option<u32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

/// Find a host by id, `external_id`, label or address (case-insensitive for
/// label/address). Exactly one match is required.
pub fn find_host<'a>(
    vaults: &[&'a VaultState],
    selector: &str,
) -> Result<(&'a VaultState, Uuid, Host)> {
    let sel = selector.trim();
    if sel.is_empty() {
        return Err(BridgeError::Invalid("host is required".into()));
    }
    let as_id = Uuid::parse_str(sel).ok();
    let mut found: Vec<(&VaultState, Uuid, Host)> = Vec::new();
    for v in vaults {
        for (id, _, h) in v.iter_kind::<Host>("host") {
            let hit = as_id == Some(id)
                || h.external_id.as_deref() == Some(sel)
                || h.label.eq_ignore_ascii_case(sel)
                || h.address.eq_ignore_ascii_case(sel);
            if hit {
                found.push((v, id, h));
            }
        }
    }
    match found.len() {
        0 => Err(BridgeError::NotFound(format!("no host matches `{sel}`"))),
        1 => Ok(found.pop().expect("one")),
        n => Err(BridgeError::Invalid(format!(
            "`{sel}` matches {n} hosts; use the host id ({})",
            found
                .iter()
                .map(|(v, id, h)| format!("{id} = {} in {}", h.label, v.name))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// SSH config of the host, falling back to its group chain (nearest first).
pub(crate) fn effective_ssh(v: &VaultState, h: &Host) -> Option<SshConfig> {
    let own = h
        .ssh_config_id
        .and_then(|c| v.get::<SshConfig>(c, "ssh_config"));
    let mut merged = own.unwrap_or_default();
    let mut group = h.group_id;
    let mut hops = 0;
    while let Some(gid) = group {
        hops += 1;
        if hops > 32 {
            break;
        }
        let Some(g) = v.get::<Group>(gid, "group") else {
            break;
        };
        if let Some(c) = g
            .ssh_config_id
            .and_then(|c| v.get::<SshConfig>(c, "ssh_config"))
        {
            merged.port = merged.port.or(c.port);
            merged.identity_id = merged.identity_id.or(c.identity_id);
            merged.host_chain_id = merged.host_chain_id.or(c.host_chain_id);
            merged.proxy_id = merged.proxy_id.or(c.proxy_id);
            merged.timeout = merged.timeout.or(c.timeout);
        }
        group = g.parent_id;
    }
    Some(merged)
}

/// Resolve the connection parameters for `host`.
pub fn resolve(v: &VaultState, host_id: Uuid, h: &Host) -> Result<Target> {
    let cfg = effective_ssh(v, h).unwrap_or_default();
    if cfg.host_chain_id.is_some() {
        return Err(BridgeError::Invalid(format!(
            "{}: jump-host chains are not supported by ssh_exec yet",
            h.label
        )));
    }
    if cfg.proxy_id.is_some() {
        return Err(BridgeError::Invalid(format!(
            "{}: proxies are not supported by ssh_exec yet",
            h.label
        )));
    }
    let ident = cfg
        .identity_id
        .and_then(|i| v.get::<Identity>(i, "identity"))
        .ok_or_else(|| {
            BridgeError::Invalid(format!(
                "{}: no identity (username) stored for this host",
                h.label
            ))
        })?;
    if ident.username.trim().is_empty() {
        return Err(BridgeError::Invalid(format!(
            "{}: identity has no username",
            h.label
        )));
    }
    let mut auth = Vec::new();
    if let Some(key) = ident.ssh_key_id.and_then(|k| v.get::<SshKey>(k, "ssh_key")) {
        if key.key_type.starts_with("sk-") {
            return Err(BridgeError::Invalid(format!(
                "{}: FIDO2 security keys cannot be used headlessly",
                h.label
            )));
        }
        auth.push(AuthMethod::Key {
            private_key: Zeroizing::new(key.private_key),
            passphrase: key.passphrase.filter(|p| !p.is_empty()).map(Zeroizing::new),
            certificate: None,
        });
    }
    if let Some(pw) = ident.password.filter(|p| !p.is_empty()) {
        auth.push(AuthMethod::Password(Zeroizing::new(pw)));
    }
    if auth.is_empty() {
        return Err(BridgeError::Invalid(format!(
            "{}: identity `{}` has neither a key nor a password",
            h.label, ident.label
        )));
    }
    let (address, port_in_address) = split_port(&h.address);
    let port = cfg.port.or(port_in_address).unwrap_or(22);
    let known_hosts = v
        .iter_kind::<KnownHost>("known_host")
        .map(|(_, _, k)| format!("{} {} {}\n", k.hostname, k.key_type, k.public_key))
        .collect::<String>();
    Ok(Target {
        vault: v.name.clone(),
        host_id,
        label: h.label.clone(),
        target: SshTarget {
            host: address,
            port,
            username: ident.username.clone(),
        },
        auth,
        timeout: Duration::from_secs(u64::from(cfg.timeout.unwrap_or(15).clamp(1, 120))),
        known_hosts,
    })
}

/// `host:port` / `[v6]:port` → (host, Some(port)); bare host → (host, None).
fn split_port(address: &str) -> (String, Option<u16>) {
    let a = address.trim();
    if let Some(rest) = a.strip_prefix('[')
        && let Some((h, p)) = rest.split_once("]:")
    {
        return (h.to_string(), p.parse().ok());
    }
    if a.matches(':').count() == 1
        && let Some((h, p)) = a.rsplit_once(':')
        && let Ok(port) = p.parse::<u16>()
    {
        return (h.to_string(), Some(port));
    }
    (a.to_string(), None)
}

/// Connect, run `command`, disconnect.
pub async fn run(
    mut t: Target,
    command: &str,
    strict_host_key: bool,
    budget: Duration,
) -> Result<Output> {
    resolve_secrets(&mut t).await?;
    if command.trim().is_empty() {
        return Err(BridgeError::Invalid("command is required".into()));
    }
    let store = Arc::new(
        Store::open_in_memory(SymmetricKey::generate())
            .map_err(|e| BridgeError::Invalid(format!("host-key store: {e}")))?,
    );
    let vault_id = store
        .local_vault()
        .map_err(|e| BridgeError::Invalid(format!("host-key store: {e}")))?
        .id;
    let kh = KnownHosts::new(store, vault_id);
    if !t.known_hosts.is_empty() {
        let _ = kh.import_openssh(&t.known_hosts);
    }
    let prompt: Arc<dyn termoso_core::hostkey::HostKeyPrompt> = if strict_host_key {
        Arc::new(StrictPrompt)
    } else {
        Arc::new(FixedPrompt(HostKeyDecision::AcceptOnce))
    };
    let mut opts = ConnectOptions::new(t.target.clone(), kh, prompt);
    opts.auth = t.auth;
    opts.timeout = t.timeout;
    let address = t.target.display();
    let label = t.label;
    let fut = async move {
        let client = SshClient::connect(opts)
            .await
            .map_err(|e| BridgeError::Invalid(format!("{label}: connect: {e}")))?;
        let out = client
            .exec(command, None)
            .await
            .map_err(|e| BridgeError::Invalid(format!("{label}: exec: {e}")));
        let _ = client.disconnect().await;
        let out = out?;
        let (stdout, t1) = clip(&out.stdout);
        let (stderr, t2) = clip(&out.stderr);
        Ok::<Output, BridgeError>(Output {
            host: label,
            address,
            exit_code: out.exit_code,
            stdout,
            stderr,
            truncated: t1 || t2,
        })
    };
    tokio::time::timeout(budget, fut).await.map_err(|_| {
        BridgeError::Invalid(format!(
            "command did not finish within {}s",
            budget.as_secs()
        ))
    })?
}

fn clip(bytes: &[u8]) -> (String, bool) {
    let truncated = bytes.len() > MAX_OUTPUT;
    let slice = if truncated {
        &bytes[..MAX_OUTPUT]
    } else {
        bytes
    };
    (String::from_utf8_lossy(slice).into_owned(), truncated)
}

/// Replace `op://` / `bw://` / `pass://` / `env://` references in the
/// target's password and passphrase with the values the manager returns.
pub async fn resolve_secrets(t: &mut Target) -> Result<()> {
    for m in &mut t.auth {
        match m {
            AuthMethod::Password(p) if termoso_core::extsecret::is_reference(p) => {
                *p = termoso_core::extsecret::resolve(p)
                    .await
                    .map_err(|e| BridgeError::Invalid(e.to_string()))?;
            }
            AuthMethod::Key {
                passphrase: Some(p),
                ..
            } if termoso_core::extsecret::is_reference(p) => {
                *p = termoso_core::extsecret::resolve(p)
                    .await
                    .map_err(|e| BridgeError::Invalid(e.to_string()))?;
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_port_forms() {
        assert_eq!(split_port("example.com"), ("example.com".into(), None));
        assert_eq!(
            split_port("example.com:2222"),
            ("example.com".into(), Some(2222))
        );
        assert_eq!(split_port("[fe80::1]:22"), ("fe80::1".into(), Some(22)));
        assert_eq!(split_port("fe80::1"), ("fe80::1".into(), None));
    }

    #[test]
    fn clip_marks_truncation() {
        let (s, t) = clip(&vec![b'a'; MAX_OUTPUT + 1]);
        assert!(t);
        assert_eq!(s.len(), MAX_OUTPUT);
        assert!(!clip(b"ok").1);
    }
}
