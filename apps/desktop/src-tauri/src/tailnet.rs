//! Hosts from an overlay network: asks the locally installed Tailscale /
//! NetBird / ZeroTier CLI for the machines it knows. Read-only — nothing is
//! stored until the user imports a device.

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use tokio::process::Command;

use crate::error::{DesktopError, Result};

const CLI_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TailnetDevice {
    /// `tailscale`, `netbird` or `zerotier`.
    pub provider: String,
    /// Machine name as the network shows it.
    pub name: String,
    /// Stable DNS name (MagicDNS / NetBird FQDN), without trailing dot.
    pub dns_name: Option<String>,
    /// Overlay addresses, IPv4 first.
    pub addresses: Vec<String>,
    pub os: Option<String>,
    pub online: bool,
    pub tags: Vec<String>,
    /// This machine itself (listed, but not worth importing).
    pub this_device: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderStatus {
    pub id: String,
    pub installed: bool,
    /// CLI found but failed (daemon down, logged out…).
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TailnetScan {
    pub providers: Vec<ProviderStatus>,
    pub devices: Vec<TailnetDevice>,
}

/// Ask every supported CLI; a missing binary is reported, not an error.
pub async fn scan() -> Result<TailnetScan> {
    let mut providers = Vec::new();
    let mut devices = Vec::new();
    for (id, candidates, args) in [
        ("tailscale", tailscale_binaries(), &["status", "--json"][..]),
        (
            "netbird",
            vec!["netbird".to_string()],
            &["status", "--json"][..],
        ),
        ("zerotier", zerotier_binaries(), &["-j", "listnetworks"][..]),
    ] {
        match run_first(&candidates, args).await {
            Ok(None) => providers.push(ProviderStatus {
                id: id.into(),
                installed: false,
                error: None,
            }),
            Ok(Some(out)) => {
                let parsed = match id {
                    "tailscale" => parse_tailscale(&out),
                    "netbird" => parse_netbird(&out),
                    _ => parse_zerotier(&out),
                };
                match parsed {
                    Ok(list) => {
                        devices.extend(list);
                        providers.push(ProviderStatus {
                            id: id.into(),
                            installed: true,
                            error: None,
                        });
                    }
                    Err(e) => providers.push(ProviderStatus {
                        id: id.into(),
                        installed: true,
                        error: Some(e.to_string()),
                    }),
                }
            }
            Err(e) => providers.push(ProviderStatus {
                id: id.into(),
                installed: true,
                error: Some(e.to_string()),
            }),
        }
    }
    devices.sort_by(|a, b| {
        b.online
            .cmp(&a.online)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(TailnetScan { providers, devices })
}

fn tailscale_binaries() -> Vec<String> {
    let mut v = vec!["tailscale".to_string()];
    if cfg!(target_os = "macos") {
        v.push("/Applications/Tailscale.app/Contents/MacOS/Tailscale".into());
        v.push("/usr/local/bin/tailscale".into());
        v.push("/opt/homebrew/bin/tailscale".into());
    }
    if cfg!(windows) {
        v.push(r"C:\Program Files\Tailscale\tailscale.exe".into());
    }
    v
}

fn zerotier_binaries() -> Vec<String> {
    let mut v = vec!["zerotier-cli".to_string()];
    if cfg!(target_os = "macos") {
        v.push("/usr/local/bin/zerotier-cli".into());
    }
    if cfg!(windows) {
        v.push(r"C:\ProgramData\ZeroTier\One\zerotier-cli.bat".into());
    }
    v
}

/// Run the first binary that exists. `Ok(None)` when none is installed.
async fn run_first(candidates: &[String], args: &[&str]) -> Result<Option<String>> {
    for bin in candidates {
        let mut cmd = Command::new(bin);
        cmd.args(args).stdin(std::process::Stdio::null());
        termoso_core::posture::hide_console_window(&mut cmd);
        let child = cmd.output();
        let out = match tokio::time::timeout(CLI_TIMEOUT, child).await {
            Err(_) => {
                return Err(DesktopError::invalid(format!(
                    "{bin} did not answer in time"
                )));
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Ok(Err(e)) => return Err(DesktopError::invalid(format!("{bin}: {e}"))),
            Ok(Ok(o)) => o,
        };
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let msg = if err.is_empty() {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            } else {
                err
            };
            return Err(DesktopError::invalid(format!(
                "{bin} exited with {}: {}",
                out.status.code().unwrap_or(-1),
                msg.lines().next().unwrap_or("")
            )));
        }
        return Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()));
    }
    Ok(None)
}

fn strs(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn sort_v4_first(addrs: &mut [String]) {
    addrs.sort_by_key(|a| a.contains(':'));
}

fn parse_tailscale(out: &str) -> Result<Vec<TailnetDevice>> {
    let v: Value = serde_json::from_str(out)
        .map_err(|e| DesktopError::invalid(format!("tailscale status: {e}")))?;
    let mut list = Vec::new();
    let mut push = |p: &Value, this: bool| {
        let name = p["HostName"].as_str().unwrap_or("").to_string();
        let dns = p["DNSName"]
            .as_str()
            .map(|s| s.trim_end_matches('.').to_string())
            .filter(|s| !s.is_empty());
        let mut addrs = strs(p.get("TailscaleIPs"));
        sort_v4_first(&mut addrs);
        if name.is_empty() && dns.is_none() && addrs.is_empty() {
            return;
        }
        list.push(TailnetDevice {
            provider: "tailscale".into(),
            name: if name.is_empty() {
                dns.clone().unwrap_or_default()
            } else {
                name
            },
            dns_name: dns,
            addresses: addrs,
            os: p["OS"].as_str().map(str::to_string),
            online: p["Online"].as_bool().unwrap_or(false),
            tags: strs(p.get("Tags"))
                .into_iter()
                .map(|t| t.trim_start_matches("tag:").to_string())
                .collect(),
            this_device: this,
        });
    };
    if let Some(me) = v.get("Self") {
        push(me, true);
    }
    if let Some(peers) = v.get("Peer").and_then(Value::as_object) {
        for p in peers.values() {
            push(p, false);
        }
    }
    Ok(list)
}

fn parse_netbird(out: &str) -> Result<Vec<TailnetDevice>> {
    let v: Value = serde_json::from_str(out)
        .map_err(|e| DesktopError::invalid(format!("netbird status: {e}")))?;
    let mut list = Vec::new();
    let fqdn = |x: &Value| {
        x.as_str()
            .map(|s| s.trim_end_matches('.').to_string())
            .filter(|s| !s.is_empty())
    };
    let ip = |x: &Value| {
        x.as_str()
            .map(|s| s.split('/').next().unwrap_or(s).to_string())
            .filter(|s| !s.is_empty())
    };
    if let Some(me) = ip(&v["netbirdIp"]) {
        let dns = fqdn(&v["fqdn"]);
        list.push(TailnetDevice {
            provider: "netbird".into(),
            name: dns
                .clone()
                .map(|d| d.split('.').next().unwrap_or(&d).to_string())
                .unwrap_or_else(|| me.clone()),
            dns_name: dns,
            addresses: vec![me],
            os: None,
            online: true,
            tags: Vec::new(),
            this_device: true,
        });
    }
    if let Some(peers) = v["peers"]["details"].as_array() {
        for p in peers {
            let dns = fqdn(&p["fqdn"]);
            let addrs: Vec<String> = ip(&p["netbirdIp"]).into_iter().collect();
            if dns.is_none() && addrs.is_empty() {
                continue;
            }
            list.push(TailnetDevice {
                provider: "netbird".into(),
                name: dns
                    .clone()
                    .map(|d| d.split('.').next().unwrap_or(&d).to_string())
                    .or_else(|| addrs.first().cloned())
                    .unwrap_or_default(),
                dns_name: dns,
                addresses: addrs,
                os: p["os"].as_str().map(str::to_string),
                online: p["connStatus"]
                    .as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case("connected")),
                tags: strs(p.get("groups")),
                this_device: false,
            });
        }
    }
    Ok(list)
}

/// ZeroTier's CLI only knows this node's own assigned addresses (peers are
/// listed by node id without IPs), so the result is the local node per
/// network — useful for the address, not for discovering other machines.
fn parse_zerotier(out: &str) -> Result<Vec<TailnetDevice>> {
    let v: Value = serde_json::from_str(out)
        .map_err(|e| DesktopError::invalid(format!("zerotier-cli: {e}")))?;
    let mut list = Vec::new();
    for n in v.as_array().into_iter().flatten() {
        let mut addrs: Vec<String> = strs(n.get("assignedAddresses"))
            .into_iter()
            .map(|a| a.split('/').next().unwrap_or(&a).to_string())
            .collect();
        sort_v4_first(&mut addrs);
        if addrs.is_empty() {
            continue;
        }
        let name = n["name"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or("ZeroTier");
        list.push(TailnetDevice {
            provider: "zerotier".into(),
            name: format!("{name} (this device)"),
            dns_name: None,
            addresses: addrs,
            os: None,
            online: n["status"].as_str().is_some_and(|s| s == "OK"),
            tags: n["nwid"].as_str().map(str::to_string).into_iter().collect(),
            this_device: true,
        });
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tailscale_json() {
        let out = r#"{"Self":{"HostName":"laptop","DNSName":"laptop.tail1234.ts.net.","TailscaleIPs":["fd7a::1","100.64.0.1"],"OS":"linux","Online":true},
        "Peer":{"k1":{"HostName":"nas","DNSName":"nas.tail1234.ts.net.","TailscaleIPs":["100.64.0.2"],"OS":"linux","Online":false,"Tags":["tag:server"]}}}"#;
        let list = parse_tailscale(out).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list[0].this_device);
        assert_eq!(list[0].addresses[0], "100.64.0.1");
        assert_eq!(list[1].dns_name.as_deref(), Some("nas.tail1234.ts.net"));
        assert_eq!(list[1].tags, vec!["server"]);
        assert!(!list[1].online);
    }

    #[test]
    fn netbird_json() {
        let out = r#"{"netbirdIp":"100.90.0.1/16","fqdn":"me.netbird.cloud","peers":{"details":[{"fqdn":"db.netbird.cloud","netbirdIp":"100.90.0.5","connStatus":"Connected","os":"Linux"}]}}"#;
        let list = parse_netbird(out).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].addresses, vec!["100.90.0.1"]);
        assert_eq!(list[1].name, "db");
        assert!(list[1].online);
    }

    #[test]
    fn zerotier_json() {
        let out = r#"[{"name":"home","nwid":"8056c2e21c000001","status":"OK","assignedAddresses":["10.147.17.5/24"]}]"#;
        let list = parse_zerotier(out).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].addresses, vec!["10.147.17.5"]);
    }
}
