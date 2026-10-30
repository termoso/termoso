//! WinSCP stored sites: `WinSCP.ini` or the file written by *Tools → Export
//! Configuration*. One `[Sessions\Folder/Name]` section per site, names and
//! paths percent-encoded (`%20`), `/` separating folders. `FSProtocol`
//! picks SCP/SFTP (imported) or FTP/WebDAV/S3 (skipped). Saved passwords are
//! obfuscated by WinSCP and are not imported.

use std::collections::BTreeMap;

use super::{ImportPreview, ImportedHost, ImportedProxy};
use crate::error::Result;

const FS_SCP: u32 = 0;
const FS_SFTP_ONLY: u32 = 1;
const FS_SFTP: u32 = 2;
const FS_FTP: u32 = 5;
const FS_WEBDAV: u32 = 6;
const FS_S3: u32 = 7;

type Opts = BTreeMap<String, String>;

pub fn parse_into(text: &str, preview: &mut ImportPreview) -> Result<()> {
    let mut sites: Vec<(String, Opts)> = Vec::new();
    let mut current: Option<(String, Opts)> = None;
    for raw in text.lines() {
        let line = raw.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            if let Some(done) = current.take() {
                sites.push(done);
            }
            current = header
                .strip_prefix("Sessions\\")
                .map(|name| (name.to_string(), Opts::new()));
            continue;
        }
        if let Some((_, opts)) = current.as_mut()
            && let Some((k, v)) = line.split_once('=')
        {
            opts.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    if let Some(done) = current.take() {
        sites.push(done);
    }
    if sites.is_empty() {
        return Err(super::invalid(
            "Not a WinSCP configuration — expected [Sessions\\…] sections (WinSCP.ini or an exported .ini)",
        ));
    }
    for (name, opts) in &sites {
        let mut path: Vec<String> = name
            .split('/')
            .filter(|s| !s.is_empty())
            .map(percent_decode)
            .collect();
        let label = path.pop().unwrap_or_default();
        if path.is_empty() && label == "Default Settings" {
            continue;
        }
        match site(&label, path, opts) {
            Ok(h) => preview.hosts.push(h),
            Err(reason) => preview.warnings.push(format!(
                "Site {} skipped: {reason}",
                if label.is_empty() {
                    "(unnamed)"
                } else {
                    &label
                }
            )),
        }
    }
    Ok(())
}

fn site(label: &str, group: Vec<String>, o: &Opts) -> std::result::Result<ImportedHost, String> {
    match num(o, "fsprotocol").unwrap_or(FS_SFTP) {
        FS_SCP | FS_SFTP_ONLY | FS_SFTP => {}
        FS_FTP => return Err("FTP sites are not supported".into()),
        FS_WEBDAV => return Err("WebDAV sites are not supported".into()),
        FS_S3 => return Err("S3 sites are not supported".into()),
        other => return Err(format!("protocol {other} is not supported")),
    }
    let address = o
        .get("hostname")
        .map(|h| percent_decode(h))
        .unwrap_or_default();
    let address = address.trim().to_string();
    if address.is_empty() {
        return Err("no host name".into());
    }
    let mut host = ImportedHost {
        label: if label.is_empty() {
            address.clone()
        } else {
            label.to_string()
        },
        address,
        protocol: "ssh".into(),
        port: num(o, "portnumber")
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p > 0),
        username: o
            .get("username")
            .map(|u| percent_decode(u))
            .unwrap_or_default(),
        group_path: group,
        notes: o.get("note").map(|n| percent_decode(n)).unwrap_or_default(),
        agent_forwarding: num(o, "agentfwd") == Some(1),
        forward_x11: num(o, "forwardx11") == Some(1),
        ..Default::default()
    };
    if o.get("password").is_some_and(|p| !p.is_empty()) {
        host.warnings
            .push("saved password is obfuscated by WinSCP and was not imported".to_string());
    }
    if let Some(key) = o
        .get("publickeyfile")
        .map(|k| percent_decode(k))
        .filter(|k| !k.trim().is_empty())
    {
        if key.to_ascii_lowercase().ends_with(".ppk") {
            host.warnings.push(format!(
                "{key}: PuTTY .ppk keys must be converted to OpenSSH format before import"
            ));
        }
        host.key_path = Some(key);
    }
    if num(o, "pingtype").is_some_and(|t| t > 0) {
        host.keep_alive_interval = num(o, "pingintervalsecs");
    }
    host.timeout = num(o, "timeout").filter(|t| *t > 0);
    if num(o, "tunnel") == Some(1)
        && let Some(jump) = o
            .get("tunnelhostname")
            .map(|h| percent_decode(h))
            .filter(|h| !h.is_empty())
    {
        let user = o
            .get("tunnelusername")
            .map(|u| percent_decode(u))
            .unwrap_or_default();
        let port = num(o, "tunnelportnumber").unwrap_or(22);
        let mut spec = String::new();
        if !user.is_empty() {
            spec.push_str(&user);
            spec.push('@');
        }
        spec.push_str(&jump);
        if port != 22 {
            spec.push_str(&format!(":{port}"));
        }
        host.jump_hosts.push(spec);
        if o.get("tunnelpassword").is_some_and(|p| !p.is_empty()) {
            host.warnings
                .push("tunnel password was not imported (obfuscated by WinSCP)".to_string());
        }
    }
    match num(o, "proxymethod").unwrap_or(0) {
        0 => {}
        kind @ 1..=3 => {
            let phost = o
                .get("proxyhost")
                .map(|h| percent_decode(h))
                .unwrap_or_default();
            if phost.is_empty() {
                host.warnings
                    .push("proxy without a host was ignored".to_string());
            } else {
                let has_password = o.get("proxypassword").is_some_and(|p| !p.is_empty());
                host.proxy = Some(ImportedProxy {
                    kind: match kind {
                        1 => "socks4",
                        2 => "socks5",
                        _ => "http",
                    }
                    .into(),
                    host: phost,
                    port: num(o, "proxyport")
                        .and_then(|p| u16::try_from(p).ok())
                        .unwrap_or(if kind == 3 { 80 } else { 1080 }),
                    username: o
                        .get("proxyusername")
                        .map(|u| percent_decode(u))
                        .unwrap_or_default(),
                    password: None,
                    has_password,
                });
                if has_password {
                    host.warnings
                        .push("proxy password was not imported (obfuscated by WinSCP)".to_string());
                }
            }
        }
        4 => host
            .warnings
            .push("Telnet/local proxy command is not supported and was ignored".to_string()),
        other => host.warnings.push(format!(
            "proxy method {other} is not supported and was ignored"
        )),
    }
    Ok(host)
}

fn num(o: &Opts, key: &str) -> Option<u32> {
    o.get(key).and_then(|v| v.trim().parse().ok())
}

/// WinSCP stores `%` and spaces as `%25` / `%20`; invalid escapes are kept.
pub(super) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::super::ImportSource;
    use super::*;

    const INI: &str = "[Configuration]\nRandomSeedFile=x\n\n[Sessions\\Default%20Settings]\nPortNumber=22\n\n[Sessions\\Prod/Web%201]\nHostName=web1.example.com\nPortNumber=2200\nUserName=deploy\nPublicKeyFile=C%3A%5Ckeys%5Cdeploy.ppk\nPassword=A35C755A1234\nNote=Primary%20web\nAgentFwd=1\nPingType=1\nPingIntervalSecs=30\nTunnel=1\nTunnelHostName=bastion.example.com\nTunnelUserName=ops\nTunnelPortNumber=2222\n\n[Sessions\\Prod/Files]\nHostName=ftp.example.com\nFSProtocol=5\n\n[Sessions\\Lab]\nHostName=10.0.0.5\nProxyMethod=2\nProxyHost=socks.example.com\nProxyPort=1081\n";

    #[test]
    fn parses_sites() {
        let mut p = ImportPreview::new(ImportSource::Winscp, "WinSCP.ini");
        parse_into(INI, &mut p).unwrap();
        assert_eq!(p.hosts.len(), 2);
        let web = &p.hosts[0];
        assert_eq!(web.label, "Web 1");
        assert_eq!(web.address, "web1.example.com");
        assert_eq!(web.port, Some(2200));
        assert_eq!(web.username, "deploy");
        assert_eq!(web.group_path, vec!["Prod"]);
        assert_eq!(web.key_path.as_deref(), Some("C:\\keys\\deploy.ppk"));
        assert_eq!(web.notes, "Primary web");
        assert!(web.agent_forwarding);
        assert_eq!(web.keep_alive_interval, Some(30));
        assert_eq!(web.jump_hosts, vec!["ops@bastion.example.com:2222"]);
        assert!(web.warnings.iter().any(|w| w.contains("password")));
        assert!(web.warnings.iter().any(|w| w.contains(".ppk")));
        let lab = &p.hosts[1];
        assert_eq!(lab.label, "Lab");
        assert!(lab.group_path.is_empty());
        let proxy = lab.proxy.as_ref().unwrap();
        assert_eq!((proxy.kind.as_str(), proxy.port), ("socks5", 1081));
        assert!(
            p.warnings
                .iter()
                .any(|w| w.contains("Files") && w.contains("FTP"))
        );
    }

    #[test]
    fn rejects_other_ini() {
        let mut p = ImportPreview::new(ImportSource::Winscp, "x.ini");
        assert!(parse_into("[Configuration]\nA=1\n", &mut p).is_err());
    }
}
