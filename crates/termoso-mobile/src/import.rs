//! Host imports on the phone: a file picked with the system picker (or pasted
//! text) is parsed by the shared parsers in `termoso_core::import` — OpenSSH
//! `ssh_config`, PuTTY `.reg`, MobaXterm bookmarks, SecureCRT settings, ZOC
//! host directory, CSV — into a preview the UI shows before creating hosts.

use std::path::Path;

use termoso_core::import::{self as core, ImportPreview, ImportSource};

use crate::error::{MobileError, Result};

/// A host found in the import, with what a phone can store.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportedHostItem {
    pub label: String,
    pub address: String,
    /// `ssh` or `telnet`.
    pub protocol: String,
    pub port: Option<u16>,
    pub username: String,
    pub password: Option<String>,
    /// Folder path in the source tool, outermost first.
    pub group_path: Vec<String>,
    pub tags: Vec<String>,
    pub notes: String,
    /// Things dropped on the way (jump hosts, proxies, key files not on this device).
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportPreviewItem {
    /// `ssh_config`, `putty`, `csv`, `mobaxterm`, `securecrt`, `zoc`, `winscp`,
    /// `royalts`, `iterm2`, `tabby`, `xshell`.
    pub source: String,
    pub hosts: Vec<ImportedHostItem>,
    pub warnings: Vec<String>,
}

fn source_name(s: ImportSource) -> &'static str {
    match s {
        ImportSource::SshConfig => "ssh_config",
        ImportSource::Putty => "putty",
        ImportSource::Csv => "csv",
        ImportSource::Mobaxterm => "mobaxterm",
        ImportSource::Securecrt => "securecrt",
        ImportSource::Zoc => "zoc",
        ImportSource::Winscp => "winscp",
        ImportSource::Royalts => "royalts",
        ImportSource::Iterm2 => "iterm2",
        ImportSource::Tabby => "tabby",
        ImportSource::Xshell => "xshell",
    }
}

fn parse_source(s: &str) -> Option<ImportSource> {
    Some(match s.trim().to_ascii_lowercase().as_str() {
        "ssh_config" | "sshconfig" | "ssh" => ImportSource::SshConfig,
        "putty" | "reg" => ImportSource::Putty,
        "csv" => ImportSource::Csv,
        "mobaxterm" | "moba" => ImportSource::Mobaxterm,
        "securecrt" => ImportSource::Securecrt,
        "zoc" => ImportSource::Zoc,
        "winscp" => ImportSource::Winscp,
        "royalts" | "royal_ts" | "rtsz" => ImportSource::Royalts,
        "iterm2" | "iterm" => ImportSource::Iterm2,
        "tabby" => ImportSource::Tabby,
        "xshell" | "xsh" => ImportSource::Xshell,
        _ => return None,
    })
}

/// Guess the format from the file name and the first lines.
pub fn detect(text: &str, file_name: &str) -> ImportSource {
    let name = file_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let ext = name.rsplit('.').next().unwrap_or("");
    let head: String = text.chars().take(4096).collect();
    let head_l = head.to_ascii_lowercase();
    if head.trim_start().starts_with("Windows Registry Editor")
        || head.contains("REGEDIT4")
        || ext == "reg"
    {
        return ImportSource::Putty;
    }
    if head_l.contains("[sessions\\") || name == "winscp.ini" {
        return ImportSource::Winscp;
    }
    if head_l.contains("<rtszdocument") || head_l.contains("<royalsshconnection") || ext == "rtsz" {
        return ImportSource::Royalts;
    }
    if head_l.contains("[connection]") || ext == "xsh" {
        return ImportSource::Xshell;
    }
    if head_l.contains("\"profiles\"")
        || head_l.contains("<key>new bookmarks</key>")
        || head_l.contains("com.googlecode.iterm2")
        || head_l.contains("\"custom command\"")
    {
        return ImportSource::Iterm2;
    }
    if head_l.contains("profiles:") && head_l.contains("type: ssh")
        || head_l.contains("connections:") && (ext == "yaml" || ext == "yml")
        || name == "config.yaml" && head_l.contains("profiles:")
    {
        return ImportSource::Tabby;
    }
    if head_l.contains("[bookmarks") || head_l.contains("subrep=") || name.contains("mobaxterm") {
        return ImportSource::Mobaxterm;
    }
    if head_l.contains("vandyke") || head_l.contains("securecrt") || name.contains("securecrt") {
        return ImportSource::Securecrt;
    }
    if head_l.contains("[hostdir")
        || head_l.contains("zoc") && ext == "zhd"
        || ext == "zhd"
        || ext == "zoc"
    {
        return ImportSource::Zoc;
    }
    if ext == "csv" {
        return ImportSource::Csv;
    }
    if head_l.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("host ") || t.starts_with("host\t") || t.starts_with("hostname ")
    }) {
        return ImportSource::SshConfig;
    }
    // A header line with several delimited columns, one of them an address-like name.
    if let Some(first) = head.lines().find(|l| !l.trim().is_empty()) {
        let cols = first.split([',', ';', '\t']).count();
        let l = first.to_ascii_lowercase();
        if cols >= 2 && (l.contains("host") || l.contains("address") || l.contains("ip")) {
            return ImportSource::Csv;
        }
    }
    ImportSource::SshConfig
}

/// Parse pasted text or a picked file into a preview. `source` overrides the guess.
pub fn parse(text: &str, file_name: &str, source: Option<String>) -> Result<ImportPreviewItem> {
    let source = match source.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => parse_source(s)
            .ok_or_else(|| MobileError::invalid(format!("unknown import format: {s}")))?,
        None => detect(text, file_name),
    };
    let mut preview = ImportPreview::new(source, file_name);
    match source {
        ImportSource::SshConfig => {
            core::ssh_config::parse_into(text, Path::new(file_name), &mut preview)
        }
        ImportSource::Putty => core::putty::parse_reg_into(text, &mut preview)?,
        ImportSource::Csv => core::csv::parse_into(text, &mut preview)?,
        ImportSource::Mobaxterm => core::mobaxterm::parse_into(text, &mut preview)?,
        ImportSource::Securecrt => {
            if text.trim_start().starts_with('<') {
                core::securecrt::parse_xml_into(text, &mut preview)?
            } else {
                core::securecrt::parse_ini_into(text, &mut preview)?
            }
        }
        ImportSource::Zoc => core::zoc::parse_into(text, &mut preview)?,
        ImportSource::Winscp => core::winscp::parse_into(text, &mut preview)?,
        ImportSource::Royalts => core::royalts::parse_into(text, &mut preview)?,
        ImportSource::Iterm2 => core::iterm2::parse_into(text, &mut preview)?,
        ImportSource::Tabby => core::tabby::parse_into(text, &mut preview)?,
        ImportSource::Xshell => {
            let label = Path::new(file_name)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            core::xshell::parse_into(text, &label, &[], &mut preview)?
        }
    }
    Ok(flatten(preview))
}

fn flatten(preview: ImportPreview) -> ImportPreviewItem {
    let mut warnings = preview.warnings.clone();
    if !preview.pf_rules.is_empty() {
        warnings.push(format!(
            "{} port forwarding rule(s) are not imported on this device",
            preview.pf_rules.len()
        ));
    }
    if !preview.keys.is_empty() {
        warnings.push(format!(
            "{} key file(s) referenced by the import are not on this device",
            preview.keys.len()
        ));
    }
    let hosts = preview
        .hosts
        .into_iter()
        .map(|h| {
            let mut w = h.warnings.clone();
            if !h.jump_hosts.is_empty() {
                w.push(format!(
                    "jump hosts not imported: {}",
                    h.jump_hosts.join(", ")
                ));
            }
            if let Some(p) = &h.proxy {
                w.push(format!(
                    "proxy not imported: {} {}:{}",
                    p.kind, p.host, p.port
                ));
            }
            if let Some(k) = &h.key_path {
                w.push(format!("key file not on this device: {k}"));
            }
            ImportedHostItem {
                label: h.label,
                address: h.address,
                protocol: h.protocol,
                port: h.port,
                username: h.username,
                password: h.password.filter(|p| !p.is_empty()),
                group_path: h.group_path,
                tags: h.tags,
                notes: h.notes,
                warnings: w,
            }
        })
        .collect();
    ImportPreviewItem {
        source: source_name(preview.source).to_string(),
        hosts,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_formats() {
        assert_eq!(
            detect("Windows Registry Editor Version 5.00\n", "x.txt"),
            ImportSource::Putty
        );
        assert_eq!(
            detect("[Bookmarks]\nSubRep=\n", "MobaXterm Sessions.mxtsessions"),
            ImportSource::Mobaxterm
        );
        assert_eq!(
            detect("<?xml?><VanDyke version=\"3.0\">", "a.xml"),
            ImportSource::Securecrt
        );
        assert_eq!(
            detect(
                "[Configuration]\n[Sessions\\Prod/Web]\nHostName=a\n",
                "WinSCP.ini"
            ),
            ImportSource::Winscp
        );
        assert_eq!(
            detect("<?xml version=\"1.0\"?><RTSZDocument>", "Servers.rtsz"),
            ImportSource::Royalts
        );
        assert_eq!(
            detect("[CONNECTION]\nHost=a\n", "web.xsh"),
            ImportSource::Xshell
        );
        assert_eq!(
            detect("{\"Profiles\": [{\"Name\": \"a\"}]}", "profiles.json"),
            ImportSource::Iterm2
        );
        assert_eq!(
            detect("profiles:\n  - type: ssh\n    name: a\n", "config.yaml"),
            ImportSource::Tabby
        );
        assert_eq!(
            detect("label,address,port\nweb,10.0.0.1,22\n", "hosts.csv"),
            ImportSource::Csv
        );
        assert_eq!(
            detect("Host web\n  HostName 10.0.0.1\n", "config"),
            ImportSource::SshConfig
        );
        assert_eq!(
            detect("host,ip\nweb,10.0.0.1\n", "paste"),
            ImportSource::Csv
        );
    }

    #[test]
    fn parses_ssh_config_text() {
        let p = parse(
            "Host web\n  HostName 203.0.113.5\n  User deploy\n  Port 2222\n",
            "pasted",
            None,
        )
        .unwrap();
        assert_eq!(p.source, "ssh_config");
        assert_eq!(p.hosts.len(), 1);
        assert_eq!(p.hosts[0].address, "203.0.113.5");
        assert_eq!(p.hosts[0].port, Some(2222));
        assert_eq!(p.hosts[0].username, "deploy");
    }
}
