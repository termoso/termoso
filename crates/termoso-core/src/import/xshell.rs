//! Xshell session files (`.xsh`, one per session, usually UTF-16): INI with
//! `[CONNECTION]` (Host, Port, Protocol, Description),
//! `[CONNECTION:AUTHENTICATION]` (UserName, UserKey, Password) and
//! `[CONNECTION:SSH]` (ForwardX11). The `Sessions` directory is scanned
//! recursively, sub-folders become groups. Passwords are encrypted with the
//! Xshell master password and keys live in Xshell's own key store, neither
//! is imported.

use std::collections::BTreeMap;
use std::path::Path;

use super::{ImportPreview, ImportedHost};
use crate::error::Result;

type Sections = BTreeMap<String, BTreeMap<String, String>>;

pub fn parse_into(
    text: &str,
    label: &str,
    group: &[String],
    preview: &mut ImportPreview,
) -> Result<()> {
    let sections = parse_ini(text);
    if !sections.contains_key("connection") {
        return Err(super::invalid(
            "Not an Xshell session — expected a [CONNECTION] section (.xsh)",
        ));
    }
    match session(label, group, &sections) {
        Ok(h) => preview.hosts.push(h),
        Err(reason) => preview.warnings.push(format!(
            "Session {} skipped: {reason}",
            if label.is_empty() { "(unnamed)" } else { label }
        )),
    }
    Ok(())
}

pub fn scan_dir(dir: &Path, preview: &mut ImportPreview) -> Result<()> {
    let root = if dir.join("Sessions").is_dir() {
        dir.join("Sessions")
    } else {
        dir.to_path_buf()
    };
    let mut group = Vec::new();
    walk(&root, &mut group, preview, 0)
}

fn walk(
    dir: &Path,
    group: &mut Vec<String>,
    preview: &mut ImportPreview,
    depth: u32,
) -> Result<()> {
    if depth > 16 {
        return Ok(());
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            group.push(name);
            walk(&path, group, preview, depth + 1)?;
            group.pop();
            continue;
        }
        let Some(stem) = name
            .strip_suffix(".xsh")
            .or_else(|| name.strip_suffix(".XSH"))
        else {
            continue;
        };
        let text = match super::read_text(&path, super::MAX_TEXT_FILE) {
            Ok(t) => t,
            Err(e) => {
                preview
                    .warnings
                    .push(format!("{}: {}", super::display(&path), e));
                continue;
            }
        };
        let sections = parse_ini(&text);
        if !sections.contains_key("connection") {
            continue;
        }
        match session(stem, group, &sections) {
            Ok(h) => preview.hosts.push(h),
            Err(reason) => preview
                .warnings
                .push(format!("Session {stem} skipped: {reason}")),
        }
    }
    Ok(())
}

fn session(
    label: &str,
    group: &[String],
    s: &Sections,
) -> std::result::Result<ImportedHost, String> {
    let get = |section: &str, key: &str| -> Option<&str> {
        s.get(section)
            .and_then(|m| m.get(key))
            .map(String::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    let protocol = match get("connection", "protocol")
        .unwrap_or("SSH")
        .to_ascii_uppercase()
        .as_str()
    {
        "SSH" | "SFTP" => "ssh",
        "TELNET" => "telnet",
        "SERIAL" => return Err("serial sessions are not supported".into()),
        other => return Err(format!("{other} sessions are not supported")),
    };
    let address = get("connection", "host").ok_or("no host name")?;
    let mut host = ImportedHost {
        label: if label.is_empty() {
            address.to_string()
        } else {
            label.to_string()
        },
        address: address.to_string(),
        protocol: protocol.into(),
        port: get("connection", "port")
            .and_then(|p| p.parse::<u16>().ok())
            .filter(|p| *p > 0),
        username: get("connection:authentication", "username")
            .unwrap_or("")
            .to_string(),
        group_path: group.to_vec(),
        notes: get("connection", "description").unwrap_or("").to_string(),
        forward_x11: get("connection:ssh", "forwardx11") == Some("1"),
        ..Default::default()
    };
    if get("connection:authentication", "password").is_some() {
        host.warnings.push(
            "saved password is encrypted with the Xshell master password and was not imported"
                .to_string(),
        );
    }
    if let Some(key) = get("connection:authentication", "userkey") {
        host.warnings.push(format!(
            "key \"{key}\" lives in Xshell's user key store — export it in OpenSSH format and attach it to the host"
        ));
    }
    if let Some(proxy) = get("connection:proxy", "proxyname") {
        host.warnings.push(format!(
            "proxy \"{proxy}\" is defined in Xshell's proxy list and was not imported"
        ));
    }
    if s.get("connection:ssh:tunneling")
        .and_then(|m| m.get("count"))
        .and_then(|c| c.trim().parse::<u32>().ok())
        .is_some_and(|c| c > 0)
    {
        host.warnings
            .push("port forwarding rules were not imported".to_string());
    }
    Ok(host)
}

fn parse_ini(text: &str) -> Sections {
    let mut out = Sections::new();
    let mut current = String::new();
    for raw in text.lines() {
        let line = raw.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = header.trim().to_ascii_lowercase();
            out.entry(current.clone()).or_default();
            continue;
        }
        if current.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.entry(current.clone())
                .or_default()
                .insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::ImportSource;
    use super::*;

    const XSH: &str = "\u{feff}[CONNECTION]\nHost=web1.example.com\nPort=2200\nProtocol=SSH\nDescription=Primary web\nVersion=7.0\n\n[CONNECTION:AUTHENTICATION]\nUserName=deploy\nPassword=3A2F8C\nUserKey=deploy_ed25519\nMethod=2\n\n[CONNECTION:SSH]\nForwardX11=1\nCompression=1\n";

    #[test]
    fn parses_session() {
        let mut p = ImportPreview::new(ImportSource::Xshell, "web1.xsh");
        parse_into(XSH, "web1", &["Prod".to_string()], &mut p).unwrap();
        assert_eq!(p.hosts.len(), 1);
        let h = &p.hosts[0];
        assert_eq!(h.label, "web1");
        assert_eq!(h.address, "web1.example.com");
        assert_eq!(h.port, Some(2200));
        assert_eq!(h.username, "deploy");
        assert_eq!(h.group_path, vec!["Prod"]);
        assert_eq!(h.notes, "Primary web");
        assert!(h.forward_x11);
        assert!(h.key_path.is_none());
        assert_eq!(h.warnings.len(), 2);
    }

    #[test]
    fn skips_serial_and_rejects_other_ini() {
        let mut p = ImportPreview::new(ImportSource::Xshell, "com1.xsh");
        parse_into(
            "[CONNECTION]\nProtocol=SERIAL\nHost=COM1\n",
            "com1",
            &[],
            &mut p,
        )
        .unwrap();
        assert!(p.hosts.is_empty());
        assert!(p.warnings[0].contains("serial"));
        assert!(parse_into("[General]\nA=1\n", "x", &[], &mut p).is_err());
    }

    #[test]
    fn scans_sessions_tree() {
        let dir = std::env::temp_dir().join(format!("termoso-xsh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Sessions").join("Lab")).unwrap();
        std::fs::write(
            dir.join("Sessions").join("edge.xsh"),
            "[CONNECTION]\nHost=edge\n",
        )
        .unwrap();
        // UTF-16 LE with BOM, the way Xshell writes.
        let mut utf16 = vec![0xff, 0xfe];
        for u in "[CONNECTION]\nHost=lab1\nPort=22\n".encode_utf16() {
            utf16.extend_from_slice(&u.to_le_bytes());
        }
        std::fs::write(dir.join("Sessions").join("Lab").join("lab1.xsh"), utf16).unwrap();
        let mut p = ImportPreview::new(ImportSource::Xshell, "dir");
        scan_dir(&dir, &mut p).unwrap();
        let mut labels: Vec<_> = p
            .hosts
            .iter()
            .map(|h| (h.label.clone(), h.group_path.clone()))
            .collect();
        labels.sort();
        assert_eq!(
            labels,
            vec![
                ("edge".to_string(), vec![]),
                ("lab1".to_string(), vec!["Lab".to_string()])
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
