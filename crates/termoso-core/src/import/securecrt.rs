//! SecureCRT sessions: the `Config/Sessions` tree (one `.ini` per session,
//! directories are folders), a single session `.ini`, or the XML written by
//! File → Export Settings. Options are typed lines — `S:"Key"=text`,
//! `D:"Key"=hex`, `Z:"Key"=count` followed by indented items. Saved
//! passwords are encrypted with the config passphrase and are not imported.

use std::collections::BTreeMap;
use std::path::Path;

use super::{ImportPreview, ImportedHost};
use crate::error::Result;

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Str(String),
    Num(u32),
    List(Vec<String>),
}

type Options = BTreeMap<String, Value>;

/// A single session file: the file carries no name, the host stands in.
pub fn parse_ini_into(text: &str, preview: &mut ImportPreview) -> Result<()> {
    let opts = parse_ini(text);
    if opts.is_empty() {
        return Err(super::invalid(
            "Not a SecureCRT session — expected S:\"…\"= / D:\"…\"= lines (Config/Sessions/*.ini)",
        ));
    }
    let label = str_opt(&opts, "Hostname").unwrap_or("SecureCRT session");
    push(label, &[], &opts, preview);
    Ok(())
}

/// `Config/Sessions` (or the `Config` directory above it): directories
/// become groups, `Default.ini` and `__FolderData__.ini` are bookkeeping.
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
            .strip_suffix(".ini")
            .or_else(|| name.strip_suffix(".INI"))
        else {
            continue;
        };
        if stem == "__FolderData__" || (depth == 0 && stem.eq_ignore_ascii_case("Default")) {
            continue;
        }
        let text = match super::read_text(&path, super::MAX_TEXT_FILE) {
            Ok(t) => t,
            Err(e) => {
                preview
                    .warnings
                    .push(format!("{}: {}", super::display(&path), e));
                continue;
            }
        };
        let opts = parse_ini(&text);
        if opts.is_empty() {
            continue;
        }
        push(stem, group, &opts, preview);
    }
    Ok(())
}

/// File → Export Settings XML (`<VanDyke><key name="Sessions">…`).
pub fn parse_xml_into(text: &str, preview: &mut ImportPreview) -> Result<()> {
    let root = parse_xml(text)
        .ok_or_else(|| super::invalid("Not a SecureCRT settings export — malformed XML"))?;
    let sessions = find_key(&root, "Sessions").ok_or_else(|| {
        super::invalid(
            "Not a SecureCRT settings export — no <key name=\"Sessions\"> (File → Export Settings)",
        )
    })?;
    let mut group = Vec::new();
    walk_xml(sessions, &mut group, preview);
    Ok(())
}

fn walk_xml(node: &Node, group: &mut Vec<String>, preview: &mut ImportPreview) {
    for child in node.children.iter().filter(|c| c.tag == "key") {
        let name = child.name.clone().unwrap_or_default();
        let opts = options_from_xml(child);
        if opts.contains_key("Hostname") || opts.contains_key("Protocol Name") {
            if name.eq_ignore_ascii_case("Default") && group.is_empty() {
                continue;
            }
            push(&name, group, &opts, preview);
        } else {
            group.push(name);
            walk_xml(child, group, preview);
            group.pop();
        }
    }
}

fn push(label: &str, group: &[String], opts: &Options, preview: &mut ImportPreview) {
    match session_host(label, group, opts) {
        Ok(h) => preview.hosts.push(h),
        Err(reason) => preview
            .warnings
            .push(format!("Session {label} skipped: {reason}")),
    }
}

fn session_host(
    label: &str,
    group: &[String],
    o: &Options,
) -> std::result::Result<ImportedHost, String> {
    let protocol = str_opt(o, "Protocol Name").unwrap_or("SSH2");
    let kind = match protocol {
        "SSH2" | "SSH1" => "ssh",
        "Telnet" => "telnet",
        other => return Err(format!("protocol {other} is not supported")),
    };
    let address = str_opt(o, "Hostname").ok_or_else(|| "no host name".to_string())?;
    let mut host = ImportedHost {
        label: label.to_string(),
        address: address.to_string(),
        protocol: kind.into(),
        port: num(o, &format!("[{protocol}] Port"))
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p > 0),
        username: str_opt(o, "Username").unwrap_or("").to_string(),
        group_path: group.to_vec(),
        ..Default::default()
    };
    if let Some(Value::List(lines)) = o.get("Description") {
        host.notes = lines.join("\n").trim().to_string();
    }
    if kind == "telnet" {
        return Ok(host);
    }
    host.forward_x11 = num(o, "Forward X11") == Some(1);
    if num(o, "Use Global Public Key").unwrap_or(1) == 0
        && let Some(key) = str_opt(o, "Identity Filename V2")
    {
        if key.contains("${") {
            host.warnings.push(format!(
                "Key path {key} uses a SecureCRT variable — pick the key file after import"
            ));
        } else {
            host.key_path = Some(key.to_string());
        }
    }
    match str_opt(o, "Firewall Name") {
        None => {}
        Some(fw) if fw.eq_ignore_ascii_case("none") => {}
        Some(fw) => match fw.get(..8).filter(|p| p.eq_ignore_ascii_case("session:")) {
            Some(_) => {
                let leaf = fw[8..].rsplit(['\\', '/']).next().unwrap_or("").trim();
                if !leaf.is_empty() {
                    host.jump_hosts.push(leaf.to_string());
                }
            }
            None => host
                .warnings
                .push(format!("Firewall/proxy {fw} is not imported")),
        },
    }
    if num(o, "Session Password Saved") == Some(1) {
        host.warnings
            .push("Saved password is encrypted by SecureCRT and was not imported".into());
    }
    Ok(host)
}

fn str_opt<'a>(o: &'a Options, key: &str) -> Option<&'a str> {
    match o.get(key) {
        Some(Value::Str(s)) => Some(s.trim()).filter(|s| !s.is_empty()),
        _ => None,
    }
}

fn num(o: &Options, key: &str) -> Option<u32> {
    match o.get(key) {
        Some(Value::Num(n)) => Some(*n),
        Some(Value::Str(s)) => s.trim().parse().ok(),
        _ => None,
    }
}

fn parse_ini(text: &str) -> Options {
    let mut opts = Options::new();
    let mut lines = text.lines().peekable();
    while let Some(raw) = lines.next() {
        let line = raw.trim_start_matches('\u{feff}');
        let Some((kind, rest)) = line.split_once(":\"") else {
            continue;
        };
        let Some((key, value)) = rest.split_once("\"=") else {
            continue;
        };
        match kind.trim() {
            "S" => {
                opts.insert(key.to_string(), Value::Str(value.trim_end().to_string()));
            }
            "D" => {
                if let Ok(n) = u32::from_str_radix(value.trim(), 16) {
                    opts.insert(key.to_string(), Value::Num(n));
                }
            }
            "Z" | "B" => {
                let mut items = Vec::new();
                while let Some(next) = lines.peek() {
                    if next.starts_with(' ') || next.starts_with('\t') {
                        items.push(next.trim().to_string());
                        lines.next();
                    } else {
                        break;
                    }
                }
                if kind.trim() == "Z" {
                    opts.insert(key.to_string(), Value::List(items));
                }
            }
            _ => {}
        }
    }
    opts
}

fn options_from_xml(node: &Node) -> Options {
    let mut opts = Options::new();
    for c in &node.children {
        let Some(name) = c.name.clone() else {
            continue;
        };
        match c.tag.as_str() {
            "string" => {
                opts.insert(name, Value::Str(c.text.trim().to_string()));
            }
            "dword" => {
                if let Ok(n) = c.text.trim().parse() {
                    opts.insert(name, Value::Num(n));
                }
            }
            "array" => {
                let items = c
                    .children
                    .iter()
                    .filter(|s| s.tag == "string")
                    .map(|s| s.text.trim().to_string())
                    .collect();
                opts.insert(name, Value::List(items));
            }
            _ => {}
        }
    }
    opts
}

fn find_key<'a>(node: &'a Node, name: &str) -> Option<&'a Node> {
    if node.tag == "key" && node.name.as_deref() == Some(name) {
        return Some(node);
    }
    node.children.iter().find_map(|c| find_key(c, name))
}

#[derive(Debug, Default)]
pub(super) struct Node {
    pub(super) tag: String,
    pub(super) name: Option<String>,
    pub(super) text: String,
    pub(super) children: Vec<Node>,
}

/// Just enough XML for VanDyke exports: elements, a `name` attribute,
/// text and the five predefined entities. Comments and processing
/// instructions are skipped.
pub(super) fn parse_xml(input: &str) -> Option<Node> {
    let mut stack: Vec<Node> = vec![Node {
        tag: "#root".into(),
        ..Default::default()
    }];
    let mut rest = input;
    while let Some(lt) = rest.find('<') {
        stack.last_mut()?.text.push_str(&unescape(&rest[..lt]));
        rest = &rest[lt + 1..];
        if rest.starts_with("!--") {
            let end = rest.find("-->")?;
            rest = &rest[end + 3..];
            continue;
        }
        if rest.starts_with('?') || rest.starts_with('!') {
            let end = rest.find('>')?;
            rest = &rest[end + 1..];
            continue;
        }
        let end = rest.find('>')?;
        let body = &rest[..end];
        rest = &rest[end + 1..];
        if body.starts_with('/') {
            let node = stack.pop()?;
            stack.last_mut()?.children.push(node);
            continue;
        }
        let self_closing = body.ends_with('/');
        let body = body.trim_end_matches('/').trim();
        let (tag, attrs) = body.split_once(char::is_whitespace).unwrap_or((body, ""));
        let node = Node {
            tag: tag.to_string(),
            name: attr(attrs, "name"),
            ..Default::default()
        };
        if self_closing {
            stack.last_mut()?.children.push(node);
        } else {
            stack.push(node);
        }
    }
    let root = stack.pop()?;
    stack.is_empty().then_some(root)
}

fn attr(attrs: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = attrs.find(&needle)? + needle.len();
    let end = attrs[start..].find('"')?;
    Some(unescape(&attrs[start..start + end]))
}

fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::super::ImportSource;
    use super::*;

    const INI: &str = "\u{feff}S:\"Username\"=admin\nS:\"Password V2\"=02:4ffff611d02e5d\nD:\"Session Password Saved\"=00000001\nB:\"Normal Font v2\"=00000060\n f3 ff ff ff 00 00\n 63 00 69 00\nD:\"Is Session\"=00000001\nS:\"Protocol Name\"=SSH2\nD:\"Forward X11\"=00000001\nS:\"Hostname\"=172.10.1.5\nS:\"Firewall Name\"=Session:Prod\\Bastion\nD:\"[SSH2] Port\"=00000016\nD:\"Use Global Public Key\"=00000000\nS:\"Identity Filename V2\"=/Users/me/.ssh/id_rsa\nZ:\"Description\"=00000002\n Core switch\n rack 4\n";

    #[test]
    fn parses_session_ini() {
        let mut p = ImportPreview::new(ImportSource::Securecrt, "test");
        parse_ini_into(INI, &mut p).unwrap();
        assert_eq!(p.hosts.len(), 1);
        let h = &p.hosts[0];
        assert_eq!(h.label, "172.10.1.5");
        assert_eq!(h.address, "172.10.1.5");
        assert_eq!(h.port, Some(22));
        assert_eq!(h.username, "admin");
        assert!(h.forward_x11);
        assert_eq!(h.key_path.as_deref(), Some("/Users/me/.ssh/id_rsa"));
        assert_eq!(h.jump_hosts, vec!["Bastion"]);
        assert_eq!(h.notes, "Core switch\nrack 4");
        assert!(h.warnings.iter().any(|w| w.contains("password")));
    }

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<VanDyke version="3.0">
  <key name="Sessions">
    <key name="Default">
      <string name="Protocol Name">SSH2</string>
      <string name="Hostname"></string>
    </key>
    <key name="Production">
      <key name="Gateway">
        <string name="Protocol Name">SSH2</string>
        <string name="Hostname">gateway.example.com</string>
        <dword name="[SSH2] Port">2202</dword>
        <string name="Username">deploy</string>
        <dword name="Use Global Public Key">0</dword>
        <string name="Identity Filename V2">/Users/deploy/.ssh/id_ed25519</string>
        <array name="Description">
          <string>Edge &amp; bastion</string>
        </array>
      </key>
      <key name="Switch">
        <string name="Protocol Name">Telnet</string>
        <string name="Hostname">10.0.0.2</string>
        <dword name="[Telnet] Port">23</dword>
        <array name="Description"/>
      </key>
    </key>
    <key name="Ignored RDP">
      <string name="Protocol Name">RDP</string>
      <string name="Hostname">desktop.example.com</string>
      <dword name="Port">3389</dword>
    </key>
  </key>
</VanDyke>
"#;

    #[test]
    fn parses_settings_export() {
        let mut p = ImportPreview::new(ImportSource::Securecrt, "test");
        parse_xml_into(XML, &mut p).unwrap();
        assert_eq!(p.hosts.len(), 2);
        let gw = &p.hosts[0];
        assert_eq!(gw.label, "Gateway");
        assert_eq!(gw.group_path, vec!["Production"]);
        assert_eq!(gw.port, Some(2202));
        assert_eq!(gw.username, "deploy");
        assert_eq!(
            gw.key_path.as_deref(),
            Some("/Users/deploy/.ssh/id_ed25519")
        );
        assert_eq!(gw.notes, "Edge & bastion");
        let sw = &p.hosts[1];
        assert_eq!(sw.protocol, "telnet");
        assert_eq!(sw.port, Some(23));
        assert!(p.warnings.iter().any(|w| w.contains("Ignored RDP")));
    }

    #[test]
    fn scans_sessions_tree() {
        let root = std::env::temp_dir().join(format!("termoso-scrt-{}", uuid::Uuid::new_v4()));
        let sessions = root.join("Config").join("Sessions").join("Prod");
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(
            sessions.join("__FolderData__.ini"),
            "Z:\"Session List V2\"=00000000\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Config").join("Sessions").join("Default.ini"),
            "S:\"Hostname\"=\n",
        )
        .unwrap();
        std::fs::write(
            sessions.join("web.ini"),
            "S:\"Hostname\"=web\nS:\"Username\"=root\n",
        )
        .unwrap();
        let mut p = ImportPreview::new(ImportSource::Securecrt, "test");
        scan_dir(&root.join("Config"), &mut p).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(p.hosts.len(), 1);
        assert_eq!(p.hosts[0].label, "web");
        assert_eq!(p.hosts[0].group_path, vec!["Prod"]);
        assert_eq!(p.hosts[0].username, "root");
    }

    #[test]
    fn rejects_other_text() {
        let mut p = ImportPreview::new(ImportSource::Securecrt, "test");
        assert!(parse_ini_into("Host foo\n", &mut p).is_err());
        assert!(parse_xml_into("<html></html>", &mut p).is_err());
    }
}
