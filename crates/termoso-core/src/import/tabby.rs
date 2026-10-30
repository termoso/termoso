//! Tabby `config.yaml`: `profiles:` entries of `type: ssh` / `type: telnet`
//! (`options.host/port/user/privateKeys/jumpHost/forwardedPorts/
//! socksProxyHost/httpProxyHost/agentForward/x11`) plus the legacy
//! `ssh: connections:` list. `jumpHost` references another profile by id and
//! is resolved to `user@host:port`. Passwords live in the system keychain
//! and are not part of the file. Only the subset of YAML that js-yaml writes
//! is understood (block mappings and sequences, quoted scalars).

use std::collections::HashMap;

use super::{ImportPreview, ImportedHost, ImportedPfRule, ImportedProxy, PfKind};
use crate::error::Result;

#[derive(Debug, Clone, PartialEq)]
enum Yaml {
    Null,
    Str(String),
    Seq(Vec<Yaml>),
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    fn get(&self, key: &str) -> Option<&Yaml> {
        match self {
            Yaml::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn str(&self) -> Option<&str> {
        match self {
            Yaml::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
    fn seq(&self) -> &[Yaml] {
        match self {
            Yaml::Seq(s) => s,
            _ => &[],
        }
    }
    fn text(&self, key: &str) -> Option<&str> {
        self.get(key)
            .and_then(Yaml::str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }
    fn num(&self, key: &str) -> Option<u32> {
        self.text(key)
            .and_then(|v| v.parse::<f64>().ok())
            .map(|f| f as u32)
    }
    fn flag(&self, key: &str) -> bool {
        self.text(key)
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }
}

pub fn parse_into(text: &str, preview: &mut ImportPreview) -> Result<()> {
    let doc = parse_yaml(text);
    let profiles: Vec<&Yaml> = doc
        .get("profiles")
        .map(Yaml::seq)
        .unwrap_or(&[])
        .iter()
        .filter(|p| p.text("type").is_some_and(|t| t == "ssh" || t == "telnet"))
        .collect();
    let legacy: &[Yaml] = doc
        .get("ssh")
        .and_then(|s| s.get("connections"))
        .map(Yaml::seq)
        .unwrap_or(&[]);
    if profiles.is_empty() && legacy.is_empty() {
        return Err(super::invalid(
            "No SSH profiles found — expected a Tabby config.yaml with profiles of type ssh",
        ));
    }
    let by_id: HashMap<&str, &Yaml> = profiles
        .iter()
        .filter_map(|p| Some((p.text("id")?, *p)))
        .collect();
    for p in &profiles {
        let label = p.text("name").unwrap_or("");
        match profile(p, label, &by_id, &mut preview.pf_rules) {
            Ok(h) => preview.hosts.push(h),
            Err(reason) => preview.warnings.push(format!(
                "Profile {} skipped: {reason}",
                if label.is_empty() { "(unnamed)" } else { label }
            )),
        }
    }
    for c in legacy {
        let label = c.text("name").unwrap_or("");
        let Some(address) = c.text("host") else {
            preview
                .warnings
                .push(format!("Connection {label} skipped: no host name"));
            continue;
        };
        let mut host = ImportedHost {
            label: if label.is_empty() {
                address.to_string()
            } else {
                label.to_string()
            },
            address: address.to_string(),
            protocol: "ssh".into(),
            port: c.num("port").and_then(|p| u16::try_from(p).ok()),
            username: c.text("user").unwrap_or("").to_string(),
            group_path: group_of(c),
            key_path: c.text("privateKey").map(str::to_string),
            agent_forwarding: c.flag("agentForward"),
            forward_x11: c.flag("x11"),
            ..Default::default()
        };
        if c.text("password").is_some() {
            host.password = c.text("password").map(str::to_string);
            host.has_password = true;
        }
        preview.hosts.push(host);
    }
    Ok(())
}

fn group_of(p: &Yaml) -> Vec<String> {
    p.text("group")
        .map(|g| {
            g.split('/')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn profile(
    p: &Yaml,
    label: &str,
    by_id: &HashMap<&str, &Yaml>,
    pf: &mut Vec<ImportedPfRule>,
) -> std::result::Result<ImportedHost, String> {
    let o = p.get("options").ok_or("no options")?;
    let address = o.text("host").ok_or("no host name")?;
    let protocol = p.text("type").unwrap_or("ssh");
    let mut host = ImportedHost {
        label: if label.is_empty() {
            address.to_string()
        } else {
            label.to_string()
        },
        address: address.to_string(),
        protocol: protocol.into(),
        port: o
            .num("port")
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p > 0),
        username: o.text("user").unwrap_or("").to_string(),
        group_path: group_of(p),
        agent_forwarding: o.flag("agentForward"),
        forward_x11: o.flag("x11"),
        keep_alive_interval: o
            .num("keepaliveInterval")
            .filter(|ms| *ms > 0)
            .map(|ms| (ms / 1000).max(1)),
        timeout: o
            .num("readyTimeout")
            .filter(|ms| *ms > 0)
            .map(|ms| (ms / 1000).max(1)),
        ..Default::default()
    };
    if protocol == "ssh" {
        let keys: Vec<&str> = o
            .get("privateKeys")
            .map(Yaml::seq)
            .unwrap_or(&[])
            .iter()
            .filter_map(Yaml::str)
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .collect();
        if let Some(first) = keys.first() {
            host.key_path = Some((*first).to_string());
            if keys.len() > 1 {
                host.warnings.push(format!(
                    "only the first of {} key files is attached",
                    keys.len()
                ));
            }
        }
        if let Some(jump) = o.text("jumpHost") {
            match by_id.get(jump).and_then(|j| j.get("options")) {
                Some(jo) => {
                    let mut spec = String::new();
                    if let Some(u) = jo.text("user") {
                        spec.push_str(u);
                        spec.push('@');
                    }
                    spec.push_str(jo.text("host").unwrap_or(jump));
                    if let Some(port) = jo.num("port").filter(|p| *p != 22) {
                        spec.push_str(&format!(":{port}"));
                    }
                    host.jump_hosts.push(spec);
                }
                None => host.warnings.push(format!(
                    "jump host profile \"{jump}\" is not in this file and was not imported"
                )),
            }
        }
        if let Some(h) = o.text("socksProxyHost") {
            host.proxy = Some(ImportedProxy {
                kind: "socks5".into(),
                host: h.to_string(),
                port: o
                    .num("socksProxyPort")
                    .and_then(|p| u16::try_from(p).ok())
                    .unwrap_or(1080),
                username: String::new(),
                password: None,
                has_password: false,
            });
        } else if let Some(h) = o.text("httpProxyHost") {
            host.proxy = Some(ImportedProxy {
                kind: "http".into(),
                host: h.to_string(),
                port: o
                    .num("httpProxyPort")
                    .and_then(|p| u16::try_from(p).ok())
                    .unwrap_or(8080),
                username: String::new(),
                password: None,
                has_password: false,
            });
        }
        if o.text("proxyCommand").is_some() {
            host.warnings
                .push("proxy command is not supported and was ignored".to_string());
        }
        for rule in o.get("forwardedPorts").map(Yaml::seq).unwrap_or(&[]) {
            let kind = match rule.text("type").unwrap_or("") {
                "Local" | "local" => PfKind::Local,
                "Remote" | "remote" => PfKind::Remote,
                "Dynamic" | "dynamic" => PfKind::Dynamic,
                other => {
                    host.warnings
                        .push(format!("port forwarding of type \"{other}\" was ignored"));
                    continue;
                }
            };
            let Some(local_port) = rule.num("port").and_then(|p| u16::try_from(p).ok()) else {
                continue;
            };
            pf.push(ImportedPfRule {
                host_label: host.label.clone(),
                kind,
                bound_address: rule.text("host").unwrap_or("").to_string(),
                local_port,
                remote_host: rule.text("targetAddress").unwrap_or("").to_string(),
                remote_port: rule
                    .num("targetPort")
                    .and_then(|p| u16::try_from(p).ok())
                    .unwrap_or(0),
            });
        }
    }
    Ok(host)
}

struct Line<'a> {
    indent: usize,
    text: &'a str,
}

fn parse_yaml(text: &str) -> Yaml {
    let lines: Vec<Line> = text
        .lines()
        .map(|l| l.trim_start_matches('\u{feff}'))
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && t != "---" && t != "..."
        })
        .map(|l| Line {
            indent: l.len() - l.trim_start().len(),
            text: l.trim(),
        })
        .collect();
    let mut idx = 0;
    if lines.is_empty() {
        return Yaml::Null;
    }
    let indent = lines[0].indent;
    block(&lines, &mut idx, indent)
}

fn block(lines: &[Line], idx: &mut usize, indent: usize) -> Yaml {
    if *idx >= lines.len() {
        return Yaml::Null;
    }
    if is_item(lines[*idx].text) {
        sequence(lines, idx, indent)
    } else {
        mapping(lines, idx, indent)
    }
}

fn is_item(text: &str) -> bool {
    text == "-" || text.starts_with("- ")
}

fn sequence(lines: &[Line], idx: &mut usize, indent: usize) -> Yaml {
    let mut out = Vec::new();
    while *idx < lines.len() {
        let line = &lines[*idx];
        if line.indent < indent || (line.indent == indent && !is_item(line.text)) {
            break;
        }
        if line.indent > indent {
            *idx += 1;
            continue;
        }
        let item = line.text[1..].trim_start();
        if item.is_empty() {
            *idx += 1;
            out.push(nested(lines, idx, indent));
        } else if is_item(item) || item.contains(": ") || item.ends_with(':') {
            let inner = indent + (line.text.len() - item.len());
            let virtual_line = Line {
                indent: inner,
                text: item,
            };
            let mut patched: Vec<Line> = Vec::with_capacity(lines.len());
            patched.extend(lines[..*idx].iter().map(|l| Line {
                indent: l.indent,
                text: l.text,
            }));
            patched.push(virtual_line);
            patched.extend(lines[*idx + 1..].iter().map(|l| Line {
                indent: l.indent,
                text: l.text,
            }));
            out.push(block(&patched, idx, inner));
        } else {
            *idx += 1;
            out.push(scalar(item));
        }
    }
    Yaml::Seq(out)
}

fn mapping(lines: &[Line], idx: &mut usize, indent: usize) -> Yaml {
    let mut out = Vec::new();
    while *idx < lines.len() {
        let line = &lines[*idx];
        if line.indent < indent || (line.indent == indent && is_item(line.text)) {
            break;
        }
        if line.indent > indent {
            *idx += 1;
            continue;
        }
        let Some((key, value)) = split_key(line.text) else {
            *idx += 1;
            continue;
        };
        *idx += 1;
        let value = if value.is_empty() {
            nested(lines, idx, indent)
        } else if value == "|" || value == ">" || value == "|-" || value == ">-" {
            let mut parts = Vec::new();
            while *idx < lines.len() && lines[*idx].indent > indent {
                parts.push(lines[*idx].text);
                *idx += 1;
            }
            Yaml::Str(parts.join(if value.starts_with('|') { "\n" } else { " " }))
        } else {
            scalar(value)
        };
        out.push((key, value));
    }
    Yaml::Map(out)
}

/// Value of a key whose content starts on the following lines: a deeper
/// block, or a sequence at the same indent (`key:\n- a`).
fn nested(lines: &[Line], idx: &mut usize, indent: usize) -> Yaml {
    match lines.get(*idx) {
        Some(next) if next.indent > indent => block(lines, idx, next.indent),
        Some(next) if next.indent == indent && is_item(next.text) => sequence(lines, idx, indent),
        _ => Yaml::Null,
    }
}

fn split_key(text: &str) -> Option<(String, &str)> {
    let (raw_key, rest) = if text.starts_with('"') || text.starts_with('\'') {
        let q = text.chars().next()?;
        let end = text[1..].find(q)? + 1;
        (&text[..=end], text[end + 1..].strip_prefix(':')?)
    } else if let Some(pos) = text.find(": ") {
        (&text[..pos], &text[pos + 1..])
    } else {
        (text.strip_suffix(':')?, "")
    };
    Some((unquote(raw_key), strip_comment(rest.trim())))
}

fn strip_comment(v: &str) -> &str {
    let Some(q) = v.chars().next().filter(|c| *c == '"' || *c == '\'') else {
        return match v.find(" #") {
            Some(pos) => v[..pos].trim_end(),
            None => v,
        };
    };
    let bytes = v.as_bytes();
    let mut i = 1;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if q == '"' && c == '\\' {
            i += 2;
            continue;
        }
        if c == q {
            if q == '\'' && bytes.get(i + 1) == Some(&b'\'') {
                i += 2;
                continue;
            }
            return &v[..=i];
        }
        i += 1;
    }
    v
}

fn scalar(raw: &str) -> Yaml {
    let v = strip_comment(raw.trim());
    match v {
        "" | "~" | "null" | "Null" | "NULL" => Yaml::Null,
        "[]" => Yaml::Seq(Vec::new()),
        "{}" => Yaml::Map(Vec::new()),
        _ if v.starts_with('[') && v.ends_with(']') => Yaml::Seq(
            v[1..v.len() - 1]
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| Yaml::Str(unquote(s)))
                .collect(),
        ),
        _ => Yaml::Str(unquote(v)),
    }
}

fn unquote(v: &str) -> String {
    let v = v.trim();
    if let Some(inner) = v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some(other) => out.push(other),
                    None => {}
                }
            } else {
                out.push(c);
            }
        }
        return out;
    }
    if let Some(inner) = v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return inner.replace("''", "'");
    }
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::super::ImportSource;
    use super::*;

    const CONFIG: &str = r#"version: 7
profiles:
  - type: ssh
    name: web1
    group: Prod/Web
    icon: fas fa-server
    options:
      host: web1.example.com
      port: 2200
      user: deploy
      auth: publicKey
      privateKeys:
        - /home/me/.ssh/id_ed25519
        - /home/me/.ssh/id_rsa
      jumpHost: ssh:custom-bastion-1
      agentForward: true
      x11: false
      keepaliveInterval: 30000
      forwardedPorts:
        - type: Local
          host: 127.0.0.1
          port: 8080
          targetAddress: localhost
          targetPort: 80
    id: ssh:custom-web1-1
  - type: ssh
    name: "bastion: ops"
    options:
      host: bastion.example.com
      port: 2222
      user: ops
      socksProxyHost: socks.example.com
      socksProxyPort: 1081
    id: ssh:custom-bastion-1
  - type: telnet
    name: switch
    options:
      host: 10.0.0.1
      port: 23
  - type: local
    name: zsh
hotkeys:
  toggle-window: []
"#;

    #[test]
    fn parses_profiles() {
        let mut p = ImportPreview::new(ImportSource::Tabby, "config.yaml");
        parse_into(CONFIG, &mut p).unwrap();
        assert_eq!(p.hosts.len(), 3, "{:?}", p.warnings);
        let web = &p.hosts[0];
        assert_eq!(web.label, "web1");
        assert_eq!(web.address, "web1.example.com");
        assert_eq!(web.port, Some(2200));
        assert_eq!(web.username, "deploy");
        assert_eq!(web.group_path, vec!["Prod", "Web"]);
        assert_eq!(web.key_path.as_deref(), Some("/home/me/.ssh/id_ed25519"));
        assert_eq!(web.jump_hosts, vec!["ops@bastion.example.com:2222"]);
        assert!(web.agent_forwarding && !web.forward_x11);
        assert_eq!(web.keep_alive_interval, Some(30));
        assert_eq!(p.pf_rules.len(), 1);
        assert_eq!(
            (p.pf_rules[0].local_port, p.pf_rules[0].remote_port),
            (8080, 80)
        );
        let bastion = &p.hosts[1];
        assert_eq!(bastion.label, "bastion: ops");
        assert_eq!(
            bastion.proxy.as_ref().map(|x| (x.kind.as_str(), x.port)),
            Some(("socks5", 1081))
        );
        assert_eq!(
            (p.hosts[2].protocol.as_str(), p.hosts[2].port),
            ("telnet", Some(23))
        );
    }

    #[test]
    fn parses_legacy_connections() {
        let yaml = "ssh:\n  connections:\n    - name: old\n      host: old.example.com\n      port: 22\n      user: root\n      group: Legacy\n      privateKey: /keys/old\n";
        let mut p = ImportPreview::new(ImportSource::Tabby, "config.yaml");
        parse_into(yaml, &mut p).unwrap();
        assert_eq!(p.hosts.len(), 1);
        assert_eq!(p.hosts[0].group_path, vec!["Legacy"]);
        assert_eq!(p.hosts[0].key_path.as_deref(), Some("/keys/old"));
    }

    #[test]
    fn rejects_other_yaml() {
        let mut p = ImportPreview::new(ImportSource::Tabby, "x.yaml");
        assert!(parse_into("terminal:\n  fontSize: 14\n", &mut p).is_err());
    }

    #[test]
    fn yaml_subset() {
        let y = parse_yaml("a:\n- x\n- y: 1\n  z: 'q''s'\nb: \"c\\nd\" # note\n");
        assert_eq!(y.get("a").unwrap().seq().len(), 2);
        assert_eq!(y.get("a").unwrap().seq()[1].text("z"), Some("q's"));
        assert_eq!(y.text("b"), Some("c\nd"));
    }
}
