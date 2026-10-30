//! iTerm2 profiles: a Dynamic Profiles JSON file (`{"Profiles": [...]}`),
//! a profile saved as JSON, or the XML plist (`com.googlecode.iterm2.plist`,
//! profiles under `New Bookmarks`). A profile becomes a host when its
//! command — *Command* with *Custom Command* = Yes, or the first line of
//! *Send text at start* — is an `ssh …` invocation; `-p -i -J -l -A -X -L
//! -R -D` and `-o ProxyJump/User/IdentityFile` are understood. Tags become
//! tags.

use serde_json::{Map, Value};

use super::securecrt::{Node, parse_xml};
use super::{ImportPreview, ImportedHost, ImportedPfRule, PfKind};
use crate::error::Result;

pub fn parse_into(text: &str, preview: &mut ImportPreview) -> Result<()> {
    let value = if text.trim_start().starts_with('<') {
        parse_xml(text)
            .and_then(|r| plist_root(&r))
            .ok_or_else(|| {
                super::invalid("Not an iTerm2 plist — expected <plist> with a profiles array")
            })?
    } else {
        serde_json::from_str::<Value>(text).map_err(|_| {
            super::invalid(
                "Not an iTerm2 profile file — expected JSON {\"Profiles\": [...]} or a plist",
            )
        })?
    };
    let profiles: Vec<Value> = match &value {
        Value::Array(a) => a.clone(),
        Value::Object(o) => o
            .get("Profiles")
            .or_else(|| o.get("New Bookmarks"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| {
                if o.contains_key("Name") {
                    vec![value.clone()]
                } else {
                    Vec::new()
                }
            }),
        _ => Vec::new(),
    };
    if profiles.is_empty() {
        return Err(super::invalid(
            "No profiles found — expected a Profiles array (Dynamic Profiles JSON or the iTerm2 plist)",
        ));
    }
    for p in &profiles {
        let name = str_of(p, "Name").unwrap_or("").trim();
        let Some(cmd) = ssh_command(p) else {
            preview.warnings.push(format!(
                "Profile {} skipped: not an ssh command",
                if name.is_empty() { "(unnamed)" } else { name }
            ));
            continue;
        };
        match host_from_ssh(name, &cmd, &mut preview.pf_rules) {
            Ok(mut h) => {
                if let Some(tags) = p.get("Tags").and_then(Value::as_array) {
                    h.tags = tags
                        .iter()
                        .filter_map(Value::as_str)
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .collect();
                }
                if let Some(d) = str_of(p, "Description").filter(|d| !d.trim().is_empty()) {
                    h.notes = d.trim().to_string();
                }
                preview.hosts.push(h);
            }
            Err(reason) => preview.warnings.push(format!(
                "Profile {} skipped: {reason}",
                if name.is_empty() { "(unnamed)" } else { name }
            )),
        }
    }
    Ok(())
}

fn ssh_command(p: &Value) -> Option<String> {
    let custom = str_of(p, "Custom Command").unwrap_or("No");
    if custom == "Yes"
        && let Some(cmd) = str_of(p, "Command").filter(|c| is_ssh(c))
    {
        return Some(cmd.to_string());
    }
    str_of(p, "Initial Text")?
        .lines()
        .map(str::trim)
        .find(|l| is_ssh(l))
        .map(str::to_string)
}

fn is_ssh(cmd: &str) -> bool {
    cmd.split_whitespace()
        .next()
        .is_some_and(|w| w.rsplit('/').next() == Some("ssh"))
}

/// Flags that take an argument; everything else single-letter is boolean.
const WITH_ARG: &str = "bcDEeFIiJLlmOopQRSWw";

fn host_from_ssh(
    label: &str,
    cmd: &str,
    pf: &mut Vec<ImportedPfRule>,
) -> std::result::Result<ImportedHost, String> {
    let args = split_args(cmd);
    let mut host = ImportedHost {
        protocol: "ssh".into(),
        ..Default::default()
    };
    let mut rules: Vec<(PfKind, String)> = Vec::new();
    let mut destination: Option<String> = None;
    let mut remote_command = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        if destination.is_some() {
            remote_command.push(a.to_string());
            i += 1;
            continue;
        }
        if a == "--" {
            i += 1;
            continue;
        }
        if let Some(flags) = a
            .strip_prefix('-')
            .filter(|f| !f.is_empty() && !a.starts_with("--"))
        {
            let mut chars = flags.chars();
            while let Some(f) = chars.next() {
                let takes = WITH_ARG.contains(f);
                let value = if takes {
                    let rest: String = chars.by_ref().collect();
                    if rest.is_empty() {
                        i += 1;
                        args.get(i)
                            .cloned()
                            .ok_or(format!("-{f} without a value"))?
                    } else {
                        rest
                    }
                } else {
                    String::new()
                };
                match f {
                    'p' => host.port = value.parse::<u16>().ok().filter(|p| *p > 0),
                    'l' => host.username = value,
                    'i' => host.key_path = Some(value),
                    'J' => host
                        .jump_hosts
                        .extend(value.split(',').map(str::trim).map(String::from)),
                    'A' => host.agent_forwarding = true,
                    'X' | 'Y' => host.forward_x11 = true,
                    'L' => rules.push((PfKind::Local, value)),
                    'R' => rules.push((PfKind::Remote, value)),
                    'D' => rules.push((PfKind::Dynamic, value)),
                    'o' => option(&mut host, &value),
                    'W' | 'w' | 'S' | 'F' | 'E' | 'e' | 'b' | 'c' | 'I' | 'm' | 'O' | 'Q' => host
                        .warnings
                        .push(format!("-{f} {value} is not supported and was ignored")),
                    _ => {}
                }
                if takes {
                    break;
                }
            }
            i += 1;
            continue;
        }
        destination = Some(a.to_string());
        i += 1;
    }
    let destination = destination.ok_or("no destination")?;
    let dest = destination.strip_prefix("ssh://").unwrap_or(&destination);
    let (user, addr) = match dest.rsplit_once('@') {
        Some((u, a)) => (Some(u), a),
        None => (None, dest),
    };
    let (address, port) = if destination.starts_with("ssh://") {
        super::split_host_port(addr)
    } else {
        (addr, None)
    };
    if address.is_empty() {
        return Err("no destination".into());
    }
    host.address = address.to_string();
    if let Some(p) = port {
        host.port = Some(p);
    }
    if let Some(u) = user.filter(|u| !u.is_empty()) {
        host.username = u.to_string();
    }
    host.label = if label.is_empty() {
        host.address.clone()
    } else {
        label.to_string()
    };
    if !remote_command.is_empty() {
        host.warnings.push(format!(
            "remote command \"{}\" is not supported and was ignored",
            remote_command.join(" ")
        ));
    }
    for (kind, spec) in rules {
        match pf_rule(&host.label, kind, &spec) {
            Some(r) => pf.push(r),
            None => host
                .warnings
                .push(format!("port forwarding \"{spec}\" was not understood")),
        }
    }
    Ok(host)
}

fn option(host: &mut ImportedHost, opt: &str) {
    let Some((k, v)) = opt.split_once('=') else {
        return;
    };
    let v = v.trim();
    match k.trim().to_ascii_lowercase().as_str() {
        "user" => host.username = v.to_string(),
        "port" => host.port = v.parse::<u16>().ok(),
        "identityfile" => host.key_path = Some(v.to_string()),
        "proxyjump" => host
            .jump_hosts
            .extend(v.split(',').map(str::trim).map(String::from)),
        "forwardagent" => host.agent_forwarding = v.eq_ignore_ascii_case("yes"),
        "forwardx11" => host.forward_x11 = v.eq_ignore_ascii_case("yes"),
        "serveraliveinterval" => host.keep_alive_interval = v.parse().ok(),
        "connecttimeout" => host.timeout = v.parse().ok(),
        "hostname" => host.address = v.to_string(),
        _ => {}
    }
}

/// `[bind:]port:host:hostport` for -L/-R, `[bind:]port` for -D.
fn pf_rule(label: &str, kind: PfKind, spec: &str) -> Option<ImportedPfRule> {
    let parts: Vec<&str> = split_pf(spec);
    let (bind, port, rhost, rport) = match (kind, parts.as_slice()) {
        (PfKind::Dynamic, [p]) => ("", *p, "", "0"),
        (PfKind::Dynamic, [b, p]) => (*b, *p, "", "0"),
        (_, [p, h, hp]) => ("", *p, *h, *hp),
        (_, [b, p, h, hp]) => (*b, *p, *h, *hp),
        _ => return None,
    };
    Some(ImportedPfRule {
        host_label: label.to_string(),
        kind,
        bound_address: bind.trim_matches(['[', ']']).to_string(),
        local_port: port.parse().ok()?,
        remote_host: rhost.trim_matches(['[', ']']).to_string(),
        remote_port: rport.parse().ok()?,
    })
}

/// Split on `:` but keep `[v6::addr]` together.
fn split_pf(spec: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = spec;
    while !rest.is_empty() {
        if rest.starts_with('[')
            && let Some(end) = rest.find(']')
        {
            out.push(&rest[..=end]);
            rest = rest[end + 1..].strip_prefix(':').unwrap_or("");
            continue;
        }
        match rest.split_once(':') {
            Some((a, b)) => {
                out.push(a);
                rest = b;
            }
            None => {
                out.push(rest);
                break;
            }
        }
    }
    out
}

/// Shell-style split: whitespace separated, single/double quotes, backslash.
fn split_args(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = cmd.chars().peekable();
    let mut pending = false;
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == q => quote = None,
            Some('"') if c == '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            Some(_) => cur.push(c),
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                pending = true;
            }
            None if c == '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            None if c.is_whitespace() => {
                if !cur.is_empty() || pending {
                    out.push(std::mem::take(&mut cur));
                    pending = false;
                }
            }
            None => cur.push(c),
        }
    }
    if !cur.is_empty() || pending {
        out.push(cur);
    }
    out
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn plist_root(root: &Node) -> Option<Value> {
    fn find(n: &Node) -> Option<&Node> {
        if n.tag == "plist" {
            return Some(n);
        }
        n.children.iter().find_map(find)
    }
    find(root)?.children.first().map(plist_value)
}

fn plist_value(n: &Node) -> Value {
    match n.tag.as_str() {
        "dict" => {
            let mut map = Map::new();
            let mut it = n.children.iter();
            while let Some(k) = it.next() {
                if k.tag != "key" {
                    continue;
                }
                if let Some(v) = it.next() {
                    map.insert(k.text.trim().to_string(), plist_value(v));
                }
            }
            Value::Object(map)
        }
        "array" => Value::Array(n.children.iter().map(plist_value).collect()),
        "string" | "date" | "data" => Value::String(n.text.trim().to_string()),
        "integer" => n
            .text
            .trim()
            .parse::<i64>()
            .map(Value::from)
            .unwrap_or(Value::Null),
        "real" => n
            .text
            .trim()
            .parse::<f64>()
            .map(Value::from)
            .unwrap_or(Value::Null),
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::super::ImportSource;
    use super::*;

    const JSON: &str = r#"{"Profiles": [
      {"Name": "web1", "Guid": "a", "Custom Command": "Yes",
       "Command": "/usr/bin/ssh -A -p 2200 -i ~/.ssh/id_ed25519 -J ops@bastion:2222 -L 8080:localhost:80 -D 1080 deploy@web1.example.com",
       "Tags": ["prod", "web"]},
      {"Name": "db", "Guid": "b", "Custom Command": "No",
       "Initial Text": "ssh -o User=postgres -o ProxyJump=bastion db.internal\n"},
      {"Name": "local zsh", "Guid": "c", "Custom Command": "Custom Shell", "Command": "/bin/zsh"}
    ]}"#;

    #[test]
    fn parses_dynamic_profiles() {
        let mut p = ImportPreview::new(ImportSource::Iterm2, "profiles.json");
        parse_into(JSON, &mut p).unwrap();
        assert_eq!(p.hosts.len(), 2);
        let web = &p.hosts[0];
        assert_eq!(web.label, "web1");
        assert_eq!(web.address, "web1.example.com");
        assert_eq!(web.port, Some(2200));
        assert_eq!(web.username, "deploy");
        assert_eq!(web.key_path.as_deref(), Some("~/.ssh/id_ed25519"));
        assert_eq!(web.jump_hosts, vec!["ops@bastion:2222"]);
        assert!(web.agent_forwarding);
        assert_eq!(web.tags, vec!["prod", "web"]);
        assert_eq!(p.pf_rules.len(), 2);
        assert_eq!(p.pf_rules[0].kind, PfKind::Local);
        assert_eq!(
            (p.pf_rules[0].local_port, p.pf_rules[0].remote_port),
            (8080, 80)
        );
        assert_eq!(p.pf_rules[1].kind, PfKind::Dynamic);
        let db = &p.hosts[1];
        assert_eq!(
            (db.address.as_str(), db.username.as_str()),
            ("db.internal", "postgres")
        );
        assert_eq!(db.jump_hosts, vec!["bastion"]);
        assert!(p.warnings.iter().any(|w| w.contains("local zsh")));
    }

    #[test]
    fn parses_plist() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>New Bookmarks</key>
  <array><dict>
    <key>Name</key><string>edge</string>
    <key>Custom Command</key><string>Yes</string>
    <key>Command</key><string>ssh ssh://root@[2001:db8::1]:2022 uptime</string>
    <key>Tags</key><array><string>edge</string></array>
  </dict></array>
</dict></plist>"#;
        let mut p = ImportPreview::new(ImportSource::Iterm2, "com.googlecode.iterm2.plist");
        parse_into(plist, &mut p).unwrap();
        let h = &p.hosts[0];
        assert_eq!(
            (h.address.as_str(), h.port, h.username.as_str()),
            ("2001:db8::1", Some(2022), "root")
        );
        assert!(h.warnings.iter().any(|w| w.contains("uptime")));
    }

    #[test]
    fn rejects_other_json() {
        let mut p = ImportPreview::new(ImportSource::Iterm2, "x.json");
        assert!(parse_into("{\"a\": 1}", &mut p).is_err());
        assert!(parse_into("not json", &mut p).is_err());
    }

    #[test]
    fn splits_quoted_args() {
        assert_eq!(
            split_args(r#"ssh -o "User=me" 'host name' a\ b"#),
            vec!["ssh", "-o", "User=me", "host name", "a b"]
        );
    }
}
