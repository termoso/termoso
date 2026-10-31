//! Royal TS documents (`.rtsz`): XML with `<RoyalFolder>`,
//! `<RoyalSSHConnection>` / `<RoyalTerminalConnection>`, `<RoyalCredential>`
//! and `<RoyalSecureGateway>` objects linked through `<ID>` / `<ParentID>`.
//! Sub-folders become groups, a secure gateway becomes a jump host, a
//! referenced credential supplies the user name. Passwords in the document
//! are encrypted by Royal TS and are not imported.

use std::collections::HashMap;

use super::securecrt::{Node, parse_xml};
use super::{ImportPreview, ImportedHost};
use crate::error::Result;

pub fn parse_into(text: &str, preview: &mut ImportPreview) -> Result<()> {
    let root = parse_xml(text)
        .filter(|r| has_tag(r, "RTSZDocument") || has_tag(r, "RoyalSSHConnection"))
        .ok_or_else(|| {
            super::invalid("Not a Royal TS document — expected RTSZDocument XML (.rtsz)")
        })?;
    let mut objects: Vec<&Node> = Vec::new();
    collect(&root, &mut objects);
    let folders: HashMap<&str, (&str, &str)> = objects
        .iter()
        .filter(|n| n.tag == "RoyalFolder")
        .filter_map(|n| {
            Some((
                child(n, "ID")?,
                (
                    child(n, "ParentID").unwrap_or(""),
                    child(n, "Name").unwrap_or(""),
                ),
            ))
        })
        .collect();
    let by_id = |tag: &str| -> HashMap<&str, &Node> {
        objects
            .iter()
            .filter(|n| n.tag == tag)
            .filter_map(|n| Some((child(n, "ID")?, *n)))
            .collect()
    };
    let credentials = by_id("RoyalCredential");
    let gateways = by_id("RoyalSecureGateway");
    for n in objects
        .iter()
        .filter(|n| n.tag == "RoyalSSHConnection" || n.tag == "RoyalTerminalConnection")
    {
        let label = child(n, "Name").unwrap_or("");
        let mut group = Vec::new();
        let mut parent = child(n, "ParentID").unwrap_or("");
        let mut depth = 0;
        while let Some((next, name)) = folders.get(parent)
            && depth < 32
        {
            group.push((*name).to_string());
            parent = next;
            depth += 1;
        }
        group.reverse();
        match connection(n, label, group, &credentials, &gateways) {
            Ok(h) => preview.hosts.push(h),
            Err(reason) => preview.warnings.push(format!(
                "Connection {} skipped: {reason}",
                if label.is_empty() { "(unnamed)" } else { label }
            )),
        }
    }
    Ok(())
}

fn connection(
    n: &Node,
    label: &str,
    group: Vec<String>,
    credentials: &HashMap<&str, &Node>,
    gateways: &HashMap<&str, &Node>,
) -> std::result::Result<ImportedHost, String> {
    let protocol = if n.tag == "RoyalSSHConnection" {
        "ssh"
    } else {
        match child(n, "TerminalConnectionType")
            .unwrap_or("SSH")
            .to_ascii_lowercase()
            .as_str()
        {
            "ssh" => "ssh",
            "telnet" => "telnet",
            other => return Err(format!("{other} terminal connections are not supported")),
        }
    };
    let uri = child(n, "URI").ok_or("no host name")?;
    let (address, uri_port) = super::split_host_port(uri);
    let port = child(n, "Port")
        .and_then(|p| p.parse::<u16>().ok())
        .filter(|p| *p > 0)
        .or(uri_port);
    let mut host = ImportedHost {
        label: if label.is_empty() {
            address.to_string()
        } else {
            label.to_string()
        },
        address: address.to_string(),
        protocol: protocol.into(),
        port,
        group_path: group,
        notes: child(n, "Description").unwrap_or("").to_string(),
        ..Default::default()
    };
    let credential = child(n, "CredentialID").and_then(|id| credentials.get(id));
    host.username = child(n, "CredentialUsername")
        .or_else(|| credential.and_then(|c| child(c, "UserName")))
        .unwrap_or("")
        .to_string();
    if child(n, "CredentialPassword").is_some()
        || credential.is_some_and(|c| child(c, "Password").is_some())
    {
        host.warnings
            .push("saved password is encrypted by Royal TS and was not imported".to_string());
    }
    if let Some(name) = child(n, "CredentialName")
        && host.username.is_empty()
    {
        host.warnings.push(format!(
            "credential \"{name}\" is referenced by name and was not resolved"
        ));
    }
    if let Some(key) = ["PrivateKeyPath", "PrivateKeyFile"]
        .iter()
        .find_map(|t| child(n, t))
        .or_else(|| credential.and_then(|c| child(c, "PrivateKeyPath")))
    {
        if key.to_ascii_lowercase().ends_with(".ppk") {
            host.warnings.push(format!(
                "{key}: PuTTY .ppk keys must be converted to OpenSSH format before import"
            ));
        }
        host.key_path = Some(key.to_string());
    }
    if let Some(gw) = child(n, "SecureGatewayID").and_then(|id| gateways.get(id)) {
        if let Some(uri) = child(gw, "URI") {
            let (gw_host, gw_port) = super::split_host_port(uri);
            let gw_port = child(gw, "Port")
                .and_then(|p| p.parse::<u16>().ok())
                .or(gw_port);
            let user = child(gw, "CredentialUsername")
                .or_else(|| {
                    child(gw, "CredentialID")
                        .and_then(|id| credentials.get(id))
                        .and_then(|c| child(c, "UserName"))
                })
                .unwrap_or("");
            let mut spec = String::new();
            if !user.is_empty() {
                spec.push_str(user);
                spec.push('@');
            }
            spec.push_str(gw_host);
            if let Some(p) = gw_port.filter(|p| *p != 22) {
                spec.push_str(&format!(":{p}"));
            }
            host.jump_hosts.push(spec);
        }
    } else if child(n, "SecureGatewayID").is_some_and(|id| !id.is_empty()) {
        host.warnings
            .push("secure gateway is not part of this document and was not imported".to_string());
    }
    Ok(host)
}

fn collect<'a>(node: &'a Node, out: &mut Vec<&'a Node>) {
    if node.tag.starts_with("Royal") {
        out.push(node);
    }
    for c in &node.children {
        collect(c, out);
    }
}

fn has_tag(node: &Node, tag: &str) -> bool {
    node.tag == tag || node.children.iter().any(|c| has_tag(c, tag))
}

/// Trimmed text of a direct child element; empty text counts as absent.
fn child<'a>(node: &'a Node, tag: &str) -> Option<&'a str> {
    node.children
        .iter()
        .find(|c| c.tag == tag)
        .map(|c| c.text.trim())
        .filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::super::ImportSource;
    use super::*;

    const RTSZ: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<RTSZDocument xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Name>Servers</Name>
  <ID>doc</ID>
  <Objects>
    <RoyalFolder><ID>f1</ID><ParentID>doc</ParentID><Name>Prod</Name></RoyalFolder>
    <RoyalFolder><ID>f2</ID><ParentID>f1</ParentID><Name>Web</Name></RoyalFolder>
    <RoyalCredential><ID>c1</ID><ParentID>doc</ParentID><Name>deploy</Name><UserName>deploy</UserName><Password>ENC:abc</Password></RoyalCredential>
    <RoyalSecureGateway><ID>g1</ID><ParentID>doc</ParentID><Name>Bastion</Name><URI>bastion.example.com</URI><Port>2222</Port><CredentialUsername>ops</CredentialUsername></RoyalSecureGateway>
    <RoyalSSHConnection>
      <ID>s1</ID><ParentID>f2</ParentID><Name>web1</Name>
      <URI>web1.example.com</URI><Port>2200</Port>
      <CredentialID>c1</CredentialID>
      <SecureGatewayID>g1</SecureGatewayID>
      <Description>Primary &amp; only</Description>
      <PrivateKeyPath>/Users/me/.ssh/id_ed25519</PrivateKeyPath>
    </RoyalSSHConnection>
    <RoyalTerminalConnection>
      <ID>s2</ID><ParentID>doc</ParentID><Name>switch</Name>
      <TerminalConnectionType>Telnet</TerminalConnectionType>
      <URI>10.0.0.1</URI><CredentialUsername>admin</CredentialUsername>
    </RoyalTerminalConnection>
    <RoyalTerminalConnection>
      <ID>s3</ID><ParentID>doc</ParentID><Name>console</Name>
      <TerminalConnectionType>Serial</TerminalConnectionType>
    </RoyalTerminalConnection>
  </Objects>
</RTSZDocument>"#;

    #[test]
    fn parses_document() {
        let mut p = ImportPreview::new(ImportSource::Royalts, "Servers.rtsz");
        parse_into(RTSZ, &mut p).unwrap();
        assert_eq!(p.hosts.len(), 2);
        let web = &p.hosts[0];
        assert_eq!(web.label, "web1");
        assert_eq!(web.address, "web1.example.com");
        assert_eq!(web.port, Some(2200));
        assert_eq!(web.username, "deploy");
        assert_eq!(web.group_path, vec!["Prod", "Web"]);
        assert_eq!(web.jump_hosts, vec!["ops@bastion.example.com:2222"]);
        assert_eq!(web.notes, "Primary & only");
        assert_eq!(web.key_path.as_deref(), Some("/Users/me/.ssh/id_ed25519"));
        assert!(web.warnings.iter().any(|w| w.contains("password")));
        let sw = &p.hosts[1];
        assert_eq!(
            (sw.protocol.as_str(), sw.username.as_str()),
            ("telnet", "admin")
        );
        assert!(sw.group_path.is_empty());
        assert!(
            p.warnings
                .iter()
                .any(|w| w.contains("console") && w.contains("serial"))
        );
    }

    #[test]
    fn rejects_other_xml() {
        let mut p = ImportPreview::new(ImportSource::Royalts, "x.xml");
        assert!(parse_into("<VanDyke version=\"3.0\"/>", &mut p).is_err());
    }
}
