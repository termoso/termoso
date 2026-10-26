//! MCP (Model Context Protocol) server over stdio: `termoso-bridge mcp`.
//!
//! Lets an AI assistant (Claude Desktop, Cursor, …) read the hosts and
//! groups of the vaults this bridge is sealed to, and — only when switched
//! on — change them or run commands on hosts over SSH. Transport is
//! newline-delimited JSON-RPC 2.0 on stdin/stdout; logs go to stderr.
//!
//! Permissions are process flags, not something the client can ask for:
//! `--allow-write` enables `upsert_*`/`delete_*`, `--allow-exec` enables
//! `ssh_exec`. Everything else is read-only.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use termoso_proto::entities::payload::{Group, Host, Identity, SshConfig, Tag};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

use crate::Bridge;
use crate::error::{BridgeError, Result};
use crate::exec;
use crate::model::{GroupRequest, HostRequest, IdentityRequest, KeyRequest, SnippetRequest};
use crate::vault::VaultState;

/// Protocol revisions we speak; the first is offered when the client's is unknown.
pub const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// What the process is allowed to do on behalf of the client.
#[derive(Debug, Clone, Copy, Default)]
pub struct McpConfig {
    pub allow_write: bool,
    pub allow_exec: bool,
    pub strict_host_key: bool,
}

pub struct McpServer {
    bridge: Arc<Bridge>,
    cfg: McpConfig,
}

/// Pick the protocol version to answer `initialize` with.
pub fn protocol_version(requested: Option<&str>) -> &'static str {
    requested
        .and_then(|r| PROTOCOL_VERSIONS.iter().find(|v| **v == r))
        .copied()
        .unwrap_or(PROTOCOL_VERSIONS[0])
}

/// Tool catalogue for the given permissions.
pub fn tools_for(cfg: McpConfig) -> Vec<Value> {
    let vault_prop = json!({"type": "string", "description": "Vault name or id; omit to search every vault the bridge can read."});
    let host_prop =
        json!({"type": "string", "description": "Host id, external_id, label or address."});
    let mut tools = vec![
        json!({"name": "list_vaults", "description": "Vaults this bridge is sealed to, with host/group counts and whether the key is usable.",
               "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}}),
        json!({"name": "list_hosts", "description": "All hosts (label, address, group, tags, SSH port, username, whether credentials are stored). Never returns passwords or keys.",
               "inputSchema": {"type": "object", "properties": {"vault": vault_prop, "query": {"type": "string", "description": "Case-insensitive substring over label, address, tags and notes."}}, "additionalProperties": false}}),
        json!({"name": "get_host", "description": "One host by id, external_id, label or address, with its resolved SSH settings.",
               "inputSchema": {"type": "object", "required": ["host"], "properties": {"host": host_prop, "vault": vault_prop}, "additionalProperties": false}}),
        json!({"name": "list_groups", "description": "All groups with parent and host counts.",
               "inputSchema": {"type": "object", "properties": {"vault": vault_prop}, "additionalProperties": false}}),
        json!({"name": "list_snippets", "description": "Snippets managed through the bridge (external_id, label, script).",
               "inputSchema": {"type": "object", "properties": {"vault": vault_prop}, "additionalProperties": false}}),
        json!({"name": "list_identities", "description": "Shared identities managed through the bridge (label, username, whether a password/key is set, how many hosts use it). Never returns secrets.",
               "inputSchema": {"type": "object", "properties": {"vault": vault_prop}, "additionalProperties": false}}),
        json!({"name": "list_keys", "description": "SSH keys managed through the bridge (label, type, public key). Never returns private keys.",
               "inputSchema": {"type": "object", "properties": {"vault": vault_prop}, "additionalProperties": false}}),
        json!({"name": "sync", "description": "Pull the latest vault changes from the Termoso server now.",
               "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}}),
    ];
    if cfg.allow_write {
        tools.extend([
            json!({"name": "upsert_host", "description": "Create or update a host by external_id (same payload as the REST API: address, label, group, tags, notes, os, ssh{port,credentials{username,password,key}}, telnet).",
                   "inputSchema": {"type": "object", "required": ["external_id", "host"], "properties": {"external_id": {"type": "string"}, "host": {"type": "object"}}, "additionalProperties": false}}),
            json!({"name": "delete_host", "description": "Delete a host by external_id.",
                   "inputSchema": {"type": "object", "required": ["external_id"], "properties": {"external_id": {"type": "string"}, "vault": vault_prop}, "additionalProperties": false}}),
            json!({"name": "upsert_group", "description": "Create or update a group by external_id (label, parent, vault, ssh/telnet defaults).",
                   "inputSchema": {"type": "object", "required": ["external_id", "group"], "properties": {"external_id": {"type": "string"}, "group": {"type": "object"}}, "additionalProperties": false}}),
            json!({"name": "delete_group", "description": "Delete a group by external_id (must be empty).",
                   "inputSchema": {"type": "object", "required": ["external_id"], "properties": {"external_id": {"type": "string"}, "vault": vault_prop}, "additionalProperties": false}}),
            json!({"name": "upsert_snippet", "description": "Create or update a snippet by external_id (label, script, close_after_run, vault).",
                   "inputSchema": {"type": "object", "required": ["external_id", "snippet"], "properties": {"external_id": {"type": "string"}, "snippet": {"type": "object"}}, "additionalProperties": false}}),
            json!({"name": "delete_snippet", "description": "Delete a snippet by external_id.",
                   "inputSchema": {"type": "object", "required": ["external_id"], "properties": {"external_id": {"type": "string"}, "vault": vault_prop}, "additionalProperties": false}}),
            json!({"name": "upsert_identity", "description": "Create or update a shared identity by external_id (label, username, password, key = external_id of a key, vault). Hosts reference it as credentials.identity.",
                   "inputSchema": {"type": "object", "required": ["external_id", "identity"], "properties": {"external_id": {"type": "string"}, "identity": {"type": "object"}}, "additionalProperties": false}}),
            json!({"name": "delete_identity", "description": "Delete a shared identity by external_id (must not be used by hosts or groups).",
                   "inputSchema": {"type": "object", "required": ["external_id"], "properties": {"external_id": {"type": "string"}, "vault": vault_prop}, "additionalProperties": false}}),
            json!({"name": "upsert_key", "description": "Create or update an SSH key by external_id (label, private (PEM/OpenSSH), public, passphrase, vault).",
                   "inputSchema": {"type": "object", "required": ["external_id", "key"], "properties": {"external_id": {"type": "string"}, "key": {"type": "object"}}, "additionalProperties": false}}),
            json!({"name": "delete_key", "description": "Delete an SSH key by external_id (must not be referenced by identities).",
                   "inputSchema": {"type": "object", "required": ["external_id"], "properties": {"external_id": {"type": "string"}, "vault": vault_prop}, "additionalProperties": false}}),
        ]);
    }
    if cfg.allow_exec {
        tools.push(json!({"name": "ssh_exec", "description": "Run one non-interactive command on a host over SSH with the credentials stored in the vault. Returns exit code, stdout and stderr (each capped at 64 KiB). No PTY, no sudo password prompts.",
               "inputSchema": {"type": "object", "required": ["host", "command"],
                   "properties": {"host": host_prop, "vault": vault_prop, "command": {"type": "string"},
                                  "timeout_secs": {"type": "integer", "minimum": 1, "maximum": exec::MAX_TIMEOUT, "description": "Budget for connect + command (default 60)."}},
                   "additionalProperties": false}}));
    }
    tools
}

/// Permission gate for a tool name.
pub fn guard(cfg: McpConfig, tool: &str) -> Result<()> {
    let denied = |flag: &str| {
        Err(BridgeError::Forbidden(format!(
            "tool `{tool}` is disabled; start the bridge with `mcp {flag}` to enable it"
        )))
    };
    match tool {
        "upsert_host" | "delete_host" | "upsert_group" | "delete_group" | "upsert_snippet"
        | "delete_snippet" | "upsert_identity" | "delete_identity" | "upsert_key"
        | "delete_key"
            if !cfg.allow_write =>
        {
            denied("--allow-write")
        }
        "ssh_exec" if !cfg.allow_exec => denied("--allow-exec"),
        _ => Ok(()),
    }
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message.into()}})
}

fn text_result(v: &impl serde::Serialize, is_error: bool) -> Value {
    let text = serde_json::to_string_pretty(v).unwrap_or_default();
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

#[derive(Debug, Deserialize)]
struct Rpc {
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(serde::Serialize)]
struct HostView {
    id: Uuid,
    vault: String,
    label: String,
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    has_credentials: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    notes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
}

fn host_view(v: &VaultState, id: Uuid, h: &Host) -> HostView {
    let ssh = h
        .ssh_config_id
        .and_then(|c| v.get::<SshConfig>(c, "ssh_config"));
    let ident = ssh
        .as_ref()
        .and_then(|c| c.identity_id)
        .and_then(|i| v.get::<Identity>(i, "identity"));
    HostView {
        id,
        vault: v.name.clone(),
        label: h.label.clone(),
        address: h.address.clone(),
        external_id: h.external_id.clone(),
        group: h
            .group_id
            .and_then(|g| v.get::<Group>(g, "group"))
            .map(|g| g.label),
        tags: h
            .tag_ids
            .iter()
            .filter_map(|t| v.get::<Tag>(*t, "tag").map(|t| t.label))
            .collect(),
        ssh_port: ssh.as_ref().map(|c| c.port.unwrap_or(22)),
        username: ident
            .as_ref()
            .map(|i| i.username.clone())
            .filter(|u| !u.is_empty()),
        has_credentials: ident.as_ref().is_some_and(|i| {
            i.ssh_key_id.is_some() || i.password.as_deref().is_some_and(|p| !p.is_empty())
        }),
        notes: h.notes.clone(),
        os: h.os_name.clone(),
    }
}

#[derive(serde::Serialize)]
struct GroupView {
    id: Uuid,
    vault: String,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    hosts: usize,
}

fn opt_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn req_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    opt_str(args, key).ok_or_else(|| BridgeError::Invalid(format!("`{key}` is required")))
}

impl McpServer {
    pub fn new(bridge: Arc<Bridge>, cfg: McpConfig) -> Self {
        Self { bridge, cfg }
    }

    /// Serve until stdin closes.
    pub async fn serve_stdio(self) -> Result<()> {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        let mut out = tokio::io::stdout();
        while let Some(line) = lines
            .next_line()
            .await
            .map_err(|e| BridgeError::Transport(e.to_string()))?
        {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let replies = match serde_json::from_str::<Value>(line) {
                Ok(Value::Array(batch)) => {
                    let mut acc = Vec::new();
                    for m in batch {
                        if let Some(r) = self.handle(m).await {
                            acc.push(r);
                        }
                    }
                    if acc.is_empty() {
                        None
                    } else {
                        Some(Value::Array(acc))
                    }
                }
                Ok(m) => self.handle(m).await,
                Err(e) => Some(rpc_error(Value::Null, -32700, format!("parse error: {e}"))),
            };
            if let Some(r) = replies {
                let mut s = serde_json::to_string(&r).unwrap_or_default();
                s.push('\n');
                out.write_all(s.as_bytes())
                    .await
                    .map_err(|e| BridgeError::Transport(e.to_string()))?;
                out.flush()
                    .await
                    .map_err(|e| BridgeError::Transport(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Handle one JSON-RPC message; `None` for notifications.
    pub async fn handle(&self, msg: Value) -> Option<Value> {
        let rpc: Rpc = match serde_json::from_value(msg) {
            Ok(r) => r,
            Err(e) => {
                return Some(rpc_error(
                    Value::Null,
                    -32600,
                    format!("invalid request: {e}"),
                ));
            }
        };
        let Some(id) = rpc.id.filter(|id| !id.is_null()) else {
            // Notifications (`notifications/initialized`, `notifications/cancelled`, …).
            tracing::debug!(method = %rpc.method, "notification");
            return None;
        };
        Some(match rpc.method.as_str() {
            "initialize" => {
                let requested = rpc.params.get("protocolVersion").and_then(Value::as_str);
                rpc_result(
                    id,
                    json!({
                        "protocolVersion": protocol_version(requested),
                        "capabilities": {"tools": {"listChanged": false}},
                        "serverInfo": {"name": "termoso-bridge", "version": env!("CARGO_PKG_VERSION")},
                        "instructions": self.instructions(),
                    }),
                )
            }
            "ping" => rpc_result(id, json!({})),
            "tools/list" => rpc_result(id, json!({"tools": tools_for(self.cfg)})),
            "tools/call" => {
                let name = rpc
                    .params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let args = rpc
                    .params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                match self.call(&name, args).await {
                    Ok(v) => rpc_result(id, text_result(&v, false)),
                    Err(BridgeError::Invalid(m)) if m.starts_with("unknown tool") => {
                        rpc_error(id, -32602, m)
                    }
                    Err(e) => rpc_result(id, text_result(&json!({"error": e.to_string()}), true)),
                }
            }
            "resources/list" => rpc_result(id, json!({"resources": []})),
            "prompts/list" => rpc_result(id, json!({"prompts": []})),
            other => rpc_error(id, -32601, format!("method not found: {other}")),
        })
    }

    fn instructions(&self) -> String {
        let mut s = String::from(
            "Termoso vault access through an API Bridge. Hosts are identified by id, external_id, label or address. Secrets are never returned.",
        );
        if !self.cfg.allow_write {
            s.push_str(" This bridge is read-only: hosts, groups, snippets, identities and keys cannot be changed.");
        }
        if self.cfg.allow_exec {
            s.push_str(" `ssh_exec` runs a single non-interactive command on a host and returns its output; prefer read-only commands and confirm destructive ones with the user first.");
        } else {
            s.push_str(" Running commands on hosts is disabled.");
        }
        s
    }

    async fn call(&self, name: &str, args: Value) -> Result<Value> {
        guard(self.cfg, name)?;
        let vault = opt_str(&args, "vault");
        match name {
            "list_vaults" => Ok(serde_json::to_value(self.bridge.status().await.vaults)?),
            "sync" => {
                let st = self.bridge.sync().await?;
                Ok(json!({"synced": true, "vaults": st.vaults.len()}))
            }
            "list_hosts" => {
                let q = opt_str(&args, "query").map(str::to_ascii_lowercase);
                self.bridge
                    .with_vaults(vault, |vaults| {
                        let mut out: Vec<HostView> = vaults
                            .iter()
                            .flat_map(|v| {
                                v.iter_kind::<Host>("host")
                                    .map(move |(id, _, h)| host_view(v, id, &h))
                            })
                            .filter(|h| {
                                q.as_deref().is_none_or(|q| {
                                    h.label.to_ascii_lowercase().contains(q)
                                        || h.address.to_ascii_lowercase().contains(q)
                                        || h.notes.to_ascii_lowercase().contains(q)
                                        || h.tags.iter().any(|t| t.to_ascii_lowercase().contains(q))
                                })
                            })
                            .collect();
                        out.sort_by(|a, b| (&a.vault, &a.label).cmp(&(&b.vault, &b.label)));
                        Ok(serde_json::to_value(out)?)
                    })
                    .await
            }
            "get_host" => {
                let sel = req_str(&args, "host")?;
                self.bridge
                    .with_vaults(vault, |vaults| {
                        let (v, id, h) = exec::find_host(vaults, sel)?;
                        let mut view = serde_json::to_value(host_view(v, id, &h))?;
                        match exec::resolve(v, id, &h) {
                            Ok(t) => {
                                view["ssh"] = json!({"host": t.target.host, "port": t.target.port, "username": t.target.username, "auth": t.auth.len()});
                            }
                            Err(e) => view["ssh_unavailable"] = Value::String(e.to_string()),
                        }
                        Ok(view)
                    })
                    .await
            }
            "list_groups" => {
                self.bridge
                    .with_vaults(vault, |vaults| {
                        let mut out: Vec<GroupView> = vaults
                            .iter()
                            .flat_map(|v| {
                                v.iter_kind::<Group>("group")
                                    .map(move |(id, _, g)| GroupView {
                                        id,
                                        vault: v.name.clone(),
                                        parent: g
                                            .parent_id
                                            .and_then(|p| v.get::<Group>(p, "group"))
                                            .map(|p| p.label),
                                        label: g.label,
                                        external_id: g.external_id,
                                        hosts: v
                                            .iter_kind::<Host>("host")
                                            .filter(|(_, _, h)| h.group_id == Some(id))
                                            .count(),
                                    })
                            })
                            .collect();
                        out.sort_by(|a, b| (&a.vault, &a.label).cmp(&(&b.vault, &b.label)));
                        Ok(serde_json::to_value(out)?)
                    })
                    .await
            }
            "upsert_host" => {
                let ext = req_str(&args, "external_id")?;
                let req: HostRequest =
                    serde_json::from_value(args.get("host").cloned().unwrap_or_default())
                        .map_err(|e| BridgeError::Invalid(format!("host: {e}")))?;
                Ok(serde_json::to_value(
                    self.bridge.upsert_host(ext, req).await?,
                )?)
            }
            "delete_host" => {
                let ext = req_str(&args, "external_id")?;
                Ok(json!({"deleted": self.bridge.delete_host(ext, vault).await?}))
            }
            "upsert_group" => {
                let ext = req_str(&args, "external_id")?;
                let req: GroupRequest =
                    serde_json::from_value(args.get("group").cloned().unwrap_or_default())
                        .map_err(|e| BridgeError::Invalid(format!("group: {e}")))?;
                Ok(serde_json::to_value(
                    self.bridge.upsert_group(ext, req).await?,
                )?)
            }
            "delete_group" => {
                let ext = req_str(&args, "external_id")?;
                Ok(json!({"deleted": self.bridge.delete_group(ext, vault).await?}))
            }
            "list_snippets" => Ok(serde_json::to_value(
                self.bridge.list_snippets(vault).await?,
            )?),
            "upsert_snippet" => {
                let ext = req_str(&args, "external_id")?;
                let req: SnippetRequest =
                    serde_json::from_value(args.get("snippet").cloned().unwrap_or_default())
                        .map_err(|e| BridgeError::Invalid(format!("snippet: {e}")))?;
                Ok(serde_json::to_value(
                    self.bridge.upsert_snippet(ext, req).await?,
                )?)
            }
            "delete_snippet" => {
                let ext = req_str(&args, "external_id")?;
                Ok(json!({"deleted": self.bridge.delete_snippet(ext, vault).await?}))
            }
            "list_identities" => Ok(serde_json::to_value(
                self.bridge.list_identities(vault).await?,
            )?),
            "upsert_identity" => {
                let ext = req_str(&args, "external_id")?;
                let req: IdentityRequest =
                    serde_json::from_value(args.get("identity").cloned().unwrap_or_default())
                        .map_err(|e| BridgeError::Invalid(format!("identity: {e}")))?;
                Ok(serde_json::to_value(
                    self.bridge.upsert_identity(ext, req).await?,
                )?)
            }
            "delete_identity" => {
                let ext = req_str(&args, "external_id")?;
                Ok(json!({"deleted": self.bridge.delete_identity(ext, vault).await?}))
            }
            "list_keys" => Ok(serde_json::to_value(self.bridge.list_keys(vault).await?)?),
            "upsert_key" => {
                let ext = req_str(&args, "external_id")?;
                let req: KeyRequest =
                    serde_json::from_value(args.get("key").cloned().unwrap_or_default())
                        .map_err(|e| BridgeError::Invalid(format!("key: {e}")))?;
                Ok(serde_json::to_value(
                    self.bridge.upsert_key(ext, req).await?,
                )?)
            }
            "delete_key" => {
                let ext = req_str(&args, "external_id")?;
                Ok(json!({"deleted": self.bridge.delete_key(ext, vault).await?}))
            }
            "ssh_exec" => {
                let sel = req_str(&args, "host")?;
                let command = req_str(&args, "command")?.to_string();
                let budget = args
                    .get("timeout_secs")
                    .and_then(Value::as_u64)
                    .unwrap_or(exec::DEFAULT_TIMEOUT)
                    .clamp(1, exec::MAX_TIMEOUT);
                let target = self
                    .bridge
                    .with_vaults(vault, |vaults| {
                        let (v, id, h) = exec::find_host(vaults, sel)?;
                        exec::resolve(v, id, &h)
                    })
                    .await?;
                tracing::info!(host = %target.label, vault = %target.vault, "ssh_exec");
                Ok(serde_json::to_value(
                    exec::run(
                        target,
                        &command,
                        self.cfg.strict_host_key,
                        Duration::from_secs(budget),
                    )
                    .await?,
                )?)
            }
            other => Err(BridgeError::Invalid(format!("unknown tool: {other}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_negotiation() {
        assert_eq!(protocol_version(Some("2024-11-05")), "2024-11-05");
        assert_eq!(protocol_version(Some("1999-01-01")), PROTOCOL_VERSIONS[0]);
        assert_eq!(protocol_version(None), PROTOCOL_VERSIONS[0]);
    }

    #[test]
    fn tool_catalogue_follows_flags() {
        let names = |cfg| {
            tools_for(cfg)
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        let ro = names(McpConfig::default());
        assert!(ro.contains(&"list_hosts".to_string()));
        assert!(!ro.contains(&"upsert_host".to_string()));
        assert!(!ro.contains(&"ssh_exec".to_string()));
        let all = names(McpConfig {
            allow_write: true,
            allow_exec: true,
            strict_host_key: false,
        });
        assert!(all.contains(&"delete_group".to_string()));
        assert!(all.contains(&"ssh_exec".to_string()));
    }

    #[test]
    fn guard_denies_disabled_tools() {
        let ro = McpConfig::default();
        assert!(guard(ro, "list_hosts").is_ok());
        assert!(
            guard(ro, "upsert_host")
                .unwrap_err()
                .to_string()
                .contains("--allow-write")
        );
        assert!(
            guard(ro, "ssh_exec")
                .unwrap_err()
                .to_string()
                .contains("--allow-exec")
        );
        assert!(guard(MccpAll::ALL, "ssh_exec").is_ok());
    }

    struct MccpAll;
    impl MccpAll {
        const ALL: McpConfig = McpConfig {
            allow_write: true,
            allow_exec: true,
            strict_host_key: true,
        };
    }
}
