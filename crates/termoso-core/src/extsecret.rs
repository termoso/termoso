//! Secrets that live in an external manager instead of the vault.
//!
//! A password or key passphrase field may hold a *reference* rather than the
//! secret itself; it is resolved on the machine that opens the connection,
//! right before authentication, and never written back to the vault:
//!
//! | reference                      | resolved with                              |
//! |--------------------------------|--------------------------------------------|
//! | `op://Vault/Item/field`        | 1Password CLI: `op read op://…`            |
//! | `bw://<item id or name>[/f]`   | Bitwarden CLI: `bw get password|<f> <item>` |
//! | `pass://path/to/entry`         | passwordstore: `pass show path` (1st line) |
//! | `env://NAME`                   | environment variable `NAME`                |
//!
//! The CLIs authenticate on their own (`op signin` / service-account token,
//! `BW_SESSION`, gpg-agent); Termoso only runs them with a timeout. Resolved
//! values are cached in memory for a few minutes so a burst of connections
//! does not prompt the manager repeatedly. Nothing here is available on
//! mobile except `env://`.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::{CoreError as Error, Result};

/// How long a resolved value is reused before the manager is asked again.
pub const CACHE_TTL: Duration = Duration::from_secs(5 * 60);
/// Longest a manager CLI may take (it may be waiting for a biometric prompt).
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// A parsed reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reference {
    /// `op://vault/item/field`.
    OnePassword(String),
    /// `bw://item[/field]`.
    Bitwarden {
        /// Item id or exact name.
        item: String,
        /// `password` (default), `username`, `totp`, `notes`, or a custom field.
        field: String,
    },
    /// `pass://path`.
    PasswordStore(String),
    /// `env://NAME`.
    Env(String),
}

impl Reference {
    /// Parse `s` as a reference; `None` for an ordinary secret.
    pub fn parse(s: &str) -> Option<Reference> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("op://") {
            if rest.matches('/').count() >= 2 && !rest.ends_with('/') {
                return Some(Reference::OnePassword(s.to_string()));
            }
            return None;
        }
        if let Some(rest) = s.strip_prefix("bw://") {
            let (item, field) = match rest.rsplit_once('/') {
                Some((i, f)) if !i.is_empty() && !f.is_empty() => (i, f),
                _ => (rest, "password"),
            };
            if item.is_empty() {
                return None;
            }
            return Some(Reference::Bitwarden {
                item: item.to_string(),
                field: field.to_string(),
            });
        }
        if let Some(path) = s.strip_prefix("pass://") {
            if path.is_empty() || path.starts_with('-') {
                return None;
            }
            return Some(Reference::PasswordStore(path.to_string()));
        }
        if let Some(name) = s.strip_prefix("env://")
            && !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Some(Reference::Env(name.to_string()));
        }
        None
    }

    /// Human name of the manager, for UI hints.
    pub fn manager(&self) -> &'static str {
        match self {
            Reference::OnePassword(_) => "1Password",
            Reference::Bitwarden { .. } => "Bitwarden",
            Reference::PasswordStore(_) => "pass",
            Reference::Env(_) => "environment",
        }
    }

    /// Whether this reference can be resolved without a CLI (mobile).
    pub fn is_env(&self) -> bool {
        matches!(self, Reference::Env(_))
    }
}

/// `true` when `s` is a reference rather than a literal secret.
pub fn is_reference(s: &str) -> bool {
    Reference::parse(s).is_some()
}

type Cache = HashMap<String, (Instant, Zeroizing<String>)>;

static CACHE: LazyLock<Mutex<Cache>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Drop every cached value (sign-out, lock).
pub fn clear_cache() {
    CACHE.lock().unwrap().clear();
}

/// Resolve `s` if it is a reference; literal secrets come back unchanged.
pub async fn resolve(s: &str) -> Result<Zeroizing<String>> {
    let Some(r) = Reference::parse(s) else {
        return Ok(Zeroizing::new(s.to_string()));
    };
    if let Some((at, v)) = CACHE.lock().unwrap().get(s.trim())
        && at.elapsed() < CACHE_TTL
    {
        return Ok(v.clone());
    }
    let value = fetch(&r).await?;
    CACHE
        .lock()
        .unwrap()
        .insert(s.trim().to_string(), (Instant::now(), value.clone()));
    Ok(value)
}

async fn fetch(r: &Reference) -> Result<Zeroizing<String>> {
    match r {
        Reference::Env(name) => std::env::var(name)
            .map(Zeroizing::new)
            .map_err(|_| Error::Invalid(format!("environment variable {name} is not set"))),
        Reference::OnePassword(uri) => run("op", &["read", "--no-newline", uri]).await,
        Reference::Bitwarden { item, field } => {
            let out = match field.as_str() {
                "password" | "username" | "totp" | "notes" | "uri" => {
                    run("bw", &["get", field, item, "--raw"]).await?
                }
                custom => {
                    let json = run("bw", &["get", "item", item, "--raw"]).await?;
                    let v: serde_json::Value = serde_json::from_str(&json)?;
                    let found = v["fields"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .find(|f| f["name"].as_str() == Some(custom))
                        .and_then(|f| f["value"].as_str())
                        .map(str::to_string);
                    match found {
                        Some(s) => Zeroizing::new(s),
                        None => {
                            return Err(Error::Invalid(format!(
                                "Bitwarden item has no field `{custom}`"
                            )));
                        }
                    }
                }
            };
            Ok(trim_newline(out))
        }
        Reference::PasswordStore(path) => {
            let out = run("pass", &["show", path]).await?;
            let first = out.lines().next().unwrap_or("").to_string();
            Ok(Zeroizing::new(first))
        }
    }
}

fn trim_newline(mut s: Zeroizing<String>) -> Zeroizing<String> {
    while s.ends_with('\n') || s.ends_with('\r') {
        s.pop();
    }
    s
}

#[cfg(any(target_os = "android", target_os = "ios"))]
async fn run(program: &str, _args: &[&str]) -> Result<Zeroizing<String>> {
    Err(Error::Invalid(format!(
        "`{program}` references are resolved by the desktop app or the API bridge, not on this device"
    )))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn run(program: &str, args: &[&str]) -> Result<Zeroizing<String>> {
    use std::process::Stdio;
    let child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Invalid(format!("`{program}` CLI is not installed or not on PATH"))
            } else {
                Error::Invalid(format!("cannot start `{program}`: {e}"))
            }
        })?;
    let out = tokio::time::timeout(TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| {
            Error::Invalid(format!(
                "`{program}` did not answer in {}s",
                TIMEOUT.as_secs()
            ))
        })??;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.lines().last().unwrap_or("").trim();
        return Err(Error::Invalid(format!(
            "`{program}` failed ({}){}{}",
            out.status,
            if err.is_empty() { "" } else { ": " },
            err
        )));
    }
    let s = String::from_utf8(out.stdout)
        .map_err(|_| Error::Invalid(format!("`{program}` returned non-UTF-8 output")))?;
    Ok(trim_newline(Zeroizing::new(s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_references() {
        assert_eq!(
            Reference::parse("op://Private/prod db/password"),
            Some(Reference::OnePassword(
                "op://Private/prod db/password".into()
            ))
        );
        assert_eq!(Reference::parse("op://Private/item"), None);
        assert_eq!(
            Reference::parse("bw://3f1e…/totp"),
            Some(Reference::Bitwarden {
                item: "3f1e…".into(),
                field: "totp".into()
            })
        );
        assert_eq!(
            Reference::parse("bw://prod-db"),
            Some(Reference::Bitwarden {
                item: "prod-db".into(),
                field: "password".into()
            })
        );
        assert_eq!(
            Reference::parse("pass://servers/db1"),
            Some(Reference::PasswordStore("servers/db1".into()))
        );
        assert_eq!(Reference::parse("pass://-x"), None);
        assert_eq!(
            Reference::parse("env://DB_PW"),
            Some(Reference::Env("DB_PW".into()))
        );
        assert_eq!(Reference::parse("env://not valid"), None);
        assert!(!is_reference("hunter2"));
        assert!(!is_reference("https://example.com"));
    }

    #[tokio::test]
    async fn env_and_literal_resolve() {
        assert!(!resolve("env://PATH").await.unwrap().is_empty());
        assert_eq!(resolve("plain").await.unwrap().as_str(), "plain");
        assert!(resolve("env://TERMOSO_EXTSECRET_MISSING").await.is_err());
    }
}
