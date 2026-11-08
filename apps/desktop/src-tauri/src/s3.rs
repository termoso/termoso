//! S3 buckets opened from the file browser. Credentials come from the
//! host's S3 section (an encrypted identity: access key + secret); a missing
//! secret and an untrusted certificate are put to the user through the same
//! prompt broker the SSH path uses.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tauri::{AppHandle, Manager, Runtime};
use termoso_core::error::CoreError;
use termoso_core::hostkey::HostKeyDecision;
use termoso_core::model::ResolvedHost;
use termoso_core::s3::{self, S3, S3Config};
use termoso_core::webdav::TlsPolicy;
use termoso_proto::entities::payload::Identity;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{DesktopError, Result};
use crate::prompts::{PromptAnswer, PromptRequest};
use crate::state::AppState;
use crate::webdav::Connection;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_SECRET_ATTEMPTS: u32 = 3;

fn spool_dir() -> PathBuf {
    std::env::temp_dir().join("termoso-s3")
}

/// Open the S3 section of `host_id`, asking the user for the secret key or
/// a certificate decision when needed. `session_id` scopes the prompts;
/// `vault_id` is the vault the caller expects the host in.
pub async fn connect<R: Runtime>(
    app: &AppHandle<R>,
    session_id: Uuid,
    host_id: Uuid,
    vault_id: Option<Uuid>,
) -> Result<Connection> {
    let state = app.state::<AppState>();
    let resolved = state.store()?.resolve_host_in(host_id, vault_id)?;
    let Some(cfg) = resolved.s3.clone() else {
        return Err(DesktopError::invalid("this host has no S3 section"));
    };
    let address = &resolved.host.data.address;
    let identity = resolved.s3_identity.as_ref().map(|i| &i.data);
    let mut base = s3::config_for(address, &cfg)?.with_identity(identity)?;
    base.proxy = match &resolved.proxy {
        Some(p) => Some(crate::sessions::proxy_config(&state, &p.data)?),
        None => None,
    };
    let display = s3::display_url(address, &cfg).unwrap_or_else(|_| address.clone());
    let access_key = base.access_key.clone();
    if access_key.is_empty() {
        return Err(DesktopError::invalid(
            "this host's S3 section has no access key",
        ));
    }
    let mut secret = Some(Zeroizing::new(base.secret_key.clone())).filter(|s| !s.is_empty());
    let mut tls = base.tls.clone();
    let mut attempts = 0;
    let mut asked = false;

    loop {
        if secret.is_none() {
            if attempts >= MAX_SECRET_ATTEMPTS {
                return Err(DesktopError::invalid("S3 secret key rejected"));
            }
            attempts += 1;
            let answer = state
                .prompts
                .ask(
                    app,
                    session_id,
                    display.clone(),
                    PromptRequest::Password {
                        username: access_key.clone(),
                        retry: asked,
                    },
                )
                .await;
            asked = true;
            match answer {
                Some(PromptAnswer::Secret { value, remember }) => {
                    if remember {
                        remember_secret(&state, &resolved, &value);
                    }
                    secret = Some(value);
                }
                _ => return Err(CoreError::Cancelled.into()),
            }
        }
        let attempt = S3Config {
            secret_key: secret.as_ref().map(|s| s.to_string()).unwrap_or_default(),
            tls: tls.clone(),
            connect_timeout: CONNECT_TIMEOUT,
            spool_dir: Some(spool_dir()),
            ..base.clone()
        };
        match S3::connect(attempt).await {
            Ok(s3) => {
                return Ok(Connection {
                    label: resolved.host.data.label.clone(),
                    display,
                    fs: Arc::new(s3),
                });
            }
            Err(CoreError::CertificateRejected { host, fingerprint })
                if matches!(tls, TlsPolicy::System) =>
            {
                let answer = state
                    .prompts
                    .ask(
                        app,
                        session_id,
                        display.clone(),
                        PromptRequest::Certificate {
                            host,
                            fingerprint: fingerprint.clone(),
                        },
                    )
                    .await;
                match answer {
                    Some(PromptAnswer::HostKey {
                        decision: HostKeyDecision::AcceptOnce,
                    }) => tls = TlsPolicy::Pinned(fingerprint),
                    Some(PromptAnswer::HostKey {
                        decision: HostKeyDecision::AcceptAndSave,
                    }) => {
                        pin_certificate(&state, &resolved, &fingerprint);
                        tls = TlsPolicy::Pinned(fingerprint);
                    }
                    _ => return Err(CoreError::Cancelled.into()),
                }
            }
            // A wrong secret is a 403 from the server; ask again.
            Err(CoreError::S3 {
                status: Some(403), ..
            }) if attempts < MAX_SECRET_ATTEMPTS => {
                secret = None;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Persist an accepted certificate on the host's S3 section.
fn pin_certificate(state: &AppState, resolved: &ResolvedHost, fingerprint: &str) {
    let Some(cfg_id) = resolved.host.data.s3_config_id else {
        return;
    };
    let Some(mut cfg) = resolved.s3.clone() else {
        return;
    };
    cfg.certificate_fingerprint = Some(fingerprint.to_string());
    if let Err(e) = state.store().and_then(|s| Ok(s.update(cfg_id, &cfg)?)) {
        tracing::warn!(error = %e, "could not pin S3 certificate");
    }
}

/// Store a secret key the user asked to remember on the section's identity.
fn remember_secret(state: &AppState, resolved: &ResolvedHost, value: &Zeroizing<String>) {
    let Some(ident) = &resolved.s3_identity else {
        return;
    };
    let data = Identity {
        password: Some(value.to_string()),
        ..ident.data.clone()
    };
    if let Err(e) = state.store().and_then(|s| Ok(s.update(ident.id, &data)?)) {
        tracing::warn!(error = %e, "could not remember S3 secret key");
    }
}
