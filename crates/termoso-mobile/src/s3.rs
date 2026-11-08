//! S3 buckets opened from the file browser. Credentials come from the
//! host's S3 section (an encrypted identity: access key + secret); a missing
//! secret and an untrusted certificate go through the same prompt broker the
//! SSH path uses, so Kotlin handles them like a password / host-key question.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use termoso_core::error::CoreError;
use termoso_core::model::{Identity, ResolvedHost};
use termoso_core::s3::{self, S3, S3Config};
use termoso_core::store::Store;
use termoso_core::webdav::TlsPolicy;
use zeroize::Zeroizing;

use crate::connect::{ConnectStage, Connector, HostKeyChoice, PromptAnswer, PromptRequest};
use crate::error::{MobileError, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_SECRET_ATTEMPTS: u32 = 3;

/// Open the S3 section of `resolved`, asking through `conn` for the secret
/// key or a certificate decision when the saved ones are not enough.
pub(crate) async fn connect_s3(
    conn: &Arc<Connector>,
    resolved: &ResolvedHost,
    spool_dir: PathBuf,
) -> Result<S3> {
    let Some(cfg) = resolved.s3.clone() else {
        return Err(MobileError::invalid("this host has no S3 section"));
    };
    let address = &resolved.host.data.address;
    let identity = resolved.s3_identity.as_ref().map(|i| &i.data);
    let mut base = s3::config_for(address, &cfg)?.with_identity(identity)?;
    base.proxy = match &resolved.proxy {
        Some(p) => Some(crate::connect::proxy_config(&conn.store, &p.data)?),
        None => None,
    };
    let display = s3::display_url(address, &cfg).unwrap_or_else(|_| address.clone());
    let access_key = base.access_key.clone();
    if access_key.is_empty() {
        return Err(MobileError::invalid(
            "this host's S3 section has no access key",
        ));
    }
    let mut secret = Some(Zeroizing::new(base.secret_key.clone())).filter(|s| !s.is_empty());
    let mut tls = base.tls.clone();
    let mut attempts = 0;
    let mut asked = false;

    conn.ui.phase(
        ConnectStage::ConnectingTo {
            target: display.clone(),
        },
        None,
    );
    loop {
        if secret.is_none() {
            if attempts >= MAX_SECRET_ATTEMPTS {
                return Err(MobileError::invalid("S3 secret key rejected"));
            }
            attempts += 1;
            let answer = conn
                .ask(PromptRequest::Password {
                    username: access_key.clone(),
                    retry: asked,
                })
                .await;
            asked = true;
            match answer {
                Some(PromptAnswer::Secret { value, remember }) => {
                    let value = Zeroizing::new(value);
                    if remember {
                        remember_secret(&conn.store, resolved, &value);
                    }
                    secret = Some(value);
                }
                _ => {
                    conn.give_up();
                    return Err(MobileError::Cancelled);
                }
            }
        }
        let attempt = S3Config {
            secret_key: secret.as_ref().map(|s| s.to_string()).unwrap_or_default(),
            tls: tls.clone(),
            connect_timeout: CONNECT_TIMEOUT,
            spool_dir: Some(spool_dir.clone()),
            ..base.clone()
        };
        match S3::connect(attempt).await {
            Ok(s3) => return Ok(s3),
            Err(CoreError::CertificateRejected { host, fingerprint })
                if matches!(tls, TlsPolicy::System) =>
            {
                let answer = conn
                    .ask(PromptRequest::Certificate {
                        host,
                        fingerprint: fingerprint.clone(),
                    })
                    .await;
                match answer {
                    Some(PromptAnswer::HostKey {
                        decision: HostKeyChoice::AcceptOnce,
                    }) => tls = TlsPolicy::Pinned(fingerprint),
                    Some(PromptAnswer::HostKey {
                        decision: HostKeyChoice::AcceptAndSave,
                    }) => {
                        pin_certificate(&conn.store, resolved, &fingerprint);
                        tls = TlsPolicy::Pinned(fingerprint);
                    }
                    _ => {
                        conn.give_up();
                        return Err(MobileError::Cancelled);
                    }
                }
            }
            // A wrong secret is a 403 from the server; ask again (the saved
            // one counts as the first attempt).
            Err(CoreError::S3 {
                status: Some(403), ..
            }) if attempts < MAX_SECRET_ATTEMPTS => {
                attempts += 1;
                let answer = conn
                    .ask(PromptRequest::Password {
                        username: access_key.clone(),
                        retry: true,
                    })
                    .await;
                asked = true;
                match answer {
                    Some(PromptAnswer::Secret { value, remember }) => {
                        let value = Zeroizing::new(value);
                        if remember {
                            remember_secret(&conn.store, resolved, &value);
                        }
                        secret = Some(value);
                    }
                    _ => {
                        conn.give_up();
                        return Err(MobileError::Cancelled);
                    }
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Persist an accepted certificate on the host's S3 section.
fn pin_certificate(store: &Store, resolved: &ResolvedHost, fingerprint: &str) {
    let Some(cfg_id) = resolved.host.data.s3_config_id else {
        return;
    };
    let Some(mut cfg) = resolved.s3.clone() else {
        return;
    };
    cfg.certificate_fingerprint = Some(fingerprint.to_string());
    if let Err(e) = store.update(cfg_id, &cfg) {
        tracing::warn!("pin S3 certificate: {e}");
    }
}

/// Store a secret key the user asked to remember on the section's identity
/// (the access key lives there, so a prompt implies the identity exists).
fn remember_secret(store: &Store, resolved: &ResolvedHost, value: &Zeroizing<String>) {
    let Some(ident) = &resolved.s3_identity else {
        return;
    };
    let data = Identity {
        password: Some(value.to_string()),
        ..ident.data.clone()
    };
    if let Err(e) = store.update(ident.id, &data) {
        tracing::warn!("remember S3 secret: {e}");
    }
}
