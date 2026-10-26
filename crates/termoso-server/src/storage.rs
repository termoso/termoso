//! Object storage for client-encrypted session logs: S3-compatible, or a
//! directory on the server's disk (`TERMOSO_LOGS_DIR`) for installs without an
//! object store. The local backend hands clients the same kind of short-lived
//! upload / download URLs (`/api/v1/logs/blob/{token}`, token sealed with the
//! master key), so clients do not know which one is behind.

use std::time::Duration;

use anyhow::Context;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::presigning::PresigningConfig;

use termoso_crypto::aead::Aad;

use crate::config::S3Config;

#[derive(Clone)]
pub struct Storage {
    backend: Backend,
    presign_ttl: Duration,
}

#[derive(Clone)]
enum Backend {
    S3 {
        client: Client,
        /// Client used only to *sign* URLs handed to end users (public endpoint).
        presign_client: Client,
        bucket: String,
    },
    Local {
        dir: std::path::PathBuf,
        /// `https://…/api/v1/logs/blob` — where tokens are redeemed.
        public_base: String,
        key: termoso_crypto::keys::SymmetricKey,
    },
}

/// What a local blob token authorises.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BlobGrant {
    pub key: String,
    /// `put` or `get`.
    pub method: String,
    /// Upper bound for uploads.
    pub max_len: i64,
    /// Unix seconds.
    pub exp: i64,
}

const BLOB_AAD: &str = "logs_blob";

pub struct Presigned {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub expires_in: u64,
}

impl Storage {
    pub async fn new(cfg: &S3Config) -> anyhow::Result<Self> {
        let build = |endpoint: Option<&str>| {
            let creds = Credentials::new(&cfg.access_key, &cfg.secret_key, None, None, "termoso");
            let mut b = aws_sdk_s3::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .credentials_provider(creds)
                .region(Region::new(
                    cfg.region.clone().unwrap_or_else(|| "us-east-1".into()),
                ))
                .force_path_style(cfg.force_path_style);
            if let Some(ep) = endpoint {
                b = b.endpoint_url(ep);
            }
            Client::from_conf(b.build())
        };
        let client = build(cfg.endpoint.as_deref());
        let presign_client = build(cfg.public_endpoint.as_deref().or(cfg.endpoint.as_deref()));
        Ok(Self {
            backend: Backend::S3 {
                client,
                presign_client,
                bucket: cfg.bucket.clone(),
            },
            presign_ttl: Duration::from_secs(cfg.presign_secs),
        })
    }

    /// Store blobs under `dir`; tokens are sealed with `key` and redeemed at
    /// `{public_url}/api/v1/logs/blob/{token}`.
    pub fn local(
        dir: std::path::PathBuf,
        public_url: &str,
        key: termoso_crypto::keys::SymmetricKey,
    ) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Self {
            backend: Backend::Local {
                dir,
                public_base: format!("{}/api/v1/logs/blob", public_url.trim_end_matches('/')),
                key,
            },
            presign_ttl: Duration::from_secs(900),
        })
    }

    pub fn is_local(&self) -> bool {
        matches!(self.backend, Backend::Local { .. })
    }

    fn local_path(dir: &std::path::Path, key: &str) -> anyhow::Result<std::path::PathBuf> {
        if key.is_empty()
            || key
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            anyhow::bail!("bad object key");
        }
        Ok(dir.join(key))
    }

    fn seal(&self, grant: &BlobGrant) -> anyhow::Result<String> {
        let Backend::Local { key, .. } = &self.backend else {
            anyhow::bail!("not a local store");
        };
        let bytes = termoso_crypto::aead::encrypt(
            key,
            &Aad::server(BLOB_AAD),
            &serde_json::to_vec(grant)?,
        )?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            bytes,
        ))
    }

    /// Validate a local blob token: returns the grant when it is intact and unexpired.
    pub fn open_grant(&self, token: &str) -> anyhow::Result<BlobGrant> {
        let Backend::Local { key, .. } = &self.backend else {
            anyhow::bail!("not a local store");
        };
        let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token)?;
        let plain = termoso_crypto::aead::decrypt(key, &Aad::server(BLOB_AAD), &raw)?;
        let grant: BlobGrant = serde_json::from_slice(&plain)?;
        if grant.exp < chrono::Utc::now().timestamp() {
            anyhow::bail!("token expired");
        }
        Ok(grant)
    }

    /// Local backend: where `key` lives on disk.
    pub fn local_file(&self, key: &str) -> anyhow::Result<std::path::PathBuf> {
        let Backend::Local { dir, .. } = &self.backend else {
            anyhow::bail!("not a local store");
        };
        Self::local_path(dir, key)
    }

    pub async fn ensure_bucket(&self) -> anyhow::Result<()> {
        let Backend::S3 { client, bucket, .. } = &self.backend else {
            return Ok(());
        };
        match client.head_bucket().bucket(bucket).send().await {
            Ok(_) => Ok(()),
            Err(_) => {
                client
                    .create_bucket()
                    .bucket(bucket)
                    .send()
                    .await
                    .with_context(|| format!("creating bucket {bucket}"))?;
                Ok(())
            }
        }
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        match &self.backend {
            Backend::S3 { client, bucket, .. } => {
                client.head_bucket().bucket(bucket).send().await?;
                Ok(())
            }
            Backend::Local { dir, .. } => {
                tokio::fs::metadata(dir).await?;
                Ok(())
            }
        }
    }

    fn grant(&self, key: &str, method: &str, max_len: i64) -> anyhow::Result<Presigned> {
        let Backend::Local { public_base, .. } = &self.backend else {
            anyhow::bail!("not a local store");
        };
        let token = self.seal(&BlobGrant {
            key: key.to_string(),
            method: method.to_string(),
            max_len,
            exp: chrono::Utc::now().timestamp() + self.presign_ttl.as_secs() as i64,
        })?;
        Ok(Presigned {
            url: format!("{public_base}/{token}"),
            headers: Vec::new(),
            expires_in: self.presign_ttl.as_secs(),
        })
    }

    fn presign_cfg(&self) -> anyhow::Result<PresigningConfig> {
        Ok(PresigningConfig::expires_in(self.presign_ttl)?)
    }

    pub async fn presign_put(&self, key: &str, max_len: i64) -> anyhow::Result<Presigned> {
        let Backend::S3 {
            presign_client,
            bucket,
            ..
        } = &self.backend
        else {
            return self.grant(key, "put", max_len);
        };
        let req = presign_client
            .put_object()
            .bucket(bucket)
            .key(key)
            .content_length(max_len)
            .presigned(self.presign_cfg()?)
            .await?;
        Ok(Presigned {
            url: req.uri().to_string(),
            headers: req
                .headers()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            expires_in: self.presign_ttl.as_secs(),
        })
    }

    pub async fn presign_get(&self, key: &str) -> anyhow::Result<Presigned> {
        let Backend::S3 {
            presign_client,
            bucket,
            ..
        } = &self.backend
        else {
            return self.grant(key, "get", 0);
        };
        let req = presign_client
            .get_object()
            .bucket(bucket)
            .key(key)
            .presigned(self.presign_cfg()?)
            .await?;
        Ok(Presigned {
            url: req.uri().to_string(),
            headers: Vec::new(),
            expires_in: self.presign_ttl.as_secs(),
        })
    }

    /// Actual size of an uploaded object, `None` if it does not exist.
    pub async fn object_size(&self, key: &str) -> anyhow::Result<Option<i64>> {
        let Backend::S3 { client, bucket, .. } = &self.backend else {
            return match tokio::fs::metadata(self.local_file(key)?).await {
                Ok(m) => Ok(Some(m.len() as i64)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e.into()),
            };
        };
        match client.head_object().bucket(bucket).key(key).send().await {
            Ok(head) => Ok(head.content_length()),
            Err(e) => {
                if e.as_service_error()
                    .map(|s| s.is_not_found())
                    .unwrap_or(false)
                {
                    Ok(None)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    pub async fn delete(&self, key: &str) -> anyhow::Result<()> {
        let Backend::S3 { client, bucket, .. } = &self.backend else {
            return match tokio::fs::remove_file(self.local_file(key)?).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            };
        };
        client
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await?;
        Ok(())
    }
}
