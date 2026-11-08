//! S3-compatible object storage (AWS S3, MinIO, RustFS, Cloudflare R2,
//! Backblaze B2, Ceph RGW, …) as a [`RemoteFs`], so the file panels, transfer
//! queues and offline copies drive a bucket exactly like an SFTP or WebDAV
//! host.
//!
//! A bucket has keys, not directories. The client shows the usual tree the
//! way every S3 console does: `/` in a key separates "folders", a listing is
//! `ListObjectsV2` with `delimiter=/`, and an empty "folder" is a zero-byte
//! object whose key ends in `/` (the marker MinIO, RustFS and the AWS console
//! create). What S3 has no answer for is reported through
//! [`RemoteCapabilities`]: no permission bits, owners or symlinks. Rename is
//! `CopyObject` + `DeleteObject` per key, which is what every S3 client does;
//! it is still exposed as `rename` because the result is the same for the
//! user, but it costs a copy and is not atomic.
//!
//! Requests are signed with Signature V4 ([`crate::cloud::sigv4`]); the HTTP
//! transport (TLS policy, pinned certificates, private CA, client certificate,
//! SNI override, proxy) is the WebDAV one.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use futures::StreamExt;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::header;
use reqwest::{Method, Response, StatusCode};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::cloud::sigv4::{self, GenericRequest};
use crate::cloud::xml;
use crate::error::{CoreError, Result};
use crate::remote::{self, RemoteCapabilities, RemoteFs, RemoteProtocol};
use crate::sftp::{EntryKind, OpenMode, RemoteEntry, Throttle, TransferOptions};
use crate::webdav::{self, ClientIdentity, TlsPolicy, WebDavConfig, normalize_path};

/// Largest file [`RemoteFs::read`] loads into memory.
const MAX_IN_MEMORY: u64 = 64 * 1024 * 1024;
/// Uploads at least this large go through a multipart upload.
const MULTIPART_THRESHOLD: u64 = 16 * 1024 * 1024;
/// Part size of a multipart upload (grown when 10 000 parts would not do).
const PART_SIZE: u64 = 16 * 1024 * 1024;
/// S3 rejects a single `CopyObject` above 5 GiB; larger copies go by parts.
const MAX_SINGLE_COPY: u64 = 5 * 1024 * 1024 * 1024;
/// Part size of a multipart copy.
const COPY_PART_SIZE: u64 = 1024 * 1024 * 1024;
/// Most parts S3 allows in one multipart upload.
const MAX_PARTS: u64 = 10_000;
/// Objects deleted concurrently when removing a tree.
const DELETE_PARALLEL: usize = 8;
/// Region used when the config leaves it empty (what MinIO/RustFS default to
/// and what AWS uses for the global endpoint).
pub const DEFAULT_REGION: &str = "us-east-1";

/// Where a bucket is and how to sign for it.
#[derive(Clone)]
pub struct S3Config {
    /// Endpoint URL: `https://s3.eu-central-1.amazonaws.com`,
    /// `https://<account>.r2.cloudflarestorage.com`, `http://10.0.0.5:9000`.
    /// A path is allowed for servers mounted below a prefix.
    pub endpoint: String,
    /// Bucket name.
    pub bucket: String,
    /// Signing region; empty = [`DEFAULT_REGION`] (`auto` for R2).
    pub region: String,
    /// Key prefix the share's `/` maps to (`backups/2026`); empty = bucket
    /// root.
    pub prefix: String,
    /// `endpoint/bucket/key` (MinIO, RustFS, most self-hosted servers) rather
    /// than `bucket.endpoint/key` (AWS default).
    pub path_style: bool,
    /// Access key ID.
    pub access_key: String,
    /// Secret access key.
    pub secret_key: String,
    /// Session token of temporary credentials (STS), sent as
    /// `x-amz-security-token`.
    pub session_token: Option<String>,
    /// Certificate policy.
    pub tls: TlsPolicy,
    /// TLS name when it differs from the endpoint's host (see
    /// [`WebDavConfig::server_name`]).
    pub server_name: Option<String>,
    /// Addresses of the endpoint host when `server_name` redirects the name
    /// check; [`S3::connect`] fills them.
    pub resolved_addrs: Option<Vec<SocketAddr>>,
    /// Client certificate for servers that require mTLS.
    pub client_identity: Option<ClientIdentity>,
    /// TCP + TLS connect deadline.
    pub connect_timeout: Duration,
    /// Where write-mode files spool before the upload; defaults to the OS
    /// temp dir (pass the app cache dir on Android).
    pub spool_dir: Option<PathBuf>,
    /// Optional SOCKS/HTTP proxy every request goes through.
    pub proxy: Option<crate::ssh::proxy::ProxyConfig>,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            bucket: String::new(),
            region: String::new(),
            prefix: String::new(),
            path_style: true,
            access_key: String::new(),
            secret_key: String::new(),
            session_token: None,
            tls: TlsPolicy::System,
            server_name: None,
            resolved_addrs: None,
            client_identity: None,
            connect_timeout: Duration::from_secs(20),
            spool_dir: None,
            proxy: None,
        }
    }
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("prefix", &self.prefix)
            .field("path_style", &self.path_style)
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .field("tls", &self.tls)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl S3Config {
    /// Endpoint URL with the bucket in the host for virtual-host addressing.
    fn origin(&self) -> Result<Url> {
        let mut url = webdav::normalize_url(self.endpoint.trim())?;
        if !self.path_style {
            let host = url
                .host_str()
                .ok_or_else(|| CoreError::Invalid("endpoint has no host".into()))?
                .to_string();
            if matches!(url.host(), Some(url::Host::Ipv4(_) | url::Host::Ipv6(_))) {
                return Err(CoreError::Invalid(
                    "virtual-host addressing needs a hostname, not an IP; use path style".into(),
                ));
            }
            url.set_host(Some(&format!("{}.{host}", self.bucket)))
                .map_err(|_| CoreError::Invalid(format!("bad bucket name {:?}", self.bucket)))?;
        }
        Ok(url)
    }

    /// The transport part, in the shape the WebDAV client builder takes.
    fn transport(&self) -> Result<WebDavConfig> {
        Ok(WebDavConfig {
            url: self.origin()?.to_string(),
            username: None,
            password: None,
            bearer_token: None,
            tls: self.tls.clone(),
            server_name: self.server_name.clone(),
            resolved_addrs: self.resolved_addrs.clone(),
            client_identity: self.client_identity.clone(),
            connect_timeout: self.connect_timeout,
            spool_dir: self.spool_dir.clone(),
            proxy: self.proxy.clone(),
        })
    }
}

/// Validate a bucket name the way S3 does (3–63 chars, lowercase letters,
/// digits, `.` and `-`, no leading/trailing separators).
pub fn validate_bucket(name: &str) -> Result<String> {
    let n = name.trim();
    let ok = (3..=63).contains(&n.len())
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !n.starts_with(['.', '-'])
        && !n.ends_with(['.', '-'])
        && !n.contains("..");
    if ok {
        Ok(n.to_string())
    } else {
        Err(CoreError::Invalid(format!("invalid bucket name {name:?}")))
    }
}

/// Normalise a key prefix to `a/b/` form (empty for the bucket root).
pub fn normalize_prefix(prefix: &str) -> String {
    let p = normalize_path(prefix).unwrap_or_else(|_| "/".into());
    match p.trim_matches('/') {
        "" => String::new(),
        s => format!("{s}/"),
    }
}

/// Characters AWS leaves unencoded in URIs (RFC 3986 unreserved).
const AWS_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

fn aws_encode(s: &str) -> String {
    utf8_percent_encode(s, AWS_ENCODE).to_string()
}

/// URI-encode an object key for the request path (`/` kept).
fn encode_key(key: &str) -> String {
    key.split('/').map(aws_encode).collect::<Vec<_>>().join("/")
}

fn s3_err(status: Option<u16>, message: impl Into<String>) -> CoreError {
    CoreError::S3 {
        status,
        message: message.into(),
    }
}

/// One object as a listing or HEAD reports it.
#[derive(Debug, Clone)]
struct Object {
    key: String,
    size: u64,
    mtime: Option<u32>,
}

#[derive(Debug, Default)]
struct ListPage {
    objects: Vec<Object>,
    prefixes: Vec<String>,
    next: Option<String>,
}

struct Inner {
    http: reqwest::Client,
    base: Url,
    /// Decoded path of `base`, with trailing slash (`/` or `/bucket/`).
    base_path: String,
    /// `host[:port]` for messages.
    host: String,
    bucket: String,
    region: String,
    /// `a/b/` or empty.
    prefix: String,
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
    has_client_identity: bool,
    spool_dir: PathBuf,
}

/// A bucket (or a prefix inside one) seen as a filesystem.
#[derive(Clone)]
pub struct S3 {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for S3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3")
            .field("host", &self.inner.host)
            .field("bucket", &self.inner.bucket)
            .field("prefix", &self.inner.prefix)
            .finish()
    }
}

impl S3 {
    /// Build a client without touching the network.
    pub fn new(cfg: S3Config) -> Result<Self> {
        let bucket = validate_bucket(&cfg.bucket)?;
        if cfg.access_key.trim().is_empty() || cfg.secret_key.trim().is_empty() {
            return Err(CoreError::Invalid(
                "access key and secret key are required".into(),
            ));
        }
        let webdav::Transport { http, base, host } = webdav::transport(&cfg.transport()?)?;
        let mut base_path = base.path().to_string();
        if !base_path.ends_with('/') {
            base_path.push('/');
        }
        if cfg.path_style {
            base_path.push_str(&bucket);
            base_path.push('/');
        }
        let region = match cfg.region.trim() {
            "" => DEFAULT_REGION.to_string(),
            r => r.to_string(),
        };
        Ok(Self {
            inner: Arc::new(Inner {
                http,
                base,
                base_path,
                host,
                bucket,
                region,
                prefix: normalize_prefix(&cfg.prefix),
                access_key: cfg.access_key.trim().to_string(),
                secret_key: cfg.secret_key.trim().to_string(),
                session_token: cfg
                    .session_token
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty()),
                has_client_identity: cfg.client_identity.is_some(),
                spool_dir: cfg.spool_dir.unwrap_or_else(std::env::temp_dir),
            }),
        })
    }

    /// Build and verify: the bucket must answer a listing of the root
    /// prefix. A certificate the policy does not trust surfaces as
    /// [`CoreError::CertificateRejected`] carrying its fingerprint.
    pub async fn connect(mut cfg: S3Config) -> Result<Self> {
        let mut probe = cfg.transport()?;
        if let Some((host, port)) =
            webdav::needs_lookup(&probe).filter(|_| cfg.resolved_addrs.is_none())
        {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|e| s3_err(None, format!("cannot resolve {host}: {e}")))?
                .collect();
            cfg.resolved_addrs = Some(addrs.clone());
            probe.resolved_addrs = Some(addrs);
        }
        let s3 = Self::new(cfg)?;
        match s3
            .list_page(&s3.inner.prefix, Some("/"), None, Some(1))
            .await
        {
            Ok(_) => Ok(s3),
            Err(CoreError::Http(e))
                if s3.inner.base.scheme() == "https" && webdav::is_tls_error(&e) =>
            {
                let fingerprint = webdav::probe_certificate(&probe).await.unwrap_or_default();
                Err(CoreError::CertificateRejected {
                    host: s3.inner.host.clone(),
                    fingerprint,
                })
            }
            Err(CoreError::Http(e)) => match webdav::client_certificate_alert(&e) {
                Some(alert) if s3.inner.has_client_identity => Err(s3_err(
                    None,
                    format!(
                        "{} rejected the client certificate ({alert})",
                        s3.inner.host
                    ),
                )),
                Some(alert) => Err(s3_err(
                    None,
                    format!("{} requires a client certificate ({alert})", s3.inner.host),
                )),
                None => Err(CoreError::Http(e)),
            },
            Err(e) => Err(e),
        }
    }

    /// Create the bucket (`PutBucket`); a bucket this key already owns is
    /// fine. For first-run setups against a self-hosted server.
    pub async fn create_bucket(&self) -> Result<()> {
        let body = if self.inner.region == DEFAULT_REGION {
            Bytes::new()
        } else {
            Bytes::from(format!(
                "<CreateBucketConfiguration><LocationConstraint>{}</LocationConstraint></CreateBucketConfiguration>",
                xml_escape(&self.inner.region)
            ))
        };
        let resp = self.call(Method::PUT, "", &[], &[], body).await?;
        match Self::check(resp, "/").await {
            Ok(_) => Ok(()),
            Err(CoreError::S3 { message, .. })
                if message.starts_with("BucketAlreadyOwnedByYou")
                    || message.starts_with("BucketAlreadyExists") =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// `host[:port]` of the endpoint.
    pub fn host(&self) -> &str {
        &self.inner.host
    }

    /// Bucket name.
    pub fn bucket(&self) -> &str {
        &self.inner.bucket
    }

    /// Object key of a share path (`/a/b` → `prefix/a/b`, `/` → `prefix/`);
    /// `dir` appends the folder-marker slash.
    fn key_of(&self, path: &str, dir: bool) -> String {
        let rel = path.trim_matches('/');
        let mut key = self.inner.prefix.clone();
        key.push_str(rel);
        if dir && !rel.is_empty() {
            key.push('/');
        }
        key
    }

    /// Share path of an object key under the prefix.
    fn path_of(&self, key: &str) -> String {
        let rel = key.strip_prefix(self.inner.prefix.as_str()).unwrap_or(key);
        format!("/{}", rel.trim_end_matches('/'))
    }

    /// Request URL and canonical query for `key` (empty key = the bucket).
    fn url_for(&self, key: &str, query: &[(&str, &str)]) -> Result<(Url, String)> {
        let mut url = self.inner.base.clone();
        let path = format!("{}{}", self.inner.base_path, encode_key(key));
        url.set_path(&path);
        let mut pairs: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (aws_encode(k), aws_encode(v)))
            .collect();
        pairs.sort();
        let canonical = pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        url.set_query(if canonical.is_empty() {
            None
        } else {
            Some(&canonical)
        });
        Ok((url, canonical))
    }

    /// Send a signed request. `headers` are signed too (all `x-amz-*`
    /// headers must be); `payload_hash` is the body's SHA-256.
    async fn send(
        &self,
        method: Method,
        key: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: Option<reqwest::Body>,
        payload_hash: &str,
    ) -> Result<Response> {
        let (url, canonical_query) = self.url_for(key, query)?;
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or("")),
            None => url.host_str().unwrap_or("").to_string(),
        };
        let mut signed_headers: Vec<(&str, &str)> = vec![("x-amz-content-sha256", payload_hash)];
        if let Some(t) = &self.inner.session_token {
            signed_headers.push(("x-amz-security-token", t));
        }
        signed_headers.extend_from_slice(headers);
        let signed = sigv4::sign_request(
            &GenericRequest {
                method: method.as_str(),
                service: "s3",
                region: &self.inner.region,
                host: &host,
                path: url.path(),
                query: &canonical_query,
                headers: &signed_headers,
                payload_hash,
            },
            &self.inner.access_key,
            &self.inner.secret_key,
            Utc::now(),
        );
        let mut rb = self
            .inner
            .http
            .request(method, url)
            .header(header::AUTHORIZATION, signed.authorization)
            .header("x-amz-date", signed.amz_date);
        for (k, v) in &signed_headers {
            rb = rb.header(*k, *v);
        }
        if let Some(b) = body {
            rb = rb.body(b);
        }
        Ok(rb.send().await?)
    }

    /// Small request with an in-memory body (or none).
    async fn call(
        &self,
        method: Method,
        key: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: Bytes,
    ) -> Result<Response> {
        let hash = hex::encode(Sha256::digest(&body));
        let body = if body.is_empty() && !matches!(method, Method::PUT | Method::POST) {
            None
        } else {
            Some(reqwest::Body::from(body))
        };
        self.send(method, key, query, headers, body, &hash).await
    }

    /// Turn a non-2xx answer into an error, reading the S3 error document.
    async fn check(resp: Response, path: &str) -> Result<Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let text = resp.text().await.unwrap_or_default();
        Err(Self::error_from(status, &text, path))
    }

    fn error_from(status: StatusCode, body: &str, path: &str) -> CoreError {
        let doc = xml::parse(body).ok();
        let code = doc
            .as_ref()
            .and_then(|d| d.text_of("Code"))
            .unwrap_or("")
            .to_string();
        let message = doc
            .as_ref()
            .and_then(|d| d.text_of("Message"))
            .unwrap_or("")
            .to_string();
        if status == StatusCode::NOT_FOUND || code == "NoSuchKey" {
            if code == "NoSuchBucket" {
                return s3_err(Some(status.as_u16()), "bucket does not exist");
            }
            return CoreError::NotFound(path.to_string());
        }
        let detail = match (code.as_str(), message.as_str()) {
            ("", "") => status
                .canonical_reason()
                .unwrap_or("request failed")
                .to_string(),
            (c, "") => c.to_string(),
            ("", m) => m.to_string(),
            (c, m) => format!("{c}: {m}"),
        };
        let detail = match code.as_str() {
            "AccessDenied" | "InvalidAccessKeyId" | "SignatureDoesNotMatch" => {
                format!("{detail} (check the access key, secret and region)")
            }
            "AuthorizationHeaderMalformed" | "IllegalLocationConstraintException" => {
                format!("{detail} (the bucket is in another region)")
            }
            _ => detail,
        };
        s3_err(Some(status.as_u16()), detail)
    }

    /// One page of `ListObjectsV2`.
    async fn list_page(
        &self,
        prefix: &str,
        delimiter: Option<&str>,
        token: Option<&str>,
        max_keys: Option<u32>,
    ) -> Result<ListPage> {
        let max = max_keys.map(|m| m.to_string());
        let mut query: Vec<(&str, &str)> = vec![("list-type", "2"), ("prefix", prefix)];
        if let Some(d) = delimiter {
            query.push(("delimiter", d));
        }
        if let Some(t) = token {
            query.push(("continuation-token", t));
        }
        if let Some(m) = &max {
            query.push(("max-keys", m));
        }
        let resp = self
            .call(Method::GET, "", &query, &[], Bytes::new())
            .await?;
        let resp = Self::check(resp, &self.path_of(prefix)).await?;
        let text = resp.text().await?;
        let doc = xml::parse(&text).map_err(|e| s3_err(None, format!("bad listing: {e}")))?;
        let mut page = ListPage::default();
        for c in doc.children("Contents") {
            let Some(key) = c.text_of("Key") else {
                continue;
            };
            page.objects.push(Object {
                key: key.to_string(),
                size: c.text_of("Size").and_then(|s| s.parse().ok()).unwrap_or(0),
                mtime: c.text_of("LastModified").and_then(webdav::parse_http_date),
            });
        }
        for p in doc.children("CommonPrefixes") {
            if let Some(prefix) = p.text_of("Prefix") {
                page.prefixes.push(prefix.to_string());
            }
        }
        if doc.text_of("IsTruncated") == Some("true") {
            page.next = doc.text_of("NextContinuationToken").map(str::to_string);
        }
        Ok(page)
    }

    /// Every object under `prefix` (recursive), oldest page first.
    async fn list_all(
        &self,
        prefix: &str,
        cancel: Option<&CancellationToken>,
    ) -> Result<Vec<Object>> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            if cancel.is_some_and(|c| c.is_cancelled()) {
                return Err(CoreError::Cancelled);
            }
            let page = self.list_page(prefix, None, token.as_deref(), None).await?;
            out.extend(page.objects);
            match page.next {
                Some(t) => token = Some(t),
                None => return Ok(out),
            }
        }
    }

    /// Does anything live under `prefix` (a folder marker or a key)?
    async fn prefix_exists(&self, prefix: &str) -> Result<bool> {
        let page = self.list_page(prefix, None, None, Some(1)).await?;
        Ok(!page.objects.is_empty())
    }

    /// `HEAD` an object.
    async fn head(&self, key: &str) -> Result<Object> {
        let resp = self.call(Method::HEAD, key, &[], &[], Bytes::new()).await?;
        let resp = Self::check(resp, &self.path_of(key)).await?;
        let size = resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mtime = resp
            .headers()
            .get(header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .and_then(webdav::parse_http_date);
        Ok(Object {
            key: key.to_string(),
            size,
            mtime,
        })
    }

    /// What `path` is: a file (object), a folder (marker or prefix with
    /// keys below) or nothing.
    async fn stat_path(&self, path: &str) -> Result<RemoteEntry> {
        let norm = normalize_path(path)?;
        if norm == "/" {
            return Ok(dir_entry("/", None));
        }
        let key = self.key_of(&norm, false);
        match self.head(&key).await {
            Ok(o) => return Ok(file_entry(&norm, &o)),
            Err(CoreError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        let dir_key = self.key_of(&norm, true);
        match self.head(&dir_key).await {
            Ok(o) => return Ok(dir_entry(&norm, o.mtime)),
            Err(CoreError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        if self.prefix_exists(&dir_key).await? {
            return Ok(dir_entry(&norm, None));
        }
        Err(CoreError::NotFound(norm))
    }

    /// Server-side copy of one object, by parts above 5 GiB.
    async fn copy_object(&self, from: &str, to: &str, size: u64) -> Result<()> {
        let source = format!("/{}/{}", aws_encode(&self.inner.bucket), encode_key(from));
        if size <= MAX_SINGLE_COPY {
            let resp = self
                .call(
                    Method::PUT,
                    to,
                    &[],
                    &[
                        ("x-amz-copy-source", &source),
                        ("x-amz-metadata-directive", "COPY"),
                    ],
                    Bytes::new(),
                )
                .await?;
            let resp = Self::check(resp, &self.path_of(from)).await?;
            // A 200 with an <Error> body happens when the copy fails midway.
            let text = resp.text().await.unwrap_or_default();
            if text.contains("<Error>") {
                return Err(Self::error_from(StatusCode::OK, &text, &self.path_of(from)));
            }
            return Ok(());
        }
        let upload = self.create_multipart(to).await?;
        let result = async {
            let mut parts = Vec::new();
            let mut offset = 0u64;
            let mut n = 1u32;
            while offset < size {
                let end = (offset + COPY_PART_SIZE).min(size) - 1;
                let range = format!("bytes={offset}-{end}");
                let num = n.to_string();
                let resp = self
                    .call(
                        Method::PUT,
                        to,
                        &[("partNumber", &num), ("uploadId", &upload)],
                        &[
                            ("x-amz-copy-source", &source),
                            ("x-amz-copy-source-range", &range),
                        ],
                        Bytes::new(),
                    )
                    .await?;
                let resp = Self::check(resp, &self.path_of(from)).await?;
                let text = resp.text().await?;
                let doc =
                    xml::parse(&text).map_err(|e| s3_err(None, format!("bad copy answer: {e}")))?;
                let etag = doc
                    .text_of("ETag")
                    .ok_or_else(|| s3_err(None, "copy part answer has no ETag"))?
                    .to_string();
                parts.push((n, etag));
                offset = end + 1;
                n += 1;
            }
            self.complete_multipart(to, &upload, &parts).await
        }
        .await;
        if result.is_err() {
            let _ = self.abort_multipart(to, &upload).await;
        }
        result
    }

    async fn create_multipart(&self, key: &str) -> Result<String> {
        let resp = self
            .call(Method::POST, key, &[("uploads", "")], &[], Bytes::new())
            .await?;
        let resp = Self::check(resp, &self.path_of(key)).await?;
        let text = resp.text().await?;
        let doc = xml::parse(&text).map_err(|e| s3_err(None, format!("bad upload answer: {e}")))?;
        doc.text_of("UploadId")
            .map(str::to_string)
            .ok_or_else(|| s3_err(None, "multipart upload answer has no UploadId"))
    }

    async fn complete_multipart(
        &self,
        key: &str,
        upload: &str,
        parts: &[(u32, String)],
    ) -> Result<()> {
        let mut body = String::from("<CompleteMultipartUpload>");
        for (n, etag) in parts {
            body.push_str(&format!(
                "<Part><PartNumber>{n}</PartNumber><ETag>{}</ETag></Part>",
                xml_escape(etag)
            ));
        }
        body.push_str("</CompleteMultipartUpload>");
        let resp = self
            .call(
                Method::POST,
                key,
                &[("uploadId", upload)],
                &[],
                Bytes::from(body),
            )
            .await?;
        let resp = Self::check(resp, &self.path_of(key)).await?;
        let text = resp.text().await.unwrap_or_default();
        if text.contains("<Error>") {
            return Err(Self::error_from(StatusCode::OK, &text, &self.path_of(key)));
        }
        Ok(())
    }

    async fn abort_multipart(&self, key: &str, upload: &str) -> Result<()> {
        let resp = self
            .call(
                Method::DELETE,
                key,
                &[("uploadId", upload)],
                &[],
                Bytes::new(),
            )
            .await?;
        Self::check(resp, &self.path_of(key)).await.map(|_| ())
    }

    /// Upload one part from memory; returns its ETag.
    async fn upload_part(&self, key: &str, upload: &str, n: u32, data: Vec<u8>) -> Result<String> {
        let num = n.to_string();
        let resp = self
            .call(
                Method::PUT,
                key,
                &[("partNumber", &num), ("uploadId", upload)],
                &[],
                Bytes::from(data),
            )
            .await?;
        let resp = Self::check(resp, &self.path_of(key)).await?;
        resp.headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| s3_err(None, "part upload answer has no ETag"))
    }

    /// Upload a local file to `key`: one `PutObject` below
    /// [`MULTIPART_THRESHOLD`], a multipart upload above it. Progress is
    /// reported per part, pacing honours `rate_limit`.
    async fn put_file(
        &self,
        local: &Path,
        key: &str,
        size: u64,
        opts: &TransferOptions,
    ) -> Result<()> {
        if opts.cancel.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
        let mut file = tokio::fs::File::open(local).await?;
        let mut throttle = Throttle::new(opts.rate_limit);
        if size < MULTIPART_THRESHOLD {
            let mut data = Vec::with_capacity(size as usize);
            file.read_to_end(&mut data).await?;
            let n = data.len();
            let resp = tokio::select! {
                r = self.call(Method::PUT, key, &[], &[], Bytes::from(data)) => r?,
                _ = opts.cancel.cancelled() => return Err(CoreError::Cancelled),
            };
            Self::check(resp, &self.path_of(key)).await?;
            throttle.pace(n, &opts.cancel).await;
            opts.report(size, Some(size));
            return Ok(());
        }
        let part_size = PART_SIZE.max(size.div_ceil(MAX_PARTS).div_ceil(1024 * 1024) * 1024 * 1024);
        let upload = self.create_multipart(key).await?;
        let result = async {
            let mut parts = Vec::new();
            let mut done = 0u64;
            let mut n = 1u32;
            while done < size {
                if opts.cancel.is_cancelled() {
                    return Err(CoreError::Cancelled);
                }
                let want = (size - done).min(part_size) as usize;
                let mut data = vec![0u8; want];
                file.read_exact(&mut data).await?;
                let etag = tokio::select! {
                    r = self.upload_part(key, &upload, n, data) => r?,
                    _ = opts.cancel.cancelled() => return Err(CoreError::Cancelled),
                };
                parts.push((n, etag));
                done += want as u64;
                n += 1;
                opts.report(done, Some(size));
                throttle.pace(want, &opts.cancel).await;
            }
            self.complete_multipart(key, &upload, &parts).await
        }
        .await;
        if result.is_err() {
            let _ = self.abort_multipart(key, &upload).await;
        }
        result
    }

    /// Delete one object (S3 answers 204 whether or not it existed).
    async fn delete_key(&self, key: &str) -> Result<()> {
        let resp = self
            .call(Method::DELETE, key, &[], &[], Bytes::new())
            .await?;
        Self::check(resp, &self.path_of(key)).await.map(|_| ())
    }

    /// Delete many objects, a few at a time.
    async fn delete_keys(&self, keys: Vec<String>, cancel: &CancellationToken) -> Result<()> {
        let mut stream = futures::stream::iter(
            keys.into_iter()
                .map(|k| async move { self.delete_key(&k).await }),
        )
        .buffer_unordered(DELETE_PARALLEL);
        while let Some(r) = stream.next().await {
            if cancel.is_cancelled() {
                return Err(CoreError::Cancelled);
            }
            r?;
        }
        Ok(())
    }

    /// Copy everything under `from_prefix` to `to_prefix` (both `a/b/`).
    async fn copy_tree(
        &self,
        from_prefix: &str,
        to_prefix: &str,
        cancel: &CancellationToken,
    ) -> Result<Vec<Object>> {
        let objects = self.list_all(from_prefix, Some(cancel)).await?;
        for o in &objects {
            if cancel.is_cancelled() {
                return Err(CoreError::Cancelled);
            }
            let rel = o.key.strip_prefix(from_prefix).unwrap_or(&o.key);
            let to = format!("{to_prefix}{rel}");
            self.copy_object(&o.key, &to, o.size).await?;
        }
        Ok(objects)
    }
}

fn empty_hash() -> String {
    hex::encode(Sha256::digest(b""))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn dir_entry(path: &str, mtime: Option<u32>) -> RemoteEntry {
    RemoteEntry {
        name: webdav::name_of(path),
        path: path.to_string(),
        kind: EntryKind::Dir,
        size: None,
        mode: None,
        uid: None,
        gid: None,
        user: None,
        group: None,
        mtime,
        atime: None,
        link_target: None,
        target_kind: None,
    }
}

fn file_entry(path: &str, o: &Object) -> RemoteEntry {
    RemoteEntry {
        name: webdav::name_of(path),
        path: path.to_string(),
        kind: EntryKind::File,
        size: Some(o.size),
        mode: None,
        uid: None,
        gid: None,
        user: None,
        group: None,
        mtime: o.mtime,
        atime: None,
        link_target: None,
        target_kind: None,
    }
}

#[async_trait::async_trait]
impl RemoteFs for S3 {
    fn protocol(&self) -> RemoteProtocol {
        RemoteProtocol::S3
    }

    fn capabilities(&self) -> RemoteCapabilities {
        RemoteCapabilities {
            permissions: false,
            symlinks: false,
            ownership: false,
            server_copy: true,
            resume_upload: false,
        }
    }

    fn home(&self) -> &str {
        "/"
    }

    async fn canonicalize(&self, path: &str) -> Result<String> {
        normalize_path(path)
    }

    async fn list(&self, dir: &str) -> Result<Vec<RemoteEntry>> {
        let norm = normalize_path(dir)?;
        let prefix = self.key_of(&norm, true);
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        let mut seen_any = false;
        loop {
            let page = self
                .list_page(&prefix, Some("/"), token.as_deref(), None)
                .await?;
            seen_any |= !page.objects.is_empty() || !page.prefixes.is_empty();
            for p in page.prefixes {
                let path = self.path_of(&p);
                if path != norm {
                    out.push(dir_entry(&path, None));
                }
            }
            for o in page.objects {
                if o.key == prefix || o.key.ends_with('/') {
                    continue;
                }
                let path = self.path_of(&o.key);
                out.push(file_entry(&path, &o));
            }
            match page.next {
                Some(t) => token = Some(t),
                None => break,
            }
        }
        if !seen_any && norm != "/" {
            // Nothing below: either an empty folder (marker) or no such path.
            self.stat_path(&norm).await?;
        }
        out.sort_by(|a, b| {
            (a.kind != EntryKind::Dir)
                .cmp(&(b.kind != EntryKind::Dir))
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(out)
    }

    async fn stat(&self, path: &str) -> Result<RemoteEntry> {
        self.stat_path(path).await
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        match self.stat_path(path).await {
            Ok(_) => Ok(true),
            Err(CoreError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn mkdir(&self, path: &str) -> Result<()> {
        let norm = normalize_path(path)?;
        if norm == "/" {
            return Ok(());
        }
        match self.stat_path(&norm).await {
            Ok(e) if e.kind == EntryKind::Dir => {
                return Err(s3_err(None, format!("{norm} already exists")));
            }
            Ok(_) => return Err(s3_err(None, format!("{norm} is a file"))),
            Err(CoreError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        let key = self.key_of(&norm, true);
        let resp = self.call(Method::PUT, &key, &[], &[], Bytes::new()).await?;
        Self::check(resp, &norm).await.map(|_| ())
    }

    async fn mkdir_all(&self, path: &str) -> Result<()> {
        let norm = normalize_path(path)?;
        if norm == "/" {
            return Ok(());
        }
        // Keys need no parents; one marker makes the whole chain visible.
        match self.stat_path(&norm).await {
            Ok(e) if e.kind == EntryKind::Dir => Ok(()),
            Ok(_) => Err(s3_err(None, format!("{norm} is a file"))),
            Err(CoreError::NotFound(_)) => {
                let key = self.key_of(&norm, true);
                let resp = self.call(Method::PUT, &key, &[], &[], Bytes::new()).await?;
                Self::check(resp, &norm).await.map(|_| ())
            }
            Err(e) => Err(e),
        }
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let from = normalize_path(from)?;
        let to = normalize_path(to)?;
        if from == "/" || to == "/" {
            return Err(s3_err(None, "cannot rename the root"));
        }
        if to == from || to.starts_with(&format!("{from}/")) {
            return Err(s3_err(None, format!("cannot move {from} into itself")));
        }
        if self.exists(&to).await? {
            return Err(s3_err(None, format!("{to} already exists")));
        }
        let cancel = CancellationToken::new();
        match self.stat_path(&from).await? {
            e if e.kind == EntryKind::File => {
                let src = self.key_of(&from, false);
                let dst = self.key_of(&to, false);
                self.copy_object(&src, &dst, e.size.unwrap_or(0)).await?;
                self.delete_key(&src).await
            }
            _ => {
                let src = self.key_of(&from, true);
                let dst = self.key_of(&to, true);
                let copied = self.copy_tree(&src, &dst, &cancel).await?;
                self.delete_keys(copied.into_iter().map(|o| o.key).collect(), &cancel)
                    .await
            }
        }
    }

    async fn copy(&self, from: &str, to: &str) -> Result<()> {
        let from = normalize_path(from)?;
        let to = normalize_path(to)?;
        if to == from || to.starts_with(&format!("{from}/")) {
            return Err(s3_err(None, format!("cannot copy {from} into itself")));
        }
        if self.exists(&to).await? {
            return Err(s3_err(None, format!("{to} already exists")));
        }
        match self.stat_path(&from).await? {
            e if e.kind == EntryKind::File => {
                self.copy_object(
                    &self.key_of(&from, false),
                    &self.key_of(&to, false),
                    e.size.unwrap_or(0),
                )
                .await
            }
            _ => {
                if from == "/" {
                    return Err(s3_err(None, "cannot copy the root"));
                }
                self.copy_tree(
                    &self.key_of(&from, true),
                    &self.key_of(&to, true),
                    &CancellationToken::new(),
                )
                .await
                .map(|_| ())
            }
        }
    }

    async fn remove_file(&self, path: &str) -> Result<()> {
        let norm = normalize_path(path)?;
        let key = self.key_of(&norm, false);
        self.head(&key).await?;
        self.delete_key(&key).await
    }

    async fn remove_dir(&self, path: &str) -> Result<()> {
        let norm = normalize_path(path)?;
        if norm == "/" {
            return Err(s3_err(None, "cannot remove the root"));
        }
        let key = self.key_of(&norm, true);
        let page = self.list_page(&key, None, None, Some(2)).await?;
        let others = page.objects.iter().filter(|o| o.key != key).count();
        if others > 0 {
            return Err(s3_err(None, format!("{norm} is not empty")));
        }
        if page.objects.is_empty() {
            return Err(CoreError::NotFound(norm));
        }
        self.delete_key(&key).await
    }

    async fn remove_dir_all(&self, path: &str, cancel: &CancellationToken) -> Result<()> {
        let norm = normalize_path(path)?;
        let key = self.key_of(&norm, true);
        let objects = self.list_all(&key, Some(cancel)).await?;
        if objects.is_empty() && norm != "/" {
            return Err(CoreError::NotFound(norm));
        }
        self.delete_keys(objects.into_iter().map(|o| o.key).collect(), cancel)
            .await
    }

    async fn chmod(&self, _path: &str, _mode: u32) -> Result<()> {
        Err(s3_err(None, "S3 has no permission bits"))
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let norm = normalize_path(path)?;
        let key = self.key_of(&norm, false);
        let o = self.head(&key).await?;
        if o.size > MAX_IN_MEMORY {
            return Err(s3_err(None, "file too large to read into memory"));
        }
        let resp = self
            .send(Method::GET, &key, &[], &[], None, &empty_hash())
            .await?;
        let resp = Self::check(resp, &norm).await?;
        let body = resp.bytes().await?;
        if body.len() as u64 > MAX_IN_MEMORY {
            return Err(s3_err(None, "file too large to read into memory"));
        }
        Ok(body.to_vec())
    }

    async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let norm = normalize_path(path)?;
        let key = self.key_of(&norm, false);
        let resp = self
            .call(Method::PUT, &key, &[], &[], Bytes::copy_from_slice(data))
            .await?;
        Self::check(resp, &norm).await.map(|_| ())
    }

    async fn open_file(&self, path: &str, mode: OpenMode) -> Result<Box<dyn remote::RemoteFile>> {
        let norm = normalize_path(path)?;
        let key = self.key_of(&norm, false);
        let existing = match self.head(&key).await {
            Ok(o) => Some(o),
            Err(CoreError::NotFound(_)) if mode != OpenMode::Read => None,
            Err(CoreError::NotFound(_)) => {
                return Err(self
                    .stat_path(&norm)
                    .await
                    .err()
                    .unwrap_or(CoreError::NotFound(norm.clone())));
            }
            Err(e) => return Err(e),
        };
        match mode {
            OpenMode::Read => {
                let o = existing.expect("head succeeded for read");
                Ok(Box::new(S3File {
                    key,
                    s3: self.clone(),
                    state: Mutex::new(FileState::Read { size: o.size }),
                }))
            }
            OpenMode::Write | OpenMode::ReadWrite => {
                tokio::fs::create_dir_all(&self.inner.spool_dir).await?;
                let spool = self
                    .inner
                    .spool_dir
                    .join(format!("termoso-s3-{}", uuid::Uuid::new_v4()));
                let mut file = tokio::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&spool)
                    .await?;
                if mode == OpenMode::ReadWrite && existing.is_some() {
                    let resp = self
                        .send(Method::GET, &key, &[], &[], None, &empty_hash())
                        .await?;
                    let resp = Self::check(resp, &norm).await?;
                    let mut stream = resp.bytes_stream();
                    while let Some(chunk) = stream.next().await {
                        file.write_all(&chunk?).await?;
                    }
                    file.flush().await?;
                }
                Ok(Box::new(S3File {
                    key,
                    s3: self.clone(),
                    state: Mutex::new(FileState::Spool {
                        file,
                        spool,
                        dirty: true,
                    }),
                }))
            }
        }
    }

    async fn download(&self, remote: &str, local: &Path, opts: &TransferOptions) -> Result<u64> {
        let norm = normalize_path(remote)?;
        let key = self.key_of(&norm, false);
        let o = match self.head(&key).await {
            Ok(o) => o,
            Err(CoreError::NotFound(_)) => {
                return match self.stat_path(&norm).await {
                    Ok(_) => Err(s3_err(None, format!("{norm} is a directory"))),
                    Err(e) => Err(e),
                };
            }
            Err(e) => return Err(e),
        };
        let total = Some(o.size);

        let mut offset = 0u64;
        let mut file = if opts.resume && local.exists() {
            let mut f = tokio::fs::OpenOptions::new()
                .append(true)
                .open(local)
                .await?;
            offset = f.metadata().await?.len();
            if offset > o.size {
                f = tokio::fs::File::create(local).await?;
                offset = 0;
            }
            f
        } else {
            if let Some(p) = local.parent() {
                tokio::fs::create_dir_all(p).await?;
            }
            tokio::fs::File::create(local).await?
        };
        if offset == o.size && offset > 0 {
            opts.report(offset, total);
            return Ok(0);
        }

        let resp = if offset > 0 {
            self.send_get_range(&key, &format!("bytes={offset}-"))
                .await?
        } else {
            self.send(Method::GET, &key, &[], &[], None, &empty_hash())
                .await?
        };
        let resp = Self::check(resp, &norm).await?;
        if offset > 0 && resp.status() != StatusCode::PARTIAL_CONTENT {
            file = tokio::fs::File::create(local).await?;
            offset = 0;
        }
        opts.report(offset, total);

        let mut done = offset;
        let mut throttle = Throttle::new(opts.rate_limit);
        let mut stream = resp.bytes_stream();
        loop {
            if opts.cancel.is_cancelled() {
                file.flush().await?;
                return Err(CoreError::Cancelled);
            }
            let next = tokio::select! {
                c = stream.next() => c,
                _ = opts.cancel.cancelled() => { file.flush().await?; return Err(CoreError::Cancelled) }
            };
            let Some(chunk) = next else { break };
            let chunk = chunk?;
            file.write_all(&chunk).await?;
            done += chunk.len() as u64;
            opts.report(done, total);
            throttle.pace(chunk.len(), &opts.cancel).await;
        }
        file.flush().await?;
        drop(file);

        if opts.preserve_mtime
            && let Some(mtime) = o.mtime
        {
            let t = std::time::UNIX_EPOCH + Duration::from_secs(mtime as u64);
            let f = std::fs::File::open(local)?;
            let _ = f.set_modified(t);
        }
        Ok(done - offset)
    }

    async fn upload(&self, local: &Path, remote: &str, opts: &TransferOptions) -> Result<u64> {
        let norm = normalize_path(remote)?;
        let meta = tokio::fs::metadata(local).await?;
        if meta.is_dir() {
            return Err(s3_err(None, format!("{} is a directory", local.display())));
        }
        let size = meta.len();
        opts.report(0, Some(size));
        self.put_file(local, &self.key_of(&norm, false), size, opts)
            .await?;
        opts.report(size, Some(size));
        Ok(size)
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

impl S3 {
    /// `GET` with a `Range` header (not signed: S3 only requires `x-amz-*`
    /// headers to be).
    async fn send_get_range(&self, key: &str, range: &str) -> Result<Response> {
        let (url, canonical_query) = self.url_for(key, &[])?;
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or("")),
            None => url.host_str().unwrap_or("").to_string(),
        };
        let hash = empty_hash();
        let mut signed_headers: Vec<(&str, &str)> = vec![("x-amz-content-sha256", &hash)];
        if let Some(t) = &self.inner.session_token {
            signed_headers.push(("x-amz-security-token", t));
        }
        let signed = sigv4::sign_request(
            &GenericRequest {
                method: "GET",
                service: "s3",
                region: &self.inner.region,
                host: &host,
                path: url.path(),
                query: &canonical_query,
                headers: &signed_headers,
                payload_hash: &hash,
            },
            &self.inner.access_key,
            &self.inner.secret_key,
            Utc::now(),
        );
        let mut rb = self
            .inner
            .http
            .get(url)
            .header(header::AUTHORIZATION, signed.authorization)
            .header("x-amz-date", signed.amz_date)
            .header(header::RANGE, range);
        for (k, v) in &signed_headers {
            rb = rb.header(*k, *v);
        }
        Ok(rb.send().await?)
    }
}

enum FileState {
    Read {
        size: u64,
    },
    Spool {
        file: tokio::fs::File,
        spool: PathBuf,
        dirty: bool,
    },
}

/// An object opened through [`RemoteFs::open_file`]: reads are ranged
/// `GET`s, writes go to a local spool file that is uploaded on `sync` /
/// `close` (objects cannot be written in place).
pub struct S3File {
    key: String,
    s3: S3,
    state: Mutex<FileState>,
}

impl S3File {
    async fn flush_spool(&self, st: &mut FileState) -> Result<()> {
        let FileState::Spool { file, spool, dirty } = st else {
            return Ok(());
        };
        if !*dirty {
            return Ok(());
        }
        let size = spool_len(file).await?;
        self.s3
            .put_file(spool, &self.key, size, &TransferOptions::default())
            .await?;
        *dirty = false;
        Ok(())
    }
}

async fn spool_len(file: &mut tokio::fs::File) -> Result<u64> {
    file.flush().await?;
    Ok(file.metadata().await?.len())
}

impl Drop for S3File {
    fn drop(&mut self) {
        if let Ok(st) = self.state.try_lock()
            && let FileState::Spool { spool, .. } = &*st
        {
            let _ = std::fs::remove_file(spool);
        }
    }
}

#[async_trait::async_trait]
impl remote::RemoteFile for S3File {
    async fn size(&self) -> Result<u64> {
        let mut st = self.state.lock().await;
        match &mut *st {
            FileState::Read { size } => Ok(*size),
            FileState::Spool { file, .. } => spool_len(file).await,
        }
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut st = self.state.lock().await;
        match &mut *st {
            FileState::Read { size } => {
                if offset >= *size {
                    return Ok(Vec::new());
                }
                let want = len.min((*size - offset) as usize);
                let range = format!("bytes={offset}-{}", offset + want as u64 - 1);
                let resp = self.s3.send_get_range(&self.key, &range).await?;
                let resp = S3::check(resp, &self.s3.path_of(&self.key)).await?;
                Ok(resp.bytes().await?.to_vec())
            }
            FileState::Spool { file, .. } => {
                let end = spool_len(file).await?;
                if offset >= end {
                    return Ok(Vec::new());
                }
                let want = len.min((end - offset) as usize);
                file.seek(std::io::SeekFrom::Start(offset)).await?;
                let mut out = vec![0u8; want];
                let mut filled = 0;
                while filled < want {
                    let n = file.read(&mut out[filled..]).await?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                out.truncate(filled);
                Ok(out)
            }
        }
    }

    async fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        let mut st = self.state.lock().await;
        match &mut *st {
            FileState::Read { .. } => Err(s3_err(None, "file is open read-only")),
            FileState::Spool { file, dirty, .. } => {
                file.seek(std::io::SeekFrom::Start(offset)).await?;
                file.write_all(data).await?;
                *dirty = true;
                Ok(())
            }
        }
    }

    async fn truncate(&self, size: u64) -> Result<()> {
        let mut st = self.state.lock().await;
        match &mut *st {
            FileState::Read { .. } => Err(s3_err(None, "file is open read-only")),
            FileState::Spool { file, dirty, .. } => {
                file.flush().await?;
                file.set_len(size).await?;
                *dirty = true;
                Ok(())
            }
        }
    }

    async fn sync(&self) -> Result<()> {
        let mut st = self.state.lock().await;
        self.flush_spool(&mut st).await
    }

    async fn close(self: Box<Self>) -> Result<()> {
        let mut st = self.state.lock().await;
        let r = self.flush_spool(&mut st).await;
        if let FileState::Spool { spool, .. } = &*st {
            let _ = tokio::fs::remove_file(spool).await;
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_encode_the_aws_way() {
        assert_eq!(encode_key("a b/c+d/é"), "a%20b/c%2Bd/%C3%A9");
        assert_eq!(encode_key("x~y-_."), "x~y-_.");
        assert_eq!(aws_encode("a/b"), "a%2Fb");
    }

    #[test]
    fn prefix_and_bucket_validation() {
        assert_eq!(normalize_prefix(""), "");
        assert_eq!(normalize_prefix("/"), "");
        assert_eq!(normalize_prefix("backups"), "backups/");
        assert_eq!(normalize_prefix("/a/b/"), "a/b/");
        assert!(validate_bucket("my-bucket.1").is_ok());
        assert!(validate_bucket("My").is_err());
        assert!(validate_bucket("-x-").is_err());
        assert!(validate_bucket("a..b").is_err());
    }

    #[test]
    fn paths_map_to_keys_under_the_prefix() {
        let s3 = S3::new(S3Config {
            endpoint: "http://127.0.0.1:9000".into(),
            bucket: "bkt".into(),
            prefix: "root/dir".into(),
            access_key: "a".into(),
            secret_key: "b".into(),
            ..S3Config::default()
        })
        .unwrap();
        assert_eq!(s3.key_of("/", true), "root/dir/");
        assert_eq!(s3.key_of("/x/y", false), "root/dir/x/y");
        assert_eq!(s3.key_of("/x/y", true), "root/dir/x/y/");
        assert_eq!(s3.path_of("root/dir/x/y/"), "/x/y");
        assert_eq!(s3.path_of("root/dir/"), "/");
        let (url, q) = s3
            .url_for("x/y z", &[("uploadId", "1/2"), ("partNumber", "3")])
            .unwrap();
        assert_eq!(url.path(), "/bkt/x/y%20z");
        assert_eq!(q, "partNumber=3&uploadId=1%2F2");
        assert_eq!(url.query(), Some("partNumber=3&uploadId=1%2F2"));
    }

    #[test]
    fn virtual_host_puts_the_bucket_in_the_name() {
        let s3 = S3::new(S3Config {
            endpoint: "https://s3.eu-central-1.amazonaws.com".into(),
            bucket: "bkt".into(),
            path_style: false,
            access_key: "a".into(),
            secret_key: "b".into(),
            ..S3Config::default()
        })
        .unwrap();
        let (url, _) = s3.url_for("k", &[]).unwrap();
        assert_eq!(url.as_str(), "https://bkt.s3.eu-central-1.amazonaws.com/k");
        assert!(
            S3::new(S3Config {
                endpoint: "https://10.0.0.1".into(),
                bucket: "bkt".into(),
                path_style: false,
                access_key: "a".into(),
                secret_key: "b".into(),
                ..S3Config::default()
            })
            .is_err()
        );
    }

    #[test]
    fn errors_name_the_s3_code() {
        let body = r#"<?xml version="1.0"?><Error><Code>AccessDenied</Code><Message>Access Denied.</Message></Error>"#;
        match S3::error_from(StatusCode::FORBIDDEN, body, "/x") {
            CoreError::S3 { status, message } => {
                assert_eq!(status, Some(403));
                assert!(message.starts_with("AccessDenied: Access Denied."));
            }
            e => panic!("{e:?}"),
        }
        assert!(matches!(
            S3::error_from(StatusCode::NOT_FOUND, "", "/x"),
            CoreError::NotFound(p) if p == "/x"
        ));
        let body = r#"<Error><Code>NoSuchBucket</Code></Error>"#;
        assert!(matches!(
            S3::error_from(StatusCode::NOT_FOUND, body, "/x"),
            CoreError::S3 { .. }
        ));
    }
}
