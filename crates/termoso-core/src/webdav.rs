//! WebDAV (RFC 4918) client over `reqwest` + rustls: PROPFIND listings, GET
//! (whole or ranged), PUT, MKCOL, MOVE, COPY, DELETE; Basic and Digest
//! authentication; system roots or a pinned self-signed certificate. Exposes
//! the same [`RemoteFs`] surface as SFTP so file panels and the Android
//! documents provider treat both alike.
//!
//! Paths are absolute `/`-separated paths *below the configured URL*: with a
//! base of `https://cloud.example/remote.php/dav/files/me/`, `/Photos/a.jpg`
//! is `…/files/me/Photos/a.jpg` on the wire.

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use futures::StreamExt;
use percent_encoding::percent_decode_str;
use rand::Rng;
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Method, Request, RequestBuilder, Response, StatusCode};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{AlertDescription, DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::cloud::xml;
use crate::error::{CoreError, Result};
use crate::remote::{self, RemoteCapabilities, RemoteFs, RemoteProtocol, parent};
use crate::sftp::{EntryKind, OpenMode, RemoteEntry, TransferOptions};

/// Chunk size for streamed transfers.
const CHUNK: usize = 256 * 1024;
/// `read` refuses files larger than this.
const MAX_IN_MEMORY: u64 = 64 * 1024 * 1024;
/// Header carrying the source mtime to servers that honour it (Nextcloud /
/// ownCloud); everyone else ignores it.
const MTIME_HEADER: &str = "X-OC-Mtime";

fn method(name: &str) -> Method {
    Method::from_bytes(name.as_bytes()).expect("valid method token")
}

/// How the server certificate is checked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode", content = "fingerprint")]
pub enum TlsPolicy {
    /// Public roots (the OS / webpki bundle); the default.
    #[default]
    System,
    /// Trust exactly the leaf certificate with this SHA-256 fingerprint
    /// (`aa:bb:…`, case-insensitive, colons optional), whatever chain it
    /// comes with. For self-signed / private-CA servers.
    Pinned(String),
    /// Trust certificates chaining to the authorities in this PEM bundle
    /// (one or more `CERTIFICATE` blocks) instead of the public roots.
    PrivateCa(String),
}

/// Client certificate + private key presented to servers that require mTLS.
pub struct ClientIdentity {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Clone for ClientIdentity {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("fingerprint", &self.fingerprint())
            .field("chain", &self.certs.len())
            .finish_non_exhaustive()
    }
}

impl ClientIdentity {
    /// Parse a PEM certificate (leaf first, intermediates after) and an
    /// unencrypted PEM private key (PKCS#8, RSA or SEC1). Encrypted keys and
    /// PKCS#12 bundles are rejected with a hint.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| CoreError::Invalid(format!("client certificate: {e}")))?;
        if certs.is_empty() {
            return Err(CoreError::Invalid(
                "client certificate: no CERTIFICATE block found".into(),
            ));
        }
        if key_pem.contains("ENCRYPTED PRIVATE KEY") || key_pem.contains("Proc-Type: 4,ENCRYPTED") {
            return Err(CoreError::Invalid(
                "client key: encrypted PEM keys are not supported; decrypt it first \
                 (openssl pkey -in key.pem -out plain.pem)"
                    .into(),
            ));
        }
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .map_err(|e| CoreError::Invalid(format!("client key: {e}")))?;
        Ok(Self { certs, key })
    }

    /// SHA-256 fingerprint of the leaf certificate (`aa:bb:…`).
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.certs[0])
    }

    /// The chain re-encoded as PEM, followed by the key — what reqwest wants.
    fn bundle_pem(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for c in &self.certs {
            out.extend_from_slice(pem_block("CERTIFICATE", c).as_bytes());
        }
        let label = match &self.key {
            PrivateKeyDer::Pkcs1(_) => "RSA PRIVATE KEY",
            PrivateKeyDer::Sec1(_) => "EC PRIVATE KEY",
            _ => "PRIVATE KEY",
        };
        out.extend_from_slice(pem_block(label, self.key.secret_der()).as_bytes());
        out
    }
}

fn pem_block(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

/// SHA-256 fingerprint of the leaf certificate in a PEM chain, for showing
/// which certificate is configured without keeping the parsed identity.
pub fn client_certificate_fingerprint(cert_pem: &str) -> Result<String> {
    let leaf = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .next()
        .ok_or_else(|| CoreError::Invalid("client certificate: no CERTIFICATE block found".into()))?
        .map_err(|e| CoreError::Invalid(format!("client certificate: {e}")))?;
    Ok(fingerprint(&leaf))
}

/// Certificate chain and private key found in one PEM text (a combined
/// bundle, a chain file or a bare key), re-encoded as canonical PEM so an
/// editor can put each half in its own field. Either half may be empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PemParts {
    /// `CERTIFICATE` blocks in file order, leaf first.
    pub certificate: String,
    /// The first private key block, or empty.
    pub private_key: String,
}

/// Split a PEM text into [`PemParts`]; encrypted keys and non-PEM input
/// (PKCS#12) are rejected.
pub fn split_client_pem(text: &str) -> Result<PemParts> {
    let mut parts = PemParts::default();
    for c in CertificateDer::pem_slice_iter(text.as_bytes()) {
        let c = c.map_err(|e| CoreError::Invalid(format!("certificate: {e}")))?;
        parts.certificate.push_str(&pem_block("CERTIFICATE", &c));
    }
    if text.contains("ENCRYPTED PRIVATE KEY") || text.contains("Proc-Type: 4,ENCRYPTED") {
        return Err(CoreError::Invalid(
            "encrypted PEM keys are not supported; decrypt it first \
             (openssl pkey -in key.pem -out plain.pem)"
                .into(),
        ));
    }
    if let Some(key) = PrivateKeyDer::pem_slice_iter(text.as_bytes()).next() {
        let key = key.map_err(|e| CoreError::Invalid(format!("private key: {e}")))?;
        let label = match &key {
            PrivateKeyDer::Pkcs1(_) => "RSA PRIVATE KEY",
            PrivateKeyDer::Sec1(_) => "EC PRIVATE KEY",
            _ => "PRIVATE KEY",
        };
        parts.private_key = pem_block(label, key.secret_der());
    }
    if parts.certificate.is_empty() && parts.private_key.is_empty() {
        return Err(CoreError::Invalid(
            "no CERTIFICATE or PRIVATE KEY block found (PKCS#12 .p12/.pfx must be converted to PEM)"
                .into(),
        ));
    }
    Ok(parts)
}

/// Connection parameters.
#[derive(Clone)]
pub struct WebDavConfig {
    /// Collection URL the paths hang off (`https://host/dav/`); a missing
    /// trailing slash is added, `http://` is allowed.
    pub url: String,
    /// Credentials; `None` for anonymous servers.
    pub username: Option<String>,
    /// Password (or app token).
    pub password: Option<String>,
    /// OAuth-style access token sent as `Authorization: Bearer …` with every
    /// request; takes precedence over `username`/`password`.
    pub bearer_token: Option<String>,
    /// Certificate policy.
    pub tls: TlsPolicy,
    /// Name sent as SNI, used as the `Host` header and checked against the
    /// certificate when it differs from the URL's host: the TCP connection
    /// still goes to the URL's host (an IP, or a name the certificate does
    /// not carry). `None` = the URL's host.
    pub server_name: Option<String>,
    /// Addresses of the URL's host when `server_name` redirects the name
    /// check; [`WebDav::connect`] fills them asynchronously, [`WebDav::new`]
    /// falls back to a blocking lookup when they are missing.
    pub resolved_addrs: Option<Vec<SocketAddr>>,
    /// Client certificate for servers that require mTLS.
    pub client_identity: Option<ClientIdentity>,
    /// TCP + TLS connect deadline.
    pub connect_timeout: Duration,
    /// Where write-mode [`RemoteFile`](remote::RemoteFile)s spool their
    /// contents before the PUT; defaults to the OS temp dir (not writable by
    /// apps on Android — pass the app cache dir there).
    pub spool_dir: Option<PathBuf>,
    /// Optional SOCKS/HTTP proxy every request goes through.
    pub proxy: Option<crate::ssh::proxy::ProxyConfig>,
}

impl Default for WebDavConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            username: None,
            password: None,
            bearer_token: None,
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

impl std::fmt::Debug for WebDavConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDavConfig")
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "…"))
            .field("bearer_token", &self.bearer_token.as_ref().map(|_| "…"))
            .field("tls", &self.tls)
            .field("server_name", &self.server_name)
            .field("resolved_addrs", &self.resolved_addrs)
            .field("client_identity", &self.client_identity)
            .field("connect_timeout", &self.connect_timeout)
            .field("spool_dir", &self.spool_dir)
            .finish()
    }
}

impl WebDavConfig {
    /// Take the login material a vault identity holds: username + password,
    /// bearer token and client certificate. Corrupt stored PEM is reported as
    /// [`CoreError::Invalid`] rather than silently connecting without mTLS.
    pub fn with_identity(mut self, identity: Option<&crate::model::Identity>) -> Result<Self> {
        let Some(identity) = identity else {
            return Ok(self);
        };
        self.username = Some(identity.username.trim().to_string()).filter(|u| !u.is_empty());
        self.password = identity.password.clone().filter(|p| !p.is_empty());
        self.bearer_token = identity.bearer_token.clone().filter(|t| !t.is_empty());
        self.client_identity = match &identity.client_certificate {
            Some(c) => Some(ClientIdentity::from_pem(&c.certificate, &c.private_key)?),
            None => None,
        };
        Ok(self)
    }
}

/// Which `Authorization` the server asked for.
#[derive(Debug, Clone)]
enum AuthScheme {
    /// Nothing sent yet / anonymous.
    None,
    Basic,
    Digest(DigestChallenge),
    /// Preconfigured access token, sent from the first request on.
    Bearer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DigestChallenge {
    realm: String,
    nonce: String,
    opaque: Option<String>,
    algorithm: DigestAlgorithm,
    /// `qop=auth` offered (RFC 2617/7616); `false` means the RFC 2069 form.
    qop_auth: bool,
    stale: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestAlgorithm {
    Md5,
    Md5Sess,
    Sha256,
    Sha256Sess,
}

impl DigestAlgorithm {
    fn parse(s: Option<&str>) -> Option<Self> {
        match s.map(|s| s.to_ascii_uppercase()).as_deref() {
            None | Some("MD5") => Some(Self::Md5),
            Some("MD5-SESS") => Some(Self::Md5Sess),
            Some("SHA-256") => Some(Self::Sha256),
            Some("SHA-256-SESS") => Some(Self::Sha256Sess),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Md5Sess => "MD5-sess",
            Self::Sha256 => "SHA-256",
            Self::Sha256Sess => "SHA-256-sess",
        }
    }

    fn session(self) -> bool {
        matches!(self, Self::Md5Sess | Self::Sha256Sess)
    }

    fn hash(self, data: &str) -> String {
        match self {
            Self::Md5 | Self::Md5Sess => format!("{:x}", md5::compute(data.as_bytes())),
            Self::Sha256 | Self::Sha256Sess => hex::encode(Sha256::digest(data.as_bytes())),
        }
    }
}

struct AuthState {
    scheme: AuthScheme,
    /// Digest nonce-count for the current nonce.
    nc: u32,
}

/// One challenge from a `WWW-Authenticate` header.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Challenge {
    scheme: String,
    params: Vec<(String, String)>,
}

impl Challenge {
    fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Parse every challenge in a `WWW-Authenticate` value (several may share
/// one header, comma-separated, RFC 7235 §4.1).
fn parse_challenges(value: &str) -> Vec<Challenge> {
    let mut out: Vec<Challenge> = Vec::new();
    let b = value.as_bytes();
    let mut i = 0;
    let skip_ws = |i: &mut usize| {
        while *i < b.len() && (b[*i] == b' ' || b[*i] == b'\t' || b[*i] == b',') {
            *i += 1;
        }
    };
    let read_token = |i: &mut usize| -> String {
        let start = *i;
        while *i < b.len() && !matches!(b[*i], b' ' | b'\t' | b',' | b'=' | b'"') {
            *i += 1;
        }
        value[start..*i].to_string()
    };
    loop {
        skip_ws(&mut i);
        if i >= b.len() {
            break;
        }
        let token = read_token(&mut i);
        if token.is_empty() {
            // Stray quote or `=`: skip one byte to guarantee progress.
            i += 1;
            continue;
        }
        let mut j = i;
        while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
            j += 1;
        }
        if j < b.len() && b[j] == b'=' {
            // auth-param
            i = j + 1;
            while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
                i += 1;
            }
            let val = if i < b.len() && b[i] == b'"' {
                i += 1;
                let mut s = String::new();
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        i += 1;
                    }
                    let ch_len = utf8_len(b[i]);
                    s.push_str(&value[i..(i + ch_len).min(b.len())]);
                    i += ch_len;
                }
                i += 1; // closing quote
                s
            } else {
                read_token(&mut i)
            };
            match out.last_mut() {
                Some(c) => c.params.push((token.to_ascii_lowercase(), val)),
                None => out.push(Challenge {
                    scheme: String::new(),
                    params: vec![(token.to_ascii_lowercase(), val)],
                }),
            }
        } else {
            out.push(Challenge {
                scheme: token.to_ascii_lowercase(),
                params: Vec::new(),
            });
        }
    }
    out.retain(|c| !c.scheme.is_empty());
    out
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

fn digest_challenge(c: &Challenge) -> Result<DigestChallenge> {
    let realm = c.param("realm").unwrap_or("").to_string();
    let nonce = c
        .param("nonce")
        .ok_or_else(|| webdav_err(None, "digest challenge without nonce"))?
        .to_string();
    let algorithm = DigestAlgorithm::parse(c.param("algorithm")).ok_or_else(|| {
        webdav_err(
            None,
            format!(
                "unsupported digest algorithm {}",
                c.param("algorithm").unwrap_or("?")
            ),
        )
    })?;
    let qop_auth = match c.param("qop") {
        None => false,
        Some(q) => {
            if q.split(',').any(|v| v.trim().eq_ignore_ascii_case("auth")) {
                true
            } else {
                return Err(webdav_err(
                    None,
                    format!("digest qop {q:?} is not supported (need auth)"),
                ));
            }
        }
    };
    Ok(DigestChallenge {
        realm,
        nonce,
        opaque: c.param("opaque").map(str::to_string),
        algorithm,
        qop_auth,
        stale: c
            .param("stale")
            .is_some_and(|s| s.eq_ignore_ascii_case("true")),
    })
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        if ch == '"' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

/// RFC 7616 response for one request.
fn digest_authorization(
    ch: &DigestChallenge,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    nc: u32,
    cnonce: &str,
) -> String {
    let alg = ch.algorithm;
    let mut ha1 = alg.hash(&format!("{username}:{}:{password}", ch.realm));
    if alg.session() {
        ha1 = alg.hash(&format!("{ha1}:{}:{cnonce}", ch.nonce));
    }
    let ha2 = alg.hash(&format!("{method}:{uri}"));
    let nc_hex = format!("{nc:08x}");
    let response = if ch.qop_auth {
        alg.hash(&format!("{ha1}:{}:{nc_hex}:{cnonce}:auth:{ha2}", ch.nonce))
    } else {
        alg.hash(&format!("{ha1}:{}:{ha2}", ch.nonce))
    };
    let mut out = format!(
        "Digest username={}, realm={}, nonce={}, uri={}, response={}, algorithm={}",
        quote(username),
        quote(&ch.realm),
        quote(&ch.nonce),
        quote(uri),
        quote(&response),
        alg.name()
    );
    if ch.qop_auth {
        out.push_str(&format!(
            ", qop=auth, nc={nc_hex}, cnonce={}",
            quote(cnonce)
        ));
    }
    if let Some(o) = &ch.opaque {
        out.push_str(&format!(", opaque={}", quote(o)));
    }
    out
}

fn random_cnonce() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn webdav_err(status: Option<u16>, message: impl Into<String>) -> CoreError {
    CoreError::WebDav {
        status,
        message: message.into(),
    }
}

/// Normalise a caller path to `/a/b` form; `.`/`..` are resolved and paths
/// escaping the root are rejected.
pub fn normalize_path(path: &str) -> Result<String> {
    if path.contains('\0') {
        return Err(CoreError::Invalid("path contains NUL".into()));
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(CoreError::Invalid(format!("path escapes root: {path}")));
                }
            }
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        Ok("/".into())
    } else {
        Ok(format!("/{}", parts.join("/")))
    }
}

fn name_of(path: &str) -> String {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Colon-separated lowercase SHA-256 of DER bytes.
pub fn fingerprint(der: &[u8]) -> String {
    fingerprint_of(&Sha256::digest(der))
}

fn fingerprint_of(digest: &[u8]) -> String {
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Canonical `aa:bb:…` form of a SHA-256 fingerprint typed with or without
/// separators, in any case.
pub fn normalize_fingerprint(s: &str) -> Result<String> {
    let bytes = parse_fingerprint(s)?;
    Ok(fingerprint_of(&bytes))
}

fn parse_fingerprint(s: &str) -> Result<[u8; 32]> {
    let hex_str: String = s
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase();
    let bytes = hex::decode(&hex_str)
        .map_err(|_| CoreError::Invalid("bad certificate fingerprint".into()))?;
    bytes
        .try_into()
        .map_err(|_| CoreError::Invalid("certificate fingerprint must be SHA-256".into()))
}

/// Accepts only the leaf with the pinned fingerprint; handshake signatures
/// are still verified against that leaf.
#[derive(Debug)]
struct PinVerifier {
    pin: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let got: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if got == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Records the leaf fingerprint and accepts; used once, to *show* the user
/// what an untrusted server presents, never to move data.
#[derive(Debug)]
struct CaptureVerifier {
    seen: std::sync::Mutex<Option<String>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().expect("capture lock") = Some(fingerprint(end_entity.as_ref()));
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_config_with(
    verifier: Arc<dyn ServerCertVerifier>,
    identity: Option<&ClientIdentity>,
) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut cfg = match identity {
        Some(id) => builder
            .with_client_auth_cert(id.certs.clone(), id.key.clone_key())
            .map_err(|e| CoreError::Invalid(format!("client certificate: {e}")))?,
        None => builder.with_no_client_auth(),
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Where the TCP connection goes and under which name the TLS handshake
/// runs: the URL as configured, or — with a `server_name` that differs from
/// the URL's host — the URL rewritten to that name plus the addresses the
/// original host resolves to, so SNI, `Host` and the certificate check all
/// use the name while the socket still opens to the address.
struct Target {
    base: Url,
    resolve: Option<(String, Vec<SocketAddr>)>,
}

/// The TLS name check should use `server_name` rather than the URL's host?
fn name_override(cfg: &WebDavConfig, base: &Url) -> Option<String> {
    let name = cfg.server_name.as_deref()?.trim();
    if name.is_empty()
        || base
            .host_str()
            .is_some_and(|h| h.eq_ignore_ascii_case(name))
    {
        return None;
    }
    Some(name.to_string())
}

/// Does `cfg` need the URL host resolved before the client can be built?
fn needs_lookup(cfg: &WebDavConfig) -> Option<(String, u16)> {
    let base = normalize_url(&cfg.url).ok()?;
    name_override(cfg, &base)?;
    match base.host()? {
        url::Host::Domain(d) => Some((d.to_string(), base.port_or_known_default().unwrap_or(443))),
        _ => None,
    }
}

fn target(cfg: &WebDavConfig) -> Result<Target> {
    let mut base = normalize_url(&cfg.url)?;
    let Some(name) = name_override(cfg, &base) else {
        return Ok(Target {
            base,
            resolve: None,
        });
    };
    validate_server_name(&name)?;
    let port = base.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = match base.host() {
        Some(url::Host::Ipv4(ip)) => vec![SocketAddr::new(ip.into(), port)],
        Some(url::Host::Ipv6(ip)) => vec![SocketAddr::new(ip.into(), port)],
        Some(url::Host::Domain(d)) => match &cfg.resolved_addrs {
            Some(a) if !a.is_empty() => a.clone(),
            _ => std::net::ToSocketAddrs::to_socket_addrs(&(d, port))
                .map_err(|e| webdav_err(None, format!("cannot resolve {d}: {e}")))?
                .collect(),
        },
        None => return Err(CoreError::Invalid("URL has no host".into())),
    };
    if addrs.is_empty() {
        return Err(webdav_err(
            None,
            format!(
                "{} does not resolve to any address",
                base.host_str().unwrap_or("")
            ),
        ));
    }
    base.set_host(Some(&name))
        .map_err(|_| CoreError::Invalid(format!("bad TLS server name {name:?}")))?;
    Ok(Target {
        base,
        resolve: Some((name, addrs)),
    })
}

/// `reqwest` proxy for a SOCKS/HTTP proxy config. SOCKS4 carries the
/// username only; HTTP and SOCKS5 take username + password.
fn reqwest_proxy(p: &crate::ssh::proxy::ProxyConfig) -> Result<reqwest::Proxy> {
    use crate::ssh::proxy::ProxyKind;
    let scheme = match p.kind {
        ProxyKind::Http => "http",
        ProxyKind::Socks4 => "socks4a",
        ProxyKind::Socks5 => "socks5h",
    };
    let host = if p.host.contains(':') && !p.host.starts_with('[') {
        format!("[{}]", p.host)
    } else {
        p.host.clone()
    };
    let mut url = reqwest::Url::parse(&format!("{scheme}://{host}:{}", p.port))
        .map_err(|e| CoreError::Invalid(format!("proxy {}:{}: {e}", p.host, p.port)))?;
    if let Some(u) = p.username.as_deref().filter(|u| !u.is_empty()) {
        url.set_username(u)
            .map_err(|_| CoreError::Invalid("proxy username is not valid in a URL".into()))?;
        if p.kind.supports_password()
            && let Some(pw) = p.password.as_deref().filter(|s| !s.is_empty())
        {
            url.set_password(Some(pw))
                .map_err(|_| CoreError::Invalid("proxy password is not valid in a URL".into()))?;
        }
    }
    reqwest::Proxy::all(url).map_err(|e| CoreError::Invalid(format!("proxy: {e}")))
}

fn http_client(
    cfg: &WebDavConfig,
    tls: Option<rustls::ClientConfig>,
    resolve: Option<&(String, Vec<SocketAddr>)>,
) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .connect_timeout(cfg.connect_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("Termoso/", env!("CARGO_PKG_VERSION")))
        .http1_only();
    if let Some((name, addrs)) = resolve {
        b = b.resolve_to_addrs(name, addrs);
    }
    if let Some(p) = &cfg.proxy {
        b = b.proxy(reqwest_proxy(p)?);
    }
    match tls {
        // A preconfigured config carries the client certificate itself.
        Some(tls) => b = b.use_preconfigured_tls(tls),
        None => {
            if let Some(id) = &cfg.client_identity {
                let identity = reqwest::Identity::from_pem(&id.bundle_pem())
                    .map_err(|e| CoreError::Invalid(format!("client certificate: {e}")))?;
                b = b.identity(identity);
            }
        }
    }
    Ok(b.build()?)
}

/// Innermost rustls error in a transport error's source chain, descending
/// into nested `io::Error`s (hyper wraps the rustls error twice).
fn rustls_error(e: &reqwest::Error) -> Option<&rustls::Error> {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(s) = src {
        if let Some(r) = s.downcast_ref::<rustls::Error>() {
            return Some(r);
        }
        src = match s.downcast_ref::<std::io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => s.source(),
        };
    }
    None
}

#[cfg(windows)]
fn connection_was_aborted(e: &reqwest::Error) -> bool {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(s) = src {
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            if io.raw_os_error() == Some(10053) {
                return true;
            }
            src = io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static));
        } else {
            src = s.source();
        }
    }
    false
}

/// Did the server close the handshake because of *our* certificate (missing
/// or not accepted)? Returns the alert name for the message.
fn client_certificate_alert(e: &reqwest::Error) -> Option<String> {
    if let Some(rustls::Error::AlertReceived(a)) = rustls_error(e)
        && matches!(
            a,
            AlertDescription::CertificateRequired
                | AlertDescription::BadCertificate
                | AlertDescription::UnknownCA
                | AlertDescription::CertificateUnknown
                | AlertDescription::CertificateRevoked
                | AlertDescription::CertificateExpired
                | AlertDescription::UnsupportedCertificate
                | AlertDescription::AccessDenied
                | AlertDescription::HandshakeFailure
        )
    {
        return Some(format!("{a:?}"));
    }
    #[cfg(windows)]
    if e.url().is_some_and(|url| url.scheme() == "https") && connection_was_aborted(e) {
        // Windows reports WSAECONNABORTED instead of forwarding the TLS
        // CertificateRequired alert when a server rejects a missing client
        // certificate.
        return Some("connection aborted during client-certificate handshake".into());
    }
    None
}

/// Is this transport error a certificate rejection? Walks the source chain,
/// descending into nested `io::Error`s (hyper wraps the rustls error twice).
fn is_tls_error(e: &reqwest::Error) -> bool {
    matches!(rustls_error(e), Some(rustls::Error::InvalidCertificate(_)))
}

/// Fetch the SHA-256 fingerprint of the certificate `url`'s server presents,
/// without trusting it. For the "trust this certificate?" prompt.
pub async fn probe_certificate(cfg: &WebDavConfig) -> Result<String> {
    let cfg = WebDavConfig {
        username: None,
        password: None,
        bearer_token: None,
        tls: TlsPolicy::System,
        client_identity: None,
        ..cfg.clone()
    };
    let Target { base, resolve } = target(&cfg)?;
    if base.scheme() != "https" {
        return Err(CoreError::Invalid("not an https URL".into()));
    }
    let verifier = Arc::new(CaptureVerifier {
        seen: std::sync::Mutex::new(None),
        provider: Arc::new(rustls::crypto::ring::default_provider()),
    });
    let client = http_client(
        &cfg,
        Some(tls_config_with(verifier.clone(), None)?),
        resolve.as_ref(),
    )?;
    // The response does not matter; the handshake does.
    let _ = client.request(method("OPTIONS"), base).send().await;
    verifier
        .seen
        .lock()
        .expect("capture lock")
        .clone()
        .ok_or_else(|| webdav_err(None, "server did not present a certificate"))
}

/// Validate a share URL: `http`/`https` only (the scheme defaults to
/// `https`), a host, no query/fragment, and a trailing slash on the path.
pub fn normalize_url(url: &str) -> Result<Url> {
    let trimmed = url.trim();
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let mut u =
        Url::parse(&with_scheme).map_err(|e| CoreError::Invalid(format!("bad URL: {e}")))?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return Err(CoreError::Invalid(format!(
            "unsupported URL scheme {}",
            u.scheme()
        )));
    }
    if u.host_str().is_none() {
        return Err(CoreError::Invalid("URL has no host".into()));
    }
    u.set_query(None);
    u.set_fragment(None);
    if !u.path().ends_with('/') {
        let p = format!("{}/", u.path());
        u.set_path(&p);
    }
    Ok(u)
}

/// Root store built from a PEM bundle of CA certificates.
fn ca_roots(pem: &str) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        let c = c.map_err(|e| CoreError::Invalid(format!("CA certificate: {e}")))?;
        roots
            .add(c)
            .map_err(|e| CoreError::Invalid(format!("CA certificate: {e}")))?;
    }
    if roots.is_empty() {
        return Err(CoreError::Invalid(
            "CA certificate: no CERTIFICATE block found".into(),
        ));
    }
    Ok(roots)
}

/// A DER certificate as a PEM `CERTIFICATE` block.
pub fn pem_of(der: &[u8]) -> String {
    pem_block("CERTIFICATE", &CertificateDer::from(der.to_vec()))
}

/// Check a PEM CA bundle parses; returns how many certificates it holds.
pub fn validate_ca_bundle(pem: &str) -> Result<usize> {
    Ok(ca_roots(pem)?.len())
}

/// Check a TLS server name (a DNS name or an IP literal) and return it
/// trimmed and lower-cased.
pub fn validate_server_name(name: &str) -> Result<String> {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() {
        return Err(CoreError::Invalid("TLS server name is empty".into()));
    }
    ServerName::try_from(name.clone())
        .map_err(|_| CoreError::Invalid(format!("bad TLS server name {name:?}")))?;
    Ok(name)
}

/// Normalise a collection path: leading and trailing slash, `/` when empty.
pub fn normalize_share_path(path: &str) -> String {
    let p = path.trim().trim_matches('/');
    if p.is_empty() {
        "/".to_string()
    } else {
        format!("/{p}/")
    }
}

/// Share URL of a host's WebDAV section: the host's address with the
/// section's scheme, port and path — or the full URL older entries stored.
pub fn share_url(address: &str, section: &crate::model::WebDavConfig) -> Result<Url> {
    if !section.url.trim().is_empty() {
        return normalize_url(&section.url);
    }
    let address = address.trim();
    if address.is_empty() {
        return Err(CoreError::Invalid("address is required".into()));
    }
    let host = if address.contains(':') && !address.starts_with('[') {
        format!("[{address}]")
    } else {
        address.to_string()
    };
    let scheme = if section.http { "http" } else { "https" };
    let default_port = if section.http { 80 } else { 443 };
    let port = match section.port {
        Some(p) if p != default_port => format!(":{p}"),
        _ => String::new(),
    };
    normalize_url(&format!(
        "{scheme}://{host}{port}{}",
        normalize_share_path(&section.path)
    ))
}

/// Host, port, scheme and path of a share URL, for turning an older stored
/// URL into the per-field form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharePieces {
    /// Host name or IP as written in the URL.
    pub host: String,
    /// Explicit port only; `None` when the URL used the scheme default.
    pub port: Option<u16>,
    /// `http://` rather than `https://`.
    pub http: bool,
    /// Normalised collection path (`/` or `/a/b/`).
    pub path: String,
}

/// Split a share URL into [`SharePieces`].
pub fn split_share_url(url: &str) -> Result<SharePieces> {
    let u = normalize_url(url)?;
    let host = match u.host() {
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        Some(h) => h.to_string(),
        None => return Err(CoreError::Invalid("URL has no host".into())),
    };
    Ok(SharePieces {
        host,
        port: u.port(),
        http: u.scheme() == "http",
        path: normalize_share_path(&percent_decode(u.path())),
    })
}

/// Runtime connection parameters for a host's WebDAV section: URL from the
/// address and section, certificate policy from the pin or CA it carries
/// (a pin wins), SNI / name override from `tls_server_name`. Credentials
/// come separately through [`WebDavConfig::with_identity`].
pub fn config_for(address: &str, section: &crate::model::WebDavConfig) -> Result<WebDavConfig> {
    let tls = match (&section.certificate_fingerprint, &section.ca_certificate) {
        (Some(fp), _) if !fp.trim().is_empty() => TlsPolicy::Pinned(fp.clone()),
        (_, Some(ca)) if !ca.trim().is_empty() => TlsPolicy::PrivateCa(ca.clone()),
        _ => TlsPolicy::System,
    };
    Ok(WebDavConfig {
        url: share_url(address, section)?.to_string(),
        tls,
        server_name: section
            .tls_server_name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(str::to_string),
        ..Default::default()
    })
}

/// A property set the server returned for one resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DavResource {
    /// Path below the base (normalised, no trailing slash except root).
    pub path: String,
    /// Collection?
    pub is_dir: bool,
    /// `getcontentlength`.
    pub size: Option<u64>,
    /// `getlastmodified` as unix seconds.
    pub mtime: Option<u32>,
    /// `getetag` (quotes stripped).
    pub etag: Option<String>,
    /// `getcontenttype`.
    pub content_type: Option<String>,
}

impl DavResource {
    fn into_entry(self) -> RemoteEntry {
        RemoteEntry {
            name: name_of(&self.path),
            kind: if self.is_dir {
                EntryKind::Dir
            } else {
                EntryKind::File
            },
            size: if self.is_dir { None } else { self.size },
            mode: None,
            uid: None,
            gid: None,
            user: None,
            group: None,
            mtime: self.mtime,
            atime: None,
            link_target: None,
            target_kind: None,
            path: self.path,
        }
    }
}

fn percent_decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// Map an `href` from a multistatus onto our path space.
fn href_to_path(href: &str, request_url: &Url, base_path: &str) -> Option<String> {
    let resolved = request_url.join(href.trim()).ok()?;
    let decoded = percent_decode(resolved.path());
    let rel = if base_path == "/" {
        decoded.as_str()
    } else {
        decoded
            .strip_prefix(base_path.trim_end_matches('/'))
            .filter(|r| r.is_empty() || r.starts_with('/'))?
    };
    let trimmed = rel.trim_end_matches('/');
    Some(if trimmed.is_empty() {
        "/".into()
    } else {
        trimmed.to_string()
    })
}

fn parse_http_status(s: &str) -> Option<u16> {
    s.split_whitespace().nth(1)?.parse().ok()
}

fn parse_http_date(s: &str) -> Option<u32> {
    let t = s.trim();
    let dt = chrono::DateTime::parse_from_rfc2822(t)
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(t))
        .ok()?;
    u32::try_from(dt.timestamp()).ok()
}

/// Parse a `207 Multi-Status` body.
pub fn parse_multistatus(
    body: &str,
    request_url: &Url,
    base_path: &str,
) -> Result<Vec<DavResource>> {
    let root = xml::parse(body).map_err(|e| webdav_err(None, format!("bad multistatus: {e}")))?;
    if root.name != "multistatus" {
        return Err(webdav_err(
            None,
            format!("expected multistatus, got <{}>", root.name),
        ));
    }
    let mut out = Vec::new();
    for resp in root.children("response") {
        let Some(href) = resp.text_of("href") else {
            continue;
        };
        let Some(path) = href_to_path(href, request_url, base_path) else {
            continue;
        };
        let mut res = DavResource {
            path,
            is_dir: false,
            size: None,
            mtime: None,
            etag: None,
            content_type: None,
        };
        let mut any_ok = false;
        for ps in resp.children("propstat") {
            let ok = match ps.text_of("status").and_then(parse_http_status) {
                Some(code) => (200..300).contains(&code),
                None => true,
            };
            if !ok {
                continue;
            }
            let Some(prop) = ps.child("prop") else {
                continue;
            };
            any_ok = true;
            if let Some(rt) = prop.child("resourcetype")
                && rt.child("collection").is_some()
            {
                res.is_dir = true;
            }
            if let Some(len) = prop.text_of("getcontentlength") {
                res.size = len.trim().parse().ok();
            }
            if let Some(lm) = prop.text_of("getlastmodified") {
                res.mtime = parse_http_date(lm);
            }
            if let Some(et) = prop.text_of("getetag") {
                res.etag = Some(et.trim().trim_matches('"').to_string());
            }
            if let Some(ct) = prop.text_of("getcontenttype") {
                res.content_type = Some(ct.trim().to_string());
            }
        }
        // A response with only failed propstats (e.g. 404 for every prop)
        // still names an existing resource; keep it as an opaque file.
        let _ = any_ok;
        out.push(res);
    }
    Ok(out)
}

const PROPFIND_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:getcontentlength/><D:getlastmodified/><D:getetag/><D:getcontenttype/></D:prop></D:propfind>"#;

/// A connected WebDAV collection. Cheap to clone; clones share the HTTP
/// pool and the negotiated authentication.
#[derive(Clone)]
pub struct WebDav {
    inner: Arc<Inner>,
}

struct Inner {
    http: reqwest::Client,
    base: Url,
    /// Decoded path of `base`, with trailing slash.
    base_path: String,
    /// `host[:port]` for messages.
    host: String,
    username: Option<String>,
    password: Option<String>,
    bearer_token: Option<String>,
    has_client_identity: bool,
    auth: Mutex<AuthState>,
    spool_dir: PathBuf,
}

impl std::fmt::Debug for WebDav {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDav")
            .field("base", &self.inner.base.as_str())
            .finish_non_exhaustive()
    }
}

impl WebDav {
    /// Build a client without touching the network.
    pub fn new(cfg: WebDavConfig) -> Result<Self> {
        let origin = normalize_url(&cfg.url)?;
        let Target { base, resolve } = target(&cfg)?;
        let tls = match &cfg.tls {
            TlsPolicy::System => None,
            TlsPolicy::Pinned(fp) => {
                let pin = parse_fingerprint(fp)?;
                Some(tls_config_with(
                    Arc::new(PinVerifier {
                        pin,
                        provider: Arc::new(rustls::crypto::ring::default_provider()),
                    }),
                    cfg.client_identity.as_ref(),
                )?)
            }
            TlsPolicy::PrivateCa(pem) => {
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                    Arc::new(ca_roots(pem)?),
                    provider,
                )
                .build()
                .map_err(|e| CoreError::Invalid(format!("CA certificate: {e}")))?;
                Some(tls_config_with(verifier, cfg.client_identity.as_ref())?)
            }
        };
        let http = http_client(&cfg, tls, resolve.as_ref())?;
        // Messages name the address the socket opens to, not the TLS name.
        let host = match origin.port() {
            Some(p) => format!("{}:{p}", origin.host_str().unwrap_or("")),
            None => origin.host_str().unwrap_or("").to_string(),
        };
        let bearer_token = cfg.bearer_token.filter(|t| !t.is_empty());
        let username = cfg.username.filter(|u| !u.is_empty());
        let password = if username.is_some() {
            Some(cfg.password.unwrap_or_default())
        } else {
            None
        };
        let scheme = if bearer_token.is_some() {
            AuthScheme::Bearer
        } else {
            AuthScheme::None
        };
        Ok(Self {
            inner: Arc::new(Inner {
                base_path: percent_decode(base.path()),
                base,
                host,
                http,
                username,
                password,
                bearer_token,
                has_client_identity: cfg.client_identity.is_some(),
                auth: Mutex::new(AuthState { scheme, nc: 0 }),
                spool_dir: cfg.spool_dir.unwrap_or_else(std::env::temp_dir),
            }),
        })
    }

    /// Build and verify: the base must answer PROPFIND as a collection. A
    /// certificate the policy does not trust surfaces as
    /// [`CoreError::CertificateRejected`] carrying its fingerprint.
    pub async fn connect(mut cfg: WebDavConfig) -> Result<Self> {
        if let Some((host, port)) = needs_lookup(&cfg).filter(|_| cfg.resolved_addrs.is_none()) {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|e| webdav_err(None, format!("cannot resolve {host}: {e}")))?
                .collect();
            cfg.resolved_addrs = Some(addrs);
        }
        let probe = cfg.clone();
        let dav = Self::new(cfg)?;
        match dav.stat("/").await {
            Ok(e) if e.kind == EntryKind::Dir => Ok(dav),
            Ok(_) => Err(webdav_err(
                None,
                format!("{} is not a WebDAV collection", dav.inner.base),
            )),
            Err(CoreError::Http(e)) if dav.inner.base.scheme() == "https" && is_tls_error(&e) => {
                let fingerprint = probe_certificate(&probe).await.unwrap_or_default();
                Err(CoreError::CertificateRejected {
                    host: dav.inner.host.clone(),
                    fingerprint,
                })
            }
            Err(CoreError::Http(e)) => match client_certificate_alert(&e) {
                Some(alert) if dav.inner.has_client_identity => Err(webdav_err(
                    None,
                    format!(
                        "{} rejected the client certificate ({alert})",
                        dav.inner.host
                    ),
                )),
                Some(alert) => Err(webdav_err(
                    None,
                    format!("{} requires a client certificate ({alert})", dav.inner.host),
                )),
                None => Err(CoreError::Http(e)),
            },
            Err(e) => Err(e),
        }
    }

    /// Collection URL.
    pub fn base_url(&self) -> &Url {
        &self.inner.base
    }

    /// `host[:port]` of the server.
    pub fn host(&self) -> &str {
        &self.inner.host
    }

    /// Wire URL for `path`; collections get a trailing slash.
    pub fn url_for(&self, path: &str, dir: bool) -> Result<Url> {
        let norm = normalize_path(path)?;
        let mut u = self.inner.base.clone();
        {
            let mut segs = u
                .path_segments_mut()
                .map_err(|_| CoreError::Invalid("URL cannot have a path".into()))?;
            segs.pop_if_empty();
            for s in norm.split('/').filter(|s| !s.is_empty()) {
                segs.push(s);
            }
            if dir || norm == "/" {
                segs.push("");
            }
        }
        Ok(u)
    }

    fn request(&self, m: Method, url: Url) -> RequestBuilder {
        self.inner.http.request(m, url)
    }

    async fn authorization(&self, req: &Request) -> Option<HeaderValue> {
        if let Some(tok) = &self.inner.bearer_token {
            return HeaderValue::from_str(&format!("Bearer {tok}")).ok();
        }
        let (user, pass) = (self.inner.username.as_ref()?, self.inner.password.as_ref()?);
        let mut guard = self.inner.auth.lock().await;
        let st = &mut *guard;
        match &st.scheme {
            AuthScheme::None | AuthScheme::Bearer => None,
            AuthScheme::Basic => {
                let tok =
                    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
                HeaderValue::from_str(&format!("Basic {tok}")).ok()
            }
            AuthScheme::Digest(ch) => {
                let nc = st.nc + 1;
                st.nc = nc;
                let uri = match req.url().query() {
                    Some(q) => format!("{}?{q}", req.url().path()),
                    None => req.url().path().to_string(),
                };
                let value = digest_authorization(
                    ch,
                    user,
                    pass,
                    req.method().as_str(),
                    &uri,
                    nc,
                    &random_cnonce(),
                );
                HeaderValue::from_str(&value).ok()
            }
        }
    }

    /// Adopt the strongest challenge we support; `Ok(true)` when a retry is
    /// worth it.
    async fn adopt_challenge(&self, headers: &HeaderMap, had_auth: bool) -> Result<bool> {
        let mut challenges = Vec::new();
        for v in headers.get_all(header::WWW_AUTHENTICATE) {
            if let Ok(s) = v.to_str() {
                challenges.extend(parse_challenges(s));
            }
        }
        let offered: Vec<String> = challenges.iter().map(|c| c.scheme.clone()).collect();
        // A token is not negotiated: the server either takes it or not.
        if self.inner.username.is_none() || self.inner.bearer_token.is_some() {
            return Err(CoreError::AuthFailed { remaining: offered });
        }
        let digest = challenges.iter().find(|c| c.scheme == "digest");
        let basic = challenges.iter().any(|c| c.scheme == "basic");
        let mut st = self.inner.auth.lock().await;
        if let Some(d) = digest {
            let ch = digest_challenge(d)?;
            let fresh_nonce = match &st.scheme {
                AuthScheme::Digest(prev) => prev.nonce != ch.nonce,
                _ => true,
            };
            if had_auth && !ch.stale && !fresh_nonce {
                return Err(CoreError::AuthFailed { remaining: offered });
            }
            st.scheme = AuthScheme::Digest(ch);
            st.nc = 0;
            return Ok(true);
        }
        if basic {
            if had_auth && matches!(st.scheme, AuthScheme::Basic) {
                return Err(CoreError::AuthFailed { remaining: offered });
            }
            st.scheme = AuthScheme::Basic;
            return Ok(true);
        }
        Err(CoreError::AuthFailed { remaining: offered })
    }

    /// Send a request, negotiating authentication once. `make` is invoked
    /// again for the retry, so streaming bodies are rebuilt rather than
    /// buffered.
    async fn send_with<F, Fut>(&self, make: F) -> Result<Response>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<RequestBuilder>>,
    {
        for attempt in 0..3 {
            let mut req = make().await?.build()?;
            let had_auth = match self.authorization(&req).await {
                Some(v) => {
                    req.headers_mut().insert(header::AUTHORIZATION, v);
                    true
                }
                None => false,
            };
            let resp = self.inner.http.execute(req).await?;
            if resp.status() != StatusCode::UNAUTHORIZED || attempt == 2 {
                return Ok(resp);
            }
            if !self.adopt_challenge(resp.headers(), had_auth).await? {
                return Ok(resp);
            }
        }
        unreachable!("loop returns")
    }

    async fn send(&self, m: Method, url: Url) -> Result<Response> {
        let rb = self.request(m, url);
        self.send_with(|| {
            let rb = rb.try_clone();
            async move { rb.ok_or_else(|| webdav_err(None, "request body is not replayable")) }
        })
        .await
    }

    /// Turn a non-success status into an error for `path`.
    fn check(resp: Response, path: &str) -> Result<Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let code = status.as_u16();
        Err(match code {
            404 | 410 => CoreError::NotFound(path.to_string()),
            401 => CoreError::AuthFailed {
                remaining: Vec::new(),
            },
            403 => webdav_err(Some(code), format!("permission denied: {path}")),
            405 => webdav_err(Some(code), format!("not allowed here: {path}")),
            409 => webdav_err(
                Some(code),
                format!("parent directory does not exist: {path}"),
            ),
            412 => webdav_err(Some(code), format!("destination already exists: {path}")),
            416 => webdav_err(Some(code), format!("range not satisfiable: {path}")),
            423 => webdav_err(Some(code), format!("locked: {path}")),
            501 => webdav_err(Some(code), "operation not supported by the server"),
            507 => webdav_err(Some(code), "insufficient storage on the server"),
            _ => webdav_err(
                Some(code),
                format!(
                    "server returned {code}{}",
                    status
                        .canonical_reason()
                        .map(|r| format!(" {r}"))
                        .unwrap_or_default()
                ),
            ),
        })
    }

    async fn propfind(&self, path: &str, depth: u8, dir: bool) -> Result<Vec<DavResource>> {
        let url = self.url_for(path, dir)?;
        let resp = self
            .send_with(|| {
                let rb = self
                    .request(method("PROPFIND"), url.clone())
                    .header("Depth", depth.to_string())
                    .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
                    .body(PROPFIND_BODY);
                async move { Ok(rb) }
            })
            .await?;
        // A collection asked for without its trailing slash: follow once.
        if resp.status().is_redirection()
            && !dir
            && let Some(loc) = resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
            && let Ok(target) = url.join(loc)
            && target.host_str() == url.host_str()
            && target.path() == format!("{}/", url.path())
        {
            return Box::pin(self.propfind(path, depth, true)).await;
        }
        let resp = Self::check(resp, path)?;
        if resp.status() != StatusCode::MULTI_STATUS {
            return Err(webdav_err(
                Some(resp.status().as_u16()),
                format!(
                    "{} did not answer PROPFIND with 207 Multi-Status",
                    self.inner.host
                ),
            ));
        }
        let body = resp.text().await?;
        parse_multistatus(&body, &url, &self.inner.base_path)
    }

    async fn stat_resource(&self, path: &str) -> Result<DavResource> {
        let norm = normalize_path(path)?;
        let mut found = self.propfind(&norm, 0, norm == "/").await?;
        // Servers answering depth 0 with the parent listing (seen on some
        // IIS builds) still include the resource itself.
        let idx = found
            .iter()
            .position(|r| r.path == norm)
            .or_else(|| (found.len() == 1).then_some(0))
            .ok_or_else(|| CoreError::NotFound(norm.clone()))?;
        let mut r = found.swap_remove(idx);
        r.path = norm;
        Ok(r)
    }

    async fn is_dir(&self, path: &str) -> Result<bool> {
        Ok(self.stat_resource(path).await?.is_dir)
    }

    async fn move_or_copy(&self, m: &str, from: &str, to: &str) -> Result<()> {
        let from_n = normalize_path(from)?;
        let to_n = normalize_path(to)?;
        if to_n == from_n || to_n.starts_with(&format!("{from_n}/")) {
            return Err(CoreError::Invalid(
                "destination is inside the source".into(),
            ));
        }
        let dir = self.is_dir(&from_n).await?;
        let src = self.url_for(&from_n, dir)?;
        let dst = self.url_for(&to_n, dir)?;
        let resp = self
            .send_with(|| {
                let rb = self
                    .request(method(m), src.clone())
                    .header("Destination", dst.as_str())
                    .header("Overwrite", "F");
                async move { Ok(rb) }
            })
            .await?;
        if resp.status() == StatusCode::PRECONDITION_FAILED {
            return Err(webdav_err(
                Some(412),
                format!("destination already exists: {to_n}"),
            ));
        }
        Self::check(resp, &from_n).map(|_| ())
    }

    async fn get_range(&self, path: &str, offset: u64, len: usize) -> Result<Bytes> {
        if len == 0 {
            return Ok(Bytes::new());
        }
        let url = self.url_for(path, false)?;
        let end = offset + len as u64 - 1;
        let resp = self
            .send_with(|| {
                let rb = self
                    .request(Method::GET, url.clone())
                    .header(header::RANGE, format!("bytes={offset}-{end}"));
                async move { Ok(rb) }
            })
            .await?;
        if resp.status() == StatusCode::RANGE_NOT_SATISFIABLE {
            return Ok(Bytes::new());
        }
        let resp = Self::check(resp, path)?;
        if resp.status() == StatusCode::PARTIAL_CONTENT {
            let b = resp.bytes().await?;
            return Ok(if b.len() > len { b.slice(..len) } else { b });
        }
        // The server ignored the range and sent the whole file: take the
        // slice we need and drop the rest of the stream.
        let mut stream = resp.bytes_stream();
        let mut out = Vec::with_capacity(len);
        let mut pos = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let chunk_end = pos + chunk.len() as u64;
            if chunk_end > offset {
                let start = offset.saturating_sub(pos) as usize;
                let take = ((end + 1).min(chunk_end) - pos.max(offset)) as usize;
                out.extend_from_slice(&chunk[start..start + take]);
            }
            pos = chunk_end;
            if pos > end {
                break;
            }
        }
        Ok(Bytes::from(out))
    }

    /// PUT the contents of `local` (from byte 0) at `remote`, streaming, with
    /// progress and cancellation. `mtime` is offered via `X-OC-Mtime`.
    async fn put_file(
        &self,
        local: &Path,
        remote: &str,
        size: u64,
        mtime: Option<u64>,
        opts: &TransferOptions,
    ) -> Result<()> {
        let url = self.url_for(remote, false)?;
        let done = Arc::new(AtomicU64::new(0));
        let progress = opts.progress.clone();
        let make = || {
            let url = url.clone();
            let done = done.clone();
            let progress = progress.clone();
            async move {
                let file = tokio::fs::File::open(local).await?;
                done.store(0, Ordering::Relaxed);
                let stream =
                    tokio_util::io::ReaderStream::with_capacity(file, CHUNK).map(move |chunk| {
                        if let Ok(c) = &chunk {
                            let d =
                                done.fetch_add(c.len() as u64, Ordering::Relaxed) + c.len() as u64;
                            if let Some(p) = &progress {
                                p(crate::sftp::Progress {
                                    done: d,
                                    total: Some(size),
                                });
                            }
                        }
                        chunk
                    });
                let mut rb = self
                    .request(Method::PUT, url)
                    .header(header::CONTENT_LENGTH, size)
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(reqwest::Body::wrap_stream(stream));
                if let Some(m) = mtime {
                    rb = rb.header(MTIME_HEADER, m);
                }
                Ok(rb)
            }
        };
        if opts.cancel.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
        let resp = tokio::select! {
            r = self.send_with(make) => r?,
            _ = opts.cancel.cancelled() => return Err(CoreError::Cancelled),
        };
        Self::check(resp, remote).map(|_| ())
    }
}

#[async_trait::async_trait]
impl RemoteFs for WebDav {
    fn protocol(&self) -> RemoteProtocol {
        RemoteProtocol::WebDav
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
        let dir = normalize_path(dir)?;
        let found = self.propfind(&dir, 1, true).await?;
        let mut out: Vec<RemoteEntry> = found
            .into_iter()
            .filter(|r| r.path != dir && parent(&r.path).as_deref() == Some(dir.as_str()))
            .map(DavResource::into_entry)
            .collect();
        out.sort_by(|a, b| {
            let da = a.kind == EntryKind::Dir;
            let db = b.kind == EntryKind::Dir;
            db.cmp(&da)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(out)
    }

    async fn stat(&self, path: &str) -> Result<RemoteEntry> {
        Ok(self.stat_resource(path).await?.into_entry())
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        match self.stat_resource(path).await {
            Ok(_) => Ok(true),
            Err(CoreError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn mkdir(&self, path: &str) -> Result<()> {
        let norm = normalize_path(path)?;
        if norm == "/" {
            return Err(webdav_err(None, "cannot create the root"));
        }
        let url = self.url_for(&norm, true)?;
        let resp = self.send(method("MKCOL"), url).await?;
        if resp.status() == StatusCode::METHOD_NOT_ALLOWED {
            return Err(webdav_err(Some(405), format!("already exists: {norm}")));
        }
        Self::check(resp, &norm).map(|_| ())
    }

    async fn mkdir_all(&self, path: &str) -> Result<()> {
        let norm = normalize_path(path)?;
        let mut cur = String::new();
        for seg in norm.split('/').filter(|s| !s.is_empty()) {
            cur.push('/');
            cur.push_str(seg);
            match self.stat_resource(&cur).await {
                Ok(r) if r.is_dir => continue,
                Ok(_) => {
                    return Err(webdav_err(
                        None,
                        format!("{cur} exists and is not a directory"),
                    ));
                }
                Err(CoreError::NotFound(_)) => self.mkdir(&cur).await?,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.move_or_copy("MOVE", from, to).await
    }

    async fn copy(&self, from: &str, to: &str) -> Result<()> {
        self.move_or_copy("COPY", from, to).await
    }

    async fn remove_file(&self, path: &str) -> Result<()> {
        let norm = normalize_path(path)?;
        let url = self.url_for(&norm, false)?;
        let resp = self.send(Method::DELETE, url).await?;
        Self::check(resp, &norm).map(|_| ())
    }

    async fn remove_dir(&self, path: &str) -> Result<()> {
        let norm = normalize_path(path)?;
        if norm == "/" {
            return Err(webdav_err(None, "cannot remove the root"));
        }
        if !self.list(&norm).await?.is_empty() {
            return Err(webdav_err(None, format!("directory not empty: {norm}")));
        }
        let url = self.url_for(&norm, true)?;
        let resp = self.send(Method::DELETE, url).await?;
        Self::check(resp, &norm).map(|_| ())
    }

    async fn remove_dir_all(&self, path: &str, cancel: &CancellationToken) -> Result<()> {
        let norm = normalize_path(path)?;
        if norm == "/" {
            return Err(webdav_err(None, "cannot remove the root"));
        }
        if cancel.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
        let url = self.url_for(&norm, true)?;
        let resp = tokio::select! {
            r = self.send(Method::DELETE, url) => r?,
            _ = cancel.cancelled() => return Err(CoreError::Cancelled),
        };
        Self::check(resp, &norm).map(|_| ())
    }

    async fn chmod(&self, _path: &str, _mode: u32) -> Result<()> {
        Err(webdav_err(None, "WebDAV has no permission bits"))
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let norm = normalize_path(path)?;
        let r = self.stat_resource(&norm).await?;
        if r.is_dir {
            return Err(webdav_err(None, format!("{norm} is a directory")));
        }
        if r.size.unwrap_or(0) > MAX_IN_MEMORY {
            return Err(webdav_err(None, "file too large to read into memory"));
        }
        let url = self.url_for(&norm, false)?;
        let resp = Self::check(self.send(Method::GET, url).await?, &norm)?;
        let mut out = Vec::with_capacity(r.size.unwrap_or(0) as usize);
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk?);
            if out.len() as u64 > MAX_IN_MEMORY {
                return Err(webdav_err(None, "file too large to read into memory"));
            }
        }
        Ok(out)
    }

    async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let norm = normalize_path(path)?;
        let url = self.url_for(&norm, false)?;
        let body = data.to_vec();
        let resp = self
            .send_with(|| {
                let rb = self
                    .request(Method::PUT, url.clone())
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(body.clone());
                async move { Ok(rb) }
            })
            .await?;
        Self::check(resp, &norm).map(|_| ())
    }

    async fn open_file(&self, path: &str, mode: OpenMode) -> Result<Box<dyn remote::RemoteFile>> {
        let norm = normalize_path(path)?;
        let existing = match self.stat_resource(&norm).await {
            Ok(r) => Some(r),
            Err(CoreError::NotFound(_)) if mode != OpenMode::Read => None,
            Err(e) => return Err(e),
        };
        if existing.as_ref().is_some_and(|r| r.is_dir) {
            return Err(webdav_err(None, format!("{norm} is a directory")));
        }
        match mode {
            OpenMode::Read => {
                let r = existing.expect("stat succeeded for read");
                Ok(Box::new(WebDavFile {
                    path: norm,
                    dav: self.clone(),
                    state: Mutex::new(FileState::Read {
                        size: r.size.unwrap_or(0),
                    }),
                }))
            }
            OpenMode::Write | OpenMode::ReadWrite => {
                tokio::fs::create_dir_all(&self.inner.spool_dir).await?;
                let spool = self
                    .inner
                    .spool_dir
                    .join(format!("termoso-webdav-{}", uuid::Uuid::new_v4()));
                let mut file = tokio::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&spool)
                    .await?;
                if mode == OpenMode::ReadWrite && existing.is_some() {
                    let url = self.url_for(&norm, false)?;
                    let resp = Self::check(self.send(Method::GET, url).await?, &norm)?;
                    let mut stream = resp.bytes_stream();
                    while let Some(chunk) = stream.next().await {
                        file.write_all(&chunk?).await?;
                    }
                    file.flush().await?;
                }
                Ok(Box::new(WebDavFile {
                    path: norm,
                    dav: self.clone(),
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
        let r = self.stat_resource(&norm).await?;
        if r.is_dir {
            return Err(webdav_err(None, format!("{norm} is a directory")));
        }
        let total = r.size;

        let mut offset = 0u64;
        let mut file = if opts.resume && local.exists() {
            let mut f = tokio::fs::OpenOptions::new()
                .append(true)
                .open(local)
                .await?;
            offset = f.metadata().await?.len();
            if let Some(t) = total
                && offset > t
            {
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
        if total == Some(offset) && offset > 0 {
            opts.report(offset, total);
            return Ok(0);
        }

        let url = self.url_for(&norm, false)?;
        let resp = self
            .send_with(|| {
                let mut rb = self.request(Method::GET, url.clone());
                if offset > 0 {
                    rb = rb.header(header::RANGE, format!("bytes={offset}-"));
                }
                async move { Ok(rb) }
            })
            .await?;
        let resp = Self::check(resp, &norm)?;
        if offset > 0 && resp.status() != StatusCode::PARTIAL_CONTENT {
            // Range ignored: start over.
            file = tokio::fs::File::create(local).await?;
            offset = 0;
        }
        opts.report(offset, total);

        let mut done = offset;
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
        }
        file.flush().await?;
        drop(file);

        if opts.preserve_mtime
            && let Some(mtime) = r.mtime
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
            return Err(webdav_err(
                None,
                format!("{} is a directory", local.display()),
            ));
        }
        let size = meta.len();
        let mtime = if opts.preserve_mtime {
            meta.modified()
                .ok()
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
        } else {
            None
        };
        opts.report(0, Some(size));
        self.put_file(local, &norm, size, mtime, opts).await?;
        opts.report(size, Some(size));
        Ok(size)
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

enum FileState {
    /// Read-only: every `read_at` is a ranged GET.
    Read { size: u64 },
    /// Writable: a local spool file, PUT on `sync`/`close`.
    Spool {
        file: tokio::fs::File,
        spool: PathBuf,
        dirty: bool,
    },
}

/// Positional access to one WebDAV resource.
pub struct WebDavFile {
    path: String,
    dav: WebDav,
    state: Mutex<FileState>,
}

impl WebDavFile {
    async fn flush_spool(&self, st: &mut FileState) -> Result<()> {
        let FileState::Spool { file, spool, dirty } = st else {
            return Ok(());
        };
        if !*dirty {
            return Ok(());
        }
        let size = spool_len(file).await?;
        self.dav
            .put_file(spool, &self.path, size, None, &TransferOptions::default())
            .await?;
        *dirty = false;
        Ok(())
    }
}

/// `tokio::fs::File::metadata` does not wait for buffered writes, so the
/// length is only accurate after a flush.
async fn spool_len(file: &mut tokio::fs::File) -> Result<u64> {
    file.flush().await?;
    Ok(file.metadata().await?.len())
}

impl Drop for WebDavFile {
    fn drop(&mut self) {
        if let Ok(st) = self.state.try_lock()
            && let FileState::Spool { spool, .. } = &*st
        {
            let _ = std::fs::remove_file(spool);
        }
    }
}

#[async_trait::async_trait]
impl remote::RemoteFile for WebDavFile {
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
                let b = self.dav.get_range(&self.path, offset, want).await?;
                Ok(b.to_vec())
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
            FileState::Read { .. } => Err(webdav_err(None, "file is open read-only")),
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
            FileState::Read { .. } => Err(webdav_err(None, "file is open read-only")),
            FileState::Spool { file, dirty, .. } => {
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
    fn normalizes_paths() {
        assert_eq!(normalize_path("").unwrap(), "/");
        assert_eq!(normalize_path("/").unwrap(), "/");
        assert_eq!(normalize_path("a/b/").unwrap(), "/a/b");
        assert_eq!(normalize_path("/a//b/./c").unwrap(), "/a/b/c");
        assert_eq!(normalize_path("/a/b/../c").unwrap(), "/a/c");
        assert!(normalize_path("/../x").is_err());
        assert!(normalize_path("/a\0b").is_err());
    }

    #[test]
    fn builds_urls_with_encoding() {
        let dav = WebDav::new(WebDavConfig {
            url: "https://cloud.example.com/remote.php/dav/files/me".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            dav.inner.base.as_str(),
            "https://cloud.example.com/remote.php/dav/files/me/"
        );
        assert_eq!(dav.inner.base_path, "/remote.php/dav/files/me/");
        assert_eq!(
            dav.url_for("/Photos/sum mer/#1 100%.jpg", false)
                .unwrap()
                .as_str(),
            "https://cloud.example.com/remote.php/dav/files/me/Photos/sum%20mer/%231%20100%25.jpg"
        );
        assert_eq!(
            dav.url_for("/Photos", true).unwrap().as_str(),
            "https://cloud.example.com/remote.php/dav/files/me/Photos/"
        );
        assert_eq!(
            dav.url_for("/", false).unwrap().as_str(),
            "https://cloud.example.com/remote.php/dav/files/me/"
        );
        assert_eq!(
            dav.url_for("/a?b", false).unwrap().as_str(),
            "https://cloud.example.com/remote.php/dav/files/me/a%3Fb"
        );
    }

    #[test]
    fn normalizes_base_urls() {
        assert_eq!(
            normalize_url("dav.example.com/x?y#z").unwrap().as_str(),
            "https://dav.example.com/x/"
        );
        assert_eq!(
            normalize_url("http://h:8080").unwrap().as_str(),
            "http://h:8080/"
        );
        assert!(normalize_url("ftp://h/").is_err());
        assert!(normalize_url("https://").is_err());
    }

    #[test]
    fn maps_hrefs_to_paths() {
        let req = Url::parse("https://h/dav/files/me/Photos/").unwrap();
        let base = "/dav/files/me/";
        assert_eq!(
            href_to_path("/dav/files/me/Photos/", &req, base).unwrap(),
            "/Photos"
        );
        assert_eq!(
            href_to_path("/dav/files/me/Photos/sum%20mer.jpg", &req, base).unwrap(),
            "/Photos/sum mer.jpg"
        );
        assert_eq!(
            href_to_path("https://other-host/dav/files/me/", &req, base).unwrap(),
            "/"
        );
        assert_eq!(href_to_path("a.txt", &req, base).unwrap(), "/Photos/a.txt");
        assert_eq!(href_to_path("/dav/files/meX/", &req, base), None);
        assert_eq!(href_to_path("/elsewhere/", &req, base), None);
        assert_eq!(href_to_path("/x/y/", &req, "/").unwrap(), "/x/y");
    }

    #[test]
    fn parses_multistatus() {
        let body = r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
 <d:response>
  <d:href>/dav/files/me/Photos/</d:href>
  <d:propstat>
   <d:prop>
    <d:resourcetype><d:collection/></d:resourcetype>
    <d:getlastmodified>Sat, 19 Sep 2026 11:05:00 GMT</d:getlastmodified>
    <d:getetag>"abc"</d:getetag>
   </d:prop>
   <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
  <d:propstat>
   <d:prop><d:getcontentlength/><d:getcontenttype/></d:prop>
   <d:status>HTTP/1.1 404 Not Found</d:status>
  </d:propstat>
 </d:response>
 <d:response>
  <d:href>/dav/files/me/Photos/sum%20mer.jpg</d:href>
  <d:propstat>
   <d:prop>
    <d:resourcetype/>
    <d:getcontentlength>12345</d:getcontentlength>
    <d:getcontenttype>image/jpeg</d:getcontenttype>
    <d:getlastmodified>Fri, 18 Sep 2026 10:00:00 GMT</d:getlastmodified>
   </d:prop>
   <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
 </d:response>
</d:multistatus>"#;
        let req = Url::parse("https://h/dav/files/me/Photos/").unwrap();
        let res = parse_multistatus(body, &req, "/dav/files/me/").unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].path, "/Photos");
        assert!(res[0].is_dir);
        assert_eq!(res[0].etag.as_deref(), Some("abc"));
        assert_eq!(res[0].mtime, Some(1789815900));
        assert_eq!(res[0].size, None);
        assert_eq!(res[1].path, "/Photos/sum mer.jpg");
        assert!(!res[1].is_dir);
        assert_eq!(res[1].size, Some(12345));
        assert_eq!(res[1].content_type.as_deref(), Some("image/jpeg"));
        let e = res[1].clone().into_entry();
        assert_eq!(e.name, "sum mer.jpg");
        assert_eq!(e.kind, EntryKind::File);
    }

    #[test]
    fn rejects_non_multistatus_xml() {
        let req = Url::parse("https://h/").unwrap();
        assert!(parse_multistatus("<html/>", &req, "/").is_err());
        assert!(parse_multistatus("not xml", &req, "/").is_err());
    }

    #[test]
    fn parses_www_authenticate() {
        let c = parse_challenges(
            r#"Digest realm="dav@example", qop="auth,auth-int", nonce="n1", opaque="o\"1", algorithm=MD5, stale=TRUE, Basic realm="dav@example""#,
        );
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].scheme, "digest");
        assert_eq!(c[0].param("realm"), Some("dav@example"));
        assert_eq!(c[0].param("qop"), Some("auth,auth-int"));
        assert_eq!(c[0].param("opaque"), Some("o\"1"));
        assert_eq!(c[0].param("algorithm"), Some("MD5"));
        assert_eq!(c[1].scheme, "basic");
        assert_eq!(c[1].param("realm"), Some("dav@example"));

        let d = digest_challenge(&c[0]).unwrap();
        assert!(d.qop_auth);
        assert!(d.stale);
        assert_eq!(d.algorithm, DigestAlgorithm::Md5);

        let b = parse_challenges("Basic");
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].scheme, "basic");

        let bad = parse_challenges(r#"Digest realm="x", nonce="n", qop="auth-int""#);
        assert!(digest_challenge(&bad[0]).is_err());
        let sha = parse_challenges(r#"Digest realm="x", nonce="n", algorithm=SHA-512-256"#);
        assert!(digest_challenge(&sha[0]).is_err());
    }

    /// RFC 7616 §3.9.1 vectors.
    #[test]
    fn digest_matches_rfc7616_examples() {
        let ch = DigestChallenge {
            realm: "http-auth@example.org".into(),
            nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v".into(),
            opaque: Some("FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS".into()),
            algorithm: DigestAlgorithm::Md5,
            qop_auth: true,
            stale: false,
        };
        let cnonce = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
        let h = digest_authorization(
            &ch,
            "Mufasa",
            "Circle of Life",
            "GET",
            "/dir/index.html",
            1,
            cnonce,
        );
        assert!(h.starts_with("Digest username=\"Mufasa\""));
        assert!(
            h.contains(r#"response="8ca523f5e9506fed4657c9700eebdbec""#),
            "{h}"
        );
        assert!(h.contains("nc=00000001"));
        assert!(h.contains("qop=auth"));
        assert!(h.contains(r#"opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#));

        let sha = DigestChallenge {
            algorithm: DigestAlgorithm::Sha256,
            ..ch
        };
        let h = digest_authorization(
            &sha,
            "Mufasa",
            "Circle of Life",
            "GET",
            "/dir/index.html",
            1,
            cnonce,
        );
        assert!(
            h.contains(
                r#"response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1""#
            ),
            "{h}"
        );
        assert!(h.contains("algorithm=SHA-256"));
        assert!(!h.contains("Circle of Life"));
    }

    #[test]
    fn digest_rfc2069_form_has_no_qop() {
        let ch = DigestChallenge {
            realm: "r".into(),
            nonce: "n".into(),
            opaque: None,
            algorithm: DigestAlgorithm::Md5,
            qop_auth: false,
            stale: false,
        };
        let h = digest_authorization(&ch, "u", "p", "GET", "/", 1, "c");
        assert!(!h.contains("qop="));
        assert!(!h.contains("cnonce="));
        let ha1 = format!("{:x}", md5::compute(b"u:r:p"));
        let ha2 = format!("{:x}", md5::compute(b"GET:/"));
        let expect = format!("{:x}", md5::compute(format!("{ha1}:n:{ha2}").as_bytes()));
        assert!(h.contains(&format!("response=\"{expect}\"")));
    }

    #[test]
    fn quotes_escape_special_characters() {
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn fingerprints() {
        let fp = fingerprint(b"abc");
        assert_eq!(
            fp,
            "ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad"
        );
        assert_eq!(
            parse_fingerprint(&fp.to_uppercase()).unwrap(),
            <[u8; 32]>::from(Sha256::digest(b"abc"))
        );
        assert!(parse_fingerprint("ab:cd").is_err());
        assert!(
            WebDav::new(WebDavConfig {
                url: "https://h/".into(),
                tls: TlsPolicy::Pinned("zz".into()),
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn parses_http_dates() {
        assert_eq!(
            parse_http_date("Sat, 19 Sep 2026 11:05:00 GMT"),
            Some(1789815900)
        );
        assert_eq!(parse_http_date("2026-09-19T11:05:00Z"), Some(1789815900));
        assert_eq!(parse_http_date("yesterday"), None);
    }

    #[test]
    fn tls_policy_serializes_tagged() {
        let s = serde_json::to_string(&TlsPolicy::Pinned("aa:bb".into())).unwrap();
        assert_eq!(s, r#"{"mode":"pinned","fingerprint":"aa:bb"}"#);
        let s = serde_json::to_string(&TlsPolicy::System).unwrap();
        assert_eq!(s, r#"{"mode":"system"}"#);
        assert_eq!(
            serde_json::from_str::<TlsPolicy>(r#"{"mode":"system"}"#).unwrap(),
            TlsPolicy::System
        );
    }
}
