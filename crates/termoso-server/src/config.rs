//! Configuration: `TERMOSO_*` environment variables, optionally layered over a
//! TOML file (`TERMOSO_CONFIG=/etc/termoso/config.toml`).
//!
//! Nested keys use `__`: `TERMOSO_S3__BUCKET`, `TERMOSO_SSO__GOOGLE__CLIENT_ID`.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::{Deserialize, Serialize};
use termoso_crypto::keys::SymmetricKey;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    /// Address to bind the API on.
    pub bind: SocketAddr,
    /// Public base URL of the API (used in emails and OAuth redirects).
    pub public_url: String,
    /// Public URL of the web cabinet (links in emails). Defaults to `public_url`.
    pub web_url: Option<String>,
    /// Dedicated origin for SSH ID handles (e.g. `https://sshid.example.com`).
    /// Requests whose `Host` matches it are served the handle lists at the
    /// root (`/<handle>`, `/<handle>/<type>`) and profiles advertise that URL.
    /// `<public_url>/sshid/<handle>` keeps working either way.
    pub sshid_url: Option<String>,
    /// Directory with the built web cabinet (`web/dist`). When set, the server
    /// serves it on `/` with an `index.html` fallback for client-side routes.
    pub web_dir: Option<String>,
    /// Show the marketing landing page on `/` of the cabinet. `false` sends
    /// `/` straight to `/login` (signed-in browsers continue to the cabinet).
    pub landing: bool,
    /// Dedicated origin for the landing page (e.g. `https://example.com`) when
    /// the cabinet and API live on a subdomain (`https://app.example.com`).
    /// Requests whose `Host` matches get the landing on `/` and its assets;
    /// every other path redirects to the same path under `web_url`. `/` on
    /// the cabinet origin then behaves as if `landing = false`.
    pub landing_url: Option<String>,
    /// Serve the documentation (`/docs`, part of the web cabinet bundle).
    /// `false` answers 404 there on every origin.
    pub docs: bool,
    /// Dedicated origin for the documentation (e.g. `https://docs.example.com`).
    /// Requests whose `Host` matches get `/docs/*` and its assets, `/` goes
    /// to `/docs`, every other path redirects to the same path under
    /// `web_url`; the landing and cabinet origins then redirect `/docs/*`
    /// here.
    pub docs_url: Option<String>,
    /// Human name shown in emails / server info.
    pub server_name: String,
    /// Android apps allowed to open this server's `https://…/invite/…` and
    /// `/join/…` links directly (Android App Links). Comma-separated
    /// `<package>=<SHA-256 signing-certificate fingerprint>` pairs, e.g.
    /// `com.termoso.android=AB:CD:…`; published as `/.well-known/assetlinks.json`.
    pub android_app_links: String,
    pub database_url: String,
    pub database_max_connections: u32,
    pub redis_url: String,
    /// Prefix for every Redis key/channel (lets deployments share one Redis).
    pub redis_prefix: String,
    /// Base64, 32 bytes. Encrypts server-side secrets at rest (OPAQUE server
    /// setup, TOTP secrets). Generate: `openssl rand -base64 32`.
    pub master_key: String,
    /// Comma-separated emails that are granted admin on first login/registration.
    pub admin_emails: String,
    /// E-mail of the server owner: the only account that can grant or revoke
    /// the admin role. Empty = the first registered account.
    pub owner_email: String,
    /// Allowed CORS origins (comma-separated). Empty = same-origin only.
    pub cors_origins: String,
    /// Trust `X-Forwarded-For` / `X-Real-IP` from the reverse proxy.
    pub trust_proxy: bool,
    pub log: String,
    pub log_format: LogFormat,
    pub s3: Option<S3Config>,
    /// Keep session logs in this directory instead of S3 (`TERMOSO_LOGS_DIR`).
    /// Ignored when `s3` is set. Not shared between replicas: use S3 for HA.
    pub logs_dir: Option<std::path::PathBuf>,
    pub smtp: Option<SmtpConfig>,
    /// Cloudflare Turnstile (`TERMOSO_TURNSTILE__SITE_KEY` / `__SECRET_KEY`).
    /// Unset = no captcha anywhere.
    pub turnstile: Option<TurnstileConfig>,
    pub webauthn: Option<WebauthnConfig>,
    pub metrics: MetricsConfig,
    pub sso: BTreeMap<String, SsoProviderConfig>,
    /// Let teams configure their own identity provider (`PUT /teams/{id}/idp`).
    /// `TERMOSO_TEAM_IDP=false` hides the feature on single-tenant servers.
    pub team_idp: bool,
    /// AI command suggestions (`POST /ai/command`). Absent = feature off.
    pub ai: Option<AiConfig>,
    /// Serve the Swagger UI at `/api/docs`.
    pub swagger_ui: bool,
    /// Offer API bridges (`/account/bridges`, bridge tokens). `false` hides
    /// the feature from the cabinet and rejects existing bridge tokens; the
    /// hosted cloud runs with it off.
    pub bridges: bool,
    /// Seconds between confirming a "start over" account reset and being
    /// allowed to complete it. The waiting period is what lets the real owner
    /// cancel a reset they did not ask for. Default: 24 hours.
    pub start_over_delay_secs: u64,
    /// Upper bound teams may set for `audit_retention_days` (30..=3650).
    /// Default: 3650.
    pub audit_retention_days_max: u32,
    /// Also write every team audit event as one JSON line to the log
    /// (target `termoso_audit`) for log shippers. Default: false.
    pub audit_sink: bool,
    /// Allow webhooks to private/loopback addresses (self-hosted internal
    /// SIEMs). Default: false.
    pub webhooks_allow_private: bool,
    /// Extra PEM bundle trusted by `syslog_tls` webhooks in addition to the
    /// OS trust store (private CAs). `TERMOSO_WEBHOOKS_SYSLOG_CA=/path.pem`.
    pub webhooks_syslog_ca: Option<String>,
    /// Where this server keeps its data (e.g. `eu`, `us`); stamped on teams
    /// at creation and shown to clients. Default: unset.
    pub data_region: Option<String>,
    /// Oldest client version allowed to sign in (semver). Default: this
    /// server's own version — clients must be at least as new as the server.
    pub min_client_version: Option<String>,
    /// Days between an owner scheduling team deletion and the purge
    /// (0 = immediate). Default: 7.
    pub team_deletion_grace_days: u32,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3Config {
    pub bucket: String,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    /// Endpoint to put into pre-signed URLs handed to clients (e.g. a public
    /// storage hostname), when different from `endpoint`.
    pub public_endpoint: Option<String>,
    pub access_key: String,
    pub secret_key: String,
    #[serde(default = "default_true")]
    pub force_path_style: bool,
    #[serde(default = "default_presign_secs")]
    pub presign_secs: u64,
}

/// Cloudflare Turnstile keys. The site key is public (sent to clients via
/// `/server/info`); the secret is only used for `siteverify`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TurnstileConfig {
    pub site_key: String,
    pub secret_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SmtpConfig {
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    /// `starttls` (default), `tls` (implicit), `none` (plain, for local dev).
    #[serde(default)]
    pub security: SmtpSecurity,
    /// `From:` header, e.g. `Termoso <no-reply@termoso.dev>`.
    pub from: String,
}

/// Any OpenAI-compatible chat-completions endpoint. The default preset is
/// Chutes' GLM-4.7-Flash chute running inside a TEE.
///
/// `TERMOSO_AI__API_KEY=…` alone turns the feature on with the defaults.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AiConfig {
    /// Base URL ending in `/v1` (the server appends `/chat/completions`).
    #[serde(default = "default_ai_url")]
    pub url: String,
    /// Bearer token for the endpoint. Never logged, never sent to clients.
    pub api_key: String,
    /// Model identifier passed in the request body.
    #[serde(default = "default_ai_model")]
    pub model: String,
    /// Provider name shown to users ("Suggested by …").
    #[serde(default = "default_ai_provider")]
    pub provider: String,
    /// The model runs in a trusted execution environment (confidential
    /// compute). Shown as a badge; set to `false` for ordinary endpoints.
    #[serde(default = "default_true")]
    pub confidential: bool,
    /// Requests per account per UTC day.
    #[serde(default = "default_ai_daily_quota")]
    pub daily_quota: u32,
    /// Upper bound on the user's request text, in characters.
    #[serde(default = "default_ai_max_prompt_chars")]
    pub max_prompt_chars: usize,
    /// Upstream request timeout.
    #[serde(default = "default_ai_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SmtpSecurity {
    #[default]
    Starttls,
    Tls,
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebauthnConfig {
    /// Relying party id, e.g. `termoso.dev`.
    pub rp_id: String,
    /// Allowed origins, comma-separated, e.g. `https://app.termoso.dev,tauri://localhost`.
    pub origins: String,
    #[serde(default = "default_rp_name")]
    pub rp_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Opt-in: expose Prometheus metrics on `bind` (a separate listener, keep it private).
    pub enabled: bool,
    pub bind: SocketAddr,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:9090".parse().expect("valid addr"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SsoProviderConfig {
    /// Display name.
    pub name: Option<String>,
    /// `oidc` (default) or `saml`.
    #[serde(default)]
    pub kind: SsoKindConfig,
    /// OIDC issuer URL (discovery). Presets: `google`, `microsoft`, `github`
    /// slugs fill this automatically when omitted.
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    /// Extra scopes (space separated) in addition to `openid email profile`.
    pub scopes: Option<String>,
    /// SAML IdP metadata: an `https://` URL, a file path, or inline XML.
    pub saml_metadata: Option<String>,
    /// Pick this `entityID` when the metadata is an `EntitiesDescriptor`
    /// aggregate (federations). Also enforced as the response `Issuer`.
    pub saml_idp_entity_id: Option<String>,
    /// Our SP `entityID`. Defaults to the SP metadata URL
    /// (`<public_url>/api/v1/auth/sso/<slug>/saml/metadata`).
    pub saml_sp_entity_id: Option<String>,
    /// SP X.509 certificate (PEM, or a path). Published in SP metadata;
    /// enables signed `AuthnRequest`s and encrypted assertions.
    pub saml_sp_certificate: Option<String>,
    /// SP RSA private key matching the certificate (PKCS#8/PKCS#1 PEM, or a path).
    pub saml_sp_private_key: Option<String>,
    /// Sign `AuthnRequest`s. Defaults to whatever the IdP metadata asks for
    /// (`WantAuthnRequestsSigned`), and requires the SP key.
    pub saml_sign_requests: Option<bool>,
    /// Accept legacy algorithms from old IdPs: RSA-SHA1 / SHA-1 digests and
    /// PKCS#1 v1.5 (`rsa-1_5`) key transport for encrypted assertions (off by
    /// default).
    #[serde(default)]
    pub saml_allow_sha1: bool,
    /// Attribute carrying the email when the IdP does not use a standard
    /// name (`mail`, `email`, the OID / WS-Fed claim URIs) or an email `NameID`.
    pub saml_email_attribute: Option<String>,
    /// Attribute carrying the display name (same fallbacks as for email).
    pub saml_name_attribute: Option<String>,
    /// Tolerated clock difference with the IdP, seconds.
    #[serde(default = "default_saml_clock_skew")]
    pub saml_clock_skew_secs: u64,
    /// Only allow emails from these domains (comma separated).
    pub allowed_domains: Option<String>,
}

fn default_saml_clock_skew() -> u64 {
    120
}

impl Default for SsoProviderConfig {
    fn default() -> Self {
        Self {
            name: None,
            kind: SsoKindConfig::default(),
            issuer: None,
            client_id: None,
            client_secret: None,
            scopes: None,
            saml_metadata: None,
            saml_idp_entity_id: None,
            saml_sp_entity_id: None,
            saml_sp_certificate: None,
            saml_sp_private_key: None,
            saml_sign_requests: None,
            saml_allow_sha1: false,
            saml_email_attribute: None,
            saml_name_attribute: None,
            saml_clock_skew_secs: default_saml_clock_skew(),
            allowed_domains: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SsoKindConfig {
    #[default]
    Oidc,
    Saml,
}

fn default_true() -> bool {
    true
}
fn default_presign_secs() -> u64 {
    900
}
fn default_smtp_port() -> u16 {
    587
}
fn default_ai_url() -> String {
    "https://llm.chutes.ai/v1".into()
}
fn default_ai_model() -> String {
    "GLM-4.7-Flash-NVFP4-TEE".into()
}
fn default_ai_provider() -> String {
    "Chutes".into()
}
fn default_ai_daily_quota() -> u32 {
    50
}
fn default_ai_max_prompt_chars() -> usize {
    500
}
fn default_ai_timeout_secs() -> u64 {
    30
}
fn default_rp_name() -> String {
    "Termoso".into()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".parse().expect("valid addr"),
            public_url: "http://localhost:8080".into(),
            web_url: None,
            sshid_url: None,
            web_dir: None,
            landing: true,
            landing_url: None,
            docs: true,
            docs_url: None,
            server_name: "Termoso".into(),
            android_app_links: String::new(),
            database_url: "postgres://termoso:termoso@localhost:5432/termoso".into(),
            database_max_connections: 20,
            redis_url: "redis://127.0.0.1:6379".into(),
            redis_prefix: "termoso:".into(),
            master_key: String::new(),
            admin_emails: String::new(),
            owner_email: String::new(),
            cors_origins: String::new(),
            trust_proxy: false,
            log: "info,sqlx=warn,hyper=warn,aws=warn".into(),
            log_format: LogFormat::Text,
            s3: None,
            logs_dir: None,
            smtp: None,
            turnstile: None,
            webauthn: None,
            metrics: MetricsConfig::default(),
            sso: BTreeMap::new(),
            team_idp: true,
            ai: None,
            swagger_ui: true,
            bridges: true,
            start_over_delay_secs: 24 * 3600,
            audit_retention_days_max: 3650,
            audit_sink: false,
            webhooks_allow_private: false,
            webhooks_syslog_ca: None,
            data_region: None,
            min_client_version: None,
            team_deletion_grace_days: 7,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let mut figment =
            Figment::from(figment::providers::Serialized::defaults(Config::default()));
        if let Ok(path) = std::env::var("TERMOSO_CONFIG") {
            figment = figment.merge(Toml::file(path));
        }
        figment = figment.merge(Env::prefixed("TERMOSO_").split("__").lowercase(true));
        let cfg: Config = figment.extract().context("invalid configuration")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.master_key.is_empty(),
            "TERMOSO_MASTER_KEY is required (generate with `openssl rand -base64 32`)"
        );
        self.master_key()?;
        url::Url::parse(&self.public_url).context("TERMOSO_PUBLIC_URL must be a URL")?;
        if let Some(u) = self.sshid_url() {
            let parsed = url::Url::parse(u).context("TERMOSO_SSHID_URL must be a URL")?;
            anyhow::ensure!(
                parsed.host_str().is_some() && parsed.path().trim_end_matches('/').is_empty(),
                "TERMOSO_SSHID_URL must be an origin without a path (e.g. https://sshid.example.com)"
            );
        }
        if let Some(dir) = self.web_dir() {
            crate::routes::web::validate_dir(&dir)?;
        }
        if let Some(u) = self.landing_url() {
            let parsed = url::Url::parse(u).context("TERMOSO_LANDING_URL must be a URL")?;
            anyhow::ensure!(
                parsed.host_str().is_some() && parsed.path().trim_end_matches('/').is_empty(),
                "TERMOSO_LANDING_URL must be an origin without a path (e.g. https://example.com)"
            );
            anyhow::ensure!(
                self.landing,
                "TERMOSO_LANDING_URL needs TERMOSO_LANDING=true (unset one of them)"
            );
            anyhow::ensure!(
                self.web_dir().is_some(),
                "TERMOSO_LANDING_URL needs TERMOSO_WEB_DIR (the landing is part of the web cabinet)"
            );
            let landing_host = host_header(u);
            anyhow::ensure!(
                landing_host != host_header(&self.public_url)
                    && landing_host != host_header(self.web_url()),
                "TERMOSO_LANDING_URL must differ from TERMOSO_PUBLIC_URL / TERMOSO_WEB_URL (use TERMOSO_LANDING=false to hide the landing on the cabinet origin)"
            );
        }
        if let Some(u) = self.docs_url() {
            let parsed = url::Url::parse(u).context("TERMOSO_DOCS_URL must be a URL")?;
            anyhow::ensure!(
                parsed.host_str().is_some() && parsed.path().trim_end_matches('/').is_empty(),
                "TERMOSO_DOCS_URL must be an origin without a path (e.g. https://docs.example.com)"
            );
            anyhow::ensure!(
                self.docs,
                "TERMOSO_DOCS_URL needs TERMOSO_DOCS=true (unset one of them)"
            );
            anyhow::ensure!(
                self.web_dir().is_some(),
                "TERMOSO_DOCS_URL needs TERMOSO_WEB_DIR (the docs are part of the web cabinet)"
            );
            let docs_host = host_header(u);
            anyhow::ensure!(
                docs_host != host_header(&self.public_url)
                    && docs_host != host_header(self.web_url())
                    && docs_host != self.landing_host(),
                "TERMOSO_DOCS_URL must differ from TERMOSO_PUBLIC_URL / TERMOSO_WEB_URL / TERMOSO_LANDING_URL"
            );
        }
        self.android_app_links()?;
        if let Some(ai) = &self.ai {
            anyhow::ensure!(
                !ai.api_key.trim().is_empty(),
                "TERMOSO_AI__API_KEY must not be empty"
            );
            let parsed = url::Url::parse(&ai.url).context("TERMOSO_AI__URL must be a URL")?;
            anyhow::ensure!(
                matches!(parsed.scheme(), "http" | "https"),
                "TERMOSO_AI__URL must be http(s)"
            );
            anyhow::ensure!(
                !ai.model.trim().is_empty(),
                "TERMOSO_AI__MODEL must not be empty"
            );
            anyhow::ensure!(
                ai.daily_quota > 0 && ai.max_prompt_chars > 0 && ai.timeout_secs > 0,
                "TERMOSO_AI__DAILY_QUOTA, MAX_PROMPT_CHARS and TIMEOUT_SECS must be positive"
            );
        }
        Ok(())
    }

    /// Parsed `android_app_links`: `(package, fingerprint)` pairs.
    pub fn android_app_links(&self) -> Result<Vec<AndroidAppLink>> {
        split_csv(&self.android_app_links)
            .into_iter()
            .map(|entry| AndroidAppLink::parse(&entry))
            .collect()
    }

    pub fn web_dir(&self) -> Option<std::path::PathBuf> {
        self.web_dir
            .as_deref()
            .filter(|d| !d.trim().is_empty())
            .map(std::path::PathBuf::from)
    }

    pub fn master_key(&self) -> Result<SymmetricKey> {
        SymmetricKey::from_b64(self.master_key.trim())
            .map_err(|_| anyhow::anyhow!("TERMOSO_MASTER_KEY must be 32 bytes base64"))
    }

    pub fn web_url(&self) -> &str {
        self.web_url.as_deref().unwrap_or(&self.public_url)
    }

    pub fn sshid_url(&self) -> Option<&str> {
        self.sshid_url
            .as_deref()
            .map(|u| u.trim().trim_end_matches('/'))
            .filter(|u| !u.is_empty())
    }

    /// `host[:port]` of `sshid_url`, as it appears in the `Host` header.
    pub fn sshid_host(&self) -> Option<String> {
        host_header(self.sshid_url()?)
    }

    pub fn landing_url(&self) -> Option<&str> {
        self.landing_url
            .as_deref()
            .map(|u| u.trim().trim_end_matches('/'))
            .filter(|u| !u.is_empty())
    }

    /// `host[:port]` of `landing_url`, as it appears in the `Host` header.
    pub fn landing_host(&self) -> Option<String> {
        host_header(self.landing_url()?)
    }

    pub fn docs_url(&self) -> Option<&str> {
        self.docs_url
            .as_deref()
            .map(|u| u.trim().trim_end_matches('/'))
            .filter(|u| !u.is_empty())
    }

    pub fn docs_host(&self) -> Option<String> {
        host_header(self.docs_url()?)
    }

    /// Whether `/` on the cabinet origin renders the landing page.
    pub fn landing_on_cabinet(&self) -> bool {
        self.landing && self.landing_url().is_none()
    }

    pub fn admin_emails(&self) -> Vec<String> {
        split_csv(&self.admin_emails)
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect()
    }

    pub fn is_bootstrap_admin(&self, email: &str) -> bool {
        self.admin_emails()
            .iter()
            .any(|a| a == &email.to_lowercase())
    }

    pub fn cors_origins(&self) -> Vec<String> {
        split_csv(&self.cors_origins)
    }
}

/// One Android app trusted to handle this server's https links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidAppLink {
    pub package: String,
    /// Upper-case colon-separated SHA-256 of the signing certificate, as
    /// printed by `keytool -printcert` / `apksigner verify --print-certs`.
    pub sha256_fingerprint: String,
}

impl AndroidAppLink {
    fn parse(entry: &str) -> Result<Self> {
        let (package, fp) = entry.split_once('=').with_context(|| {
            format!("TERMOSO_ANDROID_APP_LINKS entry `{entry}` must be <package>=<sha256>")
        })?;
        let package = package.trim();
        anyhow::ensure!(
            !package.is_empty()
                && package
                    .split('.')
                    .all(|p| !p.is_empty()
                        && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')),
            "TERMOSO_ANDROID_APP_LINKS: `{package}` is not an Android package name"
        );
        let digest: String = fp
            .chars()
            .filter(|c| *c != ':')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        anyhow::ensure!(
            digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()),
            "TERMOSO_ANDROID_APP_LINKS: fingerprint for `{package}` must be a SHA-256 (64 hex digits)"
        );
        let sha256_fingerprint = digest
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).expect("ascii hex"))
            .collect::<Vec<_>>()
            .join(":");
        Ok(Self {
            package: package.to_owned(),
            sha256_fingerprint,
        })
    }
}

/// `host[:port]` of an origin URL, lowercase, as browsers send it in `Host`.
fn host_header(origin: &str) -> Option<String> {
    let u = url::Url::parse(origin).ok()?;
    let host = u.host_str()?.to_ascii_lowercase();
    Some(match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    })
}

pub fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        Config {
            master_key: SymmetricKey::generate().to_b64(),
            ..Config::default()
        }
    }

    #[test]
    fn android_app_links_parse_and_normalise() {
        let cfg = Config {
            android_app_links: format!(
                " com.termoso.android={} , com.termoso.android.debug={}",
                "ab:cd:".repeat(16).trim_end_matches(':'),
                "0123456789abcdef".repeat(4)
            ),
            ..Config::default()
        };
        let apps = cfg.android_app_links().unwrap();
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].package, "com.termoso.android");
        assert_eq!(
            apps[0].sha256_fingerprint,
            "AB:CD:".repeat(16).trim_end_matches(':')
        );
        assert_eq!(apps[1].package, "com.termoso.android.debug");
        assert!(
            apps[1]
                .sha256_fingerprint
                .starts_with("01:23:45:67:89:AB:CD:EF:")
        );
        assert_eq!(apps[1].sha256_fingerprint.len(), 32 * 3 - 1);
        assert!(Config::default().android_app_links().unwrap().is_empty());

        for bad in [
            "com.termoso.android",
            "com.termoso.android=abcd",
            "com termoso=",
            &format!("com.termoso.android={}", "zz".repeat(32)),
        ] {
            let cfg = Config {
                android_app_links: bad.to_owned(),
                ..Config::default()
            };
            assert!(cfg.android_app_links().is_err(), "{bad}");
        }
    }

    #[test]
    fn sshid_url_optional_and_normalized() {
        let cfg = base();
        cfg.validate().unwrap();
        assert_eq!(cfg.sshid_url(), None);
        assert_eq!(cfg.sshid_host(), None);

        let cfg = Config {
            sshid_url: Some(" https://SSHID.Example.com/ ".into()),
            ..base()
        };
        cfg.validate().unwrap();
        assert_eq!(cfg.sshid_url(), Some("https://SSHID.Example.com"));
        assert_eq!(cfg.sshid_host().as_deref(), Some("sshid.example.com"));

        let cfg = Config {
            sshid_url: Some("http://localhost:8080".into()),
            ..base()
        };
        assert_eq!(cfg.sshid_host().as_deref(), Some("localhost:8080"));

        let cfg = Config {
            sshid_url: Some("".into()),
            ..base()
        };
        cfg.validate().unwrap();
        assert_eq!(cfg.sshid_url(), None);
    }

    #[test]
    fn sshid_url_rejects_paths_and_garbage() {
        for bad in [
            "sshid.example.com",
            "https://sshid.example.com/sshid",
            "not a url",
        ] {
            let cfg = Config {
                sshid_url: Some(bad.into()),
                ..base()
            };
            assert!(cfg.validate().is_err(), "{bad}");
        }
    }

    fn web_dir_for_tests() -> String {
        let dir = std::env::temp_dir().join(format!("termoso-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), "<!doctype html>").unwrap();
        dir.to_string_lossy().into_owned()
    }

    #[test]
    fn landing_defaults_to_cabinet_root() {
        let cfg = base();
        cfg.validate().unwrap();
        assert!(cfg.landing_on_cabinet());
        assert_eq!(cfg.landing_host(), None);

        let cfg = Config {
            landing: false,
            ..base()
        };
        cfg.validate().unwrap();
        assert!(!cfg.landing_on_cabinet());
    }

    #[test]
    fn landing_url_moves_the_landing_to_its_own_origin() {
        let cfg = Config {
            public_url: "https://app.example.com".into(),
            landing_url: Some(" https://Example.com/ ".into()),
            web_dir: Some(web_dir_for_tests()),
            ..base()
        };
        cfg.validate().unwrap();
        assert_eq!(cfg.landing_url(), Some("https://Example.com"));
        assert_eq!(cfg.landing_host().as_deref(), Some("example.com"));
        assert!(!cfg.landing_on_cabinet());

        let cfg = Config {
            landing_url: Some("".into()),
            ..base()
        };
        cfg.validate().unwrap();
        assert_eq!(cfg.landing_url(), None);
        assert!(cfg.landing_on_cabinet());
    }

    #[test]
    fn landing_url_rejects_inconsistent_setups() {
        let web_dir = web_dir_for_tests();
        for (name, cfg) in [
            (
                "path",
                Config {
                    public_url: "https://app.example.com".into(),
                    landing_url: Some("https://example.com/landing".into()),
                    web_dir: Some(web_dir.clone()),
                    ..base()
                },
            ),
            (
                "landing disabled",
                Config {
                    public_url: "https://app.example.com".into(),
                    landing_url: Some("https://example.com".into()),
                    landing: false,
                    web_dir: Some(web_dir.clone()),
                    ..base()
                },
            ),
            (
                "no web dir",
                Config {
                    public_url: "https://app.example.com".into(),
                    landing_url: Some("https://example.com".into()),
                    ..base()
                },
            ),
            (
                "same as public url",
                Config {
                    public_url: "https://example.com".into(),
                    landing_url: Some("https://EXAMPLE.com/".into()),
                    web_dir: Some(web_dir.clone()),
                    ..base()
                },
            ),
            (
                "same as web url",
                Config {
                    public_url: "https://api.example.com".into(),
                    web_url: Some("https://example.com".into()),
                    landing_url: Some("https://example.com".into()),
                    web_dir: Some(web_dir.clone()),
                    ..base()
                },
            ),
        ] {
            assert!(cfg.validate().is_err(), "{name}");
        }
    }
}
