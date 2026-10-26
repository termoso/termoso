//! Shared harness: boots the real server (migrations, Redis, WS fan-out) on an
//! ephemeral port against the services from `deploy/docker-compose.dev.yml`.
//!
//! Every test process gets its own freshly-created database so runs never
//! interfere. Skipped (returns `None`) when `TERMOSO_TEST_DATABASE_URL` is unset
//! and the default local Postgres is unreachable.
//!
//! Optional services are picked up when reachable (or when their
//! `TERMOSO_TEST_*` variable is set): RustFS (S3) for session logs and Mailpit for
//! outgoing email. `TERMOSO_TEST_REQUIRE_SERVICES=1` (CI) turns a missing
//! service into a failure instead of a skip. SSO is always exercised against
//! an in-process mock OpenID Connect provider.

#![allow(dead_code)]

pub mod llm;
pub mod oidc;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use reqwest::{Client, Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sqlx::Connection;
use sqlx::postgres::PgConnection;
use termoso_crypto::aead::{self, Aad};
use termoso_crypto::kdf::{Label, derive_key};
use termoso_crypto::keys::{KeyPair, SymmetricKey};
use termoso_crypto::opaque;
use termoso_crypto::recovery::RecoveryKey;
use termoso_crypto::sealed;
use termoso_proto::account::CodeRequest;
use termoso_proto::auth::{
    AccountKeysUpload, AuthResponse, DeviceApproveRequest, DeviceInfo, LoginFinishRequest,
    LoginStartRequest, LoginStartResponse, Platform, RegisterFinishRequest, RegisterStartRequest,
    RegisterStartResponse, Session,
};
use termoso_server::Inner;
use termoso_server::config::{
    AiConfig, Config, S3Config, SmtpConfig, SmtpSecurity, SsoKindConfig, SsoProviderConfig,
    WebauthnConfig,
};
use termoso_server::saml::test_support as saml_support;
use uuid::Uuid;

const DEFAULT_PG: &str = "postgres://termoso:termoso@localhost:5432/termoso";
const DEFAULT_REDIS: &str = "redis://127.0.0.1:6379";
const DEFAULT_S3: &str = "http://127.0.0.1:9000";
const DEFAULT_MAILPIT_SMTP: &str = "127.0.0.1:1025";
const DEFAULT_MAILPIT_API: &str = "http://127.0.0.1:8025";

/// Lower-case, colon-less on purpose: the server normalises it.
pub const ANDROID_DEBUG_FINGERPRINT: &str =
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
pub const WEBAUTHN_RP_ID: &str = "localhost";
pub const WEBAUTHN_ORIGIN: &str = "http://localhost";
pub const SSO_PROVIDER: &str = "mock";
/// Same IdP, but only `@corp.test` addresses may sign in through it.
pub const SSO_CORP_PROVIDER: &str = "mock-corp";
pub const SSO_CORP_DOMAIN: &str = "corp.test";
/// SAML providers (see `server()` for how they differ).
pub const SAML_PROVIDER: &str = "mock-saml";
pub const SAML_CORP_PROVIDER: &str = "mock-saml-corp";
pub const SAML_IDP_ENTITY: &str = "https://idp.test/saml";
pub const SAML_IDP_SSO_URL: &str = "https://idp.test/saml/sso";
/// Dedicated SSH ID origin (`TERMOSO_SSHID_URL`) and its `Host` value.
pub const SSHID_URL: &str = "http://sshid.test:8443";
pub const SSHID_HOST: &str = "sshid.test:8443";
/// Dedicated landing origin (`TERMOSO_LANDING_URL`) and its `Host` value; the
/// cabinet itself stays on `public_url`, so `/` there goes to `/login`.
pub const LANDING_URL: &str = "http://landing.test";
pub const LANDING_HOST: &str = "landing.test";

pub struct TestServer {
    pub addr: SocketAddr,
    pub db_name: String,
    pub database_url: String,
    pub master_key: String,
    /// Object storage (S3) is configured.
    pub storage: bool,
    /// Mailpit REST API base URL when email is configured.
    pub mailpit: Option<String>,
    pub idp: oidc::MockIdp,
    pub llm: llm::MockLlm,
    /// The running server's state, for driving background jobs directly.
    pub state: termoso_server::state::AppState,
}

static SERVER: tokio::sync::OnceCell<Option<TestServer>> = tokio::sync::OnceCell::const_new();

fn base_pg_url() -> String {
    std::env::var("TERMOSO_TEST_DATABASE_URL").unwrap_or_else(|_| DEFAULT_PG.into())
}

fn redis_url() -> String {
    std::env::var("TERMOSO_TEST_REDIS_URL").unwrap_or_else(|_| DEFAULT_REDIS.into())
}

fn with_db(url: &str, db: &str) -> String {
    let mut u = url::Url::parse(url).expect("valid postgres url");
    u.set_path(&format!("/{db}"));
    u.to_string()
}

/// Bind an ephemeral port. The std listener is handed to the server thread
/// and converted there, so the port can never be taken by anyone else in
/// between.
fn bind_ephemeral() -> std::net::TcpListener {
    std::net::TcpListener::bind("127.0.0.1:0").expect("bind")
}

fn require_services() -> bool {
    std::env::var("TERMOSO_TEST_REQUIRE_SERVICES").is_ok()
}

async fn tcp_reachable(host_port: &str) -> bool {
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(host_port),
    )
    .await
    .is_ok_and(|r| r.is_ok())
}

fn host_port(url: &str) -> String {
    let u = url::Url::parse(url).expect("valid url");
    format!(
        "{}:{}",
        u.host_str().expect("host"),
        u.port_or_known_default().expect("port")
    )
}

/// Optional service: configured when reachable, mandatory under
/// `TERMOSO_TEST_REQUIRE_SERVICES`.
async fn optional(name: &str, probe: &str) -> bool {
    if tcp_reachable(probe).await {
        return true;
    }
    if require_services() {
        panic!("{name} unavailable at {probe}");
    }
    eprintln!("{name} unavailable at {probe}: skipping tests that need it");
    false
}

async fn s3_config() -> Option<S3Config> {
    let endpoint = std::env::var("TERMOSO_TEST_S3_ENDPOINT").unwrap_or_else(|_| DEFAULT_S3.into());
    if !optional("S3 storage", &host_port(&endpoint)).await {
        return None;
    }
    Some(S3Config {
        bucket: format!("termoso-test-{}", Uuid::new_v4().simple()),
        region: None,
        endpoint: Some(endpoint.clone()),
        public_endpoint: None,
        access_key: std::env::var("TERMOSO_TEST_S3_ACCESS_KEY")
            .unwrap_or_else(|_| "minioadmin".into()),
        secret_key: std::env::var("TERMOSO_TEST_S3_SECRET_KEY")
            .unwrap_or_else(|_| "minioadmin".into()),
        force_path_style: true,
        presign_secs: 300,
    })
}

pub async fn smtp_config() -> Option<(SmtpConfig, String)> {
    let smtp =
        std::env::var("TERMOSO_TEST_SMTP_ADDR").unwrap_or_else(|_| DEFAULT_MAILPIT_SMTP.into());
    let api =
        std::env::var("TERMOSO_TEST_MAILPIT_URL").unwrap_or_else(|_| DEFAULT_MAILPIT_API.into());
    if !optional("Mailpit", &smtp).await {
        return None;
    }
    let (host, port) = smtp.rsplit_once(':').expect("host:port");
    Some((
        SmtpConfig {
            host: host.to_string(),
            port: port.parse().expect("smtp port"),
            username: None,
            password: None,
            security: SmtpSecurity::None,
            from: "Termoso Test <no-reply@test.local>".into(),
        },
        api,
    ))
}

/// Boot (once per test binary) and return the shared server, or `None` when
/// the backing services are not available.
pub async fn server() -> Option<&'static TestServer> {
    SERVER.get_or_init(boot).await.as_ref()
}

async fn boot() -> Option<TestServer> {
    let base = base_pg_url();
    let mut admin = match PgConnection::connect(&base).await {
        Ok(c) => c,
        Err(e) => {
            if std::env::var("TERMOSO_TEST_REQUIRE_SERVICES").is_ok() {
                panic!("PostgreSQL unavailable at {base}: {e}");
            }
            eprintln!("skipping integration tests: PostgreSQL unavailable ({e})");
            return None;
        }
    };
    // Databases from earlier runs are dropped lazily here (the harness has no
    // reliable shutdown hook). Anything still in use is simply skipped.
    let stale: Vec<(String,)> =
        sqlx::query_as("SELECT datname FROM pg_database WHERE datname LIKE 'termoso_test_%'")
            .fetch_all(&mut admin)
            .await
            .expect("list test databases");
    for (name,) in stale {
        let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS \"{name}\""
        )))
        .execute(&mut admin)
        .await;
    }

    let db_name = format!("termoso_test_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE \"{db_name}\""
    )))
    .execute(&mut admin)
    .await
    .expect("create test database");
    let database_url = with_db(&base, &db_name);

    let master_key = SymmetricKey::generate().to_b64();
    let listener = bind_ephemeral();
    let addr = listener.local_addr().expect("addr");
    let idp_listener = bind_ephemeral();
    let idp_addr = idp_listener.local_addr().expect("addr");
    let llm_listener = bind_ephemeral();
    let llm_addr = llm_listener.local_addr().expect("addr");

    let s3 = s3_config().await;
    let smtp = smtp_config().await;
    let storage = s3.is_some();
    let mailpit = smtp.as_ref().map(|(_, api)| api.clone());

    let mut sso = std::collections::BTreeMap::new();
    sso.insert(
        SSO_PROVIDER.to_string(),
        SsoProviderConfig {
            name: Some("Mock IdP".into()),
            kind: SsoKindConfig::Oidc,
            issuer: Some(format!("http://{idp_addr}")),
            client_id: Some(oidc::CLIENT_ID.into()),
            client_secret: Some(oidc::CLIENT_SECRET.into()),
            scopes: None,
            ..SsoProviderConfig::default()
        },
    );
    sso.insert(
        SSO_CORP_PROVIDER.to_string(),
        SsoProviderConfig {
            name: Some("Corp IdP".into()),
            kind: SsoKindConfig::Oidc,
            issuer: Some(format!("http://{idp_addr}")),
            client_id: Some(oidc::CLIENT_ID.into()),
            client_secret: Some(oidc::CLIENT_SECRET.into()),
            scopes: Some("groups".into()),
            allowed_domains: Some(format!("{SSO_CORP_DOMAIN}, Other.Example")),
            ..SsoProviderConfig::default()
        },
    );
    // SAML: HTTP-Redirect binding, unsigned requests, no SP key.
    sso.insert(
        SAML_PROVIDER.to_string(),
        SsoProviderConfig {
            name: Some("Mock SAML".into()),
            kind: SsoKindConfig::Saml,
            saml_metadata: Some(saml_support::idp_metadata_xml(
                SAML_IDP_ENTITY,
                SAML_IDP_SSO_URL,
            )),
            ..SsoProviderConfig::default()
        },
    );
    // SAML: HTTP-POST binding, IdP wants signed requests, SP has a key
    // (so encrypted assertions work), corporate domain allow-list.
    sso.insert(
        SAML_CORP_PROVIDER.to_string(),
        SsoProviderConfig {
            name: Some("Corp SAML".into()),
            kind: SsoKindConfig::Saml,
            saml_metadata: Some(saml_support::idp_metadata_xml_with(
                SAML_IDP_ENTITY,
                SAML_IDP_SSO_URL,
                termoso_server::saml::metadata::BINDING_POST,
                true,
            )),
            saml_sp_certificate: Some(saml_support::SP_CERT_PEM.into()),
            saml_sp_private_key: Some(saml_support::SP_KEY_PEM.into()),
            saml_email_attribute: Some("corpMail".into()),
            allowed_domains: Some(SSO_CORP_DOMAIN.into()),
            ..SsoProviderConfig::default()
        },
    );

    let cfg = Config {
        bind: addr,
        public_url: format!("http://{addr}"),
        sshid_url: Some(format!("{SSHID_URL}/")),
        landing_url: Some(format!("{LANDING_URL}/")),
        web_dir: Some(fake_web_dir(&db_name)),
        database_url: database_url.clone(),
        redis_url: redis_url(),
        redis_prefix: format!("{db_name}:"),
        trust_proxy: true,
        master_key: master_key.clone(),
        admin_emails: "admin@test.local".into(),
        owner_email: "admin@test.local".into(),
        android_app_links: format!("com.termoso.android.debug={}", ANDROID_DEBUG_FINGERPRINT),
        swagger_ui: true,
        s3,
        smtp: smtp.map(|(cfg, _)| cfg),
        webhooks_allow_private: true,
        webhooks_syslog_ca: Some(syslog_ca_path()),
        webauthn: Some(WebauthnConfig {
            rp_id: WEBAUTHN_RP_ID.into(),
            origins: WEBAUTHN_ORIGIN.into(),
            rp_name: "Termoso Test".into(),
        }),
        sso,
        ai: Some(AiConfig {
            url: format!("http://{llm_addr}/v1"),
            api_key: llm::API_KEY.into(),
            model: llm::MODEL.into(),
            provider: llm::PROVIDER.into(),
            confidential: true,
            daily_quota: llm::DAILY_QUOTA,
            max_prompt_chars: llm::MAX_PROMPT_CHARS,
            timeout_secs: 5,
        }),
        ..Config::default()
    };
    cfg.validate().expect("valid test config");

    // Each `#[tokio::test]` owns a runtime that is torn down when the test
    // ends, so the shared server (and the mock IdP) must live on their own
    // runtime/thread.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<
        anyhow::Result<(oidc::MockIdp, llm::MockLlm, termoso_server::state::AppState)>,
    >();
    std::thread::Builder::new()
        .name("termoso-test-server".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let idp = match oidc::serve(idp_listener).await {
                    Ok(i) => i,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let llm = match llm::serve(llm_listener).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let state = match Inner::build(cfg).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let listener = match listener
                    .set_nonblocking(true)
                    .and_then(|()| tokio::net::TcpListener::from_std(listener))
                {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.into()));
                        return;
                    }
                };
                tokio::spawn(termoso_server::ws::run_fanout(state.clone()));
                tokio::spawn(termoso_server::live::run_fanout(state.clone()));
                let app = termoso_server::app(state.clone());
                let _ = ready_tx.send(Ok((idp, llm, state)));
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .expect("serve");
            });
        })
        .expect("spawn server thread");
    let (idp, llm, state) = ready_rx
        .recv()
        .expect("server thread died")
        .expect("server state");

    Some(TestServer {
        addr,
        db_name,
        database_url,
        master_key,
        storage,
        mailpit,
        idp,
        llm,
        state,
    })
}

/// A stand-in for `web/dist`: index.html plus one hashed asset.
fn fake_web_dir(unique: &str) -> String {
    let dir = std::env::temp_dir().join(format!("{unique}_web"));
    std::fs::create_dir_all(dir.join("assets")).expect("web dir");
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>Termoso</title><div id=root></div>",
    )
    .expect("index.html");
    std::fs::write(dir.join("assets/app-abc123.js"), "export {};").expect("asset");
    std::fs::write(dir.join("favicon.svg"), "<svg/>").expect("favicon");
    dir.to_string_lossy().into_owned()
}

fn fake_ip() -> String {
    static N: AtomicU32 = AtomicU32::new(1);
    let n = N.fetch_add(1, Ordering::Relaxed);
    format!("10.{}.{}.{}", (n >> 16) & 255, (n >> 8) & 255, n & 255)
}

impl TestServer {
    /// A fresh client per call: reqwest's pool lives on the runtime that
    /// created it, and every `#[tokio::test]` has its own short-lived runtime.
    pub fn http(&self) -> Client {
        Client::builder()
            .pool_max_idle_per_host(0)
            .build()
            .expect("client")
    }

    /// Like [`Self::http`], but returns redirects instead of following them.
    pub fn http_no_redirect(&self) -> Client {
        Client::builder()
            .pool_max_idle_per_host(0)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client")
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}/api/v1{}", self.addr, path)
    }

    pub fn ws_url(&self) -> String {
        format!("ws://{}/api/v1/ws", self.addr)
    }

    pub async fn call<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&T>,
    ) -> reqwest::Response {
        // Each call comes from a unique "client" so per-IP rate limits never
        // trip while the suite hammers the auth endpoints in parallel.
        let mut req = self
            .http()
            .request(method, self.url(path))
            .header("x-forwarded-for", fake_ip());
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        req.send().await.expect("request")
    }

    pub async fn json<T: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&T>,
    ) -> R {
        let resp = self.call(method.clone(), path, token, body).await;
        let status = resp.status();
        let text = resp.text().await.expect("body");
        assert!(status.is_success(), "{method} {path} -> {status}: {text}");
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{method} {path}: {e}: {text}"))
    }

    pub async fn expect_status<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&T>,
        expected: StatusCode,
    ) -> serde_json::Value {
        let resp = self.call(method.clone(), path, token, body).await;
        let status = resp.status();
        let text = resp.text().await.expect("body");
        assert_eq!(status, expected, "{method} {path}: {text}");
        serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
    }
}

pub const NOBODY: Option<&()> = None;

impl TestServer {
    /// Newest code emailed to `to`, read back from Mailpit. Codes are in the
    /// subject (`<server>: <purpose> — code 123456`), so no body parsing.
    pub async fn emailed_code(&self, to: &str, purpose: &str) -> String {
        let api = self.mailpit.as_ref().expect("mailpit configured");
        let client = self.http();
        for _ in 0..50 {
            let v: serde_json::Value = client
                .get(format!("{api}/api/v1/search"))
                .query(&[("query", format!("to:{to}")), ("limit", "50".into())])
                .send()
                .await
                .expect("mailpit search")
                .json()
                .await
                .expect("mailpit json");
            let found = v["messages"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|m| m["Subject"].as_str())
                .find(|s| s.contains(purpose))
                .and_then(|s| s.rsplit_once("code ").map(|(_, c)| c.trim().to_string()));
            if let Some(code) = found {
                return code;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("no `{purpose}` email for {to} arrived");
    }

    /// Newest email to `to` whose subject contains `subject`; returns the
    /// plain-text body. Waits a little for delivery.
    pub async fn emailed_body(&self, to: &str, subject: &str) -> String {
        let api = self.mailpit.as_ref().expect("mailpit configured");
        let client = self.http();
        for _ in 0..50 {
            let v: serde_json::Value = client
                .get(format!("{api}/api/v1/search"))
                .query(&[("query", format!("to:{to}")), ("limit", "50".into())])
                .send()
                .await
                .expect("mailpit search")
                .json()
                .await
                .expect("mailpit json");
            let id = v["messages"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|m| m["Subject"].as_str().is_some_and(|s| s.contains(subject)))
                .and_then(|m| m["ID"].as_str().map(str::to_string));
            if let Some(id) = id {
                let m: serde_json::Value = client
                    .get(format!("{api}/api/v1/message/{id}"))
                    .send()
                    .await
                    .expect("mailpit message")
                    .json()
                    .await
                    .expect("mailpit json");
                return m["Text"].as_str().unwrap_or_default().to_string();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("no `{subject}` email for {to} arrived");
    }

    /// Number of messages Mailpit holds for `to`.
    pub async fn email_count(&self, to: &str) -> u64 {
        let api = self.mailpit.as_ref().expect("mailpit configured");
        let v: serde_json::Value = self
            .http()
            .get(format!("{api}/api/v1/search"))
            .query(&[("query", format!("to:{to}"))])
            .send()
            .await
            .expect("mailpit search")
            .json()
            .await
            .expect("mailpit json");
        v["messages_count"].as_u64().unwrap_or(0)
    }
}

/// A registered user with its client-side key material.
pub struct User {
    pub email: String,
    pub password: String,
    pub session: Session,
    pub keypair: KeyPair,
    pub personal_vault_key: SymmetricKey,
    pub recovery: RecoveryKey,
}

impl User {
    pub fn token(&self) -> &str {
        &self.session.token
    }

    pub fn id(&self) -> Uuid {
        self.session.user.id
    }

    /// Encrypt an entity payload the way a real client would.
    pub fn encrypt_entity(&self, key: &SymmetricKey, kind: &str, id: Uuid, json: &str) -> String {
        aead::encrypt_str(key, &Aad::entity(kind, &id.to_string()), json).expect("encrypt")
    }
}

impl TestServer {
    /// Run one statement against the test database (time travel for tests
    /// that would otherwise wait minutes or hours).
    /// One pass of the automations scheduler (due slots → pending runs,
    /// stale pending → missed).
    pub async fn tick_automations(&self) {
        termoso_server::routes::automations::tick(&self.state)
            .await
            .expect("automations tick");
    }

    pub async fn sql(&self, statement: &str, bind: &str) {
        let mut conn = PgConnection::connect(&self.database_url)
            .await
            .expect("connect test db");
        sqlx::query(sqlx::AssertSqlSafe(statement.to_string()))
            .bind(bind)
            .execute(&mut conn)
            .await
            .expect("test sql");
    }

    /// Pretend `token`'s last step-up happened long ago: rewinds `reauth_at`
    /// and evicts the cached session so the next request sees it.
    pub async fn age_step_up(&self, token: &str) {
        let hash = termoso_server::util::hash_token(token);
        self.sql(
            "UPDATE sessions SET reauth_at = now() - interval '1 hour' WHERE token_hash = $1",
            &hash,
        )
        .await;
        self.forget(&format!("sess:{hash}")).await;
    }

    /// Make the session look idle so the next request records a fresh
    /// `last_used_at` (touches are throttled to once per few minutes).
    pub async fn age_last_used(&self, token: &str) {
        let hash = termoso_server::util::hash_token(token);
        self.sql(
            "UPDATE sessions SET last_used_at = now() - interval '10 minutes' WHERE token_hash = $1",
            &hash,
        )
        .await;
        self.forget(&format!("sess:{hash}")).await;
    }

    /// Lift the per-address email rate limit so a long scenario can keep
    /// receiving mail.
    pub async fn reset_email_limit(&self, email: &str) {
        self.forget(&format!("rl:email:{}", email.to_lowercase()))
            .await;
    }

    /// Backdate one device's presence record so the server treats it as gone.
    pub async fn age_presence(&self, team_id: Uuid, user_id: Uuid, device_id: Uuid) {
        let client = redis::Client::open(redis_url()).expect("redis");
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .expect("redis connection");
        let key = format!("{}:presence:{team_id}", self.db_name);
        let field = format!("{user_id}:{device_id}");
        let raw: Vec<u8> = redis::cmd("HGET")
            .arg(&key)
            .arg(&field)
            .query_async(&mut conn)
            .await
            .expect("presence record");
        let mut v: serde_json::Value = serde_json::from_slice(&raw).expect("presence json");
        v["seen_at"] = serde_json::json!(chrono::Utc::now() - chrono::Duration::minutes(10));
        let _: () = redis::cmd("HSET")
            .arg(&key)
            .arg(&field)
            .arg(serde_json::to_vec(&v).unwrap())
            .query_async(&mut conn)
            .await
            .expect("age presence record");
    }

    async fn forget(&self, key: &str) {
        let client = redis::Client::open(redis_url()).expect("redis");
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .expect("redis connection");
        let _: () = redis::cmd("DEL")
            .arg(format!("{}:{key}", self.db_name))
            .query_async(&mut conn)
            .await
            .expect("forget cache key");
    }

    /// Move a pending "start over" reset into the past so it can be finished.
    pub async fn age_start_over(&self, email: &str) {
        self.sql(
            "UPDATE users SET reset_scheduled_for = now() - interval '1 minute' WHERE email = $1",
            &email.to_lowercase(),
        )
        .await;
    }
}

pub fn device(name: &str) -> DeviceInfo {
    DeviceInfo {
        name: name.into(),
        platform: Platform::Linux,
        app_version: "test".into(),
        client_device_id: Some(Uuid::new_v4()),
        posture: None,
    }
}

pub fn unique_email(prefix: &str) -> String {
    format!("{prefix}-{}@test.local", Uuid::new_v4().simple())
}

/// Full OPAQUE registration with a freshly generated key hierarchy. When email
/// is configured the address is verified right away (code read from Mailpit),
/// so the account behaves like a fully set-up one.
pub async fn register(server: &TestServer, email: &str, password: &str) -> User {
    register_with(server, email, password, None).await
}

pub async fn register_with(
    server: &TestServer,
    email: &str,
    password: &str,
    invite_token: Option<String>,
) -> User {
    let mut user = register_unverified(server, email, password, invite_token).await;
    if server.mailpit.is_some() && !user.session.user.email_verified {
        verify_email(server, &mut user).await;
    }
    user
}

/// Confirm the address with the verification code that registration emailed.
pub async fn verify_email(server: &TestServer, user: &mut User) {
    let code = server.emailed_code(&user.email, "email verification").await;
    server
        .expect_status(
            Method::POST,
            "/account/email/verify/confirm",
            Some(user.token()),
            Some(&CodeRequest { code }),
            StatusCode::NO_CONTENT,
        )
        .await;
    user.session.user.email_verified = true;
}

/// Registration only; the email stays unverified when a mailer is configured.
pub async fn register_unverified(
    server: &TestServer,
    email: &str,
    password: &str,
    invite_token: Option<String>,
) -> User {
    register_raw(server, email, password, invite_token, None).await
}

/// Registration with every optional proof a client can present.
pub async fn register_raw(
    server: &TestServer,
    email: &str,
    password: &str,
    invite_token: Option<String>,
    sso_session: Option<String>,
) -> User {
    try_register(server, email, password, invite_token, sso_session)
        .await
        .unwrap_or_else(|(status, body)| panic!("register {email} -> {status}: {body}"))
}

/// Like [`register_raw`], but a rejected `/auth/register/finish` is returned
/// as its status and error body instead of panicking.
pub async fn try_register(
    server: &TestServer,
    email: &str,
    password: &str,
    invite_token: Option<String>,
    sso_session: Option<String>,
) -> Result<User, (StatusCode, serde_json::Value)> {
    let (request, state) = opaque::client_registration_start(password.as_bytes()).expect("start");
    let start: RegisterStartResponse = server
        .json(
            Method::POST,
            "/auth/register/start",
            None,
            Some(&RegisterStartRequest {
                email: email.into(),
                opaque_request: request,
                turnstile_token: None,
            }),
        )
        .await;
    let out = opaque::client_registration_finish(
        state,
        password.as_bytes(),
        &email.to_lowercase(),
        &start.opaque_response,
    )
    .expect("finish");

    let fresh = FreshKeys::generate();
    let keys = fresh.upload_for(&out.export_key);
    let FreshKeys {
        keypair,
        recovery,
        personal_vault_key,
    } = fresh;

    let resp = server
        .call(
            Method::POST,
            "/auth/register/finish",
            None,
            Some(&RegisterFinishRequest {
                email: email.into(),
                opaque_upload: out.upload_b64,
                display_name: Some("Test User".into()),
                device: device("registration device"),
                keys,
                invite_token,
                sso_session,
            }),
        )
        .await;
    let status = resp.status();
    let text = resp.text().await.expect("body");
    if !status.is_success() {
        return Err((
            status,
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
        ));
    }
    let resp: AuthResponse = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("POST /auth/register/finish: {e}: {text}"));
    let AuthResponse::Authenticated(session) = resp else {
        panic!("expected direct session after registration, got {resp:?}");
    };
    Ok(User {
        email: email.into(),
        password: password.into(),
        session,
        keypair,
        personal_vault_key,
        recovery,
    })
}

/// A brand-new client-side key hierarchy, as generated at registration or
/// when starting an account over.
pub struct FreshKeys {
    pub keypair: KeyPair,
    pub recovery: RecoveryKey,
    pub personal_vault_key: SymmetricKey,
}

impl FreshKeys {
    pub fn generate() -> Self {
        Self {
            keypair: KeyPair::generate(),
            recovery: RecoveryKey::generate(),
            personal_vault_key: SymmetricKey::generate(),
        }
    }

    /// Wrap everything for the server, deriving the account KEK from the
    /// OPAQUE export key of the password being registered.
    pub fn upload_for(&self, export_key: &[u8]) -> AccountKeysUpload {
        let kek = derive_key(export_key, Label::AccountKek).expect("kek");
        let secret = SymmetricKey::from_bytes(self.keypair.secret_bytes());
        AccountKeysUpload {
            public_key: self.keypair.public_b64(),
            wrapped_private_key: aead::wrap_key(&kek, &Aad::account_private_key(), &secret)
                .expect("wrap"),
            recovery_wrapped_private_key: aead::wrap_key(
                &self.recovery.kek().expect("recovery kek"),
                &Aad::recovery_private_key(),
                &secret,
            )
            .expect("wrap"),
            recovery_verifier: self.recovery.verifier_b64().expect("verifier"),
            personal_vault_sealed_key: sealed::seal_vault_key(
                self.keypair.public(),
                &self.personal_vault_key,
            )
            .expect("seal"),
        }
    }
}

/// OPAQUE login from a new device. Returns the raw auth response so tests can
/// assert on MFA / approval branches too.
pub async fn login(server: &TestServer, email: &str, password: &str) -> AuthResponse {
    try_login(server, email, password)
        .await
        .expect("login should succeed")
}

/// Like [`login`] but reports a wrong password as `Err` instead of panicking.
pub async fn try_login(
    server: &TestServer,
    email: &str,
    password: &str,
) -> Result<AuthResponse, String> {
    let resp = login_raw(server, email, password, device("second device"), None).await?;
    Ok(approve_device(server, email, resp).await)
}

/// OPAQUE login as `device`, returning the server's answer verbatim (no
/// automatic device approval).
pub async fn login_raw(
    server: &TestServer,
    email: &str,
    password: &str,
    device: DeviceInfo,
    sso_session: Option<String>,
) -> Result<AuthResponse, String> {
    let (request, state) = opaque::client_login_start(password.as_bytes()).expect("start");
    let resp = server
        .call(
            Method::POST,
            "/auth/login/start",
            None,
            Some(&LoginStartRequest {
                email: email.into(),
                opaque_request: request,
                device,
                sso_session,
                turnstile_token: None,
            }),
        )
        .await;
    let status = resp.status();
    let text = resp.text().await.expect("body");
    assert!(status.is_success(), "login/start -> {status}: {text}");
    let start: LoginStartResponse = serde_json::from_str(&text).expect("json");
    let finish = opaque::client_login_finish(
        state,
        password.as_bytes(),
        &email.to_lowercase(),
        &start.opaque_response,
    );
    let Ok(finish) = finish else {
        // Wrong password: only the client can tell at this point. Still hit
        // finish with garbage so the server-side rejection path is exercised.
        let v: serde_json::Value = server
            .expect_status(
                Method::POST,
                "/auth/login/finish",
                None,
                Some(&LoginFinishRequest {
                    login_id: start.login_id,
                    opaque_finalization: "AAAA".into(),
                }),
                StatusCode::UNAUTHORIZED,
            )
            .await;
        return Err(format!("invalid credentials (server said {v})"));
    };
    let resp = server
        .call(
            Method::POST,
            "/auth/login/finish",
            None,
            Some(&LoginFinishRequest {
                login_id: start.login_id,
                opaque_finalization: finish.finalization_b64,
            }),
        )
        .await;
    let status = resp.status();
    let text = resp.text().await.expect("body");
    if !status.is_success() {
        return Err(format!("login/finish -> {status}: {text}"));
    }
    Ok(serde_json::from_str(&text).expect("json"))
}

/// Resolve the new-device approval step (code emailed to the account) if the
/// server asked for it; other responses pass through untouched.
pub async fn approve_device(server: &TestServer, email: &str, resp: AuthResponse) -> AuthResponse {
    let AuthResponse::DeviceApprovalRequired { approval_token, .. } = resp else {
        return resp;
    };
    let code = server.emailed_code(email, "new device sign-in").await;
    server
        .json(
            Method::POST,
            "/auth/device/approve",
            None,
            Some(&DeviceApproveRequest {
                approval_token,
                code,
            }),
        )
        .await
}

static ADMIN: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();

/// Token of the bootstrap admin (`admin_emails` in the test config). The
/// account is registered on first use and shared by the whole test binary.
pub async fn admin_token(server: &TestServer) -> String {
    ADMIN
        .get_or_init(|| async {
            register(server, "admin@test.local", "pw-admin-1234567")
                .await
                .token()
                .to_string()
        })
        .await
        .clone()
}

/// Cursors helper for `/sync/pull`.
pub fn cursors(pairs: &[(Uuid, i64)]) -> HashMap<Uuid, i64> {
    pairs.iter().copied().collect()
}

/// Where the syslog_tls test drops the self-signed CA the server trusts.
pub fn syslog_ca_path() -> String {
    std::env::temp_dir()
        .join("termoso-test-syslog-ca.pem")
        .to_string_lossy()
        .into_owned()
}
