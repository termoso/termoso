//! Shared application state.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use sqlx::PgPool;
use termoso_crypto::aead::{self, Aad};
use termoso_crypto::keys::SymmetricKey;
use termoso_crypto::opaque;
use termoso_proto::admin::ServerSettings;
use tokio::sync::broadcast;
use webauthn_rs::prelude::*;

use crate::cache::Cache;
use crate::config::Config;
use crate::error::ApiResult;
use crate::events::Event;
use crate::mail::Mailer;
use crate::sso::SsoRegistry;
use crate::storage::Storage;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const SETTINGS_KEY: &str = "settings";

pub type AppState = Arc<Inner>;

pub struct Inner {
    pub cfg: Config,
    pub db: PgPool,
    pub cache: Cache,
    pub storage: Option<Storage>,
    pub mailer: Option<Mailer>,
    pub webauthn: Option<Webauthn>,
    pub opaque: opaque::Server,
    pub master_key: SymmetricKey,
    pub sso: SsoRegistry,
    /// Command-suggestion model client, when configured.
    pub ai: Option<crate::ai::Ai>,
    /// `host[:port]` of `TERMOSO_SSHID_URL`, matched against `Host`.
    pub sshid_host: Option<String>,
    /// `host[:port]` of `TERMOSO_LANDING_URL`, matched against `Host`.
    pub landing_host: Option<String>,
    pub docs_host: Option<String>,
    /// Local fan-out of bus events to WebSocket connections on this instance.
    pub events: broadcast::Sender<Event>,
    /// Local fan-out of multiplayer relay frames (see `live::bus`).
    pub live: broadcast::Sender<crate::live::BusFrame>,
    pub gateway: broadcast::Sender<crate::gateway::RelayFrame>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Set on SIGTERM: `/readyz` answers 503 so the balancer drains this
    /// replica while in-flight requests finish.
    pub draining: std::sync::atomic::AtomicBool,
}

impl Inner {
    pub async fn build(cfg: Config) -> anyhow::Result<AppState> {
        let master_key = cfg.master_key()?;

        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(cfg.database_max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&cfg.database_url)
            .await
            .context("connecting to PostgreSQL")?;
        sqlx::migrate!("./migrations")
            .run(&db)
            .await
            .context("running migrations")?;

        let cache = Cache::connect(&cfg.redis_url, &cfg.redis_prefix)
            .await
            .context("connecting to Redis")?;
        cache.ping().await.context("pinging Redis")?;

        let storage = match (&cfg.s3, &cfg.logs_dir) {
            (Some(s3), _) => {
                let s = Storage::new(s3).await?;
                s.ensure_bucket().await?;
                Some(s)
            }
            (None, Some(dir)) => Some(Storage::local(
                dir.clone(),
                &cfg.public_url,
                master_key.clone(),
            )?),
            (None, None) => None,
        };

        let mailer = match &cfg.smtp {
            Some(smtp) => Some(Mailer::new(smtp, &cfg)?),
            None => None,
        };

        let webauthn = match &cfg.webauthn {
            Some(w) => {
                let origins = crate::config::split_csv(&w.origins);
                let first = origins
                    .first()
                    .context("TERMOSO_WEBAUTHN__ORIGINS must list at least one origin")?;
                let first_url = Url::parse(first).context("invalid webauthn origin")?;
                let mut b = WebauthnBuilder::new(&w.rp_id, &first_url)?.rp_name(&w.rp_name);
                for o in origins.iter().skip(1) {
                    b = b.append_allowed_origin(&Url::parse(o).context("invalid webauthn origin")?);
                }
                Some(b.build()?)
            }
            None => None,
        };

        let opaque = load_opaque_server(&db, &master_key).await?;
        let sso = SsoRegistry::from_config(&cfg).await?;
        let sshid_host = cfg.sshid_host();
        let landing_host = cfg.landing_host();
        let docs_host = cfg.docs_host();
        let ai = cfg.ai.as_ref().map(crate::ai::Ai::new).transpose()?;

        let state = Arc::new(Inner {
            sshid_host,
            landing_host,
            docs_host,
            ai,
            cfg,
            db,
            cache,
            storage,
            mailer,
            webauthn,
            opaque,
            master_key,
            sso,
            events: broadcast::channel(4096).0,
            live: broadcast::channel(4096).0,
            gateway: broadcast::channel(8192).0,
            started_at: chrono::Utc::now(),
            draining: std::sync::atomic::AtomicBool::new(false),
        });
        state.sso.load_all_teams(&state).await;
        Ok(state)
    }

    pub fn encrypt_secret(&self, purpose: &str, plaintext: &[u8]) -> ApiResult<Vec<u8>> {
        Ok(aead::encrypt(
            &self.master_key,
            &Aad::server(purpose),
            plaintext,
        )?)
    }

    pub fn decrypt_secret(&self, purpose: &str, ciphertext: &[u8]) -> ApiResult<Vec<u8>> {
        aead::decrypt(&self.master_key, &Aad::server(purpose), ciphertext)
            .map_err(|e| anyhow::anyhow!("cannot decrypt server secret `{purpose}`: {e}").into())
    }

    /// Runtime settings (admin-editable), cached in Redis for 30 s.
    pub async fn settings(&self) -> ApiResult<ServerSettings> {
        if let Some(s) = self.cache.get_json::<ServerSettings>(SETTINGS_KEY).await? {
            return Ok(s);
        }
        let row: Option<(serde_json::Value,)> =
            sqlx::query_as("SELECT data FROM server_settings WHERE id = 1")
                .fetch_optional(&self.db)
                .await?;
        let settings = match row {
            Some((v,)) => serde_json::from_value(v).unwrap_or_default(),
            None => ServerSettings::default(),
        };
        self.cache
            .set_json(SETTINGS_KEY, &settings, Duration::from_secs(30))
            .await?;
        Ok(settings)
    }

    pub async fn save_settings(
        &self,
        settings: &ServerSettings,
        updated_by: Option<uuid::Uuid>,
    ) -> ApiResult<()> {
        sqlx::query(
            "INSERT INTO server_settings (id, data, updated_at, updated_by) VALUES (1, $1, now(), $2)
             ON CONFLICT (id) DO UPDATE
                SET data = EXCLUDED.data, updated_at = now(), updated_by = EXCLUDED.updated_by",
        )
        .bind(serde_json::to_value(settings)?)
        .bind(updated_by)
        .execute(&self.db)
        .await?;
        self.cache.del(SETTINGS_KEY).await?;
        Ok(())
    }

    /// When and by whom the settings were last saved (`None` = still defaults).
    pub async fn settings_meta(
        &self,
    ) -> ApiResult<Option<(chrono::DateTime<chrono::Utc>, Option<String>)>> {
        let row: Option<(chrono::DateTime<chrono::Utc>, Option<String>)> = sqlx::query_as(
            "SELECT s.updated_at, u.email FROM server_settings s
             LEFT JOIN users u ON u.id = s.updated_by WHERE s.id = 1",
        )
        .fetch_optional(&self.db)
        .await?;
        Ok(row)
    }

    pub fn is_bootstrap_admin(&self, email: &str) -> bool {
        self.cfg.admin_emails().iter().any(|e| e == email)
    }

    /// The owner: `TERMOSO_OWNER_EMAIL` when set, otherwise the first account
    /// ever registered. Only the owner manages the admin role.
    pub async fn owner_user_id(&self) -> sqlx::Result<Option<uuid::Uuid>> {
        let owner = self.cfg.owner_email.trim().to_lowercase();
        let row: Option<(uuid::Uuid,)> = if owner.is_empty() {
            sqlx::query_as("SELECT id FROM users ORDER BY created_at, id LIMIT 1")
                .fetch_optional(&self.db)
                .await?
        } else {
            sqlx::query_as("SELECT id FROM users WHERE lower(email) = $1")
                .bind(owner)
                .fetch_optional(&self.db)
                .await?
        };
        Ok(row.map(|(id,)| id))
    }
}

async fn load_opaque_server(
    db: &PgPool,
    master_key: &SymmetricKey,
) -> anyhow::Result<opaque::Server> {
    const NAME: &str = "opaque_server_setup";
    async fn read(db: &PgPool) -> anyhow::Result<Option<Vec<u8>>> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT value FROM server_secrets WHERE name = $1")
                .bind(NAME)
                .fetch_optional(db)
                .await?;
        Ok(row.map(|r| r.0))
    }
    if read(db).await?.is_none() {
        let fresh = opaque::Server::generate();
        let enc = aead::encrypt(master_key, &Aad::server(NAME), &fresh.to_bytes())?;
        sqlx::query("INSERT INTO server_secrets (name, value) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING")
            .bind(NAME)
            .bind(enc)
            .execute(db)
            .await?;
    }
    let enc = read(db)
        .await?
        .context("opaque server setup missing after insert")?;
    let raw = aead::decrypt(master_key, &Aad::server(NAME), &enc)
        .context("TERMOSO_MASTER_KEY does not match the key this database was initialised with")?;
    Ok(opaque::Server::from_bytes(&raw)?)
}
