//! Single sign-on. The IdP only proves *who owns the email*; the vault password
//! (OPAQUE) is still required because the server never holds decryption keys.
//!
//! Supported: any OpenID Connect provider (discovery), presets for `google`
//! and `microsoft`, GitHub (plain OAuth2 + user API), and SAML 2.0 IdPs
//! (SP-initiated, HTTP-Redirect/POST out, HTTP-POST ACS in; see [`crate::saml`]).

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use anyhow::Context;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use termoso_proto::auth::{SsoIdentity, SsoKind, SsoProvider, SsoResult};

use crate::config::{Config, SsoKindConfig, SsoProviderConfig};
use crate::error::{ApiResult, Error};
use crate::saml;
use crate::state::AppState;
use crate::util::random_token;

pub const FLOW_TTL: Duration = Duration::from_secs(600);
pub const SESSION_TTL: Duration = Duration::from_secs(900);

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

type GitHubClient = oauth2::basic::BasicClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

enum Backend {
    Oidc(Box<OidcClient>),
    GitHub(Box<GitHubClient>),
    Saml(Box<saml::ServiceProvider>),
}

pub struct Provider {
    pub id: String,
    pub name: String,
    /// Set for a team's own IdP (`team-<uuid>`).
    pub team: Option<Uuid>,
    allowed_domains: Vec<String>,
    extra_scopes: Vec<String>,
    backend: Backend,
}

#[derive(Default)]
pub struct SsoRegistry {
    providers: BTreeMap<String, Arc<Provider>>,
    /// Per-team IdPs (`team_idp`), keyed by provider id; reloaded on save.
    teams: std::sync::RwLock<HashMap<String, Arc<Provider>>>,
    http: Option<reqwest::Client>,
}

pub const TEAM_PREFIX: &str = "team-";

pub fn team_provider_id(team_id: Uuid) -> String {
    format!("{TEAM_PREFIX}{team_id}")
}

pub fn team_of_provider(id: &str) -> Option<Uuid> {
    id.strip_prefix(TEAM_PREFIX).and_then(|s| s.parse().ok())
}

/// Decrypted `team_idp` row.
#[derive(Clone)]
pub struct TeamIdpRow {
    pub team_id: Uuid,
    pub kind: String,
    pub name: String,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scopes: Option<String>,
    pub saml_metadata: Option<String>,
    pub saml_idp_entity_id: Option<String>,
    pub domains: Vec<String>,
    pub enabled: bool,
    pub jit_join: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub async fn team_row(state: &AppState, team_id: Uuid) -> ApiResult<Option<TeamIdpRow>> {
    type Row = (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<Vec<u8>>,
        Option<String>,
        Option<String>,
        Option<String>,
        Vec<String>,
        bool,
        bool,
        chrono::DateTime<chrono::Utc>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT kind, name, issuer, client_id, client_secret_enc, scopes, saml_metadata,
                saml_idp_entity_id, domains, enabled, jit_join, updated_at
         FROM team_idp WHERE team_id = $1",
    )
    .bind(team_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((
        kind,
        name,
        issuer,
        client_id,
        enc,
        scopes,
        saml_metadata,
        saml_idp_entity_id,
        domains,
        enabled,
        jit_join,
        updated_at,
    )) = row
    else {
        return Ok(None);
    };
    let client_secret = match enc {
        Some(e) => Some(
            String::from_utf8(state.decrypt_secret("team_idp", &e)?)
                .map_err(|_| Error::Internal(anyhow::anyhow!("team_idp secret is not UTF-8")))?,
        ),
        None => None,
    };
    Ok(Some(TeamIdpRow {
        team_id,
        kind,
        name,
        issuer,
        client_id,
        client_secret,
        scopes,
        saml_metadata,
        saml_idp_entity_id,
        domains,
        enabled,
        jit_join,
        updated_at,
    }))
}

#[derive(Serialize, Deserialize)]
struct FlowState {
    provider: String,
    nonce: Option<String>,
    pkce: String,
    /// Where to send the browser after the callback (client deep link / web cabinet URL).
    redirect: Option<String>,
    /// SAML: the `AuthnRequest` ID the response must answer.
    #[serde(default)]
    saml_request_id: Option<String>,
    /// SAML HTTP-POST binding: form the browser has to submit to the IdP.
    #[serde(default)]
    saml_post: Option<SamlPostForm>,
    /// Account-linking flow started from the cabinet: attach the identity to
    /// this user instead of signing in.
    #[serde(default)]
    link_user: Option<uuid::Uuid>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SamlPostForm {
    pub action: String,
    pub saml_request: String,
}

/// What a consumed `sso_session` token proves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoSession {
    pub provider: String,
    pub subject: String,
    pub email: String,
    pub display_name: Option<String>,
    /// Group names asserted by the IdP (OIDC `groups`, SAML `memberOf`);
    /// drive team role mappings.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Set when the identity came from a team's own IdP (JIT join).
    #[serde(default)]
    pub team_id: Option<Uuid>,
    /// SAML `SessionIndex` of the IdP session, for Single Logout.
    #[serde(default)]
    pub session_index: Option<String>,
}

/// What a signed-in session owes to an IdP: enough to answer or send a SAML
/// `LogoutRequest` for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoLogin {
    pub provider: String,
    pub subject: String,
    #[serde(default)]
    pub session_index: Option<String>,
}

impl From<&SsoSession> for SsoLogin {
    fn from(s: &SsoSession) -> Self {
        Self {
            provider: s.provider.clone(),
            subject: s.subject.clone(),
            session_index: s.session_index.clone(),
        }
    }
}

/// `groups` claim of an already verified ID token. openidconnect's core
/// claims type has no slot for it, so read the payload directly.
fn groups_from_id_token(compact: &str) -> Vec<String> {
    use base64::Engine;
    let Some(payload) = compact.split('.').nth(1) else {
        return Vec::new();
    };
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Vec::new();
    };
    v.get("groups")
        .and_then(|g| g.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn flow_key(id: &str) -> String {
    format!("sso_flow:{id}")
}
fn result_key(id: &str) -> String {
    format!("sso_result:{id}")
}
fn session_key(token: &str) -> String {
    format!("sso_sess:{token}")
}

fn http_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .user_agent(format!("termoso-server/{}", crate::state::VERSION))
        .build()?)
}

impl SsoRegistry {
    pub async fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let http = http_client()?;
        let redirect = RedirectUrl::new(format!(
            "{}/api/v1/auth/sso/callback",
            cfg.public_url.trim_end_matches('/')
        ))?;
        let mut providers = BTreeMap::new();
        for (slug, p) in &cfg.sso {
            let slug = slug.to_lowercase();
            let provider = build_provider(&slug, p, &redirect, &http)
                .await
                .with_context(|| format!("SSO provider `{slug}`"))?;
            providers.insert(slug, Arc::new(provider));
        }
        Ok(Self {
            providers,
            teams: Default::default(),
            http: Some(http),
        })
    }

    /// Build (and validate: OIDC discovery / SAML metadata) a team provider.
    pub async fn build_team(
        &self,
        cfg: &Config,
        row: &TeamIdpRow,
    ) -> anyhow::Result<Arc<Provider>> {
        let http = self
            .http
            .as_ref()
            .context("SSO http client not initialised")?;
        let redirect = RedirectUrl::new(format!(
            "{}/api/v1/auth/sso/callback",
            cfg.public_url.trim_end_matches('/')
        ))?;
        let mut p: SsoProviderConfig =
            serde_json::from_value(serde_json::json!({})).context("default SSO config")?;
        p.name = Some(row.name.clone());
        p.kind = if row.kind == "saml" {
            SsoKindConfig::Saml
        } else {
            SsoKindConfig::Oidc
        };
        p.issuer = row.issuer.clone();
        p.client_id = row.client_id.clone();
        p.client_secret = row.client_secret.clone();
        p.scopes = row.scopes.clone();
        p.saml_metadata = row.saml_metadata.clone();
        p.saml_idp_entity_id = row.saml_idp_entity_id.clone();
        p.allowed_domains = Some(row.domains.join(","));
        let slug = team_provider_id(row.team_id);
        let mut provider = build_provider(&slug, &p, &redirect, http).await?;
        provider.team = Some(row.team_id);
        Ok(Arc::new(provider))
    }

    /// Register (or drop, with `None`) the provider of a team.
    pub fn install_team(&self, team_id: Uuid, provider: Option<Arc<Provider>>) {
        if let Ok(mut t) = self.teams.write() {
            let id = team_provider_id(team_id);
            match provider {
                Some(p) => {
                    t.insert(id, p);
                }
                None => {
                    t.remove(&id);
                }
            }
        }
    }

    /// (Re)load one team's IdP from the database. `Ok(false)` = none/disabled.
    pub async fn load_team(&self, state: &AppState, team_id: Uuid) -> anyhow::Result<bool> {
        let row = team_row(state, team_id)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        match row {
            Some(r) if r.enabled && state.cfg.team_idp => {
                let p = self.build_team(&state.cfg, &r).await?;
                self.install_team(team_id, Some(p));
                Ok(true)
            }
            _ => {
                self.install_team(team_id, None);
                Ok(false)
            }
        }
    }

    /// Startup: load every enabled team IdP; a broken one is logged, not fatal.
    pub async fn load_all_teams(&self, state: &AppState) {
        if !state.cfg.team_idp {
            return;
        }
        let ids: Vec<(Uuid,)> = match sqlx::query_as("SELECT team_id FROM team_idp WHERE enabled")
            .fetch_all(&state.db)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "cannot list team IdPs");
                return;
            }
        };
        for (team_id,) in ids {
            if let Err(e) = self.load_team(state, team_id).await {
                tracing::warn!(error = %e, %team_id, "team IdP not loaded");
            }
        }
    }

    pub fn team_provider(&self, team_id: Uuid) -> Option<Arc<Provider>> {
        self.teams
            .read()
            .ok()
            .and_then(|t| t.get(&team_provider_id(team_id)).cloned())
    }

    /// Home-realm discovery: the team IdP that claims the email's domain.
    pub fn discover(&self, email: &str) -> Option<Arc<Provider>> {
        let domain = email.rsplit('@').next()?.to_lowercase();
        if domain.is_empty() {
            return None;
        }
        self.teams.read().ok().and_then(|t| {
            t.values()
                .find(|p| p.allowed_domains.contains(&domain))
                .cloned()
        })
    }

    /// Whether a server-wide provider with this id is configured.
    pub fn has(&self, id: &str) -> bool {
        self.providers.contains_key(id)
    }

    pub fn list(&self) -> Vec<SsoProvider> {
        self.providers.values().map(|p| p.public()).collect()
    }
}

impl Provider {
    pub fn public(&self) -> SsoProvider {
        let p = self;
        SsoProvider {
            id: p.id.clone(),
            name: p.name.clone(),
            kind: match p.backend {
                Backend::Saml(_) => SsoKind::Saml,
                Backend::Oidc(_) | Backend::GitHub(_) => SsoKind::Oidc,
            },
        }
    }
}

impl SsoRegistry {
    /// SP metadata XML for a SAML provider.
    pub fn saml_metadata(&self, id: &str) -> ApiResult<String> {
        match &self.get(id)?.backend {
            Backend::Saml(sp) => Ok(sp.metadata_xml()),
            _ => Err(Error::not_found("SAML provider")),
        }
    }

    /// Every SAML provider (global and per-team): a Single Logout message
    /// names its IdP only by issuer, so each candidate gets to verify it.
    pub fn saml_providers(&self) -> Vec<Arc<Provider>> {
        let saml = |p: &&Arc<Provider>| matches!(p.backend, Backend::Saml(_));
        let mut out: Vec<Arc<Provider>> = self.providers.values().filter(saml).cloned().collect();
        if let Ok(t) = self.teams.read() {
            out.extend(t.values().filter(saml).cloned());
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    fn get(&self, id: &str) -> ApiResult<Arc<Provider>> {
        if let Some(p) = self.providers.get(id) {
            return Ok(p.clone());
        }
        self.teams
            .read()
            .ok()
            .and_then(|t| t.get(id).cloned())
            .ok_or_else(|| Error::not_found("SSO provider"))
    }
}

async fn build_provider(
    slug: &str,
    p: &SsoProviderConfig,
    redirect: &RedirectUrl,
    http: &reqwest::Client,
) -> anyhow::Result<Provider> {
    let allowed_domains: Vec<String> = p
        .allowed_domains
        .as_deref()
        .map(crate::config::split_csv)
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.to_lowercase())
        .collect();
    if p.kind == SsoKindConfig::Saml {
        let sp = build_saml(slug, p, redirect, http).await?;
        return Ok(Provider {
            id: slug.to_string(),
            team: None,
            name: p.name.clone().unwrap_or_else(|| slug.to_string()),
            allowed_domains,
            extra_scopes: Vec::new(),
            backend: Backend::Saml(Box::new(sp)),
        });
    }
    let client_id = p.client_id.clone().context("client_id is required")?;
    let client_secret = p
        .client_secret
        .clone()
        .context("client_secret is required")?;
    let extra_scopes: Vec<String> = p
        .scopes
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(String::from)
        .collect();

    let (name, backend) = if slug == "github" {
        let client = oauth2::basic::BasicClient::new(oauth2::ClientId::new(client_id))
            .set_client_secret(oauth2::ClientSecret::new(client_secret))
            .set_auth_uri(oauth2::AuthUrl::new(
                "https://github.com/login/oauth/authorize".into(),
            )?)
            .set_token_uri(oauth2::TokenUrl::new(
                "https://github.com/login/oauth/access_token".into(),
            )?)
            .set_redirect_uri(oauth2::RedirectUrl::new(redirect.to_string())?);
        ("GitHub".to_string(), Backend::GitHub(Box::new(client)))
    } else {
        let issuer = p
            .issuer
            .clone()
            .or_else(|| match slug {
                "google" => Some("https://accounts.google.com".into()),
                "microsoft" => Some("https://login.microsoftonline.com/common/v2.0".into()),
                _ => None,
            })
            .context("issuer is required for OIDC providers")?;
        let metadata = CoreProviderMetadata::discover_async(IssuerUrl::new(issuer)?, http)
            .await
            .context("OIDC discovery failed")?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
        )
        .set_redirect_uri(redirect.clone());
        let default_name = match slug {
            "google" => "Google",
            "microsoft" => "Microsoft",
            _ => slug,
        };
        (default_name.to_string(), Backend::Oidc(Box::new(client)))
    };
    Ok(Provider {
        id: slug.to_string(),
        team: None,
        name: p.name.clone().unwrap_or(name),
        allowed_domains,
        extra_scopes,
        backend,
    })
}

/// Materialise a value that may be given inline or as a file path.
fn inline_or_file(value: &str, inline_marker: &str, what: &str) -> anyhow::Result<String> {
    if value.trim_start().starts_with(inline_marker) {
        return Ok(value.to_string());
    }
    std::fs::read_to_string(value).with_context(|| format!("reading {what} from {value}"))
}

async fn build_saml(
    slug: &str,
    p: &SsoProviderConfig,
    redirect: &RedirectUrl,
    http: &reqwest::Client,
) -> anyhow::Result<saml::ServiceProvider> {
    let source = p
        .saml_metadata
        .as_deref()
        .context("saml_metadata (URL, file path or XML) is required")?;
    let xml = if source.starts_with("https://") || source.starts_with("http://") {
        http.get(source)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .with_context(|| format!("fetching IdP metadata from {source}"))?
            .text()
            .await?
    } else {
        inline_or_file(source, "<", "IdP metadata")?
    };
    let idp = saml::metadata::parse_idp(&xml, p.saml_idp_entity_id.as_deref())
        .context("parsing IdP metadata")?;

    let api_base = redirect
        .as_str()
        .trim_end_matches("/auth/sso/callback")
        .to_string();
    let acs_url = format!("{api_base}/auth/sso/saml/acs");
    let slo_url = format!("{api_base}/auth/sso/saml/slo");
    let entity_id = p
        .saml_sp_entity_id
        .clone()
        .unwrap_or_else(|| format!("{api_base}/auth/sso/{slug}/saml/metadata"));
    let cert_der = p
        .saml_sp_certificate
        .as_deref()
        .map(|c| {
            inline_or_file(c, "-----", "SP certificate").and_then(|pem| saml::pem_to_der(&pem))
        })
        .transpose()
        .context("SP certificate")?;
    let key = p
        .saml_sp_private_key
        .as_deref()
        .map(|k| {
            inline_or_file(k, "-----", "SP private key")
                .and_then(|pem| saml::parse_private_key(&pem))
        })
        .transpose()
        .context("SP private key")?;
    if let (Some(cert), Some(key)) = (&cert_der, &key) {
        let cert_pub = saml::dsig::cert_public_key(cert).context("SP certificate")?;
        anyhow::ensure!(
            &cert_pub == key.public_key(),
            "SP private key does not match the SP certificate"
        );
    }
    if idp.want_authn_requests_signed && key.is_none() && p.saml_sign_requests.is_none() {
        tracing::warn!(
            provider = slug,
            "IdP wants signed AuthnRequests but no saml_sp_private_key is configured; sending unsigned"
        );
    }
    let sign_requests = p
        .saml_sign_requests
        .unwrap_or(idp.want_authn_requests_signed && key.is_some());
    anyhow::ensure!(
        !sign_requests || key.is_some(),
        "saml_sign_requests needs saml_sp_private_key"
    );
    saml::ServiceProvider::new(
        saml::SpConfig {
            entity_id,
            acs_url,
            slo_url,
            key,
            cert_der,
            sign_requests,
            allow_sha1: p.saml_allow_sha1,
            email_attribute: p.saml_email_attribute.clone(),
            name_attribute: p.saml_name_attribute.clone(),
            clock_skew: chrono::Duration::seconds(p.saml_clock_skew_secs as i64),
        },
        idp,
    )
}

/// Begin a flow. Returns `(authorization_url, flow_id)`.
pub async fn start(
    state: &AppState,
    provider_id: &str,
    redirect: Option<String>,
    link_user: Option<uuid::Uuid>,
) -> ApiResult<(String, String)> {
    let provider = state.sso.get(provider_id)?;
    let flow_id = random_token();
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let mut saml_request_id = None;
    let mut saml_post = None;
    let (url, nonce) = match &provider.backend {
        Backend::Oidc(client) => {
            let fid = flow_id.clone();
            let mut req = client
                .authorize_url(
                    CoreAuthenticationFlow::AuthorizationCode,
                    move || CsrfToken::new(fid),
                    Nonce::new_random,
                )
                .add_scope(Scope::new("email".into()))
                .add_scope(Scope::new("profile".into()))
                .set_pkce_challenge(pkce_challenge);
            for s in &provider.extra_scopes {
                req = req.add_scope(Scope::new(s.clone()));
            }
            let (url, _csrf, nonce) = req.url();
            (url.to_string(), Some(nonce.secret().clone()))
        }
        Backend::GitHub(client) => {
            let fid = flow_id.clone();
            let mut req = client
                .authorize_url(move || oauth2::CsrfToken::new(fid))
                .add_scope(oauth2::Scope::new("read:user".into()))
                .add_scope(oauth2::Scope::new("user:email".into()))
                .set_pkce_challenge(pkce_challenge);
            for s in &provider.extra_scopes {
                req = req.add_scope(oauth2::Scope::new(s.clone()));
            }
            let (url, _csrf) = req.url();
            (url.to_string(), None)
        }
        Backend::Saml(sp) => {
            let request_id = saml::ServiceProvider::new_request_id();
            let target = sp
                .start(&request_id, &flow_id, chrono::Utc::now())
                .map_err(|e| Error::Internal(e.context("building SAML AuthnRequest")))?;
            saml_request_id = Some(request_id);
            let url = match target {
                saml::AuthnRedirect::Url(u) => u,
                saml::AuthnRedirect::Post {
                    action,
                    saml_request,
                    ..
                } => {
                    saml_post = Some(SamlPostForm {
                        action,
                        saml_request,
                    });
                    format!(
                        "{}/api/v1/auth/sso/saml/post/{flow_id}",
                        state.cfg.public_url.trim_end_matches('/')
                    )
                }
            };
            (url, None)
        }
    };
    let redirect = redirect.filter(|r| is_safe_redirect(state, r));
    state
        .cache
        .set_json(
            &flow_key(&flow_id),
            &FlowState {
                provider: provider_id.to_string(),
                nonce,
                pkce: pkce_verifier.secret().clone(),
                redirect,
                saml_request_id,
                saml_post,
                link_user,
            },
            FLOW_TTL,
        )
        .await?;
    state
        .cache
        .set_json(&result_key(&flow_id), &SsoResult::Pending, FLOW_TTL)
        .await?;
    Ok((url, flow_id))
}

/// Only allow redirects to the web cabinet or custom app schemes (desktop/mobile deep links).
fn is_safe_redirect(state: &AppState, r: &str) -> bool {
    is_safe_redirect_for(state.cfg.web_url(), &state.cfg.public_url, r)
}

/// `r` must be the app scheme, or an http(s) URL whose *origin* (scheme, host,
/// port) equals the cabinet's or the API's, or a plain-http loopback address
/// (the desktop / dev-server callbacks). Compared as parsed origins so
/// `https://app.example.com.evil.test` and `https://app.example.com@evil.test`
/// are not mistaken for the cabinet.
fn is_safe_redirect_for(web_url: &str, public_url: &str, r: &str) -> bool {
    let Ok(u) = url::Url::parse(r) else {
        return false;
    };
    match u.scheme() {
        "termoso" => true,
        "http" | "https" => {
            let origin = u.origin();
            if !origin.is_tuple() || !u.username().is_empty() || u.password().is_some() {
                return false;
            }
            let same_origin = |base: &str| {
                url::Url::parse(base).is_ok_and(|b| b.origin().is_tuple() && b.origin() == origin)
            };
            let loopback = u.scheme() == "http"
                && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
            same_origin(web_url) || same_origin(public_url) || loopback
        }
        _ => false,
    }
}

/// Handle the IdP redirect. Returns `(redirect target if any, flow_id)`.
pub async fn callback(
    state: &AppState,
    flow_id: &str,
    code: Option<&str>,
    error: Option<&str>,
) -> ApiResult<(Option<String>, String)> {
    let Some(flow) = state
        .cache
        .take_json::<FlowState>(&flow_key(flow_id))
        .await?
    else {
        return Err(Error::token_expired());
    };
    let outcome = match (code, error) {
        (_, Some(err)) => SsoResult::Failed {
            message: format!("Identity provider returned an error: {err}"),
        },
        (Some(code), None) => match exchange(state, &flow, code).await {
            Ok(sess) => match flow.link_user {
                Some(user_id) => link(state, sess, user_id).await?,
                None => finish(state, sess).await?,
            },
            Err(e) => {
                tracing::warn!(error = %e, provider = %flow.provider, "sso exchange failed");
                SsoResult::Failed {
                    message: "Could not verify your identity with the provider".into(),
                }
            }
        },
        (None, None) => SsoResult::Failed {
            message: "Missing authorization code".into(),
        },
    };
    state
        .cache
        .set_json(&result_key(flow_id), &outcome, FLOW_TTL)
        .await?;
    Ok((flow.redirect, flow_id.to_string()))
}

/// HTTP-POST binding: the form the browser auto-submits to the IdP. The flow
/// stays pending until the ACS consumes it.
pub async fn saml_post_form(state: &AppState, flow_id: &str) -> ApiResult<SamlPostForm> {
    let flow = state
        .cache
        .get_json::<FlowState>(&flow_key(flow_id))
        .await?
        .ok_or_else(Error::token_expired)?;
    flow.saml_post.ok_or_else(|| Error::not_found("SAML flow"))
}

/// Assertion Consumer Service. `relay_state` is our flow id; returns
/// `(redirect target if any, flow_id)` like [`callback`].
pub async fn saml_acs(
    state: &AppState,
    relay_state: &str,
    saml_response: &str,
) -> ApiResult<(Option<String>, String)> {
    let Some(flow) = state
        .cache
        .take_json::<FlowState>(&flow_key(relay_state))
        .await?
    else {
        return Err(Error::token_expired());
    };
    let outcome = match consume_saml(state, &flow, saml_response) {
        Ok(sess) => match flow.link_user {
            Some(user_id) => link(state, sess, user_id).await?,
            None => finish(state, sess).await?,
        },
        Err(e) => {
            tracing::warn!(error = %e, provider = %flow.provider, "saml response rejected");
            SsoResult::Failed {
                message: match e.downcast_ref::<saml::SamlError>() {
                    Some(saml::SamlError::Status(s)) => {
                        format!("Identity provider returned an error: {s}")
                    }
                    _ => "Could not verify your identity with the provider".into(),
                },
            }
        }
    };
    state
        .cache
        .set_json(&result_key(relay_state), &outcome, FLOW_TTL)
        .await?;
    Ok((flow.redirect, relay_state.to_string()))
}

fn consume_saml(
    state: &AppState,
    flow: &FlowState,
    saml_response: &str,
) -> anyhow::Result<SsoSession> {
    let provider = state
        .sso
        .get(&flow.provider)
        .map_err(|_| anyhow::anyhow!("provider vanished"))?;
    let Backend::Saml(sp) = &provider.backend else {
        anyhow::bail!("flow does not belong to a SAML provider");
    };
    let request_id = flow
        .saml_request_id
        .as_deref()
        .context("flow has no AuthnRequest id")?;
    let identity = sp.consume_response(saml_response, request_id, chrono::Utc::now())?;
    apply_domain_policy(
        &provider,
        SsoSession {
            provider: provider.id.clone(),
            subject: identity.subject,
            email: identity.email,
            display_name: identity.name,
            groups: identity.groups,
            team_id: None,
            session_index: identity.session_index,
        },
    )
}

fn apply_domain_policy(provider: &Provider, sess: SsoSession) -> anyhow::Result<SsoSession> {
    let email = crate::util::normalize_email(&sess.email).context("invalid email from provider")?;
    if !provider.allowed_domains.is_empty() {
        let domain = email.rsplit('@').next().unwrap_or_default();
        anyhow::ensure!(
            provider.allowed_domains.iter().any(|d| d == domain),
            "email domain not allowed for this provider"
        );
    }
    Ok(SsoSession {
        email,
        team_id: provider.team,
        ..sess
    })
}

async fn exchange(state: &AppState, flow: &FlowState, code: &str) -> anyhow::Result<SsoSession> {
    let provider = state
        .sso
        .get(&flow.provider)
        .map_err(|_| anyhow::anyhow!("provider vanished"))?;
    let http = state.sso.http.as_ref().context("no http client")?;
    let sess = match &provider.backend {
        Backend::Oidc(client) => {
            let tokens = client
                .exchange_code(AuthorizationCode::new(code.to_string()))?
                .set_pkce_verifier(PkceCodeVerifier::new(flow.pkce.clone()))
                .request_async(http)
                .await?;
            let id_token = tokens.id_token().context("no id_token")?;
            let nonce = Nonce::new(flow.nonce.clone().context("no nonce")?);
            let claims = id_token.claims(&client.id_token_verifier(), &nonce)?;
            let email = claims.email().context("no email claim")?.to_string();
            if claims.email_verified() == Some(false) {
                anyhow::bail!("email not verified at provider");
            }
            let display_name = claims
                .name()
                .and_then(|n| n.get(None))
                .map(|n| n.to_string());
            let groups = serde_json::to_value(id_token)
                .ok()
                .and_then(|v| v.as_str().map(groups_from_id_token))
                .unwrap_or_default();
            SsoSession {
                provider: provider.id.clone(),
                subject: claims.subject().to_string(),
                email,
                display_name,
                groups,
                team_id: None,
                session_index: None,
            }
        }
        Backend::GitHub(client) => {
            let tokens = client
                .exchange_code(oauth2::AuthorizationCode::new(code.to_string()))
                .set_pkce_verifier(oauth2::PkceCodeVerifier::new(flow.pkce.clone()))
                .request_async(http)
                .await?;
            let access = tokens.access_token().secret().clone();
            #[derive(Deserialize)]
            struct GhUser {
                id: u64,
                name: Option<String>,
                login: String,
            }
            #[derive(Deserialize)]
            struct GhEmail {
                email: String,
                primary: bool,
                verified: bool,
            }
            let user: GhUser = http
                .get("https://api.github.com/user")
                .bearer_auth(&access)
                .header("accept", "application/vnd.github+json")
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let emails: Vec<GhEmail> = http
                .get("https://api.github.com/user/emails")
                .bearer_auth(&access)
                .header("accept", "application/vnd.github+json")
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let email = emails
                .iter()
                .find(|e| e.primary && e.verified)
                .or_else(|| emails.iter().find(|e| e.verified))
                .map(|e| e.email.clone())
                .context("no verified email on GitHub account")?;
            SsoSession {
                provider: provider.id.clone(),
                subject: user.id.to_string(),
                email,
                display_name: user.name.or(Some(user.login)),
                groups: Vec::new(),
                team_id: None,
                session_index: None,
            }
        }
        Backend::Saml(_) => anyhow::bail!("SAML flows complete on the ACS, not the OAuth callback"),
    };
    apply_domain_policy(&provider, sess)
}

async fn finish(state: &AppState, sess: SsoSession) -> ApiResult<SsoResult> {
    // Prefer the linked identity; fall back to the email.
    let linked: Option<(String,)> =
        sqlx::query_as("SELECT u.email FROM sso_identities i JOIN users u ON u.id = i.user_id WHERE i.provider = $1 AND i.subject = $2")
            .bind(&sess.provider)
            .bind(&sess.subject)
            .fetch_optional(&state.db)
            .await?;
    let email = match linked {
        Some((e,)) => e,
        None => sess.email.clone(),
    };
    let exists: Option<(bool,)> =
        sqlx::query_as("SELECT disabled FROM users WHERE lower(email) = $1")
            .bind(&email)
            .fetch_optional(&state.db)
            .await?;
    let token = random_token();
    let stored = SsoSession {
        email: email.clone(),
        ..sess
    };
    state
        .cache
        .set_json(&session_key(&token), &stored, SESSION_TTL)
        .await?;
    Ok(match exists {
        Some((true,)) => SsoResult::Failed {
            message: "This account is disabled".into(),
        },
        Some((false,)) => SsoResult::LoginRequired {
            sso_session: token,
            email,
        },
        None => SsoResult::RegistrationRequired {
            sso_session: token,
            email,
            display_name: stored.display_name,
        },
    })
}

/// Outcome of a flow. Terminal results are handed out once: the `flow_id`
/// doubles as the OAuth `state` and shows up in browser history and IdP logs,
/// so nothing useful must remain behind it after the client has collected the
/// `sso_session`.
/// Account-linking flow: attach the identity to `user_id` unless it already
/// belongs to someone else.
async fn link(state: &AppState, sess: SsoSession, user_id: uuid::Uuid) -> ApiResult<SsoResult> {
    let owner: Option<(uuid::Uuid,)> =
        sqlx::query_as("SELECT user_id FROM sso_identities WHERE provider = $1 AND subject = $2")
            .bind(&sess.provider)
            .bind(&sess.subject)
            .fetch_optional(&state.db)
            .await?;
    if owner.is_some_and(|(u,)| u != user_id) {
        return Ok(SsoResult::Failed {
            message: "This identity is already linked to another account".into(),
        });
    }
    link_identity(state, &sess, user_id).await?;
    Ok(SsoResult::Linked {
        provider: sess.provider,
        email: sess.email,
    })
}

/// Identities linked to `user_id`, in link order.
pub async fn identities(state: &AppState, user_id: uuid::Uuid) -> ApiResult<Vec<SsoIdentity>> {
    let rows: Vec<(String, Option<String>, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT provider, email, created_at FROM sso_identities WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(provider, email, linked_at)| SsoIdentity {
            name: state
                .sso
                .get(&provider)
                .map(|p| p.name.clone())
                .unwrap_or_else(|_| provider.clone()),
            provider,
            email,
            linked_at,
        })
        .collect())
}

/// Removes every identity of `provider` from `user_id`. `Ok(false)` when there was none.
pub async fn unlink(state: &AppState, user_id: uuid::Uuid, provider: &str) -> ApiResult<bool> {
    let n = sqlx::query("DELETE FROM sso_identities WHERE user_id = $1 AND provider = $2")
        .bind(user_id)
        .bind(provider)
        .execute(&state.db)
        .await?
        .rows_affected();
    Ok(n > 0)
}

pub async fn poll(state: &AppState, flow_id: &str) -> ApiResult<SsoResult> {
    let key = result_key(flow_id);
    match state.cache.get_json::<SsoResult>(&key).await? {
        None => Err(Error::token_expired()),
        Some(SsoResult::Pending) => Ok(SsoResult::Pending),
        Some(_) => state
            .cache
            .take_json::<SsoResult>(&key)
            .await?
            .ok_or_else(Error::token_expired),
    }
}

/// Consume an `sso_session` token; verifies it matches `email`.
pub async fn consume_session(state: &AppState, token: &str, email: &str) -> ApiResult<SsoSession> {
    let sess = state
        .cache
        .take_json::<SsoSession>(&session_key(token))
        .await?
        .ok_or_else(Error::token_expired)?;
    if sess.email != email {
        return Err(Error::forbidden("SSO session does not match this email"));
    }
    Ok(sess)
}

pub async fn link_identity(
    state: &AppState,
    sess: &SsoSession,
    user_id: uuid::Uuid,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO sso_identities (provider, subject, user_id, email) VALUES ($1, $2, $3, $4)
         ON CONFLICT (provider, subject) DO UPDATE SET user_id = EXCLUDED.user_id, email = EXCLUDED.email",
    )
    .bind(&sess.provider)
    .bind(&sess.subject)
    .bind(user_id)
    .bind(&sess.email)
    .execute(&state.db)
    .await?;
    crate::authz::apply_group_mappings(&state.db, user_id, &sess.groups).await?;
    if let Some(team_id) = sess.team_id {
        jit_join(state, team_id, user_id, &sess.groups).await?;
    }
    Ok(())
}

/// Team IdP sign-in: join the team with the default role (`role_source =
/// idp`) when `jit_join` is on, then apply IdP group → role mappings.
async fn jit_join(
    state: &AppState,
    team_id: Uuid,
    user_id: Uuid,
    groups: &[String],
) -> ApiResult<()> {
    let jit: Option<(bool,)> =
        sqlx::query_as("SELECT jit_join FROM team_idp WHERE team_id = $1 AND enabled")
            .bind(team_id)
            .fetch_optional(&state.db)
            .await?;
    if !matches!(jit, Some((true,))) {
        return Ok(());
    }
    let default_role = crate::authz::default_role_id(&state.db, team_id).await?;
    let joined = sqlx::query(
        "INSERT INTO team_members (team_id, user_id, role, role_id, role_source)
         VALUES ($1, $2, CASE WHEN (SELECT slug FROM team_roles WHERE id = $3) = 'admin' THEN 'admin' ELSE 'member' END, $3, 'idp')
         ON CONFLICT (team_id, user_id) DO NOTHING",
    )
    .bind(team_id)
    .bind(user_id)
    .bind(default_role)
    .execute(&state.db)
    .await?
    .rows_affected();
    if joined > 0 {
        crate::audit::record(
            &state.db,
            crate::audit::Entry::by(team_id, user_id, None, "member.joined_idp").user(user_id),
        )
        .await;
        let _ = crate::events::publish(
            state,
            crate::events::Event::TeamsUpdated {
                user_ids: vec![user_id],
            },
        )
        .await;
    }
    crate::authz::apply_group_mappings_scoped(&state.db, user_id, groups, Some(team_id), "idp")
        .await?;
    Ok(())
}

// ───────────────────────────── SAML Single Logout ─────────────────────────────

/// How long we wait for the IdP to answer a `LogoutRequest` of ours.
const SLO_REQ_TTL: Duration = Duration::from_secs(600);

fn slo_key(request_id: &str) -> String {
    format!("sso:slo:{request_id}")
}

/// A message at our SingleLogoutService endpoint.
pub enum SloInbound<'a> {
    /// HTTP-Redirect binding: the raw query string as received.
    Redirect { raw_query: &'a str },
    /// HTTP-POST binding: the base64 `SAMLRequest`/`SAMLResponse` form field.
    Post {
        message: &'a str,
        relay_state: Option<&'a str>,
    },
}

pub enum SloOutcome {
    /// Send the browser on to the IdP (our `LogoutResponse`).
    Redirect(String),
    /// Nothing more to do; show a "signed out" page.
    Done,
}

/// Handle a message at the SLO endpoint. A `LogoutRequest` (IdP-initiated,
/// or the IdP fanning out a logout another SP started) revokes every
/// session we issued for that IdP subject — narrowed to the given
/// `SessionIndex`es when the IdP names them — and is answered with a
/// `LogoutResponse`. A `LogoutResponse` closes a logout we started.
pub async fn saml_slo(state: &AppState, inbound: SloInbound<'_>) -> ApiResult<SloOutcome> {
    let now = chrono::Utc::now();
    let mut message: Option<(saml::SloMessage, Option<String>)> = None;
    let mut providers: Vec<Arc<Provider>> = Vec::new();
    let mut last_err = None;
    for p in state.sso.saml_providers() {
        let Backend::Saml(sp) = &p.backend else {
            continue;
        };
        let r = match inbound {
            SloInbound::Redirect { raw_query } => sp.consume_slo_redirect(raw_query, now),
            SloInbound::Post {
                message,
                relay_state,
            } => sp
                .consume_slo_post(message, now)
                .map(|m| (m, relay_state.map(String::from))),
        };
        match r {
            Ok(m) => {
                message.get_or_insert(m);
                providers.push(p.clone());
            }
            Err(e) => last_err = Some(e),
        }
    }
    let Some((msg, relay)) = message else {
        tracing::warn!(error = ?last_err, "saml logout message rejected");
        return Err(Error::unauthorized());
    };
    match msg {
        saml::SloMessage::Request(req) => {
            let mut users: Vec<Uuid> = Vec::new();
            for p in &providers {
                for u in
                    crate::session::revoke_sso(state, &p.id, &req.name_id, &req.session_indexes)
                        .await?
                {
                    if !users.contains(&u) {
                        users.push(u);
                    }
                }
            }
            for user_id in users {
                crate::users::security_event(
                    state,
                    user_id,
                    "sso_logout",
                    None,
                    None,
                    None,
                    Some(serde_json::json!({ "provider": providers[0].id, "sessions": req.session_indexes.len() })),
                )
                .await?;
            }
            let Backend::Saml(sp) = &providers[0].backend else {
                unreachable!("only SAML providers verify SLO messages")
            };
            Ok(
                match sp.logout_response_url(&req.id, relay.as_deref(), now)? {
                    Some(url) => SloOutcome::Redirect(url),
                    None => SloOutcome::Done,
                },
            )
        }
        saml::SloMessage::Response { in_response_to, .. } => {
            let id = in_response_to
                .ok_or_else(|| Error::bad_request("LogoutResponse without InResponseTo"))?;
            if state
                .cache
                .take_json::<String>(&slo_key(&id))
                .await?
                .is_none()
            {
                return Err(Error::token_expired());
            }
            Ok(SloOutcome::Done)
        }
    }
}

/// SP-initiated logout: the URL that ends the IdP session behind
/// `session_id` as well. `None` when the session did not come from SAML or
/// the IdP has no Redirect-binding SLO endpoint. Call before revoking the
/// session locally.
pub async fn saml_logout_url(state: &AppState, session_id: Uuid) -> ApiResult<Option<String>> {
    let row: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT sso_provider, sso_subject, sso_session_index FROM sessions WHERE id = $1",
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((Some(provider), Some(subject), session_index)) = row else {
        return Ok(None);
    };
    let Ok(p) = state.sso.get(&provider) else {
        return Ok(None);
    };
    let Backend::Saml(sp) = &p.backend else {
        return Ok(None);
    };
    let request_id = saml::ServiceProvider::new_request_id();
    let Some(url) = sp.logout_request_url(
        &request_id,
        &subject,
        session_index.as_deref(),
        Some(&request_id),
        chrono::Utc::now(),
    )?
    else {
        return Ok(None);
    };
    state
        .cache
        .set_json(&slo_key(&request_id), &provider, SLO_REQ_TTL)
        .await?;
    Ok(Some(url))
}

#[cfg(test)]
mod tests {
    use super::is_safe_redirect_for;

    const WEB: &str = "https://app.example.com/";
    const API: &str = "https://api.example.com:8443";

    fn ok(r: &str) -> bool {
        is_safe_redirect_for(WEB, API, r)
    }

    #[test]
    fn own_origins_loopback_and_app_scheme_pass() {
        assert!(ok("https://app.example.com/sso/done?x=1"));
        assert!(ok("https://api.example.com:8443/cabinet"));
        assert!(ok("http://localhost:5173/sso"));
        assert!(ok("http://127.0.0.1:1420/callback"));
        assert!(ok("http://[::1]:1420/callback"));
        assert!(ok("termoso://sso"));
    }

    #[test]
    fn host_prefix_userinfo_and_scheme_tricks_fail() {
        assert!(!ok("https://app.example.com.evil.test/"));
        assert!(!ok("https://app.example.com@evil.test/"));
        assert!(!ok("https://app.example.com:pw@evil.test/"));
        assert!(!ok("https://app.example.com:444/"));
        assert!(!ok("http://app.example.com/"));
        assert!(!ok("https://api.example.com/"));
        assert!(!ok("http://localhost.evil.test/"));
        assert!(!ok("https://localhost/"));
        assert!(!ok("https://evil.example/phish"));
        assert!(!ok("javascript:alert(1)"));
        assert!(!ok("//evil.example"));
        assert!(!ok("not a url"));
    }

    #[test]
    fn web_url_defaults_to_the_api_origin() {
        assert!(is_safe_redirect_for(
            API,
            API,
            "https://api.example.com:8443/"
        ));
        assert!(!is_safe_redirect_for(API, API, "https://app.example.com/"));
    }
}
