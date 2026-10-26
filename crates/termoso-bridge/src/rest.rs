//! Local REST API (Termius API Bridge compatible paths).
//!
//! ```text
//! GET    /                          bridge status
//! GET    /healthz                   liveness
//! GET    /v1/bridge/me/             bridge status (vaults, readiness)
//! POST   /v1/sync/                  re-read /bridge/me and pull now
//! GET    /v1/vaults/
//! GET    /v1/hosts/[?vault=]
//! GET    /v1/host/{external_id}/[?vault=]
//! POST   /v1/host/{external_id}/    create or update (PUT is an alias)
//! DELETE /v1/host/{external_id}/[?vault=]
//! GET    /v1/groups/[?vault=]
//! GET    /v1/group/{external_id}/[?vault=]
//! POST   /v1/group/{external_id}/   create or update (PUT is an alias)
//! DELETE /v1/group/{external_id}/[?vault=]
//! ```
//!
//! Paths are accepted with and without the trailing slash.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::bridge::Bridge;
use crate::error::{BridgeError, Result};
use crate::model::{GroupRequest, HostRequest, IdentityRequest, KeyRequest, SnippetRequest};

const MAX_BODY: usize = 256 * 1024;

#[derive(Clone)]
pub struct RestConfig {
    /// Optional shared secret callers must send as `Authorization: Bearer …`
    /// or `X-Api-Key`. `None` = no local auth (trust the network).
    pub api_key: Option<String>,
    /// Sustained `/v1` requests per second (token bucket, burst = 2×). `0`
    /// disables the limiter.
    pub rate_limit: u32,
}

impl Default for RestConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            rate_limit: DEFAULT_RATE_LIMIT,
        }
    }
}

pub const DEFAULT_RATE_LIMIT: u32 = 50;

#[derive(Clone)]
struct App {
    bridge: Arc<Bridge>,
    api_key: Option<Arc<str>>,
    bucket: Option<Arc<Mutex<Bucket>>>,
}

/// Token bucket shared by every caller: the bridge fronts one account, and
/// the budget protects the central server (and the mirror lock) from a
/// runaway automation, not one tenant from another.
struct Bucket {
    tokens: f64,
    per_second: f64,
    burst: f64,
    last: Instant,
}

impl Bucket {
    fn new(per_second: u32) -> Self {
        let per_second = f64::from(per_second);
        Self {
            tokens: per_second * 2.0,
            per_second,
            burst: per_second * 2.0,
            last: Instant::now(),
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_second).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Build the REST router.
pub fn router(bridge: Arc<Bridge>, cfg: RestConfig) -> Router {
    let app = App {
        bridge,
        api_key: cfg.api_key.map(Into::into),
        bucket: (cfg.rate_limit > 0).then(|| Arc::new(Mutex::new(Bucket::new(cfg.rate_limit)))),
    };
    let mut v1 = Router::new();
    v1 = both(v1, "/v1/bridge/me", get(me));
    v1 = both(v1, "/v1/sync", post(sync));
    v1 = both(v1, "/v1/vaults", get(vaults));
    v1 = both(v1, "/v1/hosts", get(list_hosts));
    v1 = both(
        v1,
        "/v1/host/{external_id}",
        get(get_host)
            .post(put_host)
            .put(put_host)
            .delete(delete_host),
    );
    v1 = both(v1, "/v1/groups", get(list_groups));
    v1 = both(
        v1,
        "/v1/group/{external_id}",
        get(get_group)
            .post(put_group)
            .put(put_group)
            .delete(delete_group),
    );
    v1 = both(v1, "/v1/snippets", get(list_snippets));
    v1 = both(
        v1,
        "/v1/snippet/{external_id}",
        get(get_snippet)
            .post(put_snippet)
            .put(put_snippet)
            .delete(delete_snippet),
    );
    v1 = both(v1, "/v1/identities", get(list_identities));
    v1 = both(
        v1,
        "/v1/identity/{external_id}",
        get(get_identity)
            .post(put_identity)
            .put(put_identity)
            .delete(delete_identity),
    );
    v1 = both(v1, "/v1/keys", get(list_keys));
    v1 = both(
        v1,
        "/v1/key/{external_id}",
        get(get_key).post(put_key).put(put_key).delete(delete_key),
    );
    // Outermost first: unauthenticated hammering burns the budget too.
    let v1 = v1
        .layer(middleware::from_fn_with_state(app.clone(), require_key))
        .layer(middleware::from_fn_with_state(app.clone(), rate_limit));

    Router::new()
        .route("/", get(me))
        .route("/healthz", get(healthz))
        .merge(v1)
        .fallback(not_found)
        .layer(RequestBodyLimitLayer::new(MAX_BODY))
        .layer((
            TraceLayer::new_for_http(),
            TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(60)),
        ))
        .with_state(app)
}

fn both(r: Router<App>, path: &str, mr: MethodRouter<App>) -> Router<App> {
    r.route(path, mr.clone()).route(&format!("{path}/"), mr)
}

async fn require_key(State(app): State<App>, req: Request, next: Next) -> Response {
    if let Some(key) = &app.api_key
        && !presented(req.headers(), key)
    {
        return BridgeError::Unauthorized.into_response();
    }
    next.run(req).await
}

async fn rate_limit(State(app): State<App>, req: Request, next: Next) -> Response {
    if let Some(b) = &app.bucket {
        let allowed = b
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take(Instant::now());
        if !allowed {
            return BridgeError::RateLimited.into_response();
        }
    }
    next.run(req).await
}

fn presented(headers: &HeaderMap, key: &str) -> bool {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    let x_key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    [bearer, x_key]
        .into_iter()
        .flatten()
        .any(|p| p.as_bytes().ct_eq(key.as_bytes()).into())
}

async fn list_snippets(State(app): State<App>, Query(q): Query<VaultQuery>) -> Result<Response> {
    Ok(Json(app.bridge.list_snippets(q.vault.as_deref()).await?).into_response())
}

async fn get_snippet(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Query(q): Query<VaultQuery>,
) -> Result<Response> {
    match app
        .bridge
        .get_snippet(&external_id, q.vault.as_deref())
        .await?
    {
        Some(x) => Ok(Json(x).into_response()),
        None => Err(BridgeError::NotFound(format!(
            "snippet '{external_id}' not found"
        ))),
    }
}

async fn put_snippet(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Body(req): Body<SnippetRequest>,
) -> Result<Response> {
    Ok(Json(app.bridge.upsert_snippet(&external_id, req).await?).into_response())
}

async fn delete_snippet(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Query(q): Query<VaultQuery>,
) -> Result<Response> {
    if app
        .bridge
        .delete_snippet(&external_id, q.vault.as_deref())
        .await?
    {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(BridgeError::NotFound(format!(
            "snippet '{external_id}' not found"
        )))
    }
}

async fn list_identities(State(app): State<App>, Query(q): Query<VaultQuery>) -> Result<Response> {
    Ok(Json(app.bridge.list_identities(q.vault.as_deref()).await?).into_response())
}

async fn get_identity(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Query(q): Query<VaultQuery>,
) -> Result<Response> {
    match app
        .bridge
        .get_identity(&external_id, q.vault.as_deref())
        .await?
    {
        Some(x) => Ok(Json(x).into_response()),
        None => Err(BridgeError::NotFound(format!(
            "identity '{external_id}' not found"
        ))),
    }
}

async fn put_identity(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Body(req): Body<IdentityRequest>,
) -> Result<Response> {
    Ok(Json(app.bridge.upsert_identity(&external_id, req).await?).into_response())
}

async fn delete_identity(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Query(q): Query<VaultQuery>,
) -> Result<Response> {
    if app
        .bridge
        .delete_identity(&external_id, q.vault.as_deref())
        .await?
    {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(BridgeError::NotFound(format!(
            "identity '{external_id}' not found"
        )))
    }
}

async fn list_keys(State(app): State<App>, Query(q): Query<VaultQuery>) -> Result<Response> {
    Ok(Json(app.bridge.list_keys(q.vault.as_deref()).await?).into_response())
}

async fn get_key(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Query(q): Query<VaultQuery>,
) -> Result<Response> {
    match app.bridge.get_key(&external_id, q.vault.as_deref()).await? {
        Some(x) => Ok(Json(x).into_response()),
        None => Err(BridgeError::NotFound(format!(
            "key '{external_id}' not found"
        ))),
    }
}

async fn put_key(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Body(req): Body<KeyRequest>,
) -> Result<Response> {
    Ok(Json(app.bridge.upsert_key(&external_id, req).await?).into_response())
}

async fn delete_key(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Query(q): Query<VaultQuery>,
) -> Result<Response> {
    if app
        .bridge
        .delete_key(&external_id, q.vault.as_deref())
        .await?
    {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(BridgeError::NotFound(format!(
            "key '{external_id}' not found"
        )))
    }
}

#[derive(Deserialize, Default)]
struct VaultQuery {
    #[serde(default)]
    vault: Option<String>,
}

/// `Json` with the bridge's error envelope instead of axum's plaintext one.
struct Body<T>(T);

impl<S, T> FromRequest<S> for Body<T>
where
    S: Send + Sync,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = BridgeError;

    async fn from_request(req: Request, state: &S) -> std::result::Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Body(v)),
            Err(e) => Err(BridgeError::Invalid(e.body_text())),
        }
    }
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

async fn not_found() -> Response {
    BridgeError::NotFound("no such route".into()).into_response()
}

async fn me(State(app): State<App>) -> Response {
    Json(app.bridge.status().await).into_response()
}

async fn sync(State(app): State<App>) -> Result<Response> {
    Ok(Json(app.bridge.sync().await?).into_response())
}

async fn vaults(State(app): State<App>) -> Response {
    Json(app.bridge.status().await.vaults).into_response()
}

async fn list_hosts(State(app): State<App>, Query(q): Query<VaultQuery>) -> Result<Response> {
    Ok(Json(app.bridge.list_hosts(q.vault.as_deref()).await?).into_response())
}

async fn get_host(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Query(q): Query<VaultQuery>,
) -> Result<Response> {
    match app
        .bridge
        .get_host(&external_id, q.vault.as_deref())
        .await?
    {
        Some(h) => Ok(Json(h).into_response()),
        None => Err(BridgeError::NotFound(format!(
            "host '{external_id}' not found"
        ))),
    }
}

async fn put_host(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Body(req): Body<HostRequest>,
) -> Result<Response> {
    Ok(Json(app.bridge.upsert_host(&external_id, req).await?).into_response())
}

async fn delete_host(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Query(q): Query<VaultQuery>,
) -> Result<Response> {
    if app
        .bridge
        .delete_host(&external_id, q.vault.as_deref())
        .await?
    {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(BridgeError::NotFound(format!(
            "host '{external_id}' not found"
        )))
    }
}

async fn list_groups(State(app): State<App>, Query(q): Query<VaultQuery>) -> Result<Response> {
    Ok(Json(app.bridge.list_groups(q.vault.as_deref()).await?).into_response())
}

async fn get_group(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Query(q): Query<VaultQuery>,
) -> Result<Response> {
    let groups = app.bridge.list_groups(q.vault.as_deref()).await?;
    let hits: Vec<_> = groups
        .into_iter()
        .filter(|g| g.external_id == external_id.trim())
        .collect();
    match hits.len() {
        0 => Err(BridgeError::NotFound(format!(
            "group '{external_id}' not found"
        ))),
        1 => Ok(Json(&hits[0]).into_response()),
        _ => Err(BridgeError::Invalid(format!(
            "group '{external_id}' exists in several vaults; pass `?vault=`"
        ))),
    }
}

async fn put_group(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Body(req): Body<GroupRequest>,
) -> Result<Response> {
    Ok(Json(app.bridge.upsert_group(&external_id, req).await?).into_response())
}

async fn delete_group(
    State(app): State<App>,
    Path(external_id): Path<String>,
    Query(q): Query<VaultQuery>,
) -> Result<Response> {
    if app
        .bridge
        .delete_group(&external_id, q.vault.as_deref())
        .await?
    {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(BridgeError::NotFound(format!(
            "group '{external_id}' not found"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_refills_at_the_configured_rate() {
        let t0 = Instant::now();
        let mut b = Bucket::new(10);
        // Burst of 2× the rate, then dry.
        assert!((0..20).all(|_| b.take(t0)));
        assert!(!b.take(t0));
        // Half a second later five more tokens are back, no more.
        let t1 = t0 + Duration::from_millis(500);
        assert!((0..5).all(|_| b.take(t1)));
        assert!(!b.take(t1));
        // The bucket never overflows its burst.
        let t2 = t1 + Duration::from_secs(60);
        assert!((0..20).all(|_| b.take(t2)));
        assert!(!b.take(t2));
    }
}
