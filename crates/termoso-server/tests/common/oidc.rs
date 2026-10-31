//! Minimal OpenID Connect provider for tests: discovery, JWKS and a token
//! endpoint that mints RS256 ID tokens. There is no login page — the test
//! drives the callback itself, and the `code` it presents carries the claims
//! the provider should assert (see [`code_for`]).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

pub const CLIENT_ID: &str = "termoso-test";
pub const CLIENT_SECRET: &str = "termoso-test-secret";
const KID: &str = "test-key";

/// What the provider will assert about the "signed in" user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    /// Nonce taken from the authorization URL, echoed into the ID token.
    pub nonce: String,
    /// `groups` claim (empty = claim omitted).
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Encode an identity into an opaque authorization code.
pub fn code_for(id: &Identity) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(id).expect("json"))
}

struct Idp {
    issuer: String,
    key: RsaPrivateKey,
}

#[derive(Clone)]
pub struct MockIdp {
    pub issuer: String,
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: String,
    #[allow(dead_code)]
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn client_ok(headers: &HeaderMap, form: &TokenForm) -> bool {
    if let Some(v) = headers.get("authorization").and_then(|v| v.to_str().ok())
        && let Some(b) = v.strip_prefix("Basic ")
        && let Ok(raw) = STANDARD.decode(b.trim())
    {
        return raw == format!("{CLIENT_ID}:{CLIENT_SECRET}").as_bytes();
    }
    form.client_id.as_deref() == Some(CLIENT_ID)
        && form.client_secret.as_deref() == Some(CLIENT_SECRET)
}

async fn discovery(State(idp): State<Arc<Idp>>) -> Json<serde_json::Value> {
    let i = &idp.issuer;
    Json(serde_json::json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/authorize"),
        "token_endpoint": format!("{i}/token"),
        "jwks_uri": format!("{i}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": ["sub", "email", "email_verified", "name"],
    }))
}

async fn jwks(State(idp): State<Arc<Idp>>) -> Json<serde_json::Value> {
    let pk = RsaPublicKey::from(&idp.key);
    Json(serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KID,
            "n": b64url(&pk.n().to_bytes_be()),
            "e": b64url(&pk.e().to_bytes_be()),
        }]
    }))
}

async fn token(
    State(idp): State<Arc<Idp>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let reject = |e: &str| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
    };
    if !client_ok(&headers, &form) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_client" })),
        ));
    }
    if form.grant_type != "authorization_code" {
        return Err(reject("unsupported_grant_type"));
    }
    if form.code_verifier.as_deref().is_none_or(str::is_empty) {
        return Err(reject("invalid_request"));
    }
    let id: Identity = URL_SAFE_NO_PAD
        .decode(&form.code)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| reject("invalid_grant"))?;

    let now = chrono::Utc::now().timestamp();
    let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": KID });
    let mut claims = serde_json::json!({
        "iss": idp.issuer,
        "sub": id.sub,
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 300,
        "nonce": id.nonce,
        "email": id.email,
        "email_verified": id.email_verified,
    });
    if let Some(n) = &id.name {
        claims["name"] = serde_json::Value::String(n.clone());
    }
    if !id.groups.is_empty() {
        claims["groups"] = serde_json::json!(id.groups);
    }
    let signing_input = format!(
        "{}.{}",
        b64url(&serde_json::to_vec(&header).expect("json")),
        b64url(&serde_json::to_vec(&claims).expect("json"))
    );
    let sig = SigningKey::<Sha256>::new(idp.key.clone()).sign(signing_input.as_bytes());
    let id_token = format!("{signing_input}.{}", b64url(&sig.to_bytes()));
    Ok(Json(serde_json::json!({
        "access_token": format!("at-{}", id.sub),
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token,
    })))
}

/// Serve the provider on an already-bound listener (must be called on the
/// runtime that will keep running for the whole test binary).
pub async fn serve(listener: std::net::TcpListener) -> anyhow::Result<MockIdp> {
    let issuer = format!("http://{}", listener.local_addr()?);
    let key = RsaPrivateKey::new(&mut rand_core::OsRng, 2048)?;
    let idp = Arc::new(Idp {
        issuer: issuer.clone(),
        key,
    });
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(idp);
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock idp");
    });
    Ok(MockIdp { issuer })
}
