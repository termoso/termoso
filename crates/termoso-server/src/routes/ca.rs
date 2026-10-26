//! Team SSH certificate authority (`ca.manage` / `ca.issue`).
//!
//! One Ed25519 CA key per team, sealed at rest with the server master key.
//! Members ask the server to sign their device's public key and get a
//! short-lived user certificate; hosts need a single `TrustedUserCAKeys`
//! line (served publicly at `/ca/{team_id}`) and never see per-user keys.

use std::time::{Duration as StdDuration, SystemTime};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Duration, Utc};
use sqlx::PgExecutor;
use ssh_key::certificate::{Builder, CertType};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey, PublicKey};
use termoso_proto::ca::*;
use termoso_proto::sshid::SshIdKeyType;
use uuid::Uuid;

use crate::audit;
use crate::error::{ApiResult, Error, NoContent};
use crate::extract::{Auth, Json as Body};
use crate::policy;
use crate::state::AppState;

pub const MANAGE: &str = "ca.manage";
pub const ISSUE: &str = "ca.issue";
const CA_KEY_TYPE: &str = "ssh-ed25519";
/// Certificates are valid from a minute ago so a host with a slightly slow
/// clock accepts them right away.
const CLOCK_SKEW: Duration = Duration::minutes(1);
/// Trusted-keys text may be cached by provisioning tooling for this long.
const TRUSTED_KEYS_MAX_AGE: u32 = 300;

fn purpose(team_id: Uuid) -> String {
    format!("team_ssh_ca:{team_id}")
}

pub fn trusted_keys_url(state: &AppState, team_id: Uuid) -> String {
    format!(
        "{}/ca/{team_id}",
        state.cfg.public_url.trim_end_matches('/')
    )
}

type CaTuple = (
    String,
    String,
    Vec<u8>,
    Vec<String>,
    i32,
    Vec<String>,
    bool,
    Option<String>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
);

struct Ca {
    key_type: String,
    public_key: String,
    private_key_enc: Vec<u8>,
    principals: Vec<String>,
    ttl_hours: i32,
    extensions: Vec<String>,
    enabled: bool,
    retired_public_key: Option<String>,
    retired_until: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    rotated_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

const SELECT: &str =
    "SELECT key_type, public_key, private_key_enc, principals, ttl_hours, extensions, enabled,
        retired_public_key, retired_until, created_at, rotated_at, updated_at
    FROM team_ssh_cas WHERE team_id = $1";

async fn load<'e, E: PgExecutor<'e>>(db: E, team_id: Uuid) -> ApiResult<Option<Ca>> {
    let row: Option<CaTuple> = sqlx::query_as(SELECT)
        .bind(team_id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| Ca {
        key_type: r.0,
        public_key: r.1,
        private_key_enc: r.2,
        principals: r.3,
        ttl_hours: r.4,
        extensions: r.5,
        enabled: r.6,
        retired_public_key: r.7,
        retired_until: r.8,
        created_at: r.9,
        rotated_at: r.10,
        updated_at: r.11,
    }))
}

async fn require_ca(state: &AppState, team_id: Uuid) -> ApiResult<Ca> {
    load(&state.db, team_id)
        .await?
        .ok_or_else(|| Error::not_found("ssh ca"))
}

fn fingerprint(line: &str) -> String {
    PublicKey::from_openssh(line)
        .map(|k| k.fingerprint(HashAlg::Sha256).to_string())
        .unwrap_or_default()
}

async fn view(state: &AppState, team_id: Uuid, ca: &Ca) -> ApiResult<TeamCa> {
    let (active,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM team_ssh_certs
         WHERE team_id = $1 AND revoked_at IS NULL AND valid_before > now()",
    )
    .bind(team_id)
    .fetch_one(&state.db)
    .await?;
    let retired = ca
        .retired_until
        .filter(|until| *until > Utc::now())
        .and(ca.retired_public_key.clone());
    Ok(TeamCa {
        team_id,
        key_type: ca.key_type.clone(),
        public_key: ca.public_key.clone(),
        fingerprint: fingerprint(&ca.public_key),
        principals: ca.principals.clone(),
        ttl_hours: ca.ttl_hours,
        extensions: ca.extensions.clone(),
        enabled: ca.enabled,
        retired_until: retired.as_ref().and(ca.retired_until),
        retired_public_key: retired,
        trusted_keys_url: trusted_keys_url(state, team_id),
        active_certificates: active,
        created_at: ca.created_at,
        rotated_at: ca.rotated_at,
        updated_at: ca.updated_at,
    })
}

/// A fresh Ed25519 CA key: (`TrustedUserCAKeys` line, sealed private key PEM).
fn generate_key(state: &AppState, team_id: Uuid) -> ApiResult<(String, Vec<u8>)> {
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    termoso_crypto::random_bytes(&mut seed[..]);
    let mut key = PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&seed));
    key.set_comment(format!("termoso-ca-{team_id}"));
    let public = key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("ca public key: {e}"))?;
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("ca private key: {e}"))?;
    let sealed = state.encrypt_secret(&purpose(team_id), pem.as_bytes())?;
    Ok((public, sealed))
}

fn validate_principals(list: &[String]) -> ApiResult<Vec<String>> {
    if list.len() > PRINCIPALS_MAX {
        return Err(Error::bad_request(format!(
            "At most {PRINCIPALS_MAX} principals"
        )));
    }
    let mut out: Vec<String> = Vec::with_capacity(list.len());
    for p in list {
        let p = p.trim();
        if !valid_principal(p) {
            return Err(Error::bad_request(format!(
                "`{p}` is not a valid login name (lowercase letters, digits, `_`, `-`; 32 characters at most)"
            )));
        }
        if !out.iter().any(|o| o == p) {
            out.push(p.to_string());
        }
    }
    Ok(out)
}

fn validate_extensions(list: &[String]) -> ApiResult<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for e in list {
        let e = e.trim();
        if !EXTENSIONS.contains(&e) {
            return Err(Error::bad_request(format!(
                "Unknown extension `{e}`; known: {}",
                EXTENSIONS.join(", ")
            )));
        }
        if !out.iter().any(|o| o == e) {
            out.push(e.to_string());
        }
    }
    Ok(out)
}

fn validate_ttl(h: i32) -> ApiResult<i32> {
    if (TTL_HOURS_MIN..=TTL_HOURS_MAX).contains(&h) {
        Ok(h)
    } else {
        Err(Error::bad_request(format!(
            "ttl_hours must be {TTL_HOURS_MIN}..={TTL_HOURS_MAX}"
        )))
    }
}

#[utoipa::path(get, path = "/api/v1/teams/{id}/ca", tag = "teams", params(("id" = Uuid, Path)),
    responses((status = 200, body = TeamCa), (status = 404, description = "No CA yet")))]
pub async fn get(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TeamCa>> {
    crate::authz::require(&state, id, auth.user_id(), "team.view").await?;
    let ca = require_ca(&state, id).await?;
    Ok(Json(view(&state, id, &ca).await?))
}

#[utoipa::path(put, path = "/api/v1/teams/{id}/ca", tag = "teams", params(("id" = Uuid, Path)),
    request_body = UpdateTeamCaRequest, responses((status = 200, body = TeamCa)))]
pub async fn put(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<UpdateTeamCaRequest>,
) -> ApiResult<Json<TeamCa>> {
    crate::authz::require(&state, id, auth.user_id(), MANAGE).await?;
    let principals = req
        .principals
        .as_deref()
        .map(validate_principals)
        .transpose()?;
    let extensions = req
        .extensions
        .as_deref()
        .map(validate_extensions)
        .transpose()?;
    let ttl = req.ttl_hours.map(validate_ttl).transpose()?;

    let existing = load(&state.db, id).await?;
    let action = match existing {
        None => {
            let (public_key, sealed) = generate_key(&state, id)?;
            let principals = principals.unwrap_or_default();
            let extensions = extensions
                .unwrap_or_else(|| EXTENSIONS_DEFAULT.iter().map(|s| s.to_string()).collect());
            sqlx::query(
                "INSERT INTO team_ssh_cas (team_id, key_type, public_key, private_key_enc, principals,
                    ttl_hours, extensions, enabled)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(id)
            .bind(CA_KEY_TYPE)
            .bind(&public_key)
            .bind(&sealed)
            .bind(&principals)
            .bind(ttl.unwrap_or(TTL_HOURS_DEFAULT))
            .bind(&extensions)
            .bind(req.enabled.unwrap_or(true))
            .execute(&state.db)
            .await?;
            "ca.created"
        }
        Some(ca) => {
            sqlx::query(
                "UPDATE team_ssh_cas SET principals = $2, ttl_hours = $3, extensions = $4, enabled = $5,
                    updated_at = now()
                 WHERE team_id = $1",
            )
            .bind(id)
            .bind(principals.as_ref().unwrap_or(&ca.principals))
            .bind(ttl.unwrap_or(ca.ttl_hours))
            .bind(extensions.as_ref().unwrap_or(&ca.extensions))
            .bind(req.enabled.unwrap_or(ca.enabled))
            .execute(&state.db)
            .await?;
            if req.enabled == Some(false) && ca.enabled {
                "ca.disabled"
            } else {
                "ca.updated"
            }
        }
    };
    let ca = require_ca(&state, id).await?;
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, action).details(serde_json::json!({
            "fingerprint": fingerprint(&ca.public_key),
            "principals": ca.principals,
            "ttl_hours": ca.ttl_hours,
            "extensions": ca.extensions,
            "enabled": ca.enabled,
        })),
    )
    .await;
    Ok(Json(view(&state, id, &ca).await?))
}

/// Delete the CA and every certificate record. Hosts that still trust the
/// key keep accepting unexpired certificates until they expire.
#[utoipa::path(delete, path = "/api/v1/teams/{id}/ca", tag = "teams", params(("id" = Uuid, Path)),
    responses((status = 204)))]
pub async fn delete(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<NoContent> {
    crate::authz::require(&state, id, auth.user_id(), MANAGE).await?;
    let ca = require_ca(&state, id).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM team_ssh_certs WHERE team_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM team_ssh_cas WHERE team_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "ca.deleted")
            .details(serde_json::json!({ "fingerprint": fingerprint(&ca.public_key) })),
    )
    .await;
    Ok(NoContent)
}

#[utoipa::path(post, path = "/api/v1/teams/{id}/ca/rotate", tag = "teams", params(("id" = Uuid, Path)),
    request_body = RotateTeamCaRequest, responses((status = 200, body = TeamCa)))]
pub async fn rotate(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<RotateTeamCaRequest>,
) -> ApiResult<Json<TeamCa>> {
    crate::authz::require(&state, id, auth.user_id(), MANAGE).await?;
    let grace = req.grace_hours.unwrap_or(ROTATION_GRACE_HOURS_DEFAULT);
    if !(0..=ROTATION_GRACE_HOURS_MAX).contains(&grace) {
        return Err(Error::bad_request(format!(
            "grace_hours must be 0..={ROTATION_GRACE_HOURS_MAX}"
        )));
    }
    let old = require_ca(&state, id).await?;
    let (public_key, sealed) = generate_key(&state, id)?;
    sqlx::query(
        "UPDATE team_ssh_cas SET public_key = $2, private_key_enc = $3, retired_public_key = $4,
            retired_until = now() + make_interval(hours => $5), rotated_at = now(), updated_at = now()
         WHERE team_id = $1",
    )
    .bind(id)
    .bind(&public_key)
    .bind(&sealed)
    .bind(&old.public_key)
    .bind(grace)
    .execute(&state.db)
    .await?;
    let ca = require_ca(&state, id).await?;
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "ca.rotated").details(serde_json::json!({
            "fingerprint": fingerprint(&ca.public_key),
            "retired_fingerprint": fingerprint(&old.public_key),
            "grace_hours": grace,
        })),
    )
    .await;
    Ok(Json(view(&state, id, &ca).await?))
}

fn key_type_of(key: &PublicKey) -> ApiResult<SshIdKeyType> {
    match key.algorithm() {
        Algorithm::Ed25519 => Ok(SshIdKeyType::Ed25519),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        } => Ok(SshIdKeyType::Ecdsa),
        Algorithm::Rsa { .. } => {
            let bits = key
                .key_data()
                .rsa()
                .and_then(|r| r.n().as_positive_bytes())
                .map_or(0, |b| b.len() * 8);
            if bits < 2048 {
                return Err(Error::bad_request("RSA keys must be at least 2048 bits"));
            }
            Ok(SshIdKeyType::Rsa)
        }
        other => Err(Error::bad_request(format!(
            "Certificates are issued for ed25519, ecdsa-sha2-nistp256 and rsa keys, not {other}"
        ))),
    }
}

type CertTuple = (
    Uuid,
    Uuid,
    Uuid,
    String,
    Option<Uuid>,
    Option<String>,
    i64,
    String,
    String,
    String,
    Vec<String>,
    DateTime<Utc>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
);

macro_rules! select_cert {
    ($tail:literal) => {
        concat!(
            "SELECT c.id, c.team_id, c.user_id, u.email, c.device_id, d.name, c.serial, c.key_type,
                c.key_fingerprint, c.key_id, c.principals, c.valid_after, c.valid_before, c.revoked_at, c.created_at
             FROM team_ssh_certs c JOIN users u ON u.id = c.user_id LEFT JOIN devices d ON d.id = c.device_id",
            $tail
        )
    };
}

fn to_cert(r: CertTuple, me: Uuid) -> IssuedCertificate {
    let now = Utc::now();
    IssuedCertificate {
        id: r.0,
        team_id: r.1,
        user_id: r.2,
        user_email: r.3,
        current_device: r.4 == Some(me),
        device_id: r.4,
        device_name: r.5,
        serial: r.6,
        key_type: SshIdKeyType::from_wire_name(&r.7).unwrap_or(SshIdKeyType::Ed25519),
        key_fingerprint: r.8,
        key_id: r.9,
        principals: r.10,
        valid_after: r.11,
        valid_before: r.12,
        active: r.13.is_none() && r.12 > now && r.11 <= now,
        revoked_at: r.13,
        created_at: r.14,
    }
}

#[utoipa::path(post, path = "/api/v1/teams/{id}/ca/issue", tag = "teams", params(("id" = Uuid, Path)),
    request_body = IssueCertificateRequest, responses((status = 200, body = IssueCertificateResponse)))]
pub async fn issue(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<IssueCertificateRequest>,
) -> ApiResult<Json<IssueCertificateResponse>> {
    crate::authz::require(&state, id, auth.user_id(), ISSUE).await?;
    let ca = require_ca(&state, id).await?;
    if !ca.enabled {
        return Err(Error::conflict("The team CA is disabled"));
    }
    if ca.principals.is_empty() {
        return Err(Error::conflict(
            "The team CA has no principals (login names) configured yet",
        ));
    }
    let policies = policy::load(&state.db, id).await?;
    if policies.device_admin_approval {
        let status: Option<(String,)> = sqlx::query_as(
            "SELECT status FROM team_device_approvals WHERE team_id = $1 AND device_id = $2",
        )
        .bind(id)
        .bind(auth.device_id())
        .fetch_optional(&state.db)
        .await?;
        if status.as_ref().map(|s| s.0.as_str()) != Some("approved") {
            return Err(Error::forbidden(
                "This device has not been approved by a team admin",
            ));
        }
    }

    let line = req.public_key.trim();
    if line.len() > 8192 {
        return Err(Error::too_large("Public key is too large"));
    }
    let key = PublicKey::from_openssh(line)
        .map_err(|e| Error::bad_request(format!("Public key is not a valid OpenSSH line: {e}")))?;
    let key_type = key_type_of(&key)?;
    let principals = if req.principals.is_empty() {
        ca.principals.clone()
    } else {
        let asked = validate_principals(&req.principals)?;
        if let Some(bad) = asked.iter().find(|p| !ca.principals.contains(p)) {
            return Err(Error::bad_request(format!(
                "`{bad}` is not a principal this team issues certificates for"
            )));
        }
        asked
    };

    let me = crate::users::by_id(&state.db, auth.user_id()).await?;
    let (device_name,): (String,) = sqlx::query_as("SELECT name FROM devices WHERE id = $1")
        .bind(auth.device_id())
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| Error::not_found("device"))?;
    let (team_name,): (String,) = sqlx::query_as("SELECT name FROM teams WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await?;
    let (serial,): (i64,) = sqlx::query_as("SELECT nextval('team_ssh_cert_serial_seq')")
        .fetch_one(&state.db)
        .await?;

    let now = Utc::now();
    let valid_after = now - CLOCK_SKEW;
    let valid_before = now + Duration::hours(ca.ttl_hours as i64);
    let key_id = format!("{}/{}/{}", me.email, device_name, team_name);
    let certificate = sign(
        &state,
        id,
        &ca,
        &key,
        serial as u64,
        &key_id,
        &principals,
        valid_after,
        valid_before,
    )?;
    let cert_id = Uuid::new_v4();
    let key_fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    sqlx::query(
        "INSERT INTO team_ssh_certs (id, team_id, user_id, device_id, serial, key_type, key_fingerprint,
            key_id, principals, valid_after, valid_before)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(cert_id)
    .bind(id)
    .bind(auth.user_id())
    .bind(auth.device_id())
    .bind(serial)
    .bind(key_type.wire_name())
    .bind(&key_fingerprint)
    .bind(&key_id)
    .bind(&principals)
    .bind(valid_after)
    .bind(valid_before)
    .execute(&state.db)
    .await?;
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "ca.issued").details(serde_json::json!({
            "certificate_id": cert_id,
            "serial": serial,
            "key_fingerprint": key_fingerprint,
            "principals": principals,
            "valid_before": valid_before,
        })),
    )
    .await;
    metrics::counter!("termoso_ssh_ca_certificates_issued_total").increment(1);
    let row: CertTuple = sqlx::query_as(select_cert!(" WHERE c.id = $1"))
        .bind(cert_id)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(IssueCertificateResponse {
        certificate,
        ca_public_key: ca.public_key.clone(),
        issued: to_cert(row, auth.device_id()),
    }))
}

#[allow(clippy::too_many_arguments)]
fn sign(
    state: &AppState,
    team_id: Uuid,
    ca: &Ca,
    key: &PublicKey,
    serial: u64,
    key_id: &str,
    principals: &[String],
    valid_after: DateTime<Utc>,
    valid_before: DateTime<Utc>,
) -> ApiResult<String> {
    let pem =
        zeroize::Zeroizing::new(state.decrypt_secret(&purpose(team_id), &ca.private_key_enc)?);
    let pem = std::str::from_utf8(&pem).map_err(|_| anyhow::anyhow!("ca key is not utf-8"))?;
    let signing = PrivateKey::from_openssh(pem).map_err(|e| anyhow::anyhow!("ca key: {e}"))?;
    let mut nonce = [0u8; 32];
    termoso_crypto::random_bytes(&mut nonce);
    let to_time = |t: DateTime<Utc>| {
        SystemTime::UNIX_EPOCH + StdDuration::from_secs(t.timestamp().max(0) as u64)
    };
    let mut b = Builder::new_with_validity_times(
        nonce.to_vec(),
        key.key_data().clone(),
        to_time(valid_after),
        to_time(valid_before),
    )
    .map_err(|e| anyhow::anyhow!("certificate: {e}"))?;
    b.serial(serial)
        .and_then(|b| b.cert_type(CertType::User))
        .and_then(|b| b.key_id(key_id))
        .map_err(|e| anyhow::anyhow!("certificate: {e}"))?;
    for p in principals {
        b.valid_principal(p.as_str())
            .map_err(|e| anyhow::anyhow!("certificate principal: {e}"))?;
    }
    for e in &ca.extensions {
        b.extension(e.as_str(), "")
            .map_err(|e| anyhow::anyhow!("certificate extension: {e}"))?;
    }
    let cert = b
        .sign(&signing)
        .map_err(|e| anyhow::anyhow!("certificate signing: {e}"))?;
    cert.to_openssh()
        .map_err(|e| anyhow::anyhow!("certificate encoding: {e}").into())
}

/// Admins (`ca.manage`) see every certificate, other members their own.
#[utoipa::path(get, path = "/api/v1/teams/{id}/ca/certificates", tag = "teams", params(("id" = Uuid, Path)),
    responses((status = 200, body = IssuedCertificateList)))]
pub async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<IssuedCertificateList>> {
    let m = crate::authz::require(&state, id, auth.user_id(), "team.view").await?;
    let rows: Vec<CertTuple> = if m.has(MANAGE) {
        sqlx::query_as(select_cert!(
            " WHERE c.team_id = $1 ORDER BY c.created_at DESC LIMIT 1000"
        ))
        .bind(id)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as(select_cert!(
            " WHERE c.team_id = $1 AND c.user_id = $2 ORDER BY c.created_at DESC LIMIT 1000"
        ))
        .bind(id)
        .bind(auth.user_id())
        .fetch_all(&state.db)
        .await?
    };
    let me = auth.device_id();
    Ok(Json(IssuedCertificateList {
        certificates: rows.into_iter().map(|r| to_cert(r, me)).collect(),
    }))
}

/// Revoke one certificate: `ca.manage`, or the member it was issued to.
#[utoipa::path(post, path = "/api/v1/teams/{id}/ca/certificates/{cid}/revoke", tag = "teams",
    params(("id" = Uuid, Path), ("cid" = Uuid, Path)), responses((status = 200, body = IssuedCertificate)))]
pub async fn revoke(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, cid)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<IssuedCertificate>> {
    let m = crate::authz::require(&state, id, auth.user_id(), "team.view").await?;
    let row: CertTuple = sqlx::query_as(select_cert!(" WHERE c.team_id = $1 AND c.id = $2"))
        .bind(id)
        .bind(cid)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| Error::not_found("certificate"))?;
    if row.2 != auth.user_id() && !m.has(MANAGE) {
        return Err(crate::authz::denied(MANAGE));
    }
    sqlx::query(
        "UPDATE team_ssh_certs SET revoked_at = now(), revoked_by = $3
         WHERE team_id = $1 AND id = $2 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(cid)
    .bind(auth.user_id())
    .execute(&state.db)
    .await?;
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "ca.revoked")
            .user(row.2)
            .details(serde_json::json!({ "certificate_id": cid, "serial": row.6 })),
    )
    .await;
    let row: CertTuple = sqlx::query_as(select_cert!(" WHERE c.id = $1"))
        .bind(cid)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(to_cert(row, auth.device_id())))
}

fn text(body: String, max_age: Option<u32>) -> Response {
    let mut resp = body.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if let Some(s) = max_age
        && let Ok(v) = HeaderValue::from_str(&format!("public, max-age={s}"))
    {
        resp.headers_mut().insert(header::CACHE_CONTROL, v);
    }
    resp
}

/// Revoked, not yet expired certificates as a KRL specification
/// (`ssh-keygen -k -f revoked.krl -s ca.pub spec.txt`), one `serial:` per line.
#[utoipa::path(get, path = "/api/v1/teams/{id}/ca/revoked", tag = "teams", params(("id" = Uuid, Path)),
    responses((status = 200, content_type = "text/plain")))]
pub async fn revoked(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    crate::authz::require(&state, id, auth.user_id(), "team.view").await?;
    require_ca(&state, id).await?;
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT serial, key_id FROM team_ssh_certs
         WHERE team_id = $1 AND revoked_at IS NOT NULL AND valid_before > now()
         ORDER BY serial",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    let mut out = String::from("# Termoso team CA: revoked certificates (KRL specification)\n");
    for (serial, key_id) in rows {
        out.push_str(&format!("# {key_id}\nserial: {serial}\n"));
    }
    Ok(text(out, None))
}

/// Public `TrustedUserCAKeys` text for the team: the current key and, after
/// a rotation, the previous one until its grace period ends. 404 without an
/// enabled CA. The key is public, the team id is not guessable.
#[utoipa::path(get, path = "/ca/{team_id}", tag = "teams", params(("team_id" = Uuid, Path)),
    security(()), responses((status = 200, content_type = "text/plain")))]
pub async fn trusted_keys(
    State(state): State<AppState>,
    Path(team_id): Path<Uuid>,
) -> ApiResult<Response> {
    let ca = load(&state.db, team_id)
        .await?
        .filter(|ca| ca.enabled)
        .ok_or_else(|| Error::not_found("ssh ca"))?;
    let mut out = format!(
        "# Termoso team CA — put this file in TrustedUserCAKeys (sshd_config)\n{}\n",
        ca.public_key
    );
    if let (Some(old), Some(until)) = (&ca.retired_public_key, ca.retired_until)
        && until > Utc::now()
    {
        out.push_str(&format!(
            "# previous key, trusted until {}\n{old}\n",
            until.to_rfc3339()
        ));
    }
    Ok(text(out, Some(TRUSTED_KEYS_MAX_AGE)))
}

/// A device is gone (revoked / logged out everywhere): its live certificates
/// are revoked so the KRL reflects it.
pub async fn forget_device(state: &AppState, device_id: Uuid) -> ApiResult<()> {
    sqlx::query(
        "UPDATE team_ssh_certs SET revoked_at = now()
         WHERE device_id = $1 AND revoked_at IS NULL AND valid_before > now()",
    )
    .bind(device_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// A member left the team: their live certificates are revoked.
pub async fn forget_member<'e, E: PgExecutor<'e>>(
    db: E,
    team_id: Uuid,
    user_id: Uuid,
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE team_ssh_certs SET revoked_at = now()
         WHERE team_id = $1 AND user_id = $2 AND revoked_at IS NULL AND valid_before > now()",
    )
    .bind(team_id)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}
