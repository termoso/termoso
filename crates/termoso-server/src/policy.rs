//! Team policies: MFA level, local-key prohibition (client-enforced), session
//! TTL, SSO-only domains and mandatory device approval. The strictest value
//! across a user's teams applies to them; the owner of a team is exempt from
//! its SSO-only rule so an owner can never lock themself out.

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, PgPool};
use std::collections::HashMap;
use termoso_proto::team::{EffectivePolicies, Team, TeamPolicies};
use uuid::Uuid;

use crate::error::ApiResult;

pub const MFA_LEVELS: &[&str] = &["off", "any", "passkey"];
pub const LOCAL_KEYS: &[&str] = &["allow", "deny"];
pub const MAX_SESSION_TTL_HOURS: i32 = 2160;
pub const MAX_DOMAINS: usize = 50;
pub const MIN_AUDIT_RETENTION_DAYS: i32 = 30;
pub const MAX_AUDIT_RETENTION_DAYS: i32 = 3650;
pub const SESSION_RECORDING: &[&str] = &["optional", "required"];
pub const MAX_LOG_RETENTION_DAYS: i32 = 3650;
pub const MAX_SECRET_AGE_DAYS: i32 = 3650;
pub const AUTH: &[&str] = &["any", "keys_only"];
pub const EXPORT: &[&str] = &["allow", "deny"];
pub const MAX_FORWARD_PORTS: usize = 100;

/// Validate a port allowlist: entries are `n` or `a-b` within 1..=65535,
/// trimmed and de-duplicated; an empty list means "any port".
pub fn normalize_forward_ports(list: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for raw in list {
        let e = raw.trim();
        if e.is_empty() {
            continue;
        }
        let port = |s: &str| -> Result<u16, String> {
            s.parse::<u16>()
                .ok()
                .filter(|p| *p >= 1)
                .ok_or_else(|| format!("forward_ports: `{e}` is not a port or range"))
        };
        let norm = match e.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (port(a.trim())?, port(b.trim())?);
                if a > b {
                    return Err(format!("forward_ports: `{e}` range is reversed"));
                }
                format!("{a}-{b}")
            }
            None => port(e)?.to_string(),
        };
        if !out.contains(&norm) {
            out.push(norm);
        }
    }
    if out.len() > MAX_FORWARD_PORTS {
        return Err(format!(
            "forward_ports holds at most {MAX_FORWARD_PORTS} entries"
        ));
    }
    Ok(out)
}

#[derive(sqlx::FromRow)]
struct Row {
    mfa: String,
    local_keys: String,
    session_ttl_hours: Option<i32>,
    sso_only: bool,
    sso_provider: Option<String>,
    sso_domains: Vec<String>,
    device_approval: bool,
    audit_retention_days: i32,
    session_recording: String,
    log_retention_days: i32,
    key_max_age_days: i32,
    password_max_age_days: i32,
    ip_allowlist: Vec<String>,
    device_admin_approval: bool,
    auth: String,
    jump_host_required: bool,
    export: String,
    offline_cache: String,
    forward_ports: Vec<String>,
    posture_disk_encryption: bool,
    posture_screen_lock: bool,
    posture_secure_key: bool,
    access_review_days: i32,
    updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct TeamRow {
    team_id: Uuid,
    #[sqlx(flatten)]
    row: Row,
}

macro_rules! policy_select {
    ($head:literal, $tail:literal) => {
        concat!(
            $head,
            "mfa, local_keys, session_ttl_hours, sso_only, sso_provider, sso_domains, device_approval, audit_retention_days, session_recording, log_retention_days, key_max_age_days, password_max_age_days, ip_allowlist, device_admin_approval, auth, jump_host_required, export, forward_ports, posture_disk_encryption, posture_screen_lock, posture_secure_key, access_review_days, offline_cache, updated_at",
            $tail
        )
    };
}

fn from_row(r: Row) -> TeamPolicies {
    TeamPolicies {
        mfa: r.mfa,
        local_keys: r.local_keys,
        session_ttl_hours: r.session_ttl_hours,
        sso_only: r.sso_only,
        sso_provider: r.sso_provider,
        sso_domains: r.sso_domains,
        device_approval: r.device_approval,
        audit_retention_days: r.audit_retention_days,
        session_recording: r.session_recording,
        log_retention_days: r.log_retention_days,
        key_max_age_days: r.key_max_age_days,
        password_max_age_days: r.password_max_age_days,
        ip_allowlist: r.ip_allowlist,
        device_admin_approval: r.device_admin_approval,
        auth: r.auth,
        jump_host_required: r.jump_host_required,
        export: r.export,
        offline_cache: r.offline_cache,
        forward_ports: r.forward_ports,
        posture_disk_encryption: r.posture_disk_encryption,
        posture_screen_lock: r.posture_screen_lock,
        posture_secure_key: r.posture_secure_key,
        access_review_days: r.access_review_days,
        updated_at: r.updated_at,
    }
}

pub fn defaults() -> TeamPolicies {
    TeamPolicies {
        mfa: "off".into(),
        local_keys: "allow".into(),
        session_ttl_hours: None,
        sso_only: false,
        sso_provider: None,
        sso_domains: Vec::new(),
        device_approval: false,
        audit_retention_days: 365,
        session_recording: "optional".into(),
        log_retention_days: 0,
        key_max_age_days: 0,
        password_max_age_days: 0,
        ip_allowlist: Vec::new(),
        device_admin_approval: false,
        auth: "any".into(),
        jump_host_required: false,
        export: "allow".into(),
        offline_cache: "allow".into(),
        forward_ports: Vec::new(),
        posture_disk_encryption: false,
        posture_screen_lock: false,
        posture_secure_key: false,
        access_review_days: 0,
        updated_at: Utc::now(),
    }
}

pub fn mfa_rank(level: &str) -> u8 {
    match level {
        "passkey" => 2,
        "any" => 1,
        _ => 0,
    }
}

/// Policies of one team (defaults when the row is missing).
pub async fn load<'e, E: PgExecutor<'e>>(db: E, team_id: Uuid) -> ApiResult<TeamPolicies> {
    let row: Option<Row> = sqlx::query_as(policy_select!(
        "SELECT ",
        " FROM team_policies WHERE team_id = $1"
    ))
    .bind(team_id)
    .fetch_optional(db)
    .await?;
    Ok(row.map(from_row).unwrap_or_else(defaults))
}

/// Fill `Team.policies` for a list of teams in one query.
pub async fn attach(db: &PgPool, teams: &mut [Team]) -> ApiResult<()> {
    if teams.is_empty() {
        return Ok(());
    }
    let ids: Vec<Uuid> = teams.iter().map(|t| t.id).collect();
    let rows: Vec<TeamRow> = sqlx::query_as(policy_select!(
        "SELECT team_id, ",
        " FROM team_policies WHERE team_id = ANY($1)"
    ))
    .bind(&ids)
    .fetch_all(db)
    .await?;
    let mut map: HashMap<Uuid, TeamPolicies> = rows
        .into_iter()
        .map(|r| (r.team_id, from_row(r.row)))
        .collect();
    for t in teams.iter_mut() {
        t.policies = Some(map.remove(&t.id).unwrap_or_else(defaults));
    }
    Ok(())
}

/// Domain part of an email, lower-cased.
pub fn domain_of(email: &str) -> &str {
    email.rsplit('@').next().unwrap_or_default()
}

/// Whether `email` may be invited under `domains` (empty list = anything).
pub fn domain_allowed(domains: &[String], email: &str) -> bool {
    if domains.is_empty() {
        return true;
    }
    let d = domain_of(email).to_ascii_lowercase();
    domains.iter().any(|x| x.eq_ignore_ascii_case(&d))
}

type MemberRow = (
    Uuid,
    String,
    String,
    String,
    Option<i32>,
    bool,
    Option<String>,
    Vec<String>,
    bool,
    String,
);

/// Policy rows of every team the user belongs to, with the coarse role.
async fn rows_for<'e, E: PgExecutor<'e>>(db: E, user_id: Uuid) -> ApiResult<Vec<MemberRow>> {
    Ok(sqlx::query_as(
        "SELECT m.team_id, m.role, p.mfa, p.local_keys, p.session_ttl_hours, p.sso_only,
                p.sso_provider, p.sso_domains, p.device_approval, p.session_recording
         FROM team_members m JOIN team_policies p ON p.team_id = m.team_id
         WHERE m.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?)
}

/// `(totp, passkey)` for the user.
pub async fn factors<'e, E: PgExecutor<'e>>(db: E, user_id: Uuid) -> ApiResult<(bool, bool)> {
    Ok(sqlx::query_as(
        "SELECT u.totp_enabled, EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id)
         FROM users u WHERE u.id = $1",
    )
    .bind(user_id)
    .fetch_one(db)
    .await?)
}

pub fn satisfies(level: &str, totp: bool, passkey: bool) -> bool {
    match level {
        "passkey" => passkey,
        "any" => totp || passkey,
        _ => true,
    }
}

/// Strictest policies across the user's teams.
pub async fn effective_for(
    db: &PgPool,
    user_id: Uuid,
    email: &str,
) -> ApiResult<EffectivePolicies> {
    let rows = rows_for(db, user_id).await?;
    let (totp, passkey) = factors(db, user_id).await?;
    let mut eff = EffectivePolicies {
        mfa: "off".into(),
        mfa_team_id: None,
        mfa_satisfied: true,
        session_ttl_hours: None,
        local_keys_denied_by: Vec::new(),
        device_approval_by: Vec::new(),
        sso_provider: None,
        recording_required_by: Vec::new(),
    };
    for (team_id, role, mfa, local_keys, ttl, sso_only, provider, domains, device, recording) in
        rows
    {
        if recording == "required" {
            eff.recording_required_by.push(team_id);
        }
        if mfa_rank(&mfa) > mfa_rank(&eff.mfa) {
            eff.mfa = mfa;
            eff.mfa_team_id = Some(team_id);
        }
        if let Some(h) = ttl {
            eff.session_ttl_hours = Some(eff.session_ttl_hours.map_or(h, |cur| cur.min(h)));
        }
        if local_keys == "deny" {
            eff.local_keys_denied_by.push(team_id);
        }
        if device {
            eff.device_approval_by.push(team_id);
        }
        if sso_only && role != "owner" && domain_allowed(&domains, email) && !domains.is_empty() {
            eff.sso_provider
                .get_or_insert(resolve_provider(team_id, provider));
        }
    }
    eff.mfa_satisfied = satisfies(&eff.mfa, totp, passkey);
    Ok(eff)
}

/// Whether `team_id` makes session recording mandatory.
pub async fn recording_required<'e, E: PgExecutor<'e>>(db: E, team_id: Uuid) -> ApiResult<bool> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT session_recording FROM team_policies WHERE team_id = $1")
            .bind(team_id)
            .fetch_optional(db)
            .await?;
    Ok(row.is_some_and(|(v,)| v == "required"))
}

/// Session lifetime for a user: the server default capped by the shortest
/// team policy.
pub async fn session_ttl<'e, E: PgExecutor<'e>>(
    db: E,
    user_id: Uuid,
    server_days: u32,
) -> ApiResult<chrono::Duration> {
    let server = chrono::Duration::days(server_days.max(1) as i64);
    let (min_hours,): (Option<i32>,) = sqlx::query_as(
        "SELECT min(p.session_ttl_hours) FROM team_members m
         JOIN team_policies p ON p.team_id = m.team_id WHERE m.user_id = $1",
    )
    .bind(user_id)
    .fetch_one(db)
    .await?;
    Ok(match min_hours {
        Some(h) => server.min(chrono::Duration::hours(h.max(1) as i64)),
        None => server,
    })
}

/// Provider id (possibly empty) when a team forbids password sign-in for
/// this user's email; the team owner is never locked out.
pub async fn sso_required<'e, E: PgExecutor<'e>>(
    db: E,
    user_id: Uuid,
    email: &str,
) -> ApiResult<Option<String>> {
    let rows = rows_for(db, user_id).await?;
    Ok(rows.into_iter().find_map(
        |(team_id, role, _, _, _, sso_only, provider, domains, _, _)| {
            (sso_only && role != "owner" && !domains.is_empty() && domain_allowed(&domains, email))
                .then(|| resolve_provider(team_id, provider))
        },
    ))
}

/// Whether any of the user's teams forces email approval of new devices.
pub async fn mandatory_device_approval<'e, E: PgExecutor<'e>>(
    db: E,
    user_id: Uuid,
) -> ApiResult<bool> {
    let (on,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM team_members m JOIN team_policies p ON p.team_id = m.team_id
                        WHERE m.user_id = $1 AND p.device_approval)",
    )
    .bind(user_id)
    .fetch_one(db)
    .await?;
    Ok(on)
}

/// Cap the live sessions of a team's members to `hours` after creation.
/// Returns how many sessions were shortened.
pub async fn shorten_sessions(db: &PgPool, team_id: Uuid, hours: i32) -> ApiResult<u64> {
    let n = sqlx::query(
        "UPDATE sessions s SET expires_at = s.created_at + make_interval(hours => $2)
         WHERE s.revoked_at IS NULL AND s.expires_at > s.created_at + make_interval(hours => $2)
           AND s.user_id IN (SELECT user_id FROM team_members WHERE team_id = $1)",
    )
    .bind(team_id)
    .bind(hours)
    .execute(db)
    .await?
    .rows_affected();
    Ok(n)
}

/// Normalise a domain allow-list: lower-case, trimmed, deduplicated.
pub fn normalize_domains(input: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for d in input {
        let d = d.trim().trim_start_matches('@').to_ascii_lowercase();
        if d.is_empty() {
            continue;
        }
        if d.len() > 253
            || !d.contains('.')
            || d.chars()
                .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        {
            return Err(format!("`{d}` is not a valid domain"));
        }
        if !out.contains(&d) {
            out.push(d);
        }
    }
    if out.len() > MAX_DOMAINS {
        return Err(format!("At most {MAX_DOMAINS} domains"));
    }
    Ok(out)
}

/// `team` in `sso_provider` stands for the team's own IdP (`team-<uuid>`).
/// A team that has claimed the e-mail's domain for single sign-on
/// (`sso_only` + the domain in `sso_domains`): `(team_id, team_name, provider)`.
/// Such addresses may neither register with a password nor sign in with one,
/// member or not — otherwise anyone could sidestep the IdP by creating a
/// personal account on the corporate domain.
pub async fn domain_claim<'e, E: PgExecutor<'e>>(
    db: E,
    email: &str,
) -> ApiResult<Option<(Uuid, String, Option<String>)>> {
    let domain = domain_of(email).to_ascii_lowercase();
    if domain.is_empty() {
        return Ok(None);
    }
    let row: Option<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT t.id, t.name, p.sso_provider
         FROM team_policies p JOIN teams t ON t.id = p.team_id
         WHERE p.sso_only AND $1 = ANY(p.sso_domains)
           AND (p.sso_provider IS DISTINCT FROM 'team'
                OR EXISTS (SELECT 1 FROM team_idp i WHERE i.team_id = t.id AND i.enabled))
         ORDER BY p.updated_at LIMIT 1",
    )
    .bind(&domain)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

/// Whether `email` belongs to an owner of `team_id` (owners keep password
/// sign-in so a broken IdP can never lock the team out).
pub async fn is_team_owner_email<'e, E: PgExecutor<'e>>(
    db: E,
    team_id: Uuid,
    email: &str,
) -> ApiResult<bool> {
    let (yes,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM team_members m JOIN users u ON u.id = m.user_id
                        WHERE m.team_id = $1 AND m.role = 'owner' AND lower(u.email) = lower($2))",
    )
    .bind(team_id)
    .bind(email)
    .fetch_one(db)
    .await?;
    Ok(yes)
}

pub fn resolve_provider(team_id: Uuid, provider: Option<String>) -> String {
    match provider.as_deref() {
        Some("team") => crate::sso::team_provider_id(team_id),
        Some(p) => p.to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_and_levels() {
        assert!(domain_allowed(&[], "a@b.c"));
        assert!(domain_allowed(&["Acme.com".into()], "x@acme.COM"));
        assert!(!domain_allowed(&["acme.com".into()], "x@evil.com"));
        assert_eq!(
            normalize_domains(&[" @Acme.com ".into(), "acme.com".into(), "".into()]).unwrap(),
            vec!["acme.com".to_string()]
        );
        assert!(normalize_domains(&["no spaces here".into()]).is_err());
        assert!(satisfies("off", false, false));
        assert!(satisfies("any", true, false));
        assert!(!satisfies("passkey", true, false));
        assert!(satisfies("passkey", false, true));
        assert!(mfa_rank("passkey") > mfa_rank("any") && mfa_rank("any") > mfa_rank("off"));
    }

    #[test]
    fn forward_ports_normalised() {
        let ok =
            normalize_forward_ports(&["22".into(), " 8000-8999 ".into(), "22".into()]).unwrap();
        assert_eq!(ok, vec!["22", "8000-8999"]);
        assert!(normalize_forward_ports(&["0".into()]).is_err());
        assert!(normalize_forward_ports(&["70000".into()]).is_err());
        assert!(normalize_forward_ports(&["443-80".into()]).is_err());
        assert!(normalize_forward_ports(&["http".into()]).is_err());
        assert!(normalize_forward_ports(&[]).unwrap().is_empty());
    }
}
