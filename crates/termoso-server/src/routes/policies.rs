use crate::audit;
use crate::error::{ApiResult, Error};
use crate::extract::{Auth, Json as Body};
use crate::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
use termoso_proto::team::{TeamPolicies, TeamPoliciesResponse, UpdateTeamPoliciesRequest};
use uuid::Uuid;

use crate::policy;

#[utoipa::path(get, path = "/api/v1/teams/{id}/policies", tag = "teams", params(("id" = Uuid, Path)),
    responses((status = 200, body = TeamPoliciesResponse)))]
pub async fn get(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TeamPoliciesResponse>> {
    crate::authz::require(&state, id, auth.user_id(), "team.view").await?;
    let me = crate::users::by_id(&state.db, auth.user_id()).await?;
    Ok(Json(TeamPoliciesResponse {
        policies: policy::load(&state.db, id).await?,
        effective_for_me: policy::effective_for(&state.db, me.id, &me.email).await?,
    }))
}

#[utoipa::path(put, path = "/api/v1/teams/{id}/policies", tag = "teams", params(("id" = Uuid, Path)),
    request_body = UpdateTeamPoliciesRequest, responses((status = 200, body = TeamPoliciesResponse)))]
pub async fn put(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Body(req): Body<UpdateTeamPoliciesRequest>,
) -> ApiResult<Json<TeamPoliciesResponse>> {
    crate::authz::require(&state, id, auth.user_id(), "policies.manage").await?;
    let before = policy::load(&state.db, id).await?;
    let mut next = before.clone();
    if let Some(level) = req.mfa {
        if !policy::MFA_LEVELS.contains(&level.as_str()) {
            return Err(Error::bad_request("mfa must be off, any or passkey"));
        }
        if policy::mfa_rank(&level) > 0 {
            let (totp, passkey) = policy::factors(&state.db, auth.user_id()).await?;
            if !policy::satisfies(&level, totp, passkey) {
                return Err(Error::forbidden(
                    "Turn on this kind of two-factor authentication for your own account first",
                ));
            }
        }
        next.mfa = level;
    }
    if let Some(v) = req.local_keys {
        if !policy::LOCAL_KEYS.contains(&v.as_str()) {
            return Err(Error::bad_request("local_keys must be allow or deny"));
        }
        next.local_keys = v;
    }
    if let Some(h) = req.session_ttl_hours {
        next.session_ttl_hours = match h {
            0 => None,
            1..=policy::MAX_SESSION_TTL_HOURS => Some(h),
            _ => {
                return Err(Error::bad_request(
                    "session_ttl_hours must be 0 (off) or 1..=2160",
                ));
            }
        };
    }
    if let Some(p) = req.sso_provider {
        let p = p.trim().to_string();
        next.sso_provider = (!p.is_empty()).then_some(p);
    }
    if let Some(d) = req.sso_domains {
        next.sso_domains = policy::normalize_domains(&d).map_err(Error::bad_request)?;
    }
    if let Some(on) = req.sso_only {
        next.sso_only = on;
    }
    if next.sso_only && next.sso_domains.is_empty() {
        return Err(Error::bad_request(
            "sso_only needs at least one domain in sso_domains",
        ));
    }
    if let Some(on) = req.device_approval {
        next.device_approval = on;
    }
    if let Some(days) = req.audit_retention_days {
        let cap = (state.cfg.audit_retention_days_max as i32).clamp(
            policy::MIN_AUDIT_RETENTION_DAYS,
            policy::MAX_AUDIT_RETENTION_DAYS,
        );
        if !(policy::MIN_AUDIT_RETENTION_DAYS..=cap).contains(&days) {
            return Err(Error::bad_request(format!(
                "audit_retention_days must be within {}..={cap} on this server",
                policy::MIN_AUDIT_RETENTION_DAYS
            )));
        }
        next.audit_retention_days = days;
    }
    if let Some(v) = req.session_recording {
        if !policy::SESSION_RECORDING.contains(&v.as_str()) {
            return Err(Error::bad_request(
                "session_recording must be optional or required",
            ));
        }
        next.session_recording = v;
    }
    if let Some(days) = req.log_retention_days {
        if !(0..=policy::MAX_LOG_RETENTION_DAYS).contains(&days) {
            return Err(Error::bad_request(format!(
                "log_retention_days must be 0 (keep forever) or 1..={}",
                policy::MAX_LOG_RETENTION_DAYS
            )));
        }
        next.log_retention_days = days;
    }
    for (field, value, slot) in [
        (
            "key_max_age_days",
            req.key_max_age_days,
            &mut next.key_max_age_days,
        ),
        (
            "password_max_age_days",
            req.password_max_age_days,
            &mut next.password_max_age_days,
        ),
    ] {
        if let Some(days) = value {
            if !(0..=policy::MAX_SECRET_AGE_DAYS).contains(&days) {
                return Err(Error::bad_request(format!(
                    "{field} must be 0 (off) or 1..={}",
                    policy::MAX_SECRET_AGE_DAYS
                )));
            }
            *slot = days;
        }
    }
    if let Some(list) = req.ip_allowlist {
        next.ip_allowlist = crate::trust::normalize_allowlist(&list).map_err(Error::bad_request)?;
    }
    if let Some(on) = req.device_admin_approval {
        next.device_admin_approval = on;
    }
    if let Some(v) = req.auth {
        if !policy::AUTH.contains(&v.as_str()) {
            return Err(Error::bad_request("auth must be any or keys_only"));
        }
        next.auth = v;
    }
    if let Some(on) = req.jump_host_required {
        next.jump_host_required = on;
    }
    if let Some(v) = req.export {
        if !policy::EXPORT.contains(&v.as_str()) {
            return Err(Error::bad_request("export must be allow or deny"));
        }
        next.export = v;
    }
    if let Some(list) = req.forward_ports {
        next.forward_ports = policy::normalize_forward_ports(&list).map_err(Error::bad_request)?;
    }
    if let Some(on) = req.posture_disk_encryption {
        next.posture_disk_encryption = on;
    }
    if let Some(on) = req.posture_screen_lock {
        next.posture_screen_lock = on;
    }
    if let Some(on) = req.posture_secure_key {
        next.posture_secure_key = on;
    }
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO team_policies (team_id, mfa, local_keys, session_ttl_hours, sso_only, sso_provider,
                                    sso_domains, device_approval, audit_retention_days, session_recording,
                                    log_retention_days, key_max_age_days, password_max_age_days, ip_allowlist,
                                    device_admin_approval, auth, jump_host_required, export, forward_ports,
                                    posture_disk_encryption, posture_screen_lock, posture_secure_key,
                                    updated_by, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $9, now())
         ON CONFLICT (team_id) DO UPDATE SET mfa = EXCLUDED.mfa, local_keys = EXCLUDED.local_keys,
             session_ttl_hours = EXCLUDED.session_ttl_hours, sso_only = EXCLUDED.sso_only,
             sso_provider = EXCLUDED.sso_provider, sso_domains = EXCLUDED.sso_domains,
             device_approval = EXCLUDED.device_approval, audit_retention_days = EXCLUDED.audit_retention_days,
             session_recording = EXCLUDED.session_recording, log_retention_days = EXCLUDED.log_retention_days,
             key_max_age_days = EXCLUDED.key_max_age_days, password_max_age_days = EXCLUDED.password_max_age_days,
             ip_allowlist = EXCLUDED.ip_allowlist, device_admin_approval = EXCLUDED.device_admin_approval,
             auth = EXCLUDED.auth, jump_host_required = EXCLUDED.jump_host_required,
             export = EXCLUDED.export, forward_ports = EXCLUDED.forward_ports,
             posture_disk_encryption = EXCLUDED.posture_disk_encryption,
             posture_screen_lock = EXCLUDED.posture_screen_lock, posture_secure_key = EXCLUDED.posture_secure_key,
             updated_by = EXCLUDED.updated_by, updated_at = now()",
    )
    .bind(id)
    .bind(&next.mfa)
    .bind(&next.local_keys)
    .bind(next.session_ttl_hours)
    .bind(next.sso_only)
    .bind(&next.sso_provider)
    .bind(&next.sso_domains)
    .bind(next.device_approval)
    .bind(auth.user_id())
    .bind(next.audit_retention_days)
    .bind(&next.session_recording)
    .bind(next.log_retention_days)
    .bind(next.key_max_age_days)
    .bind(next.password_max_age_days)
    .bind(&next.ip_allowlist)
    .bind(next.device_admin_approval)
    .bind(&next.auth)
    .bind(next.jump_host_required)
    .bind(&next.export)
    .bind(&next.forward_ports)
    .bind(next.posture_disk_encryption)
    .bind(next.posture_screen_lock)
    .bind(next.posture_secure_key)
    .execute(&mut *tx)
    .await?;
    if next.session_recording == "required" {
        // Mandatory recording switches every team vault on; managers can no
        // longer switch it off while the policy stands.
        sqlx::query(
            "UPDATE vaults SET session_logging = true, updated_at = now()
             WHERE team_id = $1 AND kind = 'team' AND session_logging = false",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
    }
    if next.device_admin_approval && !before.device_admin_approval {
        crate::trust::grandfather_devices(&state.db, id, auth.user_id()).await?;
    }
    // Older clients read the coarse flag.
    sqlx::query("UPDATE teams SET require_mfa = $2, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(next.mfa != "off")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let diff = diff(&before, &next);
    audit::record(
        &state.db,
        audit::Entry::new(id, &auth, "policy.updated").details(diff),
    )
    .await;
    if let Some(h) = next.session_ttl_hours
        && before.session_ttl_hours.is_none_or(|old| h < old)
    {
        let n = policy::shorten_sessions(&state.db, id, h).await?;
        if n > 0 {
            audit::record(
                &state.db,
                audit::Entry::new(id, &auth, "policy.session_ttl_applied")
                    .details(serde_json::json!({ "sessions": n, "hours": h })),
            )
            .await;
        }
    }
    let me = crate::users::by_id(&state.db, auth.user_id()).await?;
    Ok(Json(TeamPoliciesResponse {
        policies: policy::load(&state.db, id).await?,
        effective_for_me: policy::effective_for(&state.db, me.id, &me.email).await?,
    }))
}

fn diff(a: &TeamPolicies, b: &TeamPolicies) -> serde_json::Value {
    let (a, b) = (
        serde_json::to_value(a).unwrap_or_default(),
        serde_json::to_value(b).unwrap_or_default(),
    );
    let mut out = serde_json::Map::new();
    if let (Some(a), Some(b)) = (a.as_object(), b.as_object()) {
        for (k, nv) in b {
            if k == "updated_at" {
                continue;
            }
            if a.get(k) != Some(nv) {
                out.insert(k.clone(), serde_json::json!({ "from": a.get(k), "to": nv }));
            }
        }
    }
    serde_json::Value::Object(out)
}
