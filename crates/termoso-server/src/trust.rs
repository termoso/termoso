//! Sign-in gates driven by team policy: network allow-lists (CIDRs) and
//! devices that a team admin must approve before they can sign in.

use std::net::IpAddr;

use axum::http::StatusCode;
use termoso_proto::auth::DeviceInfo;
use uuid::Uuid;

use crate::audit;
use crate::error::{ApiResult, Error};
use crate::state::AppState;

pub const MAX_ALLOWLIST: usize = 100;

/// `ip` or `ip/bits`; bare addresses get a host mask.
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, bits) = match s.split_once('/') {
        Some((a, b)) => (
            a.trim().parse::<IpAddr>().ok()?,
            b.trim().parse::<u8>().ok()?,
        ),
        None => {
            let ip: IpAddr = s.trim().parse().ok()?;
            (ip, if ip.is_ipv4() { 32 } else { 128 })
        }
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (bits <= max).then_some((ip, bits))
}

pub fn cidr_contains(net: IpAddr, bits: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            bits == 0 || {
                let m = u32::MAX << (32 - bits);
                u32::from(n) & m == u32::from(i) & m
            }
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            bits == 0 || {
                let m = u128::MAX << (128 - bits);
                u128::from(n) & m == u128::from(i) & m
            }
        }
        (IpAddr::V4(_), IpAddr::V6(i)) => i
            .to_ipv4_mapped()
            .is_some_and(|i4| cidr_contains(net, bits, IpAddr::V4(i4))),
        (IpAddr::V6(_), IpAddr::V4(_)) => false,
    }
}

/// Empty list = no restriction; an unknown client address never passes a
/// non-empty list.
pub fn ip_allowed(list: &[String], ip: Option<IpAddr>) -> bool {
    if list.is_empty() {
        return true;
    }
    let Some(ip) = ip else { return false };
    list.iter()
        .filter_map(|c| parse_cidr(c))
        .any(|(n, b)| cidr_contains(n, b, ip))
}

pub fn normalize_allowlist(input: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for raw in input {
        let s = raw.trim();
        if s.is_empty() {
            continue;
        }
        let (ip, bits) =
            parse_cidr(s).ok_or_else(|| format!("{s} is not an IP address or CIDR"))?;
        let norm = format!("{ip}/{bits}");
        if !out.contains(&norm) {
            out.push(norm);
        }
    }
    if out.len() > MAX_ALLOWLIST {
        return Err(format!(
            "ip_allowlist holds at most {MAX_ALLOWLIST} entries"
        ));
    }
    Ok(out)
}

/// First posture requirement of a team that the device does not meet.
/// A fact the client could not determine (`None`) counts as not met: the
/// policy is about proof, and an old client that reports nothing is refused
/// until it is updated.
pub fn posture_missing(
    device: &DeviceInfo,
    need_disk: bool,
    need_lock: bool,
    need_hw: bool,
) -> Option<&'static str> {
    let p = device.posture.as_ref();
    let has = |f: fn(&termoso_proto::auth::Posture) -> Option<bool>| p.and_then(f) == Some(true);
    if need_disk && !has(|p| p.disk_encryption) {
        Some("disk_encryption")
    } else if need_lock && !has(|p| p.screen_lock) {
        Some("screen_lock")
    } else if need_hw && !has(|p| p.secure_key_storage) {
        Some("secure_key_storage")
    } else {
        None
    }
}

fn posture_label(req: &str) -> &'static str {
    match req {
        "disk_encryption" => "disk encryption",
        "screen_lock" => "a screen lock",
        _ => "a hardware-backed device key (TPM, Secure Enclave or StrongBox)",
    }
}

type GateRow = (Uuid, String, Vec<String>, bool, bool, bool, bool, bool);

/// Run at sign-in once the device row exists. Refuses with `ip_not_allowed`
/// when any team of the user restricts networks and the client is outside,
/// and with `device_pending_approval` / `device_rejected` when a team wants
/// admins to vet devices and this one is not approved yet (a pending row is
/// created and the team's owners/admins are e-mailed once).
pub async fn gate(
    state: &AppState,
    user_id: Uuid,
    device_id: Uuid,
    device: &DeviceInfo,
    ip: Option<&str>,
) -> ApiResult<()> {
    let rows: Vec<GateRow> = sqlx::query_as(
        "SELECT t.id, t.name, p.ip_allowlist, p.device_admin_approval,
                p.posture_disk_encryption, p.posture_screen_lock, p.posture_secure_key,
                m.role = 'owner'
         FROM team_members m JOIN teams t ON t.id = m.team_id JOIN team_policies p ON p.team_id = m.team_id
         WHERE m.user_id = $1 AND (cardinality(p.ip_allowlist) > 0 OR p.device_admin_approval
                                   OR p.posture_disk_encryption OR p.posture_screen_lock OR p.posture_secure_key)
         ORDER BY t.created_at",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    let addr = ip.and_then(|s| s.parse::<IpAddr>().ok());
    for (team_id, team_name, list, admin, need_disk, need_lock, need_hw, is_owner) in rows {
        // Owners are exempt from posture (as from SSO-only) so a team can never lock itself out.
        if let Some(missing) = (!is_owner)
            .then(|| posture_missing(device, need_disk, need_lock, need_hw))
            .flatten()
        {
            audit::record(
                &state.db,
                audit::Entry::system(team_id, "login.posture_denied")
                    .user(user_id)
                    .details(serde_json::json!({
                        "device": device.name, "platform": device.platform,
                        "requirement": missing, "posture": device.posture,
                    })),
            )
            .await;
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                "device_posture",
                format!(
                    "The team “{team_name}” requires {} on your device",
                    posture_label(missing)
                ),
            )
            .with_details(serde_json::json!({
                "team_id": team_id, "team_name": team_name, "requirement": missing,
            })));
        }
        if !ip_allowed(&list, addr) {
            audit::record(
                &state.db,
                audit::Entry::system(team_id, "login.ip_denied")
                    .user(user_id)
                    .details(serde_json::json!({ "ip": ip, "device": device.name })),
            )
            .await;
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                "ip_not_allowed",
                format!("Sign-in from this network is not allowed by the team “{team_name}”"),
            )
            .with_details(serde_json::json!({ "team_id": team_id, "team_name": team_name })));
        }
        if admin {
            let status: Option<(String,)> = sqlx::query_as(
                "SELECT status FROM team_device_approvals WHERE team_id = $1 AND device_id = $2",
            )
            .bind(team_id)
            .bind(device_id)
            .fetch_optional(&state.db)
            .await?;
            match status.as_ref().map(|(s,)| s.as_str()) {
                Some("approved") => {}
                Some("rejected") => {
                    return Err(Error::new(
                        StatusCode::FORBIDDEN,
                        "device_rejected",
                        format!("This device was rejected by an admin of “{team_name}”"),
                    )
                    .with_details(
                        serde_json::json!({ "team_id": team_id, "team_name": team_name }),
                    ));
                }
                _ => {
                    if status.is_none() {
                        sqlx::query(
                            "INSERT INTO team_device_approvals (team_id, device_id, user_id) VALUES ($1, $2, $3)
                             ON CONFLICT DO NOTHING",
                        )
                        .bind(team_id)
                        .bind(device_id)
                        .bind(user_id)
                        .execute(&state.db)
                        .await?;
                        audit::record(
                            &state.db,
                            audit::Entry::system(team_id, "device.approval_requested")
                                .user(user_id)
                                .details(serde_json::json!({
                                    "device_id": device_id, "device": device.name,
                                    "platform": device.platform, "ip": ip,
                                })),
                        )
                        .await;
                        notify_admins(state, team_id, &team_name, user_id, device).await;
                    }
                    return Err(Error::new(
                        StatusCode::FORBIDDEN,
                        "device_pending_approval",
                        format!("An admin of “{team_name}” has to approve this device before it can sign in"),
                    )
                    .with_details(serde_json::json!({ "team_id": team_id, "team_name": team_name })));
                }
            }
        }
    }
    Ok(())
}

async fn notify_admins(
    state: &AppState,
    team_id: Uuid,
    team_name: &str,
    user_id: Uuid,
    device: &DeviceInfo,
) {
    let Some(mailer) = &state.mailer else { return };
    let rows: Vec<(String, String)> = match sqlx::query_as(
        "SELECT a.email, (SELECT email FROM users WHERE id = $2)
         FROM team_members m JOIN users a ON a.id = m.user_id
         WHERE m.team_id = $1 AND m.role IN ('owner', 'admin') LIMIT 20",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "admin lookup");
            return;
        }
    };
    let url = format!(
        "{}/team?tab=devices",
        state.cfg.public_url.trim_end_matches('/')
    );
    for (admin, who) in rows {
        let msg = crate::mail::Email::new(
            format!("New device waiting for approval: {team_name}"),
            "A member signed in from a new device",
        )
        .paragraph(format!(
            "{who} tried to sign in to Termoso from a new device (“{}”, {:?}). Team “{team_name}” requires admin approval for new devices; nothing is accessible until you approve it.",
            device.name, device.platform
        ))
        .button("Review devices", &url);
        if let Err(e) = mailer.send(&admin, &msg).await {
            tracing::warn!(error = %e, "device approval email");
        }
    }
}

/// When a team switches admin approval on, devices that already hold a
/// session are grandfathered so nobody is locked out by the flip itself.
pub async fn grandfather_devices(db: &sqlx::PgPool, team_id: Uuid, actor: Uuid) -> ApiResult<u64> {
    Ok(sqlx::query(
        "INSERT INTO team_device_approvals (team_id, device_id, user_id, status, decided_by, decided_at)
         SELECT $1, d.id, d.user_id, 'approved', $2, now()
         FROM devices d JOIN team_members m ON m.user_id = d.user_id AND m.team_id = $1
         WHERE EXISTS (SELECT 1 FROM sessions s WHERE s.device_id = d.id)
         ON CONFLICT (team_id, device_id) DO NOTHING",
    )
    .bind(team_id)
    .bind(actor)
    .execute(db)
    .await?
    .rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidrs() {
        let list = normalize_allowlist(&[
            "10.0.0.0/8".into(),
            " 203.0.113.7 ".into(),
            "2001:db8::/32".into(),
        ])
        .unwrap();
        assert_eq!(list, vec!["10.0.0.0/8", "203.0.113.7/32", "2001:db8::/32"]);
        assert!(ip_allowed(&list, "10.20.30.40".parse().ok()));
        assert!(ip_allowed(&list, "::ffff:10.1.1.1".parse().ok()));
        assert!(ip_allowed(&list, "2001:db8:1::5".parse().ok()));
        assert!(!ip_allowed(&list, "203.0.113.8".parse().ok()));
        assert!(!ip_allowed(&list, None));
        assert!(ip_allowed(&[], None));
        assert!(normalize_allowlist(&["10.0.0.0/33".into()]).is_err());
        assert!(normalize_allowlist(&["office".into()]).is_err());
        assert!(ip_allowed(&["0.0.0.0/0".into()], "8.8.8.8".parse().ok()));
    }
}
