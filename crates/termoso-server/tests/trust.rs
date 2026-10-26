//! Network allow-list and admin-approved devices.

mod common;
use common::*;
use reqwest::{Method, StatusCode};
use termoso_proto::auth::AuthResponse;
use termoso_proto::team::{AuditEventList, TeamDeviceList};
use uuid::Uuid;

/// Sign in and, when the server asks for the e-mail device approval, complete it
/// (the team gates run before that step, so their errors surface as `Err`).
async fn signin(
    s: &TestServer,
    email: &str,
    pw: &str,
    d: termoso_proto::auth::DeviceInfo,
) -> Result<AuthResponse, String> {
    match login_raw(s, email, pw, d, None).await? {
        r @ AuthResponse::DeviceApprovalRequired { .. } => Ok(approve_device(s, email, r).await),
        other => Ok(other),
    }
}

#[tokio::test]
async fn ip_allowlist_and_admin_device_approval() {
    let Some(s) = server().await else { return };
    let owner = register(s, &unique_email("tr-owner"), "pw-owner-1234567").await;
    let bob_email = unique_email("tr-bob");
    let bob_pw = "pw-bob-123456789";
    let bob = register(s, &bob_email, bob_pw).await;
    let team: serde_json::Value = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&serde_json::json!({ "name": "Trust" })),
        )
        .await;
    let team_id: Uuid = team["id"].as_str().unwrap().parse().unwrap();
    let invite: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{team_id}/invites"),
            Some(owner.token()),
            Some(&serde_json::json!({ "email": bob_email, "role": "member", "vault_ids": [] })),
        )
        .await;
    let token = invite["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    let _: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/invites/{token}/accept"),
            Some(bob.token()),
            NOBODY,
        )
        .await;
    let policies = format!("/teams/{team_id}/policies");

    // Validation.
    for bad in [
        serde_json::json!({ "ip_allowlist": ["office"] }),
        serde_json::json!({ "ip_allowlist": ["10.0.0.0/33"] }),
    ] {
        s.expect_status(
            Method::PUT,
            &policies,
            Some(owner.token()),
            Some(&bad),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }

    // Posture: a team that requires disk encryption refuses devices that do
    // not prove it (old clients report nothing → refused too); the fact is
    // stored on the device row once a compliant client signs in.
    let _: serde_json::Value = s
        .json(
            Method::PUT,
            &policies,
            Some(owner.token()),
            Some(&serde_json::json!({ "posture_disk_encryption": true })),
        )
        .await;
    let err = signin(s, &bob_email, bob_pw, device("bob old laptop"))
        .await
        .expect_err("no posture → blocked");
    assert!(err.contains("device_posture"), "{err}");
    let mut plain = device("bob plain laptop");
    plain.posture = Some(termoso_proto::auth::Posture {
        os_version: "Ubuntu 24.04".into(),
        disk_encryption: Some(false),
        ..Default::default()
    });
    let err = signin(s, &bob_email, bob_pw, plain)
        .await
        .expect_err("unencrypted → blocked");
    assert!(err.contains("disk encryption"), "{err}");
    let mut luks = device("bob luks laptop");
    luks.posture = Some(termoso_proto::auth::Posture {
        os_version: "Ubuntu 24.04".into(),
        disk_encryption: Some(true),
        screen_lock: Some(true),
        secure_key_storage: None,
    });
    signin(s, &bob_email, bob_pw, luks)
        .await
        .expect("encrypted → signs in");
    let devices: serde_json::Value = s
        .json(Method::GET, "/account/devices", Some(bob.token()), NOBODY)
        .await;
    let luks = devices["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "bob luks laptop")
        .expect("device listed");
    assert_eq!(luks["posture"]["disk_encryption"], true);
    assert_eq!(luks["posture"]["os_version"], "Ubuntu 24.04");
    assert!(luks["posture_at"].is_string());
    let _: serde_json::Value = s
        .json(
            Method::PUT,
            &policies,
            Some(owner.token()),
            Some(&serde_json::json!({ "posture_disk_encryption": false })),
        )
        .await;

    // Outside the allow-list → refused at sign-in with ip_not_allowed.
    let p: serde_json::Value = s
        .json(
            Method::PUT,
            &policies,
            Some(owner.token()),
            Some(&serde_json::json!({ "ip_allowlist": ["203.0.113.0/24"] })),
        )
        .await;
    assert_eq!(p["policies"]["ip_allowlist"][0], "203.0.113.0/24");
    let d1 = device("bob laptop");
    let err = signin(s, &bob_email, bob_pw, d1.clone())
        .await
        .expect_err("blocked");
    assert!(err.contains("ip_not_allowed"), "{err}");
    // Test clients arrive via x-forwarded-for 10.0.0.x → allowed → signs in.
    let _: serde_json::Value = s
        .json(
            Method::PUT,
            &policies,
            Some(owner.token()),
            Some(&serde_json::json!({ "ip_allowlist": ["10.0.0.0/8", "127.0.0.0/8", "::1"] })),
        )
        .await;
    let r = signin(s, &bob_email, bob_pw, d1.clone()).await;
    assert!(matches!(r, Ok(AuthResponse::Authenticated(_))), "{r:?}");

    // Admin approval: devices with a session are grandfathered, new ones wait.
    let _: serde_json::Value = s
        .json(
            Method::PUT,
            &policies,
            Some(owner.token()),
            Some(&serde_json::json!({ "device_admin_approval": true })),
        )
        .await;
    let r = signin(s, &bob_email, bob_pw, d1.clone()).await;
    assert!(matches!(r, Ok(AuthResponse::Authenticated(_))), "{r:?}");
    let d2 = device("bob phone");
    let err = signin(s, &bob_email, bob_pw, d2.clone())
        .await
        .expect_err("pending");
    assert!(err.contains("device_pending_approval"), "{err}");

    // Members cannot see the queue; the owner approves.
    let devices_path = format!("/teams/{team_id}/devices");
    s.expect_status(
        Method::GET,
        &devices_path,
        Some(bob.token()),
        NOBODY,
        StatusCode::FORBIDDEN,
    )
    .await;
    let list: TeamDeviceList = s
        .json(Method::GET, &devices_path, Some(owner.token()), NOBODY)
        .await;
    assert!(list.admin_approval);
    let pending = list
        .devices
        .iter()
        .find(|d| d.status == "pending" && d.name == "bob phone")
        .expect("pending phone");
    assert_eq!(pending.user_email, bob_email);
    let approved: serde_json::Value = s
        .json(
            Method::POST,
            &format!("{devices_path}/{}/approve", pending.device_id),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(approved["status"], "approved");
    assert!(matches!(
        signin(s, &bob_email, bob_pw, d2.clone()).await,
        Ok(AuthResponse::Authenticated(_))
    ));

    // Rejected device stays out.
    let d3 = device("bob tablet");
    let _ = signin(s, &bob_email, bob_pw, d3.clone()).await;
    let list: TeamDeviceList = s
        .json(Method::GET, &devices_path, Some(owner.token()), NOBODY)
        .await;
    let tablet = list
        .devices
        .iter()
        .find(|d| d.name == "bob tablet")
        .expect("tablet");
    let _: serde_json::Value = s
        .json(
            Method::POST,
            &format!("{devices_path}/{}/reject", tablet.device_id),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let err = signin(s, &bob_email, bob_pw, d3.clone())
        .await
        .expect_err("rejected");
    assert!(err.contains("device_rejected"), "{err}");

    let events: AuditEventList = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/audit?limit=50"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    for a in [
        "login.ip_denied",
        "device.approval_requested",
        "device.approved",
        "device.rejected",
    ] {
        assert!(events.events.iter().any(|e| e.action == a), "{a}");
    }
}
