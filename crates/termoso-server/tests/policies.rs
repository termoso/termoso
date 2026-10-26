//! Team policies: read/write permissions, validation, SSO-only domains,
//! invite domain allow-list, coarse `require_mfa` kept in sync.

mod common;

use common::*;
use reqwest::{Method, StatusCode};

#[tokio::test]
async fn policies_are_validated_and_enforced() {
    let Some(s) = server().await else { return };
    let owner = register(s, &unique_email("owner"), "pw-owner-1234567").await;
    let bob_email = unique_email("bob");
    let bob_pw = "pw-bob-123456789";
    let bob = register(s, &bob_email, bob_pw).await;
    let team: serde_json::Value = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&serde_json::json!({ "name": "Ops" })),
        )
        .await;
    let team_id = team["id"].as_str().unwrap().to_string();
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

    // Any member reads; defaults are permissive.
    let p: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/policies"),
            Some(bob.token()),
            NOBODY,
        )
        .await;
    assert_eq!(p["policies"]["mfa"], "off");
    assert_eq!(p["policies"]["local_keys"], "allow");
    assert_eq!(p["effective_for_me"]["mfa"], "off");
    assert_eq!(p["effective_for_me"]["mfa_satisfied"], true);
    // Members without `policies.manage` cannot write.
    s.expect_status(
        Method::PUT,
        &format!("/teams/{team_id}/policies"),
        Some(bob.token()),
        Some(&serde_json::json!({ "local_keys": "deny" })),
        StatusCode::FORBIDDEN,
    )
    .await;
    // Validation.
    for bad in [
        serde_json::json!({ "mfa": "sometimes" }),
        serde_json::json!({ "local_keys": "maybe" }),
        serde_json::json!({ "session_ttl_hours": 3000 }),
        serde_json::json!({ "sso_only": true }),
        serde_json::json!({ "sso_domains": ["not a domain"] }),
        serde_json::json!({ "auth": "password" }),
        serde_json::json!({ "export": "sometimes" }),
        serde_json::json!({ "forward_ports": ["0"] }),
        serde_json::json!({ "forward_ports": ["80-22"] }),
        serde_json::json!({ "forward_ports": ["ssh"] }),
    ] {
        s.expect_status(
            Method::PUT,
            &format!("/teams/{team_id}/policies"),
            Some(owner.token()),
            Some(&bad),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    // Requiring MFA needs the actor to have it.
    s.expect_status(
        Method::PUT,
        &format!("/teams/{team_id}/policies"),
        Some(owner.token()),
        Some(&serde_json::json!({ "mfa": "any" })),
        StatusCode::FORBIDDEN,
    )
    .await;
    // Client-enforced and TTL policies land in /teams for every member.
    let p: serde_json::Value = s
        .json(
            Method::PUT,
            &format!("/teams/{team_id}/policies"),
            Some(owner.token()),
            Some(&serde_json::json!({ "local_keys": "deny", "session_ttl_hours": 12 })),
        )
        .await;
    assert_eq!(p["policies"]["local_keys"], "deny");
    assert_eq!(p["effective_for_me"]["session_ttl_hours"], 12);
    assert_eq!(p["effective_for_me"]["local_keys_denied_by"][0], team_id);
    // Access policies: validated, normalised and visible to every member.
    let p: serde_json::Value = s
        .json(
            Method::PUT,
            &format!("/teams/{team_id}/policies"),
            Some(owner.token()),
            Some(&serde_json::json!({
                "auth": "keys_only",
                "jump_host_required": true,
                "export": "deny",
                "forward_ports": [" 22 ", "8000 - 8999", "22", "443"],
                "posture_disk_encryption": true,
                "posture_secure_key": true
            })),
        )
        .await;
    assert_eq!(p["policies"]["auth"], "keys_only");
    assert_eq!(p["policies"]["jump_host_required"], true);
    assert_eq!(p["policies"]["export"], "deny");
    assert_eq!(p["policies"]["posture_disk_encryption"], true);
    assert_eq!(p["policies"]["posture_screen_lock"], false);
    assert_eq!(p["policies"]["posture_secure_key"], true);
    // Posture requirements would block bob's plain test devices below; off again.
    let p: serde_json::Value = s
        .json(
            Method::PUT,
            &format!("/teams/{team_id}/policies"),
            Some(owner.token()),
            Some(&serde_json::json!({
                "posture_disk_encryption": false,
                "posture_secure_key": false
            })),
        )
        .await;
    assert_eq!(p["policies"]["posture_disk_encryption"], false);
    assert_eq!(p["policies"]["posture_secure_key"], false);
    assert_eq!(
        p["policies"]["forward_ports"],
        serde_json::json!(["22", "8000-8999", "443"])
    );
    let teams: serde_json::Value = s
        .json(Method::GET, "/teams", Some(bob.token()), NOBODY)
        .await;
    let t = teams["teams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == team_id)
        .unwrap();
    assert_eq!(t["policies"]["local_keys"], "deny");
    assert_eq!(t["policies"]["session_ttl_hours"], 12);
    // Domain allow-list: invites outside it are refused.
    let p: serde_json::Value = s
        .json(
            Method::PUT,
            &format!("/teams/{team_id}/policies"),
            Some(owner.token()),
            Some(&serde_json::json!({ "sso_domains": ["Test.local"], "sso_only": true, "sso_provider": "okta" })),
        )
        .await;
    assert_eq!(p["policies"]["sso_domains"][0], "test.local");
    let resp = s
        .call(
            Method::POST,
            &format!("/teams/{team_id}/invites"),
            Some(owner.token()),
            Some(&serde_json::json!({ "email": "x@elsewhere.example", "role": "member", "vault_ids": [] })),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(err["code"], "domain_not_allowed");
    // SSO-only: the member cannot use a password any more, the owner can.
    let (request, _) = termoso_crypto::opaque::client_login_start(bob_pw.as_bytes()).unwrap();
    let resp = s
        .call(
            Method::POST,
            "/auth/login/start",
            None,
            Some(&termoso_proto::auth::LoginStartRequest {
                email: bob_email.clone(),
                opaque_request: request,
                device: device("bob laptop"),
                sso_session: None,
                turnstile_token: None,
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let err: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(err["code"], "sso_required");
    assert_eq!(err["details"]["provider"], "okta");
    login_raw(
        s,
        &owner.email,
        "pw-owner-1234567",
        device("owner laptop"),
        None,
    )
    .await
    .expect("owner is exempt");
    let p: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/policies"),
            Some(bob.token()),
            NOBODY,
        )
        .await;
    assert_eq!(p["effective_for_me"]["sso_provider"], "okta");
    // Switching it off restores password sign-in; `sso_provider: ""` clears.
    let p: serde_json::Value = s
        .json(
            Method::PUT,
            &format!("/teams/{team_id}/policies"),
            Some(owner.token()),
            Some(&serde_json::json!({ "sso_only": false, "sso_provider": "" })),
        )
        .await;
    assert!(p["policies"]["sso_provider"].is_null());
    login_raw(s, &bob_email, bob_pw, device("bob laptop"), None)
        .await
        .expect("password sign-in again");
    // The coarse flag follows the policy and vice versa.
    let _: serde_json::Value = s
        .json(
            Method::PATCH,
            &format!("/teams/{team_id}"),
            Some(owner.token()),
            Some(&serde_json::json!({ "require_mfa": false })),
        )
        .await;
    let p: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/policies"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(p["policies"]["mfa"], "off");
    // Audit trail carries the diff.
    let audit: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/audit"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let updates: Vec<&serde_json::Value> = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "policy.updated")
        .collect();
    assert!(updates.len() >= 3, "{audit}");
    assert_eq!(
        updates.last().unwrap()["details"]["local_keys"]["to"],
        "deny"
    );
}
