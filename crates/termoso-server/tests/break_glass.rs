//! Break-glass: owner-only set-up, designated member redeems a one-time secret
//! and becomes a time-boxed admin; wrong secrets lock; expiry/end restore.

mod common;

use common::*;
use reqwest::{Method, StatusCode};

async fn role_of(s: &TestServer, owner: &User, team_id: &str, user: &User) -> String {
    let members: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/members"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    members["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["user_id"] == user.id().to_string())
        .map(|m| m["role"].as_str().unwrap().to_string())
        .unwrap_or_else(|| panic!("{members}"))
}

#[tokio::test]
async fn break_glass_lifecycle() {
    let Some(s) = server().await else { return };
    let owner = register(s, &unique_email("owner"), "pw-owner-1234567").await;
    let bob_email = unique_email("bob");
    let bob = register(s, &bob_email, "pw-bob-123456789").await;
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
    let base = format!("/teams/{team_id}/break-glass");

    // Nothing yet; only the owner may set it up; validation.
    s.expect_status(
        Method::GET,
        &base,
        Some(owner.token()),
        NOBODY,
        StatusCode::NOT_FOUND,
    )
    .await;
    s.expect_status(
        Method::PUT,
        &base,
        Some(bob.token()),
        Some(&serde_json::json!({ "user_id": bob.id(), "duration_hours": 4 })),
        StatusCode::FORBIDDEN,
    )
    .await;
    s.expect_status(
        Method::PUT,
        &base,
        Some(owner.token()),
        Some(&serde_json::json!({ "user_id": owner.id(), "duration_hours": 4 })),
        StatusCode::BAD_REQUEST,
    )
    .await;
    s.expect_status(
        Method::PUT,
        &base,
        Some(owner.token()),
        Some(&serde_json::json!({ "user_id": bob.id(), "duration_hours": 100 })),
        StatusCode::BAD_REQUEST,
    )
    .await;
    let bg: serde_json::Value = s
        .json(
            Method::PUT,
            &base,
            Some(owner.token()),
            Some(&serde_json::json!({ "user_id": bob.id(), "duration_hours": 4 })),
        )
        .await;
    let secret = bg["secret"].as_str().unwrap().to_string();
    assert!(secret.len() >= 20, "{bg}");
    assert_eq!(bg["status"], "ready");
    let status: serde_json::Value = s.json(Method::GET, &base, Some(bob.token()), NOBODY).await;
    assert!(status["secret"].is_null(), "{status}");
    assert_eq!(status["email"], bob_email);

    // Only bob may redeem; wrong secrets count and eventually lock.
    s.expect_status(
        Method::POST,
        &format!("{base}/use"),
        Some(owner.token()),
        Some(&serde_json::json!({ "secret": secret, "reason": "test" })),
        StatusCode::FORBIDDEN,
    )
    .await;
    s.expect_status(
        Method::POST,
        &format!("{base}/use"),
        Some(bob.token()),
        Some(&serde_json::json!({ "secret": "nope", "reason": "" })),
        StatusCode::BAD_REQUEST,
    )
    .await;
    for _ in 0..5 {
        s.expect_status(
            Method::POST,
            &format!("{base}/use"),
            Some(bob.token()),
            Some(&serde_json::json!({ "secret": "nope", "reason": "owner unreachable" })),
            StatusCode::FORBIDDEN,
        )
        .await;
    }
    s.expect_status(
        Method::POST,
        &format!("{base}/use"),
        Some(bob.token()),
        Some(&serde_json::json!({ "secret": secret, "reason": "owner unreachable" })),
        StatusCode::TOO_MANY_REQUESTS,
    )
    .await;
    let db = sqlx::PgPool::connect(&s.database_url).await.unwrap();
    sqlx::query("UPDATE team_break_glass SET locked_until = NULL WHERE team_id = $1::uuid")
        .bind(&team_id)
        .execute(&db)
        .await
        .unwrap();

    // Redeem: bob is an admin now, loudly.
    assert_eq!(role_of(s, &owner, &team_id, &bob).await, "member");
    let used: serde_json::Value = s
        .json(
            Method::POST,
            &format!("{base}/use"),
            Some(bob.token()),
            Some(
                &serde_json::json!({ "secret": secret, "reason": "owner unreachable, leaked key" }),
            ),
        )
        .await;
    assert_eq!(used["status"], "active", "{used}");
    assert!(used["expires_at"].is_string());
    assert_eq!(role_of(s, &owner, &team_id, &bob).await, "admin");
    let audit: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/audit?action=break_glass."),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let used_ev = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "break_glass.used")
        .expect("audited");
    assert_eq!(
        used_ev["details"]["reason"],
        "owner unreachable, leaked key"
    );
    assert!(
        audit["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["action"] == "break_glass.denied")
            .count()
            >= 6
    );
    // Spent: cannot be used twice.
    s.expect_status(
        Method::POST,
        &format!("{base}/use"),
        Some(bob.token()),
        Some(&serde_json::json!({ "secret": secret, "reason": "again" })),
        StatusCode::CONFLICT,
    )
    .await;

    // Bob ends it early → member again; a second end is a no-op conflict.
    let ended: serde_json::Value = s
        .json(
            Method::POST,
            &format!("{base}/end"),
            Some(bob.token()),
            NOBODY,
        )
        .await;
    assert_eq!(ended["status"], "used", "{ended}");
    assert_eq!(role_of(s, &owner, &team_id, &bob).await, "member");
    s.expect_status(
        Method::POST,
        &format!("{base}/end"),
        Some(bob.token()),
        NOBODY,
        StatusCode::CONFLICT,
    )
    .await;

    // New secret, redeem, let it expire → restored by the job.
    let bg: serde_json::Value = s
        .json(
            Method::PUT,
            &base,
            Some(owner.token()),
            Some(&serde_json::json!({ "user_id": bob.id(), "duration_hours": 1 })),
        )
        .await;
    let secret2 = bg["secret"].as_str().unwrap().to_string();
    assert_ne!(secret2, secret);
    let _: serde_json::Value = s
        .json(
            Method::POST,
            &format!("{base}/use"),
            Some(bob.token()),
            Some(&serde_json::json!({ "secret": secret2, "reason": "drill" })),
        )
        .await;
    assert_eq!(role_of(s, &owner, &team_id, &bob).await, "admin");
    assert_eq!(
        termoso_server::routes::break_glass::expire_pass(&s.state)
            .await
            .unwrap(),
        0
    );
    sqlx::query("UPDATE team_break_glass SET expires_at = now() - interval '1 minute' WHERE team_id = $1::uuid")
        .bind(&team_id)
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(
        termoso_server::routes::break_glass::expire_pass(&s.state)
            .await
            .unwrap(),
        1
    );
    assert_eq!(role_of(s, &owner, &team_id, &bob).await, "member");
    let status: serde_json::Value = s
        .json(Method::GET, &base, Some(owner.token()), NOBODY)
        .await;
    assert_eq!(status["status"], "used");

    // Remove.
    s.expect_status(
        Method::DELETE,
        &base,
        Some(owner.token()),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;
    s.expect_status(
        Method::GET,
        &base,
        Some(owner.token()),
        NOBODY,
        StatusCode::NOT_FOUND,
    )
    .await;
}
