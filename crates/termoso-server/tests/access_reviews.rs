//! Access reviews: open (by hand / by cadence), decide, complete applies
//! removals, cancel, policy validation.

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use termoso_crypto::keys::SymmetricKey;
use termoso_crypto::sealed;
use termoso_proto::vault::{CreateVaultRequest, VaultMemberUpsert, VaultRole};

#[tokio::test]
async fn access_review_lifecycle() {
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
    let key = SymmetricKey::generate();
    let vault: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{team_id}/vaults"),
            Some(owner.token()),
            Some(&CreateVaultRequest {
                name: "Prod".into(),
                members: vec![
                    VaultMemberUpsert {
                        user_id: owner.id(),
                        role: VaultRole::Manager,
                        sealed_key: sealed::seal_vault_key(owner.keypair.public(), &key).unwrap(),
                    },
                    VaultMemberUpsert {
                        user_id: bob.id(),
                        role: VaultRole::Viewer,
                        sealed_key: sealed::seal_vault_key(bob.keypair.public(), &key).unwrap(),
                    },
                ],
            }),
        )
        .await;
    let vault_id = vault["id"].as_str().unwrap().to_string();
    let base = format!("/teams/{team_id}/access-reviews");

    // Policy: cadence validated.
    s.expect_status(
        Method::PUT,
        &format!("/teams/{team_id}/policies"),
        Some(owner.token()),
        Some(&serde_json::json!({ "access_review_days": 3 })),
        StatusCode::BAD_REQUEST,
    )
    .await;
    let p: serde_json::Value = s
        .json(
            Method::PUT,
            &format!("/teams/{team_id}/policies"),
            Some(owner.token()),
            Some(&serde_json::json!({ "access_review_days": 30 })),
        )
        .await;
    assert_eq!(p["policies"]["access_review_days"], 30);

    // Members cannot open reviews; the owner can, once at a time.
    s.expect_status(
        Method::POST,
        &base,
        Some(bob.token()),
        NOBODY,
        StatusCode::FORBIDDEN,
    )
    .await;
    let r: serde_json::Value = s
        .json(Method::POST, &base, Some(owner.token()), NOBODY)
        .await;
    let rid = r["review"]["id"].as_str().unwrap().to_string();
    assert_eq!(r["review"]["status"], "open");
    assert_eq!(r["review"]["items"], 2, "{r}");
    let items = r["items"].as_array().unwrap();
    let member = items
        .iter()
        .find(|i| i["kind"] == "member")
        .expect("member line");
    let access = items
        .iter()
        .find(|i| i["kind"] == "vault_access")
        .expect("vault access line");
    assert_eq!(member["user_id"], bob.id().to_string());
    assert_eq!(member["role"], "member");
    assert_eq!(access["vault_id"], vault_id);
    assert_eq!(access["vault_name"], "Prod");
    assert_eq!(access["email"], bob_email);
    s.expect_status(
        Method::POST,
        &base,
        Some(owner.token()),
        NOBODY,
        StatusCode::CONFLICT,
    )
    .await;

    // Complete refuses while lines are undecided; decisions are validated.
    s.expect_status(
        Method::POST,
        &format!("{base}/{rid}/complete"),
        Some(owner.token()),
        Some(&serde_json::json!({})),
        StatusCode::CONFLICT,
    )
    .await;
    s.expect_status(
        Method::POST,
        &format!("{base}/{rid}/items/{}", access["id"].as_str().unwrap()),
        Some(owner.token()),
        Some(&serde_json::json!({ "decision": "maybe" })),
        StatusCode::BAD_REQUEST,
    )
    .await;
    let decided: serde_json::Value = s
        .json(
            Method::POST,
            &format!("{base}/{rid}/items/{}", access["id"].as_str().unwrap()),
            Some(owner.token()),
            Some(&serde_json::json!({ "decision": "remove", "note": "left the prod rotation" })),
        )
        .await;
    assert_eq!(decided["decision"], "remove");
    assert_eq!(decided["note"], "left the prod rotation");
    assert_eq!(decided["decided_by"], owner.id().to_string());

    // Complete with the rest kept: bob loses the vault, stays in the team.
    let done: serde_json::Value = s
        .json(
            Method::POST,
            &format!("{base}/{rid}/complete"),
            Some(owner.token()),
            Some(&serde_json::json!({ "undecided": "keep" })),
        )
        .await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["kept"], 1);
    assert_eq!(done["removed"], 1);
    assert_eq!(done["decided"], 2);
    let members: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/vaults/{vault_id}/members"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let listed: Vec<String> = members["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["user_id"].as_str().unwrap().to_string())
        .collect();
    assert!(!listed.contains(&bob.id().to_string()), "{members}");
    let team_members: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/members"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert!(
        team_members["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["user_id"] == bob.id().to_string()),
        "{team_members}"
    );
    let audit: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/audit?action=access_review."),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let actions: Vec<&str> = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"access_review.opened"), "{actions:?}");
    assert!(actions.contains(&"access_review.completed"), "{actions:?}");
    let revoked: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/audit?action=vault.access_revoked"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(
        revoked["events"][0]["details"]["review_id"], rid,
        "{revoked}"
    );

    // A new review now has only the membership line; cancel closes it unchanged.
    let r2: serde_json::Value = s
        .json(Method::POST, &base, Some(owner.token()), NOBODY)
        .await;
    assert_eq!(r2["review"]["items"], 1, "{r2}");
    let rid2 = r2["review"]["id"].as_str().unwrap().to_string();
    let cancelled: serde_json::Value = s
        .json(
            Method::POST,
            &format!("{base}/{rid2}/cancel"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(cancelled["status"], "cancelled");
    s.expect_status(
        Method::POST,
        &format!("{base}/{rid2}/complete"),
        Some(owner.token()),
        Some(&serde_json::json!({ "undecided": "keep" })),
        StatusCode::CONFLICT,
    )
    .await;

    // Cadence: nothing due yet; after 30 days the scheduler opens one by itself.
    let n = termoso_server::routes::access_reviews::scheduler_pass(&s.state)
        .await
        .unwrap();
    let list: serde_json::Value = s
        .json(Method::GET, &base, Some(owner.token()), NOBODY)
        .await;
    assert_eq!(list["reviews"].as_array().unwrap().len(), 2, "{n} {list}");
    let db = sqlx::PgPool::connect(&s.database_url).await.unwrap();
    sqlx::query("UPDATE team_access_reviews SET opened_at = opened_at - interval '40 days' WHERE team_id = $1::uuid")
        .bind(&team_id)
        .execute(&db)
        .await
        .unwrap();
    termoso_server::routes::access_reviews::scheduler_pass(&s.state)
        .await
        .unwrap();
    let list: serde_json::Value = s
        .json(Method::GET, &base, Some(owner.token()), NOBODY)
        .await;
    let newest = &list["reviews"][0];
    assert_eq!(newest["status"], "open", "{list}");
    assert!(newest["opened_by"].is_null(), "{list}");
    assert_eq!(newest["items"], 1);
    // Bob sees the list but cannot decide.
    let _: serde_json::Value = s.json(Method::GET, &base, Some(bob.token()), NOBODY).await;
    s.expect_status(
        Method::POST,
        &format!("{base}/{}/cancel", newest["id"].as_str().unwrap()),
        Some(bob.token()),
        NOBODY,
        StatusCode::FORBIDDEN,
    )
    .await;
}
