//! Tamper-evident audit log: hash chain, signed checkpoints, retention anchors.

mod common;

use common::*;
use reqwest::{Method, StatusCode};

async fn public_text(s: &TestServer, path: &str) -> (StatusCode, String) {
    let resp = s
        .http()
        .get(format!("http://{}{path}", s.addr))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.text().await.unwrap())
}

#[tokio::test]
async fn audit_chain_detects_tampering_and_survives_retention() {
    let Some(s) = server().await else { return };
    let owner = register(s, &unique_email("owner"), "pw-owner-1234567").await;
    let team: serde_json::Value = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&serde_json::json!({ "name": "Ops" })),
        )
        .await;
    let team_id = team["id"].as_str().unwrap().to_string();
    for name in ["Ops 2", "Ops 3", "Ops 4"] {
        let _: serde_json::Value = s
            .json(
                Method::PATCH,
                &format!("/teams/{team_id}"),
                Some(owner.token()),
                Some(&serde_json::json!({ "name": name })),
            )
            .await;
    }
    let verify = || async {
        let v: serde_json::Value = s
            .json(
                Method::GET,
                &format!("/teams/{team_id}/audit/verify"),
                Some(owner.token()),
                NOBODY,
            )
            .await;
        v
    };

    // Intact chain: every entry hashed and linked, hashes visible in the log.
    let v = verify().await;
    assert_eq!(v["ok"], true, "{v}");
    assert!(v["events"].as_i64().unwrap() >= 4, "{v}");
    assert!(v["broken_at"].is_null(), "{v}");
    let log: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/audit"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let events = log["events"].as_array().unwrap();
    assert_eq!(events[0]["hash"].as_str().unwrap().len(), 64);
    assert_eq!(events[0]["prev_hash"], events[1]["hash"]);
    assert_eq!(v["head_hash"], events[0]["hash"]);

    // Signed checkpoint: sshsig over the head, verifiable with the public key.
    let cp: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{team_id}/audit/checkpoint"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(cp["hash"], v["head_hash"], "{cp}");
    assert!(
        cp["signature"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN SSH SIGNATURE-----")
    );
    let (status, text) = public_text(s, "/audit/key").await;
    assert_eq!(status, 200, "{text}");
    let key: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(
        key["public_key"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519 ")
    );
    assert_eq!(key["namespace"], "termoso-audit");
    let again: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{team_id}/audit/checkpoint"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert!(again.is_null(), "head already checkpointed: {again}");
    let v = verify().await;
    assert_eq!(v["checkpoint_ok"], true, "{v}");
    assert_eq!(v["ok"], true, "{v}");

    // Edit an entry behind the server's back → that entry fails `hash`.
    let db = sqlx::PgPool::connect(&s.database_url).await.unwrap();
    let victim = events[1]["id"].as_i64().unwrap();
    sqlx::query("UPDATE team_audit_events SET details = details || '{\"x\":1}' WHERE id = $1")
        .bind(victim)
        .execute(&db)
        .await
        .unwrap();
    let v = verify().await;
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(v["broken_at"], victim, "{v}");
    assert_eq!(v["reason"], "hash", "{v}");
    sqlx::query("UPDATE team_audit_events SET details = details - 'x' WHERE id = $1")
        .bind(victim)
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(verify().await["ok"], true);

    // Retention removes the oldest entry but anchors its hash → still intact.
    let oldest = events.last().unwrap()["id"].as_i64().unwrap();
    sqlx::query(
        "UPDATE team_audit_events SET created_at = now() - interval '400 days' WHERE id = $1",
    )
    .bind(oldest)
    .execute(&db)
    .await
    .unwrap();
    let _: serde_json::Value = s
        .json(
            Method::PUT,
            &format!("/teams/{team_id}/policies"),
            Some(owner.token()),
            Some(&serde_json::json!({ "audit_retention_days": 30 })),
        )
        .await;
    let removed = termoso_server::audit::retention_pass(&db).await.unwrap();
    assert!(removed >= 1, "{removed}");
    let v = verify().await;
    assert_eq!(v["ok"], true, "{v}");
    assert!(v["first_id"].as_i64().unwrap() > oldest, "{v}");

    // Delete a middle entry → the next one fails `link`. (Deleting the entry
    // right after the anchor would instead report `anchor` on its successor.)
    let middle = events[1]["id"].as_i64().unwrap();
    sqlx::query("DELETE FROM team_audit_events WHERE id = $1")
        .bind(middle)
        .execute(&db)
        .await
        .unwrap();
    let v = verify().await;
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(v["reason"], "link", "{v}");
    assert_eq!(v["broken_at"], events[0]["id"], "{v}");
}
