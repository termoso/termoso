//! Streaming audit export (CSV / JSONL) and retention policy validation.

mod common;

use common::*;
use reqwest::{Method, StatusCode};

#[tokio::test]
async fn audit_export_streams_csv_and_jsonl() {
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
    let _: serde_json::Value = s
        .json(
            Method::PATCH,
            &format!("/teams/{team_id}"),
            Some(owner.token()),
            Some(&serde_json::json!({ "name": "Ops & Co" })),
        )
        .await;

    // A member without `audit.export` cannot export; bad formats are refused.
    s.expect_status(
        Method::GET,
        &format!("/teams/{team_id}/audit/export?format=jsonl"),
        Some(bob.token()),
        NOBODY,
        StatusCode::FORBIDDEN,
    )
    .await;
    s.expect_status(
        Method::GET,
        &format!("/teams/{team_id}/audit/export?format=xml"),
        Some(owner.token()),
        NOBODY,
        StatusCode::BAD_REQUEST,
    )
    .await;

    // JSONL: one event per line, newest last, filters honoured.
    let resp = s
        .call(
            Method::GET,
            &format!("/teams/{team_id}/audit/export?format=jsonl"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/x-ndjson")
    );
    assert!(
        resp.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains(".jsonl")
    );
    let body = resp.text().await.unwrap();
    let lines: Vec<serde_json::Value> = body
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("jsonl line"))
        .collect();
    assert!(lines.len() >= 3, "{body}");
    assert!(
        lines
            .windows(2)
            .all(|w| w[0]["id"].as_i64() < w[1]["id"].as_i64())
    );
    assert!(lines.iter().all(|l| l["team_id"] == team_id));
    assert!(lines.iter().any(
        |l| l["action"] == "team.renamed" || l["action"].as_str().unwrap().starts_with("team.")
    ));
    let resp = s
        .call(
            Method::GET,
            &format!("/teams/{team_id}/audit/export?format=jsonl&action=team."),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let filtered = resp.text().await.unwrap();
    assert!(filtered.lines().filter(|l| !l.is_empty()).all(|l| {
        serde_json::from_str::<serde_json::Value>(l).unwrap()["action"]
            .as_str()
            .unwrap()
            .starts_with("team.")
    }));

    // CSV: BOM + header, quoted JSON details, same row count.
    let resp = s
        .call(
            Method::GET,
            &format!("/teams/{team_id}/audit/export"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/csv")
    );
    let csv = resp.text().await.unwrap();
    assert!(
        csv.starts_with("\u{feff}id,created_at,team_id,action,"),
        "{csv}"
    );
    let rows: Vec<&str> = csv.lines().skip(1).filter(|l| !l.is_empty()).collect();
    // The export itself is audited, so CSV sees the JSONL exports too.
    assert!(rows.len() >= lines.len(), "{csv}");
    assert!(rows.iter().all(|r| r.contains(&team_id)));
    assert!(rows.iter().any(|r| r.contains("audit.exported")));

    // Retention is a policy with server-side bounds.
    s.expect_status(
        Method::PUT,
        &format!("/teams/{team_id}/policies"),
        Some(owner.token()),
        Some(&serde_json::json!({ "audit_retention_days": 29 })),
        StatusCode::BAD_REQUEST,
    )
    .await;
    let p: serde_json::Value = s
        .json(
            Method::PUT,
            &format!("/teams/{team_id}/policies"),
            Some(owner.token()),
            Some(&serde_json::json!({ "audit_retention_days": 400 })),
        )
        .await;
    assert_eq!(p["policies"]["audit_retention_days"], 400);
}

#[tokio::test]
async fn export_with_no_matching_rows_completes() {
    let Some(s) = server().await else { return };
    let owner = register(s, &unique_email("ax-empty"), "pw-owner-1234567").await;
    let team: serde_json::Value = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&serde_json::json!({ "name": "Empty export" })),
        )
        .await;
    let team_id = team["id"].as_str().unwrap();
    for format in ["jsonl", "csv"] {
        let resp = s
            .call(
                Method::GET,
                &format!("/teams/{team_id}/audit/export?format={format}&action=nothing.matches"),
                Some(owner.token()),
                NOBODY,
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.text().await.unwrap();
        let rows = body.lines().filter(|l| !l.is_empty()).count();
        assert_eq!(
            rows,
            if format == "csv" { 1 } else { 0 },
            "{format}: {body}"
        );
    }
}
