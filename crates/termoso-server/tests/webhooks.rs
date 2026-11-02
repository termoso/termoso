//! Audit webhooks: CRUD + validation, signed generic delivery through the
//! outbox, delivery history.

mod common;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use common::*;
use reqwest::{Method, StatusCode};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Received(Arc<Mutex<Vec<(HeaderMap, Bytes)>>>);

async fn sink(State(r): State<Received>, headers: HeaderMap, body: Bytes) -> StatusCode {
    r.0.lock().unwrap().push((headers, body));
    StatusCode::ACCEPTED
}

async fn receiver() -> (String, Received) {
    let received = Received::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/hook", post(sink))
        .with_state(received.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, received)
}

#[tokio::test]
async fn webhooks_deliver_signed_batches() {
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

    let (url, received) = receiver().await;
    // Validation and permissions.
    s.expect_status(
        Method::POST,
        &format!("/teams/{team_id}/webhooks"),
        Some(bob.token()),
        Some(&serde_json::json!({ "url": url, "secret": "s3cret-s3cret" })),
        StatusCode::FORBIDDEN,
    )
    .await;
    for bad in [
        serde_json::json!({ "url": "ftp://example.com/x", "secret": "s3cret-s3cret" }),
        serde_json::json!({ "url": "https://user:pw@example.com/x", "secret": "s3cret-s3cret" }),
        serde_json::json!({ "url": url, "secret": "short" }),
        serde_json::json!({ "url": url, "secret": "s3cret-s3cret", "kind": "carrier_pigeon" }),
        serde_json::json!({ "url": url, "secret": "s3cret-s3cret", "actions": ["bad action"] }),
    ] {
        s.expect_status(
            Method::POST,
            &format!("/teams/{team_id}/webhooks"),
            Some(owner.token()),
            Some(&bad),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    let hook: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{team_id}/webhooks"),
            Some(owner.token()),
            Some(&serde_json::json!({ "url": url, "secret": "s3cret-s3cret", "actions": ["team.", "webhook.test"] })),
        )
        .await;
    let wid = hook["id"].as_str().unwrap().to_string();
    assert_eq!(hook["kind"], "generic");
    assert_eq!(hook["enabled"], true);
    assert!(hook.get("secret").is_none());

    // Events matching the filter queue up; a rename matches `team.`.
    let _: serde_json::Value = s
        .json(
            Method::PATCH,
            &format!("/teams/{team_id}"),
            Some(owner.token()),
            Some(&serde_json::json!({ "name": "Ops 2" })),
        )
        .await;
    // The test endpoint drains this hook's queue synchronously.
    let d: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{team_id}/webhooks/{wid}/test"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let deliveries = d["deliveries"].as_array().unwrap();
    assert!(deliveries.len() >= 2, "{d}");
    assert!(
        deliveries
            .iter()
            .all(|x| x["status"] == "ok" && x["response_status"] == 202),
        "{d}"
    );
    assert!(deliveries.iter().any(|x| x["action"] == "webhook.test"));
    assert!(
        deliveries
            .iter()
            .any(|x| x["action"].as_str().unwrap().starts_with("team."))
    );

    // The receiver saw a signed batch.
    let got = received.0.lock().unwrap().clone();
    assert!(!got.is_empty());
    let (headers, body) = &got[0];
    let ts = headers["x-termoso-timestamp"].to_str().unwrap();
    let sig = headers["x-termoso-signature"].to_str().unwrap();
    assert_eq!(
        sig,
        termoso_server::webhooks::signature("s3cret-s3cret", ts, body)
    );
    let payload: serde_json::Value = serde_json::from_slice(body).unwrap();
    let events = payload["events"].as_array().unwrap();
    assert_eq!(
        headers["x-termoso-event-count"].to_str().unwrap(),
        events.len().to_string()
    );
    assert!(
        events
            .iter()
            .all(|e| e["team_id"] == team_id && e["actor"]["email"] == owner.email)
    );

    // Hook status reflects success; history is readable; delete removes it.
    let list: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/webhooks"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(list["webhooks"][0]["last_status"], 202);
    assert_eq!(list["webhooks"][0]["failures"], 0);
    let hist: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/webhooks/{wid}/deliveries"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert!(!hist["deliveries"].as_array().unwrap().is_empty());
    let upd: serde_json::Value = s
        .json(
            Method::PATCH,
            &format!("/teams/{team_id}/webhooks/{wid}"),
            Some(owner.token()),
            Some(&serde_json::json!({ "enabled": false, "kind": "splunk_hec" })),
        )
        .await;
    assert_eq!(upd["enabled"], false);
    assert_eq!(upd["kind"], "splunk_hec");
    s.expect_status(
        Method::DELETE,
        &format!("/teams/{team_id}/webhooks/{wid}"),
        Some(owner.token()),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;
    s.expect_status(
        Method::GET,
        &format!("/teams/{team_id}/webhooks/{wid}/deliveries"),
        Some(owner.token()),
        NOBODY,
        StatusCode::NOT_FOUND,
    )
    .await;
}

async fn failing_receiver() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let app = Router::new().route(
        "/hook",
        post(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

async fn team_with_owner(s: &TestServer) -> (User, String, String) {
    let owner_email = unique_email("owner");
    let owner = register(s, &owner_email, "pw-owner-1234567").await;
    let team: serde_json::Value = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&serde_json::json!({ "name": "Ops" })),
        )
        .await;
    let team_id = team["id"].as_str().unwrap().to_string();
    (owner, owner_email, team_id)
}

/// The 50th consecutive failure switches the hook off and emails everyone
/// with `webhooks.manage`.
#[tokio::test]
async fn webhook_auto_disable_emails_admins() {
    let Some(s) = server().await else { return };
    let (owner, owner_email, team_id) = team_with_owner(s).await;
    let url = failing_receiver().await;
    let hook: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{team_id}/webhooks"),
            Some(owner.token()),
            Some(&serde_json::json!({ "url": url, "secret": "s3cret-s3cret" })),
        )
        .await;
    let wid = hook["id"].as_str().unwrap().to_string();
    s.sql(
        "UPDATE team_webhooks SET failures = 49 WHERE id = $1::uuid",
        &wid,
    )
    .await;
    let d: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{team_id}/webhooks/{wid}/test"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert!(
        d["deliveries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["response_status"] == 500),
        "{d}"
    );
    let list: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/webhooks"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let w = list["webhooks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["id"] == wid.as_str())
        .unwrap();
    assert_eq!(w["enabled"], false, "{w}");
    assert_eq!(w["failures"], 50, "{w}");
    if s.mailpit.is_some() {
        let body = s.emailed_body(&owner_email, "Audit webhook disabled").await;
        assert!(body.contains("50 deliveries"), "{body}");
        assert!(body.contains("/hook"), "{body}");
    }
}

/// `syslog_tls`: RFC 5425 framing over TLS, one CEF line per event, the
/// private CA from `TERMOSO_WEBHOOKS_SYSLOG_CA` is trusted.
#[tokio::test]
async fn webhook_syslog_tls_delivers_cef() {
    use tokio::io::AsyncReadExt;
    use tokio_rustls::rustls;
    let Some(s) = server().await else { return };
    let (owner, _, team_id) = team_with_owner(s).await;

    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(syslog_ca_path(), ck.cert.pem()).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![ck.cert.der().clone()], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let got: Arc<Mutex<Vec<u8>>> = Arc::default();
    let sink = got.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let sink = sink.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let mut buf = Vec::new();
                    let _ = tls.read_to_end(&mut buf).await;
                    sink.lock().unwrap().extend_from_slice(&buf);
                }
            });
        }
    });

    // Kind/URL must agree; an empty secret is fine for syslog.
    s.expect_status(
        Method::POST,
        &format!("/teams/{team_id}/webhooks"),
        Some(owner.token()),
        Some(&serde_json::json!({ "url": format!("syslog+tls://localhost:{port}"), "secret": "" })),
        StatusCode::BAD_REQUEST,
    )
    .await;
    let hook: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{team_id}/webhooks"),
            Some(owner.token()),
            Some(&serde_json::json!({
                "url": format!("syslog+tls://localhost:{port}"), "secret": "", "kind": "syslog_tls"
            })),
        )
        .await;
    let wid = hook["id"].as_str().unwrap().to_string();
    let d: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{team_id}/webhooks/{wid}/test"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert!(
        d["deliveries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["status"] == "ok" && x["response_status"] == 200),
        "{d}"
    );
    let mut text = String::new();
    for _ in 0..50 {
        text = String::from_utf8_lossy(&got.lock().unwrap()).into_owned();
        if text.contains("webhook.test") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(text.contains("CEF:0|Termoso|Termoso|"), "{text}");
    assert!(text.contains("|webhook.test|webhook.test|"), "{text}");
    // Octet counting: "<len> <PRI>1 <ts> ...".
    let (len, rest) = text.split_once(' ').unwrap();
    let len: usize = len.parse().unwrap();
    assert!(
        rest.starts_with("<110>1 ") || rest.starts_with("<108>1 "),
        "{text}"
    );
    assert!(rest.len() >= len, "{text}");
}
