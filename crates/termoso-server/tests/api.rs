//! End-to-end API tests against real PostgreSQL + Redis.
//!
//!     docker compose -f deploy/docker-compose.dev.yml up -d --wait
//!     cargo test -p termoso-server --test api
//!
//! Tests are skipped (pass vacuously) when the services are unreachable, unless
//! `TERMOSO_TEST_REQUIRE_SERVICES=1` (as in CI).

mod common;

use std::time::Duration;

use common::*;
use futures::{SinkExt, StreamExt};
use reqwest::{Method, StatusCode};
use termoso_crypto::aead::{self, Aad};
use termoso_crypto::keys::SymmetricKey;
use termoso_crypto::sealed;
use termoso_proto::account::ServerInfo;
use termoso_proto::auth::AuthResponse;
use termoso_proto::sync::{
    EntityChange, EntityDelete, HistoryEntry, HistoryKind, HistoryPullResponse, HistoryPushRequest,
    PullRequest, PullResponse, PushRequest, PushResponse, PushResult,
};
use termoso_proto::team::{
    AuditEventList, CreateInviteRequest, CreateTeamRequest, DigestCadence, DigestSubscription,
    SendDigestRequest, SendDigestResponse, Team, TeamMemberList, TeamRole, UpdateDigestRequest,
    UpdateTeamRequest,
};
use termoso_proto::vault::{
    CreateVaultRequest, ResealMyKeyRequest, Vault, VaultKind, VaultList, VaultMemberUpsert,
    VaultRole,
};
use termoso_proto::ws::{ClientMessage, ServerMessage};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

macro_rules! server {
    () => {
        match server().await {
            Some(s) => s,
            None => return,
        }
    };
}

#[tokio::test]
async fn captcha_page_needs_turnstile_keys() {
    let s = server!();
    let r = reqwest::get(format!("http://{}/captcha?theme=dark", s.addr))
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "no Turnstile keys configured → no page");
}

#[tokio::test]
async fn health_and_server_info() {
    let s = server!();
    let r = s
        .http()
        .get(format!("http://{}/healthz", s.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = s
        .http()
        .get(format!("http://{}/readyz", s.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());

    let r = s.http().get(s.url("/server/info")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        r.headers()["cache-control"],
        "no-store",
        "API responses must not land in shared or disk caches"
    );
    assert_eq!(r.headers()["x-content-type-options"], "nosniff");
    assert_eq!(r.headers()["referrer-policy"], "no-referrer");
    let info: ServerInfo = r.json().await.unwrap();
    assert!(info.registration_open);
    assert_eq!(info.version, termoso_server::VERSION);
    assert_eq!(info.sshid_url, SSHID_URL);
    assert_eq!(info.web_url, format!("http://{}", s.addr));
    assert!(
        !info.landing,
        "landing has its own origin, so / here is the cabinet"
    );
    assert!(!info.landing_only);

    let r = s
        .http()
        .get(format!("http://{}/api/openapi.json", s.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let doc: serde_json::Value = r.json().await.unwrap();
    assert!(doc["paths"]["/api/v1/sync/push"].is_object());
}

#[tokio::test]
async fn web_cabinet_is_served_with_spa_fallback() {
    let s = server!();
    let get = |path: &str| s.http().get(format!("http://{}{path}", s.addr)).send();

    // The landing lives on its own origin (TERMOSO_LANDING_URL), so the
    // cabinet root goes straight to sign-in.
    let r = s
        .http_no_redirect()
        .get(format!("http://{}/", s.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(r.headers()["location"], "/login");
    assert_eq!(r.headers()["cache-control"], "no-cache");

    let r = get("/login").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        r.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    assert_eq!(r.headers()["cache-control"], "no-cache");
    assert_eq!(r.headers()["x-frame-options"], "DENY");
    assert!(
        r.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("'wasm-unsafe-eval'")
    );
    assert!(r.text().await.unwrap().contains("<div id=root>"));

    // Client-side routes deep-link to index.html.
    let r = get("/team/00000000-0000-0000-0000-000000000000")
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.text().await.unwrap().contains("<div id=root>"));

    // Hashed assets are immutable; missing assets are real 404s.
    let r = get("/assets/app-abc123.js").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        r.headers()["cache-control"],
        "public, max-age=31536000, immutable"
    );
    assert!(r.headers().get("content-security-policy").is_none());
    let r = get("/assets/missing-000.js").await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let r = get("/favicon.svg").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["cache-control"], "no-cache");
    let r = get("/humans.txt").await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    // The cabinet is not for crawlers; robots.txt is generated, not a file.
    let r = get("/robots.txt").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.text().await.unwrap().contains("Disallow: /"));

    // Android App Links statement comes from config, not from the web dir.
    let r = get("/.well-known/assetlinks.json").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        r.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    let statements: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        statements,
        serde_json::json!([{
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "com.termoso.android.debug",
                "sha256_cert_fingerprints": [
                    "01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:20"
                ]
            }
        }])
    );
    let r = get("/.well-known/other.json").await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn landing_origin_serves_only_the_landing() {
    let s = server!();
    let get = |path: &str| {
        s.http_no_redirect()
            .get(format!("http://{}{path}", s.addr))
            .header("Host", LANDING_HOST)
            .send()
    };

    // `/` is the landing page (same SPA bundle, different root behaviour).
    let r = get("/").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        r.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    assert_eq!(r.headers()["x-frame-options"], "DENY");
    assert!(r.text().await.unwrap().contains("<div id=root>"));

    // Static files and health probes are served as usual.
    let r = get("/assets/app-abc123.js").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = get("/favicon.svg").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = get("/healthz").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // The SPA learns where it is from /server/info.
    let r = get("/api/v1/server/info").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let info: ServerInfo = r.json().await.unwrap();
    assert!(info.landing);
    assert!(info.landing_only);
    assert_eq!(info.web_url, format!("http://{}", s.addr));

    // Every cabinet route is sent to the cabinet origin, path and query
    // intact, so invite / join / SSO links keep working.
    for (path, expect) in [
        ("/login", "/login"),
        ("/signup?plan=team", "/signup?plan=team"),
        ("/invite/abc", "/invite/abc"),
        (
            "/join/00000000-0000-0000-0000-000000000000",
            "/join/00000000-0000-0000-0000-000000000000",
        ),
        ("/account", "/account"),
        ("/sshid/alice", "/sshid/alice"),
    ] {
        let r = get(path).await.unwrap();
        assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT, "{path}");
        assert_eq!(
            r.headers()["location"],
            format!("http://{}{expect}", s.addr).as_str(),
            "{path}"
        );
    }
    let r = s
        .http_no_redirect()
        .post(format!("http://{}/api/v1/auth/login/start", s.addr))
        .header("Host", LANDING_HOST)
        .send()
        .await
        .unwrap();
    // The API itself is not on the landing origin (see api_is_not_served_on_the_landing_origin).
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    // A path that is no route at all is a 404 of the public site on this
    // origin (the SPA shell renders it), not a bounce into the cabinet.
    for path in ["/signin", "/pricing", "/account-x"] {
        let r = get(path).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{path}");
        assert!(
            r.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html"),
            "{path}"
        );
        assert!(r.text().await.unwrap().contains("<div id=root>"), "{path}");
    }

    // Unknown files are plain 404s, not redirects; the public site allows crawlers.
    let r = get("/humans.txt").await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let r = get("/robots.txt").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.text().await.unwrap().contains("Allow: /"));

    // Unknown API paths are simply absent here; an unknown page stays on
    // this origin as the public site's 404 (see above).
    let r = get("/api/v1/no-such-route").await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let r = get("/no-such-page").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn register_login_and_sessions() {
    let s = server!();
    let email = unique_email("alice");
    let alice = register(s, &email, "correct horse battery staple").await;
    assert_eq!(alice.session.user.email, email.to_lowercase());
    assert!(!alice.session.user.is_admin);
    assert_eq!(alice.session.keys.public_key, alice.keypair.public_b64());

    // Personal vault exists and the sealed key opens with our keypair.
    let vaults: VaultList = s
        .json(Method::GET, "/vaults", Some(alice.token()), NOBODY)
        .await;
    assert_eq!(vaults.vaults.len(), 1);
    let personal = &vaults.vaults[0];
    assert_eq!(personal.kind, VaultKind::Personal);
    let opened =
        sealed::open_vault_key(&alice.keypair, personal.sealed_key.as_ref().unwrap()).unwrap();
    assert_eq!(opened.as_bytes(), alice.personal_vault_key.as_bytes());

    // Duplicate registration is rejected.
    let (req, _) = termoso_crypto::opaque::client_registration_start(b"whatever").expect("start");
    s.expect_status(
        Method::POST,
        "/auth/register/start",
        None,
        Some(&termoso_proto::auth::RegisterStartRequest {
            email: email.clone(),
            opaque_request: req,
            turnstile_token: None,
        }),
        StatusCode::CONFLICT,
    )
    .await;

    // Login from a new device with the right password.
    let AuthResponse::Authenticated(second) =
        login(s, &email, "correct horse battery staple").await
    else {
        panic!("expected session")
    };
    assert_ne!(second.token, alice.session.token);
    assert_ne!(second.device_id, alice.session.device_id);
    assert_eq!(
        second.keys.wrapped_private_key,
        alice.session.keys.wrapped_private_key
    );

    // Wrong password fails client-side and the server never yields a session.
    assert!(try_login(s, &email, "wrong password").await.is_err());

    // Two devices visible; revoking the second one kills its token.
    let me: serde_json::Value = s
        .json(Method::GET, "/account", Some(alice.token()), NOBODY)
        .await;
    assert_eq!(me["user"]["id"], alice.id().to_string());
    let devices: serde_json::Value = s
        .json(Method::GET, "/account/devices", Some(alice.token()), NOBODY)
        .await;
    assert_eq!(devices["devices"].as_array().unwrap().len(), 2);
    s.expect_status(
        Method::DELETE,
        &format!("/account/devices/{}", second.device_id),
        Some(alice.token()),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;
    s.expect_status(
        Method::GET,
        "/account",
        Some(&second.token),
        NOBODY,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    // Logout invalidates our own token.
    s.expect_status(
        Method::POST,
        "/auth/logout",
        Some(alice.token()),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;
    s.expect_status(
        Method::GET,
        "/account",
        Some(alice.token()),
        NOBODY,
        StatusCode::UNAUTHORIZED,
    )
    .await;
}

#[tokio::test]
async fn unauthenticated_requests_are_rejected() {
    let s = server!();
    s.expect_status(
        Method::GET,
        "/vaults",
        None,
        NOBODY,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    s.expect_status(
        Method::GET,
        "/vaults",
        Some("not-a-token"),
        NOBODY,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    s.expect_status(
        Method::GET,
        "/admin/stats",
        None,
        NOBODY,
        StatusCode::UNAUTHORIZED,
    )
    .await;
}

#[tokio::test]
async fn sync_push_pull_conflicts_and_tombstones() {
    let s = server!();
    let u = register(s, &unique_email("sync"), "pw-sync-1234567").await;
    let vaults: VaultList = s
        .json(Method::GET, "/vaults", Some(u.token()), NOBODY)
        .await;
    let vault_id = vaults.vaults[0].id;
    let key = &u.personal_vault_key;

    let host_id = Uuid::new_v4();
    let change = |base: Option<i64>, label: &str| EntityChange {
        secret_rotated_at: None,
        id: host_id,
        kind: "host".into(),
        vault_id,
        base_version: base,
        key_version: 1,
        data: u.encrypt_entity(key, "host", host_id, &format!(r#"{{"label":"{label}"}}"#)),
        updated_at: chrono::Utc::now(),
    };

    // Create.
    let r: PushResponse = s
        .json(
            Method::POST,
            "/sync/push",
            Some(u.token()),
            Some(&PushRequest {
                changes: vec![change(None, "one")],
                deletes: vec![],
            }),
        )
        .await;
    let PushResult::Ok {
        version: v1,
        seq: s1,
        ..
    } = &r.results[0]
    else {
        panic!("{:?}", r.results)
    };
    assert_eq!(*v1, 1);

    // Creating again with base_version=None conflicts.
    let r: PushResponse = s
        .json(
            Method::POST,
            "/sync/push",
            Some(u.token()),
            Some(&PushRequest {
                changes: vec![change(None, "dup")],
                deletes: vec![],
            }),
        )
        .await;
    assert!(
        matches!(r.results[0], PushResult::Conflict { .. }),
        "{:?}",
        r.results
    );

    // Update on the right base version.
    let r: PushResponse = s
        .json(
            Method::POST,
            "/sync/push",
            Some(u.token()),
            Some(&PushRequest {
                changes: vec![change(Some(1), "two")],
                deletes: vec![],
            }),
        )
        .await;
    let PushResult::Ok {
        version: v2,
        seq: s2,
        ..
    } = &r.results[0]
    else {
        panic!("{:?}", r.results)
    };
    assert_eq!(*v2, 2);
    assert!(s2 > s1);

    // Stale update conflicts and returns the server copy we can decrypt.
    let r: PushResponse = s
        .json(
            Method::POST,
            "/sync/push",
            Some(u.token()),
            Some(&PushRequest {
                changes: vec![change(Some(1), "stale")],
                deletes: vec![],
            }),
        )
        .await;
    let PushResult::Conflict { server, .. } = &r.results[0] else {
        panic!("{:?}", r.results)
    };
    assert_eq!(server.version, 2);
    let plain = aead::decrypt_str(
        key,
        &Aad::entity("host", &host_id.to_string()),
        &server.data,
    )
    .unwrap();
    assert_eq!(plain, r#"{"label":"two"}"#);

    // Unknown kind and unknown vault are per-item errors, not request failures.
    let r: PushResponse = s
        .json(
            Method::POST,
            "/sync/push",
            Some(u.token()),
            Some(&PushRequest {
                changes: vec![
                    EntityChange {
                        secret_rotated_at: None,
                        kind: "spaceship".into(),
                        ..change(None, "x")
                    },
                    EntityChange {
                        secret_rotated_at: None,
                        id: Uuid::new_v4(),
                        vault_id: Uuid::new_v4(),
                        ..change(None, "x")
                    },
                ],
                deletes: vec![],
            }),
        )
        .await;
    assert!(matches!(&r.results[0], PushResult::Error { code, .. } if code == "unknown_kind"));
    assert!(matches!(&r.results[1], PushResult::Error { code, .. } if code == "forbidden"));

    // Pull from 0 returns the live entity; pull from the last seq is empty.
    let p: PullResponse = s
        .json(
            Method::POST,
            "/sync/pull",
            Some(u.token()),
            Some(&PullRequest {
                cursors: cursors(&[(vault_id, 0)]),
                limit: None,
            }),
        )
        .await;
    assert_eq!(p.entities.len(), 1);
    assert_eq!(p.entities[0].version, 2);
    assert!(!p.has_more);
    assert_eq!(p.cursors[&vault_id], *s2);
    let p: PullResponse = s
        .json(
            Method::POST,
            "/sync/pull",
            Some(u.token()),
            Some(&PullRequest {
                cursors: p.cursors,
                limit: None,
            }),
        )
        .await;
    assert!(p.entities.is_empty());

    // Delete → tombstone shows up in the next pull.
    let r: PushResponse = s
        .json(
            Method::POST,
            "/sync/push",
            Some(u.token()),
            Some(&PushRequest {
                changes: vec![],
                deletes: vec![EntityDelete {
                    id: host_id,
                    base_version: 2,
                }],
            }),
        )
        .await;
    assert!(
        matches!(r.results[0], PushResult::Ok { .. }),
        "{:?}",
        r.results
    );
    let p: PullResponse = s
        .json(
            Method::POST,
            "/sync/pull",
            Some(u.token()),
            Some(&PullRequest {
                cursors: cursors(&[(vault_id, *s2)]),
                limit: None,
            }),
        )
        .await;
    assert_eq!(p.entities.len(), 1);
    assert!(p.entities[0].deleted);
    assert!(p.entities[0].data.is_empty());

    // Pagination: many small entities, limit 3.
    let ids: Vec<Uuid> = (0..7).map(|_| Uuid::new_v4()).collect();
    let r: PushResponse = s
        .json(
            Method::POST,
            "/sync/push",
            Some(u.token()),
            Some(&PushRequest {
                changes: ids
                    .iter()
                    .map(|id| EntityChange {
                        secret_rotated_at: None,
                        id: *id,
                        kind: "snippet".into(),
                        vault_id,
                        base_version: None,
                        key_version: 1,
                        data: u.encrypt_entity(key, "snippet", *id, "{}"),
                        updated_at: chrono::Utc::now(),
                    })
                    .collect(),
                deletes: vec![],
            }),
        )
        .await;
    assert!(r.results.iter().all(|x| matches!(x, PushResult::Ok { .. })));
    let mut seen = 0;
    let mut cur = cursors(&[(vault_id, 0)]);
    let mut pages = 0;
    loop {
        let p: PullResponse = s
            .json(
                Method::POST,
                "/sync/pull",
                Some(u.token()),
                Some(&PullRequest {
                    cursors: cur,
                    limit: Some(3),
                }),
            )
            .await;
        seen += p.entities.len();
        cur = p.cursors;
        pages += 1;
        if !p.has_more {
            break;
        }
        assert!(pages < 10, "pagination did not converge");
    }
    assert_eq!(seen, 8, "7 snippets + 1 tombstone");
}

#[tokio::test]
async fn teams_vaults_invites_and_sharing() {
    let s = server!();
    let owner = register(s, &unique_email("owner"), "pw-owner-1234567").await;
    let bob_email = unique_email("bob");
    let bob = register(s, &bob_email, "pw-bob-123456789").await;

    let team: Team = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&CreateTeamRequest { name: "Ops".into() }),
        )
        .await;
    assert_eq!(team.my_role, TeamRole::Owner);
    assert_eq!(team.member_count, 1);

    // Team vault with the owner as manager; key sealed to the owner.
    let vault_key = SymmetricKey::generate();
    let vault: Vault = s
        .json(
            Method::POST,
            &format!("/teams/{}/vaults", team.id),
            Some(owner.token()),
            Some(&CreateVaultRequest {
                name: "Production".into(),
                members: vec![VaultMemberUpsert {
                    user_id: owner.id(),
                    role: VaultRole::Manager,
                    sealed_key: sealed::seal_vault_key(owner.keypair.public(), &vault_key).unwrap(),
                }],
            }),
        )
        .await;
    assert_eq!(vault.kind, VaultKind::Team);
    assert_eq!(vault.team_id, Some(team.id));

    // Bob cannot see or push into the vault yet.
    let bobs: VaultList = s
        .json(Method::GET, "/vaults", Some(bob.token()), NOBODY)
        .await;
    assert!(bobs.vaults.iter().all(|v| v.id != vault.id));
    let host_id = Uuid::new_v4();
    let r: PushResponse = s
        .json(
            Method::POST,
            "/sync/push",
            Some(bob.token()),
            Some(&PushRequest {
                changes: vec![EntityChange {
                    secret_rotated_at: None,
                    id: host_id,
                    kind: "host".into(),
                    vault_id: vault.id,
                    base_version: None,
                    key_version: 1,
                    data: bob.encrypt_entity(&vault_key, "host", host_id, "{}"),
                    updated_at: chrono::Utc::now(),
                }],
                deletes: vec![],
            }),
        )
        .await;
    assert!(matches!(&r.results[0], PushResult::Error { code, .. } if code == "forbidden"));

    // Invite Bob (member) with access to the vault; a random user can't accept.
    let invite: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{}/invites", team.id),
            Some(owner.token()),
            Some(&CreateInviteRequest {
                email: bob_email.clone(),
                role: TeamRole::Member,
                role_id: None,
                vault_ids: vec![vault.id],
            }),
        )
        .await;
    let token = invite["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    let preview: serde_json::Value = s
        .json(Method::GET, &format!("/invites/{token}"), None, NOBODY)
        .await;
    assert_eq!(preview["team_name"], "Ops");
    assert_eq!(preview["account_exists"], true);
    let mallory = register(s, &unique_email("mallory"), "pw-mallory-12345").await;
    s.expect_status(
        Method::POST,
        &format!("/invites/{token}/accept"),
        Some(mallory.token()),
        NOBODY,
        StatusCode::FORBIDDEN,
    )
    .await;
    let joined: Team = s
        .json(
            Method::POST,
            &format!("/invites/{token}/accept"),
            Some(bob.token()),
            NOBODY,
        )
        .await;
    assert_eq!(joined.my_role, TeamRole::Member);
    assert_eq!(joined.member_count, 2);

    // Bob is a vault member but has no sealed key yet → shows in pending keys.
    let bobs: VaultList = s
        .json(Method::GET, "/vaults", Some(bob.token()), NOBODY)
        .await;
    let bv = bobs
        .vaults
        .iter()
        .find(|v| v.id == vault.id)
        .expect("bob sees vault");
    assert!(bv.sealed_key.is_none());
    let pending: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{}/pending-keys", team.id),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let items = pending["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["user_id"], bob.id().to_string());
    assert_eq!(items[0]["public_key"], bob.keypair.public_b64());

    // Owner seals the key for Bob via the member upsert endpoint.
    s.expect_status(
        Method::PUT,
        &format!("/vaults/{}/members/{}", vault.id, bob.id()),
        Some(owner.token()),
        Some(&VaultMemberUpsert {
            user_id: bob.id(),
            role: VaultRole::Editor,
            sealed_key: sealed::seal_vault_key(bob.keypair.public(), &vault_key).unwrap(),
        }),
        StatusCode::NO_CONTENT,
    )
    .await;
    let bobs: VaultList = s
        .json(Method::GET, "/vaults", Some(bob.token()), NOBODY)
        .await;
    let bv = bobs.vaults.iter().find(|v| v.id == vault.id).unwrap();
    let opened = sealed::open_vault_key(&bob.keypair, bv.sealed_key.as_ref().unwrap()).unwrap();
    assert_eq!(opened.as_bytes(), vault_key.as_bytes());
    assert_eq!(bv.my_role, VaultRole::Editor);

    // Now Bob can write, and the owner pulls it.
    let r: PushResponse = s
        .json(
            Method::POST,
            "/sync/push",
            Some(bob.token()),
            Some(&PushRequest {
                changes: vec![EntityChange {
                    secret_rotated_at: None,
                    id: host_id,
                    kind: "host".into(),
                    vault_id: vault.id,
                    base_version: None,
                    key_version: bv.key_version,
                    data: bob.encrypt_entity(&vault_key, "host", host_id, r#"{"label":"db1"}"#),
                    updated_at: chrono::Utc::now(),
                }],
                deletes: vec![],
            }),
        )
        .await;
    assert!(
        matches!(r.results[0], PushResult::Ok { .. }),
        "{:?}",
        r.results
    );
    let p: PullResponse = s
        .json(
            Method::POST,
            "/sync/pull",
            Some(owner.token()),
            Some(&PullRequest {
                cursors: cursors(&[(vault.id, 0)]),
                limit: None,
            }),
        )
        .await;
    assert_eq!(p.entities.len(), 1);
    assert_eq!(p.entities[0].updated_by_device, Some(bob.session.device_id));

    // Team activity log: every step above left a metadata-only entry.
    let audit_path = format!("/teams/{}/audit", team.id);
    s.expect_status(
        Method::GET,
        &audit_path,
        Some(mallory.token()),
        NOBODY,
        StatusCode::NOT_FOUND,
    )
    .await;
    let raw = s
        .call(Method::GET, &audit_path, Some(owner.token()), NOBODY)
        .await
        .text()
        .await
        .unwrap();
    assert!(!raw.contains(&bv.sealed_key.clone().unwrap()));
    assert!(!raw.contains(&p.entities[0].data));
    let log: AuditEventList = serde_json::from_str(&raw).unwrap();
    assert!(log.next_before.is_none());
    let actions: Vec<&str> = log.events.iter().map(|e| e.action.as_str()).collect();
    for expected in [
        "team.created",
        "vault.created",
        "invite.created",
        "invite.accepted",
        "vault.access_granted",
        "entity.created",
    ] {
        assert!(
            actions.contains(&expected),
            "{expected} missing in {actions:?}"
        );
    }
    assert!(
        log.events.windows(2).all(|w| w[0].id > w[1].id),
        "newest first"
    );
    let created = log
        .events
        .iter()
        .find(|e| e.action == "entity.created")
        .unwrap();
    assert_eq!(created.actor_id, Some(bob.id()));
    assert_eq!(created.actor_email.as_deref(), Some(bob_email.as_str()));
    assert_eq!(created.vault_id, Some(vault.id));
    assert_eq!(created.device_id, Some(bob.session.device_id));
    assert_eq!(created.details["kind"], "host");
    assert_eq!(created.details["count"], 1);
    assert_eq!(created.details["ids"][0], host_id.to_string());
    let granted = log
        .events
        .iter()
        .find(|e| e.action == "vault.access_granted")
        .unwrap();
    assert_eq!(granted.actor_id, Some(owner.id()));
    assert_eq!(granted.target_user, Some(bob.id()));
    assert_eq!(granted.target_email.as_deref(), Some(bob_email.as_str()));
    assert_eq!(granted.details["role"], "editor");

    // Members see the log too, but device ids only on their own entries.
    let bobs_log: AuditEventList = s
        .json(Method::GET, &audit_path, Some(bob.token()), NOBODY)
        .await;
    assert_eq!(bobs_log.events.len(), log.events.len());
    for e in &bobs_log.events {
        assert_eq!(e.device_id.is_some(), e.actor_id == Some(bob.id()), "{e:?}");
    }

    // Filters: action prefix, vault, actor; pagination via `before`.
    let only_vault: AuditEventList = s
        .json(
            Method::GET,
            &format!("{audit_path}?action=vault.&vault={}", vault.id),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert!(!only_vault.events.is_empty());
    assert!(
        only_vault
            .events
            .iter()
            .all(|e| e.action.starts_with("vault.") && e.vault_id == Some(vault.id))
    );
    let by_bob: AuditEventList = s
        .json(
            Method::GET,
            &format!("{audit_path}?actor={}", bob.id()),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert!(by_bob.events.iter().all(|e| e.actor_id == Some(bob.id())));
    assert!(by_bob.events.iter().any(|e| e.action == "invite.accepted"));
    let page1: AuditEventList = s
        .json(
            Method::GET,
            &format!("{audit_path}?limit=2"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(page1.events.len(), 2);
    let before = page1.next_before.expect("more pages");
    let page2: AuditEventList = s
        .json(
            Method::GET,
            &format!("{audit_path}?limit=2&before={before}"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert!(page2.events.iter().all(|e| e.id < before));
    assert_eq!(page1.events[1].id, before);
    assert!(page1.total.is_none());

    // Offset paging (the web cabinet) walks the same order and reports the total.
    let off: AuditEventList = s
        .json(
            Method::GET,
            &format!("{audit_path}?limit=2&offset=2"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(
        off.events.iter().map(|e| e.id).collect::<Vec<_>>(),
        page2
            .events
            .iter()
            .take(2)
            .map(|e| e.id)
            .collect::<Vec<_>>()
    );
    assert!(off.total.is_some_and(|t| t >= 3));

    // Bob (member) cannot delete the team; owner can, and the vault disappears.
    s.expect_status(
        Method::DELETE,
        &format!("/teams/{}", team.id),
        Some(bob.token()),
        NOBODY,
        StatusCode::FORBIDDEN,
    )
    .await;
    s.expect_status(
        Method::DELETE,
        &format!("/teams/{}", team.id),
        Some(owner.token()),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;
    let bobs: VaultList = s
        .json(Method::GET, "/vaults", Some(bob.token()), NOBODY)
        .await;
    assert!(bobs.vaults.iter().all(|v| v.id != vault.id));
}

#[tokio::test]
async fn history_push_pull_clear() {
    let s = server!();
    let u = register(s, &unique_email("hist"), "pw-history-12345").await;
    let entry = |kind: HistoryKind| {
        let id = Uuid::new_v4();
        HistoryEntry {
            id,
            kind,
            data: aead::encrypt_str(
                &u.personal_vault_key,
                &Aad::label(&["termoso/v1/history", "command", &id.to_string()]),
                "ls -la",
            )
            .unwrap(),
            key_version: 1,
            created_at: chrono::Utc::now(),
            seq: 0,
            deleted: false,
        }
    };
    let entries = vec![
        entry(HistoryKind::Command),
        entry(HistoryKind::Command),
        entry(HistoryKind::Connection),
    ];
    let _: serde_json::Value = s
        .json(
            Method::POST,
            "/history/push",
            Some(u.token()),
            Some(&HistoryPushRequest {
                entries: entries.clone(),
            }),
        )
        .await;
    // Idempotent re-push.
    let _: serde_json::Value = s
        .json(
            Method::POST,
            "/history/push",
            Some(u.token()),
            Some(&HistoryPushRequest { entries }),
        )
        .await;
    let p: HistoryPullResponse = s
        .json(
            Method::GET,
            "/history/pull?since=0",
            Some(u.token()),
            NOBODY,
        )
        .await;
    assert_eq!(p.entries.len(), 3);
    assert!(p.since > 0);
    let p2: HistoryPullResponse = s
        .json(
            Method::GET,
            &format!("/history/pull?since={}", p.since),
            Some(u.token()),
            NOBODY,
        )
        .await;
    assert!(p2.entries.is_empty());

    s.expect_status(
        Method::POST,
        "/history/clear",
        Some(u.token()),
        Some(&termoso_proto::sync::HistoryClearRequest {
            kind: Some(HistoryKind::Command),
        }),
        StatusCode::NO_CONTENT,
    )
    .await;
    let p3: HistoryPullResponse = s
        .json(
            Method::GET,
            &format!("/history/pull?since={}", p.since),
            Some(u.token()),
            NOBODY,
        )
        .await;
    let deleted = p3.entries.iter().filter(|e| e.deleted).count();
    assert_eq!(deleted, 2, "two commands tombstoned, connection kept");
}

#[tokio::test]
async fn websocket_notifies_on_push_and_revocation() {
    let s = server!();
    let u = register(s, &unique_email("ws"), "pw-websocket-1234").await;
    let vaults: VaultList = s
        .json(Method::GET, "/vaults", Some(u.token()), NOBODY)
        .await;
    let vault_id = vaults.vaults[0].id;

    let (mut ws, _) = tokio_tungstenite::connect_async(s.ws_url()).await.unwrap();
    ws.send(Message::Text(
        serde_json::to_string(&ClientMessage::Auth {
            token: u.token().into(),
        })
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();

    async fn next(
        ws: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin),
    ) -> ServerMessage {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
                .await
                .expect("ws timeout")
                .expect("ws closed")
                .expect("ws error");
            match msg {
                Message::Text(t) => return serde_json::from_str(&t).unwrap(),
                Message::Ping(_) | Message::Pong(_) => continue,
                other => panic!("unexpected frame {other:?}"),
            }
        }
    }

    let ServerMessage::Hello { vault_ids, .. } = next(&mut ws).await else {
        panic!("expected hello")
    };
    assert_eq!(vault_ids, vec![vault_id]);

    ws.send(Message::Text(
        serde_json::to_string(&ClientMessage::Ping).unwrap().into(),
    ))
    .await
    .unwrap();
    assert!(matches!(next(&mut ws).await, ServerMessage::Pong));

    // A push from another "device" (same user) arrives as VaultChanged.
    let id = Uuid::new_v4();
    let r: PushResponse = s
        .json(
            Method::POST,
            "/sync/push",
            Some(u.token()),
            Some(&PushRequest {
                changes: vec![EntityChange {
                    secret_rotated_at: None,
                    id,
                    kind: "group".into(),
                    vault_id,
                    base_version: None,
                    key_version: 1,
                    data: u.encrypt_entity(&u.personal_vault_key, "group", id, "{}"),
                    updated_at: chrono::Utc::now(),
                }],
                deletes: vec![],
            }),
        )
        .await;
    let PushResult::Ok { seq, .. } = r.results[0] else {
        panic!()
    };
    match next(&mut ws).await {
        ServerMessage::VaultChanged {
            vault_id: v,
            seq: got,
            ..
        } => {
            assert_eq!(v, vault_id);
            assert_eq!(got, seq);
        }
        other => panic!("expected VaultChanged, got {other:?}"),
    }

    // Logging out this session closes the socket with SessionRevoked.
    s.expect_status(
        Method::POST,
        "/auth/logout",
        Some(u.token()),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;
    assert!(matches!(next(&mut ws).await, ServerMessage::SessionRevoked));

    // Bad first frame → error and close.
    let (mut ws2, _) = tokio_tungstenite::connect_async(s.ws_url()).await.unwrap();
    ws2.send(Message::Text(
        serde_json::to_string(&ClientMessage::Auth {
            token: "garbage".into(),
        })
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();
    assert!(matches!(next(&mut ws2).await, ServerMessage::Error { .. }));
}

#[tokio::test]
async fn admin_endpoints_require_admin() {
    let s = server!();
    let plain = register(s, &unique_email("plain"), "pw-plain-1234567").await;
    s.expect_status(
        Method::GET,
        "/admin/stats",
        Some(plain.token()),
        NOBODY,
        StatusCode::FORBIDDEN,
    )
    .await;

    let admin = register(s, "admin@test.local", "pw-admin-1234567").await;
    assert!(admin.session.user.is_admin);
    let stats: serde_json::Value = s
        .json(Method::GET, "/admin/stats", Some(admin.token()), NOBODY)
        .await;
    assert!(stats["users"].as_i64().unwrap() >= 2);
    let users: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/admin/users?q={}", plain.email),
            Some(admin.token()),
            NOBODY,
        )
        .await;
    assert_eq!(users["users"].as_array().unwrap().len(), 1);

    // Disable the user: all their sessions are revoked and login is refused.
    let updated: serde_json::Value = s
        .json(
            Method::PATCH,
            &format!("/admin/users/{}", plain.id()),
            Some(admin.token()),
            Some(&serde_json::json!({ "disabled": true })),
        )
        .await;
    assert_eq!(updated["disabled"], true, "{updated}");
    s.expect_status(
        Method::GET,
        "/account",
        Some(plain.token()),
        NOBODY,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let err = common::try_login(s, &plain.email, "pw-plain-1234567")
        .await
        .expect_err("disabled user must not log in");
    assert!(err.contains("account_disabled"), "{err}");

    // Admins cannot disable themselves.
    s.expect_status(
        Method::PATCH,
        &format!("/admin/users/{}", admin.id()),
        Some(admin.token()),
        Some(&serde_json::json!({ "disabled": true })),
        StatusCode::BAD_REQUEST,
    )
    .await;
}

/// Accounts created through a team invitation are "managed": the owner can
/// delete them outright, while pre-existing accounts can only be removed.
/// Removing or leaving turns a managed account into an individual one.
#[tokio::test]
async fn owner_deletes_team_created_accounts_only() {
    let s = server!();
    let owner = register(s, &unique_email("own"), "pw-owner-123456789").await;
    let admin = register(s, &unique_email("adm"), "pw-admin-123456789").await;
    let team: Team = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&CreateTeamRequest { name: "Ops".into() }),
        )
        .await;
    // Admin existed before joining; Carol and Dave sign up through invitations.
    let t = invite(s, team.id, owner.token(), &admin.email, TeamRole::Admin).await;
    let _: Team = s
        .json(
            Method::POST,
            &format!("/invites/{t}/accept"),
            Some(admin.token()),
            NOBODY,
        )
        .await;
    let carol_email = unique_email("carol");
    let t = invite(s, team.id, owner.token(), &carol_email, TeamRole::Member).await;
    let carol = register_with(s, &carol_email, "pw-carol-123456789", Some(t)).await;
    let dave_email = unique_email("dave");
    let t = invite(s, team.id, owner.token(), &dave_email, TeamRole::Member).await;
    let dave = register_with(s, &dave_email, "pw-dave-1234567890", Some(t)).await;
    assert_eq!(carol.session.user.managed_by_team_id, Some(team.id));
    assert_eq!(admin.session.user.managed_by_team_id, None);

    let members: TeamMemberList = s
        .json(
            Method::GET,
            &format!("/teams/{}/members", team.id),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let managed = |id: Uuid| {
        members
            .members
            .iter()
            .find(|m| m.user_id == id)
            .unwrap()
            .managed
    };
    assert!(!managed(owner.id()));
    assert!(!managed(admin.id()));
    assert!(managed(carol.id()));
    assert!(managed(dave.id()));

    let account_path = |id: Uuid| format!("/teams/{}/members/{}/account", team.id, id);
    // Admins can't; only the owner.
    s.expect_status(
        Method::DELETE,
        &account_path(carol.id()),
        Some(admin.token()),
        NOBODY,
        StatusCode::FORBIDDEN,
    )
    .await;
    // Pre-existing accounts are off limits even for the owner.
    s.expect_status(
        Method::DELETE,
        &account_path(admin.id()),
        Some(owner.token()),
        NOBODY,
        StatusCode::CONFLICT,
    )
    .await;
    // Needs a fresh step-up.
    s.age_step_up(owner.token()).await;
    let v = s
        .expect_status(
            Method::DELETE,
            &account_path(carol.id()),
            Some(owner.token()),
            NOBODY,
            StatusCode::FORBIDDEN,
        )
        .await;
    assert_eq!(v["code"], "reauth_required");
    let AuthResponse::Authenticated(fresh) =
        try_login(s, &owner.email, &owner.password).await.unwrap()
    else {
        panic!("login")
    };
    // A managed member who owns another team must hand it over first.
    let _: Team = s
        .json(
            Method::POST,
            "/teams",
            Some(carol.token()),
            Some(&CreateTeamRequest {
                name: "Side".into(),
            }),
        )
        .await;
    s.expect_status(
        Method::DELETE,
        &account_path(carol.id()),
        Some(&fresh.token),
        NOBODY,
        StatusCode::CONFLICT,
    )
    .await;

    // Dave goes: account, sessions and membership are gone; audit keeps the trace.
    s.expect_status(
        Method::DELETE,
        &account_path(dave.id()),
        Some(&fresh.token),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;
    s.expect_status(
        Method::GET,
        "/account",
        Some(dave.token()),
        NOBODY,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert!(
        try_login(s, &dave.email, "pw-dave-1234567890")
            .await
            .is_err()
    );
    let members: TeamMemberList = s
        .json(
            Method::GET,
            &format!("/teams/{}/members", team.id),
            Some(&fresh.token),
            NOBODY,
        )
        .await;
    assert!(members.members.iter().all(|m| m.user_id != dave.id()));
    s.expect_status(
        Method::DELETE,
        &account_path(dave.id()),
        Some(&fresh.token),
        NOBODY,
        StatusCode::NOT_FOUND,
    )
    .await;
    let log: AuditEventList = s
        .json(
            Method::GET,
            &format!("/teams/{}/audit", team.id),
            Some(&fresh.token),
            NOBODY,
        )
        .await;
    let deleted = log
        .events
        .iter()
        .find(|e| e.action == "member.account_deleted")
        .expect("audit entry");
    assert_eq!(deleted.target_user, Some(dave.id()));

    // Removing Carol from the team converts the account: it keeps working and
    // is no longer managed, so re-inviting doesn't make it deletable again.
    s.expect_status(
        Method::DELETE,
        &format!("/teams/{}/members/{}", team.id, carol.id()),
        Some(&fresh.token),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;
    let me: serde_json::Value = s
        .json(Method::GET, "/account", Some(carol.token()), NOBODY)
        .await;
    assert!(me["user"]["managed_by_team_id"].is_null(), "{me}");
    let removed = log_action(s, team.id, &fresh.token, "member.removed").await;
    assert_eq!(removed["details"]["account"], "converted");
    let t = invite(s, team.id, owner.token(), &carol.email, TeamRole::Member).await;
    let _: Team = s
        .json(
            Method::POST,
            &format!("/invites/{t}/accept"),
            Some(carol.token()),
            NOBODY,
        )
        .await;
    s.expect_status(
        Method::DELETE,
        &account_path(carol.id()),
        Some(&fresh.token),
        NOBODY,
        StatusCode::CONFLICT,
    )
    .await;
}

/// Admins opt in to a daily/weekly e-mail digest of the activity log; it is
/// built from the same audit rows, skipped for quiet periods, sent once per
/// period even with several server instances, and dropped when the
/// subscriber stops being an admin.
#[tokio::test]
async fn team_activity_digest_is_opt_in_per_admin() {
    let s = server!();
    if s.mailpit.is_none() {
        eprintln!("skipping: Mailpit not configured");
        return;
    }
    let owner = register(s, &unique_email("dig-own"), "pw-owner-123456789").await;
    let admin = register(s, &unique_email("dig-adm"), "pw-admin-123456789").await;
    let member = register(s, &unique_email("dig-mem"), "pw-member-12345678").await;
    let team: Team = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&CreateTeamRequest {
                name: "Digest".into(),
            }),
        )
        .await;
    for (u, role) in [(&admin, TeamRole::Admin), (&member, TeamRole::Member)] {
        let t = invite(s, team.id, owner.token(), &u.email, role).await;
        let _: Team = s
            .json(
                Method::POST,
                &format!("/invites/{t}/accept"),
                Some(u.token()),
                NOBODY,
            )
            .await;
    }
    let digest_path = format!("/teams/{}/digest", team.id);

    // Members don't get the admin view by mail either.
    s.expect_status(
        Method::GET,
        &digest_path,
        Some(member.token()),
        NOBODY,
        StatusCode::FORBIDDEN,
    )
    .await;
    s.expect_status(
        Method::PUT,
        &digest_path,
        Some(member.token()),
        Some(&UpdateDigestRequest {
            cadence: Some(DigestCadence::Daily),
        }),
        StatusCode::FORBIDDEN,
    )
    .await;

    // Nobody is subscribed until they ask.
    let sub: DigestSubscription = s
        .json(Method::GET, &digest_path, Some(admin.token()), NOBODY)
        .await;
    assert_eq!(sub.cadence, None);
    let sub: DigestSubscription = s
        .json(
            Method::PUT,
            &digest_path,
            Some(admin.token()),
            Some(&UpdateDigestRequest {
                cadence: Some(DigestCadence::Weekly),
            }),
        )
        .await;
    assert_eq!(sub.cadence, Some(DigestCadence::Weekly));
    let sub: DigestSubscription = s
        .json(
            Method::PUT,
            &digest_path,
            Some(owner.token()),
            Some(&UpdateDigestRequest {
                cadence: Some(DigestCadence::Daily),
            }),
        )
        .await;
    assert_eq!(sub.cadence, Some(DigestCadence::Daily));
    // The owner's subscription is their own, not the admin's.
    let sub: DigestSubscription = s
        .json(Method::GET, &digest_path, Some(admin.token()), NOBODY)
        .await;
    assert_eq!(sub.cadence, Some(DigestCadence::Weekly));

    let _: Team = s
        .json(
            Method::PATCH,
            &format!("/teams/{}", team.id),
            Some(owner.token()),
            Some(&UpdateTeamRequest {
                name: Some("Digest Ops".into()),
                ..Default::default()
            }),
        )
        .await;

    // "Send now" mails the last day to the caller only.
    let before = s.email_count(&admin.email).await;
    let r: SendDigestResponse = s
        .json(
            Method::POST,
            &format!("{digest_path}/send"),
            Some(admin.token()),
            Some(&SendDigestRequest {
                cadence: Some(DigestCadence::Daily),
            }),
        )
        .await;
    assert!(r.sent);
    assert!(r.events >= 4, "{r:?}");
    let body = s
        .emailed_body(&admin.email, "Digest Ops: activity for")
        .await;
    assert!(
        body.contains("renamed the team to \"Digest Ops\""),
        "{body}"
    );
    assert!(body.contains("joined the team as Admin"), "{body}");
    assert!(body.contains("Invitations: 4"), "{body}");
    // Three accounts share the display name; the digest tells them apart.
    assert!(
        body.contains(&format!(
            "Test User ({}) joined the team as Admin",
            admin.email
        )),
        "{body}"
    );
    assert!(
        body.contains(&format!("/team/{}", team.id)),
        "footer links to the team page: {body}"
    );
    assert_eq!(s.email_count(&admin.email).await, before + 1);

    // The scheduler: pretend it is the morning after (daily) and the next
    // Monday morning (weekly); each subscription is mailed exactly once, and a
    // second instance running the same tick finds nothing left to claim.
    let (smtp, _) = smtp_config().await.expect("mailpit");
    let mail_cfg = termoso_server::config::Config {
        server_name: "Termoso Test".into(),
        ..Default::default()
    };
    let mailer = termoso_server::mail::Mailer::new(&smtp, &mail_cfg).expect("mailer");
    let db = sqlx::PgPool::connect(&s.database_url).await.expect("db");
    let today = chrono::Utc::now().date_naive();
    let at_8 = |d: chrono::NaiveDate| d.and_hms_opt(8, 0, 0).expect("time").and_utc();
    let tomorrow = today.succ_opt().expect("date");
    let days_to_monday = 7 - chrono::Datelike::weekday(&today).num_days_from_monday();
    let next_monday = today
        .checked_add_days(chrono::Days::new(u64::from(days_to_monday)))
        .expect("date");
    let owner_before = s.email_count(&owner.email).await;
    let admin_before = s.email_count(&admin.email).await;
    let mut sent = 0;
    for now in [at_8(tomorrow), at_8(next_monday), at_8(next_monday)] {
        sent += termoso_server::digest::send_due(&db, &mailer, "http://cabinet.test", now)
            .await
            .expect("send_due");
    }
    assert_eq!(sent, 2, "one daily for the owner, one weekly for the admin");
    let body = s
        .emailed_body(&owner.email, "Digest Ops: activity for")
        .await;
    assert!(body.contains("Timeline (UTC):"), "{body}");
    assert!(body.contains("http://cabinet.test/team/"), "{body}");
    assert_eq!(s.email_count(&owner.email).await, owner_before + 1);
    assert_eq!(s.email_count(&admin.email).await, admin_before + 1);
    let sub: DigestSubscription = s
        .json(Method::GET, &digest_path, Some(owner.token()), NOBODY)
        .await;
    assert_eq!(
        sub.last_sent_at,
        Some(at_8(next_monday) - chrono::TimeDelta::hours(8))
    );

    // Unsubscribing is a null cadence.
    let sub: DigestSubscription = s
        .json(
            Method::PUT,
            &digest_path,
            Some(owner.token()),
            Some(&UpdateDigestRequest { cadence: None }),
        )
        .await;
    assert_eq!(sub.cadence, None);

    // Demoted to member: the subscription goes with the admin role.
    s.expect_status(
        Method::PATCH,
        &format!("/teams/{}/members/{}", team.id, admin.id()),
        Some(owner.token()),
        Some(&serde_json::json!({ "role": "member" })),
        StatusCode::NO_CONTENT,
    )
    .await;
    termoso_server::digest::send_due(&db, &mailer, "http://cabinet.test", at_8(next_monday))
        .await
        .expect("send_due");
    let (left,): (i64,) = sqlx::query_as("SELECT count(*) FROM team_digests WHERE team_id = $1")
        .bind(team.id)
        .fetch_one(&db)
        .await
        .expect("count");
    assert_eq!(left, 0);
}

async fn invite(s: &TestServer, team_id: Uuid, token: &str, email: &str, role: TeamRole) -> String {
    let invite: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{team_id}/invites"),
            Some(token),
            Some(&CreateInviteRequest {
                email: email.to_string(),
                role,
                role_id: None,
                vault_ids: vec![],
            }),
        )
        .await;
    invite["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string()
}

async fn log_action(s: &TestServer, team_id: Uuid, token: &str, action: &str) -> serde_json::Value {
    let log: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/audit"),
            Some(token),
            NOBODY,
        )
        .await;
    log["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == action)
        .cloned()
        .unwrap_or_else(|| panic!("{action} missing in {log}"))
}

#[tokio::test]
async fn reseal_my_key_upgrades_own_copy_without_granting_access() {
    let s = server!();
    let alice = register(s, &unique_email("alice"), "pw-alice-1234567").await;
    let mallory = register(s, &unique_email("mallory"), "pw-mallory-12345").await;
    let vaults: VaultList = s
        .json(Method::GET, "/vaults", Some(alice.token()), NOBODY)
        .await;
    let personal = vaults
        .vaults
        .iter()
        .find(|v| v.kind == VaultKind::Personal)
        .expect("personal vault");
    let sealed_self =
        sealed::seal_vault_key_self(&alice.keypair, &alice.personal_vault_key).unwrap();

    // A stranger cannot touch someone else's vault (404: it does not exist for them).
    s.expect_status(
        Method::PUT,
        &format!("/vaults/{}/my-key", personal.id),
        Some(mallory.token()),
        Some(&ResealMyKeyRequest {
            key_version: personal.key_version,
            sealed_key: sealed::seal_vault_key_self(&mallory.keypair, &mallory.personal_vault_key)
                .unwrap(),
        }),
        StatusCode::NOT_FOUND,
    )
    .await;
    // Malformed envelope and stale key version are rejected.
    s.expect_status(
        Method::PUT,
        &format!("/vaults/{}/my-key", personal.id),
        Some(alice.token()),
        Some(&ResealMyKeyRequest {
            key_version: personal.key_version,
            sealed_key: "not base64!".into(),
        }),
        StatusCode::BAD_REQUEST,
    )
    .await;
    s.expect_status(
        Method::PUT,
        &format!("/vaults/{}/my-key", personal.id),
        Some(alice.token()),
        Some(&ResealMyKeyRequest {
            key_version: personal.key_version + 1,
            sealed_key: sealed_self.clone(),
        }),
        StatusCode::CONFLICT,
    )
    .await;

    // Success: same key, same version, new self-authenticated envelope.
    s.expect_status(
        Method::PUT,
        &format!("/vaults/{}/my-key", personal.id),
        Some(alice.token()),
        Some(&ResealMyKeyRequest {
            key_version: personal.key_version,
            sealed_key: sealed_self.clone(),
        }),
        StatusCode::NO_CONTENT,
    )
    .await;
    let vaults: VaultList = s
        .json(Method::GET, "/vaults", Some(alice.token()), NOBODY)
        .await;
    let after = vaults.vaults.iter().find(|v| v.id == personal.id).unwrap();
    assert_eq!(after.key_version, personal.key_version);
    assert_eq!(after.sealed_key.as_deref(), Some(sealed_self.as_str()));
    let (key, origin) =
        sealed::open_vault_key_checked(&alice.keypair, after.sealed_key.as_ref().unwrap()).unwrap();
    assert_eq!(key.as_bytes(), alice.personal_vault_key.as_bytes());
    assert_eq!(origin, sealed::SealedKeyOrigin::SelfAuthenticated);

    // A team member without a sealed key (pending) cannot use it to smuggle one in.
    let team: Team = s
        .json(
            Method::POST,
            "/teams",
            Some(alice.token()),
            Some(&CreateTeamRequest { name: "Ops".into() }),
        )
        .await;
    let vault_key = SymmetricKey::generate();
    let vault: Vault = s
        .json(
            Method::POST,
            &format!("/teams/{}/vaults", team.id),
            Some(alice.token()),
            Some(&CreateVaultRequest {
                name: "Shared".into(),
                members: vec![VaultMemberUpsert {
                    user_id: alice.id(),
                    role: VaultRole::Manager,
                    sealed_key: sealed::seal_vault_key(alice.keypair.public(), &vault_key).unwrap(),
                }],
            }),
        )
        .await;
    let invite: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{}/invites", team.id),
            Some(alice.token()),
            Some(&CreateInviteRequest {
                email: mallory.email.clone(),
                role: TeamRole::Member,
                role_id: None,
                vault_ids: vec![vault.id],
            }),
        )
        .await;
    let token = invite["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    let _: Team = s
        .json(
            Method::POST,
            &format!("/invites/{token}/accept"),
            Some(mallory.token()),
            NOBODY,
        )
        .await;
    s.expect_status(
        Method::PUT,
        &format!("/vaults/{}/my-key", vault.id),
        Some(mallory.token()),
        Some(&ResealMyKeyRequest {
            key_version: 1,
            sealed_key: sealed::seal_vault_key_self(&mallory.keypair, &vault_key).unwrap(),
        }),
        StatusCode::FORBIDDEN,
    )
    .await;
    let mv: VaultList = s
        .json(Method::GET, "/vaults", Some(mallory.token()), NOBODY)
        .await;
    assert!(
        mv.vaults
            .iter()
            .find(|v| v.id == vault.id)
            .unwrap()
            .sealed_key
            .is_none()
    );
}

/// Custom team roles: catalog, create, invite with a role, enforcement,
/// reassignment and deletion.
#[tokio::test]
async fn custom_roles_are_enforced() {
    let s = server!();
    let owner = register(s, &unique_email("owner"), "pw-owner-1234567").await;
    let bob_email = unique_email("bob");
    let bob = register(s, &bob_email, "pw-bob-123456789").await;
    let team: Team = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&CreateTeamRequest { name: "Ops".into() }),
        )
        .await;
    assert_eq!(team.my_permissions, vec!["*".to_string()]);

    let catalog: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{}/permissions", team.id),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert!(catalog["permissions"].as_array().unwrap().len() >= 30);

    // Built-ins are seeded; an unknown or owner-only permission is rejected.
    let roles: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{}/roles", team.id),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let slugs: Vec<&str> = roles["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, vec!["owner", "admin", "member", "viewer", "auditor"]);
    let admin_id = roles["roles"][1]["id"].as_str().unwrap().to_string();
    for bad in ["team.delete", "nope.nothing"] {
        s.expect_status(
            Method::POST,
            &format!("/teams/{}/roles", team.id),
            Some(owner.token()),
            Some(&serde_json::json!({ "name": "Bad", "permissions": [bad] })),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    let role: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{}/roles", team.id),
            Some(owner.token()),
            Some(&serde_json::json!({
                "name": "Connect only",
                "permissions": ["team.view", "entities.read", "connect.ssh"]
            })),
        )
        .await;
    assert_eq!(role["slug"], "connect-only");
    let role_id: Uuid = role["id"].as_str().unwrap().parse().unwrap();

    // Invite Bob into the custom role; the invite carries the role.
    let invite: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{}/invites", team.id),
            Some(owner.token()),
            Some(&serde_json::json!({
                "email": bob_email, "role": "member", "role_id": role_id, "vault_ids": []
            })),
        )
        .await;
    assert_eq!(invite["role_ref"]["slug"], "connect-only");
    let token = invite["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    let joined: Team = s
        .json(
            Method::POST,
            &format!("/invites/{token}/accept"),
            Some(bob.token()),
            NOBODY,
        )
        .await;
    assert_eq!(joined.my_role, TeamRole::Member);
    assert_eq!(joined.my_role_ref.as_ref().unwrap().slug, "connect-only");
    assert!(joined.my_permissions.iter().any(|p| p == "connect.ssh"));
    assert!(!joined.my_permissions.iter().any(|p| p == "vaults.create"));

    // Enforcement: no `members.invite` → 403 permission_denied naming it.
    let resp = s
        .call(
            Method::GET,
            &format!("/teams/{}/invites", team.id),
            Some(bob.token()),
            NOBODY,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let err: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(err["code"], "permission_denied");
    assert_eq!(err["details"]["permission"], "members.invite");
    // Bob cannot give himself a role he does not hold the permissions of.
    s.expect_status(
        Method::PATCH,
        &format!("/teams/{}/members/{}", team.id, bob.id()),
        Some(bob.token()),
        Some(&serde_json::json!({ "role": "member", "role_id": admin_id })),
        StatusCode::FORBIDDEN,
    )
    .await;
    // A role in use cannot be deleted without a target; with one, members move.
    s.expect_status(
        Method::DELETE,
        &format!("/teams/{}/roles/{role_id}?reassign_to={admin_id}", team.id),
        Some(owner.token()),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;
    let after: serde_json::Value = s
        .json(Method::GET, "/teams", Some(bob.token()), NOBODY)
        .await;
    assert_eq!(after["teams"][0]["my_role_ref"]["slug"], "admin");
    assert_eq!(after["teams"][0]["my_role"], "admin");
}

#[tokio::test]
async fn api_is_not_served_on_the_landing_origin() {
    let s = server!();
    let on_landing = |path: &str| {
        s.http_no_redirect()
            .get(format!("http://{}{path}", s.addr))
            .header("host", "landing.test")
            .send()
    };

    // The landing needs `/server/info` (downloads, version) and the probes.
    let r = on_landing("/api/v1/server/info").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let info: termoso_proto::account::ServerInfo = r.json().await.unwrap();
    assert!(info.landing_only);
    let r = on_landing("/healthz").await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // Everything else in the API is absent there instead of being redirected
    // (a 307 keeps the method and body, so clients would just follow it).
    for path in [
        "/api/v1/vaults",
        "/api/v1/auth/login/start",
        "/api/v1/ws",
        "/api/openapi.json",
    ] {
        let r = on_landing(path).await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path}");
    }

    // Cabinet routes still bounce to the cabinet origin.
    let r = on_landing("/account").await.unwrap();
    assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        r.headers()["location"],
        format!("http://{}/account", s.addr)
    );
}

#[tokio::test]
async fn accepting_an_invite_verifies_the_mailbox() {
    let s = server!();
    if s.mailpit.is_none() {
        return;
    }
    let owner = register(s, &unique_email("owner"), "pw-owner-1234567").await;
    let team: Team = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&CreateTeamRequest { name: "Ops".into() }),
        )
        .await;
    let bob_email = unique_email("bob");
    let bob = register_unverified(s, &bob_email, "pw-bob-123456789", None).await;
    assert!(!bob.session.user.email_verified);
    // Unverified: no team of their own yet.
    s.expect_status(
        Method::POST,
        "/teams",
        Some(bob.token()),
        Some(&CreateTeamRequest {
            name: "Mine".into(),
        }),
        StatusCode::FORBIDDEN,
    )
    .await;

    let invite: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{}/invites", team.id),
            Some(owner.token()),
            Some(&CreateInviteRequest {
                email: bob_email.clone(),
                role: TeamRole::Member,
                role_id: None,
                vault_ids: vec![],
            }),
        )
        .await;
    let token = invite["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    // The token was mailed to that address: accepting proves the mailbox.
    let joined: Team = s
        .json(
            Method::POST,
            &format!("/invites/{token}/accept"),
            Some(bob.token()),
            NOBODY,
        )
        .await;
    assert_eq!(joined.my_role, TeamRole::Member);
    let sess: serde_json::Value = s
        .json(Method::GET, "/account", Some(bob.token()), NOBODY)
        .await;
    assert_eq!(sess["user"]["email_verified"], true, "{sess}");
    let _: Team = s
        .json(
            Method::POST,
            "/teams",
            Some(bob.token()),
            Some(&CreateTeamRequest {
                name: "Mine".into(),
            }),
        )
        .await;
}
