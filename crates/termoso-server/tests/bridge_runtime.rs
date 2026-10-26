//! `termoso-bridge` runtime against the in-process server: REST in, encrypted
//! entities out; the server never sees plaintext.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use common::*;
use reqwest::{Method, StatusCode};
use termoso_bridge::credentials::parse_credentials;
use termoso_bridge::{Bridge, RestConfig, router};
use termoso_crypto::aead::{self, Aad};
use termoso_crypto::keys::KeyPair;
use termoso_crypto::sealed;
use termoso_proto::bridge::*;
use termoso_proto::entities::payload::{Group, Host, Identity, SshConfig, SshKey, Tag};
use termoso_proto::sync::{PullRequest, PullResponse};
use termoso_proto::vault::{
    RotateVaultKeyRequest, RotateVaultKeyResponse, SealedKeyFor, VaultList,
};
use uuid::Uuid;

macro_rules! server {
    () => {
        match server().await {
            Some(s) => s,
            None => return,
        }
    };
}

const PASSWORD: &str = "hunter2-very-secret";
const KEY_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBURNOSO-TEST-KEY-NOT-REAL\n-----END OPENSSH PRIVATE KEY-----";

struct Rig {
    user: User,
    bridge: Arc<Bridge>,
    vault_id: Uuid,
    bridge_id: Uuid,
    kp: KeyPair,
    base: String,
    key: String,
}

impl Rig {
    fn http(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .build()
            .unwrap()
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, String) {
        let mut req = self
            .http()
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.key);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.expect("bridge request");
        let status = resp.status();
        (status, resp.text().await.unwrap_or_default())
    }

    async fn ok(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let (status, text) = self.call(method.clone(), path, body).await;
        assert!(status.is_success(), "{method} {path} -> {status}: {text}");
        if text.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{method} {path}: {e}: {text}"))
        }
    }

    /// Everything currently in the vault, decrypted with the owner's key.
    async fn snapshot(&self, s: &TestServer) -> HashMap<Uuid, (String, serde_json::Value)> {
        let mut cursors = HashMap::new();
        cursors.insert(self.vault_id, 0i64);
        let pulled: PullResponse = s
            .json(
                Method::POST,
                "/sync/pull",
                Some(self.user.token()),
                Some(&PullRequest {
                    cursors,
                    limit: None,
                }),
            )
            .await;
        assert!(!pulled.has_more);
        pulled
            .entities
            .into_iter()
            .filter(|e| !e.deleted)
            .map(|e| {
                let pt = aead::decrypt_str(
                    &self.user.personal_vault_key,
                    &Aad::entity(&e.kind, &e.id.to_string()),
                    &e.data,
                )
                .expect("owner decrypts what the bridge wrote");
                (e.id, (e.kind, serde_json::from_str(&pt).unwrap()))
            })
            .collect()
    }
}

fn of<T: serde::de::DeserializeOwned>(
    snap: &HashMap<Uuid, (String, serde_json::Value)>,
    id: Uuid,
    kind: &str,
) -> T {
    let (k, v) = snap
        .get(&id)
        .unwrap_or_else(|| panic!("{kind} {id} missing"));
    assert_eq!(k, kind);
    serde_json::from_value(v.clone()).unwrap()
}

fn count(snap: &HashMap<Uuid, (String, serde_json::Value)>, kind: &str) -> usize {
    snap.values().filter(|(k, _)| k == kind).count()
}

async fn rig(s: &TestServer, name: &str) -> Rig {
    rig_with(s, name, 0).await
}

async fn rig_with(s: &TestServer, name: &str, rate_limit: u32) -> Rig {
    let user = register(s, &unique_email(name), "pw-bridge-1234567").await;
    let vaults: VaultList = s
        .json(Method::GET, "/vaults", Some(user.token()), NOBODY)
        .await;
    let vault_id = vaults.vaults[0].id;
    let kp = KeyPair::generate();
    let created: CreateBridgeResponse = s
        .json(
            Method::POST,
            "/account/bridges",
            Some(user.token()),
            Some(&CreateBridgeRequest {
                name: "ansible".into(),
                public_key: kp.public_b64(),
                vaults: vec![BridgeVaultKey {
                    vault_id,
                    sealed_key: sealed::seal_vault_key(kp.public(), &user.personal_vault_key)
                        .unwrap(),
                }],
            }),
        )
        .await;

    // The credentials file exactly as the cabinet would write it.
    let file = serde_json::to_vec(&BridgeCredentials {
        version: CREDENTIALS_VERSION,
        server: format!("http://{}", s.addr),
        bridge_id: created.bridge.id,
        private_key: termoso_crypto::encoding::b64(&kp.secret_bytes()),
        token: created.token.clone(),
    })
    .unwrap();
    let creds = parse_credentials(&file).unwrap();
    let bridge = Arc::new(Bridge::connect(creds).await.expect("bridge connects"));

    let key = format!("k-{}", Uuid::new_v4().simple());
    let app = router(
        bridge.clone(),
        RestConfig {
            api_key: Some(key.clone()),
            rate_limit,
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Rig {
        user,
        bridge,
        vault_id,
        bridge_id: created.bridge.id,
        kp,
        base,
        key,
    }
}

#[tokio::test]
async fn hosts_and_groups_round_trip_encrypted() {
    let s = server!();
    let r = rig(s, "bridge-rt").await;

    // Status shows the vault ready with its key opened.
    let me = r.ok(Method::GET, "/v1/bridge/me/", None).await;
    assert_eq!(me["bridge_id"], r.bridge_id.to_string());
    assert_eq!(me["vaults"][0]["ready"], true);
    assert_eq!(me["vaults"][0]["hosts"], 0);

    // Group, then a host in it with password + key credentials.
    let g = r
        .ok(
            Method::POST,
            "/v1/group/prod/",
            Some(serde_json::json!({ "label": "Production", "ssh": { "port": 2222 } })),
        )
        .await;
    assert_eq!(g["external_id"], "prod");
    assert_eq!(g["hosts"], 0);

    let (status, text) = r
        .call(
            Method::POST,
            "/v1/host/i-0123/",
            Some(serde_json::json!({
                "group": "prod",
                "address": "10.0.0.5",
                "label": "db-1",
                "tags": ["db", "eu-west-1", "db"],
                "os": "Ubuntu 24.04",
                "ssh": {
                    "port": 22,
                    "credentials": {
                        "username": "ubuntu",
                        "password": PASSWORD,
                        "key": { "private": KEY_PEM, "public": "ssh-ed25519 AAAAC3 bridge", "passphrase": "pp" }
                    }
                }
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let h: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(h["external_id"], "i-0123");
    assert_eq!(h["group"], "prod");
    assert_eq!(h["address"], "10.0.0.5");
    assert_eq!(h["ssh_port"], 22);
    assert_eq!(h["has_credentials"], true);
    assert_eq!(h["tags"], serde_json::json!(["db", "eu-west-1"]));
    // Responses never echo secrets.
    for secret in [PASSWORD, "AAAAC3", "PRIVATE KEY", "pp"] {
        assert!(!text.contains(secret), "response leaks {secret:?}: {text}");
    }
    let host_id: Uuid = h["id"].as_str().unwrap().parse().unwrap();

    // The owner decrypts the full graph the bridge wrote.
    let snap = r.snapshot(s).await;
    let host: Host = of(&snap, host_id, "host");
    assert_eq!(host.label, "db-1");
    assert_eq!(host.address, "10.0.0.5");
    assert_eq!(host.external_id.as_deref(), Some("i-0123"));
    assert_eq!(host.os_name.as_deref(), Some("Ubuntu 24.04"));
    assert_eq!(host.tag_ids.len(), 2);
    let tag: Tag = of(&snap, host.tag_ids[0], "tag");
    assert_eq!(tag.label, "db");
    let group: Group = of(&snap, host.group_id.unwrap(), "group");
    assert_eq!(group.label, "Production");
    let gcfg: SshConfig = of(&snap, group.ssh_config_id.unwrap(), "ssh_config");
    assert_eq!(gcfg.port, Some(2222));
    let cfg: SshConfig = of(&snap, host.ssh_config_id.unwrap(), "ssh_config");
    assert_eq!(cfg.port, Some(22));
    let ident: Identity = of(&snap, cfg.identity_id.unwrap(), "identity");
    assert_eq!(ident.username, "ubuntu");
    assert_eq!(ident.password.as_deref(), Some(PASSWORD));
    assert!(
        !ident.is_visible,
        "inline identity stays out of the keychain"
    );
    let key: SshKey = of(&snap, ident.ssh_key_id.unwrap(), "ssh_key");
    assert_eq!(key.private_key.trim(), KEY_PEM);
    assert_eq!(key.public_key.as_deref(), Some("ssh-ed25519 AAAAC3 bridge"));
    assert_eq!(key.passphrase.as_deref(), Some("pp"));
    assert_eq!(key.key_type, "ed25519");
    assert_eq!(count(&snap, "host"), 1);
    assert_eq!(count(&snap, "identity"), 1);
    assert_eq!(count(&snap, "ssh_key"), 1);

    // Nothing on the wire is readable without the vault key.
    let mut cursors = HashMap::new();
    cursors.insert(r.vault_id, 0i64);
    let raw: PullResponse = s
        .json(
            Method::POST,
            "/sync/pull",
            Some(r.user.token()),
            Some(&PullRequest {
                cursors,
                limit: None,
            }),
        )
        .await;
    let wire = serde_json::to_string(&raw).unwrap();
    for secret in [
        PASSWORD,
        "10.0.0.5",
        "ubuntu",
        "db-1",
        "AAAAC3",
        "Production",
        "i-0123",
    ] {
        assert!(!wire.contains(secret), "server stores plaintext {secret:?}");
    }

    // Idempotent update: same external id → same entity ids, no duplicates,
    // dropping the key keeps the password.
    let h2 = r
        .ok(
            Method::PUT,
            "/v1/host/i-0123",
            Some(serde_json::json!({
                "group": "prod",
                "address": "10.0.0.6",
                "tags": ["db"],
                "ssh": { "credentials": { "username": "admin", "password": PASSWORD } }
            })),
        )
        .await;
    assert_eq!(h2["id"], host_id.to_string());
    assert_eq!(h2["address"], "10.0.0.6");
    assert_eq!(
        h2["label"], "10.0.0.6",
        "omitted label falls back to the address"
    );
    let snap = r.snapshot(s).await;
    let host: Host = of(&snap, host_id, "host");
    assert_eq!(host.tag_ids.len(), 1);
    assert_eq!(host.ssh_config_id, cfg_id_of(&snap, host_id));
    let cfg: SshConfig = of(&snap, host.ssh_config_id.unwrap(), "ssh_config");
    let ident: Identity = of(&snap, cfg.identity_id.unwrap(), "identity");
    assert_eq!(ident.username, "admin");
    assert_eq!(ident.ssh_key_id, None);
    assert_eq!(count(&snap, "host"), 1);
    assert_eq!(count(&snap, "identity"), 1);
    assert_eq!(count(&snap, "ssh_key"), 0, "orphaned key is removed");
    assert_eq!(
        count(&snap, "tag"),
        2,
        "tags are never deleted by the bridge"
    );

    // Listing and lookup.
    let list = r.ok(Method::GET, "/v1/hosts/", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    let one = r.ok(Method::GET, "/v1/host/i-0123/", None).await;
    assert_eq!(one["address"], "10.0.0.6");
    let (status, _) = r.call(Method::GET, "/v1/host/nope/", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let groups = r.ok(Method::GET, "/v1/groups/", None).await;
    assert_eq!(groups[0]["hosts"], 1);

    // Second host, then delete the group: hosts survive at the top level.
    r.ok(
        Method::POST,
        "/v1/host/i-0456/",
        Some(
            serde_json::json!({ "group": "prod", "address": "10.0.0.7", "telnet": { "port": 23 } }),
        ),
    )
    .await;
    let (status, _) = r.call(Method::DELETE, "/v1/group/prod/", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let snap = r.snapshot(s).await;
    assert_eq!(count(&snap, "group"), 0);
    assert_eq!(count(&snap, "host"), 2);
    assert!(
        snap.values()
            .filter(|(k, _)| k == "host")
            .all(|(_, v)| v["group_id"].is_null())
    );
    assert_eq!(
        count(&snap, "ssh_config"),
        1,
        "group config gone, host config stays (second host is telnet-only)"
    );
    let (status, _) = r.call(Method::DELETE, "/v1/group/prod/", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Delete a host: its config + identity go with it.
    let (status, _) = r.call(Method::DELETE, "/v1/host/i-0123/", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let snap = r.snapshot(s).await;
    assert_eq!(count(&snap, "host"), 1);
    assert_eq!(count(&snap, "identity"), 0);
    assert_eq!(count(&snap, "ssh_config"), 0);
    assert_eq!(count(&snap, "telnet_config"), 1);
    let (status, _) = r.call(Method::DELETE, "/v1/host/i-0123/", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

fn cfg_id_of(snap: &HashMap<Uuid, (String, serde_json::Value)>, host_id: Uuid) -> Option<Uuid> {
    let host: Host = of(snap, host_id, "host");
    host.ssh_config_id
}

#[tokio::test]
async fn bridge_survives_concurrent_owner_edits() {
    let s = server!();
    let r = rig(s, "bridge-conflict").await;
    let h = r
        .ok(
            Method::POST,
            "/v1/host/web-1/",
            Some(serde_json::json!({ "address": "web-1.internal" })),
        )
        .await;
    let host_id: Uuid = h["id"].as_str().unwrap().parse().unwrap();

    // The owner edits the same host from a desktop client behind the
    // bridge's back (bumping the version) and renames it.
    let snap = r.snapshot(s).await;
    let mut host: Host = of(&snap, host_id, "host");
    host.label = "renamed by owner".into();
    host.notes = "keep me".into();
    let version = {
        let mut cursors = HashMap::new();
        cursors.insert(r.vault_id, 0i64);
        let pulled: PullResponse = s
            .json(
                Method::POST,
                "/sync/pull",
                Some(r.user.token()),
                Some(&PullRequest {
                    cursors,
                    limit: None,
                }),
            )
            .await;
        pulled
            .entities
            .iter()
            .find(|e| e.id == host_id)
            .unwrap()
            .version
    };
    let push = termoso_proto::sync::PushRequest {
        changes: vec![termoso_proto::sync::EntityChange {
            secret_rotated_at: None,
            id: host_id,
            kind: "host".into(),
            vault_id: r.vault_id,
            base_version: Some(version),
            key_version: 1,
            data: r.user.encrypt_entity(
                &r.user.personal_vault_key,
                "host",
                host_id,
                &serde_json::to_string(&host).unwrap(),
            ),
            updated_at: chrono::Utc::now(),
        }],
        deletes: vec![],
    };
    let resp: termoso_proto::sync::PushResponse = s
        .json(
            Method::POST,
            "/sync/push",
            Some(r.user.token()),
            Some(&push),
        )
        .await;
    assert!(matches!(
        resp.results[0],
        termoso_proto::sync::PushResult::Ok { .. }
    ));

    // The bridge's mirror is stale; its next write must re-pull, rebase and
    // keep the owner's untouched fields.
    let h = r
        .ok(
            Method::POST,
            "/v1/host/web-1/",
            Some(serde_json::json!({ "address": "web-1.internal", "label": "web-1" })),
        )
        .await;
    assert_eq!(h["id"], host_id.to_string());
    let snap = r.snapshot(s).await;
    let host: Host = of(&snap, host_id, "host");
    assert_eq!(host.label, "web-1");
    assert_eq!(host.notes, "keep me");
    assert_eq!(count(&snap, "host"), 1);
}

#[tokio::test]
async fn rejects_bad_input_and_unauthenticated_callers() {
    let s = server!();
    let r = rig(s, "bridge-input").await;

    // No / wrong local key.
    let resp = r
        .http()
        .get(format!("{}/v1/hosts/", r.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = r
        .http()
        .get(format!("{}/v1/hosts/", r.base))
        .header("x-api-key", "wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = r
        .http()
        .get(format!("{}/v1/hosts/", r.base))
        .header("x-api-key", &r.key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Health needs no key.
    let resp = r
        .http()
        .get(format!("{}/healthz", r.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Malformed / invalid payloads: 400 with a stable code, nothing written.
    let resp = r
        .http()
        .post(format!("{}/v1/host/x/", r.base))
        .bearer_auth(&r.key)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "invalid_request");

    for (path, body) in [
        ("/v1/host/x/", serde_json::json!({})),
        ("/v1/host/x/", serde_json::json!({ "address": "" })),
        ("/v1/host/x/", serde_json::json!({ "address": "a b" })),
        (
            "/v1/host/x/",
            serde_json::json!({ "address": "a", "bogus": 1 }),
        ),
        (
            "/v1/host/x/",
            serde_json::json!({ "address": "a", "ssh": { "port": 0 } }),
        ),
        (
            "/v1/host/x/",
            serde_json::json!({ "address": "a", "ssh": { "port": 70000 } }),
        ),
        (
            "/v1/host/x/",
            serde_json::json!({ "address": "a", "ssh": { "credentials": { "key": { "private": "garbage" } } } }),
        ),
        (
            "/v1/host/x/",
            serde_json::json!({ "address": "a", "telnet": { "credentials": { "key": { "private": KEY_PEM } } } }),
        ),
        ("/v1/group/x/", serde_json::json!({ "label": "" })),
        (
            "/v1/group/x/",
            serde_json::json!({ "label": "ok", "parent": "x" }),
        ),
    ] {
        let (status, text) = r.call(Method::POST, path, Some(body.clone())).await;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
            "{path} {body} -> {status}: {text}"
        );
    }
    let (status, text) = r
        .call(
            Method::POST,
            "/v1/host/%20/",
            Some(serde_json::json!({ "address": "a" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    // Unknown group → 404, nothing written.
    let (status, _) = r
        .call(
            Method::POST,
            "/v1/host/x/",
            Some(serde_json::json!({ "address": "a", "group": "missing" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let snap = r.snapshot(s).await;
    assert!(
        snap.is_empty(),
        "rejected requests must not write: {snap:?}"
    );

    // Oversized body.
    let resp = r
        .http()
        .post(format!("{}/v1/host/x/", r.base))
        .bearer_auth(&r.key)
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"address":"a","notes":"{}"}}"#,
            "n".repeat(300 * 1024)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // Unknown route.
    let (status, text) = r.call(Method::GET, "/v1/nope/", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{text}");
}

#[tokio::test]
async fn local_rate_limit_returns_429_with_retry_after() {
    let s = server!();
    // Burst is 2× the rate, so at 1 req/s the third request is refused unless
    // a whole second passed since the first — with or without a valid key.
    let r = rig_with(s, "bridge-ratelimit", 1).await;
    let mut statuses = Vec::new();
    let mut limited = None;
    for i in 0..4 {
        let mut req = r.http().get(format!("{}/v1/hosts/", r.base));
        if i % 2 == 0 {
            req = req.bearer_auth(&r.key);
        }
        let resp = req.send().await.unwrap();
        statuses.push(resp.status());
        if resp.status() == StatusCode::TOO_MANY_REQUESTS && limited.is_none() {
            assert_eq!(resp.headers()["retry-after"], "1");
            limited = Some(resp.json::<serde_json::Value>().await.unwrap());
        }
    }
    let body = limited.unwrap_or_else(|| panic!("never limited: {statuses:?}"));
    assert_eq!(body["code"], "rate_limited");
    assert_eq!(statuses[0], StatusCode::OK);
    assert_eq!(statuses[1], StatusCode::UNAUTHORIZED);
    // Health stays reachable for the orchestrator.
    let resp = r
        .http()
        .get(format!("{}/healthz", r.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn rotation_pauses_writes_until_reseal() {
    let s = server!();
    let r = rig(s, "bridge-rotate").await;
    r.ok(
        Method::POST,
        "/v1/host/a/",
        Some(serde_json::json!({ "address": "a.internal" })),
    )
    .await;

    // Owner rotates the vault key: the bridge's sealed key is dropped.
    let rot: RotateVaultKeyResponse = s
        .json(
            Method::POST,
            &format!("/vaults/{}/rotate-key", r.vault_id),
            Some(r.user.token()),
            Some(&RotateVaultKeyRequest {
                base_key_version: 1,
                members: vec![SealedKeyFor {
                    user_id: r.user.id(),
                    sealed_key: sealed::seal_vault_key(
                        r.user.keypair.public(),
                        &r.user.personal_vault_key,
                    )
                    .unwrap(),
                }],
            }),
        )
        .await;
    assert_eq!(rot.key_version, 2);

    let st = r.ok(Method::POST, "/v1/sync/", None).await;
    assert_eq!(st["vaults"][0]["ready"], false);
    assert_eq!(st["vaults"][0]["key_version"], 2);
    let (status, text) = r
        .call(
            Method::POST,
            "/v1/host/b/",
            Some(serde_json::json!({ "address": "b.internal" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{text}");
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["code"], "vault_key_pending");

    // Owner re-seals for the bridge; the next write goes through with v2.
    let _: Bridge_ = s
        .json(
            Method::PUT,
            &format!("/account/bridges/{}/vaults", r.bridge_id),
            Some(r.user.token()),
            Some(&vec![BridgeVaultKey {
                vault_id: r.vault_id,
                sealed_key: sealed::seal_vault_key(r.kp.public(), &r.user.personal_vault_key)
                    .unwrap(),
            }]),
        )
        .await;
    let st = r.ok(Method::POST, "/v1/sync/", None).await;
    assert_eq!(st["vaults"][0]["ready"], true);
    assert_eq!(
        st["vaults"][0]["hosts"], 0,
        "entities under the old key stay unreadable until the owner re-encrypts"
    );

    // The owner's client re-encrypts the vault under the new key version.
    let mut cursors = HashMap::new();
    cursors.insert(r.vault_id, 0i64);
    let pulled: PullResponse = s
        .json(
            Method::POST,
            "/sync/pull",
            Some(r.user.token()),
            Some(&PullRequest {
                cursors,
                limit: None,
            }),
        )
        .await;
    let changes = pulled
        .entities
        .iter()
        .filter(|e| !e.deleted)
        .map(|e| {
            let pt = aead::decrypt_str(
                &r.user.personal_vault_key,
                &Aad::entity(&e.kind, &e.id.to_string()),
                &e.data,
            )
            .unwrap();
            termoso_proto::sync::EntityChange {
                secret_rotated_at: None,
                id: e.id,
                kind: e.kind.clone(),
                vault_id: r.vault_id,
                base_version: Some(e.version),
                key_version: 2,
                data: r
                    .user
                    .encrypt_entity(&r.user.personal_vault_key, &e.kind, e.id, &pt),
                updated_at: chrono::Utc::now(),
            }
        })
        .collect();
    let resp: termoso_proto::sync::PushResponse = s
        .json(
            Method::POST,
            "/sync/push",
            Some(r.user.token()),
            Some(&termoso_proto::sync::PushRequest {
                changes,
                deletes: vec![],
            }),
        )
        .await;
    assert!(
        resp.results
            .iter()
            .all(|x| matches!(x, termoso_proto::sync::PushResult::Ok { .. })),
        "{:?}",
        resp.results
    );
    let st = r.ok(Method::POST, "/v1/sync/", None).await;
    assert_eq!(st["vaults"][0]["hosts"], 1);
    let h = r
        .ok(
            Method::POST,
            "/v1/host/b/",
            Some(serde_json::json!({ "address": "b.internal" })),
        )
        .await;
    assert_eq!(h["address"], "b.internal");
    let list = r.ok(Method::GET, "/v1/hosts/", None).await;
    assert_eq!(list.as_array().unwrap().len(), 2);
}

type Bridge_ = termoso_proto::bridge::Bridge;

#[tokio::test]
async fn mcp_server_lists_hosts_and_gates_tools() {
    use termoso_bridge::mcp::{McpConfig, McpServer};

    let s = server!();
    let r = rig(s, "bridge-mcp").await;
    r.ok(
        Method::POST,
        "/v1/group/prod/",
        Some(serde_json::json!({ "label": "Production", "ssh": { "port": 2222 } })),
    )
    .await;
    r.ok(
        Method::POST,
        "/v1/host/i-mcp/",
        Some(serde_json::json!({
            "group": "prod",
            "address": "10.255.255.1",
            "label": "db-1",
            "tags": ["db"],
            "ssh": { "credentials": { "username": "ubuntu", "password": PASSWORD } }
        })),
    )
    .await;

    let mcp = McpServer::new(
        r.bridge.clone(),
        McpConfig {
            allow_write: false,
            allow_exec: true,
            strict_host_key: false,
        },
    );
    let call = |id: u64, method: &str, params: serde_json::Value| serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let text = |v: &serde_json::Value| -> serde_json::Value {
        serde_json::from_str(v["result"]["content"][0]["text"].as_str().expect("text"))
            .expect("json text")
    };

    let init = mcp
        .handle(call(
            1,
            "initialize",
            serde_json::json!({"protocolVersion": "2025-03-26"}),
        ))
        .await
        .expect("response");
    assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(init["result"]["serverInfo"]["name"], "termoso-bridge");
    assert!(
        mcp.handle(serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await
            .is_none()
    );

    let tools = mcp
        .handle(call(2, "tools/list", serde_json::json!({})))
        .await
        .unwrap();
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"ssh_exec"));
    assert!(!names.contains(&"upsert_host"));

    let hosts = mcp
        .handle(call(
            3,
            "tools/call",
            serde_json::json!({"name": "list_hosts", "arguments": {}}),
        ))
        .await
        .unwrap();
    assert_eq!(hosts["result"]["isError"], false);
    let list = text(&hosts);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["label"], "db-1");
    assert_eq!(list[0]["group"], "Production");
    assert_eq!(list[0]["username"], "ubuntu");
    assert_eq!(list[0]["has_credentials"], true);
    assert!(list[0].get("password").is_none());

    let host = mcp
        .handle(call(
            4,
            "tools/call",
            serde_json::json!({"name": "get_host", "arguments": {"host": "db-1"}}),
        ))
        .await
        .unwrap();
    let h = text(&host);
    assert_eq!(h["ssh"]["port"], 2222, "port inherited from the group");
    assert_eq!(h["ssh"]["username"], "ubuntu");

    let denied = mcp
        .handle(call(
            5,
            "tools/call",
            serde_json::json!({"name": "delete_host", "arguments": {"external_id": "i-mcp"}}),
        ))
        .await
        .unwrap();
    assert_eq!(denied["result"]["isError"], true);
    assert!(
        denied["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("--allow-write")
    );

    let exec = mcp
        .handle(call(
            6,
            "tools/call",
            serde_json::json!({"name": "ssh_exec", "arguments": {"host": "db-1", "command": "id", "timeout_secs": 1}}),
        ))
        .await
        .unwrap();
    assert_eq!(
        exec["result"]["isError"], true,
        "unreachable host must fail, not hang"
    );

    let unknown = mcp
        .handle(call(7, "nope", serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(unknown["error"]["code"], -32601);
}

#[tokio::test]
async fn snippets_identities_keys_round_trip() {
    let s = server!();
    let r = rig(s, "bridge-shared").await;

    // Key first; the response never echoes the private half or passphrase.
    let (status, text) = r
        .call(
            Method::PUT,
            "/v1/key/k-ops/",
            Some(serde_json::json!({
                "label": "ops key",
                "private": KEY_PEM,
                "public": "ssh-ed25519 AAAAC3 ops",
                "passphrase": "pp"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let k: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(k["external_id"], "k-ops");
    assert_eq!(k["key_type"], "ed25519");
    assert_eq!(k["has_passphrase"], true);
    assert_eq!(k["used_by"], 0);
    for secret in ["PRIVATE KEY", "\"pp\""] {
        assert!(!text.contains(secret), "response leaks {secret:?}: {text}");
    }
    let key_id: Uuid = k["id"].as_str().unwrap().parse().unwrap();

    // Identity referencing the key; a dangling key reference is a 404.
    let (status, text) = r
        .call(
            Method::PUT,
            "/v1/identity/ops/",
            Some(serde_json::json!({ "username": "ops", "password": PASSWORD, "key": "k-ops" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let i: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(i["label"], "ops");
    assert_eq!(i["key"], "k-ops");
    assert_eq!(i["has_password"], true);
    assert_eq!(i["used_by"], 0);
    assert!(!text.contains(PASSWORD));
    let identity_id: Uuid = i["id"].as_str().unwrap().parse().unwrap();
    let (status, _) = r
        .call(
            Method::PUT,
            "/v1/identity/bad/",
            Some(serde_json::json!({ "username": "x", "key": "missing" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = r
        .call(
            Method::PUT,
            "/v1/identity/empty/",
            Some(serde_json::json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A host uses the shared identity instead of inline credentials.
    let h = r
        .ok(
            Method::PUT,
            "/v1/host/web-9/",
            Some(serde_json::json!({
                "address": "10.0.0.9",
                "ssh": { "credentials": { "identity": "ops" } }
            })),
        )
        .await;
    assert_eq!(h["has_credentials"], true);
    let host_id: Uuid = h["id"].as_str().unwrap().parse().unwrap();
    let one = r.ok(Method::GET, "/v1/identity/ops/", None).await;
    assert_eq!(one["used_by"], 1);
    let keys = r.ok(Method::GET, "/v1/keys/", None).await;
    assert_eq!(keys[0]["used_by"], 1);
    let snap = r.snapshot(s).await;
    assert_eq!(
        count(&snap, "identity"),
        1,
        "no inline identity was created"
    );
    let host: Host = of(&snap, host_id, "host");
    let cfg = host.ssh_config_id.unwrap();
    let ssh: serde_json::Value = snap[&cfg].1.clone();
    assert_eq!(ssh["identity_id"], identity_id.to_string());
    let ident: serde_json::Value = snap[&identity_id].1.clone();
    assert_eq!(ident["is_visible"], true);
    assert_eq!(ident["ssh_key_id"], key_id.to_string());

    // Shared + inline together is rejected; in-use entries cannot be deleted.
    let (status, _) = r
        .call(
            Method::PUT,
            "/v1/host/web-9/",
            Some(serde_json::json!({
                "address": "10.0.0.9",
                "ssh": { "credentials": { "identity": "ops", "username": "root" } }
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = r.call(Method::DELETE, "/v1/identity/ops/", None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = r.call(Method::DELETE, "/v1/key/k-ops/", None).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Back to inline credentials: the shared identity is untouched and free to go.
    r.ok(
        Method::PUT,
        "/v1/host/web-9/",
        Some(serde_json::json!({
            "address": "10.0.0.9",
            "ssh": { "credentials": { "username": "root", "password": PASSWORD } }
        })),
    )
    .await;
    let snap = r.snapshot(s).await;
    assert_eq!(count(&snap, "identity"), 2);
    let one = r.ok(Method::GET, "/v1/identity/ops/", None).await;
    assert_eq!(one["used_by"], 0);
    let (status, _) = r.call(Method::DELETE, "/v1/identity/ops/", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = r.call(Method::DELETE, "/v1/key/k-ops/", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let snap = r.snapshot(s).await;
    assert_eq!(count(&snap, "ssh_key"), 0);
    assert_eq!(count(&snap, "identity"), 1);
    let list = r.ok(Method::GET, "/v1/identities/", None).await;
    assert!(
        list.as_array().unwrap().is_empty(),
        "inline identities are not listed"
    );

    // Snippets: upsert is idempotent by external_id.
    let sn = r
        .ok(
            Method::PUT,
            "/v1/snippet/uptime/",
            Some(serde_json::json!({ "label": "Uptime", "script": "uptime\n" })),
        )
        .await;
    assert_eq!(sn["external_id"], "uptime");
    let again = r
        .ok(
            Method::PUT,
            "/v1/snippet/uptime/",
            Some(serde_json::json!({ "label": "Uptime", "script": "uptime -p\n", "close_after_run": true })),
        )
        .await;
    assert_eq!(again["id"], sn["id"]);
    assert_eq!(again["script"], "uptime -p\n");
    assert_eq!(again["close_after_run"], true);
    let list = r.ok(Method::GET, "/v1/snippets/", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    let snap = r.snapshot(s).await;
    assert_eq!(count(&snap, "snippet"), 1);
    let (status, _) = r
        .call(
            Method::PUT,
            "/v1/snippet/bad/",
            Some(serde_json::json!({ "label": "x", "script": "y", "colour": "red" })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unknown fields are rejected"
    );
    let (status, _) = r.call(Method::DELETE, "/v1/snippet/uptime/", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = r.call(Method::DELETE, "/v1/snippet/uptime/", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
