//! Team session logs: teammates holding the vault key list and download each
//! other's recordings, pin and annotate them by role, and managers switch
//! per-vault logging. Skipped when S3 storage is unreachable (see `common`).

mod common;

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use futures::{SinkExt, StreamExt};
use reqwest::{Method, StatusCode};
use termoso_crypto::keys::SymmetricKey;
use termoso_crypto::sealed;
use termoso_proto::logs::{
    CreateLogCommentRequest, CreateLogRequest, CreateLogResponse, DownloadLogResponse, LogComment,
    LogCommentList, LogListResponse, SessionLog, UpdateLogRequest,
};
use termoso_proto::team::{AuditEventList, CreateInviteRequest, CreateTeamRequest, Team, TeamRole};
use termoso_proto::vault::{
    CreateVaultRequest, UpdateVaultRequest, Vault, VaultKind, VaultList, VaultMemberUpsert,
    VaultRole,
};
use termoso_proto::ws::{ClientMessage, ServerMessage};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

macro_rules! server_with_storage {
    () => {
        match server().await {
            Some(s) if s.storage => s,
            _ => return,
        }
    };
}

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(s: &TestServer, token: &str) -> Ws {
    let (mut ws, _) = tokio_tungstenite::connect_async(s.ws_url()).await.unwrap();
    ws.send(Message::Text(
        serde_json::to_string(&ClientMessage::Auth {
            token: token.into(),
        })
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();
    match next(&mut ws).await {
        Some(ServerMessage::Hello { .. }) => ws,
        other => panic!("expected hello, got {other:?}"),
    }
}

async fn next(ws: &mut Ws) -> Option<ServerMessage> {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("ws timeout")?
            .ok()?;
        match msg {
            Message::Text(t) => return Some(serde_json::from_str(&t).unwrap()),
            Message::Close(_) => return None,
            _ => continue,
        }
    }
}

/// Wait for `VaultLogsChanged { vault_id }` and return its `seq`.
async fn until_vault_logs(ws: &mut Ws, vault_id: Uuid) -> i64 {
    for _ in 0..30 {
        match next(ws).await {
            Some(ServerMessage::VaultLogsChanged { vault_id: v, seq }) if v == vault_id => {
                return seq;
            }
            Some(_) => {}
            None => break,
        }
    }
    panic!("no VaultLogsChanged for {vault_id}");
}

/// Assert that no `VaultLogsChanged` arrives within a short window.
async fn expect_no_vault_logs(ws: &mut Ws) {
    loop {
        match tokio::time::timeout(Duration::from_millis(700), ws.next()).await {
            Err(_) => return,
            Ok(Some(Ok(Message::Text(t)))) => {
                let m: ServerMessage = serde_json::from_str(&t).unwrap();
                assert!(
                    !matches!(m, ServerMessage::VaultLogsChanged { .. }),
                    "unexpected {m:?}"
                );
            }
            Ok(Some(Ok(_))) => continue,
            Ok(other) => panic!("socket died: {other:?}"),
        }
    }
}

/// Invite `who` into the team; `vault_ids` leaves them a member of those
/// vaults without a sealed key (pending) until a manager seals one.
async fn join(s: &TestServer, team: &Team, owner: &User, who: &User, vault_ids: Vec<Uuid>) {
    let invite: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{}/invites", team.id),
            Some(owner.token()),
            Some(&CreateInviteRequest {
                email: who.email.clone(),
                role: TeamRole::Member,
                role_id: None,
                vault_ids,
            }),
        )
        .await;
    let token = invite["url"].as_str().unwrap().rsplit('/').next().unwrap();
    let _: Team = s
        .json(
            Method::POST,
            &format!("/invites/{token}/accept"),
            Some(who.token()),
            NOBODY,
        )
        .await;
}

fn upsert(key: &SymmetricKey, u: &User, role: VaultRole) -> VaultMemberUpsert {
    VaultMemberUpsert {
        user_id: u.id(),
        role,
        sealed_key: sealed::seal_vault_key(u.keypair.public(), key).unwrap(),
    }
}

async fn team_vault(
    s: &TestServer,
    team: &Team,
    owner: &User,
    members: &[(&User, VaultRole)],
) -> (Vault, SymmetricKey) {
    let key = SymmetricKey::generate();
    let mut list = vec![upsert(&key, owner, VaultRole::Manager)];
    for (m, role) in members {
        list.push(upsert(&key, m, *role));
    }
    let v: Vault = s
        .json(
            Method::POST,
            &format!("/teams/{}/vaults", team.id),
            Some(owner.token()),
            Some(&CreateVaultRequest {
                name: "Ops vault".into(),
                members: list,
            }),
        )
        .await;
    (v, key)
}

async fn personal_vault(s: &TestServer, u: &User) -> Uuid {
    let vaults: VaultList = s
        .json(Method::GET, "/vaults", Some(u.token()), NOBODY)
        .await;
    vaults
        .vaults
        .iter()
        .find(|v| v.kind == VaultKind::Personal)
        .expect("personal vault")
        .id
}

fn meta(label: &str) -> String {
    STANDARD.encode(format!("{{\"encrypted\":\"{label}\"}}"))
}

async fn upload(s: &TestServer, resp: &CreateLogResponse, body: Vec<u8>) -> StatusCode {
    let mut req = s.http().put(&resp.upload_url).body(body);
    for (k, v) in &resp.upload_headers {
        if !k.eq_ignore_ascii_case("content-length") {
            req = req.header(k, v);
        }
    }
    req.send().await.expect("s3 put").status()
}

/// Create, upload and complete a recording of `payload` in `vault_id`.
async fn record(
    s: &TestServer,
    author: &User,
    vault_id: Uuid,
    label: &str,
    payload: &[u8],
) -> Uuid {
    let id = Uuid::new_v4();
    let created: CreateLogResponse = s
        .json(
            Method::POST,
            "/logs",
            Some(author.token()),
            Some(&CreateLogRequest {
                id,
                vault_id,
                meta: meta(label),
                key_version: 1,
                size_bytes: payload.len() as i64,
            }),
        )
        .await;
    assert!(upload(s, &created, payload.to_vec()).await.is_success());
    let done: SessionLog = s
        .json(
            Method::PATCH,
            &format!("/logs/{id}"),
            Some(author.token()),
            Some(&UpdateLogRequest {
                meta: None,
                size_bytes: Some(payload.len() as i64),
                pinned: None,
                note: None,
            }),
        )
        .await;
    assert!(done.completed);
    id
}

fn annotate(pinned: Option<bool>, note: Option<&str>) -> UpdateLogRequest {
    UpdateLogRequest {
        meta: None,
        size_bytes: None,
        pinned,
        note: note.map(str::to_owned),
    }
}

async fn vault_logs(s: &TestServer, vault_id: Uuid, token: &str, since: i64) -> LogListResponse {
    s.json(
        Method::GET,
        &format!("/vaults/{vault_id}/logs?since={since}"),
        Some(token),
        NOBODY,
    )
    .await
}

async fn download(s: &TestServer, id: Uuid, token: &str) -> Vec<u8> {
    let dl: DownloadLogResponse = s
        .json(
            Method::GET,
            &format!("/logs/{id}/download"),
            Some(token),
            NOBODY,
        )
        .await;
    let got = s.http().get(&dl.download_url).send().await.expect("s3 get");
    assert_eq!(got.status(), StatusCode::OK);
    got.bytes().await.expect("body").to_vec()
}

#[tokio::test]
async fn teammates_share_recordings_by_role() {
    let s = server_with_storage!();
    let owner = register(s, &unique_email("tl-owner"), "pw-owner-1234567").await;
    let editor = register(s, &unique_email("tl-editor"), "pw-editor-123456").await;
    let viewer = register(s, &unique_email("tl-viewer"), "pw-viewer-123456").await;
    let pending = register(s, &unique_email("tl-pending"), "pw-pending-12345").await;
    let outsider = register(s, &unique_email("tl-out"), "pw-outsider-1234").await;

    let team: Team = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&CreateTeamRequest { name: "Ops".into() }),
        )
        .await;
    for u in [&editor, &viewer] {
        join(s, &team, &owner, u, vec![]).await;
    }
    let (vault, _key) = team_vault(
        s,
        &team,
        &owner,
        &[(&editor, VaultRole::Editor), (&viewer, VaultRole::Viewer)],
    )
    .await;
    assert!(!vault.session_logging, "off by default");
    // `pending` is in the team and the vault, but has no sealed key yet.
    join(s, &team, &owner, &pending, vec![vault.id]).await;

    // Editor records in the team vault; owner records in a personal vault.
    let editor_ws_vault = vault.id;
    let mut owner_ws = connect(s, owner.token()).await;
    let mut viewer_ws = connect(s, viewer.token()).await;
    let mut outsider_ws = connect(s, outsider.token()).await;

    let body_a: Vec<u8> = (0..2048u32).map(|i| (i * 7 % 253) as u8).collect();
    let log_a = record(s, &editor, editor_ws_vault, "editor: ssh prod-1", &body_a).await;
    let vseq = until_vault_logs(&mut owner_ws, vault.id).await;
    assert!(vseq >= 1);
    until_vault_logs(&mut viewer_ws, vault.id).await;
    expect_no_vault_logs(&mut outsider_ws).await;

    let personal = personal_vault(s, &owner).await;
    let body_p: Vec<u8> = vec![9; 512];
    let log_p = record(s, &owner, personal, "owner: personal", &body_p).await;
    // Personal-vault logs never fan out to the team.
    expect_no_vault_logs(&mut viewer_ws).await;

    // Everyone holding the key sees the editor's log with its author.
    for u in [&owner, &editor, &viewer] {
        let list = vault_logs(s, vault.id, u.token(), 0).await;
        assert_eq!(list.logs.len(), 1, "{}", u.email);
        let l = &list.logs[0];
        assert_eq!(l.id, log_a);
        assert_eq!(l.user_id, editor.id());
        let author = l.author.as_ref().expect("author");
        assert_eq!(author.user_id, editor.id());
        assert_eq!(author.email, editor.email);
        assert!(l.completed);
        assert!(!l.pinned);
        assert_eq!(l.note, "");
        // Paged by the vault counter, not the author's.
        assert_eq!(list.since, l.seq);
        assert!(
            vault_logs(s, vault.id, u.token(), list.since)
                .await
                .logs
                .is_empty()
        );
        assert_eq!(download(s, log_a, u.token()).await, body_a);
    }
    // The author's own feed still pages by the author counter.
    let mine: LogListResponse = s
        .json(Method::GET, "/logs", Some(editor.token()), NOBODY)
        .await;
    assert_eq!(mine.logs.len(), 1);
    let owners: LogListResponse = s
        .json(Method::GET, "/logs", Some(owner.token()), NOBODY)
        .await;
    assert_eq!(owners.logs.len(), 1);
    assert_eq!(owners.logs[0].id, log_p);

    // Nobody but the owner sees the personal log.
    for u in [&editor, &viewer, &outsider] {
        s.expect_status(
            Method::GET,
            &format!("/logs/{log_p}/download"),
            Some(u.token()),
            NOBODY,
            StatusCode::NOT_FOUND,
        )
        .await;
    }
    // Outsiders see neither the vault listing nor the log itself.
    s.expect_status(
        Method::GET,
        &format!("/vaults/{}/logs", vault.id),
        Some(outsider.token()),
        NOBODY,
        StatusCode::NOT_FOUND,
    )
    .await;
    s.expect_status(
        Method::GET,
        &format!("/logs/{log_a}/download"),
        Some(outsider.token()),
        NOBODY,
        StatusCode::NOT_FOUND,
    )
    .await;
    s.expect_status(
        Method::PATCH,
        &format!("/logs/{log_a}"),
        Some(outsider.token()),
        Some(&annotate(Some(true), None)),
        StatusCode::NOT_FOUND,
    )
    .await;
    // A member without a sealed key cannot decrypt anything, so gets nothing.
    s.expect_status(
        Method::GET,
        &format!("/vaults/{}/logs", vault.id),
        Some(pending.token()),
        NOBODY,
        StatusCode::FORBIDDEN,
    )
    .await;
    s.expect_status(
        Method::GET,
        &format!("/logs/{log_a}/download"),
        Some(pending.token()),
        NOBODY,
        StatusCode::NOT_FOUND,
    )
    .await;

    // Viewer: read-only — no pin, no note, no delete.
    s.expect_status(
        Method::PATCH,
        &format!("/logs/{log_a}"),
        Some(viewer.token()),
        Some(&annotate(Some(true), None)),
        StatusCode::FORBIDDEN,
    )
    .await;
    s.expect_status(
        Method::PATCH,
        &format!("/logs/{log_a}"),
        Some(viewer.token()),
        Some(&annotate(None, Some("hi"))),
        StatusCode::FORBIDDEN,
    )
    .await;
    s.expect_status(
        Method::DELETE,
        &format!("/logs/{log_a}"),
        Some(viewer.token()),
        NOBODY,
        StatusCode::FORBIDDEN,
    )
    .await;

    // Manager pins the editor's log and leaves a note; the change fans out.
    let pinned: SessionLog = s
        .json(
            Method::PATCH,
            &format!("/logs/{log_a}"),
            Some(owner.token()),
            Some(&annotate(Some(true), Some("  Incident #42 root cause \n"))),
        )
        .await;
    assert!(pinned.pinned);
    assert_eq!(pinned.note, "Incident #42 root cause");
    assert_eq!(pinned.note_by, Some(owner.id()));
    assert_eq!(pinned.meta, meta("editor: ssh prod-1"), "meta untouched");
    let after_pin = until_vault_logs(&mut viewer_ws, vault.id).await;
    assert!(after_pin > vseq);
    let delta = vault_logs(s, vault.id, viewer.token(), vseq).await;
    assert_eq!(delta.logs.len(), 1);
    assert!(delta.logs[0].pinned);
    assert_eq!(delta.logs[0].note_by, Some(owner.id()));

    // Only the author may touch the recording itself.
    s.expect_status(
        Method::PATCH,
        &format!("/logs/{log_a}"),
        Some(owner.token()),
        Some(&UpdateLogRequest {
            meta: Some(meta("tampered")),
            size_bytes: None,
            pinned: None,
            note: None,
        }),
        StatusCode::FORBIDDEN,
    )
    .await;

    // Notes are bounded and must be plain text.
    s.expect_status(
        Method::PATCH,
        &format!("/logs/{log_a}"),
        Some(editor.token()),
        Some(&annotate(None, Some(&"x".repeat(2001)))),
        StatusCode::PAYLOAD_TOO_LARGE,
    )
    .await;
    s.expect_status(
        Method::PATCH,
        &format!("/logs/{log_a}"),
        Some(editor.token()),
        Some(&annotate(None, Some("bad\u{7}bell"))),
        StatusCode::BAD_REQUEST,
    )
    .await;
    // Editor clears the note: `note_by` goes with it, the pin stays.
    let cleared: SessionLog = s
        .json(
            Method::PATCH,
            &format!("/logs/{log_a}"),
            Some(editor.token()),
            Some(&annotate(None, Some(""))),
        )
        .await;
    assert!(cleared.pinned);
    assert_eq!(cleared.note, "");
    assert_eq!(cleared.note_by, None);

    // Pins and notes on a personal log are the owner's business, not audited.
    let own: SessionLog = s
        .json(
            Method::PATCH,
            &format!("/logs/{log_p}"),
            Some(owner.token()),
            Some(&annotate(Some(true), Some("keep"))),
        )
        .await;
    assert!(own.pinned);

    // Per-vault logging toggle: manager only, team vaults only, audited.
    s.expect_status(
        Method::PATCH,
        &format!("/vaults/{}", vault.id),
        Some(editor.token()),
        Some(&UpdateVaultRequest {
            name: None,
            session_logging: Some(true),
        }),
        StatusCode::FORBIDDEN,
    )
    .await;
    s.expect_status(
        Method::PATCH,
        &format!("/vaults/{personal}"),
        Some(owner.token()),
        Some(&UpdateVaultRequest {
            name: None,
            session_logging: Some(true),
        }),
        StatusCode::FORBIDDEN,
    )
    .await;
    let on: Vault = s
        .json(
            Method::PATCH,
            &format!("/vaults/{}", vault.id),
            Some(owner.token()),
            Some(&UpdateVaultRequest {
                name: None,
                session_logging: Some(true),
            }),
        )
        .await;
    assert!(on.session_logging);
    let seen: VaultList = s
        .json(Method::GET, "/vaults", Some(viewer.token()), NOBODY)
        .await;
    assert!(
        seen.vaults
            .iter()
            .find(|v| v.id == vault.id)
            .expect("vault")
            .session_logging
    );

    // Manager deletes a teammate's recording: tombstone reaches everyone,
    // the object is gone.
    let before_delete = vault_logs(s, vault.id, viewer.token(), 0).await.since;
    s.expect_status(
        Method::DELETE,
        &format!("/logs/{log_a}"),
        Some(owner.token()),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;
    until_vault_logs(&mut viewer_ws, vault.id).await;
    let tomb = vault_logs(s, vault.id, viewer.token(), before_delete).await;
    assert_eq!(tomb.logs.len(), 1);
    assert!(tomb.logs[0].deleted);
    assert!(tomb.logs[0].author.is_none());
    assert!(!tomb.logs[0].pinned);
    assert_eq!(tomb.logs[0].note, "");
    s.expect_status(
        Method::GET,
        &format!("/logs/{log_a}/download"),
        Some(editor.token()),
        NOBODY,
        StatusCode::NOT_FOUND,
    )
    .await;

    // Activity log names the pin/note, deletion and the toggle — without
    // note text or any recording bytes.
    let audit: AuditEventList = s
        .json(
            Method::GET,
            &format!("/teams/{}/audit", team.id),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let actions: Vec<&str> = audit.events.iter().map(|e| e.action.as_str()).collect();
    assert!(actions.contains(&"log.updated"), "{actions:?}");
    assert!(actions.contains(&"log.deleted"), "{actions:?}");
    assert!(actions.contains(&"vault.session_logging"), "{actions:?}");
    let dump = serde_json::to_string(&audit).unwrap();
    assert!(
        !dump.contains("Incident #42"),
        "note text leaked into audit"
    );
    assert!(!dump.contains("prod-1"), "meta leaked into audit");
    let toggle = audit
        .events
        .iter()
        .find(|e| e.action == "vault.session_logging")
        .unwrap();
    assert_eq!(toggle.details["enabled"], true);
    assert_eq!(toggle.vault_id, Some(vault.id));
}

#[tokio::test]
async fn mandatory_recording_policy_and_team_export() {
    let s = server_with_storage!();
    let owner = register(s, &unique_email("rp-owner"), "pw-owner-1234567").await;
    let editor = register(s, &unique_email("rp-editor"), "pw-editor-123456").await;
    let outsider = register(s, &unique_email("rp-out"), "pw-outsider-1234").await;
    let team: Team = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&CreateTeamRequest {
                name: "Compliance".into(),
            }),
        )
        .await;
    join(s, &team, &owner, &editor, vec![]).await;
    let (vault, _key) = team_vault(s, &team, &owner, &[(&editor, VaultRole::Editor)]).await;
    assert!(!vault.session_logging);
    let policies = format!("/teams/{}/policies", team.id);

    // Validation.
    for bad in [
        serde_json::json!({ "session_recording": "never" }),
        serde_json::json!({ "log_retention_days": -1 }),
        serde_json::json!({ "log_retention_days": 4000 }),
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

    // Mandatory recording switches every team vault on and locks the toggle.
    let p: serde_json::Value = s
        .json(
            Method::PUT,
            &policies,
            Some(owner.token()),
            Some(&serde_json::json!({ "session_recording": "required", "log_retention_days": 90 })),
        )
        .await;
    assert_eq!(p["policies"]["session_recording"], "required");
    assert_eq!(p["policies"]["log_retention_days"], 90);
    assert!(
        p["effective_for_me"]["recording_required_by"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == &serde_json::json!(team.id)),
        "{p}"
    );
    let v: Vault = s
        .json(
            Method::GET,
            &format!("/vaults/{}", vault.id),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert!(v.session_logging, "policy turns recording on");
    s.expect_status(
        Method::PATCH,
        &format!("/vaults/{}", vault.id),
        Some(owner.token()),
        Some(&UpdateVaultRequest {
            name: None,
            session_logging: Some(false),
        }),
        StatusCode::FORBIDDEN,
    )
    .await;

    // Authors cannot delete their own recordings while recording is mandatory;
    // the owner (logs.delete) still can.
    let a = record(s, &editor, vault.id, "deploy", b"first").await;
    let b = record(s, &editor, vault.id, "hotfix", b"second").await;
    s.expect_status(
        Method::DELETE,
        &format!("/logs/{a}"),
        Some(editor.token()),
        NOBODY,
        StatusCode::FORBIDDEN,
    )
    .await;

    // Team-wide listing and export.
    let listed: LogListResponse = s
        .json(
            Method::GET,
            &format!("/teams/{}/logs", team.id),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(listed.total, listed.logs.len() as i64);
    let ids: Vec<Uuid> = listed.logs.iter().map(|l| l.id).collect();
    assert!(ids.contains(&a) && ids.contains(&b), "{ids:?}");
    s.expect_status(
        Method::GET,
        &format!("/teams/{}/logs", team.id),
        Some(outsider.token()),
        NOBODY,
        StatusCode::NOT_FOUND,
    )
    .await;
    let resp = s
        .http()
        .get(s.url(&format!("/teams/{}/logs/export", team.id)))
        .bearer_auth(owner.token())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/x-ndjson")
    );
    let body = resp.text().await.unwrap();
    let lines: Vec<serde_json::Value> = body
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "{body}");
    assert!(
        lines.iter().all(|l| l["download_url"].is_string()),
        "{body}"
    );
    let events: AuditEventList = s
        .json(
            Method::GET,
            &format!("/teams/{}/audit?limit=50", team.id),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert!(events.events.iter().any(|e| e.action == "logs.exported"));

    s.expect_status(
        Method::DELETE,
        &format!("/logs/{a}"),
        Some(owner.token()),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;

    // Back to optional: authors delete their own again.
    let _: serde_json::Value = s
        .json(
            Method::PUT,
            &policies,
            Some(owner.token()),
            Some(&serde_json::json!({ "session_recording": "optional" })),
        )
        .await;
    s.expect_status(
        Method::DELETE,
        &format!("/logs/{b}"),
        Some(editor.token()),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;
}

#[tokio::test]
async fn recording_comments_by_role() {
    let s = server_with_storage!();
    let owner = register(s, &unique_email("lc-owner"), "pw-owner-1234567").await;
    let editor = register(s, &unique_email("lc-editor"), "pw-editor-123456").await;
    let viewer = register(s, &unique_email("lc-viewer"), "pw-viewer-123456").await;
    let outsider = register(s, &unique_email("lc-out"), "pw-outsider-1234").await;
    let team: Team = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&CreateTeamRequest { name: "Ops".into() }),
        )
        .await;
    for u in [&editor, &viewer] {
        join(s, &team, &owner, u, vec![]).await;
    }
    let (vault, _key) = team_vault(
        s,
        &team,
        &owner,
        &[(&editor, VaultRole::Editor), (&viewer, VaultRole::Viewer)],
    )
    .await;
    let log = record(s, &editor, vault.id, "deploy", b"xterm bytes").await;
    let say = |body: &str, offset: Option<i64>| CreateLogCommentRequest {
        body: body.to_owned(),
        offset_ms: offset,
    };

    // Empty thread for every reader; outsiders see no recording at all.
    let empty: LogCommentList = s
        .json(
            Method::GET,
            &format!("/logs/{log}/comments"),
            Some(viewer.token()),
            NOBODY,
        )
        .await;
    assert!(empty.comments.is_empty());
    s.expect_status(
        Method::GET,
        &format!("/logs/{log}/comments"),
        Some(outsider.token()),
        NOBODY,
        StatusCode::NOT_FOUND,
    )
    .await;

    // Editor (author) and owner comment; the viewer may only read.
    let first: LogComment = s
        .json(
            Method::POST,
            &format!("/logs/{log}/comments"),
            Some(editor.token()),
            Some(&say("  restart at 00:12  ", Some(12_000))),
        )
        .await;
    assert_eq!(first.body, "restart at 00:12");
    assert_eq!(first.offset_ms, Some(12_000));
    assert_eq!(first.author.as_ref().map(|a| a.user_id), Some(editor.id()));
    let second: LogComment = s
        .json(
            Method::POST,
            &format!("/logs/{log}/comments"),
            Some(owner.token()),
            Some(&say("looks fine", None)),
        )
        .await;
    s.expect_status(
        Method::POST,
        &format!("/logs/{log}/comments"),
        Some(viewer.token()),
        Some(&say("me too", None)),
        StatusCode::FORBIDDEN,
    )
    .await;
    s.expect_status(
        Method::POST,
        &format!("/logs/{log}/comments"),
        Some(editor.token()),
        Some(&say("   ", None)),
        StatusCode::BAD_REQUEST,
    )
    .await;
    s.expect_status(
        Method::POST,
        &format!("/logs/{log}/comments"),
        Some(editor.token()),
        Some(&say("back in time", Some(-1))),
        StatusCode::BAD_REQUEST,
    )
    .await;

    let thread: LogCommentList = s
        .json(
            Method::GET,
            &format!("/logs/{log}/comments"),
            Some(viewer.token()),
            NOBODY,
        )
        .await;
    assert_eq!(
        thread.comments.iter().map(|c| c.id).collect::<Vec<_>>(),
        vec![first.id, second.id],
        "oldest first"
    );

    // Deleting: the editor cannot remove the owner's comment, the owner (manager) can remove any.
    s.expect_status(
        Method::DELETE,
        &format!("/logs/{log}/comments/{}", second.id),
        Some(editor.token()),
        NOBODY,
        StatusCode::FORBIDDEN,
    )
    .await;
    s.expect_status(
        Method::DELETE,
        &format!("/logs/{log}/comments/{}", first.id),
        Some(editor.token()),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;
    s.expect_status(
        Method::DELETE,
        &format!("/logs/{log}/comments/{}", second.id),
        Some(owner.token()),
        NOBODY,
        StatusCode::NO_CONTENT,
    )
    .await;
    let gone: LogCommentList = s
        .json(
            Method::GET,
            &format!("/logs/{log}/comments"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert!(gone.comments.is_empty());

    // The team audit trail saw both the comment and its removal.
    let audit: AuditEventList = s
        .json(
            Method::GET,
            &format!("/teams/{}/audit?limit=50", team.id),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    let actions: Vec<&str> = audit.events.iter().map(|e| e.action.as_str()).collect();
    assert!(actions.contains(&"log.commented"), "{actions:?}");
    assert!(actions.contains(&"log.comment_deleted"), "{actions:?}");
}
