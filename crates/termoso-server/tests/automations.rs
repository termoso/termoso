//! Team automations: CRUD and validation, run-now, claim / finish by an
//! executor, scheduler tick (due → pending, stale pending → missed).

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use termoso_crypto::keys::SymmetricKey;
use termoso_crypto::sealed;
use termoso_proto::automation::*;
use termoso_proto::vault::{CreateVaultRequest, VaultMemberUpsert, VaultRole};
use uuid::Uuid;

macro_rules! server {
    () => {
        match server().await {
            Some(s) => s,
            None => return,
        }
    };
}

async fn team_and_vault(s: &TestServer) -> (User, String, Uuid) {
    let owner = register(s, &unique_email("auto-owner"), "pw-owner-1234567").await;
    let team: serde_json::Value = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&serde_json::json!({ "name": "Ops" })),
        )
        .await;
    let team_id = team["id"].as_str().unwrap().to_string();
    let key = SymmetricKey::generate();
    let vault: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{team_id}/vaults"),
            Some(owner.token()),
            Some(&CreateVaultRequest {
                name: "Prod".into(),
                members: vec![VaultMemberUpsert {
                    user_id: owner.id(),
                    role: VaultRole::Manager,
                    sealed_key: sealed::seal_vault_key(owner.keypair.public(), &key).unwrap(),
                }],
            }),
        )
        .await;
    let vault_id: Uuid = vault["id"].as_str().unwrap().parse().unwrap();
    (owner, team_id, vault_id)
}

fn req(vault_id: Uuid, schedule: &str) -> CreateAutomationRequest {
    CreateAutomationRequest {
        vault_id,
        snippet_id: Uuid::new_v4(),
        name: "Disk check".into(),
        host_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
        group_id: None,
        schedule: schedule.into(),
        timezone: Some("+03:00".into()),
        enabled: None,
        timeout_secs: None,
        alert_on: None,
        alert_emails: vec!["ops@example.com".into()],
        alert_admins: None,
    }
}

#[tokio::test]
async fn crud_validation_and_executor_flow() {
    let s = server!();
    let (owner, team_id, vault_id) = team_and_vault(s).await;
    let base = format!("/teams/{team_id}/automations");

    // Validation.
    for (bad, what) in [
        (req(vault_id, "* * * *"), "4 fields"),
        (req(vault_id, "0 0 31 2 *"), "never fires"),
        (req(Uuid::new_v4(), "@daily"), "foreign vault"),
    ] {
        s.expect_status(
            Method::POST,
            &base,
            Some(owner.token()),
            Some(&bad),
            StatusCode::BAD_REQUEST,
        )
        .await;
        let _ = what;
    }
    let mut no_hosts = req(vault_id, "@daily");
    no_hosts.host_ids.clear();
    s.expect_status(
        Method::POST,
        &base,
        Some(owner.token()),
        Some(&no_hosts),
        StatusCode::BAD_REQUEST,
    )
    .await;
    let mut bad_mail = req(vault_id, "@daily");
    bad_mail.alert_emails = vec!["nope".into()];
    s.expect_status(
        Method::POST,
        &base,
        Some(owner.token()),
        Some(&bad_mail),
        StatusCode::BAD_REQUEST,
    )
    .await;

    // Create.
    let a: Automation = s
        .json(
            Method::POST,
            &base,
            Some(owner.token()),
            Some(&req(vault_id, "*/15 * * * *")),
        )
        .await;
    assert_eq!(a.name, "Disk check");
    assert_eq!(a.timezone, "+03:00");
    assert_eq!(a.timeout_secs, TIMEOUT_SECS_DEFAULT);
    assert_eq!(a.alert_on, "failure");
    assert!(a.alert_admins);
    assert_eq!(a.host_ids.len(), 2);
    let next = a.next_run_at.expect("scheduled");
    assert!(
        next > chrono::Utc::now() && next <= chrono::Utc::now() + chrono::Duration::minutes(15)
    );
    assert_eq!(next.timestamp() % 900, 0, "aligned to a quarter hour");

    let list: AutomationList = s
        .json::<(), _>(Method::GET, &base, Some(owner.token()), None)
        .await;
    assert_eq!(list.automations.len(), 1);

    // Pause clears the slot; resume schedules again.
    let paused: Automation = s
        .json(
            Method::PUT,
            &format!("{base}/{}", a.id),
            Some(owner.token()),
            Some(&UpdateAutomationRequest {
                enabled: Some(false),
                ..Default::default()
            }),
        )
        .await;
    assert!(!paused.enabled && paused.next_run_at.is_none());
    let resumed: Automation = s
        .json(
            Method::PUT,
            &format!("{base}/{}", a.id),
            Some(owner.token()),
            Some(&UpdateAutomationRequest {
                enabled: Some(true),
                schedule: Some("0 3 * * 1-5".into()),
                timezone: Some("UTC".into()),
                alert_on: Some("always".into()),
                ..Default::default()
            }),
        )
        .await;
    assert!(resumed.enabled && resumed.next_run_at.is_some());
    assert_eq!(resumed.schedule, "0 3 * * 1-5");
    assert_eq!(resumed.alert_on, "always");

    // Run now → pending; a second one conflicts.
    let run: AutomationRun = s
        .json::<(), _>(
            Method::POST,
            &format!("{base}/{}/run", a.id),
            Some(owner.token()),
            None,
        )
        .await;
    assert_eq!(run.status, "pending");
    assert!(run.manual);
    s.expect_status::<()>(
        Method::POST,
        &format!("{base}/{}/run", a.id),
        Some(owner.token()),
        None,
        StatusCode::CONFLICT,
    )
    .await;

    // Nothing to finish yet: not running.
    s.expect_status(
        Method::PATCH,
        &format!("{base}/runs/{}", run.id),
        Some(owner.token()),
        Some(&FinishRunRequest {
            outcomes: vec![],
            sealed: None,
            key_version: None,
            error: None,
        }),
        StatusCode::CONFLICT,
    )
    .await;

    // Claim restricted to other vaults finds nothing; unrestricted claims it.
    let none: ClaimRunsResponse = s
        .json(
            Method::POST,
            &format!("{base}/runs/claim"),
            Some(owner.token()),
            Some(&ClaimRunsRequest {
                vault_ids: vec![Uuid::new_v4()],
                limit: None,
            }),
        )
        .await;
    assert!(none.runs.is_empty());
    let claimed: ClaimRunsResponse = s
        .json(
            Method::POST,
            &format!("{base}/runs/claim"),
            Some(owner.token()),
            Some(&ClaimRunsRequest::default()),
        )
        .await;
    assert_eq!(claimed.runs.len(), 1);
    let c = &claimed.runs[0];
    assert_eq!(c.run.id, run.id);
    assert_eq!(c.run.status, "running");
    assert_eq!(c.vault_id, vault_id);
    assert_eq!(c.snippet_id, a.snippet_id);
    assert_eq!(c.host_ids, a.host_ids);
    assert_eq!(c.name, "Disk check");
    let again: ClaimRunsResponse = s
        .json(
            Method::POST,
            &format!("{base}/runs/claim"),
            Some(owner.token()),
            Some(&ClaimRunsRequest::default()),
        )
        .await;
    assert!(again.runs.is_empty(), "claimed once");

    // Oversized sealed blob is refused.
    s.expect_status(
        Method::PATCH,
        &format!("{base}/runs/{}", run.id),
        Some(owner.token()),
        Some(&FinishRunRequest {
            outcomes: vec![],
            sealed: Some("y".repeat(SEALED_CAP + 1)),
            key_version: Some(1),
            error: None,
        }),
        StatusCode::BAD_REQUEST,
    )
    .await;

    // Finish with one failure → failed; the server keeps only {host_id, ok}
    // and the opaque sealed blob — labels/targets/output never reach it.
    let results = [
        HostRunResult {
            host_id: a.host_ids[0],
            label: "web-1".into(),
            target: "ubuntu@web-1:22".into(),
            exit_code: Some(0),
            stdout: "ok\n".into(),
            ..Default::default()
        },
        HostRunResult {
            host_id: a.host_ids[1],
            label: "web-2".into(),
            error: Some("connection refused".into()),
            ..Default::default()
        },
    ];
    let blob = "opaque-ciphertext".to_string();
    let done: AutomationRun = s
        .json(
            Method::PATCH,
            &format!("{base}/runs/{}", run.id),
            Some(owner.token()),
            Some(&FinishRunRequest {
                outcomes: results.iter().map(HostRunResult::outcome).collect(),
                sealed: Some(blob.clone()),
                key_version: Some(1),
                error: None,
            }),
        )
        .await;
    assert_eq!(done.status, "failed");
    assert_eq!((done.hosts_total, done.hosts_failed), (2, 1));
    assert_eq!(done.vault_id, vault_id);
    assert_eq!(done.outcomes.len(), 2);
    assert!(done.outcomes[0].ok && !done.outcomes[1].ok);
    assert_eq!(done.sealed.as_deref(), Some(blob.as_str()));
    assert_eq!(done.key_version, Some(1));
    assert!(
        done.results.is_empty(),
        "server never returns plaintext results"
    );
    assert!(done.claimed_by_name.is_some());
    let raw = s
        .call::<()>(
            Method::GET,
            &format!("{base}/{}/runs", a.id),
            Some(owner.token()),
            None,
        )
        .await
        .text()
        .await
        .expect("body");
    assert!(
        !raw.contains("web-1") && !raw.contains("ubuntu@"),
        "no labels/targets on the wire"
    );
    let runs: AutomationRunList = s
        .json::<(), _>(
            Method::GET,
            &format!("{base}/{}/runs", a.id),
            Some(owner.token()),
            None,
        )
        .await;
    assert_eq!(runs.runs.len(), 1);
    let fresh: Automation = s
        .json::<(), _>(
            Method::GET,
            &format!("{base}/{}", a.id),
            Some(owner.token()),
            None,
        )
        .await;
    assert_eq!(fresh.last_status.as_deref(), Some("failed"));

    // Outsider: 404 team.
    let stranger = register(s, &unique_email("auto-stranger"), "pw-stranger-1234567").await;
    s.expect_status::<()>(
        Method::GET,
        &base,
        Some(stranger.token()),
        None,
        StatusCode::NOT_FOUND,
    )
    .await;

    // Delete cascades runs.
    s.expect_status::<()>(
        Method::DELETE,
        &format!("{base}/{}", a.id),
        Some(owner.token()),
        None,
        StatusCode::NO_CONTENT,
    )
    .await;
    s.expect_status::<()>(
        Method::GET,
        &format!("{base}/{}", a.id),
        Some(owner.token()),
        None,
        StatusCode::NOT_FOUND,
    )
    .await;
}

/// The scheduler turns a due slot into a pending run and advances the
/// schedule; a pending run nobody claims in time is marked missed.
#[tokio::test]
async fn scheduler_tick_creates_and_expires_runs() {
    let s = server!();
    let (owner, team_id, vault_id) = team_and_vault(s).await;
    let base = format!("/teams/{team_id}/automations");
    let a: Automation = s
        .json(
            Method::POST,
            &base,
            Some(owner.token()),
            Some(&req(vault_id, "@hourly")),
        )
        .await;
    let aid = a.id.to_string();
    // Make the slot due.
    s.sql(
        "UPDATE team_automations SET next_run_at = now() - interval '1 minute' WHERE id = $1::uuid",
        &aid,
    )
    .await;
    s.tick_automations().await;
    let runs: AutomationRunList = s
        .json::<(), _>(
            Method::GET,
            &format!("{base}/{}/runs", a.id),
            Some(owner.token()),
            None,
        )
        .await;
    assert_eq!(runs.runs.len(), 1);
    assert_eq!(runs.runs[0].status, "pending");
    assert!(!runs.runs[0].manual);
    let after: Automation = s
        .json::<(), _>(
            Method::GET,
            &format!("{base}/{}", a.id),
            Some(owner.token()),
            None,
        )
        .await;
    assert!(after.next_run_at.unwrap() > chrono::Utc::now(), "advanced");
    // A second tick with the slot still in the future adds nothing.
    s.tick_automations().await;
    let runs: AutomationRunList = s
        .json::<(), _>(
            Method::GET,
            &format!("{base}/{}/runs", a.id),
            Some(owner.token()),
            None,
        )
        .await;
    assert_eq!(runs.runs.len(), 1);
    // Age the pending run past the claim window → missed.
    s.sql(
        "UPDATE team_automation_runs SET created_at = now() - interval '20 minutes' WHERE automation_id = $1::uuid",
        &aid,
    )
    .await;
    s.tick_automations().await;
    let runs: AutomationRunList = s
        .json::<(), _>(
            Method::GET,
            &format!("{base}/{}/runs", a.id),
            Some(owner.token()),
            None,
        )
        .await;
    assert_eq!(runs.runs[0].status, "missed");
    let after: Automation = s
        .json::<(), _>(
            Method::GET,
            &format!("{base}/{}", a.id),
            Some(owner.token()),
            None,
        )
        .await;
    assert_eq!(after.last_status.as_deref(), Some("missed"));
}
