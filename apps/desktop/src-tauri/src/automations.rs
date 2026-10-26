//! Team automations on the desktop: the team page's CRUD commands and an
//! optional executor (`Settings::run_automations`) that claims due runs for
//! teams whose vaults are unlocked here, runs the snippet on the hosts and
//! reports results — the same thing the API bridge does headless.

use std::collections::HashSet;
use std::time::Duration;

use tauri::{AppHandle, Manager, Runtime};
use termoso_core::model::{Group, Host, Snippet};
use termoso_proto::automation::*;
use uuid::Uuid;

use crate::account::api;
use crate::error::{DesktopError, Result};
use crate::state::AppState;

const POLL: Duration = Duration::from_secs(60);
const PARALLEL: usize = 4;

pub async fn list<R: Runtime>(app: &AppHandle<R>, team_id: Uuid) -> Result<AutomationList> {
    Ok(api(app).await?.team_automations(team_id).await?)
}

pub async fn create<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    req: CreateAutomationRequest,
) -> Result<Automation> {
    Ok(api(app).await?.create_automation(team_id, &req).await?)
}

pub async fn update<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    id: Uuid,
    req: UpdateAutomationRequest,
) -> Result<Automation> {
    Ok(api(app).await?.update_automation(team_id, id, &req).await?)
}

pub async fn delete<R: Runtime>(app: &AppHandle<R>, team_id: Uuid, id: Uuid) -> Result<()> {
    Ok(api(app).await?.delete_automation(team_id, id).await?)
}

pub async fn run_now<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    id: Uuid,
) -> Result<AutomationRun> {
    Ok(api(app).await?.run_automation_now(team_id, id).await?)
}

pub async fn runs<R: Runtime>(
    app: &AppHandle<R>,
    team_id: Uuid,
    id: Uuid,
) -> Result<AutomationRunList> {
    Ok(api(app).await?.automation_runs(team_id, id).await?)
}

/// Background loop; a no-op while the setting is off or nobody is signed in.
pub async fn executor<R: Runtime>(app: AppHandle<R>) {
    let mut tick = tokio::time::interval(POLL);
    loop {
        tick.tick().await;
        let enabled = app
            .state::<AppState>()
            .settings()
            .map(|s| s.run_automations)
            .unwrap_or(false);
        if !enabled {
            continue;
        }
        match pass(&app).await {
            Ok(0) | Err(_) => {}
            Ok(n) => tracing::info!(runs = n, "automations executed"),
        }
    }
}

/// Claim and execute due runs for every team with an unlocked vault here.
pub async fn pass<R: Runtime>(app: &AppHandle<R>) -> Result<usize> {
    let teams: Vec<(Uuid, Vec<Uuid>)> = {
        let state = app.state::<AppState>();
        let store = state.store()?;
        let mut out: Vec<(Uuid, Vec<Uuid>)> = Vec::new();
        for v in store.vaults()? {
            let Some(team) = v.team_id else { continue };
            if !v.unlocked {
                continue;
            }
            match out.iter_mut().find(|(t, _)| *t == team) {
                Some((_, ids)) => ids.push(v.id),
                None => out.push((team, vec![v.id])),
            }
        }
        out
    };
    if teams.is_empty() {
        return Ok(0);
    }
    let api = api(app).await?;
    let mut executed = 0;
    for (team_id, vault_ids) in teams {
        let claimed = api
            .claim_automation_runs(
                team_id,
                &ClaimRunsRequest {
                    vault_ids,
                    limit: Some(5),
                },
            )
            .await?;
        for run in claimed.runs {
            let rid = run.run.id;
            let report = execute(app, &run).await;
            api.finish_automation_run(team_id, rid, &report).await?;
            executed += 1;
        }
    }
    Ok(executed)
}

fn group_tree(groups: &[(Uuid, Option<Uuid>)], root: Uuid) -> HashSet<Uuid> {
    let mut set = HashSet::from([root]);
    loop {
        let before = set.len();
        for (id, parent) in groups {
            if parent.is_some_and(|p| set.contains(&p)) {
                set.insert(*id);
            }
        }
        if set.len() == before {
            return set;
        }
    }
}

async fn execute<R: Runtime>(app: &AppHandle<R>, run: &ClaimedRun) -> FinishRunRequest {
    let prepared: Result<(String, Vec<(Uuid, String)>)> = (|| {
        let state = app.state::<AppState>();
        let store = state.store()?;
        let snippet = store.require::<Snippet>(run.snippet_id)?;
        let mut ids: Vec<Uuid> = run.host_ids.clone();
        let hosts = store.list::<Host>(Some(run.vault_id))?;
        if let Some(g) = run.group_id {
            let groups: Vec<(Uuid, Option<Uuid>)> = store
                .list::<Group>(Some(run.vault_id))?
                .into_iter()
                .map(|g| (g.id, g.data.parent_id))
                .collect();
            let tree = group_tree(&groups, g);
            for h in &hosts {
                if h.data.group_id.is_some_and(|gid| tree.contains(&gid)) && !ids.contains(&h.id) {
                    ids.push(h.id);
                }
            }
        }
        let jobs = ids
            .into_iter()
            .map(|id| {
                let label = hosts
                    .iter()
                    .find(|h| h.id == id)
                    .map(|h| h.data.label.clone())
                    .unwrap_or_else(|| id.to_string());
                (id, label)
            })
            .collect();
        Ok((snippet.data.script, jobs))
    })();
    let (script, jobs) = match prepared {
        Ok(p) => p,
        Err(e) => {
            return FinishRunRequest {
                results: Vec::new(),
                error: Some(e.to_string()),
            };
        }
    };
    let budget = Duration::from_secs(run.timeout_secs.max(10) as u64);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(PARALLEL));
    let mut handles = Vec::with_capacity(jobs.len());
    for (host_id, label) in jobs {
        let app = app.clone();
        let script = script.clone();
        let sem = sem.clone();
        handles.push(tauri::async_runtime::spawn(async move {
            let _permit = sem.acquire().await;
            let started = std::time::Instant::now();
            let mut r = HostRunResult {
                host_id,
                label,
                ..Default::default()
            };
            let work = async {
                let conn =
                    crate::sessions::connect_host(&app, Uuid::new_v4(), host_id, None).await?;
                let out = conn.client.exec(&script, None).await;
                let target = conn.display.clone();
                conn.close().await;
                Ok::<_, DesktopError>((target, out?))
            };
            match tokio::time::timeout(budget, work).await {
                Ok(Ok((target, out))) => {
                    r.target = target;
                    r.exit_code = out.exit_code;
                    r.stdout = cap(String::from_utf8_lossy(&out.stdout).into_owned());
                    r.stderr = cap(String::from_utf8_lossy(&out.stderr).into_owned());
                    if out.exit_code.is_none() {
                        r.error = Some("no exit status".into());
                    }
                }
                Ok(Err(e)) => r.error = Some(e.to_string()),
                Err(_) => r.error = Some(format!("timed out after {}s", budget.as_secs())),
            }
            r.ms = started.elapsed().as_millis() as u64;
            r
        }));
    }
    let mut results = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(r) = h.await {
            results.push(r);
        }
    }
    FinishRunRequest {
        results,
        error: None,
    }
}

fn cap(s: String) -> String {
    if s.len() <= OUTPUT_CAP {
        return s;
    }
    let mut end = OUTPUT_CAP;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n… [truncated]", &s[..end])
}
