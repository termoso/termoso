//! Executor for team automations: claim due runs for every team whose vault
//! this bridge can open, run the snippet on the hosts, report results.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use futures::StreamExt;

use termoso_crypto::aead::{self, Aad};
use termoso_crypto::keys::SymmetricKey;
use termoso_proto::automation::{
    ClaimRunsRequest, ClaimedRun, FinishRunRequest, HostRunResult, OUTPUT_CAP, RUN_AAD,
};
use termoso_proto::entities::payload::{Group, Host, Snippet};
use uuid::Uuid;

use crate::bridge::Bridge;
use crate::error::Result;
use crate::exec;
use crate::vault::VaultState;

/// Hosts worked on at the same time within one run.
const PARALLEL: usize = 4;

/// One pass: returns how many runs were executed.
pub async fn pass(bridge: &Bridge) -> Result<usize> {
    let teams: Vec<(Uuid, Vec<Uuid>)> = bridge
        .with_inner(|me, vaults| {
            let mut out: Vec<(Uuid, Vec<Uuid>)> = Vec::new();
            for v in &me.vaults {
                let Some(team) = v.team_id else { continue };
                if !vaults.get(&v.vault_id).is_some_and(|s| s.ready()) {
                    continue;
                }
                match out.iter_mut().find(|(t, _)| *t == team) {
                    Some((_, ids)) => ids.push(v.vault_id),
                    None => out.push((team, vec![v.vault_id])),
                }
            }
            out
        })
        .await?;
    let mut executed = 0;
    for (team_id, vault_ids) in teams {
        let claimed = bridge
            .server()
            .claim_runs(
                team_id,
                &ClaimRunsRequest {
                    vault_ids,
                    limit: Some(5),
                },
            )
            .await?;
        for run in claimed.runs {
            let rid = run.run.id;
            let report = execute(bridge, &run).await;
            bridge.server().finish_run(team_id, rid, &report).await?;
            executed += 1;
        }
    }
    Ok(executed)
}

struct Job {
    host_id: Uuid,
    label: String,
    target: Option<exec::Target>,
    error: Option<String>,
}

/// Descendants of `group` (inclusive).
fn group_tree(v: &VaultState, group: Uuid) -> HashSet<Uuid> {
    let groups: Vec<(Uuid, Option<Uuid>)> = v
        .iter_kind::<Group>("group")
        .map(|(id, _, g)| (id, g.parent_id))
        .collect();
    let mut set = HashSet::from([group]);
    loop {
        let before = set.len();
        for (id, parent) in &groups {
            if parent.is_some_and(|p| set.contains(&p)) {
                set.insert(*id);
            }
        }
        if set.len() == before {
            break;
        }
    }
    set
}

async fn execute(bridge: &Bridge, run: &ClaimedRun) -> FinishRunRequest {
    let prepared: Result<(String, Vec<Job>, SymmetricKey, i32)> = bridge
        .with_inner(|_, vaults| {
            let Some(v) = vaults.get(&run.vault_id) else {
                return Err(crate::error::BridgeError::Invalid(
                    "vault is not mirrored by this bridge".into(),
                ));
            };
            let snippet: Snippet = v
                .get(run.snippet_id, "snippet")
                .ok_or_else(|| crate::error::BridgeError::Invalid("snippet not found".into()))?;
            let mut ids: Vec<Uuid> = run.host_ids.clone();
            if let Some(g) = run.group_id {
                let tree = group_tree(v, g);
                for (id, _, h) in v.iter_kind::<Host>("host") {
                    if h.group_id.is_some_and(|gid| tree.contains(&gid)) && !ids.contains(&id) {
                        ids.push(id);
                    }
                }
            }
            let jobs = ids
                .into_iter()
                .map(|host_id| match v.get::<Host>(host_id, "host") {
                    Some(h) => match exec::resolve(v, host_id, &h) {
                        Ok(t) => Job {
                            host_id,
                            label: h.label.clone(),
                            target: Some(t),
                            error: None,
                        },
                        Err(e) => Job {
                            host_id,
                            label: h.label.clone(),
                            target: None,
                            error: Some(e.to_string()),
                        },
                    },
                    None => Job {
                        host_id,
                        label: host_id.to_string(),
                        target: None,
                        error: Some("host not found in vault".into()),
                    },
                })
                .collect();
            Ok((
                snippet.script,
                jobs,
                v.require_key()?.clone(),
                v.key_version,
            ))
        })
        .await
        .and_then(|r| r);
    let (script, jobs, key, key_version) = match prepared {
        Ok(p) => p,
        Err(e) => {
            return FinishRunRequest {
                outcomes: Vec::new(),
                sealed: None,
                key_version: None,
                error: Some(e.to_string()),
            };
        }
    };
    let budget = Duration::from_secs(run.timeout_secs.max(10) as u64);
    let results: Vec<HostRunResult> = futures::stream::iter(jobs)
        .map(|j| run_one(j, &script, budget))
        .buffer_unordered(PARALLEL)
        .collect()
        .await;
    seal(&key, key_version, run.run.id, results)
}

/// Package results for the server: success flags in the clear, everything
/// else (labels, targets, output, errors) encrypted with the vault key.
fn seal(
    key: &SymmetricKey,
    key_version: i32,
    run_id: Uuid,
    results: Vec<HostRunResult>,
) -> FinishRunRequest {
    let outcomes = results.iter().map(HostRunResult::outcome).collect();
    let sealed = serde_json::to_string(&results).ok().and_then(|pt| {
        aead::encrypt_str(key, &Aad::label(&[RUN_AAD, &run_id.to_string()]), &pt).ok()
    });
    FinishRunRequest {
        outcomes,
        error: sealed
            .is_none()
            .then(|| "could not seal the results".to_string()),
        key_version: sealed.is_some().then_some(key_version),
        sealed,
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

async fn run_one(job: Job, script: &str, budget: Duration) -> HostRunResult {
    let started = Instant::now();
    let mut r = HostRunResult {
        host_id: job.host_id,
        label: job.label.clone(),
        ..Default::default()
    };
    let Some(t) = job.target else {
        r.error = job.error;
        return r;
    };
    r.target = format!("{}@{}:{}", t.target.username, t.target.host, t.target.port);
    match tokio::time::timeout(budget, exec::run(t, script, false, budget)).await {
        Ok(Ok(out)) => {
            r.exit_code = out.exit_code;
            r.stdout = cap(out.stdout);
            r.stderr = cap(out.stderr);
            if out.exit_code.is_none() {
                r.error = Some("no exit status".into());
            }
        }
        Ok(Err(e)) => r.error = Some(e.to_string()),
        Err(_) => r.error = Some(format!("timed out after {}s", budget.as_secs())),
    }
    r.ms = started.elapsed().as_millis() as u64;
    r
}
