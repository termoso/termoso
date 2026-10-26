//! Team automations (`/teams/{id}/automations`): a snippet run on a set of
//! hosts on a schedule. The server keeps only opaque entity ids and the
//! schedule; a device with the vault key (API bridge or an opted-in desktop)
//! claims due runs, executes them and reports the results.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::schema;

/// Longest a single run may take before the executor gives up (seconds).
pub const TIMEOUT_SECS_MIN: i32 = 10;
/// Longest per-run timeout (one hour).
pub const TIMEOUT_SECS_MAX: i32 = 3600;
/// Default per-run timeout.
pub const TIMEOUT_SECS_DEFAULT: i32 = 300;
/// A pending run nobody claimed within this many minutes is marked `missed`.
pub const MISSED_AFTER_MINUTES: i64 = 15;
/// Most hosts one automation targets.
pub const HOSTS_MAX: usize = 200;
/// Most extra alert recipients.
pub const ALERT_EMAILS_MAX: usize = 20;
/// Output kept per stream per host in a result (bytes).
pub const OUTPUT_CAP: usize = 8 * 1024;

/// When to send e-mail alerts.
pub const ALERT_ON: [&str; 3] = ["never", "failure", "always"];

schema! {
    /// A scheduled snippet run.
    pub struct Automation {
        /// Id.
        pub id: Uuid,
        /// Team.
        pub team_id: Uuid,
        /// Team vault holding the snippet and the hosts.
        pub vault_id: Uuid,
        /// Snippet entity (opaque to the server).
        pub snippet_id: Uuid,
        /// Admin-given name (shown in alerts and the audit log).
        pub name: String,
        /// Host entities to run on (opaque to the server).
        pub host_ids: Vec<Uuid>,
        /// Group entity whose hosts are added at run time (opaque).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group_id: Option<Uuid>,
        /// 5-field cron expression (`*/15 * * * *`, `0 3 * * 1-5`) or
        /// `@hourly` / `@daily` / `@weekly` / `@monthly`.
        pub schedule: String,
        /// `UTC` or a fixed offset such as `+03:00`.
        pub timezone: String,
        /// Paused automations keep their history but schedule nothing.
        pub enabled: bool,
        /// Per-run timeout.
        pub timeout_secs: i32,
        /// `never`, `failure` or `always`.
        pub alert_on: String,
        /// Extra recipients besides team admins.
        pub alert_emails: Vec<String>,
        /// Mail owners and admins of the team.
        pub alert_admins: bool,
        /// Last finished run.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_run_at: Option<DateTime<Utc>>,
        /// Status of the last finished run.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_status: Option<String>,
        /// Next scheduled run (`None` while paused).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next_run_at: Option<DateTime<Utc>>,
        /// Who created it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub created_by: Option<Uuid>,
        /// Creation time.
        pub created_at: DateTime<Utc>,
        /// Last change.
        pub updated_at: DateTime<Utc>,
    }
}

schema! {
    /// `POST /teams/{id}/automations`.
    pub struct CreateAutomationRequest {
        /// Team vault holding the snippet and the hosts.
        pub vault_id: Uuid,
        /// Snippet entity.
        pub snippet_id: Uuid,
        /// Name, 1–80 characters.
        pub name: String,
        /// Host entities.
        #[serde(default)]
        pub host_ids: Vec<Uuid>,
        /// Group entity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group_id: Option<Uuid>,
        /// Cron expression.
        pub schedule: String,
        /// `UTC` (default) or `+HH:MM` / `-HH:MM`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timezone: Option<String>,
        /// Start paused.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        /// Per-run timeout.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout_secs: Option<i32>,
        /// `never`, `failure` (default) or `always`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alert_on: Option<String>,
        /// Extra recipients.
        #[serde(default)]
        pub alert_emails: Vec<String>,
        /// Mail team admins (default true).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alert_admins: Option<bool>,
    }
}

schema! {
    /// `PUT /teams/{id}/automations/{aid}`: present fields are replaced.
    #[derive(Default)]
    pub struct UpdateAutomationRequest {
        /// Snippet entity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub snippet_id: Option<Uuid>,
        /// Name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// Host entities.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host_ids: Option<Vec<Uuid>>,
        /// Group entity; `Some(None)` clears it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group_id: Option<Option<Uuid>>,
        /// Cron expression.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schedule: Option<String>,
        /// Timezone.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timezone: Option<String>,
        /// Pause / resume.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        /// Per-run timeout.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout_secs: Option<i32>,
        /// Alert policy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alert_on: Option<String>,
        /// Extra recipients.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alert_emails: Option<Vec<String>>,
        /// Mail team admins.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alert_admins: Option<bool>,
    }
}

schema! {
    /// `GET /teams/{id}/automations`.
    pub struct AutomationList {
        /// All automations of the team.
        pub automations: Vec<Automation>,
    }
}

schema! {
    /// Outcome on one host.
    #[derive(Default, PartialEq, Eq)]
    pub struct HostRunResult {
        /// Host entity.
        pub host_id: Uuid,
        /// Host label at run time.
        pub label: String,
        /// `user@host:port` the command ran on (empty when connecting failed).
        #[serde(default)]
        pub target: String,
        /// Exit code of the snippet, `None` when it never ran or was killed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exit_code: Option<u32>,
        /// Standard output, capped at [`OUTPUT_CAP`].
        #[serde(default)]
        pub stdout: String,
        /// Standard error, capped.
        #[serde(default)]
        pub stderr: String,
        /// Connection / transport / timeout error; the command never finished.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        /// Wall time in milliseconds.
        #[serde(default)]
        pub ms: u64,
    }
}

impl HostRunResult {
    /// Succeeded: ran and exited 0.
    pub fn ok(&self) -> bool {
        self.error.is_none() && self.exit_code == Some(0)
    }
}

schema! {
    /// One run of an automation.
    pub struct AutomationRun {
        /// Id.
        pub id: Uuid,
        /// Automation.
        pub automation_id: Uuid,
        /// Team.
        pub team_id: Uuid,
        /// `pending`, `running`, `done`, `failed`, `missed` or `cancelled`.
        pub status: String,
        /// When the schedule asked for it (or when "run now" was pressed).
        pub scheduled_for: DateTime<Utc>,
        /// Started by hand rather than by the schedule.
        pub manual: bool,
        /// Executor device.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claimed_by_device: Option<Uuid>,
        /// Executor device name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claimed_by_name: Option<String>,
        /// Claim time.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claimed_at: Option<DateTime<Utc>>,
        /// Finish time.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub finished_at: Option<DateTime<Utc>>,
        /// Hosts attempted.
        pub hosts_total: i32,
        /// Hosts that failed (connection error or non-zero exit).
        pub hosts_failed: i32,
        /// Per-host results (empty until finished).
        #[serde(default)]
        pub results: Vec<HostRunResult>,
        /// Run-level error (executor could not start at all).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        /// Creation time.
        pub created_at: DateTime<Utc>,
    }
}

schema! {
    /// `GET /teams/{id}/automations/{aid}/runs`.
    pub struct AutomationRunList {
        /// Newest first.
        pub runs: Vec<AutomationRun>,
    }
}

schema! {
    /// What an executor needs to perform a claimed run.
    pub struct ClaimedRun {
        /// The run (status `running`).
        pub run: AutomationRun,
        /// Vault, snippet, hosts and group to resolve locally.
        pub vault_id: Uuid,
        /// Snippet entity.
        pub snippet_id: Uuid,
        /// Host entities.
        pub host_ids: Vec<Uuid>,
        /// Group entity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group_id: Option<Uuid>,
        /// Per-run timeout.
        pub timeout_secs: i32,
        /// Automation name.
        pub name: String,
    }
}

schema! {
    /// `POST /teams/{id}/automations/runs/claim`.
    #[derive(Default)]
    pub struct ClaimRunsRequest {
        /// Only runs whose vault is in this list (executors claim what they
        /// can open); empty means any vault of the team.
        #[serde(default)]
        pub vault_ids: Vec<Uuid>,
        /// At most this many runs (default 5).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<i32>,
    }
}

schema! {
    /// `POST /teams/{id}/automations/runs/claim` response.
    pub struct ClaimRunsResponse {
        /// Runs now owned by the caller.
        pub runs: Vec<ClaimedRun>,
    }
}

schema! {
    /// `PATCH /teams/{id}/automations/runs/{rid}`: report the outcome.
    pub struct FinishRunRequest {
        /// Per-host results.
        #[serde(default)]
        pub results: Vec<HostRunResult>,
        /// Run-level error when nothing could run.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
    }
}
