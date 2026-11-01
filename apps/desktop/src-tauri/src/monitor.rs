//! Remote resource monitor for the status bar under an SSH terminal.
//!
//! The webview polls [`terminal_monitor`] every few seconds while the bar is
//! visible. Each call runs the read-only probe from `termoso_core::monitor` on
//! a separate `exec` channel (the interactive shell never sees it) and turns
//! the counters into rates against the previous call for the same session.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use bytes::Bytes;
use serde::Serialize;
use tauri::State;
use termoso_core::monitor::{self, Counters, PROBE_SCRIPT, PROBE_TIMEOUT, Probe, Snapshot};
use uuid::Uuid;

use crate::error::{DesktopError, Result};
use crate::state::AppState;

/// Previous counters per session, for rate computation.
#[derive(Default)]
pub struct MonitorState {
    prev: Mutex<HashMap<Uuid, (Counters, Instant)>>,
}

/// Answer for the webview.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum MonitorReply {
    /// Fresh numbers.
    Ok { snapshot: Snapshot },
    /// The remote is not Linux (no `/proc`); the bar shows a hint and stops polling.
    Unsupported,
}

/// Probe the machine behind SSH session `id`.
#[tauri::command]
pub async fn terminal_monitor(
    state: State<'_, AppState>,
    monitor_state: State<'_, MonitorState>,
    id: Uuid,
) -> Result<MonitorReply> {
    let info = state.sessions.info(id)?;
    if info.protocol != "ssh" {
        return Ok(MonitorReply::Unsupported);
    }
    let client = state.sessions.client(id)?;
    let out = tokio::time::timeout(
        PROBE_TIMEOUT,
        client.exec("sh", Some(Bytes::from_static(PROBE_SCRIPT.as_bytes()))),
    )
    .await
    .map_err(|_| DesktopError::invalid("monitor probe timed out"))??;
    match monitor::parse(&out.stdout_str()) {
        Some(Probe::Sample(sample)) => {
            let now = Instant::now();
            let snapshot = {
                let mut prev = monitor_state.prev.lock().expect("monitor state poisoned");
                let snap = Snapshot::from_samples(
                    &sample,
                    prev.get(&id).map(|(c, at)| (c, now.duration_since(*at))),
                );
                prev.insert(id, (sample.counters, now));
                snap
            };
            Ok(MonitorReply::Ok { snapshot })
        }
        Some(Probe::Unsupported) => Ok(MonitorReply::Unsupported),
        None => Err(DesktopError::invalid("unexpected monitor output")),
    }
}

/// Forget the counters of a session (bar switched off or session closed).
#[tauri::command]
pub fn terminal_monitor_reset(monitor_state: State<'_, MonitorState>, id: Uuid) {
    monitor_state
        .prev
        .lock()
        .expect("monitor state poisoned")
        .remove(&id);
}
