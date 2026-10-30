//! "Open" / "Open with…" for remote files: the file is downloaded into a
//! private temporary directory, handed to a local application, and every
//! save the application makes is uploaded back to where it came from until
//! the edit session is closed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, Runtime};
use termoso_core::remote::RemoteFs;
use termoso_core::sftp::{EntryKind, TransferOptions};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::error::{DesktopError, Result};
use crate::state::AppState;

pub const EDIT_EVENT: &str = "sftp_edit";
const POLL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditInfo {
    pub id: Uuid,
    pub sftp_id: Uuid,
    pub remote: String,
    pub local: String,
    pub name: String,
    /// Application the file was handed to (`None` = system default).
    pub app: Option<String>,
    pub size: Option<u64>,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EditEvent {
    Opened {
        id: Uuid,
        info: EditInfo,
    },
    Uploading {
        id: Uuid,
    },
    Uploaded {
        id: Uuid,
        bytes: u64,
        at: DateTime<Utc>,
    },
    Failed {
        id: Uuid,
        message: String,
    },
    Closed {
        id: Uuid,
    },
}

struct Live {
    info: EditInfo,
    cancel: CancellationToken,
    /// Set by "Upload now" to push the current contents on the next tick.
    force: tokio::sync::Notify,
}

#[derive(Default)]
pub struct Edits {
    live: Mutex<HashMap<Uuid, Arc<Live>>>,
}

impl Edits {
    pub fn list(&self) -> Vec<EditInfo> {
        let mut v: Vec<EditInfo> = self
            .live
            .lock()
            .expect("edits poisoned")
            .values()
            .map(|l| l.info.clone())
            .collect();
        v.sort_by_key(|e| e.started_at);
        v
    }

    fn get(&self, id: Uuid) -> Result<Arc<Live>> {
        self.live
            .lock()
            .expect("edits poisoned")
            .get(&id)
            .cloned()
            .ok_or_else(|| DesktopError::not_found(format!("edit session {id}")))
    }

    fn remove(&self, id: Uuid) -> Option<Arc<Live>> {
        self.live.lock().expect("edits poisoned").remove(&id)
    }

    fn for_sftp(&self, sftp_id: Uuid) -> Vec<Uuid> {
        self.live
            .lock()
            .expect("edits poisoned")
            .values()
            .filter(|l| l.info.sftp_id == sftp_id)
            .map(|l| l.info.id)
            .collect()
    }

    /// Stop every watcher and delete all temporary copies (app exit).
    pub fn close_all(&self) {
        let all: Vec<Arc<Live>> = self
            .live
            .lock()
            .expect("edits poisoned")
            .drain()
            .map(|(_, l)| l)
            .collect();
        for live in all {
            live.cancel.cancel();
            if let Some(dir) = Path::new(&live.info.local).parent()
                && dir.starts_with(edit_root())
            {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }
}

fn edit_root() -> PathBuf {
    std::env::temp_dir().join("termoso-edit")
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

fn safe_name(remote: &str) -> String {
    let raw = remote.rsplit('/').next().unwrap_or(remote);
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':') {
                '_'
            } else {
                c
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "file".into()
    } else {
        cleaned
    }
}

/// Hand a local path to the system default application or to `with`.
pub fn open_local(path: &Path, with: Option<&str>) -> Result<()> {
    tauri_plugin_opener::open_path(path, with).map_err(|e| DesktopError::new("open", e.to_string()))
}

/// Download `remote`, open it locally and start watching for saves.
pub async fn open<R: Runtime>(
    app: AppHandle<R>,
    sftp_id: Uuid,
    remote: String,
    with: Option<String>,
) -> Result<EditInfo> {
    let state = app.state::<AppState>();
    let sftp = state.sftp.sftp(sftp_id)?;
    let entry = sftp.stat(&remote).await?;
    if entry.kind == EntryKind::Dir {
        return Err(DesktopError::invalid(format!("{remote} is a directory")));
    }
    let with = with.map(|w| w.trim().to_string()).filter(|w| !w.is_empty());

    let id = Uuid::new_v4();
    let dir = edit_root().join(id.to_string());
    let name = safe_name(&remote);
    let local = dir.join(&name);
    tokio::task::spawn_blocking({
        let dir = dir.clone();
        move || -> std::io::Result<()> {
            std::fs::create_dir_all(&dir)?;
            restrict(&dir, 0o700)
        }
    })
    .await
    .map_err(|e| DesktopError::new("io", e.to_string()))??;

    let cancel = CancellationToken::new();
    let opts = TransferOptions {
        resume: false,
        preserve_mtime: true,
        cancel: cancel.clone(),
        progress: None,
        rate_limit: None,
    };
    if let Err(e) = sftp.download(&remote, &local, &opts).await {
        let _ = tokio::fs::remove_dir_all(&dir).await;
        return Err(e.into());
    }
    let _ = restrict(&local, 0o600);
    if let Err(e) = open_local(&local, with.as_deref()) {
        let _ = tokio::fs::remove_dir_all(&dir).await;
        return Err(e);
    }

    let info = EditInfo {
        id,
        sftp_id,
        remote: remote.clone(),
        local: local.to_string_lossy().into_owned(),
        name,
        app: with,
        size: entry.size,
        started_at: Utc::now(),
    };
    let live = Arc::new(Live {
        info: info.clone(),
        cancel: cancel.clone(),
        force: tokio::sync::Notify::new(),
    });
    state
        .edits
        .live
        .lock()
        .expect("edits poisoned")
        .insert(id, live.clone());
    let _ = app.emit(
        EDIT_EVENT,
        EditEvent::Opened {
            id,
            info: info.clone(),
        },
    );
    tauri::async_runtime::spawn(watch(app.clone(), live, sftp, local, remote));
    Ok(info)
}

type Signature = (Option<std::time::SystemTime>, u64);

async fn signature(path: &Path) -> Option<Signature> {
    let m = tokio::fs::metadata(path).await.ok()?;
    Some((m.modified().ok(), m.len()))
}

/// Poll the local copy; a change that stays stable for one tick (editors
/// write in several steps) is uploaded. Runs until the session is closed.
async fn watch<R: Runtime>(
    app: AppHandle<R>,
    live: Arc<Live>,
    sftp: Arc<dyn RemoteFs>,
    local: PathBuf,
    remote: String,
) {
    let id = live.info.id;
    let mut last = signature(&local).await;
    let mut pending: Option<Signature> = None;
    loop {
        let forced = tokio::select! {
            _ = live.cancel.cancelled() => break,
            _ = tokio::time::sleep(POLL) => false,
            _ = live.force.notified() => true,
        };
        let Some(now) = signature(&local).await else {
            continue;
        };
        if !forced {
            if Some(now) == last {
                pending = None;
                continue;
            }
            if pending != Some(now) {
                pending = Some(now);
                continue;
            }
        }
        pending = None;
        let _ = app.emit(EDIT_EVENT, EditEvent::Uploading { id });
        let opts = TransferOptions {
            resume: false,
            preserve_mtime: false,
            cancel: live.cancel.clone(),
            progress: None,
            rate_limit: None,
        };
        match sftp.upload(&local, &remote, &opts).await {
            Ok(bytes) => {
                last = signature(&local).await.or(Some(now));
                let _ = app.emit(
                    EDIT_EVENT,
                    EditEvent::Uploaded {
                        id,
                        bytes,
                        at: Utc::now(),
                    },
                );
            }
            Err(e) => {
                last = Some(now);
                let _ = app.emit(
                    EDIT_EVENT,
                    EditEvent::Failed {
                        id,
                        message: e.to_string(),
                    },
                );
            }
        }
    }
}

/// Push the current local contents right away.
pub fn upload_now(state: &AppState, id: Uuid) -> Result<()> {
    state.edits.get(id)?.force.notify_one();
    Ok(())
}

/// Stop watching and delete the temporary copy.
pub async fn close<R: Runtime>(app: &AppHandle<R>, id: Uuid) -> Result<()> {
    let state = app.state::<AppState>();
    if let Some(live) = state.edits.remove(id) {
        live.cancel.cancel();
        if let Some(dir) = Path::new(&live.info.local).parent()
            && dir.starts_with(edit_root())
        {
            let _ = tokio::fs::remove_dir_all(dir).await;
        }
        let _ = app.emit(EDIT_EVENT, EditEvent::Closed { id });
    }
    Ok(())
}

/// Close every edit session that belongs to an SFTP connection being closed.
pub async fn close_for_sftp<R: Runtime>(app: &AppHandle<R>, sftp_id: Uuid) {
    let ids = app.state::<AppState>().edits.for_sftp(sftp_id);
    for id in ids {
        let _ = close(app, id).await;
    }
}

/// Remove leftovers from earlier runs that ended without closing their edits
/// or drops. Only entries older than a day go, so a second running instance
/// keeps its files.
pub fn sweep_stale() {
    let cutoff = std::time::SystemTime::now() - Duration::from_secs(24 * 3600);
    for root in [edit_root(), std::env::temp_dir().join("termoso-drop")] {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in entries.flatten() {
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .map(|t| t < cutoff)
                .unwrap_or(false);
            if old {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_sanitised() {
        assert_eq!(safe_name("/etc/nginx/nginx.conf"), "nginx.conf");
        assert_eq!(safe_name("weird:name"), "weird_name");
        assert_eq!(safe_name("/"), "file");
        assert_eq!(safe_name(".."), "file");
    }
}
