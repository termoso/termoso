//! Multiplayer: share a terminal tab with teammates, or watch someone else's.
//!
//! The heavy lifting (link secret, key derivation, frame encryption, relay
//! socket) lives in `termoso_core::live`; this module only ties it to the
//! session registry and turns relay events into Tauri events. The share
//! secret never reaches TypeScript except as the opaque link the host copies.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, Runtime};
use termoso_core::live::{HostShare, LiveEvent, LiveLink, ViewerJoin};
use termoso_core::terminal::TermSize;
use termoso_proto::live::LiveParticipant;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::account::api;
use crate::error::{DesktopError, Result};
use crate::sessions::Opened;
use crate::state::AppState;

pub const LIVE_EVENT: &str = "multiplayer";
/// `SessionInfo::protocol` of a tab that watches someone else's terminal.
pub const PROTOCOL: &str = "multiplayer";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveRole {
    Host,
    Viewer,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Participant {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
    pub is_host: bool,
    pub can_write: bool,
    pub is_me: bool,
}

/// What the tab popover shows.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ShareInfo {
    /// Local session (tab) id.
    pub id: Uuid,
    pub live_id: Uuid,
    pub role: LiveRole,
    /// Host only: the `termoso://join/…` link to hand out.
    pub link: Option<String>,
    pub participants: Vec<Participant>,
    /// Viewer: whether our keystrokes reach the host terminal.
    pub can_write: bool,
}

/// Emitted as the `multiplayer` event.
#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum LiveUiEvent {
    Participants {
        id: Uuid,
        participants: Vec<Participant>,
    },
    Control {
        id: Uuid,
        can_write: bool,
    },
    Resize {
        id: Uuid,
        cols: u16,
        rows: u16,
    },
    Title {
        id: Uuid,
        title: String,
    },
    Typing {
        id: Uuid,
        user_id: Uuid,
    },
    Ended {
        id: Uuid,
        reason: String,
        message: String,
    },
}

struct Entry {
    live_id: Uuid,
    role: LiveRole,
    link: Option<String>,
    me: Uuid,
    participants: Vec<LiveParticipant>,
    can_write: bool,
    /// Host side only: dropping it disconnects the relay.
    share: Option<HostShare>,
}

impl Entry {
    fn info(&self, id: Uuid) -> ShareInfo {
        ShareInfo {
            id,
            live_id: self.live_id,
            role: self.role,
            link: self.link.clone(),
            participants: participants(&self.participants, self.me),
            can_write: self.can_write,
        }
    }
}

fn participants(list: &[LiveParticipant], me: Uuid) -> Vec<Participant> {
    let mut v: Vec<Participant> = list
        .iter()
        .map(|p| Participant {
            user_id: p.user_id,
            email: p.email.clone(),
            display_name: p.display_name.clone(),
            avatar: p.avatar.clone(),
            is_host: p.is_host,
            can_write: p.can_write,
            is_me: p.user_id == me,
        })
        .collect();
    v.sort_by_key(|p| (!p.is_host, !p.is_me, p.email.clone()));
    v
}

/// Live shares and views, keyed by local session id.
#[derive(Default)]
pub struct Multiplayer {
    entries: Mutex<HashMap<Uuid, Entry>>,
}

impl Multiplayer {
    pub fn info(&self, id: Uuid) -> Option<ShareInfo> {
        self.entries
            .lock()
            .expect("multiplayer poisoned")
            .get(&id)
            .map(|e| e.info(id))
    }

    /// Forget a session (tab closed / relay ended). A hosted share is stopped
    /// on the server so viewers hear about it right away.
    /// Sessions this device is sharing as host.
    pub fn host_ids(&self) -> Vec<Uuid> {
        self.entries
            .lock()
            .expect("multiplayer poisoned")
            .iter()
            .filter(|(_, e)| e.role == LiveRole::Host)
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn detach(&self, id: Uuid) {
        let entry = self
            .entries
            .lock()
            .expect("multiplayer poisoned")
            .remove(&id);
        if let Some(share) = entry.and_then(|e| e.share) {
            tokio::spawn(share.stop());
        }
    }

    fn take_share(&self, id: Uuid) -> Option<HostShare> {
        self.entries
            .lock()
            .expect("multiplayer poisoned")
            .get_mut(&id)
            .and_then(|e| e.share.take())
    }

    /// The shared terminal was resized by the host.
    pub fn resized(&self, id: Uuid, size: TermSize) {
        if let Some(share) = self
            .entries
            .lock()
            .expect("multiplayer poisoned")
            .get(&id)
            .and_then(|e| e.share.as_ref())
        {
            share.resized(size);
        }
    }

    /// The host typed into a shared terminal.
    pub fn typing(&self, id: Uuid) {
        if let Some(share) = self
            .entries
            .lock()
            .expect("multiplayer poisoned")
            .get(&id)
            .and_then(|e| e.share.as_ref())
        {
            share.typing();
        }
    }
}

/// Start sharing a session. Fails when no account is signed in, when a team
/// disabled multiplayer, or when the tab is a viewer of someone else's share.
pub async fn start<R: Runtime>(app: &AppHandle<R>, id: Uuid) -> Result<ShareInfo> {
    let state = app.state::<AppState>();
    if let Some(existing) = state.multiplayer.info(id) {
        return match existing.role {
            LiveRole::Host => Ok(existing),
            LiveRole::Viewer => Err(DesktopError::invalid(
                "this tab is already a multiplayer view",
            )),
        };
    }
    let api = api(app).await?;
    let info = state.sessions.info(id)?;
    let term = state.sessions.terminal(id)?;
    let size = state.sessions.size(id)?;

    let (tx, rx) = mpsc::channel(64);
    let share = HostShare::start(api, term, size, info.title.clone(), tx).await?;
    let entry = Entry {
        live_id: share.session_id(),
        role: LiveRole::Host,
        link: Some(share.link().to_string()),
        me: share.user_id(),
        participants: Vec::new(),
        can_write: true,
        share: None,
    };
    let publisher = share.publisher();
    let result = entry.info(id);
    {
        let mut entries = state
            .multiplayer
            .entries
            .lock()
            .expect("multiplayer poisoned");
        entries.insert(
            id,
            Entry {
                share: Some(share),
                ..entry
            },
        );
    }
    if let Err(e) = state.sessions.set_tap(id, Some(publisher)) {
        // Tab vanished while we were talking to the server.
        state.multiplayer.detach(id);
        return Err(e);
    }
    tokio::spawn(forward(app.clone(), id, rx));
    Ok(result)
}

/// Stop sharing a session (host). Viewers get `Ended`; the tab keeps running.
/// End every share hosted from this device (viewers see the session close).
pub async fn stop_all<R: Runtime>(app: &AppHandle<R>) {
    let ids = app.state::<AppState>().multiplayer.host_ids();
    for id in ids {
        if let Err(e) = stop(app, id).await {
            tracing::debug!(session = %id, "stop share on lock: {e}");
        }
    }
}

pub async fn stop<R: Runtime>(app: &AppHandle<R>, id: Uuid) -> Result<()> {
    let state = app.state::<AppState>();
    let Some(share) = state.multiplayer.take_share(id) else {
        return Err(DesktopError::not_found("multiplayer session"));
    };
    let _ = state.sessions.set_tap(id, None);
    share.stop().await;
    Ok(())
}

/// Grant or revoke remote control for a viewer (host only).
pub fn set_control<R: Runtime>(
    app: &AppHandle<R>,
    id: Uuid,
    user_id: Uuid,
    enabled: bool,
) -> Result<()> {
    let state = app.state::<AppState>();
    let entries = state
        .multiplayer
        .entries
        .lock()
        .expect("multiplayer poisoned");
    let share = entries
        .get(&id)
        .and_then(|e| e.share.as_ref())
        .ok_or_else(|| DesktopError::not_found("multiplayer session"))?;
    share.set_control(user_id, enabled)?;
    Ok(())
}

/// Open someone else's terminal from a `termoso://join/…` link. Called by the
/// session registry as the `Live` open target; the tab then behaves like any
/// other session (output stream, resize, close).
pub(crate) async fn join<R: Runtime>(app: &AppHandle<R>, id: Uuid, link: &str) -> Result<Opened> {
    let state = app.state::<AppState>();
    let link = LiveLink::parse(link)?;
    let api = api(app).await?;
    if let Some(server) = &link.server {
        let ours = api.server_url();
        if server.host_str() != ours.host_str()
            || server.port_or_known_default() != ours.port_or_known_default()
        {
            return Err(DesktopError::invalid(format!(
                "this link belongs to {server}, but you are signed in to {ours}"
            )));
        }
    }
    let (tx, rx) = mpsc::channel(64);
    let ViewerJoin {
        term,
        events,
        user_id,
        participants,
    } = termoso_core::live::join(api, &link, tx).await?;
    let host = participants
        .iter()
        .find(|p| p.is_host)
        .map(|p| p.display_name.clone().unwrap_or_else(|| p.email.clone()))
        .unwrap_or_else(|| "Multiplayer".to_string());
    state
        .multiplayer
        .entries
        .lock()
        .expect("multiplayer poisoned")
        .insert(
            id,
            Entry {
                live_id: link.session_id,
                role: LiveRole::Viewer,
                link: None,
                me: user_id,
                participants,
                can_write: false,
                share: None,
            },
        );
    tokio::spawn(forward(app.clone(), id, rx));
    Ok(Opened {
        protocol: PROTOCOL,
        title: host.clone(),
        target: format!("Multiplayer · {host}"),
        host_id: None,
        vault_id: None,
        term,
        events,
        client: None,
        jumps: Vec::new(),
        startup: String::new(),
        color_scheme: None,
        shell: None,
        shell_integration: None,
    })
}

/// Turn relay events into Tauri events and keep the registry current.
async fn forward<R: Runtime>(app: AppHandle<R>, id: Uuid, mut rx: mpsc::Receiver<LiveEvent>) {
    let state = app.state::<AppState>();
    while let Some(ev) = rx.recv().await {
        let ui = {
            let mut entries = state
                .multiplayer
                .entries
                .lock()
                .expect("multiplayer poisoned");
            let Some(e) = entries.get_mut(&id) else { break };
            match ev {
                LiveEvent::Participants { participants } => {
                    e.participants = participants;
                    LiveUiEvent::Participants {
                        id,
                        participants: crate::multiplayer::participants(&e.participants, e.me),
                    }
                }
                LiveEvent::Control { can_write } => {
                    e.can_write = can_write;
                    LiveUiEvent::Control { id, can_write }
                }
                LiveEvent::Resize { cols, rows } => LiveUiEvent::Resize { id, cols, rows },
                LiveEvent::Title { title } => LiveUiEvent::Title { id, title },
                LiveEvent::Typing { user_id } => LiveUiEvent::Typing { id, user_id },
                LiveEvent::Ended { reason, message } => {
                    let entry = entries.remove(&id);
                    drop(entries);
                    if entry.map(|e| e.role) == Some(LiveRole::Host) {
                        let _ = state.sessions.set_tap(id, None);
                    }
                    let _ = app.emit(
                        LIVE_EVENT,
                        LiveUiEvent::Ended {
                            id,
                            reason,
                            message,
                        },
                    );
                    break;
                }
            }
        };
        let _ = app.emit(LIVE_EVENT, ui);
    }
}
