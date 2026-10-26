//! Gateways: reaching hosts that have no route from the client.
//!
//! An API bridge started as `termoso-bridge gateway` keeps one outbound
//! WebSocket to `GET /gateways/ws` (authenticated with its bridge token). A
//! client that wants a host behind it opens `GET /gateways/{id}/connect`,
//! names the host by *vault id + entity id*, and the server pairs the two
//! sockets: `open` goes to the gateway, which resolves the entity from the
//! vault it already holds, dials the address on its own network and answers
//! `accept`; from then on binary frames are relayed verbatim in both
//! directions. The payload is the SSH transport itself, so the relay sees
//! ciphertext — and because hosts are named by id, it never sees the address.
//!
//! Frames cross API replicas over one Redis channel ([`RelayFrame`]), like
//! the multiplayer relay. A gateway counts as online while it has pinged in
//! the last 90 s (`bridges.gateway_seen_at`).

use std::time::Duration;

use axum::Json;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::time::{interval, timeout};
use uuid::Uuid;

use crate::audit;
use crate::error::ApiResult;
use crate::extract::Auth;
use crate::session;
use crate::state::AppState;

const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(20);
const PING_EVERY: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_FRAME: usize = 256 * 1024;
/// A gateway is online while it pinged within this window.
pub const ONLINE_WITHIN_SECS: i64 = 90;

/// Relay frame kinds. `Open`/`ToGateway` travel client → gateway,
/// `Accept`/`ToClient`/`Refuse` gateway → client, `Close` either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Open,
    Accept,
    Refuse,
    ToGateway,
    ToClient,
    Close,
}

impl Kind {
    fn tag(self) -> u8 {
        match self {
            Kind::Open => 0,
            Kind::Accept => 1,
            Kind::Refuse => 2,
            Kind::ToGateway => 3,
            Kind::ToClient => 4,
            Kind::Close => 5,
        }
    }
    fn from_tag(t: u8) -> Option<Self> {
        Some(match t {
            0 => Kind::Open,
            1 => Kind::Accept,
            2 => Kind::Refuse,
            3 => Kind::ToGateway,
            4 => Kind::ToClient,
            5 => Kind::Close,
            _ => return None,
        })
    }
}

/// One relayed frame. On Redis: `conn(16) ‖ gateway(16) ‖ kind(1) ‖ data`.
#[derive(Debug, Clone)]
pub struct RelayFrame {
    pub conn_id: Uuid,
    pub gateway_id: Uuid,
    pub kind: Kind,
    pub data: Bytes,
}

impl RelayFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33 + self.data.len());
        out.extend_from_slice(self.conn_id.as_bytes());
        out.extend_from_slice(self.gateway_id.as_bytes());
        out.push(self.kind.tag());
        out.extend_from_slice(&self.data);
        out
    }
    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < 33 {
            return None;
        }
        Some(Self {
            conn_id: Uuid::from_slice(&raw[..16]).ok()?,
            gateway_id: Uuid::from_slice(&raw[16..32]).ok()?,
            kind: Kind::from_tag(raw[32])?,
            data: Bytes::copy_from_slice(&raw[33..]),
        })
    }
}

async fn publish(state: &AppState, frame: RelayFrame) -> ApiResult<()> {
    state.cache.publish_gateway(frame.encode()).await
}

/// Redis → local broadcast bridge for the gateway channel.
pub async fn run_fanout(state: AppState) {
    loop {
        if let Err(e) = fanout_once(&state).await {
            tracing::warn!(error = %e, "gateway channel subscription lost; reconnecting");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn fanout_once(state: &AppState) -> anyhow::Result<()> {
    let mut pubsub = state.cache.client().get_async_pubsub().await?;
    pubsub.subscribe(state.cache.gateway_channel()).await?;
    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let payload: Vec<u8> = msg.get_payload()?;
        match RelayFrame::decode(&payload) {
            Some(f) => {
                let _ = state.gateway.send(f);
            }
            None => tracing::warn!("malformed frame on gateway channel"),
        }
    }
    anyhow::bail!("gateway pubsub stream ended")
}

// ───────────────────────── wire messages ─────────────────────────

/// First text frame on either socket.
#[derive(Debug, Deserialize)]
pub struct AuthMessage {
    pub token: String,
    /// Client only: the vault holding the host.
    #[serde(default)]
    pub vault_id: Option<Uuid>,
    /// Client only: the host entity.
    #[serde(default)]
    pub host_id: Option<Uuid>,
}

/// Text frames server → gateway.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GatewayServerMessage {
    /// Authenticated; start accepting `open`s.
    Hello {
        gateway_id: Uuid,
    },
    /// A member wants `host_id` in `vault_id`; answer with a binary
    /// `accept`/`refuse` frame for `conn_id`.
    Open {
        conn_id: Uuid,
        vault_id: Uuid,
        host_id: Uuid,
        user_id: Uuid,
    },
    Error {
        code: String,
        message: String,
    },
}

/// Text frames server → client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GatewayClientMessage {
    /// The gateway dialled the host; binary frames flow from here on.
    Accepted,
    Error {
        code: String,
        message: String,
    },
}

/// Binary frames gateway ↔ server: `conn(16) ‖ kind(1) ‖ data`.
fn decode_agent_frame(raw: &[u8]) -> Option<(Uuid, Kind, Bytes)> {
    if raw.len() < 17 {
        return None;
    }
    Some((
        Uuid::from_slice(&raw[..16]).ok()?,
        Kind::from_tag(raw[16])?,
        Bytes::copy_from_slice(&raw[17..]),
    ))
}

fn encode_agent_frame(conn_id: Uuid, kind: Kind, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(17 + data.len());
    out.extend_from_slice(conn_id.as_bytes());
    out.push(kind.tag());
    out.extend_from_slice(data);
    out
}

async fn close_with(socket: &mut WebSocket, code: &str, message: &str) -> anyhow::Result<()> {
    let msg = serde_json::to_string(&GatewayClientMessage::Error {
        code: code.into(),
        message: message.into(),
    })?;
    socket.send(Message::Text(msg.into())).await.ok();
    socket.close().await.ok();
    Ok(())
}

// ───────────────────────── listing ─────────────────────────

pub use termoso_proto::bridge::{GatewayInfo, GatewayList};

/// `GET /gateways` — bridges that share a vault with the caller and have ever
/// run as a gateway, with their online state.
#[utoipa::path(get, path = "/api/v1/gateways", tag = "bridges", responses((status = 200, body = GatewayList)))]
pub async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<GatewayList>> {
    let rows: Vec<(Uuid, String, Option<DateTime<Utc>>, Vec<Uuid>)> = sqlx::query_as(
        "SELECT b.id, b.name, b.gateway_seen_at,
                array_agg(bv.vault_id ORDER BY bv.vault_id)
         FROM bridges b
         JOIN bridge_vaults bv ON bv.bridge_id = b.id
         JOIN vault_members vm ON vm.vault_id = bv.vault_id AND vm.user_id = $1
         WHERE b.gateway_seen_at IS NOT NULL
         GROUP BY b.id ORDER BY b.name",
    )
    .bind(auth.user_id())
    .fetch_all(&state.db)
    .await?;
    let now = Utc::now();
    Ok(Json(GatewayList {
        gateways: rows
            .into_iter()
            .map(|(id, name, seen_at, vault_ids)| GatewayInfo {
                id,
                name,
                online: seen_at.is_some_and(|t| (now - t).num_seconds() <= ONLINE_WITHIN_SECS),
                seen_at,
                vault_ids,
            })
            .collect(),
    }))
}

// ───────────────────────── gateway socket ─────────────────────────

/// `GET /gateways/ws` — the gateway's long-lived socket (bridge token).
#[utoipa::path(get, path = "/api/v1/gateways/ws", tag = "bridges",
    responses((status = 101, description = "WebSocket: first frame `{token}`")))]
pub async fn agent_ws(State(state): State<AppState>, ws: WebSocketUpgrade) -> Response {
    ws.max_message_size(MAX_FRAME)
        .on_upgrade(move |socket| async move {
            if let Err(e) = serve_agent(state, socket).await {
                tracing::debug!(error = %e, "gateway ws closed");
            }
        })
        .into_response()
}

async fn first_auth(socket: &mut WebSocket) -> Option<AuthMessage> {
    match timeout(AUTH_TIMEOUT, socket.recv()).await {
        Ok(Some(Ok(Message::Text(t)))) => serde_json::from_str(&t).ok(),
        _ => None,
    }
}

async fn mark_seen(state: &AppState, gateway_id: Uuid) -> ApiResult<()> {
    sqlx::query("UPDATE bridges SET gateway_seen_at = now() WHERE id = $1")
        .bind(gateway_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

async fn serve_agent(state: AppState, mut socket: WebSocket) -> anyhow::Result<()> {
    let Some(auth) = first_auth(&mut socket).await else {
        return close_with(&mut socket, "auth_required", "First frame must be auth").await;
    };
    let gateway_id = match session::validate(&state, &auth.token).await {
        Ok(i) if !i.disabled && i.bridge_id.is_some() => i.bridge_id.unwrap(),
        _ => return close_with(&mut socket, "unauthorized", "Invalid bridge token").await,
    };
    mark_seen(&state, gateway_id).await?;
    let hello = serde_json::to_string(&GatewayServerMessage::Hello { gateway_id })?;
    socket.send(Message::Text(hello.into())).await?;
    tracing::info!(%gateway_id, "gateway online");

    let mut rx = state.gateway.subscribe();
    let mut ping = interval(PING_EVERY);
    ping.tick().await;
    let mut last_seen = tokio::time::Instant::now();
    loop {
        tokio::select! {
            ev = rx.recv() => {
                let frame = match ev {
                    Ok(f) => f,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "gateway subscriber lagged");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if frame.gateway_id != gateway_id {
                    continue;
                }
                match frame.kind {
                    Kind::Open => {
                        // data = JSON {vault_id, host_id, user_id}
                        let open: serde_json::Value = serde_json::from_slice(&frame.data)?;
                        let msg = GatewayServerMessage::Open {
                            conn_id: frame.conn_id,
                            vault_id: open["vault_id"].as_str().and_then(|s| s.parse().ok()).unwrap_or_default(),
                            host_id: open["host_id"].as_str().and_then(|s| s.parse().ok()).unwrap_or_default(),
                            user_id: open["user_id"].as_str().and_then(|s| s.parse().ok()).unwrap_or_default(),
                        };
                        socket.send(Message::Text(serde_json::to_string(&msg)?.into())).await?;
                    }
                    Kind::ToGateway | Kind::Close => {
                        socket
                            .send(Message::Binary(encode_agent_frame(frame.conn_id, frame.kind, &frame.data).into()))
                            .await?;
                    }
                    _ => {}
                }
            }
            msg = socket.recv() => {
                let Some(msg) = msg else { break };
                last_seen = tokio::time::Instant::now();
                match msg? {
                    Message::Binary(raw) => {
                        let Some((conn_id, kind, data)) = decode_agent_frame(&raw) else { continue };
                        if matches!(kind, Kind::Accept | Kind::Refuse | Kind::ToClient | Kind::Close) {
                            publish(&state, RelayFrame { conn_id, gateway_id, kind, data }).await?;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            _ = ping.tick() => {
                if last_seen.elapsed() > IDLE_TIMEOUT {
                    break;
                }
                mark_seen(&state, gateway_id).await?;
                socket.send(Message::Ping(Bytes::new())).await?;
            }
        }
    }
    tracing::info!(%gateway_id, "gateway offline");
    sqlx::query(
        "UPDATE bridges SET gateway_seen_at = now() - make_interval(secs => $2) WHERE id = $1",
    )
    .bind(gateway_id)
    .bind(ONLINE_WITHIN_SECS as f64 + 1.0)
    .execute(&state.db)
    .await?;
    Ok(())
}

// ───────────────────────── client socket ─────────────────────────

/// `GET /gateways/{id}/connect` — a member's tunnel to one host behind the
/// gateway (first frame `{token, vault_id, host_id}`).
#[utoipa::path(get, path = "/api/v1/gateways/{id}/connect", tag = "bridges",
    params(("id" = Uuid, Path)),
    responses((status = 101, description = "WebSocket: first frame `{token, vault_id, host_id}`")))]
pub async fn client_ws(
    State(state): State<AppState>,
    Path(gateway_id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.max_message_size(MAX_FRAME)
        .on_upgrade(move |socket| async move {
            if let Err(e) = serve_client(state, gateway_id, socket).await {
                tracing::debug!(error = %e, "gateway client ws closed");
            }
        })
        .into_response()
}

async fn serve_client(
    state: AppState,
    gateway_id: Uuid,
    mut socket: WebSocket,
) -> anyhow::Result<()> {
    let Some(auth) = first_auth(&mut socket).await else {
        return close_with(&mut socket, "auth_required", "First frame must be auth").await;
    };
    let (Some(vault_id), Some(host_id)) = (auth.vault_id, auth.host_id) else {
        return close_with(
            &mut socket,
            "bad_request",
            "vault_id and host_id are required",
        )
        .await;
    };
    let info = match session::validate(&state, &auth.token).await {
        Ok(i) if !i.disabled && i.bridge_id.is_none() => i,
        _ => return close_with(&mut socket, "unauthorized", "Invalid session").await,
    };
    // The caller must open the vault, the gateway must hold it, and the team
    // (if any) must allow connecting through bridges.
    let row: Option<(Option<Uuid>, Option<DateTime<Utc>>, String)> = sqlx::query_as(
        "SELECT v.team_id, b.gateway_seen_at, b.name
         FROM bridges b
         JOIN bridge_vaults bv ON bv.bridge_id = b.id AND bv.vault_id = $2
         JOIN vaults v ON v.id = bv.vault_id
         JOIN vault_members vm ON vm.vault_id = v.id AND vm.user_id = $3
         WHERE b.id = $1",
    )
    .bind(gateway_id)
    .bind(vault_id)
    .bind(info.user_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((team_id, seen_at, name)) = row else {
        return close_with(&mut socket, "forbidden", "No such gateway for this vault").await;
    };
    if let Some(team_id) = team_id
        && let Err(e) = crate::authz::require(&state, team_id, info.user_id, "connect.bridge").await
    {
        return close_with(&mut socket, "forbidden", &e.to_string()).await;
    }
    if !seen_at.is_some_and(|t| (Utc::now() - t).num_seconds() <= ONLINE_WITHIN_SECS) {
        return close_with(
            &mut socket,
            "gateway_offline",
            &format!("Gateway “{name}” is offline"),
        )
        .await;
    }

    let conn_id = Uuid::new_v4();
    let mut rx = state.gateway.subscribe();
    publish(
        &state,
        RelayFrame {
            conn_id,
            gateway_id,
            kind: Kind::Open,
            data: serde_json::to_vec(&serde_json::json!({
                "vault_id": vault_id, "host_id": host_id, "user_id": info.user_id,
            }))?
            .into(),
        },
    )
    .await?;
    // Wait for the gateway's verdict.
    let accepted = timeout(ACCEPT_TIMEOUT, async {
        loop {
            match rx.recv().await {
                Ok(f) if f.conn_id == conn_id && f.kind == Kind::Accept => return Ok(()),
                Ok(f) if f.conn_id == conn_id && matches!(f.kind, Kind::Refuse | Kind::Close) => {
                    return Err(String::from_utf8_lossy(&f.data).into_owned());
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return Err("relay closed".into()),
            }
        }
    })
    .await;
    match accepted {
        Ok(Ok(())) => {}
        Ok(Err(why)) => return close_with(&mut socket, "refused", &why).await,
        Err(_) => {
            publish(
                &state,
                RelayFrame {
                    conn_id,
                    gateway_id,
                    kind: Kind::Close,
                    data: Bytes::new(),
                },
            )
            .await
            .ok();
            return close_with(&mut socket, "gateway_timeout", "The gateway did not answer").await;
        }
    }
    socket
        .send(Message::Text(
            serde_json::to_string(&GatewayClientMessage::Accepted)?.into(),
        ))
        .await?;
    if let Some(team_id) = team_id {
        audit::record(
            &state.db,
            audit::Entry::by(
                team_id,
                info.user_id,
                Some(info.device_id),
                "gateway.connected",
            )
            .vault(vault_id)
            .details(serde_json::json!({ "gateway_id": gateway_id, "host_id": host_id })),
        )
        .await;
    }
    metrics::counter!("termoso_gateway_connections_total").increment(1);

    let mut ping = interval(PING_EVERY);
    ping.tick().await;
    let mut last_seen = tokio::time::Instant::now();
    let result: anyhow::Result<()> = async {
        loop {
            tokio::select! {
                ev = rx.recv() => {
                    let frame = match ev {
                        Ok(f) => f,
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(lagged = n, "gateway client lagged; closing");
                            anyhow::bail!("lagged");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    };
                    if frame.conn_id != conn_id {
                        continue;
                    }
                    match frame.kind {
                        Kind::ToClient => socket.send(Message::Binary(frame.data)).await?,
                        Kind::Close => break,
                        _ => {}
                    }
                }
                msg = socket.recv() => {
                    let Some(msg) = msg else { break };
                    last_seen = tokio::time::Instant::now();
                    match msg? {
                        Message::Binary(data) => {
                            publish(&state, RelayFrame { conn_id, gateway_id, kind: Kind::ToGateway, data }).await?;
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
                _ = ping.tick() => {
                    if last_seen.elapsed() > IDLE_TIMEOUT {
                        break;
                    }
                    socket.send(Message::Ping(Bytes::new())).await?;
                }
            }
        }
        Ok(())
    }
    .await;
    publish(
        &state,
        RelayFrame {
            conn_id,
            gateway_id,
            kind: Kind::Close,
            data: Bytes::new(),
        },
    )
    .await
    .ok();
    socket.close().await.ok();
    result
}
