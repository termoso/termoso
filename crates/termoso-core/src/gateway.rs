//! Client side of gateways: an SSH transport tunnelled through the server to
//! an API bridge running `termoso-bridge gateway` on the host's network.
//!
//! The host is named by vault id + entity id; the gateway resolves the
//! address from the vault it holds, so the server relays ciphertext between
//! two sockets and never sees where the bytes go.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

use crate::api::ApiClient;
use crate::error::{CoreError, Result};

/// Where to dial through: filled by the apps from the host's `gateway_id`.
#[derive(Clone)]
pub struct GatewayDial {
    /// Signed-in API client (bearer token is read at dial time).
    pub api: Arc<ApiClient>,
    /// The bridge acting as gateway.
    pub gateway_id: Uuid,
    /// Vault holding the host.
    pub vault_id: Uuid,
    /// Host entity.
    pub host_id: Uuid,
}

impl std::fmt::Debug for GatewayDial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayDial")
            .field("gateway_id", &self.gateway_id)
            .field("vault_id", &self.vault_id)
            .field("host_id", &self.host_id)
            .finish()
    }
}

#[derive(Serialize)]
struct AuthMessage<'a> {
    token: &'a str,
    vault_id: Uuid,
    host_id: Uuid,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    Accepted,
    Error { code: String, message: String },
}

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Open the tunnel; returns once the gateway has dialled the host.
pub async fn dial(d: &GatewayDial) -> Result<WsStream> {
    let token = d.api.token().ok_or(CoreError::NotSignedIn)?;
    let url = d.api.gateway_ws_url(d.gateway_id)?;
    let (mut ws, _) = tokio_tungstenite::connect_async(url.as_str())
        .await
        .map_err(|e| CoreError::Ws(e.to_string()))?;
    let auth = serde_json::to_string(&AuthMessage {
        token: &token,
        vault_id: d.vault_id,
        host_id: d.host_id,
    })?;
    ws.send(Message::Text(auth.into()))
        .await
        .map_err(|e| CoreError::Ws(e.to_string()))?;
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(t))) => match serde_json::from_str::<ServerMessage>(&t)? {
                ServerMessage::Accepted => break,
                ServerMessage::Error { code, message } => {
                    return Err(CoreError::Ssh(format!("gateway: {message} ({code})")));
                }
            },
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | None => {
                return Err(CoreError::Ssh("gateway closed the tunnel".into()));
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(CoreError::Ws(e.to_string())),
        }
    }
    Ok(WsStream {
        ws,
        pending: Bytes::new(),
        eof: false,
    })
}

/// A WebSocket carrying a byte stream in binary frames, as `AsyncRead + AsyncWrite`.
pub struct WsStream {
    ws: Ws,
    pending: Bytes,
    eof: bool,
}

impl std::fmt::Debug for WsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WsStream")
    }
}

fn io_err(e: tokio_tungstenite::tungstenite::Error) -> std::io::Error {
    std::io::Error::other(e)
}

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(buf.remaining());
                buf.put_slice(&self.pending[..n]);
                let rest = self.pending.split_off(n);
                self.pending = rest;
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.ws).poll_next(cx)) {
                Some(Ok(Message::Binary(b))) => self.pending = b,
                Some(Ok(Message::Close(_))) | None => self.eof = true,
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Poll::Ready(Err(io_err(e))),
            }
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        ready!(Pin::new(&mut self.ws).poll_ready(cx)).map_err(io_err)?;
        let n = buf.len().min(64 * 1024);
        Pin::new(&mut self.ws)
            .start_send(Message::Binary(Bytes::copy_from_slice(&buf[..n])))
            .map_err(io_err)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.ws).poll_flush(cx).map_err(io_err)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.ws).poll_close(cx).map_err(io_err)
    }
}
