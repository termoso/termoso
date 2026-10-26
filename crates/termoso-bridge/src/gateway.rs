//! Gateway mode: the bridge keeps one outbound WebSocket to the server and,
//! when a member asks for a host of a vault it mirrors, resolves the address
//! from that vault, dials it on the local network and pipes bytes through the
//! relay. Hosts travel as vault + entity ids, so the server never sees an
//! address; the payload is the SSH transport, so it never sees plaintext.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::Bridge;
use crate::error::{BridgeError, Result};

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const CHUNK: usize = 32 * 1024;

const ACCEPT: u8 = 1;
const REFUSE: u8 = 2;
const TO_GATEWAY: u8 = 3;
const TO_CLIENT: u8 = 4;
const CLOSE: u8 = 5;

/// What the gateway may dial: hostnames, IPs and CIDRs; empty = anything.
#[derive(Debug, Clone, Default)]
pub struct Allow {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
enum Rule {
    Name(String),
    Net(IpAddr, u8),
}

impl Allow {
    pub fn parse(spec: &str) -> Result<Self> {
        let mut rules = Vec::new();
        for raw in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Some((ip, bits)) = raw.split_once('/') {
                let ip: IpAddr = ip.parse().map_err(|_| {
                    BridgeError::Invalid(format!("TERMOSO_GATEWAY_ALLOW: bad CIDR {raw}"))
                })?;
                let max = if ip.is_ipv4() { 32 } else { 128 };
                let bits: u8 = bits.parse().ok().filter(|b| *b <= max).ok_or_else(|| {
                    BridgeError::Invalid(format!("TERMOSO_GATEWAY_ALLOW: bad CIDR {raw}"))
                })?;
                rules.push(Rule::Net(ip, bits));
            } else if let Ok(ip) = raw.parse::<IpAddr>() {
                let bits = if ip.is_ipv4() { 32 } else { 128 };
                rules.push(Rule::Net(ip, bits));
            } else {
                rules.push(Rule::Name(raw.to_ascii_lowercase()));
            }
        }
        Ok(Self { rules })
    }

    /// `host` as written in the vault (name or literal IP).
    pub fn permits(&self, host: &str) -> bool {
        if self.rules.is_empty() {
            return true;
        }
        let host = host.trim().trim_matches(['[', ']']);
        let ip: Option<IpAddr> = host.parse().ok();
        self.rules.iter().any(|r| match r {
            Rule::Name(n) => host.eq_ignore_ascii_case(n),
            Rule::Net(net, bits) => ip.is_some_and(|ip| in_net(ip, *net, *bits)),
        })
    }
}

fn in_net(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            (u128::from(a) & mask) == (u128::from(n) & mask)
        }
        _ => false,
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    Hello {
        gateway_id: Uuid,
    },
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

fn frame(conn_id: Uuid, kind: u8, data: &[u8]) -> Message {
    let mut out = Vec::with_capacity(17 + data.len());
    out.extend_from_slice(conn_id.as_bytes());
    out.push(kind);
    out.extend_from_slice(data);
    Message::Binary(out.into())
}

/// Run forever, reconnecting with backoff.
pub async fn run(bridge: Arc<Bridge>, allow: Allow) {
    let mut backoff = 1u64;
    loop {
        match session(&bridge, &allow).await {
            Ok(()) => backoff = 1,
            Err(e) => {
                tracing::warn!(error = %e, "gateway tunnel lost; reconnecting in {backoff}s");
            }
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

async fn session(bridge: &Arc<Bridge>, allow: &Allow) -> Result<()> {
    let mut url = bridge.server().server_url().clone();
    let scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        other => return Err(BridgeError::Invalid(format!("unsupported scheme {other}"))),
    };
    url.set_scheme(scheme)
        .map_err(|_| BridgeError::Invalid("bad server URL".into()))?;
    let url = url
        .join("api/v1/gateways/ws")
        .map_err(|e| BridgeError::Invalid(e.to_string()))?;
    let (ws, _) = tokio_tungstenite::connect_async(url.as_str())
        .await
        .map_err(|e| BridgeError::Transport(format!("gateway ws: {e}")))?;
    let (mut sink, mut stream) = ws.split();
    sink.send(Message::Text(
        serde_json::json!({ "token": bridge.server().token() })
            .to_string()
            .into(),
    ))
    .await
    .map_err(|e| BridgeError::Transport(e.to_string()))?;

    let (tx, mut rx) = mpsc::channel::<Message>(1024);
    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if sink.send(m).await.is_err() {
                break;
            }
        }
    });
    let conns: Arc<Mutex<HashMap<Uuid, mpsc::Sender<Option<Bytes>>>>> = Default::default();

    let result: Result<()> = async {
        while let Some(msg) = stream.next().await {
            match msg.map_err(|e| BridgeError::Transport(e.to_string()))? {
                Message::Text(t) => match serde_json::from_str::<ServerMessage>(&t) {
                    Ok(ServerMessage::Hello { gateway_id }) => {
                        tracing::info!(%gateway_id, "gateway online");
                    }
                    Ok(ServerMessage::Open {
                        conn_id,
                        vault_id,
                        host_id,
                        user_id,
                    }) => {
                        let (ctx, crx) = mpsc::channel::<Option<Bytes>>(256);
                        conns.lock().await.insert(conn_id, ctx);
                        let (bridge, allow, tx, conns) =
                            (bridge.clone(), allow.clone(), tx.clone(), conns.clone());
                        tokio::spawn(async move {
                            if let Err(e) =
                                serve_conn(&bridge, &allow, &tx, conn_id, vault_id, host_id, crx).await
                            {
                                tracing::debug!(%conn_id, %user_id, error = %e, "gateway connection ended");
                            }
                            conns.lock().await.remove(&conn_id);
                        });
                    }
                    Ok(ServerMessage::Error { code, message }) => {
                        return Err(BridgeError::Transport(format!("{message} ({code})")));
                    }
                    Err(e) => tracing::debug!(error = %e, "unknown gateway message"),
                },
                Message::Binary(raw) => {
                    if raw.len() < 17 {
                        continue;
                    }
                    let Ok(conn_id) = Uuid::from_slice(&raw[..16]) else { continue };
                    let kind = raw[16];
                    let guard = conns.lock().await;
                    if let Some(c) = guard.get(&conn_id) {
                        let item = match kind {
                            TO_GATEWAY => Some(raw.slice(17..)),
                            CLOSE => None,
                            _ => continue,
                        };
                        let _ = c.send(item).await;
                    }
                }
                Message::Ping(p) => {
                    let _ = tx.send(Message::Pong(p)).await;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        Ok(())
    }
    .await;
    drop(tx);
    writer.abort();
    result
}

async fn serve_conn(
    bridge: &Bridge,
    allow: &Allow,
    tx: &mpsc::Sender<Message>,
    conn_id: Uuid,
    vault_id: Uuid,
    host_id: Uuid,
    mut rx: mpsc::Receiver<Option<Bytes>>,
) -> Result<()> {
    let refuse = |why: String| frame(conn_id, REFUSE, why.as_bytes());
    let (host, port) = match bridge.gateway_target(vault_id, host_id).await {
        Ok(t) => t,
        Err(e) => {
            let _ = tx.send(refuse(format!("unknown host: {e}"))).await;
            return Err(e);
        }
    };
    if !allow.permits(&host) {
        let _ = tx
            .send(refuse(
                "the gateway is not allowed to dial this host".into(),
            ))
            .await;
        return Err(BridgeError::Invalid(format!(
            "{host} not in TERMOSO_GATEWAY_ALLOW"
        )));
    }
    let tcp =
        match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect((host.as_str(), port))).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let _ = tx.send(refuse(format!("{host}:{port}: {e}"))).await;
                return Err(BridgeError::Transport(e.to_string()));
            }
            Err(_) => {
                let _ = tx
                    .send(refuse(format!("{host}:{port}: connect timed out")))
                    .await;
                return Err(BridgeError::Transport("dial timeout".into()));
            }
        };
    let _ = tcp.set_nodelay(true);
    tx.send(frame(conn_id, ACCEPT, b""))
        .await
        .map_err(|_| BridgeError::Transport("tunnel writer gone".into()))?;
    tracing::info!(%conn_id, host = %host, port, "gateway connection open");
    let (mut rd, mut wr) = tcp.into_split();
    let mut buf = vec![0u8; CHUNK];
    loop {
        tokio::select! {
            n = rd.read(&mut buf) => {
                match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(frame(conn_id, TO_CLIENT, &buf[..n])).await.is_err() {
                            break;
                        }
                    }
                }
            }
            item = rx.recv() => {
                match item {
                    Some(Some(data)) => {
                        if wr.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(None) | None => break,
                }
            }
        }
    }
    let _ = wr.shutdown().await;
    let _ = tx.send(frame(conn_id, CLOSE, b"")).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_rules() {
        let a = Allow::parse("10.0.0.0/8, db.internal, 2001:db8::/32, 192.168.1.5").unwrap();
        assert!(a.permits("10.20.30.40"));
        assert!(!a.permits("11.0.0.1"));
        assert!(a.permits("DB.internal"));
        assert!(!a.permits("web.internal"));
        assert!(a.permits("[2001:db8::1]"));
        assert!(a.permits("192.168.1.5"));
        assert!(!a.permits("192.168.1.6"));
        assert!(Allow::parse("").unwrap().permits("anything"));
        assert!(Allow::parse("10.0.0.0/33").is_err());
    }
}
