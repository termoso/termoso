//! Telnet (RFC 854) terminal with the handful of options a modern terminal
//! needs: NAWS window size, terminal type, suppress-go-ahead, binary.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::error::{CoreError, Result};
use crate::ssh::IpVersion;
use crate::terminal::{TermEvent, TermEvents, TermSize, TerminalSession, event_channel};

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

const OPT_BINARY: u8 = 0;
const OPT_ECHO: u8 = 1;
const OPT_SGA: u8 = 3;
const OPT_TTYPE: u8 = 24;
const OPT_NAWS: u8 = 31;

/// Connection parameters.
#[derive(Debug, Clone)]
pub struct TelnetOptions {
    /// Host.
    pub host: String,
    /// Port (23).
    pub port: u16,
    /// `TERM` to announce.
    pub term: String,
    /// Initial size.
    pub size: TermSize,
    /// Connect timeout.
    pub timeout: Duration,
    /// Address family to use when the host resolves to both.
    pub ip_version: IpVersion,
    /// Optional SOCKS/HTTP proxy for the TCP leg.
    pub proxy: Option<crate::ssh::proxy::ProxyConfig>,
}

/// A live telnet connection.
pub struct TelnetTerminal {
    writer: Mutex<tokio::net::tcp::OwnedWriteHalf>,
    size: std::sync::Mutex<TermSize>,
    naws: AtomicBool,
    closed: AtomicBool,
}

impl std::fmt::Debug for TelnetTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelnetTerminal").finish()
    }
}

/// Escape `IAC` bytes in user data.
fn escape(data: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(data.len() + 8);
    for &b in data {
        out.extend_from_slice(if b == IAC {
            &[IAC, IAC]
        } else {
            std::slice::from_ref(&b)
        });
    }
    out.freeze()
}

fn naws_packet(size: TermSize) -> Vec<u8> {
    let mut p = vec![IAC, SB, OPT_NAWS];
    for v in [size.cols, size.rows] {
        for b in v.to_be_bytes() {
            if b == IAC {
                p.push(IAC);
            }
            p.push(b);
        }
    }
    p.extend_from_slice(&[IAC, SE]);
    p
}

/// Incremental telnet option-negotiation parser.
struct Parser {
    state: State,
    sub: Vec<u8>,
}

enum State {
    Data,
    Iac,
    Opt(u8),
    Sub,
    SubIac,
}

impl Parser {
    fn new() -> Self {
        Self {
            state: State::Data,
            sub: Vec::new(),
        }
    }

    /// Returns `(screen bytes, replies to send)`.
    fn feed(
        &mut self,
        input: &[u8],
        term: &str,
        size: TermSize,
        naws: &AtomicBool,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut out = Vec::with_capacity(input.len());
        let mut reply = Vec::new();
        for &b in input {
            match self.state {
                State::Data => {
                    if b == IAC {
                        self.state = State::Iac;
                    } else {
                        out.push(b);
                    }
                }
                State::Iac => match b {
                    IAC => {
                        out.push(IAC);
                        self.state = State::Data;
                    }
                    DO | DONT | WILL | WONT => self.state = State::Opt(b),
                    SB => {
                        self.sub.clear();
                        self.state = State::Sub;
                    }
                    _ => self.state = State::Data, // NOP, GA, etc.
                },
                State::Opt(cmd) => {
                    self.state = State::Data;
                    match (cmd, b) {
                        (DO, OPT_NAWS) => {
                            reply.extend_from_slice(&[IAC, WILL, OPT_NAWS]);
                            naws.store(true, Ordering::SeqCst);
                            reply.extend_from_slice(&naws_packet(size));
                        }
                        (DO, OPT_TTYPE) | (DO, OPT_SGA) | (DO, OPT_BINARY) => {
                            reply.extend_from_slice(&[IAC, WILL, b]);
                        }
                        (DO, _) => reply.extend_from_slice(&[IAC, WONT, b]),
                        (WILL, OPT_ECHO) | (WILL, OPT_SGA) | (WILL, OPT_BINARY) => {
                            reply.extend_from_slice(&[IAC, DO, b]);
                        }
                        (WILL, _) => reply.extend_from_slice(&[IAC, DONT, b]),
                        (DONT, OPT_NAWS) => naws.store(false, Ordering::SeqCst),
                        _ => {}
                    }
                }
                State::Sub => {
                    if b == IAC {
                        self.state = State::SubIac;
                    } else {
                        self.sub.push(b);
                    }
                }
                State::SubIac => match b {
                    IAC => {
                        self.sub.push(IAC);
                        self.state = State::Sub;
                    }
                    SE => {
                        self.state = State::Data;
                        // TERMINAL-TYPE SEND
                        if self.sub.first() == Some(&OPT_TTYPE) && self.sub.get(1) == Some(&1) {
                            reply.extend_from_slice(&[IAC, SB, OPT_TTYPE, 0]);
                            reply.extend_from_slice(term.to_ascii_uppercase().as_bytes());
                            reply.extend_from_slice(&[IAC, SE]);
                        }
                    }
                    _ => self.state = State::Data,
                },
            }
        }
        (out, reply)
    }
}

impl TelnetTerminal {
    /// Connect.
    pub async fn connect(opts: TelnetOptions) -> Result<(Arc<TelnetTerminal>, TermEvents)> {
        let stream = tokio::time::timeout(opts.timeout, async {
            if let Some(p) = &opts.proxy {
                let crate::ssh::proxy::ProxyStream::Tcp(s) =
                    crate::ssh::proxy::connect(p, &opts.host, opts.port).await?
                else {
                    unreachable!("proxy::connect never returns a gateway stream")
                };
                return Ok(s);
            }
            let addrs = opts.ip_version.filter(
                tokio::net::lookup_host((opts.host.as_str(), opts.port))
                    .await?
                    .collect(),
            );
            if addrs.is_empty() {
                return Err(CoreError::Terminal(format!(
                    "telnet: {} did not resolve to any {} address",
                    opts.host,
                    opts.ip_version.label()
                )));
            }
            let mut last: Option<std::io::Error> = None;
            for addr in &addrs {
                match TcpStream::connect(addr).await {
                    Ok(s) => return Ok(s),
                    Err(e) => last = Some(e),
                }
            }
            Err(last
                .map(CoreError::from)
                .unwrap_or_else(|| CoreError::Terminal("telnet: no address to connect to".into())))
        })
        .await
        .map_err(|_| {
            CoreError::Terminal(format!("telnet: timed out connecting to {}", opts.host))
        })??;
        let _ = stream.set_nodelay(true);
        let (mut rd, wr) = stream.into_split();
        let term = Arc::new(TelnetTerminal {
            writer: Mutex::new(wr),
            size: std::sync::Mutex::new(opts.size),
            naws: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        });
        let (tx, rx) = event_channel();
        let t2 = term.clone();
        let term_name = opts.term.clone();
        tokio::spawn(async move {
            let mut parser = Parser::new();
            let mut buf = [0u8; 16 * 1024];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let size = *t2.size.lock().unwrap_or_else(|p| p.into_inner());
                        let (data, reply) = parser.feed(&buf[..n], &term_name, size, &t2.naws);
                        if !reply.is_empty() {
                            let mut w = t2.writer.lock().await;
                            if w.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                        if !data.is_empty()
                            && tx.send(TermEvent::Output(Bytes::from(data))).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(TermEvent::Error(e.to_string())).await;
                        break;
                    }
                }
            }
            t2.closed.store(true, Ordering::SeqCst);
            let _ = tx.send(TermEvent::Closed).await;
        });
        Ok((term, rx))
    }
}

#[async_trait]
impl TerminalSession for TelnetTerminal {
    async fn write(&self, data: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(CoreError::Closed);
        }
        self.writer.lock().await.write_all(&escape(data)).await?;
        Ok(())
    }

    async fn resize(&self, size: TermSize) -> Result<()> {
        *self.size.lock().unwrap_or_else(|p| p.into_inner()) = size;
        if self.naws.load(Ordering::SeqCst) && !self.closed.load(Ordering::SeqCst) {
            self.writer
                .lock()
                .await
                .write_all(&naws_packet(size))
                .await?;
        }
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let _ = self.writer.lock().await.shutdown().await;
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "telnet"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiates_and_strips_commands() {
        let mut p = Parser::new();
        let naws = AtomicBool::new(false);
        let size = TermSize {
            cols: 100,
            rows: 30,
        };
        let input = [
            b'h', IAC, DO, OPT_NAWS, b'i', IAC, IAC, IAC, WILL, OPT_ECHO, IAC, SB, OPT_TTYPE, 1,
            IAC, SE, IAC, DO, 99,
        ];
        let (data, reply) = p.feed(&input, "xterm-256color", size, &naws);
        assert_eq!(data, vec![b'h', b'i', IAC]);
        assert!(naws.load(Ordering::SeqCst));
        let mut expected = vec![IAC, WILL, OPT_NAWS];
        expected.extend_from_slice(&naws_packet(size));
        expected.extend_from_slice(&[IAC, DO, OPT_ECHO]);
        expected.extend_from_slice(&[IAC, SB, OPT_TTYPE, 0]);
        expected.extend_from_slice(b"XTERM-256COLOR");
        expected.extend_from_slice(&[IAC, SE, IAC, WONT, 99]);
        assert_eq!(reply, expected);
    }

    #[test]
    fn naws_escapes_iac_in_size() {
        let p = naws_packet(TermSize {
            cols: 255,
            rows: 24,
        });
        assert_eq!(p, vec![IAC, SB, OPT_NAWS, 0, IAC, IAC, 0, 24, IAC, SE]);
    }

    #[test]
    fn escapes_user_iac() {
        assert_eq!(escape(&[1, IAC, 2]).as_ref(), &[1, IAC, IAC, 2]);
    }

    fn opts(host: &str, port: u16, ip_version: IpVersion) -> TelnetOptions {
        TelnetOptions {
            host: host.into(),
            port,
            term: "xterm".into(),
            size: TermSize { cols: 80, rows: 24 },
            timeout: Duration::from_secs(5),
            ip_version,
            proxy: None,
        }
    }

    #[tokio::test]
    async fn ip_version_selects_address_family() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });

        let err = TelnetTerminal::connect(opts("127.0.0.1", port, IpVersion::V6))
            .await
            .expect_err("an IPv4 literal has no IPv6 address");
        assert!(
            err.to_string().contains("IPv6"),
            "error should name the requested family: {err}"
        );

        let (term, _events) = TelnetTerminal::connect(opts("127.0.0.1", port, IpVersion::V4))
            .await
            .expect("IPv4 connects to the IPv4 listener");
        accept.await.unwrap().unwrap();
        term.close().await.unwrap();
    }
}
