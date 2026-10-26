//! SSH transport built on `russh`.
//!
//! [`SshClient::connect`] does host-key verification through
//! [`crate::hostkey`], tries the configured [`AuthMethod`]s in order and returns
//! a connected, authenticated client. From there you open interactive shells
//! ([`SshClient::shell`]), run commands ([`SshClient::exec`]), open SFTP
//! ([`crate::sftp::Sftp::open`]) or tunnel TCP ([`SshClient::direct_tcpip`]).
//! Jump hosts are plain recursion: connect to the jump, then
//! [`SshClient::connect_via`] through it.

mod auth;
mod handler;
mod peek;
pub mod proxy;
mod shell;
pub mod totp;
pub mod x11;

use std::borrow::Cow;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use russh::Channel;
use russh::client::{Config, Handle, Msg};
use russh::{ChannelMsg, Preferred};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};

use crate::error::{CoreError, Result};
use crate::hostkey::{HostKeyPrompt, KnownHosts};
use crate::terminal::{TermEvents, TermSize};

pub use auth::{
    AuthMethod, InteractivePrompt, InteractiveQuestion, PasswordResponder, load_private_key,
};
pub use handler::{Algorithms, ClientHandler, ForwardedChannel};
pub use shell::SshTerminal;
pub use x11::{LocalDisplay, X11Forward};

/// Where to connect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshTarget {
    /// Hostname or IP.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Login name; empty until the user supplies one (connecting with an
    /// empty name is refused rather than defaulting to some account).
    pub username: String,
}

impl SshTarget {
    /// `user@host:port` (`host:port` while the user is unknown).
    pub fn display(&self) -> String {
        if self.username.is_empty() {
            format!("{}:{}", self.host, self.port)
        } else {
            format!("{}@{}:{}", self.username, self.host, self.port)
        }
    }
}

/// Where a connection attempt currently is. Reported through
/// [`ConnectProgress`] so a UI can show the stage instead of a bare spinner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConnectPhase {
    /// Looking the host name up in DNS.
    Resolving,
    /// Opening the TCP connection (directly, through a proxy, or over a jump).
    Connecting {
        /// Resolved address, proxy or jump host the socket goes to.
        via: String,
    },
    /// Exchanging protocol versions and keys.
    Handshake,
    /// Checking the server's host key against the trust database.
    HostKey,
    /// Trying an authentication method (`publickey`, `password`, …).
    Auth {
        /// SSH method name being attempted.
        method: String,
    },
    /// A FIDO2 security key is about to sign: the user must touch it (and
    /// may be asked for the PIN by the token).
    SecurityKeyTouch {
        /// Fingerprint of the key being used.
        key: String,
    },
    /// Transport is up and authenticated; the caller is opening channels.
    Authenticated,
    /// Starting `mosh-server` on the remote before handing over to
    /// `mosh-client`.
    MoshServer,
}

/// Receives [`ConnectPhase`] updates while [`SshClient::connect`] runs.
pub trait ConnectProgress: Send + Sync {
    /// Called from the connecting task; must not block.
    fn phase(&self, phase: ConnectPhase);
}

/// Everything needed to establish a session.
pub struct ConnectOptions {
    /// Destination.
    pub target: SshTarget,
    /// Authentication methods, tried in order.
    pub auth: Vec<AuthMethod>,
    /// Trust database.
    pub known_hosts: KnownHosts,
    /// Who to ask about unknown keys.
    pub host_key_prompt: Arc<dyn HostKeyPrompt>,
    /// Who answers keyboard-interactive prompts (falls back to the password
    /// method when `None`).
    pub interactive: Option<Arc<dyn InteractivePrompt>>,
    /// Keepalive interval (`None` = off).
    pub keepalive: Option<Duration>,
    /// TCP connect / handshake timeout.
    pub timeout: Duration,
    /// Optional proxy for the TCP leg.
    pub proxy: Option<proxy::ProxyConfig>,
    /// Tunnel through a gateway instead of dialling (takes precedence over `proxy`).
    pub gateway: Option<crate::gateway::GatewayDial>,
    /// Environment to request on every shell (`SetEnv`).
    pub env: Vec<(String, String)>,
    /// Request agent forwarding on shells.
    pub agent_forwarding: bool,
    /// Forward X11 from shells and commands to this local display (see
    /// [`x11`]); `None` = off.
    pub x11: Option<Arc<X11Forward>>,
    /// SSH agent to talk to for [`AuthMethod::Agent`] / [`AuthMethod::AgentKey`]
    /// and forwarding: a socket (named pipe on Windows) path, or `None` for
    /// the platform default (`SSH_AUTH_SOCK`, OpenSSH agent pipe, Pageant).
    pub agent_socket: Option<std::path::PathBuf>,
    /// Offer the hybrid post-quantum key exchange (`mlkem768x25519-sha256`)
    /// first. Servers without it fall back to classical algorithms either
    /// way; turning this off only matters for the rare peer whose KEXINIT
    /// parser chokes on the larger payload.
    pub post_quantum_kex: bool,
    /// Stage reporter (`None` = nobody is watching).
    pub progress: Option<Arc<dyn ConnectProgress>>,
    /// Address family to dial when the host name resolves to both.
    pub ip_version: IpVersion,
}

/// Which resolved addresses to try for the direct TCP leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpVersion {
    /// Resolver order (usually IPv6 first when the network has it).
    #[default]
    Auto,
    /// IPv4 only.
    V4,
    /// IPv6 only.
    V6,
}

impl IpVersion {
    /// Parse the stored host setting (`""`/`auto`, `4`/`ipv4`, `6`/`ipv6`).
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "4" | "v4" | "ipv4" => Self::V4,
            "6" | "v6" | "ipv6" => Self::V6,
            _ => Self::Auto,
        }
    }

    /// Keep the addresses this preference allows, in resolver order.
    pub fn filter(self, addrs: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
        match self {
            Self::Auto => addrs,
            Self::V4 => addrs.into_iter().filter(|a| a.is_ipv4()).collect(),
            Self::V6 => addrs.into_iter().filter(|a| a.is_ipv6()).collect(),
        }
    }

    /// Human name for error messages (`any`, `IPv4`, `IPv6`).
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "any",
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }
}

impl ConnectOptions {
    pub(super) fn report(&self, phase: ConnectPhase) {
        if let Some(p) = &self.progress {
            p.phase(phase);
        }
    }

    /// Sensible defaults for `target`.
    pub fn new(
        target: SshTarget,
        known_hosts: KnownHosts,
        host_key_prompt: Arc<dyn HostKeyPrompt>,
    ) -> Self {
        Self {
            target,
            auth: Vec::new(),
            known_hosts,
            host_key_prompt,
            interactive: None,
            keepalive: Some(Duration::from_secs(30)),
            timeout: Duration::from_secs(20),
            proxy: None,
            gateway: None,
            env: Vec::new(),
            agent_forwarding: false,
            x11: None,
            agent_socket: None,
            post_quantum_kex: true,
            progress: None,
            ip_version: IpVersion::Auto,
        }
    }
}

/// Output of [`SshClient::exec`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecOutput {
    /// stdout.
    pub stdout: Vec<u8>,
    /// stderr.
    pub stderr: Vec<u8>,
    /// Exit status if the server reported one.
    pub exit_code: Option<u32>,
}

impl ExecOutput {
    /// stdout as lossy UTF-8.
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

/// A connected and authenticated SSH session.
pub struct SshClient {
    handle: Handle<ClientHandler>,
    target: SshTarget,
    banner: Option<String>,
    server_id: Option<String>,
    algorithms: Option<Algorithms>,
    closed: watch::Receiver<Option<String>>,
    forwarded: handler::ForwardRoutes,
    env: Vec<(String, String)>,
    agent_forwarding: bool,
    x11: Option<Arc<X11Forward>>,
}

impl std::fmt::Debug for SshClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshClient")
            .field("target", &self.target)
            .finish()
    }
}

fn config(opts: &ConnectOptions) -> Arc<Config> {
    let mut preferred = Preferred::default();
    if !opts.post_quantum_kex {
        preferred.kex = Cow::Owned(
            preferred
                .kex
                .iter()
                .filter(|k| **k != russh::kex::MLKEM768X25519_SHA256)
                .cloned()
                .collect(),
        );
    }
    Arc::new(Config {
        client_id: russh::SshId::Standard(
            format!("SSH-2.0-termoso_{}", crate::CLIENT_VERSION).into(),
        ),
        inactivity_timeout: None,
        keepalive_interval: opts.keepalive,
        keepalive_max: 3,
        preferred,
        nodelay: true,
        // Per-channel receive window: bounds server→client bytes in flight
        // (throughput ≈ window / RTT), so keep it large for SFTP downloads.
        window_size: 8 * 1024 * 1024,
        ..Config::default()
    })
}

/// Like `tokio::time::timeout`, except the clock stops while `prompting` is
/// `true` — the user deciding about a host key must not count against the
/// network budget.
async fn timeout_unless_prompting<F: Future>(
    budget: Duration,
    mut prompting: watch::Receiver<bool>,
    fut: F,
) -> Option<F::Output> {
    let mut fut = pin!(fut);
    let mut remaining = budget;
    let mut prompt_alive = true;
    loop {
        let started = Instant::now();
        if !prompt_alive {
            return tokio::time::timeout(remaining, fut).await.ok();
        }
        tokio::select! {
            out = &mut fut => return Some(out),
            _ = tokio::time::sleep(remaining) => return None,
            started_prompt = async { prompting.wait_for(|p| *p).await.is_ok() } => {
                remaining = remaining.saturating_sub(started.elapsed());
                if !started_prompt {
                    prompt_alive = false;
                    continue;
                }
                tokio::select! {
                    out = &mut fut => return Some(out),
                    ended = async { prompting.wait_for(|p| !*p).await.is_ok() } => {
                        prompt_alive = ended;
                    }
                }
            }
        }
    }
}

impl SshClient {
    /// Connect over TCP (optionally through a proxy).
    pub async fn connect(opts: ConnectOptions) -> Result<Self> {
        if opts.target.username.trim().is_empty() {
            return Err(CoreError::Invalid(format!(
                "no username for {}: set one on the host's identity",
                opts.target.host
            )));
        }
        let stream = tokio::time::timeout(opts.timeout, async {
            if let Some(g) = &opts.gateway {
                opts.report(ConnectPhase::Connecting {
                    via: format!("gateway {}", g.gateway_id),
                });
                return crate::gateway::dial(g)
                    .await
                    .map(|s| proxy::ProxyStream::Ws(Box::new(s)));
            }
            match &opts.proxy {
                Some(p) => {
                    opts.report(ConnectPhase::Connecting {
                        via: format!("{} proxy {}:{}", p.kind.label(), p.host, p.port),
                    });
                    proxy::connect(p, &opts.target.host, opts.target.port).await
                }
                None => {
                    opts.report(ConnectPhase::Resolving);
                    let addrs = opts.ip_version.filter(
                        tokio::net::lookup_host((opts.target.host.as_str(), opts.target.port))
                            .await?
                            .collect(),
                    );
                    let Some(first) = addrs.first() else {
                        return Err(CoreError::Ssh(format!(
                            "{} did not resolve to any {} address",
                            opts.target.host,
                            opts.ip_version.label()
                        )));
                    };
                    opts.report(ConnectPhase::Connecting {
                        via: first.to_string(),
                    });
                    let mut last: Option<std::io::Error> = None;
                    for addr in &addrs {
                        match TcpStream::connect(addr).await {
                            Ok(s) => return Ok(proxy::ProxyStream::Tcp(s)),
                            Err(e) => last = Some(e),
                        }
                    }
                    Err(last
                        .map(CoreError::from)
                        .unwrap_or_else(|| CoreError::Ssh("no address to connect to".into())))
                }
            }
        })
        .await
        .map_err(|_| {
            CoreError::Ssh(format!("timed out connecting to {}", opts.target.display()))
        })??;
        Self::connect_stream(stream, opts).await
    }

    /// Connect to `opts.target` through an already-connected jump host.
    pub async fn connect_via(jump: &SshClient, opts: ConnectOptions) -> Result<Self> {
        opts.report(ConnectPhase::Connecting {
            via: format!("jump host {}", jump.target.display()),
        });
        let channel = jump
            .handle
            .channel_open_direct_tcpip(
                opts.target.host.clone(),
                opts.target.port as u32,
                "127.0.0.1",
                0,
            )
            .await
            .map_err(|e| CoreError::Ssh(format!("jump {}: {e}", jump.target.display())))?;
        Self::connect_stream(channel.into_stream(), opts).await
    }

    /// Connect over any bidirectional stream.
    pub async fn connect_stream<S>(stream: S, opts: ConnectOptions) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (closed_tx, closed_rx) = watch::channel(None);
        let forwarded: handler::ForwardRoutes = Default::default();
        let handler = ClientHandler::new(
            opts.target.host.clone(),
            opts.target.port,
            opts.known_hosts.clone(),
            opts.host_key_prompt.clone(),
            closed_tx,
            forwarded.clone(),
            opts.x11.clone(),
        );
        let banner = handler.banner();
        let algorithms = handler.algorithms();
        let prompting = handler.prompting();
        let server_id: peek::ServerId = Default::default();
        let stream = peek::IdPeek::new(stream, server_id.clone());
        opts.report(ConnectPhase::Handshake);
        if let Some(p) = &opts.progress {
            // The host-key check is the only part of the handshake the user
            // can see (and may be asked about), so surface it as its own step.
            let p = p.clone();
            let mut prompting = prompting.clone();
            tokio::spawn(async move {
                if prompting.wait_for(|v| *v).await.is_ok() {
                    p.phase(ConnectPhase::HostKey);
                }
            });
        }
        let mut handle = timeout_unless_prompting(
            opts.timeout,
            prompting,
            russh::client::connect_stream(config(&opts), stream, handler),
        )
        .await
        .ok_or_else(|| {
            CoreError::Ssh(format!(
                "handshake with {} timed out",
                opts.target.display()
            ))
        })??;

        auth::authenticate(&mut handle, &opts).await?;
        opts.report(ConnectPhase::Authenticated);

        let banner = banner.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let server_id = server_id.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let algorithms = algorithms.lock().unwrap_or_else(|p| p.into_inner()).clone();
        Ok(Self {
            handle,
            target: opts.target,
            banner,
            server_id,
            algorithms,
            closed: closed_rx,
            forwarded,
            env: opts.env,
            agent_forwarding: opts.agent_forwarding,
            x11: opts.x11,
        })
    }

    /// Destination.
    pub fn target(&self) -> &SshTarget {
        &self.target
    }

    /// Pre-auth banner the server sent, if any.
    pub fn banner(&self) -> Option<&str> {
        self.banner.as_deref()
    }

    /// The server's identification string (`SSH-2.0-OpenSSH_9.6p1 ...`).
    pub fn server_id(&self) -> Option<&str> {
        self.server_id.as_deref()
    }

    /// Algorithms negotiated during the initial key exchange.
    pub fn algorithms(&self) -> Option<&Algorithms> {
        self.algorithms.as_ref()
    }

    /// True once the transport is gone.
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed() || self.closed.borrow().is_some()
    }

    /// Resolves when the transport closes, with the reason.
    pub async fn closed(&self) -> String {
        let mut rx = self.closed.clone();
        loop {
            if let Some(reason) = rx.borrow().clone() {
                return reason;
            }
            if rx.changed().await.is_err() {
                return "connection closed".into();
            }
        }
    }

    /// Open an interactive shell with a PTY.
    pub async fn shell(
        &self,
        term: &str,
        size: TermSize,
    ) -> Result<(Arc<SshTerminal>, TermEvents)> {
        let mut channel = self.handle.channel_open_session().await?;
        for (k, v) in &self.env {
            // Servers commonly refuse env vars; that is not fatal.
            let _ = channel.set_env(false, k.clone(), v.clone()).await;
        }
        if self.agent_forwarding {
            let _ = channel.agent_forward(false).await;
        }
        self.request_x11(&mut channel).await?;
        channel
            .request_pty(true, term, size.cols as u32, size.rows as u32, 0, 0, &[])
            .await?;
        Self::await_reply(&mut channel, "pty").await?;
        channel.request_shell(true).await?;
        Self::await_reply(&mut channel, "shell").await?;
        Ok(shell::spawn(channel, self.banner.clone()))
    }

    /// Ask for X11 forwarding on a session channel when it is configured.
    /// The server may refuse (`X11Forwarding no`); the session goes on
    /// without it, as `ssh -Y` does.
    async fn request_x11(&self, channel: &mut Channel<Msg>) -> Result<()> {
        let Some(x11) = &self.x11 else {
            return Ok(());
        };
        channel
            .request_x11(
                true,
                false,
                x11::AUTH_PROTOCOL,
                x11.fake_cookie_hex(),
                x11.screen(),
            )
            .await?;
        match Self::await_reply(channel, "x11").await {
            Ok(()) => Ok(()),
            Err(CoreError::Closed) => Err(CoreError::Closed),
            Err(e) => {
                tracing::warn!(target = %self.target.display(), "X11 forwarding refused: {e}");
                Ok(())
            }
        }
    }

    /// Wait for the server's answer to a `want_reply` channel request.
    async fn await_reply(channel: &mut Channel<Msg>, what: &str) -> Result<()> {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => return Ok(()),
                Some(ChannelMsg::Failure) => {
                    return Err(CoreError::Ssh(format!("server refused {what} request")));
                }
                Some(ChannelMsg::Close) | None => return Err(CoreError::Closed),
                Some(_) => {}
            }
        }
    }

    /// Run a command without a PTY and collect its output.
    pub async fn exec(&self, command: &str, stdin: Option<Bytes>) -> Result<ExecOutput> {
        let mut channel = self.handle.channel_open_session().await?;
        for (k, v) in &self.env {
            let _ = channel.set_env(false, k.clone(), v.clone()).await;
        }
        self.request_x11(&mut channel).await?;
        channel.exec(true, command).await?;
        if let Some(data) = stdin {
            channel.data_bytes(data).await?;
        }
        channel.eof().await?;
        let mut out = ExecOutput::default();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => out.stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => out.exit_code = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(out)
    }

    /// Open a raw session channel (used by SFTP for the subsystem request).
    pub(crate) async fn open_session(&self) -> Result<russh::Channel<russh::client::Msg>> {
        Ok(self.handle.channel_open_session().await?)
    }

    /// Open a TCP tunnel to `host:port` as seen from the server.
    pub async fn direct_tcpip(
        &self,
        host: &str,
        port: u16,
        originator: (&str, u16),
    ) -> Result<russh::ChannelStream<russh::client::Msg>> {
        let ch = self
            .handle
            .channel_open_direct_tcpip(host, port as u32, originator.0, originator.1 as u32)
            .await?;
        Ok(ch.into_stream())
    }

    /// Ask the server to listen on `bind:port` and forward connections to us.
    /// Returns the port actually bound (matters for `port = 0`) and the
    /// receiver of incoming channels for it.
    pub async fn tcpip_forward(
        &self,
        bind: &str,
        port: u16,
    ) -> Result<(u16, mpsc::UnboundedReceiver<ForwardedChannel>)> {
        let bound = self.handle.tcpip_forward(bind, port as u32).await?;
        let bound = if bound == 0 { port } else { bound as u16 };
        let (tx, rx) = mpsc::unbounded_channel();
        self.forwarded
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(bound, tx);
        Ok((bound, rx))
    }

    /// Cancel a remote forward.
    pub async fn cancel_tcpip_forward(&self, bind: &str, port: u16) -> Result<()> {
        self.forwarded
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&port);
        Ok(self.handle.cancel_tcpip_forward(bind, port as u32).await?)
    }

    /// Close the connection.
    pub async fn disconnect(&self) -> Result<()> {
        if self.handle.is_closed() {
            return Ok(());
        }
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "bye", "")
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn timeout_pauses_while_prompting() {
        let tx = watch::Sender::new(false);
        let rx = tx.subscribe();
        let work = async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = tx.send(true);
            tokio::time::sleep(Duration::from_secs(60)).await;
            let _ = tx.send(false);
            tokio::time::sleep(Duration::from_secs(1)).await;
            7
        };
        let out = timeout_unless_prompting(Duration::from_secs(5), rx, work).await;
        assert_eq!(out, Some(7));
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_still_fires_without_prompt() {
        let tx = watch::Sender::new(false);
        let rx = tx.subscribe();
        let work = async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(tx);
            7
        };
        let out = timeout_unless_prompting(Duration::from_secs(5), rx, work).await;
        assert_eq!(out, None);
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_survives_dropped_prompt_sender() {
        let tx = watch::Sender::new(false);
        let rx = tx.subscribe();
        drop(tx);
        let work = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            7
        };
        let out = timeout_unless_prompting(Duration::from_secs(5), rx, work).await;
        assert_eq!(out, Some(7));
        let late = async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            7
        };
        let (tx, rx) = watch::channel(false);
        drop(tx);
        assert_eq!(
            timeout_unless_prompting(Duration::from_secs(5), rx, late).await,
            None
        );
    }

    #[test]
    fn ip_version_filters_resolved_addresses() {
        let addrs: Vec<std::net::SocketAddr> =
            vec!["[::1]:22".parse().unwrap(), "127.0.0.1:22".parse().unwrap()];
        assert_eq!(IpVersion::parse(""), IpVersion::Auto);
        assert_eq!(IpVersion::parse("4"), IpVersion::V4);
        assert_eq!(IpVersion::parse("IPv6"), IpVersion::V6);
        assert_eq!(IpVersion::Auto.filter(addrs.clone()), addrs);
        assert_eq!(IpVersion::V4.filter(addrs.clone()), vec![addrs[1]]);
        assert_eq!(IpVersion::V6.filter(addrs.clone()), vec![addrs[0]]);
    }
}
