//! Outbound proxies for the TCP leg of an SSH connection: HTTP `CONNECT`,
//! SOCKS4/4a (hostname sent to the proxy when the target is not an IPv4
//! literal) and SOCKS5 (RFC 1928, optional username/password per RFC 1929).

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Proxy type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyKind {
    /// HTTP `CONNECT`.
    Http,
    /// SOCKS4 / SOCKS4a (no password; `username` becomes the user id).
    Socks4,
    /// SOCKS5.
    Socks5,
}

impl ProxyKind {
    /// Parse the `kind` string stored in a `Proxy` entity.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "http" | "https" => Some(Self::Http),
            "socks4" | "socks4a" => Some(Self::Socks4),
            "socks" | "socks5" | "socks5h" => Some(Self::Socks5),
            _ => None,
        }
    }

    /// Whether the proxy protocol can carry a password.
    pub fn supports_password(self) -> bool {
        !matches!(self, Self::Socks4)
    }

    /// Display name (`HTTP`, `SOCKS4`, `SOCKS5`).
    pub fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Socks4 => "SOCKS4",
            Self::Socks5 => "SOCKS5",
        }
    }
}

/// Resolved proxy settings.
#[derive(Clone)]
pub struct ProxyConfig {
    /// Type.
    pub kind: ProxyKind,
    /// Proxy host.
    pub host: String,
    /// Proxy port.
    pub port: u16,
    /// Credentials.
    pub username: Option<String>,
    /// Credentials.
    pub password: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// The stream the SSH transport runs over.
pub enum ProxyStream {
    /// Direct connection.
    Tcp(TcpStream),
    /// Tunnelled through a gateway (see `crate::gateway`).
    Ws(Box<crate::gateway::WsStream>),
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            ProxyStream::Ws(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ProxyStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            ProxyStream::Ws(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            ProxyStream::Ws(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            ProxyStream::Ws(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Connect to `host:port` through `proxy`.
pub async fn connect(proxy: &ProxyConfig, host: &str, port: u16) -> Result<ProxyStream> {
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(|e| CoreError::Ssh(format!("proxy {}:{}: {e}", proxy.host, proxy.port)))?;
    let _ = stream.set_nodelay(true);
    match proxy.kind {
        ProxyKind::Http => http_connect(&mut stream, proxy, host, port).await?,
        ProxyKind::Socks4 => socks4_connect(&mut stream, proxy, host, port).await?,
        ProxyKind::Socks5 => socks5_connect(&mut stream, proxy, host, port).await?,
    }
    Ok(ProxyStream::Tcp(stream))
}

async fn http_connect(s: &mut TcpStream, proxy: &ProxyConfig, host: &str, port: u16) -> Result<()> {
    use base64::Engine;
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(user) = &proxy.username {
        let pw = proxy.password.as_deref().map(|p| p.as_str()).unwrap_or("");
        let cred = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pw}"));
        req.push_str(&format!("Proxy-Authorization: Basic {cred}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;

    // Read headers byte-wise until CRLFCRLF; the proxy must not send body
    // bytes on success, so nothing is over-read.
    let mut buf = Vec::with_capacity(512);
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if buf.len() > 16 * 1024 {
            return Err(CoreError::Ssh("proxy: response headers too large".into()));
        }
        if s.read(&mut b).await? == 0 {
            return Err(CoreError::Ssh(
                "proxy: connection closed during CONNECT".into(),
            ));
        }
        buf.push(b[0]);
    }
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| CoreError::Ssh("proxy: malformed CONNECT response".into()))?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(CoreError::Ssh(format!(
            "proxy: CONNECT failed with HTTP {status}"
        )))
    }
}

async fn socks4_connect(
    s: &mut TcpStream,
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
) -> Result<()> {
    let user = proxy.username.as_deref().unwrap_or("");
    if user.contains('\0') {
        return Err(CoreError::Ssh("socks4: user id contains NUL".into()));
    }
    let mut req = vec![4u8, 1];
    req.extend_from_slice(&port.to_be_bytes());
    let v4 = host.parse::<std::net::Ipv4Addr>().ok();
    match v4 {
        Some(ip) => req.extend_from_slice(&ip.octets()),
        // SOCKS4a: 0.0.0.x tells the proxy to resolve the name that follows.
        None => req.extend_from_slice(&[0, 0, 0, 1]),
    }
    req.extend_from_slice(user.as_bytes());
    req.push(0);
    if v4.is_none() {
        if host.contains('\0') {
            return Err(CoreError::Ssh("socks4: hostname contains NUL".into()));
        }
        req.extend_from_slice(host.as_bytes());
        req.push(0);
    }
    s.write_all(&req).await?;

    let mut resp = [0u8; 8];
    s.read_exact(&mut resp).await?;
    if resp[0] != 0 {
        return Err(CoreError::Ssh(format!(
            "socks4: bad reply version {}",
            resp[0]
        )));
    }
    match resp[1] {
        0x5a => Ok(()),
        0x5b => Err(CoreError::Ssh("socks4: request rejected or failed".into())),
        0x5c => Err(CoreError::Ssh(
            "socks4: rejected — proxy cannot reach identd on the client".into(),
        )),
        0x5d => Err(CoreError::Ssh(
            "socks4: rejected — user id does not match identd".into(),
        )),
        c => Err(CoreError::Ssh(format!("socks4: unexpected reply {c:#x}"))),
    }
}

async fn socks5_connect(
    s: &mut TcpStream,
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
) -> Result<()> {
    let with_auth = proxy.username.is_some();
    // Greeting: version 5, methods {no-auth, user/pass?}
    let greeting: &[u8] = if with_auth { &[5, 2, 0, 2] } else { &[5, 1, 0] };
    s.write_all(greeting).await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != 5 {
        return Err(CoreError::Ssh("socks5: bad version".into()));
    }
    match resp[1] {
        0 => {}
        2 => {
            let user = proxy.username.as_deref().unwrap_or("");
            let pw = proxy.password.as_deref().map(|p| p.as_str()).unwrap_or("");
            if user.len() > 255 || pw.len() > 255 {
                return Err(CoreError::Ssh("socks5: credentials too long".into()));
            }
            let mut m = vec![1u8, user.len() as u8];
            m.extend_from_slice(user.as_bytes());
            m.push(pw.len() as u8);
            m.extend_from_slice(pw.as_bytes());
            s.write_all(&m).await?;
            let mut r = [0u8; 2];
            s.read_exact(&mut r).await?;
            if r[1] != 0 {
                return Err(CoreError::Ssh("socks5: authentication rejected".into()));
            }
        }
        0xff => return Err(CoreError::Ssh("socks5: no acceptable auth method".into())),
        m => {
            return Err(CoreError::Ssh(format!(
                "socks5: unexpected auth method {m}"
            )));
        }
    }

    // CONNECT request; always send the hostname so the proxy resolves it.
    let mut req = vec![5u8, 1, 0];
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                req.push(1);
                req.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                req.push(4);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        if host.len() > 255 {
            return Err(CoreError::Ssh("socks5: hostname too long".into()));
        }
        req.push(3);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0 {
        let reason = match head[1] {
            1 => "general failure",
            2 => "connection not allowed",
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused",
            6 => "TTL expired",
            7 => "command not supported",
            8 => "address type not supported",
            _ => "unknown error",
        };
        return Err(CoreError::Ssh(format!("socks5: {reason}")));
    }
    let addr_len = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        t => {
            return Err(CoreError::Ssh(format!(
                "socks5: bad bound address type {t}"
            )));
        }
    };
    let mut skip = vec![0u8; addr_len + 2];
    s.read_exact(&mut skip).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn echo_target() -> (u16, tokio::task::JoinHandle<()>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });
        (port, h)
    }

    #[tokio::test]
    async fn socks5_with_userpass_tunnels() {
        let (target_port, target) = echo_target().await;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = l.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut g = [0u8; 4];
            s.read_exact(&mut g).await.unwrap();
            assert_eq!(g, [5, 2, 0, 2]);
            s.write_all(&[5, 2]).await.unwrap();
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).await.unwrap();
            let mut user = vec![0u8; hdr[1] as usize];
            s.read_exact(&mut user).await.unwrap();
            let mut pl = [0u8; 1];
            s.read_exact(&mut pl).await.unwrap();
            let mut pw = vec![0u8; pl[0] as usize];
            s.read_exact(&mut pw).await.unwrap();
            assert_eq!(
                (user.as_slice(), pw.as_slice()),
                (b"u".as_slice(), b"pw".as_slice())
            );
            s.write_all(&[1, 0]).await.unwrap();
            let mut req = [0u8; 4];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(req, [5, 1, 0, 3]);
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.unwrap();
            let mut name = vec![0u8; l[0] as usize];
            s.read_exact(&mut name).await.unwrap();
            assert_eq!(name, b"localhost");
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            let port = u16::from_be_bytes(port);
            let mut up = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            tokio::io::copy_bidirectional(&mut s, &mut up).await.ok();
        });
        let cfg = ProxyConfig {
            kind: ProxyKind::Socks5,
            host: "127.0.0.1".into(),
            port: proxy_port,
            username: Some("u".into()),
            password: Some(Zeroizing::new("pw".into())),
        };
        let mut s = connect(&cfg, "localhost", target_port).await.unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello");
        target.await.unwrap();
        drop(s);
        let _ = srv.await;
    }

    #[tokio::test]
    async fn socks4a_sends_hostname_and_user_id() {
        let (target_port, target) = echo_target().await;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = l.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut head = [0u8; 8];
            s.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], 4);
            assert_eq!(head[1], 1);
            let port = u16::from_be_bytes([head[2], head[3]]);
            assert_eq!(&head[4..8], &[0, 0, 0, 1]);
            let mut user = Vec::new();
            let mut b = [0u8; 1];
            loop {
                s.read_exact(&mut b).await.unwrap();
                if b[0] == 0 {
                    break;
                }
                user.push(b[0]);
            }
            assert_eq!(user, b"alice");
            let mut name = Vec::new();
            loop {
                s.read_exact(&mut b).await.unwrap();
                if b[0] == 0 {
                    break;
                }
                name.push(b[0]);
            }
            assert_eq!(name, b"localhost");
            let mut up = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            s.write_all(&[0, 0x5a, 0, 0, 0, 0, 0, 0]).await.unwrap();
            tokio::io::copy_bidirectional(&mut s, &mut up).await.ok();
        });
        let cfg = ProxyConfig {
            kind: ProxyKind::Socks4,
            host: "127.0.0.1".into(),
            port: proxy_port,
            username: Some("alice".into()),
            password: None,
        };
        let mut s = connect(&cfg, "localhost", target_port).await.unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello");
        target.await.unwrap();
        drop(s);
        let _ = srv.await;
    }

    #[tokio::test]
    async fn socks4_ipv4_literal_is_sent_inline_and_rejection_is_typed() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut req = [0u8; 9];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(req, [4, 1, 0, 22, 10, 0, 0, 7, 0]);
            s.write_all(&[0, 0x5b, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        let cfg = ProxyConfig {
            kind: ProxyKind::Socks4,
            host: "127.0.0.1".into(),
            port: proxy_port,
            username: None,
            password: None,
        };
        let err = connect(&cfg, "10.0.0.7", 22).await.err().unwrap();
        assert!(err.to_string().contains("rejected"), "{err}");
    }

    #[tokio::test]
    async fn socks5_auth_rejection_is_typed() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut g = [0u8; 4];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[5, 2]).await.unwrap();
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(&[1, 1]).await.unwrap();
        });
        let cfg = ProxyConfig {
            kind: ProxyKind::Socks5,
            host: "127.0.0.1".into(),
            port: proxy_port,
            username: Some("u".into()),
            password: Some(Zeroizing::new("wrong".into())),
        };
        let err = connect(&cfg, "localhost", 22).await.err().unwrap();
        assert!(err.to_string().contains("authentication rejected"), "{err}");
    }

    #[tokio::test]
    async fn http_connect_with_basic_auth_tunnels() {
        let (target_port, target) = echo_target().await;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = l.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut b = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut b).await.unwrap();
                buf.push(b[0]);
            }
            let text = String::from_utf8(buf).unwrap();
            assert!(text.starts_with(&format!(
                "CONNECT example.invalid:{target_port} HTTP/1.1\r\n"
            )));
            // base64("u:pw")
            assert!(
                text.contains("Proxy-Authorization: Basic dTpwdw==\r\n"),
                "{text}"
            );
            let mut up = TcpStream::connect(("127.0.0.1", target_port))
                .await
                .unwrap();
            s.write_all(b"HTTP/1.1 200 Connection established\r\nX-Proxy: test\r\n\r\n")
                .await
                .unwrap();
            tokio::io::copy_bidirectional(&mut s, &mut up).await.ok();
        });
        let cfg = ProxyConfig {
            kind: ProxyKind::Http,
            host: "127.0.0.1".into(),
            port: proxy_port,
            username: Some("u".into()),
            password: Some(Zeroizing::new("pw".into())),
        };
        let mut s = connect(&cfg, "example.invalid", target_port).await.unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello");
        target.await.unwrap();
        drop(s);
        let _ = srv.await;
    }

    #[test]
    fn parse_accepts_every_ui_kind() {
        assert_eq!(ProxyKind::parse("socks4"), Some(ProxyKind::Socks4));
        assert_eq!(ProxyKind::parse("SOCKS4a"), Some(ProxyKind::Socks4));
        assert_eq!(ProxyKind::parse("socks5"), Some(ProxyKind::Socks5));
        assert_eq!(ProxyKind::parse("http"), Some(ProxyKind::Http));
        assert_eq!(ProxyKind::parse("ftp"), None);
        assert!(!ProxyKind::Socks4.supports_password());
    }

    #[tokio::test]
    async fn http_connect_rejects_non_2xx() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let cfg = ProxyConfig {
            kind: ProxyKind::Http,
            host: "127.0.0.1".into(),
            port,
            username: None,
            password: None,
        };
        let err = connect(&cfg, "example.invalid", 22).await.err().unwrap();
        assert!(err.to_string().contains("407"), "{err}");
    }
}
