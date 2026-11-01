//! X11 forwarding (client side of `ssh -Y`).
//!
//! The shell channel asks the server for `x11-req` with a freshly generated
//! MIT-MAGIC-COOKIE-1. Remote X clients present that cookie when they open a
//! connection; the server relays each as an `x11` channel, and [`bridge`]
//! swaps the fake cookie for the real one of the local display before
//! copying bytes to the X server. The real cookie never leaves this machine
//! and a channel carrying anything but the fake one is dropped.
//!
//! Only *trusted* forwarding is implemented: remote programs get the same
//! access to the local display as local ones (like PuTTY, MobaXterm and
//! `ssh -Y`). Untrusted mode needs the SECURITY extension and `xauth
//! generate`, which is not available on every platform.

use std::path::{Path, PathBuf};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{CoreError, Result};

/// Authorization protocol offered to the server.
pub const AUTH_PROTOCOL: &str = "MIT-MAGIC-COOKIE-1";

/// Largest connection-setup packet we accept before the real X server sees
/// it (name and data are 16-bit lengths, but nothing legitimate is that big).
const MAX_SETUP: usize = 12 + 4 * 1024;

/// How a local X server is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayTarget {
    /// Unix socket (`/tmp/.X11-unix/X0`, XQuartz launchd socket).
    Unix(PathBuf),
    /// TCP (`host:6000+n`; the only option on Windows).
    Tcp(String, u16),
}

/// A parsed `DISPLAY` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDisplay {
    /// Where to connect.
    pub target: DisplayTarget,
    /// Display number (`:N`).
    pub number: u32,
    /// Screen number (`.S`, default 0), sent to the server in `x11-req`.
    pub screen: u32,
}

impl LocalDisplay {
    /// Parse `[proto/][host]:N[.S]`, `unix:N`, or an absolute launchd socket
    /// path with `:N` appended (macOS XQuartz).
    pub fn parse(display: &str) -> Result<Self> {
        let display = display.trim();
        let (host, rest) = display
            .rsplit_once(':')
            .ok_or_else(|| CoreError::Ssh(format!("invalid DISPLAY {display:?}")))?;
        let (number, screen) = match rest.split_once('.') {
            Some((n, s)) => (n, s),
            None => (rest, "0"),
        };
        let number: u32 = number
            .parse()
            .map_err(|_| CoreError::Ssh(format!("invalid DISPLAY {display:?}")))?;
        let screen: u32 = screen
            .parse()
            .map_err(|_| CoreError::Ssh(format!("invalid DISPLAY {display:?}")))?;
        let host = host.rsplit_once('/').map_or(host, |(proto, h)| {
            // `tcp/host:0`, `unix/:0`; a path keeps its slashes.
            if proto.contains('/') || h.contains('/') || proto.starts_with('/') {
                host
            } else {
                h
            }
        });
        let target = if host.starts_with('/') {
            DisplayTarget::Unix(PathBuf::from(host))
        } else if host.is_empty() || host == "unix" {
            if cfg!(windows) {
                DisplayTarget::Tcp("127.0.0.1".into(), 6000 + number as u16)
            } else {
                DisplayTarget::Unix(PathBuf::from(format!("/tmp/.X11-unix/X{number}")))
            }
        } else {
            DisplayTarget::Tcp(host.to_string(), 6000 + number as u16)
        };
        Ok(Self {
            target,
            number,
            screen,
        })
    }

    /// The display to forward to: `override` when given, else `$DISPLAY`,
    /// else `127.0.0.1:0` on Windows (VcXsrv / Xming default). `None` when
    /// there is no X server to talk to.
    pub fn detect(override_display: Option<&str>) -> Option<Self> {
        let value = override_display
            .map(str::to_string)
            .filter(|d| !d.trim().is_empty())
            .or_else(|| {
                std::env::var("DISPLAY")
                    .ok()
                    .filter(|d| !d.trim().is_empty())
            })
            .or_else(|| cfg!(windows).then(|| "127.0.0.1:0".to_string()))?;
        match Self::parse(&value) {
            Ok(d) => Some(d),
            Err(e) => {
                tracing::warn!(display = %value, "X11 forwarding off: {e}");
                None
            }
        }
    }

    async fn connect(&self) -> Result<Box<dyn Stream>> {
        match &self.target {
            DisplayTarget::Tcp(host, port) => Ok(Box::new(
                TcpStream::connect((host.as_str(), *port))
                    .await
                    .map_err(|e| CoreError::Ssh(format!("X server {host}:{port}: {e}")))?,
            )),
            #[cfg(unix)]
            DisplayTarget::Unix(path) => Ok(Box::new(
                tokio::net::UnixStream::connect(path)
                    .await
                    .map_err(|e| CoreError::Ssh(format!("X server {}: {e}", path.display())))?,
            )),
            #[cfg(not(unix))]
            DisplayTarget::Unix(path) => Err(CoreError::Ssh(format!(
                "X server socket {} is not reachable on this platform",
                path.display()
            ))),
        }
    }
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Per-connection X11 forwarding state: the display to forward to, the
/// cookie handed to the server and the one the local X server wants.
pub struct X11Forward {
    display: LocalDisplay,
    fake: [u8; 16],
    real: Option<Vec<u8>>,
}

impl std::fmt::Debug for X11Forward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X11Forward")
            .field("display", &self.display)
            .field("has_real_cookie", &self.real.is_some())
            .finish()
    }
}

impl X11Forward {
    /// Set up forwarding to `display`, looking the real cookie up in
    /// `$XAUTHORITY` / `~/.Xauthority`.
    pub fn new(display: LocalDisplay) -> Self {
        let real = xauthority_path().and_then(|p| match std::fs::read(&p) {
            Ok(bytes) => find_cookie(&bytes, &display),
            Err(e) => {
                tracing::debug!(path = %p.display(), "no Xauthority: {e}");
                None
            }
        });
        if real.is_none() {
            tracing::warn!(
                "no xauth cookie for the local display; X server host access must allow us"
            );
        }
        Self::with_cookies(display, real)
    }

    /// [`Self::new`] with an explicit real cookie (tests, custom setups).
    pub fn with_cookies(display: LocalDisplay, real: Option<Vec<u8>>) -> Self {
        let mut fake = [0u8; 16];
        rand::rng().fill_bytes(&mut fake);
        Self {
            display,
            fake,
            real,
        }
    }

    /// Cookie sent in `x11-req`, hex encoded as the protocol wants.
    pub fn fake_cookie_hex(&self) -> String {
        self.fake.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Screen number for `x11-req`.
    pub fn screen(&self) -> u32 {
        self.display.screen
    }

    /// The display being forwarded to.
    pub fn display(&self) -> &LocalDisplay {
        &self.display
    }

    /// Relay one server-opened `x11` channel to the local display. Returns
    /// when either side closes; a wrong cookie ends it before the X server
    /// is contacted.
    pub async fn bridge<S>(&self, mut remote: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let setup = read_setup(&mut remote).await?;
        let setup = self.rewrite_setup(setup)?;
        let mut local = self.display.connect().await?;
        local.write_all(&setup).await?;
        tokio::io::copy_bidirectional(&mut remote, &mut local).await?;
        Ok(())
    }

    /// Replace the fake cookie in a connection-setup packet with the real one
    /// (or with no authorization when the display has none).
    fn rewrite_setup(&self, packet: Vec<u8>) -> Result<Vec<u8>> {
        let setup = Setup::parse(&packet)?;
        if setup.name != AUTH_PROTOCOL.as_bytes() || setup.data != self.fake {
            return Err(CoreError::Ssh(
                "X11 connection presented an unknown cookie".into(),
            ));
        }
        Ok(match &self.real {
            Some(real) => setup.with_auth(AUTH_PROTOCOL.as_bytes(), real),
            None => setup.with_auth(b"", b""),
        })
    }
}

/// The X11 connection-setup request (first packet a client sends).
struct Setup {
    little_endian: bool,
    major: u16,
    minor: u16,
    name: Vec<u8>,
    data: Vec<u8>,
}

fn pad4(n: usize) -> usize {
    (4 - n % 4) % 4
}

impl Setup {
    fn parse(p: &[u8]) -> Result<Self> {
        let bad = || CoreError::Ssh("malformed X11 connection setup".into());
        if p.len() < 12 {
            return Err(bad());
        }
        let little_endian = match p[0] {
            0x6c => true,
            0x42 => false,
            _ => return Err(bad()),
        };
        let u16_at = |i: usize| {
            let b = [p[i], p[i + 1]];
            if little_endian {
                u16::from_le_bytes(b)
            } else {
                u16::from_be_bytes(b)
            }
        };
        let (major, minor) = (u16_at(2), u16_at(4));
        let (n, d) = (u16_at(6) as usize, u16_at(8) as usize);
        let name_end = 12 + n;
        let data_start = name_end + pad4(n);
        let data_end = data_start + d;
        if p.len() < data_end {
            return Err(bad());
        }
        Ok(Self {
            little_endian,
            major,
            minor,
            name: p[12..name_end].to_vec(),
            data: p[data_start..data_end].to_vec(),
        })
    }

    fn with_auth(&self, name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + name.len() + 4 + data.len() + 4);
        out.push(if self.little_endian { 0x6c } else { 0x42 });
        out.push(0);
        for v in [self.major, self.minor, name.len() as u16, data.len() as u16] {
            out.extend_from_slice(&if self.little_endian {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            });
        }
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name);
        out.extend(std::iter::repeat_n(0, pad4(name.len())));
        out.extend_from_slice(data);
        out.extend(std::iter::repeat_n(0, pad4(data.len())));
        out
    }
}

/// Read exactly one connection-setup packet from the channel.
async fn read_setup<S: AsyncRead + Unpin>(s: &mut S) -> Result<Vec<u8>> {
    let mut head = [0u8; 12];
    s.read_exact(&mut head).await?;
    let little_endian = match head[0] {
        0x6c => true,
        0x42 => false,
        _ => return Err(CoreError::Ssh("malformed X11 connection setup".into())),
    };
    let len = |i: usize| {
        let b = [head[i], head[i + 1]];
        (if little_endian {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }) as usize
    };
    let (n, d) = (len(6), len(8));
    let rest = n + pad4(n) + d + pad4(d);
    if 12 + rest > MAX_SETUP {
        return Err(CoreError::Ssh("oversized X11 connection setup".into()));
    }
    let mut packet = head.to_vec();
    packet.resize(12 + rest, 0);
    s.read_exact(&mut packet[12..]).await?;
    Ok(packet)
}

fn xauthority_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("XAUTHORITY").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(|h| Path::new(&h).join(".Xauthority"))
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .filter(|h| !h.is_empty())
                .map(|h| Path::new(&h).join(".Xauthority"))
        })
}

const FAMILY_LOCAL: u16 = 256;
const FAMILY_WILD: u16 = 65535;

/// Pick the MIT-MAGIC-COOKIE-1 for `display` out of an Xauthority file.
/// Entries for the display number with a local/wildcard family win; any
/// other family (e.g. Internet for a TCP display) is the fallback.
pub fn find_cookie(xauth: &[u8], display: &LocalDisplay) -> Option<Vec<u8>> {
    let number = display.number.to_string();
    let mut fallback = None;
    for entry in parse_xauthority(xauth) {
        if entry.name != AUTH_PROTOCOL.as_bytes() {
            continue;
        }
        if !entry.number.is_empty() && entry.number != number.as_bytes() {
            continue;
        }
        let local = matches!(entry.family, FAMILY_LOCAL | FAMILY_WILD);
        let unix = matches!(display.target, DisplayTarget::Unix(_));
        if local == unix {
            return Some(entry.data);
        }
        fallback.get_or_insert(entry.data);
    }
    fallback
}

struct XauthEntry {
    family: u16,
    number: Vec<u8>,
    name: Vec<u8>,
    data: Vec<u8>,
}

fn parse_xauthority(mut b: &[u8]) -> Vec<XauthEntry> {
    fn field<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
        if b.len() < 2 {
            return None;
        }
        let n = u16::from_be_bytes([b[0], b[1]]) as usize;
        if b.len() < 2 + n {
            return None;
        }
        let (v, rest) = b[2..].split_at(n);
        *b = rest;
        Some(v)
    }
    let mut out = Vec::new();
    while b.len() >= 2 {
        let family = u16::from_be_bytes([b[0], b[1]]);
        b = &b[2..];
        let (Some(_addr), Some(number), Some(name), Some(data)) =
            (field(&mut b), field(&mut b), field(&mut b), field(&mut b))
        else {
            break;
        };
        out.push(XauthEntry {
            family,
            number: number.to_vec(),
            name: name.to_vec(),
            data: data.to_vec(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xauth_entry(family: u16, addr: &[u8], number: &str, name: &str, data: &[u8]) -> Vec<u8> {
        let mut out = family.to_be_bytes().to_vec();
        for f in [addr, number.as_bytes(), name.as_bytes(), data] {
            out.extend_from_slice(&(f.len() as u16).to_be_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    fn setup(le: bool, name: &[u8], data: &[u8]) -> Vec<u8> {
        Setup {
            little_endian: le,
            major: 11,
            minor: 0,
            name: vec![],
            data: vec![],
        }
        .with_auth(name, data)
    }

    #[test]
    fn parses_display_forms() {
        let d = LocalDisplay::parse(":1.2").unwrap();
        assert_eq!((d.number, d.screen), (1, 2));
        if cfg!(unix) {
            assert_eq!(d.target, DisplayTarget::Unix("/tmp/.X11-unix/X1".into()));
        }
        let d = LocalDisplay::parse("unix:3").unwrap();
        assert_eq!(d.number, 3);
        let d = LocalDisplay::parse("localhost:10.0").unwrap();
        assert_eq!(d.target, DisplayTarget::Tcp("localhost".into(), 6010));
        let d = LocalDisplay::parse("tcp/desk:2").unwrap();
        assert_eq!(d.target, DisplayTarget::Tcp("desk".into(), 6002));
        let d = LocalDisplay::parse("/private/tmp/com.apple.launchd.abc/org.xquartz:0").unwrap();
        assert_eq!(
            d.target,
            DisplayTarget::Unix("/private/tmp/com.apple.launchd.abc/org.xquartz".into())
        );
        assert!(LocalDisplay::parse("nonsense").is_err());
        assert!(LocalDisplay::parse(":x").is_err());
    }

    #[test]
    fn picks_cookie_for_display_and_family() {
        let unix0 = LocalDisplay::parse(":0").unwrap();
        let tcp0 = LocalDisplay::parse("desk:0").unwrap();
        let mut file = xauth_entry(0, &[10, 0, 0, 1], "0", AUTH_PROTOCOL, b"inet-0");
        file.extend(xauth_entry(
            FAMILY_LOCAL,
            b"host",
            "1",
            AUTH_PROTOCOL,
            b"local-1",
        ));
        file.extend(xauth_entry(
            FAMILY_LOCAL,
            b"host",
            "0",
            "OTHER-PROTO",
            b"other",
        ));
        file.extend(xauth_entry(
            FAMILY_LOCAL,
            b"host",
            "0",
            AUTH_PROTOCOL,
            b"local-0",
        ));
        assert_eq!(find_cookie(&file, &unix0).as_deref(), Some(&b"local-0"[..]));
        assert_eq!(find_cookie(&file, &tcp0).as_deref(), Some(&b"inet-0"[..]));
        let unix1 = LocalDisplay::parse(":1").unwrap();
        assert_eq!(find_cookie(&file, &unix1).as_deref(), Some(&b"local-1"[..]));
        assert_eq!(
            find_cookie(&file, &LocalDisplay::parse(":7").unwrap()),
            None
        );
        // A truncated file yields what could be read, nothing more.
        assert_eq!(find_cookie(&file[..7], &unix0), None);
    }

    #[test]
    fn rewrites_fake_cookie_and_refuses_others() {
        let fwd = X11Forward::with_cookies(
            LocalDisplay::parse(":0").unwrap(),
            Some(b"REAL-COOKIE".to_vec()),
        );
        for le in [true, false] {
            let out = fwd
                .rewrite_setup(setup(le, AUTH_PROTOCOL.as_bytes(), &fwd.fake))
                .unwrap();
            let parsed = Setup::parse(&out).unwrap();
            assert_eq!(parsed.little_endian, le);
            assert_eq!((parsed.major, parsed.minor), (11, 0));
            assert_eq!(parsed.name, AUTH_PROTOCOL.as_bytes());
            assert_eq!(parsed.data, b"REAL-COOKIE");
            assert_eq!(out.len() % 4, 0);
        }
        let mut wrong = fwd.fake;
        wrong[0] ^= 1;
        assert!(
            fwd.rewrite_setup(setup(true, AUTH_PROTOCOL.as_bytes(), &wrong))
                .is_err()
        );
        assert!(fwd.rewrite_setup(setup(true, b"", b"")).is_err());
        assert!(fwd.rewrite_setup(vec![0x6c, 0, 11]).is_err());
    }

    #[test]
    fn no_real_cookie_strips_authorization() {
        let fwd = X11Forward::with_cookies(LocalDisplay::parse(":0").unwrap(), None);
        let out = fwd
            .rewrite_setup(setup(true, AUTH_PROTOCOL.as_bytes(), &fwd.fake))
            .unwrap();
        let parsed = Setup::parse(&out).unwrap();
        assert!(parsed.name.is_empty() && parsed.data.is_empty());
        assert_eq!(out.len(), 12);
    }

    #[test]
    fn fake_cookie_is_hex_and_random() {
        let a = X11Forward::with_cookies(LocalDisplay::parse(":0").unwrap(), None);
        let b = X11Forward::with_cookies(LocalDisplay::parse(":0").unwrap(), None);
        assert_eq!(a.fake_cookie_hex().len(), 32);
        assert!(a.fake_cookie_hex().chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a.fake_cookie_hex(), b.fake_cookie_hex());
    }

    #[tokio::test]
    async fn read_setup_rejects_garbage_and_oversize() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        assert!(read_setup(&mut b).await.is_err());
        let (mut a, mut b) = tokio::io::duplex(64);
        let mut head = vec![0x6c, 0, 11, 0, 0, 0];
        head.extend_from_slice(&0xffffu16.to_le_bytes());
        head.extend_from_slice(&0xffffu16.to_le_bytes());
        head.extend_from_slice(&[0, 0]);
        a.write_all(&head).await.unwrap();
        assert!(read_setup(&mut b).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bridge_swaps_cookie_and_relays_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("X9");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let display = LocalDisplay {
            target: DisplayTarget::Unix(sock.clone()),
            number: 9,
            screen: 0,
        };
        let fwd = X11Forward::with_cookies(display, Some(b"REAL".to_vec()));
        let fake = fwd.fake;
        let xserver = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            let parsed = Setup::parse(&buf[..n]).unwrap();
            assert_eq!(parsed.data, b"REAL");
            s.write_all(b"welcome").await.unwrap();
            let mut more = [0u8; 5];
            s.read_exact(&mut more).await.unwrap();
            assert_eq!(&more, b"hello");
        });
        let (mut client, server_side) = tokio::io::duplex(256);
        let bridge = tokio::spawn(async move { fwd.bridge(server_side).await });
        client
            .write_all(&setup(true, AUTH_PROTOCOL.as_bytes(), &fake))
            .await
            .unwrap();
        let mut got = [0u8; 7];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"welcome");
        client.write_all(b"hello").await.unwrap();
        xserver.await.unwrap();
        drop(client);
        let _ = bridge.await.unwrap();
    }
}
