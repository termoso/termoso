//! End-to-end tests against an in-process `russh` server: host-key trust,
//! every auth method, shell/exec/resize, SFTP, and port forwarding.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use bytes::Bytes;
use russh::keys::ssh_key::{Algorithm, PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Server as _, Session};
use russh::{Channel, ChannelId, MethodSet};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use termoso_core::error::CoreError;
use termoso_core::fido2::{GenerateOptions, SkAlgorithm, soft};
use termoso_core::forward::{Forward, ForwardSpec};
use termoso_core::hostkey::{
    self, FixedPrompt, HostKeyDecision, HostKeyPrompt, HostKeyVerdict, KnownHosts, StrictPrompt,
};
use termoso_core::sftp::{OpenMode, Sftp, TransferOptions};
#[cfg(unix)]
use termoso_core::ssh::X11Forward;
use termoso_core::ssh::{AuthMethod, ConnectOptions, PasswordResponder, SshClient, SshTarget};
use termoso_core::store::Store;
use termoso_core::terminal::{TermEvent, TermSize, TerminalSession};
use termoso_crypto::keys::SymmetricKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const USER: &str = "tester";
const PASSWORD: &str = "s3cret";

/// Everything the test server records so tests can assert on it.
#[derive(Default)]
struct Observed {
    pty: Mutex<Option<(String, u32, u32)>>,
    resized: Mutex<Option<(u32, u32)>>,
    env: Mutex<Vec<(String, String)>>,
    kbd_rounds: AtomicU32,
    forward_requests: Mutex<Vec<(String, u32)>>,
    cancelled_forwards: AtomicBool,
    offered: std::sync::Mutex<Vec<PublicKey>>,
    /// `x11-req`: (auth protocol, auth cookie hex, screen).
    x11: Mutex<Option<(String, String, u32)>>,
}

#[derive(Clone)]
struct TestServer {
    authorized: Arc<std::sync::Mutex<Vec<PublicKey>>>,
    observed: Arc<Observed>,
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    tcp_echo: Option<u16>,
}

struct TestHandler {
    srv: TestServer,
    channels: HashMap<ChannelId, Channel<Msg>>,
    shell_echo: HashMap<ChannelId, ()>,
}

impl TestServer {
    fn is_authorized(&self, key: &PublicKey) -> bool {
        self.authorized
            .lock()
            .unwrap()
            .iter()
            .any(|k| k.key_data() == key.key_data())
    }
}

impl russh::server::Server for TestServer {
    type Handler = TestHandler;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> TestHandler {
        TestHandler {
            srv: self.clone(),
            channels: HashMap::new(),
            shell_echo: HashMap::new(),
        }
    }
}

impl russh::server::Handler for TestHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(
                &[
                    russh::MethodKind::Password,
                    russh::MethodKind::PublicKey,
                    russh::MethodKind::KeyboardInteractive,
                ][..],
            )),
            partial_success: false,
        })
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == USER && password == PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.srv.observed.offered.lock().unwrap().push(key.clone());
        Ok(if self.srv.is_authorized(key) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if user == USER && self.srv.is_authorized(key) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<russh::server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let round = self.srv.observed.kbd_rounds.fetch_add(1, Ordering::SeqCst);
        match response {
            None => Ok(Auth::Partial {
                name: "Verification".into(),
                instructions: "Answer the prompts".into(),
                prompts: vec![
                    ("Password: ".into(), false),
                    ("Username (echoed): ".into(), true),
                ]
                .into(),
            }),
            Some(mut r) => {
                let pw = r.next().unwrap_or_default();
                let echoed = r.next().unwrap_or_default();
                let _ = round;
                Ok(if pw.as_ref() == PASSWORD.as_bytes() && echoed.is_empty() {
                    Auth::Accept
                } else {
                    Auth::reject()
                })
            }
        }
    }

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(Some("Welcome to the termoso test server".into()))
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _oa: &str,
        _op: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(echo) = self.srv.tcp_echo else {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        // Like sshd: loopback targets are dialled for real (this is how a
        // jump host forwards to the next hop); `echo.internal:7` is the
        // fixture name for the echo server; anything else is refused.
        let upstream = match (host, port) {
            ("echo.internal", 7) => echo,
            ("127.0.0.1" | "localhost", p) if (1..=65535).contains(&p) => p as u16,
            _ => {
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
        };
        reply.accept().await;
        tokio::spawn(async move {
            let Ok(mut sock) = tokio::net::TcpStream::connect(("127.0.0.1", upstream)).await else {
                return;
            };
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut sock).await;
        });
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        *self.srv.observed.pty.lock().await = Some((term.to_string(), cols, rows));
        session.channel_success(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.srv
            .observed
            .env
            .lock()
            .await
            .push((name.into(), value.into()));
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        _pw: u32,
        _ph: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        *self.srv.observed.resized.lock().await = Some((cols, rows));
        session.channel_success(channel)?;
        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        x11_auth_protocol: &str,
        x11_auth_cookie: &str,
        x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        *self.srv.observed.x11.lock().await = Some((
            x11_auth_protocol.to_string(),
            x11_auth_cookie.to_string(),
            x11_screen_number,
        ));
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.shell_echo.insert(channel, ());
        session.channel_success(channel)?;
        session.data(channel, Bytes::from_static(b"prompt$ "))?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        cmd: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let cmd = String::from_utf8_lossy(cmd).into_owned();
        match cmd.as_str() {
            "whoami" => {
                session.data(channel, Bytes::from_static(b"tester\n"))?;
                session.exit_status_request(channel, 0)?;
            }
            "fail" => {
                session.extended_data(channel, 1, Bytes::from_static(b"boom\n"))?;
                session.exit_status_request(channel, 7)?;
            }
            "cat" => {
                // echoes stdin until EOF; handled in `data`/`channel_eof`
                self.shell_echo.insert(channel, ());
                return Ok(());
            }
            // Acts as an X client: opens an X11 channel back to us with the
            // cookie from `x11-req`, prints whatever the "X server" answers.
            "xclient" => {
                // Without an `x11-req` a misbehaving server would still try;
                // use an all-zero cookie so the client must refuse the channel.
                let cookie = self
                    .srv
                    .observed
                    .x11
                    .lock()
                    .await
                    .clone()
                    .map_or_else(|| "00".repeat(16), |(_, c, _)| c);
                let handle = session.handle();
                tokio::spawn(async move {
                    let out = match x11_roundtrip(&handle, &cookie).await {
                        Ok(reply) => reply,
                        Err(e) => format!("x11 error: {e}").into_bytes(),
                    };
                    let _ = handle.data(channel, Bytes::from(out)).await;
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                });
                return Ok(());
            }
            termoso_core::osdetect::DETECT_COMMAND => {
                session.data(
                    channel,
                    Bytes::from_static(
                        b"Linux\nPRETTY_NAME=\"Rocky Linux 9.4\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n",
                    ),
                )?;
                session.exit_status_request(channel, 0)?;
            }
            _ => {
                session.extended_data(channel, 1, Bytes::from(format!("unknown: {cmd}\n")))?;
                session.exit_status_request(channel, 127)?;
            }
        }
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.shell_echo.contains_key(&channel) {
            if data == b"exit\n" {
                session.data(channel, Bytes::from_static(b"bye\n"))?;
                session.exit_status_request(channel, 3)?;
                session.eof(channel)?;
                session.close(channel)?;
            } else {
                session.data(channel, Bytes::copy_from_slice(data))?;
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.shell_echo.remove(&channel).is_some() {
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        let channel = self.channels.remove(&channel_id).expect("session channel");
        session.channel_success(channel_id)?;
        let files = self.srv.files.clone();
        tokio::spawn(async move {
            russh_sftp::server::run(channel.into_stream(), MemSftp::new(files)).await;
        });
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if *port == 0 {
            *port = 40_000;
        }
        self.srv
            .observed
            .forward_requests
            .lock()
            .await
            .push((address.to_string(), *port));
        let handle = session.handle();
        let address = address.to_string();
        let port = *port;
        // Simulate one inbound connection to the remote listener.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let Ok(channel) = handle
                .channel_open_forwarded_tcpip(address, port, "10.0.0.9", 5555)
                .await
            else {
                return;
            };
            let mut stream = channel.into_stream();
            let _ = stream.write_all(b"ping-from-server").await;
            let mut buf = vec![0u8; 64];
            if let Ok(n) = stream.read(&mut buf).await {
                let _ = stream.write_all(&buf[..n]).await;
            }
            let _ = stream.shutdown().await;
        });
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        _a: &str,
        _p: u32,
        _s: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.srv
            .observed
            .cancelled_forwards
            .store(true, Ordering::SeqCst);
        Ok(true)
    }
}

// ---- minimal in-memory SFTP server -------------------------------------

struct OpenFile {
    path: String,
    flags: OpenFlags,
}

struct MemSftp {
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    handles: HashMap<String, OpenFile>,
    dirs: HashMap<String, Option<Vec<File>>>,
    next: u32,
}

impl MemSftp {
    fn new(files: Arc<Mutex<HashMap<String, Vec<u8>>>>) -> Self {
        Self {
            files,
            handles: HashMap::new(),
            dirs: HashMap::new(),
            next: 1,
        }
    }
    fn handle(&mut self) -> String {
        self.next += 1;
        format!("h{}", self.next)
    }
    fn ok(id: u32) -> Status {
        Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".into(),
            language_tag: "en-US".into(),
        }
    }
    fn norm(p: &str) -> String {
        let p = if p.is_empty() || p == "." {
            "/home/tester".to_string()
        } else {
            p.to_string()
        };
        let p = if p.starts_with('/') {
            p
        } else {
            format!("/home/tester/{p}")
        };
        let mut parts: Vec<&str> = Vec::new();
        for seg in p.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                s => parts.push(s),
            }
        }
        format!("/{}", parts.join("/"))
    }
    fn is_dir(files: &HashMap<String, Vec<u8>>, p: &str) -> bool {
        p == "/" || p == "/home" || p == "/home/tester" || files.contains_key(&format!("{p}/"))
    }
    /// Symlinks live in the same map under `"<path>@"` with the target as value.
    fn link_target(files: &HashMap<String, Vec<u8>>, p: &str) -> Option<String> {
        files
            .get(&format!("{p}@"))
            .map(|t| String::from_utf8_lossy(t).into_owned())
    }
    fn attrs_for(files: &HashMap<String, Vec<u8>>, p: &str) -> Option<FileAttributes> {
        if Self::link_target(files, p).is_some() {
            let mut a = FileAttributes::default();
            a.set_symlink(true);
            a.permissions = Some(0o120777);
            return Some(a);
        }
        if Self::is_dir(files, p) {
            let mut a = FileAttributes::default();
            a.set_dir(true);
            a.permissions = Some(0o40755);
            return Some(a);
        }
        files.get(p).map(|d| FileAttributes {
            size: Some(d.len() as u64),
            permissions: Some(0o100644),
            mtime: Some(1_700_000_000),
            atime: Some(1_700_000_000),
            ..FileAttributes::default()
        })
    }
}

impl russh_sftp::server::Handler for MemSftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _ext: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let p = Self::norm(&path);
        Ok(Name {
            id,
            files: vec![File::dummy(&p)],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let mut p = Self::norm(&path);
        let files = self.files.lock().await;
        // Follow links (bounded, so a loop just ends up NoSuchFile).
        for _ in 0..8 {
            match Self::link_target(&files, &p) {
                Some(t) => p = Self::norm(&t),
                None => break,
            }
        }
        match Self::attrs_for(&files, &p) {
            Some(attrs) if !attrs.is_symlink() => Ok(Attrs { id, attrs }),
            _ => Err(StatusCode::NoSuchFile),
        }
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let p = Self::norm(&path);
        let files = self.files.lock().await;
        match Self::attrs_for(&files, &p) {
            Some(attrs) => Ok(Attrs { id, attrs }),
            None => Err(StatusCode::NoSuchFile),
        }
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let p = Self::norm(&path);
        let files = self.files.lock().await;
        match Self::link_target(&files, &p) {
            Some(t) => Ok(Name {
                id,
                files: vec![File::dummy(&t)],
            }),
            None => Err(StatusCode::NoSuchFile),
        }
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        let p = Self::norm(&linkpath);
        let mut files = self.files.lock().await;
        if Self::attrs_for(&files, &p).is_some() {
            return Err(StatusCode::Failure);
        }
        files.insert(format!("{p}@"), targetpath.into_bytes());
        Ok(Self::ok(id))
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let path = self
            .handles
            .get(&handle)
            .ok_or(StatusCode::BadMessage)?
            .path
            .clone();
        self.stat(id, path).await
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let p = Self::norm(&path);
        let files = self.files.lock().await;
        if !Self::is_dir(&files, &p) {
            return Err(StatusCode::NoSuchFile);
        }
        let prefix = if p == "/" {
            "/".to_string()
        } else {
            format!("{p}/")
        };
        let mut names: std::collections::BTreeSet<String> = Default::default();
        for k in files.keys() {
            if let Some(rest) = k.strip_prefix(&prefix) {
                if rest.is_empty() {
                    continue;
                }
                let first = rest.split('/').next().unwrap();
                names.insert(first.strip_suffix('@').unwrap_or(first).to_string());
            }
        }
        if p == "/" {
            names.insert("home".into());
        }
        if p == "/home" {
            names.insert("tester".into());
        }
        let entries = names
            .into_iter()
            .map(|n| {
                let full = format!("{prefix}{n}");
                let attrs = Self::attrs_for(&files, &full).unwrap_or_default();
                File::new(n, attrs)
            })
            .collect();
        drop(files);
        let h = self.handle();
        self.dirs.insert(h.clone(), Some(entries));
        Ok(Handle { id, handle: h })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        match self.dirs.get_mut(&handle) {
            Some(slot) => match slot.take() {
                Some(files) => Ok(Name { id, files }),
                None => Err(StatusCode::Eof),
            },
            None => Err(StatusCode::BadMessage),
        }
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        self.dirs.remove(&handle);
        Ok(Self::ok(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let p = Self::norm(&path);
        let mut files = self.files.lock().await;
        if Self::attrs_for(&files, &p).is_some() {
            return Err(StatusCode::Failure);
        }
        let parent = p
            .rsplit_once('/')
            .map(|(a, _)| if a.is_empty() { "/" } else { a })
            .unwrap_or("/");
        if !Self::is_dir(&files, parent) {
            return Err(StatusCode::NoSuchFile);
        }
        files.insert(format!("{p}/"), Vec::new());
        Ok(Self::ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let p = Self::norm(&path);
        let mut files = self.files.lock().await;
        let prefix = format!("{p}/");
        if files.keys().any(|k| k.starts_with(&prefix) && k != &prefix) {
            return Err(StatusCode::Failure);
        }
        files
            .remove(&prefix)
            .map(|_| Self::ok(id))
            .ok_or(StatusCode::NoSuchFile)
    }

    async fn remove(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let p = Self::norm(&path);
        let mut files = self.files.lock().await;
        files
            .remove(&p)
            .or_else(|| files.remove(&format!("{p}@")))
            .map(|_| Self::ok(id))
            .ok_or(StatusCode::NoSuchFile)
    }

    async fn rename(&mut self, id: u32, from: String, to: String) -> Result<Status, Self::Error> {
        let (f, t) = (Self::norm(&from), Self::norm(&to));
        let mut files = self.files.lock().await;
        let Some(data) = files.remove(&f) else {
            return Err(StatusCode::NoSuchFile);
        };
        files.insert(t, data);
        Ok(Self::ok(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        _path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        Ok(Self::ok(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = self
            .handles
            .get(&handle)
            .ok_or(StatusCode::BadMessage)?
            .path
            .clone();
        if let Some(size) = attrs.size {
            let mut files = self.files.lock().await;
            let buf = files.get_mut(&path).ok_or(StatusCode::NoSuchFile)?;
            buf.resize(size as usize, 0);
        }
        Ok(Self::ok(id))
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        flags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let p = Self::norm(&filename);
        let mut files = self.files.lock().await;
        let exists = files.contains_key(&p);
        if flags.contains(OpenFlags::CREATE) {
            if flags.contains(OpenFlags::EXCLUDE) && exists {
                return Err(StatusCode::Failure);
            }
            if !exists || flags.contains(OpenFlags::TRUNCATE) {
                files.insert(p.clone(), Vec::new());
            }
        } else if !exists {
            return Err(StatusCode::NoSuchFile);
        }
        drop(files);
        let h = self.handle();
        self.handles.insert(h.clone(), OpenFile { path: p, flags });
        Ok(Handle { id, handle: h })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let path = self
            .handles
            .get(&handle)
            .ok_or(StatusCode::BadMessage)?
            .path
            .clone();
        let files = self.files.lock().await;
        let data = files.get(&path).ok_or(StatusCode::NoSuchFile)?;
        let start = (offset as usize).min(data.len());
        if start == data.len() {
            return Err(StatusCode::Eof);
        }
        let end = (start + len as usize).min(data.len());
        Ok(Data {
            id,
            data: data[start..end].to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let f = self.handles.get(&handle).ok_or(StatusCode::BadMessage)?;
        if !f.flags.contains(OpenFlags::WRITE) {
            return Err(StatusCode::PermissionDenied);
        }
        let path = f.path.clone();
        let mut files = self.files.lock().await;
        let buf = files.get_mut(&path).ok_or(StatusCode::NoSuchFile)?;
        let end = offset as usize + data.len();
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[offset as usize..end].copy_from_slice(&data);
        Ok(Self::ok(id))
    }
}

// ---- harness -----------------------------------------------------------

struct Harness {
    port: u16,
    host_key: PublicKey,
    client_key: PrivateKey,
    authorized: Arc<std::sync::Mutex<Vec<PublicKey>>>,
    observed: Arc<Observed>,
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    store: Arc<Store>,
    kh: KnownHosts,
    _echo: Option<tokio::task::JoinHandle<()>>,
}

/// X11 connection setup packet (little-endian) carrying one auth token.
fn x11_setup(name: &[u8], data: &[u8]) -> Vec<u8> {
    let pad = |n: usize| (4 - n % 4) % 4;
    let mut p = vec![b'l', 0, 11, 0, 0, 0];
    p.extend_from_slice(&(name.len() as u16).to_le_bytes());
    p.extend_from_slice(&(data.len() as u16).to_le_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(name);
    p.extend(std::iter::repeat_n(0, pad(name.len())));
    p.extend_from_slice(data);
    p.extend(std::iter::repeat_n(0, pad(data.len())));
    p
}

async fn x11_roundtrip(
    handle: &russh::server::Handle,
    cookie_hex: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let cookie = hex::decode(cookie_hex)?;
    let ch = handle.channel_open_x11("127.0.0.1", 6000).await?;
    let mut s = ch.into_stream();
    s.write_all(&x11_setup(b"MIT-MAGIC-COOKIE-1", &cookie))
        .await?;
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await??;
    Ok(buf[..n].to_vec())
}

async fn echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (port, h)
}

async fn start() -> Harness {
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let client_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let (echo_port, echo) = echo_server().await;
    let observed = Arc::new(Observed::default());
    let files = Arc::new(Mutex::new(HashMap::new()));
    let authorized = Arc::new(std::sync::Mutex::new(vec![client_key.public_key().clone()]));
    let mut server = TestServer {
        authorized: authorized.clone(),
        observed: observed.clone(),
        files: files.clone(),
        tcp_echo: Some(echo_port),
    };
    let config = Arc::new(russh::server::Config {
        auth_rejection_time: Duration::from_millis(0),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key.clone()],
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = server.run_on_socket(config, &listener).await;
    });

    let store = Arc::new(Store::open_in_memory(SymmetricKey::generate()).unwrap());
    let vault = store.local_vault().unwrap().id;
    let kh = KnownHosts::new(store.clone(), vault);
    Harness {
        port,
        host_key: host_key.public_key().clone(),
        client_key,
        authorized,
        observed,
        files,
        store,
        kh,
        _echo: Some(echo),
    }
}

impl Harness {
    fn opts(&self, prompt: Arc<dyn termoso_core::hostkey::HostKeyPrompt>) -> ConnectOptions {
        let mut o = ConnectOptions::new(
            SshTarget {
                host: "127.0.0.1".into(),
                port: self.port,
                username: USER.into(),
            },
            self.kh.clone(),
            prompt,
        );
        o.timeout = Duration::from_secs(10);
        o
    }

    fn trusted(&self) -> ConnectOptions {
        self.kh
            .trust("127.0.0.1", self.port, &self.host_key)
            .unwrap();
        self.opts(Arc::new(StrictPrompt))
    }

    /// Add an `authorized_keys` line the server accepts.
    fn authorize(&self, public_key: &str) {
        let key = PublicKey::from_openssh(public_key).unwrap();
        self.authorized.lock().unwrap().push(key);
    }

    async fn connect_password(&self) -> SshClient {
        let mut o = self.trusted();
        o.auth
            .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
        SshClient::connect(o).await.unwrap()
    }
}

async fn collect_until_exit(
    events: &mut termoso_core::terminal::TermEvents,
) -> (Vec<u8>, Option<u32>) {
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .unwrap()
        {
            Some(TermEvent::Output(b)) => out.extend_from_slice(&b),
            Some(TermEvent::Exit { code, .. }) => return (out, code),
            Some(TermEvent::Closed) | None => return (out, None),
            Some(_) => {}
        }
    }
}

// ---- tests -------------------------------------------------------------

#[tokio::test]
async fn unknown_host_key_is_rejected_by_strict_prompt() {
    let h = start().await;
    let mut o = h.opts(Arc::new(StrictPrompt));
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    let err = SshClient::connect(o).await.err().unwrap();
    assert!(matches!(err, CoreError::HostKeyRejected { .. }), "{err:?}");
    assert!(matches!(
        h.kh.check("127.0.0.1", h.port, &h.host_key).unwrap(),
        HostKeyVerdict::Unknown { .. }
    ));
}

/// Prompt standing in for the UI's changed-key dialog: records what it was
/// shown and answers with a fixed decision even for a changed key.
struct RecordingPrompt {
    decision: HostKeyDecision,
    seen: std::sync::Mutex<Vec<HostKeyVerdict>>,
}

impl HostKeyPrompt for RecordingPrompt {
    fn decide(
        &self,
        verdict: HostKeyVerdict,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostKeyDecision> + Send + '_>> {
        self.seen.lock().unwrap().push(verdict);
        let d = self.decision;
        Box::pin(async move { d })
    }
}

#[tokio::test]
async fn changed_key_replace_and_connect_repins_and_drops_old_pin() {
    // The dialog gets both fingerprints; "Replace & connect" swaps the pin
    // so the next connection is silent, and the stale pin is gone.
    let h = start().await;
    let stale = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    h.kh.trust("127.0.0.1", h.port, stale.public_key()).unwrap();

    let prompt = Arc::new(RecordingPrompt {
        decision: HostKeyDecision::AcceptAndSave,
        seen: std::sync::Mutex::new(Vec::new()),
    });
    let mut o = h.opts(prompt.clone());
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    let c = SshClient::connect(o).await.unwrap();
    c.disconnect().await.unwrap();

    let seen = std::mem::take(&mut *prompt.seen.lock().unwrap());
    assert_eq!(seen.len(), 1);
    match &seen[0] {
        HostKeyVerdict::Changed { old, new } => {
            assert_eq!(old.fingerprint, hostkey::fingerprint(stale.public_key()));
            assert_eq!(new.fingerprint, hostkey::fingerprint(&h.host_key));
            assert_ne!(old.fingerprint, new.fingerprint);
            assert_eq!(old.key_type, new.key_type);
        }
        other => panic!("expected Changed, got {other:?}"),
    }

    assert_eq!(
        h.kh.check("127.0.0.1", h.port, &h.host_key).unwrap(),
        HostKeyVerdict::Known
    );
    let pins = h.kh.for_host("127.0.0.1", h.port).unwrap();
    assert_eq!(pins.len(), 1, "old pin replaced, not appended");

    // Silent now.
    let mut o = h.opts(Arc::new(StrictPrompt));
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    SshClient::connect(o)
        .await
        .unwrap()
        .disconnect()
        .await
        .unwrap();
}

#[tokio::test]
async fn changed_key_connect_once_keeps_old_pin() {
    let h = start().await;
    let stale = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    h.kh.trust("127.0.0.1", h.port, stale.public_key()).unwrap();

    let prompt = Arc::new(RecordingPrompt {
        decision: HostKeyDecision::AcceptOnce,
        seen: std::sync::Mutex::new(Vec::new()),
    });
    let mut o = h.opts(prompt.clone());
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    SshClient::connect(o)
        .await
        .unwrap()
        .disconnect()
        .await
        .unwrap();
    assert_eq!(prompt.seen.lock().unwrap().len(), 1);

    // Still flagged next time: nothing was written.
    assert!(matches!(
        h.kh.check("127.0.0.1", h.port, &h.host_key).unwrap(),
        HostKeyVerdict::Changed { .. }
    ));
    let pins = h.kh.for_host("127.0.0.1", h.port).unwrap();
    assert_eq!(pins.len(), 1);
    assert_eq!(
        pins[0].data.fingerprint,
        hostkey::fingerprint(stale.public_key())
    );
}

#[tokio::test]
async fn accept_and_save_pins_key_and_changed_key_is_refused() {
    let h = start().await;
    let mut o = h.opts(Arc::new(FixedPrompt(HostKeyDecision::AcceptAndSave)));
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    let c = SshClient::connect(o).await.unwrap();
    assert_eq!(c.banner(), Some("Welcome to the termoso test server"));
    assert_eq!(
        h.kh.check("127.0.0.1", h.port, &h.host_key).unwrap(),
        HostKeyVerdict::Known
    );
    c.disconnect().await.unwrap();

    // Pretend the server key rotated: pin a different key, then connect.
    let other = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    h.kh.trust("127.0.0.1", h.port, other.public_key()).unwrap();
    let mut o = h.opts(Arc::new(FixedPrompt(HostKeyDecision::AcceptAndSave)));
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    assert!(
        SshClient::connect(o).await.is_err(),
        "changed key must not be auto-accepted"
    );
    assert!(matches!(
        h.kh.check("127.0.0.1", h.port, &h.host_key).unwrap(),
        HostKeyVerdict::Changed { .. }
    ));
}

#[tokio::test]
async fn accept_once_does_not_persist() {
    let h = start().await;
    let mut o = h.opts(Arc::new(FixedPrompt(HostKeyDecision::AcceptOnce)));
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    SshClient::connect(o).await.unwrap();
    assert!(matches!(
        h.kh.check("127.0.0.1", h.port, &h.host_key).unwrap(),
        HostKeyVerdict::Unknown { .. }
    ));
}

#[tokio::test]
async fn wrong_password_then_key_succeeds_and_reports_remaining() {
    let h = start().await;
    let mut o = h.trusted();
    o.auth
        .push(AuthMethod::Password(Zeroizing::new("nope".into())));
    let err = SshClient::connect(o).await.err().unwrap();
    match err {
        CoreError::AuthFailed { remaining } => {
            assert!(remaining.iter().any(|m| m == "publickey"), "{remaining:?}")
        }
        e => panic!("{e:?}"),
    }

    let mut o = h.trusted();
    o.auth
        .push(AuthMethod::Password(Zeroizing::new("nope".into())));
    o.auth.push(AuthMethod::Key {
        private_key: Zeroizing::new(
            h.client_key
                .to_openssh(Default::default())
                .unwrap()
                .to_string(),
        ),
        passphrase: None,
        certificate: None,
    });
    SshClient::connect(o).await.unwrap();
}

#[tokio::test]
async fn encrypted_key_needs_passphrase() {
    let h = start().await;
    let enc = h.client_key.encrypt(&mut rand::rng(), b"pp").unwrap();
    let text = enc.to_openssh(Default::default()).unwrap().to_string();
    let mut o = h.trusted();
    o.auth.push(AuthMethod::Key {
        private_key: Zeroizing::new(text.clone()),
        passphrase: None,
        certificate: None,
    });
    assert!(matches!(
        SshClient::connect(o).await,
        Err(CoreError::Key(_))
    ));

    let mut o = h.trusted();
    o.auth.push(AuthMethod::Key {
        private_key: Zeroizing::new(text),
        passphrase: Some(Zeroizing::new("pp".into())),
        certificate: None,
    });
    SshClient::connect(o).await.unwrap();
}

/// Only the selected agent key is offered; the agent's other keys are not
/// tried, and a key the agent does not hold is an error, not a fallback.
#[cfg(unix)]
#[tokio::test]
async fn agent_key_offers_only_the_selected_key() {
    use termoso_core::agent::LocalAgent;

    let h = start().await;
    let dir = tempfile::tempdir().unwrap();
    let agent = LocalAgent::start(dir.path().join("agent.sock"))
        .await
        .unwrap();
    let other = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let chosen = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    agent.add_key(other.clone(), None).await.unwrap();
    agent.add_key(chosen.clone(), None).await.unwrap();
    h.authorize(&chosen.public_key().to_openssh().unwrap());
    let line = |k: &PrivateKey| k.public_key().to_openssh().unwrap();
    let offered = |h: &Harness| -> Vec<PublicKey> {
        std::mem::take(&mut *h.observed.offered.lock().unwrap())
    };

    let mut o = h.trusted();
    o.agent_socket = Some(agent.socket_path().to_path_buf());
    o.auth.push(AuthMethod::AgentKey {
        public_key: line(&chosen),
        certificate: None,
    });
    SshClient::connect(o).await.unwrap();
    assert_eq!(offered(&h), vec![chosen.public_key().clone()]);

    // Selected key is held but not authorized: fail without trying `other`
    // (which is not authorized either) or anything else.
    let mut o = h.trusted();
    o.agent_socket = Some(agent.socket_path().to_path_buf());
    o.auth.push(AuthMethod::AgentKey {
        public_key: line(&other),
        certificate: None,
    });
    assert!(matches!(
        SshClient::connect(o).await,
        Err(CoreError::AuthFailed { .. })
    ));
    assert_eq!(offered(&h), vec![other.public_key().clone()]);

    // Generic agent auth, by contrast, walks the agent's keys in the order
    // the agent lists them, stopping at the first one the server accepts.
    let mut o = h.trusted();
    o.agent_socket = Some(agent.socket_path().to_path_buf());
    o.auth.push(AuthMethod::Agent);
    SshClient::connect(o).await.unwrap();
    let tried = offered(&h);
    let mut ac = termoso_core::agent::connect_agent_at(agent.socket_path())
        .await
        .unwrap();
    let listed: Vec<PublicKey> = termoso_core::agent::list_keys(&mut ac)
        .await
        .unwrap()
        .iter()
        .map(|k| PublicKey::from_openssh(&k.public_key).unwrap())
        .collect();
    assert_eq!(listed.len(), 2);
    let pos = listed
        .iter()
        .position(|k| k.key_data() == chosen.public_key().key_data())
        .unwrap();
    assert_eq!(tried, listed[..=pos].to_vec());

    // Key the agent does not hold.
    let absent = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    h.authorize(&line(&absent));
    let mut o = h.trusted();
    o.agent_socket = Some(agent.socket_path().to_path_buf());
    o.auth.push(AuthMethod::AgentKey {
        public_key: line(&absent),
        certificate: None,
    });
    match SshClient::connect(o).await {
        Err(CoreError::Key(msg)) => assert!(msg.contains("does not hold"), "{msg}"),
        r => panic!("{r:?}"),
    }
    assert!(offered(&h).is_empty());

    // Agent unreachable.
    let mut o = h.trusted();
    o.agent_socket = Some(dir.path().join("missing.sock"));
    o.auth.push(AuthMethod::AgentKey {
        public_key: line(&chosen),
        certificate: None,
    });
    assert!(matches!(
        SshClient::connect(o).await,
        Err(CoreError::Ssh(_))
    ));

    // A certificate for a different key than the selected one is rejected
    // before anything reaches the server.
    let cert = {
        use russh::keys::ssh_key::certificate::{Builder, CertType};
        let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let mut b = Builder::new(
            [0u8; 16],
            chosen.public_key().key_data().clone(),
            0,
            u64::MAX,
        )
        .unwrap();
        b.cert_type(CertType::User).unwrap();
        b.all_principals_valid().unwrap();
        b.key_id("test").unwrap();
        b.sign(&ca).unwrap().to_openssh().unwrap()
    };
    let mut o = h.trusted();
    o.agent_socket = Some(agent.socket_path().to_path_buf());
    o.auth.push(AuthMethod::AgentKey {
        public_key: line(&other),
        certificate: Some(cert),
    });
    match SshClient::connect(o).await {
        Err(CoreError::Key(msg)) => assert!(msg.contains("different key"), "{msg}"),
        r => panic!("{r:?}"),
    }
    assert!(offered(&h).is_empty());
}

/// Records the phases the connector reports.
#[derive(Default)]
struct Phases(std::sync::Mutex<Vec<termoso_core::ssh::ConnectPhase>>);

impl termoso_core::ssh::ConnectProgress for Phases {
    fn phase(&self, phase: termoso_core::ssh::ConnectPhase) {
        self.0.lock().unwrap().push(phase);
    }
}

/// Security-key auth end to end: the `sk-*` key is minted on the software
/// authenticator, the server gets its `authorized_keys` line, and the
/// signature travels through CTAPHID / NFC framing on the way.
async fn sk_login(wire: soft::Wire, alg: SkAlgorithm, user_verification: bool) {
    let h = start().await;
    let token = soft::SoftToken::default();
    let backend = Arc::new(soft::SoftBackend::new(token.clone(), wire));
    let material = backend
        .with(|a| {
            a.generate(&GenerateOptions {
                device: None,
                algorithm: alg,
                application: None,
                resident: false,
                user_presence: true,
                user_verification,
                pin: Some(Zeroizing::new("123456".into())),
                user: None,
                comment: "phone".into(),
                passphrase: Some(Zeroizing::new("pp".into())),
            })
        })
        .unwrap();
    h.authorize(&material.public_key);
    let touches_before = token.touches();

    let phases = Arc::new(Phases::default());
    let mut o = h.trusted();
    o.progress = Some(phases.clone());
    o.auth.push(AuthMethod::SecurityKey {
        private_key: material.private_key.clone(),
        passphrase: Some(Zeroizing::new("pp".into())),
        pin: user_verification.then(|| Zeroizing::new("123456".into())),
        backend: backend.clone(),
        certificate: None,
    });
    let client = SshClient::connect(o).await.unwrap();
    assert_eq!(
        token.touches(),
        touches_before + 1,
        "one touch per signature"
    );
    assert!(
        phases
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|p| matches!(p, termoso_core::ssh::ConnectPhase::SecurityKeyTouch { .. })),
        "UI must be told to touch the key"
    );
    client.disconnect().await.unwrap();

    // Same handle on a token that never saw the credential → typed error.
    let stranger = Arc::new(soft::SoftBackend::new(soft::SoftToken::default(), wire));
    let mut o = h.trusted();
    o.auth.push(AuthMethod::SecurityKey {
        private_key: material.private_key.clone(),
        passphrase: Some(Zeroizing::new("pp".into())),
        pin: Some(Zeroizing::new("123456".into())),
        backend: stranger,
        certificate: None,
    });
    assert!(matches!(
        SshClient::connect(o).await,
        Err(CoreError::Fido2(
            termoso_core::fido2::Fido2Error::WrongDevice
        ))
    ));

    if user_verification {
        // verify-required key without a PIN → the token asks for one.
        let mut o = h.trusted();
        o.auth.push(AuthMethod::SecurityKey {
            private_key: material.private_key.clone(),
            passphrase: Some(Zeroizing::new("pp".into())),
            pin: None,
            backend: backend.clone(),
            certificate: None,
        });
        assert!(matches!(
            SshClient::connect(o).await,
            Err(CoreError::Fido2(
                termoso_core::fido2::Fido2Error::PinRequired
            ))
        ));
    }

    // User walks away → timeout surfaces as such, not as a generic auth failure.
    token.configure(|c| c.touch = soft::Touch::Timeout);
    let mut o = h.trusted();
    o.auth.push(AuthMethod::SecurityKey {
        private_key: material.private_key,
        passphrase: Some(Zeroizing::new("pp".into())),
        pin: Some(Zeroizing::new("123456".into())),
        backend,
        certificate: None,
    });
    assert!(matches!(
        SshClient::connect(o).await,
        Err(CoreError::Fido2(termoso_core::fido2::Fido2Error::Timeout))
    ));
}

#[tokio::test]
async fn security_key_ed25519_over_hid() {
    sk_login(soft::Wire::Hid, SkAlgorithm::Ed25519, false).await;
}

#[tokio::test]
async fn security_key_p256_over_nfc() {
    sk_login(soft::Wire::Nfc, SkAlgorithm::EcdsaP256, false).await;
}

#[tokio::test]
async fn security_key_verify_required() {
    sk_login(soft::Wire::Direct, SkAlgorithm::Ed25519, true).await;
}

#[tokio::test]
async fn security_key_resident_key_loaded_from_token_logs_in() {
    let h = start().await;
    let token = soft::SoftToken::default();
    let minter = soft::SoftBackend::new(token.clone(), soft::Wire::Direct);
    let original = minter
        .with(|a| {
            a.generate(&GenerateOptions {
                device: None,
                algorithm: SkAlgorithm::EcdsaP256,
                application: None,
                resident: true,
                user_presence: true,
                user_verification: false,
                pin: Some(Zeroizing::new("123456".into())),
                user: Some(USER.into()),
                comment: String::new(),
                passphrase: None,
            })
        })
        .unwrap();
    h.authorize(&original.public_key);

    // "Another phone": nothing stored locally, key handle comes from the token.
    let backend = Arc::new(soft::SoftBackend::new(token, soft::Wire::Hid));
    let loaded = backend.with(|a| a.load_resident("123456", None)).unwrap();
    assert_eq!(loaded.len(), 1);
    let mut o = h.trusted();
    o.auth.push(AuthMethod::SecurityKey {
        private_key: loaded[0].private_key.clone(),
        passphrase: None,
        pin: None,
        backend,
        certificate: None,
    });
    SshClient::connect(o).await.unwrap();
}

#[tokio::test]
async fn keyboard_interactive_uses_prompt_responder() {
    let h = start().await;
    let mut o = h.trusted();
    o.auth.push(AuthMethod::KeyboardInteractive);
    o.interactive = Some(Arc::new(PasswordResponder(Zeroizing::new(PASSWORD.into()))));
    SshClient::connect(o).await.unwrap();
    assert!(h.observed.kbd_rounds.load(Ordering::SeqCst) >= 2);

    let mut o = h.trusted();
    o.auth.push(AuthMethod::KeyboardInteractive);
    assert!(SshClient::connect(o).await.is_err(), "no responder = fail");
}

#[tokio::test]
async fn shell_streams_echo_resizes_and_exits() {
    let h = start().await;
    let c = h.connect_password().await;
    let (term, mut events) = c
        .shell(
            "xterm-256color",
            TermSize {
                cols: 120,
                rows: 40,
            },
        )
        .await
        .unwrap();
    assert_eq!(term.kind(), "ssh");
    assert_eq!(
        *h.observed.pty.lock().await,
        Some(("xterm-256color".into(), 120, 40))
    );

    term.write(b"hello\n").await.unwrap();
    term.resize(TermSize { cols: 90, rows: 30 }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(*h.observed.resized.lock().await, Some((90, 30)));
    term.write(b"exit\n").await.unwrap();

    let (out, code) = collect_until_exit(&mut events).await;
    let s = String::from_utf8_lossy(&out);
    assert!(s.starts_with("prompt$ "), "{s:?}");
    assert!(s.contains("hello\n") && s.ends_with("bye\n"), "{s:?}");
    assert_eq!(code, Some(3));
    assert!(matches!(term.write(b"x").await, Err(CoreError::Closed)));
}

#[tokio::test]
async fn exec_returns_stdout_stderr_and_status() {
    let h = start().await;
    let c = h.connect_password().await;
    let ok = c.exec("whoami", None).await.unwrap();
    assert_eq!(ok.stdout, b"tester\n");
    assert_eq!(ok.exit_code, Some(0));
    let bad = c.exec("fail", None).await.unwrap();
    assert_eq!(bad.stderr, b"boom\n");
    assert_eq!(bad.exit_code, Some(7));
    let cat = c
        .exec("cat", Some(Bytes::from_static(b"piped")))
        .await
        .unwrap();
    assert_eq!(cat.stdout, b"piped");
    assert_eq!(cat.exit_code, Some(0));
}

#[tokio::test]
async fn detects_os_and_reports_negotiated_algorithms() {
    let h = start().await;
    let c = h.connect_password().await;
    assert!(
        c.server_id().is_some_and(|id| id.starts_with("SSH-2.0-")),
        "{:?}",
        c.server_id()
    );
    let algs = c.algorithms().expect("kex_done recorded");
    assert_eq!(algs.host_key, "ssh-ed25519");
    assert!(
        algs.post_quantum(),
        "default kex should be hybrid: {algs:?}"
    );
    assert_eq!(termoso_core::osdetect::detect(&c).await, Some("rocky"));

    let mut o = h.trusted();
    o.post_quantum_kex = false;
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    let classical = SshClient::connect(o).await.unwrap();
    let algs = classical.algorithms().unwrap();
    assert!(!algs.post_quantum(), "{algs:?}");
}

#[tokio::test]
async fn env_is_sent_before_shell() {
    let h = start().await;
    let mut o = h.trusted();
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    o.env.push(("LANG".into(), "C.UTF-8".into()));
    let c = SshClient::connect(o).await.unwrap();
    let _ = c.shell("xterm", TermSize::default()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        h.observed.env.lock().await.as_slice(),
        &[("LANG".to_string(), "C.UTF-8".to_string())]
    );
}

/// Fake local X server on a Unix socket: checks the cookie it receives and
/// answers with a marker the remote "X client" prints.
#[cfg(unix)]
#[tokio::test]
async fn x11_forwarding_bridges_remote_client_to_local_display_with_real_cookie() {
    use termoso_core::ssh::x11::{DisplayTarget, LocalDisplay};

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("X7");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                break;
            };
            let seen = seen2.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 128];
                let n = s.read(&mut buf).await.unwrap_or(0);
                *seen.lock().await = buf[..n].to_vec();
                let _ = s.write_all(b"xserver-ok").await;
            });
        }
    });

    let display = LocalDisplay {
        target: DisplayTarget::Unix(sock),
        number: 7,
        screen: 3,
    };
    let fwd = Arc::new(X11Forward::with_cookies(
        display,
        Some(b"REAL-LOCAL-COOKIE".to_vec()),
    ));
    let fake_hex = fwd.fake_cookie_hex();

    let h = start().await;
    let mut o = h.trusted();
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    o.x11 = Some(fwd);
    let c = SshClient::connect(o).await.unwrap();

    let out = c.exec("xclient", None).await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "xserver-ok",
        "{out:?}"
    );
    assert_eq!(out.exit_code, Some(0));

    let req = h.observed.x11.lock().await.clone().expect("x11-req sent");
    assert_eq!(req.0, "MIT-MAGIC-COOKIE-1");
    assert_eq!(req.1, fake_hex);
    assert_eq!(req.2, 3);

    // The local X server saw the real cookie, never the fake one.
    let packet = seen.lock().await.clone();
    let fake = hex::decode(&fake_hex).unwrap();
    assert!(
        packet.windows(17).any(|w| w == b"REAL-LOCAL-COOKIE"),
        "{packet:?}"
    );
    assert!(!packet.windows(16).any(|w| w == fake.as_slice()));
}

/// Without forwarding configured the client sends no `x11-req` and refuses
/// X11 channels the server tries to open.
#[tokio::test]
async fn x11_channel_is_refused_when_forwarding_is_off() {
    let h = start().await;
    let c = h.connect_password().await;
    let out = c.exec("xclient", None).await.unwrap();
    assert!(h.observed.x11.lock().await.is_none());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("x11 error:"), "{text}");
}

#[tokio::test]
async fn disconnect_closes_transport() {
    let h = start().await;
    let c = h.connect_password().await;
    assert!(!c.is_closed());
    c.disconnect().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), c.closed())
        .await
        .unwrap();
    assert!(c.is_closed());
}

#[tokio::test]
async fn sftp_open_file_positional() {
    let h = start().await;
    let c = h.connect_password().await;
    let sftp = Sftp::open(&c).await.unwrap();
    sftp.mkdir_all("/home/tester/d").await.unwrap();

    // Write mode creates; writes land at their offsets and grow the file.
    let f = sftp
        .open_file("/home/tester/d/new.bin", OpenMode::Write)
        .await
        .unwrap();
    f.write_at(0, b"hello").await.unwrap();
    f.write_at(5, b" world").await.unwrap();
    f.sync().await.unwrap();
    assert_eq!(f.size().await.unwrap(), 11);
    f.close().await.unwrap();
    assert_eq!(
        h.files.lock().await.get("/home/tester/d/new.bin").unwrap(),
        b"hello world"
    );

    // Read mode: ranged reads over a file larger than one SFTP chunk,
    // short at the end, empty past it, never read whole.
    let payload: Vec<u8> = (0..(600 * 1024)).map(|i| (i % 253) as u8).collect();
    h.files
        .lock()
        .await
        .insert("/home/tester/d/big.bin".into(), payload.clone());
    let f = sftp
        .open_file("/home/tester/d/big.bin", OpenMode::Read)
        .await
        .unwrap();
    assert_eq!(f.size().await.unwrap(), payload.len() as u64);
    assert_eq!(f.read_at(0, 10).await.unwrap(), &payload[..10]);
    // Sequential chunks continue the stream; a backwards jump reseeks.
    let mut seq = Vec::new();
    while seq.len() < 200 * 1024 {
        seq.extend(f.read_at(10 + seq.len() as u64, 128 * 1024).await.unwrap());
    }
    assert_eq!(seq, &payload[10..10 + seq.len()]);
    assert_eq!(f.read_at(3, 20).await.unwrap(), &payload[3..23]);
    let mid = 300 * 1024 - 7;
    assert_eq!(
        f.read_at(mid as u64, 64 * 1024).await.unwrap(),
        &payload[mid..mid + 64 * 1024]
    );
    let tail = payload.len() - 100;
    assert_eq!(
        f.read_at(tail as u64, 4096).await.unwrap(),
        &payload[tail..]
    );
    assert!(
        f.read_at(payload.len() as u64 + 10, 16)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(f.write_at(0, b"x").await.is_err());
    f.close().await.unwrap();

    // ReadWrite keeps contents, edits in place, truncates.
    let f = sftp
        .open_file("/home/tester/d/new.bin", OpenMode::ReadWrite)
        .await
        .unwrap();
    assert_eq!(f.read_at(6, 5).await.unwrap(), b"world");
    f.write_at(6, b"there").await.unwrap();
    f.truncate(5).await.unwrap();
    assert_eq!(f.size().await.unwrap(), 5);
    f.close().await.unwrap();
    assert_eq!(
        h.files.lock().await.get("/home/tester/d/new.bin").unwrap(),
        b"hello"
    );

    // Directories and missing files are refused up front.
    assert!(
        sftp.open_file("/home/tester/d", OpenMode::Read)
            .await
            .is_err()
    );
    assert!(
        sftp.open_file("/home/tester/d", OpenMode::ReadWrite)
            .await
            .is_err()
    );
    assert!(matches!(
        sftp.open_file("/home/tester/d/nope", OpenMode::Read).await,
        Err(CoreError::NotFound(_))
    ));
}

#[tokio::test]
async fn sftp_end_to_end() {
    let h = start().await;
    let c = h.connect_password().await;
    let sftp = Sftp::open(&c).await.unwrap();
    assert_eq!(sftp.home(), "/home/tester");

    sftp.mkdir_all("/home/tester/a/b").await.unwrap();
    sftp.write("/home/tester/a/b/f.txt", b"hello sftp")
        .await
        .unwrap();
    assert_eq!(
        sftp.read("/home/tester/a/b/f.txt").await.unwrap(),
        b"hello sftp"
    );
    let st = sftp.stat("a/b/f.txt").await.unwrap();
    assert_eq!(st.size, Some(10));
    assert_eq!(st.kind, termoso_core::sftp::EntryKind::File);
    assert!(sftp.exists("a/b").await.unwrap());
    assert!(!sftp.exists("a/zzz").await.unwrap());
    assert!(matches!(
        sftp.stat("nope").await,
        Err(CoreError::NotFound(_))
    ));

    let list = sftp.list("/home/tester/a/b").await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "f.txt");
    assert_eq!(list[0].path, "/home/tester/a/b/f.txt");

    // A directory full of symlinks: every target is resolved (concurrently)
    // and a dangling link still lists, just without a target kind.
    sftp.mkdir_all("/home/tester/a/links").await.unwrap();
    for i in 0..40 {
        sftp.symlink(
            &format!("/home/tester/a/links/l{i:02}"),
            "/home/tester/a/b/f.txt",
        )
        .await
        .unwrap();
    }
    sftp.symlink("/home/tester/a/links/dir", "/home/tester/a/b")
        .await
        .unwrap();
    sftp.symlink("/home/tester/a/links/dangling", "/home/tester/a/nope")
        .await
        .unwrap();
    let links = sftp.list("/home/tester/a/links").await.unwrap();
    assert_eq!(links.len(), 42);
    for e in &links {
        assert_eq!(e.kind, termoso_core::sftp::EntryKind::Symlink, "{}", e.name);
        assert_eq!(e.path, format!("/home/tester/a/links/{}", e.name));
    }
    let by_name = |n: &str| links.iter().find(|e| e.name == n).unwrap();
    assert_eq!(
        by_name("l00").link_target.as_deref(),
        Some("/home/tester/a/b/f.txt")
    );
    assert_eq!(
        by_name("l39").target_kind,
        Some(termoso_core::sftp::EntryKind::File)
    );
    assert_eq!(
        by_name("dir").target_kind,
        Some(termoso_core::sftp::EntryKind::Dir)
    );
    assert_eq!(
        by_name("dangling").link_target.as_deref(),
        Some("/home/tester/a/nope")
    );
    assert_eq!(by_name("dangling").target_kind, None);
    sftp.remove_dir_all("/home/tester/a/links", &Default::default())
        .await
        .unwrap();
    assert!(!sftp.exists("a/links").await.unwrap());
    assert!(sftp.exists("a/b/f.txt").await.unwrap());

    sftp.rename("/home/tester/a/b/f.txt", "/home/tester/a/g.txt")
        .await
        .unwrap();
    let names: Vec<_> = sftp
        .list("a")
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec!["b", "g.txt"]);
    sftp.chmod("a/g.txt", 0o600).await.unwrap();

    // upload / download with progress + resume
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("big.bin");
    let payload: Vec<u8> = (0..(700 * 1024)).map(|i| (i % 251) as u8).collect();
    std::fs::write(&local, &payload).unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let opts = TransferOptions {
        progress: Some(Arc::new(move |p| s2.lock().unwrap().push(p))),
        ..TransferOptions::default()
    };
    let n = sftp.upload(&local, "a/big.bin", &opts).await.unwrap();
    assert_eq!(n, payload.len() as u64);
    {
        let prog = seen.lock().unwrap();
        assert!(prog.len() >= 3, "{}", prog.len());
        assert_eq!(prog.last().unwrap().done, payload.len() as u64);
        assert_eq!(prog.last().unwrap().total, Some(payload.len() as u64));
    }
    assert_eq!(
        h.files.lock().await.get("/home/tester/a/big.bin").unwrap(),
        &payload
    );

    // Partial local copy → resume downloads only the tail.
    let out = dir.path().join("out.bin");
    std::fs::write(&out, &payload[..300_000]).unwrap();
    let opts = TransferOptions {
        resume: true,
        ..TransferOptions::default()
    };
    let n = sftp.download("a/big.bin", &out, &opts).await.unwrap();
    assert_eq!(n, (payload.len() - 300_000) as u64);
    assert_eq!(std::fs::read(&out).unwrap(), payload);

    // Partial remote copy → resume uploads only the tail.
    h.files.lock().await.insert(
        "/home/tester/a/part.bin".into(),
        payload[..200_000].to_vec(),
    );
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let opts = TransferOptions {
        resume: true,
        progress: Some(Arc::new(move |p| s2.lock().unwrap().push(p))),
        ..TransferOptions::default()
    };
    let n = sftp.upload(&local, "a/part.bin", &opts).await.unwrap();
    assert_eq!(n, (payload.len() - 200_000) as u64);
    assert_eq!(seen.lock().unwrap()[0].done, 200_000);
    assert_eq!(
        h.files.lock().await.get("/home/tester/a/part.bin").unwrap(),
        &payload
    );

    // Remote longer than local → start over instead of appending garbage.
    let mut longer = payload.clone();
    longer.extend_from_slice(b"stale tail");
    h.files
        .lock()
        .await
        .insert("/home/tester/a/long.bin".into(), longer);
    let opts = TransferOptions {
        resume: true,
        ..TransferOptions::default()
    };
    let n = sftp.upload(&local, "a/long.bin", &opts).await.unwrap();
    assert_eq!(n, payload.len() as u64);
    assert_eq!(
        h.files.lock().await.get("/home/tester/a/long.bin").unwrap(),
        &payload
    );

    // Cancel mid-download: the partial file stays and a resume finishes it.
    let cancel = tokio_util::sync::CancellationToken::new();
    let c2 = cancel.clone();
    let part = dir.path().join("part.bin");
    let opts = TransferOptions {
        cancel,
        progress: Some(Arc::new(move |p| {
            if p.done > 0 {
                c2.cancel();
            }
        })),
        ..TransferOptions::default()
    };
    assert!(matches!(
        sftp.download("a/big.bin", &part, &opts).await,
        Err(CoreError::Cancelled)
    ));
    let have = std::fs::metadata(&part).unwrap().len();
    assert!(have > 0 && have < payload.len() as u64, "{have}");
    assert_eq!(
        &std::fs::read(&part).unwrap()[..],
        &payload[..have as usize]
    );
    let opts = TransferOptions {
        resume: true,
        ..TransferOptions::default()
    };
    let n = sftp.download("a/big.bin", &part, &opts).await.unwrap();
    assert_eq!(n, payload.len() as u64 - have);
    assert_eq!(std::fs::read(&part).unwrap(), payload);

    // Cancel mid-upload likewise keeps the remote prefix intact.
    let cancel = tokio_util::sync::CancellationToken::new();
    let c2 = cancel.clone();
    let opts = TransferOptions {
        cancel,
        progress: Some(Arc::new(move |p| {
            if p.done > 0 {
                c2.cancel();
            }
        })),
        ..TransferOptions::default()
    };
    assert!(matches!(
        sftp.upload(&local, "a/cut.bin", &opts).await,
        Err(CoreError::Cancelled)
    ));
    let have = h
        .files
        .lock()
        .await
        .get("/home/tester/a/cut.bin")
        .unwrap()
        .len();
    assert!(have > 0 && have < payload.len(), "{have}");
    let opts = TransferOptions {
        resume: true,
        ..TransferOptions::default()
    };
    let n = sftp.upload(&local, "a/cut.bin", &opts).await.unwrap();
    assert_eq!(n, (payload.len() - have) as u64);
    assert_eq!(
        h.files.lock().await.get("/home/tester/a/cut.bin").unwrap(),
        &payload
    );

    // Cancel before start.
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    let opts = TransferOptions {
        cancel,
        ..TransferOptions::default()
    };
    assert!(matches!(
        sftp.download("a/big.bin", &dir.path().join("x"), &opts)
            .await,
        Err(CoreError::Cancelled)
    ));

    sftp.remove_dir_all("/home/tester/a", &Default::default())
        .await
        .unwrap();
    assert!(!sftp.exists("a").await.unwrap());
    sftp.close().await.unwrap();
}

#[tokio::test]
async fn local_forward_pipes_through_server() {
    let h = start().await;
    let c = Arc::new(h.connect_password().await);
    let fwd = Forward::start(
        c.clone(),
        ForwardSpec::Local {
            bind: "127.0.0.1".into(),
            port: 0,
            remote_host: "echo.internal".into(),
            remote_port: 7,
        },
    )
    .await
    .unwrap();
    let addr = fwd.local_addr().unwrap();
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(b"round trip").await.unwrap();
    let mut buf = [0u8; 10];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"round trip");
    drop(s);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(fwd.stats().connections.load(Ordering::Relaxed), 1);
    fwd.stop().await;
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_err() || {
            // listener may still be draining; a second connect must fail soon
            tokio::time::sleep(Duration::from_millis(100)).await;
            tokio::net::TcpStream::connect(addr).await.is_err()
        }
    );
}

#[tokio::test]
async fn dynamic_socks5_forward() {
    let h = start().await;
    let c = Arc::new(h.connect_password().await);
    let fwd = Forward::start(
        c,
        ForwardSpec::Dynamic {
            bind: "127.0.0.1".into(),
            port: 0,
        },
    )
    .await
    .unwrap();
    let mut s = tokio::net::TcpStream::connect(fwd.local_addr().unwrap())
        .await
        .unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 0]);
    let mut req = vec![5, 1, 0, 3, 13];
    req.extend_from_slice(b"echo.internal");
    req.extend_from_slice(&7u16.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0);
    s.write_all(b"socks!").await.unwrap();
    let mut buf = [0u8; 6];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"socks!");

    // refused destination → reply 5
    let mut s = tokio::net::TcpStream::connect(fwd.local_addr().unwrap())
        .await
        .unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    s.read_exact(&mut r).await.unwrap();
    let mut req = vec![5, 1, 0, 1, 10, 0, 0, 1];
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).await.unwrap();
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 5);
}

#[tokio::test]
async fn remote_forward_delivers_server_connections_locally() {
    let h = start().await;
    let (echo_port, _echo) = echo_server().await;
    let c = Arc::new(h.connect_password().await);
    let fwd = Forward::start(
        c.clone(),
        ForwardSpec::Remote {
            bind: "localhost".into(),
            port: 0,
            local_host: "127.0.0.1".into(),
            local_port: echo_port,
        },
    )
    .await
    .unwrap();
    assert_eq!(fwd.remote_port(), Some(40_000));
    assert_eq!(
        h.observed.forward_requests.lock().await.as_slice(),
        &[("localhost".to_string(), 40_000)]
    );

    // The server "connects" once (see tcpip_forward) → our echo server → back.
    tokio::time::timeout(Duration::from_secs(5), async {
        while fwd.stats().connections.load(Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while fwd.stats().bytes_in.load(Ordering::Relaxed) < 16 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    fwd.stop().await;
    assert!(h.observed.cancelled_forwards.load(Ordering::SeqCst));
}

#[tokio::test]
async fn two_hop_jump_chain_reaches_final_host() {
    // bastion -> relay -> target: every hop is a separate server with its own
    // host key, and the final exec must run on the last one.
    let bastion = start().await;
    let relay = start().await;
    let target = start().await;

    let first = bastion.connect_password().await;

    let mut o = relay.trusted();
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    let second = SshClient::connect_via(&first, o).await.unwrap();

    let mut o = target.trusted();
    o.auth.push(AuthMethod::Key {
        private_key: Zeroizing::new(
            target
                .client_key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
        ),
        passphrase: None,
        certificate: None,
    });
    let third = SshClient::connect_via(&second, o).await.unwrap();

    let out = third.exec("whoami", None).await.unwrap();
    assert_eq!(out.stdout, b"tester\n");
    assert!(!first.is_closed() && !second.is_closed());

    // Each hop trusted its own key; nothing leaked across stores.
    assert_eq!(bastion.kh.all().unwrap().len(), 1);
    assert_eq!(relay.kh.all().unwrap().len(), 1);
    assert_eq!(target.kh.all().unwrap().len(), 1);

    // Tearing down the bastion transport takes the inner hops with it.
    first.disconnect().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), third.closed())
        .await
        .expect("inner hop must close when the outer transport is gone");
}

#[tokio::test]
async fn jump_host_changed_key_is_rejected_by_strict_prompt() {
    // A MITM on the second hop presents a different key than the one on
    // record; StrictPrompt must refuse and the bastion must stay usable.
    let bastion = start().await;
    let target = start().await;
    let first = bastion.connect_password().await;

    let imposter = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    target
        .kh
        .trust("127.0.0.1", target.port, imposter.public_key())
        .unwrap();
    let mut o = target.opts(Arc::new(StrictPrompt));
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    let err = SshClient::connect_via(&first, o).await.err().unwrap();
    assert!(matches!(err, CoreError::HostKeyRejected { .. }), "{err:?}");
    assert!(matches!(
        target
            .kh
            .check("127.0.0.1", target.port, &target.host_key)
            .unwrap(),
        HostKeyVerdict::Changed { .. }
    ));
    assert!(!first.is_closed());
}

/// Minimal no-auth SOCKS5 relay that dials whatever the client asks for.
async fn socks5_relay() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut g = [0u8; 2];
                s.read_exact(&mut g).await.unwrap();
                let mut methods = vec![0u8; g[1] as usize];
                s.read_exact(&mut methods).await.unwrap();
                s.write_all(&[5, 0]).await.unwrap();
                let mut head = [0u8; 4];
                s.read_exact(&mut head).await.unwrap();
                assert_eq!(head[3], 1, "client sends IPv4 literals inline");
                let mut addr = [0u8; 6];
                s.read_exact(&mut addr).await.unwrap();
                let ip = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                let port = u16::from_be_bytes([addr[4], addr[5]]);
                let mut up = tokio::net::TcpStream::connect((ip, port)).await.unwrap();
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn ssh_over_socks5_proxy_then_jump() {
    // proxy -> bastion -> target, exercising the proxied TCP leg together
    // with a direct-tcpip hop on top of it.
    let bastion = start().await;
    let target = start().await;
    let proxy_port = socks5_relay().await;

    let mut o = bastion.trusted();
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    o.proxy = Some(termoso_core::ssh::proxy::ProxyConfig {
        kind: termoso_core::ssh::proxy::ProxyKind::Socks5,
        host: "127.0.0.1".into(),
        port: proxy_port,
        username: None,
        password: None,
    });
    let first = SshClient::connect(o).await.unwrap();

    let mut o = target.trusted();
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    let second = SshClient::connect_via(&first, o).await.unwrap();
    let out = second.exec("whoami", None).await.unwrap();
    assert_eq!(out.stdout, b"tester\n");
    second.disconnect().await.unwrap();
    first.disconnect().await.unwrap();
}

#[tokio::test]
async fn jump_host_chain() {
    // An unreachable target behind the jump yields a typed error and leaves
    // the jump session alive.
    let h = start().await;
    let jump = h.connect_password().await;
    let mut o = h.trusted();
    o.target.host = "unreachable.internal".into();
    o.auth
        .push(AuthMethod::Password(Zeroizing::new(PASSWORD.into())));
    let err = SshClient::connect_via(&jump, o).await.err().unwrap();
    assert!(matches!(err, CoreError::Ssh(_)), "{err:?}");
    assert!(!jump.is_closed());
    let _ = h.store.local_vault().unwrap();
}
