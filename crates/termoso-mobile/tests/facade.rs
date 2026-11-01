//! The façade as Kotlin sees it: open a profile, edit hosts / keys /
//! settings, then drive an SSH session against an in-process `russh`
//! server through the listener callbacks.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use russh::keys::ssh_key::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Server as _, Session};
use russh::{Channel, ChannelId, MethodSet};
#[cfg(unix)]
use termoso_mobile::LocalShell;
use termoso_mobile::{
    ConnectStage, HostKeyChoice, IdentityDraft, KeyAlgorithm, KeyGenerateDraft, KeyImportDraft,
    LiveEndReason, LiveListener, LiveParticipantCard, MobileError, PfKind, PfRuleDraft,
    PromptAnswer, PromptRequest, QuickTarget, SessionListener, SessionState, SftpListener,
    SshIdKeyKind, SshSession, TelnetDraft, TerminalOptions, TermosoApp, TransferCard, Transport,
    TunnelListener, TunnelState, VaultKind, WebDavDraft, flag, generate_master_key, is_live_link,
    parse_target, profile_exists, sshid_handle_valid,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const USER: &str = "tester";
const PASSWORD: &str = "s3cret";

/// Detached `mosh-server` processes the test sshd started; killed on exit.
static MOSH_PIDS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

struct KillMoshServers;

impl Drop for KillMoshServers {
    fn drop(&mut self) {
        for pid in MOSH_PIDS.lock().unwrap().drain(..) {
            let _ = std::process::Command::new("kill")
                .arg(pid.to_string())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
}

fn mosh_server_installed() -> bool {
    let ok = std::process::Command::new("sh")
        .args(["-c", "command -v mosh-server"])
        .stdout(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        assert!(
            std::env::var("TERMOSO_TEST_REQUIRE_MOSH").is_err(),
            "mosh-server not installed but TERMOSO_TEST_REQUIRE_MOSH is set"
        );
        eprintln!("mosh-server not installed; skipping");
    }
    ok
}

// ---- tiny SSH server ------------------------------------------------------

#[derive(Clone, Default)]
struct Srv {
    kbd: bool,
    /// Accept any public key for `USER` instead of a password.
    pubkey: bool,
}

struct Handler {
    srv: Srv,
    shells: HashMap<ChannelId, ()>,
}

impl russh::server::Server for Srv {
    type Handler = Handler;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Handler {
        Handler {
            srv: self.clone(),
            shells: HashMap::new(),
        }
    }
}

impl Handler {
    fn offered(&self) -> Auth {
        let methods: &[russh::MethodKind] = if self.srv.kbd {
            &[russh::MethodKind::KeyboardInteractive]
        } else if self.srv.pubkey {
            &[russh::MethodKind::PublicKey]
        } else {
            &[russh::MethodKind::Password]
        };
        Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(methods)),
            partial_success: false,
        }
    }
}

impl russh::server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(self.offered())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if !self.srv.kbd && user == USER && password == PASSWORD {
            Auth::Accept
        } else {
            self.offered()
        })
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _offer: russh::server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(if self.srv.pubkey {
            Auth::Accept
        } else {
            self.offered()
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(if self.srv.pubkey && user == USER {
            Auth::Accept
        } else {
            self.offered()
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<russh::server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        match response {
            None => Ok(Auth::Partial {
                name: "Verification".into(),
                instructions: "Answer the prompts".into(),
                prompts: vec![("Code: ".into(), false)].into(),
            }),
            Some(mut r) => {
                let code = r.next().unwrap_or_default();
                Ok(if code.as_ref() == b"424242" {
                    Auth::Accept
                } else {
                    self.offered()
                })
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = channel;
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
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
        session.channel_success(channel)?;
        session.data(
            channel,
            Bytes::from(format!("\r\nresized {cols}x{rows}\r\n")),
        )?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.shells.insert(channel, ());
        session.channel_success(channel)?;
        session.data(
            channel,
            Bytes::from_static(b"\x1b]0;tester@box\x07\x1b[1;32mprompt$\x1b[0m "),
        )?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        cmd: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        if cmd == termoso_core::osdetect::DETECT_COMMAND.as_bytes() {
            session.data(
                channel,
                Bytes::from_static(b"Linux\nPRETTY_NAME=\"Ubuntu 24.04\"\nID=ubuntu\n"),
            )?;
        } else if cmd.starts_with(b"mosh-server") {
            // Run the real thing so the bootstrap banner and the UDP side
            // come from the reference implementation.
            let out = tokio::process::Command::new("sh")
                .arg("-c")
                .arg(String::from_utf8_lossy(cmd).into_owned())
                .env("SSH_CONNECTION", "127.0.0.1 1 127.0.0.1 22")
                .env("TERM", "xterm-256color")
                .stdin(std::process::Stdio::null())
                .output()
                .await
                .expect("run mosh-server");
            for l in String::from_utf8_lossy(&out.stderr).lines() {
                if let Some(pid) = l
                    .strip_prefix("[mosh-server detached, pid = ")
                    .and_then(|r| r.trim_end_matches(']').trim().parse::<u32>().ok())
                {
                    MOSH_PIDS.lock().unwrap().push(pid);
                }
            }
            session.data(channel, Bytes::from(out.stdout))?;
            session.extended_data(channel, 1, Bytes::from(out.stderr))?;
            session.exit_status_request(channel, out.status.code().unwrap_or(1) as u32)?;
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(());
        }
        session.exit_status_request(channel, 0)?;
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
        if self.shells.contains_key(&channel) {
            if data == b"exit\r" || data == b"exit\n" {
                session.data(channel, Bytes::from_static(b"\r\nbye\r\n"))?;
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                session.close(channel)?;
            } else {
                session.data(channel, Bytes::copy_from_slice(data))?;
            }
        }
        Ok(())
    }
}

async fn start(kbd: bool) -> u16 {
    start_with(Srv { kbd, pubkey: false }).await
}

async fn start_with(mut server: Srv) -> u16 {
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let config = Arc::new(russh::server::Config {
        auth_rejection_time: Duration::from_millis(0),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = server.run_on_socket(config, &listener).await;
    });
    port
}

// ---- listener that records everything ------------------------------------

#[derive(Default)]
struct Recorder {
    states: Mutex<Vec<SessionState>>,
    prompts: Mutex<Vec<(u64, PromptRequest)>>,
    titles: Mutex<Vec<Option<String>>>,
    os: Mutex<Vec<String>>,
    renders: Mutex<u32>,
}

impl SessionListener for Recorder {
    fn on_state(&self, state: SessionState) {
        self.states.lock().unwrap().push(state);
    }
    fn on_render(&self) {
        *self.renders.lock().unwrap() += 1;
    }
    fn on_prompt(&self, prompt_id: u64, request: PromptRequest) {
        self.prompts.lock().unwrap().push((prompt_id, request));
    }
    fn on_title(&self, title: Option<String>) {
        self.titles.lock().unwrap().push(title);
    }
    fn on_bell(&self) {}
    fn on_clipboard(&self, _text: String) {}
    fn on_os_detected(&self, os_name: String) {
        self.os.lock().unwrap().push(os_name);
    }
}

impl Recorder {
    fn wait_prompt(&self, after: usize) -> (u64, PromptRequest) {
        let t = Instant::now();
        loop {
            if let Some(p) = self.prompts.lock().unwrap().get(after) {
                return p.clone();
            }
            assert!(
                t.elapsed() < Duration::from_secs(15),
                "no prompt #{after}; states {:?}",
                self.states.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_state(&self, pred: impl Fn(&SessionState) -> bool) -> SessionState {
        let t = Instant::now();
        loop {
            if let Some(s) = self.states.lock().unwrap().iter().find(|s| pred(s)) {
                return s.clone();
            }
            assert!(
                t.elapsed() < Duration::from_secs(15),
                "state not reached; seen {:?}",
                self.states.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[derive(Default)]
struct SftpRecorder {
    states: Mutex<Vec<SessionState>>,
}

impl SftpListener for SftpRecorder {
    fn on_state(&self, state: SessionState) {
        self.states.lock().unwrap().push(state);
    }
    fn on_prompt(&self, _prompt_id: u64, _request: PromptRequest) {}
    fn on_transfer(&self, _transfer: TransferCard) {}
}

fn wait_text(session: &SshSession, needle: &str) -> Vec<String> {
    let t = Instant::now();
    loop {
        let rows = session.visible_text();
        if rows.iter().any(|r| r.contains(needle)) {
            return rows;
        }
        assert!(
            t.elapsed() < Duration::from_secs(15),
            "{needle:?} not on screen: {rows:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn app() -> (Arc<TermosoApp>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_master_key();
    assert_eq!(key.len(), 32);
    let app = TermosoApp::open(dir.path().to_string_lossy().into_owned(), key).unwrap();
    (app, dir)
}

fn opts() -> TerminalOptions {
    TerminalOptions {
        cols: 40,
        rows: 6,
        term_type: String::new(),
        palette: None,
        transport: Transport::Auto,
    }
}

fn local_vault(app: &Arc<TermosoApp>) -> String {
    app.local_vault().unwrap().id
}

/// Every connect entry point takes the vault the caller believes the host
/// lives in; a mismatch is refused before any credential is read or a
/// session is started, so a stale id from another vault cannot ride an
/// already-unlocked one.
#[test]
fn connecting_checks_the_host_vault() {
    let (app, _dir) = app();
    let vault = local_vault(&app);
    let mut d = app.new_host_draft(vault.clone(), None).unwrap();
    d.label = "pg".into();
    d.address = "127.0.0.1".into();
    d.telnet = Some(TelnetDraft::default());
    d.webdav = Some(WebDavDraft {
        path: "/dav".into(),
        ..WebDavDraft::default()
    });
    let host = app.save_host(d).unwrap();
    let other = uuid::Uuid::new_v4().to_string();

    let rec = Arc::new(Recorder::default());
    let err = app
        .connect_host(host.id.clone(), other.clone(), opts(), rec.clone())
        .err()
        .expect("foreign vault");
    assert!(matches!(err, MobileError::Invalid { .. }), "{err}");
    assert!(err.to_string().contains("another vault"), "{err}");
    let err = app
        .connect_host(
            host.id.clone(),
            other.clone(),
            TerminalOptions {
                transport: Transport::Telnet,
                ..opts()
            },
            rec.clone(),
        )
        .err()
        .expect("foreign vault");
    assert!(matches!(err, MobileError::Invalid { .. }), "{err}");
    let files = Arc::new(SftpRecorder::default());
    let err = app
        .sftp_host(host.id.clone(), other.clone(), files.clone())
        .err()
        .expect("foreign vault");
    assert!(matches!(err, MobileError::Invalid { .. }), "{err}");
    let err = app
        .webdav_host(host.id.clone(), other, files.clone())
        .err()
        .expect("foreign vault");
    assert!(matches!(err, MobileError::Invalid { .. }), "{err}");
    assert!(rec.states.lock().unwrap().is_empty());
    assert!(rec.prompts.lock().unwrap().is_empty());
    assert!(files.states.lock().unwrap().is_empty());
    assert!(app.history(10).unwrap().is_empty());

    // The right vault still resolves (the target is not reachable, but the
    // session starts and reports it instead of refusing up front).
    let rec = Arc::new(Recorder::default());
    let s = app
        .connect_host(host.id, vault, opts(), rec.clone())
        .unwrap();
    s.disconnect();
}

// ---- tests ----------------------------------------------------------------

#[test]
fn profile_roundtrip_and_wrong_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_string_lossy().into_owned();
    assert!(!profile_exists(path.clone()));
    let key = generate_master_key();
    let app = TermosoApp::open(path.clone(), key.clone()).unwrap();
    let vault = app.local_vault().unwrap();
    assert_eq!(vault.kind, VaultKind::Local);
    let mut d = app.new_host_draft(vault.id.clone(), None).unwrap();
    d.label = "box".into();
    d.address = "10.0.0.1".into();
    app.save_host(d).unwrap();
    drop(app);
    assert!(profile_exists(path.clone()));

    let again = TermosoApp::open(path.clone(), key).unwrap();
    assert_eq!(again.hosts(None).unwrap().len(), 1);
    drop(again);

    assert!(TermosoApp::open(path.clone(), generate_master_key()).is_err());
    assert!(matches!(
        TermosoApp::open(path, vec![1, 2, 3]),
        Err(MobileError::Invalid { .. })
    ));
}

#[test]
fn hosts_crud_without_secrets_in_cards() {
    let (app, _dir) = app();
    let vault = app.local_vault().unwrap().id;
    let group = app
        .save_group(vault.clone(), None, "prod".into(), None)
        .unwrap();

    let mut d = app
        .new_host_draft(vault.clone(), Some(group.id.clone()))
        .unwrap();
    d.label = "web-1".into();
    d.address = "web1.example.org".into();
    d.username = "deploy".into();
    d.port = Some(2222);
    d.password = Some("hunter2".into());
    let web = app.create_tag(vault.clone(), "web".into()).unwrap();
    let eu = app.create_tag(vault.clone(), " eu ".into()).unwrap();
    assert_eq!(
        app.create_tag(vault.clone(), "WEB".into()).unwrap().id,
        web.id
    );
    d.tag_ids = vec![web.id, eu.id];
    let card = app.save_host(d).unwrap();
    assert_eq!(card.label, "web-1");
    assert_eq!(card.port, 2222);
    assert_eq!(card.username, "deploy");
    assert_eq!(card.group_path, vec!["prod".to_string()]);
    assert_eq!(card.tags.len(), 2);
    let json = serde_json::to_string(&serde_json::json!({
        "label": card.label, "address": card.address, "notes": card.notes,
        "username": card.username, "protocol": card.protocol,
    }))
    .unwrap();
    assert!(!json.contains("hunter2"));

    let draft = app.host_draft(card.id.clone()).unwrap();
    assert!(draft.has_password);
    assert_eq!(draft.password, None, "stored password never leaves Rust");

    // Edit keeps the password when the draft leaves it as None.
    let mut edit = draft.clone();
    edit.label = "web-01".into();
    let card2 = app.save_host(edit).unwrap();
    assert_eq!(card2.label, "web-01");
    assert!(app.host_draft(card2.id.clone()).unwrap().has_password);

    // Some("") clears it.
    let mut clear = app.host_draft(card2.id.clone()).unwrap();
    clear.password = Some(String::new());
    app.save_host(clear).unwrap();
    assert!(!app.host_draft(card2.id.clone()).unwrap().has_password);

    assert_eq!(app.hosts(Some(vault.clone())).unwrap().len(), 1);
    assert_eq!(app.tags(None).unwrap().len(), 2);
    let dup = app.duplicate_host(card2.id.clone()).unwrap();
    assert_ne!(dup.id, card2.id);
    app.move_hosts(vec![dup.id.clone()], None).unwrap();
    assert!(app.host(dup.id.clone()).unwrap().group_path.is_empty());
    app.delete_hosts(vec![card2.id, dup.id]).unwrap();
    assert!(app.hosts(None).unwrap().is_empty());
    app.delete_group(group.id).unwrap();
    assert!(app.groups(None).unwrap().is_empty());
    assert!(matches!(
        app.host("not-a-uuid".into()),
        Err(MobileError::Invalid { .. })
    ));
}

#[test]
fn keychain_and_identities() {
    let (app, _dir) = app();
    let vault = app.local_vault().unwrap().id;
    let key = app
        .generate_key(KeyGenerateDraft {
            vault_id: vault.clone(),
            label: "phone".into(),
            algorithm: KeyAlgorithm::Ed25519,
            comment: "termoso@phone".into(),
            passphrase: Some("pp".into()),
            remember_passphrase: false,
        })
        .unwrap();
    assert_eq!(key.key_type, "ssh-ed25519");
    assert!(key.public_key.starts_with("ssh-ed25519 "));
    assert!(key.encrypted && !key.has_passphrase);
    assert!(
        app.public_key(key.id.clone())
            .unwrap()
            .starts_with("ssh-ed25519 ")
    );

    // Only the explicit export returns private material, and it needs the
    // passphrase when it is not remembered.
    assert!(app.export_private_key(key.id.clone(), None, None).is_err());
    let pem = app
        .export_private_key(key.id.clone(), Some("pp".into()), None)
        .unwrap();
    assert!(pem.contains("BEGIN OPENSSH PRIVATE KEY"));

    let preview = app.inspect_private_key(pem.clone()).unwrap();
    assert_eq!(preview.key_type, "ssh-ed25519");
    let imported = app
        .import_key(KeyImportDraft {
            vault_id: vault.clone(),
            label: "imported".into(),
            private_key: pem,
            passphrase: None,
            remember_passphrase: false,
            certificate: None,
        })
        .unwrap();
    assert_eq!(imported.fingerprint, key.fingerprint);

    let ident = app
        .save_identity(IdentityDraft {
            id: None,
            vault_id: vault.clone(),
            label: "deploy".into(),
            username: "deploy".into(),
            password: Some("pw".into()),
            ssh_key_id: Some(key.id.clone()),
            ssh_id: false,
            ssh_id_key_type: None,
            totp_secret: None,
        })
        .unwrap();
    assert!(ident.has_password);
    assert!(!ident.ssh_id);
    assert_eq!(ident.ssh_key_label.as_deref(), Some("phone"));
    assert_eq!(app.keys(None).unwrap().len(), 2);
    assert_eq!(
        app.keys(None).unwrap()[0].used_by + app.keys(None).unwrap()[1].used_by,
        1
    );

    app.delete_identity(ident.id).unwrap();
    app.delete_key(key.id).unwrap();
    app.delete_key(imported.id).unwrap();
    assert!(app.keys(None).unwrap().is_empty());
    assert!(app.identities(None).unwrap().is_empty());
}

#[test]
fn sshid_identity_and_signed_out_view() {
    let (app, _dir) = app();
    let vault = app.vaults().unwrap()[0].id.clone();
    // Signed out: no handle, no keys, nothing to publish; no network.
    let view = app.sshid().unwrap();
    assert!(!view.signed_in);
    assert!(view.handle.is_none() && view.keys.is_empty() && view.device_keys.is_empty());
    assert!(matches!(
        app.sshid_create("alice".into()),
        Err(MobileError::Invalid { .. })
    ));
    assert!(sshid_handle_valid("@Alice".into()) && !sshid_handle_valid("a".into()));

    // An identity may log in with SSH ID alone (no username / password / key).
    let ident = app
        .save_identity(IdentityDraft {
            id: None,
            vault_id: vault.clone(),
            label: "me".into(),
            username: String::new(),
            password: None,
            ssh_key_id: None,
            ssh_id: true,
            ssh_id_key_type: Some(SshIdKeyKind::Ecdsa),
            totp_secret: None,
        })
        .unwrap();
    assert!(ident.ssh_id && !ident.has_password && ident.ssh_key_id.is_none());
    assert_eq!(ident.ssh_id_key_type, Some(SshIdKeyKind::Ecdsa));
    let again = app.identities(None).unwrap();
    assert!(again[0].ssh_id && again[0].ssh_id_key_type == Some(SshIdKeyKind::Ecdsa));

    // Same on a host's inline credentials; the draft round-trips.
    let mut draft = app.new_host_draft(vault.clone(), None).unwrap();
    draft.label = "box".into();
    draft.address = "box.local".into();
    draft.ssh_id = true;
    draft.ssh_id_key_type = Some(SshIdKeyKind::Rsa);
    let saved = app.save_host(draft).unwrap();
    let back = app.host_draft(saved.id.clone()).unwrap();
    assert!(back.ssh_id && back.username.is_empty());
    assert_eq!(back.ssh_id_key_type, Some(SshIdKeyKind::Rsa));
    // Turning SSH ID off drops the preferred type too.
    let mut off = back;
    off.ssh_id = false;
    let off = app.host_draft(app.save_host(off).unwrap().id).unwrap();
    assert!(!off.ssh_id && off.ssh_id_key_type.is_none());
}

#[test]
fn settings_persist_with_defaults() {
    let (app, _dir) = app();
    let mut s = app.settings().unwrap();
    assert_eq!(s.terminal_font_size, 14);
    assert!(!s.welcome_seen);
    s.welcome_seen = true;
    s.terminal_font_size = 99; // clamped
    s.app_theme = "dark".into();
    app.save_settings(s).unwrap();
    let s = app.settings().unwrap();
    assert!(s.welcome_seen);
    assert_eq!(s.terminal_font_size, 40);
    assert_eq!(s.app_theme, "dark");
}

struct NoLive;

impl LiveListener for NoLive {
    fn on_typing(&self, _user_id: String) {}
    fn on_participants(&self, _: Vec<LiveParticipantCard>) {}
    fn on_control(&self, _: bool) {}
    fn on_ended(&self, _: LiveEndReason, _: String) {}
}

#[test]
fn live_links_are_recognised_and_need_an_account() {
    let (app, _dir) = app();
    assert!(is_live_link(
        "termoso://join/6f1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d?s=https://x.test#secret".into()
    ));
    assert!(!is_live_link("termoso://invite/abc".into()));
    assert!(!is_live_link("ssh://root@box".into()));
    let rec = Arc::new(Recorder::default());
    let err = app
        .join_live("not a link".into(), opts(), rec.clone(), Arc::new(NoLive))
        .err()
        .expect("garbage is not a link");
    assert!(matches!(err, MobileError::Invalid { .. }), "{err}");
    // A well-formed link still needs a signed-in account before any network.
    let err = app
        .join_live(
            "termoso://join/6f1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d?s=https://x.test#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            opts(),
            rec,
            Arc::new(NoLive),
        )
        .err()
        .expect("joining while signed out must fail");
    assert!(err.to_string().contains("not signed in"), "{err}");
    // Same for hosting: a terminal that is still connecting cannot be shared
    // without an account either, and stays unshared.
    let session = app
        .connect_quick(
            QuickTarget {
                host: "127.0.0.1".into(),
                port: 1,
                username: USER.into(),
                protocol: "ssh".into(),
            },
            opts(),
            Arc::new(Recorder::default()),
        )
        .unwrap();
    let err = app
        .share_session(session.clone(), "box".into(), Arc::new(NoLive))
        .err()
        .expect("sharing while signed out must fail");
    assert!(err.to_string().contains("not signed in"), "{err}");
    assert!(!session.is_shared());
    session.disconnect();
}

#[test]
fn parse_targets() {
    let t = parse_target("ssh://deploy@example.org:2200".into()).unwrap();
    assert_eq!(
        (t.username.as_str(), t.host.as_str(), t.port),
        ("deploy", "example.org", 2200)
    );
    // No user in the target: left empty so the connect path asks for it.
    let t = parse_target("example.org".into()).unwrap();
    assert_eq!((t.username.as_str(), t.port), ("", 22));
    let t = parse_target("me@[::1]:23".into()).unwrap();
    assert_eq!((t.host.as_str(), t.port), ("::1", 23));
    assert_eq!(t.protocol, "ssh");
    let t = parse_target("telnet://router.lan".into()).unwrap();
    assert_eq!(
        (t.host.as_str(), t.port, t.protocol.as_str()),
        ("router.lan", 23, "telnet")
    );
    let t = parse_target("telnet://10.0.0.1:2323/".into()).unwrap();
    assert_eq!((t.host.as_str(), t.port), ("10.0.0.1", 2323));
    assert!(parse_target("  ".into()).is_err());
    assert!(parse_target("telnet://".into()).is_err());
}

/// A telnet server that negotiates NAWS, prints a banner and echoes lines
/// back until it reads `bye`.
async fn start_telnet() -> u16 {
    const IAC: u8 = 255;
    const DO: u8 = 253;
    const NAWS: u8 = 31;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                sock.write_all(&[IAC, DO, NAWS]).await.ok();
                sock.write_all(b"telnet banner\r\nlogin: ").await.ok();
                let mut buf = [0u8; 256];
                let mut line = Vec::new();
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    // Skip negotiation replies the client sends; keep printable bytes.
                    let mut i = 0;
                    while i < n {
                        if buf[i] == IAC {
                            i += if i + 1 < n && buf[i + 1] == 250 {
                                buf[i..n]
                                    .iter()
                                    .position(|&b| b == 240)
                                    .map_or(n, |p| p + 1)
                            } else {
                                3
                            };
                            continue;
                        }
                        line.push(buf[i]);
                        i += 1;
                    }
                    if let Some(p) = line.iter().position(|&b| b == b'\r' || b == b'\n') {
                        let cmd = String::from_utf8_lossy(&line[..p]).trim().to_string();
                        line.clear();
                        if cmd == "bye" {
                            sock.write_all(b"\r\nGoodbye\r\n").await.ok();
                            return;
                        }
                        sock.write_all(format!("\r\nyou said {cmd}\r\nlogin: ").as_bytes())
                            .await
                            .ok();
                    }
                }
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread")]
async fn telnet_quick_and_saved_host() {
    let port = start_telnet().await;
    let (app, _dir) = app();

    // Ad-hoc telnet: no host key, no credentials, straight to the banner.
    let rec = Arc::new(Recorder::default());
    let session = app
        .connect_quick(
            parse_target(format!("telnet://127.0.0.1:{port}")).unwrap(),
            opts(),
            rec.clone(),
        )
        .unwrap();
    rec.wait_state(|s| matches!(s, SessionState::Connected));
    wait_text(&session, "telnet banner");
    session.write(b"hello\r".to_vec());
    wait_text(&session, "you said hello");
    session.write(b"bye\r".to_vec());
    rec.wait_state(|s| matches!(s, SessionState::Closed { .. }));
    assert!(rec.prompts.lock().unwrap().is_empty());

    // A Telnet-only saved host is listed as such and connects the same way.
    let vault = app.local_vault().unwrap().id;
    let mut d = app.new_host_draft(vault, None).unwrap();
    d.label = "router".into();
    d.address = "127.0.0.1".into();
    d.ssh = false;
    d.telnet = Some(TelnetDraft {
        port: Some(port),
        username: "admin".into(),
        ..TelnetDraft::default()
    });
    let host = app.save_host(d).unwrap();
    assert_eq!((host.protocol.as_str(), host.port), ("telnet", port));
    let back = app.host_draft(host.id.clone()).unwrap();
    assert!(!back.ssh);
    assert_eq!(
        back.telnet.as_ref().map(|t| t.username.as_str()),
        Some("admin")
    );

    let rec = Arc::new(Recorder::default());
    let session = app
        .connect_host(host.id.clone(), local_vault(&app), opts(), rec.clone())
        .unwrap();
    rec.wait_state(|s| matches!(s, SessionState::Connected));
    wait_text(&session, "login:");
    session.disconnect();
    rec.wait_state(|s| matches!(s, SessionState::Closed { .. }));

    // An SSH-only host has no Telnet section to pick.
    let mut d = app
        .new_host_draft(app.local_vault().unwrap().id, None)
        .unwrap();
    d.label = "ssh-only".into();
    d.address = "127.0.0.1".into();
    let ssh_only = app.save_host(d).unwrap();
    let err = app
        .connect_host(
            ssh_only.id,
            local_vault(&app),
            TerminalOptions {
                transport: Transport::Telnet,
                ..opts()
            },
            Arc::new(Recorder::default()),
        )
        .err()
        .expect("no telnet section");
    assert!(err.to_string().contains("Telnet"), "{err}");

    let hist = app.history(10).unwrap();
    assert_eq!(hist.len(), 2);
    assert!(hist.iter().all(|h| h.protocol == "telnet"));
    assert!(
        hist.iter()
            .any(|h| h.host_id.is_some() && h.label == "router")
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn local_shell_session() {
    let (app, dir) = app();
    let rec = Arc::new(Recorder::default());
    let session = app
        .connect_local(
            LocalShell {
                argv: vec!["/bin/sh".into()],
                home: dir.path().to_string_lossy().into_owned(),
                env: vec!["PS1=local$ ".into(), "TERMOSO_TEST=1".into()],
            },
            opts(),
            rec.clone(),
        )
        .unwrap();
    rec.wait_state(|s| matches!(s, SessionState::Connected));
    session.write(b"echo $TERMOSO_TEST-$TERM\r".to_vec());
    wait_text(&session, "1-xterm-256color");
    session.write(b"pwd\r".to_vec());
    wait_text(&session, &dir.path().to_string_lossy());
    session.write(b"exit\r".to_vec());
    rec.wait_state(|s| matches!(s, SessionState::Closed { .. }));
    let hist = app.history(10).unwrap();
    assert_eq!(hist.len(), 1);
    assert_eq!(
        (hist[0].protocol.as_str(), hist[0].label.as_str()),
        ("local", "Local")
    );
    assert!(hist[0].error.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn quick_connect_password_flow() {
    let port = start(false).await;
    let (app, _dir) = app();
    let rec = Arc::new(Recorder::default());
    let session = app
        .connect_quick(
            QuickTarget {
                host: "127.0.0.1".into(),
                port,
                username: USER.into(),
                protocol: "ssh".into(),
            },
            opts(),
            rec.clone(),
        )
        .unwrap();

    // 1. unknown host key → accept and save
    let (id, req) = rec.wait_prompt(0);
    let PromptRequest::HostKeyUnknown {
        key_type,
        fingerprint,
        ..
    } = req
    else {
        panic!("expected host key prompt, got {req:?}");
    };
    assert_eq!(key_type, "ssh-ed25519");
    assert!(fingerprint.starts_with("SHA256:"));
    assert!(session.answer(
        id,
        PromptAnswer::HostKey {
            decision: HostKeyChoice::AcceptAndSave
        }
    ));

    // 2. password: wrong first, then right
    let (id, req) = rec.wait_prompt(1);
    assert!(matches!(req, PromptRequest::Password { retry: false, .. }));
    assert!(session.answer(
        id,
        PromptAnswer::Secret {
            value: "nope".into(),
            remember: false
        }
    ));
    let (id, req) = rec.wait_prompt(2);
    assert!(matches!(req, PromptRequest::Password { retry: true, .. }));
    assert!(session.answer(
        id,
        PromptAnswer::Secret {
            value: PASSWORD.into(),
            remember: false
        }
    ));

    rec.wait_state(|s| matches!(s, SessionState::Connected));
    let rows = wait_text(&session, "prompt$");
    assert!(rows[0].starts_with("prompt$"));
    let snap = session.snapshot();
    assert_eq!((snap.cols, snap.rows), (40, 6));
    // bold green prompt cell
    assert_ne!(snap.flags[0] & flag::BOLD, 0);
    assert!(
        rec.titles
            .lock()
            .unwrap()
            .contains(&Some("tester@box".into()))
    );

    // A plain terminal is neither a view nor shared.
    assert!(!session.is_view());
    assert!(session.can_write());
    assert!(!session.is_shared());
    assert!(session.live_participants().is_empty());

    // 3. typing echoes, resize is forwarded, OS detected
    session.write(b"echo hi".to_vec());
    wait_text(&session, "prompt$ echo hi");
    session.resize(50, 8);
    wait_text(&session, "resized 50x8");
    assert_eq!(session.snapshot().cols, 50);
    let t = Instant::now();
    while rec.os.lock().unwrap().is_empty() {
        assert!(t.elapsed() < Duration::from_secs(15), "no OS detected");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(rec.os.lock().unwrap()[0], "ubuntu");

    // 4. remote exit closes the session and lands in history + known hosts
    session.write(b"exit\r".to_vec());
    let st = rec.wait_state(|s| matches!(s, SessionState::Closed { .. }));
    assert!(matches!(st, SessionState::Closed { .. }));
    assert!(*rec.renders.lock().unwrap() > 0);

    let kh = app.known_hosts().unwrap();
    assert_eq!(kh.len(), 1);
    assert_eq!(kh[0].hostname, format!("[127.0.0.1]:{port}"));
    let hist = app.history(10).unwrap();
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].protocol, "ssh");
    assert!(hist[0].error.is_none());
    app.forget_known_host(kh[0].id.clone()).unwrap();
    assert!(app.known_hosts().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn saved_host_keyboard_interactive_and_rejected_key() {
    let port = start(true).await;
    let (app, _dir) = app();
    let vault = app.local_vault().unwrap().id;
    let mut d = app.new_host_draft(vault, None).unwrap();
    d.label = "kbd".into();
    d.address = "127.0.0.1".into();
    d.port = Some(port);
    d.username = USER.into();
    let host = app.save_host(d).unwrap();

    // Rejecting the key fails the session with a typed error.
    let rec = Arc::new(Recorder::default());
    let s = app
        .connect_host(host.id.clone(), local_vault(&app), opts(), rec.clone())
        .unwrap();
    let (id, _) = rec.wait_prompt(0);
    assert!(s.answer(
        id,
        PromptAnswer::HostKey {
            decision: HostKeyChoice::Reject
        }
    ));
    let st = rec.wait_state(|s| matches!(s, SessionState::Failed { .. }));
    let SessionState::Failed { kind, .. } = st else {
        unreachable!()
    };
    assert_eq!(kind, "host_key_rejected");
    assert!(app.known_hosts().unwrap().is_empty());
    let hist = app.history(10).unwrap();
    assert_eq!(hist.len(), 1);
    assert!(hist[0].error.is_some());

    // Accept once + keyboard-interactive.
    let rec = Arc::new(Recorder::default());
    let s = app
        .connect_host(host.id.clone(), local_vault(&app), opts(), rec.clone())
        .unwrap();
    let (id, _) = rec.wait_prompt(0);
    assert!(s.answer(
        id,
        PromptAnswer::HostKey {
            decision: HostKeyChoice::AcceptOnce
        }
    ));
    let (id, req) = rec.wait_prompt(1);
    let PromptRequest::KeyboardInteractive { questions, .. } = req else {
        panic!("expected kbd-interactive, got {req:?}");
    };
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].prompt, "Code: ");
    assert!(!questions[0].echo);
    assert!(s.answer(
        id,
        PromptAnswer::Answers {
            values: vec!["424242".into()]
        }
    ));
    rec.wait_state(|s| matches!(s, SessionState::Connected));
    wait_text(&s, "prompt$");
    assert!(
        app.known_hosts().unwrap().is_empty(),
        "accept once does not save"
    );
    // OS detection runs on a side channel after `Connected`; closing the
    // session before it lands would leave `os_name` unset (flaky otherwise).
    let t = Instant::now();
    while rec.os.lock().unwrap().is_empty() {
        assert!(t.elapsed() < Duration::from_secs(15), "os not detected");
        std::thread::sleep(Duration::from_millis(20));
    }

    // Local close.
    s.disconnect();
    rec.wait_state(|s| matches!(s, SessionState::Closed { .. }));
    assert_eq!(app.history(10).unwrap().len(), 2);
    let h = app.host(host.id).unwrap();
    assert!(h.last_connected.is_some());
    assert_eq!(h.os_name.as_deref(), Some("ubuntu"));

    // Cancelling a prompt fails the session cleanly.
    let rec = Arc::new(Recorder::default());
    let s = app
        .connect_host(h.id, local_vault(&app), opts(), rec.clone())
        .unwrap();
    let (id, _) = rec.wait_prompt(0);
    assert!(s.answer(id, PromptAnswer::Cancel));
    let st = rec.wait_state(|s| matches!(s, SessionState::Failed { .. }));
    let SessionState::Failed { kind, .. } = st else {
        unreachable!()
    };
    assert_eq!(kind, "cancelled");
    assert!(!s.answer(id, PromptAnswer::Cancel), "stale prompt id");
}

/// Connects a saved key-authenticated host, answering the host-key prompt
/// once and the passphrase prompt (with `remember`) when it comes. Returns
/// whether a passphrase was asked for.
fn connect_with_key(app: &Arc<TermosoApp>, host: &str, passphrase: &str, remember: bool) -> bool {
    let rec = Arc::new(Recorder::default());
    let s = app
        .connect_host(host.to_string(), local_vault(app), opts(), rec.clone())
        .unwrap();
    let mut n = 0;
    let mut asked = false;
    let t = Instant::now();
    loop {
        let prompt = rec.prompts.lock().unwrap().get(n).cloned();
        match prompt {
            Some((id, PromptRequest::HostKeyUnknown { .. })) => {
                n += 1;
                assert!(s.answer(
                    id,
                    PromptAnswer::HostKey {
                        decision: HostKeyChoice::AcceptAndSave
                    }
                ));
            }
            Some((id, PromptRequest::Passphrase { retry, .. })) => {
                n += 1;
                assert!(!retry);
                asked = true;
                assert!(s.answer(
                    id,
                    PromptAnswer::Secret {
                        value: passphrase.into(),
                        remember,
                    }
                ));
            }
            Some((_, other)) => panic!("unexpected prompt {other:?}"),
            None => {
                let done =
                    rec.states.lock().unwrap().iter().any(|st| {
                        matches!(st, SessionState::Connected | SessionState::Failed { .. })
                    });
                if done {
                    break;
                }
                assert!(
                    t.elapsed() < Duration::from_secs(15),
                    "stuck; states {:?}",
                    rec.states.lock().unwrap()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    let st =
        rec.wait_state(|st| matches!(st, SessionState::Connected | SessionState::Failed { .. }));
    assert!(matches!(st, SessionState::Connected), "{st:?}");
    s.disconnect();
    rec.wait_state(|st| matches!(st, SessionState::Closed { .. }));
    asked
}

/// Opt-in RAM cache: a passphrase typed without "remember" is reused for
/// the next connection with that key, never written to the vault, and
/// dropped on lock; the setting off asks every time; "remember" still
/// persists as before.
#[tokio::test(flavor = "multi_thread")]
async fn key_passphrase_cached_in_memory_until_lock() {
    let port = start_with(Srv {
        kbd: false,
        pubkey: true,
    })
    .await;
    let (app, _dir) = app();
    let vault = app.local_vault().unwrap().id;
    let key = app
        .generate_key(KeyGenerateDraft {
            vault_id: vault.clone(),
            label: "locked".into(),
            algorithm: KeyAlgorithm::Ed25519,
            comment: String::new(),
            passphrase: Some("pp".into()),
            remember_passphrase: false,
        })
        .unwrap();
    let mut d = app.new_host_draft(vault, None).unwrap();
    d.label = "key".into();
    d.address = "127.0.0.1".into();
    d.port = Some(port);
    d.username = USER.into();
    d.ssh_key_id = Some(key.id.clone());
    let host = app.save_host(d).unwrap();

    // Default: off. Every connection asks.
    assert!(!app.settings().unwrap().cache_passphrases);
    assert!(connect_with_key(&app, &host.id, "pp", false));
    assert!(connect_with_key(&app, &host.id, "pp", false));
    assert_eq!(app.cached_passphrase_count(), 0);

    // On: asked once, then served from memory; the vault stays clean.
    let mut settings = app.settings().unwrap();
    settings.cache_passphrases = true;
    app.save_settings(settings).unwrap();
    assert!(connect_with_key(&app, &host.id, "pp", false));
    assert_eq!(app.cached_passphrase_count(), 1);
    assert!(!connect_with_key(&app, &host.id, "pp", false));
    let vault_key = |id: &str| {
        app.keys(None)
            .unwrap()
            .into_iter()
            .find(|k| k.id == id)
            .unwrap()
    };
    assert!(
        !vault_key(&key.id).has_passphrase,
        "RAM cache must not persist"
    );
    assert!(
        app.export_private_key(key.id.clone(), None, None).is_err(),
        "vault copy still needs the passphrase"
    );

    // Lock (or any explicit clear) forgets it.
    app.forget_cached_passphrases();
    assert_eq!(app.cached_passphrase_count(), 0);
    assert!(connect_with_key(&app, &host.id, "pp", false));
    assert_eq!(app.cached_passphrase_count(), 1);

    // Turning the setting off clears the cache too.
    let mut settings = app.settings().unwrap();
    settings.cache_passphrases = false;
    app.save_settings(settings).unwrap();
    assert_eq!(app.cached_passphrase_count(), 0);
    assert!(connect_with_key(&app, &host.id, "pp", false));

    // "Remember" still writes to the vault and does not go through the cache.
    let mut settings = app.settings().unwrap();
    settings.cache_passphrases = true;
    app.save_settings(settings).unwrap();
    assert!(connect_with_key(&app, &host.id, "pp", true));
    assert_eq!(app.cached_passphrase_count(), 0);
    assert!(vault_key(&key.id).has_passphrase);
    assert!(!connect_with_key(&app, &host.id, "pp", false));
}

// ---- Mosh -----------------------------------------------------------------

/// A saved host with Mosh on: the usual SSH prompts, then `mosh-server` is
/// started over that connection and the terminal continues over UDP with the
/// same grid, input queue and history entry.
#[tokio::test(flavor = "multi_thread")]
async fn saved_host_over_mosh() {
    if !mosh_server_installed() {
        return;
    }
    let _cleanup = KillMoshServers;
    let port = start(false).await;
    let (app, _dir) = app();
    let vault = app.local_vault().unwrap().id;
    let mut d = app.new_host_draft(vault, None).unwrap();
    d.label = "roaming".into();
    d.address = "127.0.0.1".into();
    d.port = Some(port);
    d.username = USER.into();
    d.password = Some(PASSWORD.into());
    d.use_mosh = true;
    // Loopback-only server with a shell that evaluates whole lines.
    d.mosh_server_command = Some(
        "mosh-server new -s -i 127.0.0.1 -c 256 -l LANG=C.UTF-8 -- sh -c 'stty -echo; printf READY_%s\\\\n MARK; while IFS= read -r l; do eval \"$l\"; done'"
            .into(),
    );
    let host = app.save_host(d).unwrap();
    let card = app.host(host.id.clone()).unwrap();
    assert!(card.use_mosh);
    let draft = app.host_draft(host.id.clone()).unwrap();
    assert!(draft.use_mosh);
    assert!(
        draft
            .mosh_server_command
            .as_deref()
            .is_some_and(|c| c.starts_with("mosh-server new -s -i 127.0.0.1"))
    );

    let rec = Arc::new(Recorder::default());
    let s = app
        .connect_host(host.id.clone(), local_vault(&app), opts(), rec.clone())
        .unwrap();
    let (id, _) = rec.wait_prompt(0);
    assert!(s.answer(
        id,
        PromptAnswer::HostKey {
            decision: HostKeyChoice::AcceptAndSave
        }
    ));
    rec.wait_state(|st| matches!(st, SessionState::Connected));
    assert!(rec.states.lock().unwrap().iter().any(|st| matches!(
        st,
        SessionState::Connecting { detail, stage: ConnectStage::MoshServer, hop: None }
            if detail.starts_with("Starting mosh-server")
    )));
    wait_text(&s, "READY_MARK");

    // Keystrokes travel over UDP and are evaluated by the remote shell.
    s.write(b"printf '%s%s\\n' PONG _OK\n".to_vec());
    wait_text(&s, "PONG_OK");
    // So does the window size.
    s.resize(60, 10);
    s.write(b"printf 'SIZE=%s\\n' \"$(stty size)\"\n".to_vec());
    wait_text(&s, "SIZE=10 60");

    // Local disconnect shuts the Mosh session down and lands in history as mosh.
    s.disconnect();
    rec.wait_state(|st| matches!(st, SessionState::Closed { .. }));
    let hist = app.history(10).unwrap();
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].protocol, "mosh");
    assert!(hist[0].error.is_none());
    let t = Instant::now();
    while MOSH_PIDS
        .lock()
        .unwrap()
        .iter()
        .any(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
    {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "mosh-server still running after disconnect"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // Explicit transport selection wins over the host setting: SSH-only
    // opens the plain shell of the test server.
    let rec = Arc::new(Recorder::default());
    let s = app
        .connect_host(
            host.id.clone(),
            local_vault(&app),
            TerminalOptions {
                transport: Transport::Ssh,
                ..opts()
            },
            rec.clone(),
        )
        .unwrap();
    rec.wait_state(|st| matches!(st, SessionState::Connected));
    wait_text(&s, "prompt$");
    s.disconnect();
    rec.wait_state(|st| matches!(st, SessionState::Closed { .. }));
    assert_eq!(app.history(10).unwrap()[0].protocol, "ssh");
}

// ---- port forwarding ------------------------------------------------------

#[derive(Default)]
struct TunnelRecorder {
    states: Mutex<Vec<TunnelState>>,
}

impl TunnelListener for TunnelRecorder {
    fn on_state(&self, state: TunnelState) {
        self.states.lock().unwrap().push(state);
    }
    fn on_prompt(&self, _prompt_id: u64, _request: PromptRequest) {}
}

impl TunnelRecorder {
    fn wait_terminal(&self) -> TunnelState {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(s) = self.states.lock().unwrap().iter().rev().find(|s| {
                matches!(
                    s,
                    TunnelState::Failed { .. } | TunnelState::Stopped | TunnelState::Running { .. }
                )
            }) {
                return s.clone();
            }
            assert!(Instant::now() < deadline, "tunnel never settled");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[test]
fn pf_rules_crud_and_validation() {
    let (app, _dir) = app();
    let vault = app.local_vault().unwrap().id;
    let mut d = app.new_host_draft(vault.clone(), None).unwrap();
    d.label = "bastion".into();
    d.address = "bastion.example.org".into();
    let host = app.save_host(d).unwrap();

    let draft = |kind: PfKind| PfRuleDraft {
        id: None,
        vault_id: vault.clone(),
        label: String::new(),
        host_id: host.id.clone(),
        kind,
        bound_address: String::new(),
        local_port: 8080,
        remote_host: "db".into(),
        remote_port: 5432,
        auto_start: true,
    };

    // Validation errors are `Invalid`.
    let mut bad = draft(PfKind::Local);
    bad.remote_host.clear();
    assert!(matches!(
        app.save_pf_rule(bad),
        Err(MobileError::Invalid { .. })
    ));
    let mut bad = draft(PfKind::Local);
    bad.host_id = uuid::Uuid::new_v4().to_string();
    assert!(matches!(
        app.save_pf_rule(bad),
        Err(MobileError::NotFound { .. })
    ));

    let local = app.save_pf_rule(draft(PfKind::Local)).unwrap();
    assert_eq!(local.route, "127.0.0.1:8080 → db:5432");
    assert_eq!(local.host_label, "bastion");
    assert!(local.auto_start);
    let mut dynamic = draft(PfKind::Dynamic);
    dynamic.label = "socks".into();
    let dynamic = app.save_pf_rule(dynamic).unwrap();

    // Labelled rules sort first.
    let list = app.pf_rules(Some(vault.clone())).unwrap();
    assert_eq!(
        list.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        vec![dynamic.id.as_str(), local.id.as_str()]
    );

    // Edit keeps the id; duplicate makes a copy.
    let mut edit = draft(PfKind::Local);
    edit.id = Some(local.id.clone());
    edit.local_port = 9090;
    let edited = app.save_pf_rule(edit).unwrap();
    assert_eq!(edited.id, local.id);
    assert_eq!(edited.local_port, 9090);
    let copy = app.duplicate_pf_rule(dynamic.id.clone()).unwrap();
    assert_eq!(copy.label, "socks copy");
    assert_eq!(app.pf_rules(None).unwrap().len(), 3);

    app.delete_pf_rule(copy.id.clone()).unwrap();
    assert!(matches!(
        app.pf_rule(copy.id),
        Err(MobileError::NotFound { .. })
    ));
    assert_eq!(app.pf_rules(None).unwrap().len(), 2);

    // Deleting the host leaves the rule pointing at a missing host.
    app.delete_host(host.id.clone()).unwrap();
    let orphan = app.pf_rule(local.id.clone()).unwrap();
    assert!(orphan.host_missing);
    assert!(matches!(
        app.start_pf(local.id, Arc::new(TunnelRecorder::default())),
        Err(MobileError::NotFound { .. })
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn pf_tunnel_fails_and_stops_cleanly() {
    let (app, _dir) = app();
    let vault = app.local_vault().unwrap().id;
    // Nothing listens here: the connect fails fast.
    let free = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = free.local_addr().unwrap().port();
    drop(free);
    let mut d = app.new_host_draft(vault.clone(), None).unwrap();
    d.address = "127.0.0.1".into();
    d.port = Some(port);
    d.username = USER.into();
    let host = app.save_host(d).unwrap();
    let rule = app
        .save_pf_rule(PfRuleDraft {
            id: None,
            vault_id: vault,
            label: String::new(),
            host_id: host.id,
            kind: PfKind::Dynamic,
            bound_address: String::new(),
            local_port: 1080,
            remote_host: String::new(),
            remote_port: 0,
            auto_start: false,
        })
        .unwrap();

    let rec = Arc::new(TunnelRecorder::default());
    let tunnel = app.start_pf(rule.id.clone(), rec.clone()).unwrap();
    assert_eq!(tunnel.rule_id(), rule.id);
    let state = tokio::task::spawn_blocking(move || rec.wait_terminal())
        .await
        .unwrap();
    assert!(matches!(state, TunnelState::Failed { .. }), "{state:?}");
    assert_eq!(tunnel.stats().connections, 0);
    tunnel.stop();
    assert!(matches!(
        tunnel.state(),
        TunnelState::Failed { .. } | TunnelState::Stopped
    ));
}
