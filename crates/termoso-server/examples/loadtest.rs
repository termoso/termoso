//! Self-contained load generator for a running Termoso server.
//!
//! Every virtual user registers with real OPAQUE, discovers its personal vault
//! and then loops: push a batch of encrypted host entities, pull the vault by
//! cursor. Latency percentiles and status counts are printed at the end;
//! nothing leaves the machine except the requests to the server under test.
//!
//! ```bash
//! cargo run -p termoso-server --release --example loadtest -- \
//!     --url http://127.0.0.1:8080 --users 20 --duration 30 --batch 20
//! ```
//!
//! Per-user pushes are paced to stay under the server's sync rate limit
//! (`--think-ms`); registrations are subject to the per-IP auth limit, so keep
//! `--users` below 30 per minute from one address or run several instances.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::json;
use termoso_crypto::aead::{self, Aad};
use termoso_crypto::kdf::{Label, derive_key};
use termoso_crypto::keys::{KeyPair, SymmetricKey};
use termoso_crypto::opaque;
use termoso_crypto::recovery::RecoveryKey;
use termoso_crypto::sealed;
use termoso_proto::auth::{
    AccountKeysUpload, AuthResponse, DeviceInfo, Platform, RegisterFinishRequest,
    RegisterStartRequest, RegisterStartResponse,
};
use termoso_proto::sync::{EntityChange, PullRequest, PullResponse, PushRequest, PushResponse};
use termoso_proto::vault::{VaultKind, VaultList};
use uuid::Uuid;

struct Options {
    url: String,
    users: usize,
    duration: Duration,
    batch: usize,
    think: Duration,
}

impl Options {
    fn parse() -> Self {
        let mut o = Options {
            url: "http://127.0.0.1:8080".into(),
            users: 20,
            duration: Duration::from_secs(30),
            batch: 20,
            think: Duration::from_millis(600),
        };
        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            if matches!(flag.as_str(), "-h" | "--help") {
                usage("");
            }
            let value = args
                .next()
                .unwrap_or_else(|| usage(&format!("{flag} needs a value")));
            let value = || value.clone();
            match flag.as_str() {
                "--url" => o.url = value().trim_end_matches('/').to_string(),
                "--users" => o.users = value().parse().unwrap_or_else(|_| usage("--users")),
                "--duration" => {
                    o.duration =
                        Duration::from_secs(value().parse().unwrap_or_else(|_| usage("--duration")))
                }
                "--batch" => o.batch = value().parse().unwrap_or_else(|_| usage("--batch")),
                "--think-ms" => {
                    o.think = Duration::from_millis(
                        value().parse().unwrap_or_else(|_| usage("--think-ms")),
                    )
                }
                other => usage(&format!("unknown flag {other}")),
            }
        }
        o
    }
}

fn usage(msg: &str) -> ! {
    if !msg.is_empty() {
        eprintln!("error: {msg}\n");
    }
    eprintln!(
        "usage: loadtest [--url URL] [--users N] [--duration SECS] [--batch N] [--think-ms MS]"
    );
    std::process::exit(2)
}

/// Per-endpoint latency samples and status counts.
#[derive(Default)]
struct Stats {
    latencies: HashMap<&'static str, Vec<Duration>>,
    statuses: BTreeMap<(&'static str, u16), u64>,
    transport_errors: u64,
}

impl Stats {
    fn record(&mut self, name: &'static str, status: StatusCode, took: Duration) {
        self.latencies.entry(name).or_default().push(took);
        *self.statuses.entry((name, status.as_u16())).or_default() += 1;
    }

    fn report(&self, elapsed: Duration) {
        println!("\n=== results ({:.1}s) ===", elapsed.as_secs_f64());
        let mut names: Vec<_> = self.latencies.keys().copied().collect();
        names.sort_unstable();
        println!(
            "{:<10} {:>8} {:>8} {:>9} {:>9} {:>9} {:>9}",
            "endpoint", "reqs", "req/s", "p50 ms", "p95 ms", "p99 ms", "max ms"
        );
        for name in names {
            let mut v = self.latencies[name].clone();
            v.sort_unstable();
            let pct = |p: f64| {
                let idx = ((v.len() as f64 - 1.0) * p).round() as usize;
                v[idx].as_secs_f64() * 1000.0
            };
            println!(
                "{:<10} {:>8} {:>8.1} {:>9.1} {:>9.1} {:>9.1} {:>9.1}",
                name,
                v.len(),
                v.len() as f64 / elapsed.as_secs_f64(),
                pct(0.50),
                pct(0.95),
                pct(0.99),
                pct(1.0),
            );
        }
        println!("\nstatus codes:");
        for ((name, status), n) in &self.statuses {
            println!("  {name:<10} {status}  x{n}");
        }
        if self.transport_errors > 0 {
            println!("\ntransport errors: {}", self.transport_errors);
        }
    }
}

type Shared = Arc<Mutex<Stats>>;

struct Api {
    http: Client,
    base: String,
    stats: Shared,
}

impl Api {
    /// One timed request; non-2xx responses are counted and surfaced as `Err`.
    async fn call<T: DeserializeOwned>(
        &self,
        name: &'static str,
        path: &str,
        token: Option<&str>,
        body: Option<&impl serde::Serialize>,
    ) -> Result<T, String> {
        let url = format!("{}/api/v1{path}", self.base);
        let mut req = match body {
            Some(b) => self.http.post(&url).json(b),
            None => self.http.get(&url),
        };
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let started = Instant::now();
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                self.stats.lock().unwrap().transport_errors += 1;
                return Err(format!("{name}: {e}"));
            }
        };
        let status = resp.status();
        let text = resp.text().await.map_err(|e| format!("{name}: {e}"))?;
        self.stats
            .lock()
            .unwrap()
            .record(name, status, started.elapsed());
        if !status.is_success() {
            return Err(format!("{name}: {status} {text}"));
        }
        serde_json::from_str(&text).map_err(|e| format!("{name}: bad json: {e}"))
    }
}

struct VirtualUser {
    token: String,
    vault_id: Uuid,
    vault_key: SymmetricKey,
    key_version: i32,
    cursor: i64,
}

async fn register(api: &Api, n: usize) -> Result<VirtualUser, String> {
    let email = format!("load-{}-{n}@loadtest.invalid", Uuid::new_v4().simple());
    let password = format!("load-{}", Uuid::new_v4());
    let (request, state) =
        opaque::client_registration_start(password.as_bytes()).map_err(|e| e.to_string())?;
    let start: RegisterStartResponse = api
        .call(
            "reg/start",
            "/auth/register/start",
            None,
            Some(&RegisterStartRequest {
                email: email.clone(),
                opaque_request: request,
                turnstile_token: None,
            }),
        )
        .await?;
    let out = opaque::client_registration_finish(
        state,
        password.as_bytes(),
        &email,
        &start.opaque_response,
    )
    .map_err(|e| e.to_string())?;

    let kek = derive_key(&out.export_key, Label::AccountKek).map_err(|e| e.to_string())?;
    let keypair = KeyPair::generate();
    let recovery = RecoveryKey::generate();
    let vault_key = SymmetricKey::generate();
    let secret = SymmetricKey::from_bytes(keypair.secret_bytes());
    let wrap =
        |k: &SymmetricKey, aad: Aad| aead::wrap_key(k, &aad, &secret).map_err(|e| e.to_string());
    let keys = AccountKeysUpload {
        public_key: keypair.public_b64(),
        wrapped_private_key: wrap(&kek, Aad::account_private_key())?,
        recovery_wrapped_private_key: wrap(
            &recovery.kek().map_err(|e| e.to_string())?,
            Aad::recovery_private_key(),
        )?,
        recovery_verifier: recovery.verifier_b64().map_err(|e| e.to_string())?,
        personal_vault_sealed_key: sealed::seal_vault_key(keypair.public(), &vault_key)
            .map_err(|e| e.to_string())?,
    };
    let resp: AuthResponse = api
        .call(
            "reg/finish",
            "/auth/register/finish",
            None,
            Some(&RegisterFinishRequest {
                email,
                opaque_upload: out.upload_b64,
                display_name: Some(format!("Load user {n}")),
                device: DeviceInfo {
                    name: "loadtest".into(),
                    platform: Platform::Linux,
                    app_version: "loadtest".into(),
                    client_device_id: Some(Uuid::new_v4()),
                    posture: None,
                },
                keys,
                invite_token: None,
                sso_session: None,
            }),
        )
        .await?;
    let AuthResponse::Authenticated(session) = resp else {
        return Err(format!("registration did not yield a session: {resp:?}"));
    };

    let vaults: VaultList = api
        .call::<VaultList>("vaults", "/vaults", Some(&session.token), None::<&()>)
        .await?;
    let personal = vaults
        .vaults
        .into_iter()
        .find(|v| v.kind == VaultKind::Personal)
        .ok_or("no personal vault")?;
    Ok(VirtualUser {
        token: session.token,
        vault_id: personal.id,
        vault_key,
        key_version: personal.key_version,
        cursor: 0,
    })
}

async fn run_user(api: Arc<Api>, mut user: VirtualUser, o: &Options, deadline: Instant) {
    while Instant::now() < deadline {
        let changes: Vec<EntityChange> = (0..o.batch)
            .map(|i| {
                let id = Uuid::new_v4();
                let plaintext = json!({
                    "label": format!("host-{i}"),
                    "address": format!("10.0.{}.{}", i / 256, i % 256),
                    "port": 22,
                    "username": "root",
                })
                .to_string();
                EntityChange {
                    secret_rotated_at: None,
                    id,
                    kind: "host".into(),
                    vault_id: user.vault_id,
                    base_version: None,
                    key_version: user.key_version,
                    data: aead::encrypt_str(
                        &user.vault_key,
                        &Aad::entity("host", &id.to_string()),
                        &plaintext,
                    )
                    .expect("encrypt"),
                    updated_at: Utc::now(),
                }
            })
            .collect();
        let _ = api
            .call::<PushResponse>(
                "push",
                "/sync/push",
                Some(&user.token),
                Some(&PushRequest {
                    changes,
                    deletes: vec![],
                }),
            )
            .await;

        let mut cursors = HashMap::new();
        cursors.insert(user.vault_id, user.cursor);
        if let Ok(pull) = api
            .call::<PullResponse>(
                "pull",
                "/sync/pull",
                Some(&user.token),
                Some(&PullRequest {
                    cursors,
                    limit: None,
                }),
            )
            .await
            && let Some(c) = pull.cursors.get(&user.vault_id)
        {
            user.cursor = *c;
        }
        tokio::time::sleep(o.think).await;
    }
}

#[tokio::main]
async fn main() {
    let o = Options::parse();
    let api = Arc::new(Api {
        http: Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client"),
        base: o.url.clone(),
        stats: Arc::default(),
    });

    println!("registering {} users against {} ...", o.users, o.url);
    let started = Instant::now();
    let mut users = Vec::with_capacity(o.users);
    for n in 0..o.users {
        match register(&api, n).await {
            Ok(u) => users.push(u),
            Err(e) => eprintln!("user {n}: {e}"),
        }
    }
    if users.is_empty() {
        eprintln!("no users registered, aborting");
        std::process::exit(1);
    }
    println!(
        "{} users ready in {:.1}s; running for {}s (batch {}, think {}ms)",
        users.len(),
        started.elapsed().as_secs_f64(),
        o.duration.as_secs(),
        o.batch,
        o.think.as_millis()
    );

    let run_started = Instant::now();
    let deadline = run_started + o.duration;
    let o = Arc::new(o);
    let tasks: Vec<_> = users
        .into_iter()
        .map(|u| {
            let api = api.clone();
            let o = o.clone();
            tokio::spawn(async move { run_user(api, u, &o, deadline).await })
        })
        .collect();
    for t in tasks {
        let _ = t.await;
    }
    api.stats.lock().unwrap().report(started.elapsed());
}
