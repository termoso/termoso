//! `termoso-server backup | restore | backup-check`: logical PostgreSQL
//! backups with a manifest that makes restores verifiable.
//!
//! * `backup --out <dir> [--age-recipient <age1…>]` runs `pg_dump -Fc`
//!   (optionally piped through `age -r`), writes `termoso-<utc>.dump[.age]`
//!   plus `….manifest.json` (server version, schema version, master key
//!   fingerprint, row counts, SHA-256 of the file).
//! * `restore --from <file> [--age-identity <key>] [--force-key] [--yes]`
//!   refuses dumps from a newer schema or a different master key, runs
//!   `pg_restore --clean --if-exists`, applies missing migrations and
//!   compares row counts with the manifest.
//! * `backup-check --from <file>` verifies the SHA-256 and the manifest
//!   against the configured server without touching the database.
//!
//! `pg_dump`/`pg_restore` must match the server's major version; override
//! the binaries with `TERMOSO_PG_DUMP` / `TERMOSO_PG_RESTORE`. The API must
//! be stopped (or drained) while restoring.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::Config;

pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub manifest_version: u32,
    pub termoso_version: String,
    /// Highest applied `_sqlx_migrations.version`.
    pub schema_version: i64,
    /// First 16 hex chars of SHA-256 over the master key; restores refuse a
    /// dump sealed with another key.
    pub master_key_fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub file: String,
    pub encrypted: bool,
    pub sha256: String,
    pub bytes: u64,
    pub counts: Counts,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counts {
    pub users: i64,
    pub teams: i64,
    pub vaults: i64,
    pub entities: i64,
}

/// Everything the commands need from the server configuration.
pub struct Ctx {
    pub database_url: String,
    pub master_key_fingerprint: String,
    pub pg_dump: String,
    pub pg_restore: String,
    pub age: String,
}

impl Ctx {
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let key = cfg.master_key()?;
        Ok(Self {
            database_url: cfg.database_url.clone(),
            master_key_fingerprint: fingerprint(&key.to_b64()),
            pg_dump: std::env::var("TERMOSO_PG_DUMP").unwrap_or_else(|_| "pg_dump".into()),
            pg_restore: std::env::var("TERMOSO_PG_RESTORE").unwrap_or_else(|_| "pg_restore".into()),
            age: std::env::var("TERMOSO_AGE").unwrap_or_else(|_| "age".into()),
        })
    }
}

pub fn fingerprint(master_key_b64: &str) -> String {
    let d = Sha256::digest(master_key_b64.trim().as_bytes());
    hex(&d[..8])
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Highest migration version compiled into this binary.
pub fn embedded_schema_version() -> i64 {
    sqlx::migrate!("./migrations")
        .migrations
        .iter()
        .map(|m| m.version)
        .max()
        .unwrap_or(0)
}

pub async fn schema_version(db: &PgPool) -> anyhow::Result<i64> {
    let (v,): (Option<i64>,) =
        sqlx::query_as("SELECT max(version) FROM _sqlx_migrations WHERE success")
            .fetch_one(db)
            .await?;
    Ok(v.unwrap_or(0))
}

pub async fn counts(db: &PgPool) -> anyhow::Result<Counts> {
    let (users, teams, vaults, entities): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM teams),
                (SELECT count(*) FROM vaults), (SELECT count(*) FROM entities)",
    )
    .fetch_one(db)
    .await?;
    Ok(Counts {
        users,
        teams,
        vaults,
        entities,
    })
}

fn manifest_path(file: &Path) -> PathBuf {
    let mut p = file.as_os_str().to_owned();
    p.push(".manifest.json");
    PathBuf::from(p)
}

async fn connect(ctx: &Ctx) -> anyhow::Result<PgPool> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(&ctx.database_url)
        .await
        .context("connecting to PostgreSQL")
}

/// Copy `reader` to `path`, hashing on the way.
async fn write_hashed<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    path: &Path,
) -> anyhow::Result<(String, u64)> {
    let mut file = tokio::fs::File::create(path)
        .await
        .with_context(|| format!("creating {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n]).await?;
        total += n as u64;
    }
    file.flush().await?;
    Ok((hex(&hasher.finalize()), total))
}

async fn sha256_file(path: &Path) -> anyhow::Result<(String, u64)> {
    let mut f = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex(&hasher.finalize()), total))
}

async fn wait_ok(mut child: tokio::process::Child, what: &str) -> anyhow::Result<()> {
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        e.read_to_string(&mut err).await.ok();
    }
    let status = child.wait().await?;
    anyhow::ensure!(
        status.success(),
        "{what} failed ({status}): {}",
        err.trim().chars().take(2000).collect::<String>()
    );
    if !err.trim().is_empty() {
        tracing::debug!(tool = what, stderr = %err.trim());
    }
    Ok(())
}

fn child_stdout_to_stdio(stdout: tokio::process::ChildStdout) -> anyhow::Result<Stdio> {
    #[cfg(unix)]
    {
        Ok(Stdio::from(stdout.into_owned_fd()?))
    }
    #[cfg(windows)]
    {
        Ok(Stdio::from(stdout.into_owned_handle()?))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = stdout;
        anyhow::bail!("piping child stdout is unsupported on this platform")
    }
}

/// Dump the database into `out_dir`; returns the dump path.
pub async fn backup(
    ctx: &Ctx,
    out_dir: &Path,
    age_recipient: Option<&str>,
) -> anyhow::Result<PathBuf> {
    tokio::fs::create_dir_all(out_dir).await?;
    let db = connect(ctx).await?;
    let schema_version = schema_version(&db).await?;
    let counts = counts(&db).await?;
    db.close().await;

    let created_at = Utc::now();
    let name = format!(
        "termoso-{}.dump{}",
        created_at.format("%Y%m%dT%H%M%SZ"),
        if age_recipient.is_some() { ".age" } else { "" }
    );
    let path = out_dir.join(&name);

    let mut dump = tokio::process::Command::new(&ctx.pg_dump)
        .args([
            "--format=custom",
            "--no-owner",
            "--no-privileges",
            "--dbname",
        ])
        .arg(&ctx.database_url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", ctx.pg_dump))?;
    let dump_out = dump.stdout.take().expect("piped");

    let (sha256, bytes) = match age_recipient {
        Some(recipient) => {
            let mut age = tokio::process::Command::new(&ctx.age)
                .args(["-r", recipient])
                .stdin(child_stdout_to_stdio(dump_out)?)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .with_context(|| format!("spawning {}", ctx.age))?;
            let age_out = age.stdout.take().expect("piped");
            let res = write_hashed(age_out, &path).await;
            wait_ok(age, "age").await?;
            wait_ok(dump, "pg_dump").await?;
            res?
        }
        None => {
            let res = write_hashed(dump_out, &path).await;
            wait_ok(dump, "pg_dump").await?;
            res?
        }
    };

    let manifest = Manifest {
        manifest_version: MANIFEST_VERSION,
        termoso_version: crate::VERSION.to_string(),
        schema_version,
        master_key_fingerprint: ctx.master_key_fingerprint.clone(),
        created_at,
        file: name,
        encrypted: age_recipient.is_some(),
        sha256,
        bytes,
        counts,
    };
    tokio::fs::write(manifest_path(&path), serde_json::to_vec_pretty(&manifest)?).await?;
    Ok(path)
}

pub async fn read_manifest(file: &Path) -> anyhow::Result<Manifest> {
    let p = manifest_path(file);
    let raw = tokio::fs::read(&p)
        .await
        .with_context(|| format!("reading {}", p.display()))?;
    let m: Manifest = serde_json::from_slice(&raw).context("parsing manifest")?;
    anyhow::ensure!(
        m.manifest_version <= MANIFEST_VERSION,
        "manifest version {} is newer than this server understands ({MANIFEST_VERSION})",
        m.manifest_version
    );
    Ok(m)
}

/// Why a dump must not be restored here.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    NewerSchema { dump: i64, server: i64 },
    KeyMismatch { dump: String, server: String },
    Corrupt { expected: String, actual: String },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NewerSchema { dump, server } => write!(
                f,
                "dump schema {dump} is newer than this server's {server}: upgrade the server image first"
            ),
            Refusal::KeyMismatch { dump, server } => write!(
                f,
                "dump was sealed with master key {dump}, this server has {server}: restore it with the original TERMOSO_MASTER_KEY (or --force-key to get a database whose secrets cannot be opened)"
            ),
            Refusal::Corrupt { expected, actual } => {
                write!(f, "SHA-256 mismatch: manifest {expected}, file {actual}")
            }
        }
    }
}

/// Pure checks shared by `restore` and `backup-check`.
pub fn admissible(
    m: &Manifest,
    server_schema: i64,
    server_fingerprint: &str,
    file_sha256: &str,
    force_key: bool,
) -> Result<(), Refusal> {
    if m.sha256 != file_sha256 {
        return Err(Refusal::Corrupt {
            expected: m.sha256.clone(),
            actual: file_sha256.to_string(),
        });
    }
    if m.schema_version > server_schema {
        return Err(Refusal::NewerSchema {
            dump: m.schema_version,
            server: server_schema,
        });
    }
    if !force_key && m.master_key_fingerprint != server_fingerprint {
        return Err(Refusal::KeyMismatch {
            dump: m.master_key_fingerprint.clone(),
            server: server_fingerprint.to_string(),
        });
    }
    Ok(())
}

pub struct RestoreOptions<'a> {
    pub age_identity: Option<&'a Path>,
    pub force_key: bool,
}

#[derive(Debug, Serialize)]
pub struct RestoreReport {
    pub manifest: Manifest,
    pub schema_before: i64,
    pub schema_after: i64,
    pub counts_after: Counts,
    pub counts_match: bool,
}

/// Verify, `pg_restore --clean --if-exists`, migrate, compare counts.
pub async fn restore(
    ctx: &Ctx,
    file: &Path,
    opts: RestoreOptions<'_>,
) -> anyhow::Result<RestoreReport> {
    let manifest = read_manifest(file).await?;
    let (sha, _) = sha256_file(file).await?;
    admissible(
        &manifest,
        embedded_schema_version(),
        &ctx.master_key_fingerprint,
        &sha,
        opts.force_key,
    )
    .map_err(|r| anyhow::anyhow!("{r}"))?;
    anyhow::ensure!(
        !manifest.encrypted || opts.age_identity.is_some(),
        "the dump is age-encrypted: pass --age-identity <key file>"
    );

    let db = connect(ctx).await?;
    let schema_before = schema_version(&db).await.unwrap_or(0);
    db.close().await;

    let input = tokio::fs::File::open(file)
        .await
        .with_context(|| format!("opening {}", file.display()))?;
    let mut restore = tokio::process::Command::new(&ctx.pg_restore);
    restore
        .args([
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-privileges",
            "--exit-on-error",
            "--dbname",
        ])
        .arg(&ctx.database_url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match opts.age_identity {
        Some(identity) => {
            let mut age = tokio::process::Command::new(&ctx.age)
                .arg("-d")
                .arg("-i")
                .arg(identity)
                .stdin(Stdio::from(input.into_std().await))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .with_context(|| format!("spawning {}", ctx.age))?;
            let out = age.stdout.take().expect("piped");
            let child = restore
                .stdin(child_stdout_to_stdio(out)?)
                .spawn()
                .with_context(|| format!("spawning {}", ctx.pg_restore))?;
            wait_ok(age, "age").await?;
            wait_ok(child, "pg_restore").await?;
        }
        None => {
            let child = restore
                .stdin(Stdio::from(input.into_std().await))
                .spawn()
                .with_context(|| format!("spawning {}", ctx.pg_restore))?;
            wait_ok(child, "pg_restore").await?;
        }
    }

    let db = connect(ctx).await?;
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .context("running migrations after restore")?;
    let schema_after = schema_version(&db).await?;
    let counts_after = counts(&db).await?;
    db.close().await;
    let counts_match = counts_after == manifest.counts;
    Ok(RestoreReport {
        manifest,
        schema_before,
        schema_after,
        counts_after,
        counts_match,
    })
}

pub async fn check(ctx: &Ctx, file: &Path, force_key: bool) -> anyhow::Result<Manifest> {
    let manifest = read_manifest(file).await?;
    let (sha, _) = sha256_file(file).await?;
    admissible(
        &manifest,
        embedded_schema_version(),
        &ctx.master_key_fingerprint,
        &sha,
        force_key,
    )
    .map_err(|r| anyhow::anyhow!("{r}"))?;
    Ok(manifest)
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Entry point for `termoso-server backup|restore|backup-check …`.
pub async fn run_cli(cfg: &Config, args: &[String]) -> anyhow::Result<()> {
    let ctx = Ctx::from_config(cfg)?;
    match args.first().map(String::as_str) {
        Some("backup") => {
            let out = flag(args, "--out").ok_or_else(|| anyhow::anyhow!("backup --out <dir>"))?;
            let recipient = flag(args, "--age-recipient")
                .map(str::to_string)
                .or_else(|| std::env::var("TERMOSO_BACKUP_AGE_RECIPIENT").ok());
            let path = backup(&ctx, Path::new(out), recipient.as_deref()).await?;
            let m = read_manifest(&path).await?;
            println!("{}", path.display());
            eprintln!(
                "schema {} · key {} · users {} teams {} vaults {} entities {} · {} bytes · sha256 {}",
                m.schema_version,
                m.master_key_fingerprint,
                m.counts.users,
                m.counts.teams,
                m.counts.vaults,
                m.counts.entities,
                m.bytes,
                &m.sha256[..16]
            );
            Ok(())
        }
        Some("backup-check") => {
            let from = flag(args, "--from")
                .ok_or_else(|| anyhow::anyhow!("backup-check --from <file>"))?;
            let m = check(
                &ctx,
                Path::new(from),
                args.iter().any(|a| a == "--force-key"),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&m)?);
            Ok(())
        }
        Some("restore") => {
            let from =
                flag(args, "--from").ok_or_else(|| anyhow::anyhow!("restore --from <file>"))?;
            if !args.iter().any(|a| a == "--yes") {
                anyhow::bail!(
                    "restore replaces every table in {}; stop the API first, then re-run with --yes",
                    redact(&ctx.database_url)
                );
            }
            let report = restore(
                &ctx,
                Path::new(from),
                RestoreOptions {
                    age_identity: flag(args, "--age-identity").map(Path::new),
                    force_key: args.iter().any(|a| a == "--force-key"),
                },
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            anyhow::ensure!(
                report.counts_match,
                "row counts differ from the manifest (see report above)"
            );
            Ok(())
        }
        _ => anyhow::bail!("usage: termoso-server backup|restore|backup-check …"),
    }
}

fn redact(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut u) => {
            let _ = u.set_password(None);
            u.to_string()
        }
        Err(_) => "<database>".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            manifest_version: 1,
            termoso_version: "0.9.0".into(),
            schema_version: 20,
            master_key_fingerprint: "aa".repeat(8),
            created_at: Utc::now(),
            file: "x.dump".into(),
            encrypted: false,
            sha256: "s".into(),
            bytes: 1,
            counts: Counts::default(),
        }
    }

    #[test]
    fn refusals() {
        let m = manifest();
        let fp = "aa".repeat(8);
        assert_eq!(admissible(&m, 20, &fp, "s", false), Ok(()));
        assert_eq!(admissible(&m, 25, &fp, "s", false), Ok(()));
        assert!(matches!(
            admissible(&m, 19, &fp, "s", false),
            Err(Refusal::NewerSchema {
                dump: 20,
                server: 19
            })
        ));
        assert!(matches!(
            admissible(&m, 20, "bb", "s", false),
            Err(Refusal::KeyMismatch { .. })
        ));
        assert_eq!(admissible(&m, 20, "bb", "s", true), Ok(()));
        assert!(matches!(
            admissible(&m, 20, &fp, "other", true),
            Err(Refusal::Corrupt { .. })
        ));
    }

    #[test]
    fn fingerprint_is_stable_and_short() {
        assert_eq!(fingerprint("abc"), fingerprint(" abc\n"));
        assert_eq!(fingerprint("abc").len(), 16);
        assert_ne!(fingerprint("abc"), fingerprint("abd"));
    }

    #[test]
    fn embedded_schema_is_latest_migration() {
        assert!(embedded_schema_version() >= 20);
    }
}
