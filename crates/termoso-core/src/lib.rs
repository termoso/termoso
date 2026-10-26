//! Termoso client core.
//!
//! Everything a Termoso client does that is not pixels lives here so the
//! desktop (Tauri) and mobile (UniFFI) shells stay thin:
//!
//! * [`store`] – encrypted local database (SQLite). Works fully offline with a
//!   *local vault*; an account only adds synchronisation.
//! * [`secrets`] – the single local master key, kept in the OS keychain.
//! * [`api`] – typed client for the Termoso server (OPAQUE login, vaults, sync,
//!   history, logs, realtime notifications).
//! * [`sync`] – bidirectional sync engine between [`store`] and [`api`] with
//!   optimistic concurrency and deterministic conflict resolution.
//! * [`ssh`] – SSH transport (russh): host-key trust, password / key / agent /
//!   keyboard-interactive auth, interactive PTY, exec, port forwarding, jump
//!   hosts.
//! * [`sftp`] – SFTP over an SSH session with progress reporting.
//! * [`terminal`] – protocol-agnostic interactive session (SSH shell, local
//!   PTY, Telnet) that the UI drives with bytes and resize events.
//! * [`keys`] – SSH key generation, import, export and fingerprints.
//! * [`fido2`] – security keys (`sk-*`): the private key stays on the token.
//! * [`agent`] – in-process SSH agent serving the keys in the vault.
//! * [`osdetect`] – figure out what OS a host runs (for its icon).
//! * [`cloud`] – list machines at AWS / DigitalOcean / Azure to import them
//!   as hosts.
//!
//! Nothing in this crate phones home: the only network peers are the servers
//! the user connects to, the Termoso server they configured and — only when
//! they ask for a cloud import — the provider API they gave credentials for.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod account;
pub mod agent;
pub mod agent_server;
pub mod api;
pub mod autocomplete;
pub mod ca;
pub mod cloud;
pub mod error;
pub mod extsecret;
pub mod fido2;
pub mod forward;
pub mod gateway;
pub mod hostkey;
pub mod import;
pub mod keys;
pub mod live;
pub mod localfs;
pub mod mdns;
pub mod model;
pub mod mosh;
pub mod osdetect;
pub mod policy;
pub mod posture;
pub mod remote;
pub mod secrets;
pub mod sftp;
pub mod ssh;
pub mod sshid;
pub mod store;
pub mod sync;
pub mod telnet;
pub mod terminal;
pub mod webdav;

pub mod charset;
#[cfg(feature = "local-pty")]
pub mod pty;
#[cfg(feature = "serial")]
pub mod serial;

pub use error::CoreError;
pub use termoso_crypto;
pub use termoso_proto;

/// Client version reported to servers (`app_version`).
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");
