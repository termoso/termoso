//! Termoso API Bridge.
//!
//! A headless client you run in your own infrastructure. It exposes a small
//! REST API (compatible in spirit with the Termius API Bridge) that scripts,
//! CMDBs and autoscalers call with *plaintext* hosts, groups and credentials.
//! The bridge encrypts every entity locally with the vault keys the cabinet
//! sealed to it and pushes the ciphertext through the normal sync protocol,
//! so the Termoso server keeps storing opaque blobs only.
//!
//! ```text
//!   your automation ── plaintext ──▶ termoso-bridge ── ciphertext ──▶ termoso-server
//!                                    (your network)                  (opaque sync)
//! ```

pub mod automations;
pub mod bridge;
pub mod credentials;
pub mod error;
pub mod exec;
pub mod gateway;
pub mod mcp;
pub mod model;
pub mod rest;
pub mod server;
pub mod vault;

pub use bridge::Bridge;
pub use credentials::load_credentials;
pub use error::{BridgeError, Result};
pub use rest::{RestConfig, router};
