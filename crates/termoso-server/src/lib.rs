//! Termoso server library (the binary is a thin wrapper, tests build the router directly).

#![forbid(unsafe_code)]
// Ad-hoc row tuples for `sqlx::query_as` are clearer at the call site than
// dozens of one-off named types.
#![allow(clippy::type_complexity)]

pub mod acl;
pub mod ai;
pub mod audit;
pub mod authz;
pub mod avatar;
pub mod backup;
pub mod cache;
pub mod codes;
pub mod config;
pub mod cron;
pub mod digest;
pub mod enterprise;
pub mod error;
pub mod events;
pub mod extract;
pub mod jobs;
pub mod live;
pub mod mail;
pub mod metrics;
pub mod openapi;
pub mod policy;
pub mod presence;
pub mod ratelimit;
pub mod routes;
pub mod saml;
pub mod scim;
pub mod session;
pub mod sso;
pub mod state;
pub mod storage;
pub mod trust;
pub mod turnstile;
pub mod users;
pub mod util;
pub mod webhooks;
pub mod ws;

pub use state::{AppState, Inner, VERSION};

use axum::Router;

/// Build the full application router for the given state.
pub fn app(state: AppState) -> Router {
    routes::router(state)
}
