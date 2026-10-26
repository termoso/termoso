//! Wire types shared by the Termoso server and all clients.
//!
//! Every type here is plain `serde` data. Fields that hold user secrets are
//! *always* ciphertext envelopes produced by `termoso-crypto` (base64 strings);
//! the server treats them as opaque.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod account;
pub mod admin;
pub mod ai;
pub mod auth;
pub mod automation;
pub mod bridge;
pub mod ca;
pub mod entities;
pub mod error;
pub mod live;
pub mod logs;
pub mod sshid;
pub mod sync;
pub mod team;
pub mod vault;
pub mod ws;

/// API version prefix for all REST routes.
pub const API_PREFIX: &str = "/api/v1";

/// Header carrying the device session token.
pub const AUTH_HEADER: &str = "authorization";

/// Macro to derive the OpenAPI schema only when the `openapi` feature is on.
macro_rules! schema {
    ($(#[$m:meta])* $vis:vis struct $name:ident $($rest:tt)*) => {
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$m])*
        $vis struct $name $($rest)*
    };
    ($(#[$m:meta])* $vis:vis enum $name:ident $($rest:tt)*) => {
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$m])*
        $vis enum $name $($rest)*
    };
}
pub(crate) use schema;
