//! Team SSH certificate authority (`/teams/{id}/ca`): the server holds one CA
//! key per team and signs short-lived user certificates for members' device
//! keys. Hosts trust the CA with a single `TrustedUserCAKeys` line, and
//! leaving the team (or losing a device) stops new certificates without
//! touching any `authorized_keys`.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::schema;
use crate::sshid::SshIdKeyType;

/// Shortest and longest certificate lifetime an admin can configure.
pub const TTL_HOURS_MIN: i32 = 1;
/// Longest certificate lifetime an admin can configure (a week).
pub const TTL_HOURS_MAX: i32 = 168;
/// Default lifetime of an issued certificate.
pub const TTL_HOURS_DEFAULT: i32 = 8;
/// How long the previous CA key stays trusted after a rotation (default and
/// ceiling, hours).
pub const ROTATION_GRACE_HOURS_DEFAULT: i32 = 24;
/// Longest grace period after a rotation (30 days).
pub const ROTATION_GRACE_HOURS_MAX: i32 = 720;
/// Most principals (login names) one team CA can hand out.
pub const PRINCIPALS_MAX: usize = 64;
/// Certificate extensions a team can enable.
pub const EXTENSIONS: [&str; 5] = [
    "permit-pty",
    "permit-port-forwarding",
    "permit-agent-forwarding",
    "permit-X11-forwarding",
    "permit-user-rc",
];
/// Extensions a new CA starts with.
pub const EXTENSIONS_DEFAULT: [&str; 3] =
    ["permit-pty", "permit-port-forwarding", "permit-user-rc"];

/// A POSIX login name a certificate may carry as a principal.
pub fn valid_principal(p: &str) -> bool {
    let mut chars = p.chars();
    let ok_first = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_');
    ok_first
        && p.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

schema! {
    /// The team's CA as seen by members (`GET /teams/{id}/ca`).
    pub struct TeamCa {
        /// Team the CA belongs to.
        pub team_id: Uuid,
        /// Algorithm of the CA key (`ssh-ed25519`).
        pub key_type: String,
        /// `TrustedUserCAKeys` line for the current key.
        pub public_key: String,
        /// `SHA256:…` of the current key.
        pub fingerprint: String,
        /// Login names certificates may be issued for; a request may ask for a
        /// subset. Empty means the CA issues nothing yet.
        pub principals: Vec<String>,
        /// Lifetime of issued certificates.
        pub ttl_hours: i32,
        /// Enabled certificate extensions (see [`EXTENSIONS`]).
        pub extensions: Vec<String>,
        /// Whether certificates are issued at all.
        pub enabled: bool,
        /// Previous key still trusted after a rotation, with its deadline.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retired_public_key: Option<String>,
        /// When the previous key stops being trusted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retired_until: Option<DateTime<Utc>>,
        /// Public URL that serves the `TrustedUserCAKeys` text (current and
        /// retired keys), for host provisioning.
        pub trusted_keys_url: String,
        /// Certificates currently valid (not expired, not revoked).
        pub active_certificates: i64,
        /// Creation time.
        pub created_at: DateTime<Utc>,
        /// Last rotation, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rotated_at: Option<DateTime<Utc>>,
        /// Last settings change.
        pub updated_at: DateTime<Utc>,
    }
}

schema! {
    /// `PUT /teams/{id}/ca`: creates the CA on first call, then updates the
    /// fields that are present.
    #[derive(Default)]
    pub struct UpdateTeamCaRequest {
        /// Replace the allowed login names.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub principals: Option<Vec<String>>,
        /// Certificate lifetime, 1..=168 hours.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ttl_hours: Option<i32>,
        /// Replace the enabled extensions.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub extensions: Option<Vec<String>>,
        /// Pause or resume issuing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
    }
}

schema! {
    /// `POST /teams/{id}/ca/rotate`.
    #[derive(Default)]
    pub struct RotateTeamCaRequest {
        /// Hours the previous key stays in the trusted list (default 24).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grace_hours: Option<i32>,
    }
}

schema! {
    /// `POST /teams/{id}/ca/issue`: sign this device's public key.
    pub struct IssueCertificateRequest {
        /// `authorized_keys` line of a software key (ed25519, ecdsa, rsa).
        pub public_key: String,
        /// Requested principals; empty means every principal the team allows.
        #[serde(default)]
        pub principals: Vec<String>,
    }
}

schema! {
    /// One issued certificate (metadata only; the certificate text is
    /// returned once, to the device that asked).
    pub struct IssuedCertificate {
        /// Certificate record id.
        pub id: Uuid,
        /// Team the CA belongs to.
        pub team_id: Uuid,
        /// Member the certificate was issued to.
        pub user_id: Uuid,
        /// Their email.
        pub user_email: String,
        /// Device that asked (gone once the device is deleted).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device_id: Option<Uuid>,
        /// Device name at listing time.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device_name: Option<String>,
        /// Certificate serial (unique per team).
        pub serial: i64,
        /// Algorithm of the certified key.
        pub key_type: SshIdKeyType,
        /// `SHA256:…` of the certified public key.
        pub key_fingerprint: String,
        /// Certificate key id (`email/device/team`).
        pub key_id: String,
        /// Login names in the certificate.
        pub principals: Vec<String>,
        /// Start of validity.
        pub valid_after: DateTime<Utc>,
        /// Expiry.
        pub valid_before: DateTime<Utc>,
        /// Revocation time, if revoked.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked_at: Option<DateTime<Utc>>,
        /// Valid right now (not expired, not revoked).
        pub active: bool,
        /// Issued to the device making the request.
        pub current_device: bool,
        /// Creation time.
        pub created_at: DateTime<Utc>,
    }
}

schema! {
    /// `POST /teams/{id}/ca/issue` response.
    pub struct IssueCertificateResponse {
        /// `ssh-ed25519-cert-v01@openssh.com AAAA…` line.
        pub certificate: String,
        /// `TrustedUserCAKeys` line of the signing key.
        pub ca_public_key: String,
        /// Metadata of the new certificate.
        pub issued: IssuedCertificate,
    }
}

schema! {
    /// `GET /teams/{id}/ca/certificates`.
    pub struct IssuedCertificateList {
        /// Newest first.
        pub certificates: Vec<IssuedCertificate>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principals() {
        for ok in ["ubuntu", "_svc", "deploy-1", "a", "www_data"] {
            assert!(valid_principal(ok), "{ok}");
        }
        for bad in [
            "",
            "Root",
            "1abc",
            "a b",
            "x".repeat(33).as_str(),
            "näme",
            "a/b",
        ] {
            assert!(!valid_principal(bad), "{bad}");
        }
    }
}
