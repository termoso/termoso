//! Authentication: OPAQUE registration/login, MFA, device approval, recovery, SSO.
//!
//! All `opaque_*` fields are base64-encoded OPAQUE protocol messages produced
//! by `termoso_crypto::opaque`.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::account::{AccountKeys, UserProfile};
use crate::schema;

schema! {
    /// Client platform.
    #[derive(Copy, PartialEq, Eq, Hash)]
    #[serde(rename_all = "snake_case")]
    pub enum Platform {
        /// Windows desktop.
        Windows,
        /// Linux desktop.
        Linux,
        /// macOS desktop.
        Macos,
        /// Android.
        Android,
        /// iOS / iPadOS.
        Ios,
        /// Browser (account portal).
        Web,
        /// Command line / scripts.
        Cli,
    }
}

schema! {
    /// Description of the device performing the request.
    pub struct DeviceInfo {
        /// Human-readable device name (e.g. "Ivan's ThinkPad").
        pub name: String,
        /// Platform.
        pub platform: Platform,
        /// Client application version.
        pub app_version: String,
        /// Client-generated stable device identifier (UUID). Lets a reinstalled
        /// app re-attach to an existing device record after approval.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client_device_id: Option<Uuid>,
        /// Security facts about the device; `None` when the client cannot tell.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub posture: Option<Posture>,
    }
}

schema! {
    /// What a client knows about the security state of its own device.
    /// Each fact is `None` when it could not be determined on this platform.
    #[derive(Default, PartialEq, Eq)]
    pub struct Posture {
        /// OS version string, e.g. `14.5`, `10.0.22631`, `Ubuntu 24.04`, `Android 15`.
        pub os_version: String,
        /// System disk (or the app's data) is encrypted at rest.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub disk_encryption: Option<bool>,
        /// A password / PIN / biometric lock protects the device.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub screen_lock: Option<bool>,
        /// The device key is held by hardware (TPM, Secure Enclave, StrongBox / TEE).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub secure_key_storage: Option<bool>,
    }
}

schema! {
    /// Keys uploaded at registration (see termoso-crypto docs for the hierarchy).
    pub struct AccountKeysUpload {
        /// X25519 public key (base64, 32 bytes).
        pub public_key: String,
        /// Account private key wrapped with the account KEK (envelope, base64).
        pub wrapped_private_key: String,
        /// Account private key wrapped with the recovery KEK (envelope, base64).
        pub recovery_wrapped_private_key: String,
        /// Recovery verifier (base64, 32 bytes). The server stores only its hash.
        pub recovery_verifier: String,
        /// Personal vault key sealed to `public_key` (base64 sealed box).
        pub personal_vault_sealed_key: String,
    }
}

schema! {
    /// `POST /auth/register/start`
    pub struct RegisterStartRequest {
        /// Email address (will be lower-cased).
        pub email: String,
        /// OPAQUE `RegistrationRequest`.
        pub opaque_request: String,
        /// Cloudflare Turnstile response token; required when the server has
        /// Turnstile configured (see `ServerInfo::turnstile_site_key`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub turnstile_token: Option<String>,
    }
}

schema! {
    /// Response to `RegisterStartRequest`.
    pub struct RegisterStartResponse {
        /// OPAQUE `RegistrationResponse`.
        pub opaque_response: String,
    }
}

schema! {
    /// `POST /auth/register/finish`
    pub struct RegisterFinishRequest {
        /// Same email as in the start request.
        pub email: String,
        /// OPAQUE `RegistrationUpload`.
        pub opaque_upload: String,
        /// Optional display name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        /// Device performing the registration (gets a session immediately).
        pub device: DeviceInfo,
        /// Account keys.
        pub keys: AccountKeysUpload,
        /// Team invite token, if signing up from an invitation link.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub invite_token: Option<String>,
        /// SSO session proving the email was verified by an identity provider.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sso_session: Option<String>,
    }
}

schema! {
    /// `POST /auth/login/start`
    pub struct LoginStartRequest {
        /// Email.
        pub email: String,
        /// OPAQUE `CredentialRequest`.
        pub opaque_request: String,
        /// Device performing the login.
        pub device: DeviceInfo,
        /// SSO session (skips new-device email approval).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sso_session: Option<String>,
        /// Cloudflare Turnstile response token; required when the server has
        /// Turnstile configured (see `ServerInfo::turnstile_site_key`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub turnstile_token: Option<String>,
    }
}

schema! {
    /// Response to `LoginStartRequest`.
    pub struct LoginStartResponse {
        /// Opaque handle for the finish step (valid for a short time).
        pub login_id: String,
        /// OPAQUE `CredentialResponse`.
        pub opaque_response: String,
    }
}

schema! {
    /// `POST /auth/login/finish`
    pub struct LoginFinishRequest {
        /// From `LoginStartResponse`.
        pub login_id: String,
        /// OPAQUE `CredentialFinalization`.
        pub opaque_finalization: String,
    }
}

schema! {
    /// Available second factors.
    #[derive(Copy, PartialEq, Eq, Hash)]
    #[serde(rename_all = "snake_case")]
    pub enum MfaMethod {
        /// Time-based one-time password (RFC 6238).
        Totp,
        /// WebAuthn / passkey / FIDO2 security key.
        Webauthn,
        /// One of the single-use backup codes.
        BackupCode,
        /// Code sent by email.
        Email,
    }
}

schema! {
    /// Credential presented to satisfy MFA.
    #[serde(tag = "method", rename_all = "snake_case")]
    pub enum MfaCredential {
        /// 6-digit TOTP.
        Totp {
            /// The code.
            code: String,
        },
        /// Backup code.
        BackupCode {
            /// The code.
            code: String,
        },
        /// WebAuthn assertion (JSON as produced by `navigator.credentials.get` / platform API).
        Webauthn {
            /// PublicKeyCredential JSON.
            credential: serde_json::Value,
        },
        /// Email code.
        Email {
            /// The code.
            code: String,
        },
    }
}

schema! {
    /// `POST /auth/mfa/verify`
    pub struct MfaVerifyRequest {
        /// From `AuthResponse::MfaRequired`.
        pub mfa_token: String,
        /// The credential.
        pub credential: MfaCredential,
    }
}

schema! {
    /// `POST /auth/mfa/webauthn/challenge` – request an assertion challenge for a pending MFA.
    pub struct WebauthnChallengeRequest {
        /// From `AuthResponse::MfaRequired`.
        pub mfa_token: String,
    }
}

schema! {
    /// `POST /auth/device/approve`
    pub struct DeviceApproveRequest {
        /// From `AuthResponse::DeviceApprovalRequired`.
        pub approval_token: String,
        /// Code from the email.
        pub code: String,
    }
}

schema! {
    /// `POST /auth/device/approve/resend`
    pub struct DeviceApproveResendRequest {
        /// From `AuthResponse::DeviceApprovalRequired`.
        pub approval_token: String,
    }
}

schema! {
    /// Successful authentication payload.
    pub struct Session {
        /// Bearer token. Send as `Authorization: Bearer <token>`.
        pub token: String,
        /// Absolute expiry (sliding on use).
        pub expires_at: DateTime<Utc>,
        /// Server-side device id.
        pub device_id: Uuid,
        /// The user.
        pub user: UserProfile,
        /// Account keys needed to unlock the vaults.
        pub keys: AccountKeys,
    }
}

schema! {
    /// Outcome of a login / registration / MFA / approval step.
    #[serde(tag = "status", rename_all = "snake_case")]
    pub enum AuthResponse {
        /// Done.
        Authenticated(Session),
        /// A second factor is required.
        MfaRequired {
            /// Handle for `MfaVerifyRequest`.
            mfa_token: String,
            /// Methods the user has enabled.
            methods: Vec<MfaMethod>,
        },
        /// New device must be approved with a code sent to the account email.
        DeviceApprovalRequired {
            /// Handle for `DeviceApproveRequest`.
            approval_token: String,
            /// Masked email the code was sent to (e.g. `i***@example.com`).
            email_hint: String,
        },
        /// Step-up succeeded: the current session may perform sensitive
        /// operations until `reauth_expires_at`.
        Reauthenticated {
            /// When the step-up window closes.
            reauth_expires_at: DateTime<Utc>,
        },
    }
}

// ───────────────────────────── step-up (re-authentication) ─────────────────────────────

schema! {
    /// How the current session proves it is still the account owner.
    #[derive(Copy, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum ReauthMethod {
        /// OPAQUE login with the account password.
        Password,
        /// One-time code sent to the account email (accounts without a password).
        Email,
        /// Nothing to prove before the second factor (no password and no email
        /// on this server, but two-factor authentication is on): call `finish`
        /// right away and complete the MFA challenge it returns.
        None,
    }
}

schema! {
    /// `POST /auth/reauth/start` – begin a step-up for the current session.
    ///
    /// Sensitive account mutations (password / recovery / email / MFA / device /
    /// account deletion / SSH ID) require a fresh step-up: a bearer token alone
    /// is not enough. Recovery with the recovery phrase is a separate proof and
    /// does not use this flow.
    pub struct ReauthStartRequest {
        /// OPAQUE `CredentialRequest` for the account password. Required when the
        /// account has a password; ignored otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub opaque_request: Option<String>,
    }
}

schema! {
    /// Response to `ReauthStartRequest`.
    pub struct ReauthStartResponse {
        /// Handle for `ReauthFinishRequest`.
        pub reauth_id: String,
        /// Which proof the server expects in `finish`.
        pub method: ReauthMethod,
        /// OPAQUE `CredentialResponse` (`method == password`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub opaque_response: Option<String>,
        /// Masked email the code was sent to (`method == email`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub email_hint: Option<String>,
    }
}

schema! {
    /// `POST /auth/reauth/finish`
    pub struct ReauthFinishRequest {
        /// From `ReauthStartResponse`.
        pub reauth_id: String,
        /// OPAQUE `CredentialFinalization` (`method == password`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub opaque_finalization: Option<String>,
        /// Code from the email (`method == email`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
    }
}

// ───────────────────────────── start over ─────────────────────────────

schema! {
    /// `POST /auth/start-over/request` – for users who lost both the password
    /// and the recovery phrase. Proves email ownership, then schedules an
    /// irreversible reset: all encrypted data of the account is destroyed and a
    /// fresh key set is created. The server cannot decrypt the old data and
    /// therefore cannot restore it.
    pub struct StartOverRequest {
        /// Account email.
        pub email: String,
        /// Cloudflare Turnstile response token; required when the server has
        /// Turnstile configured (see `ServerInfo::turnstile_site_key`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub turnstile_token: Option<String>,
    }
}

schema! {
    /// Response to `StartOverRequest`. Returned whether or not the account
    /// exists so the endpoint does not reveal registered emails.
    pub struct StartOverRequestResponse {
        /// Handle for `StartOverConfirmRequest`.
        pub request_token: String,
        /// Masked email the code was sent to.
        pub email_hint: String,
    }
}

schema! {
    /// `POST /auth/start-over/confirm`
    pub struct StartOverConfirmRequest {
        /// From `StartOverRequestResponse`.
        pub request_token: String,
        /// Code from the email.
        pub code: String,
        /// Authenticator or backup code; required while two-factor
        /// authentication is enabled on the account (a reset never bypasses it).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mfa_code: Option<String>,
    }
}

schema! {
    /// Response to `StartOverConfirmRequest`: the reset is scheduled; the email
    /// received a cancel link and a link to finish once the delay has passed.
    pub struct StartOverScheduled {
        /// Earliest moment the reset can be completed.
        pub scheduled_for: DateTime<Utc>,
        /// Masked email that received the cancel / finish links.
        pub email_hint: String,
    }
}

schema! {
    /// `GET /auth/start-over/{token}` – state of a scheduled reset.
    pub struct StartOverStatus {
        /// Masked account email.
        pub email_hint: String,
        /// Account email; the client binds the new OPAQUE registration to it. Only
        /// the holder of the emailed finish token gets here.
        pub email: String,
        /// Earliest moment the reset can be completed.
        pub scheduled_for: DateTime<Utc>,
        /// Whether the delay has passed and `finish` will be accepted.
        pub ready: bool,
    }
}

schema! {
    /// `POST /auth/start-over/cancel`
    pub struct StartOverCancelRequest {
        /// Cancel token from the email.
        pub cancel_token: String,
    }
}

schema! {
    /// `POST /auth/start-over/password/start`
    pub struct StartOverPasswordStartRequest {
        /// Finish token from the email.
        pub token: String,
        /// OPAQUE `RegistrationRequest` for the new password.
        pub opaque_request: String,
    }
}

schema! {
    /// `POST /auth/start-over/finish` – destroys the old encrypted data and
    /// installs a brand-new key set. Irreversible.
    pub struct StartOverFinishRequest {
        /// Finish token from the email.
        pub token: String,
        /// OPAQUE `RegistrationUpload` for the new password.
        pub opaque_upload: String,
        /// Freshly generated keys (same shape as at registration).
        pub keys: AccountKeysUpload,
        /// Device performing the reset.
        pub device: DeviceInfo,
    }
}

// ───────────────────────────── password change / recovery ─────────────────────────────

schema! {
    /// Step 1 of setting a new password (authenticated change or recovery).
    pub struct PasswordSetupStartRequest {
        /// Recovery token (from `RecoveryStartResponse`); omitted for an authenticated change.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recovery_token: Option<String>,
        /// OPAQUE `RegistrationRequest` for the new password.
        pub opaque_request: String,
    }
}

schema! {
    /// Response to `PasswordSetupStartRequest`.
    pub struct PasswordSetupStartResponse {
        /// OPAQUE `RegistrationResponse`.
        pub opaque_response: String,
    }
}

schema! {
    /// Step 2 of setting a new password.
    pub struct PasswordSetupFinishRequest {
        /// Recovery token; omitted for an authenticated change.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recovery_token: Option<String>,
        /// OPAQUE `RegistrationUpload` for the new password.
        pub opaque_upload: String,
        /// Account private key re-wrapped with the new account KEK.
        pub wrapped_private_key: String,
        /// Optionally rotate the recovery key at the same time.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub new_recovery: Option<RecoveryRotate>,
        /// Deprecated: a new password always signs every other device out.
        /// Kept so older clients keep parsing; the value is ignored.
        #[serde(default = "default_true")]
        pub revoke_other_sessions: bool,
        /// Device performing the recovery (ignored for authenticated change).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device: Option<DeviceInfo>,
    }
}

fn default_true() -> bool {
    true
}

schema! {
    /// New recovery material.
    pub struct RecoveryRotate {
        /// Account private key wrapped with the new recovery KEK.
        pub recovery_wrapped_private_key: String,
        /// New recovery verifier (base64, 32 bytes).
        pub recovery_verifier: String,
    }
}

schema! {
    /// `POST /auth/recovery/start`
    pub struct RecoveryStartRequest {
        /// Email.
        pub email: String,
        /// Recovery verifier derived from the mnemonic (base64, 32 bytes).
        pub recovery_verifier: String,
        /// Cloudflare Turnstile response token; required when the server has
        /// Turnstile configured (see `ServerInfo::turnstile_site_key`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub turnstile_token: Option<String>,
    }
}

schema! {
    /// Response to `RecoveryStartRequest`.
    pub struct RecoveryStartResponse {
        /// Short-lived token for the password setup steps.
        pub recovery_token: String,
        /// Account private key wrapped with the recovery KEK – unwrap it locally,
        /// then re-wrap with the new account KEK.
        pub recovery_wrapped_private_key: String,
        /// Public key (to verify the unwrapped private key).
        pub public_key: String,
    }
}

// ───────────────────────────── devices ─────────────────────────────

schema! {
    /// A device / session.
    pub struct Device {
        /// Server id.
        pub id: Uuid,
        /// Name.
        pub name: String,
        /// Platform.
        pub platform: Platform,
        /// App version at last use.
        pub app_version: String,
        /// Created.
        pub created_at: DateTime<Utc>,
        /// Last request.
        pub last_seen_at: DateTime<Utc>,
        /// Last known IP (as seen by the server; stored for the user's own security review only).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_ip: Option<String>,
        /// Whether this is the device making the request.
        pub current: bool,
        /// Last reported posture, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub posture: Option<Posture>,
        /// When `posture` was reported.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub posture_at: Option<DateTime<Utc>>,
    }
}

schema! {
    /// `GET /account/devices`
    pub struct DeviceList {
        /// Devices.
        pub devices: Vec<Device>,
    }
}

// ───────────────────────────── MFA management ─────────────────────────────

schema! {
    /// `GET /account/mfa`
    pub struct MfaStatus {
        /// TOTP enabled.
        pub totp_enabled: bool,
        /// Registered WebAuthn credentials.
        pub webauthn_credentials: Vec<WebauthnCredentialInfo>,
        /// Remaining backup codes.
        pub backup_codes_remaining: u32,
    }
}

schema! {
    /// A registered WebAuthn credential.
    pub struct WebauthnCredentialInfo {
        /// Id.
        pub id: Uuid,
        /// User-given name.
        pub name: String,
        /// Created.
        pub created_at: DateTime<Utc>,
        /// Last used.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_used_at: Option<DateTime<Utc>>,
    }
}

schema! {
    /// `POST /account/mfa/totp/setup`
    pub struct TotpSetupResponse {
        /// Base32 secret (to display for manual entry).
        pub secret: String,
        /// `otpauth://` URL for QR code.
        pub otpauth_url: String,
    }
}

schema! {
    /// `POST /account/mfa/totp/confirm` and `DELETE /account/mfa/totp`
    pub struct TotpCodeRequest {
        /// 6-digit code.
        pub code: String,
    }
}

schema! {
    /// Freshly generated backup codes (shown once).
    pub struct BackupCodes {
        /// Codes.
        pub codes: Vec<String>,
    }
}

schema! {
    /// `POST /account/mfa/webauthn/register/finish`
    pub struct WebauthnRegisterFinishRequest {
        /// Name for the credential.
        pub name: String,
        /// `RegisterPublicKeyCredential` JSON.
        pub credential: serde_json::Value,
    }
}

// ───────────────────────────── SSO ─────────────────────────────

schema! {
    /// Public SSO provider description.
    pub struct SsoProvider {
        /// Provider slug used in URLs (e.g. `google`).
        pub id: String,
        /// Display name.
        pub name: String,
        /// Provider kind.
        pub kind: SsoKind,
    }
}

schema! {
    /// SSO protocol.
    #[derive(Copy, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum SsoKind {
        /// OpenID Connect.
        Oidc,
        /// SAML 2.0.
        Saml,
    }
}

schema! {
    /// `GET /auth/sso/{provider}/start`
    pub struct SsoStartResponse {
        /// URL to open in the browser.
        pub authorization_url: String,
        /// Poll handle (for desktop clients without a redirect target).
        pub flow_id: String,
    }
}

schema! {
    /// `POST /auth/logout/sso`
    pub struct SsoLogoutResponse {
        /// Open in the browser to end the identity-provider session as well
        /// (SAML Single Logout). Absent when the session did not come from
        /// SAML or the IdP has no logout endpoint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub logout_url: Option<String>,
    }
}

schema! {
    /// Result of an SSO round-trip (`GET /auth/sso/flow/{flow_id}` or deep link).
    #[serde(tag = "status", rename_all = "snake_case")]
    pub enum SsoResult {
        /// Waiting for the browser.
        Pending,
        /// Email verified via IdP; account exists → proceed to OPAQUE login with `sso_session`.
        LoginRequired {
            /// Handle proving IdP authentication.
            sso_session: String,
            /// Verified email.
            email: String,
        },
        /// Email verified via IdP; no account → proceed to registration with `sso_session`.
        RegistrationRequired {
            /// Handle proving IdP authentication.
            sso_session: String,
            /// Verified email.
            email: String,
            /// Display name from the IdP, if any.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            display_name: Option<String>,
        },
        /// Account-linking flow (`GET /account/sso/{provider}/link/start`)
        /// finished: the identity now belongs to the signed-in account.
        Linked {
            /// Provider slug.
            provider: String,
            /// Email at the identity provider.
            email: String,
        },
        /// IdP returned an error.
        Failed {
            /// Message.
            message: String,
        },
    }
}
schema! {
    /// An identity-provider account linked to the user (`GET /account/sso`).
    pub struct SsoIdentity {
        /// Provider slug.
        pub provider: String,
        /// Provider display name.
        pub name: String,
        /// Email at the identity provider when it was linked.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub email: Option<String>,
        /// When the link was made.
        pub linked_at: chrono::DateTime<chrono::Utc>,
    }
}

schema! {
    /// `GET /auth/sso/discover?email=` — home-realm discovery: the team IdP
    /// an email domain is routed to, if any.
    pub struct SsoDiscoverResponse {
        /// Team provider to start the flow with.
        #[serde(default)]
        pub provider: Option<SsoProvider>,
        /// Team that owns the provider.
        #[serde(default)]
        pub team_name: Option<String>,
        /// Password sign-in is refused for this address (team policy).
        #[serde(default)]
        pub required: bool,
    }
}
