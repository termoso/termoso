//! Account lifecycle on a device: registration, sign-in (OPAQUE + MFA + new
//! device approval), unlocking the account key, discovering vault keys and
//! signing out.
//!
//! Zero-knowledge boundary: the password only feeds the OPAQUE client, the
//! export key stays in memory for the duration of the flow, and the server
//! receives exclusively public keys, wrapped/sealed blobs and OPAQUE
//! messages. Everything secret that must survive a restart goes into the
//! encrypted [`Store`].

use std::sync::Arc;

use chrono::Utc;
use termoso_crypto::aead::{self, Aad};
use termoso_crypto::encoding::unb64;
use termoso_crypto::kdf::{Label, derive_key};
use termoso_crypto::keys::{KeyPair, SymmetricKey, public_key_from_b64};
use termoso_crypto::opaque::{self, ClientLoginState};
use termoso_crypto::recovery::RecoveryKey;
use termoso_crypto::sealed;
use termoso_proto::auth::{
    AccountKeysUpload, AuthResponse, DeviceInfo, LoginFinishRequest, LoginStartRequest,
    MfaCredential, MfaMethod, Platform, ReauthFinishRequest, ReauthMethod, ReauthStartRequest,
    RegisterFinishRequest, RegisterStartRequest, Session,
};
use termoso_proto::vault::{ResealMyKeyRequest, Vault};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api::ApiClient;
use crate::error::{CoreError, Result};
use crate::store::{LocalVaultKind, Store, StoredAccount};

/// Describe this installation to the server. `client_device_id` is the
/// stable per-store id so re-logins reuse the device record.
pub fn device_info(
    store: &Store,
    name: &str,
    platform: Platform,
    app_version: &str,
) -> Result<DeviceInfo> {
    Ok(DeviceInfo {
        name: name.to_string(),
        platform,
        app_version: app_version.to_string(),
        client_device_id: Some(store.device_id()?),
    })
}

/// Platform of the current build.
pub fn current_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else if cfg!(target_os = "android") {
        Platform::Android
    } else if cfg!(target_os = "ios") {
        Platform::Ios
    } else {
        Platform::Linux
    }
}

/// Signed-in account plus everything the rest of the core needs to talk to
/// the server on its behalf.
#[derive(Debug, Clone)]
pub struct SignedIn {
    /// Persisted profile.
    pub account: StoredAccount,
    /// Session expiry reported by the server at sign-in (`None` after a
    /// resume — the server extends it on every request).
    pub expires_at: Option<chrono::DateTime<Utc>>,
    /// Vaults now available locally (personal first).
    pub vaults: Vec<Uuid>,
}

/// What a sign-in step produced.
#[derive(Debug)]
pub enum LoginStep {
    /// Done — the store holds the session and keys.
    Done(Box<SignedIn>),
    /// The account has a second factor. Call [`LoginFlow::mfa`].
    MfaRequired {
        /// Methods the account can answer with.
        methods: Vec<MfaMethod>,
    },
    /// The server emailed a code to the account owner. Call
    /// [`LoginFlow::approve_device`].
    DeviceApprovalRequired {
        /// Masked recipient for the UI.
        email_hint: String,
    },
}

/// Multi-step sign-in. Holds the OPAQUE export key between steps so the
/// private key can be unwrapped once the server finally hands back a session.
pub struct LoginFlow {
    api: Arc<ApiClient>,
    store: Arc<Store>,
    email: String,
    export_key: Zeroizing<Vec<u8>>,
    mfa_token: Option<String>,
    approval_token: Option<String>,
}

impl std::fmt::Debug for LoginFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginFlow")
            .field("email", &self.email)
            .field("mfa_pending", &self.mfa_token.is_some())
            .field("approval_pending", &self.approval_token.is_some())
            .finish()
    }
}

impl LoginFlow {
    /// Run the OPAQUE exchange. On success the session (or the next
    /// challenge) is returned together with the flow to continue it.
    pub async fn start(
        api: Arc<ApiClient>,
        store: Arc<Store>,
        email: &str,
        password: &str,
        device: DeviceInfo,
        sso_session: Option<String>,
        turnstile_token: Option<String>,
    ) -> Result<(Self, LoginStep)> {
        let email = email.trim().to_lowercase();
        let (request, state) = opaque::client_login_start(password.as_bytes())?;
        let start = api
            .login_start(&LoginStartRequest {
                email: email.clone(),
                opaque_request: request,
                device,
                sso_session,
                turnstile_token,
            })
            .await?;
        let out = finish_opaque(state, password, &email, &start.opaque_response)?;
        let export_key = Zeroizing::new(out.export_key.to_vec());
        let resp = api
            .login_finish(&LoginFinishRequest {
                login_id: start.login_id,
                opaque_finalization: out.finalization_b64,
            })
            .await?;
        let mut flow = Self {
            api,
            store,
            email,
            export_key,
            mfa_token: None,
            approval_token: None,
        };
        let step = flow.handle(resp).await?;
        Ok((flow, step))
    }

    /// Answer the second factor.
    pub async fn mfa(&mut self, credential: MfaCredential) -> Result<LoginStep> {
        let token = self
            .mfa_token
            .clone()
            .ok_or_else(|| CoreError::Invalid("no MFA challenge pending".into()))?;
        let resp = self.api.mfa_verify(&token, credential).await?;
        self.handle(resp).await
    }

    /// Ask the server to email a one-time MFA code (method `email`).
    pub async fn send_mfa_email(&self) -> Result<()> {
        let token = self
            .mfa_token
            .as_deref()
            .ok_or_else(|| CoreError::Invalid("no MFA challenge pending".into()))?;
        self.api.mfa_email_send(token).await
    }

    /// WebAuthn request options for the platform authenticator.
    pub async fn webauthn_challenge(&self) -> Result<serde_json::Value> {
        let token = self
            .mfa_token
            .as_deref()
            .ok_or_else(|| CoreError::Invalid("no MFA challenge pending".into()))?;
        self.api.mfa_webauthn_challenge(token).await
    }

    /// Submit the emailed new-device code.
    pub async fn approve_device(&mut self, code: &str) -> Result<LoginStep> {
        let token = self
            .approval_token
            .clone()
            .ok_or_else(|| CoreError::Invalid("no device approval pending".into()))?;
        let resp = self.api.device_approve(&token, code.trim()).await?;
        self.handle(resp).await
    }

    /// Re-send the new-device code.
    pub async fn resend_device_code(&self) -> Result<()> {
        let token = self
            .approval_token
            .as_deref()
            .ok_or_else(|| CoreError::Invalid("no device approval pending".into()))?;
        self.api.device_approve_resend(token).await
    }

    async fn handle(&mut self, resp: AuthResponse) -> Result<LoginStep> {
        match resp {
            AuthResponse::Authenticated(session) => {
                let private_key = unlock_private_key(&self.export_key, &session)?;
                let signed =
                    install_session(&self.api, &self.store, &session, &private_key).await?;
                Ok(LoginStep::Done(Box::new(signed)))
            }
            AuthResponse::MfaRequired { mfa_token, methods } => {
                self.mfa_token = Some(mfa_token);
                Ok(LoginStep::MfaRequired { methods })
            }
            AuthResponse::DeviceApprovalRequired {
                approval_token,
                email_hint,
            } => {
                self.approval_token = Some(approval_token);
                Ok(LoginStep::DeviceApprovalRequired { email_hint })
            }
            AuthResponse::Reauthenticated { .. } => Err(CoreError::Invalid(
                "unexpected step-up answer during sign-in".into(),
            )),
        }
    }
}

/// What a step-up (re-authentication) step produced.
#[derive(Debug)]
pub enum ReauthStep {
    /// The session may perform sensitive changes until `expires_at`.
    Done {
        /// When the step-up window closes.
        expires_at: chrono::DateTime<Utc>,
    },
    /// The account has a second factor. Call [`ReauthFlow::mfa`].
    MfaRequired {
        /// Methods the account can answer with.
        methods: Vec<MfaMethod>,
    },
    /// The account has no password; the server emailed a code. Call
    /// [`ReauthFlow::email_code`].
    EmailCodeRequired {
        /// Masked recipient for the UI.
        email_hint: String,
    },
}

/// Step-up for the current session: sensitive account mutations (revoking
/// devices, deleting security keys, dropping the SSH ID, ...) answer
/// `reauth_required` until the owner proves the password (and second factor)
/// again. The password feeds the OPAQUE client only, exactly as at sign-in.
pub struct ReauthFlow {
    api: Arc<ApiClient>,
    reauth_id: String,
    mfa_token: Option<String>,
}

impl std::fmt::Debug for ReauthFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReauthFlow")
            .field("mfa_pending", &self.mfa_token.is_some())
            .finish_non_exhaustive()
    }
}

impl ReauthFlow {
    /// Prove the password for the signed-in session. Accounts without a
    /// password (SSO) get an emailed code instead; `password` is ignored then.
    pub async fn start(
        api: Arc<ApiClient>,
        email: &str,
        password: &str,
    ) -> Result<(Self, ReauthStep)> {
        let email = email.trim().to_lowercase();
        let (request, state) = opaque::client_login_start(password.as_bytes())?;
        let start = api
            .reauth_start(&ReauthStartRequest {
                opaque_request: Some(request),
            })
            .await?;
        let mut flow = Self {
            api,
            reauth_id: start.reauth_id,
            mfa_token: None,
        };
        match start.method {
            ReauthMethod::Password => {
                let response = start
                    .opaque_response
                    .as_deref()
                    .ok_or_else(|| CoreError::Invalid("server sent no OPAQUE response".into()))?;
                let out = finish_opaque(state, password, &email, response)?;
                let step = flow.finish(Some(out.finalization_b64), None).await?;
                Ok((flow, step))
            }
            ReauthMethod::Email => Ok((
                flow,
                ReauthStep::EmailCodeRequired {
                    email_hint: start.email_hint.unwrap_or_default(),
                },
            )),
            ReauthMethod::None => {
                let step = flow.finish(None, None).await?;
                Ok((flow, step))
            }
        }
    }

    /// Submit the emailed code (method `email`).
    pub async fn email_code(&mut self, code: &str) -> Result<ReauthStep> {
        self.finish(None, Some(code.trim().to_string())).await
    }

    /// Answer the second factor.
    pub async fn mfa(&mut self, credential: MfaCredential) -> Result<ReauthStep> {
        let token = self
            .mfa_token
            .clone()
            .ok_or_else(|| CoreError::Invalid("no MFA challenge pending".into()))?;
        let resp = self.api.mfa_verify(&token, credential).await?;
        self.handle(resp)
    }

    /// Ask the server to email a one-time MFA code (method `email`).
    pub async fn send_mfa_email(&self) -> Result<()> {
        let token = self
            .mfa_token
            .as_deref()
            .ok_or_else(|| CoreError::Invalid("no MFA challenge pending".into()))?;
        self.api.mfa_email_send(token).await
    }

    /// WebAuthn request options for the platform authenticator.
    pub async fn webauthn_challenge(&self) -> Result<serde_json::Value> {
        let token = self
            .mfa_token
            .as_deref()
            .ok_or_else(|| CoreError::Invalid("no MFA challenge pending".into()))?;
        self.api.mfa_webauthn_challenge(token).await
    }

    async fn finish(
        &mut self,
        opaque_finalization: Option<String>,
        code: Option<String>,
    ) -> Result<ReauthStep> {
        let resp = self
            .api
            .reauth_finish(&ReauthFinishRequest {
                reauth_id: self.reauth_id.clone(),
                opaque_finalization,
                code,
            })
            .await?;
        self.handle(resp)
    }

    fn handle(&mut self, resp: AuthResponse) -> Result<ReauthStep> {
        match resp {
            AuthResponse::Reauthenticated { reauth_expires_at } => Ok(ReauthStep::Done {
                expires_at: reauth_expires_at,
            }),
            AuthResponse::MfaRequired { mfa_token, methods } => {
                self.mfa_token = Some(mfa_token);
                Ok(ReauthStep::MfaRequired { methods })
            }
            AuthResponse::Authenticated(_) | AuthResponse::DeviceApprovalRequired { .. } => Err(
                CoreError::Invalid("unexpected sign-in answer during step-up".into()),
            ),
        }
    }
}

/// Inputs for a new account.
#[derive(Debug, Clone)]
pub struct RegisterInput {
    /// Email.
    pub email: String,
    /// Master password (never leaves the OPAQUE client).
    pub password: String,
    /// Optional display name.
    pub display_name: Option<String>,
    /// This device.
    pub device: DeviceInfo,
    /// Team invitation to accept on creation.
    pub invite_token: Option<String>,
    /// Verified SSO session to bind.
    pub sso_session: Option<String>,
    /// Cloudflare Turnstile token when the server demands one
    /// (`turnstile_required`); native clients get it from `/captcha`.
    pub turnstile_token: Option<String>,
}

/// Result of a successful registration.
pub struct Registered {
    /// Signed-in state (the store is populated).
    pub signed_in: SignedIn,
    /// 24-word recovery phrase. Shown exactly once; it is not stored anywhere.
    pub recovery_phrase: Zeroizing<String>,
}

impl std::fmt::Debug for Registered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registered")
            .field("signed_in", &self.signed_in)
            .finish_non_exhaustive()
    }
}

/// Create an account: OPAQUE registration, fresh account keypair, recovery
/// key and personal vault key, all generated here. The server gets the
/// public key and wrapped/sealed blobs only.
pub async fn register(
    api: Arc<ApiClient>,
    store: Arc<Store>,
    input: RegisterInput,
) -> Result<Registered> {
    let email = input.email.trim().to_lowercase();
    let (request, state) = opaque::client_registration_start(input.password.as_bytes())?;
    let start = api
        .register_start(&RegisterStartRequest {
            email: email.clone(),
            opaque_request: request,
            turnstile_token: input.turnstile_token.clone(),
        })
        .await?;
    let out = opaque::client_registration_finish(
        state,
        input.password.as_bytes(),
        &email,
        &start.opaque_response,
    )?;
    let export_key = Zeroizing::new(out.export_key.to_vec());

    let kek = derive_key(&export_key, Label::AccountKek)?;
    let pair = KeyPair::generate();
    let recovery = RecoveryKey::generate();
    let recovery_kek = recovery.kek()?;
    let personal_vault_key = SymmetricKey::generate();
    let secret = SymmetricKey::from_bytes(pair.secret_bytes());

    let keys = AccountKeysUpload {
        public_key: pair.public_b64(),
        wrapped_private_key: aead::wrap_key(&kek, &Aad::account_private_key(), &secret)?,
        recovery_wrapped_private_key: aead::wrap_key(
            &recovery_kek,
            &Aad::recovery_private_key(),
            &secret,
        )?,
        recovery_verifier: recovery.verifier_b64()?,
        personal_vault_sealed_key: sealed::seal_vault_key_self(&pair, &personal_vault_key)?,
    };

    let resp = api
        .register_finish(&RegisterFinishRequest {
            email,
            opaque_upload: out.upload_b64,
            display_name: input.display_name,
            device: input.device,
            keys,
            invite_token: input.invite_token,
            sso_session: input.sso_session,
        })
        .await?;
    let AuthResponse::Authenticated(session) = resp else {
        return Err(CoreError::Invalid(
            "server did not return a session after registration".into(),
        ));
    };
    let private_key = unlock_private_key(&export_key, &session)?;
    let signed_in = install_session(&api, &store, &session, &private_key).await?;
    Ok(Registered {
        signed_in,
        recovery_phrase: Zeroizing::new(recovery.phrase()),
    })
}

/// Resume a previously persisted session: installs the token on the API
/// client and refreshes profile + vault keys. Returns `Ok(None)` when no
/// account is stored.
pub async fn resume(api: &ApiClient, store: &Store) -> Result<Option<SignedIn>> {
    if store.account()?.is_none() {
        return Ok(None);
    }
    let secrets = store.account_secrets()?;
    api.set_token(Some(secrets.token));
    let me = api.account().await?;
    store.update_account_profile(
        &me.user.email,
        me.user.display_name.as_deref(),
        me.user.avatar.as_deref(),
        me.user.is_admin,
    )?;
    let vaults = refresh_vaults(api, store).await?;
    let account = store.account()?.ok_or(CoreError::NotSignedIn)?;
    Ok(Some(SignedIn {
        account,
        expires_at: None,
        vaults,
    }))
}

/// Sign out: revoke the session on the server (best effort) and forget the
/// token, account keys and synced vaults locally. The local vault stays.
pub async fn sign_out(api: &ApiClient, store: &Store) -> Result<()> {
    if api.token().is_some() {
        match api.logout().await {
            Ok(()) => {}
            Err(e) if e.is_unauthorized() => {}
            Err(e) => tracing::warn!("server logout failed: {e}"),
        }
    }
    sign_out_local(api, store)
}

/// Forget the session locally without contacting the server (revoked
/// session, offline sign-out).
pub fn sign_out_local(api: &ApiClient, store: &Store) -> Result<()> {
    api.set_token(None);
    crate::sshid::forget(store)?;
    crate::ca::forget_certificates(store)?;
    crate::policy::clear(store)?;
    store.clear_account()
}

/// Fetch `GET /vaults`, open every sealed key with the account private key
/// and mirror the list into the store. Vaults we lost access to are removed.
/// When the key version moved, everything we hold is re-encrypted under the
/// new key and queued for push (the protocol has members re-upload after a
/// rotation). Returns the ids of unlocked vaults.
pub async fn refresh_vaults(api: &ApiClient, store: &Store) -> Result<Vec<Uuid>> {
    let remote = api.vaults().await?;
    let secrets = store.account_secrets()?;
    let applied = apply_vault_list(store, &secrets.private_key, &remote)?;
    for (id, key_version) in applied.reseal {
        let sealed_key = sealed::seal_vault_key_self(&secrets.private_key, &store.vault_key(id)?)?;
        if let Err(e) = api
            .reseal_my_key(
                id,
                &ResealMyKeyRequest {
                    key_version,
                    sealed_key,
                },
            )
            .await
        {
            tracing::warn!(vault = %id, "cannot upgrade personal vault key envelope: {e}");
        }
    }
    Ok(applied.unlocked)
}

struct AppliedVaults {
    /// Ids of vaults whose key we hold, personal vault first.
    unlocked: Vec<Uuid>,
    /// Personal vaults whose server-side envelope is still an anonymous
    /// sealed box and should be re-sealed to ourselves: `(id, key_version)`.
    reseal: Vec<(Uuid, i32)>,
}

/// Mirror the server's vault list into the store, deciding per vault whether
/// the offered key may replace the one we hold. The server is not trusted
/// with key material, so:
///
/// * a key we already hold is never replaced at the same `key_version`;
/// * `key_version` never moves backwards;
/// * for the personal vault a new key is only accepted from a
///   self-authenticated envelope (produced with the account private key);
///   team vault keys are sealed by a team manager, whose identity the
///   anonymous sealed box cannot prove (see SECURITY.md);
/// * a vault we have no key for yet accepts whatever opens (first use).
fn apply_vault_list(
    store: &Store,
    private_key: &KeyPair,
    remote: &[Vault],
) -> Result<AppliedVaults> {
    let local = store.vaults()?;
    let mut unlocked = Vec::new();
    let mut reseal = Vec::new();
    for v in remote {
        let existing = local.iter().find(|l| l.id == v.id);
        let offered = match &v.sealed_key {
            Some(sealed) => match sealed::open_vault_key_checked(private_key, sealed) {
                Ok(k) => Some(k),
                Err(e) => {
                    tracing::warn!(vault = %v.id, "cannot open sealed vault key: {e}");
                    None
                }
            },
            None => None,
        };
        let held = match existing {
            Some(l) if l.unlocked => Some((store.vault_key(l.id)?, l.key_version)),
            _ => None,
        };
        let personal = v.kind == termoso_proto::vault::VaultKind::Personal;
        let offered_origin = offered.as_ref().map(|(_, o)| *o);
        // (key to install, key to re-encrypt from, key_version to record)
        let (install, rotated_from, key_version) = match (held, offered) {
            (None, Some((k, _))) => (Some(k), None, v.key_version),
            (None, None) => (None, None, v.key_version),
            (Some((h, hv)), Some((k, _))) if hv == v.key_version => {
                if h.as_bytes() != k.as_bytes() {
                    tracing::warn!(vault = %v.id, "server offered a different key for the version we hold; ignoring");
                }
                (None, None, hv)
            }
            (Some((_, hv)), Some(_)) if v.key_version < hv => {
                tracing::warn!(vault = %v.id, "server rolled the vault key version back ({} -> {}); ignoring", hv, v.key_version);
                (None, None, hv)
            }
            (Some((_, hv)), Some((_, origin)))
                if personal && origin != sealed::SealedKeyOrigin::SelfAuthenticated =>
            {
                tracing::warn!(vault = %v.id, "refusing personal vault key rotation: envelope was not produced with the account key");
                (None, None, hv)
            }
            (Some((h, _)), Some((k, _))) => (Some(k), Some(h), v.key_version),
            (Some((_, hv)), None) => (None, None, hv),
        };
        store.upsert_vault(
            v.id,
            LocalVaultKind::from(v.kind),
            &v.name,
            v.team_id,
            v.my_role,
            install.as_ref(),
            key_version,
        )?;
        store.set_vault_session_logging(v.id, v.session_logging)?;
        store.set_vault_default(v.id, v.is_default)?;
        if let Some(old) = rotated_from {
            store.reencrypt_vault(v.id, &old)?;
        }
        let now_unlocked = install.is_some() || existing.is_some_and(|l| l.unlocked);
        if now_unlocked {
            unlocked.push(v.id);
        }
        if personal
            && now_unlocked
            && key_version == v.key_version
            && offered_origin == Some(sealed::SealedKeyOrigin::Anonymous)
        {
            reseal.push((v.id, v.key_version));
        }
    }
    for l in local.iter().filter(|l| l.kind.is_synced()) {
        if !remote.iter().any(|v| v.id == l.id) {
            store.remove_vault(l.id)?;
        }
    }
    // Personal vault first so callers that want "the" vault get it cheaply.
    unlocked.sort_by_key(|id| {
        remote.iter().position(|v| v.id == *id).map(|p| {
            (
                remote[p].kind != termoso_proto::vault::VaultKind::Personal,
                p,
            )
        })
    });
    Ok(AppliedVaults { unlocked, reseal })
}

fn finish_opaque(
    state: ClientLoginState,
    password: &str,
    email: &str,
    response_b64: &str,
) -> Result<opaque::ClientLoginOutput> {
    opaque::client_login_finish(state, password.as_bytes(), email, response_b64).map_err(|e| {
        // A wrong password surfaces as an envelope failure on the client side.
        match e {
            termoso_crypto::CryptoError::Opaque(_) => CoreError::Api {
                status: 401,
                code: termoso_proto::error::codes::INVALID_CREDENTIALS.into(),
                message: "Invalid email or password".into(),
            },
            other => other.into(),
        }
    })
}

fn unlock_private_key(export_key: &[u8], session: &Session) -> Result<KeyPair> {
    let kek = derive_key(export_key, Label::AccountKek)?;
    let secret = aead::unwrap_key(
        &kek,
        &Aad::account_private_key(),
        &session.keys.wrapped_private_key,
    )?;
    let pair = KeyPair::from_secret_bytes(secret.as_bytes())?;
    let expected = public_key_from_b64(&session.keys.public_key)?;
    if pair.public().as_bytes() != expected.as_bytes() {
        return Err(CoreError::Crypto(termoso_crypto::CryptoError::Key));
    }
    // Sanity: the server must hand back valid base64 for the public key it
    // claims we own.
    unb64(&session.keys.public_key)?;
    Ok(pair)
}

async fn install_session(
    api: &ApiClient,
    store: &Store,
    session: &Session,
    private_key: &KeyPair,
) -> Result<SignedIn> {
    let account = StoredAccount {
        server_url: api.server_url().to_string(),
        user_id: session.user.id,
        email: session.user.email.clone(),
        display_name: session.user.display_name.clone(),
        avatar: session.user.avatar.clone(),
        is_admin: session.user.is_admin,
        device_id: session.device_id,
        public_key: session.keys.public_key.clone(),
        key_version: session.keys.key_version,
        history_cursor: 0,
        logs_cursor: 0,
        signed_in_at: Utc::now(),
    };
    // A different user than the one previously stored: drop their synced data.
    if let Some(prev) = store.account()?
        && prev.user_id != account.user_id
    {
        store.clear_account()?;
    }
    store.save_account(&account, &session.token, private_key)?;
    api.set_token(Some(session.token.clone()));
    let vaults = match refresh_vaults(api, store).await {
        Ok(v) => v,
        Err(e) => {
            // Roll back so a half-installed session cannot linger.
            let _ = sign_out_local(api, store);
            return Err(e);
        }
    };
    Ok(SignedIn {
        account,
        expires_at: Some(session.expires_at),
        vaults,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoso_proto::vault::{VaultKind, VaultRole};

    fn vault(id: Uuid, kind: VaultKind, sealed: Option<String>, kv: i32) -> Vault {
        Vault {
            id,
            kind,
            team_id: (kind == VaultKind::Team).then(Uuid::new_v4),
            name: "v".into(),
            created_at: Utc::now(),
            my_role: VaultRole::Editor,
            sealed_key: sealed,
            key_version: kv,
            session_logging: false,
            is_default: false,
        }
    }

    #[test]
    fn vault_list_is_mirrored_into_store() {
        let store = Store::open_in_memory(SymmetricKey::generate()).unwrap();
        let me = KeyPair::generate();
        let personal_key = SymmetricKey::generate();
        let team_key = SymmetricKey::generate();
        let personal = Uuid::new_v4();
        let team = Uuid::new_v4();
        let pending = Uuid::new_v4();
        let remote = vec![
            vault(
                team,
                VaultKind::Team,
                Some(sealed::seal_vault_key(me.public(), &team_key).unwrap()),
                1,
            ),
            vault(
                personal,
                VaultKind::Personal,
                Some(sealed::seal_vault_key(me.public(), &personal_key).unwrap()),
                1,
            ),
            vault(pending, VaultKind::Team, None, 1),
        ];
        let applied = apply_vault_list(&store, &me, &remote).unwrap();
        assert_eq!(applied.unlocked, vec![personal, team]);
        // Legacy anonymous personal envelope: accepted on first use, queued for upgrade.
        assert_eq!(applied.reseal, vec![(personal, 1)]);
        assert_eq!(
            store.vault_key(personal).unwrap().as_bytes(),
            personal_key.as_bytes()
        );
        assert!(matches!(
            store.vault_key(pending),
            Err(CoreError::VaultLocked(_))
        ));
        assert_eq!(store.vaults().unwrap().len(), 4); // + local

        // Lost access to the team vault, key rotated on the personal one.
        let host_id = Uuid::new_v4();
        store
            .put_raw(
                personal,
                "host",
                host_id,
                &serde_json::json!({"label": "a"}),
            )
            .unwrap();
        store.mark_pushed(host_id, 1, 1).unwrap();
        assert_eq!(store.pending_changes().unwrap(), 0);
        let new_personal = SymmetricKey::generate();
        store.set_vault_cursor(personal, 42).unwrap();
        let remote = vec![vault(
            personal,
            VaultKind::Personal,
            Some(sealed::seal_vault_key_self(&me, &new_personal).unwrap()),
            2,
        )];
        let applied = apply_vault_list(&store, &me, &remote).unwrap();
        assert_eq!(applied.unlocked, vec![personal]);
        assert!(applied.reseal.is_empty());
        assert!(store.vault(team).is_err());
        let v = store.vault(personal).unwrap();
        assert_eq!((v.key_version, v.cursor), (2, 42));
        assert_eq!(
            store.vault_key(personal).unwrap().as_bytes(),
            new_personal.as_bytes()
        );
        // Entities were re-encrypted under the new key and queued for push.
        let row = store.row(host_id).unwrap().unwrap();
        assert!(row.dirty && row.key_version == 2);
        let listed = store
            .list_any(&crate::store::EntityFilter {
                vault_id: Some(personal),
                kind: None,
                include_deleted: false,
            })
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].data["label"], "a");
    }

    /// A server (or anyone who knows our public key) must not be able to swap
    /// the personal vault key for one it knows: at the same version the held
    /// key wins, at a newer version only a self-authenticated envelope counts,
    /// and the version never moves backwards.
    #[test]
    fn personal_key_is_not_replaced_by_server_supplied_envelopes() {
        let store = Store::open_in_memory(SymmetricKey::generate()).unwrap();
        let me = KeyPair::generate();
        let real = SymmetricKey::generate();
        let personal = Uuid::new_v4();
        let remote = vec![vault(
            personal,
            VaultKind::Personal,
            Some(sealed::seal_vault_key_self(&me, &real).unwrap()),
            1,
        )];
        let applied = apply_vault_list(&store, &me, &remote).unwrap();
        assert_eq!(applied.unlocked, vec![personal]);
        assert!(applied.reseal.is_empty());
        let host_id = Uuid::new_v4();
        store
            .put_raw(
                personal,
                "host",
                host_id,
                &serde_json::json!({"label": "a"}),
            )
            .unwrap();
        store.mark_pushed(host_id, 1, 1).unwrap();

        let evil = SymmetricKey::generate();
        let holds_real = |store: &Store| {
            let v = store.vault(personal).unwrap();
            assert!(v.unlocked);
            assert_eq!(v.key_version, 1);
            assert_eq!(
                store.vault_key(personal).unwrap().as_bytes(),
                real.as_bytes()
            );
            let row = store.row(host_id).unwrap().unwrap();
            assert!(!row.dirty && row.key_version == 1);
        };

        // Same version, different key (anonymous envelope): ignored.
        let remote = vec![vault(
            personal,
            VaultKind::Personal,
            Some(sealed::seal_vault_key(me.public(), &evil).unwrap()),
            1,
        )];
        let applied = apply_vault_list(&store, &me, &remote).unwrap();
        assert_eq!(applied.unlocked, vec![personal]);
        holds_real(&store);
        // ...and we would overwrite the server copy with our own key, not adopt theirs.
        assert_eq!(applied.reseal, vec![(personal, 1)]);

        // "Rotation" to a key the server made up (anonymous envelope): refused,
        // nothing is re-encrypted, local version stays.
        let remote = vec![vault(
            personal,
            VaultKind::Personal,
            Some(sealed::seal_vault_key(me.public(), &evil).unwrap()),
            2,
        )];
        let applied = apply_vault_list(&store, &me, &remote).unwrap();
        assert_eq!(applied.unlocked, vec![personal]);
        assert!(applied.reseal.is_empty());
        holds_real(&store);

        // Version rollback with the (old) real key: refused too.
        let remote = vec![vault(
            personal,
            VaultKind::Personal,
            Some(sealed::seal_vault_key_self(&me, &real).unwrap()),
            0,
        )];
        apply_vault_list(&store, &me, &remote).unwrap();
        holds_real(&store);

        // Missing envelope keeps the held key.
        let remote = vec![vault(personal, VaultKind::Personal, None, 1)];
        let applied = apply_vault_list(&store, &me, &remote).unwrap();
        assert_eq!(applied.unlocked, vec![personal]);
        holds_real(&store);

        // A genuine rotation from another of our devices is accepted.
        let rotated = SymmetricKey::generate();
        let remote = vec![vault(
            personal,
            VaultKind::Personal,
            Some(sealed::seal_vault_key_self(&me, &rotated).unwrap()),
            2,
        )];
        apply_vault_list(&store, &me, &remote).unwrap();
        let v = store.vault(personal).unwrap();
        assert_eq!(v.key_version, 2);
        assert_eq!(
            store.vault_key(personal).unwrap().as_bytes(),
            rotated.as_bytes()
        );
        let row = store.row(host_id).unwrap().unwrap();
        assert!(row.dirty && row.key_version == 2);
    }

    /// Team keys are sealed by a manager (anonymous box), so a rotation is
    /// accepted, but the same-version and rollback rules still apply.
    #[test]
    fn team_key_same_version_and_rollback_are_ignored() {
        let store = Store::open_in_memory(SymmetricKey::generate()).unwrap();
        let me = KeyPair::generate();
        let k1 = SymmetricKey::generate();
        let k2 = SymmetricKey::generate();
        let team = Uuid::new_v4();
        let seal = |k: &SymmetricKey| Some(sealed::seal_vault_key(me.public(), k).unwrap());
        apply_vault_list(&store, &me, &[vault(team, VaultKind::Team, seal(&k1), 1)]).unwrap();
        apply_vault_list(&store, &me, &[vault(team, VaultKind::Team, seal(&k2), 1)]).unwrap();
        assert_eq!(store.vault_key(team).unwrap().as_bytes(), k1.as_bytes());
        let applied =
            apply_vault_list(&store, &me, &[vault(team, VaultKind::Team, seal(&k2), 2)]).unwrap();
        assert!(applied.reseal.is_empty());
        assert_eq!(store.vault_key(team).unwrap().as_bytes(), k2.as_bytes());
        apply_vault_list(&store, &me, &[vault(team, VaultKind::Team, seal(&k1), 1)]).unwrap();
        assert_eq!(store.vault(team).unwrap().key_version, 2);
        assert_eq!(store.vault_key(team).unwrap().as_bytes(), k2.as_bytes());
    }

    #[test]
    fn unlock_checks_public_key() {
        let export = [7u8; 64];
        let kek = derive_key(&export, Label::AccountKek).unwrap();
        let pair = KeyPair::generate();
        let wrapped = aead::wrap_key(
            &kek,
            &Aad::account_private_key(),
            &SymmetricKey::from_bytes(pair.secret_bytes()),
        )
        .unwrap();
        let mut session = Session {
            token: "t".into(),
            expires_at: Utc::now(),
            device_id: Uuid::new_v4(),
            user: termoso_proto::account::UserProfile {
                id: Uuid::new_v4(),
                email: "a@b".into(),
                email_verified: false,
                display_name: None,
                created_at: Utc::now(),
                is_admin: false,
                is_owner: false,
                mfa_enabled: false,
                reset_scheduled_for: None,
                presence_hidden: false,
                avatar: None,
                managed_by_team_id: None,
            },
            keys: termoso_proto::account::AccountKeys {
                public_key: pair.public_b64(),
                wrapped_private_key: wrapped,
                key_version: 1,
            },
        };
        let got = unlock_private_key(&export, &session).unwrap();
        assert_eq!(got.public_bytes(), pair.public_bytes());
        assert!(unlock_private_key(&[8u8; 64], &session).is_err());
        session.keys.public_key = KeyPair::generate().public_b64();
        assert!(unlock_private_key(&export, &session).is_err());
    }
}
