//! HTTP routing.

pub mod access;
pub mod access_reviews;
pub mod account;
pub mod acl;
pub mod admin;
pub mod ai;
pub mod auth;
pub mod automations;
pub mod break_glass;
pub mod bridges;
pub mod ca;
pub mod captcha;
pub mod gdpr;
pub mod history;
pub mod idp;
pub mod logs;
pub mod mfa;
pub mod policies;
pub mod roles;
pub mod rotation;
pub mod scim_admin;
pub mod server;
pub mod sshid;
pub mod sshid_page;
pub mod start_over;
pub mod sync;
pub mod teams;
pub mod trust;
pub mod vaults;
pub mod web;

use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method, header};
use axum::routing::{delete, get, patch, post, put};
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// 8 MiB: a full sync push of 500 × 16 KiB entities fits comfortably.
const BODY_LIMIT: usize = 8 * 1024 * 1024;

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/server/info", get(server::info))
        // auth
        .route("/auth/register/start", post(auth::register_start))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/start", post(auth::login_start))
        .route("/auth/login/finish", post(auth::login_finish))
        .route("/auth/mfa/verify", post(auth::mfa_verify))
        .route(
            "/auth/mfa/webauthn/challenge",
            post(auth::mfa_webauthn_challenge),
        )
        .route("/auth/mfa/email/send", post(auth::mfa_email_send))
        .route("/auth/device/approve", post(auth::device_approve))
        .route(
            "/auth/device/approve/resend",
            post(auth::device_approve_resend),
        )
        .route("/auth/recovery/start", post(auth::recovery_start))
        .route("/auth/password/start", post(auth::password_start))
        .route("/auth/password/finish", post(auth::password_finish))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/logout/sso", post(auth::logout_sso))
        .route("/auth/reauth/start", post(auth::reauth_start))
        .route("/auth/reauth/finish", post(auth::reauth_finish))
        .route("/auth/start-over/request", post(start_over::request))
        .route("/auth/start-over/confirm", post(start_over::confirm))
        .route("/auth/start-over/cancel", post(start_over::cancel))
        .route(
            "/auth/start-over/password/start",
            post(start_over::password_start),
        )
        .route("/auth/start-over/finish", post(start_over::finish))
        .route("/auth/start-over/{token}", get(start_over::status))
        .route(
            "/account/start-over/cancel",
            post(start_over::cancel_authenticated),
        )
        .route("/auth/sso/providers", get(auth::sso_providers))
        .route("/auth/sso/discover", get(idp::discover))
        .route("/auth/sso/callback", get(auth::sso_callback))
        .route("/auth/sso/flow/{flow_id}", get(auth::sso_poll))
        .route("/auth/sso/{provider}/start", get(auth::sso_start))
        .route(
            "/auth/sso/{provider}/saml/metadata",
            get(auth::sso_saml_metadata),
        )
        .route("/auth/sso/saml/post/{flow_id}", get(auth::sso_saml_post))
        .route("/auth/sso/saml/acs", post(auth::sso_saml_acs))
        .route(
            "/auth/sso/saml/slo",
            get(auth::sso_saml_slo_redirect).post(auth::sso_saml_slo_post),
        )
        // account
        .route(
            "/account",
            get(account::get).delete(account::delete_account),
        )
        .route("/account/profile", patch(account::update_profile))
        .route("/account/presence", put(account::put_presence))
        .route("/account/ai", get(ai::status).put(ai::put_settings))
        .route("/ai/command", post(ai::command))
        .route(
            "/account/avatar",
            put(account::put_avatar)
                .delete(account::delete_avatar)
                .layer(DefaultBodyLimit::max(crate::avatar::MAX_UPLOAD)),
        )
        .route("/users/{id}/avatar", get(account::user_avatar))
        .route(
            "/account/email/verify/send",
            post(account::email_verify_send),
        )
        .route(
            "/account/email/verify/confirm",
            post(account::email_verify_confirm),
        )
        .route("/account/email/change", post(account::email_change))
        .route(
            "/account/email/change/confirm",
            post(account::email_change_confirm),
        )
        .route(
            "/account/settings",
            get(account::get_settings).put(account::put_settings),
        )
        .route("/account/devices", get(account::devices))
        .route("/account/devices/{id}", delete(account::revoke_device))
        .route("/account/bridges", get(bridges::list).post(bridges::create))
        .route("/account/bridges/{id}", delete(bridges::revoke))
        .route("/account/bridges/{id}/vaults", put(bridges::set_vaults))
        .route("/bridge/me", get(bridges::me))
        .route(
            "/account/sshid",
            get(sshid::get).post(sshid::create).delete(sshid::delete),
        )
        .route("/account/sshid/keys/device", put(sshid::put_device_keys))
        .route("/account/sshid/keys", post(sshid::add_public_key))
        .route("/account/sshid/keys/fido2", post(sshid::add_fido2_key))
        .route("/account/sshid/keys/{id}", delete(sshid::remove_key))
        .route("/account/security-events", get(account::security_events))
        .route("/account/sso", get(account::sso_identities))
        .route("/account/sso/{provider}", delete(account::sso_unlink))
        .route(
            "/account/sso/{provider}/link/start",
            get(account::sso_link_start),
        )
        .route("/account/recovery/rotate", post(account::rotate_recovery))
        // mfa management
        .route("/account/mfa", get(mfa::status))
        .route("/account/mfa/totp/setup", post(mfa::totp_setup))
        .route("/account/mfa/totp/confirm", post(mfa::totp_confirm))
        .route("/account/mfa/totp", delete(mfa::totp_disable))
        .route("/account/mfa/backup-codes", post(mfa::backup_codes))
        .route(
            "/account/mfa/webauthn/register/start",
            post(mfa::webauthn_register_start),
        )
        .route(
            "/account/mfa/webauthn/register/finish",
            post(mfa::webauthn_register_finish),
        )
        .route("/account/mfa/webauthn/{id}", delete(mfa::webauthn_delete))
        // teams
        .route("/teams", get(teams::list).post(teams::create))
        .route(
            "/teams/{id}",
            get(teams::get).patch(teams::update).delete(teams::delete),
        )
        .route("/teams/{id}/members", get(teams::members))
        .route(
            "/teams/{id}/members/{user_id}",
            patch(teams::update_member).delete(teams::remove_member),
        )
        .route(
            "/teams/{id}/members/{user_id}/account",
            delete(teams::delete_member_account),
        )
        .route("/teams/{id}/leave", post(teams::leave))
        .route(
            "/teams/{id}/invites",
            get(teams::invites).post(teams::create_invite),
        )
        .route(
            "/teams/{id}/invites/{invite_id}",
            delete(teams::delete_invite),
        )
        .route("/teams/{id}/pending-keys", get(teams::pending_keys))
        .route("/teams/{id}/presence", get(teams::get_presence))
        .route("/teams/{id}/audit", get(crate::audit::list))
        .route("/teams/{id}/audit/export", get(crate::audit::export))
        .route("/teams/{id}/audit/verify", get(crate::audit_chain::verify))
        .route(
            "/teams/{id}/access-reviews",
            get(access_reviews::list).post(access_reviews::open),
        )
        .route("/teams/{id}/access-reviews/{rid}", get(access_reviews::get))
        .route(
            "/teams/{id}/access-reviews/{rid}/items/{iid}",
            post(access_reviews::decide),
        )
        .route(
            "/teams/{id}/access-reviews/{rid}/complete",
            post(access_reviews::complete),
        )
        .route(
            "/teams/{id}/access-reviews/{rid}/cancel",
            post(access_reviews::cancel),
        )
        .route(
            "/teams/{id}/break-glass",
            get(break_glass::get)
                .put(break_glass::configure)
                .delete(break_glass::remove),
        )
        .route("/teams/{id}/break-glass/use", post(break_glass::use_secret))
        .route("/teams/{id}/break-glass/end", post(break_glass::end))
        .route(
            "/teams/{id}/audit/checkpoint",
            post(crate::audit_chain::checkpoint),
        )
        .route(
            "/teams/{id}/webhooks",
            get(crate::webhooks::list).post(crate::webhooks::create),
        )
        .route(
            "/teams/{id}/webhooks/{wid}",
            patch(crate::webhooks::update).delete(crate::webhooks::delete),
        )
        .route(
            "/teams/{id}/webhooks/{wid}/test",
            post(crate::webhooks::test),
        )
        .route(
            "/teams/{id}/webhooks/{wid}/deliveries",
            get(crate::webhooks::deliveries),
        )
        .route(
            "/teams/{id}/scim/tokens",
            get(scim_admin::list_tokens).post(scim_admin::create_token),
        )
        .route(
            "/teams/{id}/scim/tokens/{tid}",
            delete(scim_admin::revoke_token),
        )
        .route("/teams/{id}/scim/groups", get(scim_admin::list_groups))
        .route(
            "/teams/{id}/scim/groups/{gid}/vaults",
            put(scim_admin::set_group_vaults),
        )
        .route(
            "/teams/{id}/ca",
            get(ca::get).put(ca::put).delete(ca::delete),
        )
        .route("/teams/{id}/ca/rotate", post(ca::rotate))
        .route("/teams/{id}/ca/issue", post(ca::issue))
        .route("/teams/{id}/ca/certificates", get(ca::list))
        .route("/teams/{id}/ca/certificates/{cid}/revoke", post(ca::revoke))
        .route("/teams/{id}/ca/revoked", get(ca::revoked))
        .route(
            "/teams/{id}/automations",
            get(automations::list).post(automations::create),
        )
        .route(
            "/teams/{id}/automations/runs/claim",
            post(automations::claim),
        )
        .route(
            "/teams/{id}/automations/runs/{rid}",
            get(automations::run).patch(automations::finish),
        )
        .route(
            "/teams/{id}/automations/{aid}",
            get(automations::get)
                .put(automations::update)
                .delete(automations::delete),
        )
        .route(
            "/teams/{id}/automations/{aid}/run",
            post(automations::run_now),
        )
        .route("/teams/{id}/automations/{aid}/runs", get(automations::runs))
        .route(
            "/teams/{id}/policies",
            get(policies::get).put(policies::put),
        )
        .route(
            "/teams/{id}/idp",
            get(idp::get).put(idp::put).delete(idp::delete),
        )
        .route("/teams/{id}/idp/test", post(idp::test))
        .route(
            "/teams/{id}/vaults/{vault_id}/acl",
            get(acl::list).put(acl::upsert),
        )
        .route(
            "/teams/{id}/vaults/{vault_id}/acl/{rule_id}",
            delete(acl::delete),
        )
        .route("/acl/me", get(acl::me))
        .route("/teams/{id}/permissions", get(roles::catalog))
        .route("/teams/{id}/roles", get(roles::list).post(roles::create))
        .route(
            "/teams/{id}/roles/{role_id}",
            patch(roles::update).delete(roles::delete),
        )
        .route("/teams/{id}/default-role", put(roles::set_default))
        .route(
            "/teams/{id}/role-mappings",
            get(roles::mappings).put(roles::set_mappings),
        )
        .route(
            "/teams/{id}/digest",
            get(crate::digest::get).put(crate::digest::put),
        )
        .route("/teams/{id}/digest/send", post(crate::digest::send_now))
        .route("/teams/{id}/vaults", post(vaults::create_team_vault))
        .route("/invites/{token}", get(teams::invite_preview))
        .route("/invites/{token}/accept", post(teams::accept_invite))
        // vaults
        .route("/vaults", get(vaults::list))
        .route(
            "/vaults/{id}",
            get(vaults::get)
                .patch(vaults::update)
                .delete(vaults::delete),
        )
        .route("/vaults/{id}/members", get(vaults::members))
        .route(
            "/vaults/{id}/members/{user_id}",
            put(vaults::upsert_member).delete(vaults::remove_member),
        )
        .route("/vaults/{id}/rotate-key", post(vaults::rotate_key))
        .route("/vaults/{id}/my-key", put(vaults::reseal_my_key))
        // sync
        .route("/sync/push", post(sync::push))
        .route("/sync/pull", post(sync::pull))
        .route("/history/push", post(history::push))
        .route("/history/pull", get(history::pull))
        .route("/history/clear", post(history::clear))
        // logs
        .route("/logs", get(logs::list).post(logs::create))
        .route("/logs/{id}", patch(logs::update).delete(logs::delete))
        .route("/logs/{id}/download", get(logs::download))
        .route("/vaults/{id}/logs", get(logs::list_vault))
        .route("/teams/{id}/logs", get(logs::team_list))
        .route("/teams/{id}/logs/export", get(logs::team_export))
        .route(
            "/teams/{id}/access-requests",
            get(access::list).post(access::create),
        )
        .route("/teams/{id}/access-requests/{rid}", delete(access::cancel))
        .route(
            "/teams/{id}/access-requests/{rid}/approve",
            post(access::approve),
        )
        .route("/teams/{id}/access-requests/{rid}/deny", post(access::deny))
        .route(
            "/teams/{id}/access-requests/{rid}/revoke",
            post(access::revoke),
        )
        .route("/teams/{id}/devices", get(trust::list))
        .route(
            "/teams/{id}/devices/{device_id}/approve",
            post(trust::approve),
        )
        .route(
            "/teams/{id}/devices/{device_id}/reject",
            post(trust::reject),
        )
        .route("/teams/{id}/data", get(gdpr::status))
        .route("/teams/{id}/export", get(gdpr::export))
        .route(
            "/teams/{id}/deletion",
            post(gdpr::schedule).delete(gdpr::cancel),
        )
        .route("/teams/{id}/rotation", get(rotation::overview))
        .route("/teams/{id}/rotation/jobs", post(rotation::create))
        .route("/rotation/jobs", get(rotation::mine))
        .route(
            "/rotation/jobs/{id}",
            patch(rotation::update).delete(rotation::delete),
        )
        // realtime
        .route("/ws", get(crate::ws::handler))
        // multiplayer
        .route("/live", get(crate::live::list).post(crate::live::create))
        .route("/live/{id}/stop", post(crate::live::stop))
        .route("/live/{id}/ws", get(crate::live::ws))
        .route("/gateways", get(crate::gateway::list))
        .route("/gateways/ws", get(crate::gateway::agent_ws))
        .route("/gateways/{id}/connect", get(crate::gateway::client_ws))
        // admin
        .route("/admin/stats", get(admin::stats))
        .route("/admin/config", get(admin::config))
        .route("/admin/users", get(admin::users))
        .route(
            "/admin/users/{id}",
            get(admin::user)
                .patch(admin::update_user)
                .delete(admin::delete_user),
        )
        .route(
            "/admin/users/{id}/revoke-sessions",
            post(admin::revoke_sessions),
        )
        .route("/admin/users/{id}/reset-mfa", post(admin::reset_mfa))
        .route("/admin/teams", get(admin::teams))
        .route(
            "/admin/teams/{id}",
            get(admin::team_detail).delete(admin::delete_team),
        )
        .route("/admin/teams/{id}/members", post(admin::add_member))
        .route(
            "/admin/teams/{id}/members/{user_id}",
            delete(admin::remove_member),
        )
        .route("/admin/jobs", get(admin::jobs))
        .route(
            "/admin/settings",
            get(admin::get_settings).put(admin::put_settings),
        )
        .route("/admin/email/test", post(admin::test_email))
        .fallback(async || crate::error::Error::not_found("route"));

    let mut app = Router::new()
        .route("/healthz", get(server::healthz))
        .route("/readyz", get(server::readyz))
        .route("/.well-known/assetlinks.json", get(server::assetlinks))
        .route("/captcha", get(captcha::page))
        .nest("/scim/v2", crate::scim::router())
        .route("/ca/{team_id}", get(ca::trusted_keys))
        .route("/audit/key", get(crate::audit_chain::public_key))
        .route(
            "/api/v1/logs/blob/{token}",
            get(logs::blob_get).put(logs::blob_put),
        )
        .route("/sshid/{handle}", get(sshid::public_default))
        .route("/sshid/{handle}/{type}", get(sshid::public_typed))
        .nest(
            "/api/v1",
            api.layer(SetResponseHeaderLayer::if_not_present(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            )),
        );

    if state.cfg.swagger_ui {
        app = app.merge(crate::openapi::swagger());
    }
    if let Some(dir) = state.cfg.web_dir() {
        let seo = web::Seo::load(
            &dir,
            web::Origins {
                web: state.cfg.web_url().trim_end_matches('/').to_string(),
                landing: state.cfg.landing_url().map(str::to_string),
                docs: state.cfg.docs_url().map(str::to_string),
            },
        );
        app = app.merge(web::router(
            dir,
            state.cfg.landing_on_cabinet(),
            state.cfg.docs,
            state.cfg.turnstile.is_some(),
            seo,
        ));
    }

    let cors = cors_layer(&state);
    // Host-based rewrites for the dedicated SSH ID / landing origins have to
    // run before routing, so they wrap the finished router instead of being
    // route layers.
    let sshid_host = axum::middleware::from_fn_with_state(state.clone(), sshid::host_layer);
    let landing_host = axum::middleware::from_fn_with_state(state.clone(), web::landing_host_layer);

    let app = app
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT))
        .layer(
            tower::ServiceBuilder::new()
                .layer(TraceLayer::new_for_http().make_span_with(request_span))
                .layer(SetResponseHeaderLayer::overriding(
                    header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    header::REFERRER_POLICY,
                    HeaderValue::from_static("no-referrer"),
                ))
                .layer(cors)
                .layer(CompressionLayer::new())
                .layer(TimeoutLayer::with_status_code(
                    axum::http::StatusCode::REQUEST_TIMEOUT,
                    Duration::from_secs(60),
                )),
        )
        .with_state(state);

    let app = tower::Layer::layer(&landing_host, app);
    Router::new().fallback_service(tower::Layer::layer(&sshid_host, app))
}

/// `host[:port]` the request was addressed to, lowercase.
pub(crate) fn request_host(req: &axum::extract::Request) -> String {
    req.uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            req.headers()
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn cors_layer(state: &AppState) -> CorsLayer {
    let origins = state.cfg.cors_origins();
    let allow = if origins.is_empty() {
        // Desktop (tauri://, http://tauri.localhost) and mobile clients do not
        // send a browser Origin the server can pre-validate; the web cabinet is
        // expected to be same-origin unless TERMOSO_CORS_ORIGINS is set.
        AllowOrigin::predicate(|origin: &HeaderValue, _| {
            origin.to_str().is_ok_and(is_local_client_origin)
        })
    } else {
        AllowOrigin::list(origins.iter().filter_map(|o| HeaderValue::from_str(o).ok()))
    };
    CorsLayer::new()
        .allow_origin(allow)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(Duration::from_secs(3600))
}

/// The request span carries the path only: query strings hold SSO codes and
/// flow tokens, and the invite / start-over routes carry their secret in the
/// path, so those segments are masked even at `debug`.
fn request_span(req: &axum::http::Request<axum::body::Body>) -> tracing::Span {
    tracing::debug_span!(
        "request",
        method = %req.method(),
        path = %redact_path(req.uri().path()),
    )
}

fn redact_path(path: &str) -> String {
    const SECRET_AFTER: [&str; 2] = ["/invites/", "/auth/start-over/"];
    for marker in SECRET_AFTER {
        if let Some(i) = path.find(marker) {
            let start = i + marker.len();
            let end = path[start..].find('/').map_or(path.len(), |j| start + j);
            if end > start {
                return format!("{}[redacted]{}", &path[..start], &path[end..]);
            }
        }
    }
    path.to_string()
}

/// Origins of the desktop WebView (`tauri://localhost`, `http://tauri.localhost`)
/// and a Vite dev server on the loopback host. The host is matched exactly so
/// `http://localhost.example.com` does not qualify.
fn is_local_client_origin(origin: &str) -> bool {
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    let host = rest.rsplit_once(':').map_or(rest, |(h, port)| {
        if port.bytes().all(|b| b.is_ascii_digit()) {
            h
        } else {
            rest
        }
    });
    match scheme {
        "tauri" => host == "localhost",
        "http" | "https" => matches!(
            host,
            "localhost" | "tauri.localhost" | "127.0.0.1" | "[::1]"
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{is_local_client_origin, redact_path};

    #[test]
    fn secret_path_segments_are_masked() {
        assert_eq!(
            redact_path("/api/v1/invites/abc123/accept"),
            "/api/v1/invites/[redacted]/accept"
        );
        assert_eq!(
            redact_path("/api/v1/auth/start-over/tok"),
            "/api/v1/auth/start-over/[redacted]"
        );
        assert_eq!(redact_path("/api/v1/invites/"), "/api/v1/invites/");
        assert_eq!(redact_path("/api/v1/hosts"), "/api/v1/hosts");
    }

    #[test]
    fn local_origins_match_exactly() {
        for ok in [
            "tauri://localhost",
            "http://tauri.localhost",
            "http://localhost",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://[::1]:5173",
        ] {
            assert!(is_local_client_origin(ok), "{ok}");
        }
        for bad in [
            "http://localhost.example.com",
            "http://localhost.example.com:80",
            "http://tauri.localhost.evil",
            "tauri://evil",
            "localhost",
            "null",
        ] {
            assert!(!is_local_client_origin(bad), "{bad}");
        }
    }
}
