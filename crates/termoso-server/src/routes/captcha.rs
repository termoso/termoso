//! `GET /captcha` — a bare page with the Cloudflare Turnstile widget for the
//! native clients, which cannot render the widget themselves. The desktop app
//! frames it, the mobile apps open it in a system web view; the resulting
//! token is handed back through `postMessage` / a JS bridge and sent with the
//! next `turnstile_token` request. Only served when Turnstile is configured.

use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde::Deserialize;

use crate::error::Error;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct Params {
    #[serde(default)]
    theme: Option<String>,
}

/// Widget theme; anything unknown falls back to `auto`.
fn theme(raw: Option<&str>) -> &'static str {
    match raw {
        Some("light") => "light",
        Some("dark") => "dark",
        _ => "auto",
    }
}

fn nonce() -> String {
    let mut b = [0u8; 16];
    rand::fill(&mut b);
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// The page body. `site_key` is public; `theme` is one of `light`/`dark`/`auto`.
pub fn render(site_key: &str, theme: &str, nonce: &str) -> String {
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Verification</title>
<style nonce="{nonce}">
  :root {{ color-scheme: {scheme}; }}
  html, body {{ margin: 0; height: 100%; background: transparent; }}
  body {{ display: flex; align-items: flex-start; justify-content: center; padding-top: 4px; box-sizing: border-box; }}
</style>
</head>
<body>
<div id="w"></div>
<script nonce="{nonce}">
  function deliver(token) {{
    var msg = {{ type: "termoso:captcha", token: token }};
    try {{ if (window.parent && window.parent !== window) window.parent.postMessage(msg, "*"); }} catch (e) {{}}
    try {{ if (window.TermosoCaptcha) window.TermosoCaptcha.onToken(token == null ? null : String(token)); }} catch (e) {{}}
    try {{
      var h = window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.termosoCaptcha;
      if (h) h.postMessage(token == null ? "" : String(token));
    }} catch (e) {{}}
  }}
  window.onloadTurnstile = function () {{
    turnstile.render("#w", {{
      sitekey: "{site_key}",
      theme: "{theme}",
      callback: function (t) {{ deliver(t); }},
      "expired-callback": function () {{ deliver(null); }},
      "error-callback": function () {{ deliver(null); }}
    }});
  }};
</script>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onloadTurnstile&render=explicit" nonce="{nonce}" async defer></script>
</body>
</html>
"##,
        nonce = escape(nonce),
        scheme = if theme == "auto" { "light dark" } else { theme },
        site_key = escape(site_key),
        theme = theme,
    )
}

/// Origins allowed to frame the page: the server itself and the Tauri
/// desktop app (its webview origin differs per platform).
const FRAME_ANCESTORS: &str =
    "'self' tauri://localhost http://tauri.localhost https://tauri.localhost http://localhost:5174";

pub async fn page(State(state): State<AppState>, Query(q): Query<Params>) -> Response {
    let Some(cfg) = &state.cfg.turnstile else {
        return Error::not_found("route").into_response();
    };
    let nonce = nonce();
    let body = render(&cfg.site_key, theme(q.theme.as_deref()), &nonce);
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{nonce}' https://challenges.cloudflare.com; \
         style-src 'nonce-{nonce}'; frame-src https://challenges.cloudflare.com; \
         connect-src https://challenges.cloudflare.com; base-uri 'none'; form-action 'none'; \
         frame-ancestors {FRAME_ANCESTORS}"
    );
    let mut res = (StatusCode::OK, body).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(&csp) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_is_whitelisted() {
        assert_eq!(theme(Some("dark")), "dark");
        assert_eq!(theme(Some("light")), "light");
        assert_eq!(theme(Some("<x>")), "auto");
        assert_eq!(theme(None), "auto");
    }

    #[test]
    fn page_embeds_key_and_escapes() {
        let html = render("0x4\"<k>", "dark", "n0nce");
        assert!(html.contains(r#"sitekey: "0x4&quot;&lt;k&gt;""#));
        assert!(html.contains(r#"theme: "dark""#));
        assert!(html.contains(r#"nonce="n0nce""#));
        assert!(html.contains("challenges.cloudflare.com/turnstile/v0/api.js"));
        assert!(html.contains("termoso:captcha"));
    }
}
