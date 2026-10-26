---
title: Configuration
description: The environment variables that matter, the reverse proxy, domains, e-mail, passkeys and SSO.
---

The server reads `TERMOSO_*` environment variables; nested sections use a double underscore (`TERMOSO_S3__ENDPOINT`). The complete annotated list is [`deploy/.env.example`](https://github.com/termoso/termoso/blob/main/deploy/.env.example). The server validates its configuration on start and refuses to run with an invalid one.

To check what a running server actually picked up, open **Server settings → Environment** in the cabinet (administrators only) or call `GET /api/v1/admin/config`: it lists every effective value with the variable it came from, secrets removed, together with live PostgreSQL / Redis / S3 probes, uptime and the minimum client version in force.

## Minimum

```dotenv
TERMOSO_MASTER_KEY=            # openssl rand -base64 32 — back it up with the database
TERMOSO_PUBLIC_URL=https://termoso.example.com
POSTGRES_PASSWORD=             # openssl rand -hex 24
RUSTFS_ACCESS_KEY=termoso
RUSTFS_SECRET_KEY=             # openssl rand -hex 24
TERMOSO_S3__PUBLIC_ENDPOINT=https://s3.termoso.example.com
TERMOSO_ADMIN_EMAILS=you@example.com
```

`TERMOSO_MASTER_KEY` wraps the server-side secrets (SSO client secrets, bridge tokens, WebAuthn state). A database restored with a different master key is unusable — store the key next to the backups.

## E-mail

```dotenv
TERMOSO_SMTP__HOST=smtp.example.com
TERMOSO_SMTP__PORT=587
TERMOSO_SMTP__USERNAME=…
TERMOSO_SMTP__PASSWORD=…
TERMOSO_SMTP__SECURITY=starttls
TERMOSO_SMTP__FROM=Termoso <no-reply@example.com>
```

Without SMTP the server still runs, but e-mail verification, device approval by e-mail, e-mail MFA and team digests are off.

## Captcha

```dotenv
TERMOSO_TURNSTILE__SITE_KEY=0x4AAAAAAA…
TERMOSO_TURNSTILE__SECRET_KEY=0x4AAAAAAA…
```

Optional [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/). With both keys set, sign-up, "start over", account recovery and — after three failed attempts from one address — login require a Turnstile token, verified server-side against `siteverify`. Without the keys there is no captcha anywhere; the site key is published through `/api/v1/server/info` so clients know when to show the widget.

## Reverse proxy

The API and the cabinet share one origin. Forward everything to `api:8080`, including WebSocket upgrades on `/api/v1/ws`, and set `X-Forwarded-For`. The Compose `proxy` profile does this with Caddy:

```dotenv
TERMOSO_DOMAIN=termoso.example.com
TERMOSO_S3_DOMAIN=s3.termoso.example.com
ACME_EMAIL=you@example.com
```

Never enable `TERMOSO_TRUST_PROXY` on a server that is reachable without the proxy in front.

## Landing page and domains

| Layout                   | Settings                                                                                                                               | Result                                                                                                                       |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| One origin (default)     | `TERMOSO_PUBLIC_URL=https://termoso.example.com`                                                                                       | `/` is the landing, `/docs` the docs, `/login` the cabinet                                                                   |
| No landing               | `TERMOSO_LANDING=false`                                                                                                                | `/` goes straight to sign-in                                                                                                 |
| Docs on their own domain | `TERMOSO_DOCS_URL=https://docs.example.com`                                                                                            | `docs.example.com` serves the documentation; `/docs` elsewhere redirects there. `TERMOSO_DOCS=false` hides the docs entirely |
| Landing on the apex      | `TERMOSO_PUBLIC_URL=https://app.example.com`<br>`TERMOSO_WEB_URL=https://app.example.com`<br>`TERMOSO_LANDING_URL=https://example.com` | `example.com` serves the landing and `/docs`; cabinet paths (`/login`, `/invite/…`, `/account`, …) redirect to `app.example.com`; anything else is a 404 of the site on `example.com`, and the API (apart from `/api/v1/server/info`) answers 404 there                                |

The landing and the docs pages ship with real `<title>`, description, canonical and Open Graph tags (image `/og.png`) rendered once at start-up, so search engines and link previews work without JavaScript. Cabinet routes are `noindex`; `/robots.txt` and `/sitemap.xml` follow the layout above, pointing at `TERMOSO_LANDING_URL` / `TERMOSO_DOCS_URL` when set.

## Passkeys, App Links, SSO

- `TERMOSO_WEBAUTHN__RP_ID` must be the registrable domain of `TERMOSO_PUBLIC_URL`. Keep the `tauri://localhost,http://tauri.localhost` origins so the desktop app can use passkeys.
- `TERMOSO_ANDROID_APP_LINKS=<package>=<SHA-256>` publishes `/.well-known/assetlinks.json` so invitation and join links open in the Android app.
- SSO providers are `TERMOSO_SSO__<slug>__*`: OpenID Connect (any discovery URL, presets for Google and Microsoft, GitHub over OAuth2) or SAML 2.0 (`KIND=saml`). The OIDC redirect URI is `<TERMOSO_PUBLIC_URL>/api/v1/auth/sso/callback`. SAML endpoints are published in the SP metadata at `/api/v1/auth/sso/<slug>/saml/metadata`: the ACS (`/api/v1/auth/sso/saml/acs`, HTTP-POST) and the SingleLogoutService (`/api/v1/auth/sso/saml/slo`, HTTP-Redirect and HTTP-POST). When the IdP metadata advertises a SingleLogoutService, signing out of the app offers to end the IdP session too, and a signed `LogoutRequest` from the IdP (the user signed out elsewhere, or an admin killed their IdP session) revokes every Termoso session that IdP session opened — narrowed to the named `SessionIndex` when the IdP sends one. Unsigned logout messages are rejected.

## Optional features

| Setting                    | Feature                                                       |
| -------------------------- | ------------------------------------------------------------- |
| `TERMOSO_S3__*`            | Session logs stored on the server                             |
| `TERMOSO_AI__*`            | Opt-in AI command suggestions through your own model endpoint |
| `TERMOSO_SSHID_URL`        | SSH ID on a dedicated origin                                  |
| `TERMOSO_METRICS__ENABLED` | Prometheus metrics on a separate, unpublished listener        |
| `TERMOSO_SWAGGER_UI`       | Swagger UI at `/api/docs`                                     |

## Session logs without S3

Session recordings are client-encrypted blobs. By default they go to S3-compatible storage (`TERMOSO_S3__*`). A single-server install can keep them on disk instead:

```sh
TERMOSO_LOGS_DIR=/var/lib/termoso/logs
```

Clients still receive short-lived upload / download URLs — now pointing at `/api/v1/logs/blob/{token}` on the server, the token sealed with the master key for 15 minutes and bound to one object, one direction and (for uploads) a size cap. Quotas, retention and the compliance export work the same. The directory is not shared between replicas: for HA, use S3. `TERMOSO_S3__*` wins when both are set.
