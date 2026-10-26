<p align="center"><img src=".github/banner.svg" alt="Termoso" width="100%"></p>

<p align="center"><img src=".github/screens/terminal.png" alt="Termoso desktop: terminal with tabs and splits" width="100%"></p>
<p align="center">
  <img src=".github/screens/hosts.png" alt="Hosts, groups and identities" width="49.5%">
  <img src=".github/screens/sftp.png" alt="SFTP: two panes, local or remote on either side" width="49.5%">
</p>

# Termoso

A free, open-source, self-hostable SSH / SFTP / WebDAV / Mosh / Telnet / Serial
workstation in the spirit of Termius: one Rust core, native clients for Linux,
Windows, macOS, Android and iOS, a web cabinet for accounts and teams, and an
optional sync server you can run yourself. Every feature is available to every
user — there are no tiers, seats or paywalls.

Termoso follows one rule: **software reports to you, not on you**. There is no
telemetry, no analytics, no crash reporting and no "phone home". Clients talk
only to the server you point them at (or to nothing at all in offline mode);
the server's only metrics are opt-in Prometheus counters on a private listener.

* Website / hosted instance: <https://termoso.dev> (the same server image
  everyone can self-host; hosted accounts are free)
* Downloads: [GitHub Releases](https://github.com/termoso/termoso/releases)
  (`.deb` / `.rpm` / AppImage, NSIS / MSI, `.dmg`, APK, unsigned `.ipa`)
* License: [AGPL-3.0](LICENSE)

## Contents

1. [What works today](#what-works-today)
2. [Repository layout](#repository-layout)
3. [Architecture in one screen](#architecture-in-one-screen)
4. [Security model](#security-model)
5. [Self-hosting](#self-hosting)
6. [Configuration](#configuration)
7. [Local development](#local-development)
8. [Tests and checks](#tests-and-checks)
9. [Releases](#releases)
10. [API overview](#api-overview)
11. [Sponsoring](#sponsoring)
12. [Open source](#open-source)
13. [Contributing](#contributing)

## What works today

A picture gallery of every screen below is in [docs/SCREENSHOTS.md](docs/SCREENSHOTS.md).

Version 0.9.x. Each row is shipped and covered by CI; the last column lists what
is knowingly missing.

| Component | Platforms | Shipped | Not yet |
|---|---|---|---|
| **Desktop** (`apps/desktop`, Tauri 2) | Linux x86_64 + aarch64, Windows x86_64, macOS (Apple Silicon + Intel) | SSH (password, key, agent, keyboard-interactive, FIDO2 security keys, certificates, jump hosts, HTTP/SOCKS proxy, ML-KEM hybrid KEX), Mosh, Telnet, Serial, local shell; terminal tabs/splits/broadcast, 64 themes, bundled Nerd Fonts, shell integration (OSC 133) with autocomplete and history; SFTP and WebDAV (Basic/Digest, pinned self-signed certificates) in one two-pane Files view with queue, edit-in-place, drag-and-drop; port forwarding (L/R/D, autoreconnect); keychain (keys, identities, certificates, FIDO2, SSH ID, public-only keys signed by the system SSH agent — KeePassXC, ssh-add, Pageant); snippets with variables and bulk run; known hosts; encrypted session logs; workspaces and session restore; command palette and configurable shortcuts; import from `ssh_config`, PuTTY, Termius, AWS EC2 / DigitalOcean / Azure; teams, team vaults, presence, multiplayer terminals, activity log; opt-in AI command suggestions; master password + App Lock (lock on start, Lock now, inactivity timer); signed self-updater (off by default) | ARM Linux and Windows-on-ARM bundles |
| **Android** (`apps/android`, Kotlin + Compose, minSdk 26) | arm64-v8a, armeabi-v7a, x86_64 | The same core over UniFFI/JNI: SSH / Mosh / Telnet and local-shell terminal with a Termius-style key panel, autocomplete, session recording, foreground service; SFTP and WebDAV with transfer queue and pause/resume, and every SSH or WebDAV host exposed to the system Files app and document pickers (Storage Access Framework); port forwarding; keychain incl. FIDO2 over USB and NFC; snippets; account sync, teams, presence, multiplayer (host and viewer), SSH ID, security-key MFA; Material You dynamic colour; app lock (biometric / device credential); Android App Links for invite/join URLs | Serial, workspaces, import from other clients |
| **iOS** (`apps/ios`, SwiftUI, iOS 17+) | iPhone (sideloaded — see below) | Encrypted local vault (key in the Keychain), hosts/groups/tags and host editor, SSH terminal with extra-key panel, host-key/password/passphrase prompts, session tabs, autocomplete | Account sync, SFTP, port forwarding, keychain, snippets, biometric lock, iPad layout |
| **Web cabinet** (`web`) | any browser | Sign-up/sign-in (OPAQUE in WASM, no password ever leaves the browser), MFA (TOTP, passkeys, e-mail, backup codes), device approval, recovery key, devices, security events, teams and roles, team vaults and key rotation, API bridges, admin pages, invitation and join landing pages | Vault contents are never shown in the browser by design — hosts live in the clients |
| **Server** (`crates/termoso-server`, Axum) | Linux container (`ghcr.io/termoso/termoso-server`, amd64 + arm64) | Accounts, devices, MFA, teams, sealed vault keys, encrypted sync with conflicts and tombstones, realtime WebSocket, session-log storage (S3 or local disk), presence, multiplayer relay, audit log and e-mail digests, SSO (OpenID Connect, SAML 2.0 with Single Logout), SSH ID, team policies (MFA, SSO-only, device approval, IP allow-list, keys-only auth, mandatory jump host, export ban, port-forward allow-list, device posture: disk encryption / screen lock / hardware key), team SSH CA (short-lived user certificates), passwords/passphrases by reference from 1Password, Bitwarden, pass or the environment, scheduled automations (snippets on host groups with per-host results and alerts), AI proxy, admin API, OpenAPI 3.1 | IdP-initiated SAML sign-in (unsolicited responses are rejected by design) |
| **API Bridge** (`crates/termoso-bridge`) | Linux container (`ghcr.io/termoso/termoso-bridge`, amd64 + arm64) | Headless client that exposes a Termius-compatible REST API for hosts/groups and pushes only ciphertext to the server — [docs/API_BRIDGE.md](docs/API_BRIDGE.md) | Snippets, keys and identities over the bridge (hosts and groups only) |

Distribution notes:

* **macOS** builds are ad-hoc signed unless the release is configured with a
  Developer ID, so the first launch needs right-click → *Open* (or
  `xattr -cr /Applications/Termoso.app`). Details in
  [docs/RELEASING.md](docs/RELEASING.md#macos-signing-and-gatekeeper).
* **iOS** has no App Store listing. Every release ships an unsigned `.ipa` and
  an AltStore/SideStore source (`termoso-altstore.json`); the store app signs
  it with your own Apple ID and refreshes the 7-day profile —
  [docs/IOS_SIDELOAD.md](docs/IOS_SIDELOAD.md).
* **Android** APKs are signed with the project key and carry no Play Services
  dependency; there is no in-app updater.

## Repository layout

```
Cargo.toml              Rust workspace (edition 2024, rust-version 1.94)
crates/
  termoso-crypto        OPAQUE, Argon2id, XChaCha20-Poly1305, X25519 sealed boxes, BIP39-style recovery key
  termoso-proto         API request/response types shared by server and clients
  termoso-server        API server: axum + PostgreSQL (sqlx) + Redis + S3-compatible storage
  termoso-core          client engine: encrypted SQLite store, SSH/SFTP/WebDAV/Mosh/Telnet/Serial/PTY,
                        port forwarding, SSH agent, FIDO2 (CTAP2 over HID/NFC), account + sync client
  termoso-client        higher-level client modules shared by desktop and mobile (keychain, snippets, …)
  termoso-mobile        UniFFI façade over termoso-core for Android (JNI) and iOS (Swift)
  termoso-bridge        API Bridge: headless client with a Termius-compatible REST API and an MCP server
  termoso-wasm          termoso-crypto compiled to WebAssembly for the web cabinet
apps/
  desktop/              Tauri 2 app: Rust owns state, storage and sessions; React + MUI renders
  android/              Gradle project; :core builds the Rust library with cargo-ndk, :app is Compose
  ios/                  xcodegen project; build-core.sh produces the xcframework + Swift bindings
web/                    web cabinet (Vite + React + MUI); all cryptography runs in the WASM module
deploy/
  Dockerfile            server image (API + built cabinet), distroless, runs as nonroot
  Dockerfile.bridge     bridge image
  docker-compose.yml    self-hosted stack (API, PostgreSQL, Redis, RustFS; optional bridge)
  docker-compose.dev.yml  backing services for development and tests (+ Mailpit)
  quadlet/              the same stack as Podman Quadlet units for systemd
  .env.example          annotated server configuration
docs/                   ARCHITECTURE, BUILDING, SELF_HOSTING, API_BRIDGE, RELEASING, IOS_SIDELOAD, SFTP_BENCHMARK
scripts/check.sh        runs the same checks as CI, per component
.github/workflows/      ci.yml (every push/PR), release.yml (tags)
```

## Architecture in one screen

```
 ┌────────────── clients ──────────────┐        ┌──────────── server ────────────┐
 │ desktop (Tauri)   React/MUI webview │        │ termoso-server (axum)          │
 │   └─ termoso-core ──────────────────┼─ HTTPS ┼─► /api/v1  REST + WebSocket    │
 │ android (Compose) ─ termoso-mobile  │  + WS  │   PostgreSQL  accounts, teams, │
 │ ios (SwiftUI) ───── termoso-mobile  │        │               ciphertext, logs │
 │ bridge (headless) ─ termoso-core    │        │   Redis       sessions cache,  │
 │ web cabinet ─────── termoso-wasm    │        │               rate limits, bus │
 └─────────────────────────────────────┘        │   S3          session logs     │
        every client encrypts locally           └────────────────────────────────┘
        with per-vault keys; the server            stateless: scale by replicas
        stores ciphertext + sync metadata
```

* **Clients are the source of truth.** Hosts, keys, snippets and settings live
  in an encrypted SQLite store on the device (`termoso-core::store`). Sync is
  optional and works offline-first: changes queue locally and reconcile by
  version with tombstones.
* **The server never sees plaintext vault data.** It authenticates, stores
  ciphertext, hands out sealed vault keys to members and fans out change
  notifications over Redis pub/sub to WebSocket subscribers.
* **One core, three UIs.** `termoso-core` is used directly by the desktop
  (Tauri commands) and the bridge, and through `termoso-mobile` (UniFFI) by
  Android and iOS. Feature parity gaps are UI work, not protocol work.

A longer walk-through of the crates, the sync protocol and the client runtime
lives in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security model

* **Zero-knowledge vaults.** Entities are encrypted on the client with
  per-vault keys (XChaCha20-Poly1305). The server stores opaque ciphertext plus
  the minimum metadata needed for sync (ids, versions, timestamps).
* **OPAQUE** password authentication: the server never sees the password and
  cannot brute-force it offline from a stolen database.
* Each account has an **X25519 key pair**. Vault keys are delivered to members
  as sealed boxes for their public key; the private key is wrapped by a KEK
  derived from the OPAQUE export key (Argon2id) and, separately, by a
  **24-word recovery key**. There is no third copy: if both are lost the data
  is unrecoverable and the only way forward is **Start over** — an
  e-mail-confirmed reset with a 24-hour delay (cancellable from the
  notification) that wipes the old vault and issues fresh keys.
* **Step-up re-authentication** for anything that could lock the owner out:
  changing the password, recovery key, e-mail or second factors, revoking
  devices, deleting the account or SSH ID keys require re-proving the password
  (and MFA) within the last 5 minutes. The owner is e-mailed about every such
  change.
* Sessions are opaque bearer tokens bound to a registered device; devices can
  be listed and revoked from any signed-in client, and revocation is pushed
  live over the WebSocket. A device holds one live session: signing in again
  on it replaces the previous token instead of leaving it valid until expiry.
* **SSO** (OpenID Connect, GitHub, SAML 2.0) only proves who owns the e-mail.
  It replaces e-mail codes and new-device approval, never the vault password:
  the vault key is derived from the password, so an identity provider cannot
  read vaults. Providers are connected and disconnected per account in
  Security → *Connected accounts* (step-up required to disconnect); an
  identity already linked to another account cannot be taken over.
* **MFA**: TOTP, WebAuthn / passkeys / security keys, e-mail codes, backup
  codes. New-device sign-in approval by e-mail.
* Server-side secrets (OPAQUE server setup, TOTP secrets) are encrypted at rest
  with `TERMOSO_MASTER_KEY`.
* **Session logs** are encrypted client-side and uploaded through pre-signed
  URLs to S3-compatible storage; the server never handles the plaintext.
* **Team features** (shared vaults, presence, multiplayer terminals, activity
  log) are opt-in per team and use the same sealed-key model; the multiplayer
  relay forwards end-to-end encrypted frames it cannot read.
* **API Bridge** automation stays zero-knowledge: the bridge runs in your
  infrastructure, holds only the vault keys you seal for it and pushes
  ciphertext ([docs/API_BRIDGE.md](docs/API_BRIDGE.md)).
* **AI command suggestions** are absent unless the operator configures a
  provider *and* the user opts in. The only data sent is the short request the
  user typed plus the host's OS/shell label — never the terminal buffer, host
  names, credentials or vault contents. The answer is one command shown for
  review; nothing is executed automatically. Prompts and answers are not logged.
* **Supply chain**: desktop updates are minisign-verified against a public key
  compiled into the app; Android APKs use the standard v2/v3 signature; Docker
  images are built by CI from the tagged commit.

Found a vulnerability? Please follow [SECURITY.md](SECURITY.md) instead of
opening a public issue.

## Self-hosting

Requirements: a Linux host with Docker Compose v2 *or* Podman (Quadlet),
one public hostname with TLS (plus one for the storage endpoint if you enable
session logs), and — recommended — an SMTP account. PostgreSQL 18, Redis 8
and RustFS are part of the stack.

```bash
git clone https://github.com/termoso/termoso.git && cd termoso
cp deploy/.env.example deploy/.env
$EDITOR deploy/.env                 # TERMOSO_MASTER_KEY, passwords, public URLs
docker compose -f deploy/docker-compose.yml up -d --wait
```

This starts the server on `127.0.0.1:8080`, PostgreSQL, Redis and RustFS. The
image bundles the web cabinet: the API lives under `/api/v1` and everything
else on the same origin serves the cabinet, so **one hostname is enough**
(the landing on `/` can be switched off or moved to its own domain with
`TERMOSO_LANDING` / `TERMOSO_LANDING_URL`). Put
a TLS-terminating reverse proxy in front of the server and — for pre-signed
log uploads — in front of RustFS (`--profile proxy` ships a ready Caddy with
automatic certificates), and set `TERMOSO_PUBLIC_URL` and
`TERMOSO_S3__PUBLIC_ENDPOINT` accordingly. Migrations run automatically on
start; the API is stateless and can be scaled by running more replicas behind
one proxy.

* `GET /healthz` liveness, `GET /readyz` readiness (checks PostgreSQL and Redis);
  the image ships `termoso-server --healthcheck` for container probes.
* `GET /api/openapi.json` (OpenAPI 3.1) and `GET /docs` (Swagger UI) while
  `TERMOSO_SWAGGER_UI=true` (default; the example `.env` turns it off).
* Optional: `--profile bridge` also starts the API Bridge.

Podman users get the same stack as systemd units:

```bash
sudo install -d -m 0750 /etc/termoso
sudo install -m 0600 deploy/.env /etc/termoso/env
sudo install -m 0600 deploy/quadlet/stack.env.example /etc/termoso/stack.env   # then edit
sudo cp deploy/quadlet/*.{container,network,volume} /etc/containers/systemd/
sudo systemctl daemon-reload && sudo systemctl start termoso-api
```

Reverse proxies, backups and restore, upgrades, rootless Podman, horizontal
scaling and the differences between the development and production stacks
are documented in [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md).

## Configuration

The server reads `TERMOSO_*` environment variables (nested sections use `__`,
e.g. `TERMOSO_S3__BUCKET`), optionally layered over a TOML file pointed to by
`TERMOSO_CONFIG`. [`deploy/.env.example`](deploy/.env.example) is the annotated
list; the source of truth is
[`crates/termoso-server/src/config.rs`](crates/termoso-server/src/config.rs).

| Variable | Default | Purpose |
|---|---|---|
| `TERMOSO_MASTER_KEY` | — | **required**; 32 random bytes, base64 (`openssl rand -base64 32`). Losing it makes server-side secrets unreadable |
| `TERMOSO_PUBLIC_URL` | `http://localhost:8080` | origin of the server (API + cabinet); used in e-mails and OAuth redirects |
| `TERMOSO_WEB_URL` | = public URL | origin of the web cabinet, when it differs from the public URL |
| `TERMOSO_LANDING` | `true` | `false` hides the landing page: `/` goes straight to `/login` |
| `TERMOSO_LANDING_URL` | unset | serve the landing on its own origin (`https://example.com`) while cabinet + API stay on `TERMOSO_PUBLIC_URL` (`https://app.example.com`); every non-landing path on that host redirects to the cabinet |
| `TERMOSO_SSHID_URL` | unset | dedicated origin for SSH ID handles (`https://sshid.example.com/<handle>[/<type>]`); `<public URL>/sshid/<handle>` always works |
| `TERMOSO_WEB_DIR` | unset (image: `/app/web`) | directory with the built cabinet to serve on `/`; unset = API only |
| `TERMOSO_BIND` | `0.0.0.0:8080` | listen address |
| `TERMOSO_DATABASE_URL` | `postgres://termoso:termoso@localhost:5432/termoso` | PostgreSQL |
| `TERMOSO_DATABASE_MAX_CONNECTIONS` | `20` | pool size per replica |
| `TERMOSO_REDIS_URL` / `TERMOSO_REDIS_PREFIX` | `redis://127.0.0.1:6379` / `termoso:` | Redis; the prefix lets deployments share one instance |
| `TERMOSO_ADMIN_EMAILS` | empty | comma-separated e-mails granted the admin role on sign-up / sign-in |
| `TERMOSO_OWNER_EMAIL` | empty | the server owner — the only account that can grant or revoke admin and cannot be disabled, demoted or deleted; empty = the first registered account |
| `TERMOSO_TURNSTILE__SITE_KEY` / `TERMOSO_TURNSTILE__SECRET_KEY` | empty | Cloudflare Turnstile; when both are set a captcha is required on sign-up, start over, account recovery and on login after 3 failed attempts from one IP. Unset = no captcha |
| `TERMOSO_SERVER_NAME` | `Termoso` | name shown in e-mails and server info |
| `TERMOSO_CORS_ORIGINS` | empty | extra browser origins allowed to call the API |
| `TERMOSO_TRUST_PROXY` | `false` | honour `X-Forwarded-For` / `X-Real-IP` (set behind a reverse proxy) |
| `TERMOSO_S3__{BUCKET,ENDPOINT,PUBLIC_ENDPOINT,REGION,ACCESS_KEY,SECRET_KEY,FORCE_PATH_STYLE,PRESIGN_SECS}` | unset | S3-compatible storage for session logs; unset = feature off |
| `TERMOSO_SMTP__{HOST,PORT,USERNAME,PASSWORD,SECURITY,FROM}` | unset | outgoing e-mail (`starttls` / `tls` / `none`); unset = e-mail features off |
| `TERMOSO_WEBAUTHN__{RP_ID,ORIGINS,RP_NAME}` | unset | passkeys / security keys as MFA |
| `TERMOSO_SSO__<slug>__{NAME,KIND,ISSUER,CLIENT_ID,CLIENT_SECRET,SCOPES,ALLOWED_DOMAINS}` | none | OIDC providers (`google`, `github`, `microsoft` presets or any discovery URL) |
| `TERMOSO_SSO__<slug>__{SAML_METADATA,SAML_IDP_ENTITY_ID,SAML_SP_ENTITY_ID,SAML_SP_CERTIFICATE,SAML_SP_PRIVATE_KEY,SAML_SIGN_REQUESTS,SAML_ALLOW_SHA1,SAML_EMAIL_ATTRIBUTE,SAML_NAME_ATTRIBUTE,SAML_CLOCK_SKEW_SECS}` | none | SAML 2.0 providers (`KIND=saml`): IdP metadata as URL/path/XML, optional SP certificate + key for signed requests and encrypted assertions; SP metadata at `/api/v1/auth/sso/<slug>/saml/metadata` — see [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) |
| `TERMOSO_AI__{API_KEY,URL,MODEL,PROVIDER,CONFIDENTIAL,DAILY_QUOTA,MAX_PROMPT_CHARS,TIMEOUT_SECS}` | unset | AI command suggestions via any OpenAI-compatible endpoint; `API_KEY` alone enables it with the defaults |
| `TERMOSO_ANDROID_APP_LINKS` | empty | `<package>=<SHA-256 cert fingerprint>` pairs published at `/.well-known/assetlinks.json` |
| `TERMOSO_METRICS__ENABLED` / `TERMOSO_METRICS__BIND` | `false` / `127.0.0.1:9090` | opt-in Prometheus metrics on a separate listener |
| `TERMOSO_LOG` / `TERMOSO_LOG_FORMAT` | `info,sqlx=warn,…` / `text` | tracing filter and `text` or `json` output |
| `TERMOSO_SWAGGER_UI` | `true` | serve Swagger UI at `/api/docs` and the OpenAPI document at `/api/openapi.json` |
| `TERMOSO_DOCS` | `true` | serve the documentation at `/docs` |
| `TERMOSO_DOCS_URL` | – | dedicated origin for the documentation (`https://docs.example.com`); `/docs` on the other origins redirects there |
| `TERMOSO_BRIDGES` | `true` | offer API bridges (cabinet page, bridge tokens); `false` hides the page and rejects bridge tokens. The hosted cloud at `app.termoso.dev` runs with it on |
| `TERMOSO_START_OVER_DELAY_SECS` | `86400` | waiting period of the *Start over* account reset |

Client-side settings live in the apps. Desktop honours `TERMOSO_PROFILE_DIR`
(profile location) and `TERMOSO_LOG` (stderr filter).

## Local development

This section is the dev loop (hot reload, tests). To produce the release
artifacts yourself — container images, installers for Linux/Windows/macOS,
signed APKs, the iOS `.ipa` — follow [docs/BUILDING.md](docs/BUILDING.md).

Prerequisites per component (all optional — work on what you touch):

| Component | Needs |
|---|---|
| Rust workspace | Rust 1.94+ (`rustup`), Docker or Podman for the backing services; Linux additionally needs the Tauri system libraries (`libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libudev-dev`) because `apps/desktop/src-tauri` is a workspace member; `mosh` for the Mosh interop tests |
| Web cabinet | Node 22.12+, `wasm-pack` (`cargo install wasm-pack`) |
| Desktop | Node 22.12+, [Tauri 2 prerequisites](https://tauri.app/start/prerequisites/) |
| Android | JDK 17, Android SDK (platform 36, build-tools 36.0.0, NDK 27.2.12479018), `cargo-ndk` 4.x, Rust targets `aarch64-linux-android` (+ `x86_64-linux-android` for the emulator) |
| iOS | macOS with Xcode 16, `xcodegen` (`brew install xcodegen`), Rust targets `aarch64-apple-ios{,-sim}` |

### Server

```bash
docker compose -f deploy/docker-compose.dev.yml up -d --wait   # postgres, redis, rustfs, mailpit
export TERMOSO_MASTER_KEY=$(openssl rand -base64 32)
cargo run -p termoso-server
# → http://localhost:8080/api/docs   (Mailpit UI: http://localhost:8025)
```

The defaults connect to `postgres://termoso:termoso@localhost:5432/termoso`
and `redis://127.0.0.1:6379`. To also serve the cabinet, build it once (below)
and run with `TERMOSO_WEB_DIR=web/dist`.

### Web cabinet

```bash
cd web
npm ci
npm run wasm      # builds crates/termoso-wasm → src/crypto/pkg (generated, git-ignored)
npm run dev       # http://localhost:5173, proxies /api to the server on :8080
```

Re-run `npm run wasm` after changing `termoso-crypto` or `termoso-wasm`. The
cabinet talks to `/api/v1` on its own origin only — there are no third-party
scripts, fonts or analytics (the one exception is the optional Cloudflare
Turnstile captcha on sign-up, loaded only when the operator configured keys).

### Desktop

```bash
cd apps/desktop
npm ci
npm run tauri dev          # Vite on :5174 + the Rust app with hot reload
npm run tauri build        # .deb / .rpm / .AppImage, NSIS / MSI, .app / .dmg
```

The profile (encrypted SQLite store, settings) lives in the OS data directory
(`~/.local/share/termoso/default` on Linux, `%APPDATA%\termoso\default` on
Windows, `~/Library/Application Support/termoso/default` on macOS). The store
key sits in the OS keychain (Secret Service / Credential Manager / Keychain)
with an owner-only file fallback; an optional **master password** (Settings →
Security) wraps it instead and turns on App Lock — locked at start, *Lock now*,
and an inactivity timer (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#desktop-master-password-and-app-lock)
for what a lock closes and why a lost password cannot be reset). On macOS
shortcuts use ⌘ where Linux and Windows use Ctrl, so Ctrl+C still reaches
the shell.

Linux renders through WebKitGTK, whose DMA-BUF renderer does not get along
with the proprietary NVIDIA driver (blank or see-through window, flicker,
crash on resize — [tauri-apps/tauri#9394](https://github.com/tauri-apps/tauri/issues/9394)).
When the `nvidia` kernel module is loaded the app therefore starts with
`WEBKIT_DISABLE_DMABUF_RENDERER=1`; export the variable yourself (`=0` keeps
the renderer on, `=1` forces it off on other GPUs) to override that. If the
window still stays blank, try `__NV_DISABLE_EXPLICIT_SYNC=1` or, as a last
resort, `WEBKIT_DISABLE_COMPOSITING_MODE=1`.

The AppImage is built on Ubuntu 22.04 and carries its own GTK/WebKitGTK, but
deliberately **not** `libwayland-*`: a bundled copy shadows the system one and
a current Mesa (linked against a newer libwayland than 22.04 ships) then cannot load its EGL driver
(`EGL_BAD_PARAMETER`, WebKitWebProcess aborts, the window stays blank —
[tauri-apps/tauri#15665](https://github.com/tauri-apps/tauri/issues/15665)).
Releases up to 0.6.1 did bundle it; on Arch/Fedora and other rolling distros
either upgrade or run `./Termoso.AppImage --appimage-extract && rm squashfs-root/usr/lib/libwayland-*.so* && squashfs-root/AppRun`.
On Wayland the AppImage runs natively; `GDK_BACKEND=x11 ./Termoso.AppImage`
puts it through XWayland instead if the compositor misbehaves. The `.deb`/`.rpm` use the distribution's WebKitGTK and are
not affected.

### Android

```bash
export ANDROID_HOME=~/Android/Sdk          # or wherever the SDK lives
cd apps/android
./gradlew :app:assembleDebug               # :core runs cargo-ndk and generates the Kotlin bindings
./gradlew :app:testDebugUnitTest :app:lintDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

`gradle.properties` → `termoso.abis` controls which Rust targets are built
(default `arm64-v8a,x86_64`; CI passes `-Ptermoso.abis=arm64-v8a`).
`termoso.appLinkHost` is the server whose `https://…/invite/…` and `/join/…`
links open in the app — change it for a self-hosted build and publish the
signing certificate through `TERMOSO_ANDROID_APP_LINKS`.

### iOS

```bash
cd apps/ios
./build-core.sh                 # Rust → TermosoCoreFFI.xcframework + TermosoCore.swift (simulator)
xcodegen generate               # Termoso.xcodeproj
open Termoso.xcodeproj          # or: xcodebuild -scheme Termoso -destination 'platform=iOS Simulator,name=iPhone 16'
```

`./build-core.sh --release --device` produces the device slice used by the
release workflow. Generated files (`Termoso.xcodeproj`, the xcframework, the
Swift bindings) are git-ignored.

## Tests and checks

`scripts/check.sh` runs exactly what CI runs, per component, and skips
components whose toolchain is not installed:

```bash
scripts/check.sh                 # rust + web + desktop (+ android when the SDK is present)
scripts/check.sh rust            # cargo fmt --check, clippy --all-targets, cargo test --workspace
scripts/check.sh web desktop     # npm ci, wasm, format:check, typecheck, lint, (vitest), build
scripts/check.sh android         # gradle assembleDebug + unit tests + lint
scripts/check.sh compose         # docker compose config for both stacks
```

The Rust integration suite (`crates/termoso-server/tests`) boots a real server
against PostgreSQL and Redis, creating a throw-away database per run. RustFS
(session logs) and Mailpit (every e-mail flow) are picked up when reachable;
SSO runs against an in-process mock OpenID Connect provider. Tests needing an
unavailable service are skipped with a notice; `TERMOSO_TEST_REQUIRE_SERVICES=1`
turns that into a failure (CI sets it). `TERMOSO_TEST_DATABASE_URL`,
`TERMOSO_TEST_REDIS_URL`, `TERMOSO_TEST_S3_ENDPOINT`, `TERMOSO_TEST_SMTP_ADDR`
and `TERMOSO_TEST_MAILPIT_URL` override the defaults.

CI (`.github/workflows/ci.yml`) additionally builds the macOS app and runs a
runtime smoke on a Mac runner, builds the iOS app and runs XCTest/XCUITest in
the simulator, and builds both Docker images (pushed to GHCR on `main`).

A load generator that exercises the real client crypto paths is available as a
Rust example: `cargo run -p termoso-server --release --example loadtest -- --url
http://127.0.0.1:8080 --users 20 --duration 30`.

## Releases

Every `v*` tag triggers `.github/workflows/release.yml`: Linux, Windows and
macOS bundles (minisign-signed, with `latest.json` for the built-in updater),
signed Android APKs per ABI, the unsigned iOS `.ipa` with its AltStore source,
`SHA256SUMS.txt`, and the `ghcr.io/termoso/termoso-server:<version>` and
`termoso-bridge:<version>` images; stable releases are then pushed to the
apt/dnf repositories (`pkg.termoso.dev`), the Homebrew tap
(`brew install --cask termoso/termoso/termoso`) and winget (`Termoso.Termoso`).
The version must match in the workspace
`Cargo.toml`, `apps/desktop/package.json` and `apps/ios/project.yml`. Process,
secrets and the updater behaviour: [docs/RELEASING.md](docs/RELEASING.md);
building the same artifacts on your own machine, with your own signing keys:
[docs/BUILDING.md](docs/BUILDING.md).

## API overview

All routes live under `/api/v1`; authenticated routes take
`Authorization: Bearer <token>`. The complete, generated reference is
`GET /api/openapi.json` on a server running with `TERMOSO_SWAGGER_UI=true`
(the development default).

| Area | Routes |
|---|---|
| auth | OPAQUE `register/{start,finish}`, `login/{start,finish}`, `password/{start,finish}`, recovery-key login, MFA step, device approval, step-up `reauth/{start,finish}`, `start-over/*`, SSO (`sso/providers`, `sso/{provider}/start`, callback), `logout` |
| account | profile and avatar, e-mail change/verification, devices, key material, recovery-key rotation, security events, deletion; `account/mfa` (TOTP, WebAuthn, backup codes); `account/sshid` (handle, device and FIDO2 public keys); `account/ai` (opt-in); `account/bridges` (API bridges with sealed vault keys) |
| teams | teams, members and roles, invites, settings (presence, multiplayer), owner-side member account deletion, access reviews (periodic keep/remove of memberships and vault access), break-glass (sealed one-time secret that makes a designated member a time-boxed admin, loudly), gateways (`termoso-bridge gateway`: outbound-only relay to hosts behind NAT, named by id so the server never sees addresses), export to `ssh_config` / Ansible inventory, Wake-on-LAN, SFTP as root via sudo, session logs on local disk (`TERMOSO_LOGS_DIR`) without S3, tamper-evident activity log (`/teams/{id}/audit`: per-team SHA-256 hash chain, signed checkpoints, `/audit/verify`), e-mail digest (`/teams/{id}/digest`) |
| vaults | personal and team vaults, members, sealed vault keys, key rotation, pending keys |
| sync | `push` / `pull` of encrypted entities with per-vault cursors, version conflicts and tombstones |
| history, logs | encrypted command/connection history; session-log upload via pre-signed multipart URLs, listing, deletion |
| presence, live | team presence snapshots; multiplayer sessions (create/join/stop) and the encrypted relay |
| ws | realtime notifications (vault changed, session revoked, account updated, presence) |
| ai | `POST ai/command` → one suggested command, never executed |
| admin | users (disable, reset MFA, revoke sessions), teams, server settings, stats, e-mail test |
| public | `/healthz`, `/readyz`, `/.well-known/assetlinks.json`, `/sshid/<handle>[/<type>]`, `/bridge/me` |

## Sponsoring

Termoso has no paid tier. Development is funded by the people and companies
who rely on it: one-off or monthly sponsorship, and support agreements for
organisations running their own server (deployment, SLA-backed support,
SSO / SCIM / SIEM integration work). Details and wallets are on
[termoso.dev/sponsor](https://termoso.dev/sponsor); write to
[hello@termoso.dev](mailto:hello@termoso.dev).

## Open source

Termoso stands on other people's work. The parts a user actually touches:

| Area | Projects |
| --- | --- |
| Terminal | [alacritty_terminal](https://github.com/alacritty/alacritty) (grid and VT parser on Android), [xterm.js](https://xtermjs.org) with its fit / search / unicode11 / web-links / WebGL addons (desktop and cabinet), [portable-pty](https://github.com/wez/wezterm) (local shells) |
| SSH, SFTP, serial | [russh](https://github.com/Eugeny/russh) and russh-sftp, [ssh-key](https://github.com/RustCrypto/SSH), [serialport](https://gitlab.com/susurrus/serialport-rs), [ctap-hid-fido2](https://github.com/gebogebogebo/ctap-hid-fido2) (FIDO2 keys), [dav-server](https://github.com/messense/dav-server-rs) (WebDAV) |
| Cryptography | [opaque-ke](https://github.com/facebook/opaque-ke) (OPAQUE sign-in), [aws-lc-rs](https://github.com/aws/aws-lc-rs), [rustls](https://github.com/rustls/rustls), [RustCrypto](https://github.com/RustCrypto) (argon2, chacha20poly1305, hkdf, sha2, ed25519-dalek, p256, aes), [blake3](https://github.com/BLAKE3-team/BLAKE3), [webauthn-rs](https://github.com/kanidm/webauthn-rs), [totp-rs](https://github.com/constantoine/totp-rs), [bip39](https://github.com/rust-bitcoin/rust-bip39) |
| Server | [tokio](https://tokio.rs), [axum](https://github.com/tokio-rs/axum), [tower](https://github.com/tower-rs/tower), [sqlx](https://github.com/launchbadge/sqlx), [redis-rs](https://github.com/redis-rs/redis-rs), [aws-sdk-s3](https://github.com/awslabs/aws-sdk-rust), [openidconnect](https://github.com/ramosbugs/openidconnect-rs) and oauth2, [lettre](https://lettre.rs), [utoipa](https://github.com/juhaku/utoipa), [metrics](https://github.com/metrics-rs/metrics), [figment](https://github.com/SergioBenitez/Figment), [tracing](https://github.com/tokio-rs/tracing) |
| Desktop | [Tauri 2](https://tauri.app) and its plugins, [React](https://react.dev), [MUI](https://mui.com), [TanStack Query](https://tanstack.com/query), [Emotion](https://emotion.sh), [Vite](https://vitejs.dev), [Vitest](https://vitest.dev) |
| Android | [Jetpack Compose](https://developer.android.com/compose) and AndroidX, [Kotlin coroutines](https://github.com/Kotlin/kotlinx.coroutines), [UniFFI](https://mozilla.github.io/uniffi-rs/) (Rust ↔ Kotlin), [JNA](https://github.com/java-native-access/jna), [CameraX](https://developer.android.com/training/camerax); the local Linux uses [proot](https://proot-me.github.io) in the [Termux](https://github.com/termux/proot) build with [talloc](https://talloc.samba.org) and [libandroid-shmem](https://github.com/termux/libandroid-shmem), and the official [Alpine Linux](https://alpinelinux.org) mini root filesystem or [Ubuntu Base](https://cdimage.ubuntu.com/ubuntu-base/) |
| Web cabinet | React, MUI, TanStack Query, [React Router](https://reactrouter.com), [SimpleWebAuthn](https://simplewebauthn.dev), [marked](https://marked.js.org), [qrcode.react](https://github.com/zpao/qrcode.react) |
| Fonts | [JetBrains Mono](https://www.jetbrains.com/lp/mono/), [Fira Code](https://github.com/tonsky/FiraCode), [Source Code Pro](https://github.com/adobe-fonts/source-code-pro), [Inter](https://rsms.me/inter/), [Cascadia Code](https://github.com/microsoft/cascadia-code), [Geist Mono](https://vercel.com/font), [Monaspace](https://monaspace.githubnext.com), [Intel One Mono](https://github.com/intel/intel-one-mono), [Commit Mono](https://commitmono.com), [Victor Mono](https://rubjo.github.io/victor-mono/), IBM Plex Mono, Red Hat Mono, Roboto Mono, Noto Sans Mono, Inconsolata, Anonymous Pro, Cousine, DejaVu Sans Mono, Fira Mono, PT Mono, Space Mono (all SIL OFL via [Fontsource](https://fontsource.org)), [Ubuntu Mono](https://design.ubuntu.com/font) (Ubuntu Font Licence), [Symbols Nerd Font Mono](https://www.nerdfonts.com) (MIT) |
| Infrastructure | [PostgreSQL](https://www.postgresql.org), [Redis](https://redis.io), [RustFS](https://rustfs.com) (S3 storage in the reference deployment), [Mailpit](https://mailpit.axllent.org) (mail in CI), [Coolify](https://coolify.io) (reference hosting), [GitHub Actions](https://github.com/features/actions), [Sigstore](https://www.sigstore.dev) and [CycloneDX](https://cyclonedx.org) / [SPDX](https://spdx.dev) for release attestations and SBOMs |

Licences of the Rust and npm dependencies are permissive (MIT, Apache-2.0, BSD, ISC, MPL-2.0, Zlib, CC0); proot is GPL-2.0 and talloc LGPL-3.0, both shipped as separate binaries and invoked as processes. The one piece that is not open source is Google ML Kit, used only to read QR codes in the Android Quick Import camera; everything else works without it. `cargo deny` and `npm audit` run in CI on every push, and every release carries a CycloneDX and SPDX SBOM. Thank you to everyone who maintains these projects.

## Contributing

Issues and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md)
covers the toolchains, `scripts/check.sh`, branch and commit conventions and
what reviewers look for; [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies to
every project space. Security reports go through [SECURITY.md](SECURITY.md).

Termoso is licensed under the [GNU AGPL v3](LICENSE): run it, change it, host
it — and keep it free for whoever you host it for.

Termius is a trademark of Termius Corporation. Termoso is an independent
project, not affiliated with or endorsed by Termius; the name is used only to
describe compatibility and comparison.
