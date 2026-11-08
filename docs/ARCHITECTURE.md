# Architecture

This document explains how the pieces of Termoso fit together: which crate owns
what, how a change made on one device reaches another, and which invariants
every component must keep. It is written for people who want to change the
code; the user-facing summary lives in the [README](../README.md).

## Guiding constraints

1. **The server must never be able to read vault data.** Anything a user
   types into a host, key, snippet or setting is encrypted on the device with
   a per-vault key before it is stored or sent. The server sees ciphertext,
   ids, versions and timestamps — nothing else.
2. **Offline is the default, sync is an add-on.** Every client works fully
   with a *local vault* that never leaves the device. Signing in adds
   personal/team vaults that synchronise; it never becomes a requirement.
3. **One core, thin shells.** Everything that is not pixels lives in Rust
   (`termoso-core`, `termoso-client`) and is reused by every client. UI layers
   (React in a Tauri webview, Jetpack Compose, SwiftUI) render state and send
   intents; they do not hold business logic or secrets of their own.
4. **No phone-home.** The only network peers are the hosts the user connects
   to, the Termoso server the user configured, and — only on explicit request —
   a cloud provider API during import or the configured AI endpoint.

## Crates

```
termoso-crypto ─┬─► termoso-proto ─┬─► termoso-server            (axum, sqlx, redis, aws-sdk-s3)
                │                  ├─► termoso-core ─┬─► termoso-client ─┬─► apps/desktop/src-tauri
                │                  │                 │                   ├─► termoso-mobile ─► android / ios
                │                  │                 │                   └─► termoso-bridge
                └─► termoso-wasm ──┘ (browser)       └────────────────────► apps/desktop/src-tauri
```

| Crate | Role | Key modules |
|---|---|---|
| `termoso-crypto` | Every primitive used by clients and server: OPAQUE (`opaque-ke`), Argon2id KDF, XChaCha20-Poly1305 envelopes with AAD, X25519 sealed boxes, BIP39-style 24-word recovery key, key wrapping. No I/O. | `opaque`, `kdf`, `aead`, `sealed`, `keys`, `recovery`, `live` |
| `termoso-proto` | Request/response and entity types shared by server and all clients, with `utoipa` schemas. Changing a type here changes the wire protocol — keep it backward compatible (add optional fields, never repurpose). | `auth`, `account`, `vault`, `entities`, `sync`, `team`, `logs`, `ws` |
| `termoso-server` | Stateless HTTP/WebSocket API. PostgreSQL holds durable state, Redis holds sessions cache, rate limits, short-lived login state and the pub/sub bus for realtime fan-out, S3-compatible storage holds encrypted session logs. | `routes/*`, `session`, `ws`, `events`, `sso`, `live`, `presence`, `audit`, `digest`, `ai`, `metrics` |
| `termoso-core` | Client engine: encrypted local store, secrets, API client, sync engine, SSH/SFTP/WebDAV/S3/Mosh/Telnet/Serial/PTY transports, terminal session abstraction, port forwarding, in-process SSH agent, FIDO2/CTAP2, OS detection, cloud import, autocomplete. `#![forbid(unsafe_code)]`. | `store`, `secrets`, `api`, `sync`, `ssh`, `sftp`, `webdav`, `s3`, `remote`, `terminal`, `forward`, `agent`, `keys`, `fido2`, `mosh`, `serial`, `telnet`, `pty`, `live`, `cloud`, `autocomplete` |
| `termoso-client` | Higher-level repositories over the store used identically by desktop and mobile: hosts with inherited group credentials, keychain façade (keys, identities, certificates), snippets with variables. | `hosts`, `keychain`, `snippets` |
| `termoso-mobile` | UniFFI façade (`cdylib` + `staticlib`) exposing `termoso-core`/`termoso-client` to Kotlin and Swift. Owns the tokio runtime and terminal emulation (`alacritty_terminal`) so both mobile apps get identical grid frames. | `app`, `connect`, `session`, `sftp`, `webdav`, `forward`, `keys`, `account`, `live`, `presence`, `fido2`, `ai` |
| `termoso-bridge` | Headless client for automation: pulls a vault, exposes a Termius-compatible REST API for hosts/groups, pushes ciphertext back. See [API_BRIDGE.md](API_BRIDGE.md). | `rest`, `sync` |
| `termoso-wasm` | `termoso-crypto` compiled with `wasm-bindgen` for the web cabinet, so passwords and keys never leave the browser in clear. | — |

`apps/desktop/src-tauri` (`termoso-desktop`) is also a workspace member: it
wires `termoso-core` into Tauri commands and events and holds desktop-only
runtime (workspaces, updater, imports, multiplayer host/viewer, presence).

## Data model

### Vaults and entities

* A **vault** is the unit of sharing and of encryption. Every device has a
  *local* vault (never synced). Signing in adds the account's **personal**
  vault and any **team** vaults the account is a member of.
* Every vault has a symmetric **vault key** (versioned; rotation bumps
  `key_version`). The server stores one sealed copy per member and cannot
  open any of them. Two envelope formats exist (`termoso-crypto::sealed`):
  * **Team vaults** use an anonymous sealed box (ephemeral X25519 →
    member's account public key). Anyone who knows the member's public key
    can produce one, which is what lets a vault manager hand keys to new
    members; the member trusts the server's key directory for who is in the
    vault (see the threat model in `SECURITY.md`).
  * **Personal vaults** use a *self-authenticated* envelope
    (`0x01 ‖ nonce ‖ crypto_box(me → me)`). Only the holder of the account
    private key can create it, so a server cannot substitute a personal
    vault key it chose. Clients accept a *new* personal `key_version` only
    in this format, never replace a personal key they already hold with a
    same-version envelope from the server, ignore lower versions, and
    re-seal a legacy anonymous envelope through `PUT /vaults/{id}/my-key`
    (same version, caller must already hold the key) on first sync. Signup
    and personal rotation on every client (core, WASM/web) seal this way.
* An **entity** is one encrypted record with a client-generated UUID, a `kind`
  (`termoso_proto::entities::KINDS`: `host`, `group`, `ssh_config`,
  `telnet_config`, `webdav_config`, `serial_config`, `identity`, `ssh_key`, `ssh_certificate`,
  `known_host`, `snippet`, `snippet_package`, `host_snippet`, `pf_rule`,
  `proxy`, `host_chain`, `tag`, `tag_host`, `port_knocking`, `cloud_import`,
  `workspace`, `workspace_template`, `log_bookmark`), a `version` for
  optimistic concurrency, a per-vault `seq` used as the pull cursor, a
  `deleted` tombstone flag and the encrypted `data` envelope. The AAD binds the
  ciphertext to `termoso/v1/entity/<kind>/<id>`, so an envelope cannot be
  swapped between records.
* Credential kinds (`ssh_key`, `identity`, …) can be marked *local-only* on a
  device; they are then excluded from sync while still being usable.

### Local store (`termoso-core::store`)

One SQLite file per profile (`~/.local/share/termoso/<profile>/` on Linux;
app-private storage on mobile). Tables: `vaults` (vault keys wrapped with the
device master key), `entities` (payload encrypted with the vault key **in the
exact envelope the server stores**, so sync is a byte-for-byte copy),
`history`, `session_logs`, `account` (session token and wrapped account private
key). The **device master key** never touches the database file: desktop keeps
it in the OS keychain (Secret Service / Credential Manager / Keychain) with an
owner-only file fallback, Android in the Keystore (optionally gated by
biometrics), iOS in the Keychain (this-device-only, excluded from backups).

### Desktop master password and App Lock

The master password does **not** replace the device master key: the SQLite
store stays encrypted with the same random 256-bit key, so enabling, changing
or removing the password never rewrites or rekeys the database. What changes
is where that key lives.

* **Off (default).** The key is in the OS keychain (or `master.key`, owner-only,
  when no keychain is available). Anyone logged into your OS account can open
  the vault; nothing is asked at start-up.
* **On.** `master.pw` in the profile holds the key wrapped with a key derived
  from the password (Argon2id, 64 MiB / 3 passes, random 16-byte salt;
  XChaCha20-Poly1305 over the raw key). The wrapper is written to a temporary
  file in the same directory, read back and unwrapped with the new password,
  fsynced, then renamed over the old one — only after that is the keychain
  entry / `master.key` deleted. The keychain therefore holds **no copy** once
  the password is on; a stale `master.pw.tmp` from a crash is ignored and
  replaced. Wrong passwords fail closed with a generic error and leave the
  wrapper untouched.
* **Start-up.** With `master.pw` present the app starts *locked*: the window
  shows the unlock screen and no `Store` exists in the process. Nothing in
  the profile is read until the password is entered.
* **Lock.** *Lock now* (Settings → Security, command palette, `Ctrl+Shift+L`)
  and the inactivity timer (Settings → Security → *Lock after inactivity*;
  the webview reports keyboard/pointer input, `0` = never) run the same
  sequence: end hosted multiplayer shares, close every terminal session
  (including viewer tabs), SFTP/WebDAV connection and transfer, port-forward
  rule and edit-in-place watcher, suspend the account runtime (the sync
  engine stops, the API token is dropped from memory but the signed-in
  session is kept), then drop the `Store` so the master key is gone. Every
  vault command returns the `locked` error until the next unlock, which
  re-opens the store and re-runs the normal start-up (account resume,
  forwarding autostart).

**Recovery.** A forgotten master password cannot be reset: the key exists only
inside `master.pw`, and there is no escrow. The supported way back is an
*encrypted backup* (Settings → Security → Export…, or Account → Backup), which
has its own password and restores every vault into a fresh profile. Turning
the password off (with the current password) moves the key back to the
keychain / file. Deleting `master.pw` — or both the keychain entry and
`master.key` while the password is off — makes the database permanently
unreadable.

### Server storage

PostgreSQL (migrations in `crates/termoso-server/migrations`, applied on start)
holds accounts, devices/sessions, MFA material, teams, vault memberships and
sealed keys, entities, history, session-log metadata, live sessions, audit
events, bridges and digests. Server-side secrets that must be recoverable
(OPAQUE server setup, TOTP secrets) are encrypted at rest with
`TERMOSO_MASTER_KEY`. Redis is a cache and message bus only — losing it logs
users out of nothing and loses no data.

### Public site and e-mail (`routes/web.rs`, `mail.rs`)

The same container serves three origins: the landing (`TERMOSO_LANDING_URL`),
the docs (`TERMOSO_DOCS_URL`) and the cabinet (`TERMOSO_PUBLIC_URL`). The web
build writes `seo.json` (title/description per public route, from the docs'
front matter); `Seo::load` renders one HTML shell per public route **once at
start** — title, description, canonical, Open Graph/Twitter card — and one
`noindex` shell for cabinet routes, so a request is a `HashMap` lookup with
no disk read or templating. `/robots.txt` and `/sitemap.xml` are generated
per origin. E-mails are built from a single `Email` structure and sent as
`multipart/alternative` (text/plain + HTML on nested tables with inline
styles, no external CSS/JS/tracking; the logo is the only image). The daily
and weekly digests are skipped when the period has no activity.

## Sync protocol (`termoso-proto::sync`, `termoso-core::sync`)

Each vault has an independent, monotonically increasing `seq`. A client keeps
`since = max(seq)` per vault.

```
sync_once
  ├─ for every unlocked synced vault
  │    ├─ push  dirty rows (changes + deletes, base_version) → per item Ok | Conflict{server copy} | Error
  │    └─ pull  cursors → apply_remote (skipping or resolving rows that are dirty locally)
  ├─ history  push dirty → pull since cursor
  └─ logs     upload finished recordings, push deletions → pull metadata
```

* **Conflicts** are detected by `base_version` mismatch. The server returns its
  copy; the client resolves deterministically (default: the newer `updated_at`
  wins, the loser is re-pushed on top). Deletes are tombstones, so a delete
  and a concurrent edit converge on every device.
* **Realtime.** Clients hold one WebSocket per account. Frames carry **no
  payload** — only "vault X changed", "session revoked", "account updated",
  presence updates — and the client answers by hitting the REST endpoint. The
  server fans frames out through Redis pub/sub, which is what makes replicas
  interchangeable.
* **Key rotation.** Rotating a vault key re-seals it for every member. A
  push made with an outdated key is rejected with `stale_key_version`; the
  client then refreshes its vault keys and the next pass re-encrypts and
  re-pushes with the current `key_version`.

## Authentication and keys

* **OPAQUE** registration/login: the server stores a per-user OPAQUE record
  and never learns the password. The protocol's *export key* seeds an Argon2id
  KDF whose output wraps the account's X25519 private key.
* The same private key is independently wrapped with the **recovery key**
  (24 words). Password change re-wraps; recovery-key rotation re-wraps; there
  is deliberately no server-side escrow.
* **Sessions** are opaque bearer tokens bound to a device row. **Step-up**
  (`reauth`) marks a session as recently re-proved for 5 minutes and gates
  every account-altering endpoint. Revocation is pushed live over the
  WebSocket and enforced server-side on the next request. `session::issue`
  revokes every live session of the same device before inserting the new
  one, so a device holds exactly one valid token (clients identify
  themselves with a stable `client_device_id`, which is what lets
  `upsert_device` reuse the device row).
* **MFA** methods are pluggable server-side (`routes/mfa.rs`): TOTP, WebAuthn
  (also used for security-key sign-in from Android over CTAP2), e-mail codes,
  backup codes. New devices need e-mail approval when SMTP is configured.
* **SSO** (`sso.rs`): OpenID Connect providers (any discovery URL, presets
  for Google/Microsoft, GitHub over plain OAuth2) and SAML 2.0 as an
  SP-initiated service provider (`saml/`): IdP metadata parsing, SP metadata,
  optionally signed `AuthnRequest`s over HTTP-Redirect or HTTP-POST, an
  HTTP-POST ACS, XML-DSig verification against the IdP metadata certificates
  only (pure-Rust C14N 1.0/1.1/exclusive, RSA-SHA256+, single-signature and
  duplicate-ID rejection) and XML-Encryption for encrypted assertions
  (`rsa-oaep-mgf1p`, `rsa-oaep` with any SHA-1/2 digest and MGF1 hash
  combination, `rsa-1_5` only with `SAML_ALLOW_SHA1`; AES-CBC/GCM content).
  All SP private-key operations — request signing and key unwrapping — run in
  AWS-LC (`aws-lc-rs`, plus `crates/termoso-awslc-rsa`, the one `unsafe` FFI
  boundary in the workspace, so OAEP digest and MGF1 hash can be set
  independently as XML Encryption allows); the RustCrypto `rsa` crate only
  parses keys and verifies IdP signatures. Every
  response is checked for `InResponseTo`, `Destination`, `Issuer`, audience,
  recipient, status and time window, and the RelayState is bound to the
  one-shot flow state in Redis. SSO only proves who owns the e-mail; the
  vault password (OPAQUE) and the recovery key remain the only ways to unwrap
  key material, so an IdP cannot read vaults.
  **Identities** live in `sso_identities` (`(provider, subject)` → user, plus
  the e-mail the IdP reported). An identity is linked at SSO sign-up, after a
  successful password login that was started through SSO, or from the
  cabinet (`GET /account/sso/{provider}/link/start` binds the flow to the
  signed-in user and the callback answers `linked`). Sign-in through a linked
  identity resolves the account by `(provider, subject)` even if the IdP
  e-mail changed; an identity owned by another account is refused.
  `GET /account/sso` lists links, `DELETE /account/sso/{provider}` (step-up)
  removes one and records an `sso_unlinked` security event.
* **Account reset** (`start_over.rs`): an e-mail-confirmed "start over" with
  a 24-hour waiting period (`TERMOSO_START_OVER_DELAY_SECS`) that the owner
  can cancel from the notification; completing it wipes the vaults and issues
  fresh keys. It is the only recovery path when password and recovery key
  are both lost.
* **SSH ID**: an account can publish public keys under a handle
  (`/sshid/<handle>`), served as `authorized_keys` text so servers can trust a
  person rather than a file.

## Client runtime

### Desktop (`apps/desktop`)

Tauri 2. Rust (`src-tauri`) owns all state: the store, the sync engine,
sessions, transfers, forwarding runtime, presence, multiplayer, updater. The
React/MUI frontend (`src`) is a rendering layer that calls commands over IPC
(`src/ipc`) and subscribes to events. Terminal bytes stream over Tauri
channels into xterm.js; frontend stores (`src/terminal/store.ts` and friends)
mirror Rust state, they are not the source of truth. Shell integration (OSC
133), autocomplete and keyword highlighting are implemented as stream
transformers with unit tests (`vitest`).

### Android (`apps/android`)

Two Gradle modules. `:core` runs `cargo ndk` for each ABI in `termoso.abis`,
then `uniffi-bindgen` against the built library to generate the Kotlin
bindings, and packages both into an AAR. `:app` is Jetpack Compose + Material
3 (dynamic colour on API 31+) with a small hand-rolled DI container
(`data/AppContainer.kt`) and manager classes (`SessionManager`, `SftpManager`,
`ForwardManager`, `AccountManager`, `PresenceManager`, `Fido2Manager`,
`AiManager`) that adapt the UniFFI façade to Kotlin coroutines/flows. Sessions
run inside a foreground service so they survive backgrounding, and the
service's notification lists the active sessions with open/disconnect
actions; the master key is wrapped by the Android Keystore (`MasterKeyStore`).
The local shell is a full Linux user space: `LinuxManager.kt` downloads a
rootfs on first use and runs it under proot, so `apt`/`apk` work without
root. FIDO2 is implemented
over USB HID and NFC IsoDep transports handed to Rust through a UniFFI callback
interface.

### iOS (`apps/ios`)

`build-core.sh` cross-compiles `termoso-mobile` for `aarch64-apple-ios` and
`aarch64-apple-ios-sim`, generates the Swift bindings and assembles
`TermosoCoreFFI.xcframework` inside the `TermosoCore` Swift package.
`project.yml` (xcodegen) defines the app, XCTest and XCUITest targets. The
SwiftUI app mirrors the Android structure (`AppContainer`, `VaultRepository`,
`SessionStore`, `MasterKeyStore`); the terminal view renders the same grid
frames as Android. The store key lives in the Keychain with
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.

### Terminal pipeline

Transports (`ssh`, `mosh`, `telnet`, `serial`, `pty`) implement one
`terminal::Session` abstraction: bytes in, bytes out, resize. Desktop feeds
the bytes to xterm.js; mobile runs `alacritty_terminal` inside `termoso-mobile`
and ships packed **grid frames** (cells, attributes, cursor, dirty rows) to
Compose/SwiftUI canvases, which keeps rendering identical across both mobile
platforms and lets recording, multiplayer and OS detection tap the same
stream.

### Team features

* **Presence** — devices publish "connected to host X in team vault Y" over
  the WebSocket; the server keeps a Redis snapshot and fans updates out.
  Opt-in per team and per user.
* **Multiplayer** — a host client creates a live session, encrypts its
  terminal stream with a per-session key and publishes it; viewers join with a
  `termoso://join/…` or `https://<server>/join/<id>#<secret>` link that
  carries the key in the fragment. The relay (`live.rs`) forwards frames it
  cannot decrypt.
* **Audit log and digest** — team-relevant events (membership, vault access,
  multiplayer, entity changes) are written server-side with retention; admins
  can opt into a daily/weekly e-mail digest.
* **Roles, policies, ACL** — team roles carry a permission catalogue
  (`authz.rs`); policies (`policy.rs`) tighten what the server allows (MFA,
  SSO-only, device approval, IP allow-list, mandatory recording, retention,
  rotation ages). Entity ACL (`acl.rs`) maps a role, member or IdP group to a
  group or host inside a team vault with `none/connect/read/edit`. Because
  entities are ciphertext to the server, it cannot tell which hosts a group
  contains: clients resolve inheritance and hide/limit what the rules say,
  while the server hard-refuses writes and deletes below `edit` for entities a
  rule names directly. **ACL is not a substitute for a separate vault**: a
  member who holds the vault key can decrypt everything in that vault, so data
  that must stay invisible to someone belongs in a vault they are not a member
  of. The vault is the cryptographic boundary; ACL is order and convenience
  inside it (same model as collections in Bitwarden/1Password).
* **Enterprise plumbing** — per-team IdP (OIDC/SAML, secret under the master
  key, home-realm discovery by e-mail domain), SCIM 2.0, server-side session
  recordings with team-wide export, rotation jobs executed by clients, JIT
  access requests that create expiring vault memberships, GDPR team export and
  scheduled deletion, admin-approved devices, and a corporate mode (home team,
  SSO-only, no personal vaults) switched from server settings.

## Cross-cutting rules

* **Logs never contain secrets or addresses.** Use structured fields and the
  masking helpers; the "no-echo" terminal mode masks typed passwords in
  recordings.
* **New configuration** goes into `crates/termoso-server/src/config.rs` with a
  doc comment, into `deploy/.env.example`, into the README table and into
  `deploy/quadlet` if the Compose stack needs it.
* **New entity kinds** need: the string in `KINDS`, a model in
  `termoso-core::model`, store/repo support, and UI on every client (or an
  explicit note in the README's "Not yet" column).
* **Migrations** are forward-only SQL files under `migrations/`; the server
  applies them on start, so a rolling upgrade must keep the previous binary
  working against the new schema.
* **Tests**: unit tests live next to the code; server integration tests boot
  a real server against PostgreSQL/Redis (`crates/termoso-server/tests`);
  `termoso-core` tests run against an in-process `russh` server; desktop
  frontend uses `vitest`; Android has JVM unit tests; iOS has XCTest against
  the real core and XCUITest in the simulator; CI runs a macOS runtime smoke
  of the built app.
