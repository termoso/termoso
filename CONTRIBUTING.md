# Contributing to Termoso

Thanks for helping. This document tells you how to get a working tree, what
the checks are, and what a good pull request looks like. Architecture lives
in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); the product rules that every
change has to respect are short:

* **No telemetry, ever.** No analytics, crash reporters, update pings beyond
  the opt-in updater, or third-party SDKs that phone home.
* **The server never sees plaintext vault data.** New entity kinds are
  encrypted client-side like the existing ones; new server features work on
  ciphertext and metadata only.
* **Every feature for every user.** No tiers, seats or paywalled flags.
* **Offline first.** A client must keep working without the server.

## Repository map

```
crates/          Rust workspace: crypto, proto, core, client, mobile (UniFFI), server, bridge, wasm
apps/desktop/    Tauri 2 + React/MUI desktop app (src-tauri is a workspace member)
apps/android/    Kotlin/Jetpack Compose app over the mobile crate (cargo-ndk + JNI)
apps/ios/        SwiftUI app over the mobile crate (UniFFI Swift, xcodegen)
web/             React/MUI web cabinet (accounts, teams, admin) using the wasm crate
deploy/          Dockerfiles, Compose stacks, Podman Quadlet units, .env.example
docs/            architecture, self-hosting, API bridge, releasing, iOS sideload
scripts/check.sh what CI runs, runnable locally
```

## Prerequisites

Work on what you touch; nothing below is needed for everything.

| Area | Needs |
|---|---|
| Rust (all crates) | Rust **1.94+** via `rustup` (the toolchain is `stable`; `rust-version` in `Cargo.toml` is the floor). On Linux the Tauri crate is a workspace member, so `cargo clippy --workspace` also needs `libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libudev-dev`. `mosh` for the Mosh interop tests. |
| Server integration tests | Docker or Podman for `deploy/docker-compose.dev.yml` (PostgreSQL, Redis, RustFS, Mailpit). Tests that need a service skip when it is unreachable and `TERMOSO_TEST_REQUIRE_SERVICES` is unset. |
| Web cabinet | Node **22.12+** (older Node silently skips the optional Rolldown native binding and `npm run build` fails), `wasm-pack` (`cargo install wasm-pack`) for `npm run wasm`. |
| Desktop | Node 22 plus the Rust prerequisites; `npm run tauri dev` for a live app. |
| Android | JDK **17**, Android SDK with platform **36**, build-tools **36.0.0**, NDK **27.2.12479018**, `cargo-ndk` (`cargo install cargo-ndk`) and the `aarch64-linux-android` / `x86_64-linux-android` targets. `ANDROID_HOME` must be set. |
| iOS | macOS with Xcode 16, `xcodegen` (`brew install xcodegen`), the `aarch64-apple-ios` / `aarch64-apple-ios-sim` targets. `apps/ios/build-core.sh` builds the core and Swift bindings. |

### First run

```bash
git clone https://github.com/termoso/termoso.git && cd termoso
docker compose -f deploy/docker-compose.dev.yml up -d --wait
cargo test --workspace
cargo run -p termoso-server            # http://localhost:8080 (API only until web/ is built)

cd web && npm ci && npm run wasm && npm run dev          # cabinet on :5173 → API on :8080
cd apps/desktop && npm ci && npm run tauri dev           # desktop app
cd apps/android && ./gradlew :app:assembleDebug          # builds the Rust core via cargo-ndk first
cd apps/ios && ./build-core.sh --debug --sim && xcodegen generate && open Termoso.xcodeproj
```

The web dev server proxies `/api` to `localhost:8080`; the server serves the
built cabinet itself when `TERMOSO_WEB_DIR` points at `web/dist`. Release-style
artifacts (images, installers, APKs, `.ipa`) and the signing keys they need are
covered in [docs/BUILDING.md](docs/BUILDING.md).

## Checks

`scripts/check.sh` runs the same commands as CI and skips components whose
toolchain is missing on your machine:

```bash
scripts/check.sh              # everything available
scripts/check.sh rust web     # subset: rust | web | desktop | android | deploy
```

What it runs, per area:

| Area | Commands |
|---|---|
| rust | `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked` (warnings are errors), `cargo test --workspace --locked` |
| web | `npm ci`, `npm run wasm`, `format:check`, `typecheck`, `lint`, `build` in `web/` |
| desktop | `npm ci`, `format:check`, `typecheck`, `lint`, `test`, `build` in `apps/desktop/` |
| android | `./gradlew :app:assembleDebug :app:testDebugUnitTest :app:lintDebug` in `apps/android/` |
| deploy | `docker compose config` for both stacks, Quadlet `-dryrun` when the binary exists |

CI additionally runs a **supply chain** job (`cargo deny --locked check
advisories bans licenses sources` against `deny.toml`, plus `npm audit` for
the web and desktop packages — a new RustSec advisory fails the build until it
is fixed or given a reasoned `ignore` entry) and a **fuzz** job that checks
the `fuzz/` targets on nightly and runs a short smoke of each; see
[fuzz/README.md](fuzz/README.md). Server integration tests need the backing
services: `docker compose -f deploy/docker-compose.dev.yml up -d` (or plain
`postgres`, `redis` and `axllent/mailpit` containers) and
`TERMOSO_TEST_DATABASE_URL` / `TERMOSO_TEST_REDIS_URL`; without them they are
skipped.

macOS and iOS builds run only in CI (Apple-hosted runners); the `macos` job
also launches the built app for a scripted smoke, the `ios` job runs XCTest
and XCUITest in a simulator. If you change the desktop Rust side, keep
`#[cfg(target_os = …)]` branches compiling on all three platforms.

Formatting is enforced: `cargo fmt` (settings in `rustfmt.toml`), Prettier
for TypeScript (`npm run format`), Android Lint for Kotlin, and `.editorconfig`
for everything else.

## Making changes

### Branches and commits

* Branch from `main`: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`.
* Commit messages: imperative subject ≤ 72 characters, optionally prefixed
  with the area (`server:`, `desktop:`, `android:`, `ios:`, `web:`, `core:`,
  `deploy:`, `docs:`), body explains *why* when the diff does not.
* Keep commits focused; a reviewer should be able to read the history.

### Pull requests

* One topic per PR. Refactors that enable a change go in first or in a
  separate commit.
* Fill in the template: what changed, why, how you tested, what a reviewer
  should look at. Screenshots for UI, before/after for performance.
* CI must be green. Do not weaken lints, tests or dependency pinning to get
  there — fix the cause or explain in the PR why the check is wrong.
* Squash-merge is the default; make the PR title a good commit subject.
* `.github/CODEOWNERS` assigns reviewers per area automatically.

### AI-assisted contributions

AI assistants are a normal part of the toolbox here, for reading the code,
drafting a report or writing a patch. What we ask is simple: you remain the
author.

* Reproduce the bug yourself and describe what you actually saw.
* Read every line of your patch, run the checks locally, and be ready to
  explain it in review.
* If a report or PR turns out to be unverified model output (invented APIs,
  wrong paths, tests that do not run), we will close it and ask you to come
  back with a checked version.

### Rules of the codebase

* **Configuration** is `TERMOSO_*` environment variables parsed in
  `crates/termoso-server/src/config.rs`. Add new keys there with defaults,
  document them in `deploy/.env.example` and the README table.
* **Database changes** are new numbered files in
  `crates/termoso-server/migrations/`; never edit an applied migration.
* **New synced data** is a new entity kind in
  `crates/termoso-proto/src/entities.rs`, encrypted like the others; the
  server must not gain a column that decrypts it.
* **Client features** live in Rust (`termoso-core` / `termoso-client`) and
  are exposed through `termoso-mobile` (UniFFI) and `apps/desktop/src-tauri`
  commands; TypeScript, Kotlin and Swift are presentation layers.
* **Tests** accompany behaviour: Rust unit/integration tests, Vitest for the
  desktop webview, Android unit tests, XCTest for iOS. Server tests run
  against real PostgreSQL/Redis/RustFS from the dev stack.
* **Secrets** never enter the tree or logs: no `.env`, keystores,
  credentials files, or test fixtures with real keys. Log lines must not
  contain passwords, tokens, key material or host addresses.
* **Dependencies**: prefer what is already in `Cargo.lock` / `package-lock.json`.
  New ones need a reason in the PR, a permissive licence (AGPL-3.0
  compatible) and a pinned version. Dependabot files weekly grouped updates.
* **Generated files** (`Cargo.lock`, lockfiles, UniFFI bindings, the theme
  registry, WASM package) are regenerated by their tools, not edited.
* No comments that narrate a diff; explain non-obvious invariants only.

### Reporting security issues

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under the project licence, AGPL-3.0-only. By
opening a PR you confirm you have the right to contribute the code under it.
