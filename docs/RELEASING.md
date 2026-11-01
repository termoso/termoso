# Releasing the desktop and Android apps

Desktop and Android builds are produced by `.github/workflows/release.yml`.
Nothing is built on a developer machine and no private key ever leaves
GitHub Actions.

## What a release contains

| Platform | Installers                                                                                                                  | Updater artifact                                                                                                                                                          |
| -------- | --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Linux    | `_amd64.deb` / `.x86_64.rpm` / `_amd64.AppImage` (x86_64), `_arm64.deb` / `.aarch64.rpm` / `_aarch64.AppImage` (64-bit ARM) | `*.AppImage` + `*.AppImage.sig` per architecture                                                                                                                          |
| Windows  | NSIS `*-setup.exe`, `*.msi`                                                                                                 | `*-setup.exe` + `.sig` (preferred), `*.msi` + `.sig`                                                                                                                      |
| macOS    | `*_aarch64.dmg` (Apple Silicon), `*_x64.dmg` (Intel)                                                                        | `*_aarch64.app.tar.gz` / `*_x64.app.tar.gz` + `.sig`                                                                                                                      |
| Android  | `termoso-<version>-{arm64-v8a,armeabi-v7a,x86_64,universal}.apk`                                                            | — (no in-app updater on Android; the APKs carry the standard v2/v3 APK signature)                                                                                         |
| iOS      | `termoso-<version>-ios.ipa` (**unsigned**, sideload)                                                                        | `termoso-altstore.json` — AltStore/SideStore source; the store app signs with the user's Apple ID and refreshes the 7-day profile, see [IOS_SIDELOAD.md](IOS_SIDELOAD.md) |

plus:

- `latest.json` — the updater manifest: version, release notes, publication
  date and, per platform target, the artifact URL and its signature;
- `SHA256SUMS.txt` — checksums of every asset above.

Signatures are [minisign](https://jedisct1.github.io/minisign/) signatures
made with the project signing key. The matching public key is compiled into
the app (`apps/desktop/src-tauri/tauri.conf.json` → `plugins.updater.pubkey`),
and the updater refuses any artifact whose signature does not verify — a
compromised web server or mirror cannot push code to users.

## Cutting a release

1. `scripts/bump-version.sh X.Y.Z` bumps every file the workflow checks:
   `Cargo.toml` (+ lock), `apps/desktop/package.json`, `web/package.json`,
   `MARKETING_VERSION` in `apps/ios/project.yml`, the Helm chart and the store
   manifests under `packaging/` (the workflow fails if any of them differs, or
   if the tag does not match them).
2. Merge to `main`, then tag and push:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

   A tag with a pre-release suffix (`v0.2.0-rc.1`) is marked _pre-release_
   and never becomes `releases/latest`, so it is invisible to the default
   updater feed.

3. The workflow builds Linux (x86_64, aarch64), Windows (x86_64, ARM64), macOS (two native builds rather than
   one universal binary: half the download, and the updater picks the right
   one), Android and iOS in parallel, signs the artifacts (except the iOS
   `.ipa`, which is signed on the user's device), assembles a **draft**
   release, verifies that every bundle and signature is present, rebuilds
   `latest.json` from the uploaded assets (the parallel jobs each merge their
   own entries into it, and a concurrent upload can drop one), adds
   `SHA256SUMS.txt` and only then publishes the release. Until
   that last step `releases/latest/download/latest.json` still points at the
   previous version, so clients never see a half-uploaded release.

Pull requests that touch packaging (the workflow itself, `tauri.conf.json`,
`tauri.macos.conf.json`, capabilities, icons, the desktop
`Cargo.toml`/`package.json`, the Android Gradle files, `apps/ios/project.yml`,
`build-core.sh` and the AltStore template) and
`workflow_dispatch` (the **Run workflow** button) build the same bundles and
attach them to the workflow run as artifacts without creating a release —
that is how packaging changes are smoke-tested.

## Secrets

| Secret                                                                      | Purpose                                                                                                         |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `TAURI_SIGNING_PRIVATE_KEY`                                                 | minisign private key (contents of the `.key` file)                                                              |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`                                        | its password                                                                                                    |
| `ANDROID_KEYSTORE_BASE64`                                                   | Android release keystore, `base64 -w0 termoso-release.jks`                                                      |
| `ANDROID_KEYSTORE_PASSWORD`                                                 | its store password (the single key uses alias `termoso` and the same password)                                  |
| `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY` | _optional_ — Developer ID signing, see [macOS](#macos-signing-and-gatekeeper)                                   |
| `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID`                               | _optional_ — notarization with `notarytool` (app-specific password)                                             |
| `TERMOSO_REPO_GPG_KEY`                                                      | armored RSA signing key for the apt/dnf repositories (no passphrase), see [Package channels](#package-channels) |
| `TERMOSO_REPO_DEPLOY_KEY`, `HOMEBREW_TAP_DEPLOY_KEY`                        | write deploy keys (ed25519 private halves) of `termoso/termoso-repo` and `termoso/homebrew-termoso`             |
| `WINGET_TOKEN`                                                              | _optional_ — GitHub token with `public_repo` for the winget-pkgs fork; without it the winget step is skipped    |

Generate a key pair once with

```bash
npx tauri signer generate -w ~/.termoso-signing/termoso.key
```

store the private key and password as repository Actions secrets, keep an
offline backup (losing the key means shipping a new key and asking every
user to reinstall), and paste the `.key.pub` contents into
`plugins.updater.pubkey`. Rotating the key requires one release signed with
the _old_ key whose binary already carries the _new_ public key.

The Android keystore is created once with

```bash
keytool -genkeypair -keystore termoso-release.jks -alias termoso \
  -keyalg RSA -keysize 4096 -validity 10950
```

Android refuses to update an installed app whose new APK is signed with a
different key, so back this file up the same way as the minisign key. The
version code is derived from the workspace version (`MAJOR*10000 + MINOR*100 +
PATCH`; `apps/android/app/build.gradle.kts`) so every release installs over the
previous one. Locally, `TERMOSO_ANDROID_KEYSTORE=/path/to.jks
TERMOSO_ANDROID_KEYSTORE_PASSWORD=… ./gradlew :app:assembleRelease` signs the
same way; without those variables the release APK is left unsigned.

The signing certificate also powers Android App Links: the app declares
`https://app.termoso.dev/{invite,join}/…` and Android only lets it claim those
URLs after fetching `https://app.termoso.dev/.well-known/assetlinks.json` and
finding the certificate there. Print the fingerprint and put it in the
server's `TERMOSO_ANDROID_APP_LINKS` (self-hosted servers do the same for
their own builds):

```bash
keytool -list -v -keystore termoso-release.jks -alias termoso | grep SHA256
# or, for a built APK:
apksigner verify --print-certs termoso-x.y.z-arm64-v8a.apk | grep SHA-256

TERMOSO_ANDROID_APP_LINKS="com.termoso.android=AA:BB:…"
```

Self-hosted servers are still reachable from the app through the same links:
the web landing pages (`/invite/<token>`, `/join/<id>#<secret>`) offer _Open in
Termoso_, which hands the link to the installed app over the `termoso://`
scheme, so App Links are an optimisation, not a requirement.

## Package channels

The `distribute` job of `release.yml` runs after `publish` for stable tags
(no `-` in the tag) and feeds three channels from the assets that were just
published:

| Channel   | Where                                                                                            | How                                                                                                                                                                                                                                                                         |
| --------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| apt + dnf | [termoso/termoso-repo](https://github.com/termoso/termoso-repo) → GitHub Pages `pkg.termoso.dev` | `scripts/repo/build.sh` rebuilds `deb/` (apt-ftparchive, `InRelease` + `Release.gpg`) and `rpm/<arch>/` (rpms re-signed with `rpmsign`, `createrepo_c`, `repomd.xml.asc`), keeps the two newest versions in the pools, pushes over the `TERMOSO_REPO_DEPLOY_KEY` deploy key |
| Homebrew  | [termoso/homebrew-termoso](https://github.com/termoso/homebrew-termoso)                          | `scripts/repo/cask.sh` renders `Casks/termoso.rb` from `SHA256SUMS.txt` (both dmg architectures), pushes over `HOMEBREW_TAP_DEPLOY_KEY`                                                                                                                                     |
| winget    | `microsoft/winget-pkgs`, package `Termoso.Termoso`                                               | [Komac](https://github.com/russellbanks/Komac) `update --submit` opens the version PR from the fork owned by `WINGET_TOKEN`; `continue-on-error`, so a winget hiccup never fails the release                                                                                |

The repositories are signed with the "Termoso Packages <packages@termoso.dev>"
RSA key held in `TERMOSO_REPO_GPG_KEY`; its public half is served as
`termoso.gpg` / `termoso.asc` next to the repositories. Rotating it means
replacing the secret and telling users to re-import the key — the previous
`InRelease` and `repomd.xml.asc` stop verifying.

First-time winget submission is manual (`komac new Termoso.Termoso --version X --urls <msi url> ...`
answers a few prompts and opens the PR); the job only handles updates once the
package exists upstream. Both side repositories are generated — never edit them
by hand, the next release overwrites everything.

Everything the job needs can be rebuilt locally against any release:

```sh
gh release download v0.8.5 -p '*.deb' -p '*.rpm' -p SHA256SUMS.txt -D assets
scripts/repo/build.sh assets path/to/termoso-repo 0.8.5 packages@termoso.dev
scripts/repo/cask.sh assets/SHA256SUMS.txt 0.8.5 > path/to/homebrew-termoso/Casks/termoso.rb
```

## macOS: signing and Gatekeeper

The macOS builds need no Apple account. Without the `APPLE_*` secrets the
bundler signs the app **ad hoc** (`tauri.macos.conf.json` →
`bundle.macOS.signingIdentity: "-"`, i.e. `codesign -s -`): the binary is
integrity-sealed, so it runs at all on Apple Silicon (which refuses unsigned
code), but it carries no Developer ID and is not notarized. Gatekeeper
therefore blocks the first launch of a downloaded copy with a message such as
_"Termoso" is damaged and can't be opened_ or _Apple could not verify
"Termoso" is free of malware_. Users clear the quarantine flag once, after
dragging the app to Applications:

```bash
xattr -cr /Applications/Termoso.app
```

(or right-click → _Open_, and on macOS 15+ confirm in System Settings →
Privacy & Security → _Open Anyway_). The release notes generated by the
workflow say the same. This is a one-time step per download; in-app updates
extract the new bundle themselves, so they do not pick up the quarantine
attribute that browsers attach. Because an ad-hoc signature identifies a
specific build rather than a developer, macOS treats each update as a new
application for Keychain purposes and may ask once more to allow Termoso to
read its master key (_Always Allow_).

To ship builds that open without any of that, add the optional secrets and
the same workflow signs with a Developer ID and notarizes:

| Secret                       | Value                                                                                                                   |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `APPLE_CERTIFICATE`          | the _Developer ID Application_ certificate exported from Keychain Access as `.p12`, then `base64 -i cert.p12 \| pbcopy` |
| `APPLE_CERTIFICATE_PASSWORD` | the password chosen at export                                                                                           |
| `APPLE_SIGNING_IDENTITY`     | the certificate name, e.g. `Developer ID Application: Jane Doe (TEAMID1234)`                                            |
| `APPLE_ID`                   | the Apple ID e-mail of the developer account                                                                            |
| `APPLE_PASSWORD`             | an [app-specific password](https://support.apple.com/102654) for that Apple ID                                          |
| `APPLE_TEAM_ID`              | the 10-character team ID from the developer portal                                                                      |

`APPLE_SIGNING_IDENTITY` overrides the ad-hoc identity from the config; the
notarization trio is only used when all three are present (signing without
notarization still leaves a Gatekeeper warning, but a milder one). Tauri's
bundler imports the certificate into a temporary keychain on the runner and
removes it afterwards; the private key never lands in the repository.

Locally, `npm run tauri build -- --bundles app,dmg` on a Mac produces the
same ad-hoc bundle; `--target x86_64-apple-darwin` (with that Rust target
installed) cross-builds the Intel one on an Apple Silicon machine.

## How the updater behaves

- **Off by default.** The app never contacts any server unless the user
  clicks _Check for updates_ or turns on _Check on startup_ in Settings →
  Updates. There is no background polling and no telemetry of any kind in the
  request — it is a plain `GET` of `latest.json`.
- **Explicit install.** A found update is shown with its notes; download and
  installation start only when the user asks, and the app restarts only when
  the user confirms.
- **Verified.** The downloaded artifact must carry a valid signature for the
  embedded public key, and the feed URL must be `https://` — anything else is
  rejected before a request is made.
- **Rust-owned.** Checking, downloading and verification live in
  `apps/desktop/src-tauri/src/update.rs`; the webview only renders progress and
  metadata and never sees keys or artifact bytes.

## Self-hosting the update feed

The default feed is `https://github.com/termoso/termoso/releases/latest/download/latest.json`.
To keep updates entirely on infrastructure you control:

1. Download `latest.json`, the updater artifacts and their `.sig` files from
   the release and put them on any HTTPS static host (the same server that
   runs `termoso-server`, an S3 bucket, nginx — anything that serves files).
2. Rewrite the `url` fields inside `latest.json` to point at your copies.
   Signatures stay as they are: they cover the artifact bytes, not the URL.
3. In the app, Settings → Updates → _Release feed_, enter the URL of your
   `latest.json`. Every device using that feed now updates only from your
   server, still verifying against the project public key.

If you also fork the project and build your own binaries, generate your own
signing key (above), embed its public key and publish your own `latest.json`.
Clients of a fork trust the fork's key only.

`latest.json` looks like this:

```json
{
  "version": "0.2.0",
  "notes": "Signed desktop builds of Termoso 0.2.0.",
  "pub_date": "2026-09-10T17:00:00Z",
  "platforms": {
    "linux-x86_64": {
      "url": "https://updates.example.com/termoso/0.2.0/Termoso_0.2.0_amd64.AppImage",
      "signature": "dW50cnVzdGVkIGNvbW1lbnQ6…"
    },
    "windows-x86_64": {
      "url": "https://updates.example.com/termoso/0.2.0/Termoso_0.2.0_x64-setup.exe",
      "signature": "dW50cnVzdGVkIGNvbW1lbnQ6…"
    },
    "darwin-aarch64": {
      "url": "https://updates.example.com/termoso/0.2.0/Termoso_0.2.0_aarch64.app.tar.gz",
      "signature": "dW50cnVzdGVkIGNvbW1lbnQ6…"
    },
    "darwin-x86_64": {
      "url": "https://updates.example.com/termoso/0.2.0/Termoso_0.2.0_x64.app.tar.gz",
      "signature": "dW50cnVzdGVkIGNvbW1lbnQ6…"
    }
  }
}
```

## PostgreSQL major upgrades

`deploy/Dockerfile.backup` pins `postgresql-client-18` and the Compose stack
runs `postgres:18`; `pg_dump`/`pg_restore` must be at least the server's
major. When the stack moves to a new PostgreSQL major, bump both in the same
release, note in the changelog that operators restore _old_ dumps with the
_new_ image (allowed), and run `deploy/restore-test.sh` against a dump taken
on the previous major before tagging.
