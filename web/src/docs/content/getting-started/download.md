---
title: Download and install
description: Native builds for every platform, published with each release on GitHub. No store account, no installer telemetry.
---

Every release on [GitHub](https://github.com/termoso/termoso/releases/latest) ships the same version for all platforms, together with `SHA256SUMS.txt` and signatures for the desktop updater.

## Package managers

Stable releases are also published to package repositories, so you get updates
with the rest of your system:

```sh
# Debian / Ubuntu
sudo install -d -m 0755 /usr/share/keyrings
curl -fsSL https://pkg.termoso.dev/termoso.gpg | sudo tee /usr/share/keyrings/termoso.gpg > /dev/null
curl -fsSL https://pkg.termoso.dev/termoso.list | sudo tee /etc/apt/sources.list.d/termoso.list
sudo apt update && sudo apt install termoso

# Fedora / RHEL / openSUSE
sudo curl -fsSL -o /etc/yum.repos.d/termoso.repo https://pkg.termoso.dev/termoso.repo
sudo dnf install termoso

# macOS
brew install --cask termoso/termoso/termoso

# Windows
winget install Termoso.Termoso
```

The apt and dnf repositories are signed; the key fingerprint is shown at
[pkg.termoso.dev](https://pkg.termoso.dev/).
Packages installed this way still use the built-in updater on Windows and
macOS; on Linux the repository is the update channel.

## Desktop

| Platform               | Files                                              | Notes                                                                                                        |
| ---------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Linux x86_64 / aarch64 | `.deb`, `.rpm`, `.AppImage`                        | The AppImage runs on any recent distribution without installing.                                             |
| Windows x86_64         | `_x64-setup.exe`, `_x64_en-US.msi`                 | The `.exe` installs per user, the `.msi` suits managed deployments.                                          |
| Windows ARM64          | `_arm64-setup.exe`, `_arm64_en-US.msi`             | The `.exe` installs per user, the `.msi` suits managed deployments.                                          |
| macOS                  | `_aarch64.dmg` (Apple Silicon), `_x64.dmg` (Intel) | Ad-hoc signed: on first launch right-click the app → **Open**, or run `xattr -cr /Applications/Termoso.app`. |

### Updates

Nothing is fetched unless you ask. **Settings → Updates** has two modes — **Only when I ask** (default) and **Once at startup** — and a **Release feed** field that defaults to GitHub and can point at your own server. Every update is verified against the project's signing key before it is installed.

## Android

APKs are signed with the project key and need no Google Play Services:

- `termoso-<version>-arm64-v8a.apk` — almost every phone made since 2017;
- `termoso-<version>-armeabi-v7a.apk` — older 32-bit devices;
- `termoso-<version>-x86_64.apk` — emulators and Chromebooks;
- `termoso-<version>-universal.apk` — all of the above in one larger file.

Allow installing from your browser or file manager when Android asks. There is no in-app updater: install a newer APK over the old one, your data stays — including the Local vault and an installed [Linux environment](/docs/terminal/linux-on-android). Android 8.0 (API 26) or newer is required; the app targets the current Android release.

## iOS

There is no App Store listing. Each release has an unsigned `termoso-<version>-ios.ipa` and an AltStore/SideStore source, `termoso-altstore.json`. Add the source in AltStore or SideStore; the store app signs Termoso with your own Apple ID and refreshes it every seven days.

> [!NOTE]
> The iOS app is younger than the others: it has the encrypted local vault, the host editor and the SSH terminal, but not yet account sync, SFTP or port forwarding.

## Verify a download

```bash
sha256sum --ignore-missing -c SHA256SUMS.txt
```

The checksum file is produced by the same release workflow that builds the binaries, from the public repository.
