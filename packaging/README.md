# Packaging manifests

Ready-to-submit manifests for stores that build from our GitHub releases. None
of them is published automatically: each store wants an account and a review,
so the release workflow only checks that the versions here match the
workspace version. Hashes marked `REPLACE_WITH_…` come from the
release's `SHA256SUMS`.

| Directory | Store | Builds from |
| --- | --- | --- |
| `flatpak/` | Flathub (`com.termoso.Termoso`) | release source tarball, vendored crates/npm |
| `snap/` | Snap Store (`termoso`) | the signed release `.deb` |
| `scoop/` | Scoop (`termoso.json` for a bucket such as `extras`) | the signed release `.exe` installer |
| `fdroid/` | F-Droid (`com.termoso.android`) | source, cargo-ndk inside the F-Droid builder |

Already live: apt/dnf repositories, the Homebrew tap, winget and AUR (see the
download page in the docs).
