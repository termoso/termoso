#!/usr/bin/env bash
# Bump the project version everywhere release.yml checks it.
#
#   scripts/bump-version.sh 0.12.0
#
# Touches: Cargo.toml (+ Cargo.lock), apps/desktop/package.json (+ lock),
# web/package.json (+ lock), apps/ios/project.yml, deploy/helm Chart.yaml,
# packaging/{snap,scoop,fdroid,flatpak} and the AppStream metainfo. Store hashes
# (scoop, flatpak tarball) are placeholders until the release exists; fill them
# from SHA256SUMS.txt afterwards (see packaging/README.md).
set -euo pipefail
new="${1:?usage: scripts/bump-version.sh X.Y.Z}"
[[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must be X.Y.Z" >&2; exit 1; }
cd "$(dirname "$0")/.."
old=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ "$old" != "$new" ] || { echo "already at $new" >&2; exit 1; }
IFS=. read -r major minor patch <<<"$new"
code=$((major * 10000 + minor * 100 + patch))
today=$(date -u +%F)

sed -i "0,/^version = \"$old\"/s//version = \"$new\"/" Cargo.toml
(cd apps/desktop && npm version --no-git-tag-version --allow-same-version "$new" >/dev/null)
(cd web && npm version --no-git-tag-version --allow-same-version "$new" >/dev/null)
sed -i "s/^    MARKETING_VERSION: \"$old\"/    MARKETING_VERSION: \"$new\"/" apps/ios/project.yml
sed -i "s/^appVersion: \"$old\"/appVersion: \"$new\"/" deploy/helm/termoso/Chart.yaml
sed -i "s/^version: \"$old\"/version: \"$new\"/" packaging/snap/snapcraft.yaml

node - "$new" <<'JS'
const fs = require("fs");
const v = process.argv[2];
const p = "packaging/scoop/termoso.json";
const m = JSON.parse(fs.readFileSync(p, "utf8"));
m.version = v;
for (const [arch, suffix] of [["64bit", "x64"], ["arm64", "arm64"]]) {
  m.architecture[arch].url = `https://github.com/termoso/termoso/releases/download/v${v}/Termoso_${v}_${suffix}-setup.exe#/dl.7z`;
  m.architecture[arch].hash = "REPLACE_WITH_SHA256_FROM_RELEASE_SHA256SUMS";
}
fs.writeFileSync(p, JSON.stringify(m, null, 2) + "\n");
JS

f=packaging/flatpak/dev.termoso.Termoso.yml
sed -i "s|/archive/refs/tags/v$old\.tar\.gz|/archive/refs/tags/v$new.tar.gz|; s|^\(        sha256: \).*|\1REPLACE_WITH_RELEASE_TARBALL_SHA256|" "$f"
sed -i "s|raw.githubusercontent.com/termoso/termoso/v$old/|raw.githubusercontent.com/termoso/termoso/v$new/|g; s|  <releases>|  <releases>\n    <release version=\"$new\" date=\"$today\" />|" packaging/flatpak/dev.termoso.Termoso.metainfo.xml

f=packaging/fdroid/com.termoso.android.yml
python3 - "$f" "$old" "$new" "$code" <<'PY'
import re, sys
path, old, new, code = sys.argv[1:]
s = open(path).read()
m = re.search(rf"  - versionName: {re.escape(old)}\n    versionCode: \d+\n    commit: v{re.escape(old)}\n(?:    .*\n|\n)*?(?=  - versionName:|\nAutoUpdateMode)", s)
if not m:
    sys.exit(f"{path}: no Builds entry for {old}")
entry = m.group(0).replace(f"versionName: {old}", f"versionName: {new}").replace(f"commit: v{old}", f"commit: v{new}")
entry = re.sub(r"versionCode: \d+", f"versionCode: {code}", entry)
s = s[: m.end()] + entry + s[m.end() :]
s = re.sub(r"^CurrentVersion: .*$", f"CurrentVersion: {new}", s, flags=re.M)
s = re.sub(r"^CurrentVersionCode: .*$", f"CurrentVersionCode: {code}", s, flags=re.M)
open(path, "w").write(s)
PY

cargo update -w --offline -q 2>/dev/null || cargo update -w -q
echo "bumped $old -> $new (android versionCode $code)"
git --no-pager diff --stat
