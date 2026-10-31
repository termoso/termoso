#!/usr/bin/env bash
# Runtime smoke of a *debug* macOS bundle on a real (CI) Mac: launches the
# .app with an isolated profile, lets smoke/desktop.js drive the UI inside the
# webview, takes a window screenshot whenever the script asks for one, and
# fails on FAIL/crash/timeout/panic. Artifacts land in <out-dir>.
#
# usage: smoke/macos.sh <Termoso.app> <out-dir>
set -euo pipefail

app=${1:?path to Termoso.app}
out=${2:?output directory}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)

exe="$app/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist")"
report="$out/report.txt"
: >"$report"

swiftc -O -o "$out/window" "$here/window.swift"

# zsh is what a Mac user gets by default, whatever the runner account uses.
SHELL=/bin/zsh \
  TERMOSO_PROFILE_DIR="$out/profile" \
  TERMOSO_SMOKE_SCRIPT="$here/desktop.js" \
  TERMOSO_SMOKE_REPORT="$report" \
  TERMOSO_LOG=info \
  "$exe" >"$out/app.log" 2>&1 &
pid=$!
echo "launched $exe (pid $pid)"

cleanup() {
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.5
    done
    kill -9 "$pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

fail() {
  echo "::error::$1"
  echo "--- app.log (tail) ---"
  tail -n 80 "$out/app.log" || true
  echo "--- report ---"
  cat "$report" || true
  exit 1
}

window_id() { "$out/window" "$pid" 2>/dev/null; }

# screencapture -l fails with "could not create image from window" while the
# window server has not composited the window yet (seen on GitHub macOS runners
# right after launch); retry, then fall back to the whole screen.
shoot() {
  local name=$1 wid attempt
  for attempt in 1 2 3 4 5; do
    if wid=$(window_id) && screencapture -x -o -l "$wid" "$out/$name.png" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "::warning::no window capture for screenshot $name after $attempt attempts, capturing the whole screen"
  screencapture -x "$out/$name.png"
}

# The window must appear on its own (before the script does anything).
for i in $(seq 1 60); do
  kill -0 "$pid" 2>/dev/null || fail "app exited before showing a window"
  if wid=$(window_id); then
    echo "window $wid visible after ${i}s"
    break
  fi
  sleep 1
  [ "$i" -lt 60 ] || fail "no window after 60s"
done

status=
seen=0
deadline=$((SECONDS + 180))
while [ "$SECONDS" -lt "$deadline" ]; do
  kill -0 "$pid" 2>/dev/null || { status=crashed; break; }
  total=$(wc -l <"$report")
  while [ "$seen" -lt "$total" ]; do
    seen=$((seen + 1))
    line=$(sed -n "${seen}p" "$report")
    echo "[smoke] $line"
    case "$line" in
      "shot "*) shoot "${line#shot }" ;;
      DONE) status=ok ;;
      "FAIL "*) status=fail; shoot failure ;;
    esac
  done
  [ -z "$status" ] || break
  sleep 0.5
done

case "$status" in
  ok) ;;
  crashed) fail "app exited during the smoke" ;;
  fail) fail "smoke script failed" ;;
  *) fail "smoke did not finish within 180s" ;;
esac

# Graceful quit must work and must not panic on the way out.
kill "$pid"
for _ in $(seq 1 40); do
  kill -0 "$pid" 2>/dev/null || break
  sleep 0.5
done
kill -0 "$pid" 2>/dev/null && fail "app did not quit within 20s of SIGTERM"
wait "$pid" 2>/dev/null || true

grep -q 'panicked at' "$out/app.log" && fail "panic in app.log"
if grep -E '^\S+\s+ERROR' "$out/app.log"; then
  echo "::warning::ERROR lines in app.log (see artifact)"
fi
test -s "$out/profile/vault.db" || fail "profile store was not created"

for shot in welcome hosts terminal terminal-output terminal-dom settings; do
  f="$out/$shot.png"
  test -s "$f" || fail "missing screenshot $shot"
  size=$(stat -f%z "$f")
  [ "$size" -gt 5000 ] || fail "screenshot $shot is only $size bytes (blank window?)"
  echo "$shot.png: $(sips -g pixelWidth -g pixelHeight "$f" | awk '/pixel/ {printf "%s ", $2}')px, $size bytes"
done
echo "smoke ok"
