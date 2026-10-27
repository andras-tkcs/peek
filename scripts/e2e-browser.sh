#!/usr/bin/env bash
# e2e-browser.sh - browser test of the viewer's trust boundary.
#
# Builds the binaries, boots a throwaway Peek server, uploads a probe page and
# drives headless Chromium to check that peek.fetch rejects paths that leave
# the page's backend prefix, that postMessage events from anything but the
# page frame are ignored, and that a comment can be posted.
#
# Requires: go, node (>=20), pnpm install, and Google Chrome / Chromium.
# Override Chrome with:
#   CHROME="/path/to/chrome" scripts/e2e-browser.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PEEK_E2E_BROWSER_PORT:-7797}"
BASE="http://localhost:$PORT"
DATA="$(mktemp -d)"
COOKIE="$DATA/cookies.txt"
SRV_PID=""

cleanup() {
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true
  sleep 0.3
  chmod -R u+w "$DATA" 2>/dev/null || true
  rm -rf "$DATA" 2>/dev/null || true
}
trap cleanup EXIT

command -v go >/dev/null || { echo "error: go not found"; exit 1; }
command -v node >/dev/null || { echo "error: node not found"; exit 1; }
node -e "import('playwright-core')" >/dev/null 2>&1 || { echo "error: Playwright not installed; run: pnpm install"; exit 1; }

if [ -z "${CHROME:-}" ]; then
  for c in \
    "$(command -v google-chrome || true)" \
    "$(command -v chromium || true)" \
    "$(command -v chromium-browser || true)" \
    "$(ls /opt/pw-browsers/chromium-*/chrome-linux64/chrome 2>/dev/null | head -n1 || true)"; do
    if [ -n "$c" ] && [ -x "$c" ]; then CHROME="$c"; break; fi
  done
fi
[ -n "${CHROME:-}" ] || { echo "error: Chrome/Chromium not found (set CHROME=...)"; exit 1; }

echo "-> building binaries"
go build -o bin/peekd ./cmd/peekd
go build -o bin/peek ./cmd/peek

echo "-> starting peekd on :$PORT"
./bin/peekd --addr ":$PORT" --data "$DATA" --base-url "$BASE" >/dev/null 2>&1 &
SRV_PID=$!
for _ in $(seq 1 50); do
  curl -fsS "$BASE/" >/dev/null 2>&1 && break
  sleep 0.1
done

csrf_from_html() {
  sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -n1
}

json_value() {
  key="$1"
  sed -n "s/.*\"$key\":\"\\([^\"]*\\)\".*/\\1/p"
}

echo "-> creating first admin + API key"
SETUP_CODE="$(tr -d '\n\r' < "$DATA/setup.key")"
SETUP_HTML="$(curl -fsS -c "$COOKIE" "$BASE/setup?code=$SETUP_CODE")"
SETUP_CSRF="$(printf '%s' "$SETUP_HTML" | csrf_from_html)"
curl -fsS -b "$COOKIE" -c "$COOKIE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "email=admin@example.com" \
  --data-urlencode "name=Admin" \
  --data-urlencode "password=asset-admin-password" \
  --data-urlencode "code=$SETUP_CODE" \
  --data-urlencode "csrf=$SETUP_CSRF" \
  "$BASE/setup" >/dev/null

DASH_HTML="$(curl -fsS -b "$COOKIE" -c "$COOKIE" "$BASE/dashboard")"
DASH_CSRF="$(printf '%s' "$DASH_HTML" | csrf_from_html)"
KEY_HTML="$(curl -fsS -b "$COOKIE" -c "$COOKIE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name=e2e-browser" \
  --data-urlencode "csrf=$DASH_CSRF" \
  "$BASE/dashboard/api-keys")"
TOKEN="$(printf '%s' "$KEY_HTML" | sed -n 's/.*id="hn-api-key"[^>]*>\(peek_[^<]*\)<.*/\1/p' | head -n1)"
[ -n "$TOKEN" ] || { echo "error: API key setup failed"; exit 1; }

echo "-> uploading probe page"
UP="$(curl -fsS -H "Authorization: Bearer $TOKEN" \
  -F "file=@scripts/e2e-browser-page.html;type=text/html" \
  -F "visibility=public" \
  "$BASE/api/upload")"
SLUG="$(printf '%s' "$UP" | json_value slug)"
[ -n "$SLUG" ] || { echo "error: upload failed: $UP"; exit 1; }

echo "-> driving the browser"
BASE="$BASE" SLUG="$SLUG" CHROME="$CHROME" node scripts/e2e-browser.mjs
