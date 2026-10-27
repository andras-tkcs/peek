#!/usr/bin/env bash
# make-release-fixture.sh - build a database with a real released peekd.
#
# Usage: scripts/make-release-fixture.sh <tag>   (for example v0.10.0)
#
# Builds <tag> in a throwaway git worktree, boots it, seeds pages, a comment,
# a grant and an invite through that release's own HTTP API, then writes
# internal/db/testdata/peek-<tag>.db (a peekd backup) and peek-<tag>.json
# (the identifiers internal/db/release_fixture_test.go asserts on).
#
# Requires: go, git, curl. The tag's toolchain is the installed one
# (GOTOOLCHAIN=local), so the tag's pinned Go version need not be downloadable.
set -euo pipefail

TAG="${1:-}"
[ -n "$TAG" ] || { echo "usage: $0 <tag>"; exit 2; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PEEK_FIXTURE_PORT:-7796}"
BASE="http://localhost:$PORT"
WORK="$(mktemp -d)"
TREE="$WORK/tree"
DATA="$WORK/data"
COOKIE="$WORK/cookies.txt"
OUT_DIR="$ROOT/internal/db/testdata"
SRV_PID=""

cleanup() {
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true
  sleep 0.3
  git -C "$ROOT" worktree remove --force "$TREE" 2>/dev/null || true
  chmod -R u+w "$WORK" 2>/dev/null || true
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

command -v go >/dev/null || { echo "error: go not found"; exit 1; }
command -v curl >/dev/null || { echo "error: curl not found"; exit 1; }
git rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null \
  || { echo "error: tag $TAG not found (try: git fetch --tags origin)"; exit 1; }

GO="$(go env GOROOT)/bin/go"

echo "-> building $TAG"
git worktree add --detach "$TREE" "$TAG" >/dev/null
mkdir -p "$DATA"
(cd "$TREE" && GOTOOLCHAIN=local "$GO" build -o "$WORK/peekd" ./cmd/peekd)

echo "-> starting peekd on :$PORT"
"$WORK/peekd" --addr ":$PORT" --data "$DATA" --base-url "$BASE" >"$WORK/peekd.log" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 100); do
  curl -fsS "$BASE/" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "$BASE/" >/dev/null 2>&1 || { echo "error: peekd did not start"; cat "$WORK/peekd.log"; exit 1; }

csrf_from_html() {
  sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -n1
}

json_value() {
  key="$1"
  sed -n "s/.*\"$key\":\"\\([^\"]*\\)\".*/\\1/p"
}

echo "-> creating first admin + CLI token"
SETUP_CODE="$(tr -d '\n\r' < "$DATA/setup.key")"
SETUP_HTML="$(curl -fsS -c "$COOKIE" "$BASE/setup?code=$SETUP_CODE")"
SETUP_CSRF="$(printf '%s' "$SETUP_HTML" | csrf_from_html)"
curl -fsS -b "$COOKIE" -c "$COOKIE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "email=admin@example.com" \
  --data-urlencode "name=Admin" \
  --data-urlencode "password=fixture-admin-password" \
  --data-urlencode "code=$SETUP_CODE" \
  --data-urlencode "csrf=$SETUP_CSRF" \
  "$BASE/setup" >/dev/null

START="$(curl -fsS -X POST "$BASE/api/cli/login/start")"
DEVICE_CODE="$(printf '%s' "$START" | json_value device_code)"
USER_CODE="$(printf '%s' "$START" | json_value user_code)"
ENTRY_HTML="$(curl -fsS -b "$COOKIE" -c "$COOKIE" "$BASE/cli-login")"
ENTRY_CSRF="$(printf '%s' "$ENTRY_HTML" | csrf_from_html)"
APPROVE_HTML="$(curl -fsS -b "$COOKIE" -c "$COOKIE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "csrf=$ENTRY_CSRF" \
  --data-urlencode "code=$USER_CODE" \
  "$BASE/cli-login")"
APPROVE_CSRF="$(printf '%s' "$APPROVE_HTML" | csrf_from_html)"
curl -fsS -b "$COOKIE" -c "$COOKIE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "csrf=$APPROVE_CSRF" \
  --data-urlencode "decision=approve" \
  "$BASE/cli-login/$USER_CODE" >/dev/null
POLL="$(curl -fsS -H "Content-Type: application/json" \
  -d "{\"device_code\":\"$DEVICE_CODE\"}" \
  "$BASE/api/cli/login/poll")"
TOKEN="$(printf '%s' "$POLL" | json_value token)"
[ -n "$TOKEN" ] || { echo "error: token setup failed: $POLL"; exit 1; }

api() { curl -fsS -H "Authorization: Bearer $TOKEN" "$@"; }

echo "-> seeding uploads"
UP="$(printf '<!doctype html><h1>Public</h1>' | api --data-binary @- \
  -H "Content-Type: text/html" \
  "$BASE/api/upload?filename=fixture-public.html&visibility=public")"
PUBLIC_SLUG="$(printf '%s' "$UP" | json_value slug)"
[ -n "$PUBLIC_SLUG" ] || { echo "error: public upload failed: $UP"; exit 1; }
printf '<!doctype html><h1>Public v2</h1>' | api --data-binary @- \
  -H "Content-Type: text/html" \
  "$BASE/api/upload?filename=fixture-public.html&slug=$PUBLIC_SLUG" >/dev/null

COMMENT_BODY="Fixture comment"
curl -fsS -H "Content-Type: application/json" \
  -d "{\"selector\":\"h1\",\"element_text\":\"Public\",\"anchor_kind\":\"text\",\"name\":\"Fixture\",\"body\":\"$COMMENT_BODY\"}" \
  "$BASE/api/uploads/$PUBLIC_SLUG/comments" >/dev/null

UP="$(printf '<!doctype html><h1>Private</h1>' | api --data-binary @- \
  -H "Content-Type: text/html" \
  "$BASE/api/upload?filename=fixture-private.html&visibility=private")"
PRIVATE_SLUG="$(printf '%s' "$UP" | json_value slug)"
[ -n "$PRIVATE_SLUG" ] || { echo "error: private upload failed: $UP"; exit 1; }

UP="$(printf '<!doctype html><h1>Password</h1>' | api \
  -F "file=@-;filename=fixture-password.html;type=text/html" \
  -F "visibility=password" -F "password=fixture-password" \
  "$BASE/api/upload")"
PASSWORD_SLUG="$(printf '%s' "$UP" | json_value slug)"
[ -n "$PASSWORD_SLUG" ] || { echo "error: password upload failed: $UP"; exit 1; }

UP="$(printf '<!doctype html><h1>Restricted</h1>' | api \
  -F "file=@-;filename=fixture-restricted.html;type=text/html" \
  -F "visibility=restricted" \
  "$BASE/api/upload")"
RESTRICTED_SLUG="$(printf '%s' "$UP" | json_value slug)"
[ -n "$RESTRICTED_SLUG" ] || { echo "error: restricted upload failed: $UP"; exit 1; }
api -H "Content-Type: application/json" \
  -d '{"kind":"user","email":"reviewer@example.com"}' \
  "$BASE/api/uploads/$RESTRICTED_SLUG/grants" >/dev/null

echo "-> creating invite"
DASH_HTML="$(curl -fsS -b "$COOKIE" -c "$COOKIE" "$BASE/dashboard")"
DASH_CSRF="$(printf '%s' "$DASH_HTML" | csrf_from_html)"
[ -n "$DASH_CSRF" ] || { echo "error: no dashboard CSRF token"; exit 1; }
curl -fsS -b "$COOKIE" -c "$COOKIE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "csrf=$DASH_CSRF" \
  --data-urlencode "email=invitee@example.com" \
  "$BASE/dashboard/invites" >/dev/null

echo "-> stopping peekd and writing the backup"
kill "$SRV_PID"
wait "$SRV_PID" 2>/dev/null || true
SRV_PID=""

mkdir -p "$OUT_DIR"
DB_OUT="$OUT_DIR/peek-$TAG.db"
rm -f "$DB_OUT"
"$WORK/peekd" backup --data "$DATA" "$DB_OUT"

cat > "$OUT_DIR/peek-$TAG.json" <<JSON
{"release":"$TAG","admin_email":"admin@example.com","api_token":"$TOKEN","public_slug":"$PUBLIC_SLUG","private_slug":"$PRIVATE_SLUG","password_slug":"$PASSWORD_SLUG","restricted_slug":"$RESTRICTED_SLUG","grant_email":"reviewer@example.com","invite_email":"invitee@example.com","comment_body":"$COMMENT_BODY"}
JSON
echo "-> wrote $DB_OUT and peek-$TAG.json"
