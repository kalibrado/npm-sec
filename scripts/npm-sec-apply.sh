#!/usr/bin/env bash
set -euo pipefail

# Run on the Docker host, not from the dashboard container.
# This script intentionally uses the local Docker CLI, never an exposed socket.
NPM_CONTAINER="${NPM_CONTAINER:-npm}"
EXPORT_DIR="${EXPORT_DIR:-./data/exports}"
TARGET="/data/nginx/custom/npm-security"
HTTP_SNIPPET="${EXPORT_DIR}/npm-blocklist.conf"
SERVER_SNIPPET="${EXPORT_DIR}/npm-server-guard.conf"
STATUS_FILE="${EXPORT_DIR}/deployment-status.json"

die() { echo "[npm-sec] ERROR: $*" >&2; exit 1; }
for command in docker sha256sum python3; do
  command -v "$command" >/dev/null 2>&1 || die "missing $command"
done
test -s "$HTTP_SNIPPET" || die "missing $HTTP_SNIPPET"
test -s "$SERVER_SNIPPET" || die "missing $SERVER_SNIPPET"

docker inspect -f '{{.State.Running}}' "$NPM_CONTAINER" 2>/dev/null | grep -qx true ||
  die "NPM container is not running: $NPM_CONTAINER"

# Never overwrite NPM's existing custom configuration. An administrator
# adds the following includes once, keeping the rest of their configuration.
docker exec "$NPM_CONTAINER" sh -c 'grep -Fq "$1" "$2"' sh \
  "include $TARGET/npm-blocklist.conf;" "/data/nginx/custom/http_top.conf" ||
  die "missing include in /data/nginx/custom/http_top.conf (see docs/NPM_POLICY_ENFORCEMENT.md)"
docker exec "$NPM_CONTAINER" sh -c 'grep -Fq "$1" "$2"' sh \
  "include $TARGET/npm-server-guard.conf;" "/data/nginx/custom/server_proxy.conf" ||
  die "missing include in /data/nginx/custom/server_proxy.conf (see docs/NPM_POLICY_ENFORCEMENT.md)"

docker exec "$NPM_CONTAINER" mkdir -p "$TARGET"
# Existing files must be present: otherwise a rollback could leave the
# NPM include pointing at a nonexistent file.
docker exec "$NPM_CONTAINER" test -f "$TARGET/npm-blocklist.conf" ||
  die "bootstrap the first HTTP policy file before enabling includes"
docker exec "$NPM_CONTAINER" test -f "$TARGET/npm-server-guard.conf" ||
  die "bootstrap the first server guard before enabling includes"

docker exec "$NPM_CONTAINER" cp "$TARGET/npm-blocklist.conf" "$TARGET/npm-blocklist.conf.previous"
docker exec "$NPM_CONTAINER" cp "$TARGET/npm-server-guard.conf" "$TARGET/npm-server-guard.conf.previous"
docker cp "$HTTP_SNIPPET" "$NPM_CONTAINER:$TARGET/npm-blocklist.conf.candidate"
docker cp "$SERVER_SNIPPET" "$NPM_CONTAINER:$TARGET/npm-server-guard.conf.candidate"
docker exec "$NPM_CONTAINER" mv "$TARGET/npm-blocklist.conf.candidate" "$TARGET/npm-blocklist.conf"
docker exec "$NPM_CONTAINER" mv "$TARGET/npm-server-guard.conf.candidate" "$TARGET/npm-server-guard.conf"

rollback() {
  echo "[npm-sec] restoring previous NPM configuration" >&2
  docker exec "$NPM_CONTAINER" cp "$TARGET/npm-blocklist.conf.previous" "$TARGET/npm-blocklist.conf" || true
  docker exec "$NPM_CONTAINER" cp "$TARGET/npm-server-guard.conf.previous" "$TARGET/npm-server-guard.conf" || true
}

if ! docker exec "$NPM_CONTAINER" nginx -t; then
  rollback
  die "nginx -t failed: previous rules restored; no reload issued"
fi
if ! docker exec "$NPM_CONTAINER" nginx -s reload; then
  rollback
  docker exec "$NPM_CONTAINER" nginx -t || true
  docker exec "$NPM_CONTAINER" nginx -s reload || true
  die "Nginx reload failed: previous rules restored"
fi

hash_file() { sha256sum "$1" | awk '{print $1}'; }
HASH=$(printf '%s%s' "$(hash_file "$HTTP_SNIPPET")" "$(hash_file "$SERVER_SNIPPET")" | sha256sum | awk '{print $1}')
python3 - "$STATUS_FILE" "$HASH" "$NPM_CONTAINER" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import sys

status = Path(sys.argv[1])
payload = {
    "status": "applied",
    "applied_hash": sys.argv[2],
    "container": sys.argv[3],
    "applied_at": datetime.now(timezone.utc).isoformat(),
    "validation": "nginx -t",
    "reload": "nginx -s reload",
}
temp = status.with_suffix(".tmp")
temp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
os.replace(temp, status)
PY

echo "[npm-sec] configuration validated and reloaded: $HASH"
