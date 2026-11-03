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
# Accept either the original direct include or the Git-managed profile.
# In managed mode both hops must exist; otherwise Nginx might silently
# keep using stale rules even when the copy/reload succeeds.
check_hook() {
  local parent="$1" direct="$2" profile="$3"
  if docker exec "$NPM_CONTAINER" grep -Fq "include $direct;" "$parent"; then
    return 0
  fi
  if docker exec "$NPM_CONTAINER" grep -Fq "include $profile;" "$parent" &&
     docker exec "$NPM_CONTAINER" grep -Fq "include $direct;" "$profile"; then
    return 0
  fi
  die "missing policy include (direct or via managed profile) in $parent"
}
check_hook "/data/nginx/custom/http_top.conf" \
  "$TARGET/npm-blocklist.conf" "$TARGET/http-security.conf"
check_hook "/data/nginx/custom/server_proxy.conf" \
  "$TARGET/npm-server-guard.conf" "$TARGET/server-security.conf"

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
