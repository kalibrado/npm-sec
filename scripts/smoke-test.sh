#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${BASE_URL:-http://localhost:8000}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

need_admin() {
  if [[ -z "$ADMIN_TOKEN" ]]; then
    echo "❌ ADMIN_TOKEN manquant. Ex: ADMIN_TOKEN=xxx ./scripts/smoke-test.sh"
    exit 1
  fi
}

check_public() {
  local path="$1"
  echo "GET $path"
  curl -fsS "$BASE_URL$path" >/dev/null
}

check_admin() {
  local path="$1"
  need_admin
  echo "GET admin $path"
  curl -fsS -H "X-Admin-Token: $ADMIN_TOKEN" "$BASE_URL$path" >/dev/null
}

post_admin() {
  local path="$1"
  need_admin
  echo "POST admin $path"
  curl -fsS -X POST -H "X-Admin-Token: $ADMIN_TOKEN" "$BASE_URL$path" >/dev/null
}

check_public /version
check_public /health
check_admin /stats
check_admin '/history?limit=1'
check_admin /widget
check_admin /config
check_admin /npm-health
check_admin /metrics
check_admin /threats
check_admin /ban-events
check_admin /threats/simulate-autoban
check_admin /threat-intel/bruteforce

echo "✅ smoke-test OK"
