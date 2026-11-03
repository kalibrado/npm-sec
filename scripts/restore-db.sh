#!/usr/bin/env bash
set -euo pipefail

BACKUP="${1:-}"
if [[ -z "$BACKUP" || ! -f "$BACKUP" ]]; then
  echo "❌ Backup invalide: $BACKUP"
  exit 1
fi

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

DB_FILE="${DB_FILE:-./data/logs.db}"

host_path() {
  local p="$1"
  if [[ "$p" == /data ]]; then
    printf './data'
  elif [[ "$p" == /data/* ]]; then
    printf './data/%s' "${p#/data/}"
  else
    printf '%s' "$p"
  fi
}

DB_FILE="$(host_path "$DB_FILE")"
mkdir -p "$(dirname "$DB_FILE")"

if docker compose ps npm-security-dashboard --status running >/dev/null 2>&1; then
  echo "⚠️  Le conteneur semble démarré. Stop conseillé avant restore: docker compose stop npm-security-dashboard"
fi

TS="$(date +%Y%m%d-%H%M%S)"
if [[ -f "$DB_FILE" ]]; then
  cp -a "$DB_FILE" "$DB_FILE.pre-restore-$TS"
  rm -f "$DB_FILE-wal" "$DB_FILE-shm"
fi

cp -a "$BACKUP" "$DB_FILE"
chmod 600 "$DB_FILE" || true
echo "✅ DB restaurée depuis: $BACKUP"
echo "ℹ️  Redémarre ensuite: docker compose up -d"
