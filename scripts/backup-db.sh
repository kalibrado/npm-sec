#!/usr/bin/env bash
set -euo pipefail

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

DB_FILE="${DB_FILE:-./data/logs.db}"
BACKUP_DIR="${BACKUP_DIR:-./data/backups}"

# Les chemins .env sont souvent des chemins conteneur (/data/...).
# Pour les scripts exécutés depuis l'hôte, on les remappe vers ./data/...
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
BACKUP_DIR="$(host_path "$BACKUP_DIR")"
mkdir -p "$BACKUP_DIR"

if [[ ! -f "$DB_FILE" ]]; then
  echo "❌ DB introuvable: $DB_FILE"
  exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
DEST="$BACKUP_DIR/logs-$TS.db"

python3 - "$DB_FILE" "$DEST" <<'PY'
import sqlite3, sys
src, dst = sys.argv[1], sys.argv[2]
with sqlite3.connect(src) as src_conn, sqlite3.connect(dst) as dst_conn:
    src_conn.backup(dst_conn)
PY

chmod 600 "$DEST" || true
echo "✅ Backup créé: $DEST"
