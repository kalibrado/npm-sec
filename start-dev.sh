#!/usr/bin/env bash
set -euo pipefail

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
else
  echo "⚠️  .env introuvable. Copie .env.example vers .env puis adapte les secrets."
  echo "    cp .env.example .env"
fi

PORT="${PORT:-8010}"
fuser -k "${PORT}/tcp" >/dev/null 2>&1 || true
uvicorn main:app --host 0.0.0.0 --port "${PORT}" --reload
