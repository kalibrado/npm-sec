#!/bin/sh
set -eu

WATCH_DIR="${WATCH_DIR:-/watch}"
CONTAINER_NAME="${CONTAINER_NAME:-npm}"
DEBOUNCE_SECONDS="${DEBOUNCE_SECONDS:-3}"

echo "[npm-reloader] watching ${WATCH_DIR}"
echo "[npm-reloader] target container: ${CONTAINER_NAME}"

last_restart=0

restart_npm() {
    now="$(date +%s)"
    
    if [ $((now - last_restart)) -lt "${DEBOUNCE_SECONDS}" ]; then
        echo "[npm-reloader] debounce active, skipping duplicate restart"
        return 0
    fi
    
    last_restart="${now}"
    
    echo "[npm-reloader] blocklist changed, restarting ${CONTAINER_NAME}"
    
    curl --fail --vvv --show-error \
    --unix-socket /var/run/docker.sock \
    -X POST "http://localhost/containers/${CONTAINER_NAME}/restart?t=3"
    
    echo "[npm-reloader] restart requested"
}

while true; do
    inotifywait -r \
    -e close_write,create,delete,move \
    "${WATCH_DIR}" >/dev/null 2>&1 || true
    
    restart_npm || echo "[npm-reloader] restart failed"
done