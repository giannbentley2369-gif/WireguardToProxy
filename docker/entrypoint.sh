#!/bin/sh
# Prepares the data volume, then drops root before starting the application.
set -eu

DATA_DIR="${WGPROXY_DATA_DIR:-/data}"
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA_DIR"
    # Docker creates a missing ./data bind mount as root: hand it to the runtime user.
    find "$DATA_DIR" \( ! -user "$PUID" -o ! -group "$PGID" \) -exec chown -h "$PUID:$PGID" {} +
    chmod 0700 "$DATA_DIR"
    exec setpriv --reuid="$PUID" --regid="$PGID" --clear-groups -- "$@"
fi

if [ ! -w "$DATA_DIR" ]; then
    echo "error: $DATA_DIR is not writable by uid $(id -u)." >&2
    echo "       Fix it on the host with: sudo chown -R $(id -u):$(id -g) ./data" >&2
    exit 1
fi
exec "$@"
