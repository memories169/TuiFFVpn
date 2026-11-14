#!/bin/sh
# Runs as root: prepares the state dir, then drops to the app user.
set -e

mkdir -p /data
chown 10001:10001 /data

# Persistent Chromium profile is no longer required (capture runs on the PC),
# but keep the dir so old volumes mount cleanly.
mkdir -p /data/chrome-profile
chown 10001:10001 /data/chrome-profile

# PC-browser ingest key: the userscript posts tokens to /api/ingest with it.
export FXVPN_INGEST_KEY="${FXVPN_INGEST_KEY:-}"

# su-exec is the reliable way to switch uid/gid in Alpine.
exec su-exec 10001:10001 /app/fxvpn-webui "$@"
