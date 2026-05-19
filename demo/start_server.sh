#!/usr/bin/env bash
# Start the tursodb sync server in the foreground with the demo's JWT config.
# Sources setup.env automatically so it can be run standalone.
#
# Usage:
#   ./start_server.sh                 # foreground (good for development)
#   ./start_server.sh &               # background (tour.sh does this)
#   ./stop_server.sh                  # corresponding kill

set -euo pipefail
cd "$(dirname "$0")"
source setup.env

# Locate the built binary. Prefer debug build (matches the cargo build line
# in README); fall back to release.
TURSODB=""
for candidate in \
    ../target/debug/tursodb.exe \
    ../target/debug/tursodb \
    ../target/release/tursodb.exe \
    ../target/release/tursodb
do
    if [[ -x "$candidate" ]]; then
        TURSODB="$candidate"
        break
    fi
done

if [[ -z "$TURSODB" ]]; then
    echo "tursodb binary not found. Build first:" >&2
    echo "  cargo build -p turso_cli --no-default-features --features fts,pure-rust-crypto" >&2
    exit 1
fi

echo "[demo] starting $TURSODB sync server on $TURSO_SYNC_SERVER_ADDR"
echo "[demo] DB file: $TURSO_DEMO_DB"
echo "[demo] JWT iss allow-list: $TURSO_SYNC_JWT_ISSUERS"
echo "[demo] role source: Mode A ($TURSO_SYNC_JWT_ROLE_SOURCE)"

# `--sync-server` flag puts tursodb into sync-server mode and binds the
# given address. The env vars above are read by run_sync_server in
# cli/main.rs.
exec "$TURSODB" \
    --sync-server "$TURSO_SYNC_SERVER_ADDR" \
    "$TURSO_DEMO_DB"
