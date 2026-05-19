#!/usr/bin/env bash
# RBAC sync-server tour: end-to-end demo.
#
# Builds (if needed), starts the server, runs every scenario in order, and
# tears down. Safe to re-run — the DB file is deleted at the start of each
# tour so we always begin from a clean state (empty grants, no admin).
#
# Exit code is 0 on full success, non-zero if any scenario fails.
set -euo pipefail
cd "$(dirname "$0")"

echo "═══════════════════════════════════════════════════════════════════"
echo " Turso RBAC sync-server tour"
echo "═══════════════════════════════════════════════════════════════════"

source setup.env

# Sanity checks: we don't want to start the demo and crash three steps in
# because curl/openssl is missing. Git Bash on Windows bundles both.
# `jq` is NOT required — pipeline.sh does its own JSON construction and
# parsing — but it's nice-to-have for ad-hoc poking after the tour.
for bin in curl openssl; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "ERROR: $bin is required but not on PATH." >&2
        echo "On Windows, install Git for Windows which bundles both." >&2
        exit 1
    fi
done
if ! command -v jq >/dev/null 2>&1; then
    echo "[tour] note: jq not on PATH. The demo doesn't need it, but it" >&2
    echo "       makes ad-hoc curl exploration nicer:" >&2
    echo "         winget install jqlang.jq          # Windows 11" >&2
    echo "         choco install jq                  # Chocolatey" >&2
    echo "         scoop install jq                  # Scoop" >&2
    echo "         brew install jq                   # macOS" >&2
    echo "         apt-get install jq                # Debian/Ubuntu" >&2
fi

# 1. Clean slate. We want TOFU to fire, so the grants table must be empty.
echo
echo "[tour] removing any prior DB state"
rm -f "$TURSO_DEMO_DB" "${TURSO_DEMO_DB}-wal" "${TURSO_DEMO_DB}-shm"

# 2. Stop any leftover server, then start fresh.
./stop_server.sh >/dev/null 2>&1 || true

echo "[tour] starting sync server (logs → server.log)"
./start_server.sh >server.log 2>&1 &
SERVER_PID=$!
trap '
    echo
    echo "[tour] tearing down (pid=$SERVER_PID)"
    kill $SERVER_PID 2>/dev/null || true
    ./stop_server.sh >/dev/null 2>&1 || true
' EXIT INT TERM

# 3. Wait for the server to be listening. We probe with a deliberately bad
#    request — anything from "connection refused" → "401 Unauthorized" means
#    the listener is up.
echo -n "[tour] waiting for server"
for _ in $(seq 1 50); do
    if curl -sS -o /dev/null --max-time 1 "http://${TURSO_SYNC_SERVER_ADDR}/v2/pipeline" 2>/dev/null; then
        echo " (ready)"
        break
    fi
    sleep 0.2
    echo -n "."
done

# 4. Run scenarios in order. Each is standalone so any can be re-run later.
for scenario in scenarios/*.sh; do
    bash "$scenario"
done

echo
echo "═══════════════════════════════════════════════════════════════════"
echo " Tour complete. The server is still running in the background;"
echo " run ./stop_server.sh to kill it, or just exit this shell."
echo "═══════════════════════════════════════════════════════════════════"
echo
echo " Logs:    server.log"
echo " DB:      $TURSO_DEMO_DB"
echo " Try:     ./scenarios/04_editor_blocked.sh   (replay any scenario)"

# Detach trap so the server keeps running for ad-hoc poking.
trap - EXIT INT TERM
