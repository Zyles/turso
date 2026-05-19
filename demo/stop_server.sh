#!/usr/bin/env bash
# Stop any running tursodb sync-server instance bound to TURSO_SYNC_SERVER_ADDR.
# Idempotent: safe to call when nothing is running.
set -euo pipefail
cd "$(dirname "$0")"
source setup.env

port="${TURSO_SYNC_SERVER_ADDR##*:}"

if command -v lsof >/dev/null 2>&1; then
    # Linux/macOS path.
    pids=$(lsof -ti ":$port" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        echo "[demo] killing tursodb pids: $pids"
        kill $pids 2>/dev/null || true
        sleep 0.2
    fi
elif command -v powershell.exe >/dev/null 2>&1; then
    # Windows: ask the OS for the owning PID. -SilentlyContinue keeps the
    # script idempotent when nothing is bound.
    powershell.exe -NoProfile -Command "
        Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess |
        Sort-Object -Unique |
        ForEach-Object { Stop-Process -Id \$_ -Force -ErrorAction SilentlyContinue }
    " 2>/dev/null || true
fi

# Final sanity: brute-force any tursodb left around.
pkill -f 'tursodb.*--sync-server' 2>/dev/null || true

echo "[demo] sync server stopped."
