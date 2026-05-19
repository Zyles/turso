#!/usr/bin/env bash
# Mint an HS256 JWT against TURSO_SYNC_JWT_HS_SECRET.
#
# Usage:
#   source jwt.sh
#   token=$(mint_jwt operator)              # iss/kid/roles from env
#   token=$(mint_jwt alice "user,reader")   # claim "roles" — Mode A
#                                           # discards this, Mode B uses it
#
# Notes:
# - Pure bash + openssl. No Python, no Node. Works on Git Bash for Windows.
# - We base64url-encode (RFC 7515): swap +→-, /→_, strip =.
# - exp is set to now + 3600s so demo runs aren't broken by clock skew.

set -euo pipefail

_b64url() {
    # Read from stdin, write base64url to stdout. -A keeps openssl from
    # wrapping output every 76 chars; tr does the URL-safe alphabet swap;
    # the `%` quirks strip = padding without invoking sed.
    openssl base64 -A | tr '+/' '-_' | tr -d '='
}

mint_jwt() {
    local sub="${1:?sub required}"
    local roles_csv="${2:-}"
    : "${TURSO_SYNC_JWT_HS_SECRET:?source setup.env first}"
    : "${TURSO_SYNC_JWT_KID:=hs1}"
    local iss
    iss=$(printf %s "${TURSO_SYNC_JWT_ISSUERS:?source setup.env first}" \
        | cut -d, -f1)

    local now exp
    now=$(date +%s)
    exp=$((now + 3600))

    # Build the roles JSON array. Empty CSV → omit the claim entirely.
    local roles_json=""
    if [[ -n "$roles_csv" ]]; then
        roles_json=',"roles":['
        local first=1
        IFS=',' read -ra ROLES <<<"$roles_csv"
        for r in "${ROLES[@]}"; do
            if [[ $first -eq 0 ]]; then roles_json+=','; fi
            roles_json+="\"$(printf %s "$r" | sed 's/"/\\"/g')\""
            first=0
        done
        roles_json+=']'
    fi

    local header payload sig
    header=$(printf '{"alg":"HS256","typ":"JWT","kid":"%s"}' "$TURSO_SYNC_JWT_KID" \
        | _b64url)
    payload=$(printf '{"iss":"%s","sub":"%s","iat":%d,"exp":%d%s}' \
        "$iss" "$sub" "$now" "$exp" "$roles_json" \
        | _b64url)

    # HMAC-SHA256 over `header.payload`, key from env. -binary keeps the raw
    # 32 bytes; base64url then encodes them.
    sig=$(printf '%s.%s' "$header" "$payload" \
        | openssl dgst -sha256 -hmac "$TURSO_SYNC_JWT_HS_SECRET" -binary \
        | _b64url)

    printf '%s.%s.%s' "$header" "$payload" "$sig"
}

# Print a JWT and stop here when invoked directly (not sourced).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mint_jwt "${1:?usage: jwt.sh <sub> [roles_csv]}" "${2:-}"
    echo
fi
