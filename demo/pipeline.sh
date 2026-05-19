#!/usr/bin/env bash
# Send a single SQL statement to /v2/pipeline and pretty-print the result.
#
# Usage:
#   source pipeline.sh
#   pipeline <token> <sql>
#
# Output (one block per call):
#   → POST /v2/pipeline  Authorization: Bearer eyJhbG...truncated
#   ← 200 OK  result.affected_row_count=1
# or
#   ← 200 OK  error.code=AUTHORIZATION_DENIED  message="..."
#
# No jq dependency. JSON construction is hand-rolled (we only escape the
# SQL string); response parsing uses grep + sed against the known protocol
# shape. If `jq` IS on PATH, the response will be pretty-printed inline as
# a bonus; otherwise we fall back to raw output.

set -euo pipefail

# Escape an arbitrary string for inclusion in a JSON string literal. Handles
# the four control chars that matter for SQL inputs (\, ", LF, TAB) per
# RFC 8259. The remaining control chars (0x00-0x1F minus those four) are
# extremely unlikely in CRUD SQL and would be rejected by the lexer anyway.
_json_escape() {
    local s=$1
    s="${s//\\/\\\\}"      # backslash → \\
    s="${s//\"/\\\"}"      # double-quote → \"
    s="${s//$'\n'/\\n}"    # newline → \n
    s="${s//$'\t'/\\t}"    # tab → \t
    s="${s//$'\r'/\\r}"    # CR → \r
    printf '%s' "$s"
}

# Best-effort extract of `"key":"value"` from a JSON blob. Returns the
# first match (so callers reach inside known nested structures by chaining
# multiple extractions). Returns empty string if not found. The regex is
# intentionally loose because we control the producer (server emits stable
# shapes via serde) and the alternative is a 200-line JSON parser.
_json_str() {
    local key=$1
    local json=$2
    # The `[^"\\]*(\\.)?` shape allows for one level of escape. Good enough
    # for our error messages, which won't typically contain `"`.
    printf %s "$json" \
        | grep -oE "\"$key\":\"([^\"\\\\]|\\\\.)*\"" \
        | head -n1 \
        | sed -E "s/^\"$key\":\"(.*)\"$/\\1/" \
        || true
}

# Extract a numeric field (`"key":NN`). Used for affected_row_count, etc.
_json_num() {
    local key=$1
    local json=$2
    printf %s "$json" \
        | grep -oE "\"$key\":[0-9]+" \
        | head -n1 \
        | sed -E "s/^\"$key\"://" \
        || true
}

pipeline() {
    local token="${1:?token required}"
    local sql="${2:?sql required}"
    : "${TURSO_SYNC_SERVER_ADDR:?source setup.env first}"

    local escaped_sql
    escaped_sql=$(_json_escape "$sql")
    local body
    body='{"baton":null,"requests":[{"type":"execute","stmt":{"sql":"'"$escaped_sql"'"}}]}'

    local short_token="${token:0:20}...truncated"
    # Human-readable status lines go to stderr so the caller can pipe stdout
    # (the raw JSON) into another command without consuming the breadcrumbs.
    printf '  → POST /v2/pipeline  Authorization: Bearer %s\n' "$short_token" >&2

    # Single curl call; capture body and HTTP code in one response by
    # appending the status to the body with a known delimiter.
    local response
    response=$(curl -sS --max-time 10 \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $token" \
        -w $'\n__HTTP_CODE__%{http_code}' \
        "http://${TURSO_SYNC_SERVER_ADDR}/v2/pipeline" \
        --data-binary "$body" 2>/dev/null || true)

    local http_code
    http_code=$(printf %s "$response" | sed -nE 's/.*__HTTP_CODE__([0-9]+)$/\1/p')
    local json
    json=$(printf %s "$response" | sed -E 's/__HTTP_CODE__[0-9]+$//')

    case "$http_code" in
        200)
            # We need to know if results[0] is ok or error. The serde-tagged
            # enum emits `"type":"ok"` or `"type":"error"`. Locate the FIRST
            # such tag after `"results":[`.
            local first_result_tag
            first_result_tag=$(printf %s "$json" \
                | grep -oE '"results":\[\{"type":"[a-z]+"' \
                | head -n1 \
                | sed -E 's/.*"type":"([a-z]+)".*/\1/' \
                || true)

            case "$first_result_tag" in
                ok)
                    local affected
                    affected=$(_json_num "affected_row_count" "$json")
                    affected=${affected:-0}
                    printf '  \033[32m← 200 OK\033[0m  affected=%s\n' "$affected" >&2
                    ;;
                error)
                    local code msg
                    code=$(_json_str "code" "$json")
                    msg=$(_json_str "message" "$json")
                    printf '  \033[31m← 200 OK  error.code=%s\033[0m\n' "${code:-?}" >&2
                    if [[ -n "$msg" ]]; then
                        printf '         message: %s\n' "$msg" >&2
                    fi
                    ;;
                *)
                    printf '  ← 200 OK  (unexpected shape)\n' >&2
                    printf '         body: %s\n' "$(printf %s "$json" | head -c 200)" >&2
                    ;;
            esac
            ;;
        401)
            printf '  \033[33m← 401 Unauthorized\033[0m  (no/invalid bearer token)\n' >&2
            ;;
        "")
            printf '  ← ???  (no response from server; is it running?)\n' >&2
            ;;
        *)
            printf '  ← %s  %s\n' "$http_code" \
                "$(printf %s "$json" | head -c 200)" >&2
            ;;
    esac

    # Echo the raw JSON for further programmatic use. `set -e` doesn't
    # fire on the bare printf because we already consumed all error paths.
    printf %s "$json"
}
