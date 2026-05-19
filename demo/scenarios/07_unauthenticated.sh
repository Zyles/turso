#!/usr/bin/env bash
# Scenario 7: unauthenticated request. Server rejects with 401.
#
# Confirms the default-deny property: without a valid `Authorization:
# Bearer <jwt>` header, the request never even reaches the authorizer —
# `authenticate()` returns Err and handle_connection emits 401 with
# `WWW-Authenticate: Bearer error="invalid_token"`.
set -euo pipefail
cd "$(dirname "$0")/.."
source setup.env

echo
echo "═══ Scenario 7: unauthenticated request ═══"

echo
echo "─── POST /v2/pipeline with NO Authorization header"
http_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "Content-Type: application/json" \
    --data-binary '{"baton":null,"requests":[{"type":"execute","stmt":{"sql":"SELECT 1"}}]}' \
    "http://${TURSO_SYNC_SERVER_ADDR}/v2/pipeline" || true)
echo "  ← HTTP $http_code"
[[ "$http_code" == "401" ]] || { echo "expected 401, got $http_code"; exit 1; }

echo
echo "─── POST /v2/pipeline with a GARBAGE Authorization header"
http_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer not-a-real-jwt" \
    --data-binary '{"baton":null,"requests":[{"type":"execute","stmt":{"sql":"SELECT 1"}}]}' \
    "http://${TURSO_SYNC_SERVER_ADDR}/v2/pipeline" || true)
echo "  ← HTTP $http_code"
[[ "$http_code" == "401" ]] || { echo "expected 401, got $http_code"; exit 1; }

echo
echo "─── POST /v2/pipeline with a JWT signed by the WRONG secret"
# Mint a token using a different HS secret. The verifier rejects because
# the signature doesn't validate against the configured secret.
forged=$(
    SECRET_BACKUP="$TURSO_SYNC_JWT_HS_SECRET"
    export TURSO_SYNC_JWT_HS_SECRET="some-other-secret-key"
    source jwt.sh
    mint_jwt "operator"
    export TURSO_SYNC_JWT_HS_SECRET="$SECRET_BACKUP"
)
http_code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $forged" \
    --data-binary '{"baton":null,"requests":[{"type":"execute","stmt":{"sql":"SELECT 1"}}]}' \
    "http://${TURSO_SYNC_SERVER_ADDR}/v2/pipeline" || true)
echo "  ← HTTP $http_code"
[[ "$http_code" == "401" ]] || { echo "expected 401, got $http_code"; exit 1; }

echo
echo "✓ all unauthenticated/forged-token requests rejected with 401."
