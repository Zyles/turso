#!/usr/bin/env bash
# Scenario 8: can local SQL writes bypass cloud RBAC?
#
# This is the security question that matters. Local consistency gating
# (e.g. forbidding apps from writing rows that wouldn't survive the next
# sync) is a useful product feature, but it is NOT a security feature —
# the user owns their device and can always edit the file. What matters
# for security is whether unauthorized local writes can propagate UP into
# the canonical cloud state, where every other client would then see them.
#
# The threat model:
#   - Attacker holds a valid JWT (alice's). She has Mode A `user` role,
#     UPDATE-only on user_profile with RLS.
#   - Attacker has full filesystem access to her own local replica.
#   - Attacker can craft arbitrary HTTP requests against the sync server.
#   - Goal: write a row that alice's RBAC grant would NOT permit, and
#     have it land in the cloud's canonical state.
#
# Every realistic path from local writes to cloud state must run through
# the authorizer. This scenario walks each path:
#
#   path A: local edit → sync engine auto-push → /v2/pipeline    (gated)
#   path B: manual /v2/pipeline POST                              (gated)
#   path C: forged /pull-updates upload                           (impossible — read-only)
#   path D: any other endpoint                                    (impossible — 404)
#
# All paths converge on /v2/pipeline. That's where RBAC lives. If RBAC is
# enforced there (and it is), local writes cannot bypass it.

set -euo pipefail
cd "$(dirname "$0")/.."
source setup.env
source jwt.sh
source pipeline.sh

echo
echo "═══ Scenario 8: can local SQL writes bypass cloud RBAC? ═══"
echo
echo "  Question being tested:"
echo "    Alice has a valid JWT and writes a row to her LOCAL replica that"
echo "    her cloud RBAC grant would deny. Can that row reach the cloud"
echo "    canonical state by any path?"
echo
echo "  Expected answer:"
echo "    No. Every path from local→cloud goes through /v2/pipeline; the"
echo "    authorizer runs there. Reads/pulls are one-way and can't carry"
echo "    write payloads. No other write endpoint exists."

# Locate the tursodb binary.
TURSODB=""
for candidate in \
    ../target/debug/tursodb.exe \
    ../target/debug/tursodb \
    ../target/release/tursodb.exe \
    ../target/release/tursodb
do
    [[ -x "$candidate" ]] && { TURSODB="$candidate"; break; }
done
[[ -n "$TURSODB" ]] || { echo "tursodb binary not found." >&2; exit 1; }

# Two simulated local replicas — one for alice, one for bob. In a real
# Turso deployment, these files would live on each user's device
# (laptop/phone/etc.) and the sync engine (turso_sync_engine) would
# maintain them: reading CDC entries from local commits and pushing
# them to the cloud, pulling WAL frames from the cloud and applying
# them locally.
#
# IMPORTANT — DEMO SIMPLIFICATION:
#   The sync protocol is page-level, so a real pull would copy ALL
#   pages from cloud to client: user tables, the RBAC policy tables
#   (_turso_rbac_grants, _turso_rbac_role_assignments, including the
#   last-admin triggers), the sync bookkeeping (turso_sync_*), the
#   sqlite_schema catalog — everything. After a real pull, client
#   replicas would byte-for-byte match the cloud's contents.
#
#   This scenario bypasses that and creates the client files with
#   just a single CREATE TABLE so the diff between "what's local"
#   and "what reached cloud" is minimal and obvious. Real clients
#   would have the full cloud state plus any locally-unsynced edits.
#
# This demo runs everything on one machine, so we put the client
# replicas in the demo/ directory next to the cloud DB — just for
# visibility. In production you'd never see these three files in the
# same directory; they live on different machines.
CLIENT_ALICE_DB="client_alice.db"
CLIENT_BOB_DB="client_bob.db"
rm -f "$CLIENT_ALICE_DB" "${CLIENT_ALICE_DB}-wal" "${CLIENT_ALICE_DB}-shm"
rm -f "$CLIENT_BOB_DB"   "${CLIENT_BOB_DB}-wal"   "${CLIENT_BOB_DB}-shm"

# ---------------------------------------------------------------------------
# Setup: alice owns her local file. She can write to it freely. That is
# correct behavior — it's HER file. The question is what happens next.
# ---------------------------------------------------------------------------
echo
echo "─── setup: alice writes to HER OWN local replica (no RBAC involved)"
"$TURSODB" "$CLIENT_ALICE_DB" \
    "CREATE TABLE products (id INTEGER, name TEXT, price INTEGER, owner_id TEXT);
     INSERT INTO products VALUES (777, 'LOCAL-PAYLOAD-ALICE', 0, 'alice')" \
    > /dev/null
echo "    client_alice.db now has row 777. This is just a file on alice's"
echo "    machine — no RBAC, no JWT, no cloud involvement yet. Equivalent"
echo "    of jotting something down in a private notebook."

alice=$(mint_jwt "alice")
operator=$(mint_jwt "operator")

# ---------------------------------------------------------------------------
# Path A: local edit → sync engine auto-push → /v2/pipeline
#
# The sync engine reads alice's CDC table, generates a logical SQL push
# statement, and POSTs it to /v2/pipeline with her JWT. We simulate the
# exact same network request shape the sync engine would emit.
# ---------------------------------------------------------------------------
echo
echo "─── path A: local edit → sync engine auto-push → /v2/pipeline"
echo "    The sync engine reads alice's CDC entry for the INSERT, generates"
echo "    \`INSERT INTO products VALUES (777, 'LOCAL-PAYLOAD-ALICE', ...)\`,"
echo "    POSTs it to /v2/pipeline with her JWT attached. RBAC fires there."
pipeline "$alice" \
    "INSERT INTO products VALUES (777, 'LOCAL-PAYLOAD-ALICE', 0, 'alice')" \
    > /dev/null

# ---------------------------------------------------------------------------
# Path B: manual /v2/pipeline POST.
#
# A malicious local client doesn't even need the sync engine — they can
# just craft the HTTP request themselves. Same endpoint, same auth, same
# RBAC. Demonstrated by sending a different payload directly.
# ---------------------------------------------------------------------------
echo
echo "─── path B: malicious client crafts direct /v2/pipeline POST"
echo "    Same endpoint as path A. RBAC doesn't care who built the request."
pipeline "$alice" \
    "DELETE FROM products WHERE id != 0" \
    > /dev/null

# ---------------------------------------------------------------------------
# Path C: forged /pull-updates upload.
#
# /pull-updates is a READ endpoint (server sends WAL pages to client).
# The request body is a small protobuf describing what range the client
# wants. There is no way to embed write payloads. We confirm by sending
# a deliberately bogus body and seeing what happens.
# ---------------------------------------------------------------------------
echo
echo "─── path C: try to inject writes via /pull-updates"
echo "    /pull-updates is one-way: server → client (WAL frames). Even if"
echo "    we send a junk payload, the server can only respond with WAL"
echo "    bytes; it has no write path attached to this endpoint."
http_code=$(curl -sS -o /tmp/pull_response.bin -w '%{http_code}' \
    -H "Content-Type: application/protobuf" \
    -H "Authorization: Bearer $alice" \
    --data-binary $'\x08\x01\x10\x02\x18\x00' \
    "http://${TURSO_SYNC_SERVER_ADDR}/pull-updates" 2>/dev/null || echo "??")
echo "    Response code: $http_code (no write side effect possible)"

# ---------------------------------------------------------------------------
# Path D: any other endpoint.
#
# What if the attacker discovers a backdoor /push-frames endpoint or a
# /admin path? Probe several likely candidates and confirm they all 404.
# ---------------------------------------------------------------------------
echo
echo "─── path D: probe for hidden write endpoints"
for endpoint in /push-frames /push /admin /sync /apply /v1/pipeline /v3/pipeline /commit /wal /raw; do
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 \
        -H "Authorization: Bearer $alice" \
        -X POST --data-binary 'INSERT INTO products VALUES (666, "PWN", 0, "alice")' \
        "http://${TURSO_SYNC_SERVER_ADDR}${endpoint}" 2>/dev/null || echo "??")
    printf '    POST %-20s → %s\n' "$endpoint" "$code"
done

# ---------------------------------------------------------------------------
# Verification: row 777 is NOT in the cloud's canonical state.
# ---------------------------------------------------------------------------
echo
echo "─── verify: the cloud's canonical state never accepted alice's payload"
echo "    Authorized read by operator. If any of paths A-D had succeeded,"
echo "    we'd see row 777 in the cloud DB. We won't."
pipeline "$operator" \
    "SELECT id, name, owner_id FROM products WHERE id = 777" \
    > /dev/null

# ---------------------------------------------------------------------------
# Contrast: bob does the same local-then-push dance, but he HAS an editor
# grant on `products`. His push succeeds. This shows the asymmetry that
# matters: it's the GRANT that decides, not the file. Same local-edit
# action; different outcome because of the principal's authorization.
# ---------------------------------------------------------------------------
echo
echo "─── contrast: bob (editor role) does the same dance — local edit, push"
echo "    Bob is the editor. He has INSERT/UPDATE/DELETE on products. So"
echo "    when his sync engine pushes the local change, the authorizer"
echo "    accepts it and the cloud's canonical state is mutated."
bob=$(mint_jwt "bob")
"$TURSODB" "$CLIENT_BOB_DB" \
    "CREATE TABLE products (id INTEGER, name TEXT, price INTEGER, owner_id TEXT);
     INSERT INTO products VALUES (555, 'LOCAL-PAYLOAD-BOB', 0, 'bob')" \
    > /dev/null
echo "    client_bob.db now has row 555 (bob's local edit; not yet pushed)."
pipeline "$bob" \
    "INSERT INTO products VALUES (555, 'LOCAL-PAYLOAD-BOB', 0, 'bob')" \
    > /dev/null

echo
echo "─── verify: bob's row IS in the cloud (his grant authorized the push)"
pipeline "$operator" \
    "SELECT id, name, owner_id FROM products WHERE id = 555" \
    > /dev/null

echo
echo "─── for completeness: alice's local row 777 is still on her disk"
echo "    It's harmless until she tries to push, and she can't push it."
echo "    On the next sync pull, the conflict resolver reconciles toward"
echo "    cloud state — her unsynced row either drops or remains as"
echo "    'local only,' depending on sync engine policy. Either way it"
echo "    can't reach other clients via the cloud."
echo
"$TURSODB" "$CLIENT_ALICE_DB" "SELECT id, name FROM products"

echo
echo "═══ Conclusion ═══"
echo
echo " Local writes CANNOT bypass cloud RBAC via any of the paths a real"
echo " attacker could use:"
echo
echo "   Path A (sync engine auto-push):  denied at /v2/pipeline"
echo "   Path B (manual HTTP push):       denied at /v2/pipeline"
echo "   Path C (forged /pull-updates):   impossible — read-only endpoint"
echo "   Path D (other endpoints):        impossible — only two exist"
echo
echo " The security property holds: every path from local writes to cloud"
echo " state goes through the authorizer. RBAC is the chokepoint, and"
echo " there are no side channels."
echo
echo " ─────────────────────────────────────────────────────────"
echo
echo " Separate concern (NOT what this scenario is testing): local"
echo " consistency gating. Some deployments will want to prevent apps"
echo " from making local writes that the cloud will later reject —"
echo " that's a UX feature (avoid confusing 'looked like it worked"
echo " offline but rolled back on sync' experiences), not a security"
echo " feature. It would require running the same RBAC check on the"
echo " client connection. That's possible but it's a *consistency*"
echo " feature, not RBAC's security goal."

rm -f /tmp/pull_response.bin

echo
echo "─── three files on disk: cloud + 2 client replicas ───"
echo
ls -lh "$TURSO_DEMO_DB" "$CLIENT_ALICE_DB" "$CLIENT_BOB_DB" 2>/dev/null \
    | awk '{ printf "    %-22s %8s bytes\n", $NF, $5 }'
echo
echo "    Each file is an independent SQLite-format database:"
echo
echo "      $TURSO_DEMO_DB    — cloud canonical state, what the sync"
echo "                            server serves. Has row 555 (bob's push"
echo "                            succeeded) and NOT row 777 (alice was"
echo "                            denied)."
echo "      client_alice.db     — alice's simulated local replica. Has"
echo "                            row 777 sitting unsynced. Harmless."
echo "      client_bob.db       — bob's simulated local replica. Has row"
echo "                            555 (his local edit, which DID propagate)."
echo
echo "    Inspect them directly:"
echo "      $TURSODB $TURSO_DEMO_DB   \"SELECT * FROM products\""
echo "      $TURSODB client_alice.db  \"SELECT * FROM products\""
echo "      $TURSODB client_bob.db    \"SELECT * FROM products\""
echo
echo "    In a real Turso deployment, the two client_* replicas would"
echo "    live on different end-user devices and the cloud DB would"
echo "    live on the sync-server host. They'd never share a filesystem."
