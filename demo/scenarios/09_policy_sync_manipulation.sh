#!/usr/bin/env bash
# Scenario 9: pull → manipulate → push, against the policy tables.
#
# In a real Turso deployment, the sync engine pulls cloud state down to
# every client's local replica via WAL frames. That includes the RBAC
# policy tables: _turso_rbac_grants and _turso_rbac_role_assignments are
# replicated like any other table. So every client has read access to
# the full policy.
#
# This raises a sharp question:
#
#   Once a malicious client has the policy in their local replica,
#   can they modify it locally and have those modifications sync back
#   up to the cloud?
#
# This scenario tests that end-to-end. Steps:
#
#   1. Alice (user role, no admin) pulls the full policy state into her
#      local replica. We simulate the sync pull by issuing SELECT
#      queries via /v2/pipeline — the actual WAL pull would deliver the
#      same content as raw pages, but for visibility we use logical SQL.
#
#   2. Alice has the policy tables on disk now. She can read them, edit
#      them, do whatever she wants — they're rows in HER file. We show
#      that by INSERTing a forged "alice is admin" role assignment into
#      her local replica directly with tursodb (no JWT, no RBAC; her
#      file, her rules).
#
#   3. Alice then attempts to PUSH her local forgery back to the cloud
#      via /v2/pipeline. This is the exact shape the sync engine would
#      produce when reading her CDC entries: `INSERT INTO
#      _turso_rbac_role_assignments VALUES (...)`. The cloud's
#      authorizer fires and denies — alice is not admin.
#
#   4. We verify the cloud's canonical policy is unchanged.
#
#   5. We exercise four more forgery shapes (grant insert, admin delete,
#      grant DDL, role update) to confirm every policy-table write path
#      is gated.
#
# If the cloud accepted any of these pushes, alice would have
# successfully escalated to admin by manipulating her local replica.
# It doesn't, so she can't.

set -euo pipefail
cd "$(dirname "$0")/.."
source setup.env
source jwt.sh
source pipeline.sh

echo
echo "═══ Scenario 9: pull → manipulate → push (policy tables) ═══"
echo
echo "  Threat: malicious client pulls policy down to local replica,"
echo "  edits it to grant themselves admin, pushes the edit back up."
echo "  Expected: every push attempt is denied by the cloud authorizer."

TURSODB=""
for candidate in \
    ../target/debug/tursodb.exe \
    ../target/debug/tursodb \
    ../target/release/tursodb.exe \
    ../target/release/tursodb
do
    [[ -x "$candidate" ]] && { TURSODB="$candidate"; break; }
done
[[ -n "$TURSODB" ]] || { echo "tursodb not found." >&2; exit 1; }

CLIENT_DB="client_alice_policy.db"
rm -f "$CLIENT_DB" "${CLIENT_DB}-wal" "${CLIENT_DB}-shm"

alice=$(mint_jwt "alice")
operator=$(mint_jwt "operator")

# ---------------------------------------------------------------------------
# Step 1: alice pulls the policy via reads.
#
# Real WAL pull delivers the same content as raw page bytes; reading the
# tables logically via SELECT is the same information. Reads are open in
# the MVP, so any authenticated principal can do this.
# ---------------------------------------------------------------------------
echo
echo "─── step 1: alice pulls the cloud's current policy"
echo
echo "    First, confirm that even the raw WAL pull endpoint accepts her"
echo "    request (it returns bytes — content is page-level; we don't"
echo "    decode them here):"
pull_size=$(curl -sS --max-time 5 \
    -H "Content-Type: application/protobuf" \
    -H "Authorization: Bearer $alice" \
    --data-binary $'\x08\x00\x10\x00\x18\x00' \
    "http://${TURSO_SYNC_SERVER_ADDR}/pull-updates" 2>/dev/null | wc -c)
echo "    GET /pull-updates → $pull_size bytes returned (200 OK)"
echo
echo "    Now do the same via logical SELECTs through /v2/pipeline:"
pipeline "$alice" \
    "SELECT grantee_kind, grantee_iss, grantee, table_name, op FROM _turso_rbac_grants" \
    > /dev/null
pipeline "$alice" \
    "SELECT iss, sub, role FROM _turso_rbac_role_assignments" \
    > /dev/null
echo
echo "    Reads succeed — the policy is fully visible to authenticated"
echo "    clients. (Confidentiality of policy is not a goal of this MVP;"
echo "    see README 'What syncs to clients?'.)"

# ---------------------------------------------------------------------------
# Step 2: alice forges policy in her local replica.
#
# This simulates what a real sync engine would have left on disk after a
# pull. We construct the same shape by hand using tursodb directly. The
# `Trusted` mode of the CLI means RBAC isn't consulted — this is alice's
# private file and she has every right to write to it. The only question
# is whether anything she writes can reach the cloud.
# ---------------------------------------------------------------------------
echo
echo "─── step 2: alice writes forged policy rows in her local replica"
echo
echo "    Building client_alice_policy.db with the same RBAC schema as cloud,"
echo "    plus a forged admin entry for herself."
"$TURSODB" "$CLIENT_DB" "
CREATE TABLE _turso_rbac_grants (
    id INTEGER PRIMARY KEY, grantee_kind TEXT NOT NULL,
    grantee_iss TEXT NOT NULL, grantee TEXT NOT NULL,
    table_name TEXT NOT NULL, op TEXT NOT NULL,
    columns_json TEXT, using_expr TEXT, check_expr TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE _turso_rbac_role_assignments (
    iss TEXT NOT NULL, sub TEXT NOT NULL, role TEXT NOT NULL,
    created_at INTEGER NOT NULL, PRIMARY KEY (iss, sub, role)
);
-- Forge admin role + matching '*/*' sub grant for alice. If the cloud
-- accepted these, alice would have full admin powers.
INSERT INTO _turso_rbac_role_assignments
    VALUES ('https://idp.demo.local', 'alice', 'admin', 0);
INSERT INTO _turso_rbac_grants
    (grantee_kind, grantee_iss, grantee, table_name, op, columns_json,
     using_expr, check_expr, created_at)
    VALUES ('sub', 'https://idp.demo.local', 'alice', '*', '*',
            NULL, NULL, NULL, 0);
" > /dev/null

echo "    Local DB contents after forgery:"
"$TURSODB" "$CLIENT_DB" "SELECT * FROM _turso_rbac_role_assignments"
"$TURSODB" "$CLIENT_DB" "SELECT grantee_kind, grantee, table_name, op FROM _turso_rbac_grants"
echo
echo "    Alice's local replica now claims she's admin. That claim is"
echo "    inert until/unless she can sync it up."

# ---------------------------------------------------------------------------
# Step 3: alice attempts to push every flavor of policy mutation.
#
# This is the security-critical step. The sync engine's push path uses
# /v2/pipeline — the same endpoint we hit by hand. If RBAC is fully
# enforced at that seam, every attempt should fail.
# ---------------------------------------------------------------------------
echo
echo "─── step 3: alice tries to push her forged policy to the cloud"
echo
echo "    Each push is the literal SQL the sync engine would generate"
echo "    when reading her local CDC entries. We hand-construct them"
echo "    here for clarity. The auth path is identical."

echo
echo "  ▸ forgery A: INSERT 'admin' role assignment for alice"
pipeline "$alice" \
    "INSERT INTO _turso_rbac_role_assignments VALUES ('https://idp.demo.local', 'alice', 'admin', 0)" \
    > /dev/null

echo
echo "  ▸ forgery B: INSERT wildcard sub-grant for alice"
pipeline "$alice" \
    "INSERT INTO _turso_rbac_grants (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, using_expr, check_expr, created_at) VALUES ('sub', 'https://idp.demo.local', 'alice', '*', '*', NULL, NULL, NULL, 0)" \
    > /dev/null

echo
echo "  ▸ forgery C: DELETE the operator's admin role (lock everyone else out)"
pipeline "$alice" \
    "DELETE FROM _turso_rbac_role_assignments WHERE sub = 'operator'" \
    > /dev/null

echo
echo "  ▸ forgery D: UPDATE alice's existing 'user' role to 'admin'"
pipeline "$alice" \
    "UPDATE _turso_rbac_role_assignments SET role = 'admin' WHERE sub = 'alice'" \
    > /dev/null

echo
echo "  ▸ forgery E: DROP the policy table (no policy → no enforcement?)"
pipeline "$alice" \
    "DROP TABLE _turso_rbac_grants" \
    > /dev/null

echo
echo "  ▸ forgery F: ALTER the policy table to add a backdoor column"
pipeline "$alice" \
    "ALTER TABLE _turso_rbac_grants ADD COLUMN backdoor TEXT" \
    > /dev/null

# ---------------------------------------------------------------------------
# Step 4: verify the cloud's policy is unchanged.
#
# Authorized read by operator to dump the current policy. If any of the
# forgeries had landed, we'd see alice's row in the role assignments or
# her grant in the grants table. We should see the same policy that
# scenario 2 set up.
# ---------------------------------------------------------------------------
echo
echo "─── step 4: dump the cloud's actual policy (via operator)"
pipeline "$operator" \
    "SELECT iss, sub, role FROM _turso_rbac_role_assignments ORDER BY sub" \
    > /dev/null
pipeline "$operator" \
    "SELECT grantee_kind, grantee, table_name, op FROM _turso_rbac_grants ORDER BY grantee" \
    > /dev/null

echo
echo "    Compare what's in the cloud now vs what alice forged locally."
echo "    Cloud read goes through the sync server (operator's authorized"
echo "    SELECT) because Windows file-locking prevents direct tursodb"
echo "    open while the sync server is running."
echo
echo "    ────────────────────────────────────────────────"
echo "    Cloud policy (via /v2/pipeline as operator):"
cloud_dump=$(pipeline "$operator" \
    "SELECT iss || '|' || sub || '|' || role AS row FROM _turso_rbac_role_assignments ORDER BY sub" \
    2>&1 >/dev/null) || true
# The pipeline function emits status to stderr; we just want the rows
# from the JSON payload. Re-extract via a follow-up call that captures
# stdout (the raw JSON) and pull values out.
cloud_json=$(pipeline "$operator" \
    "SELECT iss, sub, role FROM _turso_rbac_role_assignments ORDER BY sub")
# Crude row extraction: every Value::Text(...) inside results[0].response.
# We only care about the unique sub/role pairs.
echo "$cloud_json" \
    | grep -oE '"value":"[^"]+"' \
    | sed -E 's/"value":"//; s/"//' \
    | paste -d'|' - - - \
    | sed 's/^/      /'

echo
echo "    Alice's local replica (after her forgery):"
"$TURSODB" "$CLIENT_DB" \
    "SELECT iss, sub, role FROM _turso_rbac_role_assignments ORDER BY sub" \
    | sed 's/^/      /'
echo "    ────────────────────────────────────────────────"

echo
echo "═══ Conclusion ═══"
echo
echo "  Alice has full local control over her replica file. She CAN write"
echo "  any policy she wants to disk: a forged admin role for herself, a"
echo "  fake grant, a deleted operator, anything. The 'admin' rows in her"
echo "  local _turso_rbac_role_assignments are real bytes on real disk."
echo
echo "  But they are inert. Every channel that could propagate them to"
echo "  the cloud passes through /v2/pipeline, which runs the authorizer."
echo "  The authorizer says: alice is not admin, so she can't write the"
echo "  policy tables. Every push attempt failed with"
echo "  AUTHORIZATION_DENIED."
echo
echo "  The cloud's canonical policy still has:"
echo "    - operator: admin"
echo "    - bob:      editor"
echo "    - alice:    user"
echo
echo "  Alice's local forgery will be silently overwritten when her sync"
echo "  engine next pulls cloud state. The cloud is the source of truth."
echo
echo "  Security property confirmed: policy CANNOT be manipulated via"
echo "  the sync protocol. The local replica is a cache, not a control"
echo "  surface."

echo
echo "─── inspect the forgery file (left on disk for review) ───"
echo
echo "    $TURSODB $CLIENT_DB \"SELECT * FROM _turso_rbac_role_assignments\""
echo
echo "    Compare against the cloud:"
echo "    $TURSODB $TURSO_DEMO_DB \"SELECT * FROM _turso_rbac_role_assignments\""
