#!/usr/bin/env bash
# Scenario 4: editor (bob) tries to escalate privileges. EVERY attempt
# must surface as AUTHORIZATION_DENIED (or an equivalent block).
#
# This is the security-critical scenario: it directly answers
# "what can an editor token do that they shouldn't?"
set -euo pipefail
cd "$(dirname "$0")/.."
source setup.env
source jwt.sh
source pipeline.sh

echo
echo "═══ Scenario 4: editor escalation attempts (all must DENY) ═══"

bob=$(mint_jwt "bob")

echo
echo "─── editor tries DDL (admin-only)"
pipeline "$bob" "CREATE TABLE shadow (x INTEGER)" >/dev/null

echo
echo "─── editor tries DROP TABLE on the products table they CAN write to"
pipeline "$bob" "DROP TABLE products" >/dev/null

echo
echo "─── editor tries ALTER TABLE products ADD COLUMN backdoor"
pipeline "$bob" "ALTER TABLE products ADD COLUMN backdoor TEXT" >/dev/null

echo
echo "─── editor tries self-grant admin via role assignments"
pipeline "$bob" \
    "INSERT INTO _turso_rbac_role_assignments VALUES ('https://idp.demo.local', 'bob', 'admin', 0)" \
    >/dev/null

echo
echo "─── editor tries to write into _turso_rbac_grants directly"
pipeline "$bob" \
    "INSERT INTO _turso_rbac_grants (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, using_expr, check_expr, created_at) VALUES ('sub', 'https://idp.demo.local', 'bob', '*', '*', NULL, NULL, NULL, 0)" \
    >/dev/null

echo
echo "─── editor tries dangerous PRAGMA (writable_schema)"
pipeline "$bob" "PRAGMA writable_schema = ON" >/dev/null

echo
echo "─── editor tries PRAGMA foreign_keys = OFF"
pipeline "$bob" "PRAGMA foreign_keys = OFF" >/dev/null

echo
echo "─── editor tries direct UPDATE on sqlite_schema"
pipeline "$bob" \
    "UPDATE sqlite_schema SET tbl_name = 'pwned' WHERE name = 'products'" \
    >/dev/null

echo
echo "─── editor tries INSERT into user_profile (out of scope)"
pipeline "$bob" \
    "INSERT INTO user_profile (id, sub, email, prefs) VALUES (99, 'forged', 'x', '{}')" \
    >/dev/null

echo
echo "─── editor tries to UPDATE user_profile (out of scope)"
pipeline "$bob" \
    "UPDATE user_profile SET email = 'pwned' WHERE id = 1" \
    >/dev/null

echo
echo "✓ every escalation attempt blocked. Editor stays editor."
