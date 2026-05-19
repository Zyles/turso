#!/usr/bin/env bash
# Scenario 2: admin grants roles to bob (editor) and alice (user).
#
# Demonstrates the hot-reload fix (GAP 1+2): immediately after the admin's
# request that writes _turso_rbac_grants / _turso_rbac_role_assignments,
# the server's handle_pipeline_authn calls reload_grants() so the new
# policy is visible to the NEXT request without restart.
set -euo pipefail
cd "$(dirname "$0")/.."
source setup.env
source jwt.sh
source pipeline.sh

echo
echo "═══ Scenario 2: admin issues grants & role assignments ═══"

operator_token=$(mint_jwt "operator")

echo
echo "─── grant editor role to bob"
pipeline "$operator_token" \
    "INSERT INTO _turso_rbac_role_assignments VALUES ('https://idp.demo.local', 'bob', 'editor', 0)" \
    >/dev/null

echo
echo "─── grant editor INSERT/UPDATE/DELETE on products (all columns)"
pipeline "$operator_token" \
    "INSERT INTO _turso_rbac_grants (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, using_expr, check_expr, created_at) VALUES ('role', '*', 'editor', 'products', 'INSERT', NULL, NULL, NULL, 0)" \
    >/dev/null
pipeline "$operator_token" \
    "INSERT INTO _turso_rbac_grants (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, using_expr, check_expr, created_at) VALUES ('role', '*', 'editor', 'products', 'UPDATE', NULL, NULL, NULL, 0)" \
    >/dev/null
pipeline "$operator_token" \
    "INSERT INTO _turso_rbac_grants (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, using_expr, check_expr, created_at) VALUES ('role', '*', 'editor', 'products', 'DELETE', NULL, NULL, NULL, 0)" \
    >/dev/null

echo
echo "─── grant user role to alice"
pipeline "$operator_token" \
    "INSERT INTO _turso_rbac_role_assignments VALUES ('https://idp.demo.local', 'alice', 'user', 0)" \
    >/dev/null

echo
echo "─── grant user UPDATE on user_profile with RLS USING sub = @principal.sub"
# The USING predicate is what scopes alice's updates to her own row only.
pipeline "$operator_token" \
    "INSERT INTO _turso_rbac_grants (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, using_expr, check_expr, created_at) VALUES ('role', '*', 'user', 'user_profile', 'UPDATE', NULL, 'sub = @principal.sub', NULL, 0)" \
    >/dev/null

echo
echo "✓ bob is editor on products. alice is user on her own row of user_profile."
