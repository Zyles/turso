#!/usr/bin/env bash
# Scenario 1: TOFU bootstrap.
#
# The grants table is empty when the server starts. The first principal who
# successfully authenticates is atomically promoted to `admin` (an INSERT
# into _turso_rbac_role_assignments + a matching (sub, *, *) sub grant in
# _turso_rbac_grants). Every subsequent principal sees the admin row and
# default-denies until that admin issues them privileges.
#
# Verifies plan §8: "The principal that just promoted itself sees admin
# grants on its very first real statement."
set -euo pipefail
cd "$(dirname "$0")/.."
source setup.env
source jwt.sh
source pipeline.sh

echo
echo "═══ Scenario 1: TOFU bootstrap ═══"
echo "Operator presents the first JWT the server has ever seen."

operator_token=$(mint_jwt "operator")

# A DDL statement is the cheapest way to prove the operator has admin-CHECK
# powers immediately after TOFU. If reload_grants() ran correctly, this
# CREATE TABLE succeeds; if the in-memory authorizer is stale (the old GAP
# 1 behavior), it would fail with "ddl-requires-admin" because the role
# assignment exists in the DB but not in the authorizer's snapshot.
echo
echo "─── operator creates the products table (admin-only DDL)"
pipeline "$operator_token" \
    "CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price INTEGER, owner_id TEXT)" \
    >/dev/null

echo
echo "─── operator creates the user_profile table"
pipeline "$operator_token" \
    "CREATE TABLE user_profile (id INTEGER PRIMARY KEY, sub TEXT, email TEXT, prefs TEXT)" \
    >/dev/null

echo
echo "─── operator INSERTs seed data (covered by their (sub, *, *) grant)"
pipeline "$operator_token" \
    "INSERT INTO products (id, name, price, owner_id) VALUES (1, 'Widget', 100, 'alice'), (2, 'Gadget', 200, 'bob')" \
    >/dev/null
pipeline "$operator_token" \
    "INSERT INTO user_profile (id, sub, email, prefs) VALUES (1, 'alice', 'alice@x', '{}'), (2, 'bob', 'bob@x', '{}')" \
    >/dev/null

echo
echo "✓ operator is admin and can DDL + write user tables."
