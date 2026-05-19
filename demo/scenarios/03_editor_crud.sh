#!/usr/bin/env bash
# Scenario 3: editor (bob) does CRUD on products.
#
# Each operation must succeed because bob's editor role grants
# INSERT/UPDATE/DELETE on products. The Mode A role lookup populates
# principal.roles=["editor"] from the role_assignments table at auth time;
# the in-memory GrantSet (reloaded after scenario 2) has the three grants.
set -euo pipefail
cd "$(dirname "$0")/.."
source setup.env
source jwt.sh
source pipeline.sh

echo
echo "═══ Scenario 3: editor (bob) CRUD on products ═══"

bob=$(mint_jwt "bob")

echo
echo "─── editor INSERT product"
pipeline "$bob" \
    "INSERT INTO products (id, name, price, owner_id) VALUES (3, 'Sprocket', 50, 'bob')" \
    >/dev/null

echo
echo "─── editor UPDATE product"
pipeline "$bob" \
    "UPDATE products SET price = 75 WHERE id = 3" \
    >/dev/null

echo
echo "─── editor DELETE product"
pipeline "$bob" \
    "DELETE FROM products WHERE id = 3" \
    >/dev/null

echo
echo "─── editor SELECT (reads are uncontrolled in MVP)"
pipeline "$bob" \
    "SELECT id, name, price FROM products" \
    >/dev/null

echo
echo "✓ editor can fully manage products."
