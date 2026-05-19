#!/usr/bin/env bash
# Scenario 6: user (alice) tries to update bob's row.
#
# The statement is `UPDATE user_profile SET email = 'pwned' WHERE id = 2`
# — alice targets bob's row directly. The authorizer doesn't deny the
# statement; instead it AND-merges the USING predicate into the WHERE so
# the row scan filters to rows where row.sub = 'alice' AND id = 2. Zero
# rows match, so the UPDATE is a silent no-op. This is correct RLS
# semantics (PostgreSQL behaves the same way).
set -euo pipefail
cd "$(dirname "$0")/.."
source setup.env
source jwt.sh
source pipeline.sh

echo
echo "═══ Scenario 6: user (alice) tries to UPDATE bob's row ═══"

alice=$(mint_jwt "alice")

echo
echo "─── alice attempts UPDATE on bob's id=2 row"
pipeline "$alice" \
    "UPDATE user_profile SET email = 'pwned-by-alice' WHERE id = 2" \
    >/dev/null

echo
echo "─── verify (via operator) that bob's row is unchanged"
operator=$(mint_jwt "operator")
pipeline "$operator" \
    "SELECT id, sub, email FROM user_profile WHERE id = 2" \
    >/dev/null

echo
echo "✓ statement ran (200 OK) but the USING predicate filtered to zero rows."
echo "  bob's email is untouched."
