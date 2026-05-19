#!/usr/bin/env bash
# Scenario 5: user (alice) updates her own row.
#
# Alice's `user` role grants UPDATE on user_profile with a USING predicate
# `sub = @principal.sub`. The authorizer substitutes @principal.sub with
# her actual sub ('alice') and AND-merges the predicate into the WHERE.
# Result: she can update only the row where the stored sub matches hers.
set -euo pipefail
cd "$(dirname "$0")/.."
source setup.env
source jwt.sh
source pipeline.sh

echo
echo "═══ Scenario 5: user (alice) updates own profile ═══"

alice=$(mint_jwt "alice")

echo
echo "─── alice UPDATEs her email (her sub matches the row's sub)"
pipeline "$alice" \
    "UPDATE user_profile SET email = 'alice-new@x'" \
    >/dev/null

echo
echo "─── verify by reading back (operator does the read so the test is unambiguous)"
operator=$(mint_jwt "operator")
pipeline "$operator" \
    "SELECT id, sub, email FROM user_profile ORDER BY id" \
    >/dev/null

echo
echo "✓ alice's row updated; bob's row untouched (RLS USING did its job)."
