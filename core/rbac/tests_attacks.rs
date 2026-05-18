//! Adversarial RBAC tests.
//!
//! Every test in this file plays the role of a hostile principal trying to do
//! something it shouldn't be able to do. The goal is breadth: each named
//! attack class gets at least one test that locks in the deny path, so a
//! refactor that accidentally re-opens the hole regresses here first.
//!
//! Tests are organised into groups by attack surface:
//!
//! - **write-grant-misuse**: a principal with a narrow write grant tries to
//!   escalate across columns, tables, ops, schema, PRAGMA, ATTACH, RBAC
//!   tables, sqlite_schema, etc.
//! - **empty-policy-tables**: what the engine does when the RBAC tables
//!   exist but are empty (the moment after bootstrap, the moment before
//!   TOFU promotion).
//! - **mode-transition**: connection state moves between Trusted ↔ Anonymous
//!   ↔ Authenticated and we assert the no-leakage property.
//! - **shape-bypass**: the same logical write expressed in three different
//!   SQL shapes (explicit cols, DEFAULT VALUES, INSERT SELECT) must all be
//!   gated identically.
//! - **predicate-misuse**: USING/CHECK predicate text tries to encode an
//!   escalation.
//! - **trigger-and-cascade**: indirect writes through triggers run under the
//!   firing principal, not the trigger author.

use std::collections::BTreeMap;

use crate::connection::{AuthMode, ConnectionAuthorizer, Principal};
use crate::io::MemoryIO;
use crate::rbac::{compile_row, GrantSet};
use crate::sync::Arc;
use crate::{Database, LimboError, IO};

use super::authorizer::RbacAuthorizer;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

fn open_db() -> Arc<Database> {
    let io: Arc<dyn IO> = Arc::new(MemoryIO::new());
    Database::open_file(io, ":memory:rbac-attacks").unwrap()
}

fn install(conn: &Arc<crate::Connection>, gs: GrantSet) {
    let auth: Arc<dyn ConnectionAuthorizer> = Arc::new(RbacAuthorizer::new(gs, false));
    conn.set_authorizer(auth);
}

fn principal(iss: &str, sub: &str, roles: &[&str]) -> Arc<Principal> {
    Arc::new(
        Principal::new(
            iss,
            sub,
            roles.iter().map(|s| s.to_string()).collect(),
            BTreeMap::new(),
            i64::MAX,
        )
        .unwrap(),
    )
}

type GrantRow<'a> = (
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
);

fn grants(rows: &[GrantRow<'_>]) -> GrantSet {
    let mut gs = GrantSet::default();
    for (kind, iss, grantee, table, op, cols, using, check) in rows {
        gs.push(
            compile_row(kind, iss, grantee, table, op, *cols, *using, *check)
                .expect("test grant compiles"),
        );
    }
    gs
}

/// Build the standard "alice has INSERT on foo(id,name) only" world.
/// Includes the RBAC bootstrap tables so the self-grant attack tests can
/// attempt to write into them (and get denied). Returns the connection
/// ready for `with_principal(alice)`.
fn alice_with_insert_only_on_foo() -> Arc<crate::Connection> {
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE foo (id INTEGER, name TEXT, secret TEXT)")
        .unwrap();
    conn.execute("CREATE TABLE other (x INTEGER)").unwrap();
    crate::rbac::apply_bootstrap(&conn).unwrap();
    let gs = grants(&[(
        "sub",
        "https://idp",
        "alice",
        "foo",
        "INSERT",
        Some(r#"["id", "name"]"#),
        None,
        None,
    )]);
    install(&conn, gs);
    conn.downgrade_to_anonymous();
    conn
}

/// Assert that `result` blocked the operation. We accept any error variant
/// because some attack vectors are blocked by pre-existing translate-layer
/// checks (e.g. sqlite_schema "table may not be modified") that fire BEFORE
/// the authorizer. The security property is "the write was blocked", not
/// "AuthorizationDenied specifically fired".
fn assert_blocked(result: crate::Result<()>, what: &str) {
    match result {
        Err(_) => {}
        Ok(()) => panic!("expected {what} to be blocked, but it succeeded"),
    }
}

fn alice() -> Arc<Principal> {
    principal("https://idp", "alice", &[])
}

fn admin() -> Arc<Principal> {
    principal("https://idp", "admin", &["admin"])
}

fn assert_denied(result: crate::Result<()>, what: &str) {
    match result {
        Err(LimboError::AuthorizationDenied(msg)) => {
            assert!(
                !msg.is_empty(),
                "denial for {what} must carry a reason string"
            );
        }
        Err(other) => panic!("expected AuthorizationDenied for {what}, got {other:?}"),
        Ok(()) => panic!("expected {what} to be denied, but it succeeded"),
    }
}

// ===========================================================================
// Group 1: write-grant-misuse
//
// "I have an INSERT grant on foo(id,name). What else can I do with it?"
// Answer: ONLY that. Everything below must deny.
// ===========================================================================

#[test]
fn write_token_cannot_insert_into_other_table() {
    // Alice has INSERT on `foo`. Inserting into `other` is a cross-table
    // escalation — no grant matches, default-deny fires.
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute("INSERT INTO other VALUES (42)"),
        "cross-table INSERT",
    );
}

#[test]
fn write_token_cannot_insert_into_ungranted_column() {
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute("INSERT INTO foo (id, name, secret) VALUES (1, 'a', 'leak')"),
        "INSERT into ungranted column",
    );
}

#[test]
fn write_token_cannot_update_target_table() {
    let conn = alice_with_insert_only_on_foo();
    {
        let _g = conn.with_principal(alice());
        conn.execute("INSERT INTO foo (id, name) VALUES (1, 'alice')")
            .unwrap();
    }
    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute("UPDATE foo SET name = 'eve' WHERE id = 1"),
        "UPDATE without grant",
    );
}

#[test]
fn write_token_cannot_delete_from_target_table() {
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute("DELETE FROM foo WHERE id = 1"),
        "DELETE without grant",
    );
}

#[test]
fn write_token_cannot_create_new_table() {
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute("CREATE TABLE smuggle (x INTEGER)"),
        "CREATE TABLE by non-admin",
    );
}

#[test]
fn write_token_cannot_drop_target_table() {
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_denied(conn.execute("DROP TABLE foo"), "DROP target table");
}

#[test]
fn write_token_cannot_alter_target_table() {
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute("ALTER TABLE foo ADD COLUMN backdoor TEXT"),
        "ALTER target table",
    );
}

#[test]
fn write_token_cannot_enable_dangerous_pragma() {
    // Threat #8: PRAGMA writable_schema is the lever that opens sqlite_schema
    // writes. It hard-denies for everyone running over the network.
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute("PRAGMA writable_schema = ON"),
        "dangerous PRAGMA",
    );
    assert_denied(
        conn.execute("PRAGMA legacy_alter_table = ON"),
        "dangerous PRAGMA (legacy_alter_table)",
    );
}

#[test]
fn write_token_cannot_disable_foreign_keys_pragma() {
    // Threat #9: PRAGMA foreign_keys is admin-only when active. A user with
    // a write grant on `foo` shouldn't be able to flip FK enforcement off
    // for the whole connection (would affect every other user too).
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute("PRAGMA foreign_keys = OFF"),
        "mutating PRAGMA by non-admin",
    );
}

#[test]
fn write_token_cannot_attach_database_to_smuggle_data() {
    // Threat #10: ATTACH lets you mount a database that has no grants table,
    // round-trip data through it, and bypass the entire RBAC layer.
    //
    // ATTACH is also gated by an `experimental_attach` flag that defaults
    // off, so for an unauthorized principal it gets blocked by EITHER the
    // experimental gate OR the RBAC ATTACH-admin-only gate. The security
    // property we care about is "blocked", not which gate fired first.
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_blocked(
        conn.execute("ATTACH ':memory:evil' AS evil"),
        "ATTACH by non-admin",
    );
}

#[test]
fn write_token_cannot_write_to_sqlite_schema_directly() {
    // Threat #8 belt-and-braces: sqlite_schema direct writes are denied. The
    // existing turso `allow_user_dml` check fires at parse time BEFORE our
    // hook, so the deny is a ParseError rather than AuthorizationDenied —
    // but the security property holds either way. The RBAC hard-deny is
    // belt-and-braces in case that check is ever loosened.
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_blocked(
        conn.execute("INSERT INTO sqlite_schema VALUES ('table', 'x', 'x', 2, 'CREATE TABLE x(a)')"),
        "INSERT into sqlite_schema",
    );
    assert_blocked(
        conn.execute("UPDATE sqlite_schema SET tbl_name = 'x' WHERE name = 'foo'"),
        "UPDATE sqlite_schema",
    );
    assert_blocked(
        conn.execute("DELETE FROM sqlite_schema WHERE name = 'foo'"),
        "DELETE from sqlite_schema",
    );
}

#[test]
fn write_token_cannot_self_grant_via_rbac_grants_insert() {
    // Threat #16: most blatant escalation — write a grant for yourself
    // straight into _turso_rbac_grants. Refused by the admin gate.
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute(
            "INSERT INTO _turso_rbac_grants \
             (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, \
              using_expr, check_expr, created_at) \
             VALUES ('sub', 'https://idp', 'alice', '*', '*', NULL, NULL, NULL, 0)",
        ),
        "self-INSERT into _turso_rbac_grants",
    );
}

#[test]
fn write_token_cannot_self_grant_admin_via_role_assignments() {
    // Same shape, different table: inserting `(iss, sub, 'admin')` into
    // _turso_rbac_role_assignments would make alice admin on her next
    // request. Admin gate refuses.
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute(
            "INSERT INTO _turso_rbac_role_assignments \
             VALUES ('https://idp', 'alice', 'admin', 0)",
        ),
        "self-grant admin role",
    );
}

#[test]
fn write_token_can_still_read_anything_documented_behavior() {
    // Reads are uncontrolled in the MVP. This test documents that behavior
    // so anyone tightening the security model can find this assertion and
    // flip it deliberately.
    let conn = alice_with_insert_only_on_foo();
    {
        // Pre-populate as the admin-equivalent (Trusted connection at this
        // point we've already downgraded; use a sibling).
        let boot = conn.database().connect().unwrap();
        boot.execute("INSERT INTO foo (id, name, secret) VALUES (1, 'a', 'leaked-from-disk')")
            .unwrap();
    }
    let _g = conn.with_principal(alice());
    let mut stmt = conn
        .prepare("SELECT id, name, secret FROM foo")
        .unwrap();
    let rows = stmt.run_collect_rows().unwrap();
    assert_eq!(rows.len(), 1, "SELECT must return the row regardless of grants");
}

#[test]
fn write_token_upsert_do_nothing_is_allowed() {
    // The UPSERT-as-UPDATE check fires only on DO UPDATE; DO NOTHING means
    // no UPDATE — the INSERT grant suffices. Verifies we're not
    // over-restrictive.
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    conn.execute(
        "INSERT INTO foo (id, name) VALUES (1, 'alice') ON CONFLICT DO NOTHING",
    )
    .unwrap();
}

#[test]
fn write_token_cannot_use_default_values_to_bypass_column_check() {
    // `INSERT INTO foo DEFAULT VALUES` touches every column. If alice only
    // has INSERT on (id, name) and `secret` exists, this must deny because
    // `secret` is in the touched set.
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute("INSERT INTO foo DEFAULT VALUES"),
        "DEFAULT VALUES bypass attempt",
    );
}

#[test]
fn write_token_cannot_use_no_col_list_insert_to_bypass_column_check() {
    // CDC-replay shape. Same logic as DEFAULT VALUES — the hook expands the
    // missing column list to the full schema, sees `secret`, denies.
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute("INSERT INTO foo VALUES (1, 'alice', 'leak')"),
        "no-col-list INSERT bypass attempt",
    );
}

#[test]
fn write_token_cannot_use_insert_select_to_bypass_column_check() {
    // INSERT INTO target(cols) SELECT ... — the INSERT side is authorized
    // against the target's columns. SELECT is open. Trying to write to
    // `secret` via INSERT SELECT must still hit the column denial.
    let conn = alice_with_insert_only_on_foo();
    // Add a source table to read from.
    {
        let boot = conn.database().connect().unwrap();
        boot.execute("CREATE TABLE src (v INTEGER)").unwrap();
        boot.execute("INSERT INTO src VALUES (1)").unwrap();
    }
    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute("INSERT INTO foo (id, name, secret) SELECT v, 'eve', 'leak' FROM src"),
        "INSERT SELECT bypass attempt",
    );
}

// ===========================================================================
// Group 2: empty-policy-tables
//
// "What if the RBAC tables exist but contain no rows?"
//
// Two distinct shapes:
//  (a) In-process: connection stays Trusted, no authorizer installed →
//      everything works. This is the embedded/CLI use case.
//  (b) Sync server: authorizer installed + downgraded → default-deny
//      for every write that isn't system-table-whitelisted.
// ===========================================================================

#[test]
fn empty_rbac_tables_in_process_trusted_can_do_everything() {
    // Direct answer to "if there is no user in the rbac table, can the user
    // still do everything they want locally?" — YES, in-process, because the
    // connection stays Trusted and `is_dormant()` returns true.
    let db = open_db();
    let conn = db.connect().unwrap();
    // Bring up the RBAC tables but never install an authorizer or downgrade.
    crate::rbac::apply_bootstrap(&conn).unwrap();
    // No grants. No role assignments. No authorizer. Connection is Trusted.
    assert!(crate::rbac::is_dormant(&conn));
    conn.execute("CREATE TABLE work (x INTEGER)").unwrap();
    conn.execute("INSERT INTO work VALUES (1)").unwrap();
    conn.execute("UPDATE work SET x = 2").unwrap();
    conn.execute("DELETE FROM work").unwrap();
    conn.execute("DROP TABLE work").unwrap();
    // Even dangerous PRAGMA succeeds locally — this is the CLI REPL contract.
    // (We don't actually toggle writable_schema here to keep the test
    // hermetic; the assertion is just that nothing in the authz path fired.)
}

#[test]
fn empty_grants_table_authenticated_default_denies_all_writes() {
    // Sync-server shape: tables bootstrapped, authorizer installed, no
    // grants. Every write must deny. This is the post-bootstrap / pre-TOFU
    // window — if TOFU is disabled the principal stays denied permanently.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE foo (x INTEGER)").unwrap();
    install(&conn, GrantSet::default());
    conn.downgrade_to_anonymous();

    let _g = conn.with_principal(alice());
    assert_denied(conn.execute("INSERT INTO foo VALUES (1)"), "INSERT");
    assert_denied(conn.execute("UPDATE foo SET x = 1"), "UPDATE");
    assert_denied(conn.execute("DELETE FROM foo"), "DELETE");
    assert_denied(conn.execute("CREATE TABLE y (a INTEGER)"), "DDL");
}

#[test]
fn empty_role_assignments_means_no_admin_role() {
    // Mode A: roles come from _turso_rbac_role_assignments. If the table is
    // empty, no principal is admin regardless of what their JWT claims say.
    // Principals constructed with `roles=[]` (the Mode A default) cannot
    // pass admin gates.
    let db = open_db();
    let conn = db.connect().unwrap();
    install(&conn, GrantSet::default());
    conn.downgrade_to_anonymous();

    // Principal has NO roles — even though they're called "admin", they
    // can't do DDL.
    let p = principal("https://idp", "admin", &[]);
    let _g = conn.with_principal(p);
    assert_denied(
        conn.execute("CREATE TABLE x (a INTEGER)"),
        "DDL by non-admin (Mode A)",
    );
}

#[test]
fn anonymous_writes_are_denied_even_to_whitelisted_tables() {
    // The system-table whitelist runs INSIDE the authorizer, which itself
    // is only reached for `Authenticated` principals. An Anonymous
    // connection short-circuits to Deny upstream of the whitelist.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE turso_sync_last_change_id (change_id INTEGER)")
        .unwrap();
    install(&conn, GrantSet::default());
    conn.downgrade_to_anonymous();
    // No with_principal — Anonymous.
    assert_denied(
        conn.execute("INSERT INTO turso_sync_last_change_id VALUES (1)"),
        "Anonymous INSERT into whitelisted table",
    );
}

// ===========================================================================
// Group 3: mode-transition
//
// State machine: Trusted → Anonymous → Authenticated(p) → Anonymous → ...
// We verify the no-leakage property at each edge.
// ===========================================================================

#[test]
fn principal_state_resets_to_anonymous_between_requests() {
    let conn = alice_with_insert_only_on_foo();

    // Request 1: alice does an allowed INSERT.
    {
        let _g = conn.with_principal(alice());
        conn.execute("INSERT INTO foo (id, name) VALUES (1, 'a')")
            .unwrap();
    }
    // Connection is back to Anonymous — no in-flight principal.
    assert!(matches!(conn.auth_mode_snapshot(), AuthMode::Anonymous));

    // Request 2: a different principal (bob) shows up. The previous request's
    // alice identity must not leak into bob's authz check.
    let bob = principal("https://idp", "bob", &[]);
    {
        let _g = conn.with_principal(bob);
        // Bob has no grants; even though alice could INSERT, bob can't.
        assert_denied(
            conn.execute("INSERT INTO foo (id, name) VALUES (2, 'b')"),
            "bob INSERT (alice's request must not leak)",
        );
    }
    assert!(matches!(conn.auth_mode_snapshot(), AuthMode::Anonymous));
}

#[test]
fn auto_commit_state_does_not_leak_across_principals() {
    // Threat #12: per-connection state pollution. If request N turned
    // auto_commit off and panicked, request N+1 must not still see it off.
    let conn = alice_with_insert_only_on_foo();
    let initial_auto = conn.get_auto_commit();

    {
        let _g = conn.with_principal(alice());
        // Simulate a request that modified state and then "panicked" by
        // exiting scope without explicit cleanup. We manually set the flag
        // here because driving a real panic across the Drop boundary would
        // make the test brittle on Windows.
        conn.auto_commit
            .store(false, crate::sync::atomic::Ordering::SeqCst);
    }
    // Guard dropped → state restored.
    assert_eq!(
        conn.get_auto_commit(),
        initial_auto,
        "auto_commit must restore to pre-request value on guard Drop"
    );
}

#[test]
fn set_authorizer_cannot_be_swapped() {
    // Threat #13: one-shot enforcement. Even if a malicious extension or
    // FFI consumer obtained a `&Connection`, they cannot swap out the
    // authorizer to install a more permissive one.
    let db = open_db();
    let conn = db.connect().unwrap();
    install(&conn, GrantSet::default());
    // A second install must panic — there's no `clear()` API and the
    // one-shot guard is enforced even from Trusted mode.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        install(&conn, GrantSet::default());
    }));
    assert!(
        result.is_err(),
        "second set_authorizer must panic (one-shot guarantee)"
    );
}

// ===========================================================================
// Group 4: shape-bypass
//
// The same logical "I want to write to column X" expressed through every
// SQL shape the parser accepts must be gated identically.
// ===========================================================================

#[test]
fn explicit_columns_default_values_and_no_col_list_all_gate_identically() {
    // All three shapes must deny on the ungranted `secret` column. Codified
    // here so future parser refactors that add a fourth shape (e.g. a
    // RETURNING extension that mutates) get tested too.
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());

    assert_denied(
        conn.execute("INSERT INTO foo (id, name, secret) VALUES (1, 'a', 'leak')"),
        "explicit columns",
    );
    assert_denied(
        conn.execute("INSERT INTO foo DEFAULT VALUES"),
        "DEFAULT VALUES",
    );
    assert_denied(
        conn.execute("INSERT INTO foo VALUES (1, 'a', 'leak')"),
        "no col list",
    );
}

// ===========================================================================
// Group 5: predicate-misuse
//
// The USING/CHECK predicate text is operator-authored, but the principal
// could try to provoke surprising behavior by crafting input rows.
// ===========================================================================

#[test]
fn using_predicate_filters_dont_grant_extra_columns() {
    // Alice has UPDATE on (status) only, USING owner_id = @principal.sub.
    // She tries to UPDATE `secret` (not in her column grant). The USING
    // narrows the row scope, but it does NOT widen the column scope —
    // column-coverage check denies.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute(
        "CREATE TABLE orders (id INTEGER, owner_id TEXT, status TEXT, secret TEXT)",
    )
    .unwrap();
    conn.execute("INSERT INTO orders VALUES (1, 'alice', 'pending', 's')")
        .unwrap();

    let gs = grants(&[(
        "sub",
        "https://idp",
        "alice",
        "orders",
        "UPDATE",
        Some(r#"["status"]"#),
        Some("owner_id = @principal.sub"),
        None,
    )]);
    install(&conn, gs);
    conn.downgrade_to_anonymous();

    let _g = conn.with_principal(alice());
    // Granted column → allowed.
    conn.execute("UPDATE orders SET status = 'shipped'").unwrap();
    // Ungranted column → denied even though the USING predicate matches.
    assert_denied(
        conn.execute("UPDATE orders SET secret = 'pwned'"),
        "UPDATE on ungranted column with matching USING",
    );
}

#[test]
fn using_predicate_does_not_let_alice_update_bobs_rows() {
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE orders (id INTEGER, owner_id TEXT, status TEXT)")
        .unwrap();
    conn.execute("INSERT INTO orders VALUES (1, 'alice', 'pending'), (2, 'bob', 'pending')")
        .unwrap();

    let gs = grants(&[(
        "sub",
        "https://idp",
        "alice",
        "orders",
        "UPDATE",
        None,
        Some("owner_id = @principal.sub"),
        None,
    )]);
    install(&conn, gs);
    conn.downgrade_to_anonymous();

    {
        let _g = conn.with_principal(alice());
        // Alice tries to update bob's row directly by id. USING narrows.
        conn.execute("UPDATE orders SET status = 'pwned' WHERE id = 2")
            .unwrap();
        // Statement runs, but the USING predicate (AND'd into WHERE) means
        // no rows match.
    }
    let _g = conn.with_principal(alice());
    let mut stmt = conn
        .prepare("SELECT id, status FROM orders WHERE id = 2")
        .unwrap();
    let rows = stmt.run_collect_rows().unwrap();
    let status = match &rows[0][1] {
        crate::Value::Text(t) => t.value.to_string(),
        _ => panic!(),
    };
    assert_eq!(
        status, "pending",
        "USING predicate must prevent alice from touching bob's row"
    );
}

// ===========================================================================
// Group 6: trigger-and-cascade
//
// Indirect writes through triggers must run under the *firing* principal —
// not the trigger author's principal. Otherwise an admin-defined trigger
// would effectively grant elevated privileges to anyone whose statement
// fires it.
// ===========================================================================

#[test]
fn trigger_inner_write_runs_under_firing_principal() {
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE public_log (msg TEXT)").unwrap();
    conn.execute("CREATE TABLE sensitive (x TEXT)").unwrap();
    conn.execute(
        "CREATE TRIGGER on_log_insert AFTER INSERT ON public_log \
         BEGIN INSERT INTO sensitive VALUES (NEW.msg); END",
    )
    .unwrap();

    // Alice has INSERT on `public_log` but NOT on `sensitive`. The trigger
    // body runs under alice's principal so its INSERT into `sensitive`
    // hits the deny path.
    let gs = grants(&[(
        "sub",
        "https://idp",
        "alice",
        "public_log",
        "INSERT",
        None,
        None,
        None,
    )]);
    install(&conn, gs);
    conn.downgrade_to_anonymous();

    let _g = conn.with_principal(alice());
    assert_denied(
        conn.execute("INSERT INTO public_log VALUES ('hi')"),
        "trigger writing to ungranted table",
    );
}

// ===========================================================================
// Group 7: system-table whitelist boundaries
//
// `turso_sync_*`/`_turso_*` are sync-engine bookkeeping. They're allowed for
// authenticated principals, but the boundary is exactly that — they must NOT
// be a bridge to RBAC table or sqlite_schema writes.
// ===========================================================================

#[test]
fn system_table_whitelist_does_not_cover_rbac_tables() {
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute(
        "CREATE TABLE _turso_rbac_grants (\
            id INTEGER PRIMARY KEY, grantee_kind TEXT, grantee_iss TEXT, \
            grantee TEXT, table_name TEXT, op TEXT, columns_json TEXT, \
            using_expr TEXT, check_expr TEXT, created_at INTEGER\
         )",
    )
    .unwrap();
    install(&conn, GrantSet::default());
    conn.downgrade_to_anonymous();

    let _g = conn.with_principal(alice());
    // Even though `_turso_rbac_grants` matches the `_turso_*` prefix,
    // the RBAC-table admin gate runs FIRST and denies non-admin writes.
    assert_denied(
        conn.execute(
            "INSERT INTO _turso_rbac_grants \
             (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, \
              using_expr, check_expr, created_at) \
             VALUES ('sub', 'https://idp', 'alice', '*', '*', NULL, NULL, NULL, 0)",
        ),
        "non-admin write to _turso_rbac_grants via prefix-match",
    );
}

#[test]
fn admin_can_modify_grants_table_data_but_not_schema() {
    // Admin gate lets data writes through; DDL gate denies schema mutation
    // even for admin. Two assertions in one because they share fixtures.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute(
        "CREATE TABLE _turso_rbac_grants (\
            id INTEGER PRIMARY KEY, grantee_kind TEXT, grantee_iss TEXT, \
            grantee TEXT, table_name TEXT, op TEXT, columns_json TEXT, \
            using_expr TEXT, check_expr TEXT, created_at INTEGER\
         )",
    )
    .unwrap();
    install(&conn, GrantSet::default());
    conn.downgrade_to_anonymous();

    let _g = conn.with_principal(admin());
    // Data write — succeeds.
    conn.execute(
        "INSERT INTO _turso_rbac_grants \
         (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, \
          using_expr, check_expr, created_at) \
         VALUES ('sub', 'https://idp', 'bob', 'orders', 'UPDATE', NULL, NULL, NULL, 0)",
    )
    .unwrap();
    // Schema mutation — denied even for admin.
    assert_denied(
        conn.execute("ALTER TABLE _turso_rbac_grants ADD COLUMN backdoor TEXT"),
        "ALTER on RBAC table even by admin",
    );
    assert_denied(
        conn.execute("DROP TABLE _turso_rbac_grants"),
        "DROP RBAC table even by admin",
    );
}

#[test]
fn turso_sync_writes_allowed_for_any_authenticated_principal() {
    // Closing the loop: non-RBAC sync internal tables ARE allowed because
    // every push batch writes to them. This is the system-table whitelist
    // working as intended.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE turso_sync_last_change_id (change_id INTEGER)")
        .unwrap();
    install(&conn, GrantSet::default());
    conn.downgrade_to_anonymous();

    let _g = conn.with_principal(alice());
    conn.execute("INSERT INTO turso_sync_last_change_id VALUES (1)")
        .unwrap();
}

// ===========================================================================
// Group 8: cross-issuer & role-source confusion
//
// Replays of the plan's threat table entries that aren't already covered
// in tests_integration.rs.
// ===========================================================================

#[test]
fn jwt_claim_named_principal_sub_does_not_collide_with_struct_sub() {
    // Threat #14: a malicious or buggy IdP that includes a claim literally
    // named "principal.sub" must not be reachable via the `@principal.sub`
    // placeholder. The two namespaces are disjoint by construction
    // (separate internal prefixes). The compile-time check in
    // predicates.rs rejects unknown @principal.* names, so this test
    // mostly documents the boundary at the JWT-claim level: even with a
    // hostile claim, the principal struct field wins.
    let mut hostile_claims = BTreeMap::new();
    hostile_claims.insert(
        "principal.sub".to_string(),
        crate::connection::ClaimValue::String("EVIL-VALUE".into()),
    );
    hostile_claims.insert(
        "sub".to_string(),
        crate::connection::ClaimValue::String("CLAIM-LEVEL-SUB".into()),
    );
    let p = Principal::new(
        "https://idp",
        "REAL-STRUCT-SUB",
        vec![],
        hostile_claims,
        i64::MAX,
    )
    .unwrap();
    // The compile_predicate path for `@principal.sub` resolves to the
    // struct field, NOT either claim entry. We verify by compiling and
    // substituting, then inspecting the resulting Expr.
    let mut compiled = crate::rbac::compile_predicate("@principal.sub").unwrap();
    crate::rbac::substitute_placeholders(&mut compiled.expr, &p);
    let s = match &compiled.expr {
        turso_parser::ast::Expr::Literal(turso_parser::ast::Literal::String(s)) => s.clone(),
        other => panic!("expected literal, got {other:?}"),
    };
    assert!(
        s.contains("REAL-STRUCT-SUB"),
        "@principal.sub must resolve to the struct sub, not any claim, got: {s}"
    );
    assert!(
        !s.contains("EVIL-VALUE") && !s.contains("CLAIM-LEVEL-SUB"),
        "@principal.sub must NOT resolve to a claim-level value, got: {s}"
    );
}

#[test]
fn role_grant_requires_principal_to_carry_the_role() {
    // Mode A enforcement at the matcher level: a JWT that came in with
    // `roles=[]` (because Mode A discards the claim) cannot use a
    // role-grant even if the role exists in the grant table.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE orders (id INTEGER)").unwrap();
    let gs = grants(&[(
        "role",
        "*",
        "editor",
        "orders",
        "INSERT",
        None,
        None,
        None,
    )]);
    install(&conn, gs);
    conn.downgrade_to_anonymous();

    // Principal has roles=[] (Mode A would have produced this even if the
    // JWT claimed "roles": ["editor"]).
    let p = principal("https://idp", "alice", &[]);
    let _g = conn.with_principal(p);
    assert_denied(
        conn.execute("INSERT INTO orders VALUES (1)"),
        "role grant should not match principal lacking the role",
    );
}

// ===========================================================================
// Group 9: AuthorizationDenied error shape
//
// Defense in depth: the error must always carry a non-empty message so a
// future log emitter can't accidentally produce a blank "Authorization
// denied:" line that obscures which rule fired.
// ===========================================================================

#[test]
fn every_deny_path_carries_a_reason_label() {
    // For deny paths that route through the RBAC authorizer (not the
    // pre-existing translate validators like sqlite_schema or
    // experimental_attach), the error must be `AuthorizationDenied` with a
    // non-empty message.
    let conn = alice_with_insert_only_on_foo();
    let _g = conn.with_principal(alice());

    for (sql, name) in [
        ("INSERT INTO other VALUES (1)", "cross-table"),
        ("UPDATE foo SET name = 'x'", "no-update-grant"),
        ("DELETE FROM foo", "no-delete-grant"),
        ("CREATE TABLE z (a INTEGER)", "ddl-non-admin"),
        ("PRAGMA writable_schema = ON", "dangerous-pragma"),
        ("PRAGMA foreign_keys = OFF", "mutating-pragma"),
    ] {
        match conn.execute(sql) {
            Err(LimboError::AuthorizationDenied(msg)) => {
                assert!(
                    msg.chars().any(|c| !c.is_whitespace()),
                    "{name}: empty deny message"
                );
            }
            other => panic!("{name}: expected AuthorizationDenied, got {other:?}"),
        }
    }
}
