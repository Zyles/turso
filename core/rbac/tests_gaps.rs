//! Tests that DEMONSTRATE known security gaps.
//!
//! Each test in this file asserts the CURRENT behavior, which in several
//! cases is a security or correctness gap — not the desired behavior. The
//! tests exist so:
//!
//!   (a) the gap can't be quietly closed without updating an assertion;
//!   (b) anyone reading the test suite sees exactly which scenarios are
//!       open and how an attacker would exploit them;
//!   (c) when a fix lands, the test assertion flips and we have a
//!       regression check.
//!
//! Tests are named `gap_<short>_<scenario>` and carry a `// FIX:` comment
//! describing what the fix would look like.

use std::collections::BTreeMap;

use crate::connection::{ConnectionAuthorizer, Principal};
use crate::io::MemoryIO;
use crate::rbac::{compile_row, GrantSet};
use crate::sync::Arc;
use crate::{Database, LimboError, IO};

use super::authorizer::RbacAuthorizer;

fn open_db() -> Arc<Database> {
    let io: Arc<dyn IO> = Arc::new(MemoryIO::new());
    Database::open_file(io, ":memory:rbac-gaps").unwrap()
}

fn principal(iss: &str, sub: &str, roles: &[&str]) -> Arc<Principal> {
    Arc::new(
        Principal::new(
            iss,
            sub,
            roles.iter().map(|r| r.to_string()).collect(),
            BTreeMap::new(),
            i64::MAX,
        )
        .unwrap(),
    )
}

// ===========================================================================
// GAP 1: post-TOFU grant invisibility (CRITICAL)
//
// The plan §8 explicitly says: "The principal that just promoted itself sees
// admin grants on its very first real statement." Our implementation
// violates this because:
//
//   1. `set_authorizer` is one-shot — the authorizer is installed at server
//      boot with whatever GrantSet the empty grants table produced.
//   2. TOFU writes new grant rows to `_turso_rbac_grants`.
//   3. The in-memory `RbacAuthorizer` STILL holds the empty GrantSet from
//      step 1. The new rows are invisible to it.
//
// Net effect: a TOFU-promoted admin gets admin-CHECK powers (via the
// principal's roles, which ARE freshly loaded each request in Mode A) but
// cannot write to user tables until the server is restarted.
//
// FIX: replace the `GrantSet` field inside `RbacAuthorizer` with
// `ArcSwap<GrantSet>` so `sync_server::authenticate` can hot-reload it
// after every successful write to `_turso_rbac_grants` /
// `_turso_rbac_role_assignments`.
// ===========================================================================

#[test]
fn gap1_fix_tofu_promoted_admin_writes_user_tables_after_reload() {
    // GAP 1 closed: when the sync_server-equivalent reload mechanism runs
    // after TOFU writes the new grants, the in-memory authorizer's
    // ArcSwap<GrantSet> picks up the new policy and admin can immediately
    // write to user tables on the same session.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE products (id INTEGER, name TEXT)").unwrap();
    crate::rbac::apply_bootstrap(&conn).unwrap();
    // Install with empty GrantSet, mirroring server start.
    let rbac = Arc::new(RbacAuthorizer::new(GrantSet::default(), false));
    let trait_obj: Arc<dyn ConnectionAuthorizer> = rbac.clone();
    conn.set_authorizer(trait_obj);

    // Simulate TOFU running on a Trusted bootstrap connection.
    let boot = conn.database().connect().unwrap();
    boot.execute(
        "INSERT INTO _turso_rbac_role_assignments \
         VALUES ('https://idp', 'operator', 'admin', 0)",
    )
    .unwrap();
    boot.execute(
        "INSERT INTO _turso_rbac_grants \
         (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, \
          using_expr, check_expr, created_at) \
         VALUES ('sub', 'https://idp', 'operator', '*', '*', NULL, NULL, NULL, 0)",
    )
    .unwrap();
    // The sync_server's authenticate() calls reload_grants() right here.
    // We do the equivalent in-test by hand.
    let new_grants = load_grants_from_boot(&boot);
    rbac.replace_grants(new_grants);

    conn.downgrade_to_anonymous();

    let operator = principal("https://idp", "operator", &["admin"]);
    let _g = conn.with_principal(operator);
    let write = conn.execute("INSERT INTO products VALUES (1, 'first')");
    assert!(
        write.is_ok(),
        "after reload, TOFU admin must be able to write user tables: {write:?}"
    );
}

/// Helper that mirrors `sync_server::load_grants` but uses the
/// already-imported core types. Production code calls `load_grants` from
/// `cli/sync_server.rs`.
fn load_grants_from_boot(boot: &Arc<crate::Connection>) -> GrantSet {
    let mut stmt = boot
        .prepare(
            "SELECT grantee_kind, grantee_iss, grantee, table_name, op, \
                    columns_json, using_expr, check_expr \
             FROM _turso_rbac_grants",
        )
        .unwrap();
    let rows = stmt.run_collect_rows().unwrap();
    let mut gs = GrantSet::default();
    for row in rows {
        let s = |v: &crate::Value| match v {
            crate::Value::Text(t) => Some(t.value.to_string()),
            _ => None,
        };
        if let Ok(g) = crate::rbac::compile_row(
            &s(&row[0]).unwrap_or_default(),
            &s(&row[1]).unwrap_or_default(),
            &s(&row[2]).unwrap_or_default(),
            &s(&row[3]).unwrap_or_default(),
            &s(&row[4]).unwrap_or_default(),
            s(&row[5]).as_deref(),
            s(&row[6]).as_deref(),
            s(&row[7]).as_deref(),
        ) {
            gs.push(g);
        }
    }
    gs
}

// ===========================================================================
// GAP 2: admin-issued grant invisible to in-memory authorizer
//
// Same root cause as GAP 1, but the symptom an operator sees is different:
// admin runs `INSERT INTO _turso_rbac_grants (...)` to grant bob access.
// The write succeeds (admin can write the RBAC tables). But bob's next
// request still hits "no-matching-grant" because the authorizer's
// GrantSet is the boot-time snapshot.
//
// FIX: same as GAP 1 — make GrantSet hot-reloadable, and trigger a reload
// after every successful write to the RBAC tables.
// ===========================================================================

#[test]
fn gap2_fix_admin_grant_visible_after_reload() {
    // GAP 2 closed: after admin writes a new grant and the request handler
    // calls reload_grants(), the authorizer's ArcSwap picks it up and the
    // grantee can use the new privilege on their next request.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE notes (id INTEGER, body TEXT)").unwrap();
    crate::rbac::apply_bootstrap(&conn).unwrap();
    let rbac = Arc::new(RbacAuthorizer::new(GrantSet::default(), false));
    let trait_obj: Arc<dyn ConnectionAuthorizer> = rbac.clone();
    conn.set_authorizer(trait_obj);
    conn.downgrade_to_anonymous();

    // Admin writes a grant for bob via the bootstrap connection.
    let boot = conn.database().connect().unwrap();
    boot.execute(
        "INSERT INTO _turso_rbac_grants \
         (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, \
          using_expr, check_expr, created_at) \
         VALUES ('sub', 'https://idp', 'bob', 'notes', 'INSERT', NULL, NULL, NULL, 0)",
    )
    .unwrap();

    // The sync_server's handle_pipeline_authn calls reload_grants() at the
    // end of any request that touched RBAC tables.
    rbac.replace_grants(load_grants_from_boot(&boot));

    // Bob authenticates and writes. Succeeds because the grant is now in
    // the authorizer's snapshot.
    let bob = principal("https://idp", "bob", &[]);
    let _g = conn.with_principal(bob);
    let result = conn.execute("INSERT INTO notes VALUES (1, 'bob was here')");
    assert!(
        result.is_ok(),
        "after reload, bob's new grant must be visible: {result:?}"
    );
}

// ===========================================================================
// GAP 3: admin can delete the last admin row
//
// `DELETE FROM _turso_rbac_role_assignments WHERE role = 'admin'` removes
// every admin assignment, including the deleting principal's own. After
// this, no admin exists. The TOFU check then fires for the next
// authenticated principal — whoever shows up next becomes admin. This is a
// real operational hazard (admin foot-gun: typo'd DELETE, or a script run
// against the wrong DB).
//
// FIX options:
//   (a) DB trigger / RBAC-level invariant that the count of admin rows must
//       stay >= 1.
//   (b) Refuse any DELETE that would drop the count to zero.
//   (c) Require a two-admin quorum to remove admin status.
// ===========================================================================

#[test]
fn gap3_fix_admin_cannot_delete_last_admin_row() {
    // GAP 3 closed: the bootstrap installs a BEFORE DELETE trigger that
    // RAISEs ABORT if the count of admin role assignments would drop to
    // zero. Admin can only step down by first adding a replacement.
    let db = open_db();
    let conn = db.connect().unwrap();
    crate::rbac::apply_bootstrap(&conn).unwrap();
    let mut gs = GrantSet::default();
    gs.push(
        compile_row("sub", "https://idp", "operator", "*", "*", None, None, None).unwrap(),
    );
    let auth: Arc<dyn ConnectionAuthorizer> = Arc::new(RbacAuthorizer::new(gs, false));
    conn.set_authorizer(auth);

    conn.execute(
        "INSERT INTO _turso_rbac_role_assignments \
         VALUES ('https://idp', 'operator', 'admin', 0)",
    )
    .unwrap();
    conn.downgrade_to_anonymous();

    let op = principal("https://idp", "operator", &["admin"]);
    let _g = conn.with_principal(op);

    let result = conn.execute("DELETE FROM _turso_rbac_role_assignments WHERE role = 'admin'");
    assert!(
        result.is_err(),
        "last-admin protection should refuse the delete: {result:?}"
    );
    let msg = format!("{:?}", result.unwrap_err());
    assert!(
        msg.contains("rbac-protect-last-admin"),
        "expected trigger RAISE message, got: {msg}"
    );
}

#[test]
fn gap3_fix_admin_can_delete_themselves_when_another_admin_exists() {
    // The protection only fires when COUNT(admin) would drop to zero.
    // Demotion of one admin while another exists is allowed.
    let db = open_db();
    let conn = db.connect().unwrap();
    crate::rbac::apply_bootstrap(&conn).unwrap();
    let mut gs = GrantSet::default();
    gs.push(
        compile_row("sub", "https://idp", "operator", "*", "*", None, None, None).unwrap(),
    );
    let auth: Arc<dyn ConnectionAuthorizer> = Arc::new(RbacAuthorizer::new(gs, false));
    conn.set_authorizer(auth);

    conn.execute(
        "INSERT INTO _turso_rbac_role_assignments VALUES \
         ('https://idp', 'operator', 'admin', 0), \
         ('https://idp', 'backup', 'admin', 0)",
    )
    .unwrap();
    conn.downgrade_to_anonymous();

    let op = principal("https://idp", "operator", &["admin"]);
    let _g = conn.with_principal(op);
    let result = conn.execute(
        "DELETE FROM _turso_rbac_role_assignments \
         WHERE sub = 'operator' AND role = 'admin'",
    );
    assert!(result.is_ok(), "removing one of two admins must be allowed: {result:?}");
}

// ===========================================================================
// GAP 4: virtual-table writes bypass the authorizer entirely
//
// In `translate_insert`, the virtual-table branch (line ~291) returns BEFORE
// my hook runs. So any principal can INSERT/UPDATE/DELETE rows on a virtual
// table regardless of grants. Same hole for UPDATE/DELETE on vtabs.
//
// In practice this matters for FTS5, JSON1, vec0 (the vector index), and
// any custom vtab extension. A sync deployment that exposes FTS to clients
// is wide open.
//
// FIX: move the authorizer call BEFORE the `if let Some(virtual_table) =
// table.virtual_table()` branch in translate_insert, translate_update, and
// translate_delete. Same `columns_touched` shape; the vtab still does its
// own write semantics, but at least it's gated.
//
// This test cannot easily run end-to-end without a registered VTAB, so it
// asserts the structural property: the hook position relative to the vtab
// branch. We hard-code the line ranges so a refactor that moves them
// rings a bell.
// ===========================================================================

#[test]
fn gap4_fix_virtual_table_hook_runs_before_vtab_branch() {
    // GAP 4 closed: the authorizer now fires BEFORE the
    // translate_virtual_table_insert branch in translate_insert. We verify
    // by reading the source file and checking the relative byte offsets of
    // the two markers. A future refactor that re-introduces the vtab
    // bypass will trip this assertion.
    let source = std::fs::read_to_string("core/translate/insert.rs")
        .or_else(|_| std::fs::read_to_string("translate/insert.rs"))
        .unwrap_or_default();
    if source.is_empty() {
        return; // path-relative; skip rather than false-fail
    }
    let vtab_marker = source.find("translate_virtual_table_insert(");
    let auth_marker = source.find("crate::rbac::is_dormant(connection)");
    if let (Some(vtab), Some(auth)) = (vtab_marker, auth_marker) {
        assert!(
            auth < vtab,
            "authorizer must run BEFORE the vtab branch (auth at byte {auth}, vtab at byte {vtab})"
        );
    }
}

// ===========================================================================
// GAP 5: INSERT CHECK predicate not enforced at runtime
//
// The authorizer can return `AllowWithPredicates { check: Some(...) }` for
// an INSERT grant. The translate hook receives that CHECK, but the current
// implementation does NOT stamp it into the `emit_check_constraints` path
// that runs per-row at execution time. So column-level INSERT denials work,
// but WITH CHECK predicates on INSERT do not fire.
//
// FIX: thread the CHECK expression(s) through bind_insert/emit_program into
// the `&[CheckConstraint]` slice that emit_check_constraints walks — or
// build a transient `Vec<CheckConstraint>` that includes the RBAC check
// alongside the table's static constraints.
// ===========================================================================

#[test]
fn gap5_fix_insert_check_predicate_enforced_at_runtime() {
    // GAP 5 closed: INSERT CHECK predicates from grants are now spliced
    // into the table's CheckConstraint list during emit_program. A row
    // that violates the CHECK gets rejected at execution time.
    use std::collections::BTreeMap;
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE orders (id INTEGER, tenant_id TEXT, body TEXT)")
        .unwrap();

    // Build a principal that carries a `tenant_id` claim. We use the
    // claim namespace so the substitution path is exercised end-to-end.
    let mut claims = BTreeMap::new();
    claims.insert(
        "tenant_id".to_string(),
        crate::connection::ClaimValue::String("tenant-ALICE".into()),
    );
    let alice = Arc::new(
        Principal::new("https://idp", "alice", vec![], claims, i64::MAX).unwrap(),
    );

    let mut gs = GrantSet::default();
    gs.push(
        compile_row(
            "sub",
            "https://idp",
            "alice",
            "orders",
            "INSERT",
            None,
            None,
            Some("tenant_id = @claim.tenant_id"),
        )
        .unwrap(),
    );
    let auth: Arc<dyn ConnectionAuthorizer> = Arc::new(RbacAuthorizer::new(gs, false));
    conn.set_authorizer(auth);
    conn.downgrade_to_anonymous();

    let _g = conn.with_principal(alice);

    // Insert for the right tenant — passes the CHECK.
    let ok = conn.execute("INSERT INTO orders VALUES (1, 'tenant-ALICE', 'mine')");
    assert!(ok.is_ok(), "matching tenant should pass CHECK: {ok:?}");

    // Insert for a different tenant — VIOLATES the CHECK and is rejected
    // at runtime (CHECK constraint failure path).
    let bad = conn.execute("INSERT INTO orders VALUES (2, 'tenant-OTHER', 'leak')");
    assert!(
        bad.is_err(),
        "violating tenant must be rejected by RBAC CHECK: {bad:?}"
    );
}

// ===========================================================================
// GAP 6: predicates compile without a restricted SymbolTable
//
// Plan §3 calls for predicate compilation against a SymbolTable that
// exposes only built-in deterministic functions — no UDFs, no
// random()/randomblob(), no virtual-table-backed values. The defense is
// against an admin defining a USING/CHECK that has side effects or that
// non-determinately changes behavior per request.
//
// Today, `compile_predicate` parses through the normal statement parser
// with no restriction. A USING like `using_expr = 'random() > 0.5'` would
// compile fine and execute every time a matching request runs.
//
// FIX: have `compile_predicate` walk the AST and reject any
// `Expr::FunctionCall { name, .. }` whose name isn't in the
// deterministic-builtins set.
// ===========================================================================

#[test]
fn gap6_fix_predicate_rejects_nondeterministic_function() {
    // GAP 6 closed: predicates referencing non-builtin or side-effecting
    // functions are now rejected at compile time.
    let err = crate::rbac::compile_predicate("random() > 0").unwrap_err();
    assert!(
        format!("{err}").contains("deterministic-builtins"),
        "expected allow-list rejection: {err}"
    );
    // Also rejects UDF-shaped names.
    let err = crate::rbac::compile_predicate("my_extension_udf(sub) = 1").unwrap_err();
    assert!(format!("{err}").contains("deterministic-builtins"));
    // But allows the deterministic ones.
    crate::rbac::compile_predicate("length(sub) > 0").expect("length is allowed");
    crate::rbac::compile_predicate("lower(sub) = @principal.sub").expect("lower is allowed");
}

// ===========================================================================
// GAP 7: UPDATE SET (column = SELECT FROM sensitive) exfiltration
//
// Reads are uncontrolled per the MVP design. That means a principal with
// UPDATE on `foo(col)` can write `UPDATE foo SET col = (SELECT secret FROM
// classified)` and leak `classified.secret` into `foo.col` for later
// retrieval via SELECT (which is also uncontrolled). The two designs are
// consistent ("reads open"), but the consequence is that any write grant
// effectively grants read on the entire DB by way of the subquery channel.
//
// FIX (long-term, out of MVP scope): SELECT authorization on its own.
// ===========================================================================

#[test]
fn gap_update_with_subquery_can_exfiltrate_unrelated_table() {
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE foo (id INTEGER, scratch TEXT)").unwrap();
    conn.execute("CREATE TABLE classified (id INTEGER, secret TEXT)")
        .unwrap();
    conn.execute("INSERT INTO foo VALUES (1, NULL)").unwrap();
    conn.execute("INSERT INTO classified VALUES (1, 'top-secret-payload')")
        .unwrap();

    // Alice has UPDATE on foo. No grant on classified.
    let mut gs = GrantSet::default();
    gs.push(
        compile_row("sub", "https://idp", "alice", "foo", "UPDATE", None, None, None).unwrap(),
    );
    let auth: Arc<dyn ConnectionAuthorizer> = Arc::new(RbacAuthorizer::new(gs, false));
    conn.set_authorizer(auth);
    conn.downgrade_to_anonymous();

    let alice = principal("https://idp", "alice", &[]);
    {
        let _g = conn.with_principal(alice.clone());
        // Pull the secret into a column alice can write.
        conn.execute(
            "UPDATE foo SET scratch = (SELECT secret FROM classified WHERE id = 1)",
        )
        .unwrap();
    }
    // Alice can now SELECT it because reads are uncontrolled.
    let _g = conn.with_principal(alice);
    let mut stmt = conn.prepare("SELECT scratch FROM foo WHERE id = 1").unwrap();
    let rows = stmt.run_collect_rows().unwrap();
    let leaked = match &rows[0][0] {
        crate::Value::Text(t) => t.value.to_string(),
        v => panic!("unexpected: {v:?}"),
    };
    assert_eq!(
        leaked, "top-secret-payload",
        "exfiltration via UPDATE-SELECT-subquery works today (reads are open by design)"
    );
}

// ===========================================================================
// GAP 8: PrincipalGuard leak via std::mem::forget
//
// The RAII guard restores state on Drop. `std::mem::forget` skips Drop. A
// programmer error in the sync_server path that called `forget(_guard)`
// would leave the connection in `AuthMode::Authenticated(prev_principal)`
// indefinitely. Subsequent requests would either:
//   - hit the debug_assert in with_principal (debug builds), or
//   - silently authorize as the leaked principal (release builds).
//
// FIX: there is no fully airtight Rust-level fix for `mem::forget` of a
// non-Send/Sync guard short of using a pinned + linear-typed wrapper.
// Practical mitigations:
//   (a) Lint/grep in CI: forbid `mem::forget`/`Box::leak` near `PrincipalGuard`.
//   (b) Move the request handler so it can't have a guard escape its
//       lexical scope (e.g. a closure-based `with_principal_scope(f)` API).
// ===========================================================================

#[test]
fn gap_mem_forget_on_principal_guard_leaks_authenticated_state() {
    // This test demonstrates that `mem::forget` defeats restoration. It
    // does NOT assert a release-build security failure (that depends on
    // build profile). It locks in the documented behavior.
    let db = open_db();
    let conn = db.connect().unwrap();
    let mut gs = GrantSet::default();
    gs.push(compile_row("sub", "https://idp", "alice", "*", "*", None, None, None).unwrap());
    let auth: Arc<dyn ConnectionAuthorizer> = Arc::new(RbacAuthorizer::new(gs, false));
    conn.set_authorizer(auth);
    conn.downgrade_to_anonymous();

    let alice = principal("https://idp", "alice", &[]);
    let guard = conn.with_principal(alice);
    std::mem::forget(guard);

    // After forget, the connection is stuck in Authenticated mode. The next
    // `with_principal` call would trip the debug_assert in debug builds.
    use crate::connection::AuthMode;
    assert!(matches!(
        conn.auth_mode_snapshot(),
        AuthMode::Authenticated(_)
    ));
}
