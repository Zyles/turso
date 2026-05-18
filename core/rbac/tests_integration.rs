//! End-to-end RBAC integration tests.
//!
//! These tests drive real SQL through the translate-layer hooks. They exist
//! to lock in the security-critical behaviour described in the plan's threat
//! table — denials must fire on the column/op/predicate boundaries that
//! callers are documented to depend on, and reads must remain untouched.
//!
//! Pattern: each test opens an in-memory DB, installs a custom
//! `RbacAuthorizer` populated with hand-built grants, downgrades the shared
//! connection to `Anonymous`, then wraps SQL in a `with_principal` scope
//! and asserts on the resulting `LimboError::AuthorizationDenied` or
//! `Ok`. Anything that flows through these tests therefore also flows
//! through the production code path — `rbac::authorize` + the translate
//! hooks — so a regression in the hook wiring will surface here first.

use std::collections::BTreeMap;

use crate::connection::{AuthMode, ConnectionAuthorizer, Principal};
use crate::io::MemoryIO;
use crate::rbac::{compile_row, GrantSet};
use crate::sync::Arc;
use crate::{Database, LimboError, IO};

use super::authorizer::RbacAuthorizer;

fn open_db() -> Arc<Database> {
    let io: Arc<dyn IO> = Arc::new(MemoryIO::new());
    Database::open_file(io, ":memory:rbac-it").unwrap()
}

fn install_authorizer(conn: &Arc<crate::Connection>, grant_set: GrantSet) {
    let auth: Arc<dyn ConnectionAuthorizer> = Arc::new(RbacAuthorizer::new(grant_set, false));
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

/// Compact (kind, iss, grantee, table, op, columns_json|None, using|None,
/// check|None) tuple used to build test grant tables row-by-row.
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

#[test]
fn anonymous_connection_denies_insert() {
    // Anonymous mode means "authenticated but no principal was attached".
    // We install an authorizer with no grants and downgrade; an INSERT
    // attempted under Anonymous mode (no with_principal scope) must fail
    // at the translate hook with AuthorizationDenied.
    let db = open_db();
    let conn = db.connect().unwrap();
    // Set up the table while still Trusted (default).
    conn.execute("CREATE TABLE foo (id INTEGER, name TEXT)")
        .unwrap();
    install_authorizer(&conn, GrantSet::default());
    conn.downgrade_to_anonymous();

    // No with_principal — connection is Anonymous. Translate hook denies.
    let err = conn
        .execute("INSERT INTO foo VALUES (1, 'alice')")
        .unwrap_err();
    assert!(
        matches!(err, LimboError::AuthorizationDenied(_)),
        "anonymous INSERT should be denied: got {err:?}"
    );
}

#[test]
fn principal_with_full_wildcard_grant_can_insert() {
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE foo (id INTEGER, name TEXT)")
        .unwrap();

    let gs = grants(&[("sub", "https://idp", "alice", "*", "*", None, None, None)]);
    install_authorizer(&conn, gs);
    conn.downgrade_to_anonymous();

    let _guard = conn.with_principal(principal("https://idp", "alice", &[]));
    conn.execute("INSERT INTO foo VALUES (1, 'alice')").unwrap();
}

#[test]
fn column_level_insert_denied_when_column_not_granted() {
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE foo (id INTEGER, name TEXT, secret TEXT)")
        .unwrap();

    // Grant INSERT on (id, name) only — `secret` is excluded.
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
    install_authorizer(&conn, gs);
    conn.downgrade_to_anonymous();

    let _guard = conn.with_principal(principal("https://idp", "alice", &[]));
    // Touches only granted columns → succeeds.
    conn.execute("INSERT INTO foo (id, name) VALUES (1, 'alice')")
        .unwrap();
    // Touches `secret` → denied at the translate hook BEFORE bytecode emit.
    let err = conn
        .execute("INSERT INTO foo (id, name, secret) VALUES (2, 'eve', 'x')")
        .unwrap_err();
    assert!(matches!(err, LimboError::AuthorizationDenied(_)));
}

#[test]
fn cdc_replay_shape_insert_authorizes_full_schema() {
    // `INSERT INTO foo VALUES (?, ?, ?)` with no explicit column list is the
    // sync-engine push shape. The hook must expand to the full table column
    // list before authorizing — otherwise this denial would never fire.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE foo (id INTEGER, name TEXT, secret TEXT)")
        .unwrap();

    // Grant INSERT on (id, name) — secret is excluded.
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
    install_authorizer(&conn, gs);
    conn.downgrade_to_anonymous();

    let _guard = conn.with_principal(principal("https://idp", "alice", &[]));
    let err = conn
        .execute("INSERT INTO foo VALUES (3, 'eve', 'leak')")
        .unwrap_err();
    assert!(
        matches!(err, LimboError::AuthorizationDenied(_)),
        "no-col-list INSERT must expand to all columns and deny on secret"
    );
}

#[test]
fn upsert_do_update_authorizes_as_update() {
    // Closes threat #6: an attacker with INSERT-only on `foo` runs
    // `INSERT INTO foo ... ON CONFLICT(id) DO UPDATE SET locked_col = ?`.
    // The hook MUST additionally authorize Update on `locked_col` and
    // deny when there is no UPDATE grant.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE foo (id INTEGER PRIMARY KEY, name TEXT, locked_col TEXT)")
        .unwrap();

    // Grant INSERT on everything but no UPDATE.
    let gs = grants(&[(
        "sub",
        "https://idp",
        "alice",
        "foo",
        "INSERT",
        None,
        None,
        None,
    )]);
    install_authorizer(&conn, gs);
    conn.downgrade_to_anonymous();

    let _guard = conn.with_principal(principal("https://idp", "alice", &[]));
    let err = conn
        .execute(
            "INSERT INTO foo VALUES (1, 'alice', 'a') \
             ON CONFLICT(id) DO UPDATE SET locked_col = 'b'",
        )
        .unwrap_err();
    assert!(
        matches!(err, LimboError::AuthorizationDenied(_)),
        "UPSERT DO UPDATE must run UPDATE authz on SET targets; got: {err:?}"
    );
}

#[test]
fn select_is_uncontrolled() {
    // Reads are entirely out of scope for the MVP. Even with no grants and
    // an Anonymous-ish principal-with-no-rights, SELECT must succeed.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE foo (id INTEGER, name TEXT)")
        .unwrap();
    conn.execute("INSERT INTO foo VALUES (1, 'alice')").unwrap();

    install_authorizer(&conn, GrantSet::default());
    conn.downgrade_to_anonymous();

    let _guard = conn.with_principal(principal("https://idp", "stranger", &[]));
    let mut stmt = conn.prepare("SELECT id, name FROM foo").unwrap();
    let rows = stmt.run_collect_rows().unwrap();
    assert_eq!(rows.len(), 1);
}

#[test]
fn ddl_requires_admin() {
    let db = open_db();
    let conn = db.connect().unwrap();

    // Empty grant set — no admin role assignment for this principal.
    install_authorizer(&conn, GrantSet::default());
    conn.downgrade_to_anonymous();

    let _guard = conn.with_principal(principal("https://idp", "alice", &[]));
    let err = conn.execute("CREATE TABLE secret (x INTEGER)").unwrap_err();
    assert!(matches!(err, LimboError::AuthorizationDenied(_)));
}

#[test]
fn ddl_on_rbac_tables_forbidden_even_for_admin() {
    // Threat #16: an admin shouldn't be able to ALTER or DROP the RBAC
    // system tables and lock everyone out (or, depending on bootstrap,
    // open the floodgates).
    let db = open_db();
    let conn = db.connect().unwrap();
    // Pre-create the RBAC tables on the Trusted connection.
    conn.execute(
        "CREATE TABLE _turso_rbac_grants (\
            id INTEGER PRIMARY KEY, grantee_kind TEXT, grantee_iss TEXT, \
            grantee TEXT, table_name TEXT, op TEXT, columns_json TEXT, \
            using_expr TEXT, check_expr TEXT, created_at INTEGER\
         )",
    )
    .unwrap();

    install_authorizer(&conn, GrantSet::default());
    conn.downgrade_to_anonymous();

    // Even an admin principal can't ALTER the RBAC tables.
    let _guard = conn.with_principal(principal("https://idp", "admin", &["admin"]));
    let err = conn.execute("DROP TABLE _turso_rbac_grants").unwrap_err();
    assert!(
        matches!(err, LimboError::AuthorizationDenied(_)),
        "DDL on RBAC tables must be denied for everyone, got: {err:?}"
    );
}

#[test]
fn writable_schema_pragma_hard_denied() {
    // Threat #8: PRAGMA writable_schema = ON unlocks direct sqlite_schema
    // writes. The dangerous-pragma hard-deny path refuses this for everyone
    // running over the network (Trusted callers in-process still succeed
    // so the CLI REPL works).
    let db = open_db();
    let conn = db.connect().unwrap();

    install_authorizer(&conn, GrantSet::default());
    conn.downgrade_to_anonymous();

    let _guard = conn.with_principal(principal("https://idp", "admin", &["admin"]));
    let err = conn.execute("PRAGMA writable_schema = ON").unwrap_err();
    assert!(
        matches!(err, LimboError::AuthorizationDenied(_)),
        "writable_schema must hard-deny for admin via SQL, got: {err:?}"
    );
}

#[test]
fn system_table_writes_allowed_for_non_admin() {
    // The system-table whitelist lets push batches write to
    // turso_sync_last_change_id without an explicit grant. Without this,
    // every sync push from a non-admin would fail at step 1.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE turso_sync_last_change_id (change_id INTEGER)")
        .unwrap();

    install_authorizer(&conn, GrantSet::default());
    conn.downgrade_to_anonymous();

    let _guard = conn.with_principal(principal("https://idp", "alice", &[]));
    conn.execute("INSERT INTO turso_sync_last_change_id VALUES (1)")
        .unwrap();
}

#[test]
fn cross_issuer_sub_collision_blocked() {
    // Threat #4: a `sub="admin"` from `iss="evil"` must NOT match a grant
    // keyed on `iss="trusted"` and `sub="admin"`.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE orders (id INTEGER, status TEXT)")
        .unwrap();

    let gs = grants(&[(
        "sub",
        "https://trusted-idp",
        "admin",
        "orders",
        "INSERT",
        None,
        None,
        None,
    )]);
    install_authorizer(&conn, gs);
    conn.downgrade_to_anonymous();

    // Same sub, different iss → no match.
    let _guard = conn.with_principal(principal("https://evil-idp", "admin", &[]));
    let err = conn
        .execute("INSERT INTO orders VALUES (1, 'pending')")
        .unwrap_err();
    assert!(
        matches!(err, LimboError::AuthorizationDenied(_)),
        "cross-issuer sub collision must be blocked; got: {err:?}"
    );
}

#[test]
fn rls_using_predicate_filters_update() {
    // Plan §4: UPDATE with a USING predicate AND-merges into WHERE, so the
    // UPDATE only touches rows that satisfy the predicate. Other rows are
    // unchanged.
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE orders (id INTEGER, owner_id TEXT, status TEXT)")
        .unwrap();
    conn.execute("INSERT INTO orders VALUES (1, 'alice', 'pending'), (2, 'bob', 'pending')")
        .unwrap();

    // Alice may UPDATE only her own rows.
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
    install_authorizer(&conn, gs);
    conn.downgrade_to_anonymous();

    {
        let _guard = conn.with_principal(principal("https://idp", "alice", &[]));
        // Without a WHERE in the SQL, the USING predicate is the only
        // filter — only Alice's row changes.
        conn.execute("UPDATE orders SET status = 'shipped'")
            .unwrap();
    }

    // Verify only Alice's row was updated. Drop the guard first; reading
    // happens on a Trusted connection (the test connection is back to
    // Anonymous, but Select is uncontrolled by design).
    let _guard = conn.with_principal(principal("https://idp", "alice", &[]));
    let mut stmt = conn
        .prepare("SELECT id, status FROM orders ORDER BY id")
        .unwrap();
    let rows = stmt.run_collect_rows().unwrap();
    let mut got: Vec<(i64, String)> = Vec::new();
    for row in rows {
        let id = match &row[0] {
            crate::Value::Numeric(crate::Numeric::Integer(i)) => *i,
            _ => panic!("unexpected"),
        };
        let s = match &row[1] {
            crate::Value::Text(t) => t.value.to_string(),
            _ => panic!("unexpected"),
        };
        got.push((id, s));
    }
    assert_eq!(
        got,
        vec![(1, "shipped".to_string()), (2, "pending".to_string())],
        "USING predicate must filter UPDATE to Alice's rows only"
    );
}

#[test]
fn rls_using_predicate_filters_delete() {
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE orders (id INTEGER, owner_id TEXT)")
        .unwrap();
    conn.execute("INSERT INTO orders VALUES (1, 'alice'), (2, 'bob')")
        .unwrap();

    let gs = grants(&[(
        "sub",
        "https://idp",
        "alice",
        "orders",
        "DELETE",
        None,
        Some("owner_id = @principal.sub"),
        None,
    )]);
    install_authorizer(&conn, gs);
    conn.downgrade_to_anonymous();

    {
        let _guard = conn.with_principal(principal("https://idp", "alice", &[]));
        conn.execute("DELETE FROM orders").unwrap();
    }

    let _guard = conn.with_principal(principal("https://idp", "alice", &[]));
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM orders").unwrap();
    let rows = stmt.run_collect_rows().unwrap();
    let n = match &rows[0][0] {
        crate::Value::Numeric(crate::Numeric::Integer(i)) => *i,
        _ => panic!(),
    };
    assert_eq!(
        n, 1,
        "USING predicate must filter DELETE to Alice's row only"
    );
}

#[test]
fn auth_mode_resting_state_is_anonymous_between_requests() {
    let db = open_db();
    let conn = db.connect().unwrap();

    install_authorizer(&conn, GrantSet::default());
    conn.downgrade_to_anonymous();

    {
        let _guard = conn.with_principal(principal("https://idp", "alice", &[]));
        assert!(matches!(
            conn.auth_mode_snapshot(),
            AuthMode::Authenticated(_)
        ));
    }
    // Guard dropped — state must be Anonymous, not Trusted.
    assert!(matches!(conn.auth_mode_snapshot(), AuthMode::Anonymous));
}

#[test]
fn role_grant_iss_wildcard_lets_role_from_any_issuer_match() {
    let db = open_db();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE orders (id INTEGER, status TEXT)")
        .unwrap();

    let gs = grants(&[("role", "*", "editor", "orders", "INSERT", None, None, None)]);
    install_authorizer(&conn, gs);
    conn.downgrade_to_anonymous();

    let _guard = conn.with_principal(principal("https://idp-from-anywhere", "alice", &["editor"]));
    conn.execute("INSERT INTO orders VALUES (1, 'pending')")
        .unwrap();
}
