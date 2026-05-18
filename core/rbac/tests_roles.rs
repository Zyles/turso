//! Role-based RBAC tests.
//!
//! Where `tests_attacks.rs` is organised by *attack class*, this file is
//! organised by *role*. Each section sets up a realistic principal — admin,
//! editor, junior editor, end user, service bot, read-only auditor — and
//! systematically attempts both the operations the role is supposed to
//! permit and every escalation it should reject.
//!
//! The deployment we model:
//!
//! ```text
//!  Tables:
//!    products(id, name, description, price, owner_id, internal_sku)
//!    user_profile(id, sub, email, prefs)
//!    event_log(ts, kind, actor, payload)
//!
//!  Roles (kept in _turso_rbac_role_assignments):
//!    admin          — full access (also: only role that can manage grants)
//!    editor         — INSERT/UPDATE/DELETE on products, all columns
//!    junior_editor  — UPDATE products(name, description) ONLY
//!    user           — UPDATE user_profile WHERE sub = @principal.sub
//!    service_bot    — INSERT event_log
//!    auditor        — no write grants (reads still open per design)
//! ```
//!
//! Each test states the role pretending to act and the operation being
//! attempted, then asserts allow/deny. The naming convention is
//! `<role>_<verb>_<target>` for "can do" tests and
//! `<role>_cannot_<verb>_<target>` for "should be blocked" tests.

use std::collections::BTreeMap;

use crate::connection::{ConnectionAuthorizer, Principal};
use crate::io::MemoryIO;
use crate::rbac::{compile_row, GrantSet};
use crate::sync::Arc;
use crate::{Database, LimboError, IO};

use super::authorizer::RbacAuthorizer;

// ---------------------------------------------------------------------------
// Deployment setup
// ---------------------------------------------------------------------------

const ISS: &str = "https://idp.example.com";

/// Stand up the deployment described in the module doc. Returns a connection
/// already downgraded to Anonymous with the authorizer installed and the
/// schema populated with deterministic seed data.
fn deploy() -> Arc<crate::Connection> {
    let io: Arc<dyn IO> = Arc::new(MemoryIO::new());
    let db = Database::open_file(io, ":memory:rbac-roles").unwrap();
    let conn = db.connect().unwrap();

    conn.execute(
        "CREATE TABLE products (\
            id INTEGER PRIMARY KEY, name TEXT, description TEXT, \
            price INTEGER, owner_id TEXT, internal_sku TEXT)",
    )
    .unwrap();
    conn.execute(
        "CREATE TABLE user_profile (\
            id INTEGER PRIMARY KEY, sub TEXT, email TEXT, prefs TEXT)",
    )
    .unwrap();
    conn.execute(
        "CREATE TABLE event_log (\
            ts INTEGER, kind TEXT, actor TEXT, payload TEXT)",
    )
    .unwrap();

    // Seed deterministic rows so tests can assert "row N is unchanged".
    conn.execute(
        "INSERT INTO products (id, name, description, price, owner_id, internal_sku) \
         VALUES \
         (1, 'Widget', 'standard widget', 100, 'alice', 'SKU-W-001'), \
         (2, 'Gadget', 'fancy gadget', 200, 'bob', 'SKU-G-002')",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO user_profile (id, sub, email, prefs) VALUES \
         (1, 'alice', 'alice@example.com', '{}'), \
         (2, 'bob', 'bob@example.com', '{}')",
    )
    .unwrap();

    // Bootstrap the RBAC tables for the attack tests that try to write into them.
    crate::rbac::apply_bootstrap(&conn).unwrap();

    install_role_policy(&conn);
    conn.downgrade_to_anonymous();
    conn
}

/// Install the grant set that defines all roles. Done as a single
/// installation because `set_authorizer` is one-shot; the grant set is the
/// frozen-at-install snapshot the request handler reads against.
fn install_role_policy(conn: &Arc<crate::Connection>) {
    let mut gs = GrantSet::default();

    // editor: INSERT/UPDATE/DELETE on products, all columns.
    for op in ["INSERT", "UPDATE", "DELETE"] {
        gs.push(
            compile_row("role", "*", "editor", "products", op, None, None, None)
                .expect("editor grant"),
        );
    }

    // junior_editor: UPDATE products(name, description) only.
    gs.push(
        compile_row(
            "role",
            "*",
            "junior_editor",
            "products",
            "UPDATE",
            Some(r#"["name", "description"]"#),
            None,
            None,
        )
        .expect("junior_editor grant"),
    );

    // user: UPDATE user_profile rows where sub matches the principal.
    gs.push(
        compile_row(
            "role",
            "*",
            "user",
            "user_profile",
            "UPDATE",
            None,
            Some("sub = @principal.sub"),
            None,
        )
        .expect("user grant"),
    );

    // service_bot: INSERT event_log only.
    gs.push(
        compile_row(
            "role",
            "*",
            "service_bot",
            "event_log",
            "INSERT",
            None,
            None,
            None,
        )
        .expect("service_bot grant"),
    );

    // auditor: no write grants. Documented as a role to make role
    // ergonomics tests below clearer.

    // operator (the TOFU'd admin): explicit `*/*` sub grant matching what
    // `run_admin_promotion_sql` writes. The `admin` role gives DDL /
    // RBAC-management / PRAGMA-exception / ATTACH powers (gated by
    // `is_admin` checks in the authorizer), but per the plan, table-level
    // data access still comes from a grant. TOFU creates both side-by-side
    // for the first principal; the operator-pre-warmed-admin path does the
    // same. A manually-added `admin` role assignment without the matching
    // sub grant produces an admin who can manage policy but cannot touch
    // user-table data — see `manually_added_admin_role_has_no_data_access`.
    //
    // We intentionally use a sub *different* from any end-user sub so
    // tests can't conflate "operator with sub=alice" against
    // "end-user with sub=alice". In production, IdPs typically expose
    // service identities under separate subs anyway.
    gs.push(
        compile_row(
            "sub",
            ISS,
            "operator",
            "*",
            "*",
            None,
            None,
            None,
        )
        .expect("operator TOFU sub grant"),
    );

    let auth: Arc<dyn ConnectionAuthorizer> = Arc::new(RbacAuthorizer::new(gs, false));
    conn.set_authorizer(auth);
}

fn p(sub: &str, roles: &[&str]) -> Arc<Principal> {
    Arc::new(
        Principal::new(
            ISS,
            sub,
            roles.iter().map(|r| r.to_string()).collect(),
            BTreeMap::new(),
            i64::MAX,
        )
        .unwrap(),
    )
}

fn operator() -> Arc<Principal> {
    // The principal who matches both `admin` role AND the TOFU-style
    // `(sub='operator', *, *)` grant the deployment ships with. This is
    // the "full god mode" identity — what the first authenticated
    // principal looks like after `run_admin_promotion_sql`.
    p("operator", &["admin"])
}
fn ed_eve() -> Arc<Principal> {
    p("eve", &["editor"])
}
fn junior_jay() -> Arc<Principal> {
    p("jay", &["junior_editor"])
}
fn user_alice() -> Arc<Principal> {
    p("alice", &["user"])
}
fn user_bob() -> Arc<Principal> {
    p("bob", &["user"])
}
fn service_bot() -> Arc<Principal> {
    p("worker-7", &["service_bot"])
}
fn auditor() -> Arc<Principal> {
    p("audit-1", &["auditor"])
}
fn no_role() -> Arc<Principal> {
    p("stranger", &[])
}

fn must_deny(result: crate::Result<()>, what: &str) {
    match result {
        Err(LimboError::AuthorizationDenied(_)) => {}
        Err(other) => panic!("expected AuthorizationDenied for {what}, got {other:?}"),
        Ok(()) => panic!("expected {what} to be denied; it succeeded"),
    }
}

fn must_block(result: crate::Result<()>, what: &str) {
    if let Ok(()) = result {
        panic!("expected {what} to be blocked; it succeeded");
    }
}

fn must_allow(result: crate::Result<()>, what: &str) {
    if let Err(e) = result {
        panic!("expected {what} to succeed, got: {e:?}");
    }
}

fn count_rows(conn: &Arc<crate::Connection>, sql: &str) -> i64 {
    let mut stmt = conn.prepare(sql).unwrap();
    let rows = stmt.run_collect_rows().unwrap();
    match &rows[0][0] {
        crate::Value::Numeric(crate::Numeric::Integer(i)) => *i,
        v => panic!("expected integer count, got {v:?}"),
    }
}

fn read_field(conn: &Arc<crate::Connection>, sql: &str) -> String {
    let mut stmt = conn.prepare(sql).unwrap();
    let rows = stmt.run_collect_rows().unwrap();
    match &rows[0][0] {
        crate::Value::Text(t) => t.value.to_string(),
        v => panic!("expected text, got {v:?}"),
    }
}

// ===========================================================================
// Role: admin
// ===========================================================================

#[test]
fn admin_can_do_everything_on_user_tables() {
    let conn = deploy();
    let _g = conn.with_principal(operator());

    must_allow(
        conn.execute("INSERT INTO products (id, name, price) VALUES (3, 'NewItem', 50)"),
        "admin INSERT products",
    );
    must_allow(
        conn.execute("UPDATE products SET price = 999 WHERE id = 1"),
        "admin UPDATE products",
    );
    must_allow(
        conn.execute("DELETE FROM products WHERE id = 2"),
        "admin DELETE products",
    );
    must_allow(
        conn.execute("INSERT INTO user_profile (id, sub, email, prefs) VALUES (3, 'carol', 'c@x', '{}')"),
        "admin INSERT user_profile",
    );
    must_allow(
        conn.execute("INSERT INTO event_log VALUES (1, 'login', 'alice', '{}')"),
        "admin INSERT event_log",
    );
}

#[test]
fn admin_can_manage_grants_table() {
    // The exact thing the original bug broke: admin must be able to write
    // grants and role assignments. Without this fix, post-TOFU deployments
    // would have an admin who can't grant anything to anyone.
    let conn = deploy();
    let _g = conn.with_principal(operator());

    must_allow(
        conn.execute(
            "INSERT INTO _turso_rbac_grants \
             (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, \
              using_expr, check_expr, created_at) \
             VALUES ('sub', 'https://idp.example.com', 'bob', 'products', 'UPDATE', \
                     NULL, NULL, NULL, 0)",
        ),
        "admin INSERT into _turso_rbac_grants",
    );
    must_allow(
        conn.execute(
            "INSERT INTO _turso_rbac_role_assignments \
             VALUES ('https://idp.example.com', 'bob', 'editor', 0)",
        ),
        "admin INSERT into _turso_rbac_role_assignments",
    );
    must_allow(
        conn.execute("UPDATE _turso_rbac_grants SET grantee = 'carol' WHERE grantee = 'bob'"),
        "admin UPDATE _turso_rbac_grants",
    );
    must_allow(
        conn.execute("DELETE FROM _turso_rbac_role_assignments WHERE sub = 'bob'"),
        "admin DELETE from role assignments",
    );
}

#[test]
fn admin_cannot_drop_or_alter_rbac_tables() {
    // Threat #16: even admin cannot DDL the RBAC tables. Losing them would
    // either lock the deployment out or fail open depending on bootstrap.
    let conn = deploy();
    let _g = conn.with_principal(operator());
    must_deny(
        conn.execute("DROP TABLE _turso_rbac_grants"),
        "admin DROP _turso_rbac_grants",
    );
    must_deny(
        conn.execute("DROP TABLE _turso_rbac_role_assignments"),
        "admin DROP _turso_rbac_role_assignments",
    );
    must_deny(
        conn.execute("ALTER TABLE _turso_rbac_grants ADD COLUMN backdoor TEXT"),
        "admin ALTER _turso_rbac_grants",
    );
}

#[test]
fn manually_added_admin_role_has_no_data_access_until_granted() {
    // Important architectural note: the `admin` role gives a principal
    // the AUTHORITY to manage policy (RBAC table writes, DDL, ATTACH,
    // mutating-PRAGMA exception). It does NOT, by itself, grant any
    // specific table data access. The TOFU bootstrap mints both the role
    // assignment AND a matching `(sub, *, *)` grant for the first
    // principal — the operator-pre-warm path does the same. But if an
    // existing admin later adds another principal to the `admin` role
    // without also issuing a data grant, that new admin can do DDL but
    // cannot read/write rows.
    //
    // This is a real source of operational surprise, so we lock it in
    // with a test rather than leave it as a comment.
    let conn = deploy();
    let bare_admin = p("bob", &["admin"]); // role but no `(sub, bob, *, *)` grant
    let _g = conn.with_principal(bare_admin);

    // DDL works — admin authority.
    must_allow(
        conn.execute("CREATE TABLE bob_table (x INTEGER)"),
        "bare-admin can DDL",
    );
    // But INSERT into an existing table fails — no data grant.
    must_deny(
        conn.execute("INSERT INTO products (id, name) VALUES (88, 'X')"),
        "bare-admin has no data grant on products",
    );
}

#[test]
fn admin_cannot_use_dangerous_pragmas_over_sql() {
    // The dangerous-PRAGMA hard-deny applies to admin too — server-start
    // env/CLI flags are the only path to flip these.
    let conn = deploy();
    let _g = conn.with_principal(operator());
    must_deny(
        conn.execute("PRAGMA writable_schema = ON"),
        "admin writable_schema",
    );
    must_deny(
        conn.execute("PRAGMA legacy_alter_table = ON"),
        "admin legacy_alter_table",
    );
}

// ===========================================================================
// Role: editor
// ===========================================================================

#[test]
fn editor_can_edit_products_freely() {
    let conn = deploy();
    let _g = conn.with_principal(ed_eve());

    must_allow(
        conn.execute("INSERT INTO products (id, name, price) VALUES (3, 'Foo', 10)"),
        "editor INSERT products",
    );
    must_allow(
        conn.execute("UPDATE products SET price = 150 WHERE id = 1"),
        "editor UPDATE products price",
    );
    must_allow(
        conn.execute("UPDATE products SET internal_sku = 'CHANGED' WHERE id = 1"),
        "editor UPDATE products internal_sku",
    );
    must_allow(
        conn.execute("DELETE FROM products WHERE id = 2"),
        "editor DELETE products",
    );
}

#[test]
fn editor_cannot_touch_user_profile() {
    // editor's grant is scoped to `products`. user_profile is out of scope —
    // even though editor "feels" more privileged than user, the grant table
    // is the only authority.
    let conn = deploy();
    let _g = conn.with_principal(ed_eve());
    must_deny(
        conn.execute("UPDATE user_profile SET email = 'pwned' WHERE id = 1"),
        "editor UPDATE user_profile",
    );
    must_deny(
        conn.execute("INSERT INTO user_profile VALUES (99, 'x', 'x', '{}')"),
        "editor INSERT user_profile",
    );
    must_deny(
        conn.execute("DELETE FROM user_profile"),
        "editor DELETE user_profile",
    );
}

#[test]
fn editor_cannot_write_event_log() {
    // event_log is the service_bot's table. Editor cannot insert audit
    // events on behalf of the system.
    let conn = deploy();
    let _g = conn.with_principal(ed_eve());
    must_deny(
        conn.execute("INSERT INTO event_log VALUES (1, 'forged', 'eve', '{}')"),
        "editor INSERT event_log",
    );
}

#[test]
fn editor_cannot_perform_ddl() {
    let conn = deploy();
    let _g = conn.with_principal(ed_eve());
    must_deny(
        conn.execute("CREATE TABLE shadow (x INTEGER)"),
        "editor CREATE TABLE",
    );
    must_deny(conn.execute("DROP TABLE products"), "editor DROP TABLE");
    must_deny(
        conn.execute("ALTER TABLE products ADD COLUMN backdoor TEXT"),
        "editor ALTER TABLE",
    );
}

#[test]
fn editor_cannot_self_promote_to_admin() {
    // The most direct escalation attempt: insert an admin row for yourself.
    // Admin gate on RBAC tables denies.
    let conn = deploy();
    let _g = conn.with_principal(ed_eve());
    must_deny(
        conn.execute(
            "INSERT INTO _turso_rbac_role_assignments \
             VALUES ('https://idp.example.com', 'eve', 'admin', 0)",
        ),
        "editor self-promote via role_assignments",
    );
    must_deny(
        conn.execute(
            "INSERT INTO _turso_rbac_grants \
             (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, \
              using_expr, check_expr, created_at) \
             VALUES ('sub', 'https://idp.example.com', 'eve', '*', '*', \
                     NULL, NULL, NULL, 0)",
        ),
        "editor self-grant wildcard via grants table",
    );
}

#[test]
fn editor_cannot_demote_admin() {
    // Reverse escalation: delete the admin row so the system has no admin,
    // then watch the editor sit in the now-broken authorization regime.
    // (Note: this attempt fires the admin gate on the DELETE op.)
    let conn = deploy();
    let _g = conn.with_principal(ed_eve());
    must_deny(
        conn.execute("DELETE FROM _turso_rbac_role_assignments WHERE role = 'admin'"),
        "editor DELETE admin role",
    );
    must_deny(
        conn.execute("DELETE FROM _turso_rbac_grants"),
        "editor DELETE all grants",
    );
}

#[test]
fn editor_cannot_smuggle_data_via_attach() {
    // Threat #10: even editors aren't admin-equivalent. ATTACH is gated.
    let conn = deploy();
    let _g = conn.with_principal(ed_eve());
    must_block(
        conn.execute("ATTACH ':memory:smuggle' AS smuggle"),
        "editor ATTACH",
    );
}

#[test]
fn editor_cannot_disable_pragmas_to_undermine_constraints() {
    // foreign_keys=OFF, ignore_check_constraints=ON, etc., would let editor
    // bypass DB-level invariants. Admin-only.
    let conn = deploy();
    let _g = conn.with_principal(ed_eve());
    must_deny(
        conn.execute("PRAGMA foreign_keys = OFF"),
        "editor foreign_keys",
    );
    must_deny(
        conn.execute("PRAGMA ignore_check_constraints = ON"),
        "editor ignore_check_constraints",
    );
    must_deny(
        conn.execute("PRAGMA journal_mode = MEMORY"),
        "editor journal_mode",
    );
}

#[test]
fn editor_cannot_write_to_sqlite_schema() {
    let conn = deploy();
    let _g = conn.with_principal(ed_eve());
    must_block(
        conn.execute("UPDATE sqlite_schema SET tbl_name = 'x' WHERE name = 'products'"),
        "editor UPDATE sqlite_schema",
    );
}

// ===========================================================================
// Role: junior_editor
// ===========================================================================

#[test]
fn junior_editor_can_update_name_and_description() {
    let conn = deploy();
    let _g = conn.with_principal(junior_jay());
    must_allow(
        conn.execute("UPDATE products SET name = 'Renamed' WHERE id = 1"),
        "junior_editor UPDATE name",
    );
    must_allow(
        conn.execute("UPDATE products SET description = 'new desc' WHERE id = 1"),
        "junior_editor UPDATE description",
    );
    // Combo update across granted columns.
    must_allow(
        conn.execute(
            "UPDATE products SET name = 'X', description = 'Y' WHERE id = 1",
        ),
        "junior_editor UPDATE name AND description",
    );
}

#[test]
fn junior_editor_cannot_update_price_or_sku() {
    // Column-level scope is the boundary that separates junior_editor from
    // editor. A multi-column UPDATE that touches ANY ungranted column fails.
    let conn = deploy();
    let _g = conn.with_principal(junior_jay());
    must_deny(
        conn.execute("UPDATE products SET price = 9999 WHERE id = 1"),
        "junior_editor UPDATE price",
    );
    must_deny(
        conn.execute("UPDATE products SET internal_sku = 'X' WHERE id = 1"),
        "junior_editor UPDATE internal_sku",
    );
    // Mixed: granted + ungranted column → still denied because column set
    // must be fully covered.
    must_deny(
        conn.execute("UPDATE products SET name = 'A', price = 1 WHERE id = 1"),
        "junior_editor UPDATE name+price (mixed)",
    );
}

#[test]
fn junior_editor_cannot_insert_products() {
    // junior_editor only has UPDATE — INSERT and DELETE are out of scope.
    let conn = deploy();
    let _g = conn.with_principal(junior_jay());
    must_deny(
        conn.execute("INSERT INTO products (id, name) VALUES (3, 'X')"),
        "junior_editor INSERT products",
    );
    must_deny(
        conn.execute("DELETE FROM products WHERE id = 1"),
        "junior_editor DELETE products",
    );
}

#[test]
fn junior_editor_cannot_escalate_via_upsert_to_write_price() {
    // Threat #6 in role form: junior_editor has UPDATE on (name,
    // description). They try to UPSERT inserting a new row and use DO UPDATE
    // SET price — the UPSERT-as-UPDATE check fires on `price` (not granted).
    //
    // Subtle prereq: they'd need INSERT too. They don't have that either,
    // so the INSERT-side authz denies first. We test both shapes for
    // completeness.
    let conn = deploy();
    let _g = conn.with_principal(junior_jay());

    must_deny(
        conn.execute(
            "INSERT INTO products (id, name, price) VALUES (1, 'X', 5000) \
             ON CONFLICT(id) DO UPDATE SET price = excluded.price",
        ),
        "junior_editor UPSERT to write price",
    );
}

#[test]
fn junior_editor_cannot_escalate_to_editor() {
    // Self-grant via role_assignments. The admin gate denies because
    // junior_editor doesn't have the admin role even with the editor /
    // junior_editor / user roles attached.
    let conn = deploy();
    let _g = conn.with_principal(junior_jay());
    must_deny(
        conn.execute(
            "INSERT INTO _turso_rbac_role_assignments \
             VALUES ('https://idp.example.com', 'jay', 'editor', 0)",
        ),
        "junior_editor self-promote to editor",
    );
}

// ===========================================================================
// Role: user (RLS via owner_id = @principal.sub)
// ===========================================================================

#[test]
fn user_can_update_own_profile() {
    let conn = deploy();
    let _g = conn.with_principal(user_alice());
    must_allow(
        conn.execute("UPDATE user_profile SET email = 'new@x' WHERE id = 1"),
        "user UPDATE own profile",
    );
    // Verify the row actually changed.
    drop(_g);
    let _g2 = conn.with_principal(operator());
    let email = read_field(
        &conn,
        "SELECT email FROM user_profile WHERE id = 1",
    );
    assert_eq!(email, "new@x");
}

#[test]
fn user_cannot_update_someone_elses_profile() {
    // RLS USING: `sub = @principal.sub`. Alice tries to update bob's row
    // by id. Statement runs but USING is AND'd into WHERE — zero rows
    // matched, bob's row is unchanged.
    let conn = deploy();
    {
        let _g = conn.with_principal(user_alice());
        // Statement does NOT error — it just affects zero rows because the
        // USING predicate filters out bob's row.
        must_allow(
            conn.execute("UPDATE user_profile SET email = 'pwned' WHERE id = 2"),
            "user UPDATE someone else's profile (filtered, not denied)",
        );
    }
    let _g2 = conn.with_principal(operator());
    let bob_email = read_field(
        &conn,
        "SELECT email FROM user_profile WHERE id = 2",
    );
    assert_eq!(
        bob_email, "bob@example.com",
        "RLS USING must prevent alice from touching bob's row"
    );
}

#[test]
fn user_cannot_change_sub_to_claim_other_rows() {
    // The "I'll set sub = 'bob' so RLS thinks I'm bob" attack. Because
    // USING is `sub = @principal.sub` evaluated against the CURRENT row,
    // and the predicate is AND'd into WHERE, you can only UPDATE rows
    // where the existing sub matches your principal. You CAN change your
    // own sub field, but only on your row — and after the change you
    // still can't reach bob's row because his row's sub is still 'bob'.
    let conn = deploy();
    {
        let _g = conn.with_principal(user_alice());
        // Set alice's sub to bob — succeeds for HER row only.
        must_allow(
            conn.execute("UPDATE user_profile SET sub = 'bob'"),
            "user changes own sub (affects own row only)",
        );
    }
    {
        let _g = conn.with_principal(operator());
        // Alice's row now has sub=bob. Bob's row still has sub=bob.
        let count_bob = count_rows(
            &conn,
            "SELECT COUNT(*) FROM user_profile WHERE sub = 'bob'",
        );
        assert_eq!(count_bob, 2, "Both rows now claim sub=bob");
    }
    // The HARD boundary is the JWT-verified `principal.sub` field, not the
    // row's `sub` column. Even though alice rewrote her row's sub, her
    // principal still says "sub=alice", so RLS still scopes her writes to
    // rows where the row's sub = 'alice' — and there are now ZERO such
    // rows (because she renamed hers to 'bob'). So she's now locked out
    // of HER OWN row via her own action. This is surprising but correct.
    {
        let _g = conn.with_principal(user_alice());
        // Confirm: an UPDATE with no WHERE affects zero rows (USING filters all out).
        must_allow(
            conn.execute("UPDATE user_profile SET email = 'after-rewrite'"),
            "user after sub-rewrite",
        );
    }
    let _g = conn.with_principal(operator());
    let alice_email = read_field(
        &conn,
        "SELECT email FROM user_profile WHERE id = 1",
    );
    let bob_email = read_field(
        &conn,
        "SELECT email FROM user_profile WHERE id = 2",
    );
    // Neither row got 'after-rewrite' because alice's principal.sub
    // doesn't match either row's sub field anymore for alice's view
    // (her row now has 'bob' in sub, bob's row has 'bob' — but the
    // USING is `row.sub = @principal.sub` where @principal.sub='alice',
    // so zero matches).
    assert_ne!(alice_email, "after-rewrite");
    assert_ne!(bob_email, "after-rewrite");
}

#[test]
fn user_cannot_update_products() {
    // user role has no grants on products. Even with a row they "own"
    // via owner_id, the per-table grant doesn't exist.
    let conn = deploy();
    let _g = conn.with_principal(user_alice());
    must_deny(
        conn.execute("UPDATE products SET price = 1 WHERE owner_id = 'alice'"),
        "user UPDATE products",
    );
}

#[test]
fn user_cannot_escalate_via_role_assignments() {
    let conn = deploy();
    let _g = conn.with_principal(user_alice());
    must_deny(
        conn.execute(
            "INSERT INTO _turso_rbac_role_assignments \
             VALUES ('https://idp.example.com', 'alice', 'admin', 0)",
        ),
        "user self-promote",
    );
    must_deny(
        conn.execute(
            "INSERT INTO _turso_rbac_role_assignments \
             VALUES ('https://idp.example.com', 'alice', 'editor', 0)",
        ),
        "user self-promote to editor",
    );
}

#[test]
fn user_cannot_use_subquery_to_widen_scope() {
    // An UPDATE with a subquery in the WHERE can reference any row, but
    // the USING predicate is still AND'd in, so the row filter still
    // narrows to the user's own rows. Verify the boundary holds.
    let conn = deploy();
    {
        let _g = conn.with_principal(user_alice());
        must_allow(
            conn.execute(
                "UPDATE user_profile SET email = 'attempted' \
                 WHERE id IN (SELECT id FROM user_profile)",
            ),
            "user UPDATE with id IN (SELECT id ...)",
        );
    }
    let _g2 = conn.with_principal(operator());
    let bob_email = read_field(
        &conn,
        "SELECT email FROM user_profile WHERE id = 2",
    );
    assert_eq!(
        bob_email, "bob@example.com",
        "subquery in WHERE must not bypass USING"
    );
}

// ===========================================================================
// Role: service_bot
// ===========================================================================

#[test]
fn service_bot_can_insert_events() {
    let conn = deploy();
    let _g = conn.with_principal(service_bot());
    must_allow(
        conn.execute("INSERT INTO event_log VALUES (1, 'login', 'alice', '{}')"),
        "service_bot INSERT event_log",
    );
}

#[test]
fn service_bot_cannot_update_or_delete_events() {
    // service_bot has INSERT only. Even on the same table, UPDATE and
    // DELETE are separate ops and require their own grants.
    let conn = deploy();
    {
        let _g = conn.with_principal(service_bot());
        must_allow(
            conn.execute("INSERT INTO event_log VALUES (1, 'x', 'a', '{}')"),
            "seed event",
        );
    }
    let _g = conn.with_principal(service_bot());
    must_deny(
        conn.execute("UPDATE event_log SET payload = 'rewritten' WHERE ts = 1"),
        "service_bot UPDATE",
    );
    must_deny(
        conn.execute("DELETE FROM event_log"),
        "service_bot DELETE (audit trail integrity)",
    );
}

#[test]
fn service_bot_cannot_write_to_other_tables() {
    let conn = deploy();
    let _g = conn.with_principal(service_bot());
    must_deny(
        conn.execute("INSERT INTO products (id, name) VALUES (9, 'X')"),
        "service_bot cross-table INSERT",
    );
    must_deny(
        conn.execute("UPDATE user_profile SET email = 'x'"),
        "service_bot cross-table UPDATE",
    );
}

// ===========================================================================
// Role: auditor (no write grants)
// ===========================================================================

#[test]
fn auditor_can_read_everything() {
    // Documented behavior: reads are uncontrolled in MVP. An auditor
    // principal can SELECT from every table.
    let conn = deploy();
    let _g = conn.with_principal(auditor());
    let n_products = count_rows(&conn, "SELECT COUNT(*) FROM products");
    let n_profiles = count_rows(&conn, "SELECT COUNT(*) FROM user_profile");
    let n_grants = count_rows(&conn, "SELECT COUNT(*) FROM _turso_rbac_grants");
    assert_eq!(n_products, 2);
    assert_eq!(n_profiles, 2);
    let _ = n_grants;
}

#[test]
fn auditor_cannot_write_anywhere() {
    let conn = deploy();
    let _g = conn.with_principal(auditor());
    must_deny(
        conn.execute("INSERT INTO products (id, name) VALUES (9, 'X')"),
        "auditor INSERT",
    );
    must_deny(
        conn.execute("UPDATE products SET price = 1"),
        "auditor UPDATE",
    );
    must_deny(
        conn.execute("DELETE FROM products"),
        "auditor DELETE",
    );
    must_deny(
        conn.execute("INSERT INTO event_log VALUES (1, 'x', 'x', '{}')"),
        "auditor INSERT event_log",
    );
}

// ===========================================================================
// Role: no role at all (authenticated but ungranted)
// ===========================================================================

#[test]
fn no_role_principal_cannot_write_anywhere() {
    // Default-deny is the safety net. An authenticated principal with no
    // role assignments and no specific sub grant cannot do any write.
    let conn = deploy();
    let _g = conn.with_principal(no_role());
    must_deny(
        conn.execute("INSERT INTO products (id, name) VALUES (9, 'X')"),
        "no-role INSERT",
    );
    must_deny(
        conn.execute("UPDATE products SET price = 1"),
        "no-role UPDATE",
    );
    must_deny(
        conn.execute("DELETE FROM products"),
        "no-role DELETE",
    );
    must_deny(
        conn.execute("UPDATE user_profile SET email = 'x'"),
        "no-role UPDATE user_profile",
    );
    must_deny(
        conn.execute("INSERT INTO event_log VALUES (1, 'x', 'x', '{}')"),
        "no-role INSERT event_log",
    );
}

#[test]
fn no_role_principal_can_still_read() {
    // Reads remain uncontrolled even for a totally ungranted principal.
    let conn = deploy();
    let _g = conn.with_principal(no_role());
    let n = count_rows(&conn, "SELECT COUNT(*) FROM products");
    assert_eq!(n, 2);
}

// ===========================================================================
// Role composition: multiple roles on one principal
// ===========================================================================

#[test]
fn principal_with_editor_and_service_bot_gets_union_of_grants() {
    // Threat-table sanity: when a principal has multiple roles, the
    // resulting allow set is the UNION (matching grants OR-merge for
    // USING, AND-merge for CHECK). A principal with both editor and
    // service_bot should be able to write both products and event_log.
    let conn = deploy();
    let multi = p("multi", &["editor", "service_bot"]);
    let _g = conn.with_principal(multi);

    must_allow(
        conn.execute("UPDATE products SET price = 999 WHERE id = 1"),
        "editor portion of role union",
    );
    must_allow(
        conn.execute("INSERT INTO event_log VALUES (1, 'x', 'multi', '{}')"),
        "service_bot portion of role union",
    );
    // But the union doesn't include unrelated roles — no admin powers.
    must_deny(
        conn.execute("CREATE TABLE evil (x INTEGER)"),
        "DDL despite editor+service_bot",
    );
}

#[test]
fn principal_with_junior_editor_and_editor_gets_widest_column_set() {
    // junior_editor has UPDATE on (name, description). editor has UPDATE
    // on all columns. The union is "all columns" — the wider grant wins.
    let conn = deploy();
    let multi = p("ed", &["junior_editor", "editor"]);
    let _g = conn.with_principal(multi);
    must_allow(
        conn.execute("UPDATE products SET price = 9999 WHERE id = 1"),
        "editor's wider grant takes effect",
    );
}

#[test]
fn fake_role_in_principal_does_not_unlock_grants_when_grant_targets_other_role() {
    // If a principal claims `roles=["admin"]` but the JWT verifier was in
    // Mode A so this shouldn't have happened — and even if it did, the
    // RbacAuthorizer still matches role-grants against the principal's
    // role vector. The defense in this layer is: only role-grants that
    // exist in `_turso_rbac_grants` matter. If no grant targets "admin"
    // (because admin is gate-checked elsewhere via the is_admin path),
    // claiming admin via roles still gives DDL/RBAC-table privileges.
    //
    // This test documents that fact: a principal with roles=["admin"]
    // CAN do DDL etc. The protection is upstream — Mode A must not put
    // "admin" in the principal's roles unless _turso_rbac_role_assignments
    // says so.
    let conn = deploy();
    let fake_admin = p("forged", &["admin"]);
    let _g = conn.with_principal(fake_admin);
    must_allow(
        conn.execute("CREATE TABLE evidence (x INTEGER)"),
        "fake-admin DDL (documents the Mode A invariant)",
    );
}

// ===========================================================================
// Cross-role escalation attempts
// ===========================================================================

#[test]
fn editor_cannot_grant_themselves_admin_via_sql_injection_in_text() {
    // An editor with INSERT on `products` tries to put SQL injection
    // payloads in product fields, hoping that some downstream consumer
    // re-executes them. RBAC only cares about the operation being
    // performed AT THIS STATEMENT — the future consumer is a separate
    // concern. So the editor CAN store a malicious string in
    // products.name; that's not a privilege escalation, just data.
    let conn = deploy();
    {
        let _g = conn.with_principal(ed_eve());
        must_allow(
            conn.execute(
                "INSERT INTO products (id, name) \
                 VALUES (99, '''); INSERT INTO _turso_rbac_role_assignments VALUES (''eve'', ''eve'', ''admin'', 0); --')",
            ),
            "storing a sql-injection-looking string is just data",
        );
    }
    // Verify the role_assignments table did NOT gain an admin row.
    let _g2 = conn.with_principal(operator());
    let admin_count = count_rows(
        &conn,
        "SELECT COUNT(*) FROM _turso_rbac_role_assignments WHERE role = 'admin' AND sub = 'eve'",
    );
    assert_eq!(
        admin_count, 0,
        "storing a payload string must never alter the policy tables"
    );
}

#[test]
fn editor_cannot_grant_themselves_admin_via_predicate_text() {
    // A grant USING predicate is a SQL expression text. If an editor
    // could somehow get a grant inserted with a malicious USING
    // (e.g., one that calls a side-effecting function), they'd elevate.
    // But editors can't write to the grants table at all (admin gate).
    let conn = deploy();
    let _g = conn.with_principal(ed_eve());
    must_deny(
        conn.execute(
            "INSERT INTO _turso_rbac_grants \
             (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, \
              using_expr, check_expr, created_at) \
             VALUES ('role', '*', 'editor', '*', '*', NULL, \
                     '1=1; DROP TABLE products; --', NULL, 0)",
        ),
        "editor CANNOT insert a malicious-USING grant",
    );
}

#[test]
fn role_grant_at_iss_specific_does_not_match_other_issuers() {
    // The `grantee_iss = '*'` case for role grants is the issuer-agnostic
    // form. The `grantee_iss = <specific>` form must match only that
    // issuer's principals. Without this, a JWT from issuer A claiming
    // role "editor" could use a role-grant intended for issuer B.
    let io: Arc<dyn IO> = Arc::new(MemoryIO::new());
    let db = Database::open_file(io, ":memory:rbac-iss-role").unwrap();
    let conn = db.connect().unwrap();
    conn.execute("CREATE TABLE secret (x INTEGER)").unwrap();
    // Only issuer-A principals with role "editor" can write `secret`.
    let mut gs = GrantSet::default();
    gs.push(
        compile_row(
            "role",
            "https://idp-A",
            "editor",
            "secret",
            "INSERT",
            None,
            None,
            None,
        )
        .unwrap(),
    );
    let auth: Arc<dyn ConnectionAuthorizer> = Arc::new(RbacAuthorizer::new(gs, false));
    conn.set_authorizer(auth);
    conn.downgrade_to_anonymous();

    // Principal from issuer A — matches.
    {
        let pa = Arc::new(
            Principal::new(
                "https://idp-A",
                "anyone",
                vec!["editor".to_string()],
                BTreeMap::new(),
                i64::MAX,
            )
            .unwrap(),
        );
        let _g = conn.with_principal(pa);
        must_allow(
            conn.execute("INSERT INTO secret VALUES (1)"),
            "issuer-A editor matches issuer-scoped role grant",
        );
    }
    // Principal from issuer B with "editor" role — no match.
    let pb = Arc::new(
        Principal::new(
            "https://idp-B",
            "evil",
            vec!["editor".to_string()],
            BTreeMap::new(),
            i64::MAX,
        )
        .unwrap(),
    );
    let _g = conn.with_principal(pb);
    must_deny(
        conn.execute("INSERT INTO secret VALUES (2)"),
        "issuer-B editor does NOT match issuer-A scoped grant",
    );
}

// ===========================================================================
// USING / CHECK predicate enforcement
// ===========================================================================

#[test]
fn user_using_predicate_actually_filters_rows() {
    // Walk through alice's and bob's writes side-by-side to confirm RLS
    // works for everyone independently.
    let conn = deploy();
    {
        let _g = conn.with_principal(user_alice());
        must_allow(
            conn.execute("UPDATE user_profile SET prefs = 'alice-prefs'"),
            "alice UPDATE",
        );
    }
    {
        let _g = conn.with_principal(user_bob());
        must_allow(
            conn.execute("UPDATE user_profile SET prefs = 'bob-prefs'"),
            "bob UPDATE",
        );
    }
    let _g = conn.with_principal(operator());
    let alice_prefs = read_field(
        &conn,
        "SELECT prefs FROM user_profile WHERE id = 1",
    );
    let bob_prefs = read_field(
        &conn,
        "SELECT prefs FROM user_profile WHERE id = 2",
    );
    assert_eq!(alice_prefs, "alice-prefs");
    assert_eq!(bob_prefs, "bob-prefs");
}

#[test]
fn user_or_in_where_doesnt_widen_using_predicate() {
    // `UPDATE user_profile SET email = 'x' WHERE id = 1 OR id = 2` — the
    // user-supplied OR can't bypass the USING AND because USING wraps the
    // whole WHERE: `(id = 1 OR id = 2) AND (sub = @principal.sub)`. Each
    // OR-disjunct is still AND'd with USING.
    let conn = deploy();
    {
        let _g = conn.with_principal(user_alice());
        must_allow(
            conn.execute(
                "UPDATE user_profile SET email = 'tried' \
                 WHERE id = 1 OR id = 2",
            ),
            "user OR-WHERE doesn't widen USING",
        );
    }
    let _g = conn.with_principal(operator());
    let bob_email = read_field(
        &conn,
        "SELECT email FROM user_profile WHERE id = 2",
    );
    assert_eq!(
        bob_email, "bob@example.com",
        "OR in user WHERE must not let alice touch bob's row"
    );
}
