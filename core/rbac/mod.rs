//! RBAC: column- and row-level write authorization for the sync server.
//!
//! ## Module layout
//!
//! - [`authorizer`] — `Authorizer` trait, `AuthOp`/`AuthRequest`/`AuthDecision`
//!   types, and the production `RbacAuthorizer` impl.
//! - [`predicates`] — USING/CHECK predicate compilation, placeholder
//!   substitution, and AST splicing helpers used by the translate-layer hooks.
//! - [`pragma_policy`] — classification table consulted by the PRAGMA hook.
//!
//! ## Bootstrap responsibilities
//!
//! Two tables: `_turso_rbac_grants` (the policy itself) and
//! `_turso_rbac_role_assignments` (Mode A role membership). Both have a
//! one-shot CREATE IF NOT EXISTS path that runs from a `Trusted`
//! `connect_untracked` connection at server startup. DDL on the tables is
//! hard-denied for everyone after bootstrap; schema migrations would have to
//! go through a versioned in-process migration path that bypasses the
//! authorizer (not implemented in this MVP — admins must rebuild the DB).
//!
//! ## TOFU bootstrap
//!
//! On every successful JWT verification, the sync server runs an atomic
//! "first-auth-becomes-admin" check (see [`tofu_promote_if_needed`]). The
//! check is idempotent and race-safe via SQLite's `BEGIN IMMEDIATE`
//! serialization; two concurrent first-auth attempts cannot both promote.

pub mod authorizer;
pub mod pragma_policy;
pub mod predicates;
#[cfg(test)]
mod tests_attacks;
#[cfg(test)]
mod tests_gaps;
#[cfg(test)]
mod tests_integration;
#[cfg(test)]
mod tests_roles;

use std::collections::BTreeSet;

use crate::connection::Principal;
use crate::{LimboError, Result};

pub use authorizer::{AuthDecision, AuthOp, AuthRequest, DdlKind, RbacAuthorizer};
pub use predicates::{
    and_into_where, compile_predicate, substitute_placeholders, CompiledPredicate,
};

use crate::connection::{AuthMode, Connection};
use crate::schema::Schema;
use crate::sync::Arc;

/// Predicate payload carried by `HookDecision::Predicates`. Boxed so the
/// outer enum stays small (Allow is unit-sized).
#[derive(Debug, Default)]
pub struct HookPredicates {
    pub using: Option<turso_parser::ast::Expr>,
    pub check: Option<turso_parser::ast::Expr>,
}

/// Outcome surfaced to translate hooks. `Allow` is the fast path — the hook
/// continues compilation without touching the plan. `Predicates` carries the
/// post-substitution USING/CHECK expressions ready for splicing.
#[derive(Debug)]
pub enum HookDecision {
    Allow,
    Predicates(Box<HookPredicates>),
}

/// Cheap predicate the translate hooks consult before doing any work for
/// authorization. Returns `true` when the connection is in `Trusted` mode AND
/// no authorizer is installed — the common case for in-process callers (CLI
/// REPL, embedded users, simulator, `connect_untracked`). When `true`, the
/// hook can skip the column-name allocation and AuthRequest construction
/// entirely and proceed to bytecode emission as it would have before RBAC.
///
/// We *don't* fast-path on Trusted mode alone: a hypothetical future caller
/// could install an authorizer on a Trusted connection for early-warning
/// telemetry, and the helper's mode short-circuit handles that branch
/// without us having to think about it twice. The fast-path is purely an
/// allocation optimization, not a correctness shortcut.
#[inline]
pub fn is_dormant(connection: &Arc<Connection>) -> bool {
    let auth = connection.auth.read();
    matches!(auth.mode, AuthMode::Trusted) && auth.authorizer.is_none()
}

/// Single entry point used by every translate hook. Returns:
///   - `Ok(HookDecision::Allow)` when the principal may proceed unchanged.
///   - `Ok(HookDecision::Predicates { .. })` when row-level predicates must
///     be spliced. The caller is responsible for AND-ing USING into the
///     statement's WHERE clause and threading CHECK through the constraint
///     emission path; the splicing differs per statement shape.
///   - `Err(LimboError::AuthorizationDenied(..))` when the decision is Deny.
///
/// Trust-mode short-circuit lives here so individual hooks don't have to
/// re-implement it. `is_nested_stmt()` is not a bypass — triggers compile
/// under the firing principal by design.
pub fn authorize(
    connection: &Arc<Connection>,
    schema: &Schema,
    table: Option<&str>,
    op: AuthOp,
    columns_touched: &[String],
) -> crate::Result<HookDecision> {
    // Snapshot the auth mode to keep the auth lock held briefly. The match
    // below clones an Arc<Principal> only on the Authenticated branch.
    let mode = connection.auth_mode_snapshot();
    let principal = match mode {
        AuthMode::Trusted => return Ok(HookDecision::Allow),
        AuthMode::Anonymous => {
            return Err(crate::LimboError::AuthorizationDenied(format!(
                "anonymous connection cannot perform {op:?}{}",
                table.map(|t| format!(" on {t}")).unwrap_or_default()
            )));
        }
        AuthMode::Authenticated(p) => p,
    };

    let authorizer = connection.authorizer_snapshot().ok_or_else(|| {
        // This should be impossible — with_principal panics if no authorizer
        // is installed — but a defense-in-depth check costs nothing.
        crate::LimboError::AuthorizationDenied(
            "internal error: Authenticated mode without an authorizer installed".into(),
        )
    })?;

    let request = AuthRequest {
        table,
        op: op.clone(),
        columns_touched,
        principal: &principal,
        schema,
    };

    match authorizer.authorize_dyn(&request) {
        AuthDecision::Allow => Ok(HookDecision::Allow),
        AuthDecision::AllowWithPredicates(payload) => {
            // Substitute placeholders in both predicates against the live
            // principal so the planner sees concrete literals, not unresolved
            // @__turso_p_* variables.
            let authorizer::AllowPredicates { using, check } = *payload;
            let using = using.map(|mut p| {
                substitute_placeholders(&mut p.expr, &principal);
                p.expr
            });
            let check = check.map(|mut p| {
                substitute_placeholders(&mut p.expr, &principal);
                p.expr
            });
            Ok(HookDecision::Predicates(Box::new(HookPredicates {
                using,
                check,
            })))
        }
        AuthDecision::Deny(rule) => Err(crate::LimboError::AuthorizationDenied(format!(
            "{rule} for {op:?}{}",
            table.map(|t| format!(" on {t}")).unwrap_or_default()
        ))),
    }
}

/// SQL executed by the server bootstrap to create both RBAC system tables.
/// Idempotent (`IF NOT EXISTS`). Indexes are created in the same statement
/// list so a partially-bootstrapped database — e.g. after a crash — converges
/// on a consistent shape the next time the sync server starts.
/// Bootstrap SQL split into individual statements. We can't use a single
/// SQL string with naive `split(';')` splitting because the
/// last-admin-protection triggers contain `;` inside their bodies. Each
/// element here is one statement, executed in order by `bootstrap()`.
pub const BOOTSTRAP_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS _turso_rbac_grants (
        id            INTEGER PRIMARY KEY,
        grantee_kind  TEXT NOT NULL,
        grantee_iss   TEXT NOT NULL,
        grantee       TEXT NOT NULL,
        table_name    TEXT NOT NULL,
        op            TEXT NOT NULL,
        columns_json  TEXT,
        using_expr    TEXT,
        check_expr    TEXT,
        created_at    INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS _turso_rbac_grants_lookup
        ON _turso_rbac_grants(grantee_kind, grantee_iss, grantee, table_name, op)",
    "CREATE TABLE IF NOT EXISTS _turso_rbac_role_assignments (
        iss           TEXT NOT NULL,
        sub           TEXT NOT NULL,
        role          TEXT NOT NULL,
        created_at    INTEGER NOT NULL,
        PRIMARY KEY (iss, sub, role)
    )",
    // GAP 3 fix: refuse any DELETE that would remove the last admin row.
    // Without this, a typo'd `DELETE FROM _turso_rbac_role_assignments
    // WHERE role = 'admin'` empties the table; TOFU then fires for the
    // next authenticated principal — whoever shows up next becomes admin.
    "CREATE TRIGGER IF NOT EXISTS _turso_rbac_protect_last_admin_delete
        BEFORE DELETE ON _turso_rbac_role_assignments
        FOR EACH ROW WHEN OLD.role = 'admin'
        BEGIN
          SELECT CASE
            WHEN (SELECT COUNT(*) FROM _turso_rbac_role_assignments WHERE role = 'admin') <= 1
            THEN RAISE(ABORT, 'rbac-protect-last-admin: refusing to remove the last admin')
          END;
        END",
    // Same protection against UPDATE-based demotion (admin changes their
    // own role to something else).
    "CREATE TRIGGER IF NOT EXISTS _turso_rbac_protect_last_admin_update
        BEFORE UPDATE ON _turso_rbac_role_assignments
        FOR EACH ROW WHEN OLD.role = 'admin' AND NEW.role <> 'admin'
        BEGIN
          SELECT CASE
            WHEN (SELECT COUNT(*) FROM _turso_rbac_role_assignments WHERE role = 'admin') <= 1
            THEN RAISE(ABORT, 'rbac-protect-last-admin: refusing to demote the last admin')
          END;
        END",
];

/// Apply the bootstrap SQL on a (Trusted) connection. Idempotent because
/// every statement uses `IF NOT EXISTS`. Callers (sync_server boot, tests)
/// should use this helper rather than splitting `BOOTSTRAP_STATEMENTS`
/// themselves so future bootstrap additions don't require changing every
/// callsite.
pub fn apply_bootstrap(conn: &crate::sync::Arc<crate::Connection>) -> crate::Result<()> {
    for stmt in BOOTSTRAP_STATEMENTS {
        conn.prepare(stmt)
            .map_err(|e| {
                crate::LimboError::InternalError(format!(
                    "RBAC bootstrap prepare failed for {stmt:?}: {e}"
                ))
            })?
            .run_ignore_rows()?;
    }
    Ok(())
}

/// SQL run on every successful JWT verification to handle the
/// "first-auth-becomes-admin" promotion. Idempotent and race-safe under
/// `BEGIN IMMEDIATE` serialization. Caller binds `:iss`, `:sub`, `:now`.
///
/// **The guards (`WHERE NOT EXISTS`) are load-bearing**: without them, every
/// authenticated request would re-insert the admin row, creating an
/// ever-growing role-assignment table.
pub const TOFU_SQL: &str = r#"
BEGIN IMMEDIATE;
INSERT INTO _turso_rbac_grants
    (grantee_kind, grantee_iss, grantee, table_name, op, columns_json,
     using_expr, check_expr, created_at)
SELECT 'sub', :iss, :sub, '*', '*', NULL, NULL, NULL, :now
WHERE NOT EXISTS (
    SELECT 1 FROM _turso_rbac_grants
    WHERE grantee_kind = 'sub' AND op IN ('*', 'DDL')
      AND table_name = '*'
);
INSERT INTO _turso_rbac_role_assignments (iss, sub, role, created_at)
SELECT :iss, :sub, 'admin', :now
WHERE NOT EXISTS (
    SELECT 1 FROM _turso_rbac_role_assignments WHERE role = 'admin'
);
COMMIT;
"#;

/// A single compiled grant after being read out of `_turso_rbac_grants`.
/// Predicates are stored as their compiled `ast::Expr` (no per-request
/// parse overhead). Column sets are pre-canonicalized into a `BTreeSet`
/// for fast `contains` checks during column coverage.
#[derive(Debug, Clone)]
pub struct CompiledGrant {
    pub grantee_kind: GranteeKind,
    pub grantee_iss: String,
    pub grantee: String,
    pub table_name: String,
    pub op: String,
    pub columns: Option<BTreeSet<String>>,
    pub using: Option<CompiledPredicate>,
    pub check: Option<CompiledPredicate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GranteeKind {
    Role,
    Sub,
}

impl GranteeKind {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "role" => Ok(Self::Role),
            "sub" => Ok(Self::Sub),
            other => Err(LimboError::ParseError(format!(
                "invalid grantee_kind {other:?}; expected 'role' or 'sub'"
            ))),
        }
    }
}

/// Loaded grant set used by `RbacAuthorizer` for matching against a
/// `(principal, table, op)` tuple. Built once per request from the
/// `_turso_rbac_grants` table snapshot.
#[derive(Debug, Default, Clone)]
pub struct GrantSet {
    grants: Vec<CompiledGrant>,
}

impl GrantSet {
    pub fn new(grants: Vec<CompiledGrant>) -> Self {
        Self { grants }
    }

    pub fn len(&self) -> usize {
        self.grants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    pub fn push(&mut self, g: CompiledGrant) {
        self.grants.push(g);
    }

    /// Return references to all grants that match the given principal/table/op
    /// tuple. Matching rules (see plan §3):
    ///
    /// - `grantee_kind = 'sub'` matches when `(grantee_iss, grantee) ==
    ///   (principal.iss, principal.sub)`. Cross-issuer sub collision is closed
    ///   because `iss` is part of the key.
    /// - `grantee_kind = 'role'` matches when `principal.roles` contains
    ///   `grantee`. The grant's `grantee_iss` is `'*'` (issuer-agnostic role)
    ///   or equal to `principal.iss` (issuer-scoped role).
    /// - `table_name` matches when it equals the table or is `'*'`.
    /// - `op` matches when it equals the operation label or is `'*'`.
    ///
    /// The `jwt_roles_authoritative` flag is presently unused here — role
    /// resolution happens before grants are matched: the `Principal.roles`
    /// vector is populated either from `_turso_rbac_role_assignments` (Mode A)
    /// or from the JWT (Mode B). The parameter is accepted so the matching
    /// signature stays stable if Mode B ever needs to be checked here too.
    pub fn matching(
        &self,
        principal: &Principal,
        table: &str,
        op_label: &str,
        _jwt_roles_authoritative: bool,
    ) -> Vec<&CompiledGrant> {
        let mut out = Vec::new();
        for g in &self.grants {
            if !grant_applies_to_table(&g.table_name, table) {
                continue;
            }
            if !grant_applies_to_op(&g.op, op_label) {
                continue;
            }
            match g.grantee_kind {
                GranteeKind::Sub => {
                    if g.grantee_iss == principal.iss && g.grantee == principal.sub {
                        out.push(g);
                    }
                }
                GranteeKind::Role => {
                    let iss_ok = g.grantee_iss == "*" || g.grantee_iss == principal.iss;
                    if iss_ok && principal.roles.iter().any(|r| r == &g.grantee) {
                        out.push(g);
                    }
                }
            }
        }
        out
    }
}

fn grant_applies_to_table(grant_table: &str, request_table: &str) -> bool {
    grant_table == "*" || grant_table.eq_ignore_ascii_case(request_table)
}

fn grant_applies_to_op(grant_op: &str, request_op: &str) -> bool {
    grant_op == "*" || grant_op.eq_ignore_ascii_case(request_op)
}

/// Parse a row from `_turso_rbac_grants` into a `CompiledGrant`. The caller
/// passes the row's columns already typed; the only failure paths here are
/// "predicate text won't parse" or "grantee_kind isn't role/sub" — both of
/// which should have been caught at INSERT time. Loading the grants table at
/// request entry re-validates as a defense-in-depth.
///
/// Eight arguments mirror the eight relevant grant-table columns 1:1, which
/// is the most-readable shape at the call sites in `sync_server::load_grants`
/// and the integration tests. Splitting into a builder would add a layer
/// without reducing the cognitive load.
#[allow(clippy::too_many_arguments)]
pub fn compile_row(
    grantee_kind: &str,
    grantee_iss: &str,
    grantee: &str,
    table_name: &str,
    op: &str,
    columns_json: Option<&str>,
    using_expr: Option<&str>,
    check_expr: Option<&str>,
) -> Result<CompiledGrant> {
    let kind = GranteeKind::parse(grantee_kind)?;

    if kind == GranteeKind::Sub && grantee_iss == "*" {
        return Err(LimboError::ParseError(
            "grantee_iss='*' is only valid for grantee_kind='role'".into(),
        ));
    }

    let columns = match columns_json {
        None => None,
        Some(text) => Some(parse_columns_json(text)?),
    };

    let using = match using_expr {
        None => None,
        Some(text) => Some(predicates::compile_predicate(text)?),
    };
    let check = match check_expr {
        None => None,
        Some(text) => Some(predicates::compile_predicate(text)?),
    };

    Ok(CompiledGrant {
        grantee_kind: kind,
        grantee_iss: grantee_iss.to_string(),
        grantee: grantee.to_string(),
        table_name: table_name.to_string(),
        op: op.to_string(),
        columns,
        using,
        check,
    })
}

/// Parse the `columns_json` column. It must be a JSON array of identifier
/// strings. We do a hand-rolled mini-parser instead of pulling `serde_json`
/// into `core`'s dependency graph; the format is fixed and trivially
/// recursive-free.
fn parse_columns_json(text: &str) -> Result<BTreeSet<String>> {
    let text = text.trim();
    if !text.starts_with('[') || !text.ends_with(']') {
        return Err(LimboError::ParseError(format!(
            "columns_json must be a JSON array, got {text:?}"
        )));
    }
    let inner = &text[1..text.len() - 1].trim();
    if inner.is_empty() {
        return Err(LimboError::ParseError(
            "columns_json must list at least one column; use NULL for 'all columns'".into(),
        ));
    }
    let mut set = BTreeSet::new();
    for raw in inner.split(',') {
        let s = raw.trim();
        if !(s.starts_with('"') && s.ends_with('"') && s.len() >= 2) {
            return Err(LimboError::ParseError(format!(
                "columns_json entries must be double-quoted strings, got {s:?}"
            )));
        }
        let name = &s[1..s.len() - 1];
        if name.is_empty() {
            return Err(LimboError::ParseError(
                "columns_json must not contain empty column names".into(),
            ));
        }
        set.insert(name.to_string());
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn principal(iss: &str, sub: &str, roles: &[&str]) -> Principal {
        Principal::new(
            iss,
            sub,
            roles.iter().map(|r| r.to_string()).collect(),
            BTreeMap::new(),
            0,
        )
        .unwrap()
    }

    #[test]
    fn sub_grants_are_iss_scoped() {
        // Two grants from different issuers, both with sub="admin".
        // A principal from issuer A should not match grants from issuer B even
        // though sub is identical. Closes cross-issuer sub collision (threat #4).
        let mut gs = GrantSet::default();
        gs.push(compile_row("sub", "https://idp-a", "admin", "*", "*", None, None, None).unwrap());
        gs.push(compile_row("sub", "https://idp-b", "admin", "*", "*", None, None, None).unwrap());

        let p = principal("https://idp-a", "admin", &[]);
        let m = gs.matching(&p, "anything", "INSERT", false);
        assert_eq!(m.len(), 1, "only the issuer-A grant should match");
        assert_eq!(m[0].grantee_iss, "https://idp-a");
    }

    #[test]
    fn role_grants_iss_wildcard_works() {
        let mut gs = GrantSet::default();
        gs.push(compile_row("role", "*", "editor", "orders", "UPDATE", None, None, None).unwrap());

        let p = principal("https://idp-a", "alice", &["editor"]);
        let m = gs.matching(&p, "orders", "UPDATE", false);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn wildcard_table_and_op_match() {
        let mut gs = GrantSet::default();
        gs.push(compile_row("sub", "https://idp", "alice", "*", "*", None, None, None).unwrap());

        let p = principal("https://idp", "alice", &[]);
        assert_eq!(gs.matching(&p, "orders", "INSERT", false).len(), 1);
        assert_eq!(gs.matching(&p, "orders", "UPDATE", false).len(), 1);
        assert_eq!(gs.matching(&p, "anything", "DELETE", false).len(), 1);
    }

    #[test]
    fn empty_columns_json_rejected() {
        assert!(parse_columns_json("[]").is_err());
        assert!(parse_columns_json("[ ]").is_err());
    }

    #[test]
    fn columns_json_parses_set() {
        let s = parse_columns_json(r#"["a", "b", "c"]"#).unwrap();
        assert!(s.contains("a"));
        assert!(s.contains("b"));
        assert!(s.contains("c"));
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn empty_predicate_rejected_at_grant_load() {
        // The compile_row path must reject empty/whitespace using_expr or
        // check_expr to enforce the "NULL means no constraint" invariant.
        let err = compile_row(
            "sub",
            "https://idp",
            "alice",
            "orders",
            "UPDATE",
            None,
            Some(""),
            None,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("non-empty"), "got error: {msg}");
    }

    #[test]
    fn sub_grant_with_wildcard_iss_rejected() {
        // grantee_iss='*' is meaningful for role grants (issuer-agnostic role)
        // but for sub grants it would let a principal with the same sub from
        // ANY issuer match — exactly the cross-issuer collision we close.
        let err = compile_row("sub", "*", "alice", "*", "*", None, None, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("'*'") || msg.contains("only valid"),
            "got: {msg}"
        );
    }
}
