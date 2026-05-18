//! Authorizer hook trait and request/decision types.
//!
//! The translate-layer hooks (insert/update/delete/DDL/PRAGMA/ATTACH) build an
//! `AuthRequest` describing the operation about to be compiled and call
//! `Authorizer::authorize`. The returned `AuthDecision` either short-circuits
//! the compile with an `AuthorizationDenied` error or feeds RLS predicates
//! into the planner.

use crate::connection::{ConnectionAuthorizer, Principal};
use crate::schema::Schema;
use turso_parser::ast;

use super::predicates::CompiledPredicate;
use super::GrantSet;

/// The shape of operation being authorized. Distinguishing INSERT vs UPDATE vs
/// DELETE up front lets the policy table separate column-level INSERT grants
/// from column-level UPDATE grants — important so a principal granted only
/// INSERT on `(col_a)` cannot escalate to UPDATE on `(col_a)` via a different
/// statement form.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthOp {
    Insert,
    Update,
    Delete,
    /// Declared for trait completeness/future-proofing. SELECT is intentionally
    /// not hooked in the MVP — reads are uncontrolled per the design.
    Select,
    Ddl {
        kind: DdlKind,
    },
    Pragma {
        name: String,
        mutates: bool,
    },
    Attach,
    Detach,
}

/// DDL operation taxonomy. The translate layer passes the AST node kind so the
/// authorizer doesn't have to re-derive it from a SQL string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DdlKind {
    CreateTable,
    DropTable,
    AlterTable,
    CreateIndex,
    DropIndex,
    CreateTrigger,
    DropTrigger,
    CreateView,
    DropView,
    /// Catch-all for VACUUM, REINDEX, and other rare schema-touching commands.
    Other,
}

/// Pre-translate request packet. The translate hook builds one of these per
/// statement and hands it to the authorizer.
#[derive(Debug)]
pub struct AuthRequest<'a> {
    /// Target table (resolved name, not the AST `Name`). `None` for ATTACH and
    /// for PRAGMAs that scope to the connection rather than a table.
    pub table: Option<&'a str>,
    pub op: AuthOp,
    /// Columns affected by the operation:
    /// - INSERT: the resolved column list (expanded if the SQL omitted it).
    /// - UPDATE: the SET-clause targets.
    /// - DELETE: empty.
    pub columns_touched: &'a [String],
    pub principal: &'a Principal,
    pub schema: &'a Schema,
}

/// Decision returned by an authorizer.
#[derive(Debug)]
pub enum AuthDecision {
    /// Allow with no row-level predicate.
    Allow,
    /// Allow but inject the contained USING/CHECK predicates into the plan.
    /// The payload is boxed so `AuthDecision` stays small (most calls return
    /// `Allow` or `Deny`, both ~pointer-sized) — clippy was right to flag
    /// the variant-size disparity.
    AllowWithPredicates(Box<AllowPredicates>),
    Deny(&'static str),
}

/// Predicates carried by `AuthDecision::AllowWithPredicates`. Boxed by the
/// variant so the enum stays cache-friendly.
#[derive(Debug)]
pub struct AllowPredicates {
    pub using: Option<CompiledPredicate>,
    pub check: Option<CompiledPredicate>,
}

/// Concrete authorizer used by the sync server. Holds the compiled
/// `GrantSet` behind an `ArcSwap` so it can be hot-reloaded after admin
/// writes to `_turso_rbac_grants` / `_turso_rbac_role_assignments` without
/// taking the connection offline. This closes the original "TOFU promotion
/// stays invisible until server restart" gap — the sync server now reloads
/// the grant snapshot after each successful RBAC-table write, including the
/// implicit TOFU INSERTs.
pub struct RbacAuthorizer {
    grants: arc_swap::ArcSwap<GrantSet>,
    /// When `true`, the JWT `roles` claim is authoritative (Mode B). When
    /// `false`, roles come from `_turso_rbac_role_assignments` already
    /// populated on the `Principal` (Mode A — the default).
    pub jwt_roles_authoritative: bool,
}

impl RbacAuthorizer {
    pub fn new(grants: GrantSet, jwt_roles_authoritative: bool) -> Self {
        Self {
            grants: arc_swap::ArcSwap::from_pointee(grants),
            jwt_roles_authoritative,
        }
    }

    /// Atomically swap in a freshly-loaded `GrantSet`. Called by the sync
    /// server after every successful write to the RBAC tables (including
    /// the per-request TOFU promotion) so newly-issued grants are visible
    /// to the next statement on this connection without a server restart.
    ///
    /// Uses `ArcSwap::store` so the swap is wait-free for in-flight
    /// authorize_dyn calls — readers either see the old or the new
    /// snapshot, never a torn intermediate.
    pub fn replace_grants(&self, new: GrantSet) {
        self.grants.store(crate::sync::Arc::new(new));
    }

    /// Internal decision pipeline broken out for readability. The order is
    /// security-critical and is enumerated in the plan §3:
    ///   1. RBAC-table DDL hard-deny (must precede every other check).
    ///   2. Direct `sqlite_schema` UPDATE hard-deny.
    ///   3. Admin gate for RBAC-table writes / dangerous PRAGMAs / ATTACH.
    ///   4. System-table whitelist (turso_sync_*, _turso_*, sqlite_*).
    ///   5. Grant lookup.
    ///   6. Default deny.
    fn decide(&self, req: &AuthRequest<'_>) -> AuthDecision {
        // 1. DDL on the RBAC system tables is forbidden for everyone —
        //    including admin and Trusted (Trusted never reaches here, but the
        //    invariant is worth documenting in code).
        if let AuthOp::Ddl { .. } = req.op {
            if let Some(table) = req.table {
                if is_rbac_table(table) {
                    return AuthDecision::Deny("rbac-table-ddl-forbidden");
                }
            }
        }

        // 2. Direct UPDATE/INSERT/DELETE on sqlite_schema is forbidden via SQL
        //    regardless of grant. `PRAGMA writable_schema = ON` is the lever
        //    that would normally unlock this; we hard-deny it elsewhere.
        if let Some(table) = req.table {
            if is_sqlite_schema(table)
                && matches!(req.op, AuthOp::Insert | AuthOp::Update | AuthOp::Delete)
            {
                return AuthDecision::Deny("sqlite-schema-direct-write-forbidden");
            }
        }

        let is_admin = self.principal_has_role(req.principal, "admin");

        // 3a. Writes to RBAC system tables require admin AND return Allow for
        //     admin (positive allow). Falling through to the grant lookup
        //     would deny admin RBAC writes because there's no specific
        //     grant — that was a real bug caught by the attack-test suite,
        //     because in production admin would be unable to manage grants
        //     even though that's the whole point of the role.
        if let Some(table) = req.table {
            if is_rbac_table(table)
                && matches!(req.op, AuthOp::Insert | AuthOp::Update | AuthOp::Delete)
            {
                return if is_admin {
                    AuthDecision::Allow
                } else {
                    AuthDecision::Deny("rbac-table-write-requires-admin")
                };
            }
        }

        // 3b. DDL anywhere requires admin (after the RBAC-table hard-deny above).
        if matches!(req.op, AuthOp::Ddl { .. }) && !is_admin {
            return AuthDecision::Deny("ddl-requires-admin");
        }

        // 3c. ATTACH / DETACH require admin.
        if matches!(req.op, AuthOp::Attach | AuthOp::Detach) && !is_admin {
            return AuthDecision::Deny("attach-requires-admin");
        }

        // 3d. PRAGMAs are categorised in pragma_policy. Dangerous PRAGMAs were
        //     already hard-denied at the translate seam; here we still gate
        //     mutating connection-scope PRAGMAs on admin.
        if let AuthOp::Pragma { mutates: true, .. } = &req.op {
            if !is_admin {
                return AuthDecision::Deny("mutating-pragma-requires-admin");
            }
            return AuthDecision::Allow;
        }

        // 4. System-table whitelist for writes. Reads aren't authorized here at
        //    all; the translate layer only invokes us for writes.
        if let Some(table) = req.table {
            if !is_rbac_table(table) && is_system_table(table) {
                return AuthDecision::Allow;
            }
        }

        // 5. Grant lookup. Returns an AllowWithPredicates if any grants match;
        //    Deny otherwise.
        match &req.op {
            AuthOp::Insert | AuthOp::Update | AuthOp::Delete => self.grant_decision(req),
            AuthOp::Select => AuthDecision::Allow, // reads are open in MVP
            AuthOp::Ddl { .. } | AuthOp::Attach | AuthOp::Detach | AuthOp::Pragma { .. } => {
                // These were all gated above; falling through here means admin
                // was approved (DDL/ATTACH/DETACH/PRAGMA admin gates allow above).
                AuthDecision::Allow
            }
        }
    }

    /// Resolve grants for a non-system-table write. Combines column-set checks
    /// and USING/CHECK predicate aggregation per the rules:
    ///   - Column check: every column in `columns_touched` must appear in the
    ///     union of `columns_json` across matching grants.
    ///   - `using`: OR-joined across matching grants (any grant lets the row
    ///     through).
    ///   - `check`: AND-joined (every grant's CHECK must hold), PostgreSQL RLS
    ///     semantics.
    fn grant_decision(&self, req: &AuthRequest<'_>) -> AuthDecision {
        let Some(table) = req.table else {
            return AuthDecision::Deny("missing-table-context");
        };

        // Load the current grant snapshot. `ArcSwap::load` is wait-free; the
        // guard borrows the inner Arc until end-of-scope so concurrent
        // `replace_grants` swaps don't invalidate the view we're matching
        // against.
        let grants = self.grants.load();
        let matches = grants.matching(
            req.principal,
            table,
            op_label(&req.op),
            self.jwt_roles_authoritative,
        );
        if matches.is_empty() {
            return AuthDecision::Deny("no-matching-grant");
        }

        // Column-coverage check. NULL columns_json on a grant means "all
        // columns"; if any matching grant covers all columns, the column
        // check passes.
        let any_wildcard_columns = matches.iter().any(|g| g.columns.is_none());
        if !any_wildcard_columns {
            for col in req.columns_touched {
                let covered = matches
                    .iter()
                    .any(|g| g.columns.as_ref().is_some_and(|cs| cs.contains(col)));
                if !covered {
                    return AuthDecision::Deny("column-not-granted");
                }
            }
        }

        // Predicate aggregation.
        let using = combine_or(matches.iter().filter_map(|g| g.using.clone()));
        let check = combine_and(matches.iter().filter_map(|g| g.check.clone()));
        if using.is_some() || check.is_some() {
            AuthDecision::AllowWithPredicates(Box::new(AllowPredicates { using, check }))
        } else {
            AuthDecision::Allow
        }
    }

    fn principal_has_role(&self, p: &Principal, role: &str) -> bool {
        p.roles.iter().any(|r| r == role)
    }
}

impl ConnectionAuthorizer for RbacAuthorizer {
    fn authorize_dyn(&self, request: &AuthRequest<'_>) -> AuthDecision {
        self.decide(request)
    }
}

/// Op label used as the column value in `_turso_rbac_grants.op`. Matched
/// against the SQL-stored `op` ('INSERT'|'UPDATE'|'DELETE'|'DDL'|'PRAGMA'|
/// 'ATTACH'|'*').
pub(crate) fn op_label(op: &AuthOp) -> &'static str {
    match op {
        AuthOp::Insert => "INSERT",
        AuthOp::Update => "UPDATE",
        AuthOp::Delete => "DELETE",
        AuthOp::Select => "SELECT",
        AuthOp::Ddl { .. } => "DDL",
        AuthOp::Pragma { .. } => "PRAGMA",
        AuthOp::Attach => "ATTACH",
        AuthOp::Detach => "DETACH",
    }
}

/// Tables that store RBAC policy itself. Writes here are admin-only; DDL is
/// forbidden for everyone.
pub(crate) fn is_rbac_table(name: &str) -> bool {
    name.eq_ignore_ascii_case("_turso_rbac_grants")
        || name.eq_ignore_ascii_case("_turso_rbac_role_assignments")
}

pub(crate) fn is_sqlite_schema(name: &str) -> bool {
    name.eq_ignore_ascii_case("sqlite_schema")
        || name.eq_ignore_ascii_case("sqlite_master")
        || name.eq_ignore_ascii_case("sqlite_temp_schema")
        || name.eq_ignore_ascii_case("sqlite_temp_master")
}

/// System-table whitelist for write authorization. The sync engine writes to
/// `turso_sync_*` bookkeeping on every push batch, and CDC apply may touch
/// `_turso_cdc_*`. These are infrastructure; gating them per-grant would
/// break sync entirely. RBAC tables are explicitly excluded by the caller
/// (their write gate is higher-precedence than the whitelist).
pub(crate) fn is_system_table(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("turso_sync_") || lower.starts_with("_turso_") || lower.starts_with("sqlite_")
}

fn combine_or<I>(mut iter: I) -> Option<CompiledPredicate>
where
    I: Iterator<Item = CompiledPredicate>,
{
    let first = iter.next()?;
    let mut acc = first.expr;
    for p in iter {
        acc = ast::Expr::Binary(Box::new(acc), ast::Operator::Or, Box::new(p.expr));
    }
    Some(CompiledPredicate { expr: acc })
}

fn combine_and<I>(mut iter: I) -> Option<CompiledPredicate>
where
    I: Iterator<Item = CompiledPredicate>,
{
    let first = iter.next()?;
    let mut acc = first.expr;
    for p in iter {
        acc = ast::Expr::Binary(Box::new(acc), ast::Operator::And, Box::new(p.expr));
    }
    Some(CompiledPredicate { expr: acc })
}
