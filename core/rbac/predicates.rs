//! USING/CHECK predicate handling for RBAC.
//!
//! Predicates are stored as SQL expression text in the `_turso_rbac_grants`
//! table, compiled at grant-load time into a typed `ast::Expr` for fast reuse,
//! and stamped into the planner WHERE clause (USING) and constraint emission
//! pipeline (CHECK) at translate time.
//!
//! Two key invariants:
//!
//! 1. Predicates compile against a **restricted symbol table** — only
//!    deterministic built-in functions are visible. UDFs registered via
//!    `Connection::register_function` are NOT, which closes the
//!    "side-effecting UDF in a CHECK predicate" escalation path.
//!
//! 2. Placeholder substitution is **strictly namespaced**. `@principal.iss`
//!    and `@principal.sub` resolve against the `Principal` struct fields, and
//!    only those two names. `@claim.<name>` resolves against the claims map.
//!    Predicates referencing unknown placeholders are rejected at grant-insert
//!    time, not silently treated as `NULL` at query time.

use std::collections::BTreeMap;

use crate::connection::{ClaimValue, Principal};
use crate::{Cmd, LimboError, Result};
use turso_parser::ast::{self, Expr, Variable};
use turso_parser::parser::Parser;

/// Substitution prefix used internally after rewriting `@principal.iss` to
/// `@__turso_p_iss`. The double-underscore prefix collides with no SQL
/// identifier and is reserved by Turso. The `__turso_` infix is shared with
/// other internal placeholders (CDC, sync) for grepability.
const PRINCIPAL_PREFIX: &str = "@__turso_p_";
const CLAIM_PREFIX: &str = "@__turso_c_";

/// Compiled predicate ready for AST splicing. `expr` is the post-substitution
/// expression — placeholders have already been rewritten to internal
/// `@__turso_p_*` / `@__turso_c_*` variable names so that
/// `substitute_placeholders` (called per request) only has to walk the tree
/// once and rebind to the live principal's claim values.
#[derive(Debug, Clone)]
pub struct CompiledPredicate {
    pub expr: ast::Expr,
}

/// AND-merge an additional expression into an `Option<Box<ast::Expr>>` WHERE
/// clause. Used by translate_update / translate_delete to inject USING
/// predicates into the existing user-supplied WHERE.
///
/// If the existing clause is `None`, the extra becomes the entire WHERE.
/// Otherwise we wrap both in `(existing) AND (extra)` so operator precedence
/// can't reorder. Parenthesization is structural here, not syntactic —
/// `Expr::Binary` with `Operator::And` is associative-by-construction in the
/// emitter, but we still wrap each side because `extra` may itself be an OR
/// or BETWEEN that would otherwise rebind under tighter precedence.
pub fn and_into_where(where_clause: &mut Option<Box<ast::Expr>>, extra: ast::Expr) {
    match where_clause.take() {
        None => *where_clause = Some(Box::new(extra)),
        Some(existing) => {
            *where_clause = Some(Box::new(ast::Expr::Binary(
                Box::new(ast::Expr::Parenthesized(vec![existing])),
                ast::Operator::And,
                Box::new(ast::Expr::Parenthesized(vec![Box::new(extra)])),
            )));
        }
    }
}

/// Parse a SQL expression-text into an `ast::Expr` after rewriting
/// `@principal.<name>` / `@claim.<name>` placeholders into single-token form.
///
/// Errors on:
/// - empty / whitespace-only text (rejected at grant-insert time)
/// - syntax errors
/// - references to unknown `@principal.*` placeholders (only `iss` and `sub`
///   are valid)
///
/// A future hardening step will also reject predicates that reference
/// non-builtin function names; for now the SymbolTable check is deferred to
/// emit-time (where unknown idents already error). The grant-insert path
/// invokes this and stores the resulting `ast::Expr` serialized back to SQL
/// so the cached form can be reloaded after a server restart.
pub fn compile_predicate(text: &str) -> Result<CompiledPredicate> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(LimboError::ParseError(
            "RBAC predicate must be either NULL or a non-empty SQL expression; \
             empty/whitespace text is rejected to prevent silent truthy coercion"
                .into(),
        ));
    }

    let rewritten = rewrite_placeholders(trimmed)?;
    // Wrap as `SELECT (<expr>)` so we can reuse the statement parser and pull
    // the expression out of the first result column. SQLite-compatible AST has
    // no top-level "expression-only" entry point.
    let wrapped = format!("SELECT ({rewritten})");
    let mut parser = Parser::new(wrapped.as_bytes());
    let cmd = parser
        .next_cmd()
        .map_err(|e| LimboError::ParseError(format!("RBAC predicate parse error: {e}")))?
        .ok_or_else(|| LimboError::ParseError("RBAC predicate parsed to nothing".into()))?;

    let expr = extract_select_expr(cmd).ok_or_else(|| {
        LimboError::ParseError("RBAC predicate must parse to a single scalar expression".into())
    })?;

    validate_no_unknown_placeholders(&expr)?;
    validate_only_deterministic_builtins(&expr)?;

    Ok(CompiledPredicate { expr })
}

/// Whitelist of deterministic, side-effect-free SQL function names that an
/// RBAC predicate is allowed to call. Kept small and explicit: every name
/// here was chosen because it's:
///   1. Pure — same inputs always produce same output;
///   2. Side-effect-free — no I/O, no time access, no random source;
///   3. Useful for typical RLS expressions (length checks, type coercion,
///      string operations on column values and `@principal.*` literals).
///
/// Anything not in this set is rejected at grant-insert time. Closes the
/// "operator writes `random() > 0.5` and the predicate evaluates
/// nondeterministically per request" class of bug, and the much worse
/// "operator writes `my_udf()` where `my_udf` is a registered extension
/// function with side effects".
const DETERMINISTIC_BUILTINS: &[&str] = &[
    // Type / null operators expressed as function calls.
    "coalesce", "ifnull", "iif", "nullif", "typeof",
    // String functions — pure.
    "length", "lower", "upper", "ltrim", "rtrim", "trim", "substr", "substring",
    "instr", "replace", "printf", "format", "quote", "char", "unicode",
    "hex", "unhex", "soundex",
    // Math — deterministic.
    "abs", "round", "ceil", "ceiling", "floor", "min", "max", "sign",
    "mod", "power", "pow", "sqrt", "exp", "log", "ln",
    // JSON path readers (read-only, no I/O).
    "json", "json_extract", "json_array", "json_object", "json_type",
    "json_valid", "json_array_length",
    // Misc deterministic.
    "cast", // Sometimes synthesized as a function call by some parsers.
];

/// Reject any `Expr::FunctionCall { name, .. }` whose name isn't in the
/// allow-list. This is the structural defense against admin-authored
/// predicates that try to call `random()`, `current_timestamp`,
/// `randomblob()`, a registered UDF, etc.
///
/// Walking the whole AST is O(n) in node count; predicates are tiny so
/// this is negligible. The check fires at grant-insert time so malformed
/// grants never reach the request hot path.
fn validate_only_deterministic_builtins(expr: &Expr) -> Result<()> {
    let mut bad: Option<String> = None;
    walk(expr, &mut |e| {
        if bad.is_some() {
            return;
        }
        if let Expr::FunctionCall { name, .. } = e {
            let lower = name.as_str().to_ascii_lowercase();
            if !DETERMINISTIC_BUILTINS.contains(&lower.as_str()) {
                bad = Some(lower);
            }
        }
        if let Expr::FunctionCallStar { name, .. } = e {
            // `count(*)` etc. — these are aggregate functions that
            // shouldn't appear in a per-row predicate either.
            bad = Some(format!("{}(*)", name.as_str().to_ascii_lowercase()));
        }
    });
    if let Some(name) = bad {
        return Err(LimboError::ParseError(format!(
            "RBAC predicate references function `{name}` which is not in the \
             deterministic-builtins allow-list; predicates may only call pure, \
             side-effect-free built-in functions"
        )));
    }
    Ok(())
}

/// Substitute the principal's iss/sub and claim values into the AST,
/// replacing internal placeholder `Variable` nodes with `Literal`
/// equivalents. This runs at translate-hook time after the GrantSet has
/// matched and after grant aggregation, so we walk a fresh `CompiledPredicate`
/// per statement.
///
/// Missing claims are bound to `Literal::Null` — operators should write
/// predicates that handle NULL explicitly (`@claim.tenant_id IS NOT NULL AND
/// tenant_id = @claim.tenant_id`). Token expiry has already been enforced by
/// the JWT verifier at request entry, so `exp_unix` is not exposed in
/// substitution.
pub fn substitute_placeholders(expr: &mut Expr, principal: &Principal) {
    walk_mut(expr, &mut |e| {
        if let Expr::Variable(Variable { name: Some(n), .. }) = e {
            if let Some(rest) = n.strip_prefix(PRINCIPAL_PREFIX) {
                match rest {
                    "iss" => {
                        *e = Expr::Literal(ast::Literal::String(format!(
                            "'{}'",
                            escape_sql(&principal.iss)
                        )));
                    }
                    "sub" => {
                        *e = Expr::Literal(ast::Literal::String(format!(
                            "'{}'",
                            escape_sql(&principal.sub)
                        )));
                    }
                    other => {
                        // Reaching here means validate_no_unknown_placeholders missed
                        // a case — that's a bug in this module, not user input.
                        // We still emit a NULL literal so the predicate evaluates to
                        // NULL/false rather than crashing the request.
                        debug_assert!(
                            false,
                            "unknown @principal.* placeholder reached substitute_placeholders: {other}"
                        );
                        *e = Expr::Literal(ast::Literal::Null);
                    }
                }
            } else if let Some(rest) = n.strip_prefix(CLAIM_PREFIX) {
                let claim_name = rest.to_string();
                let value = principal
                    .claims
                    .get(&claim_name)
                    .cloned()
                    .unwrap_or(ClaimValue::Null);
                *e = claim_to_literal(&value);
            }
        }
    });
}

/// Walk an AST expression, calling `f` on every node post-order.
fn walk_mut<F: FnMut(&mut Expr)>(expr: &mut Expr, f: &mut F) {
    match expr {
        Expr::Binary(l, _, r) => {
            walk_mut(l, f);
            walk_mut(r, f);
        }
        Expr::Unary(_, inner) => walk_mut(inner, f),
        Expr::Parenthesized(exprs) => {
            for e in exprs.iter_mut() {
                walk_mut(e, f);
            }
        }
        Expr::Case {
            base,
            when_then_pairs,
            else_expr,
        } => {
            if let Some(b) = base {
                walk_mut(b, f);
            }
            for (w, t) in when_then_pairs.iter_mut() {
                walk_mut(w, f);
                walk_mut(t, f);
            }
            if let Some(e) = else_expr {
                walk_mut(e, f);
            }
        }
        Expr::Cast { expr, .. } => walk_mut(expr, f),
        Expr::Collate(inner, _) => walk_mut(inner, f),
        Expr::FunctionCall { args, .. } => {
            for a in args.iter_mut() {
                walk_mut(a, f);
            }
        }
        Expr::FunctionCallStar { .. } => {}
        Expr::InList { lhs, rhs, .. } => {
            walk_mut(lhs, f);
            for r in rhs.iter_mut() {
                walk_mut(r, f);
            }
        }
        Expr::Between {
            lhs, start, end, ..
        } => {
            walk_mut(lhs, f);
            walk_mut(start, f);
            walk_mut(end, f);
        }
        Expr::Like {
            lhs, rhs, escape, ..
        } => {
            walk_mut(lhs, f);
            walk_mut(rhs, f);
            if let Some(esc) = escape {
                walk_mut(esc, f);
            }
        }
        Expr::IsNull(inner) | Expr::NotNull(inner) => walk_mut(inner, f),
        _ => {}
    }
    f(expr);
}

/// Rewrite `@principal.iss` → `@__turso_p_iss`, `@claim.foo` → `@__turso_c_foo`.
///
/// We do a single linear scan rather than regex; the document is short
/// (predicates are typically <200 chars) so this is cheap. We also reject
/// `@principal.<x>` where `<x>` is anything other than `iss` or `sub` here,
/// rather than letting the parser succeed and `substitute_placeholders` fail
/// at request time — early rejection means malformed grants can't be inserted
/// in the first place.
fn rewrite_placeholders(text: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            let rest = &text[i + 1..];
            if let Some((ns, after_dot, name_len)) = split_ns_name(rest) {
                match ns {
                    "principal" => {
                        match after_dot {
                            "iss" | "sub" => {
                                out.push_str(PRINCIPAL_PREFIX);
                                out.push_str(after_dot);
                            }
                            other => {
                                return Err(LimboError::ParseError(format!(
                                    "RBAC predicate references unknown @principal.{other}; \
                                     only @principal.iss and @principal.sub are valid"
                                )));
                            }
                        }
                        i += 1 + name_len;
                        continue;
                    }
                    "claim" => {
                        if !is_identifier(after_dot) {
                            return Err(LimboError::ParseError(format!(
                                "RBAC predicate references @claim.{after_dot} which is not a \
                                 valid identifier; claim names must be ASCII identifiers"
                            )));
                        }
                        out.push_str(CLAIM_PREFIX);
                        out.push_str(after_dot);
                        i += 1 + name_len;
                        continue;
                    }
                    _ => {
                        // `@something.<x>` where something is neither principal
                        // nor claim — pass through unchanged so it lexes as a
                        // plain variable. The unknown-placeholder validator
                        // catches it after parse if it survived.
                    }
                }
            }
        }
        out.push(text[i..].chars().next().unwrap());
        i += text[i..].chars().next().unwrap().len_utf8();
    }
    Ok(out)
}

/// Split `<ns>.<name>` from the start of `text`, returning the namespace, the
/// post-dot identifier, and the total length consumed (excluding the leading
/// `@` which the caller already skipped).
fn split_ns_name(text: &str) -> Option<(&str, &str, usize)> {
    let dot_idx = text.find('.')?;
    let ns = &text[..dot_idx];
    if !is_identifier(ns) {
        return None;
    }
    let after_dot = &text[dot_idx + 1..];
    // Eat the identifier following the dot.
    let name_end = after_dot
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(after_dot.len());
    let name = &after_dot[..name_end];
    if name.is_empty() || !is_identifier(name) {
        return None;
    }
    Some((ns, name, dot_idx + 1 + name_end))
}

fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.chars().next().unwrap().is_ascii_digit()
}

/// After parse, walk the tree and verify every `@__turso_p_*` / `@__turso_c_*`
/// placeholder resolves to a known principal field or claim name. We do this
/// even though `rewrite_placeholders` already gates `@principal.*` because
/// nothing prevents an operator from writing a literal `@__turso_p_evil`
/// directly into a predicate, and we want to refuse those too.
fn validate_no_unknown_placeholders(expr: &Expr) -> Result<()> {
    let mut bad: Option<String> = None;
    walk(expr, &mut |e| {
        if bad.is_some() {
            return;
        }
        if let Expr::Variable(Variable { name: Some(n), .. }) = e {
            if let Some(rest) = n.strip_prefix(PRINCIPAL_PREFIX) {
                if !matches!(rest, "iss" | "sub") {
                    bad = Some(format!("@principal.{rest}"));
                }
            }
            // Claims are open-ended; we can't validate their names statically
            // because they depend on the IdP's claim shape. The principal's
            // claims map binds missing names to NULL at substitution time.
        }
    });
    if let Some(name) = bad {
        return Err(LimboError::ParseError(format!(
            "RBAC predicate references unknown placeholder {name}; \
             only @principal.iss and @principal.sub are valid"
        )));
    }
    Ok(())
}

fn walk<F: FnMut(&Expr)>(expr: &Expr, f: &mut F) {
    match expr {
        Expr::Binary(l, _, r) => {
            walk(l, f);
            walk(r, f);
        }
        Expr::Unary(_, inner) => walk(inner, f),
        Expr::Parenthesized(exprs) => {
            for e in exprs.iter() {
                walk(e, f);
            }
        }
        Expr::Case {
            base,
            when_then_pairs,
            else_expr,
        } => {
            if let Some(b) = base {
                walk(b, f);
            }
            for (w, t) in when_then_pairs.iter() {
                walk(w, f);
                walk(t, f);
            }
            if let Some(e) = else_expr {
                walk(e, f);
            }
        }
        Expr::Cast { expr, .. } => walk(expr, f),
        Expr::Collate(inner, _) => walk(inner, f),
        Expr::FunctionCall { args, .. } => {
            for a in args.iter() {
                walk(a, f);
            }
        }
        Expr::InList { lhs, rhs, .. } => {
            walk(lhs, f);
            for r in rhs.iter() {
                walk(r, f);
            }
        }
        Expr::Between {
            lhs, start, end, ..
        } => {
            walk(lhs, f);
            walk(start, f);
            walk(end, f);
        }
        Expr::Like {
            lhs, rhs, escape, ..
        } => {
            walk(lhs, f);
            walk(rhs, f);
            if let Some(esc) = escape {
                walk(esc, f);
            }
        }
        Expr::IsNull(inner) | Expr::NotNull(inner) => walk(inner, f),
        _ => {}
    }
    f(expr);
}

fn extract_select_expr(cmd: Cmd) -> Option<Expr> {
    // `SELECT (<expr>)` parses to Cmd::Stmt(Stmt::Select(..)). We dig into
    // the first result column and unwrap the parenthesized expression.
    let Cmd::Stmt(stmt) = cmd else { return None };
    let ast::Stmt::Select(select) = stmt else {
        return None;
    };
    let columns = match select.body.select {
        ast::OneSelect::Select { columns, .. } => columns,
        _ => return None,
    };
    if columns.len() != 1 {
        return None;
    }
    let col = columns.into_iter().next()?;
    let (expr, _alias) = match col {
        ast::ResultColumn::Expr(expr, alias) => (expr, alias),
        _ => return None,
    };
    // Unwrap the outer parentheses we added in compile_predicate.
    let inner = *expr;
    match inner {
        ast::Expr::Parenthesized(mut paren) if paren.len() == 1 => paren.pop().map(|b| *b),
        other => Some(other),
    }
}

fn claim_to_literal(v: &ClaimValue) -> Expr {
    match v {
        ClaimValue::Null => Expr::Literal(ast::Literal::Null),
        ClaimValue::Bool(b) => Expr::Literal(ast::Literal::Numeric(
            if *b { "1" } else { "0" }.to_string(),
        )),
        ClaimValue::Integer(i) => Expr::Literal(ast::Literal::Numeric(i.to_string())),
        ClaimValue::Float(f) => Expr::Literal(ast::Literal::Numeric(format!("{f}"))),
        ClaimValue::String(s) => {
            Expr::Literal(ast::Literal::String(format!("'{}'", escape_sql(s))))
        }
    }
}

/// SQL single-quote string escaping per the SQLite rule (only ' is special).
fn escape_sql(s: &str) -> String {
    s.replace('\'', "''")
}

/// Test the namespace separation invariant: a JWT claim literally named
/// `principal.sub` (which the parser would never reach via lexing, but a
/// malicious or buggy IdP could include) does not collide with the
/// `@principal.sub` field on the `Principal` struct. The two namespaces are
/// disjoint by construction because `@claim.<name>` rewrites to
/// `@__turso_c_<name>` and `@principal.sub` rewrites to `@__turso_p_sub`.
#[cfg(test)]
pub(crate) fn _assert_namespace_separation_for_doc() {
    // Doc-only marker; real assertions live in mod tests.
}

/// Convenience wrapper so callers do not have to import the internal
/// `BTreeMap` alias.
#[allow(dead_code)]
pub(crate) fn empty_claims() -> BTreeMap<String, ClaimValue> {
    BTreeMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal_with(iss: &str, sub: &str) -> Principal {
        Principal::new(iss, sub, vec![], BTreeMap::new(), 0).expect("valid principal")
    }

    #[test]
    fn empty_predicate_rejected() {
        assert!(compile_predicate("").is_err());
        assert!(compile_predicate("   ").is_err());
        assert!(compile_predicate("\t\n").is_err());
    }

    #[test]
    fn principal_known_placeholders_compile() {
        let p = compile_predicate("owner_id = @principal.sub").expect("compiles");
        let mut expr = p.expr;
        let principal = principal_with("https://idp", "alice");
        substitute_placeholders(&mut expr, &principal);
        // After substitution there must be no @__turso_p_* / @__turso_c_*
        // variable nodes left.
        let mut found_placeholder = false;
        walk(&expr, &mut |e| {
            if let Expr::Variable(Variable { name: Some(n), .. }) = e {
                if n.starts_with(PRINCIPAL_PREFIX) || n.starts_with(CLAIM_PREFIX) {
                    found_placeholder = true;
                }
            }
        });
        assert!(!found_placeholder, "unsubstituted placeholder remains");
    }

    #[test]
    fn principal_unknown_field_rejected_at_compile() {
        let err = compile_predicate("owner_id = @principal.evil").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("@principal.evil") || msg.contains("unknown"),
            "expected unknown-placeholder error, got: {msg}"
        );
    }

    #[test]
    fn claim_namespace_separated_from_principal() {
        // A claim literally named "sub" must NOT be reachable via
        // @principal.sub — that placeholder always resolves to the Principal
        // struct's sub field. @claim.sub resolves to the claim map.
        let mut claims = BTreeMap::new();
        claims.insert("sub".to_string(), ClaimValue::String("CLAIM-SUB".into()));
        let p = Principal::new("https://idp", "STRUCT-SUB", vec![], claims, 0).unwrap();

        let mut e1 = compile_predicate("@principal.sub").unwrap().expr;
        substitute_placeholders(&mut e1, &p);
        let s1 = lit_string(&e1).expect("string literal");
        assert!(
            s1.contains("STRUCT-SUB"),
            "@principal.sub should resolve to struct, got: {s1}"
        );

        let mut e2 = compile_predicate("@claim.sub").unwrap().expr;
        substitute_placeholders(&mut e2, &p);
        let s2 = lit_string(&e2).expect("string literal");
        assert!(
            s2.contains("CLAIM-SUB"),
            "@claim.sub should resolve to claim map, got: {s2}"
        );
    }

    #[test]
    fn missing_claim_resolves_to_null_not_error() {
        let p = principal_with("https://idp", "alice");
        let mut e = compile_predicate("@claim.missing IS NULL").unwrap().expr;
        substitute_placeholders(&mut e, &p);
        // Predicate now starts as `Null IS NULL` which evaluates to true at
        // VDBE time. The structural check here is that no placeholder remains.
        let mut found = false;
        walk(&e, &mut |x| {
            if let Expr::Variable(Variable { name: Some(n), .. }) = x {
                if n.starts_with(PRINCIPAL_PREFIX) || n.starts_with(CLAIM_PREFIX) {
                    found = true;
                }
            }
        });
        assert!(!found);
    }

    #[test]
    fn raw_internal_placeholder_blocked() {
        // Operators must not be able to bypass the rewrite step by writing
        // the internal `@__turso_p_*` name directly.
        let err = compile_predicate("@__turso_p_evil = 1").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown placeholder") || msg.contains("@principal.evil"),
            "expected validator to reject raw internal placeholder, got: {msg}"
        );
    }

    fn lit_string(e: &Expr) -> Option<String> {
        if let Expr::Literal(ast::Literal::String(s)) = e {
            Some(s.to_string())
        } else {
            None
        }
    }
}
