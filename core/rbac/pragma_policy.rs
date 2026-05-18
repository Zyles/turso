//! PRAGMA classification table.
//!
//! Consulted by the translate-layer PRAGMA hook before falling through to the
//! grant lookup. The categories follow the plan §3:
//!
//! - **Introspection**: read-only schema/index/foreign-key introspection.
//!   Allowed for any authenticated principal.
//! - **Harmless**: connection-scope settings that don't affect data integrity
//!   (e.g. `busy_timeout`). Allowed for any authenticated principal.
//! - **AdminOnly**: connection-scope settings that affect durability/integrity
//!   for everyone on the shared connection. Only admin can flip them.
//! - **Dangerous**: enforcement-disabling PRAGMAs (`writable_schema`,
//!   `legacy_alter_table`). Hard-denied for everyone, including admin via SQL.
//!   Server start-time flags are the only way to set them.
//! - **SyncInternal**: sync-engine bookkeeping PRAGMAs. Admin only.

/// Classification of a PRAGMA. The `mutates` field on `AuthOp::Pragma` is
/// derived from this: `Introspection` and `Harmless` have `mutates=false`,
/// the rest have `mutates=true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PragmaClass {
    Introspection,
    Harmless,
    AdminOnly,
    Dangerous,
    SyncInternal,
    /// Unknown PRAGMA — treated as `AdminOnly` for safety, since unknown
    /// PRAGMAs could be vendor extensions with arbitrary effects.
    Unknown,
}

impl PragmaClass {
    pub fn is_mutating(self) -> bool {
        !matches!(self, PragmaClass::Introspection | PragmaClass::Harmless)
    }

    pub fn is_dangerous(self) -> bool {
        matches!(self, PragmaClass::Dangerous)
    }
}

/// Classify a PRAGMA name. Case-insensitive; whitespace is the caller's
/// problem.
pub fn classify(name: &str) -> PragmaClass {
    // ASCII-fold without allocating for the common case.
    let lower = name.trim().to_ascii_lowercase();
    match lower.as_str() {
        // Introspection — read-only.
        "table_info" | "table_xinfo" | "index_list" | "index_info" | "index_xinfo"
        | "foreign_key_list" | "foreign_key_check" | "database_list" | "function_list"
        | "module_list" | "pragma_list" | "collation_list" | "integrity_check" | "quick_check"
        | "schema_version" | "user_version" | "data_version" | "freelist_count" | "page_count"
        | "page_size" | "compile_options" | "encoding" | "stats" => PragmaClass::Introspection,

        // Harmless connection-scope.
        "busy_timeout"
        | "case_sensitive_like"
        | "count_changes"
        | "empty_result_callbacks"
        | "full_column_names"
        | "short_column_names"
        | "show_datatypes" => PragmaClass::Harmless,

        // Admin-only: behaviour-changing connection-scope. These flip
        // durability/integrity guarantees that the entire connection's
        // statement pipeline depends on.
        "foreign_keys"
        | "defer_foreign_keys"
        | "ignore_check_constraints"
        | "cache_size"
        | "cache_spill"
        | "journal_mode"
        | "journal_size_limit"
        | "synchronous"
        | "temp_store"
        | "auto_vacuum"
        | "incremental_vacuum"
        | "secure_delete"
        | "checkpoint_fullfsync"
        | "fullfsync"
        | "mmap_size"
        | "locking_mode"
        | "read_uncommitted"
        | "recursive_triggers"
        | "reverse_unordered_selects"
        | "trusted_schema"
        | "automatic_index" => PragmaClass::AdminOnly,

        // Dangerous — enforcement-disabling. Hard-deny for everyone via SQL.
        // SQLite's `writable_schema` lets you write `sqlite_schema` rows
        // directly, which is a backdoor into arbitrary schema corruption.
        // `legacy_alter_table` reverts to the pre-3.25 ALTER semantics where
        // referenced tables aren't updated, breaking foreign keys silently.
        "writable_schema" | "legacy_alter_table" | "legacy_file_format" => PragmaClass::Dangerous,

        // Sync-internal. CDC capture configuration, etc.
        "capture_data_changes_conn"
        | "capture_data_changes"
        | "wal_auto_actions"
        | "wal_auto_actions_disable" => PragmaClass::SyncInternal,

        // VDBE / debug. Admin only because they can perturb diagnostics
        // visible across the connection.
        "vdbe_trace" | "vdbe_listing" | "vdbe_debug" | "stmt_status" => PragmaClass::AdminOnly,

        _ => PragmaClass::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writable_schema_is_dangerous() {
        assert_eq!(classify("writable_schema"), PragmaClass::Dangerous);
        assert_eq!(classify("WRITABLE_SCHEMA"), PragmaClass::Dangerous);
    }

    #[test]
    fn table_info_is_introspection() {
        assert_eq!(classify("table_info"), PragmaClass::Introspection);
        assert!(!classify("table_info").is_mutating());
    }

    #[test]
    fn foreign_keys_is_admin_only() {
        assert_eq!(classify("foreign_keys"), PragmaClass::AdminOnly);
        assert!(classify("foreign_keys").is_mutating());
        assert!(!classify("foreign_keys").is_dangerous());
    }

    #[test]
    fn unknown_pragma_is_unknown() {
        assert_eq!(classify("xyzzy_made_up_pragma"), PragmaClass::Unknown);
        // Unknown is treated as mutating for safety.
        assert!(classify("xyzzy_made_up_pragma").is_mutating());
    }
}
