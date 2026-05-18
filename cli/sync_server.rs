use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use prost::Message;
use roaring::RoaringBitmap;
use tracing::{debug, error, info, warn};

use turso_core::auth::ConnectionAuthorizer;
use turso_core::rbac::{authorizer::RbacAuthorizer, GrantSet};
use turso_core::{Connection, Value as CoreValue};
use turso_sync_engine::server_proto::{
    BatchCond, BatchResult, BatchStep, BatchStreamReq, BatchStreamResp, Col, Error,
    ExecuteStreamReq, ExecuteStreamResp, PageData, PageSetRawEncodingProto, PageUpdatesEncodingReq,
    PipelineReqBody, PipelineRespBody, PullUpdatesReqProtoBody, PullUpdatesRespProtoBody, Row,
    StmtResult, StreamRequest, StreamResponse, StreamResult, Value,
};

use crate::sync_auth::{extract_bearer_token, JwtVerifier, RoleSource};

const WAL_FRAME_HEADER_SIZE: usize = 24;
const PAGE_SIZE: usize = 4096;

/// CORS allow-list. `None` falls back to the original wildcard `*` behaviour;
/// `Some(set)` echoes the request `Origin` only when it matches an entry,
/// otherwise omits the header (browser blocks).
type CorsAllowList = Option<HashSet<String>>;

pub struct TursoSyncServer {
    address: String,
    /// Shared request-serving connection. Permanently in `AuthMode::Anonymous`
    /// after `new` returns; transitions to `Authenticated` only inside a
    /// `with_principal` scope held by the request handler.
    conn: Arc<Mutex<Arc<Connection>>>,
    /// Bootstrap-only connection. Stays in `AuthMode::Trusted` for the
    /// lifetime of the server so admin-only RBAC table writes (TOFU
    /// promotion, Mode A role lookup) can run regardless of the
    /// requesting principal. Never serves a network request directly.
    bootstrap_conn: Arc<Mutex<Arc<Connection>>>,
    interrupt_count: Arc<AtomicUsize>,
    jwt: Arc<JwtVerifier>,
    cors_origins: CorsAllowList,
    /// Direct handle on the concrete authorizer so we can call
    /// `replace_grants` after RBAC-table writes. `set_authorizer` on the
    /// connection takes the same Arc as a trait object — both pointers stay
    /// referent-equal for the server lifetime.
    rbac_authorizer: Arc<RbacAuthorizer>,
}

impl TursoSyncServer {
    pub fn new(
        address: String,
        conn: Arc<Connection>,
        interrupt_count: Arc<AtomicUsize>,
        jwt: Arc<JwtVerifier>,
        cors_origins: CorsAllowList,
        initial_admin: Option<(String, String)>,
    ) -> Result<Self> {
        conn.wal_auto_actions_disable();

        // Phase 1: RBAC schema bootstrap on the still-Trusted shared
        // connection. Idempotent — re-running on a populated database is a
        // no-op via IF NOT EXISTS.
        run_rbac_bootstrap_sql(&conn)?;

        // Phase 2: optional pre-warmed admin. The operator can pass
        // --initial-admin-iss-sub or TURSO_SYNC_INITIAL_ADMIN_ISS_SUB to
        // skip TOFU; the first valid token for that (iss,sub) starts as
        // admin, every other principal default-denies until an admin grants
        // them something.
        if let Some((iss, sub)) = &initial_admin {
            run_admin_promotion_sql(&conn, iss, sub)?;
            warn!(
                "[rbac] pre-warmed admin grant present iss=\"{}\" sub=\"{}\"",
                iss, sub
            );
        }

        // Phase 3: install the authorizer and downgrade the shared
        // connection to Anonymous. The authorizer holds the GrantSet behind
        // an `ArcSwap` so we can hot-reload it after admin writes to the
        // RBAC tables (including the TOFU promotion that happens on first
        // auth). We keep our own typed `Arc<RbacAuthorizer>` so
        // `replace_grants` is reachable; the connection holds the same Arc
        // as a `dyn ConnectionAuthorizer` trait object.
        let initial_grants = load_grants(&conn)?;
        let rbac_authorizer = Arc::new(RbacAuthorizer::new(
            initial_grants,
            matches!(jwt.role_source(), RoleSource::Jwt),
        ));
        let trait_obj: Arc<dyn ConnectionAuthorizer> = rbac_authorizer.clone();
        conn.set_authorizer(trait_obj);

        // Phase 4: open a permanent bootstrap connection that stays Trusted
        // and downgrade the shared one. After this, the shared connection
        // cannot do admin-only writes through SQL; TOFU and grant lookups
        // ride the bootstrap connection.
        let bootstrap_conn = conn.database().connect()?;
        bootstrap_conn.wal_auto_actions_disable();
        conn.downgrade_to_anonymous();

        Ok(Self {
            address,
            conn: Arc::new(Mutex::new(conn)),
            bootstrap_conn: Arc::new(Mutex::new(bootstrap_conn)),
            interrupt_count,
            jwt,
            cors_origins,
            rbac_authorizer,
        })
    }

    pub fn run(&self) -> Result<()> {
        info!("Starting TursoSyncServer on {}", self.address);

        let listener = TcpListener::bind(&self.address)?;
        listener.set_nonblocking(true)?;

        let interrupt_count = self.interrupt_count.clone();
        let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_flag_clone = shutdown_flag.clone();

        let monitor_handle = thread::spawn(move || loop {
            if interrupt_count.load(Ordering::SeqCst) > 0 {
                debug!("Interrupt detected, signaling shutdown");
                shutdown_flag_clone.store(true, Ordering::SeqCst);
                break;
            }
            thread::sleep(std::time::Duration::from_millis(100));
        });

        loop {
            if shutdown_flag.load(Ordering::SeqCst) {
                info!("Shutdown signal received, stopping server");
                break;
            }

            match listener.accept() {
                Ok((stream, addr)) => {
                    info!("Accepted connection from {}", addr);
                    if let Err(e) = self.handle_connection(stream) {
                        error!("Error handling connection: {}", e);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }

        let _ = monitor_handle.join();
        info!("TursoSyncServer stopped");
        Ok(())
    }

    fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;

        let mut buffer = [0u8; 8192];
        let mut request_data = Vec::new();

        loop {
            let n = stream.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            request_data.extend_from_slice(&buffer[..n]);

            if let Some(header_end) = find_header_end(&request_data) {
                let headers = String::from_utf8_lossy(&request_data[..header_end]);
                if let Some(content_length) = parse_content_length(&headers) {
                    let body_start = header_end + 4;
                    let total_expected = body_start + content_length;
                    while request_data.len() < total_expected {
                        let n = stream.read(&mut buffer)?;
                        if n == 0 {
                            break;
                        }
                        request_data.extend_from_slice(&buffer[..n]);
                    }
                }
                break;
            }
        }

        let (method, path, headers, body) = parse_http_request(&request_data)?;
        info!("Request: {} {}", method, path);
        let origin = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("origin"))
            .map(|(_, v)| v.clone());

        // OPTIONS preflight is unauthenticated by design — browsers send it
        // before the real request without `Authorization`, and refusing it
        // would break every CORS-enabled client.
        let response = if method == "OPTIONS" {
            Ok(HttpResponse {
                status: 204,
                content_type: "text/plain".to_string(),
                body: Vec::new(),
                headers: vec![],
            })
        } else {
            // Authenticate. Failure → 401 with WWW-Authenticate: Bearer.
            // We DO NOT log the bearer token value here or anywhere; only
            // the principal's iss/sub appear in subsequent traces.
            let auth_result = self.authenticate(&headers);
            match auth_result {
                Ok(principal) => match (method.as_str(), path.as_str()) {
                    ("POST", "/v2/pipeline") => self.handle_pipeline_authn(&principal, &body),
                    ("POST", "/pull-updates") => {
                        // Pull is JWT-valid is sufficient. No further authz.
                        // The client receives raw WAL pages, which the plan
                        // (§6) explicitly leaves unauthorized.
                        debug!(
                            "[rbac] pull-updates iss={} sub={}",
                            principal.iss, principal.sub
                        );
                        self.handle_pull_updates(&body)
                    }
                    _ => Ok(HttpResponse {
                        status: 404,
                        content_type: "text/plain".to_string(),
                        body: b"Not Found".to_vec(),
                        headers: vec![],
                    }),
                },
                Err(e) => {
                    // Don't echo the failure detail to the client; that would
                    // help an attacker enumerate which check fired.
                    debug!("[rbac] auth failure: {e}");
                    Ok(HttpResponse {
                        status: 401,
                        content_type: "text/plain".to_string(),
                        body: b"Unauthorized".to_vec(),
                        headers: vec![],
                    })
                }
            }
        };

        let mut http_response = match response {
            Ok(resp) => resp,
            Err(e) => {
                error!("Request error: {}", e);
                HttpResponse {
                    status: 500,
                    content_type: "text/plain".to_string(),
                    body: format!("Internal Server Error: {e}").into_bytes(),
                    headers: vec![],
                }
            }
        };

        // 401s must include the WWW-Authenticate header to be a spec-correct
        // Bearer challenge.
        if http_response.status == 401 {
            http_response.headers.push((
                "WWW-Authenticate".to_string(),
                "Bearer error=\"invalid_token\"".to_string(),
            ));
        }

        let response_bytes =
            format_http_response(&http_response, &self.cors_origins, origin.as_deref());
        stream.write_all(&response_bytes)?;
        stream.flush()?;

        Ok(())
    }

    /// JWT verification + Mode A role lookup + TOFU admin promotion.
    /// Returns the fully-populated `Principal` ready for `with_principal`.
    fn authenticate(
        &self,
        headers: &BTreeMap<String, String>,
    ) -> Result<turso_core::auth::Principal> {
        let token = extract_bearer_token(headers)
            .ok_or_else(|| anyhow!("missing Authorization: Bearer header"))?;
        let mut principal = self.jwt.verify(token)?;

        // Mode A: populate principal.roles from _turso_rbac_role_assignments.
        // Mode B already has them from the JWT.
        if matches!(self.jwt.role_source(), RoleSource::Table) {
            let boot = self.bootstrap_conn.lock().unwrap();
            principal.roles = load_roles_for(&boot, &principal.iss, &principal.sub)?;
        }

        // TOFU: idempotent atomic "first auth becomes admin". Race-safe via
        // BEGIN IMMEDIATE serialization inside `run_admin_promotion_sql`.
        // Subsequent authentications no-op because the WHERE NOT EXISTS
        // guard sees the existing admin row.
        let promoted = {
            let boot = self.bootstrap_conn.lock().unwrap();
            let admin_existed_before = admin_grant_exists(&boot)?;
            run_admin_promotion_sql(&boot, &principal.iss, &principal.sub)?;
            !admin_existed_before
        };
        if promoted {
            warn!(
                "[rbac] bootstrap admin promoted iss=\"{}\" sub=\"{}\" \
                 — verify this matches the operator's identity",
                principal.iss, principal.sub
            );
            // Hot-reload the authorizer's GrantSet so the brand-new admin's
            // `(sub, *, *)` grant is visible on the very first statement.
            // Per plan §8: "The principal that just promoted itself sees
            // admin grants on its very first real statement." Without this
            // reload the authorizer's snapshot stays at the boot-time empty
            // GrantSet and TOFU admin can do DDL (via role) but can't write
            // user tables.
            self.reload_grants()?;
            if matches!(self.jwt.role_source(), RoleSource::Table) {
                let boot = self.bootstrap_conn.lock().unwrap();
                principal.roles = load_roles_for(&boot, &principal.iss, &principal.sub)?;
            }
        }

        Ok(principal)
    }

    /// Reload the authorizer's GrantSet from the (post-write) database
    /// state. Cheap enough to do per-RBAC-table-write but we don't want it
    /// running on every request — call only after an operation that could
    /// have changed grants.
    fn reload_grants(&self) -> Result<()> {
        let new_grants = {
            let boot = self.bootstrap_conn.lock().unwrap();
            load_grants(&boot)?
        };
        self.rbac_authorizer.replace_grants(new_grants);
        Ok(())
    }

    fn handle_pipeline_authn(
        &self,
        principal: &turso_core::auth::Principal,
        body: &[u8],
    ) -> Result<HttpResponse> {
        let req: PipelineReqBody = serde_json::from_slice(body)
            .map_err(|e| anyhow!("Failed to parse pipeline request: {}", e))?;

        // Track whether the request touched RBAC tables. If it did, we
        // hot-reload the authorizer's GrantSet at the end so the next
        // request (potentially the same principal granting another user)
        // sees the new policy without a server restart.
        let mut touched_rbac_tables = false;

        let conn = self.conn.lock().unwrap();
        let _guard = conn.with_principal(Arc::new(principal.clone()));

        let mut results = Vec::new();
        for request in req.requests {
            let result = match &request {
                StreamRequest::Execute(exec_req) => {
                    if let Some(sql) = exec_req.stmt.sql.as_deref() {
                        if sql_touches_rbac_tables(sql) {
                            touched_rbac_tables = true;
                        }
                    }
                    self.execute_statement(&conn, exec_req)
                }
                StreamRequest::Batch(batch_req) => {
                    for step in &batch_req.batch.steps {
                        if let Some(sql) = step.stmt.sql.as_deref() {
                            if sql_touches_rbac_tables(sql) {
                                touched_rbac_tables = true;
                            }
                        }
                    }
                    self.execute_batch(&conn, batch_req)
                }
                StreamRequest::None => StreamResult::Error {
                    error: Error {
                        message: "Unknown request type".to_string(),
                        code: "UNKNOWN".to_string(),
                    },
                },
            };
            results.push(result);
        }

        // Drop the principal guard so the connection returns to Anonymous
        // before we reload — the reload itself happens via the bootstrap
        // connection and is unaffected, but discipline matters.
        drop(_guard);
        if touched_rbac_tables {
            if let Err(e) = self.reload_grants() {
                error!("[rbac] failed to reload grants after admin write: {e}");
            }
        }

        let resp = PipelineRespBody {
            baton: req.baton,
            base_url: None,
            results,
        };
        let body = serde_json::to_vec(&resp)?;
        Ok(HttpResponse {
            status: 200,
            content_type: "application/json".to_string(),
            body,
            headers: vec![],
        })
    }

    fn execute_statement(&self, conn: &Arc<Connection>, req: &ExecuteStreamReq) -> StreamResult {
        let sql = match &req.stmt.sql {
            Some(s) => s.clone(),
            None => {
                return StreamResult::Error {
                    error: Error {
                        message: "No SQL provided".to_string(),
                        code: "NO_SQL".to_string(),
                    },
                }
            }
        };

        debug!("Executing SQL: {}", sql);

        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to prepare statement: {}", e);
                return StreamResult::Error {
                    error: Error {
                        message: e.to_string(),
                        code: "PREPARE_ERROR".to_string(),
                    },
                };
            }
        };

        for (i, arg) in req.stmt.args.iter().enumerate() {
            let core_value = convert_value_to_core(arg);
            stmt.bind_at(std::num::NonZero::new(i + 1).unwrap(), core_value);
        }

        let want_rows = req.stmt.want_rows.unwrap_or(true);

        if want_rows {
            match stmt.run_collect_rows() {
                Ok(rows) => {
                    let cols: Vec<Col> = (0..stmt.num_columns())
                        .map(|i| Col {
                            name: Some(stmt.get_column_name(i).to_string()),
                            decltype: stmt.get_column_decltype(i),
                        })
                        .collect();

                    let result_rows: Vec<Row> = rows
                        .into_iter()
                        .map(|row| Row {
                            values: row.into_iter().map(convert_core_to_value).collect(),
                        })
                        .collect();

                    StreamResult::Ok {
                        response: StreamResponse::Execute(ExecuteStreamResp {
                            result: StmtResult {
                                cols,
                                rows: result_rows,
                                affected_row_count: 0,
                                last_insert_rowid: None,
                                replication_index: None,
                                rows_read: 0,
                                rows_written: 0,
                                query_duration_ms: 0.0,
                            },
                        }),
                    }
                }
                Err(e) => {
                    error!("Failed to execute statement: {}", e);
                    StreamResult::Error {
                        error: Error {
                            message: e.to_string(),
                            code: "EXECUTE_ERROR".to_string(),
                        },
                    }
                }
            }
        } else {
            match stmt.run_ignore_rows() {
                Ok(()) => StreamResult::Ok {
                    response: StreamResponse::Execute(ExecuteStreamResp {
                        result: StmtResult {
                            cols: vec![],
                            rows: vec![],
                            affected_row_count: 0,
                            last_insert_rowid: None,
                            replication_index: None,
                            rows_read: 0,
                            rows_written: 0,
                            query_duration_ms: 0.0,
                        },
                    }),
                },
                Err(e) => {
                    error!("Failed to execute statement: {}", e);
                    StreamResult::Error {
                        error: Error {
                            message: e.to_string(),
                            code: "EXECUTE_ERROR".to_string(),
                        },
                    }
                }
            }
        }
    }

    fn execute_batch(&self, conn: &Arc<Connection>, req: &BatchStreamReq) -> StreamResult {
        let batch = &req.batch;
        let mut step_results: Vec<Option<StmtResult>> = Vec::with_capacity(batch.steps.len());
        let mut step_errors: Vec<Option<Error>> = Vec::with_capacity(batch.steps.len());
        // RBAC: track whether ANY step was denied. The original behavior
        // recorded per-step errors but kept executing — and since the
        // batch's final COMMIT had `condition: None`, the transaction
        // committed every other step. That's an open hole for an RBAC
        // system because a batch with one denied write would silently
        // partial-commit the rest.
        let mut denied = false;

        for (step_idx, step) in batch.steps.iter().enumerate() {
            if denied {
                // Skip the rest of the batch — preparing them just re-runs
                // the authorizer. We still push None placeholders so the
                // client's step-error indexing stays consistent.
                step_results.push(None);
                step_errors.push(None);
                continue;
            }

            let should_execute = match &step.condition {
                None => true,
                Some(cond) => Self::evaluate_condition(cond, &step_results, &step_errors, conn),
            };

            if should_execute {
                let result = self.execute_batch_step(conn, step);
                match result {
                    Ok(stmt_result) => {
                        step_results.push(Some(stmt_result));
                        step_errors.push(None);
                    }
                    Err(e) => {
                        let is_authz_denied = e
                            .downcast_ref::<turso_core::LimboError>()
                            .map(|le| matches!(le, turso_core::LimboError::AuthorizationDenied(_)))
                            .unwrap_or_else(|| {
                                // Fall back to substring matching when the
                                // error chain has been wrapped: the
                                // discriminant prefix is fixed
                                // ("Authorization denied").
                                e.to_string().starts_with("Authorization denied")
                            });
                        let code = if is_authz_denied {
                            denied = true;
                            "AUTHORIZATION_DENIED"
                        } else {
                            "BATCH_STEP_ERROR"
                        };
                        error!("Batch step {} failed ({}): {}", step_idx, code, e);
                        step_results.push(None);
                        step_errors.push(Some(Error {
                            message: e.to_string(),
                            code: code.to_string(),
                        }));
                    }
                }
            } else {
                step_results.push(None);
                step_errors.push(None);
            }
        }

        if denied {
            // Force ROLLBACK regardless of whether the batch already
            // executed a COMMIT step. The PrincipalGuard's Drop will also
            // attempt rollback at end-of-request, but explicit rollback
            // here lets us return the in-progress state to the client.
            if let Err(e) = conn
                .prepare("ROLLBACK")
                .and_then(|mut s| s.run_ignore_rows())
            {
                error!("Forced ROLLBACK after authz denial failed: {e}");
            }
        }

        StreamResult::Ok {
            response: StreamResponse::Batch(BatchStreamResp {
                result: BatchResult {
                    step_results,
                    step_errors,
                    replication_index: None,
                },
            }),
        }
    }

    fn evaluate_condition(
        cond: &BatchCond,
        step_results: &[Option<StmtResult>],
        step_errors: &[Option<Error>],
        conn: &Arc<Connection>,
    ) -> bool {
        match cond {
            BatchCond::None => true,
            BatchCond::Ok { step } => {
                let idx = *step as usize;
                idx < step_results.len() && step_results[idx].is_some()
            }
            BatchCond::Error { step } => {
                let idx = *step as usize;
                idx < step_errors.len() && step_errors[idx].is_some()
            }
            BatchCond::Not { cond } => {
                !Self::evaluate_condition(cond, step_results, step_errors, conn)
            }
            BatchCond::And(list) => list
                .conds
                .iter()
                .all(|c| Self::evaluate_condition(c, step_results, step_errors, conn)),
            BatchCond::Or(list) => list
                .conds
                .iter()
                .any(|c| Self::evaluate_condition(c, step_results, step_errors, conn)),
            BatchCond::IsAutocommit {} => conn.get_auto_commit(),
        }
    }

    fn execute_batch_step(&self, conn: &Arc<Connection>, step: &BatchStep) -> Result<StmtResult> {
        let sql = step
            .stmt
            .sql
            .as_ref()
            .ok_or_else(|| anyhow!("No SQL in batch step"))?;

        debug!("Executing batch step SQL: {}", sql);

        let mut stmt = conn.prepare(sql)?;

        for (i, arg) in step.stmt.args.iter().enumerate() {
            let core_value = convert_value_to_core(arg);
            stmt.bind_at(std::num::NonZero::new(i + 1).unwrap(), core_value);
        }

        let want_rows = step.stmt.want_rows.unwrap_or(true);

        if want_rows {
            let rows = stmt.run_collect_rows()?;

            let cols: Vec<Col> = (0..stmt.num_columns())
                .map(|i| Col {
                    name: Some(stmt.get_column_name(i).to_string()),
                    decltype: stmt.get_column_decltype(i),
                })
                .collect();

            let result_rows: Vec<Row> = rows
                .into_iter()
                .map(|row| Row {
                    values: row.into_iter().map(convert_core_to_value).collect(),
                })
                .collect();

            Ok(StmtResult {
                cols,
                rows: result_rows,
                affected_row_count: 0,
                last_insert_rowid: None,
                replication_index: None,
                rows_read: 0,
                rows_written: 0,
                query_duration_ms: 0.0,
            })
        } else {
            stmt.run_ignore_rows()?;
            Ok(StmtResult {
                cols: vec![],
                rows: vec![],
                affected_row_count: 0,
                last_insert_rowid: None,
                replication_index: None,
                rows_read: 0,
                rows_written: 0,
                query_duration_ms: 0.0,
            })
        }
    }

    fn handle_pull_updates(&self, body: &[u8]) -> Result<HttpResponse> {
        let req = <PullUpdatesReqProtoBody as Message>::decode(body)
            .map_err(|e| anyhow!("Failed to decode PullUpdatesRequest: {}", e))?;

        debug!(
            "Pull updates request: server_revision={}, client_revision={}",
            req.server_revision, req.client_revision
        );

        let encoding =
            PageUpdatesEncodingReq::try_from(req.encoding).unwrap_or(PageUpdatesEncodingReq::Raw);

        if encoding == PageUpdatesEncodingReq::Zstd {
            return Err(anyhow!("Zstd encoding is not supported"));
        }

        let conn = self.conn.lock().unwrap();

        let wal_state = conn.wal_state()?;
        debug!("WAL state: max_frame={}", wal_state.max_frame);

        let server_revision: u64 = if req.server_revision.is_empty() {
            wal_state.max_frame
        } else {
            req.server_revision.parse().unwrap_or(wal_state.max_frame)
        };

        let client_revision: u64 = if req.client_revision.is_empty() {
            0
        } else {
            req.client_revision.parse().unwrap_or(0)
        };

        debug!(
            "Using server_revision={}, client_revision={}",
            server_revision, client_revision
        );

        let pages_selector: Option<RoaringBitmap> = if !req.server_pages_selector.is_empty() {
            Some(
                RoaringBitmap::deserialize_from(&req.server_pages_selector[..])
                    .map_err(|e| anyhow!("Failed to parse server_pages_selector: {}", e))?,
            )
        } else {
            None
        };

        let mut seen_pages: HashSet<u32> = HashSet::new();
        let mut pages_to_send: Vec<(u32, Vec<u8>)> = Vec::new();

        let frame_size = WAL_FRAME_HEADER_SIZE + PAGE_SIZE;
        let mut frame_buffer = vec![0u8; frame_size];

        debug!(
            "pull-updates: scanning WAL frames {}..={} (client_revision={}, server_revision={})",
            client_revision + 1,
            server_revision,
            client_revision,
            server_revision
        );

        if server_revision > client_revision {
            for frame_no in (client_revision + 1..=server_revision).rev() {
                let frame_info = conn.wal_get_frame(frame_no, &mut frame_buffer)?;

                let page_no = frame_info.page_no;
                // WAL uses 1-based page numbers, sync protocol uses 0-based
                let page_id = page_no - 1;

                if seen_pages.contains(&page_no) {
                    continue;
                }

                if let Some(ref selector) = pages_selector {
                    if !selector.contains(page_id) {
                        continue;
                    }
                }

                seen_pages.insert(page_no);

                let type_byte = frame_buffer[WAL_FRAME_HEADER_SIZE];
                debug!(
                    "pull-updates: including page_no={}, frame_no={}, type_byte={}, db_size={}",
                    page_no, frame_no, type_byte, frame_info.db_size
                );

                let page_data = frame_buffer[WAL_FRAME_HEADER_SIZE..].to_vec();
                pages_to_send.push((page_id, page_data));
            }
        }

        debug!(
            "pull-updates: sending {} pages, seen_pages={:?}",
            pages_to_send.len(),
            seen_pages
        );
        pages_to_send.reverse();

        let db_size = if wal_state.max_frame > 0 {
            let mut last_frame = vec![0u8; frame_size];
            let last_info = conn.wal_get_frame(wal_state.max_frame, &mut last_frame)?;
            last_info.db_size as u64
        } else {
            0
        };

        let header = PullUpdatesRespProtoBody {
            server_revision: server_revision.to_string(),
            db_size,
            raw_encoding: Some(PageSetRawEncodingProto {}),
            zstd_encoding: None,
        };

        let mut response_body = Vec::new();

        let header_bytes = header.encode_to_vec();
        encode_length_delimited(&mut response_body, &header_bytes);

        for (page_id, page_data) in pages_to_send {
            let page_msg = PageData {
                page_id: page_id as u64,
                encoded_page: Bytes::from(page_data),
            };
            let page_bytes = page_msg.encode_to_vec();
            encode_length_delimited(&mut response_body, &page_bytes);
        }

        debug!(
            "Sending {} bytes in pull-updates response",
            response_body.len()
        );

        Ok(HttpResponse {
            status: 200,
            content_type: "application/protobuf".to_string(),
            body: response_body,
            headers: vec![],
        })
    }
}

struct HttpResponse {
    status: u16,
    content_type: String,
    body: Vec<u8>,
    /// Extra response headers (e.g. `WWW-Authenticate` on 401). Each entry
    /// is `(name, value)`; names are emitted verbatim, so callers MUST NOT
    /// stash user-controlled data here.
    headers: Vec<(String, String)>,
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    (0..data.len().saturating_sub(3)).find(|&i| &data[i..i + 4] == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            let value = line.split(':').nth(1)?.trim();
            return value.parse().ok();
        }
    }
    None
}

/// HTTP request decomposition: `(method, path, headers, body)`. Header names
/// are preserved in their on-the-wire casing for tracing; callers must do a
/// case-insensitive lookup because RFC 7230 says header names are
/// case-insensitive.
type ParsedRequest = (String, String, BTreeMap<String, String>, Vec<u8>);

fn parse_http_request(data: &[u8]) -> Result<ParsedRequest> {
    let header_end = find_header_end(data).ok_or_else(|| anyhow!("Invalid HTTP request"))?;
    let headers_str = String::from_utf8_lossy(&data[..header_end]);

    let mut lines = headers_str.lines();
    let first_line = lines.next().ok_or_else(|| anyhow!("Empty request"))?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        return Err(anyhow!("Invalid request line"));
    }

    let method = parts[0].to_string();
    let path = parts[1].to_string();
    let body = data[header_end + 4..].to_vec();

    // Parse header lines into a name->value map. Names are normalized to
    // their on-the-wire form for tracing; lookups are case-insensitive at
    // call sites because RFC 7230 says they must be.
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_string();
            let value = line[colon + 1..].trim().to_string();
            if !name.is_empty() {
                headers.insert(name, value);
            }
        }
    }

    Ok((method, path, headers, body))
}

fn format_http_response(
    resp: &HttpResponse,
    cors_origins: &CorsAllowList,
    request_origin: Option<&str>,
) -> Vec<u8> {
    let status_text = match resp.status {
        200 => "OK",
        204 => "No Content",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    };

    let mut header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        resp.status,
        status_text,
        resp.content_type,
        resp.body.len()
    );

    // CORS. Bearer auth + Allow-Credentials: false makes the wildcard origin
    // spec-safe (tokens don't auto-attach cross-origin). For operators who
    // want a tighter policy, set TURSO_SYNC_CORS_ORIGINS to an allow-list.
    match pick_cors_origin(cors_origins, request_origin) {
        CorsOriginDecision::Wildcard => {
            header.push_str("Access-Control-Allow-Origin: *\r\n");
        }
        CorsOriginDecision::Echo(o) => {
            header.push_str(&format!("Access-Control-Allow-Origin: {o}\r\n"));
            header.push_str("Vary: Origin\r\n");
        }
        CorsOriginDecision::Omit => {
            // No Allow-Origin → browser blocks. Still emit Vary so caches
            // don't merge responses from different origins.
            header.push_str("Vary: Origin\r\n");
        }
    }
    header.push_str("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
    header.push_str("Access-Control-Allow-Headers: Content-Type, Authorization\r\n");
    header.push_str("Access-Control-Expose-Headers: *\r\n");

    for (name, value) in &resp.headers {
        header.push_str(&format!("{name}: {value}\r\n"));
    }
    header.push_str("\r\n");

    let mut result = header.into_bytes();
    result.extend_from_slice(&resp.body);
    result
}

fn encode_length_delimited(output: &mut Vec<u8>, data: &[u8]) {
    let mut len = data.len();
    while len >= 0x80 {
        output.push((len as u8) | 0x80);
        len >>= 7;
    }
    output.push(len as u8);
    output.extend_from_slice(data);
}

fn convert_value_to_core(value: &Value) -> CoreValue {
    match value {
        Value::None | Value::Null => CoreValue::Null,
        Value::Integer { value } => CoreValue::from_i64(*value),
        Value::Float { value } => CoreValue::from_f64(*value),
        Value::Text { value } => CoreValue::Text(turso_core::types::Text {
            value: std::borrow::Cow::Owned(value.clone()),
            subtype: turso_core::types::TextSubtype::Text,
        }),
        Value::Blob { value } => CoreValue::Blob(value.to_vec()),
    }
}

fn convert_core_to_value(value: CoreValue) -> Value {
    match value {
        CoreValue::Null => Value::Null,
        CoreValue::Numeric(turso_core::Numeric::Integer(v)) => Value::Integer { value: v },
        CoreValue::Numeric(turso_core::Numeric::Float(v)) => Value::Float {
            value: f64::from(v),
        },
        CoreValue::Text(t) => Value::Text {
            value: t.value.to_string(),
        },
        CoreValue::Blob(b) => Value::Blob {
            value: Bytes::from(b),
        },
    }
}

// ---------------------------------------------------------------------------
// RBAC bootstrap & helpers
// ---------------------------------------------------------------------------

/// Run the RBAC schema bootstrap on a Trusted connection. Idempotent.
fn run_rbac_bootstrap_sql(conn: &Arc<Connection>) -> Result<()> {
    turso_core::rbac::apply_bootstrap(conn).map_err(|e| anyhow!("{e}"))
}

/// Insert an admin grant + role assignment for `(iss, sub)` if no admin
/// exists yet. Idempotent and race-safe under BEGIN IMMEDIATE.
fn run_admin_promotion_sql(conn: &Arc<Connection>, iss: &str, sub: &str) -> Result<()> {
    let now = now_unix();
    let stmts = vec![
        "BEGIN IMMEDIATE".to_string(),
        format!(
            "INSERT INTO _turso_rbac_grants \
             (grantee_kind, grantee_iss, grantee, table_name, op, columns_json, \
              using_expr, check_expr, created_at) \
             SELECT 'sub', {iss}, {sub}, '*', '*', NULL, NULL, NULL, {now} \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM _turso_rbac_grants \
                 WHERE grantee_kind = 'sub' AND op IN ('*', 'DDL') \
                   AND table_name = '*' \
             )",
            iss = sql_quote(iss),
            sub = sql_quote(sub),
            now = now
        ),
        format!(
            "INSERT INTO _turso_rbac_role_assignments (iss, sub, role, created_at) \
             SELECT {iss}, {sub}, 'admin', {now} \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM _turso_rbac_role_assignments WHERE role = 'admin' \
             )",
            iss = sql_quote(iss),
            sub = sql_quote(sub),
            now = now
        ),
        "COMMIT".to_string(),
    ];

    for stmt in stmts {
        if let Err(e) = conn
            .prepare(&stmt)
            .and_then(|mut s| s.run_ignore_rows().map(|_| ()))
        {
            // On failure, attempt to clean up any open transaction.
            let _ = conn
                .prepare("ROLLBACK")
                .and_then(|mut s| s.run_ignore_rows());
            return Err(anyhow!("admin promotion SQL failed for {stmt:?}: {e}"));
        }
    }
    Ok(())
}

/// Load the current grants table snapshot into a `GrantSet`. Called on
/// server start and after each TOFU promotion so the authorizer sees fresh
/// admin grants without a full server restart.
fn load_grants(conn: &Arc<Connection>) -> Result<GrantSet> {
    let mut stmt = conn
        .prepare(
            "SELECT grantee_kind, grantee_iss, grantee, table_name, op, \
                    columns_json, using_expr, check_expr \
             FROM _turso_rbac_grants",
        )
        .map_err(|e| anyhow!("grant load prepare failed: {e}"))?;
    let rows = stmt
        .run_collect_rows()
        .map_err(|e| anyhow!("grant load execute failed: {e}"))?;

    let mut grant_set = GrantSet::default();
    for row in rows {
        if row.len() < 8 {
            continue;
        }
        let s = |v: &CoreValue| match v {
            CoreValue::Text(t) => Some(t.value.to_string()),
            CoreValue::Null => None,
            _ => None,
        };
        let kind = s(&row[0]).unwrap_or_default();
        let iss = s(&row[1]).unwrap_or_default();
        let grantee = s(&row[2]).unwrap_or_default();
        let table = s(&row[3]).unwrap_or_default();
        let op = s(&row[4]).unwrap_or_default();
        let cols = s(&row[5]);
        let using_expr = s(&row[6]);
        let check_expr = s(&row[7]);

        match turso_core::rbac::compile_row(
            &kind,
            &iss,
            &grantee,
            &table,
            &op,
            cols.as_deref(),
            using_expr.as_deref(),
            check_expr.as_deref(),
        ) {
            Ok(g) => grant_set.push(g),
            Err(e) => {
                error!("[rbac] skipping malformed grant on load: {e}");
            }
        }
    }
    Ok(grant_set)
}

/// Cheap heuristic: does this SQL string reference one of the RBAC policy
/// tables? Used by the request handler to decide whether to hot-reload the
/// authorizer's GrantSet after dispatch. False positives are acceptable (a
/// reload that finds no new rows is cheap); false negatives are NOT — they
/// would let a grant change go unnoticed until restart.
///
/// We deliberately avoid parsing the SQL — a substring match is robust
/// across statement shapes (INSERT, UPDATE, DELETE, MERGE, CREATE TRIGGER
/// AS SELECT, etc.) and the false-positive cost is one extra grant table
/// scan. Case-insensitive because table names in SQL are.
fn sql_touches_rbac_tables(sql: &str) -> bool {
    let lower = sql.to_ascii_lowercase();
    lower.contains("_turso_rbac_grants") || lower.contains("_turso_rbac_role_assignments")
}

/// Return true if there is already at least one principal with the `admin`
/// role in `_turso_rbac_role_assignments`. Used by TOFU to decide whether
/// the current request is the bootstrap (no admin yet) or a regular login.
fn admin_grant_exists(conn: &Arc<Connection>) -> Result<bool> {
    let mut stmt = conn
        .prepare("SELECT 1 FROM _turso_rbac_role_assignments WHERE role = 'admin' LIMIT 1")
        .map_err(|e| anyhow!("admin existence check prepare failed: {e}"))?;
    let rows = stmt
        .run_collect_rows()
        .map_err(|e| anyhow!("admin existence check execute failed: {e}"))?;
    Ok(!rows.is_empty())
}

/// Look up Mode A roles for a (iss, sub). Returns an empty vec if the role
/// assignments table is empty for this principal.
fn load_roles_for(conn: &Arc<Connection>, iss: &str, sub: &str) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT role FROM _turso_rbac_role_assignments WHERE iss = ? AND sub = ?")
        .map_err(|e| anyhow!("role lookup prepare failed: {e}"))?;
    stmt.bind_at(
        std::num::NonZero::new(1).unwrap(),
        CoreValue::Text(turso_core::types::Text::new(iss.to_string())),
    );
    stmt.bind_at(
        std::num::NonZero::new(2).unwrap(),
        CoreValue::Text(turso_core::types::Text::new(sub.to_string())),
    );
    let rows = stmt
        .run_collect_rows()
        .map_err(|e| anyhow!("role lookup execute failed: {e}"))?;
    let mut roles = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(CoreValue::Text(t)) = row.first() {
            roles.push(t.value.to_string());
        }
    }
    Ok(roles)
}

fn sql_quote(s: &str) -> String {
    let escaped = s.replace('\'', "''");
    format!("'{escaped}'")
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Decide which (if any) Origin to echo back. Returns `Some(&str)` to echo,
/// `None` to omit (browser blocks), or — for the wildcard default — the
/// caller emits `*`.
fn pick_cors_origin<'a>(
    allow_list: &CorsAllowList,
    request_origin: Option<&'a str>,
) -> CorsOriginDecision<'a> {
    match (allow_list, request_origin) {
        (None, _) => CorsOriginDecision::Wildcard,
        (Some(set), Some(origin)) if set.contains(origin) => CorsOriginDecision::Echo(origin),
        (Some(_), _) => CorsOriginDecision::Omit,
    }
}

enum CorsOriginDecision<'a> {
    Wildcard,
    Echo(&'a str),
    Omit,
}
