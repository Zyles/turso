#![allow(clippy::arc_with_non_send_sync)]
mod app;
mod commands;
mod config;
mod helper;
mod input;
mod manual;
mod mcp_server;
mod opcodes_dictionary;
mod read_state_machine;
mod sync_auth;
mod sync_server;

#[cfg(feature = "mvcc_repl")]
mod mvcc_repl;

use config::CONFIG_DIR;
use mcp_server::TursoMcpServer;
use rustyline::{error::ReadlineError, Config, Editor};
use std::{
    path::PathBuf,
    sync::{atomic::Ordering, LazyLock},
};

use crate::sync_server::TursoSyncServer;

#[cfg(all(feature = "mimalloc", not(target_family = "wasm"), not(miri)))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn rustyline_config() -> Config {
    Config::builder()
        .completion_type(rustyline::CompletionType::List)
        .auto_add_history(true)
        .build()
}

pub static HOME_DIR: LazyLock<PathBuf> =
    LazyLock::new(|| dirs::home_dir().expect("Could not determine home directory"));

pub static HISTORY_FILE: LazyLock<PathBuf> = LazyLock::new(|| HOME_DIR.join(".limbo_history"));

fn run_mcp_server(app: app::Limbo) -> anyhow::Result<()> {
    let conn = app.get_connection();
    let interrupt_count = app.get_interrupt_count();
    let mcp_server = TursoMcpServer::new(conn, interrupt_count);

    mcp_server.run()
}

fn run_sync_server(app: app::Limbo) -> anyhow::Result<()> {
    let address = app.opts.sync_server_address.clone().unwrap();
    let conn = app.get_connection();
    let interrupt_count = app.get_interrupt_count();

    // RBAC configuration is env-driven so a sync deployment can roll out
    // bearer-token auth without changing the CLI surface. Operators set:
    //   TURSO_SYNC_JWT_HS_SECRET       — HS256 key bytes (single-key dev shape)
    //   TURSO_SYNC_JWT_KID             — kid for the HS256 key (default: "hs1")
    //   TURSO_SYNC_JWT_ISSUERS         — comma-separated iss allow-list (required)
    //   TURSO_SYNC_JWT_AUDIENCES       — comma-separated aud allow-list (optional)
    //   TURSO_SYNC_JWT_ROLE_SOURCE     — "table" (default, Mode A) or "jwt" (Mode B)
    //   TURSO_SYNC_CORS_ORIGINS        — comma-separated CORS allow-list (default *)
    //   TURSO_SYNC_INITIAL_ADMIN_ISS_SUB — pre-warm admin, format "<iss>:<sub>"
    use crate::sync_auth::{JwtKey, JwtVerifier, RoleSource};
    use jsonwebtoken::{Algorithm, DecodingKey};

    let issuers = std::env::var("TURSO_SYNC_JWT_ISSUERS").map_err(|_| {
        anyhow::anyhow!(
            "sync server requires TURSO_SYNC_JWT_ISSUERS (comma-separated allow-list) \
             to be set; this is mandatory to close cross-issuer sub collision"
        )
    })?;
    let role_source =
        RoleSource::from_env_value(std::env::var("TURSO_SYNC_JWT_ROLE_SOURCE").ok().as_deref());

    let mut verifier_builder = JwtVerifier::builder().role_source(role_source);
    for iss in issuers
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        verifier_builder = verifier_builder.add_issuer(iss);
    }
    if let Ok(auds) = std::env::var("TURSO_SYNC_JWT_AUDIENCES") {
        for aud in auds.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            verifier_builder = verifier_builder.add_audience(aud);
        }
    }
    // Clock-skew tolerance for `exp` / `nbf` validation. JwtVerifier's
    // default is 30s (JWT-spec convention). Operators can tune this when
    // IdP and server clocks drift in production environments.
    if let Ok(s) = std::env::var("TURSO_SYNC_JWT_LEEWAY_SECS") {
        if let Ok(n) = s.parse::<u64>() {
            verifier_builder = verifier_builder.leeway_secs(n);
        }
    }
    if let Ok(secret) = std::env::var("TURSO_SYNC_JWT_HS_SECRET") {
        let kid = std::env::var("TURSO_SYNC_JWT_KID").unwrap_or_else(|_| "hs1".to_string());
        verifier_builder = verifier_builder.add_key(JwtKey {
            kid,
            algorithm: Algorithm::HS256,
            key: DecodingKey::from_secret(secret.as_bytes()),
        });
    }
    let verifier = verifier_builder.build()?;

    let cors_origins: Option<std::collections::HashSet<String>> =
        std::env::var("TURSO_SYNC_CORS_ORIGINS").ok().map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        });

    let initial_admin = std::env::var("TURSO_SYNC_INITIAL_ADMIN_ISS_SUB")
        .ok()
        .and_then(|s| {
            let mut it = s.splitn(2, ':');
            match (it.next(), it.next()) {
                (Some(iss), Some(sub)) if !iss.is_empty() && !sub.is_empty() => {
                    Some((iss.to_string(), sub.to_string()))
                }
                _ => None,
            }
        });

    let sync_server = TursoSyncServer::new(
        address,
        conn,
        interrupt_count,
        verifier,
        cors_origins,
        initial_admin,
    )?;

    sync_server.run()
}

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "mvcc_repl")]
    {
        use clap::Parser as _;
        let opts = app::Opts::parse();
        if opts.mvcc {
            let path = opts
                .database
                .as_ref()
                .and_then(|p| p.to_str())
                .unwrap_or(":memory:")
                .to_owned();
            return mvcc_repl::run(&path);
        }
    }

    let (mut app, _guard) = app::Limbo::new()?;

    if app.is_mcp_mode() {
        return run_mcp_server(app);
    }
    if app.is_sync_server_mode() {
        return run_sync_server(app);
    }

    let interactive_stdin = std::io::IsTerminal::is_terminal(&std::io::stdin());
    if interactive_stdin {
        let mut rl = Editor::with_config(rustyline_config())?;
        if HISTORY_FILE.exists() {
            rl.load_history(HISTORY_FILE.as_path())?;
        }
        let config_file = CONFIG_DIR.join("limbo.toml");

        let config = config::Config::from_config_file(config_file);
        tracing::info!("Configuration: {:?}", config);
        app = app.with_config(config);

        app = app.with_readline(rl);
    } else {
        tracing::debug!("not in tty");
    }

    loop {
        match app.readline() {
            Ok(_) => app.consume(false),
            Err(ReadlineError::Interrupted) => {
                // At prompt, increment interrupt count
                if app.interrupt_count.fetch_add(1, Ordering::SeqCst) >= 1 {
                    eprintln!("Interrupted. Exiting...");
                    let _ = app.close_conn();
                    break;
                }
                println!("Use .quit to exit or press Ctrl-C again to force quit.");
                app.reset_input();
                continue;
            }
            Err(ReadlineError::Eof) => {
                // consume remaining input before exit
                app.consume(true);
                let _ = app.close_conn();
                break;
            }
            Err(err) => {
                let _ = app.close_conn();
                anyhow::bail!(err)
            }
        }
    }
    if !interactive_stdin && app.has_query_error() {
        std::process::exit(1);
    }
    Ok(())
}
