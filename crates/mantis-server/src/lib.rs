//! mantis-server — HTTP/SSE API that wraps the mantis-chat engine and
//! exposes a small subset of the daemon's engagement operations.
//!
//! This crate is the "expose CLI as an API" leg of the conversational
//! rewrite. It is consumed by the `mantis serve` subcommand and by
//! third-party clients (web UI, IDE plugins) that want to drive a
//! chat session without re-implementing provider selection or tool
//! loops.
//!
//! Public entry point: [`run`]. The router is built from
//! [`ServerConfig`]; auth tokens are persisted under
//! `$MANTIS_HOME/server.token` and required on every `/v1/*` route
//! when [`ServerConfig::require_auth`] is true. The `/healthz` probe
//! is always anonymous.
//!
//! Testing hook: [`ServerConfig::provider_override`] accepts a stub
//! [`LlmAdapter`] so handler tests can drive the chat surface without
//! talking to a real provider.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use mantis_synthesizer::LlmAdapter;

pub mod auth;
pub mod error;
pub mod handlers;
pub mod provider;
pub mod routes;

pub use error::ApiError;

/// Runtime configuration for the server.
///
/// The defaults match the CLI's expectations: bind on loopback, look
/// for the daemon on the standard gRPC port, and read/write the auth
/// token under `$MANTIS_HOME/server.token`.
pub struct ServerConfig {
    /// Address to bind. CLI default is `127.0.0.1:8787`.
    pub bind: SocketAddr,
    /// When `false`, the bearer-token middleware is bypassed entirely.
    /// Useful for localhost dev sessions that already gate by network.
    pub require_auth: bool,
    /// Path to the bearer token file. Auto-generated on first run
    /// when `require_auth` is true and the file is missing.
    pub token_path: PathBuf,
    /// `$MANTIS_HOME` — used by the chat surface for user tools and
    /// (future) history persistence.
    pub mantis_home: PathBuf,
    /// gRPC endpoint of the local daemon. Default
    /// `http://127.0.0.1:50451`.
    pub daemon_endpoint: String,
    /// Optional stub adapter that bypasses [`provider::pick_chat_adapter`].
    /// Tests inject a scripted adapter here so the chat handler can be
    /// exercised without provider credentials.
    pub provider_override: Option<Arc<dyn LlmAdapter>>,
}

impl ServerConfig {
    /// Build a config with library defaults. `mantis_home` is required;
    /// callers usually pass `$MANTIS_HOME` or the CLI's
    /// `default_workspace_root()`.
    pub fn new(mantis_home: PathBuf) -> Self {
        let token_path = mantis_home.join("server.token");
        Self {
            bind: "127.0.0.1:8787"
                .parse()
                .expect("hard-coded SocketAddr is always valid"),
            require_auth: true,
            token_path,
            mantis_home,
            daemon_endpoint: "http://127.0.0.1:50451".into(),
            provider_override: None,
        }
    }
}

/// Build the router from `config` and serve it on `config.bind`.
///
/// On first run with `require_auth`, this generates a fresh 32-byte
/// hex bearer token at `config.token_path` (mode 0600 on unix). The
/// resolved token is logged at INFO so an operator running
/// `mantis serve` can see it. Subsequent runs reuse the persisted
/// token.
pub async fn run(config: ServerConfig) -> anyhow::Result<()> {
    let bind = config.bind;
    let app = routes::build_router(config)?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(addr = %bind, "mantis-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
