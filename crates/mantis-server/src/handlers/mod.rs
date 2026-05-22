//! HTTP route handlers.
//!
//! Each module exposes Axum handler functions plus the request/
//! response DTOs they serialize. Handlers return
//! `Result<impl IntoResponse, ApiError>`; see [`crate::error`].

pub mod chat;
pub mod engagements;

/// Shared handler state — injected via `Router::with_state`.
#[derive(Clone)]
pub struct AppState {
    pub mantis_home: std::path::PathBuf,
    pub daemon_endpoint: String,
    /// Optional stub adapter for tests. When `Some`, the chat handler
    /// uses it verbatim; when `None`, [`crate::provider::pick_chat_adapter`]
    /// resolves a real adapter at request time.
    pub provider_override: Option<std::sync::Arc<dyn mantis_synthesizer::LlmAdapter>>,
}

/// `GET /healthz` — anonymous liveness probe. Always 200.
pub async fn healthz() -> &'static str {
    "ok"
}
