//! Router construction. Keeps route registration separate from the
//! handler implementations and from `run()` so handler tests can build
//! a fresh router per case.

use anyhow::Result;
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::auth::{ensure_token, require_bearer, BearerState};
use crate::handlers::{chat, engagements, healthz, AppState};
use crate::ServerConfig;

/// Build the full router. Mounts the bearer middleware on `/v1/*`
/// when `config.require_auth` is true and always exposes `/healthz`
/// anonymously.
pub fn build_router(config: ServerConfig) -> Result<Router> {
    let app_state = AppState {
        mantis_home: config.mantis_home.clone(),
        daemon_endpoint: config.daemon_endpoint.clone(),
        provider_override: config.provider_override.clone(),
    };

    let v1 = Router::new()
        .route("/chat", post(chat::handle_chat))
        .route("/engagements", get(engagements::list_engagements))
        .route("/scan", post(engagements::create_scan))
        .route("/findings/:engagement_id", get(engagements::list_findings))
        .with_state(app_state.clone());

    let v1 = if config.require_auth {
        let token = ensure_token(&config.token_path)?;
        tracing::info!(
            token_path = %config.token_path.display(),
            "bearer token loaded (set Authorization: Bearer <token>)"
        );
        let bearer_state = BearerState { token };
        v1.layer(middleware::from_fn_with_state(
            bearer_state,
            require_bearer::<axum::body::Body>,
        ))
    } else {
        v1
    };

    let router = Router::new()
        .route("/healthz", get(healthz))
        .nest("/v1", v1)
        .layer(TraceLayer::new_for_http());

    Ok(router)
}
