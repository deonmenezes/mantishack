//! Engagement endpoints — thin wrappers around the daemon's gRPC
//! `Engagement` service.
//!
//! - `GET  /v1/engagements`          → `Engagement::List`
//! - `POST /v1/scan`                 → `Engagement::Create` + `Start`
//! - `GET  /v1/findings/:engagement` → stubbed (proto lacks a findings RPC)
//!
//! The daemon endpoint is configured per-request from
//! [`AppState::daemon_endpoint`] so a single server process can be
//! repointed without restart.

use axum::extract::{Path, State};
use axum::Json;
use mantis_proto::v1::engagement_client::EngagementClient;
use mantis_proto::v1::{
    CreateRequest, EngagementState as ProtoEngagementState, ListRequest, StartRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ApiError;
use crate::handlers::AppState;

/// Single engagement entry returned in the list response. The wire
/// shape stays narrow (id / target / state / created_at) so the
/// daemon can grow its `EngagementInfo` proto without breaking
/// HTTP clients.
#[derive(Debug, Serialize)]
pub struct EngagementSummary {
    pub id: String,
    pub target: String,
    pub state: &'static str,
    pub created_at: u64,
}

/// `GET /v1/engagements`
pub async fn list_engagements(
    State(state): State<AppState>,
) -> Result<Json<Vec<EngagementSummary>>, ApiError> {
    let mut client = EngagementClient::connect(state.daemon_endpoint.clone())
        .await
        .map_err(|e| ApiError::upstream(format!("connect daemon: {e}")))?;

    let resp = client
        .list(ListRequest {})
        .await
        .map_err(|e| ApiError::upstream(format!("daemon list: {e}")))?;

    let engs = resp
        .into_inner()
        .engagements
        .into_iter()
        .map(|e| EngagementSummary {
            id: e.id,
            target: e.name,
            state: state_label(e.state),
            created_at: e.created_at_unix,
        })
        .collect();

    Ok(Json(engs))
}

/// Request body for `POST /v1/scan`.
///
/// `i_have_authorization` MUST be literal `true`. Anything else
/// (missing field, `false`, non-bool) is a 403 — mirrors the CLI's
/// `--i-have-authorization` gate. `scope` is reserved for future
/// signed-scope support; the daemon currently accepts a single target
/// at the start of a scan and authorizes via a separate RPC.
#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub target: String,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub i_have_authorization: bool,
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub engagement_id: String,
    pub state: &'static str,
}

/// `POST /v1/scan` — create an engagement and transition it to ACTIVE.
///
/// Note: the daemon expects an `Authorize` call between `Create` and
/// `Start` for production engagements. Until the HTTP API has a
/// signed-scope upload route, this endpoint requires the caller to
/// affirm authorization in the request body and skips straight to
/// `Start` against a draft engagement. The daemon will refuse the
/// `Start` if its policy requires authorization first; that failure
/// is surfaced as a 502 with the daemon's error message intact.
pub async fn create_scan(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, ApiError> {
    if !req.i_have_authorization {
        return Err(ApiError::forbidden(
            "missing authorization affirmation: set `i_have_authorization: true`",
        ));
    }

    if req.target.trim().is_empty() {
        return Err(ApiError::bad_request("`target` must not be empty"));
    }

    let mut client = EngagementClient::connect(state.daemon_endpoint.clone())
        .await
        .map_err(|e| ApiError::upstream(format!("connect daemon: {e}")))?;

    let created = client
        .create(CreateRequest {
            name: req.target.clone(),
        })
        .await
        .map_err(|e| ApiError::upstream(format!("daemon create: {e}")))?
        .into_inner();

    // Try to start immediately. If the daemon rejects because the
    // engagement is still in DRAFT, surface the original error — the
    // operator needs to know they must authorize via the CLI first.
    let started = client
        .start(StartRequest {
            id: created.id.clone(),
        })
        .await
        .map_err(|e| ApiError::upstream(format!("daemon start: {e}")))?
        .into_inner();

    Ok(Json(ScanResponse {
        engagement_id: started.id,
        state: state_label(started.state),
    }))
}

/// `GET /v1/findings/:engagement_id`.
///
/// Stubbed: the daemon's `Engagement` proto does not currently expose
/// a list-findings RPC. We return an empty array with the engagement
/// id echoed back so clients can wire the route now and switch to a
/// real implementation once the proto grows the call.
pub async fn list_findings(
    Path(engagement_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(json!({
        "engagement_id": engagement_id,
        "findings": [],
    })))
}

fn state_label(state: i32) -> &'static str {
    match ProtoEngagementState::try_from(state) {
        Ok(ProtoEngagementState::Draft) => "DRAFT",
        Ok(ProtoEngagementState::Authorized) => "AUTHORIZED",
        Ok(ProtoEngagementState::Active) => "RECON",
        Ok(ProtoEngagementState::Paused) => "PAUSED",
        Ok(ProtoEngagementState::Completed) => "COMPLETED",
        Ok(ProtoEngagementState::Archived) => "ARCHIVED",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::json;
    use tower::ServiceExt;

    fn build_app() -> axum::Router {
        let config = crate::ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            require_auth: false,
            token_path: std::env::temp_dir().join("mantis-server-eng-test.token"),
            mantis_home: std::env::temp_dir(),
            // Point at an unused port so any handler that hits the
            // daemon fails fast — these tests only exercise input
            // validation, which runs before the gRPC call.
            daemon_endpoint: "http://127.0.0.1:1".into(),
            provider_override: None,
        };
        crate::routes::build_router(config).expect("build router")
    }

    #[tokio::test]
    async fn scan_refuses_without_authorization() {
        let app = build_app();

        let body = json!({
            "target": "example.com",
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/scan")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn scan_refuses_with_authorization_false() {
        let app = build_app();

        let body = json!({
            "target": "example.com",
            "i_have_authorization": false,
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/scan")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn findings_returns_empty_stub() {
        let app = build_app();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/findings/eng-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["engagement_id"], "eng-123");
        assert!(body["findings"].as_array().unwrap().is_empty());
    }
}
