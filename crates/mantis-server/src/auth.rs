//! Bearer-token authentication for the HTTP API.
//!
//! The server has a single shared bearer token, persisted at
//! `$MANTIS_HOME/server.token`. On first run, `ensure_token` generates
//! 32 random bytes and writes them hex-encoded (mode 0600 on unix);
//! subsequent runs trust whatever the file contains so an operator
//! can hand-pick a value.
//!
//! [`require_bearer`] returns an Axum middleware that rejects any
//! request without a matching `Authorization: Bearer <token>` header.
//! `/healthz` is excluded from this middleware in [`crate::routes`].

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use rand::RngCore;

/// Read the existing token at `path`, or generate a fresh 32-byte hex
/// token and write it. Returns the resolved token string (trimmed of
/// trailing whitespace).
///
/// When the file already exists with non-empty content we trust the
/// caller — this lets an operator pin a known value by writing the
/// file ahead of time.
pub fn ensure_token(path: &Path) -> Result<String> {
    if let Ok(existing) = fs::read_to_string(path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir {}", parent.display()))?;
    }

    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let hex = hex::encode(bytes);

    let mut opts = fs::OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("write token file {}", path.display()))?;
    f.write_all(hex.as_bytes())?;
    f.flush()?;
    Ok(hex)
}

/// Shared state for the bearer middleware.
#[derive(Clone)]
pub struct BearerState {
    pub token: String,
}

/// Axum middleware that rejects requests missing a matching
/// `Authorization: Bearer <token>` header. Returns 401 on mismatch.
pub async fn require_bearer<B>(
    State(state): State<BearerState>,
    req: Request<B>,
    next: Next,
) -> Result<Response, StatusCode>
where
    B: Send + 'static,
    Request<B>: Into<Request<axum::body::Body>>,
{
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| raw.strip_prefix("Bearer ").map(str::trim));

    match provided {
        Some(tok) if tok == state.token => Ok(next.run(req.into()).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn token_generation_persists_to_disk() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("server.token");

        let first = ensure_token(&path).expect("generate");
        assert_eq!(first.len(), 64, "32-byte hex => 64 chars");
        assert!(path.exists());

        let second = ensure_token(&path).expect("reread");
        assert_eq!(first, second, "second call must read the persisted value");
    }

    #[test]
    fn token_ignores_blank_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("server.token");
        fs::write(&path, "   \n").unwrap();

        let tok = ensure_token(&path).expect("generate");
        assert!(!tok.trim().is_empty());
        assert_eq!(tok.len(), 64);
    }

    #[cfg(unix)]
    #[test]
    fn token_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("server.token");
        ensure_token(&path).expect("generate");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "token file must be 0600, got {mode:o}");
    }
}
