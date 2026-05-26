//! GitHub code-scanning SARIF upload envelope.
//!
//! Spec: <https://docs.github.com/en/rest/code-scanning/code-scanning#upload-an-analysis-as-sarif-data>.
//!
//! The endpoint `POST /repos/{owner}/{repo}/code-scanning/sarifs` accepts a
//! JSON body whose `sarif` field is a base64-encoded gzip-compressed SARIF
//! document. This module owns the gzip + base64 encoding and produces the
//! complete request body. The dispatcher performs the actual POST.

use std::fmt;
use std::io::Write;

use base64::Engine;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::Value;

/// Required + optional fields for a GitHub code-scanning SARIF upload.
#[derive(Debug, Clone)]
pub struct SarifUploadConfig<'a> {
    /// 40-character commit SHA the analysis applies to.
    pub commit_sha: &'a str,
    /// Git ref the SHA belongs to (e.g. `"refs/heads/main"`, `"refs/pull/12/merge"`).
    pub git_ref: &'a str,
    /// Optional tool name override (when omitted, GitHub reads it from the SARIF).
    pub tool_name: Option<&'a str>,
    /// Optional checkout URI (`"file:///github/workspace"` is the GitHub Action default).
    pub checkout_uri: Option<&'a str>,
    /// Optional ISO-8601 timestamp when the analysis started.
    pub started_at: Option<&'a str>,
}

impl<'a> SarifUploadConfig<'a> {
    /// Construct a minimal config with required fields only.
    pub fn new(commit_sha: &'a str, git_ref: &'a str) -> Self {
        Self {
            commit_sha,
            git_ref,
            tool_name: None,
            checkout_uri: None,
            started_at: None,
        }
    }
}

/// Errors returned during SARIF encoding.
#[derive(Debug)]
pub enum SarifUploadError {
    /// gzip compression failed.
    Gzip(std::io::Error),
}

impl fmt::Display for SarifUploadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gzip(e) => write!(f, "gzip compression failed: {e}"),
        }
    }
}

impl std::error::Error for SarifUploadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Gzip(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for SarifUploadError {
    fn from(e: std::io::Error) -> Self {
        Self::Gzip(e)
    }
}

/// gzip-compress and base64-encode a SARIF JSON document.
///
/// Returned string is the value that goes into the `sarif` field of the
/// upload envelope.
pub fn encode_sarif(sarif_json: &str) -> Result<String, SarifUploadError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(sarif_json.as_bytes())?;
    let gzipped = encoder.finish()?;
    Ok(base64::engine::general_purpose::STANDARD.encode(&gzipped))
}

/// Build the full request body for `POST /repos/.../code-scanning/sarifs`.
pub fn format(sarif_json: &str, cfg: &SarifUploadConfig<'_>) -> Result<Value, SarifUploadError> {
    let encoded = encode_sarif(sarif_json)?;
    let mut body = serde_json::Map::new();
    body.insert(
        "commit_sha".into(),
        Value::String(cfg.commit_sha.to_string()),
    );
    body.insert("ref".into(), Value::String(cfg.git_ref.to_string()));
    body.insert("sarif".into(), Value::String(encoded));
    if let Some(tool) = cfg.tool_name {
        body.insert("tool_name".into(), Value::String(tool.to_string()));
    }
    if let Some(uri) = cfg.checkout_uri {
        body.insert("checkout_uri".into(), Value::String(uri.to_string()));
    }
    if let Some(t) = cfg.started_at {
        body.insert("started_at".into(), Value::String(t.to_string()));
    }
    Ok(Value::Object(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    use base64::engine::general_purpose::STANDARD as B64;
    use flate2::read::GzDecoder;

    const SARIF: &str = r#"{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[]}"#;
    const SHA: &str = "0000000000000000000000000000000000000000";

    #[test]
    fn encode_sarif_round_trips_through_gunzip_and_base64() {
        let encoded = encode_sarif(SARIF).unwrap();
        let gzipped = B64.decode(&encoded).unwrap();
        let mut gz = GzDecoder::new(&gzipped[..]);
        let mut out = String::new();
        gz.read_to_string(&mut out).unwrap();
        assert_eq!(out, SARIF);
    }

    #[test]
    fn body_contains_required_fields() {
        let cfg = SarifUploadConfig::new(SHA, "refs/heads/main");
        let body = format(SARIF, &cfg).unwrap();
        assert!(body["commit_sha"].is_string());
        assert!(body["ref"].is_string());
        assert!(body["sarif"].is_string());
        assert_eq!(body["ref"], "refs/heads/main");
    }

    #[test]
    fn body_omits_optional_fields_when_unset() {
        let cfg = SarifUploadConfig::new(SHA, "refs/heads/main");
        let body = format(SARIF, &cfg).unwrap();
        assert!(body.get("tool_name").is_none());
        assert!(body.get("checkout_uri").is_none());
        assert!(body.get("started_at").is_none());
    }

    #[test]
    fn body_includes_tool_name_when_set() {
        let mut cfg = SarifUploadConfig::new(SHA, "refs/heads/main");
        cfg.tool_name = Some("Mantis");
        let body = format(SARIF, &cfg).unwrap();
        assert_eq!(body["tool_name"], "Mantis");
    }

    #[test]
    fn body_includes_checkout_uri_and_started_at_when_set() {
        let mut cfg = SarifUploadConfig::new(SHA, "refs/heads/main");
        cfg.checkout_uri = Some("file:///github/workspace");
        cfg.started_at = Some("2025-01-01T00:00:00Z");
        let body = format(SARIF, &cfg).unwrap();
        assert_eq!(body["checkout_uri"], "file:///github/workspace");
        assert_eq!(body["started_at"], "2025-01-01T00:00:00Z");
    }

    #[test]
    fn sarif_field_is_smaller_than_input() {
        // Quick sanity check that gzip actually compressed something. With a
        // repeating SARIF body, base64-encoded gzip should be smaller than the
        // raw input, demonstrating compression isn't being skipped.
        let repeated = SARIF.repeat(50);
        let encoded = encode_sarif(&repeated).unwrap();
        assert!(
            encoded.len() < repeated.len(),
            "encoded {} ; input {}",
            encoded.len(),
            repeated.len()
        );
    }

    #[test]
    fn encoded_string_is_valid_base64() {
        let encoded = encode_sarif(SARIF).unwrap();
        // Should decode without error.
        assert!(B64.decode(&encoded).is_ok());
    }
}
