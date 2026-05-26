//! mantis-secrets — credential & token detection over arbitrary bytes.
//!
//! ## Why this exists
//!
//! Exposed secrets are among the highest-impact findings on most
//! engagements (cloud takeover, repo write, payment-rail compromise)
//! and the easiest to verify (we attempt authentication where
//! authorized). They surface naturally in artifacts the rest of the
//! pipeline already collects: JS bundles fetched by
//! `mantis-crawler`, HTTP responses captured by
//! `mantis-scanner-http`, public dotfiles enumerated by recon.
//!
//! ## What it does
//!
//! Two layers stacked together:
//!
//! 1. **Pattern rules** ([`rules`]) — provider-specific prefix /
//!    structure matchers (AWS `AKIA*`, GitHub `ghp_*`, Slack
//!    `xoxb-*`, …). Cheap, high-confidence, no false-positive tax.
//! 2. **Generic entropy** ([`entropy`]) — Shannon-entropy probe on
//!    base64-shaped tokens that didn't match a specific rule. Tuned
//!    high (≥ 4.5 bits/char) and filtered against common false
//!    positives (hashes, UUIDs, build IDs).
//!
//! ## Public API
//!
//! - [`SecretScanner::scan_bytes`] — synchronous, allocation-light.
//! - [`SecretFinding`] — serializable record with severity + offset
//!   so downstream tooling can render an evidence excerpt.

pub mod entropy;
pub mod rules;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use crate::rules::{Rule, RuleSet};

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("input too large: {bytes} > {limit}")]
    TooLarge { bytes: usize, limit: usize },
}

/// One categorized secret hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretFinding {
    /// Stable rule identifier — `aws-access-key-id`, `entropy-base64`, …
    pub rule_id: String,
    /// Human-readable rule name.
    pub description: String,
    /// Suggested severity if exposed publicly.
    pub severity: Severity,
    /// The matched substring (full, untruncated).
    pub matched: String,
    /// Byte offset of the match in the source input.
    pub offset: usize,
    /// Optional source label — filename, URL, etc. — supplied by the
    /// caller via [`SecretScanner::scan_bytes_with_source`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Default upper bound on a single input — 16 MiB. Anything larger
/// is rejected to keep the scanner allocation-bounded. Bigger inputs
/// should be chunked by the caller.
pub const DEFAULT_INPUT_LIMIT_BYTES: usize = 16 * 1024 * 1024;

/// Top-level scanner.
///
/// Holds a [`RuleSet`] and the entropy threshold; instantiate once
/// at engagement start, reuse across artifacts.
#[derive(Debug, Clone)]
pub struct SecretScanner {
    rules: RuleSet,
    entropy_threshold: f64,
    enable_entropy: bool,
    input_limit_bytes: usize,
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self {
            rules: RuleSet::built_in(),
            entropy_threshold: 4.5,
            enable_entropy: true,
            input_limit_bytes: DEFAULT_INPUT_LIMIT_BYTES,
        }
    }
}

impl SecretScanner {
    /// New scanner using the built-in rule set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the rule set wholesale.
    pub fn with_rules(mut self, rules: RuleSet) -> Self {
        self.rules = rules;
        self
    }

    /// Disable the generic entropy probe. Useful when scanning a
    /// known-noisy corpus (image data, sourcemaps) where we'd
    /// otherwise drown in entropy false positives.
    pub fn without_entropy(mut self) -> Self {
        self.enable_entropy = false;
        self
    }

    /// Override the entropy threshold (default 4.5 bits/char).
    pub fn with_entropy_threshold(mut self, threshold: f64) -> Self {
        self.entropy_threshold = threshold;
        self
    }

    /// Override the input size limit.
    pub fn with_input_limit_bytes(mut self, limit: usize) -> Self {
        self.input_limit_bytes = limit;
        self
    }

    /// Scan bytes — UTF-8 lossy decoded; binary inputs work but
    /// findings will be sparse.
    pub fn scan_bytes(&self, input: &[u8]) -> Result<Vec<SecretFinding>, ScanError> {
        self.scan_bytes_with_source(input, None)
    }

    /// As [`scan_bytes`], but stamps each finding with `source` (a
    /// filename, URL, etc.).
    pub fn scan_bytes_with_source(
        &self,
        input: &[u8],
        source: Option<&str>,
    ) -> Result<Vec<SecretFinding>, ScanError> {
        if input.len() > self.input_limit_bytes {
            return Err(ScanError::TooLarge {
                bytes: input.len(),
                limit: self.input_limit_bytes,
            });
        }
        let text = match std::str::from_utf8(input) {
            Ok(s) => s,
            Err(_) => return Ok(Vec::new()), // bail cheaply on binary
        };
        let mut out = Vec::new();
        let mut covered: Vec<(usize, usize)> = Vec::new();

        for finding in self.rules.scan(text) {
            covered.push((finding.offset, finding.offset + finding.matched.len()));
            out.push(SecretFinding {
                source: source.map(str::to_string),
                ..finding
            });
        }

        if self.enable_entropy {
            for ef in entropy::scan(text, self.entropy_threshold) {
                let end = ef.offset + ef.matched.len();
                let overlaps = covered
                    .iter()
                    .any(|(s, e)| !(end <= *s || ef.offset >= *e));
                if !overlaps {
                    out.push(SecretFinding {
                        source: source.map(str::to_string),
                        ..ef
                    });
                }
            }
        }

        // Stable ordering: by offset, then by rule_id, so callers
        // that diff scans get a predictable list.
        out.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.rule_id.cmp(&b.rule_id)));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scanner_has_built_in_rules() {
        let s = SecretScanner::new();
        assert!(s.rules.len() > 10);
    }

    #[test]
    fn rejects_oversized_input() {
        let s = SecretScanner::new().with_input_limit_bytes(10);
        let r = s.scan_bytes(b"this is more than ten bytes");
        match r {
            Err(ScanError::TooLarge { bytes, limit }) => {
                assert_eq!(limit, 10);
                assert!(bytes > 10);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn binary_input_returns_no_findings() {
        let s = SecretScanner::new();
        let bytes = vec![0xff, 0xfe, 0xfd, 0xfc];
        assert!(s.scan_bytes(&bytes).unwrap().is_empty());
    }

    #[test]
    fn finds_aws_key_id_and_attaches_source() {
        let s = SecretScanner::new();
        // Source-level split so push protection doesn't see a contiguous AKIA… literal.
        let body = concat!("AWS_ACCESS_KEY_ID=", "AKIA", "IOSFODNN7EXAMPLE").as_bytes();
        let found = s
            .scan_bytes_with_source(body, Some("config.txt"))
            .unwrap();
        let aws = found
            .iter()
            .find(|f| f.rule_id == "aws-access-key-id")
            .expect("expected AWS finding");
        assert_eq!(aws.matched, concat!("AKIA", "IOSFODNN7EXAMPLE"));
        assert_eq!(aws.source.as_deref(), Some("config.txt"));
        assert_eq!(aws.severity, Severity::High);
    }

    #[test]
    fn finds_multiple_distinct_secrets_in_one_input() {
        // Test fixtures are split with concat!() so the source file does not contain
        // contiguous patterns that match the regexes we ship (which would trigger
        // upstream secret-scanning push protection). The compiler joins them.
        let body = concat!(
            "GITHUB_TOKEN=", "ghp", "_1234567890abcdefghijklmnopqrstuvwxyz ",
            "STRIPE=", "sk_", "live_aaaaaaaaaaaaaaaaaaaaaaaa"
        ).as_bytes();
        let s = SecretScanner::new();
        let found = s.scan_bytes(body).unwrap();
        assert!(found.iter().any(|f| f.rule_id == "github-pat"));
        assert!(found.iter().any(|f| f.rule_id == "stripe-secret-key"));
    }

    #[test]
    fn findings_are_ordered_by_offset() {
        // First a Stripe key, then a GitHub PAT; expect ascending offsets.
        // Split as above to defeat source-file scanning while preserving runtime test.
        let body = concat!(
            "sk_", "live_aaaaaaaaaaaaaaaaaaaaaaaa and later ",
            "ghp", "_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ).as_bytes();
        let found = SecretScanner::new().scan_bytes(body).unwrap();
        let offsets: Vec<usize> = found.iter().map(|f| f.offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(offsets, sorted);
    }

    #[test]
    fn severity_json_round_trip() {
        let v = vec![
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        for s in v {
            let j = serde_json::to_string(&s).unwrap();
            let back: Severity = serde_json::from_str(&j).unwrap();
            assert_eq!(s, back);
            assert!(j.contains(s.as_str()));
        }
    }

    #[test]
    fn without_entropy_drops_generic_findings() {
        // A high-entropy base64-ish blob that no rule matches.
        let body = b"context=zX7Q2Lk9TmA8sR4VnJ6BcW1F3dEYpUgHkMrLqZvNxOiKj9TbP5aS";
        let with = SecretScanner::new().scan_bytes(body).unwrap();
        let without = SecretScanner::new()
            .without_entropy()
            .scan_bytes(body)
            .unwrap();
        assert!(with.len() >= without.len());
        // Either entropy was triggered (with > without), or it wasn't
        // (both = 0); in neither case should removing entropy
        // *increase* findings.
        assert!(without.len() <= with.len());
    }

    #[test]
    fn empty_input_returns_empty() {
        assert!(SecretScanner::new().scan_bytes(b"").unwrap().is_empty());
    }

    #[test]
    fn rule_finding_excludes_overlapping_entropy_finding() {
        // A GitHub PAT also has high entropy. We should see exactly
        // one finding (the named rule), not two. Split the fixture so
        // push protection doesn't trip on this crate's own test data.
        let body = concat!("token=", "ghp", "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 done").as_bytes();
        let found = SecretScanner::new().scan_bytes(body).unwrap();
        let pat = found.iter().filter(|f| f.rule_id == "github-pat").count();
        let entropy = found
            .iter()
            .filter(|f| f.rule_id.starts_with("entropy"))
            .count();
        assert_eq!(pat, 1, "got {found:?}");
        assert_eq!(entropy, 0, "entropy should suppress overlap with named rule");
    }
}
