//! Verifier — accepts or rejects an LLM-produced finding.
//!
//! The verifier reads the exploit script's output and decides
//! whether it constitutes evidence of a vulnerability. Used by:
//! - The medium tier (single pass: accept first hit).
//! - The hard tier (loop: reject + iterate until accepted or
//!   budget exhausts).
//!
//! Verification is pattern-based: the operator (or the orchestrator
//! synthesizing a probe) supplies a set of `MarkerPattern`s — each
//! is a substring that, if present in stdout/stderr, confirms the
//! vuln. Plus a set of `NegativeMarker`s that, if present, prove
//! the exploit didn't land.

use crate::adapter::SandboxOutput;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifierVerdict {
    /// Exploit landed — the output contains expected evidence and
    /// no negative markers fired.
    Accepted {
        matched_markers: Vec<String>,
        evidence_excerpt: String,
    },
    /// Negative marker fired ("Unauthorized", "expired", "404") —
    /// the exploit was blocked by the target.
    RejectedNegative { marker: String },
    /// Neither positive nor negative markers fired — the script
    /// produced output but nothing the verifier recognizes. The
    /// hard tier sends this back to the LLM as "needs refinement".
    Inconclusive { stdout_len: usize, stderr_len: usize },
    /// Script died (non-zero exit or runtime error).
    Crashed { exit_code: i32, stderr_excerpt: String },
}

impl VerifierVerdict {
    pub fn accepted(&self) -> bool {
        matches!(self, VerifierVerdict::Accepted { .. })
    }

    pub fn short_label(&self) -> &'static str {
        match self {
            VerifierVerdict::Accepted { .. } => "accepted",
            VerifierVerdict::RejectedNegative { .. } => "rejected-negative",
            VerifierVerdict::Inconclusive { .. } => "inconclusive",
            VerifierVerdict::Crashed { .. } => "crashed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierConfig {
    /// Substrings that prove the exploit worked. ANY match → accept.
    /// Example for cross-tenant read: `"victim-org"`, `"another tenant"`.
    pub positive_markers: Vec<String>,
    /// Substrings that prove the exploit was blocked. ANY match →
    /// reject-negative. Checked BEFORE positive markers so a 401
    /// body doesn't get confused with success.
    pub negative_markers: Vec<String>,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            positive_markers: vec![],
            negative_markers: vec![
                "Unauthorized".into(),
                "Forbidden".into(),
                "JWT expired".into(),
                "Not Found".into(),
                "permission denied".into(),
                "row-level security".into(),
            ],
        }
    }
}

pub fn verify_finding(out: &SandboxOutput, cfg: &VerifierConfig) -> VerifierVerdict {
    if out.exit_code != 0 && out.stdout.is_empty() {
        return VerifierVerdict::Crashed {
            exit_code: out.exit_code,
            stderr_excerpt: out.stderr.chars().take(400).collect(),
        };
    }
    let combined = format!("{}\n{}", out.stdout, out.stderr);
    // Negative markers first — guard against false positives where
    // a positive marker shows up inside an error message.
    for n in &cfg.negative_markers {
        if combined.contains(n) {
            return VerifierVerdict::RejectedNegative { marker: n.clone() };
        }
    }
    let mut matched: Vec<String> = Vec::new();
    for p in &cfg.positive_markers {
        if combined.contains(p) {
            matched.push(p.clone());
        }
    }
    if !matched.is_empty() {
        let excerpt: String = out.stdout.chars().take(800).collect();
        return VerifierVerdict::Accepted {
            matched_markers: matched,
            evidence_excerpt: excerpt,
        };
    }
    VerifierVerdict::Inconclusive {
        stdout_len: out.stdout.len(),
        stderr_len: out.stderr.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(stdout: &str, stderr: &str, exit: i32) -> SandboxOutput {
        SandboxOutput {
            exit_code: exit,
            stdout: stdout.into(),
            stderr: stderr.into(),
            duration_ms: 0,
        }
    }

    #[test]
    fn positive_marker_accepts() {
        let cfg = VerifierConfig {
            positive_markers: vec!["victim-org".into()],
            negative_markers: vec![],
        };
        let v = verify_finding(&out(r#"[{"organization_id":"victim-org"}]"#, "", 0), &cfg);
        assert!(v.accepted());
    }

    #[test]
    fn negative_marker_rejects_even_with_positive() {
        let cfg = VerifierConfig {
            positive_markers: vec!["victim-org".into()],
            negative_markers: vec!["Unauthorized".into()],
        };
        let v = verify_finding(
            &out("HTTP 401 Unauthorized — victim-org in error body", "", 0),
            &cfg,
        );
        assert!(matches!(v, VerifierVerdict::RejectedNegative { .. }));
    }

    #[test]
    fn no_markers_means_inconclusive() {
        let cfg = VerifierConfig {
            positive_markers: vec!["never-matches".into()],
            negative_markers: vec![],
        };
        let v = verify_finding(&out("normal response body", "", 0), &cfg);
        assert!(matches!(v, VerifierVerdict::Inconclusive { .. }));
    }

    #[test]
    fn nonzero_exit_with_empty_stdout_is_crashed() {
        let v = verify_finding(&out("", "bash: not found", 127), &VerifierConfig::default());
        assert!(matches!(v, VerifierVerdict::Crashed { .. }));
    }

    #[test]
    fn nonzero_exit_with_stdout_is_still_evaluated() {
        // Script exited non-zero but printed actual data → don't
        // skip the verification.
        let cfg = VerifierConfig {
            positive_markers: vec!["victim-org".into()],
            negative_markers: vec![],
        };
        let v = verify_finding(&out("victim-org leaked", "warning", 1), &cfg);
        assert!(v.accepted());
    }

    #[test]
    fn default_negative_markers_catch_common_blocks() {
        let cfg = VerifierConfig::default();
        for stderr in &["JWT expired", "permission denied", "row-level security"] {
            let v = verify_finding(&out("", stderr, 0), &cfg);
            assert!(
                matches!(v, VerifierVerdict::RejectedNegative { .. }),
                "expected reject for {stderr:?}, got {v:?}"
            );
        }
    }

    #[test]
    fn verifier_verdict_short_labels() {
        let accepted = VerifierVerdict::Accepted {
            matched_markers: vec![],
            evidence_excerpt: "".into(),
        };
        assert_eq!(accepted.short_label(), "accepted");
        let crashed = VerifierVerdict::Crashed {
            exit_code: 1,
            stderr_excerpt: "".into(),
        };
        assert_eq!(crashed.short_label(), "crashed");
    }
}
