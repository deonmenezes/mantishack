//! Engagement goals.
//!
//! A goal is a declarative success criterion attached to an
//! engagement. The orchestrator (or the `mantis goal` CLI) keeps
//! driving the pipeline forward until the goal's
//! [`Goal::is_met`] returns true against the current
//! [`crate::SessionState`].
//!
//! Goals are NOT a substitute for the FSM gates. They sit on top:
//! every transition still has to pass its gate. A goal just tells
//! the orchestrator when it's allowed to stop iterating waves /
//! cascades / report renders inside a phase.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Categories of goals the orchestrator knows how to drive. The
/// string variants accept operator-defined intent that the
/// orchestrator interprets per-engagement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GoalKind {
    /// "Find all endpoints / surfaces" — keep running RECON
    /// waves until no new surfaces are discovered for a tunable
    /// number of consecutive passes.
    EnumerateEndpoints {
        /// Minimum count of distinct surfaces to consider the goal
        /// non-trivially progressed.
        #[serde(default = "default_min_surfaces")]
        min_surfaces: u32,
        /// Stop after this many consecutive passes that add zero
        /// surfaces.
        #[serde(default = "default_stagnation")]
        stagnation_passes: u32,
    },
    /// "Find vulnerabilities" — keep iterating HUNT waves until
    /// at least `min_verified` `reportable: true` claims at or
    /// above `min_severity` survive the cascade.
    FindVulnerabilities {
        #[serde(default = "default_min_verified")]
        min_verified: u32,
        /// `info|low|medium|high|critical`.
        #[serde(default = "default_min_sev")]
        min_severity: String,
    },
    /// "Authenticate and re-scan" — succeeds when `auth_status`
    /// becomes `authenticated` AND a re-scan has been done.
    AuthenticatedScan,
    /// Class-specific hunt: "find idor", "find sqli", etc.
    /// Succeeds on ≥1 verified reportable claim whose
    /// `vuln_class` contains the supplied substring.
    SpecificVulnClass { vuln_class: String },
    /// Operator-supplied free-form goal. The orchestrator passes
    /// `description` to the hunter brief but cannot
    /// auto-determine completion — the operator must call
    /// `mantis goal mark-met` explicitly.
    Custom { description: String },
}

fn default_min_surfaces() -> u32 {
    5
}
fn default_stagnation() -> u32 {
    2
}
fn default_min_verified() -> u32 {
    1
}
fn default_min_sev() -> String {
    "medium".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalStatus {
    Pending,
    InProgress,
    Met,
    Abandoned,
}

impl GoalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            GoalStatus::Pending => "pending",
            GoalStatus::InProgress => "in_progress",
            GoalStatus::Met => "met",
            GoalStatus::Abandoned => "abandoned",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Goal {
    pub kind: GoalKind,
    pub description: String,
    pub status: GoalStatus,
    /// Wall-clock unix seconds when the goal was first attached.
    pub opened_at_unix: u64,
    /// Wall-clock unix seconds when the goal transitioned to Met
    /// or Abandoned. `None` while in flight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at_unix: Option<u64>,
    /// Number of waves / passes the orchestrator has spent on this
    /// goal so far. Useful for stagnation detection.
    #[serde(default)]
    pub passes_spent: u32,
    /// Snapshot of `explored.len()` at the end of the prior pass —
    /// used by `EnumerateEndpoints` to detect stagnation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_surface_count: Option<u32>,
    /// Consecutive passes that produced zero new surfaces. Tracked
    /// for `EnumerateEndpoints` stagnation cap.
    #[serde(default)]
    pub stagnation_streak: u32,
}

impl Goal {
    pub fn new(kind: GoalKind, description: impl Into<String>, now_unix: u64) -> Self {
        Self {
            kind,
            description: description.into(),
            status: GoalStatus::Pending,
            opened_at_unix: now_unix,
            closed_at_unix: None,
            passes_spent: 0,
            last_surface_count: None,
            stagnation_streak: 0,
        }
    }

    /// Parse a free-form goal string into a structured `Goal`. The
    /// description always carries the original string verbatim. The
    /// kind is inferred by simple keyword matching; unknowns become
    /// [`GoalKind::Custom`].
    pub fn parse(description: impl AsRef<str>, now_unix: u64) -> Self {
        let raw = description.as_ref();
        let lower = raw.to_ascii_lowercase();
        let kind = if lower.contains("endpoint")
            || lower.contains("surface")
            || lower.contains("enumerate")
        {
            GoalKind::EnumerateEndpoints {
                min_surfaces: default_min_surfaces(),
                stagnation_passes: default_stagnation(),
            }
        } else if lower.contains("auth") && lower.contains("scan") {
            GoalKind::AuthenticatedScan
        } else if lower.contains("vuln") || lower.contains("bug") || lower.contains("find") {
            // Look for an inline vuln class hint.
            for class in [
                "idor",
                "sqli",
                "xss",
                "ssrf",
                "rce",
                "xxe",
                "csrf",
                "open-redirect",
                "auth-bypass",
                "broken-access-control",
            ] {
                if lower.contains(class) {
                    return Self {
                        kind: GoalKind::SpecificVulnClass {
                            vuln_class: class.into(),
                        },
                        description: raw.into(),
                        status: GoalStatus::Pending,
                        opened_at_unix: now_unix,
                        closed_at_unix: None,
                        passes_spent: 0,
                        last_surface_count: None,
                        stagnation_streak: 0,
                    };
                }
            }
            GoalKind::FindVulnerabilities {
                min_verified: default_min_verified(),
                min_severity: default_min_sev(),
            }
        } else {
            GoalKind::Custom {
                description: raw.into(),
            }
        };
        Self::new(kind, raw, now_unix)
    }

    /// Returns `Met`, `InProgress`, or (for `Custom`) `Pending`.
    /// The orchestrator calls this after every pass and stops
    /// iterating once the result is `Met`.
    pub fn evaluate(
        &self,
        explored_count: u32,
        reportable_findings: &[FindingSummary],
    ) -> GoalStatus {
        match &self.kind {
            GoalKind::EnumerateEndpoints {
                min_surfaces,
                stagnation_passes,
            } => {
                if explored_count >= *min_surfaces && self.stagnation_streak >= *stagnation_passes {
                    GoalStatus::Met
                } else if self.passes_spent == 0 {
                    GoalStatus::Pending
                } else {
                    GoalStatus::InProgress
                }
            }
            GoalKind::FindVulnerabilities {
                min_verified,
                min_severity,
            } => {
                let threshold = severity_rank(min_severity);
                let qualifying = reportable_findings
                    .iter()
                    .filter(|f| severity_rank(&f.severity) >= threshold)
                    .count() as u32;
                if qualifying >= *min_verified {
                    GoalStatus::Met
                } else if self.passes_spent == 0 {
                    GoalStatus::Pending
                } else {
                    GoalStatus::InProgress
                }
            }
            GoalKind::SpecificVulnClass { vuln_class } => {
                let needle = vuln_class.to_ascii_lowercase();
                if reportable_findings
                    .iter()
                    .any(|f| f.vuln_class.to_ascii_lowercase().contains(&needle))
                {
                    GoalStatus::Met
                } else if self.passes_spent == 0 {
                    GoalStatus::Pending
                } else {
                    GoalStatus::InProgress
                }
            }
            GoalKind::AuthenticatedScan => GoalStatus::InProgress, // operator-marked
            GoalKind::Custom { .. } => GoalStatus::InProgress,     // operator-marked
        }
    }

    /// Bookkeeping the orchestrator calls after every pass. Updates
    /// `passes_spent`, `last_surface_count`, and
    /// `stagnation_streak`.
    pub fn record_pass(&mut self, explored_count: u32) {
        self.passes_spent += 1;
        if let Some(prev) = self.last_surface_count {
            if explored_count <= prev {
                self.stagnation_streak += 1;
            } else {
                self.stagnation_streak = 0;
            }
        } else {
            self.stagnation_streak = 0;
        }
        self.last_surface_count = Some(explored_count);
        if matches!(self.status, GoalStatus::Pending) {
            self.status = GoalStatus::InProgress;
        }
    }

    pub fn mark_met(&mut self, now_unix: u64) {
        self.status = GoalStatus::Met;
        self.closed_at_unix = Some(now_unix);
    }

    pub fn mark_abandoned(&mut self, now_unix: u64) {
        self.status = GoalStatus::Abandoned;
        self.closed_at_unix = Some(now_unix);
    }

    pub fn is_done(&self) -> bool {
        matches!(self.status, GoalStatus::Met | GoalStatus::Abandoned)
    }
}

impl fmt::Display for GoalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Compact summary that the orchestrator hands to `Goal::evaluate`.
/// Decoupled from `FindingVerdict` so callers can supply either
/// fresh wave findings or cascade survivors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSummary {
    pub finding_id: String,
    pub vuln_class: String,
    pub severity: String,
}

fn severity_rank(s: &str) -> u8 {
    match s.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(class: &str, sev: &str) -> FindingSummary {
        FindingSummary {
            finding_id: format!("F-{class}"),
            vuln_class: class.into(),
            severity: sev.into(),
        }
    }

    #[test]
    fn parse_endpoints() {
        let g = Goal::parse("find all endpoints", 0);
        assert!(matches!(
            g.kind,
            GoalKind::EnumerateEndpoints {
                min_surfaces: 5,
                stagnation_passes: 2
            }
        ));
        assert_eq!(g.description, "find all endpoints");
        assert_eq!(g.status, GoalStatus::Pending);
    }

    #[test]
    fn parse_authenticated_scan() {
        let g = Goal::parse("authenticate then scan", 0);
        assert!(matches!(g.kind, GoalKind::AuthenticatedScan));
    }

    #[test]
    fn parse_specific_vuln_class() {
        let g = Goal::parse("find IDOR bugs", 0);
        assert!(
            matches!(g.kind, GoalKind::SpecificVulnClass { ref vuln_class } if vuln_class == "idor")
        );
    }

    #[test]
    fn parse_generic_find_vulns() {
        let g = Goal::parse("find vulnerabilities", 0);
        assert!(matches!(g.kind, GoalKind::FindVulnerabilities { .. }));
    }

    #[test]
    fn parse_custom_falls_back() {
        let g = Goal::parse("write a haiku", 0);
        assert!(
            matches!(g.kind, GoalKind::Custom { ref description } if description == "write a haiku")
        );
    }

    #[test]
    fn enumerate_endpoints_needs_surfaces_and_stagnation() {
        let mut g = Goal::parse("find all endpoints", 0);
        // 3 surfaces, no stagnation -> in_progress (after first pass).
        g.record_pass(3);
        assert_eq!(g.evaluate(3, &[]), GoalStatus::InProgress);
        // 10 surfaces, stagnation 0 -> in_progress (we need stagnation).
        g.last_surface_count = Some(10);
        g.stagnation_streak = 0;
        assert_eq!(g.evaluate(10, &[]), GoalStatus::InProgress);
        // 10 surfaces, stagnation 2 -> met.
        g.stagnation_streak = 2;
        assert_eq!(g.evaluate(10, &[]), GoalStatus::Met);
    }

    #[test]
    fn find_vulnerabilities_needs_medium_or_higher() {
        let mut g = Goal::parse("find vulnerabilities", 0);
        g.record_pass(5);
        // One low-severity reportable: not enough.
        assert_eq!(
            g.evaluate(5, &[finding("info-disclosure", "low")]),
            GoalStatus::InProgress
        );
        // One medium: meets the default.
        assert_eq!(
            g.evaluate(5, &[finding("xss-reflected", "medium")]),
            GoalStatus::Met
        );
    }

    #[test]
    fn specific_class_matches_substring() {
        let mut g = Goal::parse("find IDOR", 0);
        g.record_pass(5);
        assert_eq!(
            g.evaluate(5, &[finding("broken-access-control.idor", "high")]),
            GoalStatus::Met
        );
        // Wrong class: still in_progress.
        let mut g2 = Goal::parse("find SQLi", 0);
        g2.record_pass(5);
        assert_eq!(
            g2.evaluate(5, &[finding("xss-reflected", "medium")]),
            GoalStatus::InProgress
        );
    }

    #[test]
    fn record_pass_tracks_stagnation() {
        let mut g = Goal::parse("find all endpoints", 0);
        g.record_pass(3); // first pass: stagnation 0
        assert_eq!(g.stagnation_streak, 0);
        g.record_pass(3); // same count: stagnation 1
        assert_eq!(g.stagnation_streak, 1);
        g.record_pass(3); // same count: stagnation 2
        assert_eq!(g.stagnation_streak, 2);
        g.record_pass(7); // new surfaces: stagnation resets
        assert_eq!(g.stagnation_streak, 0);
    }

    #[test]
    fn mark_met_closes_out() {
        let mut g = Goal::parse("find all endpoints", 1000);
        g.mark_met(1500);
        assert_eq!(g.status, GoalStatus::Met);
        assert_eq!(g.closed_at_unix, Some(1500));
        assert!(g.is_done());
    }

    #[test]
    fn json_round_trip() {
        let g = Goal::parse("find IDOR", 0);
        let j = serde_json::to_string(&g).unwrap();
        let back: Goal = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }
}
