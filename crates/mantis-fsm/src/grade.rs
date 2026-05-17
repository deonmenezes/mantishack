//! Five-axis grader and SUBMIT/HOLD/SKIP verdict.
//!
//! Score = impact (0-30) + proof_quality (0-25) + severity_accuracy
//! (0-15) + chain_potential (0-15) + report_quality (0-15). Caps and
//! thresholds match hacker-bob's grader.

use crate::Severity;
use serde::{Deserialize, Serialize};

pub const GRADE_HOLD_MIN_SCORE: u16 = 20;
pub const GRADE_SUBMIT_MIN_SCORE: u16 = 40;

const IMPACT_MAX: u16 = 30;
const PROOF_MAX: u16 = 25;
const SEVERITY_MAX: u16 = 15;
const CHAIN_MAX: u16 = 15;
const REPORT_MAX: u16 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Submit,
    Hold,
    Skip,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Submit => "SUBMIT",
            Verdict::Hold => "HOLD",
            Verdict::Skip => "SKIP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxisScores {
    pub impact: u16,
    pub proof_quality: u16,
    pub severity_accuracy: u16,
    pub chain_potential: u16,
    pub report_quality: u16,
}

impl AxisScores {
    pub fn total(self) -> u16 {
        self.impact
            .saturating_add(self.proof_quality)
            .saturating_add(self.severity_accuracy)
            .saturating_add(self.chain_potential)
            .saturating_add(self.report_quality)
    }

    /// Returns the first axis whose value exceeds its cap, if any.
    pub fn validate(self) -> Result<(), String> {
        if self.impact > IMPACT_MAX {
            return Err(format!("impact > {IMPACT_MAX}"));
        }
        if self.proof_quality > PROOF_MAX {
            return Err(format!("proof_quality > {PROOF_MAX}"));
        }
        if self.severity_accuracy > SEVERITY_MAX {
            return Err(format!("severity_accuracy > {SEVERITY_MAX}"));
        }
        if self.chain_potential > CHAIN_MAX {
            return Err(format!("chain_potential > {CHAIN_MAX}"));
        }
        if self.report_quality > REPORT_MAX {
            return Err(format!("report_quality > {REPORT_MAX}"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingGrade {
    pub finding_id: String,
    pub severity: Severity,
    pub axes: AxisScores,
    pub total_score: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback: Option<String>,
}

impl FindingGrade {
    pub fn new(
        finding_id: impl Into<String>,
        severity: Severity,
        axes: AxisScores,
    ) -> Result<Self, String> {
        axes.validate()?;
        let total_score = axes.total();
        Ok(Self {
            finding_id: finding_id.into(),
            severity,
            axes,
            total_score,
            feedback: None,
        })
    }

    pub fn with_feedback(mut self, fb: impl Into<String>) -> Self {
        self.feedback = Some(fb.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GradeVerdict {
    pub verdict: Verdict,
    pub total_score: u16,
    pub findings: Vec<FindingGrade>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback: Option<String>,
}

impl GradeVerdict {
    /// Compute a verdict from the supplied finding grades. Matches
    /// hacker-bob: `SUBMIT` requires total ≥ 40 AND at least one
    /// Medium-or-higher finding; otherwise `HOLD` (20–39) or `SKIP`
    /// (< 20). Empty `findings` always grades as `SKIP`.
    pub fn compute(findings: Vec<FindingGrade>, feedback: Option<String>) -> Self {
        if findings.is_empty() {
            return Self {
                verdict: Verdict::Skip,
                total_score: 0,
                findings,
                feedback,
            };
        }
        let total_score = findings.iter().map(|f| f.total_score).sum::<u16>();
        let has_medium_or_higher = findings
            .iter()
            .any(|f| f.severity.rank() >= Severity::Medium.rank());

        let verdict = if total_score >= GRADE_SUBMIT_MIN_SCORE && has_medium_or_higher {
            Verdict::Submit
        } else if total_score >= GRADE_HOLD_MIN_SCORE {
            Verdict::Hold
        } else {
            Verdict::Skip
        };

        Self {
            verdict,
            total_score,
            findings,
            feedback,
        }
    }

    pub fn is_submit(&self) -> bool {
        matches!(self.verdict, Verdict::Submit)
    }
    pub fn is_hold(&self) -> bool {
        matches!(self.verdict, Verdict::Hold)
    }
    pub fn is_skip(&self) -> bool {
        matches!(self.verdict, Verdict::Skip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perfect_axes() -> AxisScores {
        AxisScores {
            impact: 30,
            proof_quality: 25,
            severity_accuracy: 15,
            chain_potential: 15,
            report_quality: 15,
        }
    }

    #[test]
    fn perfect_axes_total_100() {
        assert_eq!(perfect_axes().total(), 100);
    }

    #[test]
    fn axis_over_cap_is_rejected() {
        let bad = AxisScores {
            impact: 31,
            proof_quality: 0,
            severity_accuracy: 0,
            chain_potential: 0,
            report_quality: 0,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn submit_requires_high_score_and_medium_or_higher() {
        let f =
            FindingGrade::new("F-1", Severity::High, perfect_axes()).unwrap();
        let v = GradeVerdict::compute(vec![f], None);
        assert!(v.is_submit());
        assert_eq!(v.total_score, 100);
    }

    #[test]
    fn submit_requires_at_least_medium_even_at_high_score() {
        let low = FindingGrade::new("F-1", Severity::Low, perfect_axes()).unwrap();
        let v = GradeVerdict::compute(vec![low], None);
        // 100 points but severity Low -> not eligible for SUBMIT; HOLD
        // because total >= 20.
        assert_eq!(v.verdict, Verdict::Hold);
    }

    #[test]
    fn hold_range_is_20_to_39() {
        let axes = AxisScores {
            impact: 10,
            proof_quality: 10,
            severity_accuracy: 5,
            chain_potential: 0,
            report_quality: 5,
        };
        let f = FindingGrade::new("F-1", Severity::High, axes).unwrap();
        let v = GradeVerdict::compute(vec![f], None);
        assert_eq!(v.total_score, 30);
        assert!(v.is_hold());
    }

    #[test]
    fn skip_below_20() {
        let axes = AxisScores {
            impact: 5,
            proof_quality: 5,
            severity_accuracy: 5,
            chain_potential: 0,
            report_quality: 0,
        };
        let f = FindingGrade::new("F-1", Severity::High, axes).unwrap();
        let v = GradeVerdict::compute(vec![f], None);
        assert_eq!(v.total_score, 15);
        assert!(v.is_skip());
    }

    #[test]
    fn empty_findings_grade_skip() {
        let v = GradeVerdict::compute(vec![], None);
        assert!(v.is_skip());
        assert_eq!(v.total_score, 0);
    }

    #[test]
    fn json_round_trip() {
        let f = FindingGrade::new("F-1", Severity::High, perfect_axes()).unwrap();
        let v = GradeVerdict::compute(vec![f], Some("looks good".into()));
        let j = serde_json::to_string(&v).unwrap();
        let back: GradeVerdict = serde_json::from_str(&j).unwrap();
        assert_eq!(v, back);
    }
}
