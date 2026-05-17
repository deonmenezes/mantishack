//! Severity model shared by FSM, grader, and renderer.
//!
//! Five tiers matching the OWASP / CVSS-aligned canon. `Info` is the
//! default for unclassified or recon-only observations and is excluded
//! from rendered reports unless the operator drops the floor.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

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
    /// Higher rank = higher severity.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

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

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" | "informational" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(format!("unknown severity: {other}")),
        }
    }
}

/// Severity floor: findings strictly below the floor are dropped from
/// rendered reports. The Mantis report renderer defaults to
/// [`SeverityFloor::Low`]; operators may relax to [`SeverityFloor::Info`]
/// for internal noise sweeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityFloor {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityFloor {
    pub const DEFAULT: SeverityFloor = SeverityFloor::Low;

    pub fn admits(self, sev: Severity) -> bool {
        sev.rank() >= self.threshold().rank()
    }

    fn threshold(self) -> Severity {
        match self {
            SeverityFloor::Info => Severity::Info,
            SeverityFloor::Low => Severity::Low,
            SeverityFloor::Medium => Severity::Medium,
            SeverityFloor::High => Severity::High,
            SeverityFloor::Critical => Severity::Critical,
        }
    }
}

impl Default for SeverityFloor {
    fn default() -> Self {
        SeverityFloor::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_strictly_increases() {
        assert!(Severity::Critical.rank() > Severity::High.rank());
        assert!(Severity::High.rank() > Severity::Medium.rank());
        assert!(Severity::Medium.rank() > Severity::Low.rank());
        assert!(Severity::Low.rank() > Severity::Info.rank());
    }

    #[test]
    fn parse_round_trips() {
        for s in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(Severity::from_str(s.as_str()).unwrap(), s);
        }
    }

    #[test]
    fn default_floor_drops_info() {
        let floor = SeverityFloor::default();
        assert!(!floor.admits(Severity::Info));
        assert!(floor.admits(Severity::Low));
        assert!(floor.admits(Severity::Critical));
    }

    #[test]
    fn high_floor_drops_low_and_medium() {
        let floor = SeverityFloor::High;
        assert!(!floor.admits(Severity::Low));
        assert!(!floor.admits(Severity::Medium));
        assert!(floor.admits(Severity::High));
        assert!(floor.admits(Severity::Critical));
    }

    #[test]
    fn info_floor_admits_everything() {
        let floor = SeverityFloor::Info;
        for s in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert!(floor.admits(s));
        }
    }

    #[test]
    fn json_round_trip() {
        let s = Severity::High;
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, "\"high\"");
        let back: Severity = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
