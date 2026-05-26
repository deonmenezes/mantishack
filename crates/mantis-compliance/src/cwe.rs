//! Common Weakness Enumeration (CWE) identifiers.
//!
//! Strings like `"CWE-89"` are passed around the codebase in feed parsers and
//! report templates. This wrapper normalizes the format (uppercase prefix,
//! integer body) so downstream code can compare and serialize them without
//! re-parsing strings.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A CWE identifier such as `CWE-79` (Cross-site Scripting).
///
/// Constructed from a `u32` ID; renders as `CWE-<id>` and serializes/parses
/// from the same canonical string form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cwe(pub u32);

impl Cwe {
    /// Construct a CWE from its numeric ID.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Numeric ID without the `CWE-` prefix.
    pub fn id(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Cwe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CWE-{}", self.0)
    }
}

/// Error returned when a string cannot be parsed as a CWE identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CweParseError {
    /// The string did not start with the `CWE-` prefix (case-insensitive).
    #[error("missing CWE- prefix")]
    MissingPrefix,
    /// The numeric body could not be parsed as a u32.
    #[error("invalid CWE id: {0}")]
    InvalidId(String),
}

impl FromStr for Cwe {
    type Err = CweParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let body = s
            .strip_prefix("CWE-")
            .or_else(|| s.strip_prefix("cwe-"))
            .or_else(|| s.strip_prefix("Cwe-"))
            .ok_or(CweParseError::MissingPrefix)?;
        let id: u32 = body
            .parse()
            .map_err(|_| CweParseError::InvalidId(body.to_string()))?;
        Ok(Cwe(id))
    }
}

impl Serialize for Cwe {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cwe {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_uses_canonical_form() {
        assert_eq!(Cwe(89).to_string(), "CWE-89");
        assert_eq!(Cwe(1).to_string(), "CWE-1");
    }

    #[test]
    fn parse_accepts_canonical_form() {
        assert_eq!("CWE-79".parse::<Cwe>().unwrap(), Cwe(79));
    }

    #[test]
    fn parse_is_case_insensitive_for_prefix() {
        assert_eq!("cwe-22".parse::<Cwe>().unwrap(), Cwe(22));
        assert_eq!("Cwe-22".parse::<Cwe>().unwrap(), Cwe(22));
    }

    #[test]
    fn parse_rejects_missing_prefix() {
        assert_eq!("79".parse::<Cwe>(), Err(CweParseError::MissingPrefix));
    }

    #[test]
    fn parse_rejects_non_numeric() {
        assert!(matches!(
            "CWE-abc".parse::<Cwe>(),
            Err(CweParseError::InvalidId(_))
        ));
    }

    #[test]
    fn parse_trims_whitespace() {
        assert_eq!("  CWE-79  ".parse::<Cwe>().unwrap(), Cwe(79));
    }

    #[test]
    fn round_trips_through_serde_json() {
        let cwe = Cwe(89);
        let s = serde_json::to_string(&cwe).unwrap();
        assert_eq!(s, "\"CWE-89\"");
        let back: Cwe = serde_json::from_str(&s).unwrap();
        assert_eq!(back, cwe);
    }

    #[test]
    fn ordering_is_by_numeric_id() {
        assert!(Cwe(20) < Cwe(79));
        assert!(Cwe(917) > Cwe(89));
    }
}
