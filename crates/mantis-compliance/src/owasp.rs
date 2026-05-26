//! OWASP Top 10 (2021) categories and CWE → Top 10 mapping.
//!
//! Source: <https://owasp.org/Top10/> (2021 mapping notes).
//!
//! The 2021 list maps each category to a set of "Notable CWEs". Many CWEs are
//! mentioned only by reference and several CWEs map to more than one category
//! conceptually — this table captures the *primary* mapping the OWASP team
//! publishes, suitable for surface-level claim categorization in reports.
//!
//! For weaknesses outside the table, [`owasp_for_cwe`] returns `None` rather
//! than guessing. The planner can then either fall back on heuristics or leave
//! the claim untagged.

use serde::{Deserialize, Serialize};

use crate::cwe::Cwe;

/// OWASP Top 10 — 2021 edition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OwaspTop10 {
    /// A01:2021 — Broken Access Control.
    A01BrokenAccessControl,
    /// A02:2021 — Cryptographic Failures.
    A02CryptographicFailures,
    /// A03:2021 — Injection.
    A03Injection,
    /// A04:2021 — Insecure Design.
    A04InsecureDesign,
    /// A05:2021 — Security Misconfiguration.
    A05SecurityMisconfiguration,
    /// A06:2021 — Vulnerable and Outdated Components.
    A06VulnerableComponents,
    /// A07:2021 — Identification and Authentication Failures.
    A07AuthenticationFailures,
    /// A08:2021 — Software and Data Integrity Failures.
    A08IntegrityFailures,
    /// A09:2021 — Security Logging and Monitoring Failures.
    A09LoggingFailures,
    /// A10:2021 — Server-Side Request Forgery (SSRF).
    A10Ssrf,
}

impl OwaspTop10 {
    /// Canonical short identifier, e.g. `"A01:2021"`.
    pub const fn id(self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "A01:2021",
            Self::A02CryptographicFailures => "A02:2021",
            Self::A03Injection => "A03:2021",
            Self::A04InsecureDesign => "A04:2021",
            Self::A05SecurityMisconfiguration => "A05:2021",
            Self::A06VulnerableComponents => "A06:2021",
            Self::A07AuthenticationFailures => "A07:2021",
            Self::A08IntegrityFailures => "A08:2021",
            Self::A09LoggingFailures => "A09:2021",
            Self::A10Ssrf => "A10:2021",
        }
    }

    /// Human-readable title.
    pub const fn title(self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "Broken Access Control",
            Self::A02CryptographicFailures => "Cryptographic Failures",
            Self::A03Injection => "Injection",
            Self::A04InsecureDesign => "Insecure Design",
            Self::A05SecurityMisconfiguration => "Security Misconfiguration",
            Self::A06VulnerableComponents => "Vulnerable and Outdated Components",
            Self::A07AuthenticationFailures => "Identification and Authentication Failures",
            Self::A08IntegrityFailures => "Software and Data Integrity Failures",
            Self::A09LoggingFailures => "Security Logging and Monitoring Failures",
            Self::A10Ssrf => "Server-Side Request Forgery (SSRF)",
        }
    }

    /// All ten categories in numerical order.
    pub const fn all() -> [OwaspTop10; 10] {
        [
            Self::A01BrokenAccessControl,
            Self::A02CryptographicFailures,
            Self::A03Injection,
            Self::A04InsecureDesign,
            Self::A05SecurityMisconfiguration,
            Self::A06VulnerableComponents,
            Self::A07AuthenticationFailures,
            Self::A08IntegrityFailures,
            Self::A09LoggingFailures,
            Self::A10Ssrf,
        ]
    }
}

/// Map a CWE to its primary OWASP Top 10 (2021) category, if any.
///
/// The table covers the "Notable CWEs" enumerated by the OWASP 2021 release
/// for each category. Returns `None` for CWEs outside that set rather than
/// guessing — the planner can fall back to heuristics or leave the claim
/// untagged.
pub const fn owasp_for_cwe(cwe: Cwe) -> Option<OwaspTop10> {
    use OwaspTop10::*;
    // Authoritative source: https://owasp.org/Top10/ (notable-CWEs per category, 2021 edition).
    // Listed roughly in CWE-ID order within each branch; duplicates that OWASP
    // shows under multiple categories are mapped to the most-specific category.
    Some(match cwe.0 {
        // A01 — Broken Access Control
        22 | 23 | 35 | 59 | 200 | 201 | 219 | 264 | 275 | 276 | 284 | 285 | 352 | 359 | 377
        | 402 | 425 | 441 | 497 | 538 | 540 | 552 | 566 | 601 | 639 | 651 | 668 | 706 | 862
        | 863 | 913 | 922 | 1275 => A01BrokenAccessControl,

        // A02 — Cryptographic Failures
        261 | 296 | 310 | 319 | 321 | 322 | 323 | 324 | 325 | 326 | 327 | 328 | 329 | 330 | 331
        | 335 | 336 | 337 | 338 | 340 | 347 | 523 | 720 | 757 | 759 | 760 | 780 | 818 | 916 => {
            A02CryptographicFailures
        }

        // A03 — Injection (includes XSS in 2021 per OWASP's mapping)
        20 | 74 | 75 | 77 | 78 | 79 | 80 | 83 | 87 | 88 | 89 | 90 | 91 | 93 | 94 | 95 | 96 | 97
        | 98 | 99 | 100 | 113 | 116 | 138 | 184 | 470 | 471 | 564 | 610 | 643 | 644 | 652 | 917 => {
            A03Injection
        }

        // A04 — Insecure Design
        73 | 183 | 209 | 213 | 235 | 256 | 257 | 266 | 269 | 280 | 311 | 312 | 313 | 316 | 419
        | 430 | 434 | 444 | 451 | 472 | 501 | 522 | 525 | 539 | 579 | 598 | 602 | 642 | 646
        | 650 | 653 | 656 | 657 | 799 | 807 | 840 | 841 | 927 | 1021 | 1173 => A04InsecureDesign,

        // A05 — Security Misconfiguration (XXE is here in 2021)
        2 | 11 | 13 | 15 | 16 | 260 | 315 | 520 | 526 | 537 | 541 | 547 | 611 | 614 | 756 | 776
        | 942 | 1004 | 1032 | 1174 => A05SecurityMisconfiguration,

        // A06 — Vulnerable and Outdated Components
        937 | 1035 | 1104 => A06VulnerableComponents,

        // A07 — Identification and Authentication Failures
        255 | 259 | 287 | 288 | 290 | 294 | 295 | 297 | 300 | 302 | 304 | 306 | 307 | 346 | 384
        | 521 | 613 | 620 | 640 | 798 | 940 | 1216 => A07AuthenticationFailures,

        // A08 — Software and Data Integrity Failures
        345 | 353 | 426 | 494 | 502 | 565 | 784 | 829 | 830 | 915 => A08IntegrityFailures,

        // A09 — Security Logging and Monitoring Failures
        117 | 223 | 532 | 778 => A09LoggingFailures,

        // A10 — Server-Side Request Forgery
        918 => A10Ssrf,

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_categories_have_distinct_ids() {
        let mut ids: Vec<&str> = OwaspTop10::all().iter().map(|c| c.id()).collect();
        let original_len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), original_len);
        assert_eq!(ids.len(), 10);
    }

    #[test]
    fn all_categories_have_titles() {
        for cat in OwaspTop10::all() {
            assert!(!cat.title().is_empty());
        }
    }

    #[test]
    fn sqli_maps_to_injection() {
        assert_eq!(owasp_for_cwe(Cwe(89)), Some(OwaspTop10::A03Injection));
    }

    #[test]
    fn xss_maps_to_injection_in_2021() {
        // OWASP merged XSS into Injection for the 2021 edition.
        assert_eq!(owasp_for_cwe(Cwe(79)), Some(OwaspTop10::A03Injection));
    }

    #[test]
    fn path_traversal_maps_to_access_control() {
        assert_eq!(
            owasp_for_cwe(Cwe(22)),
            Some(OwaspTop10::A01BrokenAccessControl)
        );
    }

    #[test]
    fn ssrf_maps_to_a10() {
        assert_eq!(owasp_for_cwe(Cwe(918)), Some(OwaspTop10::A10Ssrf));
    }

    #[test]
    fn log4j_jndi_cwe_maps_to_injection() {
        // CWE-917 (Improper Neutralization of Special Elements used in an
        // Expression Language Statement) — the Log4Shell CWE.
        assert_eq!(owasp_for_cwe(Cwe(917)), Some(OwaspTop10::A03Injection));
    }

    #[test]
    fn xxe_maps_to_misconfiguration_in_2021() {
        // OWASP moved XXE into Security Misconfiguration in 2021.
        assert_eq!(
            owasp_for_cwe(Cwe(611)),
            Some(OwaspTop10::A05SecurityMisconfiguration)
        );
    }

    #[test]
    fn deserialization_cwe_then_owasp_lookup() {
        // Used in the report pipeline: deserialize "CWE-89" from a feed, then
        // ask for its OWASP category.
        let cwe: Cwe = serde_json::from_str("\"CWE-89\"").unwrap();
        assert_eq!(owasp_for_cwe(cwe), Some(OwaspTop10::A03Injection));
    }

    #[test]
    fn unmapped_cwe_returns_none() {
        // CWE-1234567 doesn't exist in MITRE's catalog; should not be tagged.
        assert_eq!(owasp_for_cwe(Cwe(1_234_567)), None);
    }

    #[test]
    fn vulnerable_components_known_cwes_map() {
        assert_eq!(
            owasp_for_cwe(Cwe(1104)),
            Some(OwaspTop10::A06VulnerableComponents)
        );
    }

    #[test]
    fn ids_match_canonical_format() {
        assert_eq!(OwaspTop10::A01BrokenAccessControl.id(), "A01:2021");
        assert_eq!(OwaspTop10::A10Ssrf.id(), "A10:2021");
    }
}
