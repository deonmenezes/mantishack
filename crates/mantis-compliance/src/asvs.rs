//! OWASP Application Security Verification Standard v4 chapter tagging.
//!
//! Reference: <https://owasp.org/www-project-application-security-verification-standard/>.
//!
//! ASVS v4 organizes ~286 verification requirements into 14 chapters (V1–V14).
//! Each requirement has CWE references in the appendix mapping. This module
//! exposes the chapter taxonomy and a best-effort CWE → chapter mapper for
//! coverage reporting. The full requirement-level granularity (V2.1.1, etc.)
//! is intentionally out of scope — Mantis tags claims at the chapter level,
//! which matches how ASVS coverage is reported in pentest deliverables.

use serde::{Deserialize, Serialize};

use crate::cwe::Cwe;

/// ASVS v4 chapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AsvsChapter {
    /// V1 — Architecture, Design and Threat Modeling.
    V1Architecture,
    /// V2 — Authentication.
    V2Authentication,
    /// V3 — Session Management.
    V3Session,
    /// V4 — Access Control.
    V4AccessControl,
    /// V5 — Validation, Sanitization and Encoding.
    V5Validation,
    /// V6 — Stored Cryptography.
    V6Cryptography,
    /// V7 — Error Handling and Logging.
    V7Logging,
    /// V8 — Data Protection.
    V8DataProtection,
    /// V9 — Communications.
    V9Communications,
    /// V10 — Malicious Code.
    V10MaliciousCode,
    /// V11 — Business Logic.
    V11BusinessLogic,
    /// V12 — Files and Resources.
    V12FilesAndResources,
    /// V13 — API and Web Service.
    V13Api,
    /// V14 — Configuration.
    V14Configuration,
}

impl AsvsChapter {
    /// Canonical chapter ID (`"V1"`–`"V14"`).
    pub const fn id(self) -> &'static str {
        match self {
            Self::V1Architecture => "V1",
            Self::V2Authentication => "V2",
            Self::V3Session => "V3",
            Self::V4AccessControl => "V4",
            Self::V5Validation => "V5",
            Self::V6Cryptography => "V6",
            Self::V7Logging => "V7",
            Self::V8DataProtection => "V8",
            Self::V9Communications => "V9",
            Self::V10MaliciousCode => "V10",
            Self::V11BusinessLogic => "V11",
            Self::V12FilesAndResources => "V12",
            Self::V13Api => "V13",
            Self::V14Configuration => "V14",
        }
    }

    /// Chapter title.
    pub const fn title(self) -> &'static str {
        match self {
            Self::V1Architecture => "Architecture, Design and Threat Modeling",
            Self::V2Authentication => "Authentication",
            Self::V3Session => "Session Management",
            Self::V4AccessControl => "Access Control",
            Self::V5Validation => "Validation, Sanitization and Encoding",
            Self::V6Cryptography => "Stored Cryptography",
            Self::V7Logging => "Error Handling and Logging",
            Self::V8DataProtection => "Data Protection",
            Self::V9Communications => "Communications",
            Self::V10MaliciousCode => "Malicious Code",
            Self::V11BusinessLogic => "Business Logic",
            Self::V12FilesAndResources => "Files and Resources",
            Self::V13Api => "API and Web Service",
            Self::V14Configuration => "Configuration",
        }
    }

    /// All 14 chapters in order.
    pub const fn all() -> [AsvsChapter; 14] {
        [
            Self::V1Architecture,
            Self::V2Authentication,
            Self::V3Session,
            Self::V4AccessControl,
            Self::V5Validation,
            Self::V6Cryptography,
            Self::V7Logging,
            Self::V8DataProtection,
            Self::V9Communications,
            Self::V10MaliciousCode,
            Self::V11BusinessLogic,
            Self::V12FilesAndResources,
            Self::V13Api,
            Self::V14Configuration,
        ]
    }
}

/// Map a CWE to its primary ASVS chapter, if any.
pub const fn asvs_for_cwe(cwe: Cwe) -> Option<AsvsChapter> {
    use AsvsChapter::*;
    Some(match cwe.0 {
        // V2 — Authentication
        255 | 259 | 287 | 288 | 290 | 294 | 295 | 297 | 300 | 306 | 307 | 521 | 798 => {
            V2Authentication
        }

        // V3 — Session Management
        352 | 384 | 539 | 613 | 614 => V3Session,

        // V4 — Access Control
        22 | 23 | 35 | 200 | 264 | 269 | 275 | 276 | 284 | 285 | 425 | 552 | 639 | 668 | 862
        | 863 => V4AccessControl,

        // V5 — Validation, Sanitization, Encoding (Injection family)
        20 | 74 | 75 | 77 | 78 | 79 | 80 | 83 | 87 | 88 | 89 | 90 | 91 | 94 | 95 | 116 | 643
        | 917 => V5Validation,

        // V6 — Cryptography
        261 | 310 | 311 | 320 | 321 | 326 | 327 | 329 | 330 | 331 | 338 | 916 => V6Cryptography,

        // V7 — Error Handling / Logging
        117 | 209 | 223 | 489 | 532 | 778 => V7Logging,

        // V8 — Data Protection
        212 | 256 | 312 | 313 | 359 | 522 | 538 | 540 => V8DataProtection,

        // V9 — Communications
        296 | 319 | 322 | 323 | 324 | 325 | 523 => V9Communications,

        // V11 — Business Logic
        366 | 367 | 837 | 840 | 841 => V11BusinessLogic,

        // V12 — Files and Resources
        73 | 426 | 434 => V12FilesAndResources,

        // V13 — API
        444 | 915 | 918 => V13Api,

        // V14 — Configuration
        2 | 11 | 13 | 15 | 16 | 260 | 526 | 537 | 547 | 942 | 1004 | 1032 => V14Configuration,

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_chapters_have_distinct_ids() {
        let mut ids: Vec<&str> = AsvsChapter::all().iter().map(|c| c.id()).collect();
        let len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), len);
        assert_eq!(ids.len(), 14);
    }

    #[test]
    fn chapter_titles_non_empty() {
        for c in AsvsChapter::all() {
            assert!(!c.title().is_empty());
        }
    }

    #[test]
    fn sqli_maps_to_validation_chapter() {
        assert_eq!(asvs_for_cwe(Cwe(89)), Some(AsvsChapter::V5Validation));
    }

    #[test]
    fn weak_password_maps_to_authentication() {
        assert_eq!(asvs_for_cwe(Cwe(521)), Some(AsvsChapter::V2Authentication));
    }

    #[test]
    fn csrf_maps_to_session_chapter() {
        assert_eq!(asvs_for_cwe(Cwe(352)), Some(AsvsChapter::V3Session));
    }

    #[test]
    fn ssrf_maps_to_api_chapter() {
        assert_eq!(asvs_for_cwe(Cwe(918)), Some(AsvsChapter::V13Api));
    }

    #[test]
    fn path_traversal_maps_to_access_control() {
        assert_eq!(asvs_for_cwe(Cwe(22)), Some(AsvsChapter::V4AccessControl));
    }

    #[test]
    fn cleartext_transmission_maps_to_communications() {
        assert_eq!(asvs_for_cwe(Cwe(319)), Some(AsvsChapter::V9Communications));
    }

    #[test]
    fn missing_security_headers_maps_to_configuration() {
        assert_eq!(asvs_for_cwe(Cwe(1004)), Some(AsvsChapter::V14Configuration));
    }

    #[test]
    fn unmapped_cwe_returns_none() {
        assert_eq!(asvs_for_cwe(Cwe(1_234_567)), None);
    }

    #[test]
    fn ids_match_canonical_format() {
        assert_eq!(AsvsChapter::V1Architecture.id(), "V1");
        assert_eq!(AsvsChapter::V14Configuration.id(), "V14");
    }
}
