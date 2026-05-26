//! OWASP Mobile Application Security Verification Standard v2 control tagging.
//!
//! Reference: <https://mas.owasp.org/MASVS/>.
//!
//! MASVS v2 organizes mobile-specific verification requirements into 7 control
//! categories (MASVS-STORAGE, MASVS-CRYPTO, MASVS-AUTH, MASVS-NETWORK,
//! MASVS-PLATFORM, MASVS-CODE, MASVS-RESILIENCE). This module exposes the
//! taxonomy and a best-effort CWE → control mapping for mobile findings.

use serde::{Deserialize, Serialize};

use crate::cwe::Cwe;

/// MASVS v2 control category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MasvsControl {
    /// MASVS-STORAGE — secure storage of sensitive data.
    Storage,
    /// MASVS-CRYPTO — cryptography best practices.
    Crypto,
    /// MASVS-AUTH — authentication and authorization controls.
    Auth,
    /// MASVS-NETWORK — secure network communications.
    Network,
    /// MASVS-PLATFORM — secure interaction with the underlying mobile platform.
    Platform,
    /// MASVS-CODE — secure coding and tamper-resistant binaries.
    Code,
    /// MASVS-RESILIENCE — resilience against reverse engineering and tampering.
    Resilience,
}

impl MasvsControl {
    /// Canonical control identifier (`"MASVS-STORAGE"` etc.).
    pub const fn id(self) -> &'static str {
        match self {
            Self::Storage => "MASVS-STORAGE",
            Self::Crypto => "MASVS-CRYPTO",
            Self::Auth => "MASVS-AUTH",
            Self::Network => "MASVS-NETWORK",
            Self::Platform => "MASVS-PLATFORM",
            Self::Code => "MASVS-CODE",
            Self::Resilience => "MASVS-RESILIENCE",
        }
    }

    /// One-line category description.
    pub const fn title(self) -> &'static str {
        match self {
            Self::Storage => "Secure Storage of Sensitive Data",
            Self::Crypto => "Cryptography Best Practices",
            Self::Auth => "Authentication and Authorization",
            Self::Network => "Network Communication",
            Self::Platform => "Platform Interaction",
            Self::Code => "Code Quality and Build Setting",
            Self::Resilience => "Resilience Against Reverse Engineering and Tampering",
        }
    }

    /// All 7 control categories in canonical order.
    pub const fn all() -> [MasvsControl; 7] {
        [
            Self::Storage,
            Self::Crypto,
            Self::Auth,
            Self::Network,
            Self::Platform,
            Self::Code,
            Self::Resilience,
        ]
    }
}

/// Map a CWE to its primary MASVS control category, if any.
///
/// The mapping focuses on mobile-relevant CWEs. Web-only CWEs (e.g. CSRF,
/// SSRF) intentionally return `None` — they belong to ASVS, not MASVS.
pub const fn masvs_for_cwe(cwe: Cwe) -> Option<MasvsControl> {
    use MasvsControl::*;
    Some(match cwe.0 {
        // Storage — sensitive data at rest on device.
        200 | 312 | 313 | 359 | 522 | 532 | 538 | 921 | 922 => Storage,

        // Crypto
        261 | 310 | 311 | 321 | 326 | 327 | 329 | 330 | 331 | 338 | 916 => Crypto,

        // Auth (mobile-relevant: biometric, device, session)
        287 | 290 | 294 | 295 | 297 | 306 | 798 | 308 => Auth,

        // Network (TLS pinning, cleartext)
        296 | 319 | 322 | 323 | 324 | 325 | 523 | 757 | 940 => Network,

        // Platform — IPC misuse, deeplinks, exposed components.
        927 | 939 => Platform,

        // Code — buffer overflows, format strings, IL/native code injection.
        119 | 120 | 121 | 122 | 134 | 250 | 367 | 415 | 416 | 476 | 787 => Code,

        // Resilience — tamper detection, anti-debug, obfuscation.
        693 | 1278 | 1357 => Resilience,

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_controls_have_distinct_ids() {
        let mut ids: Vec<&str> = MasvsControl::all().iter().map(|c| c.id()).collect();
        let len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), len);
        assert_eq!(ids.len(), 7);
    }

    #[test]
    fn titles_non_empty() {
        for c in MasvsControl::all() {
            assert!(!c.title().is_empty());
        }
    }

    #[test]
    fn ids_match_canonical_form() {
        assert_eq!(MasvsControl::Storage.id(), "MASVS-STORAGE");
        assert_eq!(MasvsControl::Resilience.id(), "MASVS-RESILIENCE");
    }

    #[test]
    fn cleartext_storage_maps_to_storage() {
        assert_eq!(masvs_for_cwe(Cwe(312)), Some(MasvsControl::Storage));
    }

    #[test]
    fn hardcoded_creds_map_to_auth() {
        assert_eq!(masvs_for_cwe(Cwe(798)), Some(MasvsControl::Auth));
    }

    #[test]
    fn cleartext_transmission_maps_to_network() {
        assert_eq!(masvs_for_cwe(Cwe(319)), Some(MasvsControl::Network));
    }

    #[test]
    fn weak_crypto_maps_to_crypto() {
        assert_eq!(masvs_for_cwe(Cwe(327)), Some(MasvsControl::Crypto));
    }

    #[test]
    fn buffer_overflow_maps_to_code() {
        assert_eq!(masvs_for_cwe(Cwe(120)), Some(MasvsControl::Code));
    }

    #[test]
    fn unmapped_cwe_returns_none() {
        // CWE-918 (SSRF) is web-only — no MASVS mapping.
        assert_eq!(masvs_for_cwe(Cwe(918)), None);
        assert_eq!(masvs_for_cwe(Cwe(1_234_567)), None);
    }

    #[test]
    fn ipc_misuse_maps_to_platform() {
        assert_eq!(masvs_for_cwe(Cwe(927)), Some(MasvsControl::Platform));
    }
}
