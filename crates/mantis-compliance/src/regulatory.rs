//! Regulatory framework tagging — PCI-DSS, SOC2, HIPAA.
//!
//! Mantis claims need to be tagged with the regulatory controls they
//! implicate so enterprise reports can answer the auditor's question:
//! "what frameworks does this finding violate?" The tables here are
//! coarse — they tag claims at the *requirement family* level, not at
//! the individual control level, because:
//!
//! 1. Pentest findings rarely map cleanly to a single subrequirement.
//! 2. Auditors interpret findings against their own organization's
//!    control catalog; Mantis just needs to point them at the right
//!    chapter.
//!
//! Framework references:
//!
//! - **PCI-DSS v4.0** — <https://www.pcisecuritystandards.org/document_library/>
//!   Requirements 1–12.
//! - **SOC2 Trust Services Criteria** — <https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2>
//!   Categories CC (Common Criteria) 1–9, A (Availability), C (Confidentiality),
//!   PI (Processing Integrity), P (Privacy).
//! - **HIPAA Security Rule** — 45 CFR §164.308 (Administrative), §164.310
//!   (Physical), §164.312 (Technical safeguards).

use serde::{Deserialize, Serialize};

use crate::cwe::Cwe;

/// PCI-DSS v4.0 top-level requirement (Requirement 1–12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PciDssRequirement {
    /// Req 1 — Install and Maintain Network Security Controls.
    R1NetworkSecurity,
    /// Req 2 — Apply Secure Configurations to All System Components.
    R2SecureConfiguration,
    /// Req 3 — Protect Stored Account Data.
    R3StoredData,
    /// Req 4 — Protect Cardholder Data with Strong Cryptography During Transmission.
    R4Transmission,
    /// Req 5 — Protect All Systems and Networks from Malicious Software.
    R5Malware,
    /// Req 6 — Develop and Maintain Secure Systems and Software.
    R6SecureDevelopment,
    /// Req 7 — Restrict Access to System Components and Cardholder Data.
    R7AccessRestriction,
    /// Req 8 — Identify Users and Authenticate Access.
    R8Authentication,
    /// Req 9 — Restrict Physical Access.
    R9PhysicalAccess,
    /// Req 10 — Log and Monitor All Access.
    R10Logging,
    /// Req 11 — Test Security of Systems and Networks Regularly.
    R11Testing,
    /// Req 12 — Support Information Security with Organizational Policies.
    R12Policies,
}

impl PciDssRequirement {
    /// Canonical identifier (`"PCI-DSS-1"` etc.).
    pub fn id(self) -> String {
        format!("PCI-DSS-{}", self.number())
    }

    /// Numeric requirement (1–12).
    pub const fn number(self) -> u8 {
        match self {
            Self::R1NetworkSecurity => 1,
            Self::R2SecureConfiguration => 2,
            Self::R3StoredData => 3,
            Self::R4Transmission => 4,
            Self::R5Malware => 5,
            Self::R6SecureDevelopment => 6,
            Self::R7AccessRestriction => 7,
            Self::R8Authentication => 8,
            Self::R9PhysicalAccess => 9,
            Self::R10Logging => 10,
            Self::R11Testing => 11,
            Self::R12Policies => 12,
        }
    }
}

/// SOC2 Trust Services Criterion family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Soc2Criterion {
    /// CC6 — Logical and Physical Access Controls.
    CC6LogicalAccess,
    /// CC7 — System Operations.
    CC7Operations,
    /// CC8 — Change Management.
    CC8ChangeManagement,
    /// A1 — Availability.
    A1Availability,
    /// C1 — Confidentiality.
    C1Confidentiality,
    /// PI1 — Processing Integrity.
    PI1ProcessingIntegrity,
    /// P-Series — Privacy.
    PPrivacy,
}

impl Soc2Criterion {
    /// Canonical identifier (`"SOC2-CC6"` etc.).
    pub const fn id(self) -> &'static str {
        match self {
            Self::CC6LogicalAccess => "SOC2-CC6",
            Self::CC7Operations => "SOC2-CC7",
            Self::CC8ChangeManagement => "SOC2-CC8",
            Self::A1Availability => "SOC2-A1",
            Self::C1Confidentiality => "SOC2-C1",
            Self::PI1ProcessingIntegrity => "SOC2-PI1",
            Self::PPrivacy => "SOC2-P",
        }
    }
}

/// HIPAA Security Rule safeguard category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HipaaSafeguard {
    /// 45 CFR §164.308 — Administrative safeguards.
    Administrative,
    /// 45 CFR §164.310 — Physical safeguards.
    Physical,
    /// 45 CFR §164.312 — Technical safeguards.
    Technical,
}

impl HipaaSafeguard {
    /// Canonical CFR section.
    pub const fn cfr_section(self) -> &'static str {
        match self {
            Self::Administrative => "45 CFR §164.308",
            Self::Physical => "45 CFR §164.310",
            Self::Technical => "45 CFR §164.312",
        }
    }
}

/// Compliance tags across all three regulatory frameworks for a single CWE.
#[derive(Debug, Clone, Serialize)]
pub struct RegulatoryTags {
    /// PCI-DSS top-level requirement (none if CWE has no mapping).
    pub pci_dss: Option<PciDssRequirement>,
    /// SOC2 trust services criterion (none if no mapping).
    pub soc2: Option<Soc2Criterion>,
    /// HIPAA safeguard category (none if no mapping).
    pub hipaa: Option<HipaaSafeguard>,
}

/// Compute regulatory tags for a CWE.
pub fn regulatory_for_cwe(cwe: Cwe) -> RegulatoryTags {
    RegulatoryTags {
        pci_dss: pci_dss_for_cwe(cwe),
        soc2: soc2_for_cwe(cwe),
        hipaa: hipaa_for_cwe(cwe),
    }
}

/// Map a CWE to a primary PCI-DSS requirement.
pub const fn pci_dss_for_cwe(cwe: Cwe) -> Option<PciDssRequirement> {
    use PciDssRequirement::*;
    Some(match cwe.0 {
        // Req 6 — Secure development (most injection / coding-error CWEs)
        20 | 22 | 74 | 77 | 78 | 79 | 80 | 87 | 89 | 90 | 91 | 94 | 95 | 116 | 643 | 917 | 918 => {
            R6SecureDevelopment
        }
        // Req 7 — Access restriction (IDOR, missing access control)
        264 | 269 | 275 | 276 | 284 | 285 | 425 | 552 | 639 | 668 | 862 | 863 => R7AccessRestriction,
        // Req 8 — Authentication
        255 | 259 | 287 | 290 | 294 | 295 | 297 | 306 | 307 | 384 | 521 | 798 => R8Authentication,
        // Req 4 — Transmission protection (TLS)
        296 | 319 | 322 | 323 | 324 | 325 | 523 => R4Transmission,
        // Req 3 — Stored data protection
        261 | 311 | 312 | 313 | 321 | 326 | 327 | 916 => R3StoredData,
        // Req 10 — Logging
        117 | 223 | 489 | 532 | 778 => R10Logging,
        // Req 2 — Secure configuration
        2 | 11 | 13 | 15 | 16 | 260 | 526 | 537 | 547 | 614 | 942 | 1004 | 1032 => {
            R2SecureConfiguration
        }
        _ => return None,
    })
}

/// Map a CWE to a primary SOC2 criterion.
pub const fn soc2_for_cwe(cwe: Cwe) -> Option<Soc2Criterion> {
    use Soc2Criterion::*;
    Some(match cwe.0 {
        // CC6 — Logical and physical access controls (auth + access control)
        22 | 200 | 264 | 269 | 275 | 276 | 284 | 285 | 287 | 290 | 294 | 295 | 297 | 306 | 307
        | 425 | 521 | 552 | 639 | 668 | 798 | 862 | 863 => CC6LogicalAccess,

        // PI1 — Processing integrity (injection, deserialization, validation)
        20 | 74 | 77 | 78 | 79 | 80 | 89 | 90 | 94 | 95 | 502 | 917 | 918 | 915 => {
            PI1ProcessingIntegrity
        }

        // C1 — Confidentiality (info disclosure, exposed secrets, cleartext data)
        209 | 312 | 313 | 359 | 522 | 532 | 538 | 540 => C1Confidentiality,

        // CC7 — System operations / monitoring
        117 | 223 | 489 | 778 => CC7Operations,

        // C1 again for cleartext transit
        319 | 322 | 323 | 324 | 325 => C1Confidentiality,

        _ => return None,
    })
}

/// Map a CWE to a HIPAA safeguard category.
pub const fn hipaa_for_cwe(cwe: Cwe) -> Option<HipaaSafeguard> {
    use HipaaSafeguard::*;
    Some(match cwe.0 {
        // Technical — most app-level vulnerabilities fall here.
        20 | 22 | 74 | 77 | 78 | 79 | 80 | 89 | 90 | 94 | 95 | 116 | 200 | 209 | 264 | 269
        | 284 | 285 | 287 | 295 | 306 | 307 | 312 | 313 | 319 | 322 | 326 | 327 | 425 | 502
        | 521 | 532 | 538 | 552 | 639 | 798 | 862 | 863 | 915 | 917 | 918 => Technical,

        // Administrative — policy / monitoring / training gaps
        223 | 359 | 489 | 778 => Administrative,

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_dss_ids_are_canonical() {
        assert_eq!(PciDssRequirement::R6SecureDevelopment.id(), "PCI-DSS-6");
        assert_eq!(PciDssRequirement::R8Authentication.id(), "PCI-DSS-8");
        assert_eq!(PciDssRequirement::R12Policies.number(), 12);
    }

    #[test]
    fn soc2_ids_match_cc_format() {
        assert_eq!(Soc2Criterion::CC6LogicalAccess.id(), "SOC2-CC6");
        assert_eq!(Soc2Criterion::PI1ProcessingIntegrity.id(), "SOC2-PI1");
    }

    #[test]
    fn hipaa_cfr_sections_match() {
        assert_eq!(HipaaSafeguard::Technical.cfr_section(), "45 CFR §164.312");
        assert_eq!(HipaaSafeguard::Administrative.cfr_section(), "45 CFR §164.308");
    }

    #[test]
    fn sqli_tagged_across_three_frameworks() {
        let tags = regulatory_for_cwe(Cwe(89));
        assert_eq!(tags.pci_dss, Some(PciDssRequirement::R6SecureDevelopment));
        assert_eq!(tags.soc2, Some(Soc2Criterion::PI1ProcessingIntegrity));
        assert_eq!(tags.hipaa, Some(HipaaSafeguard::Technical));
    }

    #[test]
    fn idor_tagged_for_access_control_under_all_three() {
        let tags = regulatory_for_cwe(Cwe(639));
        assert_eq!(tags.pci_dss, Some(PciDssRequirement::R7AccessRestriction));
        assert_eq!(tags.soc2, Some(Soc2Criterion::CC6LogicalAccess));
        assert_eq!(tags.hipaa, Some(HipaaSafeguard::Technical));
    }

    #[test]
    fn cleartext_transmission_maps_to_pci_req4() {
        let tags = regulatory_for_cwe(Cwe(319));
        assert_eq!(tags.pci_dss, Some(PciDssRequirement::R4Transmission));
        assert_eq!(tags.soc2, Some(Soc2Criterion::C1Confidentiality));
    }

    #[test]
    fn hardcoded_creds_tag_for_pci_req8_auth() {
        let tags = regulatory_for_cwe(Cwe(798));
        assert_eq!(tags.pci_dss, Some(PciDssRequirement::R8Authentication));
        assert_eq!(tags.soc2, Some(Soc2Criterion::CC6LogicalAccess));
    }

    #[test]
    fn unmapped_cwe_returns_none_in_all_three() {
        let tags = regulatory_for_cwe(Cwe(1_234_567));
        assert!(tags.pci_dss.is_none());
        assert!(tags.soc2.is_none());
        assert!(tags.hipaa.is_none());
    }

    #[test]
    fn missing_security_headers_tagged_for_pci_req2() {
        let tags = regulatory_for_cwe(Cwe(1004));
        assert_eq!(tags.pci_dss, Some(PciDssRequirement::R2SecureConfiguration));
    }

    #[test]
    fn info_disclosure_is_confidentiality() {
        let tags = regulatory_for_cwe(Cwe(312));
        assert_eq!(tags.soc2, Some(Soc2Criterion::C1Confidentiality));
        assert_eq!(tags.hipaa, Some(HipaaSafeguard::Technical));
    }

    #[test]
    fn missing_logging_is_admin_safeguard() {
        let tags = regulatory_for_cwe(Cwe(778));
        assert_eq!(tags.hipaa, Some(HipaaSafeguard::Administrative));
        assert_eq!(tags.soc2, Some(Soc2Criterion::CC7Operations));
        assert_eq!(tags.pci_dss, Some(PciDssRequirement::R10Logging));
    }
}
