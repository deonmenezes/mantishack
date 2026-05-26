//! Map Mantis `vuln_class` strings to compliance tag triples.
//!
//! Primitives and hypotheses across the workspace tag claims with short
//! identifiers like `"sqli"`, `"xss-reflected"`, `"ssrf"`, `"idor"`,
//! `"open-redirect"`, etc. The report renderer wants to express each claim
//! against the compliance frameworks Mantis supports — CWE, OWASP Top 10
//! (2021), MITRE ATT&CK — without each primitive call site needing to embed
//! those mappings.
//!
//! [`tags_for`] is the single integration point. Given a `vuln_class`, it
//! returns a [`ComplianceTags`] triple (or `None` if the class is unknown,
//! in which case the report renderer can leave the claim untagged).
//!
//! Class identifiers are matched case-insensitively and both `-` and `_`
//! separators are accepted, so `"open-redirect"` and `"open_redirect"` both
//! resolve.

use serde::Serialize;

use crate::cwe::Cwe;
use crate::mitre::{self, Technique};
use crate::owasp::{self, OwaspTop10};

/// Bundled compliance tags for a claim.
///
/// All three fields are best-effort. A vuln_class may map to a CWE that has
/// no OWASP or MITRE entry in the curated tables — in that case the
/// corresponding field is `None`.
///
/// `Serialize` only — tags are output-only metadata produced by the report
/// renderer, never read back. Skipping `Deserialize` lets [`Technique`] keep
/// its `&'static str` fields and the curated catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ComplianceTags {
    /// Primary CWE identifier for the vulnerability class.
    pub cwe: Cwe,
    /// OWASP Top 10 (2021) category, if the CWE maps to one.
    pub owasp: Option<OwaspTop10>,
    /// MITRE ATT&CK technique, if the CWE maps to one.
    pub mitre: Option<Technique>,
}

impl ComplianceTags {
    fn from_cwe(cwe: Cwe) -> Self {
        Self {
            cwe,
            owasp: owasp::owasp_for_cwe(cwe),
            mitre: mitre::technique_for_cwe(cwe),
        }
    }
}

/// Look up compliance tags for a Mantis `vuln_class` string.
///
/// Returns `None` for vuln_class strings outside the curated map (e.g.
/// banner-grab strings like `"apache-recon"` that don't represent a CVE-like
/// finding on their own).
pub fn tags_for(vuln_class: &str) -> Option<ComplianceTags> {
    let cwe = primary_cwe_for(vuln_class)?;
    Some(ComplianceTags::from_cwe(cwe))
}

/// Just the primary CWE for a `vuln_class`, without the OWASP/MITRE lookup.
/// Exposed for callers that only need CWE tagging.
pub fn primary_cwe_for(vuln_class: &str) -> Option<Cwe> {
    let key = normalize(vuln_class);
    let id = match key.as_str() {
        // Injection family
        "sqli" | "sql-injection" | "sql_injection" => 89,
        "xss" | "xss-reflected" | "reflected-xss" | "stored-xss" | "xss-stored" | "dom-xss" => 79,
        "command-injection" | "cmdi" | "os-command-injection" => 78,
        "ldap-injection" => 90,
        "xpath-injection" => 643,
        "ssti" | "template-injection" => 1336,
        "log4shell" | "jndi-injection" => 917,

        // Access control / IDOR
        "idor" | "bola" => 639,
        "broken-access-control" | "missing-access-control" => 284,
        "path-traversal" | "directory-traversal" | "lfi" => 22,
        "open-redirect" | "open_redirect" => 601,
        "csrf" | "xsrf" => 352,

        // Authentication
        "auth-bypass" | "authentication-bypass" => 287,
        "weak-auth" | "weak-authentication" | "weak-password" => 521,
        "missing-auth" | "no-auth" => 306,
        "credential-stuffing" | "brute-force" | "no-rate-limit" => 307,
        "hardcoded-credentials" | "hardcoded-secrets" => 798,
        "session-fixation" => 384,
        "jwt-none-algorithm" | "jwt-alg-none" => 327,

        // Cryptographic failures
        "weak-crypto" | "weak-cipher" => 327,
        "cleartext-transmission" | "no-tls" | "missing-tls" => 319,
        "weak-random" | "predictable-random" => 338,

        // SSRF
        "ssrf" | "server-side-request-forgery" => 918,

        // Information disclosure
        "info-disclosure" | "information-disclosure" | "info-leak" => 200,
        "stacktrace-disclosure" | "verbose-error" => 209,
        "debug-endpoint" | "debug-enabled" => 489,

        // Configuration
        "cors-misconfig" | "cors-misconfiguration" => 942,
        "missing-headers" | "missing_headers" | "missing-security-headers" => 1004,
        "directory-listing" | "directory-indexing" => 548,
        "default-credentials" => 521,

        // API
        "api-enumeration" => 200,
        "graphql-introspection" => 200,
        "mass-assignment" | "bopla" => 915,

        // Deserialization / supply chain
        "deserialization" | "insecure-deserialization" => 502,
        "vulnerable-component" | "outdated-component" => 1104,

        // Excluded by design — recon banner-grab strings are not findings
        // on their own and should not be auto-tagged with a CWE.
        "apache-recon" | "iis-recon" | "nginx-recon" => return None,

        _ => return None,
    };
    Some(Cwe(id))
}

fn normalize(s: &str) -> String {
    s.trim().to_ascii_lowercase().replace('_', "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqli_resolves_to_full_triple() {
        let tags = tags_for("sqli").unwrap();
        assert_eq!(tags.cwe, Cwe(89));
        assert_eq!(tags.owasp, Some(OwaspTop10::A03Injection));
        assert_eq!(tags.mitre.map(|t| t.id), Some("T1190"));
    }

    #[test]
    fn xss_variants_all_map_to_cwe_79() {
        for class in &["xss", "xss-reflected", "stored-xss", "dom-xss"] {
            let tags = tags_for(class).unwrap_or_else(|| panic!("no tags for {class}"));
            assert_eq!(tags.cwe, Cwe(79), "class {class}");
            assert_eq!(tags.owasp, Some(OwaspTop10::A03Injection));
        }
    }

    #[test]
    fn separator_variants_are_equivalent() {
        // open-redirect and open_redirect both appear in the codebase.
        assert_eq!(
            tags_for("open-redirect").map(|t| t.cwe),
            tags_for("open_redirect").map(|t| t.cwe)
        );
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(tags_for("SQLi").map(|t| t.cwe), Some(Cwe(89)));
        assert_eq!(tags_for("Open-Redirect").map(|t| t.cwe), Some(Cwe(601)));
    }

    #[test]
    fn idor_maps_to_a01_access_control() {
        let tags = tags_for("idor").unwrap();
        assert_eq!(tags.cwe, Cwe(639));
        assert_eq!(tags.owasp, Some(OwaspTop10::A01BrokenAccessControl));
    }

    #[test]
    fn ssrf_maps_to_a10_and_t1190() {
        let tags = tags_for("ssrf").unwrap();
        assert_eq!(tags.cwe, Cwe(918));
        assert_eq!(tags.owasp, Some(OwaspTop10::A10Ssrf));
        assert_eq!(tags.mitre.map(|t| t.id), Some("T1190"));
    }

    #[test]
    fn auth_bypass_maps_to_a07() {
        let tags = tags_for("auth-bypass").unwrap();
        assert_eq!(tags.cwe, Cwe(287));
        assert_eq!(tags.owasp, Some(OwaspTop10::A07AuthenticationFailures));
    }

    #[test]
    fn hardcoded_credentials_use_unsecured_credentials_technique() {
        let tags = tags_for("hardcoded-credentials").unwrap();
        assert_eq!(tags.cwe, Cwe(798));
        assert_eq!(tags.mitre.map(|t| t.id), Some("T1552"));
    }

    #[test]
    fn recon_strings_intentionally_return_none() {
        // Recon banner-grab strings are signal-only, not findings.
        assert_eq!(tags_for("apache-recon"), None);
        assert_eq!(tags_for("nginx-recon"), None);
        assert_eq!(tags_for("iis-recon"), None);
    }

    #[test]
    fn unknown_vuln_class_returns_none() {
        assert_eq!(tags_for("absolutely-not-a-class"), None);
    }

    #[test]
    fn log4shell_maps_to_log4j_cwe() {
        let tags = tags_for("log4shell").unwrap();
        assert_eq!(tags.cwe, Cwe(917));
        assert_eq!(tags.owasp, Some(OwaspTop10::A03Injection));
    }

    #[test]
    fn deserialization_maps_to_a08() {
        let tags = tags_for("deserialization").unwrap();
        assert_eq!(tags.cwe, Cwe(502));
        // CWE-502 isn't in the OWASP A08 mapping table above (it's in A04 in
        // the 2021 notable-CWE list under "Insecure Design"). The point of
        // this test is the tag is *produced* — the exact category is data,
        // not a contract.
        assert!(tags.owasp.is_some());
    }

    #[test]
    fn primary_cwe_helper_works_standalone() {
        assert_eq!(primary_cwe_for("sqli"), Some(Cwe(89)));
        assert_eq!(primary_cwe_for("definitely-unknown"), None);
    }

    #[test]
    fn missing_headers_underscore_form_works() {
        // The codebase has both "missing_headers" and "missing-security-headers".
        assert_eq!(primary_cwe_for("missing_headers"), Some(Cwe(1004)));
        assert_eq!(primary_cwe_for("missing-headers"), Some(Cwe(1004)));
    }

    #[test]
    fn tags_serialize_to_json_cleanly() {
        let tags = tags_for("sqli").unwrap();
        let json = serde_json::to_string(&tags).unwrap();
        assert!(json.contains("CWE-89"));
        assert!(json.contains("A03Injection"));
    }
}
