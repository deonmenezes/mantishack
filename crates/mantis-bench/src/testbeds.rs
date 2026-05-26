//! Catalog of intentionally vulnerable testbeds for regression testing.
//!
//! Mantis runs against published vulnerable targets (DVWA, OWASP Juice Shop,
//! WebGoat, VulnHub images) on every release to prove that primitives still
//! land on the vulnerabilities they're designed to find. This module is the
//! single source of truth for those targets:
//!
//! - Docker image references for pull/run.
//! - Expected vulnerability classes per route (vuln_class strings the
//!   primitives emit).
//! - Recommended scan profile (recon/web/auth).
//!
//! The harness that drives regression runs ([`mantis_bench::regression`])
//! iterates these entries, runs Mantis against the local Docker target, and
//! compares the produced claims against the `expected_findings` list.

use serde::Serialize;

/// One intentionally vulnerable testbed.
///
/// `Serialize` only — the catalog is static data; consumers serialize it for
/// report metadata and harness output. Deserializing into a struct with
/// `&'static str` fields isn't compatible with how serde manages lifetimes,
/// so it's intentionally omitted.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Testbed {
    /// Short identifier (`"dvwa"`, `"juice-shop"`, `"webgoat"`).
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Upstream project URL.
    pub upstream_url: &'static str,
    /// License of the upstream project (affects vendoring decisions).
    pub license: &'static str,
    /// Docker image to pull, fully qualified (`registry/name:tag`).
    pub docker_image: &'static str,
    /// Default port exposed by the container.
    pub default_port: u16,
    /// HTTP path prefix where the app is rooted (typically `"/"`).
    pub base_path: &'static str,
    /// Expected vulnerability classes the scanner should find when run with
    /// the recommended profile. Each entry is a `vuln_class` string the
    /// primitives emit (matches `mantis_compliance::tags_for` keys).
    pub expected_findings: &'static [&'static str],
    /// Recommended Mantis scan profile name.
    pub recommended_profile: &'static str,
    /// Notes — quirks, login requirements, gotchas.
    pub notes: &'static str,
}

/// DVWA — Damn Vulnerable Web Application (PHP).
pub const DVWA: Testbed = Testbed {
    id: "dvwa",
    name: "DVWA — Damn Vulnerable Web Application",
    upstream_url: "https://github.com/digininja/DVWA",
    license: "GPL-3.0",
    docker_image: "vulnerables/web-dvwa:latest",
    default_port: 80,
    base_path: "/",
    expected_findings: &[
        "sqli",
        "xss-reflected",
        "xss",
        "command-injection",
        "csrf",
        "path-traversal",
        "weak-auth",
        "broken-access-control",
    ],
    recommended_profile: "web-authenticated",
    notes: "Requires login (admin/password) and Security level set to Low for full coverage.",
};

/// OWASP Juice Shop — modern Node.js/Angular vulnerable web app.
pub const JUICE_SHOP: Testbed = Testbed {
    id: "juice-shop",
    name: "OWASP Juice Shop",
    upstream_url: "https://github.com/juice-shop/juice-shop",
    license: "MIT",
    docker_image: "bkimminich/juice-shop:latest",
    default_port: 3000,
    base_path: "/",
    expected_findings: &[
        "sqli",
        "xss",
        "xss-reflected",
        "idor",
        "broken-access-control",
        "ssti",
        "open-redirect",
        "weak-auth",
        "hardcoded-credentials",
        "info-disclosure",
        "mass-assignment",
    ],
    recommended_profile: "web-full",
    notes: "No login required for many flaws. JS-heavy SPA — use mantis-crawler-dynamic for full coverage.",
};

/// WebGoat — OWASP Java-based learning platform.
pub const WEBGOAT: Testbed = Testbed {
    id: "webgoat",
    name: "OWASP WebGoat",
    upstream_url: "https://github.com/WebGoat/WebGoat",
    license: "GPL-2.0",
    docker_image: "webgoat/webgoat:latest",
    default_port: 8080,
    base_path: "/WebGoat/",
    expected_findings: &[
        "sqli",
        "xss",
        "xss-reflected",
        "broken-access-control",
        "idor",
        "csrf",
        "deserialization",
        "ssrf",
        "auth-bypass",
        "weak-auth",
    ],
    recommended_profile: "web-authenticated",
    notes: "Lesson-based — many vulns gated behind interactive flows. Use Selenium or scripted state to exercise.",
};

/// VulnHub — collection of intentionally vulnerable VMs (catch-all entry).
/// Specific VMs are added by image-tag override at run time.
pub const VULNHUB: Testbed = Testbed {
    id: "vulnhub",
    name: "VulnHub",
    upstream_url: "https://www.vulnhub.com/",
    license: "Various (per-VM)",
    docker_image: "vulnhub/placeholder:latest",
    default_port: 80,
    base_path: "/",
    expected_findings: &[],
    recommended_profile: "recon-full",
    notes: "Placeholder entry — VulnHub VMs are downloaded as OVA/VMDK individually; harness sets a per-VM testbed.",
};

/// All built-in testbeds.
pub const ALL: &[&Testbed] = &[&DVWA, &JUICE_SHOP, &WEBGOAT, &VULNHUB];

/// Look up a testbed by its short identifier.
pub fn by_id(id: &str) -> Option<&'static Testbed> {
    ALL.iter().copied().find(|tb| tb.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_testbeds_have_unique_ids() {
        let mut ids: Vec<&str> = ALL.iter().map(|tb| tb.id).collect();
        let len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), len);
    }

    #[test]
    fn all_testbeds_have_docker_image_and_url() {
        for tb in ALL {
            assert!(
                !tb.docker_image.is_empty(),
                "{} missing docker_image",
                tb.id
            );
            assert!(
                !tb.upstream_url.is_empty(),
                "{} missing upstream_url",
                tb.id
            );
        }
    }

    #[test]
    fn lookup_by_id_returns_expected() {
        assert_eq!(by_id("dvwa").unwrap().id, "dvwa");
        assert_eq!(by_id("juice-shop").unwrap().id, "juice-shop");
        assert_eq!(by_id("webgoat").unwrap().id, "webgoat");
        assert!(by_id("nonexistent").is_none());
    }

    #[test]
    fn dvwa_includes_sqli_xss_in_expected_findings() {
        assert!(DVWA.expected_findings.contains(&"sqli"));
        assert!(DVWA.expected_findings.contains(&"xss"));
    }

    #[test]
    fn juice_shop_lists_modern_app_vulns() {
        assert!(JUICE_SHOP.expected_findings.contains(&"mass-assignment"));
        assert!(JUICE_SHOP.expected_findings.contains(&"open-redirect"));
    }

    #[test]
    fn licenses_are_documented() {
        for tb in ALL {
            assert!(!tb.license.is_empty(), "{} missing license", tb.id);
        }
    }

    #[test]
    fn ports_are_nonzero_for_real_targets() {
        for tb in &[&DVWA, &JUICE_SHOP, &WEBGOAT] {
            assert!(tb.default_port > 0, "{} has zero port", tb.id);
        }
    }

    #[test]
    fn vulnhub_is_a_placeholder_with_empty_findings() {
        // VulnHub entries are per-VM; the catch-all placeholder must not
        // accidentally assert findings for the placeholder itself.
        assert!(VULNHUB.expected_findings.is_empty());
    }

    #[test]
    fn serializes_to_json_cleanly() {
        let json = serde_json::to_string(&DVWA).unwrap();
        assert!(json.contains("\"id\":\"dvwa\""));
        assert!(json.contains("\"docker_image\":\"vulnerables/web-dvwa"));
        assert!(json.contains("sqli"));
    }
}
