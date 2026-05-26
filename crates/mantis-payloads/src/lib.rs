//! mantis-payloads — versioned, categorized payload corpus.
//!
//! ## What this crate is
//!
//! A pure-data crate: zero runtime, no I/O. Embeds a curated subset
//! of two upstream corpora into the binary so primitive / fuzzer /
//! scanner crates can reach for battle-tested seed inputs without a
//! disk dependency.
//!
//! Upstream sources (both MIT-licensed):
//! - `swisskyrepo/PayloadsAllTheThings`
//! - `danielmiessler/SecLists`
//!
//! The vendored snapshots are reproduced verbatim where the upstream
//! license requires preservation of the original payload text;
//! taxonomy and Rust packaging are original to Mantis.
//!
//! ## Versioning
//!
//! [`CORPUS_VERSION`] is bumped whenever a payload is added, removed,
//! or relabelled. Downstream crates that produce evidence chains
//! should record this string so reproducers stay reproducible.
//!
//! ## Public API
//!
//! - [`PayloadCategory`] enumerates the vulnerability classes covered.
//! - [`Payload`] is a single seed input with provenance metadata.
//! - [`catalog`] returns the full vendored corpus as a slice.
//! - [`for_category`] returns only payloads for one class.

pub mod cmdi;
pub mod lfi;
pub mod open_redirect;
pub mod sqli;
pub mod ssrf;
pub mod ssti;
pub mod wordlists;
pub mod xss;
pub mod xxe;

use serde::{Deserialize, Serialize};

/// Bumped when the embedded corpus changes. Downstream evidence
/// chains should record this so reproducers can pin to the exact
/// payload set.
pub const CORPUS_VERSION: &str = "2026.05.25-1";

/// Vulnerability classes the corpus covers. The full set is small on
/// purpose — these are the categories Mantis's primitive crate
/// already knows how to chain into a verifiable claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PayloadCategory {
    Sqli,
    Xss,
    Ssti,
    Lfi,
    Cmdi,
    Ssrf,
    Xxe,
    OpenRedirect,
}

impl PayloadCategory {
    /// All known categories. Order is stable.
    pub fn all() -> &'static [PayloadCategory] {
        &[
            PayloadCategory::Sqli,
            PayloadCategory::Xss,
            PayloadCategory::Ssti,
            PayloadCategory::Lfi,
            PayloadCategory::Cmdi,
            PayloadCategory::Ssrf,
            PayloadCategory::Xxe,
            PayloadCategory::OpenRedirect,
        ]
    }

    /// Short kebab-case slug — matches the `serde(rename_all)`
    /// representation. Useful for filenames + log lines.
    pub fn slug(self) -> &'static str {
        match self {
            PayloadCategory::Sqli => "sqli",
            PayloadCategory::Xss => "xss",
            PayloadCategory::Ssti => "ssti",
            PayloadCategory::Lfi => "lfi",
            PayloadCategory::Cmdi => "cmdi",
            PayloadCategory::Ssrf => "ssrf",
            PayloadCategory::Xxe => "xxe",
            PayloadCategory::OpenRedirect => "open-redirect",
        }
    }
}

/// One seed payload.
///
/// `value` is the literal byte sequence to inject; `notes` is a short
/// human-readable annotation (used in claim evidence so a triager can
/// see *why* this string was chosen); `tags` are free-form labels
/// (e.g. `"mysql"`, `"polyglot"`, `"oast"`) that primitives can
/// filter on.
///
/// `Deserialize` is intentionally omitted — payloads are embedded
/// constants, not data flowing in from the wire. Downstream code that
/// needs an owned version should convert via [`Payload::to_owned`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Payload {
    pub category: PayloadCategory,
    pub value: &'static str,
    pub notes: &'static str,
    pub tags: &'static [&'static str],
}

/// Owned counterpart for downstream code that needs to mutate or
/// serialize/deserialize payloads (e.g. in the evidence log).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedPayload {
    pub category: PayloadCategory,
    pub value: String,
    pub notes: String,
    pub tags: Vec<String>,
}

impl Payload {
    /// Stable string used when computing per-payload provenance
    /// hashes in the merkle log. Includes the corpus version so the
    /// hash changes whenever the embedded text changes.
    pub fn provenance_key(&self) -> String {
        format!("{}|{}|{}", CORPUS_VERSION, self.category.slug(), self.value)
    }

    /// Convert to an owned, deserializable representation.
    pub fn to_owned_payload(&self) -> OwnedPayload {
        OwnedPayload {
            category: self.category,
            value: self.value.to_string(),
            notes: self.notes.to_string(),
            tags: self.tags.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// All embedded payloads concatenated. Cheap — every nested slice is
/// `&'static`, so this just clones pointer + length pairs.
pub fn catalog() -> Vec<Payload> {
    let mut out = Vec::new();
    out.extend_from_slice(sqli::PAYLOADS);
    out.extend_from_slice(xss::PAYLOADS);
    out.extend_from_slice(ssti::PAYLOADS);
    out.extend_from_slice(lfi::PAYLOADS);
    out.extend_from_slice(cmdi::PAYLOADS);
    out.extend_from_slice(ssrf::PAYLOADS);
    out.extend_from_slice(xxe::PAYLOADS);
    out.extend_from_slice(open_redirect::PAYLOADS);
    out
}

/// Just the payloads tagged with `category`.
pub fn for_category(category: PayloadCategory) -> &'static [Payload] {
    match category {
        PayloadCategory::Sqli => sqli::PAYLOADS,
        PayloadCategory::Xss => xss::PAYLOADS,
        PayloadCategory::Ssti => ssti::PAYLOADS,
        PayloadCategory::Lfi => lfi::PAYLOADS,
        PayloadCategory::Cmdi => cmdi::PAYLOADS,
        PayloadCategory::Ssrf => ssrf::PAYLOADS,
        PayloadCategory::Xxe => xxe::PAYLOADS,
        PayloadCategory::OpenRedirect => open_redirect::PAYLOADS,
    }
}

/// Payloads matching `tag` (case-sensitive). Returns owned `Vec`
/// because the filter is rarely on the hot path.
pub fn with_tag(tag: &str) -> Vec<Payload> {
    catalog()
        .into_iter()
        .filter(|p| p.tags.contains(&tag))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_version_is_semver_ish() {
        assert!(CORPUS_VERSION.contains('.'));
        assert!(!CORPUS_VERSION.is_empty());
    }

    #[test]
    fn every_category_has_payloads() {
        for c in PayloadCategory::all() {
            let p = for_category(*c);
            assert!(!p.is_empty(), "no payloads for {:?}", c);
        }
    }

    #[test]
    fn category_slugs_round_trip_through_serde() {
        for c in PayloadCategory::all() {
            let j = serde_json::to_string(c).unwrap();
            let back: PayloadCategory = serde_json::from_str(&j).unwrap();
            assert_eq!(*c, back);
            // Slug should appear in serialized form.
            assert!(j.contains(c.slug()), "slug {} missing in {}", c.slug(), j);
        }
    }

    #[test]
    fn category_slugs_unique() {
        let mut slugs: Vec<&str> = PayloadCategory::all().iter().map(|c| c.slug()).collect();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(slugs.len(), PayloadCategory::all().len());
    }

    #[test]
    fn payload_provenance_key_is_stable_and_distinct() {
        let a = &sqli::PAYLOADS[0];
        let b = &xss::PAYLOADS[0];
        assert_ne!(a.provenance_key(), b.provenance_key());
        assert_eq!(a.provenance_key(), a.provenance_key());
        assert!(a.provenance_key().contains(CORPUS_VERSION));
    }

    #[test]
    fn catalog_contains_every_category_payload() {
        let total: usize = PayloadCategory::all()
            .iter()
            .map(|c| for_category(*c).len())
            .sum();
        assert_eq!(catalog().len(), total);
    }

    #[test]
    fn with_tag_finds_known_tag() {
        // SSTI corpus tags Jinja payloads with "jinja2".
        let jinja = with_tag("jinja2");
        assert!(!jinja.is_empty());
        assert!(jinja.iter().all(|p| p.category == PayloadCategory::Ssti));
    }

    #[test]
    fn payload_category_field_matches_module() {
        for p in sqli::PAYLOADS {
            assert_eq!(p.category, PayloadCategory::Sqli);
        }
        for p in xss::PAYLOADS {
            assert_eq!(p.category, PayloadCategory::Xss);
        }
        for p in lfi::PAYLOADS {
            assert_eq!(p.category, PayloadCategory::Lfi);
        }
    }

    #[test]
    fn wordlists_module_is_non_empty() {
        assert!(!wordlists::COMMON_API_PATHS.is_empty());
        assert!(!wordlists::COMMON_SUBDOMAINS.is_empty());
        assert!(!wordlists::COMMON_PARAMS.is_empty());
    }

    #[test]
    fn payload_serializes_to_json() {
        let p = &sqli::PAYLOADS[0];
        let j = serde_json::to_string(p).unwrap();
        assert!(j.contains("sqli"));
        assert!(j.contains("value"));
    }

    #[test]
    fn owned_payload_round_trips_through_serde() {
        let owned = sqli::PAYLOADS[0].to_owned_payload();
        let j = serde_json::to_string(&owned).unwrap();
        let back: OwnedPayload = serde_json::from_str(&j).unwrap();
        assert_eq!(owned, back);
    }
}
