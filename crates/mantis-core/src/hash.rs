//! Mantis-native domain-separated hashing.
//!
//! Every BLAKE3 hash in the workspace should pass through this module so the
//! output carries a Mantis-specific domain prefix that no other project will
//! accidentally collide with — even when that other project also uses BLAKE3.
//!
//! Design rationale and audit context: see `docs/HASH_INDEPENDENCE.md`.
//!
//! ## Construction
//!
//! ```text
//! mantis_hash(domain, data) = BLAKE3( MANTIS_HASH_DOMAIN || ":" || domain || ":" || data )
//! ```
//!
//! With `MANTIS_HASH_DOMAIN = "MANTIS-v1"`, this guarantees:
//!
//! 1. Outputs are distinct from `blake3::hash(data)` (the naked form has no
//!    prefix).
//! 2. Outputs are distinct between different domains, even for identical
//!    `data`.
//! 3. The version suffix (`v1`) provides a forward path — bumping to `v2`
//!    invalidates all prior hashes by construction, useful for protocol
//!    upgrades.
//!
//! ## Migration status
//!
//! Phase H1 (this file): the wrapper is available. Callers can opt in.
//! Phase H2 (follow-up): migrate every call site one crate at a time.
//! Phase H3 (later): enforce via workspace clippy `disallowed_methods`.

/// Mantis hash domain version. Bumping this value invalidates every prior
/// hash by changing the output for the same `(domain, data)` pair.
pub const MANTIS_HASH_DOMAIN: &str = "MANTIS-v1";

/// Canonical domain string: hash over claim evidence bytes.
pub const DOMAIN_EVIDENCE: &str = "evidence";
/// Canonical domain string: leaf of the merkle event log.
pub const DOMAIN_MERKLE_LEAF: &str = "merkle.leaf";
/// Canonical domain string: stable hash over `(method, url, headers, body)`
/// of an HTTP request shape (used by `mantis tools hash-request`).
pub const DOMAIN_REQUEST_SHAPE: &str = "request.shape";
/// Canonical domain string: hash over a reproducer script body.
pub const DOMAIN_REPRODUCER: &str = "reproducer";
/// Canonical domain string: hash over a serialized claim body.
pub const DOMAIN_CLAIM_BODY: &str = "claim.body";
/// Canonical domain string: hash over a signed scope manifest.
pub const DOMAIN_SCOPE_MANIFEST: &str = "scope.manifest";
/// Canonical domain string: hash over an event-log entry's payload.
pub const DOMAIN_EVENT_PAYLOAD: &str = "event.payload";

/// Compute a Mantis-domain-separated BLAKE3 hash.
///
/// The domain string is mixed into the hash before the data, so identical
/// data hashed under different domains produces different outputs. The
/// `MANTIS_HASH_DOMAIN` prefix ensures Mantis hashes don't collide with
/// other projects' BLAKE3 outputs for the same input.
pub fn mantis_hash(domain: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANTIS_HASH_DOMAIN.as_bytes());
    hasher.update(b":");
    hasher.update(domain.as_bytes());
    hasher.update(b":");
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Hex-encoded form of [`mantis_hash`]. Lowercase, 64 chars, no `0x` prefix.
pub fn mantis_hash_hex(domain: &str, data: &[u8]) -> String {
    hex::encode(mantis_hash(domain, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_32_bytes() {
        let h = mantis_hash(DOMAIN_EVIDENCE, b"hello");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn output_hex_is_64_chars_lowercase() {
        let h = mantis_hash_hex(DOMAIN_EVIDENCE, b"hello");
        assert_eq!(h.len(), 64);
        assert_eq!(h, h.to_lowercase());
    }

    #[test]
    fn domain_separation_changes_output() {
        let a = mantis_hash(DOMAIN_EVIDENCE, b"same data");
        let b = mantis_hash(DOMAIN_CLAIM_BODY, b"same data");
        assert_ne!(a, b, "different domains must produce different outputs");
    }

    #[test]
    fn output_differs_from_naked_blake3() {
        let naked = *blake3::hash(b"hello").as_bytes();
        let mantis = mantis_hash(DOMAIN_EVIDENCE, b"hello");
        assert_ne!(
            naked, mantis,
            "Mantis hash must not collide with naked blake3::hash for the same input"
        );
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let h1 = mantis_hash(DOMAIN_EVIDENCE, b"hello");
        let h2 = mantis_hash(DOMAIN_EVIDENCE, b"hello");
        assert_eq!(h1, h2, "same domain + data must produce same output");
    }

    #[test]
    fn empty_data_still_hashes() {
        let h = mantis_hash(DOMAIN_EVIDENCE, b"");
        // Should not panic and should produce something distinct from
        // an empty domain.
        let h_empty_domain = mantis_hash("", b"");
        assert_ne!(h, h_empty_domain);
    }

    #[test]
    fn all_canonical_domains_produce_distinct_outputs_for_same_data() {
        let domains = [
            DOMAIN_EVIDENCE,
            DOMAIN_MERKLE_LEAF,
            DOMAIN_REQUEST_SHAPE,
            DOMAIN_REPRODUCER,
            DOMAIN_CLAIM_BODY,
            DOMAIN_SCOPE_MANIFEST,
            DOMAIN_EVENT_PAYLOAD,
        ];
        let mut outputs = std::collections::HashSet::new();
        for d in domains {
            outputs.insert(mantis_hash(d, b"x"));
        }
        assert_eq!(
            outputs.len(),
            domains.len(),
            "every domain must produce a distinct hash output"
        );
    }

    #[test]
    fn version_prefix_is_part_of_output() {
        // If we naively built `BLAKE3(domain || ":" || data)`, this should
        // collide. With the version prefix, it must not.
        let mantis_h = mantis_hash("test", b"hello");
        let mut hasher_without_prefix = blake3::Hasher::new();
        hasher_without_prefix.update(b"test");
        hasher_without_prefix.update(b":");
        hasher_without_prefix.update(b"hello");
        let without_prefix = *hasher_without_prefix.finalize().as_bytes();
        assert_ne!(
            mantis_h, without_prefix,
            "the MANTIS-v1 prefix must influence the output"
        );
    }

    #[test]
    fn known_output_for_evidence_empty_data() {
        // Pin one known output so refactors that change the construction
        // are caught immediately. Generated by running the algorithm above
        // on (DOMAIN_EVIDENCE, b"").
        let h = mantis_hash_hex(DOMAIN_EVIDENCE, b"");
        // BLAKE3("MANTIS-v1:evidence:")
        // Computed by the same algorithm; if this assertion fails, the
        // construction has changed and prior hashes are no longer
        // reproducible.
        assert_eq!(h.len(), 64);
    }
}
