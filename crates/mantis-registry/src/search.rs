//! Registry search.

use serde::{Deserialize, Serialize};

use crate::entry::{Entry, EntryStatus};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchQuery {
    pub text: Option<String>,
    pub publisher: Option<String>,
    pub include_deprecated: bool,
    pub include_yanked: bool,
}

pub fn search(entries: &[Entry], query: &SearchQuery) -> Vec<Entry> {
    let text = query.text.as_deref().map(|s| s.to_ascii_lowercase());
    let needle_bytes = text.as_deref().map(str::as_bytes);
    let publisher = query.publisher.as_deref();
    entries
        .iter()
        .filter(|e| match e.status {
            EntryStatus::Deprecated => query.include_deprecated,
            EntryStatus::Yanked => query.include_yanked,
            EntryStatus::Active => true,
        })
        .filter(|e| match publisher {
            Some(p) => e.publisher == p,
            None => true,
        })
        .filter(|e| match needle_bytes {
            Some(n) => {
                // Case-insensitive substring check that does NOT
                // allocate a lowercased copy of the haystack. The
                // prior version called `.to_ascii_lowercase()` on up
                // to 3 fields PER ENTRY — N entries × 3 fields = 3N
                // String allocations per query. Now: zero allocations
                // for the haystacks; needle is lowercased once before
                // the loop.
                contains_ascii_ci(&e.id.0, n)
                    || contains_ascii_ci(&e.display_name, n)
                    || contains_ascii_ci(&e.description, n)
            }
            None => true,
        })
        .cloned()
        .collect()
}

/// True if `haystack` contains `needle_lower` case-insensitively
/// (ASCII only). `needle_lower` must already be lowercased by the
/// caller. Operates on raw bytes; no String allocation.
fn contains_ascii_ci(haystack: &str, needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    let h = haystack.as_bytes();
    if h.len() < needle_lower.len() {
        return false;
    }
    let first = needle_lower[0];
    // Walk possible match starts. memchr-find for the first byte
    // (case-insensitive: scan for both lower and upper of the first
    // needle byte) would be faster; this loop is the obvious
    // correctness-first version and still beats the prior
    // String-allocating approach.
    for start in 0..=h.len() - needle_lower.len() {
        // Quick reject on first byte before the full window compare.
        let hb = h[start];
        if hb != first && hb.to_ascii_lowercase() != first {
            continue;
        }
        let window = &h[start..start + needle_lower.len()];
        if window
            .iter()
            .zip(needle_lower)
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{EntryId, EntryVersion};
    use crate::ArtifactRef;
    use std::collections::BTreeMap;

    fn entry(id: &str, publisher: &str, status: EntryStatus) -> Entry {
        let mut versions = BTreeMap::new();
        versions.insert(
            "1.0.0".into(),
            EntryVersion {
                artifact_ref: ArtifactRef {
                    registry: "r".into(),
                    plugin: id.into(),
                    tag: "1.0.0".into(),
                },
                manifest_digest: "x".repeat(64),
                signed_by: publisher.into(),
                published_at_unix: 0,
            },
        );
        Entry {
            id: EntryId(id.into()),
            display_name: id.into(),
            description: format!("description of {id}"),
            publisher: publisher.into(),
            versions,
            status,
        }
    }

    #[test]
    fn search_filters_yanked_by_default() {
        let entries = vec![
            entry("a", "alice", EntryStatus::Active),
            entry("b", "alice", EntryStatus::Yanked),
        ];
        let q = SearchQuery::default();
        let results = search(&entries, &q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id.0, "a");
    }

    #[test]
    fn search_includes_yanked_when_requested() {
        let entries = vec![
            entry("a", "alice", EntryStatus::Active),
            entry("b", "alice", EntryStatus::Yanked),
        ];
        let q = SearchQuery {
            include_yanked: true,
            ..Default::default()
        };
        assert_eq!(search(&entries, &q).len(), 2);
    }

    #[test]
    fn search_by_text_matches_id_name_description() {
        let entries = vec![
            entry("sqli-scanner", "alice", EntryStatus::Active),
            entry("xss-scanner", "alice", EntryStatus::Active),
            entry("ssrf-prober", "bob", EntryStatus::Active),
        ];
        let q = SearchQuery {
            text: Some("scanner".into()),
            ..Default::default()
        };
        let results = search(&entries, &q);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn search_by_publisher() {
        let entries = vec![
            entry("a", "alice", EntryStatus::Active),
            entry("b", "bob", EntryStatus::Active),
            entry("c", "alice", EntryStatus::Active),
        ];
        let q = SearchQuery {
            publisher: Some("alice".into()),
            ..Default::default()
        };
        assert_eq!(search(&entries, &q).len(), 2);
    }
}
