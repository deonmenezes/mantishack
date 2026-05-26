//! # Apache-2.0 §4(b) notice — derivative work
//!
//! Portions of this file are derived from or mirror algorithm
//! shape, named constants, threshold values, or workflow logic from
//! Hacker Bob (<https://github.com/vmihalis/hacker-bob>),
//! Copyright 2026 Michail Vasileiadis, licensed under the Apache
//! License, Version 2.0. The surrounding Rust implementation is
//! independent and was written from scratch.
//!
//! See the project NOTICE for the upstream attribution and the
//! compliance-history apology. This notice is provided per
//! Apache-2.0 §4(b) ("You must cause any modified files to carry
//! prominent notices stating that You changed the files").
//!
//! Coverage tracking.
//!
//! Ports hacker-bob's coverage discipline (`coverage.js`,
//! `COVERAGE_STATUS_VALUES`). Each (surface, method, endpoint,
//! bug_class, auth_profile) tuple has a latest row in
//! `{Tested, Blocked, Promising, NeedsAuth, Requeue}`. The
//! HUNT→CHAIN gate refuses to open while any latest row is in the
//! "unfinished" set (`Promising`/`NeedsAuth`/`Requeue`) — those
//! surfaces get re-queued to the next wave instead of leaking into
//! CHAIN with half-explored territory.
//!
//! "Latest by key" semantics: writing a row with the same key
//! overwrites the previous one. Re-testing a surface/endpoint flips
//! its status without leaving duplicate history rows in the gate
//! computation.

use serde::{Deserialize, Serialize};

/// Latest disposition for one (surface, method, endpoint, bug_class,
/// auth_profile) tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageStatus {
    /// Probe completed; nothing actionable left for this tuple.
    Tested,
    /// Hard-blocked (WAF challenge, 403, geofence, etc.) — exclude
    /// from re-queue but record the block.
    Blocked,
    /// Hunter found a promising signal but didn't finish; should
    /// re-run with refined parameters.
    Promising,
    /// Hunter needs an auth profile that didn't exist; promote when
    /// auth lands.
    NeedsAuth,
    /// Generic re-queue: any other reason the tuple isn't done.
    Requeue,
}

impl CoverageStatus {
    /// True iff this status keeps the tuple in the "unfinished"
    /// set that gates HUNT→CHAIN.
    pub fn is_unfinished(self) -> bool {
        matches!(
            self,
            CoverageStatus::Promising | CoverageStatus::NeedsAuth | CoverageStatus::Requeue
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CoverageStatus::Tested => "tested",
            CoverageStatus::Blocked => "blocked",
            CoverageStatus::Promising => "promising",
            CoverageStatus::NeedsAuth => "needs_auth",
            CoverageStatus::Requeue => "requeue",
        }
    }
}

/// Composite key. Mirrors hacker-bob's coverage row tuple.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CoverageKey {
    pub surface_id: String,
    pub method: String,
    pub endpoint: String,
    pub bug_class: String,
    /// `None` for unauthenticated probes; `Some("attacker")` when
    /// the probe ran under that profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_profile: Option<String>,
}

impl CoverageKey {
    pub fn new(
        surface_id: impl Into<String>,
        method: impl Into<String>,
        endpoint: impl Into<String>,
        bug_class: impl Into<String>,
    ) -> Self {
        Self {
            surface_id: surface_id.into(),
            method: method.into(),
            endpoint: endpoint.into(),
            bug_class: bug_class.into(),
            auth_profile: None,
        }
    }

    pub fn with_auth_profile(mut self, profile: impl Into<String>) -> Self {
        self.auth_profile = Some(profile.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRow {
    #[serde(flatten)]
    pub key: CoverageKey,
    pub status: CoverageStatus,
    /// Optional operator note — short and bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Wall-clock unix seconds when this row was last written.
    /// Latest-wins ordering uses this when keys collide.
    pub wall_clock_unix: u64,
}

impl CoverageRow {
    pub fn tested(key: CoverageKey, ts: u64) -> Self {
        Self {
            key,
            status: CoverageStatus::Tested,
            note: None,
            wall_clock_unix: ts,
        }
    }
    pub fn requeue(key: CoverageKey, ts: u64) -> Self {
        Self {
            key,
            status: CoverageStatus::Requeue,
            note: None,
            wall_clock_unix: ts,
        }
    }
    pub fn promising(key: CoverageKey, ts: u64) -> Self {
        Self {
            key,
            status: CoverageStatus::Promising,
            note: None,
            wall_clock_unix: ts,
        }
    }
    pub fn needs_auth(key: CoverageKey, ts: u64) -> Self {
        Self {
            key,
            status: CoverageStatus::NeedsAuth,
            note: None,
            wall_clock_unix: ts,
        }
    }
    pub fn blocked(key: CoverageKey, ts: u64) -> Self {
        Self {
            key,
            status: CoverageStatus::Blocked,
            note: None,
            wall_clock_unix: ts,
        }
    }
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// Latest-by-key reducer. Replays the rows in arrival order and
/// keeps the most recent row per key (highest `wall_clock_unix`
/// breaks ties; identical timestamps keep insertion order).
pub fn latest_by_key(rows: &[CoverageRow]) -> Vec<&CoverageRow> {
    use std::collections::BTreeMap;
    let mut latest: BTreeMap<&CoverageKey, &CoverageRow> = BTreeMap::new();
    for row in rows {
        match latest.get(&row.key) {
            Some(prev) if prev.wall_clock_unix > row.wall_clock_unix => {}
            _ => {
                latest.insert(&row.key, row);
            }
        }
    }
    latest.into_values().collect()
}

/// Surface IDs whose latest row is in the unfinished set. Stable
/// (deduplicated, sorted) — feeds the HUNT→CHAIN gate's
/// `open_requeue_coverage` blocker.
pub fn open_requeue_surface_ids(rows: &[CoverageRow]) -> Vec<String> {
    let latest = latest_by_key(rows);
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for row in latest {
        if row.status.is_unfinished() {
            out.insert(row.key.surface_id.clone());
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(surf: &str, ep: &str, bc: &str) -> CoverageKey {
        CoverageKey::new(surf, "GET", ep, bc)
    }

    #[test]
    fn unfinished_set_matches_hacker_bob() {
        assert!(CoverageStatus::Promising.is_unfinished());
        assert!(CoverageStatus::NeedsAuth.is_unfinished());
        assert!(CoverageStatus::Requeue.is_unfinished());
        assert!(!CoverageStatus::Tested.is_unfinished());
        assert!(!CoverageStatus::Blocked.is_unfinished());
    }

    #[test]
    fn latest_overwrites_older_row_for_same_key() {
        let k = key("s-1", "/login", "auth-bypass");
        let rows = vec![
            CoverageRow::requeue(k.clone(), 10),
            CoverageRow::tested(k, 20),
        ];
        let latest = latest_by_key(&rows);
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].status, CoverageStatus::Tested);
    }

    #[test]
    fn different_auth_profiles_are_different_keys() {
        let mut k1 = key("s-1", "/me", "idor");
        k1 = k1.with_auth_profile("attacker");
        let mut k2 = key("s-1", "/me", "idor");
        k2 = k2.with_auth_profile("victim");
        let rows = vec![CoverageRow::tested(k1, 10), CoverageRow::requeue(k2, 20)];
        let latest = latest_by_key(&rows);
        assert_eq!(latest.len(), 2);
    }

    #[test]
    fn open_requeue_surfaces_dedupes_across_endpoints() {
        let rows = vec![
            CoverageRow::requeue(key("s-1", "/a", "xss"), 1),
            CoverageRow::requeue(key("s-1", "/b", "xss"), 2),
            CoverageRow::tested(key("s-2", "/c", "xss"), 3),
        ];
        let ids = open_requeue_surface_ids(&rows);
        assert_eq!(ids, vec!["s-1".to_string()]);
    }

    #[test]
    fn open_requeue_empty_when_everything_tested() {
        let rows = vec![
            CoverageRow::tested(key("s-1", "/a", "xss"), 1),
            CoverageRow::blocked(key("s-2", "/c", "xss"), 2),
        ];
        let ids = open_requeue_surface_ids(&rows);
        assert!(ids.is_empty());
    }

    #[test]
    fn requeue_flipped_to_tested_drops_from_open() {
        let k = key("s-1", "/a", "xss");
        let rows = vec![
            CoverageRow::requeue(k.clone(), 10),
            CoverageRow::tested(k, 20),
        ];
        let ids = open_requeue_surface_ids(&rows);
        assert!(ids.is_empty());
    }

    #[test]
    fn tested_then_requeue_flips_back_to_open() {
        let k = key("s-1", "/a", "xss");
        let rows = vec![
            CoverageRow::tested(k.clone(), 10),
            CoverageRow::needs_auth(k, 20),
        ];
        let ids = open_requeue_surface_ids(&rows);
        assert_eq!(ids, vec!["s-1".to_string()]);
    }

    #[test]
    fn json_round_trip() {
        let row = CoverageRow::promising(
            CoverageKey::new("s-1", "POST", "/login", "auth-bypass").with_auth_profile("attacker"),
            1700,
        )
        .with_note("token rotated mid-test");
        let j = serde_json::to_string(&row).unwrap();
        let back: CoverageRow = serde_json::from_str(&j).unwrap();
        assert_eq!(row, back);
    }
}
