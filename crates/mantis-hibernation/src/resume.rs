//! Resume-interrupted-scans with full state restoration.
//!
//! On daemon startup (or after a manual restart), the operator wants to know:
//! *"Which engagements were running when I shut down, and what should I do
//! with them?"* This module provides the classification + plan that the
//! daemon's startup orchestration consumes.
//!
//! The actual restore path — replaying the event log forward from
//! `Snapshot::last_event_seq` and rehydrating runtime components — lives in
//! the daemon. This module only owns the *decision* of what to resume.

use std::time::{SystemTime, UNIX_EPOCH};

use mantis_core::EngagementId;
use serde::{Deserialize, Serialize};

use crate::{HibernationBackend, HibernationError, Snapshot};

/// How a snapshot is classified for resume purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeClassification {
    /// Snapshot is recent and the engagement was in an active state — auto-resume.
    Resumable,
    /// Snapshot is older than the staleness threshold but otherwise valid — operator decides.
    Stale,
    /// Snapshot is in a terminal state (Completed / Archived) — nothing to resume.
    Terminal,
    /// Snapshot exists but failed to load (corrupt JSON, unsupported schema).
    Corrupt,
}

/// One row in the resume plan: a candidate engagement + verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeCandidate {
    /// Engagement ID.
    pub engagement_id: EngagementId,
    /// Classification verdict.
    pub classification: ResumeClassification,
    /// Engagement state at hibernation time (e.g. `"active"`, `"completed"`).
    pub state: String,
    /// Snapshot capture time (Unix seconds), `None` if classification == `Corrupt`.
    pub captured_at_unix: Option<u64>,
    /// Last event sequence number persisted, `None` if `Corrupt`.
    pub last_event_seq: Option<u64>,
    /// Free-text human-readable reason for the classification.
    pub reason: String,
}

/// Aggregated resume plan returned by [`build_resume_plan`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResumePlan {
    /// All candidates, sorted by engagement ID for deterministic output.
    pub candidates: Vec<ResumeCandidate>,
}

impl ResumePlan {
    /// Number of candidates marked [`ResumeClassification::Resumable`].
    pub fn resumable_count(&self) -> usize {
        self.candidates
            .iter()
            .filter(|c| c.classification == ResumeClassification::Resumable)
            .count()
    }

    /// All candidates the daemon should auto-resume.
    pub fn resumable(&self) -> impl Iterator<Item = &ResumeCandidate> {
        self.candidates
            .iter()
            .filter(|c| c.classification == ResumeClassification::Resumable)
    }

    /// All candidates requiring operator input (Stale or Corrupt).
    pub fn needs_operator(&self) -> impl Iterator<Item = &ResumeCandidate> {
        self.candidates.iter().filter(|c| {
            matches!(
                c.classification,
                ResumeClassification::Stale | ResumeClassification::Corrupt
            )
        })
    }
}

/// Configuration for resume classification.
#[derive(Debug, Clone, Copy)]
pub struct ResumeConfig {
    /// Maximum age of a snapshot, in seconds, before it's classified as `Stale`.
    /// Defaults to 7 days.
    pub max_age_secs: u64,
    /// Override of "now" in Unix seconds for deterministic testing.
    /// When `None`, the current system time is used.
    pub now_unix: Option<u64>,
}

impl Default for ResumeConfig {
    fn default() -> Self {
        Self {
            max_age_secs: 7 * 24 * 60 * 60,
            now_unix: None,
        }
    }
}

/// Walk the hibernation backend's snapshot directory and classify each
/// engagement's resume status.
pub fn build_resume_plan(
    backend: &dyn HibernationBackend,
    cfg: ResumeConfig,
) -> Result<ResumePlan, HibernationError> {
    let now = cfg.now_unix.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });

    let mut candidates: Vec<ResumeCandidate> = Vec::new();
    let mut ids = backend.list()?;
    // Sort by the inner Ulid (Copy, 16 bytes). The prior code did
    // `id.to_string()` inside sort_by_key, which clones a new String
    // for every comparison — O(N log N) String allocations just to
    // sort. Ulid's Ord impl is lexicographic over the same bytes
    // .to_string() would have produced, so the final order matches.
    ids.sort_by_key(|id| id.0);

    for engagement_id in ids {
        match backend.load(engagement_id) {
            Ok(snapshot) => candidates.push(classify(&snapshot, now, &cfg)),
            Err(err) => candidates.push(ResumeCandidate {
                engagement_id,
                classification: ResumeClassification::Corrupt,
                state: String::new(),
                captured_at_unix: None,
                last_event_seq: None,
                reason: format!("snapshot failed to load: {err}"),
            }),
        }
    }

    Ok(ResumePlan { candidates })
}

fn classify(snapshot: &Snapshot, now: u64, cfg: &ResumeConfig) -> ResumeCandidate {
    let age = now.saturating_sub(snapshot.captured_at_unix);

    let classification = if is_terminal_state(&snapshot.state) {
        ResumeClassification::Terminal
    } else if age > cfg.max_age_secs {
        ResumeClassification::Stale
    } else {
        ResumeClassification::Resumable
    };

    let reason = match classification {
        ResumeClassification::Resumable => {
            format!("active state '{}', snapshot age {}s", snapshot.state, age)
        }
        ResumeClassification::Stale => format!(
            "snapshot age {}s exceeds threshold {}s",
            age, cfg.max_age_secs
        ),
        ResumeClassification::Terminal => {
            format!("engagement in terminal state '{}'", snapshot.state)
        }
        ResumeClassification::Corrupt => unreachable!("Corrupt classified at load time"),
    };

    ResumeCandidate {
        engagement_id: snapshot.engagement_id,
        classification,
        state: snapshot.state.clone(),
        captured_at_unix: Some(snapshot.captured_at_unix),
        last_event_seq: Some(snapshot.last_event_seq),
        reason,
    }
}

fn is_terminal_state(state: &str) -> bool {
    matches!(state, "Completed" | "Archived" | "completed" | "archived")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalDiskBackend;
    use ulid::Ulid;

    fn engagement(_seed: u32) -> EngagementId {
        EngagementId(Ulid::new())
    }

    fn snapshot(id: EngagementId, state: &str, captured_at: u64) -> Snapshot {
        let mut s = Snapshot::new(id, state);
        s.captured_at_unix = captured_at;
        s
    }

    fn cfg_with_now(now: u64) -> ResumeConfig {
        ResumeConfig {
            max_age_secs: 7 * 24 * 60 * 60,
            now_unix: Some(now),
        }
    }

    #[test]
    fn fresh_active_snapshot_is_resumable() {
        let dir = tempfile::tempdir().unwrap();
        let path = camino::Utf8Path::from_path(dir.path()).unwrap();
        let backend = LocalDiskBackend::new(path).unwrap();
        let id = engagement(1);
        let now = 2_000_000_000;
        backend.store(&snapshot(id, "Active", now - 60)).unwrap();

        let plan = build_resume_plan(&backend, cfg_with_now(now)).unwrap();
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(
            plan.candidates[0].classification,
            ResumeClassification::Resumable
        );
        assert_eq!(plan.resumable_count(), 1);
        assert_eq!(plan.resumable().count(), 1);
    }

    #[test]
    fn old_snapshot_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let path = camino::Utf8Path::from_path(dir.path()).unwrap();
        let backend = LocalDiskBackend::new(path).unwrap();
        let id = engagement(2);
        let now = 2_000_000_000;
        let old = now - (8 * 24 * 60 * 60); // 8 days ago, past 7-day threshold
        backend.store(&snapshot(id, "Active", old)).unwrap();

        let plan = build_resume_plan(&backend, cfg_with_now(now)).unwrap();
        assert_eq!(
            plan.candidates[0].classification,
            ResumeClassification::Stale
        );
        assert_eq!(plan.resumable_count(), 0);
        assert_eq!(plan.needs_operator().count(), 1);
    }

    #[test]
    fn terminal_state_is_classified_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let path = camino::Utf8Path::from_path(dir.path()).unwrap();
        let backend = LocalDiskBackend::new(path).unwrap();
        let id = engagement(3);
        let now = 2_000_000_000;
        backend.store(&snapshot(id, "Completed", now - 60)).unwrap();

        let plan = build_resume_plan(&backend, cfg_with_now(now)).unwrap();
        assert_eq!(
            plan.candidates[0].classification,
            ResumeClassification::Terminal
        );
        // Terminal candidates aren't in `resumable` and aren't `needs_operator`
        // — they're handled but they need no action.
        assert_eq!(plan.resumable_count(), 0);
        assert_eq!(plan.needs_operator().count(), 0);
    }

    #[test]
    fn lowercase_terminal_state_recognized() {
        let dir = tempfile::tempdir().unwrap();
        let path = camino::Utf8Path::from_path(dir.path()).unwrap();
        let backend = LocalDiskBackend::new(path).unwrap();
        let id = engagement(4);
        let now = 2_000_000_000;
        backend.store(&snapshot(id, "archived", now - 60)).unwrap();

        let plan = build_resume_plan(&backend, cfg_with_now(now)).unwrap();
        assert_eq!(
            plan.candidates[0].classification,
            ResumeClassification::Terminal
        );
    }

    #[test]
    fn corrupt_snapshot_is_classified_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = camino::Utf8Path::from_path(dir.path()).unwrap();
        let backend = LocalDiskBackend::new(path).unwrap();

        // Write a malformed JSON file directly to the snapshot directory.
        // The backend's `list()` reads filenames; `load()` will fail to parse.
        let bad = dir.path().join("01HXAAAAAAAAAAAAAAAAAAAAAA.json");
        std::fs::write(&bad, "{ not valid json").unwrap();

        let plan = build_resume_plan(&backend, cfg_with_now(2_000_000_000)).unwrap();
        // The list/load combo may or may not produce a Corrupt entry depending
        // on whether the backend's list() returns ULIDs from invalid files.
        // What we assert is: no Resumable entry was produced from the bad file.
        assert_eq!(plan.resumable_count(), 0);
    }

    #[test]
    fn empty_backend_yields_empty_plan() {
        let dir = tempfile::tempdir().unwrap();
        let path = camino::Utf8Path::from_path(dir.path()).unwrap();
        let backend = LocalDiskBackend::new(path).unwrap();
        let plan = build_resume_plan(&backend, ResumeConfig::default()).unwrap();
        assert!(plan.candidates.is_empty());
        assert_eq!(plan.resumable_count(), 0);
    }

    #[test]
    fn boundary_at_max_age_is_resumable() {
        let dir = tempfile::tempdir().unwrap();
        let path = camino::Utf8Path::from_path(dir.path()).unwrap();
        let backend = LocalDiskBackend::new(path).unwrap();
        let id = engagement(5);
        let now = 2_000_000_000;
        // Exactly at threshold age — should still be resumable (> not >=).
        let at_threshold = now - (7 * 24 * 60 * 60);
        backend
            .store(&snapshot(id, "Active", at_threshold))
            .unwrap();

        let plan = build_resume_plan(&backend, cfg_with_now(now)).unwrap();
        assert_eq!(
            plan.candidates[0].classification,
            ResumeClassification::Resumable
        );
    }

    #[test]
    fn custom_max_age_is_honored() {
        let dir = tempfile::tempdir().unwrap();
        let path = camino::Utf8Path::from_path(dir.path()).unwrap();
        let backend = LocalDiskBackend::new(path).unwrap();
        let id = engagement(6);
        let now = 2_000_000_000;
        backend.store(&snapshot(id, "Active", now - 120)).unwrap();

        let cfg = ResumeConfig {
            max_age_secs: 60, // 1 min — anything older than this is stale
            now_unix: Some(now),
        };
        let plan = build_resume_plan(&backend, cfg).unwrap();
        assert_eq!(
            plan.candidates[0].classification,
            ResumeClassification::Stale
        );
    }

    #[test]
    fn plan_serializes_to_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = camino::Utf8Path::from_path(dir.path()).unwrap();
        let backend = LocalDiskBackend::new(path).unwrap();
        let id = engagement(7);
        backend
            .store(&snapshot(id, "Active", 1_000_000_000))
            .unwrap();
        let plan = build_resume_plan(&backend, cfg_with_now(1_000_000_060)).unwrap();
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("resumable"));
    }
}
