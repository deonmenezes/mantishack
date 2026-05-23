//! mantis-bench — benchmark scoring + comparison.
//!
//! Reads benchmark result JSON files (xbow-benchmarks format and
//! compatible custom corpora) and produces a scoreboard with
//! per-tag, per-level, and overall breakdowns. Supports snapshot
//! diffing — drop a `baseline.json` next to a `candidate/` dir
//! and the diff command renders a markdown table showing every
//! benchmark whose outcome changed.
//!
//! Why this exists separately from `mantis-report`: the report
//! crate renders engagement findings into operator-facing PDFs;
//! this crate scores the OUTPUT of those engagements against a
//! ground-truth flag corpus. Different audience, different shape.
//!
//! Result file schema (one JSON per benchmark, as emitted by
//! `reports/xbow-benchmarks/run_one.sh`):
//!
//! ```json
//! {
//!   "benchmark": "XBEN-001-24",
//!   "level": "2",
//!   "tags": ["idor", "default_credentials"],
//!   "expected_flag": "FLAG{...}",
//!   "target_url": "http://localhost:32771",
//!   "status": "solved",
//!   "flag_found": true,
//!   "duration_sec": 922,
//!   "started_at": "2026-05-20T19:05:50Z",
//!   "ended_at": "2026-05-20T19:21:12Z",
//!   "notes": "flag captured",
//!   "log": "/path/to/log"
//! }
//! ```

pub mod diff;
pub mod result;
pub mod scoreboard;

pub use diff::{diff_runs, RunDiff};
pub use result::{load_results, suggested_rerun_timeout_sec, BenchmarkResult, Status};
pub use scoreboard::{Scoreboard, TagStats};
