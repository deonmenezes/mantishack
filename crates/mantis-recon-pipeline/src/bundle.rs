//! The [`ReconBundle`] — what the deterministic pipeline produces
//! and what the LLM consumes.
//!
//! The shape is intentionally LLM-friendly: short flat fields, no
//! deeply-nested JSON, and a `to_handoff_markdown` method that
//! renders the bundle into the natural-language brief the chat
//! surface drops into the conversation.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use mantis_static_scan::{Finding, Severity};

use crate::anomaly::Anomaly;

/// Per-scanner telemetry — wall-clock duration and finding count.
/// Surfaced in the handoff so the operator (and the LLM) can see
/// where the time went and whether any scanner produced nothing
/// useful.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerStats {
    pub scanner: String,
    pub elapsed_ms: u64,
    pub finding_count: usize,
    /// `None` when the scanner ran successfully. `Some(msg)` when
    /// the binary wasn't on PATH (install hint) or the run errored.
    /// The pipeline continues on per-scanner failures — one missing
    /// scanner doesn't sink the whole bundle.
    pub error: Option<String>,
}

/// One live HTTP surface discovered by httpx (or another HTTP
/// probe). Compact shape — full httpx output stays in the
/// underlying `Finding.raw` for callers that want detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpSurface {
    pub url: String,
    pub status: Option<u16>,
    pub title: Option<String>,
    pub webserver: Option<String>,
    pub tech: Vec<String>,
}

/// What `run_pipeline` returns. JSON-serializable end-to-end so
/// the MCP layer can stuff it into a `CallToolResult` and the
/// chat surface can drop the markdown render directly into the
/// LLM context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconBundle {
    /// Bundle schema version. Bumped on breaking changes so cached
    /// bundles produced by an older mantis aren't blindly reused.
    pub schema_version: u32,
    /// The original target string passed to `run_pipeline` —
    /// `example.com`, `https://api.example.com`, etc.
    pub target: String,
    /// Unix seconds when the pipeline started.
    pub started_at_unix: u64,
    /// Total wall-clock duration of the parallel fan-out.
    pub elapsed_ms: u64,

    /// Discovered subdomains (subfinder).
    pub subdomains: Vec<String>,
    /// Live HTTP surfaces (httpx). Already deduped on `url`.
    pub live_surfaces: Vec<HttpSurface>,
    /// Aggregate tech-stack fingerprint across all live surfaces.
    /// Map of category → set of detected entries, e.g.
    /// `{"server": ["nginx 1.24"], "framework": ["next.js"]}`.
    pub tech_stack: BTreeMap<String, Vec<String>>,

    /// Every Finding produced by every scanner, normalized through
    /// `mantis_static_scan::Finding`. Filter by `tool` / `kind` /
    /// `severity` on the consumer side.
    pub findings: Vec<Finding>,

    /// Heuristic anomalies — patterns in the findings + surfaces
    /// that warrant LLM attention (admin endpoints, IDOR-shaped
    /// URLs, exposed config, JWT signals, etc.).
    pub anomalies: Vec<Anomaly>,

    /// Per-scanner stats. Same length as the active scanners list.
    pub scanner_stats: Vec<ScannerStats>,
}

impl ReconBundle {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            target: target.into(),
            started_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            elapsed_ms: 0,
            subdomains: Vec::new(),
            live_surfaces: Vec::new(),
            tech_stack: BTreeMap::new(),
            findings: Vec::new(),
            anomalies: Vec::new(),
            scanner_stats: Vec::new(),
        }
    }

    /// Convenience accessor: highest severity found by any scanner.
    /// Returns `Severity::Info` when the bundle is empty.
    pub fn peak_severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    /// Convenience accessor: total finding count, grouped by
    /// severity. Useful for the handoff header.
    pub fn severity_breakdown(&self) -> [usize; 5] {
        let mut counts = [0usize; 5];
        for f in &self.findings {
            let i = match f.severity {
                Severity::Info => 0,
                Severity::Low => 1,
                Severity::Medium => 2,
                Severity::High => 3,
                Severity::Critical => 4,
            };
            counts[i] += 1;
        }
        counts
    }

    /// Render the bundle as a markdown brief suitable for dropping
    /// directly into an LLM context. Tuned for compactness — short
    /// sections, dense bullets, full URL/CVE detail only on the
    /// highest-signal items. The model gets enough to decide where
    /// to dig without needing to re-issue recon calls.
    pub fn to_handoff_markdown(&self) -> String {
        let mut s = String::new();
        let [info, low, med, high, crit] = self.severity_breakdown();

        s.push_str(&format!(
            "RECON COMPLETE for `{}` ({:.1}s · {} surfaces · {} findings: {}C/{}H/{}M/{}L/{}I)\n\n",
            self.target,
            self.elapsed_ms as f64 / 1000.0,
            self.live_surfaces.len(),
            self.findings.len(),
            crit,
            high,
            med,
            low,
            info
        ));

        // Surface graph
        if !self.live_surfaces.is_empty() || !self.subdomains.is_empty() {
            s.push_str("## Surface graph\n");
            for surf in self.live_surfaces.iter().take(20) {
                let status = surf.status.map(|c| format!("{c}")).unwrap_or_else(|| "?".into());
                let title = surf.title.as_deref().unwrap_or("");
                let tech = if surf.tech.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", surf.tech.join(", "))
                };
                s.push_str(&format!(
                    "- `{}` {status} {title}{tech}\n",
                    surf.url
                ));
            }
            if self.live_surfaces.len() > 20 {
                s.push_str(&format!(
                    "- (+{} more surfaces, in `live_surfaces`)\n",
                    self.live_surfaces.len() - 20
                ));
            }
            let extra_subs = self
                .subdomains
                .iter()
                .filter(|sd| {
                    !self
                        .live_surfaces
                        .iter()
                        .any(|surf| surf.url.contains(sd.as_str()))
                })
                .count();
            if extra_subs > 0 {
                s.push_str(&format!(
                    "- (+{extra_subs} non-responding subdomains, in `subdomains`)\n"
                ));
            }
            s.push('\n');
        }

        // Tech stack
        if !self.tech_stack.is_empty() {
            s.push_str("## Tech fingerprint\n");
            for (cat, vals) in &self.tech_stack {
                if vals.is_empty() {
                    continue;
                }
                s.push_str(&format!("- {}: {}\n", cat, vals.join(", ")));
            }
            s.push('\n');
        }

        // High-signal findings (Critical/High first)
        let high_signal: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::Medium)
            .collect();
        if !high_signal.is_empty() {
            s.push_str(&format!(
                "## Baseline findings ({} ≥ medium)\n",
                high_signal.len()
            ));
            for f in high_signal.iter().take(15) {
                let sev = match f.severity {
                    Severity::Critical => "CRIT",
                    Severity::High => "HIGH",
                    Severity::Medium => "MED",
                    _ => "",
                };
                let cve = f.meta.get("cve").map(String::as_str).unwrap_or("");
                let cve_tag = if cve.is_empty() {
                    String::new()
                } else {
                    format!(" ({cve})")
                };
                s.push_str(&format!(
                    "- [{sev}] {} on `{}`{cve_tag}\n",
                    f.title, f.target
                ));
            }
            if high_signal.len() > 15 {
                s.push_str(&format!(
                    "- (+{} more medium+ findings, in `findings`)\n",
                    high_signal.len() - 15
                ));
            }
            s.push('\n');
        }

        // Anomalies — the heuristic "worth investigating" list
        if !self.anomalies.is_empty() {
            s.push_str(&format!(
                "## Anomalies worth investigating ({})\n",
                self.anomalies.len()
            ));
            for a in self.anomalies.iter().take(10) {
                s.push_str(&format!("- {}: {}\n", a.kind.label(), a.rationale));
            }
            s.push('\n');
        }

        // Scanner stats — useful for the operator to see where time went
        s.push_str("## Scanner timing\n");
        for st in &self.scanner_stats {
            let status = if let Some(err) = &st.error {
                format!("[{err}]")
            } else {
                format!("{} findings", st.finding_count)
            };
            s.push_str(&format!(
                "- {}: {}ms · {status}\n",
                st.scanner, st.elapsed_ms
            ));
        }
        s.push('\n');

        s.push_str("What should we hunt first?\n");
        s
    }

    pub(crate) fn finalize_elapsed(&mut self, started: SystemTime) {
        self.elapsed_ms = started.elapsed().unwrap_or(Duration::ZERO).as_millis() as u64;
    }
}

/// Bumped on breaking changes so cached bundles produced by an
/// older mantis are invalidated cleanly.
pub const SCHEMA_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn finding(sev: Severity, title: &str, target: &str) -> Finding {
        Finding::new("nuclei", "vuln", target, sev, title)
    }

    #[test]
    fn severity_breakdown_buckets_correctly() {
        let mut b = ReconBundle::new("x");
        b.findings.push(finding(Severity::Critical, "a", "x"));
        b.findings.push(finding(Severity::Critical, "b", "x"));
        b.findings.push(finding(Severity::High, "c", "x"));
        b.findings.push(finding(Severity::Info, "d", "x"));
        let [i, l, m, h, c] = b.severity_breakdown();
        assert_eq!((i, l, m, h, c), (1, 0, 0, 1, 2));
    }

    #[test]
    fn peak_severity_returns_highest() {
        let mut b = ReconBundle::new("x");
        b.findings.push(finding(Severity::Low, "a", "x"));
        b.findings.push(finding(Severity::High, "b", "x"));
        b.findings.push(finding(Severity::Medium, "c", "x"));
        assert_eq!(b.peak_severity(), Severity::High);
    }

    #[test]
    fn peak_severity_empty_bundle_is_info() {
        let b = ReconBundle::new("x");
        assert_eq!(b.peak_severity(), Severity::Info);
    }

    #[test]
    fn handoff_markdown_contains_target_and_summary() {
        let mut b = ReconBundle::new("example.com");
        b.elapsed_ms = 1234;
        b.findings.push(
            Finding::new("nuclei", "vuln", "https://x", Severity::Critical, "Log4j RCE")
                .with_meta("cve", "CVE-2021-44228")
                .with_raw(json!({})),
        );
        b.live_surfaces.push(HttpSurface {
            url: "https://example.com".into(),
            status: Some(200),
            title: Some("Welcome".into()),
            webserver: Some("nginx".into()),
            tech: vec!["next.js".into()],
        });
        b.scanner_stats.push(ScannerStats {
            scanner: "nuclei".into(),
            elapsed_ms: 1100,
            finding_count: 1,
            error: None,
        });

        let md = b.to_handoff_markdown();
        assert!(md.contains("example.com"));
        assert!(md.contains("1.2s")); // elapsed in seconds
        assert!(md.contains("Log4j RCE"));
        assert!(md.contains("CVE-2021-44228"));
        assert!(md.contains("nuclei"));
        assert!(md.contains("What should we hunt first?"));
    }

    #[test]
    fn handoff_truncates_large_surface_lists() {
        let mut b = ReconBundle::new("x");
        for i in 0..30 {
            b.live_surfaces.push(HttpSurface {
                url: format!("https://s{i}.example/"),
                status: Some(200),
                title: None,
                webserver: None,
                tech: vec![],
            });
        }
        let md = b.to_handoff_markdown();
        assert!(md.contains("+10 more surfaces"));
    }
}
