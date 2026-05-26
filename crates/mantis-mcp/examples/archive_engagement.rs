//! Per-target report archival.
//!
//! Reads a Mantis engagement's events.jsonl + wave merges and
//! writes a structured per-target folder under `./reports/<host>/<engagement-id>/`
//! so every move the daemon made is durably logged in human-readable
//! markdown alongside the raw merkle event stream:
//!
//! ```
//! ./reports/<host>/<engagement-id>/
//! ├── README.md                 — engagement index + severity counts
//! ├── vulnerability-report.md   — consolidated full report
//! ├── timeline.md               — chronological activity log
//! ├── findings/F-1.md ... F-N.md
//! ├── phases/01-recon.md ...
//! ├── waves/wave-1.md ...
//! └── events.jsonl              — copy of the raw signed event log
//! ```
//!
//! Idempotent. Re-running overwrites the markdown but never deletes.
//!
//! Usage:
//!   mantis-archive-engagement <engagement_id> [--severity-floor low|info|...]

use mantis_mcp::server::{
    load_wave_merges, parse_severity_floor, render_markdown, severity_rank, EngagementSummary,
    Surface,
};
use mantis_mcp::pass;
use mantis_proto::v1::engagement_client::EngagementClient;
use mantis_proto::v1::{ExportRequest, StatusRequest};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let engagement_id = args
        .next()
        .ok_or("usage: archive_engagement <engagement_id> [--severity-floor <floor>]")?;
    let mut floor_arg: Option<String> = None;
    let mut target_override: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--severity-floor" => floor_arg = args.next(),
            "--target-host" => target_override = args.next(),
            _ => {}
        }
    }
    let floor_rank = parse_severity_floor(floor_arg.as_deref());

    // --- pull engagement metadata + raw event log from the daemon ---
    let mut client = EngagementClient::connect("http://127.0.0.1:50451").await?;
    let info = client
        .status(StatusRequest {
            id: engagement_id.clone(),
        })
        .await?
        .into_inner();
    let summary = EngagementSummary::from(info);
    let jsonl = client
        .export(ExportRequest {
            id: engagement_id.clone(),
        })
        .await?
        .into_inner()
        .jsonl;
    let jsonl_text = String::from_utf8_lossy(&jsonl).to_string();

    // --- load wave merges from the existing engagement dir ---
    let src_dir = PathBuf::from(format!("./mantishack-{}", summary.id));
    let waves = load_wave_merges(&src_dir);
    let mut chain_attempts: Vec<(u32, Vec<pass::ChainAttempt>)> = Vec::new();
    for w in &waves {
        let attempts = pass::read_chain_attempts(&summary.id, w.wave_number);
        if !attempts.is_empty() {
            chain_attempts.push((w.wave_number, attempts));
        }
    }

    // --- derive the target host. Override beats auto-derivation.
    let target_host = match target_override {
        Some(h) => normalize_host(&h),
        None => derive_target_host_with_findings(&jsonl_text, &waves, &summary.name),
    };

    // --- prepare output folders ---
    let out_root = PathBuf::from("reports")
        .join(&target_host)
        .join(&summary.id);
    std::fs::create_dir_all(out_root.join("findings"))?;
    std::fs::create_dir_all(out_root.join("phases"))?;
    std::fs::create_dir_all(out_root.join("waves"))?;

    // --- copy raw event log ---
    std::fs::write(out_root.join("events.jsonl"), &jsonl)?;

    // --- consolidated vulnerability report ---
    let surfaces: Vec<Surface> = parse_surfaces(&jsonl_text);
    let vuln_report = render_markdown(&summary, &surfaces, &waves, &chain_attempts, floor_rank);
    std::fs::write(out_root.join("vulnerability-report.md"), &vuln_report)?;

    // --- per-finding markdown files ---
    let mut all_findings: Vec<&pass::Finding> = Vec::new();
    for w in &waves {
        for f in &w.findings {
            all_findings.push(f);
        }
    }
    // Sort: critical first, then high, medium, low, info.
    all_findings.sort_by_key(|f| std::cmp::Reverse(severity_rank(&f.severity)));
    let mut finding_index: Vec<(usize, &pass::Finding)> = Vec::new();
    for (idx, f) in all_findings.iter().enumerate() {
        let n = idx + 1;
        finding_index.push((n, *f));
        let path = out_root.join("findings").join(format!("F-{n:02}.md"));
        std::fs::write(&path, render_finding_md(n, f))?;
    }

    // --- per-phase markdown files (one per PhaseTransitioned event) ---
    let phase_events = parse_phase_events(&jsonl_text);
    for (idx, (from, to, override_reason, blocker_codes, ts)) in phase_events.iter().enumerate() {
        let n = idx + 1;
        let name = format!("{n:02}-{}-to-{}.md", from.to_lowercase(), to.to_lowercase());
        let body = render_phase_md(n, from, to, override_reason.as_deref(), blocker_codes, *ts);
        std::fs::write(out_root.join("phases").join(name), body)?;
    }
    // If no phase events were recorded, emit a stub so the folder is non-empty.
    if phase_events.is_empty() {
        std::fs::write(
            out_root.join("phases").join("00-no-transitions.md"),
            "# No phase transitions recorded\n\nThis engagement did not record any \
             `PhaseTransitioned` events. Either the orchestrator never drove the FSM, or \
             the engagement was ingested directly via a pre-built wave merge.\n",
        )?;
    }

    // --- per-wave markdown files ---
    for w in &waves {
        let body = render_wave_md(w, floor_rank);
        std::fs::write(
            out_root
                .join("waves")
                .join(format!("wave-{}.md", w.wave_number)),
            body,
        )?;
    }

    // --- timeline.md — every event in order ---
    let timeline = render_timeline(&jsonl_text);
    std::fs::write(out_root.join("timeline.md"), &timeline)?;

    // --- README.md — index ---
    let mut by_sev: BTreeMap<String, u32> = BTreeMap::new();
    for w in &waves {
        for (k, v) in &w.findings_by_severity {
            *by_sev.entry(k.clone()).or_default() += v;
        }
    }
    let readme = render_readme(
        &summary,
        &target_host,
        &waves,
        &by_sev,
        &finding_index,
        &phase_events,
        floor_rank,
    );
    std::fs::write(out_root.join("README.md"), &readme)?;

    // --- summary to stdout ---
    println!("Target host:       {}", target_host);
    println!("Engagement id:     {}", summary.id);
    println!("Engagement name:   {}", summary.name);
    println!("State:             {}", summary.state);
    println!("Surfaces:          {}", surfaces.len());
    println!("Waves merged:      {}", waves.len());
    println!("Phase events:      {}", phase_events.len());
    println!("Findings written:  {}", finding_index.len());
    println!("Output folder:     {}", out_root.display());
    println!();
    println!("Open the index:    {}/README.md", out_root.display());
    println!(
        "Full vuln report:  {}/vulnerability-report.md",
        out_root.display()
    );
    Ok(())
}

/// Host derivation that also consults wave-merge finding surfaces
/// (for ingest-only engagements with no live `SurfaceDiscovered`
/// events). Picks the most-common host across finding surfaces so
/// a multi-subdomain ingest groups under its dominant host.
fn derive_target_host_with_findings(
    jsonl: &str,
    waves: &[pass::WaveMerge],
    fallback_name: &str,
) -> String {
    // First try the live-event paths.
    let from_events = derive_target_host(jsonl, "");
    if !from_events.is_empty() && from_events != normalize_host(fallback_name) {
        return from_events;
    }
    // Fall back to scanning wave findings for the most-common host.
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for w in waves {
        for f in &w.findings {
            if let Some(h) = host_from_url(&f.surface) {
                *counts.entry(normalize_host(&h)).or_default() += 1;
            }
        }
    }
    if let Some((host, _)) = counts.iter().max_by_key(|(_, n)| **n) {
        return host.clone();
    }
    normalize_host(fallback_name)
}

fn host_from_url(url: &str) -> Option<String> {
    let s = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = s.split(['/', '?', '#']).next()?;
    let host = host.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// First-pass host derivation. Walks events.jsonl looking for a
/// `SurfaceDiscovered` event and uses its host. Falls back to a
/// `ScopeDecisionLogged.target` (host:port — strip the port), then
/// to the engagement name. Lowercased + stripped of `www.` to keep
/// `./reports/example.com/` and `./reports/www.example.com/` from
/// diverging.
fn derive_target_host(jsonl: &str, fallback_name: &str) -> String {
    for line in jsonl.lines() {
        let Ok(v): Result<Value, _> = serde_json::from_str(line) else {
            continue;
        };
        let kind = v
            .get("kind")
            .and_then(|k| k.get("kind"))
            .and_then(|k| k.as_str());
        if kind == Some("SurfaceDiscovered") {
            if let Some(h) = v
                .get("kind")
                .and_then(|k| k.get("host"))
                .and_then(|h| h.as_str())
            {
                return normalize_host(h);
            }
        }
    }
    // Fallback: scope decision.
    for line in jsonl.lines() {
        let Ok(v): Result<Value, _> = serde_json::from_str(line) else {
            continue;
        };
        let kind = v
            .get("kind")
            .and_then(|k| k.get("kind"))
            .and_then(|k| k.as_str());
        if kind == Some("ScopeDecisionLogged") {
            if let Some(t) = v
                .get("kind")
                .and_then(|k| k.get("target"))
                .and_then(|h| h.as_str())
            {
                let host = t.split(':').next().unwrap_or(t);
                return normalize_host(host);
            }
        }
    }
    // Final fallback — sanitize the engagement name.
    normalize_host(fallback_name)
}

fn normalize_host(h: &str) -> String {
    let lower = h.to_ascii_lowercase();
    let stripped = lower.strip_prefix("www.").unwrap_or(&lower);
    // Filesystem-safe: replace anything that isn't [a-z0-9.-_] with '_'.
    stripped
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn parse_surfaces(jsonl: &str) -> Vec<Surface> {
    let mut out = Vec::new();
    for line in jsonl.lines() {
        let Ok(v): Result<Value, _> = serde_json::from_str(line) else {
            continue;
        };
        let kind = v
            .get("kind")
            .and_then(|k| k.get("kind"))
            .and_then(|k| k.as_str());
        if kind != Some("SurfaceDiscovered") {
            continue;
        }
        let seq = v.get("seq").and_then(|s| s.as_u64()).unwrap_or(0);
        let k = match v.get("kind") {
            Some(k) => k,
            None => continue,
        };
        out.push(Surface {
            seq,
            host: k
                .get("host")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            port: k.get("port").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            scheme: k
                .get("scheme")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            path: k
                .get("path")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            status: k.get("status").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            server: k.get("server").and_then(|x| x.as_str()).map(str::to_string),
            tech_hints: k
                .get("tech_hints")
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|h| h.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    out
}

type PhaseEvent = (String, String, Option<String>, Vec<String>, u64);

fn parse_phase_events(jsonl: &str) -> Vec<PhaseEvent> {
    let mut out = Vec::new();
    for line in jsonl.lines() {
        let Ok(v): Result<Value, _> = serde_json::from_str(line) else {
            continue;
        };
        let kind = v
            .get("kind")
            .and_then(|k| k.get("kind"))
            .and_then(|k| k.as_str());
        if kind != Some("PhaseTransitioned") {
            continue;
        }
        let k = match v.get("kind") {
            Some(k) => k,
            None => continue,
        };
        let from = k
            .get("from")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let to = k
            .get("to")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let override_reason = k
            .get("override_reason")
            .and_then(|x| x.as_str())
            .map(str::to_string);
        let blocker_codes = k
            .get("blocker_codes")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let ts = v
            .get("wall_clock_unix")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        out.push((from, to, override_reason, blocker_codes, ts));
    }
    out
}

fn render_finding_md(n: usize, f: &pass::Finding) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Finding F-{n:02}\n");

    let _ = writeln!(s, "- **Title:** {}", f.title);

    let _ = writeln!(s, "- **Severity:** `{}`", f.severity);

    let _ = writeln!(s, "- **Surface:** `{}`\n", f.surface);

    s.push_str("## Evidence\n\n");
    s.push_str(&f.evidence);
    s.push_str("\n\n");
    s.push_str("## Reproducer\n\n");
    s.push_str(
        "The evidence above describes the request/response shape that demonstrates the bug. \
         To reproduce, re-run the request against the surface with a valid authentication \
         profile and observe the documented behavior. See the project's per-finding \
         curl/Python helpers when present.\n\n",
    );
    s.push_str("## Provenance\n\n");
    s.push_str(
        "This finding is recorded as a wave-handoff entry in the engagement's \
         `waves/<n>/merged.json` and is reachable from the consolidated \
         `vulnerability-report.md` at the engagement root. The raw merkle event stream is \
         in `events.jsonl`; verify inclusion proofs with the standalone `mantis-verify` \
         binary.\n",
    );
    s
}

fn render_phase_md(
    n: usize,
    from: &str,
    to: &str,
    override_reason: Option<&str>,
    blocker_codes: &[String],
    ts: u64,
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Phase transition {n:02}: {from} → {to}\n");

    let _ = writeln!(s, "- **From:** `{from}`");

    let _ = writeln!(s, "- **To:** `{to}`");

    let _ = writeln!(s, "- **Unix timestamp:** `{ts}`");

    if let Some(r) = override_reason {
        s.push_str("- **Override applied:** yes\n");
        let _ = writeln!(s, "- **Override reason:** {r}");
    } else {
        s.push_str("- **Override applied:** no (gate opened cleanly)\n");
    }
    if !blocker_codes.is_empty() {
        s.push_str("- **Blocker codes (captured at transition time):**\n");
        for code in blocker_codes {
            let _ = writeln!(s, "  - `{code}`");
        }
    }
    s.push_str("\n## Audit trail\n\n");
    s.push_str(
        "This transition is recorded as a `PhaseTransitioned` event in the engagement's \
         signed merkle log. The blockers listed above (if any) were what the gate \
         would have refused; an operator override carrying ≥20-char rationale was \
         required to override them.\n",
    );
    s
}

fn render_wave_md(w: &pass::WaveMerge, floor_rank: u8) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Wave {}\n", w.wave_number);

    let _ = writeln!(s, "- **Merged at (unix):** {}", w.merged_at_unix);

    let _ = writeln!(
        s,
        "- **Handoffs:** {}/{} received",
        w.handoffs_received, w.assignments_total
    );
    if !w.handoffs_missing.is_empty() {
        let _ = writeln!(
            s,
            "- **Missing handoffs:** `{}`",
            w.handoffs_missing.join("`, `")
        );
    }
    let _ = writeln!(s, "- **Findings (raw):** {}", w.findings_total);

    let _ = writeln!(s, "- **Dead-ends:** {}", w.dead_ends_total);

    let _ = writeln!(s, "- **Coverage entries:** {}\n", w.coverage_total);

    s.push_str("## Findings by severity\n\n");
    s.push_str("| Severity | Count | Reported |\n|---|---|---|\n");
    for sev in ["critical", "high", "medium", "low", "info"] {
        if let Some(n) = w.findings_by_severity.get(sev) {
            let admitted = if severity_rank(sev) >= floor_rank {
                "yes"
            } else {
                "no"
            };
            let _ = writeln!(s, "| {sev} | {n} | {admitted} |");
        }
    }
    s.push('\n');

    s.push_str("## Findings (above floor)\n\n");
    for sev in ["critical", "high", "medium", "low", "info"] {
        if severity_rank(sev) < floor_rank {
            continue;
        }
        let group: Vec<&pass::Finding> = w.findings.iter().filter(|f| f.severity == sev).collect();
        if group.is_empty() {
            continue;
        }
        let _ = writeln!(
            s,
            "### {sev} ({} finding{})\n",
            group.len(),
            if group.len() == 1 { "" } else { "s" }
        );
        for f in group {
            let _ = writeln!(s, "- **{}** — `{}`", f.title, f.surface);

            let evidence_one_line: String =
                f.evidence.replace('\n', " ").chars().take(400).collect();
            let _ = writeln!(s, "  - _evidence_: {evidence_one_line}");
        }
        s.push('\n');
    }
    s
}

fn render_timeline(jsonl: &str) -> String {
    let mut s = String::new();
    s.push_str("# Engagement timeline\n\n");
    s.push_str(
        "Chronological log of every event in the engagement's signed merkle stream. \
         Each row corresponds to one signed leaf in the per-engagement Merkle tree.\n\n",
    );
    s.push_str("| seq | unix | kind | summary |\n|---|---|---|---|\n");
    for line in jsonl.lines() {
        let Ok(v): Result<Value, _> = serde_json::from_str(line) else {
            continue;
        };
        let seq = v.get("seq").and_then(|x| x.as_u64()).unwrap_or(0);
        let ts = v
            .get("wall_clock_unix")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let kind = v
            .get("kind")
            .and_then(|k| k.get("kind"))
            .and_then(|k| k.as_str())
            .unwrap_or("?");
        let summary = summarize_event_kind(kind, &v);
        let _ = writeln!(s, "| {seq} | {ts} | `{kind}` | {summary} |");
    }
    s
}

fn summarize_event_kind(kind: &str, v: &Value) -> String {
    let k = match v.get("kind") {
        Some(k) => k,
        None => return String::new(),
    };
    let g = |field: &str| {
        k.get(field)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };
    match kind {
        "EngagementCreated" => format!("name=`{}`", g("name")),
        "EngagementAuthorized" => format!("scope_hash=`{}`", g("scope_hash")),
        "EngagementStarted" | "EngagementPaused" | "EngagementResumed" | "EngagementCompleted" => {
            "—".to_string()
        }
        "ScopeDecisionLogged" => format!(
            "in_scope={} target=`{}` reason={}",
            k.get("in_scope")
                .and_then(|x| x.as_bool())
                .map(|b| b.to_string())
                .unwrap_or_default(),
            g("target"),
            g("reason"),
        ),
        "SurfaceDiscovered" => format!(
            "{}://{}:{}{} status={}",
            g("scheme"),
            g("host"),
            k.get("port").and_then(|x| x.as_u64()).unwrap_or(0),
            g("path"),
            k.get("status").and_then(|x| x.as_u64()).unwrap_or(0),
        ),
        "HypothesisGenerated" => format!(
            "surface=`{}` vuln_class=`{}` prior={}",
            g("surface_id"),
            g("vuln_class"),
            k.get("prior").and_then(|x| x.as_u64()).unwrap_or(0),
        ),
        "PrimitiveExecuted" => {
            format!("primitive=`{}` verdict={}", g("primitive_id"), g("verdict"))
        }
        "ClaimVerified" => format!(
            "primitive=`{}` verifier=`{}`",
            g("primitive_id"),
            g("verifier_id")
        ),
        "ClaimRejected" | "ClaimRetained" => {
            format!("primitive=`{}` reason={}", g("primitive_id"), g("reason"))
        }
        "PhaseTransitioned" => format!("{} → {}", g("from"), g("to")),
        "VerificationAttemptOpened" => format!(
            "attempt=`{}` snapshot=`{}`",
            g("attempt_id"),
            g("snapshot_hash")
        ),
        "VerificationRoundWritten" => format!(
            "round=`{}` attempt=`{}` results={}",
            g("round"),
            g("attempt_id"),
            k.get("results_count").and_then(|x| x.as_u64()).unwrap_or(0)
        ),
        "AdjudicationBuilt" => format!(
            "attempt=`{}` plan=`{}` agreed={} replay_required={}",
            g("attempt_id"),
            g("plan_hash"),
            k.get("agreed_count").and_then(|x| x.as_u64()).unwrap_or(0),
            k.get("replay_required_count")
                .and_then(|x| x.as_u64())
                .unwrap_or(0)
        ),
        _ => "—".to_string(),
    }
}

fn render_readme(
    summary: &EngagementSummary,
    target_host: &str,
    waves: &[pass::WaveMerge],
    by_sev: &BTreeMap<String, u32>,
    findings: &[(usize, &pass::Finding)],
    phase_events: &[PhaseEvent],
    floor_rank: u8,
) -> String {
    let total_findings: u32 = waves.iter().map(|w| w.findings_total).sum();
    let mut s = String::new();
    let _ = writeln!(s, "# {target_host} — engagement `{}`\n", summary.id);
    let _ = writeln!(s, "- **Engagement name:** `{}`", summary.name);

    let _ = writeln!(s, "- **Daemon state:** `{}`", summary.state);

    let _ = writeln!(s, "- **Events recorded:** {}", summary.event_count);

    if let Some(h) = &summary.scope_hash {
        let _ = writeln!(s, "- **Scope hash:** `{}`", h);
    }
    let _ = writeln!(s, "- **Waves merged:** {}", waves.len());

    let _ = writeln!(s, "- **Findings (raw):** {}", total_findings);

    let _ = writeln!(s, "- **Phase events:** {}", phase_events.len());

    s.push_str("\n## Severity breakdown\n\n");
    s.push_str("| Severity | Count | Reported |\n|---|---|---|\n");
    for sev in ["critical", "high", "medium", "low", "info"] {
        if let Some(n) = by_sev.get(sev) {
            let admitted = if severity_rank(sev) >= floor_rank {
                "yes"
            } else {
                "no"
            };
            let _ = writeln!(s, "| {sev} | {n} | {admitted} |");
        }
    }
    s.push_str("\n## Layout\n\n");
    s.push_str("```\n");
    s.push_str("README.md                  this file\n");
    s.push_str("vulnerability-report.md    consolidated report\n");
    s.push_str("timeline.md                chronological event log\n");
    s.push_str("events.jsonl               raw signed merkle stream\n");
    s.push_str("findings/                  one .md per finding\n");
    s.push_str("phases/                    one .md per phase transition\n");
    s.push_str("waves/                     one .md per wave merge\n");
    s.push_str("```\n");
    s.push_str("\n## Findings index\n\n");
    if findings.is_empty() {
        s.push_str("_No findings recorded._\n");
    } else {
        s.push_str("| # | Severity | Title | File |\n|---|---|---|---|\n");
        for (n, f) in findings {
            let one_line: String = f.title.replace('|', "\\|").chars().take(120).collect();
            let _ = writeln!(
                s,
                "| F-{n:02} | `{}` | {} | [`findings/F-{n:02}.md`](findings/F-{n:02}.md) |",
                f.severity, one_line
            );
        }
    }
    s.push_str("\n## Phase log\n\n");
    if phase_events.is_empty() {
        s.push_str("_No `PhaseTransitioned` events recorded._\n");
    } else {
        s.push_str("| # | From | To | Override | File |\n|---|---|---|---|---|\n");
        for (idx, (from, to, override_reason, _bc, _ts)) in phase_events.iter().enumerate() {
            let n = idx + 1;
            let name = format!("{n:02}-{}-to-{}.md", from.to_lowercase(), to.to_lowercase());
            let override_str = if override_reason.is_some() {
                "yes"
            } else {
                "no"
            };
            let _ = writeln!(s,
                "| {n:02} | `{from}` | `{to}` | {override_str} | [`phases/{name}`](phases/{name}) |"
            );
        }
    }
    s.push_str("\n## Provenance\n\n");
    s.push_str(
        "Every entry above is reproducible from the `events.jsonl` file in this folder. \
         The events are leaves in the engagement's BLAKE3 Merkle tree, signed by the \
         workspace's Ed25519 key. Verify any inclusion proof with the standalone \
         `mantis-verify` binary.\n",
    );
    s
}
