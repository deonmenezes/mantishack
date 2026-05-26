//! Render a Mantis engagement report from an already-merged wave on
//! disk. Used for the "ingest prior research findings" flow — when
//! findings come from a captured bug-bounty handoff rather than a
//! live Mantis-driven scan.
//!
//! Usage:
//!   mantis-mcp-render-ingest <engagement_id> [--severity-floor low|info|...]
//!
//! Looks for `./mantishack-<engagement_id>/waves/*/merged.json`
//! (already produced by the operator's ingest script), reads the
//! engagement status from the daemon, renders markdown to
//! `./mantishack-<engagement_id>/report.md`, and prints a summary.

use mantis_mcp::server::{
    load_wave_merges, parse_severity_floor, render_markdown, severity_rank, EngagementSummary,
    Surface,
};
use mantis_mcp::pass;
use mantis_proto::v1::engagement_client::EngagementClient;
use mantis_proto::v1::StatusRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let engagement_id = args
        .next()
        .ok_or("usage: render_ingest <engagement_id> [--severity-floor <floor>]")?;
    let mut floor_arg: Option<String> = None;
    while let Some(a) = args.next() {
        if a == "--severity-floor" {
            floor_arg = args.next();
        }
    }
    let floor_rank = parse_severity_floor(floor_arg.as_deref());

    // Load engagement metadata from the running daemon.
    let mut client = EngagementClient::connect("http://127.0.0.1:50451").await?;
    let info = client
        .status(StatusRequest {
            id: engagement_id.clone(),
        })
        .await?
        .into_inner();
    let summary = EngagementSummary::from(info);

    let dir = std::path::PathBuf::from(format!("./mantishack-{}", engagement_id));
    let waves = load_wave_merges(&dir);
    let mut chains: Vec<(u32, Vec<pass::ChainAttempt>)> = Vec::new();
    for w in &waves {
        let attempts = pass::read_chain_attempts(&summary.id, w.wave_number);
        if !attempts.is_empty() {
            chains.push((w.wave_number, attempts));
        }
    }

    let surfaces: Vec<Surface> = Vec::new(); // no surface ingest in this flow
    let report = render_markdown(&summary, &surfaces, &waves, &chains, floor_rank);
    let out = dir.join("report.md");
    std::fs::write(&out, &report)?;

    let total_findings: u32 = waves.iter().map(|w| w.findings_total).sum();
    let mut by_sev = std::collections::BTreeMap::<String, u32>::new();
    for w in &waves {
        for (k, v) in &w.findings_by_severity {
            *by_sev.entry(k.clone()).or_default() += v;
        }
    }
    println!("Engagement:    {}", summary.id);
    println!("Name:          {}", summary.name);
    println!("State:         {}", summary.state);
    println!("Waves merged:  {}", waves.len());
    println!("Findings (raw):");
    for sev in ["critical", "high", "medium", "low", "info"] {
        if let Some(n) = by_sev.get(sev) {
            let admitted = if severity_rank(sev) >= floor_rank {
                "reported"
            } else {
                "suppressed"
            };
            println!("  {sev:10} {n:>4}  ({admitted})");
        }
    }
    println!("Findings total: {}", total_findings);
    println!("Floor applied:  rank {}", floor_rank);
    println!("Report:         {}", out.display());
    Ok(())
}
