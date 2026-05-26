//! Per-target archival of an [`crate::AuthBugReport`].
//!
//! Mirrors the layout from `mantis-mcp::examples::archive_engagement`
//! so every Mantis-discovered finding lives under the same
//! `reports/<host>/<engagement-id>/` structure regardless of which
//! subcommand produced it.
//!
//! Layout:
//! ```text
//! reports/<host>/<engagement-id>/
//! ├── README.md
//! ├── vulnerability-report.md
//! ├── timeline.md
//! ├── findings.json
//! ├── findings/F-01.md ... F-N.md
//! └── phases/01-signup-attacker.md ... 05-aggregate.md
//! ```

use crate::find_auth_bugs::AuthBugReport;
use mantis_auth_differential::DiffFinding;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum ArchiveError {
    #[error("io error writing {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::sync::Arc<std::io::Error>,
    },
    #[error("encode error: {0}")]
    Encode(String),
}

#[derive(Debug, Clone)]
pub struct ArchiveOutcome {
    pub root: PathBuf,
    pub readme: PathBuf,
    pub vuln_report: PathBuf,
    pub findings_json: PathBuf,
    pub finding_count: usize,
}

/// Write the full archive. `engagement_id` is the operator-visible
/// ULID for this run.
pub fn write_archive(
    report: &AuthBugReport,
    engagement_id: &str,
    reports_root: &Path,
) -> Result<ArchiveOutcome, ArchiveError> {
    let host = host_from_url(&report.target_url);
    let root = reports_root.join(&host).join(engagement_id);
    let findings_dir = root.join("findings");
    let phases_dir = root.join("phases");
    fs_create(&findings_dir)?;
    fs_create(&phases_dir)?;

    // 1. findings.json — every finding aggregated for machine consumers.
    let flat_findings: Vec<FlatFinding> = report
        .per_endpoint
        .iter()
        .flat_map(|ep| {
            ep.findings.iter().map(move |f| FlatFinding {
                finding_id: f.finding_id.clone(),
                class: format!("{:?}", f.class),
                vuln_class: f.class.vuln_class().to_string(),
                severity: f.class.default_severity().to_string(),
                url: f.url.clone(),
                evidence: f.evidence.clone(),
                finding_hash: f.finding_hash.clone(),
            })
        })
        .collect();
    let findings_json = root.join("findings.json");
    fs_write(
        &findings_json,
        serde_json::to_vec_pretty(&serde_json::json!({
            "engagement_id": engagement_id,
            "target_url": report.target_url,
            "host": host,
            "attacker_email": report.attacker_email,
            "victim_email": report.victim_email,
            "endpoints_probed": report.endpoints_probed,
            "endpoints_with_findings": report.endpoints_with_findings,
            "findings_total": report.findings_total,
            "by_severity": report.findings_by_severity,
            "by_class": report.findings_by_class,
            "findings": flat_findings,
        }))
        .map_err(|e| ArchiveError::Encode(e.to_string()))?,
    )?;

    // 2. Per-finding markdown files.
    let mut numbered: Vec<(usize, &DiffFinding, &str)> = Vec::new();
    let mut sorted_endpoints: Vec<_> = report.per_endpoint.iter().collect();
    sorted_endpoints.sort_by(|a, b| {
        // Endpoints with more findings first, then by URL.
        b.findings
            .len()
            .cmp(&a.findings.len())
            .then(a.url.cmp(&b.url))
    });
    let mut idx = 0usize;
    for ep in &sorted_endpoints {
        for f in &ep.findings {
            idx += 1;
            numbered.push((idx, f, ep.url.as_str()));
            let path = findings_dir.join(format!("F-{idx:02}.md"));
            fs_write(&path, render_finding_md(idx, f).into_bytes())?;
        }
    }

    // 3. Phase log — one file per pipeline stage.
    let phases: Vec<(&str, &str, String)> = vec![
        (
            "01-signup-attacker.md",
            "01 Signup attacker",
            match &report.attacker_email {
                Some(e) => format!(
                    "Attacker account registered with email `{e}`. Profile bound to `apikey` + `Authorization: Bearer …` headers.\n",
                ),
                None => "Skipped — no Supabase signup config supplied; pipeline ran unauth-only or with BYO profile.\n".into(),
            },
        ),
        (
            "02-signup-victim.md",
            "02 Signup victim",
            match &report.victim_email {
                Some(e) => format!(
                    "Victim account registered with email `{e}`. Distinct identity from attacker — divergence between the two responses is the auth-diff signal.\n",
                ),
                None => "Skipped — no Supabase signup config supplied; pipeline ran unauth-only or with BYO profile.\n".into(),
            },
        ),
        (
            "03-enumerate.md",
            "03 Enumerate endpoints",
            format!(
                "Wordlist + operator-supplied `--extra-path` expanded the seed URL into {} candidate(s); {} were probed before the budget cap fired.\n",
                report.endpoints_probed, report.endpoints_probed,
            ),
        ),
        (
            "04-auth-diff.md",
            "04 Auth-differential per endpoint",
            {
                let mut s = String::new();
                // The original first push_str(&format!()) had no
                // interpolation args at all — write a plain str instead
                // of allocating a redundant intermediate String.
                s.push_str("Replayed each candidate URL under all available profiles (unauthenticated, attacker, victim). Per-endpoint hits below:\n\n");
                for ep in &report.per_endpoint {
                    if ep.findings.is_empty() {
                        continue;
                    }
                    // write! lets the formatter write directly into `s`
                    // instead of allocating a fresh String per line via
                    // format!() then push_str-ing it. Per endpoint with
                    // K findings we save 1 + K String allocations.
                    let _ = writeln!(s, "- `{}` — {} finding(s)", ep.url, ep.findings.len());
                    for f in &ep.findings {
                        let _ = writeln!(
                            s,
                            "  - **{:?}** severity=`{}` hash=`{}`",
                            f.class,
                            f.class.default_severity(),
                            &f.finding_hash[..16.min(f.finding_hash.len())]
                        );
                    }
                }
                // Bound the line-count iteration: we only need to
                // know if there are ≤ 2 lines, so `.take(3)` lets the
                // count exit as soon as we hit 3. For a long auth-diff
                // section this avoids scanning the whole string.
                if s.lines().take(3).count() <= 2 {
                    s.push_str("_No divergence detected on any probed endpoint._\n");
                }
                s
            },
        ),
        (
            "05-aggregate.md",
            "05 Aggregate findings",
            format!(
                "**Endpoints with findings:** {} / {} probed\n\n\
                 **Findings by severity:**\n\n{}\n\
                 **Findings by class:**\n\n{}\n",
                report.endpoints_with_findings,
                report.endpoints_probed,
                bullets_kv(&report.findings_by_severity),
                bullets_kv(&report.findings_by_class),
            ),
        ),
    ];
    for (filename, title, body) in &phases {
        let path = phases_dir.join(filename);
        let md = format!(
            "# {title}\n\n{body}\n\n## Provenance\n\nThis phase is one stage of the `mantis find-auth-bugs` pipeline. The full chain — signup×2 → enumerate → auth-diff×N → aggregate — runs in a single CLI invocation and is reproducible via the JSON archive at `../findings.json`.\n",
        );
        fs_write(&path, md.into_bytes())?;
    }

    // 4. timeline.md — flat chronological log.
    let mut tl = String::new();
    tl.push_str("# Pipeline timeline\n\n");
    tl.push_str("| # | stage | summary |\n|---|---|---|\n");
    for (i, (filename, title, _)) in phases.iter().enumerate() {
        let _ = writeln!(tl, "| {} | [{title}](phases/{filename}) | — |", i + 1);
    }
    tl.push_str("\n## Findings landed\n\n");
    if numbered.is_empty() {
        tl.push_str("_No findings._\n");
    } else {
        tl.push_str("| F-# | class | severity | URL |\n|---|---|---|---|\n");
        for (n, f, url) in &numbered {
            let _ = writeln!(
                tl,
                "| F-{n:02} | `{}` | `{}` | `{url}` |",
                f.class.vuln_class(),
                f.class.default_severity(),
            );
        }
    }
    fs_write(&root.join("timeline.md"), tl.into_bytes())?;

    // 5. vulnerability-report.md — the consolidated full report.
    let vuln_path = root.join("vulnerability-report.md");
    fs_write(
        &vuln_path,
        render_vulnerability_report(report, &numbered).into_bytes(),
    )?;

    // 6. README.md — index.
    let readme_path = root.join("README.md");
    fs_write(
        &readme_path,
        render_readme(report, engagement_id, &host, &numbered).into_bytes(),
    )?;

    Ok(ArchiveOutcome {
        root,
        readme: readme_path,
        vuln_report: vuln_path,
        findings_json,
        finding_count: numbered.len(),
    })
}

fn fs_create(p: &Path) -> Result<(), ArchiveError> {
    std::fs::create_dir_all(p).map_err(|e| ArchiveError::Io {
        path: p.display().to_string(),
        source: std::sync::Arc::new(e),
    })
}

fn fs_write(p: &Path, bytes: Vec<u8>) -> Result<(), ArchiveError> {
    if let Some(parent) = p.parent() {
        fs_create(parent)?;
    }
    std::fs::write(p, bytes).map_err(|e| ArchiveError::Io {
        path: p.display().to_string(),
        source: std::sync::Arc::new(e),
    })
}

fn host_from_url(url: &str) -> String {
    let s = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = s.split(['/', '?', '#']).next().unwrap_or(s);
    let host = host.split(':').next().unwrap_or(host);
    let normalized = host.trim_start_matches("www.").to_ascii_lowercase();
    normalized
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

#[derive(serde::Serialize)]
struct FlatFinding {
    finding_id: String,
    class: String,
    vuln_class: String,
    severity: String,
    url: String,
    evidence: String,
    finding_hash: String,
}

fn bullets_kv(map: &std::collections::BTreeMap<String, u32>) -> String {
    if map.is_empty() {
        return "_(empty)_\n".into();
    }
    map.iter()
        .map(|(k, v)| format!("- `{k}` × {v}\n"))
        .collect()
}

fn render_finding_md(n: usize, f: &DiffFinding) -> String {
    format!(
        "# Finding F-{n:02}\n\n\
         - **Class:** `{:?}`\n\
         - **Vuln class:** `{}`\n\
         - **Severity:** `{}`\n\
         - **URL:** `{}`\n\
         - **Finding hash:** `{}`\n\n\
         ## Evidence\n\n{}\n\n\
         ## Reproducer\n\n\
         Re-run the auth-differential against the same URL with attacker + victim profiles. The shape divergence above is the signal. Use:\n\n\
         ```sh\n\
         mantis auth-diff \\\n    \
             --url {} \\\n    \
             --profile attacker=./attacker.json \\\n    \
             --profile victim=./victim.json \\\n    \
             --i-have-authorization\n\
         ```\n\n\
         ## Provenance\n\n\
         Discovered by the `mantis find-auth-bugs` end-to-end pipeline. The full per-endpoint diff record is in `../findings.json`; the raw merkle event log for the parent engagement (when run through the daemon) is `events.jsonl` at the engagement root.\n",
        f.class,
        f.class.vuln_class(),
        f.class.default_severity(),
        f.url,
        f.finding_hash,
        f.evidence,
        f.url,
    )
}

fn render_vulnerability_report(
    report: &AuthBugReport,
    numbered: &[(usize, &DiffFinding, &str)],
) -> String {
    let mut s = String::new();
    s.push_str("# Vulnerability report\n\n");
    let _ = writeln!(s, "- **Target:** `{}`", report.target_url);
    if let Some(e) = &report.attacker_email {
        let _ = writeln!(s, "- **Attacker account:** `{e}`");
    }
    if let Some(e) = &report.victim_email {
        let _ = writeln!(s, "- **Victim account:** `{e}`");
    }
    let _ = writeln!(s, "- **Endpoints probed:** {}", report.endpoints_probed);
    let _ = writeln!(
        s,
        "- **Endpoints with findings:** {}",
        report.endpoints_with_findings
    );
    let _ = writeln!(s, "- **Findings total:** {}", report.findings_total);
    s.push_str("\n## Severity breakdown\n\n");
    s.push_str("| Severity | Count |\n|---|---|\n");
    for sev in ["critical", "high", "medium", "low", "info"] {
        if let Some(n) = report.findings_by_severity.get(sev) {
            let _ = writeln!(s, "| {sev} | {n} |");
        }
    }
    s.push_str("\n## Class breakdown\n\n");
    s.push_str("| Class | Count |\n|---|---|\n");
    for (k, v) in &report.findings_by_class {
        let _ = writeln!(s, "| `{k}` | {v} |");
    }
    s.push_str("\n## Findings\n\n");
    if numbered.is_empty() {
        s.push_str("_No findings discovered._\n");
    } else {
        for (n, f, url) in numbered {
            let _ = writeln!(
                s,
                "### F-{n:02} — `{}` (`{}`)\n",
                f.class.vuln_class(),
                f.class.default_severity()
            );
            let _ = writeln!(s, "- **URL:** `{url}`");
            let _ = writeln!(s, "- **Hash:** `{}`\n", f.finding_hash);
            s.push_str("**Evidence**\n\n");
            s.push_str(&f.evidence);
            s.push_str("\n\n---\n\n");
        }
    }
    s
}

fn render_readme(
    report: &AuthBugReport,
    engagement_id: &str,
    host: &str,
    numbered: &[(usize, &DiffFinding, &str)],
) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# {host} — `find-auth-bugs` engagement `{engagement_id}`\n"
    );
    let _ = writeln!(s, "- **Target URL:** `{}`", report.target_url);
    if let Some(e) = &report.attacker_email {
        let _ = writeln!(s, "- **Attacker:** `{e}`");
    }
    if let Some(e) = &report.victim_email {
        let _ = writeln!(s, "- **Victim:** `{e}`");
    }
    let _ = writeln!(s, "- **Endpoints probed:** {}", report.endpoints_probed);
    let _ = writeln!(
        s,
        "- **Endpoints with findings:** {}",
        report.endpoints_with_findings
    );
    let _ = writeln!(s, "- **Findings total:** {}", report.findings_total);
    s.push_str("\n## Severity breakdown\n\n");
    s.push_str("| Severity | Count |\n|---|---|\n");
    for sev in ["critical", "high", "medium", "low", "info"] {
        if let Some(n) = report.findings_by_severity.get(sev) {
            let _ = writeln!(s, "| {sev} | {n} |");
        }
    }
    s.push_str("\n## Layout\n\n```\n");
    s.push_str("README.md                  this file\n");
    s.push_str("vulnerability-report.md    consolidated full report\n");
    s.push_str("timeline.md                pipeline timeline + finding index\n");
    s.push_str("findings.json              machine-readable findings record\n");
    s.push_str("findings/                  one .md per finding (F-01.md ...)\n");
    s.push_str("phases/                    one .md per pipeline stage\n");
    s.push_str("```\n");
    s.push_str("\n## Findings index\n\n");
    if numbered.is_empty() {
        s.push_str("_No findings._\n");
    } else {
        s.push_str("| F-# | severity | class | URL | file |\n|---|---|---|---|---|\n");
        for (n, f, url) in numbered {
            let _ = writeln!(
                s,
                "| F-{n:02} | `{}` | `{:?}` | `{url}` | [`findings/F-{n:02}.md`](findings/F-{n:02}.md) |",
                f.class.default_severity(),
                f.class,
            );
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::find_auth_bugs::{AuthBugReport, EndpointResult};
    use mantis_auth_differential::{DiffFinding, DivergenceClass};

    fn fake_finding(class: DivergenceClass, url: &str) -> DiffFinding {
        DiffFinding {
            finding_id: "auth-diff-1".into(),
            class,
            url: url.into(),
            evidence: "shape match across attacker+victim".into(),
            finding_hash: "deadbeef00000000".into(),
        }
    }

    fn report_with_findings() -> AuthBugReport {
        let mut by_sev = std::collections::BTreeMap::new();
        by_sev.insert("critical".into(), 2u32);
        let mut by_class = std::collections::BTreeMap::new();
        by_class.insert("broken-access-control.cross-tenant-read".into(), 2u32);
        AuthBugReport {
            target_url: "https://app.example.com/".into(),
            attacker_email: Some("attacker@mantis-test.invalid".into()),
            victim_email: Some("victim@mantis-test.invalid".into()),
            endpoints_probed: 30,
            endpoints_with_findings: 2,
            findings_total: 2,
            findings_by_severity: by_sev,
            findings_by_class: by_class,
            per_endpoint: vec![
                EndpointResult {
                    url: "https://app.example.com/rest/v1/orders".into(),
                    findings: vec![fake_finding(
                        DivergenceClass::CrossTenantRead,
                        "https://app.example.com/rest/v1/orders",
                    )],
                },
                EndpointResult {
                    url: "https://app.example.com/api/users".into(),
                    findings: vec![fake_finding(
                        DivergenceClass::CrossTenantRead,
                        "https://app.example.com/api/users",
                    )],
                },
            ],
        }
    }

    #[test]
    fn host_extraction_strips_www_and_lowercases() {
        assert_eq!(host_from_url("https://www.Example.COM/x"), "example.com");
        assert_eq!(host_from_url("http://localhost:8080/"), "localhost");
        assert_eq!(
            host_from_url("https://api.example.com:443/v1"),
            "api.example.com"
        );
    }

    #[test]
    fn writes_all_expected_files() {
        let tmp = tempfile::tempdir().unwrap();
        let report = report_with_findings();
        let outcome = write_archive(&report, "ENG-1", tmp.path()).unwrap();
        assert!(outcome.readme.exists());
        assert!(outcome.vuln_report.exists());
        assert!(outcome.findings_json.exists());
        assert_eq!(outcome.finding_count, 2);
        assert!(outcome.root.join("findings/F-01.md").exists());
        assert!(outcome.root.join("findings/F-02.md").exists());
        assert!(outcome.root.join("phases/01-signup-attacker.md").exists());
        assert!(outcome.root.join("phases/05-aggregate.md").exists());
        assert!(outcome.root.join("timeline.md").exists());
    }

    #[test]
    fn finding_md_quotes_evidence_and_curl_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let report = report_with_findings();
        write_archive(&report, "ENG-1", tmp.path()).unwrap();
        let md = std::fs::read_to_string(tmp.path().join("app.example.com/ENG-1/findings/F-01.md"))
            .unwrap();
        assert!(md.contains("shape match across attacker+victim"));
        assert!(md.contains("mantis auth-diff"));
        assert!(md.contains("CrossTenantRead"));
    }

    #[test]
    fn empty_report_still_writes_skeleton() {
        let tmp = tempfile::tempdir().unwrap();
        let report = AuthBugReport {
            target_url: "https://nothing.example/".into(),
            attacker_email: None,
            victim_email: None,
            endpoints_probed: 0,
            endpoints_with_findings: 0,
            findings_total: 0,
            findings_by_severity: Default::default(),
            findings_by_class: Default::default(),
            per_endpoint: vec![],
        };
        let outcome = write_archive(&report, "ENG-EMPTY", tmp.path()).unwrap();
        assert_eq!(outcome.finding_count, 0);
        assert!(outcome.readme.exists());
        assert!(outcome.vuln_report.exists());
        let readme = std::fs::read_to_string(&outcome.readme).unwrap();
        assert!(readme.contains("No findings"));
    }

    #[test]
    fn host_normalization_replaces_unsafe_chars() {
        assert_eq!(host_from_url("https://a/b"), "a");
        assert_eq!(host_from_url("https://EXAMPLE.com:8443/x"), "example.com");
    }
}
