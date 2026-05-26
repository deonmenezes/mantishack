//! Parallel scanner fan-out — the headline perf win.
//!
//! [`run_pipeline`] launches all five scanners simultaneously via
//! `tokio::join!`, then aggregates the results into a single
//! [`ReconBundle`]. Wall-clock is the slowest scanner's duration,
//! not the sum — typically a 4–6× speedup over the LLM-driven
//! flow that issues one scanner call per turn.
//!
//! Each scanner is wrapped so a missing binary or a per-scanner
//! failure degrades to "skip this scanner" rather than aborting
//! the whole pipeline. The [`ScannerStats`] entry records what
//! happened so the operator can see what ran and what didn't.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use mantis_static_scan::{
    httpx::HttpxAdapter, nuclei::NucleiAdapter, subfinder::SubfinderAdapter, trivy::TrivyAdapter,
    trufflehog::TrufflehogAdapter, Finding, ScanError, Severity,
};

use crate::anomaly::detect;
use crate::bundle::{HttpSurface, ReconBundle, ScannerStats};
use crate::cache::{cache_key, default_cache_dir, read_cached, write_cached, DEFAULT_TTL_SECS};
use crate::PipelineError;

/// How deep the pipeline runs. `Quick` keeps the wall-clock under
/// ~60s for fast iteration; `Deep` runs the full battery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PipelineDepth {
    /// nuclei high+critical only, subfinder + httpx, no trivy /
    /// trufflehog filesystem scans. Wall-clock ~30-90s.
    Quick,
    /// All scanners, all severities. Wall-clock 2-10min depending
    /// on target surface size.
    Deep,
}

impl PipelineDepth {
    pub fn label(self) -> &'static str {
        match self {
            PipelineDepth::Quick => "quick",
            PipelineDepth::Deep => "deep",
        }
    }
}

/// Options for one pipeline run.
#[derive(Debug, Clone)]
pub struct PipelineOptions {
    pub depth: PipelineDepth,
    /// Optional scope-manifest hash to mix into the cache key —
    /// scoping change = different bundle.
    pub scope_hash: Option<String>,
    /// Filesystem path for `trufflehog` / `trivy` scans (e.g. a
    /// cloned repo for the target). `None` skips those scanners.
    pub filesystem_root: Option<PathBuf>,
    /// Cache TTL. `Duration::ZERO` disables caching for this call.
    pub cache_ttl: Duration,
    /// Where to read/write cached bundles. Defaults to
    /// `$MANTIS_HOME/recon-cache/`.
    pub cache_dir: PathBuf,
}

impl Default for PipelineOptions {
    fn default() -> Self {
        Self {
            depth: PipelineDepth::Quick,
            scope_hash: None,
            filesystem_root: None,
            cache_ttl: Duration::from_secs(DEFAULT_TTL_SECS),
            cache_dir: default_cache_dir(),
        }
    }
}

/// Run all enabled scanners in parallel against `target` and
/// return a [`ReconBundle`]. Honours `opts.cache_ttl`: a cache hit
/// short-circuits the entire run.
pub async fn run_pipeline(
    target: &str,
    opts: PipelineOptions,
) -> Result<ReconBundle, PipelineError> {
    if target.trim().is_empty() {
        return Err(PipelineError::BadTarget(target.to_string()));
    }

    // Cache lookup before doing any work.
    if opts.cache_ttl > Duration::ZERO {
        let key = cache_key(target, opts.scope_hash.as_deref(), opts.depth.label());
        if let Ok(Some(cached)) = read_cached(&opts.cache_dir, &key, opts.cache_ttl) {
            debug!(target, depth = ?opts.depth, "recon-pipeline cache hit");
            return Ok(cached);
        }
    }

    let started = SystemTime::now();
    let pipeline_started_at = Instant::now();
    let mut bundle = ReconBundle::new(target);

    // Normalise: subdomain enum wants a bare domain. httpx + nuclei
    // want URLs. Build both from the target.
    let domain = strip_scheme(target);
    let target_url = ensure_scheme(target);

    // Fan out. Each future is independent; tokio drives them
    // concurrently on the runtime. We use named futures + join!
    // rather than spawning tasks so failures stay local to each
    // scanner branch and don't require Arc<Mutex<...>> coordination.
    let nuclei_fut = run_nuclei(&target_url, opts.depth);
    let subfinder_fut = run_subfinder(domain);
    let httpx_fut = run_httpx_seeded(&target_url, domain);
    let trufflehog_fut = run_trufflehog(opts.filesystem_root.as_deref(), opts.depth);
    let trivy_fut = run_trivy(opts.filesystem_root.as_deref(), opts.depth);

    let (nuclei_res, subfinder_res, httpx_res, trufflehog_res, trivy_res) = tokio::join!(
        nuclei_fut,
        subfinder_fut,
        httpx_fut,
        trufflehog_fut,
        trivy_fut
    );

    push_scanner_result(&mut bundle, "nuclei", nuclei_res);
    push_subfinder_result(&mut bundle, subfinder_res);
    push_httpx_result(&mut bundle, httpx_res);
    push_scanner_result(&mut bundle, "trufflehog", trufflehog_res);
    push_scanner_result(&mut bundle, "trivy", trivy_res);

    // Derive tech_stack from httpx tech tags (collected during
    // push_httpx_result via the bundle's `live_surfaces`).
    bundle.tech_stack = derive_tech_stack(&bundle.live_surfaces);

    // Run deterministic anomaly detection. Fast (pure pattern
    // matching, ~ms even on hundreds of findings) so we always do
    // it inline.
    bundle.anomalies = detect(&bundle);

    bundle.finalize_elapsed(started);
    debug!(
        target,
        elapsed_ms = bundle.elapsed_ms,
        finding_count = bundle.findings.len(),
        anomaly_count = bundle.anomalies.len(),
        "recon-pipeline complete"
    );

    // Store in cache (best-effort).
    if opts.cache_ttl > Duration::ZERO {
        let key = cache_key(target, opts.scope_hash.as_deref(), opts.depth.label());
        if let Err(e) = write_cached(&opts.cache_dir, &key, &bundle) {
            warn!("recon-pipeline cache write failed: {e}");
        }
    }

    let _ = pipeline_started_at;
    Ok(bundle)
}

// ---------- per-scanner runners ----------

#[derive(Debug)]
struct ScannerResult {
    elapsed_ms: u64,
    outcome: Result<Vec<Finding>, ScanError>,
}

async fn run_nuclei(target_url: &str, depth: PipelineDepth) -> ScannerResult {
    let started = Instant::now();
    let mut adapter = NucleiAdapter::new();
    if matches!(depth, PipelineDepth::Quick) {
        adapter = adapter
            .with_severity_floor(Severity::High)
            .with_timeout(Duration::from_secs(120));
    } else {
        adapter = adapter
            .with_severity_floor(Severity::Low)
            .with_timeout(Duration::from_secs(600));
    }
    let outcome = adapter.scan(target_url).await;
    ScannerResult {
        elapsed_ms: started.elapsed().as_millis() as u64,
        outcome,
    }
}

async fn run_subfinder(domain: &str) -> ScannerResult {
    let started = Instant::now();
    let adapter = SubfinderAdapter::new();
    let outcome = adapter.enumerate(domain).await;
    ScannerResult {
        elapsed_ms: started.elapsed().as_millis() as u64,
        outcome,
    }
}

/// Probe both the original target AND the bare-domain root with
/// httpx. Two-element list is enough for a quick fingerprint; the
/// fuller probe-the-subfinder-output flow lives in `mantis_recon_burst`
/// (which calls run_pipeline + a follow-up httpx pass).
async fn run_httpx_seeded(target_url: &str, domain: &str) -> ScannerResult {
    let started = Instant::now();
    let adapter = HttpxAdapter::new();
    let targets = vec![target_url.to_string(), format!("https://{domain}")];
    let outcome = adapter.probe(&targets).await;
    ScannerResult {
        elapsed_ms: started.elapsed().as_millis() as u64,
        outcome,
    }
}

async fn run_trufflehog(filesystem_root: Option<&Path>, depth: PipelineDepth) -> ScannerResult {
    let started = Instant::now();
    let Some(root) = filesystem_root else {
        return ScannerResult {
            elapsed_ms: 0,
            outcome: Ok(Vec::new()),
        };
    };
    if matches!(depth, PipelineDepth::Quick) {
        // Quick mode: skip trufflehog (filesystem walks are slow).
        return ScannerResult {
            elapsed_ms: 0,
            outcome: Ok(Vec::new()),
        };
    }
    let adapter = TrufflehogAdapter::new();
    let outcome = adapter.scan_filesystem(root).await;
    ScannerResult {
        elapsed_ms: started.elapsed().as_millis() as u64,
        outcome,
    }
}

async fn run_trivy(filesystem_root: Option<&Path>, depth: PipelineDepth) -> ScannerResult {
    let started = Instant::now();
    let Some(root) = filesystem_root else {
        return ScannerResult {
            elapsed_ms: 0,
            outcome: Ok(Vec::new()),
        };
    };
    if matches!(depth, PipelineDepth::Quick) {
        return ScannerResult {
            elapsed_ms: 0,
            outcome: Ok(Vec::new()),
        };
    }
    let adapter = TrivyAdapter::new();
    let outcome = adapter.scan_filesystem(root).await;
    ScannerResult {
        elapsed_ms: started.elapsed().as_millis() as u64,
        outcome,
    }
}

// ---------- result aggregation ----------

fn push_scanner_result(bundle: &mut ReconBundle, name: &str, res: ScannerResult) {
    match res.outcome {
        Ok(findings) => {
            let count = findings.len();
            bundle.findings.extend(findings);
            bundle.scanner_stats.push(ScannerStats {
                scanner: name.to_string(),
                elapsed_ms: res.elapsed_ms,
                finding_count: count,
                error: None,
            });
        }
        Err(e) => {
            warn!(scanner = name, error = %e, "recon-pipeline scanner failed");
            bundle.scanner_stats.push(ScannerStats {
                scanner: name.to_string(),
                elapsed_ms: res.elapsed_ms,
                finding_count: 0,
                error: Some(e.to_string()),
            });
        }
    }
}

fn push_subfinder_result(bundle: &mut ReconBundle, res: ScannerResult) {
    match res.outcome {
        Ok(findings) => {
            let mut hosts: Vec<String> = findings.iter().map(|f| f.target.clone()).collect();
            hosts.sort();
            hosts.dedup();
            let count = hosts.len();
            bundle.subdomains = hosts;
            bundle.findings.extend(findings);
            bundle.scanner_stats.push(ScannerStats {
                scanner: "subfinder".into(),
                elapsed_ms: res.elapsed_ms,
                finding_count: count,
                error: None,
            });
        }
        Err(e) => {
            warn!(error = %e, "recon-pipeline subfinder failed");
            bundle.scanner_stats.push(ScannerStats {
                scanner: "subfinder".into(),
                elapsed_ms: res.elapsed_ms,
                finding_count: 0,
                error: Some(e.to_string()),
            });
        }
    }
}

fn push_httpx_result(bundle: &mut ReconBundle, res: ScannerResult) {
    match res.outcome {
        Ok(findings) => {
            let surfaces: Vec<HttpSurface> = findings
                .iter()
                .map(|f| HttpSurface {
                    url: f.target.clone(),
                    status: f
                        .meta
                        .get("status_code")
                        .and_then(|s| s.parse::<u16>().ok()),
                    title: extract_title_from_httpx(&f.title),
                    webserver: f.meta.get("webserver").cloned(),
                    tech: f
                        .meta
                        .get("tech")
                        .map(|s| {
                            s.split(',')
                                .map(|x| x.trim().to_string())
                                .filter(|x| !x.is_empty())
                                .collect()
                        })
                        .unwrap_or_default(),
                })
                .collect();
            let count = surfaces.len();
            bundle.live_surfaces = surfaces;
            bundle.findings.extend(findings);
            bundle.scanner_stats.push(ScannerStats {
                scanner: "httpx".into(),
                elapsed_ms: res.elapsed_ms,
                finding_count: count,
                error: None,
            });
        }
        Err(e) => {
            warn!(error = %e, "recon-pipeline httpx failed");
            bundle.scanner_stats.push(ScannerStats {
                scanner: "httpx".into(),
                elapsed_ms: res.elapsed_ms,
                finding_count: 0,
                error: Some(e.to_string()),
            });
        }
    }
}

/// httpx adapter packs status + webserver + title into its Finding
/// title; recover just the human-readable HTML title for the
/// surface graph. Title field shape is roughly `"<status> <webserver> <title>"`.
fn extract_title_from_httpx(t: &str) -> Option<String> {
    let pieces: Vec<&str> = t.splitn(3, ' ').collect();
    if pieces.len() == 3 {
        let body = pieces[2].trim();
        if body.is_empty() {
            None
        } else {
            Some(body.to_string())
        }
    } else {
        None
    }
}

fn derive_tech_stack(surfaces: &[HttpSurface]) -> std::collections::BTreeMap<String, Vec<String>> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut by_cat: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for s in surfaces {
        if let Some(ws) = &s.webserver {
            if !ws.is_empty() {
                by_cat
                    .entry("server".into())
                    .or_default()
                    .insert(ws.clone());
            }
        }
        for tech in &s.tech {
            by_cat
                .entry("framework".into())
                .or_default()
                .insert(tech.clone());
        }
    }
    by_cat
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().collect()))
        .collect()
}

fn strip_scheme(target: &str) -> &str {
    target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
        .map(|s| s.split('/').next().unwrap_or(s))
        .map(|s| s.split(':').next().unwrap_or(s))
        .unwrap_or(target)
}

fn ensure_scheme(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{target}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_scheme_removes_protocol_and_path() {
        assert_eq!(strip_scheme("https://example.com/foo"), "example.com");
        assert_eq!(
            strip_scheme("http://api.example.com:8080/x"),
            "api.example.com"
        );
        assert_eq!(strip_scheme("example.com"), "example.com");
    }

    #[test]
    fn ensure_scheme_adds_https_when_absent() {
        assert_eq!(ensure_scheme("example.com"), "https://example.com");
        assert_eq!(ensure_scheme("https://x"), "https://x");
        assert_eq!(ensure_scheme("http://x"), "http://x");
    }

    #[test]
    fn extract_title_from_httpx_format() {
        assert_eq!(
            extract_title_from_httpx("200 nginx Welcome to example.com"),
            Some("Welcome to example.com".into())
        );
        assert_eq!(extract_title_from_httpx("200 nginx "), None);
        assert_eq!(extract_title_from_httpx("404"), None);
    }

    #[test]
    fn empty_target_is_rejected() {
        let opts = PipelineOptions::default();
        let r = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run_pipeline("", opts));
        assert!(matches!(r, Err(PipelineError::BadTarget(_))));
    }

    // -------------------------------------------------------------
    // Parallelism benchmark. Validates the headline claim that
    // the pipeline is bound by max(scanner_durations), not sum.
    //
    // We can't easily inject mock scanners into the public API
    // without a larger refactor (the adapters own their own
    // spawn logic). Instead, run the equivalent join! pattern
    // directly with controlled-delay async tasks and assert the
    // wall-clock matches the parallel ideal.
    // -------------------------------------------------------------
    #[tokio::test]
    async fn parallel_fan_out_completes_in_max_duration_not_sum() {
        let started = std::time::Instant::now();

        // Five "scanners" with staggered delays — mirrors the
        // shape of run_pipeline's tokio::join! call.
        let (a, b, c, d, e) = tokio::join!(
            async {
                tokio::time::sleep(Duration::from_millis(80)).await;
                1u32
            },
            async {
                tokio::time::sleep(Duration::from_millis(120)).await;
                2u32
            },
            async {
                tokio::time::sleep(Duration::from_millis(60)).await;
                3u32
            },
            async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                4u32
            },
            async {
                tokio::time::sleep(Duration::from_millis(40)).await;
                5u32
            },
        );

        let elapsed = started.elapsed();
        // Sum would be 400ms; parallel ideal is 120ms. Allow some
        // scheduler overhead — anything below 250ms confirms the
        // parallelism is real.
        assert!(
            elapsed < Duration::from_millis(250),
            "expected parallel ideal ~120ms, got {elapsed:?} \
             (would-be-sequential would be 400ms)"
        );
        assert_eq!(a + b + c + d + e, 15);
    }
}
