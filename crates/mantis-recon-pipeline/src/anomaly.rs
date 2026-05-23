//! Deterministic anomaly detection — pure pattern matching against
//! recon findings + surfaces. No LLM in this layer.
//!
//! Each rule is a small predicate over the bundle that flags
//! patterns experienced operators would manually highlight: admin
//! panels, IDOR-shaped URLs, JWT signals, leaked debug endpoints,
//! version mismatches, etc. The flags are emitted as [`Anomaly`]
//! entries so the LLM gets a curated "look here first" list rather
//! than 30 nuclei findings of equal weight.

use serde::{Deserialize, Serialize};

use mantis_static_scan::{Finding, Severity};

use crate::bundle::{HttpSurface, ReconBundle};

/// Class of anomaly. Used for grouping in the handoff and for
/// downstream filtering / weighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyKind {
    AdminEndpoint,
    PossibleIdor,
    ExposedConfig,
    DebugEndpoint,
    JwtPresent,
    OutdatedTech,
    AuthMismatch,
    SecretSignal,
    UnusualPort,
    PublicGitData,
    EnvLeak,
    ApiVersion,
    Other,
}

impl AnomalyKind {
    pub fn label(&self) -> &'static str {
        match self {
            AnomalyKind::AdminEndpoint => "admin endpoint",
            AnomalyKind::PossibleIdor => "possible IDOR",
            AnomalyKind::ExposedConfig => "exposed config",
            AnomalyKind::DebugEndpoint => "debug endpoint",
            AnomalyKind::JwtPresent => "JWT detected",
            AnomalyKind::OutdatedTech => "outdated tech",
            AnomalyKind::AuthMismatch => "auth mismatch",
            AnomalyKind::SecretSignal => "secret signal",
            AnomalyKind::UnusualPort => "unusual port",
            AnomalyKind::PublicGitData => "exposed git data",
            AnomalyKind::EnvLeak => "env/build leak",
            AnomalyKind::ApiVersion => "API version exposed",
            AnomalyKind::Other => "other",
        }
    }
}

/// One flagged pattern. `surface` is the URL / host / path the
/// rule fired on. `rationale` is one-line operator-readable text
/// explaining why we flagged it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub kind: AnomalyKind,
    pub surface: String,
    pub rationale: String,
}

impl Anomaly {
    pub fn new(
        kind: AnomalyKind,
        surface: impl Into<String>,
        rationale: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            surface: surface.into(),
            rationale: rationale.into(),
        }
    }
}

/// Run every detection rule against the bundle. Each rule is
/// independent and may emit zero or more anomalies. Duplicate
/// `(kind, surface)` pairs are deduped before return.
pub fn detect(bundle: &ReconBundle) -> Vec<Anomaly> {
    let mut found: Vec<Anomaly> = Vec::new();

    detect_admin_endpoints(&bundle.live_surfaces, &mut found);
    detect_idor_shaped_urls(&bundle.live_surfaces, &mut found);
    detect_debug_and_config_exposure(&bundle.live_surfaces, &mut found);
    detect_jwt_signals(&bundle.findings, &mut found);
    detect_env_leak(&bundle.findings, &mut found);
    detect_unusual_ports(&bundle.live_surfaces, &mut found);
    detect_api_version_exposure(&bundle.live_surfaces, &mut found);
    detect_secret_signals(&bundle.findings, &mut found);
    detect_outdated_tech(&bundle.tech_stack, &mut found);

    // Dedupe on (kind, surface). Keep the first hit's rationale.
    let mut seen = std::collections::HashSet::new();
    found.retain(|a| seen.insert((a.kind, a.surface.clone())));
    found
}

// ----- individual rules -----

const ADMIN_PATH_FRAGMENTS: &[&str] = &[
    "/admin",
    "/administrator",
    "/wp-admin",
    "/console",
    "/manage",
    "/control",
    "/cpanel",
    "/dashboard",
    "/api/admin",
    "/internal",
    "/staff",
];

fn detect_admin_endpoints(surfaces: &[HttpSurface], out: &mut Vec<Anomaly>) {
    for s in surfaces {
        let url_lower = s.url.to_ascii_lowercase();
        if let Some(frag) = ADMIN_PATH_FRAGMENTS.iter().find(|p| url_lower.contains(*p)) {
            out.push(Anomaly::new(
                AnomalyKind::AdminEndpoint,
                &s.url,
                format!(
                    "URL contains `{frag}` — admin/control surface candidate. \
                     Probe for auth-bypass via direct API call or default creds."
                ),
            ));
        }
    }
}

fn detect_idor_shaped_urls(surfaces: &[HttpSurface], out: &mut Vec<Anomaly>) {
    // Heuristic: URLs with a numeric path segment that looks like a
    // user/order/resource id. Pattern: `/<word>/<digits>` or
    // `/<word>/<uuid-like>`.
    for s in surfaces {
        let path = s.url.split('?').next().unwrap_or(&s.url);
        let segs: Vec<&str> = path.trim_end_matches('/').split('/').collect();
        for i in 1..segs.len() {
            let prev = segs[i - 1];
            let cur = segs[i];
            if prev.is_empty() || cur.is_empty() {
                continue;
            }
            // Numeric ID pattern.
            let all_digits = cur.chars().all(|c| c.is_ascii_digit());
            if all_digits && cur.len() <= 12 && prev.chars().any(|c| c.is_ascii_alphabetic()) {
                out.push(Anomaly::new(
                    AnomalyKind::PossibleIdor,
                    &s.url,
                    format!(
                        "Path segment `/{prev}/{cur}` matches IDOR pattern. \
                         Try sequential id substitution, auth-cross-test."
                    ),
                ));
                break;
            }
            // UUID-like pattern.
            if cur.len() >= 32 && cur.chars().filter(|c| *c == '-').count() >= 4 {
                out.push(Anomaly::new(
                    AnomalyKind::PossibleIdor,
                    &s.url,
                    format!(
                        "Path segment `/{prev}/{cur}` looks like a UUID. \
                         Resource ID — check auth boundary."
                    ),
                ));
                break;
            }
        }
    }
}

const CONFIG_FRAGMENTS: &[&str] = &[
    "/.env",
    "/.git/",
    "/.git/config",
    "/config.json",
    "/config.yaml",
    "/wp-config.php",
    "/web.config",
    "/.aws/",
    "/composer.json",
    "/package-lock.json",
    "/yarn.lock",
];

const DEBUG_FRAGMENTS: &[&str] = &[
    "/debug",
    "/_debug",
    "/_status",
    "/_health",
    "/healthz",
    "/metrics",
    "/actuator",
    "/phpinfo.php",
    "/server-info",
    "/server-status",
];

fn detect_debug_and_config_exposure(surfaces: &[HttpSurface], out: &mut Vec<Anomaly>) {
    for s in surfaces {
        let url_lower = s.url.to_ascii_lowercase();
        if let Some(frag) = CONFIG_FRAGMENTS.iter().find(|p| url_lower.contains(*p)) {
            out.push(Anomaly::new(
                AnomalyKind::ExposedConfig,
                &s.url,
                format!(
                    "Config-shaped path `{frag}` reachable. \
                     If 200/403 — probe for partial-read / auth bypass."
                ),
            ));
        }
        if let Some(frag) = DEBUG_FRAGMENTS.iter().find(|p| url_lower.contains(*p)) {
            out.push(Anomaly::new(
                AnomalyKind::DebugEndpoint,
                &s.url,
                format!(
                    "Debug-shaped path `{frag}` reachable. \
                     Often leaks build info, env vars, dependency tree."
                ),
            ));
        }
        // Git directory exposed.
        if url_lower.contains("/.git/") && s.status == Some(200) {
            out.push(Anomaly::new(
                AnomalyKind::PublicGitData,
                &s.url,
                "Live `.git/` directory — recover full repo via git-dumper or \
                 fetching objects/HEAD."
                    .to_string(),
            ));
        }
    }
}

fn detect_jwt_signals(findings: &[Finding], out: &mut Vec<Anomaly>) {
    for f in findings {
        let blob = format!(
            "{} {} {}",
            f.title,
            f.description,
            f.meta.values().cloned().collect::<Vec<_>>().join(" ")
        )
        .to_ascii_lowercase();
        if blob.contains("jwt") || blob.contains("bearer ") {
            out.push(Anomaly::new(
                AnomalyKind::JwtPresent,
                &f.target,
                "JWT signal detected — check algorithm (`none`/`HS256` vs `RS256`), \
                 kid traversal, and token replay across users."
                    .to_string(),
            ));
            break; // one JWT signal is enough; don't spam
        }
    }
}

fn detect_env_leak(findings: &[Finding], out: &mut Vec<Anomaly>) {
    for f in findings {
        if f.severity == Severity::Critical || f.severity == Severity::High {
            continue; // already prominent on its own
        }
        let blob = format!("{} {}", f.title, f.description).to_ascii_lowercase();
        if blob.contains("debug") || blob.contains("staging") || blob.contains("test-key") {
            out.push(Anomaly::new(
                AnomalyKind::EnvLeak,
                &f.target,
                format!(
                    "Build/env signal in `{}` — possible prod/test mixup.",
                    f.title
                ),
            ));
        }
    }
}

fn detect_unusual_ports(surfaces: &[HttpSurface], out: &mut Vec<Anomaly>) {
    for s in surfaces {
        if let Some(port_str) = extract_port(&s.url) {
            if let Ok(port) = port_str.parse::<u16>() {
                if !matches!(port, 80 | 443 | 8080 | 8443 | 3000 | 5000 | 8000 | 8888) {
                    out.push(Anomaly::new(
                        AnomalyKind::UnusualPort,
                        &s.url,
                        format!(
                            "HTTP on non-standard port {port} — often dev/staging \
                             admin tools (Grafana, Jenkins, etc.)."
                        ),
                    ));
                }
            }
        }
    }
}

fn extract_port(url: &str) -> Option<&str> {
    let after_scheme = url.split("://").nth(1)?;
    let host_part = after_scheme.split('/').next()?;
    let colon = host_part.find(':')?;
    Some(&host_part[colon + 1..])
}

fn detect_api_version_exposure(surfaces: &[HttpSurface], out: &mut Vec<Anomaly>) {
    for s in surfaces {
        let url = &s.url;
        // Match /v1, /v2, /api/v3, etc.
        if let Some(idx) = url.find("/v") {
            let after = &url[idx + 2..];
            let n: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !n.is_empty() && n.len() <= 2 {
                out.push(Anomaly::new(
                    AnomalyKind::ApiVersion,
                    url,
                    format!(
                        "API version `v{n}` exposed in URL. Probe older versions \
                         (`/v{}/`...) — auth/scope often drifts across versions.",
                        if n == "1" {
                            "0".to_string()
                        } else {
                            (n.parse::<u8>().unwrap_or(2) - 1).to_string()
                        }
                    ),
                ));
            }
        }
    }
}

fn detect_secret_signals(findings: &[Finding], out: &mut Vec<Anomaly>) {
    for f in findings {
        if f.kind == "secret" && f.severity == Severity::Critical {
            out.push(Anomaly::new(
                AnomalyKind::SecretSignal,
                &f.target,
                format!(
                    "Verified secret leaked at `{}` ({}). Live credential — \
                     rotate AND chain into auth-cross-test.",
                    f.target,
                    f.meta
                        .get("detector")
                        .cloned()
                        .unwrap_or_else(|| "?".into())
                ),
            ));
        }
    }
}

fn detect_outdated_tech(
    tech_stack: &std::collections::BTreeMap<String, Vec<String>>,
    out: &mut Vec<Anomaly>,
) {
    // Heuristic: any entry containing a "0.x" version or any version
    // we know is old. Conservative — only fire on clear signals.
    for (cat, vals) in tech_stack {
        for v in vals {
            let v_lower = v.to_ascii_lowercase();
            // PHP <= 7
            if v_lower.starts_with("php/5") || v_lower.starts_with("php/7") {
                out.push(Anomaly::new(
                    AnomalyKind::OutdatedTech,
                    cat,
                    format!("Old PHP version `{v}` — EOL, many known CVEs."),
                ));
            }
            // Apache 2.2, 2.0
            if v_lower.starts_with("apache/2.2") || v_lower.starts_with("apache/2.0") {
                out.push(Anomaly::new(
                    AnomalyKind::OutdatedTech,
                    cat,
                    format!("Old Apache version `{v}` — EOL, range of HTTP CVEs."),
                ));
            }
            // OpenSSL 1.0.x
            if v_lower.starts_with("openssl/1.0") {
                out.push(Anomaly::new(
                    AnomalyKind::OutdatedTech,
                    cat,
                    format!("Old OpenSSL `{v}` — Heartbleed-era CVEs in scope."),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::HttpSurface;

    fn surf(url: &str) -> HttpSurface {
        HttpSurface {
            url: url.into(),
            status: Some(200),
            title: None,
            webserver: None,
            tech: vec![],
        }
    }

    #[test]
    fn admin_endpoint_rule_fires_on_obvious_paths() {
        let mut b = ReconBundle::new("x");
        b.live_surfaces
            .push(surf("https://example.com/admin/login"));
        b.live_surfaces
            .push(surf("https://api.example.com/v1/wp-admin"));
        b.live_surfaces
            .push(surf("https://example.com/static/img.png"));
        let anomalies = detect(&b);
        let admins: Vec<_> = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::AdminEndpoint)
            .collect();
        assert_eq!(admins.len(), 2);
    }

    #[test]
    fn idor_rule_fires_on_numeric_id_path() {
        let mut b = ReconBundle::new("x");
        b.live_surfaces
            .push(surf("https://api.example.com/users/42/profile"));
        b.live_surfaces
            .push(surf("https://api.example.com/orders/12345"));
        let anomalies = detect(&b);
        assert!(anomalies
            .iter()
            .any(|a| a.kind == AnomalyKind::PossibleIdor));
        // Two surfaces, two IDOR signals (dedupe is by (kind,surface) pair).
        let idors: Vec<_> = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::PossibleIdor)
            .collect();
        assert_eq!(idors.len(), 2);
    }

    #[test]
    fn idor_rule_does_not_fire_on_static_paths() {
        let mut b = ReconBundle::new("x");
        b.live_surfaces
            .push(surf("https://example.com/static/main.css"));
        b.live_surfaces
            .push(surf("https://example.com/assets/img.png"));
        let anomalies = detect(&b);
        assert!(!anomalies
            .iter()
            .any(|a| a.kind == AnomalyKind::PossibleIdor));
    }

    #[test]
    fn config_exposure_rule_fires_on_dotenv() {
        let mut b = ReconBundle::new("x");
        b.live_surfaces.push(surf("https://example.com/.env"));
        b.live_surfaces
            .push(surf("https://example.com/.git/config"));
        let anomalies = detect(&b);
        let configs: Vec<_> = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::ExposedConfig)
            .collect();
        assert_eq!(configs.len(), 2);
    }

    #[test]
    fn debug_endpoint_rule_fires() {
        let mut b = ReconBundle::new("x");
        b.live_surfaces.push(surf("https://example.com/_status"));
        b.live_surfaces
            .push(surf("https://example.com/actuator/health"));
        let anomalies = detect(&b);
        let debugs: Vec<_> = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::DebugEndpoint)
            .collect();
        assert_eq!(debugs.len(), 2);
    }

    #[test]
    fn unusual_port_rule_fires_on_dev_ports() {
        let mut b = ReconBundle::new("x");
        b.live_surfaces.push(surf("http://example.com:9090/")); // Prometheus default
        b.live_surfaces.push(surf("http://example.com:443/")); // standard, no flag
        let anomalies = detect(&b);
        let ports: Vec<_> = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::UnusualPort)
            .collect();
        assert_eq!(ports.len(), 1);
        assert!(ports[0].surface.contains(":9090"));
    }

    #[test]
    fn api_version_rule_fires_and_suggests_lower_version() {
        let mut b = ReconBundle::new("x");
        b.live_surfaces
            .push(surf("https://api.example.com/v2/users"));
        let anomalies = detect(&b);
        let ver: Vec<_> = anomalies
            .iter()
            .filter(|a| a.kind == AnomalyKind::ApiVersion)
            .collect();
        assert_eq!(ver.len(), 1);
        assert!(ver[0].rationale.contains("v1"));
    }

    #[test]
    fn git_exposure_rule_fires_when_status_200() {
        let mut b = ReconBundle::new("x");
        b.live_surfaces
            .push(surf("https://example.com/.git/config"));
        let anomalies = detect(&b);
        assert!(anomalies
            .iter()
            .any(|a| a.kind == AnomalyKind::PublicGitData));
    }

    #[test]
    fn dedupe_collapses_same_kind_same_surface() {
        // ExposedConfig + PublicGitData both fire on /.git/config but
        // they're different kinds, so both should appear.
        let mut b = ReconBundle::new("x");
        b.live_surfaces
            .push(surf("https://example.com/.git/config"));
        let anomalies = detect(&b);
        assert!(anomalies
            .iter()
            .any(|a| a.kind == AnomalyKind::ExposedConfig));
        assert!(anomalies
            .iter()
            .any(|a| a.kind == AnomalyKind::PublicGitData));
    }
}
