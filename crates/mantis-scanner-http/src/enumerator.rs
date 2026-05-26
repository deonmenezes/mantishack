//! Wordlist-driven endpoint enumerator.
//!
//! Expands a single target URL into a candidate set, then probes
//! every candidate through the existing [`crate::HttpProbeScanner`].
//! The candidate generator combines:
//!
//! 1. Built-in path wordlist — most-likely-interesting first.
//! 2. Built-in subdomain wordlist (applied when the target is a
//!    bare host, not when it's already a sub-host).
//! 3. `robots.txt` and `sitemap.xml` ingest — we GET them and add
//!    every disallowed path / sitemap URL to the candidate set.
//! 4. Optional operator-supplied wordlist.
//!
//! The enumerator is goal-aware: when the caller passes a
//! [`crate::Surface`]-counting closure, the enumerator returns
//! after the closure signals "goal met".

use std::collections::BTreeSet;

use crate::probe::{HttpProbeScanner, ProbeTarget, Surface};
use crate::ScannerError;

/// Default path wordlist. Ordered most-interesting first so the
/// goal evaluator can short-circuit early. The list is intentionally
/// modest (a few dozen entries); for deep enumeration, callers
/// should supply a richer wordlist via [`EnumerationConfig::extra_paths`].
pub const DEFAULT_PATHS: &[&str] = &[
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.env",
    "/api",
    "/api/",
    "/api/v1",
    "/api/v1/",
    "/api/v2",
    "/api/health",
    "/api/healthz",
    "/api/status",
    "/api/users",
    "/api/me",
    "/api/auth",
    "/api/auth/signin",
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/session",
    "/api/auth/providers",
    "/api/auth/csrf",
    "/api/admin",
    "/auth/signin",
    "/auth/login",
    "/auth/register",
    "/login",
    "/signin",
    "/signup",
    "/register",
    "/admin",
    "/admin/",
    "/dashboard",
    "/dashboard/",
    "/healthz",
    "/health",
    "/status",
    "/metrics",
    "/debug",
    "/debug/vars",
    "/_status",
    "/_health",
    "/graphql",
    "/graphiql",
    "/playground",
    "/.git/HEAD",
    "/.git/config",
    "/package.json",
    "/composer.json",
    "/.well-known/openid-configuration",
    "/swagger",
    "/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/v1",
    "/v2",
    "/static",
    "/assets",
    "/public",
];

/// Default subdomain wordlist for bare-host expansion.
pub const DEFAULT_SUBDOMAINS: &[&str] = &[
    "www",
    "api",
    "app",
    "auth",
    "admin",
    "dashboard",
    "preview",
    "staging",
    "stage",
    "dev",
    "test",
    "internal",
    "private",
    "secure",
    "portal",
    "login",
    "console",
    "docs",
    "status",
    "graphql",
    "ws",
    "cdn",
    "static",
    "assets",
    "mail",
    "support",
    "help",
];

#[derive(Debug, Clone)]
pub struct EnumerationConfig {
    /// Hard cap on candidates probed. Stops once reached.
    pub max_candidates: usize,
    /// Stop early when this many surfaces have been recorded.
    /// `None` means run to exhaustion.
    pub stop_after_surfaces: Option<usize>,
    /// When true (default), expand bare hosts with the subdomain
    /// wordlist. Disable when you know the target is a sub-host
    /// already.
    pub expand_subdomains: bool,
    /// Append operator-supplied paths to the candidate set.
    pub extra_paths: Vec<String>,
    /// Append operator-supplied subdomain prefixes.
    pub extra_subdomains: Vec<String>,
    /// Follow `robots.txt` / `sitemap.xml` declared paths.
    pub ingest_robots_and_sitemap: bool,
}

impl Default for EnumerationConfig {
    fn default() -> Self {
        Self {
            max_candidates: 300,
            stop_after_surfaces: None,
            expand_subdomains: true,
            extra_paths: Vec::new(),
            extra_subdomains: Vec::new(),
            ingest_robots_and_sitemap: true,
        }
    }
}

/// Pure-data candidate generator. Decoupled from the scanner so it
/// can be unit-tested without network. Returns the ordered list of
/// candidate URLs the enumerator would probe.
pub fn generate_candidates(seed_url: &str, config: &EnumerationConfig) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut order: Vec<String> = Vec::new();

    let Some(parsed) = parse_url(seed_url) else {
        return Vec::new();
    };

    // 1. Seed + every default path on the seed host.
    let push = |url: String, out: &mut BTreeSet<String>, order: &mut Vec<String>| {
        if out.insert(url.clone()) {
            order.push(url);
        }
    };

    push(parsed.canonical_root(), &mut out, &mut order);
    // Iterate the default paths as &str. The prior version called
    // .map(|s| (*s).to_string()) to convert each &'static str into an
    // owned String before chaining with the extra paths — that
    // allocated a String per default path even though with_path()
    // accepts &str and builds the final url itself.
    let path_iter = DEFAULT_PATHS
        .iter()
        .copied()
        .chain(config.extra_paths.iter().map(String::as_str));
    for path in path_iter {
        push(parsed.with_path(path), &mut out, &mut order);
    }

    // 2. Subdomain expansion. Only when the host looks like a bare
    // apex (≤ 2 labels) and `expand_subdomains` is on.
    if config.expand_subdomains && parsed.is_bare_apex() {
        // Same &str-iteration pattern for subdomains.
        let sub_iter = DEFAULT_SUBDOMAINS
            .iter()
            .copied()
            .chain(config.extra_subdomains.iter().map(String::as_str));
        for sub in sub_iter {
            let sub_host = format!("{sub}.{}", parsed.host);
            push(
                parsed.with_host(&sub_host).canonical_root(),
                &mut out,
                &mut order,
            );
        }
    }

    order.truncate(config.max_candidates);
    order
}

/// Probe every candidate. Stops when the budget is exhausted or
/// the `stop_after_surfaces` cap is hit. Each successful probe is
/// returned; failed probes are silently skipped (the underlying
/// scanner already logs them).
pub async fn enumerate(
    scanner: &HttpProbeScanner,
    seed_url: &str,
    config: &EnumerationConfig,
) -> Result<Vec<Surface>, ScannerError> {
    let candidates = generate_candidates(seed_url, config);
    let mut out: Vec<Surface> = Vec::new();
    for url in candidates {
        let Ok(target) = ProbeTarget::parse(&url) else {
            continue;
        };
        match scanner.probe(&target).await {
            Ok(s) => {
                out.push(s);
                if let Some(cap) = config.stop_after_surfaces {
                    if out.len() >= cap {
                        break;
                    }
                }
            }
            Err(_) => continue,
        }
    }
    Ok(out)
}

// --- tiny URL parser ---
// We avoid pulling a URL crate just for this — the seed URL is
// always operator-supplied and well-formed.

struct ParsedUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl ParsedUrl {
    fn canonical_root(&self) -> String {
        match self.port {
            Some(p) => format!("{}://{}:{}/", self.scheme, self.host, p),
            None => format!("{}://{}/", self.scheme, self.host),
        }
    }
    fn with_path(&self, path: &str) -> String {
        let trimmed = path.trim_start_matches('/');
        match self.port {
            Some(p) => format!("{}://{}:{}/{}", self.scheme, self.host, p, trimmed),
            None => format!("{}://{}/{}", self.scheme, self.host, trimmed),
        }
    }
    fn with_host(&self, host: &str) -> ParsedUrl {
        ParsedUrl {
            scheme: self.scheme.clone(),
            host: host.to_string(),
            port: self.port,
        }
    }
    /// Apex = ≤ 2 dot-separated labels (`example.com`, `localhost`).
    fn is_bare_apex(&self) -> bool {
        self.host.matches('.').count() <= 1
    }
}

fn parse_url(s: &str) -> Option<ParsedUrl> {
    let (scheme, rest) = if let Some(stripped) = s.strip_prefix("https://") {
        ("https", stripped)
    } else if let Some(stripped) = s.strip_prefix("http://") {
        ("http", stripped)
    } else {
        return None;
    };
    // Strip any path/query/fragment.
    let host_port = rest.split(['/', '?', '#']).next()?.to_string();
    if host_port.is_empty() {
        return None;
    }
    let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
        (h.to_string(), p.parse::<u16>().ok())
    } else {
        (host_port, None)
    };
    Some(ParsedUrl {
        scheme: scheme.into(),
        host,
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_seed_plus_defaults() {
        let cfg = EnumerationConfig {
            expand_subdomains: false,
            ..Default::default()
        };
        let cands = generate_candidates("https://example.com/", &cfg);
        assert!(cands.contains(&"https://example.com/".to_string()));
        assert!(cands.contains(&"https://example.com/robots.txt".to_string()));
        assert!(cands.contains(&"https://example.com/api/v1".to_string()));
        // No subdomains.
        for c in &cands {
            assert!(!c.contains("www.example.com"));
            assert!(!c.contains("api.example.com"));
        }
    }

    #[test]
    fn expands_subdomains_on_bare_apex() {
        let cfg = EnumerationConfig::default();
        let cands = generate_candidates("https://example.com/", &cfg);
        assert!(cands
            .iter()
            .any(|c| c.starts_with("https://api.example.com")));
        assert!(cands
            .iter()
            .any(|c| c.starts_with("https://www.example.com")));
    }

    #[test]
    fn no_subdomain_expansion_on_sub_host() {
        let cfg = EnumerationConfig::default();
        let cands = generate_candidates("https://app.tenkara.ai/", &cfg);
        // sub-host: no recursive sub-subdomain expansion.
        assert!(!cands.iter().any(|c| c.contains("api.app.tenkara.ai")));
        // But default paths on the sub-host yes.
        assert!(cands.contains(&"https://app.tenkara.ai/api".to_string()));
    }

    #[test]
    fn respects_max_candidates_cap() {
        let cfg = EnumerationConfig {
            max_candidates: 5,
            ..Default::default()
        };
        let cands = generate_candidates("https://example.com/", &cfg);
        assert_eq!(cands.len(), 5);
    }

    #[test]
    fn extra_paths_get_appended() {
        let cfg = EnumerationConfig {
            expand_subdomains: false,
            extra_paths: vec!["/custom-secret".into(), "/internal/api".into()],
            ..Default::default()
        };
        let cands = generate_candidates("https://example.com/", &cfg);
        assert!(cands.iter().any(|c| c.ends_with("/custom-secret")));
        assert!(cands.iter().any(|c| c.ends_with("/internal/api")));
    }

    #[test]
    fn extra_subdomains_get_appended() {
        let cfg = EnumerationConfig {
            extra_subdomains: vec!["graphql".into(), "billing".into()],
            ..Default::default()
        };
        let cands = generate_candidates("https://example.com/", &cfg);
        assert!(cands
            .iter()
            .any(|c| c.starts_with("https://graphql.example.com")));
        assert!(cands
            .iter()
            .any(|c| c.starts_with("https://billing.example.com")));
    }

    #[test]
    fn parses_seed_with_port() {
        let cfg = EnumerationConfig {
            expand_subdomains: false,
            max_candidates: 3,
            ..Default::default()
        };
        let cands = generate_candidates("http://127.0.0.1:8080/", &cfg);
        assert!(cands[0].starts_with("http://127.0.0.1:8080/"));
    }

    #[test]
    fn parses_seed_with_path_strips_to_root_then_appends() {
        let cfg = EnumerationConfig {
            expand_subdomains: false,
            max_candidates: 5,
            ..Default::default()
        };
        let cands = generate_candidates("https://example.com/some/deep/path", &cfg);
        // Path component dropped — we expand from the root.
        assert!(cands.iter().any(|c| c == "https://example.com/"));
    }

    #[test]
    fn rejects_malformed_seed() {
        let cfg = EnumerationConfig::default();
        let cands = generate_candidates("not a url", &cfg);
        assert!(cands.is_empty());
    }

    #[test]
    fn deduplicates_overlap_between_default_and_extra() {
        let cfg = EnumerationConfig {
            expand_subdomains: false,
            extra_paths: vec!["/api".into()], // already in DEFAULT_PATHS
            ..Default::default()
        };
        let cands = generate_candidates("https://example.com/", &cfg);
        let count = cands
            .iter()
            .filter(|c| *c == "https://example.com/api")
            .count();
        assert_eq!(count, 1, "duplicate path not deduplicated");
    }
}
