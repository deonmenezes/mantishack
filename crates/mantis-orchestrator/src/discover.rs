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
//! Auto-discovery of auth-stack configuration from a target's HTML.
//!
//! Saves the operator from having to pass `--supabase-signup` and
//! `--supabase-apikey` by hand. Mirrors hacker-bob's
//! `bounty_signup_detect` heuristics, specialized for the
//! Supabase-on-the-front-end shape.
//!
//! Strategy:
//! 1. GET the target URL and follow up to N redirects.
//! 2. Regex-scan the response body for `*.supabase.co` hostnames
//!    and Supabase anon JWTs (`eyJhbGciOi...`-prefixed).
//! 3. For each candidate hostname, optionally fetch a few common
//!    JS bundle paths (`/_next/static/.../*.js`) and re-scan.
//! 4. Return the highest-confidence pair.
//!
//! Conservative: never auto-uses a discovered key for *writes*, only
//! for the signup probe. Operators can always override via the CLI.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredAuthConfig {
    /// Full Supabase project URL (e.g. `https://abc.supabase.co`).
    pub supabase_url: Option<String>,
    /// Public anon JWT seen in the bundle.
    pub supabase_anon_key: Option<String>,
    /// Derived signup URL (`{supabase_url}/auth/v1/signup`).
    pub supabase_signup_url: Option<String>,
    /// Free-form notes about how the values were found (for the
    /// archive's discovery phase file).
    pub notes: Vec<String>,
}

impl DiscoveredAuthConfig {
    pub fn is_supabase_ready(&self) -> bool {
        self.supabase_url.is_some() && self.supabase_anon_key.is_some()
    }
}

/// Common Vercel WAF challenge signature — chunky Astro-rendered
/// HTML containing the literal text below. Used to detect responses
/// that should NOT be scanned for config (they're intercepted).
const VERCEL_CHALLENGE_MARKER: &str = "Vercel Security Checkpoint";

/// Bypass paths that Vercel's WAF challenge does NOT block — these
/// are CDN-cached static assets served before the challenge fires.
/// Tried IN ADDITION to scraping the index HTML.
const STATIC_BYPASS_PATHS: &[&str] = &[
    "/sw.js",
    "/service-worker.js",
    "/manifest.json",
    "/site.webmanifest",
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/opensearch.xml",
    "/.well-known/openid-configuration",
    "/_next/static/chunks/webpack.js",
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/main-app.js",
    "/_next/static/chunks/framework.js",
    "/_next/static/chunks/polyfills.js",
    "/_next/static/chunks/pages/_app.js",
    "/_next/static/chunks/pages/index.js",
    "/_next/static/chunks/pages/_error.js",
    "/_next/build-manifest.json",
    "/_next/routes-manifest.json",
    "/_next/prerender-manifest.json",
    "/__NEXT_DATA__.json",
    "/api/config",
    "/api/env",
    "/api/runtime-config",
];

/// Common Tenkara-style subdomain probes. When the seed is blocked
/// by WAF, sibling subdomains often aren't (e.g. www.* on a Framer
/// marketing site that the same project uses; api.* for headless
/// APIs; cdn.* / static.* for asset hosts).
const SUBDOMAIN_PROBES: &[&str] = &[
    "www", "api", "cdn", "static", "assets", "app", "auth", "supabase",
];

/// Pull the target URL and any obvious JS bundle URLs to scan for
/// Supabase configuration. Aggressive — tries many bypass paths to
/// defeat Vercel-style WAF challenges. Mantis runs this once at the
/// start of every `mantis hack` invocation.
pub async fn discover(target_url: &str) -> DiscoveredAuthConfig {
    discover_with_cookie(target_url, None).await
}

/// Same as [`discover`] but passes a `Cookie:` header through every
/// probe. Use after the operator solves the target's WAF challenge
/// once in their browser and pastes the cookie from DevTools.
/// Successful discoveries (both supabase_url AND supabase_anon_key
/// found) are cached on-disk under
/// `~/.mantis/discovery-cache/<host>.json` so subsequent
/// `mantis hack` invocations don't hammer the WAF.
pub async fn discover_with_cookie(target_url: &str, cookie: Option<&str>) -> DiscoveredAuthConfig {
    // 0. Cache hit?
    if let Some(cached) = read_cache(target_url) {
        if cached.is_supabase_ready() {
            let mut hit = cached;
            hit.notes.insert(0, "loaded from cache".to_string());
            return hit;
        }
    }
    let result = discover_uncached(target_url, cookie).await;
    if result.is_supabase_ready() {
        if let Err(e) = write_cache(target_url, &result) {
            // Cache failures are non-fatal — caller still gets the
            // fresh result.
            tracing::debug!("[discover] cache write failed: {e}");
        }
    }
    result
}

async fn discover_uncached(target_url: &str, cookie: Option<&str>) -> DiscoveredAuthConfig {
    let mut out = DiscoveredAuthConfig::default();
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(
            // Pretend to be a normal Chrome — some WAFs treat
            // `mantis-hack/0.0.1` as a bot signal and 403 earlier.
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        );
    if let Some(c) = cookie {
        let mut headers = reqwest::header::HeaderMap::new();
        match reqwest::header::HeaderValue::from_str(c) {
            Ok(v) => {
                headers.insert(reqwest::header::COOKIE, v);
                builder = builder.default_headers(headers);
            }
            Err(e) => out
                .notes
                .push(format!("invalid cookie header (ignored): {e}")),
        }
    }
    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            out.notes.push(format!("client build failed: {e}"));
            return out;
        }
    };

    let mut bodies_scanned: Vec<(String, String)> = Vec::new(); // (url, body)

    // 1. Fetch the target HTML.
    if let Some((url, body)) = fetch_and_filter(&client, target_url).await {
        if !out.notes.iter().any(|n| n.contains("challenge")) {
            out.notes.push(format!("GET {} -> ok", target_url));
        }
        bodies_scanned.push((url, body));
    } else {
        out.notes
            .push(format!("GET {} -> blocked or empty", target_url));
    }

    // 2. From the index HTML, pull obvious JS bundle URLs and fetch
    //    them. Cap at 30 — the Supabase init can be in any chunk,
    //    and modern Next.js apps have 10-25 chunks. Keep it bounded
    //    to avoid pathological cases.
    let bundle_urls: Vec<String> = bodies_scanned
        .iter()
        .flat_map(|(_, html)| extract_bundle_urls(html, target_url))
        .collect();
    for u in bundle_urls.iter().take(30) {
        if let Some((url, body)) = fetch_and_filter(&client, u).await {
            out.notes.push(format!("scanned bundle {url}"));
            bodies_scanned.push((url, body));
            // Short-circuit greedily — many apps have the Supabase
            // init in the very first chunk.
            if scan_bodies_for_config(&bodies_scanned, &mut out) {
                break;
            }
        }
    }

    // 3. Try a wide set of bypass paths on the seed host. These are
    //    Vercel-CDN-cached static assets that the WAF challenge
    //    doesn't intercept.
    let base_origin = base_origin(target_url);
    for path in STATIC_BYPASS_PATHS {
        let url = format!("{base_origin}{path}");
        if bodies_scanned.iter().any(|(u, _)| u == &url) {
            continue;
        }
        if let Some((url, body)) = fetch_and_filter(&client, &url).await {
            out.notes.push(format!("bypass path {url} -> ok"));
            bodies_scanned.push((url, body));
            // Scan greedily — if we hit the key already, stop after
            // each fetch to save round-trips.
            if scan_bodies_for_config(&bodies_scanned, &mut out) {
                break;
            }
        }
    }

    // 4. If we still don't have the key, walk sibling subdomains.
    //    Tenkara-shape targets often have the config leaked on a
    //    sibling marketing site (www, cdn, static).
    if out.supabase_anon_key.is_none() {
        let parent = parent_domain(target_url);
        if let Some(parent) = parent {
            for sub in SUBDOMAIN_PROBES {
                let candidate = format!("https://{sub}.{parent}/");
                if bodies_scanned
                    .iter()
                    .any(|(u, _)| u.starts_with(&candidate))
                {
                    continue;
                }
                if let Some((url, body)) = fetch_and_filter(&client, &candidate).await {
                    out.notes.push(format!("sibling {url} -> ok"));
                    bodies_scanned.push((url, body));
                    if scan_bodies_for_config(&bodies_scanned, &mut out) {
                        break;
                    }
                }
            }
        }
    }

    // 5. Final scan over every body collected.
    scan_bodies_for_config(&bodies_scanned, &mut out);

    if let Some(url) = &out.supabase_url {
        out.supabase_signup_url = Some(format!("{url}/auth/v1/signup"));
    }

    out
}

/// Fetch a URL and return `Some((final_url, body))` only when the
/// response is non-empty AND doesn't look like a Vercel WAF
/// challenge page. The WAF returns ~33KB of Astro-rendered HTML
/// with a distinctive marker; we skip those bodies because they
/// can't contain config.
async fn fetch_and_filter(client: &reqwest::Client, url: &str) -> Option<(String, String)> {
    let resp = client.get(url).send().await.ok()?;
    let final_url = resp.url().to_string();
    // Skip 5xx and connection-refused-ish statuses.
    if !resp.status().is_success() && resp.status().as_u16() != 304 {
        // Some Vercel bundles return 200 even when challenged; some
        // return 401 with auth-required bodies. Continue with the
        // body — challenge-marker detection catches the rest.
        if resp.status().as_u16() >= 500 {
            return None;
        }
    }
    let body = resp.text().await.ok()?;
    if body.is_empty() {
        return None;
    }
    if body.contains(VERCEL_CHALLENGE_MARKER) {
        return None;
    }
    Some((final_url, body))
}

/// Scan accumulated `(url, body)` pairs. Updates `out` and returns
/// true iff BOTH supabase_url AND supabase_anon_key are now set
/// (caller can short-circuit further probes).
fn scan_bodies_for_config(bodies: &[(String, String)], out: &mut DiscoveredAuthConfig) -> bool {
    for (_url, body) in bodies {
        if out.supabase_url.is_none() {
            if let Some(host) = find_supabase_host(body) {
                let url = format!("https://{host}");
                out.notes.push(format!("supabase url: {url}"));
                out.supabase_url = Some(url);
            }
        }
        if out.supabase_anon_key.is_none() {
            if let Some(key) = find_supabase_anon_jwt(body) {
                out.notes
                    .push(format!("supabase anon key: {}…", &key[..key.len().min(16)]));
                out.supabase_anon_key = Some(key);
            }
        }
        if out.supabase_url.is_some() && out.supabase_anon_key.is_some() {
            return true;
        }
    }
    false
}

/// Cache TTL — 24 hours. The Supabase anon key is the public anon
/// JWT; it rotates only when the project owner regenerates it, which
/// is rare. 24h keeps the cache useful without staleness risk.
const CACHE_TTL_SECS: u64 = 60 * 60 * 24;

fn cache_dir() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let dir = std::path::PathBuf::from(home)
        .join(".mantis")
        .join("discovery-cache");
    Some(dir)
}

fn cache_path(target_url: &str) -> Option<std::path::PathBuf> {
    let host = target_url
        .strip_prefix("https://")
        .or_else(|| target_url.strip_prefix("http://"))?
        .split(['/', '?', '#'])
        .next()?
        .split(':')
        .next()?
        .to_ascii_lowercase();
    let host = host.trim_start_matches("www.").to_string();
    let safe: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    Some(cache_dir()?.join(format!("{safe}.json")))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CachedDiscovery {
    wall_clock_unix: u64,
    config: DiscoveredAuthConfig,
}

fn read_cache(target_url: &str) -> Option<DiscoveredAuthConfig> {
    let path = cache_path(target_url)?;
    let bytes = std::fs::read(&path).ok()?;
    let parsed: CachedDiscovery = serde_json::from_slice(&bytes).ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.saturating_sub(parsed.wall_clock_unix) > CACHE_TTL_SECS {
        return None;
    }
    Some(parsed.config)
}

fn write_cache(target_url: &str, config: &DiscoveredAuthConfig) -> std::io::Result<()> {
    let path = cache_path(target_url).ok_or_else(|| std::io::Error::other("bad target url"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let payload = CachedDiscovery {
        wall_clock_unix: now,
        config: config.clone(),
    };
    std::fs::write(path, serde_json::to_vec_pretty(&payload)?)
}

/// Return the parent registered domain for a target URL. For
/// `https://app.example.com/...` returns `example.com`. Very
/// simple: drops the leftmost label when there are ≥3 labels.
fn parent_domain(target_url: &str) -> Option<String> {
    let s = target_url
        .strip_prefix("https://")
        .or_else(|| target_url.strip_prefix("http://"))?;
    let host = s.split(['/', '?', '#']).next()?;
    let host = host.split(':').next()?;
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 3 {
        return None;
    }
    Some(labels[1..].join("."))
}

/// Pull `<host>.supabase.co` from a body. Returns the first hit.
pub fn find_supabase_host(body: &str) -> Option<String> {
    // Look for `https://<id>.supabase.co` or just `<id>.supabase.co`.
    // We scan character by character; the project id is `[a-z0-9]+`.
    let bytes = body.as_bytes();
    let needle = b".supabase.co";
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if bytes[i..].starts_with(needle) {
            // Walk backwards to find the start of the host.
            let mut start = i;
            while start > 0 {
                let c = bytes[start - 1];
                if c.is_ascii_alphanumeric() || c == b'-' {
                    start -= 1;
                } else {
                    break;
                }
            }
            if start < i {
                let host = &body[start..i + needle.len()];
                // Reject if it's literally `.supabase.co` (no project id).
                if host.len() > needle.len() && host.split('.').next().unwrap_or("").len() >= 6 {
                    return Some(host.to_string());
                }
            }
            i += needle.len();
        } else {
            i += 1;
        }
    }
    None
}

/// Find a Supabase anon JWT in the body. Anon JWTs are unsigned-from-
/// the-browser-perspective tokens starting with `eyJhbGciOi` (the
/// base64url-encoded `{"alg":"...` header). We pull the longest
/// such substring that has two dots (3-segment JWT) and ≥80
/// characters.
///
/// Modern minifiers sometimes inline these as `\"eyJ...\"` (escaped
/// JSON inside a string), so we accept the prefix anywhere and
/// stop only on bytes that aren't valid base64url or `.`.
pub fn find_supabase_anon_jwt(body: &str) -> Option<String> {
    let prefixes = ["eyJhbGciOi", "eyJhbGciOI"]; // case variants seen in the wild
    for prefix in prefixes {
        let mut start = 0;
        while let Some(pos) = body[start..].find(prefix) {
            let abs = start + pos;
            let bytes = body.as_bytes();
            let mut end = abs;
            while end < bytes.len() {
                let c = bytes[end];
                let ok = c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.';
                if ok {
                    end += 1;
                } else {
                    break;
                }
            }
            let candidate = &body[abs..end];
            // JWT must have at least two dots and a substantive
            // payload — Supabase anon JWTs are 200+ chars.
            if candidate.matches('.').count() >= 2 && candidate.len() >= 80 {
                return Some(candidate.to_string());
            }
            start = end.max(abs + 1);
        }
    }
    None
}

/// Naïve `<script src=...>` extractor + a handful of `/_next/...`
/// chunk patterns. We don't need a real HTML parser — these patterns
/// are stable enough across Next.js / Vite / Framer that a small set
/// of regex-lite scans covers it.
fn extract_bundle_urls(html: &str, base: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let base_origin = base_origin(base);
    let scan_for = |needle: &str, html: &str, out: &mut Vec<String>| {
        let mut start = 0;
        while let Some(pos) = html[start..].find(needle) {
            let abs = start + pos + needle.len();
            // Skip until the next `"` or `'` then take that substring.
            if let Some(quote) = html[abs..].find(['"', '\''].as_ref()) {
                let url_start = abs;
                let url_end = abs + quote;
                let raw = &html[url_start..url_end];
                // Only accept URLs that end in `.js` or have `_next/` in them.
                if raw.ends_with(".js") || raw.contains("_next/") {
                    let abs_url = absolutize(raw, &base_origin);
                    if !out.contains(&abs_url) {
                        out.push(abs_url);
                    }
                }
            }
            start = abs;
        }
    };
    scan_for("src=\"", html, &mut out);
    scan_for("src='", html, &mut out);
    out
}

fn base_origin(url: &str) -> String {
    let s = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let scheme = if url.starts_with("http://") {
        "http"
    } else {
        "https"
    };
    let host = s.split(['/', '?', '#']).next().unwrap_or(s);
    format!("{scheme}://{host}")
}

fn absolutize(raw: &str, origin: &str) -> String {
    if raw.starts_with("http://") || raw.starts_with("https://") {
        raw.to_string()
    } else if let Some(stripped) = raw.strip_prefix("//") {
        format!("https://{stripped}")
    } else if raw.starts_with('/') {
        format!("{origin}{raw}")
    } else {
        format!("{origin}/{raw}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_supabase_host_in_body() {
        let body = r#"<script>const SUPABASE_URL = "https://abcdefghij.supabase.co";</script>"#;
        let host = find_supabase_host(body);
        assert_eq!(host.as_deref(), Some("abcdefghij.supabase.co"));
    }

    #[test]
    fn rejects_too_short_project_id() {
        let body = r#"https://x.supabase.co"#;
        // Project IDs are typically 20+ chars; we require ≥6 just to
        // weed out the trivial case.
        assert!(find_supabase_host(body).is_none());
    }

    #[test]
    fn finds_first_anon_jwt() {
        // Realistic-shape Supabase anon JWT: header
        // ({"alg":"HS256","typ":"JWT"}) + payload (project ref, role,
        // iat, exp) + signature. ≥80 chars.
        let body = r#"
            window.SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWYiOiJhYmNkZWZnaGlqIiwicm9sZSI6ImFub24iLCJpYXQiOjE1MTYyMzkwMjJ9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        "#;
        let jwt = find_supabase_anon_jwt(body);
        assert!(jwt.is_some(), "expected a JWT");
        let jwt = jwt.unwrap();
        assert!(jwt.starts_with("eyJhbGciOi"));
        assert_eq!(jwt.matches('.').count(), 2);
        assert!(jwt.len() >= 80);
    }

    #[test]
    fn rejects_short_jwt_lookalike() {
        let body = "eyJhbGciOiAAA";
        assert!(find_supabase_anon_jwt(body).is_none());
    }

    #[test]
    fn rejects_jwt_without_dots() {
        let body = format!("eyJhbGciOi{}", "A".repeat(100));
        assert!(find_supabase_anon_jwt(&body).is_none());
    }

    #[test]
    fn bundle_extractor_finds_script_src() {
        let html = r#"
            <html><body>
            <script src="/_next/static/chunks/main-abc.js"></script>
            <script src="https://cdn.example.com/lib.js"></script>
            </body></html>
        "#;
        let urls = extract_bundle_urls(html, "https://example.com/");
        assert!(urls.iter().any(|u| u.contains("/_next/static")));
        assert!(urls.iter().any(|u| u.contains("cdn.example.com")));
    }

    #[test]
    fn absolutize_handles_relative_paths() {
        assert_eq!(
            absolutize("/x/y.js", "https://example.com"),
            "https://example.com/x/y.js"
        );
        assert_eq!(
            absolutize("https://cdn.example.com/y.js", "https://example.com"),
            "https://cdn.example.com/y.js"
        );
        assert_eq!(
            absolutize("//cdn.example.com/y.js", "https://example.com"),
            "https://cdn.example.com/y.js"
        );
    }

    #[test]
    fn parent_domain_drops_first_label() {
        assert_eq!(
            parent_domain("https://app.tenkara.ai/"),
            Some("tenkara.ai".into())
        );
        assert_eq!(
            parent_domain("https://api.example.com/v1/users"),
            Some("example.com".into())
        );
    }

    #[test]
    fn parent_domain_returns_none_for_apex_or_short() {
        assert!(parent_domain("https://example.com/").is_none());
        assert!(parent_domain("https://localhost/").is_none());
    }

    #[test]
    fn scan_bodies_picks_up_url_and_key_from_separate_bodies() {
        let bodies = vec![
            (
                "https://a/main.js".into(),
                "config = { url: 'https://abcdefghij.supabase.co' }".to_string(),
            ),
            (
                "https://a/chunk.js".into(),
                "const key = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWYiOiJhYmNkZWZnaGlqIiwicm9sZSI6ImFub24iLCJpYXQiOjE1MTYyMzkwMjJ9.AAAAAAAAAAAAAAAAAAAAAA';"
                    .to_string(),
            ),
        ];
        let mut out = DiscoveredAuthConfig::default();
        let done = scan_bodies_for_config(&bodies, &mut out);
        assert!(done);
        assert!(out.supabase_url.is_some());
        assert!(out.supabase_anon_key.is_some());
    }

    #[test]
    fn scan_bodies_returns_false_when_only_url_found() {
        let bodies = vec![(
            "https://a/main.js".into(),
            "config = { url: 'https://abcdefghij.supabase.co' }".to_string(),
        )];
        let mut out = DiscoveredAuthConfig::default();
        let done = scan_bodies_for_config(&bodies, &mut out);
        assert!(!done);
        assert!(out.supabase_url.is_some());
        assert!(out.supabase_anon_key.is_none());
    }

    #[test]
    fn cache_path_normalizes_host() {
        // Cache key strips www., lowercases, strips schemes/paths.
        let p1 = cache_path("https://app.example.com/").map(|p| p.file_name().unwrap().to_owned());
        let p2 =
            cache_path("https://APP.example.com/x/y?z").map(|p| p.file_name().unwrap().to_owned());
        assert_eq!(p1, p2);
    }

    #[test]
    fn cache_path_returns_none_for_malformed_url() {
        assert!(cache_path("not a url").is_none());
        assert!(cache_path("ftp://example.com").is_none());
    }

    #[test]
    fn cache_write_then_read_round_trips() {
        // Use a unique host name so this test doesn't collide.
        let target = format!(
            "https://test-cache-{}.example.com/",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let cfg = DiscoveredAuthConfig {
            supabase_url: Some("https://x.supabase.co".into()),
            supabase_anon_key: Some("eyJhbGciOi.AAAA.BBBB".into()),
            supabase_signup_url: Some("https://x.supabase.co/auth/v1/signup".into()),
            notes: vec!["test".into()],
        };
        write_cache(&target, &cfg).unwrap();
        let read_back = read_cache(&target).expect("cache hit");
        assert_eq!(read_back, cfg);
        // Clean up.
        if let Some(p) = cache_path(&target) {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn discovered_config_is_ready_when_both_set() {
        let c = DiscoveredAuthConfig {
            supabase_url: Some("https://x.supabase.co".into()),
            supabase_anon_key: Some("eyJxxx.yyy.zzz".into()),
            supabase_signup_url: Some("https://x.supabase.co/auth/v1/signup".into()),
            notes: vec![],
        };
        assert!(c.is_supabase_ready());

        let c2 = DiscoveredAuthConfig {
            supabase_url: Some("https://x.supabase.co".into()),
            supabase_anon_key: None,
            supabase_signup_url: None,
            notes: vec![],
        };
        assert!(!c2.is_supabase_ready());
    }
}
