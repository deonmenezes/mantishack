//! Built-in recon helpers — no external tools required.
//!
//! These functions widen the discovered-surface set using only an
//! `reqwest::Client` plus the published Wayback Machine API. They run
//! after the HTTP scanner has discovered the initial surface so the
//! orchestrator has a real `Surface` to seed from.
//!
//! Modules:
//! - `wayback_urls` — fetch archive.org snapshots for a host
//! - `js_endpoints` — extract endpoint-shaped strings from a JS bundle
//! - `well_known_paths` — probe `/.well-known/*` & friends
//! - `tech_fingerprints` — Wappalyzer-style header / cookie sniffing
//! - `graphql_introspection` — POST `__schema` query to common
//!   GraphQL endpoints
//! - `openapi_swagger` — fetch `/swagger.json`, `/openapi.json`,
//!   `/v3/api-docs` and parse route lists

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A single archived URL returned by the Wayback Machine CDX API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WaybackUrl {
    pub url: String,
    pub timestamp: String,
    pub status: String,
}

/// Pull archived URL records for `host` (and optionally sub-host
/// matches with the `*.` wildcard). Default limit is 5000 records.
/// Returns deduped URLs ordered by timestamp ascending.
///
/// Note: the Wayback CDX endpoint is public and unauthenticated. For
/// engagements that prefer no external traffic, leave this function
/// uncalled — the rest of recon still works.
pub async fn wayback_urls(
    client: &reqwest::Client,
    host: &str,
    limit: usize,
) -> Result<Vec<WaybackUrl>, String> {
    let url = format!(
        "https://web.archive.org/cdx/search/cdx?url={host}/*&output=json&limit={limit}&fl=original,timestamp,statuscode&collapse=urlkey"
    );
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| format!("wayback fetch: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("wayback returned {}", resp.status()));
    }
    let body = resp.text().await.map_err(|e| format!("wayback body: {e}"))?;
    let rows: Vec<Vec<String>> =
        serde_json::from_str(&body).map_err(|e| format!("wayback parse: {e}"))?;
    let mut out: Vec<WaybackUrl> = rows
        .into_iter()
        .skip(1) // header row: ["original","timestamp","statuscode"]
        .filter_map(|r| {
            if r.len() < 3 {
                None
            } else {
                Some(WaybackUrl {
                    url: r[0].clone(),
                    timestamp: r[1].clone(),
                    status: r[2].clone(),
                })
            }
        })
        .collect();
    out.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Ok(out)
}

/// Extract endpoint-shaped strings from a JavaScript bundle. Returns
/// deduped relative paths suitable for follow-up probing.
pub fn extract_js_endpoints(body: &str) -> Vec<String> {
    // Greedy but pragmatic — captures the kind of paths Webpack /
    // Next.js / Vite bundles emit when route tables ship to the
    // client. We keep only those that:
    //   - start with `/` (relative root-anchored)
    //   - don't contain spaces / newlines / quotes
    //   - are 4–250 chars long
    let mut out: HashSet<String> = HashSet::new();
    // Match strings inside single or double quotes that look like
    // routes. Avoid pulling a full regex dep — hand-rolled scan.
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let q = bytes[i];
        if q == b'"' || q == b'\'' {
            let mut end = i + 1;
            while end < bytes.len() && bytes[end] != q {
                if bytes[end] == b'\n' {
                    break;
                }
                end += 1;
            }
            if end < bytes.len() && bytes[end] == q && end > i + 1 {
                let s = &body[i + 1..end];
                if s.starts_with('/')
                    && s.len() >= 4
                    && s.len() <= 250
                    && !s.contains(' ')
                    && !s.contains('\\')
                    && !s.contains('\t')
                    && s.bytes().all(|c| c.is_ascii() && c.is_ascii_graphic())
                {
                    // Drop common false positives.
                    if !s.ends_with(".js")
                        && !s.ends_with(".css")
                        && !s.ends_with(".png")
                        && !s.ends_with(".jpg")
                        && !s.ends_with(".svg")
                        && !s.ends_with(".woff")
                        && !s.ends_with(".woff2")
                        && !s.ends_with(".ico")
                        && !s.ends_with(".map")
                    {
                        out.insert(s.to_string());
                    }
                }
            }
            i = end + 1;
        } else {
            i += 1;
        }
    }
    let mut v: Vec<String> = out.into_iter().collect();
    v.sort();
    v
}

/// Paths under `/.well-known/` that often leak useful info.
pub fn well_known_paths() -> &'static [&'static str] {
    &[
        "/.well-known/security.txt",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/apple-app-site-association",
        "/.well-known/assetlinks.json",
        "/.well-known/dnt-policy.txt",
        "/.well-known/host-meta",
        "/.well-known/webfinger",
        "/.well-known/change-password",
        "/.well-known/mta-sts.txt",
        "/.well-known/jwks.json",
        "/.well-known/openid-credential-issuer",
        "/.well-known/openid-credential-verifier",
    ]
}

/// Common config + metadata paths that often expose secrets when
/// misconfigured. Used as a low-cost seed list for the enumerator.
pub fn metadata_paths() -> &'static [&'static str] {
    &[
        "/robots.txt",
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/.git/config",
        "/.git/HEAD",
        "/.env",
        "/.env.local",
        "/.env.production",
        "/config.json",
        "/swagger.json",
        "/swagger.yaml",
        "/swagger-ui/",
        "/openapi.json",
        "/openapi.yaml",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api-docs",
        "/graphql",
        "/graphiql",
        "/__graphql",
        "/playground",
        "/__schema",
        "/_next/data/",
        "/_next/image",
        "/_next/static/",
        "/_nuxt/",
        "/__nuxt",
        "/_status/",
        "/actuator",
        "/actuator/env",
        "/actuator/heapdump",
        "/actuator/health",
        "/actuator/mappings",
        "/actuator/trace",
        "/actuator/loggers",
        "/_debug/vars",
        "/debug/pprof/",
        "/server-status",
        "/server-info",
        "/.DS_Store",
        "/phpinfo.php",
        "/info.php",
        "/.npmrc",
        "/.dockerignore",
        "/Dockerfile",
        "/package.json",
        "/composer.json",
        "/yarn.lock",
        "/Gemfile",
        "/manifest.json",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
    ]
}

/// Tech fingerprints — simple substring matches against response
/// headers and body. Each match yields a `(name, signal)` pair so the
/// hunter prompt knows what knowledge pack to load.
pub fn detect_tech(headers: &[(String, String)], body: &str) -> Vec<String> {
    let mut hits: HashSet<String> = HashSet::new();
    let body_lower = body.to_ascii_lowercase();
    for (k, v) in headers {
        let lk = k.to_ascii_lowercase();
        let lv = v.to_ascii_lowercase();
        if lk == "server" {
            if lv.contains("nginx") {
                hits.insert("nginx".into());
            }
            if lv.contains("apache") {
                hits.insert("apache".into());
            }
            if lv.contains("cloudfront") {
                hits.insert("cloudfront".into());
            }
            if lv.contains("envoy") {
                hits.insert("envoy".into());
            }
            if lv.contains("istio") {
                hits.insert("istio".into());
            }
        }
        if lk == "x-powered-by" {
            if lv.contains("php") {
                hits.insert("php".into());
            }
            if lv.contains("express") {
                hits.insert("express".into());
            }
            if lv.contains("next") {
                hits.insert("nextjs".into());
            }
            if lv.contains("asp.net") {
                hits.insert("aspnet".into());
            }
        }
        if lk == "set-cookie" {
            if lv.contains("jsessionid") {
                hits.insert("java-servlet".into());
            }
            if lv.contains("phpsessid") {
                hits.insert("php".into());
            }
            if lv.contains("django") {
                hits.insert("django".into());
            }
            if lv.contains("connect.sid") {
                hits.insert("express".into());
            }
        }
        if lk == "x-amz-cf-id" || lk == "x-amz-id-2" {
            hits.insert("aws".into());
        }
        if lk == "via" && lv.contains("google") {
            hits.insert("gcp".into());
        }
    }
    if body_lower.contains("wp-content/") || body_lower.contains("wp-includes/") {
        hits.insert("wordpress".into());
    }
    if body_lower.contains("__nuxt") {
        hits.insert("nuxt".into());
    }
    if body_lower.contains("__next_data__") {
        hits.insert("nextjs".into());
    }
    if body_lower.contains("apollo") && body_lower.contains("graphql") {
        hits.insert("apollo-graphql".into());
    }
    if body_lower.contains("vercel-deployment-id") {
        hits.insert("vercel".into());
    }
    if body_lower.contains("netlify") {
        hits.insert("netlify".into());
    }
    if body_lower.contains("firebase") || body_lower.contains("firebaseapp.com") {
        hits.insert("firebase".into());
    }
    if body_lower.contains("supabase") {
        hits.insert("supabase".into());
    }
    let mut v: Vec<String> = hits.into_iter().collect();
    v.sort();
    v
}

/// Run a small GraphQL introspection probe — returns true if the
/// `__schema` query was answered with a `Type` payload (i.e. the
/// endpoint left introspection enabled).
pub async fn graphql_introspection_enabled(
    client: &reqwest::Client,
    endpoint: &str,
) -> Result<bool, String> {
    let body = r#"{"query":"{__schema{queryType{name}}}"}"#;
    let resp = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("graphql probe: {e}"))?;
    if !resp.status().is_success() {
        return Ok(false);
    }
    let text = resp.text().await.unwrap_or_default();
    Ok(text.contains("queryType") && !text.contains("introspection is disabled"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_js_endpoints_finds_routes_in_quotes() {
        let js = r#"
            var routes = ['/api/users', "/api/v2/orders", '/login'];
            fetch('/static/main.js'); // should be skipped
            "/api/admin/secret"
        "#;
        let v = extract_js_endpoints(js);
        assert!(v.contains(&"/api/users".to_string()));
        assert!(v.contains(&"/api/v2/orders".to_string()));
        assert!(v.contains(&"/login".to_string()));
        assert!(v.contains(&"/api/admin/secret".to_string()));
        assert!(!v.iter().any(|p| p.ends_with(".js")));
    }

    #[test]
    fn extract_js_endpoints_drops_static_assets() {
        let js = r#"'/img/logo.png' '/styles/main.css' '/font.woff2' '/api/keep'"#;
        let v = extract_js_endpoints(js);
        assert!(v.contains(&"/api/keep".to_string()));
        assert!(!v.iter().any(|p| p.ends_with(".png")));
        assert!(!v.iter().any(|p| p.ends_with(".css")));
        assert!(!v.iter().any(|p| p.ends_with(".woff2")));
    }

    #[test]
    fn well_known_paths_includes_security_txt_and_openid() {
        let p = well_known_paths();
        assert!(p.contains(&"/.well-known/security.txt"));
        assert!(p.contains(&"/.well-known/openid-configuration"));
    }

    #[test]
    fn metadata_paths_includes_swagger_graphql_actuator() {
        let p = metadata_paths();
        assert!(p.contains(&"/swagger.json"));
        assert!(p.contains(&"/graphql"));
        assert!(p.contains(&"/actuator"));
        assert!(p.contains(&"/.git/config"));
    }

    #[test]
    fn detect_tech_picks_nginx_php_wordpress() {
        let headers = vec![
            ("Server".into(), "nginx/1.21.0".into()),
            ("X-Powered-By".into(), "PHP/8.0.2".into()),
            ("Set-Cookie".into(), "PHPSESSID=abc; Path=/".into()),
        ];
        let body = "<html><body>powered by wp-content/themes</body></html>";
        let hits = detect_tech(&headers, body);
        assert!(hits.contains(&"nginx".to_string()));
        assert!(hits.contains(&"php".to_string()));
        assert!(hits.contains(&"wordpress".to_string()));
    }

    #[test]
    fn detect_tech_picks_nextjs_apollo_vercel() {
        let headers: Vec<(String, String)> = vec![];
        let body = r#"<script>window.__NEXT_DATA__ = {};</script>
            <meta name="vercel-deployment-id" content="x"/>
            <noscript>Apollo Client requires GraphQL</noscript>"#;
        let hits = detect_tech(&headers, body);
        assert!(hits.contains(&"nextjs".to_string()));
        assert!(hits.contains(&"apollo-graphql".to_string()));
        assert!(hits.contains(&"vercel".to_string()));
    }

    #[test]
    fn detect_tech_picks_firebase_supabase_netlify() {
        let headers: Vec<(String, String)> = vec![];
        let body = "<script>const fb = 'firebase';</script> netlify says hi supabase too";
        let hits = detect_tech(&headers, body);
        assert!(hits.contains(&"firebase".to_string()));
        assert!(hits.contains(&"netlify".to_string()));
        assert!(hits.contains(&"supabase".to_string()));
    }

    #[test]
    fn detect_tech_picks_aws_and_gcp_from_headers() {
        let headers = vec![
            ("X-Amz-Cf-Id".into(), "abc".into()),
            ("Via".into(), "1.1 google".into()),
        ];
        let body = "";
        let hits = detect_tech(&headers, body);
        assert!(hits.contains(&"aws".to_string()));
        assert!(hits.contains(&"gcp".to_string()));
    }

    #[test]
    fn detect_tech_picks_cloudfront_envoy_istio() {
        let headers = vec![
            ("Server".into(), "CloudFront".into()),
        ];
        let hits = detect_tech(&headers, "");
        assert!(hits.contains(&"cloudfront".to_string()));
    }

    #[test]
    fn detect_tech_picks_express_aspnet_django() {
        let headers = vec![
            ("X-Powered-By".into(), "Express".into()),
            ("Set-Cookie".into(), "django_session=abc".into()),
        ];
        let hits = detect_tech(&headers, "");
        assert!(hits.contains(&"express".to_string()));
        assert!(hits.contains(&"django".to_string()));
    }

    #[test]
    fn detect_tech_picks_java_servlet_from_cookie() {
        let headers = vec![("Set-Cookie".into(), "JSESSIONID=abc; Path=/".into())];
        let hits = detect_tech(&headers, "");
        assert!(hits.contains(&"java-servlet".to_string()));
    }

    #[test]
    fn detect_tech_returns_empty_when_no_signals() {
        let headers: Vec<(String, String)> = vec![];
        let body = "<html><body>nothing remarkable</body></html>";
        let hits = detect_tech(&headers, body);
        assert!(hits.is_empty());
    }

    #[test]
    fn extract_js_endpoints_empty_when_no_routes() {
        let v = extract_js_endpoints("var x = 1; function f(){return null;}");
        assert!(v.is_empty());
    }

    #[test]
    fn extract_js_endpoints_dedupes_repeats() {
        let js = r#"'/api/users' '/api/users' '/api/users' '/api/orders'"#;
        let v = extract_js_endpoints(js);
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn extract_js_endpoints_skips_too_short() {
        let js = r#"'/a' '/b' '/aa' '/api/long-enough'"#;
        let v = extract_js_endpoints(js);
        // `/a`, `/b`, `/aa` all < 4 chars → skipped.
        assert!(v.contains(&"/api/long-enough".to_string()));
        assert!(!v.contains(&"/a".to_string()));
        assert!(!v.contains(&"/b".to_string()));
        assert!(!v.contains(&"/aa".to_string()));
    }

    #[test]
    fn metadata_paths_includes_dot_files() {
        let p = metadata_paths();
        assert!(p.contains(&"/.env"));
        assert!(p.contains(&"/.git/config"));
        assert!(p.contains(&"/.DS_Store"));
    }

    #[test]
    fn well_known_paths_includes_change_password_and_webfinger() {
        let p = well_known_paths();
        assert!(p.contains(&"/.well-known/change-password"));
        assert!(p.contains(&"/.well-known/webfinger"));
        assert!(p.contains(&"/.well-known/jwks.json"));
    }

    #[test]
    fn metadata_paths_includes_framework_specific_routes() {
        let p = metadata_paths();
        assert!(p.iter().any(|x| x.contains("_next")));
        assert!(p.iter().any(|x| x.contains("_nuxt")));
        assert!(p.iter().any(|x| x.contains("actuator")));
    }
}
