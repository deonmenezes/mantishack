//! httpx-style concurrent HTTP probe.
//!
//! Takes a list of hosts (or full URLs) and, with a bounded
//! concurrency window, fetches each one and records:
//! - status code
//! - title (if HTML)
//! - selected response headers
//! - the resolved URL after redirects
//! - basic tech fingerprints (matched against header substrings)
//!
//! It is intentionally close in shape to the JSON emitted by
//! `projectdiscovery/httpx` so callers can swap between the native
//! probe here and the subprocess wrapper in `mantis-recon-tools`
//! without code changes.

use crate::ReconError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Debug, Clone)]
pub struct ProbeOptions {
    pub concurrency: usize,
    pub timeout: Duration,
    pub follow_redirects: bool,
    pub max_body_bytes: usize,
    pub user_agent: String,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            concurrency: 32,
            timeout: Duration::from_secs(10),
            follow_redirects: true,
            max_body_bytes: 1024 * 256, // 256 KiB cap
            user_agent: "mantis-recon/0.0.9".into(),
        }
    }
}

/// One probe outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProbeResult {
    pub url: String,
    pub final_url: String,
    pub status_code: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default)]
    pub tech: Vec<String>,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    pub content_length: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Probe `inputs` and return one [`HttpProbeResult`] per input. Order
/// is preserved.
///
/// `inputs` may be:
/// - a bare hostname (`example.com`) — both `https://` and `http://`
///   are tried; the first to respond wins
/// - a full URL (`https://example.com/api`) — used verbatim
pub async fn probe(
    inputs: &[String],
    opts: &ProbeOptions,
) -> Result<Vec<HttpProbeResult>, ReconError> {
    let mut builder = reqwest::Client::builder()
        .user_agent(&opts.user_agent)
        .timeout(opts.timeout);
    if !opts.follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }
    let client = builder
        .build()
        .map_err(|e| ReconError::Network(e.to_string()))?;

    let sem = Arc::new(Semaphore::new(opts.concurrency.max(1)));
    let mut tasks = Vec::with_capacity(inputs.len());
    for input in inputs {
        let sem = sem.clone();
        let client = client.clone();
        let input = input.clone();
        let max_body = opts.max_body_bytes;
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore not closed");
            probe_one(&client, &input, max_body).await
        }));
    }
    let mut out = Vec::with_capacity(tasks.len());
    for t in tasks {
        match t.await {
            Ok(r) => out.push(r),
            Err(e) => out.push(HttpProbeResult {
                url: String::new(),
                final_url: String::new(),
                status_code: 0,
                title: None,
                tech: Vec::new(),
                headers: Vec::new(),
                content_length: 0,
                error: Some(format!("join: {e}")),
            }),
        }
    }
    Ok(out)
}

async fn probe_one(client: &reqwest::Client, input: &str, max_body: usize) -> HttpProbeResult {
    // Build candidate URLs without intermediate Vec<String> allocations.
    // The happy path tries exactly one URL; the prior `vec![format!(),
    // format!()]` allocated both up front even when the first succeeded.
    let already_scheme = input.starts_with("http://") || input.starts_with("https://");

    let mut last_err = None;
    let schemes: &[&str] = if already_scheme {
        &[""]
    } else {
        &["https://", "http://"]
    };
    for scheme in schemes {
        // String built once per attempt instead of all up front.
        let url = if scheme.is_empty() {
            input.to_string()
        } else {
            format!("{scheme}{input}")
        };
        match try_url(client, &url, max_body).await {
            Ok(r) => return r,
            Err(e) => last_err = Some(e),
        }
    }
    HttpProbeResult {
        url: input.to_string(),
        final_url: String::new(),
        status_code: 0,
        title: None,
        tech: Vec::new(),
        headers: Vec::new(),
        content_length: 0,
        error: Some(last_err.unwrap_or_else(|| "no candidate URL succeeded".into())),
    }
}

async fn try_url(
    client: &reqwest::Client,
    url: &str,
    max_body: usize,
) -> Result<HttpProbeResult, String> {
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect();

    // Avoid copying the response body into a Vec just to truncate it.
    // `Bytes` is reference-counted; `slice()` creates a zero-copy view.
    let body_bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    let content_length = body_bytes.len();
    let truncated = if body_bytes.len() > max_body {
        body_bytes.slice(0..max_body)
    } else {
        body_bytes
    };
    let body_text = String::from_utf8_lossy(&truncated);

    let title = extract_title(&body_text);
    let tech = fingerprint(&headers, &body_text);

    Ok(HttpProbeResult {
        url: url.to_string(),
        final_url,
        status_code: status,
        title,
        tech,
        headers,
        content_length,
        error: None,
    })
}

/// Extract `<title>...</title>` content if present.
pub fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let after_open = body[start..].find('>')? + start + 1;
    let lower_after = body[after_open..].to_ascii_lowercase();
    let end_rel = lower_after.find("</title>")?;
    let title = body[after_open..after_open + end_rel].trim();
    if title.is_empty() {
        None
    } else {
        Some(title.chars().take(200).collect())
    }
}

/// Simple header + body substring matchers — a lightweight subset of
/// the Wappalyzer-style detection in `mantis-recon-tools::intel`. We
/// duplicate a few signals here so this crate can run standalone.
pub fn fingerprint(headers: &[(String, String)], body: &str) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut out: BTreeSet<String> = BTreeSet::new();
    let body_lower = body.to_ascii_lowercase();
    for (k, v) in headers {
        let lk = k.to_ascii_lowercase();
        let lv = v.to_ascii_lowercase();
        if lk == "server" {
            for needle in [
                "nginx",
                "apache",
                "cloudfront",
                "envoy",
                "istio",
                "lighttpd",
            ] {
                if lv.contains(needle) {
                    out.insert(needle.into());
                }
            }
        }
        if lk == "x-powered-by" {
            for (needle, tag) in [
                ("php", "php"),
                ("express", "express"),
                ("next", "nextjs"),
                ("asp.net", "aspnet"),
            ] {
                if lv.contains(needle) {
                    out.insert(tag.into());
                }
            }
        }
        if lk == "set-cookie" {
            if lv.contains("jsessionid") {
                out.insert("java-servlet".into());
            }
            if lv.contains("phpsessid") {
                out.insert("php".into());
            }
            if lv.contains("connect.sid") {
                out.insert("express".into());
            }
        }
        if lk == "via" && lv.contains("google") {
            out.insert("gcp".into());
        }
        if lk == "x-amz-cf-id" || lk == "x-amz-id-2" {
            out.insert("aws".into());
        }
    }
    if body_lower.contains("__next_data__") {
        out.insert("nextjs".into());
    }
    if body_lower.contains("__nuxt") {
        out.insert("nuxt".into());
    }
    if body_lower.contains("wp-content/") || body_lower.contains("wp-includes/") {
        out.insert("wordpress".into());
    }
    if body_lower.contains("apollo") && body_lower.contains("graphql") {
        out.insert("apollo-graphql".into());
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_title_finds_basic_title() {
        assert_eq!(
            extract_title("<html><head><title>Hello</title></head></html>").as_deref(),
            Some("Hello")
        );
    }

    #[test]
    fn extract_title_handles_attributes_on_title_tag() {
        assert_eq!(
            extract_title("<TiTle lang=\"en\">Greeting</TITLE>").as_deref(),
            Some("Greeting")
        );
    }

    #[test]
    fn extract_title_returns_none_when_empty() {
        assert!(extract_title("<title></title>").is_none());
    }

    #[test]
    fn extract_title_returns_none_when_missing() {
        assert!(extract_title("<html><body>no title</body></html>").is_none());
    }

    #[test]
    fn extract_title_truncates_long_title() {
        let body = format!("<title>{}</title>", "a".repeat(500));
        let t = extract_title(&body).unwrap();
        assert!(t.len() <= 200);
    }

    #[test]
    fn fingerprint_picks_nginx_php_wordpress() {
        let headers = vec![
            ("Server".into(), "nginx/1.21.0".into()),
            ("X-Powered-By".into(), "PHP/8.0.2".into()),
            ("Set-Cookie".into(), "PHPSESSID=abc; Path=/".into()),
        ];
        let body = "<html><body>wp-content/themes</body></html>";
        let hits = fingerprint(&headers, body);
        assert!(hits.contains(&"nginx".to_string()));
        assert!(hits.contains(&"php".to_string()));
        assert!(hits.contains(&"wordpress".to_string()));
    }

    #[test]
    fn fingerprint_picks_aws_and_gcp_from_headers() {
        let headers = vec![
            ("X-Amz-Cf-Id".into(), "abc".into()),
            ("Via".into(), "1.1 google".into()),
        ];
        let hits = fingerprint(&headers, "");
        assert!(hits.contains(&"aws".to_string()));
        assert!(hits.contains(&"gcp".to_string()));
    }

    #[test]
    fn fingerprint_returns_empty_when_no_signals() {
        let hits = fingerprint(&[], "nothing interesting");
        assert!(hits.is_empty());
    }

    #[test]
    fn http_probe_result_round_trips_through_json() {
        let r = HttpProbeResult {
            url: "https://example.com".into(),
            final_url: "https://example.com/".into(),
            status_code: 200,
            title: Some("Example".into()),
            tech: vec!["nginx".into()],
            headers: vec![("server".into(), "nginx".into())],
            content_length: 1234,
            error: None,
        };
        let j = serde_json::to_string(&r).unwrap();
        let back: HttpProbeResult = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn probe_options_defaults_are_sane() {
        let o = ProbeOptions::default();
        assert!(o.concurrency >= 1);
        assert!(o.timeout >= Duration::from_secs(1));
        assert!(o.max_body_bytes > 0);
        assert!(!o.user_agent.is_empty());
    }

    #[tokio::test]
    async fn probe_with_empty_inputs_returns_empty_vec() {
        let out = probe(&[], &ProbeOptions::default()).await.unwrap();
        assert!(out.is_empty());
    }
}
