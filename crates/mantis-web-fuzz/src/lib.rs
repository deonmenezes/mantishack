//! mantis-web-fuzz — HTTP-request-shape fuzzer.
//!
//! [`mantis-fuzzer`] is grammar-aware: it mutates *payload values*
//! for vuln classes (XSS / SQLi / SSRF / etc.). This crate fills the
//! complementary gap — fuzzing the *shape of the request itself*:
//!
//! * [`FuzzMode::Path`] — brute-force paths under a base URL, the
//!   classic ffuf / feroxbuster usage.
//! * [`FuzzMode::Vhost`] — brute-force the `Host:` header to find
//!   virtual hosts the IP serves.
//! * [`FuzzMode::Parameter`] — brute-force query-string parameter
//!   *names* (the value is fixed; what we vary is whether `?foo=v`
//!   is reflected or alters behaviour).
//! * [`FuzzMode::Header`] — brute-force HTTP header *names*.
//!
//! Recursive path discovery is implemented as a follow-up call on
//! interesting hits — see [`fuzz_recursive`].
//!
//! ## Wordlist convention
//!
//! Every mode takes a `Vec<String>` of candidates. The substitution
//! token in [`FuzzRequest::template`] is `FUZZ` (the ffuf default);
//! e.g. `https://target/FUZZ` for path mode, `?FUZZ=x` for parameter,
//! `FUZZ: y` for header. This keeps existing seclists/ffuf wordlists
//! directly usable.
//!
//! ## Filtering
//!
//! [`MatchRules`] follows the ffuf vocabulary: status codes,
//! response sizes, word counts, line counts. A response is reported
//! when **all** rules match. The default rule set keeps everything
//! that is not 404 — a sane signal for path / vhost discovery.
//!
//! ## Concurrency
//!
//! Requests are streamed through a `futures::stream::buffer_unordered`
//! pool. The default concurrency of 40 mirrors feroxbuster and is
//! conservative enough that mantis-egress's per-host quota will
//! happily admit it.
//!
//! ## Not in scope
//!
//! * No FFI to libcurl / ffuf — we use the workspace `reqwest`
//!   client so TLS + connection pooling are consistent with the rest
//!   of mantis.
//! * No on-disk wordlist parsing helpers; callers feed already-loaded
//!   `Vec<String>`. The thinking is that wordlist provenance belongs
//!   in `mantis-recon-tools`, which can stream from disk and dedupe.

use std::collections::HashSet;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use mantis_static_scan::{Finding, Severity};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, HOST};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The literal substitution token. Compatible with ffuf wordlists.
pub const FUZZ_TOKEN: &str = "FUZZ";

/// Which dimension of the request we're varying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FuzzMode {
    /// Substitute FUZZ into the URL path / query.
    Path,
    /// Substitute FUZZ into the `Host:` header. The URL stays fixed,
    /// typically the bare IP.
    Vhost,
    /// Substitute FUZZ into a query parameter *name*.
    Parameter,
    /// Substitute FUZZ into a header *name*.
    Header,
}

/// The request to fuzz. Exactly one occurrence of [`FUZZ_TOKEN`]
/// must appear somewhere in `template` or `header_template`.
#[derive(Debug, Clone)]
pub struct FuzzRequest {
    pub mode: FuzzMode,
    /// URL template — for [`FuzzMode::Path`] or
    /// [`FuzzMode::Parameter`] this contains FUZZ; for
    /// [`FuzzMode::Vhost`] / [`FuzzMode::Header`] it's a fixed URL.
    pub template: String,
    /// For [`FuzzMode::Vhost`]: ignored, we inject Host directly.
    /// For [`FuzzMode::Header`]: the *value* of the header whose
    /// name we're brute-forcing — typically a sentinel like
    /// `"mantis-fuzz"` so reflections are obvious. For other modes:
    /// `None`.
    pub header_value: Option<String>,
    pub method: Method,
}

/// Rules for deciding whether a response counts as a "hit". All
/// non-`None` rules must hold; default is "anything not 404".
#[derive(Debug, Clone, Default)]
pub struct MatchRules {
    pub status_in: Option<Vec<u16>>,
    pub status_not_in: Option<Vec<u16>>,
    pub size_in: Option<Vec<usize>>,
    pub size_not_in: Option<Vec<usize>>,
    pub words_in: Option<Vec<usize>>,
    pub lines_in: Option<Vec<usize>>,
}

impl MatchRules {
    /// Default "discovery" preset — drop 404s, accept everything else.
    pub fn discovery() -> Self {
        Self {
            status_not_in: Some(vec![404]),
            ..Self::default()
        }
    }

    /// Accept only successful (2xx / 3xx) responses.
    pub fn success_only() -> Self {
        Self {
            status_in: Some((200..400).collect()),
            ..Self::default()
        }
    }

    /// True iff this response shape satisfies every rule that is set.
    pub fn matches(&self, shape: &ResponseShape) -> bool {
        if let Some(allow) = &self.status_in {
            if !allow.contains(&shape.status) {
                return false;
            }
        }
        if let Some(deny) = &self.status_not_in {
            if deny.contains(&shape.status) {
                return false;
            }
        }
        if let Some(sizes) = &self.size_in {
            if !sizes.contains(&shape.size) {
                return false;
            }
        }
        if let Some(deny) = &self.size_not_in {
            if deny.contains(&shape.size) {
                return false;
            }
        }
        if let Some(words) = &self.words_in {
            if !words.contains(&shape.words) {
                return false;
            }
        }
        if let Some(lines) = &self.lines_in {
            if !lines.contains(&shape.lines) {
                return false;
            }
        }
        true
    }
}

/// What we observed for one probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseShape {
    pub status: u16,
    pub size: usize,
    pub words: usize,
    pub lines: usize,
}

impl ResponseShape {
    pub fn from_body(status: u16, body: &str) -> Self {
        Self {
            status,
            size: body.len(),
            words: body.split_whitespace().count(),
            lines: body.lines().count().max(1),
        }
    }
}

/// One reported hit.
#[derive(Debug, Clone)]
pub struct FuzzHit {
    pub mode: FuzzMode,
    /// Whatever was substituted in for `FUZZ`.
    pub candidate: String,
    /// Final URL we hit (after substitution).
    pub url: String,
    pub shape: ResponseShape,
}

impl FuzzHit {
    /// Lift this hit into a normalised [`Finding`] so the rest of
    /// mantis can ingest it without knowing about the fuzz vocabulary.
    pub fn into_finding(self) -> Finding {
        let kind = match self.mode {
            FuzzMode::Path => "discovered-path",
            FuzzMode::Vhost => "discovered-vhost",
            FuzzMode::Parameter => "discovered-param",
            FuzzMode::Header => "discovered-header",
        };
        let severity = match self.shape.status {
            200..=299 => Severity::Low,
            300..=399 => Severity::Info,
            400..=403 => Severity::Info,
            500..=599 => Severity::Medium,
            _ => Severity::Info,
        };
        let title = format!("{kind} {} -> {}", self.candidate, self.shape.status);
        Finding::new("mantis-web-fuzz", kind, self.url.clone(), severity, title)
            .with_meta("candidate", self.candidate)
            .with_meta("status", self.shape.status.to_string())
            .with_meta("size", self.shape.size.to_string())
            .with_meta("words", self.shape.words.to_string())
            .with_meta("lines", self.shape.lines.to_string())
    }
}

#[derive(Debug, Error)]
pub enum FuzzError {
    #[error("template must contain the FUZZ token")]
    NoFuzzToken,
    #[error("invalid candidate `{0}` for header/host position")]
    InvalidCandidate(String),
    #[error("http client construction failed: {0}")]
    Client(#[from] reqwest::Error),
}

/// Engine config: timeout, concurrency, follow-redirects.
#[derive(Debug, Clone)]
pub struct FuzzConfig {
    pub timeout: Duration,
    pub concurrency: usize,
    pub follow_redirects: bool,
    pub user_agent: String,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            concurrency: 40,
            follow_redirects: false,
            user_agent: format!("mantis-web-fuzz/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

/// Build the reqwest client used for fuzzing. Public so callers can
/// reuse it across multiple [`fuzz`] invocations and benefit from
/// connection pooling.
pub fn build_client(cfg: &FuzzConfig) -> Result<reqwest::Client, FuzzError> {
    let mut builder = reqwest::Client::builder()
        .timeout(cfg.timeout)
        .user_agent(&cfg.user_agent);
    builder = if cfg.follow_redirects {
        builder.redirect(reqwest::redirect::Policy::limited(5))
    } else {
        builder.redirect(reqwest::redirect::Policy::none())
    };
    Ok(builder.build()?)
}

/// Run a single fuzz pass and return the hits.
pub async fn fuzz(
    client: &reqwest::Client,
    req: &FuzzRequest,
    candidates: &[String],
    rules: &MatchRules,
    cfg: &FuzzConfig,
) -> Result<Vec<FuzzHit>, FuzzError> {
    // Pre-flight: template validation depends on mode.
    match req.mode {
        FuzzMode::Path | FuzzMode::Parameter => {
            if !req.template.contains(FUZZ_TOKEN) {
                return Err(FuzzError::NoFuzzToken);
            }
        }
        FuzzMode::Vhost | FuzzMode::Header => {
            // template is fixed URL; nothing to substitute there.
            // The substitution happens in the header.
        }
    }

    let stream = stream::iter(candidates.iter().cloned()).map(|cand| {
        let req = req.clone();
        async move { probe(client, &req, &cand).await }
    });

    let results: Vec<_> = stream.buffer_unordered(cfg.concurrency).collect().await;

    let mut hits = Vec::new();
    for r in results {
        match r {
            Ok(hit) if rules.matches(&hit.shape) => hits.push(hit),
            Ok(_) => {}
            Err(_) => {
                // Probe-level errors (network / DNS) are swallowed —
                // a failing candidate isn't a hit, but it also
                // shouldn't kill the whole sweep. tracing::warn elided
                // here so tests stay deterministic.
            }
        }
    }
    Ok(hits)
}

async fn probe(
    client: &reqwest::Client,
    req: &FuzzRequest,
    candidate: &str,
) -> Result<FuzzHit, FuzzError> {
    let (url, header_overrides) = build_request(req, candidate)?;

    let builder = client
        .request(req.method.clone(), &url)
        .headers(header_overrides);
    let resp = builder.send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    let shape = ResponseShape::from_body(status, &body);
    Ok(FuzzHit {
        mode: req.mode,
        candidate: candidate.to_string(),
        url,
        shape,
    })
}

/// Build the concrete URL + per-request header overrides for a
/// candidate. Pulled out for testability.
pub fn build_request(req: &FuzzRequest, candidate: &str) -> Result<(String, HeaderMap), FuzzError> {
    let mut headers = HeaderMap::new();
    let url = match req.mode {
        FuzzMode::Path => req.template.replace(FUZZ_TOKEN, candidate),
        FuzzMode::Parameter => req.template.replace(FUZZ_TOKEN, candidate),
        FuzzMode::Vhost => {
            let host = HeaderValue::from_str(candidate)
                .map_err(|_| FuzzError::InvalidCandidate(candidate.to_string()))?;
            headers.insert(HOST, host);
            req.template.clone()
        }
        FuzzMode::Header => {
            let name = HeaderName::from_bytes(candidate.as_bytes())
                .map_err(|_| FuzzError::InvalidCandidate(candidate.to_string()))?;
            let value = HeaderValue::from_str(req.header_value.as_deref().unwrap_or("mantis-fuzz"))
                .map_err(|_| FuzzError::InvalidCandidate(candidate.to_string()))?;
            headers.insert(name, value);
            req.template.clone()
        }
    };
    Ok((url, headers))
}

/// Recursive path discovery. Runs an initial path-mode fuzz, then
/// re-fuzzes the same wordlist beneath every hit whose status is in
/// `recurse_status` and whose path depth is below `max_depth`.
///
/// `max_depth` is counted from the seed URL: depth=0 is the seed
/// itself, depth=1 is one level beneath, etc. A `max_depth` of 2
/// is a sensible default — feroxbuster's default is 4 but most
/// targets saturate the wordlist long before then.
pub async fn fuzz_recursive(
    client: &reqwest::Client,
    base_url: &str,
    wordlist: &[String],
    rules: &MatchRules,
    cfg: &FuzzConfig,
    recurse_status: &[u16],
    max_depth: usize,
) -> Result<Vec<FuzzHit>, FuzzError> {
    let mut all_hits = Vec::new();
    let mut frontier: Vec<(String, usize)> = vec![(base_url.trim_end_matches('/').to_string(), 0)];
    let mut seen: HashSet<String> = HashSet::new();

    while let Some((url, depth)) = frontier.pop() {
        if !seen.insert(url.clone()) {
            continue;
        }
        let template = format!("{url}/{FUZZ_TOKEN}");
        let req = FuzzRequest {
            mode: FuzzMode::Path,
            template,
            header_value: None,
            method: Method::GET,
        };
        let hits = fuzz(client, &req, wordlist, rules, cfg).await?;

        if depth < max_depth {
            for hit in &hits {
                if recurse_status.contains(&hit.shape.status) {
                    frontier.push((hit.url.trim_end_matches('/').to_string(), depth + 1));
                }
            }
        }
        all_hits.extend(hits);
    }
    Ok(all_hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_token_is_ffuf_compatible() {
        assert_eq!(FUZZ_TOKEN, "FUZZ");
    }

    #[test]
    fn build_request_substitutes_path_token() {
        let req = FuzzRequest {
            mode: FuzzMode::Path,
            template: "https://x/FUZZ".into(),
            header_value: None,
            method: Method::GET,
        };
        let (url, headers) = build_request(&req, "admin").unwrap();
        assert_eq!(url, "https://x/admin");
        assert!(headers.is_empty());
    }

    #[test]
    fn build_request_substitutes_parameter_token() {
        let req = FuzzRequest {
            mode: FuzzMode::Parameter,
            template: "https://x/?FUZZ=1".into(),
            header_value: None,
            method: Method::GET,
        };
        let (url, _) = build_request(&req, "debug").unwrap();
        assert_eq!(url, "https://x/?debug=1");
    }

    #[test]
    fn build_request_sets_host_for_vhost_mode() {
        let req = FuzzRequest {
            mode: FuzzMode::Vhost,
            template: "https://10.0.0.1/".into(),
            header_value: None,
            method: Method::GET,
        };
        let (url, headers) = build_request(&req, "admin.target.example").unwrap();
        assert_eq!(url, "https://10.0.0.1/");
        assert_eq!(headers.get(HOST).unwrap(), "admin.target.example");
    }

    #[test]
    fn build_request_sets_header_for_header_mode() {
        let req = FuzzRequest {
            mode: FuzzMode::Header,
            template: "https://x/".into(),
            header_value: Some("123".into()),
            method: Method::GET,
        };
        let (url, headers) = build_request(&req, "X-Forwarded-For").unwrap();
        assert_eq!(url, "https://x/");
        assert_eq!(headers.get("x-forwarded-for").unwrap(), "123");
    }

    #[test]
    fn build_request_rejects_invalid_header_name() {
        let req = FuzzRequest {
            mode: FuzzMode::Header,
            template: "https://x/".into(),
            header_value: None,
            method: Method::GET,
        };
        let err = build_request(&req, "Bad Header With Space").unwrap_err();
        match err {
            FuzzError::InvalidCandidate(_) => {}
            other => panic!("expected InvalidCandidate, got {other:?}"),
        }
    }

    #[test]
    fn response_shape_counts_lines_and_words() {
        let s = ResponseShape::from_body(200, "hello world\nsecond line\n");
        assert_eq!(s.status, 200);
        assert_eq!(s.size, "hello world\nsecond line\n".len());
        assert_eq!(s.words, 4);
        assert_eq!(s.lines, 2);
    }

    #[test]
    fn response_shape_empty_body_has_one_line() {
        let s = ResponseShape::from_body(204, "");
        assert_eq!(s.lines, 1);
        assert_eq!(s.words, 0);
        assert_eq!(s.size, 0);
    }

    #[test]
    fn match_rules_default_accepts_everything() {
        let rules = MatchRules::default();
        let shape = ResponseShape::from_body(404, "nope");
        assert!(rules.matches(&shape));
    }

    #[test]
    fn match_rules_discovery_drops_404() {
        let rules = MatchRules::discovery();
        assert!(!rules.matches(&ResponseShape::from_body(404, "x")));
        assert!(rules.matches(&ResponseShape::from_body(200, "x")));
        assert!(rules.matches(&ResponseShape::from_body(403, "x")));
    }

    #[test]
    fn match_rules_success_only_accepts_2xx_3xx() {
        let rules = MatchRules::success_only();
        assert!(rules.matches(&ResponseShape::from_body(200, "x")));
        assert!(rules.matches(&ResponseShape::from_body(302, "x")));
        assert!(!rules.matches(&ResponseShape::from_body(401, "x")));
        assert!(!rules.matches(&ResponseShape::from_body(500, "x")));
    }

    #[test]
    fn match_rules_size_filter() {
        let rules = MatchRules {
            size_not_in: Some(vec![0]),
            ..MatchRules::default()
        };
        assert!(!rules.matches(&ResponseShape::from_body(200, "")));
        assert!(rules.matches(&ResponseShape::from_body(200, "x")));
    }

    #[test]
    fn fuzz_hit_into_finding_assigns_kind_per_mode() {
        for (mode, expected_kind) in [
            (FuzzMode::Path, "discovered-path"),
            (FuzzMode::Vhost, "discovered-vhost"),
            (FuzzMode::Parameter, "discovered-param"),
            (FuzzMode::Header, "discovered-header"),
        ] {
            let hit = FuzzHit {
                mode,
                candidate: "x".into(),
                url: "https://t/x".into(),
                shape: ResponseShape::from_body(200, "body"),
            };
            let finding = hit.into_finding();
            assert_eq!(finding.tool, "mantis-web-fuzz");
            assert_eq!(finding.kind, expected_kind);
        }
    }

    #[test]
    fn fuzz_hit_into_finding_severity_ladder() {
        let h = |status: u16| FuzzHit {
            mode: FuzzMode::Path,
            candidate: "x".into(),
            url: "https://t/x".into(),
            shape: ResponseShape::from_body(status, ""),
        };
        assert_eq!(h(200).into_finding().severity, Severity::Low);
        assert_eq!(h(301).into_finding().severity, Severity::Info);
        assert_eq!(h(401).into_finding().severity, Severity::Info);
        assert_eq!(h(500).into_finding().severity, Severity::Medium);
    }

    #[tokio::test]
    async fn fuzz_returns_no_fuzz_token_for_path_template_without_marker() {
        let cfg = FuzzConfig::default();
        let client = build_client(&cfg).unwrap();
        let req = FuzzRequest {
            mode: FuzzMode::Path,
            template: "https://x/no-token-here".into(),
            header_value: None,
            method: Method::GET,
        };
        let err = fuzz(&client, &req, &["a".into()], &MatchRules::default(), &cfg)
            .await
            .unwrap_err();
        match err {
            FuzzError::NoFuzzToken => {}
            other => panic!("expected NoFuzzToken, got {other:?}"),
        }
    }
}
