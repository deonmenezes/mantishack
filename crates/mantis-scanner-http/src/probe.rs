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
//! HTTP probe scanner.
//!
//! Issues a single GET against each target URL, captures status, server
//! header, content length, and a small set of tech fingerprints. Each
//! probe result is written to the event log as a
//! [`EventKind::SurfaceDiscovered`].
//!
//! In production the [`ProbeConfig::proxy`] field is set to the local
//! egress proxy's URL so every request routes through the scope
//! enforcement layer. Phase 0 unit tests omit the proxy and hit
//! localhost mock servers directly.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use mantis_auth::AuthProfile;
use mantis_core::{EngagementId, Signer};
use mantis_event_store::{EventKind, EventStore};
use reqwest::Client;
use tracing::{debug, warn};

use crate::error::ScannerError;

/// A single probe target — `scheme://host:port/path`.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl ProbeTarget {
    pub fn parse(url: &str) -> Result<Self, ScannerError> {
        let parsed =
            reqwest::Url::parse(url).map_err(|e| ScannerError::InvalidTarget(e.to_string()))?;
        let scheme = parsed.scheme().to_owned();
        let host = parsed
            .host_str()
            .ok_or_else(|| ScannerError::InvalidTarget("no host".into()))?
            .to_owned();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| ScannerError::InvalidTarget(format!("no port for scheme {scheme}")))?;
        let path = if parsed.path().is_empty() {
            "/".to_owned()
        } else {
            parsed.path().to_owned()
        };
        Ok(Self {
            scheme,
            host,
            port,
            path,
        })
    }

    pub fn url(&self) -> String {
        format!("{}://{}:{}{}", self.scheme, self.host, self.port, self.path)
    }
}

/// Captured response data plus inferred fingerprints.
#[derive(Debug, Clone)]
pub struct Surface {
    pub target: ProbeTarget,
    pub status: u16,
    pub server: Option<String>,
    pub content_length: Option<u64>,
    pub tech_hints: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// Optional proxy URL (e.g. `http://127.0.0.1:8080`). When set,
    /// reqwest tunnels every request through this proxy.
    pub proxy: Option<String>,
    /// Per-request timeout.
    pub timeout: Duration,
    /// User-Agent header value.
    pub user_agent: String,
    /// Optional auth profile. When set, every probe injects the
    /// profile's cookies, headers, and query parameters into the
    /// outbound request. Mirrors hacker-bob's `auth_profile` arg on
    /// `bounty_http_scan`.
    pub auth_profile: Option<AuthProfile>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            proxy: None,
            timeout: Duration::from_secs(10),
            user_agent: format!("mantis/{}", env!("CARGO_PKG_VERSION")),
            auth_profile: None,
        }
    }
}

/// Probe scanner that records each result into the event log.
pub struct HttpProbeScanner {
    client: Client,
    event_store: Arc<EventStore>,
    engagement_id: EngagementId,
    signer: Arc<dyn Signer>,
    /// Auth profile to inject into every probe. Cookies are
    /// concatenated into a single `Cookie:` header; declared headers
    /// override the default `User-Agent`; query parameters are
    /// appended to the URL.
    auth_profile: Option<AuthProfile>,
}

impl std::fmt::Debug for HttpProbeScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpProbeScanner")
            .field("engagement_id", &self.engagement_id)
            .finish_non_exhaustive()
    }
}

impl HttpProbeScanner {
    pub fn new(
        event_store: Arc<EventStore>,
        engagement_id: EngagementId,
        signer: Arc<dyn Signer>,
        config: ProbeConfig,
    ) -> Result<Self, ScannerError> {
        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent(config.user_agent)
            .redirect(reqwest::redirect::Policy::none())
            // Phase 0: scanners may hit self-signed certs in test
            // environments. Production engagements should re-evaluate.
            .danger_accept_invalid_certs(true);
        if let Some(proxy_url) = config.proxy {
            let proxy = reqwest::Proxy::all(&proxy_url)
                .map_err(|e| ScannerError::InvalidProxy(e.to_string()))?;
            builder = builder.proxy(proxy);
        }
        let client = builder.build()?;
        Ok(Self {
            client,
            event_store,
            engagement_id,
            signer,
            auth_profile: config.auth_profile,
        })
    }

    /// Replace this scanner's auth profile at runtime. Useful when
    /// the orchestrator captures fresh credentials mid-engagement
    /// (e.g. after token refresh).
    pub fn set_auth_profile(&mut self, profile: Option<AuthProfile>) {
        self.auth_profile = profile;
    }

    /// Build a request builder for `target` with the configured auth
    /// profile applied. Cookies join into one header; named headers
    /// from the profile override scanner defaults.
    fn request_with_auth(&self, target: &ProbeTarget) -> reqwest::RequestBuilder {
        let mut url = target.url();
        // Append query parameters from the auth profile directly into
        // `url`. The prior implementation built a Vec<String> via map+
        // collect, joined it, then format!-ed into a fresh String — at
        // least 2 + 2*query.len() string allocations. This version
        // makes the same number of urlencode allocations (unavoidable)
        // but no intermediate Vec, no extra format! pass.
        if let Some(profile) = &self.auth_profile {
            if !profile.query.is_empty() {
                url.push(if url.contains('?') { '&' } else { '?' });
                let mut first = true;
                for (k, v) in &profile.query {
                    if !first {
                        url.push('&');
                    }
                    first = false;
                    url.push_str(&urlencode(k.as_str()));
                    url.push('=');
                    url.push_str(&urlencode(v.as_str()));
                }
            }
        }
        let mut req = self.client.get(url);
        if let Some(profile) = &self.auth_profile {
            for h in &profile.headers {
                req = req.header(h.name.as_str(), h.value.as_str());
            }
            if !profile.cookies.is_empty() {
                // Pre-size the header string to avoid mid-build realloc.
                // Format is `name=value; name=value; …`; per cookie we
                // need name + 1 ('=') + value + 2 ("; ") but the last
                // skips the separator. Over-estimating slightly is
                // cheaper than reallocing.
                let cap: usize = profile
                    .cookies
                    .iter()
                    .map(|c| c.name.len() + c.value.len() + 3)
                    .sum();
                let mut cookie_header = String::with_capacity(cap);
                let mut first = true;
                for c in &profile.cookies {
                    if !first {
                        cookie_header.push_str("; ");
                    }
                    first = false;
                    cookie_header.push_str(&c.name);
                    cookie_header.push('=');
                    cookie_header.push_str(&c.value);
                }
                req = req.header(reqwest::header::COOKIE, cookie_header);
            }
        }
        req
    }

    /// Probe one target, return the parsed [`Surface`] without writing
    /// to the event store. Used by tests.
    pub async fn probe_no_log(&self, target: &ProbeTarget) -> Result<Surface, ScannerError> {
        let response = self.request_with_auth(target).send().await?;
        let status = response.status().as_u16();
        let server = response
            .headers()
            .get(reqwest::header::SERVER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());
        let content_length = response.content_length();
        let tech_hints = fingerprint(&response, server.as_deref());
        Ok(Surface {
            target: target.clone(),
            status,
            server,
            content_length,
            tech_hints,
        })
    }

    /// Probe one target and persist the result as a `SurfaceDiscovered`
    /// event.
    pub async fn probe(&self, target: &ProbeTarget) -> Result<Surface, ScannerError> {
        let surface = self.probe_no_log(target).await?;
        let event = EventKind::SurfaceDiscovered {
            host: surface.target.host.clone(),
            port: surface.target.port,
            scheme: surface.target.scheme.clone(),
            path: surface.target.path.clone(),
            status: surface.status,
            server: surface.server.clone(),
            content_length: surface.content_length,
            tech_hints: surface.tech_hints.clone(),
        };
        self.event_store
            .append(self.engagement_id, event, self.signer.as_ref())?;
        Ok(surface)
    }

    /// Probe every target sequentially. Errors on individual targets
    /// are logged and skipped; the rest continue.
    pub async fn probe_all(&self, targets: &[ProbeTarget]) -> Vec<Surface> {
        let mut out = Vec::with_capacity(targets.len());
        for target in targets {
            match self.probe(target).await {
                Ok(s) => {
                    debug!(host = %target.host, status = s.status, "probe ok");
                    out.push(s);
                }
                Err(e) => warn!(host = %target.host, error = %e, "probe failed"),
            }
        }
        out
    }
}

/// Minimal URL-component encoder for the auth-query injection path.
/// We do NOT pull a full URL crate just for this; `%`, space, and
/// the standard reserved set are escaped.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                let _ = write!(out, "{:02X}", b);
            }
        }
    }
    out
}

/// Best-effort technology fingerprint based on response headers and
/// server identity. Phase 0 catalog covers the most common cases;
/// later milestones move to a richer signature library.
fn fingerprint(response: &reqwest::Response, server: Option<&str>) -> Vec<String> {
    let mut hints = vec![];
    let lower_server = server.map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    for needle in [
        "nginx",
        "apache",
        "iis",
        "caddy",
        "envoy",
        "cloudflare",
        "fastly",
        "akamai",
        "node",
        "gunicorn",
        "uvicorn",
        "tomcat",
        "jetty",
    ] {
        if lower_server.contains(needle) {
            hints.push(format!("server:{needle}"));
        }
    }
    for header in [
        "x-powered-by",
        "x-aspnet-version",
        "x-runtime",
        "x-drupal-cache",
        "x-generator",
    ] {
        if response.headers().contains_key(header) {
            hints.push(format!("header:{header}"));
        }
    }
    if let Some(ct) = response.headers().get(reqwest::header::CONTENT_TYPE) {
        let s = ct.to_str().unwrap_or("");
        if s.contains("application/json") {
            hints.push("content:json".into());
        }
        if s.contains("text/html") {
            hints.push("content:html".into());
        }
        if s.contains("graphql") {
            hints.push("content:graphql".into());
        }
    }
    hints
}
