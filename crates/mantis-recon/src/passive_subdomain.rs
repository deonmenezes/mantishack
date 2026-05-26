//! Passive subdomain enumeration — no packets to the target.
//!
//! Queries Certificate Transparency log aggregators (`crt.sh`) and
//! other public sources to discover hostnames that share the apex
//! domain. The target itself is never contacted.
//!
//! ## Sources
//!
//! - **crt.sh** — public CT log mirror. Returns every certificate
//!   ever issued under `*.domain`. We deduplicate by SAN.
//! - **HackerTarget** — free hostname API (rate-limited; we honor
//!   the rate limit by not retrying on 429).
//! - **Alienvault OTX** — passive DNS dataset.
//!
//! Sources can be enabled selectively via [`enumerate_passive`].

use crate::ReconError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;

/// Which passive sources to query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PassiveSource {
    Crtsh,
    HackerTarget,
    AlienvaultOtx,
}

impl PassiveSource {
    pub fn all() -> &'static [PassiveSource] {
        &[
            PassiveSource::Crtsh,
            PassiveSource::HackerTarget,
            PassiveSource::AlienvaultOtx,
        ]
    }

    pub fn slug(self) -> &'static str {
        // Must match the serde kebab-case representation so a slug
        // round-trips through serialization.
        match self {
            PassiveSource::Crtsh => "crtsh",
            PassiveSource::HackerTarget => "hacker-target",
            PassiveSource::AlienvaultOtx => "alienvault-otx",
        }
    }
}

/// One discovered subdomain with provenance — which source(s) saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubdomainRecord {
    pub host: String,
    pub sources: Vec<PassiveSource>,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Enumerate subdomains for `apex` using the given passive sources.
///
/// Errors from individual sources are swallowed (logged via
/// `tracing::warn!`) so a single broken source doesn't kill the whole
/// pipeline. The returned `Vec` is sorted by host name.
pub async fn enumerate_passive(
    client: &reqwest::Client,
    apex: &str,
    sources: &[PassiveSource],
) -> Vec<SubdomainRecord> {
    let apex = apex.trim().trim_start_matches('.').to_ascii_lowercase();
    let mut per_source: Vec<(PassiveSource, BTreeSet<String>)> = Vec::new();

    for &src in sources {
        let res = match src {
            PassiveSource::Crtsh => query_crtsh(client, &apex).await,
            PassiveSource::HackerTarget => query_hackertarget(client, &apex).await,
            PassiveSource::AlienvaultOtx => query_alienvault(client, &apex).await,
        };
        match res {
            Ok(hosts) => per_source.push((src, hosts)),
            Err(e) => tracing::warn!(source = src.slug(), err = %e, "passive source failed"),
        }
    }

    // Merge by host.
    let mut merged: std::collections::BTreeMap<String, Vec<PassiveSource>> =
        std::collections::BTreeMap::new();
    for (src, hosts) in per_source {
        for host in hosts {
            merged.entry(host).or_default().push(src);
        }
    }
    merged
        .into_iter()
        .map(|(host, mut sources)| {
            sources.sort_unstable();
            sources.dedup();
            SubdomainRecord { host, sources }
        })
        .collect()
}

async fn query_crtsh(
    client: &reqwest::Client,
    apex: &str,
) -> Result<BTreeSet<String>, ReconError> {
    let url = format!("https://crt.sh/?q=%25.{apex}&output=json");
    let resp = client
        .get(&url)
        .header("user-agent", "mantis-recon/0.0.9")
        .timeout(DEFAULT_TIMEOUT)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(ReconError::Network(format!(
            "crt.sh returned {}",
            resp.status()
        )));
    }
    let body = resp.text().await?;
    parse_crtsh_response(&body, apex)
}

pub(crate) fn parse_crtsh_response(
    body: &str,
    apex: &str,
) -> Result<BTreeSet<String>, ReconError> {
    let docs: Vec<serde_json::Value> = serde_json::from_str(body)
        .map_err(|e| ReconError::Parse(format!("crt.sh json: {e}")))?;
    let mut out = BTreeSet::new();
    let suffix = format!(".{apex}");
    for doc in docs {
        for field in ["name_value", "common_name"] {
            if let Some(s) = doc.get(field).and_then(|v| v.as_str()) {
                // crt.sh sometimes returns multiple names joined by \n
                for line in s.split('\n') {
                    let host = line
                        .trim()
                        .trim_start_matches("*.")
                        .to_ascii_lowercase();
                    if (host == apex || host.ends_with(&suffix)) && valid_hostname(&host) {
                        out.insert(host);
                    }
                }
            }
        }
    }
    Ok(out)
}

async fn query_hackertarget(
    client: &reqwest::Client,
    apex: &str,
) -> Result<BTreeSet<String>, ReconError> {
    let url = format!("https://api.hackertarget.com/hostsearch/?q={apex}");
    let resp = client
        .get(&url)
        .header("user-agent", "mantis-recon/0.0.9")
        .timeout(DEFAULT_TIMEOUT)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(ReconError::Network(format!(
            "hackertarget returned {}",
            resp.status()
        )));
    }
    let body = resp.text().await?;
    Ok(parse_hackertarget_response(&body, apex))
}

pub(crate) fn parse_hackertarget_response(body: &str, apex: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let suffix = format!(".{apex}");
    for line in body.lines() {
        let host = line.split(',').next().unwrap_or("").trim().to_ascii_lowercase();
        if host.is_empty() {
            continue;
        }
        if (host == apex || host.ends_with(&suffix)) && valid_hostname(&host) {
            out.insert(host);
        }
    }
    out
}

async fn query_alienvault(
    client: &reqwest::Client,
    apex: &str,
) -> Result<BTreeSet<String>, ReconError> {
    let url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns");
    let resp = client
        .get(&url)
        .header("user-agent", "mantis-recon/0.0.9")
        .timeout(DEFAULT_TIMEOUT)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(ReconError::Network(format!(
            "alienvault returned {}",
            resp.status()
        )));
    }
    let body = resp.text().await?;
    parse_alienvault_response(&body, apex)
}

pub(crate) fn parse_alienvault_response(
    body: &str,
    apex: &str,
) -> Result<BTreeSet<String>, ReconError> {
    let doc: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| ReconError::Parse(format!("alienvault json: {e}")))?;
    let mut out = BTreeSet::new();
    let suffix = format!(".{apex}");
    if let Some(records) = doc.get("passive_dns").and_then(|v| v.as_array()) {
        for r in records {
            if let Some(host) = r.get("hostname").and_then(|v| v.as_str()) {
                let host = host.trim().to_ascii_lowercase();
                if (host == apex || host.ends_with(&suffix)) && valid_hostname(&host) {
                    out.insert(host);
                }
            }
        }
    }
    Ok(out)
}

/// Loose hostname validation — labels of 1..=63 of `[a-z0-9-]`,
/// joined by `.`, total length ≤ 253. Wildcard `*` is rejected.
pub fn valid_hostname(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 || s.contains("..") || s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        for c in label.chars() {
            if !(c.is_ascii_alphanumeric() || c == '-') {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_hostname_accepts_typical_names() {
        assert!(valid_hostname("example.com"));
        assert!(valid_hostname("www.example.com"));
        assert!(valid_hostname("a-b-c.sub.example.io"));
        assert!(valid_hostname("xn--ls8h.example"));
    }

    #[test]
    fn valid_hostname_rejects_wildcards_and_bad_shapes() {
        assert!(!valid_hostname(""));
        assert!(!valid_hostname("."));
        assert!(!valid_hostname("*.example.com"));
        assert!(!valid_hostname("-leading.example.com"));
        assert!(!valid_hostname("trailing-.example.com"));
        assert!(!valid_hostname("double..dot.com"));
        assert!(!valid_hostname(".leading.dot"));
        assert!(!valid_hostname("trailing.dot."));
        assert!(!valid_hostname(&"a".repeat(254)));
        assert!(!valid_hostname(&format!("{}.com", "a".repeat(64))));
    }

    #[test]
    fn parse_crtsh_response_dedupes_and_filters_to_apex() {
        // Sample of the crt.sh JSON shape.
        let body = r#"[
            {"name_value":"www.example.com\nadmin.example.com","common_name":"www.example.com"},
            {"name_value":"*.example.com","common_name":"example.com"},
            {"name_value":"www.example.com"},
            {"name_value":"sneaky.evil.org","common_name":"sneaky.evil.org"}
        ]"#;
        let out = parse_crtsh_response(body, "example.com").unwrap();
        assert!(out.contains("www.example.com"));
        assert!(out.contains("admin.example.com"));
        assert!(out.contains("example.com"));
        // Wildcard stripped, then matched. Should NOT add `*.example.com`.
        assert!(!out.contains("*.example.com"));
        // Out-of-scope host filtered.
        assert!(!out.contains("sneaky.evil.org"));
    }

    #[test]
    fn parse_crtsh_response_handles_empty_array() {
        let out = parse_crtsh_response("[]", "example.com").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn parse_crtsh_response_returns_error_on_bad_json() {
        let r = parse_crtsh_response("not-json", "x.com");
        assert!(r.is_err());
    }

    #[test]
    fn parse_hackertarget_response_extracts_hostname_column() {
        let body = "www.example.com,93.184.216.34\nadmin.example.com,1.2.3.4\nout.of.scope.org,5.6.7.8\n";
        let out = parse_hackertarget_response(body, "example.com");
        assert!(out.contains("www.example.com"));
        assert!(out.contains("admin.example.com"));
        assert!(!out.contains("out.of.scope.org"));
    }

    #[test]
    fn parse_alienvault_response_extracts_hostname_field() {
        let body = r#"{
            "passive_dns":[
                {"hostname":"alpha.example.com","record_type":"A"},
                {"hostname":"beta.example.com","record_type":"A"},
                {"hostname":"out.of.scope.org","record_type":"A"}
            ]
        }"#;
        let out = parse_alienvault_response(body, "example.com").unwrap();
        assert!(out.contains("alpha.example.com"));
        assert!(out.contains("beta.example.com"));
        assert!(!out.contains("out.of.scope.org"));
    }

    #[test]
    fn parse_alienvault_response_missing_field_returns_empty() {
        let body = r#"{"unrelated":[1,2,3]}"#;
        let out = parse_alienvault_response(body, "example.com").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn passive_source_all_round_trips_through_serde() {
        for &s in PassiveSource::all() {
            let j = serde_json::to_string(&s).unwrap();
            let back: PassiveSource = serde_json::from_str(&j).unwrap();
            assert_eq!(s, back);
            assert!(j.contains(s.slug()));
        }
    }

    #[test]
    fn subdomain_record_serializes() {
        let r = SubdomainRecord {
            host: "example.com".into(),
            sources: vec![PassiveSource::Crtsh, PassiveSource::AlienvaultOtx],
        };
        let j = serde_json::to_string(&r).unwrap();
        let back: SubdomainRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
