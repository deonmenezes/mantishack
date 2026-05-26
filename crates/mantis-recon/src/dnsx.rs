//! dnsx-style async DNS resolver — A/AAAA records.
//!
//! Wraps `tokio::net::lookup_host` (which delegates to the OS
//! resolver) for the common case. CNAME/MX/NS/TXT support would need
//! a real DNS client (`hickory-resolver`) and is intentionally
//! out-of-scope for the initial cut.
//!
//! Multiple hosts are resolved concurrently with a semaphore-bounded
//! window so we don't blow past `ulimit -n` on big sweeps.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResolution {
    pub host: String,
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Resolve `hosts` concurrently. `concurrency` caps how many in
/// flight at once; `timeout` applies per host.
pub async fn resolve_a(
    hosts: &[String],
    concurrency: usize,
    timeout: Duration,
) -> Vec<DnsResolution> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = Vec::with_capacity(hosts.len());
    for host in hosts {
        let sem = sem.clone();
        let host = host.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore not closed");
            resolve_one(&host, timeout).await
        }));
    }
    let mut out = Vec::with_capacity(tasks.len());
    for t in tasks {
        match t.await {
            Ok(r) => out.push(r),
            Err(e) => out.push(DnsResolution {
                host: String::new(),
                a: Vec::new(),
                aaaa: Vec::new(),
                error: Some(format!("join: {e}")),
            }),
        }
    }
    out
}

async fn resolve_one(host: &str, timeout: Duration) -> DnsResolution {
    // Cow avoids the host.to_string() clone on the common path where
    // `host` already carries a port suffix (e.g. "example.com:443").
    // Only the no-port branch needs to allocate the ":0" variant.
    let probe_host: std::borrow::Cow<'_, str> = if host.contains(':') {
        std::borrow::Cow::Borrowed(host)
    } else {
        std::borrow::Cow::Owned(format!("{host}:0"))
    };
    let lookup = tokio::time::timeout(timeout, tokio::net::lookup_host(probe_host.as_ref())).await;
    match lookup {
        Ok(Ok(iter)) => {
            let mut a = Vec::new();
            let mut aaaa = Vec::new();
            for addr in iter {
                match addr.ip() {
                    IpAddr::V4(v) => {
                        let s = v.to_string();
                        if !a.contains(&s) {
                            a.push(s);
                        }
                    }
                    IpAddr::V6(v) => {
                        let s = v.to_string();
                        if !aaaa.contains(&s) {
                            aaaa.push(s);
                        }
                    }
                }
            }
            a.sort();
            aaaa.sort();
            DnsResolution {
                host: strip_port(host).to_string(),
                a,
                aaaa,
                error: None,
            }
        }
        Ok(Err(e)) => DnsResolution {
            host: strip_port(host).to_string(),
            a: Vec::new(),
            aaaa: Vec::new(),
            error: Some(e.to_string()),
        },
        Err(_) => DnsResolution {
            host: strip_port(host).to_string(),
            a: Vec::new(),
            aaaa: Vec::new(),
            error: Some("timeout".into()),
        },
    }
}

fn strip_port(host: &str) -> &str {
    match host.rfind(':') {
        Some(idx) => &host[..idx],
        None => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_port_removes_trailing_port() {
        assert_eq!(strip_port("example.com:8080"), "example.com");
        assert_eq!(strip_port("example.com"), "example.com");
    }

    #[test]
    fn dns_resolution_round_trips_through_json() {
        let r = DnsResolution {
            host: "example.com".into(),
            a: vec!["93.184.216.34".into()],
            aaaa: vec!["2606:2800:220:1:248:1893:25c8:1946".into()],
            error: None,
        };
        let j = serde_json::to_string(&r).unwrap();
        let back: DnsResolution = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[tokio::test]
    async fn resolve_a_returns_one_entry_per_host_in_order() {
        // We use bogus hosts that should fail fast. We're verifying
        // the shape of the result, not actual resolution.
        let hosts = vec![
            "mantis-test-bogus-1.invalid".to_string(),
            "mantis-test-bogus-2.invalid".to_string(),
        ];
        let out = resolve_a(&hosts, 4, Duration::from_secs(2)).await;
        assert_eq!(out.len(), hosts.len());
        for (i, r) in out.iter().enumerate() {
            // Each should either fail or timeout — either way, error
            // should be set OR a/aaaa empty.
            assert_eq!(r.host, strip_port(&hosts[i]));
        }
    }

    #[tokio::test]
    async fn resolve_a_handles_empty_input() {
        let out = resolve_a(&[], 4, Duration::from_secs(1)).await;
        assert!(out.is_empty());
    }
}
