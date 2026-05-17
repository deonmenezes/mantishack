//! Async invocations of external recon tools.
//!
//! Each runner:
//! 1. Returns [`ToolError::NotInstalled`] immediately if the binary
//!    isn't on PATH (no detection round-trip needed — caller can
//!    just try the runner and fall back on `NotInstalled`).
//! 2. Spawns the tool with a hard timeout.
//! 3. Parses canonical line-delimited output into owned Rust types.
//!
//! Output is intentionally minimal — these runners are gateways,
//! not analysis. The orchestrator folds their results into Mantis's
//! own surface set + hypothesis catalog.

use crate::inventory::{ToolInfo, ToolKind, ToolInventory};
use crate::ToolError;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Verify the tool is installed and return its `ToolInfo`. Used
/// internally by every runner; callers can also use it directly.
fn require(kind: ToolKind) -> Result<ToolInfo, ToolError> {
    let inv = ToolInventory::scan();
    match inv.get(kind) {
        Some(info) if info.installed => Ok(info.clone()),
        _ => Err(ToolError::NotInstalled(kind.binary_name().into())),
    }
}

async fn run_with_stdin(
    binary: &str,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
    timeout: Duration,
) -> Result<(i32, Vec<u8>, Vec<u8>), ToolError> {
    let mut cmd = Command::new(binary);
    cmd.args(args);
    if stdin_bytes.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| ToolError::Failed {
        tool: binary.into(),
        exit_code: None,
        stderr: e.to_string(),
    })?;
    if let Some(bytes) = stdin_bytes {
        if let Some(mut sin) = child.stdin.take() {
            sin.write_all(bytes).await.ok();
            // Drop closes the pipe so the tool sees EOF.
        }
    }
    let result = tokio::time::timeout(timeout, child.wait_with_output()).await;
    let output = match result {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return Err(ToolError::Failed {
                tool: binary.into(),
                exit_code: None,
                stderr: e.to_string(),
            })
        }
        Err(_) => return Err(ToolError::Timeout(binary.into())),
    };
    let exit = output.status.code().unwrap_or(-1);
    Ok((exit, output.stdout, output.stderr))
}

// ---------- subfinder ----------

/// Run subfinder on `domain` and return discovered subdomains.
pub async fn run_subfinder(domain: &str) -> Result<Vec<String>, ToolError> {
    let info = require(ToolKind::Subfinder)?;
    let path = info.path.as_deref().unwrap_or("subfinder");
    let (_exit, stdout, _stderr) =
        run_with_stdin(path, &["-d", domain, "-silent"], None, DEFAULT_TIMEOUT).await?;
    let out = parse_lines(&stdout);
    Ok(out)
}

// ---------- httpx ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpxResult {
    pub url: String,
    pub status_code: Option<u16>,
    pub title: Option<String>,
    pub tech: Vec<String>,
}

/// Run httpx over a list of hosts/URLs (one per line via stdin)
/// and return the parsed JSON-line output.
pub async fn run_httpx(hosts: &[String]) -> Result<Vec<HttpxResult>, ToolError> {
    let info = require(ToolKind::Httpx)?;
    let path = info.path.as_deref().unwrap_or("httpx");
    let stdin = hosts.join("\n").into_bytes();
    let (_exit, stdout, _stderr) = run_with_stdin(
        path,
        &["-silent", "-json", "-title", "-tech-detect", "-status-code"],
        Some(&stdin),
        DEFAULT_TIMEOUT,
    )
    .await?;
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(&stdout).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        out.push(HttpxResult {
            url: v.get("url").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            status_code: v
                .get("status_code")
                .or_else(|| v.get("status-code"))
                .and_then(|x| x.as_u64())
                .map(|n| n as u16),
            title: v.get("title").and_then(|x| x.as_str()).map(str::to_string),
            tech: v
                .get("tech")
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    Ok(out)
}

// ---------- nuclei ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NucleiHit {
    pub template_id: String,
    pub severity: String,
    pub host: String,
    pub matched_at: String,
    pub info_name: Option<String>,
}

/// Run nuclei over a set of URLs. Lazy on templates — we pass
/// `-silent -jsonl` and let the operator's local template registry
/// decide what to fire.
pub async fn run_nuclei(urls: &[String]) -> Result<Vec<NucleiHit>, ToolError> {
    let info = require(ToolKind::Nuclei)?;
    let path = info.path.as_deref().unwrap_or("nuclei");
    let stdin = urls.join("\n").into_bytes();
    let (_exit, stdout, _stderr) = run_with_stdin(
        path,
        &["-silent", "-jsonl"],
        Some(&stdin),
        Duration::from_secs(300), // nuclei runs are slow
    )
    .await?;
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(&stdout).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        out.push(NucleiHit {
            template_id: v.get("template-id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            severity: v
                .get("info")
                .and_then(|i| i.get("severity"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            host: v.get("host").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            matched_at: v.get("matched-at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            info_name: v
                .get("info")
                .and_then(|i| i.get("name"))
                .and_then(|x| x.as_str())
                .map(str::to_string),
        });
    }
    Ok(out)
}

// ---------- dnsx ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub host: String,
    pub a: Vec<String>,
    pub cname: Vec<String>,
}

pub async fn run_dnsx(domains: &[String]) -> Result<Vec<DnsRecord>, ToolError> {
    let info = require(ToolKind::Dnsx)?;
    let path = info.path.as_deref().unwrap_or("dnsx");
    let stdin = domains.join("\n").into_bytes();
    let (_exit, stdout, _stderr) = run_with_stdin(
        path,
        &["-silent", "-json", "-a", "-cname"],
        Some(&stdin),
        DEFAULT_TIMEOUT,
    )
    .await?;
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(&stdout).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        out.push(DnsRecord {
            host: v.get("host").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            a: v.get("a").and_then(|x| x.as_array()).map(|a| {
                a.iter()
                    .filter_map(|t| t.as_str().map(str::to_string))
                    .collect()
            }).unwrap_or_default(),
            cname: v.get("cname").and_then(|x| x.as_array()).map(|a| {
                a.iter()
                    .filter_map(|t| t.as_str().map(str::to_string))
                    .collect()
            }).unwrap_or_default(),
        });
    }
    Ok(out)
}

// ---------- tlsx ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsRecord {
    pub host: String,
    pub issuer: Option<String>,
    pub subject_cn: Option<String>,
    pub not_after: Option<String>,
    pub sans: Vec<String>,
}

pub async fn run_tlsx(hosts: &[String]) -> Result<Vec<TlsRecord>, ToolError> {
    let info = require(ToolKind::Tlsx)?;
    let path = info.path.as_deref().unwrap_or("tlsx");
    let stdin = hosts.join("\n").into_bytes();
    let (_exit, stdout, _stderr) = run_with_stdin(
        path,
        &["-silent", "-json", "-san", "-cn", "-not-after"],
        Some(&stdin),
        DEFAULT_TIMEOUT,
    )
    .await?;
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(&stdout).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        out.push(TlsRecord {
            host: v.get("host").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            issuer: v
                .get("issuer_cn")
                .or_else(|| v.get("issuer-cn"))
                .and_then(|x| x.as_str())
                .map(str::to_string),
            subject_cn: v
                .get("subject_cn")
                .or_else(|| v.get("subject-cn"))
                .and_then(|x| x.as_str())
                .map(str::to_string),
            not_after: v
                .get("not_after")
                .or_else(|| v.get("not-after"))
                .and_then(|x| x.as_str())
                .map(str::to_string),
            sans: v
                .get("subject_an")
                .or_else(|| v.get("subject-an"))
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    Ok(out)
}

// ---------- katana ----------

pub async fn run_katana(seed_url: &str) -> Result<Vec<String>, ToolError> {
    let info = require(ToolKind::Katana)?;
    let path = info.path.as_deref().unwrap_or("katana");
    let (_exit, stdout, _stderr) = run_with_stdin(
        path,
        &["-u", seed_url, "-silent", "-d", "2"],
        None,
        Duration::from_secs(120),
    )
    .await?;
    Ok(parse_lines(&stdout))
}

// ---------- jwt_tool ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtDecode {
    pub header_json: String,
    pub payload_json: String,
    pub raw_output: String,
}

/// Decode a JWT with ticarpi/jwt_tool. We don't drive its fuzzing
/// modes here — just a structured inspection.
pub async fn run_jwt_tool_decode(jwt: &str) -> Result<JwtDecode, ToolError> {
    let info = require(ToolKind::JwtTool)?;
    let path = info.path.as_deref().unwrap_or("jwt_tool");
    let (_exit, stdout, _stderr) =
        run_with_stdin(path, &[jwt], None, DEFAULT_TIMEOUT).await?;
    let raw = String::from_utf8_lossy(&stdout).to_string();
    // jwt_tool prints prose. We capture the whole thing and let the
    // caller pattern-match. We also try to pull header/payload JSON
    // blocks heuristically.
    let header_json = extract_json_block(&raw, "Token header:").unwrap_or_default();
    let payload_json = extract_json_block(&raw, "Token payload:").unwrap_or_default();
    Ok(JwtDecode {
        header_json,
        payload_json,
        raw_output: raw,
    })
}

fn extract_json_block(haystack: &str, anchor: &str) -> Option<String> {
    let start = haystack.find(anchor)?;
    let after = &haystack[start + anchor.len()..];
    let brace_start = after.find('{')?;
    let mut depth = 0i32;
    for (i, c) in after[brace_start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(after[brace_start..brace_start + i + 1].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_lines(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    text.lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lines_filters_blanks() {
        let out = parse_lines(b"a.example.com\n\nb.example.com\n   \nc.example.com");
        assert_eq!(out, vec!["a.example.com", "b.example.com", "c.example.com"]);
    }

    #[test]
    fn extract_json_block_handles_nested() {
        let s = "Token header: {\"alg\":\"HS256\",\"nested\":{\"k\":\"v\"}} more text";
        let block = extract_json_block(s, "Token header:");
        assert_eq!(block.as_deref(), Some("{\"alg\":\"HS256\",\"nested\":{\"k\":\"v\"}}"));
    }

    #[test]
    fn extract_json_block_returns_none_when_no_brace() {
        assert!(extract_json_block("Token header: nope", "Token header:").is_none());
    }

    #[tokio::test]
    async fn missing_tool_returns_not_installed() {
        // We invoke a clearly-not-installed binary by naming a kind
        // whose binary almost certainly isn't on `PATH` in CI. We
        // rely on the inventory probe returning installed=false.
        let result = run_subfinder("example.com").await;
        match result {
            Err(ToolError::NotInstalled(name)) => assert_eq!(name, "subfinder"),
            // If subfinder IS installed locally, the call may succeed
            // — that's also fine. We're not asserting unconditional
            // failure, just that the error variant is correct when it
            // does fail.
            Ok(_) => {}
            Err(other) => panic!("expected NotInstalled or Ok, got {other:?}"),
        }
    }

    #[test]
    fn httpx_result_json_round_trip() {
        let r = HttpxResult {
            url: "https://example.com".into(),
            status_code: Some(200),
            title: Some("Example".into()),
            tech: vec!["Nginx".into(), "React".into()],
        };
        let j = serde_json::to_string(&r).unwrap();
        let back: HttpxResult = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn nuclei_hit_json_round_trip() {
        let h = NucleiHit {
            template_id: "exposed-config".into(),
            severity: "high".into(),
            host: "https://example.com".into(),
            matched_at: "https://example.com/.env".into(),
            info_name: Some("Exposed .env".into()),
        };
        let j = serde_json::to_string(&h).unwrap();
        let back: NucleiHit = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }
}
