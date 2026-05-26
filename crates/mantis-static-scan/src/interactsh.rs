//! Interactsh adapter — out-of-band interaction server for verifying
//! blind vulnerability classes.
//!
//! Interactsh (https://github.com/projectdiscovery/interactsh) is the
//! canonical OOB primitive for security research: register a unique
//! subdomain, embed it in a payload, watch for DNS / HTTP / SMTP
//! callbacks. It's how you confirm blind SSRF (the target makes an
//! outbound request to your listener), blind command injection (a
//! shell payload curls your URL), blind XXE (the parser dereferences
//! an external entity hosted on your listener), and any other class
//! where the target swallows the in-band response.
//!
//! Without OOB, Mantis cannot detect these classes. The xbow-
//! benchmark scoreboard reflects that: 0% on SSRF (3 attempts),
//! 0% on XXE (3 attempts), 0% on command_injection (11 attempts).
//! Adding this adapter is a precondition for moving those numbers.
//!
//! Architecture: this adapter does NOT host its own DNS/HTTP server
//! — it shells out to `interactsh-client`, the upstream binary,
//! which handles all the protocol details (DNS authority, HTTP
//! server, TLS via Let's Encrypt, callback persistence). The
//! adapter:
//!   1. Spawns `interactsh-client -json -v -server <server>`.
//!    2. Reads the assigned listener URL from the first JSON line of
//!       stdout (`{"url":"<id>.oast.fun"}`).
//!   3. Polls until `poll_timeout` for callback events, emitting
//!       each as a `Finding` with `kind: "oob_callback"`.
//!
//! Install:
//! ```text
//! brew install interactsh-client
//! # or
//! go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
//! ```

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

use crate::{binary_available, Finding, ScanError, Severity};

const BIN: &str = "interactsh-client";
const INSTALL_HINT: &str =
    "`brew install interactsh-client` (or `go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest`)";
/// Public OAST server defaults — interactsh-client cycles across
/// these automatically. Operators in air-gapped or strict-scope
/// environments should pass `with_server(custom)`.
const DEFAULT_SERVER: &str = "oast.fun,oast.live,oast.site,oast.online,oast.me,oast.pro";

#[derive(Debug, Clone)]
pub struct InteractshAdapter {
    binary: String,
    /// Comma-separated list of interactsh servers. Defaults to the
    /// public projectdiscovery OAST domains.
    server: String,
    /// Total time to wait for callbacks after registering the
    /// listener URL. The adapter returns the findings collected
    /// up to this point — late callbacks are lost.
    poll_timeout: Duration,
    /// Stop polling early if at least one callback arrived AND
    /// `idle_drain` has elapsed since the last callback. Lets a
    /// fast-firing payload return immediately while still giving
    /// slower exploits the full `poll_timeout`.
    idle_drain: Duration,
}

impl InteractshAdapter {
    pub fn new() -> Self {
        Self {
            binary: BIN.into(),
            server: DEFAULT_SERVER.into(),
            poll_timeout: Duration::from_secs(60),
            idle_drain: Duration::from_secs(10),
        }
    }

    pub fn with_binary(mut self, b: impl Into<String>) -> Self {
        self.binary = b.into();
        self
    }

    pub fn with_server(mut self, server: impl Into<String>) -> Self {
        self.server = server.into();
        self
    }

    pub fn with_poll_timeout(mut self, t: Duration) -> Self {
        self.poll_timeout = t;
        self
    }

    pub fn with_idle_drain(mut self, t: Duration) -> Self {
        self.idle_drain = t;
        self
    }

    pub async fn ensure_available(&self) -> Result<(), ScanError> {
        if binary_available(&self.binary).await {
            Ok(())
        } else {
            Err(ScanError::Unavailable {
                tool: BIN,
                install_hint: INSTALL_HINT,
            })
        }
    }

    /// Open a listener and return its callback URL. The session
    /// continues until [`InteractshSession::collect`] is called,
    /// at which point we drain pending callbacks and shut down
    /// the subprocess.
    ///
    /// Typical usage from a hunter:
    /// ```ignore
    /// let adapter = InteractshAdapter::new();
    /// let mut session = adapter.start_listener().await?;
    /// let url = session.url().to_string();
    /// // Inject `url` into payloads, send them at the target...
    /// let findings = session.collect().await?;
    /// ```
    pub async fn start_listener(&self) -> Result<InteractshSession, ScanError> {
        self.ensure_available().await?;

        let mut cmd = Command::new(&self.binary);
        cmd.arg("-json")
            .arg("-v")
            .arg("-server")
            .arg(&self.server);
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        let mut child = cmd
            .spawn()
            .map_err(|e| ScanError::Spawn { tool: BIN, source: e })?;

        // The first JSON line of stdout carries the registered URL.
        // We block briefly to acquire it; if it doesn't arrive
        // within 10s, the binary is wedged and we bail out.
        let stdout = child.stdout.take().ok_or_else(|| ScanError::Spawn {
            tool: BIN,
            source: std::io::Error::other("interactsh stdout unavailable"),
        })?;
        let mut reader = BufReader::new(stdout);
        let mut url = String::new();
        let acquire = tokio::time::timeout(
            Duration::from_secs(10),
            extract_listener_url(&mut reader),
        )
        .await
        .map_err(|_| ScanError::Timeout {
            tool: BIN,
            seconds: 10,
        })??;
        url = acquire;

        Ok(InteractshSession {
            child,
            reader,
            url,
            poll_timeout: self.poll_timeout,
            idle_drain: self.idle_drain,
        })
    }
}

impl Default for InteractshAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Active OOB listener — holds the subprocess + a buffered reader
/// over its stdout.
pub struct InteractshSession {
    child: Child,
    reader: BufReader<tokio::process::ChildStdout>,
    url: String,
    poll_timeout: Duration,
    idle_drain: Duration,
}

impl InteractshSession {
    /// The registered callback URL (e.g. `xyz123.oast.fun`). Embed
    /// this in payloads.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Drain pending callbacks. Returns once one of:
    ///   - `poll_timeout` total wall-clock has elapsed
    ///   - the listener has been idle for `idle_drain` AND we've
    ///     already received at least one callback
    /// then shuts down the subprocess and returns the accumulated
    /// findings.
    pub async fn collect(mut self) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();
        let started = tokio::time::Instant::now();
        let mut last_event = tokio::time::Instant::now();

        loop {
            let total = started.elapsed();
            if total >= self.poll_timeout {
                break;
            }
            if !findings.is_empty() && last_event.elapsed() >= self.idle_drain {
                break;
            }

            // Read one line with a tight timeout so the outer loop
            // can re-check budget often. interactsh-client emits
            // one JSON object per event on stdout.
            let mut line = String::new();
            let read = tokio::time::timeout(
                Duration::from_millis(500),
                self.reader.read_line(&mut line),
            )
            .await;

            match read {
                Ok(Ok(0)) => break, // child exited
                Ok(Ok(_)) => {
                    if let Some(f) = parse_interactsh_event(line.trim(), &self.url) {
                        findings.push(f);
                        last_event = tokio::time::Instant::now();
                    }
                }
                Ok(Err(e)) => {
                    return Err(ScanError::Spawn { tool: BIN, source: e });
                }
                Err(_) => {
                    // Timeout on a single read — fine, loop again.
                }
            }
        }

        // Best-effort cleanup of the child.
        let _ = self.child.kill().await;
        Ok(findings)
    }
}

/// Read lines from `interactsh-client` until we see one with a
/// `url` field — that's the registered listener URL.
async fn extract_listener_url(
    reader: &mut BufReader<tokio::process::ChildStdout>,
) -> Result<String, ScanError> {
    let mut line = String::new();
    for _ in 0..50 {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| ScanError::Spawn { tool: BIN, source: e })?;
        if n == 0 {
            return Err(ScanError::BadOutput(
                "interactsh-client exited before registering listener".into(),
            ));
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) {
            if let Some(u) = v.get("url").and_then(|x| x.as_str()) {
                return Ok(u.to_string());
            }
            // Some versions emit a status banner first; try
            // alternate field names.
            if let Some(u) = v.get("listener").and_then(|x| x.as_str()) {
                return Ok(u.to_string());
            }
        }
    }
    Err(ScanError::BadOutput(
        "interactsh-client did not emit a listener URL in the first 50 lines".into(),
    ))
}

/// Parse one stdout event line into a `Finding`. Returns `None`
/// for the listener-registration line (already consumed by
/// `extract_listener_url`) and for events without a `protocol` field.
pub(crate) fn parse_interactsh_event(line: &str, listener_url: &str) -> Option<Finding> {
    if line.is_empty() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let protocol = v.get("protocol").and_then(|x| x.as_str())?;
    let remote_addr = v
        .get("remote-address")
        .or_else(|| v.get("remote_address"))
        .and_then(|x| x.as_str())
        .unwrap_or("(unknown)");
    let full_id = v.get("full-id").and_then(|x| x.as_str()).unwrap_or("");
    let unique_id = v
        .get("unique-id")
        .or_else(|| v.get("uniqueId"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let timestamp = v
        .get("timestamp")
        .and_then(|x| x.as_str())
        .unwrap_or("");

    let title = format!("OOB {protocol} callback to {listener_url}");
    let mut desc = format!(
        "Out-of-band callback received via {protocol} from `{remote_addr}` at `{timestamp}`."
    );
    if let Some(req) = v.get("raw-request").and_then(|x| x.as_str()) {
        // Build the preview directly into desc — skips the intermediate
        // Vec<&str> + join + format!()-allocated " Request preview: …"
        // String. push_str into the existing buffer is one fewer alloc.
        desc.push_str(" Request preview: ");
        let mut first = true;
        for line in req.lines().take(3) {
            if !first {
                desc.push_str(" | ");
            }
            first = false;
            desc.push_str(line);
        }
    }

    let mut finding = Finding::new(
        "interactsh",
        "oob_callback",
        listener_url,
        Severity::Critical,
        title,
    )
    .with_description(desc)
    .with_meta("protocol", protocol)
    .with_meta("remote_address", remote_addr)
    .with_raw(v.clone());
    if !full_id.is_empty() {
        finding = finding.with_meta("full_id", full_id);
    }
    if !unique_id.is_empty() {
        finding = finding.with_meta("unique_id", unique_id);
    }
    Some(finding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_callback() {
        let line = r#"{"protocol":"http","unique-id":"abc123","full-id":"abc123def456","timestamp":"2026-05-22T10:00:00Z","remote-address":"203.0.113.10","raw-request":"GET /x HTTP/1.1\r\nHost: abc123.oast.fun\r\n\r\n"}"#;
        let finding = parse_interactsh_event(line, "abc123def456.oast.fun").unwrap();
        assert_eq!(finding.tool, "interactsh");
        assert_eq!(finding.kind, "oob_callback");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(
            finding.meta.get("protocol").map(String::as_str),
            Some("http")
        );
        assert_eq!(
            finding.meta.get("remote_address").map(String::as_str),
            Some("203.0.113.10")
        );
        assert!(finding.title.contains("http callback"));
        assert!(finding.description.contains("203.0.113.10"));
    }

    #[test]
    fn parses_dns_callback() {
        let line = r#"{"protocol":"dns","unique-id":"xyz789","full-id":"xyz789aaa","timestamp":"2026-05-22T10:00:00Z","remote-address":"1.1.1.1"}"#;
        let finding = parse_interactsh_event(line, "xyz.oast.fun").unwrap();
        assert_eq!(finding.meta.get("protocol").map(String::as_str), Some("dns"));
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn ignores_non_event_lines() {
        let banner = r#"{"url":"abc.oast.fun"}"#;
        assert!(parse_interactsh_event(banner, "abc.oast.fun").is_none());

        let empty = "";
        assert!(parse_interactsh_event(empty, "abc.oast.fun").is_none());

        let bad = "not json at all";
        assert!(parse_interactsh_event(bad, "abc.oast.fun").is_none());
    }

    #[test]
    fn smtp_callback_records_protocol() {
        let line = r#"{"protocol":"smtp","unique-id":"e","full-id":"ee","timestamp":"now","remote-address":"10.0.0.1"}"#;
        let finding = parse_interactsh_event(line, "abc.oast.fun").unwrap();
        assert_eq!(
            finding.meta.get("protocol").map(String::as_str),
            Some("smtp")
        );
    }
}
