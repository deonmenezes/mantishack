//! Claude CLI LLM adapter.
//!
//! Instead of calling the Anthropic REST API directly, this adapter
//! shells out to the local `claude` CLI in non-interactive (`--print`)
//! mode. That lets the Mantis synthesizer reuse whatever Claude Code
//! authentication the user already has — no `ANTHROPIC_API_KEY`
//! required.
//!
//! Env vars:
//! - `MANTIS_CLAUDE_CLI_BIN`            override the binary (default: `claude`)
//! - `MANTIS_CLAUDE_CLI_MODEL`          override the model (passed as `--model`)
//! - `MANTIS_CLAUDE_CLI_TIMEOUT_SECS`   per-request timeout (default: 60s)

use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::{LlmAdapter, SynthError};

const DEFAULT_BIN: &str = "claude";
const DEFAULT_TIMEOUT_SECS: u64 = 60;
/// Legacy synthesizer prompt — used when the adapter is wired into
/// the offensive pipeline (`mantis pentest` / `mantis hack`) and the
/// caller hasn't overridden the system prompt. The conversational
/// surface explicitly disables it via [`ClaudeCliAdapter::with_system_prompt(None)`]
/// so chat replies are not coerced into payload-only mode.
const SYNTHESIZER_SYSTEM_PROMPT: &str =
    "You are a payload generator for an offensive-security synthesizer. \
     Reply with ONLY the requested payload as plain text. No prose, \
     no markdown fences, no commentary, no tool calls.";

pub struct ClaudeCliAdapter {
    binary: String,
    model: Option<String>,
    timeout: Duration,
    /// `Some(prompt)` passes `--system-prompt <prompt>` to `claude`.
    /// `None` lets Claude Code use its own default — which is what
    /// the conversational chat path wants (the user's system message
    /// is already inside the flattened transcript).
    system_prompt: Option<String>,
    /// When true, strip Claude Code's session-hook / `✓ claude done`
    /// noise lines from the captured stdout before returning. On by
    /// default; disable via `with_noise_filter(false)` for tests
    /// that rely on the raw bytes.
    filter_noise: bool,
}

impl ClaudeCliAdapter {
    pub fn new() -> Self {
        let timeout_secs = std::env::var("MANTIS_CLAUDE_CLI_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
        Self {
            binary: std::env::var("MANTIS_CLAUDE_CLI_BIN").unwrap_or_else(|_| DEFAULT_BIN.into()),
            model: std::env::var("MANTIS_CLAUDE_CLI_MODEL").ok(),
            timeout: Duration::from_secs(timeout_secs),
            system_prompt: Some(SYNTHESIZER_SYSTEM_PROMPT.to_string()),
            filter_noise: true,
        }
    }

    pub fn with_binary(mut self, binary: impl Into<String>) -> Self {
        self.binary = binary.into();
        self
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the `--system-prompt` argument passed to the
    /// underlying `claude` CLI. `None` strips the argument entirely,
    /// which is what the conversational surface uses so chat replies
    /// aren't coerced into the legacy synthesizer's payload-only
    /// mode.
    pub fn with_system_prompt(mut self, system_prompt: Option<String>) -> Self {
        self.system_prompt = system_prompt;
        self
    }

    /// Toggle the post-process filter that strips Claude Code's
    /// session-hook lines (`· session hook_started`, `✓ claude
    /// done`, etc.) from captured stdout before returning. On by
    /// default; tests may disable it.
    pub fn with_noise_filter(mut self, enabled: bool) -> Self {
        self.filter_noise = enabled;
        self
    }
}

impl Default for ClaudeCliAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LlmAdapter for ClaudeCliAdapter {
    async fn complete(&self, prompt: &str) -> Result<String, SynthError> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("--print").arg("--no-session-persistence");
        if let Some(sys) = &self.system_prompt {
            cmd.arg("--system-prompt").arg(sys);
        }
        if let Some(m) = &self.model {
            cmd.arg("--model").arg(m);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| SynthError::Backend(format!("spawn `{}`: {e}", self.binary)))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(prompt.as_bytes())
                .await
                .map_err(|e| SynthError::Backend(format!("write prompt to claude cli: {e}")))?;
        }

        let out = match timeout(self.timeout, child.wait_with_output()).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => return Err(SynthError::Backend(format!("wait claude cli: {e}"))),
            Err(_) => {
                return Err(SynthError::Backend(format!(
                    "claude cli timed out after {}s",
                    self.timeout.as_secs()
                )));
            }
        };
        if !out.status.success() {
            return Err(SynthError::Backend(format!(
                "claude cli exited with status {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let raw = String::from_utf8_lossy(&out.stdout).into_owned();
        let stdout = if self.filter_noise {
            filter_claude_noise(&raw)
        } else {
            raw.trim().to_string()
        };
        if stdout.is_empty() {
            return Err(SynthError::Backend(
                "claude cli returned empty stdout".into(),
            ));
        }
        Ok(stdout)
    }
}

/// Remove Claude Code's status decorations from a captured stdout
/// blob so the chat surface doesn't surface session-hook noise as
/// part of the model's reply.
///
/// Filters (line-by-line, trimmed-leading-whitespace):
///   * `· session …`            — Claude Code session events
///   * `· claude done …`        — completion banner alt form
///   * `✓ claude done …`        — completion banner with checkmark
///   * `✓ session …` / `✗ …`    — status glyph variants
///   * Lines containing literal "session hook_started" / "hook_response"
///     anywhere (defensive against indented variants).
///
/// Empty leading/trailing lines are then trimmed.
pub(crate) fn filter_claude_noise(raw: &str) -> String {
    let kept: Vec<&str> = raw
        .lines()
        .filter(|line| !is_noise_line(line))
        .collect();
    // Re-join, then trim the boundary whitespace so callers don't
    // see leading/trailing blanks left behind by the filter.
    kept.join("\n").trim().to_string()
}

fn is_noise_line(line: &str) -> bool {
    let t = line.trim_start();
    if t.is_empty() {
        return false; // keep blanks; trimmed at the end
    }
    // Status-decorated lines from Claude Code's banner.
    let starts = ["· session", "· claude", "✓ claude", "✓ session", "✗ "];
    if starts.iter().any(|p| t.starts_with(p)) {
        return true;
    }
    // Defensive: tolerate indented session-hook lines.
    if t.contains("session hook_started") || t.contains("session hook_response") {
        return true;
    }
    false
}

#[cfg(test)]
mod noise_filter_tests {
    use super::filter_claude_noise;

    #[test]
    fn strips_session_hook_and_claude_done_lines() {
        let raw = "· session hook_started\n\
                   · session hook_response\n\
                   · session init\n\
                   Real reply text here\n\
                   · session success (1 turns, $0.07)\n\
                   ✓ claude done (3s)\n";
        let out = filter_claude_noise(raw);
        assert_eq!(out, "Real reply text here");
    }

    #[test]
    fn keeps_multiline_real_reply() {
        let raw = "First line\n\
                   Second line.\n\
                   ✓ claude done (1s)\n";
        let out = filter_claude_noise(raw);
        assert_eq!(out, "First line\nSecond line.");
    }

    #[test]
    fn empty_after_filter_yields_empty_string() {
        let raw = "· session hook_started\n✓ claude done\n";
        assert_eq!(filter_claude_noise(raw), "");
    }

    #[test]
    fn preserves_blank_lines_inside_reply() {
        let raw = "para1\n\npara2\n· session success (1 turns, $0.01)\n";
        assert_eq!(filter_claude_noise(raw), "para1\n\npara2");
    }

    #[test]
    fn does_not_touch_reply_starting_with_dot() {
        let raw = ". this is a normal line starting with a period\n";
        assert_eq!(
            filter_claude_noise(raw),
            ". this is a normal line starting with a period"
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_fake_cli(script: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake-claude");
        std::fs::write(&path, script).unwrap();
        let mut perm = std::fs::metadata(&path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&path, perm).unwrap();
        (dir, path)
    }

    #[tokio::test]
    async fn returns_subprocess_stdout() {
        // Script ignores its args and echoes stdin to stdout.
        let (_dir, bin) = write_fake_cli("#!/bin/sh\ncat\n");
        let adapter = ClaudeCliAdapter::new().with_binary(bin.to_str().unwrap());
        let out = adapter.complete("the-payload").await.unwrap();
        assert_eq!(out, "the-payload");
    }

    #[tokio::test]
    async fn nonzero_exit_becomes_backend_error() {
        let (_dir, bin) = write_fake_cli("#!/bin/sh\necho boom >&2\nexit 7\n");
        let adapter = ClaudeCliAdapter::new().with_binary(bin.to_str().unwrap());
        let err = adapter.complete("anything").await.unwrap_err();
        match err {
            SynthError::Backend(msg) => {
                assert!(msg.contains("exited"), "msg: {msg}");
                assert!(msg.contains("boom"), "msg: {msg}");
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_binary_becomes_backend_error() {
        let adapter =
            ClaudeCliAdapter::new().with_binary("/this/does/not/exist/at/all/nope-claude");
        let err = adapter.complete("anything").await.unwrap_err();
        assert!(matches!(err, SynthError::Backend(_)));
    }

    #[tokio::test]
    async fn empty_stdout_becomes_backend_error() {
        let (_dir, bin) = write_fake_cli("#!/bin/sh\nexit 0\n");
        let adapter = ClaudeCliAdapter::new().with_binary(bin.to_str().unwrap());
        let err = adapter.complete("anything").await.unwrap_err();
        match err {
            SynthError::Backend(msg) => assert!(msg.contains("empty"), "msg: {msg}"),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn timeout_becomes_backend_error() {
        let (_dir, bin) = write_fake_cli("#!/bin/sh\nsleep 5\n");
        let adapter = ClaudeCliAdapter::new()
            .with_binary(bin.to_str().unwrap())
            .with_timeout(Duration::from_millis(200));
        let err = adapter.complete("anything").await.unwrap_err();
        match err {
            SynthError::Backend(msg) => assert!(msg.contains("timed out"), "msg: {msg}"),
            other => panic!("expected Backend, got {other:?}"),
        }
    }
}
