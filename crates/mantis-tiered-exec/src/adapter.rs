//! Adapter traits — keep the LLM + sandbox plumbing out of the
//! core tier logic so we can unit-test with mocks.

use crate::{Probe, TierError};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

/// Code-generating LLM adapter. The medium and hard tiers call
/// `generate` to get an exploit script for a probe. The orchestrator
/// wires this to whichever provider (`anthropic`, `openai`,
/// `claude-cli`) is configured.
pub trait LlmCodegen: Send + Sync {
    /// Returns either a script body (`#!/usr/bin/env python3 ...`) or
    /// an error. Mantis does not inspect the language — the sandbox
    /// runner reads the shebang.
    fn generate<'a>(
        &'a self,
        probe: &'a Probe,
        previous_attempts: &'a [LlmAttempt],
    ) -> Pin<Box<dyn Future<Output = Result<String, TierError>> + Send + 'a>>;
}

/// Sandbox runner — executes a script with bounded resources and
/// returns its stdout/stderr/exit. The default
/// [`SubprocessSandbox`] shells out to a local interpreter; the
/// orchestrator can swap in a stricter (e.g. nsjail / Docker)
/// implementation for higher safety.
pub trait SandboxRunner: Send + Sync {
    fn run<'a>(
        &'a self,
        script: &'a str,
        env: &'a [(String, String)],
        timeout_secs: u32,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxOutput, TierError>> + Send + 'a>>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// One round of LLM codegen + sandbox-run. The hard tier
/// accumulates a vec of these and feeds them back to the LLM as
/// context for the next attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmAttempt {
    pub script: String,
    pub output: SandboxOutput,
    /// Operator-visible note ("verifier rejected: no evidence
    /// of cross-tenant read in stdout").
    pub verdict: String,
}

// ---------- mock + null implementations for tests ----------

/// `NullLlm` always fails. Use to verify the runner gracefully
/// falls through when the operator hasn't configured an LLM.
pub struct NullLlm;

impl LlmCodegen for NullLlm {
    fn generate<'a>(
        &'a self,
        _probe: &'a Probe,
        _previous_attempts: &'a [LlmAttempt],
    ) -> Pin<Box<dyn Future<Output = Result<String, TierError>> + Send + 'a>> {
        Box::pin(async move { Err(TierError::Llm("no LLM provider configured".into())) })
    }
}

/// `MockLlm` returns a canned response. Used in tests.
pub struct MockLlm {
    pub script: String,
}

impl LlmCodegen for MockLlm {
    fn generate<'a>(
        &'a self,
        _probe: &'a Probe,
        _previous_attempts: &'a [LlmAttempt],
    ) -> Pin<Box<dyn Future<Output = Result<String, TierError>> + Send + 'a>> {
        let script = self.script.clone();
        Box::pin(async move { Ok(script) })
    }
}

/// Subprocess-backed sandbox. Reads the script's shebang to choose
/// an interpreter; falls back to `bash -s`.
pub struct SubprocessSandbox;

impl SandboxRunner for SubprocessSandbox {
    fn run<'a>(
        &'a self,
        script: &'a str,
        env: &'a [(String, String)],
        timeout_secs: u32,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxOutput, TierError>> + Send + 'a>> {
        let script_owned = script.to_string();
        let env_owned: Vec<(String, String)> = env.to_vec();
        Box::pin(async move { run_subprocess(&script_owned, &env_owned, timeout_secs).await })
    }
}

async fn run_subprocess(
    script: &str,
    env: &[(String, String)],
    timeout_secs: u32,
) -> Result<SandboxOutput, TierError> {
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;

    // Pick interpreter from shebang.
    let (interp, args): (std::path::PathBuf, Vec<&str>) =
        if script.starts_with("#!/usr/bin/env python") || script.starts_with("#!/usr/bin/python") {
            ("python3".into(), vec![])
        } else if script.starts_with("#!/usr/bin/env node") || script.starts_with("#!/usr/bin/node")
        {
            ("node".into(), vec![])
        } else if script.starts_with("#!/bin/sh") || script.starts_with("#!/bin/bash") {
            (bash_interpreter(), vec![])
        } else {
            // Default: bash -s reads script from stdin.
            (bash_interpreter(), vec!["-s"])
        };

    let start = std::time::Instant::now();
    let mut cmd = Command::new(interp);
    cmd.args(&args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| TierError::Sandbox(e.to_string()))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(script.as_bytes()).await;
        // Drop closes the pipe.
    }
    let timeout = std::time::Duration::from_secs(timeout_secs as u64);
    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return Err(TierError::Sandbox(e.to_string())),
        Err(_) => return Err(TierError::Sandbox("timeout".into())),
    };
    Ok(SandboxOutput {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        duration_ms: start.elapsed().as_millis() as u64,
    })
}

fn bash_interpreter() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        for path in [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
            r"C:\Program Files (x86)\Git\bin\bash.exe",
        ] {
            let candidate = std::path::PathBuf::from(path);
            if candidate.is_file() {
                return candidate;
            }
        }
    }

    "bash".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn null_llm_errors() {
        let probe = Probe {
            target_url: "https://x".into(),
            objective: "test".into(),
            attacker_profile: None,
            victim_profile: None,
            budget_seconds: 1,
        };
        let r = NullLlm.generate(&probe, &[]).await;
        assert!(matches!(r, Err(TierError::Llm(_))));
    }

    #[tokio::test]
    async fn mock_llm_returns_canned_script() {
        let probe = Probe {
            target_url: "https://x".into(),
            objective: "test".into(),
            attacker_profile: None,
            victim_profile: None,
            budget_seconds: 1,
        };
        let llm = MockLlm {
            script: "#!/bin/bash\necho hello".into(),
        };
        let r = llm.generate(&probe, &[]).await.unwrap();
        assert!(r.contains("echo hello"));
    }

    #[tokio::test]
    async fn subprocess_sandbox_runs_bash_script() {
        let sandbox = SubprocessSandbox;
        let out = sandbox
            .run("#!/bin/bash\necho found-tenant-leak", &[], 5)
            .await
            .unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("found-tenant-leak"));
    }

    #[tokio::test]
    async fn subprocess_sandbox_times_out() {
        let sandbox = SubprocessSandbox;
        let err = sandbox
            .run("#!/bin/bash\nsleep 10", &[], 1)
            .await
            .unwrap_err();
        match err {
            TierError::Sandbox(s) => assert!(s.contains("timeout")),
            _ => panic!("expected timeout"),
        }
    }

    #[tokio::test]
    async fn sandbox_output_captures_stderr() {
        let sandbox = SubprocessSandbox;
        let out = sandbox
            .run("#!/bin/bash\necho oops >&2; exit 3", &[], 5)
            .await
            .unwrap();
        assert_eq!(out.exit_code, 3);
        assert!(out.stderr.contains("oops"));
    }
}
