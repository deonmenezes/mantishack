//! Bridge from the `mantis-synthesizer` `LlmAdapter` trait (which
//! talks to Anthropic / OpenAI / Claude CLI) into the
//! `mantis-tiered-exec` `LlmCodegen` trait (which generates exploit
//! scripts for the medium and hard tiers).
//!
//! `LlmAdapter::complete(prompt)` takes a free-form prompt and returns
//! a free-form completion. `LlmCodegen::generate(probe, attempts)`
//! formats a script-generation prompt that includes the probe's
//! objective, prior attempts, sandbox safety rules, and returns the
//! cleaned script body.
//!
//! This is the smallest piece of glue needed to make medium/hard tiers
//! reach a real LLM. The orchestrator (or the daemon) constructs the
//! synthesizer-side adapter using whatever provider the operator has
//! configured (env vars, CLI flags, or config), wraps it in
//! `SynthesizerLlmCodegen`, and hands the result to `TieredRunner`.

use std::sync::Arc;

use crate::adapter::{LlmAttempt, LlmCodegen};
use crate::{Probe, TierError};

use mantis_synthesizer::LlmAdapter;

const RED_TEAM_SYSTEM: &str = "You are a senior red-team operator generating a one-shot \
exploit verification script. Reply with ONLY the script body (no commentary, no markdown \
fences). The script must: (1) start with a shebang line; (2) make HTTP requests targeting \
the supplied URL and objective; (3) print a clearly marked PROOF=<evidence> line to stdout \
when the vulnerability is observed; (4) print a clearly marked NO_PROOF=<reason> line when \
inconclusive; (5) avoid destructive actions, large data exfil, or DoS. Use python3 with \
stdlib only (no pip installs).";

/// Wraps a `mantis-synthesizer::LlmAdapter` and exposes it as a
/// `mantis-tiered-exec::LlmCodegen`.
pub struct SynthesizerLlmCodegen {
    inner: Arc<dyn LlmAdapter>,
}

impl SynthesizerLlmCodegen {
    pub fn new(inner: Arc<dyn LlmAdapter>) -> Self {
        Self { inner }
    }

    pub fn from_arc(inner: Arc<dyn LlmAdapter>) -> Self {
        Self { inner }
    }

    /// Format the per-probe codegen prompt. Public so tests and
    /// the orchestrator can reuse the exact same prompt.
    pub fn build_prompt(probe: &Probe, attempts: &[LlmAttempt]) -> String {
        let mut s = String::with_capacity(1024);
        s.push_str(RED_TEAM_SYSTEM);
        s.push_str("\n\n--- TARGET ---\n");
        s.push_str(&probe.target_url);
        s.push_str("\n\n--- OBJECTIVE ---\n");
        s.push_str(&probe.objective);
        if let Some(attacker) = &probe.attacker_profile {
            s.push_str("\n\n--- ATTACKER AUTH (cookies/headers redacted to placeholders) ---\n");
            s.push_str(&render_profile(attacker));
        }
        if let Some(victim) = &probe.victim_profile {
            s.push_str("\n\n--- VICTIM AUTH (use only to identify the cross-tenant target) ---\n");
            s.push_str(&render_profile(victim));
        }
        if !attempts.is_empty() {
            s.push_str("\n\n--- PRIOR ATTEMPTS (rewrite to fix the verdicts below) ---\n");
            for (i, a) in attempts.iter().enumerate() {
                s.push_str(&format!(
                    "[attempt {} verdict] {}\n[attempt {} stdout]\n{}\n[attempt {} stderr]\n{}\n\n",
                    i + 1,
                    a.verdict,
                    i + 1,
                    truncate(&a.output.stdout, 2_000),
                    i + 1,
                    truncate(&a.output.stderr, 2_000),
                ));
            }
        }
        s.push_str(&format!(
            "\n\n--- BUDGET ---\nbudget_seconds = {}\n",
            probe.budget_seconds
        ));
        s.push_str(
            "\n\n--- OUTPUT FORMAT ---\nReturn the raw script body. No backticks. \
            No commentary. The first line MUST be a shebang.\n",
        );
        s
    }
}

impl LlmCodegen for SynthesizerLlmCodegen {
    fn generate<'a>(
        &'a self,
        probe: &'a Probe,
        previous_attempts: &'a [LlmAttempt],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<String, TierError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let prompt = Self::build_prompt(probe, previous_attempts);
            let raw = self
                .inner
                .complete(&prompt)
                .await
                .map_err(|e| TierError::Llm(e.to_string()))?;
            let cleaned = strip_markdown_fences(&raw);
            if !cleaned.lines().next().map(|l| l.starts_with("#!")).unwrap_or(false) {
                // If the LLM forgot the shebang, prepend a default.
                return Ok(format!("#!/usr/bin/env python3\n{cleaned}"));
            }
            Ok(cleaned)
        })
    }
}

fn render_profile(profile: &mantis_auth::AuthProfile) -> String {
    let mut s = String::new();
    if !profile.cookies.is_empty() {
        s.push_str("cookies:\n");
        for c in &profile.cookies {
            s.push_str(&format!("  - {}=<REDACTED>\n", c.name));
        }
    }
    if !profile.headers.is_empty() {
        s.push_str("headers:\n");
        for h in &profile.headers {
            s.push_str(&format!("  - {}: <REDACTED>\n", h.name));
        }
    }
    if !profile.query.is_empty() {
        s.push_str("query:\n");
        for (k, _) in &profile.query {
            s.push_str(&format!("  - {}=<REDACTED>\n", k));
        }
    }
    if s.is_empty() {
        s.push_str("(no auth)\n");
    }
    s
}

fn truncate(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        s.to_string()
    } else {
        let mut out = s[..max_bytes].to_string();
        out.push_str("…<truncated>");
        out
    }
}

fn strip_markdown_fences(raw: &str) -> String {
    let trimmed = raw.trim();
    let after_open = trimmed
        .strip_prefix("```python")
        .or_else(|| trimmed.strip_prefix("```bash"))
        .or_else(|| trimmed.strip_prefix("```sh"))
        .or_else(|| trimmed.strip_prefix("```"))
        .unwrap_or(trimmed);
    let after_close = after_open
        .strip_suffix("```")
        .unwrap_or(after_open)
        .trim();
    after_close.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mantis_synthesizer::SynthError;

    struct CannedSynthAdapter(&'static str);

    #[async_trait]
    impl LlmAdapter for CannedSynthAdapter {
        async fn complete(&self, _prompt: &str) -> Result<String, SynthError> {
            Ok(self.0.into())
        }
    }

    fn probe() -> Probe {
        Probe {
            target_url: "https://example.com/api/users/{id}".into(),
            objective: "IDOR test — try reading another tenant's user record".into(),
            attacker_profile: None,
            victim_profile: None,
            budget_seconds: 30,
        }
    }

    #[tokio::test]
    async fn bridge_returns_clean_script() {
        let inner: Arc<dyn LlmAdapter> = Arc::new(CannedSynthAdapter(
            "#!/usr/bin/env python3\nimport urllib.request\nprint('PROOF=read')",
        ));
        let bridge = SynthesizerLlmCodegen::new(inner);
        let r = bridge.generate(&probe(), &[]).await.unwrap();
        assert!(r.starts_with("#!"));
        assert!(r.contains("PROOF=read"));
    }

    #[tokio::test]
    async fn bridge_strips_markdown_fences() {
        let inner: Arc<dyn LlmAdapter> = Arc::new(CannedSynthAdapter(
            "```python\n#!/usr/bin/env python3\nprint('hi')\n```",
        ));
        let bridge = SynthesizerLlmCodegen::new(inner);
        let r = bridge.generate(&probe(), &[]).await.unwrap();
        assert!(r.starts_with("#!/usr/bin/env python3"));
        assert!(!r.contains("```"));
    }

    #[tokio::test]
    async fn bridge_prepends_default_shebang_when_missing() {
        let inner: Arc<dyn LlmAdapter> = Arc::new(CannedSynthAdapter("print('no shebang here')"));
        let bridge = SynthesizerLlmCodegen::new(inner);
        let r = bridge.generate(&probe(), &[]).await.unwrap();
        assert!(r.starts_with("#!/usr/bin/env python3"));
    }

    #[tokio::test]
    async fn bridge_propagates_synth_error() {
        struct ErrAdapter;
        #[async_trait]
        impl LlmAdapter for ErrAdapter {
            async fn complete(&self, _prompt: &str) -> Result<String, SynthError> {
                Err(SynthError::Backend("rate limited".into()))
            }
        }
        let bridge = SynthesizerLlmCodegen::new(Arc::new(ErrAdapter));
        let err = bridge.generate(&probe(), &[]).await.unwrap_err();
        match err {
            TierError::Llm(m) => assert!(m.contains("rate limited")),
            other => panic!("expected Llm, got {other:?}"),
        }
    }

    #[test]
    fn prompt_includes_objective_and_target() {
        let prompt = SynthesizerLlmCodegen::build_prompt(&probe(), &[]);
        assert!(prompt.contains("https://example.com/api/users/{id}"));
        assert!(prompt.contains("IDOR test"));
        assert!(prompt.contains("PROOF="));
    }

    #[test]
    fn prompt_includes_prior_attempts() {
        let attempts = vec![LlmAttempt {
            script: "old".into(),
            output: crate::adapter::SandboxOutput {
                exit_code: 1,
                stdout: "got 401".into(),
                stderr: "auth failed".into(),
                duration_ms: 10,
            },
            verdict: "verifier rejected: no cross-tenant evidence".into(),
        }];
        let prompt = SynthesizerLlmCodegen::build_prompt(&probe(), &attempts);
        assert!(prompt.contains("PRIOR ATTEMPTS"));
        assert!(prompt.contains("verifier rejected"));
        assert!(prompt.contains("got 401"));
    }
}
