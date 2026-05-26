//! First-available LLM adapter picker.
//!
//! Used by the offensive pipeline (`mantis hack`, `mantis pentest`,
//! `mantis goal`) and the conversational surface (`mantis chat`,
//! `mantis ask`, `mantis serve`) to opportunistically call an LLM
//! without forcing the user to configure one.
//!
//! Provider catalogue (set the env var on the right to enable):
//!
//! | Provider id     | Env var                  | Native adapter / base URL                                   | Default model                |
//! | --------------- | ------------------------ | ----------------------------------------------------------- | ---------------------------- |
//! | `anthropic`     | `ANTHROPIC_API_KEY`      | AnthropicAdapter                                            | `claude-opus-4-7`            |
//! | `openai`        | `OPENAI_API_KEY`         | OpenAIAdapter                                               | `gpt-4o-mini`                |
//! | `gemini`        | `GEMINI_API_KEY`         | GeminiAdapter                                               | `gemini-2.0-flash-exp`       |
//! | `moonshot`      | `MOONSHOT_API_KEY`       | OpenAI-compatible → `https://api.moonshot.cn/v1`            | `moonshot-v1-32k` (Kimi)     |
//! | `deepseek`      | `DEEPSEEK_API_KEY`       | OpenAI-compatible → `https://api.deepseek.com/v1`           | `deepseek-chat`              |
//! | `groq`          | `GROQ_API_KEY`           | OpenAI-compatible → `https://api.groq.com/openai/v1`        | `llama-3.3-70b-versatile`    |
//! | `mistral`       | `MISTRAL_API_KEY`        | OpenAI-compatible → `https://api.mistral.ai/v1`             | `mistral-large-latest`       |
//! | `xai`           | `XAI_API_KEY`            | OpenAI-compatible → `https://api.x.ai/v1`                   | `grok-2-latest`              |
//! | `openrouter`    | `OPENROUTER_API_KEY`     | OpenAI-compatible → `https://openrouter.ai/api/v1`          | `anthropic/claude-3.5-sonnet`|
//! | `qwen`          | `DASHSCOPE_API_KEY`      | OpenAI-compatible → Alibaba DashScope                       | `qwen-max`                   |
//! | `zhipu`         | `ZHIPU_API_KEY`          | OpenAI-compatible → `https://open.bigmodel.cn/api/paas/v4`  | `glm-4-plus`                 |
//! | `bedrock`       | `AWS_BEDROCK_PROXY_URL` + `AWS_BEDROCK_API_KEY` | OpenAI-compatible against a LiteLLM / Bedrock Access Gateway proxy | `anthropic.claude-3-5-sonnet-20241022-v2:0` |
//! | `ollama`        | `OLLAMA_HOST` (or always available when forced) | OllamaAdapter → local model server                          | `llama3.2`                   |
//! | `claude-cli`    | `claude` binary on PATH  | Shells out to `claude --print`                              | (uses CLI's own model)       |
//!
//! Auto-pick order (top first) — set the env var to enable:
//!   `ANTHROPIC_API_KEY` → `OPENAI_API_KEY` → `GEMINI_API_KEY` →
//!   `MOONSHOT_API_KEY` → `DEEPSEEK_API_KEY` → `GROQ_API_KEY` →
//!   `MISTRAL_API_KEY` → `XAI_API_KEY` → `OPENROUTER_API_KEY` →
//!   `DASHSCOPE_API_KEY` → `ZHIPU_API_KEY` → `AWS_BEDROCK_PROXY_URL`
//!   → `OLLAMA_HOST` → `claude` on PATH → None.
//!
//! Honors:
//! - `MANTIS_NO_LLM=1`  → always returns `None`
//! - `MANTIS_LLM_PROVIDER=<id>` → force a specific provider
//!   (any of the ids above); errors if unavailable.

use mantis_synthesizer::{
    anthropic::AnthropicAdapter, claude_cli::ClaudeCliAdapter, gemini::GeminiAdapter,
    ollama::OllamaAdapter, openai::OpenAIAdapter, LlmAdapter,
};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// What kind of provider was picked. Lets callers log what they used
/// without re-running the picker.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PickedProvider {
    Anthropic,
    OpenAI,
    Gemini,
    Moonshot,
    DeepSeek,
    Groq,
    Mistral,
    XAi,
    OpenRouter,
    Qwen,
    Zhipu,
    Bedrock,
    Ollama,
    ClaudeCli,
}

impl PickedProvider {
    pub(crate) fn label(self) -> &'static str {
        match self {
            PickedProvider::Anthropic => "anthropic",
            PickedProvider::OpenAI => "openai",
            PickedProvider::Gemini => "gemini",
            PickedProvider::Moonshot => "moonshot",
            PickedProvider::DeepSeek => "deepseek",
            PickedProvider::Groq => "groq",
            PickedProvider::Mistral => "mistral",
            PickedProvider::XAi => "xai",
            PickedProvider::OpenRouter => "openrouter",
            PickedProvider::Qwen => "qwen",
            PickedProvider::Zhipu => "zhipu",
            PickedProvider::Bedrock => "bedrock",
            PickedProvider::Ollama => "ollama",
            PickedProvider::ClaudeCli => "claude-cli",
        }
    }
}

/// Default base URL + model for each OpenAI-compatible provider.
/// Kept module-private; the CLI's `pick_chat_adapter` re-uses these
/// constants via accessor functions so the catalogue lives in ONE
/// place.
pub(crate) const MOONSHOT_BASE: &str = "https://api.moonshot.cn/v1";
pub(crate) const MOONSHOT_MODEL: &str = "moonshot-v1-32k";
pub(crate) const DEEPSEEK_BASE: &str = "https://api.deepseek.com/v1";
pub(crate) const DEEPSEEK_MODEL: &str = "deepseek-chat";
pub(crate) const GROQ_BASE: &str = "https://api.groq.com/openai/v1";
pub(crate) const GROQ_MODEL: &str = "llama-3.3-70b-versatile";
pub(crate) const MISTRAL_BASE: &str = "https://api.mistral.ai/v1";
pub(crate) const MISTRAL_MODEL: &str = "mistral-large-latest";
pub(crate) const XAI_BASE: &str = "https://api.x.ai/v1";
pub(crate) const XAI_MODEL: &str = "grok-2-latest";
pub(crate) const OPENROUTER_BASE: &str = "https://openrouter.ai/api/v1";
pub(crate) const OPENROUTER_MODEL: &str = "anthropic/claude-3.5-sonnet";
pub(crate) const QWEN_BASE: &str = "https://dashscope.aliyuncs.com/compatible-mode/v1";
pub(crate) const QWEN_MODEL: &str = "qwen-max";
pub(crate) const ZHIPU_BASE: &str = "https://open.bigmodel.cn/api/paas/v4";
pub(crate) const ZHIPU_MODEL: &str = "glm-4-plus";
pub(crate) const BEDROCK_MODEL: &str = "anthropic.claude-3-5-sonnet-20241022-v2:0";

fn openai_compat(key: String, base_url: &str) -> Arc<dyn LlmAdapter> {
    Arc::new(
        OpenAIAdapter::new(key)
            .with_base_url(base_url)
            .with_max_tokens(1024),
    )
}

/// Pick the first ready provider. Returns `None` when LLM is disabled
/// or no provider is available. The caller should treat `None` as
/// "skip the LLM-augmented step" — never as a fatal error.
pub(crate) fn pick() -> Option<(Arc<dyn LlmAdapter>, PickedProvider)> {
    if std::env::var_os("MANTIS_NO_LLM").is_some() {
        return None;
    }

    // Forced provider — useful for tests and for users who have
    // multiple keys but want to lock in one.
    if let Ok(forced) = std::env::var("MANTIS_LLM_PROVIDER") {
        return force(&forced);
    }

    // Auto-pick. Direct-API providers first (lowest latency); local
    // Ollama and the claude-cli subprocess fall through last.
    if let Some(key) = nonempty_env("ANTHROPIC_API_KEY") {
        let adapter = AnthropicAdapter::new(key).with_max_tokens(1024);
        return Some((Arc::new(adapter), PickedProvider::Anthropic));
    }
    if let Some(key) = nonempty_env("OPENAI_API_KEY") {
        let adapter = OpenAIAdapter::new(key).with_max_tokens(1024);
        return Some((Arc::new(adapter), PickedProvider::OpenAI));
    }
    if let Some(key) = nonempty_env("GEMINI_API_KEY") {
        let adapter = GeminiAdapter::new(key);
        return Some((Arc::new(adapter), PickedProvider::Gemini));
    }
    if let Some(key) = nonempty_env("MOONSHOT_API_KEY") {
        return Some((openai_compat(key, MOONSHOT_BASE), PickedProvider::Moonshot));
    }
    if let Some(key) = nonempty_env("DEEPSEEK_API_KEY") {
        return Some((openai_compat(key, DEEPSEEK_BASE), PickedProvider::DeepSeek));
    }
    if let Some(key) = nonempty_env("GROQ_API_KEY") {
        return Some((openai_compat(key, GROQ_BASE), PickedProvider::Groq));
    }
    if let Some(key) = nonempty_env("MISTRAL_API_KEY") {
        return Some((openai_compat(key, MISTRAL_BASE), PickedProvider::Mistral));
    }
    if let Some(key) = nonempty_env("XAI_API_KEY") {
        return Some((openai_compat(key, XAI_BASE), PickedProvider::XAi));
    }
    if let Some(key) = nonempty_env("OPENROUTER_API_KEY") {
        return Some((
            openai_compat(key, OPENROUTER_BASE),
            PickedProvider::OpenRouter,
        ));
    }
    if let Some(key) = nonempty_env("DASHSCOPE_API_KEY") {
        return Some((openai_compat(key, QWEN_BASE), PickedProvider::Qwen));
    }
    if let Some(key) = nonempty_env("ZHIPU_API_KEY") {
        return Some((openai_compat(key, ZHIPU_BASE), PickedProvider::Zhipu));
    }
    if let (Some(proxy), Some(key)) = (
        nonempty_env("AWS_BEDROCK_PROXY_URL"),
        nonempty_env("AWS_BEDROCK_API_KEY"),
    ) {
        return Some((openai_compat(key, &proxy), PickedProvider::Bedrock));
    }
    if let Some(host) = nonempty_env("OLLAMA_HOST") {
        let adapter = OllamaAdapter::new().with_base_url(host);
        return Some((Arc::new(adapter), PickedProvider::Ollama));
    }
    if which("claude").is_some() {
        let adapter = ClaudeCliAdapter::new();
        return Some((Arc::new(adapter), PickedProvider::ClaudeCli));
    }
    None
}

fn force(id: &str) -> Option<(Arc<dyn LlmAdapter>, PickedProvider)> {
    match id {
        "anthropic" => nonempty_env("ANTHROPIC_API_KEY").map(|k| {
            let a: Arc<dyn LlmAdapter> = Arc::new(AnthropicAdapter::new(k).with_max_tokens(1024));
            (a, PickedProvider::Anthropic)
        }),
        "openai" => nonempty_env("OPENAI_API_KEY").map(|k| {
            let a: Arc<dyn LlmAdapter> = Arc::new(OpenAIAdapter::new(k).with_max_tokens(1024));
            (a, PickedProvider::OpenAI)
        }),
        "gemini" => nonempty_env("GEMINI_API_KEY").map(|k| {
            let a: Arc<dyn LlmAdapter> = Arc::new(GeminiAdapter::new(k));
            (a, PickedProvider::Gemini)
        }),
        "moonshot" | "kimi" => nonempty_env("MOONSHOT_API_KEY")
            .map(|k| (openai_compat(k, MOONSHOT_BASE), PickedProvider::Moonshot)),
        "deepseek" => nonempty_env("DEEPSEEK_API_KEY")
            .map(|k| (openai_compat(k, DEEPSEEK_BASE), PickedProvider::DeepSeek)),
        "groq" => nonempty_env("GROQ_API_KEY")
            .map(|k| (openai_compat(k, GROQ_BASE), PickedProvider::Groq)),
        "mistral" => nonempty_env("MISTRAL_API_KEY")
            .map(|k| (openai_compat(k, MISTRAL_BASE), PickedProvider::Mistral)),
        "xai" | "grok" => {
            nonempty_env("XAI_API_KEY").map(|k| (openai_compat(k, XAI_BASE), PickedProvider::XAi))
        }
        "openrouter" => nonempty_env("OPENROUTER_API_KEY").map(|k| {
            (
                openai_compat(k, OPENROUTER_BASE),
                PickedProvider::OpenRouter,
            )
        }),
        "qwen" | "dashscope" => nonempty_env("DASHSCOPE_API_KEY")
            .map(|k| (openai_compat(k, QWEN_BASE), PickedProvider::Qwen)),
        "zhipu" | "glm" => nonempty_env("ZHIPU_API_KEY")
            .map(|k| (openai_compat(k, ZHIPU_BASE), PickedProvider::Zhipu)),
        "bedrock" => match (
            nonempty_env("AWS_BEDROCK_PROXY_URL"),
            nonempty_env("AWS_BEDROCK_API_KEY"),
        ) {
            (Some(proxy), Some(key)) => Some((openai_compat(key, &proxy), PickedProvider::Bedrock)),
            _ => {
                eprintln!(
                    "[mantis] bedrock requires AWS_BEDROCK_PROXY_URL + AWS_BEDROCK_API_KEY \
                     (point them at a LiteLLM or Bedrock Access Gateway proxy)"
                );
                None
            }
        },
        "ollama" => {
            // Ollama doesn't need an API key. Honor OLLAMA_HOST if
            // set; otherwise the adapter falls back to its built-in
            // localhost default. Always available when forced.
            let mut adapter = OllamaAdapter::new();
            if let Some(host) = nonempty_env("OLLAMA_HOST") {
                adapter = adapter.with_base_url(host);
            }
            let a: Arc<dyn LlmAdapter> = Arc::new(adapter);
            Some((a, PickedProvider::Ollama))
        }
        "claude-cli" => which("claude").map(|_| {
            let a: Arc<dyn LlmAdapter> = Arc::new(ClaudeCliAdapter::new());
            (a, PickedProvider::ClaudeCli)
        }),
        other => {
            eprintln!(
                "[mantis] warning: MANTIS_LLM_PROVIDER={other} is not a known provider. \
                 known: anthropic, openai, gemini, moonshot (kimi), deepseek, groq, \
                 mistral, xai (grok), openrouter, qwen (dashscope), zhipu (glm), bedrock, \
                 ollama, claude-cli — skipping LLM"
            );
            None
        }
    }
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &std::path::Path) -> bool {
    p.is_file()
}

// ---------------------------------------------------------------------------
// LLM-augmented pipeline helpers.
//
// Both functions are best-effort: any failure (network, malformed
// reply, auth, sandbox) is logged to stderr and yields a no-op
// result. The deterministic pipeline must never depend on these
// succeeding.
// ---------------------------------------------------------------------------

/// Cap LLM-suggested paths so a hallucinating model can't blow up
/// the wordlist. 50 is generous — typical reply yields 10–25.
const MAX_LLM_PATHS: usize = 50;

/// Ask the LLM for high-signal API endpoint paths to add to the
/// wordlist, based on the recon notes from Phase 1.
pub(crate) async fn suggest_paths(
    adapter: &dyn LlmAdapter,
    target_url: &str,
    discovery_notes: &[String],
    supabase_detected: bool,
) -> Vec<String> {
    let notes_block = if discovery_notes.is_empty() {
        "(no discovery notes)".to_string()
    } else {
        discovery_notes
            .iter()
            .take(40)
            .map(|n| format!("- {n}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let backend = if supabase_detected {
        "Supabase"
    } else {
        "unknown / none detected"
    };
    let prompt = format!(
        "You are an offensive-security recon assistant. Based on this target's \
         discovered surface, list up to 25 high-signal API endpoint paths to probe \
         for broken authorization (IDOR, tenant isolation, role escalation, \
         unauthenticated reads).\n\n\
         OUTPUT FORMAT (strict): one path per line. Each path starts with '/'. \
         No commentary, no markdown, no numbering. If you have no good guesses, \
         output nothing.\n\n\
         Target:        {target_url}\n\
         Auth backend:  {backend}\n\
         Discovery notes:\n{notes_block}"
    );
    match adapter.complete(&prompt).await {
        Ok(text) => parse_paths(&text),
        Err(e) => {
            eprintln!(
                "[mantis] LLM hypothesis call failed ({e}); continuing without LLM-suggested paths"
            );
            Vec::new()
        }
    }
}

fn parse_paths(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        // Strip leading bullets, numbering, whitespace, code fences.
        let stripped = raw
            .trim()
            .trim_start_matches("```")
            .trim_start_matches(|c: char| {
                c.is_whitespace()
                    || matches!(c, '-' | '*' | '•' | '.' | ')' | '(')
                    || c.is_ascii_digit()
            })
            .trim();
        // Some models wrap paths in backticks.
        let stripped = stripped.trim_matches('`');
        if !stripped.starts_with('/') {
            continue;
        }
        // Reject pathological lines.
        if stripped.len() > 200 || stripped.contains(char::is_whitespace) {
            continue;
        }
        out.push(stripped.to_string());
        if out.len() >= MAX_LLM_PATHS {
            break;
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Append an LLM-drafted Executive Summary section to the
/// vulnerability-report markdown. `findings_summary` should be a
/// short factual blob (counts, top classes, top endpoints) — keep
/// the prompt under a few KB so it works for free-tier models too.
pub(crate) async fn append_exec_summary(
    adapter: &dyn LlmAdapter,
    report_path: &Path,
    findings_summary: &str,
) {
    let prompt = format!(
        "You are writing the Executive Summary section of a penetration-test report. \
         Below is the deterministic pipeline's findings summary — treat it as the \
         single source of truth. DO NOT invent findings, severities, endpoints, or \
         attack chains that aren't already in the summary.\n\n\
         Produce 3-6 sentences of plain markdown (no top-level heading; the section \
         heading is added by the caller). Cover, in order:\n\
         1. testing scope and method, in one line;\n\
         2. the result in one line;\n\
         3. the top 3 most important risks if any (else: explicit statement that \
            none were found);\n\
         4. the single most impactful next step.\n\n\
         Findings summary:\n{findings_summary}"
    );
    match adapter.complete(&prompt).await {
        Ok(text) => {
            let body = text.trim();
            if body.is_empty() {
                eprintln!("[mantis] LLM exec-summary returned empty; skipping append");
                return;
            }
            let block = format!(
                "\n\n## Executive Summary (LLM-augmented)\n\n_Generated by an LLM from the deterministic findings above. The findings themselves are authoritative._\n\n{body}\n"
            );
            match std::fs::OpenOptions::new().append(true).open(report_path) {
                Ok(mut f) => {
                    use std::io::Write;
                    if let Err(e) = f.write_all(block.as_bytes()) {
                        eprintln!("[mantis] LLM exec-summary write failed ({e})");
                    }
                }
                Err(e) => eprintln!(
                    "[mantis] LLM exec-summary cannot open report {} ({e})",
                    report_path.display()
                ),
            }
        }
        Err(e) => eprintln!("[mantis] LLM exec-summary call failed ({e}); continuing"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_paths_extracts_clean_paths() {
        let text = "/api/users\n/api/orders\n  /admin/keys  \nblah\n- /api/foo\n  2. /api/bar\n";
        let paths = parse_paths(text);
        assert!(paths.contains(&"/api/users".to_string()));
        assert!(paths.contains(&"/api/orders".to_string()));
        assert!(paths.contains(&"/admin/keys".to_string()));
        assert!(paths.contains(&"/api/foo".to_string()));
        assert!(paths.contains(&"/api/bar".to_string()));
        assert!(!paths.contains(&"blah".to_string()));
    }

    #[test]
    fn parse_paths_dedupes_and_caps() {
        let mut text = String::new();
        for i in 0..200 {
            let _ = writeln!(text, "/api/x{i}");
        }
        let paths = parse_paths(&text);
        assert!(paths.len() <= MAX_LLM_PATHS);
    }

    #[test]
    fn parse_paths_rejects_paths_with_spaces() {
        let text = "/api/has space\n/clean\n";
        let paths = parse_paths(text);
        assert_eq!(paths, vec!["/clean".to_string()]);
    }
}
