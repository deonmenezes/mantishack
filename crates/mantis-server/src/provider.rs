//! Adapter resolution. Mirrors `pick_chat_adapter` from
//! `mantis-cli/src/main.rs` so the server picks the same provider as
//! the interactive CLI when no override is requested. The CLI's
//! version is `pub(crate)` / file-local, so this is a deliberate copy
//! kept in sync by convention.

use std::sync::Arc;

use anyhow::{Context, Result};
use mantis_synthesizer::{
    anthropic::AnthropicAdapter, claude_cli::ClaudeCliAdapter, gemini::GeminiAdapter,
    ollama::OllamaAdapter, openai::OpenAIAdapter, LlmAdapter,
};

/// Resolve the chat adapter for a request.
///
/// Returns the adapter alongside the resolved provider id and model
/// label so handlers can surface them in response envelopes / logs.
/// Selection order:
/// 1. `provider_override` (request body or query)
/// 2. `MANTIS_LLM_PROVIDER` env var
/// 3. [`detect_provider`] auto-detection
pub fn pick_chat_adapter(
    provider_override: Option<&str>,
    model_override: Option<&str>,
) -> Result<(Arc<dyn LlmAdapter>, String, String)> {
    let provider = match provider_override {
        Some(p) => p.to_string(),
        None => std::env::var("MANTIS_LLM_PROVIDER").unwrap_or_else(|_| detect_provider()),
    };

    let (adapter, model_label): (Arc<dyn LlmAdapter>, String) = match provider.as_str() {
        "anthropic" => {
            let key = std::env::var("ANTHROPIC_API_KEY")
                .context("ANTHROPIC_API_KEY is not set — export it or pick a different provider")?;
            let mut a = AnthropicAdapter::new(key).with_max_tokens(4096);
            let model = model_override
                .map(str::to_string)
                .unwrap_or_else(|| "claude-opus-4-7".to_string());
            a = a.with_model(model.clone());
            (Arc::new(a), model)
        }
        "openai" => {
            let key = std::env::var("OPENAI_API_KEY")
                .context("OPENAI_API_KEY is not set — export it or pick a different provider")?;
            let mut a = OpenAIAdapter::new(key).with_max_tokens(4096);
            let model = model_override
                .map(str::to_string)
                .unwrap_or_else(|| "gpt-4o-mini".to_string());
            a = a.with_model(model.clone());
            (Arc::new(a), model)
        }
        "gemini" => {
            let key = std::env::var("GEMINI_API_KEY")
                .context("GEMINI_API_KEY is not set — export it or pick a different provider")?;
            let mut a = GeminiAdapter::new(key);
            let model = model_override
                .map(str::to_string)
                .unwrap_or_else(|| "gemini-2.0-flash-exp".to_string());
            a = a.with_model(model.clone());
            (Arc::new(a), model)
        }
        "ollama" => {
            let mut a = OllamaAdapter::new();
            if let Some(host) = std::env::var("OLLAMA_HOST").ok().filter(|s| !s.is_empty()) {
                a = a.with_base_url(host);
            }
            let model = model_override
                .map(str::to_string)
                .unwrap_or_else(|| "llama3.2".to_string());
            a = a.with_model(model.clone());
            (Arc::new(a), model)
        }
        "claude-cli" => {
            let mut a = ClaudeCliAdapter::new();
            let model = model_override
                .map(str::to_string)
                .unwrap_or_else(|| "claude-opus-4-7".to_string());
            a = a.with_model(model.clone());
            (Arc::new(a), model)
        }
        other => anyhow::bail!(
            "unknown provider `{other}` — supported: anthropic, openai, gemini, ollama, claude-cli"
        ),
    };

    Ok((adapter, provider, model_label))
}

/// Pick the first provider whose env condition is satisfied. Falls
/// back to `claude-cli` when nothing is set; that adapter shells out
/// to the local `claude` binary.
pub fn detect_provider() -> String {
    if env_nonempty("ANTHROPIC_API_KEY") {
        return "anthropic".into();
    }
    if env_nonempty("OPENAI_API_KEY") {
        return "openai".into();
    }
    if env_nonempty("GEMINI_API_KEY") {
        return "gemini".into();
    }
    if env_nonempty("OLLAMA_HOST") {
        return "ollama".into();
    }
    "claude-cli".into()
}

fn env_nonempty(name: &str) -> bool {
    std::env::var(name)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}
