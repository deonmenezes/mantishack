//! Provider selection for the tiered runner's LLM tier.
//!
//! Precedence (first match wins):
//!   1. Explicit constructor argument (used by tests + CLI flags)
//!   2. Env var `MANTIS_LLM_PROVIDER` ∈ {anthropic, openai, claude-cli, groq, ollama, null}
//!   3. Presence of `ANTHROPIC_API_KEY` → anthropic
//!   4. Presence of `OPENAI_API_KEY` → openai
//!   5. Presence of a usable `claude` binary on PATH → claude-cli
//!   6. Fall back to `NullLlm` (medium/hard tiers will be skipped)
//!
//! Models pick from `MANTIS_LLM_MODEL` if set; otherwise the
//! provider-specific default.

use std::sync::Arc;

use crate::adapter::LlmCodegen;
use crate::llm_bridge::SynthesizerLlmCodegen;
use mantis_synthesizer::{
    anthropic::AnthropicAdapter, claude_cli::ClaudeCliAdapter, openai::OpenAIAdapter, LlmAdapter,
    NullLlm as NullSynthLlm,
};

/// Operator-facing provider names. Lowercase, hyphenated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Anthropic,
    OpenAi,
    ClaudeCli,
    Groq,
    Ollama,
    Null,
}

impl ProviderKind {
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "anthropic" | "claude" => Some(Self::Anthropic),
            "openai" | "gpt" => Some(Self::OpenAi),
            "claude-cli" | "claude_cli" | "cli" => Some(Self::ClaudeCli),
            "groq" => Some(Self::Groq),
            "ollama" => Some(Self::Ollama),
            "null" | "none" => Some(Self::Null),
            _ => None,
        }
    }
}

/// Look at the environment and pick a provider. Operator override
/// via `provider_override` short-circuits the env-var scan.
pub fn auto_select(provider_override: Option<ProviderKind>) -> ProviderKind {
    if let Some(p) = provider_override {
        return p;
    }
    if let Ok(name) = std::env::var("MANTIS_LLM_PROVIDER") {
        if let Some(p) = ProviderKind::parse(&name) {
            return p;
        }
    }
    if std::env::var("ANTHROPIC_API_KEY").is_ok() {
        return ProviderKind::Anthropic;
    }
    if std::env::var("OPENAI_API_KEY").is_ok() {
        return ProviderKind::OpenAi;
    }
    if std::env::var("GROQ_API_KEY").is_ok() {
        return ProviderKind::Groq;
    }
    // Default to the local Claude CLI if available; if not, the
    // bridge will surface a useful error at first use.
    ProviderKind::ClaudeCli
}

/// Construct an `LlmAdapter` (the synthesizer side) for a chosen
/// provider. Returns `None` for `ProviderKind::Null`.
pub fn build_llm_adapter(provider: ProviderKind) -> Option<Arc<dyn LlmAdapter>> {
    let model = std::env::var("MANTIS_LLM_MODEL").ok();
    match provider {
        ProviderKind::Anthropic => {
            let key = std::env::var("ANTHROPIC_API_KEY").ok()?;
            let mut a = AnthropicAdapter::new(key);
            if let Some(m) = model {
                a = a.with_model(m);
            }
            Some(Arc::new(a))
        }
        ProviderKind::OpenAi => {
            let key = std::env::var("OPENAI_API_KEY").ok()?;
            let mut a = OpenAIAdapter::new(key);
            if let Some(m) = model {
                a = a.with_model(m);
            }
            Some(Arc::new(a))
        }
        ProviderKind::Groq => {
            // Groq exposes an OpenAI-compatible Chat Completions API.
            let key = std::env::var("GROQ_API_KEY").ok()?;
            let mut a = OpenAIAdapter::new(key).with_base_url("https://api.groq.com/openai");
            if let Some(m) = model {
                a = a.with_model(m);
            } else {
                a = a.with_model("llama-3.3-70b-versatile");
            }
            Some(Arc::new(a))
        }
        ProviderKind::Ollama => {
            // Ollama exposes an OpenAI-compatible endpoint at /v1.
            let base =
                std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "http://127.0.0.1:11434".into());
            let mut a = OpenAIAdapter::new("ollama-dummy-key").with_base_url(base);
            if let Some(m) = model {
                a = a.with_model(m);
            } else {
                a = a.with_model("llama3");
            }
            Some(Arc::new(a))
        }
        ProviderKind::ClaudeCli => {
            let mut a = ClaudeCliAdapter::new();
            if let Some(m) = model {
                a = a.with_model(m);
            }
            Some(Arc::new(a))
        }
        ProviderKind::Null => Some(Arc::new(NullSynthLlm)),
    }
}

/// Convenience wrapper: auto-select a provider and return a ready
/// `Arc<dyn LlmCodegen>` for `TieredRunner`.
pub fn build_codegen(provider_override: Option<ProviderKind>) -> Arc<dyn LlmCodegen> {
    let kind = auto_select(provider_override);
    match build_llm_adapter(kind) {
        Some(adapter) => Arc::new(SynthesizerLlmCodegen::new(adapter)),
        None => {
            // No usable provider — fall back to a Null bridge so the
            // runner still constructs but medium/hard tiers fail with
            // a clear "no LLM configured" message.
            Arc::new(SynthesizerLlmCodegen::new(Arc::new(NullSynthLlm)))
        }
    }
}

/// True if the operator has supplied at least one signal that an LLM
/// provider is available. Callers use this to decide whether to
/// activate the medium/hard tier escalation path at all.
pub fn llm_signal_present() -> bool {
    std::env::var("MANTIS_LLM_PROVIDER").is_ok()
        || std::env::var("ANTHROPIC_API_KEY").is_ok()
        || std::env::var("OPENAI_API_KEY").is_ok()
        || std::env::var("GROQ_API_KEY").is_ok()
        || std::env::var("OLLAMA_HOST").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_aliases() {
        assert_eq!(
            ProviderKind::parse("anthropic"),
            Some(ProviderKind::Anthropic)
        );
        assert_eq!(ProviderKind::parse("CLAUDE"), Some(ProviderKind::Anthropic));
        assert_eq!(ProviderKind::parse("openai"), Some(ProviderKind::OpenAi));
        assert_eq!(ProviderKind::parse("gpt"), Some(ProviderKind::OpenAi));
        assert_eq!(
            ProviderKind::parse("claude-cli"),
            Some(ProviderKind::ClaudeCli)
        );
        assert_eq!(ProviderKind::parse("groq"), Some(ProviderKind::Groq));
        assert_eq!(ProviderKind::parse("ollama"), Some(ProviderKind::Ollama));
        assert_eq!(ProviderKind::parse("null"), Some(ProviderKind::Null));
        assert_eq!(ProviderKind::parse("bogus"), None);
    }

    #[test]
    fn explicit_override_wins() {
        assert_eq!(auto_select(Some(ProviderKind::Null)), ProviderKind::Null);
    }

    #[test]
    fn build_codegen_always_returns_some_bridge() {
        // Even with no config, we get a non-null bridge that surfaces
        // a clear error on first use.
        let _ = build_codegen(Some(ProviderKind::Null));
    }
}
