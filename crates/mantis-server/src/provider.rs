//! Adapter resolution for the HTTP API. Mirrors `pick_chat_adapter`
//! from `mantis-cli/src/main.rs` so the server picks the same
//! provider as the interactive CLI when no override is requested.
//!
//! Provider catalogue (env var → adapter):
//! - `ANTHROPIC_API_KEY` → AnthropicAdapter
//! - `OPENAI_API_KEY`    → OpenAIAdapter
//! - `GEMINI_API_KEY`    → GeminiAdapter
//! - `MOONSHOT_API_KEY`  → OpenAI-compatible, Moonshot Kimi
//! - `DEEPSEEK_API_KEY`  → OpenAI-compatible, DeepSeek
//! - `GROQ_API_KEY`      → OpenAI-compatible, Groq
//! - `MISTRAL_API_KEY`   → OpenAI-compatible, Mistral
//! - `XAI_API_KEY`       → OpenAI-compatible, xAI / Grok
//! - `OPENROUTER_API_KEY`→ OpenAI-compatible, OpenRouter
//! - `DASHSCOPE_API_KEY` → OpenAI-compatible, Alibaba Qwen
//! - `ZHIPU_API_KEY`     → OpenAI-compatible, Zhipu GLM
//! - `AWS_BEDROCK_PROXY_URL` + `AWS_BEDROCK_API_KEY` → OpenAI-compatible Bedrock proxy
//! - `OLLAMA_HOST`       → OllamaAdapter (local)
//! - `claude` on PATH    → ClaudeCliAdapter

use std::sync::Arc;

use anyhow::{Context, Result};
use mantis_synthesizer::{
    anthropic::AnthropicAdapter, claude_cli::ClaudeCliAdapter, gemini::GeminiAdapter,
    ollama::OllamaAdapter, openai::OpenAIAdapter, LlmAdapter,
};

// Base URLs + default models for OpenAI-compatible providers.
const MOONSHOT_BASE: &str = "https://api.moonshot.cn/v1";
const MOONSHOT_MODEL: &str = "moonshot-v1-32k";
const DEEPSEEK_BASE: &str = "https://api.deepseek.com/v1";
const DEEPSEEK_MODEL: &str = "deepseek-chat";
const GROQ_BASE: &str = "https://api.groq.com/openai/v1";
const GROQ_MODEL: &str = "llama-3.3-70b-versatile";
const MISTRAL_BASE: &str = "https://api.mistral.ai/v1";
const MISTRAL_MODEL: &str = "mistral-large-latest";
const XAI_BASE: &str = "https://api.x.ai/v1";
const XAI_MODEL: &str = "grok-2-latest";
const OPENROUTER_BASE: &str = "https://openrouter.ai/api/v1";
const OPENROUTER_MODEL: &str = "anthropic/claude-3.5-sonnet";
const QWEN_BASE: &str = "https://dashscope.aliyuncs.com/compatible-mode/v1";
const QWEN_MODEL: &str = "qwen-max";
const ZHIPU_BASE: &str = "https://open.bigmodel.cn/api/paas/v4";
const ZHIPU_MODEL: &str = "glm-4-plus";
const BEDROCK_MODEL: &str = "anthropic.claude-3-5-sonnet-20241022-v2:0";

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

    let openai_compat =
        |key: String, base_url: &str, default_model: &str| -> (Arc<dyn LlmAdapter>, String) {
            let model = model_override
                .map(str::to_string)
                .unwrap_or_else(|| default_model.to_string());
            let a = OpenAIAdapter::new(key)
                .with_base_url(base_url)
                .with_model(model.clone())
                .with_max_tokens(4096);
            (Arc::new(a), model)
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
        "moonshot" | "kimi" => {
            let key = std::env::var("MOONSHOT_API_KEY")
                .context("MOONSHOT_API_KEY is not set — get one at platform.moonshot.cn")?;
            openai_compat(key, MOONSHOT_BASE, MOONSHOT_MODEL)
        }
        "deepseek" => {
            let key = std::env::var("DEEPSEEK_API_KEY")
                .context("DEEPSEEK_API_KEY is not set — get one at platform.deepseek.com")?;
            openai_compat(key, DEEPSEEK_BASE, DEEPSEEK_MODEL)
        }
        "groq" => {
            let key = std::env::var("GROQ_API_KEY")
                .context("GROQ_API_KEY is not set — get one at console.groq.com")?;
            openai_compat(key, GROQ_BASE, GROQ_MODEL)
        }
        "mistral" => {
            let key = std::env::var("MISTRAL_API_KEY")
                .context("MISTRAL_API_KEY is not set — get one at console.mistral.ai")?;
            openai_compat(key, MISTRAL_BASE, MISTRAL_MODEL)
        }
        "xai" | "grok" => {
            let key = std::env::var("XAI_API_KEY")
                .context("XAI_API_KEY is not set — get one at console.x.ai")?;
            openai_compat(key, XAI_BASE, XAI_MODEL)
        }
        "openrouter" => {
            let key = std::env::var("OPENROUTER_API_KEY")
                .context("OPENROUTER_API_KEY is not set — get one at openrouter.ai")?;
            openai_compat(key, OPENROUTER_BASE, OPENROUTER_MODEL)
        }
        "qwen" | "dashscope" => {
            let key = std::env::var("DASHSCOPE_API_KEY").context(
                "DASHSCOPE_API_KEY is not set — get one at dashscope.console.aliyun.com",
            )?;
            openai_compat(key, QWEN_BASE, QWEN_MODEL)
        }
        "zhipu" | "glm" => {
            let key = std::env::var("ZHIPU_API_KEY")
                .context("ZHIPU_API_KEY is not set — get one at open.bigmodel.cn")?;
            openai_compat(key, ZHIPU_BASE, ZHIPU_MODEL)
        }
        "bedrock" => {
            let proxy = std::env::var("AWS_BEDROCK_PROXY_URL").context(
                "AWS_BEDROCK_PROXY_URL is not set — point it at a LiteLLM or Bedrock \
                 Access Gateway proxy",
            )?;
            let key = std::env::var("AWS_BEDROCK_API_KEY")
                .context("AWS_BEDROCK_API_KEY is not set (the bearer token your proxy expects)")?;
            openai_compat(key, &proxy, BEDROCK_MODEL)
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
            "unknown provider `{other}` — supported: anthropic, openai, gemini, \
             moonshot (kimi), deepseek, groq, mistral, xai (grok), openrouter, \
             qwen (dashscope), zhipu (glm), bedrock, ollama, claude-cli"
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
    if env_nonempty("MOONSHOT_API_KEY") {
        return "moonshot".into();
    }
    if env_nonempty("DEEPSEEK_API_KEY") {
        return "deepseek".into();
    }
    if env_nonempty("GROQ_API_KEY") {
        return "groq".into();
    }
    if env_nonempty("MISTRAL_API_KEY") {
        return "mistral".into();
    }
    if env_nonempty("XAI_API_KEY") {
        return "xai".into();
    }
    if env_nonempty("OPENROUTER_API_KEY") {
        return "openrouter".into();
    }
    if env_nonempty("DASHSCOPE_API_KEY") {
        return "qwen".into();
    }
    if env_nonempty("ZHIPU_API_KEY") {
        return "zhipu".into();
    }
    if env_nonempty("AWS_BEDROCK_PROXY_URL") && env_nonempty("AWS_BEDROCK_API_KEY") {
        return "bedrock".into();
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
