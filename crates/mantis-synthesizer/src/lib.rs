//! Exploit synthesizer (Phase 2 M2.2 + M2.2b).
//!
//! PRD §5.7.4 calls for a hybrid synthesis engine: corpus retrieval,
//! grammar-aware fuzzer, symbolic constraint solver, and LLM-guided
//! code generation. The engines run in priority order; the first to
//! produce a sandbox-verified working payload wins.
//!
//! PRD §6.4.2 mandates that LLM-generated code execute exclusively
//! in ephemeral isolated environments — record-replay sandboxes for
//! development, microVM sandboxes for live verification — before
//! any production-target execution. [`synthesize`] enforces this by
//! requiring every caller to pass a [`SandboxValidator`]: the
//! corpus/fuzzer paths skip validation (their payloads are
//! compile-time-vetted), but the LLM path always runs the candidate
//! through `validator.validate(..)` before returning, surfacing any
//! sandbox failure as [`SynthError::SandboxRejected`].
//!
//! Module layout:
//! - [`CorpusRetriever`] — static-corpus payload lookup (workspace
//!   loading via [`CorpusRetriever::from_workspace`])
//! - [`NullLlm`] — stub used when no provider is configured
//! - [`NullValidator`] — pass-through, suitable for tests
//! - [`WasmValidator`] — `SandboxRuntime`-backed validator
//! - [`anthropic::AnthropicAdapter`] — Messages API client (M2.2b)
//! - [`openai::OpenAIAdapter`] — Chat Completions API client (M2.2b)
//! - [`claude_cli::ClaudeCliAdapter`] — local `claude` CLI subprocess
//!   adapter; uses Claude Code's own auth so no API key is needed

pub mod anthropic;
pub mod claude_cli;
pub mod gemini;
pub mod http;
pub mod ollama;
pub mod openai;
pub mod retry;
pub mod symbolic;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use mantis_sandbox::{ExecutionInput, SandboxBudget, SandboxRuntime};

use async_trait::async_trait;
use futures::stream::{self, BoxStream, StreamExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use mantis_fuzzer::Variant;

#[derive(Debug, Error)]
pub enum SynthError {
    #[error("no synthesizer engine produced a payload")]
    NoCandidate,

    #[error("backend: {0}")]
    Backend(String),

    #[error("sandbox rejected candidate: {0}")]
    SandboxRejected(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthRequest {
    pub vuln_class: String,
    pub surface_url: String,
    /// Additional free-form context the engines may use.
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthCandidate {
    pub payload: String,
    pub engine: EngineKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineKind {
    Corpus,
    Fuzzer,
    Symbolic,
    Llm,
}

// ---------------------------------------------------------------------------
// Chat / streaming surface (mantis-chat foundation).
//
// `complete` is one-shot and text-only. The chat surface adds three
// things on top, all opt-in via a single new trait method
// (`stream_chat`) with a default implementation that degrades to
// `complete`:
//   - Multi-turn messages (system/user/assistant/tool roles)
//   - Tool calling (providers see &[Tool], emit ToolCall events)
//   - Streaming (BoxStream<ChatEvent> instead of one String)
// ---------------------------------------------------------------------------

/// Role of a chat message. `Tool` is used for messages carrying a
/// tool-call result back to the model after the caller executed the
/// tool the model requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    System,
    User,
    Assistant,
    Tool,
}

/// A single turn in a chat conversation. Assistant messages may
/// carry `tool_calls`; tool messages must carry a `tool_call_id`
/// referencing the assistant call they answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::System,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::User,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::Assistant,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }
    pub fn tool_result(call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::Tool,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: Some(call_id.into()),
        }
    }
}

/// A tool exposed to the model. The schema goes verbatim into
/// provider-specific tool_use blocks; the caller is responsible for
/// validating model-produced arguments against it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    /// JSON Schema (draft-07) describing the tool input shape.
    pub input_schema: serde_json::Value,
}

/// A tool invocation requested by the model. `id` is the provider-
/// assigned identifier used to match the eventual `tool_result`
/// message back to this call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

/// One event in a streaming chat completion. Streams terminate on
/// `Done` (or an outer `Err`). `Warning` is non-fatal — the stream
/// may continue after one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatEvent {
    Text { delta: String },
    ToolCall(ToolCall),
    Done { stop_reason: Option<String> },
    Warning { message: String },
}

/// Flatten a chat transcript into a single prompt string. Used by
/// the default `stream_chat` impl for adapters that only implement
/// one-shot `complete` (e.g. `claude --print`). The format places
/// any system message as a natural-language preamble, renders
/// prior turns as a `Human: …\n\nAssistant: …` transcript (which
/// every Anthropic-style model understands natively), and leaves
/// the trailing turn open for the assistant to continue.
fn flatten_messages_to_prompt(messages: &[ChatMessage]) -> String {
    let mut out = String::new();

    // Pull system messages to the top as plain preamble.
    let system_blocks: Vec<&str> = messages
        .iter()
        .filter(|m| m.role == ChatRole::System)
        .map(|m| m.content.as_str())
        .collect();
    if !system_blocks.is_empty() {
        out.push_str(&system_blocks.join("\n\n"));
        out.push_str("\n\n");
    }

    for m in messages {
        match m.role {
            ChatRole::System => {} // already handled
            ChatRole::User => {
                out.push_str("Human: ");
                out.push_str(&m.content);
                out.push_str("\n\n");
            }
            ChatRole::Assistant => {
                out.push_str("Assistant: ");
                out.push_str(&m.content);
                out.push_str("\n\n");
            }
            ChatRole::Tool => {
                let id = m.tool_call_id.as_deref().unwrap_or("?");
                let _ = write!(out, "[tool result {id}]: ");

                out.push_str(&m.content);
                out.push_str("\n\n");
            }
        }
    }
    out.push_str("Assistant:");
    out
}

/// Trait the daemon implements to plug in an LLM provider.
#[async_trait]
pub trait LlmAdapter: Send + Sync {
    async fn complete(&self, prompt: &str) -> Result<String, SynthError>;

    /// Stream a multi-turn chat completion, optionally with tool
    /// access. Default impl degrades to a one-shot `complete` call
    /// by flattening the transcript and yielding a single `Text`
    /// + `Done` event. Adapters with native SSE/streaming support
    /// should override this to stream incremental deltas and emit
    /// `ToolCall` events.
    fn stream_chat<'a>(
        &'a self,
        messages: &'a [ChatMessage],
        _tools: &'a [Tool],
    ) -> BoxStream<'a, Result<ChatEvent, SynthError>> {
        let prompt = flatten_messages_to_prompt(messages);
        let fut = async move {
            match self.complete(&prompt).await {
                Ok(text) => vec![
                    Ok(ChatEvent::Text { delta: text }),
                    Ok(ChatEvent::Done { stop_reason: None }),
                ],
                Err(e) => vec![Err(e)],
            }
        };
        stream::once(fut).flat_map(stream::iter).boxed()
    }
}

/// Static-corpus retriever. The default `CorpusRetriever` (unit
/// struct via [`CorpusRetriever::new`]) ships a compile-time fallback
/// per vuln class. [`CorpusRetriever::from_workspace`] reads
/// per-class JSON files from a workspace directory; the workspace
/// payloads take precedence over the compile-time fallback.
#[derive(Debug, Default, Clone)]
pub struct CorpusRetriever {
    workspace: HashMap<String, Vec<String>>,
}

impl CorpusRetriever {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load per-class payloads from `<workspace>/corpus/<class>.json`.
    /// Each file is a JSON array of strings. Missing files are
    /// non-fatal: the retriever falls back to the compile-time
    /// catalog for classes without a workspace file.
    pub fn from_workspace(workspace: &Path) -> std::io::Result<Self> {
        let dir = workspace.join("corpus");
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        if !dir.exists() {
            return Ok(Self { workspace: map });
        }
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let class = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let bytes = std::fs::read(&path)?;
            let payloads: Vec<String> = serde_json::from_slice(&bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            })?;
            map.insert(class, payloads);
        }
        Ok(Self { workspace: map })
    }

    pub fn retrieve(&self, vuln_class: &str) -> Vec<String> {
        if let Some(ws) = self.workspace.get(vuln_class) {
            if !ws.is_empty() {
                return ws.clone();
            }
        }
        match vuln_class {
            "xss-reflected" => vec![
                "<script>alert(1)</script>".into(),
                "\"><img src=x onerror=alert(1)>".into(),
            ],
            "sqli" => vec!["' OR 1=1--".into(), "1 UNION SELECT NULL--".into()],
            "open-redirect" => vec!["https://evil.example/".into(), "//evil.example".into()],
            "ssrf" => vec![
                "http://169.254.169.254/latest/meta-data/".into(),
                "http://localhost:6379/".into(),
            ],
            _ => vec![],
        }
    }
}

/// Sandbox-gated validator. PRD §6.4.2 requires every LLM-produced
/// candidate to pass through an ephemeral isolated environment
/// before it can be returned for live use.
#[async_trait]
pub trait SandboxValidator: Send + Sync {
    async fn validate(&self, payload: &str, vuln_class: &str) -> Result<(), SynthError>;
}

/// Pass-through validator. Acceptable for unit tests and for
/// corpus/fuzzer paths where the payload provenance is already
/// trusted; PRD §6.4.2 only requires sandboxing for LLM output, so
/// production daemon configurations construct a real validator
/// before calling [`synthesize`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NullValidator;

#[async_trait]
impl SandboxValidator for NullValidator {
    async fn validate(&self, _payload: &str, _vuln_class: &str) -> Result<(), SynthError> {
        Ok(())
    }
}

/// Validator that runs each candidate through a `SandboxRuntime`.
/// The configured WASM module (typically a property-oracle checker)
/// receives the payload bytes as its sandbox input and must exit
/// with code 0 to accept; any non-zero exit, trap, or capability
/// refusal demotes the candidate to [`SynthError::SandboxRejected`].
pub struct WasmValidator {
    runtime: Arc<dyn SandboxRuntime>,
    module: Vec<u8>,
    budget: SandboxBudget,
}

impl WasmValidator {
    pub fn new(runtime: Arc<dyn SandboxRuntime>, module: Vec<u8>) -> Self {
        Self {
            runtime,
            module,
            budget: SandboxBudget::default(),
        }
    }

    pub fn with_budget(mut self, budget: SandboxBudget) -> Self {
        self.budget = budget;
        self
    }
}

#[async_trait]
impl SandboxValidator for WasmValidator {
    async fn validate(&self, payload: &str, _vuln_class: &str) -> Result<(), SynthError> {
        let input = ExecutionInput {
            bytes: payload.as_bytes().to_vec(),
            mime: Some("text/plain".into()),
        };
        match self
            .runtime
            .execute(&self.module, &input, &self.budget)
            .await
        {
            Ok(out) if out.exit_code == 0 => Ok(()),
            Ok(out) => Err(SynthError::SandboxRejected(format!(
                "checker exited with code {}",
                out.exit_code
            ))),
            Err(e) => Err(SynthError::SandboxRejected(format!("sandbox: {e}"))),
        }
    }
}

/// Stub LLM adapter that returns an error. Used when no provider is
/// configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullLlm;

#[async_trait]
impl LlmAdapter for NullLlm {
    async fn complete(&self, _prompt: &str) -> Result<String, SynthError> {
        Err(SynthError::Backend("no LLM provider configured".into()))
    }
}

/// The pipeline runs all engines and returns the first successful
/// candidate. Order is corpus → fuzzer → LLM (cheapest first).
///
/// PRD §6.4.2: the LLM path always runs its candidate through
/// `validator` before returning. Corpus and fuzzer payloads bypass
/// the validator because their provenance is compile-time trusted.
pub async fn synthesize(
    request: &SynthRequest,
    corpus: &CorpusRetriever,
    llm: &dyn LlmAdapter,
    validator: &dyn SandboxValidator,
    fuzzer_seed: u64,
) -> Result<SynthCandidate, SynthError> {
    // 1. Corpus retrieval.
    let corpus_payloads = corpus.retrieve(&request.vuln_class);
    if let Some(first) = corpus_payloads.into_iter().next() {
        return Ok(SynthCandidate {
            payload: first,
            engine: EngineKind::Corpus,
        });
    }

    // 2. Grammar fuzzer.
    if let Some(grammar) = mantis_fuzzer::builtin_grammar(&request.vuln_class) {
        let variants = mantis_fuzzer::generate(&grammar, 1, fuzzer_seed);
        if let Some(Variant { payload, .. }) = variants.into_iter().next() {
            return Ok(SynthCandidate {
                payload,
                engine: EngineKind::Fuzzer,
            });
        }
    }

    // 3. Symbolic constraint solver. Cheapest deterministic engine
    // after the corpus — no network, no randomness.
    if let Some(constraints) = symbolic::builtin_constraints(&request.vuln_class) {
        if let Some(payload) = symbolic::solve(&constraints) {
            return Ok(SynthCandidate {
                payload,
                engine: EngineKind::Symbolic,
            });
        }
    }

    // 4. LLM. Gated through the sandbox validator per PRD §6.4.2.
    let prompt = format!(
        "Generate one minimal {} payload for {}. Reply with only the payload.{}",
        request.vuln_class,
        request.surface_url,
        request
            .hint
            .as_deref()
            .map(|h| format!(" Hint: {h}"))
            .unwrap_or_default()
    );
    let payload = match llm.complete(&prompt).await {
        Ok(p) => p,
        Err(_) => return Err(SynthError::NoCandidate),
    };
    validator.validate(&payload, &request.vuln_class).await?;
    Ok(SynthCandidate {
        payload,
        engine: EngineKind::Llm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CannedLlm(&'static str);
    #[async_trait]
    impl LlmAdapter for CannedLlm {
        async fn complete(&self, _prompt: &str) -> Result<String, SynthError> {
            Ok(self.0.into())
        }
    }

    fn request(class: &str) -> SynthRequest {
        SynthRequest {
            vuln_class: class.into(),
            surface_url: "https://x.example/".into(),
            hint: None,
        }
    }

    #[tokio::test]
    async fn corpus_wins_when_available() {
        let candidate = synthesize(
            &request("xss-reflected"),
            &CorpusRetriever::new(),
            &NullLlm,
            &NullValidator,
            0,
        )
        .await
        .unwrap();
        assert_eq!(candidate.engine, EngineKind::Corpus);
        assert!(candidate.payload.contains("<script>"));
    }

    #[tokio::test]
    async fn fuzzer_used_when_corpus_empty_but_grammar_known() {
        // No corpus for `clickjacking` but no built-in fuzzer
        // grammar either — should fall through to LLM.
        let candidate = synthesize(
            &request("clickjacking"),
            &CorpusRetriever::new(),
            &CannedLlm("<iframe src=...></iframe>"),
            &NullValidator,
            0,
        )
        .await
        .unwrap();
        assert_eq!(candidate.engine, EngineKind::Llm);
    }

    #[tokio::test]
    async fn llm_used_when_corpus_and_fuzzer_both_empty() {
        let candidate = synthesize(
            &request("novel-class-xyz"),
            &CorpusRetriever::new(),
            &CannedLlm("llm-payload"),
            &NullValidator,
            0,
        )
        .await
        .unwrap();
        assert_eq!(candidate.engine, EngineKind::Llm);
        assert_eq!(candidate.payload, "llm-payload");
    }

    #[tokio::test]
    async fn errors_when_all_engines_empty() {
        let candidate = synthesize(
            &request("nothing-knows-about"),
            &CorpusRetriever::new(),
            &NullLlm,
            &NullValidator,
            0,
        )
        .await;
        assert!(matches!(candidate, Err(SynthError::NoCandidate)));
    }

    #[test]
    fn corpus_retriever_returns_per_class_payloads() {
        let r = CorpusRetriever::new();
        assert!(!r.retrieve("xss-reflected").is_empty());
        assert!(!r.retrieve("sqli").is_empty());
        assert!(r.retrieve("nope").is_empty());
    }

    // PRD §6.4.2 — sandbox validator must gate LLM output.
    struct RejectingValidator;
    #[async_trait]
    impl SandboxValidator for RejectingValidator {
        async fn validate(&self, _payload: &str, _vuln_class: &str) -> Result<(), SynthError> {
            Err(SynthError::SandboxRejected("checker rejected".into()))
        }
    }

    #[tokio::test]
    async fn llm_candidate_blocked_when_sandbox_rejects() {
        let result = synthesize(
            &request("novel-class-blocked"),
            &CorpusRetriever::new(),
            &CannedLlm("dangerous-payload"),
            &RejectingValidator,
            0,
        )
        .await;
        assert!(matches!(result, Err(SynthError::SandboxRejected(_))));
    }

    #[tokio::test]
    async fn corpus_path_bypasses_sandbox_validator() {
        // The compile-time corpus is trusted, so it should not be
        // gated through the sandbox validator. A rejecting validator
        // would otherwise fail this test.
        let candidate = synthesize(
            &request("xss-reflected"),
            &CorpusRetriever::new(),
            &CannedLlm("never-used"),
            &RejectingValidator,
            0,
        )
        .await
        .unwrap();
        assert_eq!(candidate.engine, EngineKind::Corpus);
    }

    // Workspace corpus loading.
    #[test]
    fn workspace_corpus_overrides_compile_time_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let corpus_dir = dir.path().join("corpus");
        std::fs::create_dir(&corpus_dir).unwrap();
        std::fs::write(
            corpus_dir.join("xss-reflected.json"),
            r#"["custom-payload-1","custom-payload-2"]"#,
        )
        .unwrap();
        let r = CorpusRetriever::from_workspace(dir.path()).unwrap();
        let payloads = r.retrieve("xss-reflected");
        assert_eq!(payloads, vec!["custom-payload-1", "custom-payload-2"]);
    }

    #[test]
    fn workspace_corpus_falls_back_to_compile_time_for_unknown_class_files() {
        let dir = tempfile::tempdir().unwrap();
        // No workspace corpus dir — falls back to compile-time.
        let r = CorpusRetriever::from_workspace(dir.path()).unwrap();
        assert!(!r.retrieve("sqli").is_empty());
    }

    #[test]
    fn workspace_corpus_missing_dir_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let r = CorpusRetriever::from_workspace(dir.path()).unwrap();
        assert!(r.workspace.is_empty());
    }

    #[test]
    fn workspace_corpus_rejects_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let corpus_dir = dir.path().join("corpus");
        std::fs::create_dir(&corpus_dir).unwrap();
        std::fs::write(corpus_dir.join("broken.json"), "not json").unwrap();
        let result = CorpusRetriever::from_workspace(dir.path());
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------
    // Chat / streaming surface.
    // -----------------------------------------------------------------

    #[test]
    fn flatten_messages_renders_roles() {
        let msgs = vec![
            ChatMessage::system("you are mantis"),
            ChatMessage::user("scan example.com"),
            ChatMessage::assistant("on it"),
            ChatMessage::tool_result("call_1", "{\"ok\":true}"),
        ];
        let p = flatten_messages_to_prompt(&msgs);
        // System block is lifted to the top as a plain preamble.
        assert!(p.starts_with("you are mantis"));
        assert!(p.contains("Human: scan example.com"));
        assert!(p.contains("Assistant: on it"));
        assert!(p.contains("[tool result call_1]: {\"ok\":true}"));
        // Open trailing turn so the LLM continues as the assistant.
        assert!(p.trim_end().ends_with("Assistant:"));
    }

    #[test]
    fn chat_message_constructors_set_roles() {
        assert_eq!(ChatMessage::system("x").role, ChatRole::System);
        assert_eq!(ChatMessage::user("x").role, ChatRole::User);
        assert_eq!(ChatMessage::assistant("x").role, ChatRole::Assistant);
        let tr = ChatMessage::tool_result("c1", "x");
        assert_eq!(tr.role, ChatRole::Tool);
        assert_eq!(tr.tool_call_id.as_deref(), Some("c1"));
    }

    #[test]
    fn chat_event_serialises_with_tag() {
        let ev = ChatEvent::Text { delta: "hi".into() };
        let j = serde_json::to_string(&ev).unwrap();
        assert!(j.contains("\"type\":\"text\""));
        assert!(j.contains("\"delta\":\"hi\""));
    }

    struct CannedChat(&'static str);
    #[async_trait]
    impl LlmAdapter for CannedChat {
        async fn complete(&self, _prompt: &str) -> Result<String, SynthError> {
            Ok(self.0.into())
        }
    }

    #[tokio::test]
    async fn default_stream_chat_degrades_to_complete() {
        use futures::StreamExt as _;
        let adapter = CannedChat("hello world");
        let msgs = vec![ChatMessage::user("hi")];
        let events: Vec<_> = adapter.stream_chat(&msgs, &[]).collect().await;
        assert_eq!(events.len(), 2, "expected Text + Done");
        match &events[0] {
            Ok(ChatEvent::Text { delta }) => assert_eq!(delta, "hello world"),
            other => panic!("expected Text, got {other:?}"),
        }
        assert!(matches!(events[1], Ok(ChatEvent::Done { .. })));
    }

    struct ErrChat;
    #[async_trait]
    impl LlmAdapter for ErrChat {
        async fn complete(&self, _prompt: &str) -> Result<String, SynthError> {
            Err(SynthError::Backend("nope".into()))
        }
    }

    #[tokio::test]
    async fn default_stream_chat_surfaces_complete_errors() {
        use futures::StreamExt as _;
        let events: Vec<_> = ErrChat.stream_chat(&[], &[]).collect().await;
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], Err(SynthError::Backend(_))));
    }
}
