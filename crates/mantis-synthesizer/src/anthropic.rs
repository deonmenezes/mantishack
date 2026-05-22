//! Anthropic Messages API adapter (PRD §5.7.4, M2.2b).
//!
//! Talks to the Anthropic Messages endpoint (`/v1/messages`) and
//! returns the concatenated text of the first non-empty text block.
//! The default model is `claude-opus-4-7` (the most-capable model
//! at the time of writing); pass any other model id via
//! [`AnthropicAdapter::with_model`].

use async_trait::async_trait;
use futures::stream::{self, BoxStream, StreamExt};
use serde::{Deserialize, Serialize};

use crate::retry::{classify_status, parse_retry_after, RetryDecision, RetryPolicy};
use crate::{ChatEvent, ChatMessage, ChatRole, LlmAdapter, SynthError, Tool, ToolCall};

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
const DEFAULT_MODEL: &str = "claude-opus-4-7";
const DEFAULT_API_VERSION: &str = "2023-06-01";
const DEFAULT_MAX_TOKENS: u32 = 1024;

#[derive(Debug, Clone)]
pub struct AnthropicAdapter {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
    api_version: String,
    max_tokens: u32,
    retry: RetryPolicy,
    /// When true (default), attaches `cache_control: ephemeral`
    /// markers to the system prompt and the last tool definition.
    /// Anthropic then caches the system + tools prefix for 5
    /// minutes and bills cache reads at 10% of the input price.
    /// Reply quality is identical — purely a server-side hint.
    cache_prompts: bool,
}

impl AnthropicAdapter {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            // Process-wide pooled client — shares TLS sessions and
            // HTTP/1.1 keep-alive across every adapter instance.
            client: crate::http::shared_client(),
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.into(),
            model: DEFAULT_MODEL.into(),
            api_version: DEFAULT_API_VERSION.into(),
            max_tokens: DEFAULT_MAX_TOKENS,
            retry: RetryPolicy::default(),
            cache_prompts: true,
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Toggle prompt caching. On by default — disable only for
    /// tests that assert on the raw request body shape.
    pub fn with_prompt_caching(mut self, enabled: bool) -> Self {
        self.cache_prompts = enabled;
        self
    }
}

#[async_trait]
impl LlmAdapter for AnthropicAdapter {
    async fn complete(&self, prompt: &str) -> Result<String, SynthError> {
        let body = Request {
            model: &self.model,
            max_tokens: self.max_tokens,
            messages: vec![Message {
                role: "user",
                content: prompt,
            }],
        };
        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| SynthError::Backend(format!("anthropic serialize: {e}")))?;

        let mut last_error = String::new();
        for attempt in 1..=self.retry.max_attempts {
            let resp = self
                .client
                .post(&url)
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", &self.api_version)
                .header("content-type", "application/json")
                .body(body_bytes.clone())
                .send()
                .await
                .map_err(|e| SynthError::Backend(format!("anthropic request: {e}")))?;

            let status = resp.status().as_u16();
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_retry_after);
            let text = resp
                .text()
                .await
                .map_err(|e| SynthError::Backend(format!("anthropic body: {e}")))?;

            match classify_status(status, retry_after, &self.retry, attempt) {
                RetryDecision::Done => {
                    let parsed: Response = serde_json::from_str(&text)
                        .map_err(|e| SynthError::Backend(format!("anthropic parse: {e}")))?;
                    return parsed
                        .content
                        .into_iter()
                        .find_map(|block| match block {
                            ContentBlock::Text { text } if !text.is_empty() => Some(text),
                            _ => None,
                        })
                        .ok_or_else(|| {
                            SynthError::Backend("anthropic returned no text block".into())
                        });
                }
                RetryDecision::Retry(delay) => {
                    last_error = format!("anthropic {status}: {text}");
                    tokio::time::sleep(delay).await;
                    continue;
                }
                RetryDecision::Fatal => {
                    return Err(SynthError::Backend(format!("anthropic {status}: {text}")));
                }
            }
        }
        Err(SynthError::Backend(format!(
            "anthropic exhausted retries: {last_error}"
        )))
    }

    fn stream_chat<'a>(
        &'a self,
        messages: &'a [ChatMessage],
        tools: &'a [Tool],
    ) -> BoxStream<'a, Result<ChatEvent, SynthError>> {
        let fut = async move {
            match self.run_stream_chat(messages, tools).await {
                Ok(events) => events,
                Err(e) => vec![Err(e)],
            }
        };
        stream::once(fut).flat_map(stream::iter).boxed()
    }
}

impl AnthropicAdapter {
    /// Issue a streaming `/v1/messages` request and collect SSE events
    /// into an ordered vector of [`ChatEvent`]s. See the analogous
    /// note in `openai.rs::run_stream_chat` — we buffer the body
    /// before parsing because the workspace reqwest config doesn't
    /// expose `bytes_stream()`. The parser API is identical, so
    /// flipping to a streaming `Response::bytes_stream()` would be
    /// a localized change.
    async fn run_stream_chat(
        &self,
        messages: &[ChatMessage],
        tools: &[Tool],
    ) -> Result<Vec<Result<ChatEvent, SynthError>>, SynthError> {
        let (system_text, request_messages) = chat_messages_to_anthropic(messages);
        let mut req_tools: Vec<StreamTool> = tools.iter().map(tool_to_anthropic).collect();

        // Wrap the system prompt in the array-form `SystemField` so
        // we can attach a cache marker. On the last tool, set the
        // same marker — Anthropic caches everything up to that
        // point (system + all tools). Subsequent turns get 10%
        // input pricing on the cached prefix and ~30% faster TTFT.
        let system_field = match system_text {
            None => None,
            Some(text) if text.is_empty() => None,
            Some(text) => Some(if self.cache_prompts {
                SystemField::Blocks(vec![SystemBlock {
                    typ: "text",
                    text,
                    cache_control: Some(CacheControl::ephemeral()),
                }])
            } else {
                SystemField::Text(text)
            }),
        };
        if self.cache_prompts {
            if let Some(last) = req_tools.last_mut() {
                last.cache_control = Some(CacheControl::ephemeral());
            }
        }

        let body = StreamRequest {
            model: &self.model,
            max_tokens: self.max_tokens,
            stream: true,
            system: system_field,
            messages: request_messages,
            tools: if req_tools.is_empty() {
                None
            } else {
                Some(req_tools)
            },
        };
        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| SynthError::Backend(format!("anthropic stream serialize: {e}")))?;

        let mut last_error = String::new();
        for attempt in 1..=self.retry.max_attempts {
            let resp = self
                .client
                .post(&url)
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", &self.api_version)
                .header("content-type", "application/json")
                .header("accept", "text/event-stream")
                .body(body_bytes.clone())
                .send()
                .await
                .map_err(|e| SynthError::Backend(format!("anthropic stream request: {e}")))?;

            let status = resp.status().as_u16();
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_retry_after);

            match classify_status(status, retry_after, &self.retry, attempt) {
                RetryDecision::Done => {
                    let bytes = resp
                        .bytes()
                        .await
                        .map_err(|e| SynthError::Backend(format!("anthropic stream body: {e}")))?;
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    return Ok(parse_anthropic_sse(&text));
                }
                RetryDecision::Retry(delay) => {
                    let text = resp.text().await.unwrap_or_default();
                    last_error = format!("anthropic stream {status}: {text}");
                    tokio::time::sleep(delay).await;
                    continue;
                }
                RetryDecision::Fatal => {
                    let text = resp.text().await.unwrap_or_default();
                    return Err(SynthError::Backend(format!(
                        "anthropic stream {status}: {text}"
                    )));
                }
            }
        }
        Err(SynthError::Backend(format!(
            "anthropic stream exhausted retries: {last_error}"
        )))
    }
}

// ---------------------------------------------------------------------------
// SSE / request wire types and parsing for /v1/messages streaming.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StreamRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<SystemField>,
    messages: Vec<StreamMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<StreamTool>>,
}

/// Anthropic accepts `system` as either a string or an array of
/// content blocks. The array form lets us attach a
/// `cache_control: {"type":"ephemeral"}` marker to the last block,
/// which caches the system prompt server-side for 5 minutes —
/// subsequent turns pay 10% of input price on the cached prefix
/// instead of the full rate. Reply quality is identical; it's
/// purely an infrastructure hint.
#[derive(Serialize)]
#[serde(untagged)]
enum SystemField {
    Text(String),
    Blocks(Vec<SystemBlock>),
}

#[derive(Serialize)]
struct SystemBlock {
    #[serde(rename = "type")]
    typ: &'static str,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<CacheControl>,
}

/// Marker attached to a system block or the last tool definition to
/// signal "cache everything up to here on the server for 5 minutes."
/// See https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching
#[derive(Serialize, Clone, Copy)]
struct CacheControl {
    #[serde(rename = "type")]
    typ: &'static str,
}

impl CacheControl {
    const fn ephemeral() -> Self {
        Self { typ: "ephemeral" }
    }
}

#[derive(Serialize)]
struct StreamMessage {
    role: &'static str,
    content: StreamContent,
}

/// Anthropic accepts either a string or an array of content blocks
/// for `messages[].content`. We always emit blocks when there's
/// tool-related content; plain text becomes a `String` for brevity.
#[derive(Serialize)]
#[serde(untagged)]
enum StreamContent {
    Text(String),
    Blocks(Vec<StreamContentBlock>),
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum StreamContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
    },
}

#[derive(Serialize)]
struct StreamTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
    /// When set on the LAST tool in the list, Anthropic caches the
    /// entire system + tools prefix server-side. Subsequent turns
    /// reuse the cache for 5 minutes at 10% of input price.
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<CacheControl>,
}

/// Convert a transcript into Anthropic's `(system, messages)`
/// shape. Tool messages render as a `user` turn containing a single
/// `tool_result` block; assistant messages with `tool_calls` render
/// as a mixed text + tool_use block list.
fn chat_messages_to_anthropic(messages: &[ChatMessage]) -> (Option<String>, Vec<StreamMessage>) {
    let mut system_parts: Vec<String> = Vec::new();
    let mut out: Vec<StreamMessage> = Vec::new();
    for m in messages {
        match m.role {
            ChatRole::System => {
                if !m.content.is_empty() {
                    system_parts.push(m.content.clone());
                }
            }
            ChatRole::User => {
                out.push(StreamMessage {
                    role: "user",
                    content: StreamContent::Text(m.content.clone()),
                });
            }
            ChatRole::Assistant => {
                if m.tool_calls.is_empty() {
                    out.push(StreamMessage {
                        role: "assistant",
                        content: StreamContent::Text(m.content.clone()),
                    });
                } else {
                    let mut blocks: Vec<StreamContentBlock> = Vec::new();
                    if !m.content.is_empty() {
                        blocks.push(StreamContentBlock::Text {
                            text: m.content.clone(),
                        });
                    }
                    for tc in &m.tool_calls {
                        blocks.push(StreamContentBlock::ToolUse {
                            id: tc.id.clone(),
                            name: tc.name.clone(),
                            input: tc.arguments.clone(),
                        });
                    }
                    out.push(StreamMessage {
                        role: "assistant",
                        content: StreamContent::Blocks(blocks),
                    });
                }
            }
            ChatRole::Tool => {
                let id = m.tool_call_id.clone().unwrap_or_default();
                out.push(StreamMessage {
                    role: "user",
                    content: StreamContent::Blocks(vec![StreamContentBlock::ToolResult {
                        tool_use_id: id,
                        content: m.content.clone(),
                    }]),
                });
            }
        }
    }
    let system = if system_parts.is_empty() {
        None
    } else {
        Some(system_parts.join("\n\n"))
    };
    (system, out)
}

fn tool_to_anthropic(t: &Tool) -> StreamTool {
    StreamTool {
        name: t.name.clone(),
        description: t.description.clone(),
        input_schema: t.input_schema.clone(),
        // `run_stream_chat` decides which tool gets the cache
        // marker (the last one) — default is None here.
        cache_control: None,
    }
}

// SSE event payload shapes we care about.

#[derive(Deserialize)]
struct ContentBlockStart {
    index: usize,
    content_block: StartedBlock,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum StartedBlock {
    #[serde(rename = "tool_use")]
    ToolUse { id: String, name: String },
    // `text` blocks emit deltas via `content_block_delta`, so we
    // don't need to capture their initial (usually empty) text here.
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct ContentBlockDelta {
    index: usize,
    delta: BlockDeltaPayload,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum BlockDeltaPayload {
    #[serde(rename = "text_delta")]
    TextDelta { text: String },
    #[serde(rename = "input_json_delta")]
    InputJsonDelta { partial_json: String },
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct ContentBlockStop {
    index: usize,
}

#[derive(Deserialize)]
struct MessageDelta {
    delta: MessageDeltaInner,
}

#[derive(Deserialize)]
struct MessageDeltaInner {
    #[serde(default)]
    stop_reason: Option<String>,
}

#[derive(Default)]
struct AnthropicToolBuffer {
    id: String,
    name: String,
    arguments: String,
}

/// Parse a buffered Anthropic SSE response into an ordered list of
/// `ChatEvent`s. Anthropic emits typed events:
///   event: <type>
///   data: <json>
///   (blank line)
fn parse_anthropic_sse(body: &str) -> Vec<Result<ChatEvent, SynthError>> {
    let mut events: Vec<Result<ChatEvent, SynthError>> = Vec::new();
    // Buffer per content-block index. Only `tool_use` blocks need a
    // buffer; text blocks emit their delta immediately.
    let mut tool_buffers: std::collections::HashMap<usize, AnthropicToolBuffer> =
        std::collections::HashMap::new();
    let mut stop_reason: Option<String> = None;

    for frame in body.split("\n\n") {
        let frame = frame.trim_start_matches('\r').trim();
        if frame.is_empty() {
            continue;
        }
        let mut event_name: Option<String> = None;
        let mut payload = String::new();
        for line in frame.lines() {
            let line = line.trim_end_matches('\r');
            if let Some(rest) = line.strip_prefix("event:") {
                event_name = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                if !payload.is_empty() {
                    payload.push('\n');
                }
                payload.push_str(rest.trim_start());
            }
        }
        let Some(name) = event_name else { continue };
        match name.as_str() {
            "content_block_start" => {
                let parsed: ContentBlockStart = match serde_json::from_str(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        events.push(Ok(ChatEvent::Warning {
                            message: format!("anthropic content_block_start parse: {e}"),
                        }));
                        continue;
                    }
                };
                if let StartedBlock::ToolUse { id, name } = parsed.content_block {
                    tool_buffers.insert(
                        parsed.index,
                        AnthropicToolBuffer {
                            id,
                            name,
                            arguments: String::new(),
                        },
                    );
                }
            }
            "content_block_delta" => {
                let parsed: ContentBlockDelta = match serde_json::from_str(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        events.push(Ok(ChatEvent::Warning {
                            message: format!("anthropic content_block_delta parse: {e}"),
                        }));
                        continue;
                    }
                };
                match parsed.delta {
                    BlockDeltaPayload::TextDelta { text } => {
                        if !text.is_empty() {
                            events.push(Ok(ChatEvent::Text { delta: text }));
                        }
                    }
                    BlockDeltaPayload::InputJsonDelta { partial_json } => {
                        if let Some(buf) = tool_buffers.get_mut(&parsed.index) {
                            buf.arguments.push_str(&partial_json);
                        }
                    }
                    BlockDeltaPayload::Other => {}
                }
            }
            "content_block_stop" => {
                let parsed: ContentBlockStop = match serde_json::from_str(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        events.push(Ok(ChatEvent::Warning {
                            message: format!("anthropic content_block_stop parse: {e}"),
                        }));
                        continue;
                    }
                };
                if let Some(buf) = tool_buffers.remove(&parsed.index) {
                    let arguments = if buf.arguments.is_empty() {
                        serde_json::Value::Object(Default::default())
                    } else {
                        match serde_json::from_str::<serde_json::Value>(&buf.arguments) {
                            Ok(v) => v,
                            Err(e) => {
                                events.push(Ok(ChatEvent::Warning {
                                    message: format!(
                                        "anthropic tool args parse ({}): {e}",
                                        buf.name
                                    ),
                                }));
                                serde_json::Value::String(buf.arguments.clone())
                            }
                        }
                    };
                    events.push(Ok(ChatEvent::ToolCall(ToolCall {
                        id: buf.id,
                        name: buf.name,
                        arguments,
                    })));
                }
            }
            "message_delta" => {
                if let Ok(parsed) = serde_json::from_str::<MessageDelta>(&payload) {
                    if let Some(reason) = parsed.delta.stop_reason {
                        stop_reason = Some(reason);
                    }
                }
            }
            "message_stop" => {
                events.push(Ok(ChatEvent::Done {
                    stop_reason: stop_reason.clone(),
                }));
                return events;
            }
            "message_start" | "ping" => {}
            _ => {}
        }
    }
    // Stream ended without a `message_stop`. Synthesize one so the
    // caller still sees a clean termination.
    events.push(Ok(ChatEvent::Done { stop_reason }));
    events
}

#[derive(Serialize)]
struct Request<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<Message<'a>>,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct Response {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(other)]
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    struct CapturedRequest {
        headers_blob: String,
        body: String,
    }

    /// Spawn a one-shot HTTP server that captures the first request
    /// and replies with `response_body` (JSON).
    async fn mock_server(
        response_body: String,
        captured: Arc<Mutex<Option<CapturedRequest>>>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap();
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            let (headers_blob, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
            *captured.lock().await = Some(CapturedRequest {
                headers_blob: headers_blob.to_string(),
                body: body.to_string(),
            });

            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            socket.write_all(resp.as_bytes()).await.unwrap();
            socket.shutdown().await.ok();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn returns_text_from_first_text_block() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(
            r#"{"content":[{"type":"text","text":"hello world"}]}"#.into(),
            captured.clone(),
        )
        .await;
        let adapter = AnthropicAdapter::new("test-key").with_base_url(base);
        let result = adapter.complete("ping").await.unwrap();
        assert_eq!(result, "hello world");
    }

    #[tokio::test]
    async fn sends_required_headers_and_body() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(
            r#"{"content":[{"type":"text","text":"ok"}]}"#.into(),
            captured.clone(),
        )
        .await;
        let adapter = AnthropicAdapter::new("sk-test")
            .with_base_url(base)
            .with_model("claude-sonnet-4-6");
        let _ = adapter.complete("prompt-x").await.unwrap();

        let req = captured.lock().await.take().unwrap();
        assert!(req.headers_blob.contains("POST /v1/messages"));
        assert!(req
            .headers_blob
            .to_lowercase()
            .contains("x-api-key: sk-test"));
        assert!(req
            .headers_blob
            .to_lowercase()
            .contains("anthropic-version: 2023-06-01"));
        assert!(req.body.contains("\"model\":\"claude-sonnet-4-6\""));
        assert!(req.body.contains("\"content\":\"prompt-x\""));
        assert!(req.body.contains("\"role\":\"user\""));
    }

    #[tokio::test]
    async fn http_error_surfaces_as_backend_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"error":{"message":"bad key"}}"#;
            let resp = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.shutdown().await;
        });

        let adapter = AnthropicAdapter::new("bad").with_base_url(format!("http://{addr}"));
        let err = adapter.complete("hi").await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("401") || msg.contains("anthropic"));
    }

    #[tokio::test]
    async fn empty_content_array_is_error() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(r#"{"content":[]}"#.into(), captured).await;
        let adapter = AnthropicAdapter::new("k").with_base_url(base);
        let err = adapter.complete("p").await.unwrap_err();
        assert!(format!("{err}").contains("no text block"));
    }

    #[test]
    fn defaults_match_published_constants() {
        let a = AnthropicAdapter::new("k");
        assert_eq!(a.base_url, DEFAULT_BASE_URL);
        assert_eq!(a.model, DEFAULT_MODEL);
        assert_eq!(a.api_version, DEFAULT_API_VERSION);
        assert_eq!(a.max_tokens, DEFAULT_MAX_TOKENS);
    }

    /// Spawn a one-shot HTTP server that replies with an SSE body
    /// (Content-Type: text/event-stream). Adequate for tests that
    /// only assert the parser handles well-formed Anthropic frames.
    async fn mock_sse_server(sse_body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = socket.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/event-stream\r\n\r\n{}",
                sse_body.len(),
                sse_body
            );
            socket.write_all(resp.as_bytes()).await.unwrap();
            socket.shutdown().await.ok();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn stream_chat_yields_text_deltas() {
        use futures::StreamExt as _;
        let sse = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\", \"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"world\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        );
        let base = mock_sse_server(sse.to_string()).await;
        let adapter = AnthropicAdapter::new("sk-ant-test").with_base_url(base);
        let msgs = vec![crate::ChatMessage::user("hi")];
        let events: Vec<_> = adapter.stream_chat(&msgs, &[]).collect().await;

        let texts: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                Ok(ChatEvent::Text { delta }) => Some(delta.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(texts, vec!["Hello", ", ", "world"]);
        match events.last().expect("at least one event") {
            Ok(ChatEvent::Done { stop_reason }) => {
                assert_eq!(stop_reason.as_deref(), Some("end_turn"));
            }
            other => panic!("expected Done last, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stream_chat_emits_tool_call() {
        use futures::StreamExt as _;
        let sse = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"lookup\",\"input\":{}}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"q\\\":\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"mantis\\\"}\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        );
        let base = mock_sse_server(sse.to_string()).await;
        let adapter = AnthropicAdapter::new("sk-ant-test").with_base_url(base);
        let msgs = vec![crate::ChatMessage::user("call the tool")];
        let tools = vec![crate::Tool {
            name: "lookup".into(),
            description: "look up".into(),
            input_schema: serde_json::json!({"type":"object"}),
        }];
        let events: Vec<_> = adapter.stream_chat(&msgs, &tools).collect().await;

        let tool_call = events
            .iter()
            .find_map(|e| match e {
                Ok(ChatEvent::ToolCall(tc)) => Some(tc.clone()),
                _ => None,
            })
            .expect("expected a ToolCall event");
        assert_eq!(tool_call.id, "toolu_1");
        assert_eq!(tool_call.name, "lookup");
        assert_eq!(tool_call.arguments, serde_json::json!({"q": "mantis"}));
        match events.last() {
            Some(Ok(ChatEvent::Done { stop_reason })) => {
                assert_eq!(stop_reason.as_deref(), Some("tool_use"));
            }
            other => panic!("expected Done last, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Prompt caching wire-format tests. We don't need a live API to
    // verify these — just build a StreamRequest and assert the JSON
    // shape. The actual cache hit/miss happens server-side.
    // -----------------------------------------------------------------

    fn build_body_for_test(
        adapter: &AnthropicAdapter,
        messages: &[ChatMessage],
        tools: &[Tool],
    ) -> serde_json::Value {
        let (system_text, request_messages) = chat_messages_to_anthropic(messages);
        let mut req_tools: Vec<StreamTool> = tools.iter().map(tool_to_anthropic).collect();
        let system_field = match system_text {
            None => None,
            Some(text) if text.is_empty() => None,
            Some(text) => Some(if adapter.cache_prompts {
                SystemField::Blocks(vec![SystemBlock {
                    typ: "text",
                    text,
                    cache_control: Some(CacheControl::ephemeral()),
                }])
            } else {
                SystemField::Text(text)
            }),
        };
        if adapter.cache_prompts {
            if let Some(last) = req_tools.last_mut() {
                last.cache_control = Some(CacheControl::ephemeral());
            }
        }
        let body = StreamRequest {
            model: &adapter.model,
            max_tokens: adapter.max_tokens,
            stream: true,
            system: system_field,
            messages: request_messages,
            tools: if req_tools.is_empty() {
                None
            } else {
                Some(req_tools)
            },
        };
        serde_json::to_value(&body).unwrap()
    }

    #[test]
    fn prompt_caching_emits_cache_control_on_system_block() {
        let adapter = AnthropicAdapter::new("k");
        let messages = vec![
            ChatMessage::system("you are mantis, a security assistant"),
            ChatMessage::user("hello"),
        ];
        let body = build_body_for_test(&adapter, &messages, &[]);
        let system = body.get("system").expect("system field present");
        // Should be an ARRAY (blocks form) when caching is enabled.
        let arr = system.as_array().expect("system as blocks array");
        assert_eq!(arr.len(), 1);
        let block = &arr[0];
        assert_eq!(block["type"], "text");
        assert!(block["text"].as_str().unwrap().contains("mantis"));
        assert_eq!(block["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn prompt_caching_emits_cache_control_on_last_tool() {
        let adapter = AnthropicAdapter::new("k");
        let messages = vec![ChatMessage::user("hi")];
        let tools = vec![
            Tool {
                name: "alpha".into(),
                description: "first".into(),
                input_schema: serde_json::json!({}),
            },
            Tool {
                name: "beta".into(),
                description: "second".into(),
                input_schema: serde_json::json!({}),
            },
            Tool {
                name: "gamma".into(),
                description: "last".into(),
                input_schema: serde_json::json!({}),
            },
        ];
        let body = build_body_for_test(&adapter, &messages, &tools);
        let tools_arr = body
            .get("tools")
            .and_then(|t| t.as_array())
            .expect("tools array");
        assert_eq!(tools_arr.len(), 3);
        // Only the LAST tool carries the cache marker.
        assert!(tools_arr[0].get("cache_control").is_none());
        assert!(tools_arr[1].get("cache_control").is_none());
        assert_eq!(tools_arr[2]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn prompt_caching_off_falls_back_to_string_system_field() {
        let adapter = AnthropicAdapter::new("k").with_prompt_caching(false);
        let messages = vec![
            ChatMessage::system("you are mantis"),
            ChatMessage::user("hi"),
        ];
        let body = build_body_for_test(&adapter, &messages, &[]);
        // With caching off, system is a plain string (no blocks).
        let system = &body["system"];
        assert!(system.is_string(), "expected string when cache off: {system}");
    }

    #[test]
    fn prompt_caching_skips_empty_system() {
        let adapter = AnthropicAdapter::new("k");
        let messages = vec![ChatMessage::user("hi")]; // no system
        let body = build_body_for_test(&adapter, &messages, &[]);
        assert!(
            body.get("system").is_none(),
            "system field should be absent when no system message exists"
        );
    }
}
