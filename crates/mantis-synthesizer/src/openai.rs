//! OpenAI Chat Completions API adapter (PRD §5.7.4, M2.2b).
//!
//! Posts to `/v1/chat/completions` and returns the text of the first
//! choice's message content. Default model is `gpt-4o-mini` — the
//! caller can swap in any chat-completions-compatible model id.

use async_trait::async_trait;
use futures::stream::{self, BoxStream, StreamExt};
use serde::{Deserialize, Serialize};

use crate::retry::{classify_status, parse_retry_after, RetryDecision, RetryPolicy};
use crate::{ChatEvent, ChatMessage, ChatRole, LlmAdapter, SynthError, Tool, ToolCall};

const DEFAULT_BASE_URL: &str = "https://api.openai.com";
const DEFAULT_MODEL: &str = "gpt-4o-mini";
const DEFAULT_MAX_TOKENS: u32 = 1024;

#[derive(Debug, Clone)]
pub struct OpenAIAdapter {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    retry: RetryPolicy,
}

impl OpenAIAdapter {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            // Pooled HTTP client — TLS handshakes amortise across
            // every turn / every adapter instance in the process.
            client: crate::http::shared_client(),
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.into(),
            model: DEFAULT_MODEL.into(),
            max_tokens: DEFAULT_MAX_TOKENS,
            retry: RetryPolicy::default(),
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
}

#[async_trait]
impl LlmAdapter for OpenAIAdapter {
    async fn complete(&self, prompt: &str) -> Result<String, SynthError> {
        let body = Request {
            model: &self.model,
            max_tokens: self.max_tokens,
            messages: vec![Message {
                role: "user",
                content: prompt,
            }],
        };
        let url = format!(
            "{}/v1/chat/completions",
            self.base_url.trim_end_matches('/')
        );
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| SynthError::Backend(format!("openai serialize: {e}")))?;

        let mut last_error = String::new();
        for attempt in 1..=self.retry.max_attempts {
            let resp = self
                .client
                .post(&url)
                .bearer_auth(&self.api_key)
                .header("content-type", "application/json")
                .body(body_bytes.clone())
                .send()
                .await
                .map_err(|e| SynthError::Backend(format!("openai request: {e}")))?;

            let status = resp.status().as_u16();
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_retry_after);
            let text = resp
                .text()
                .await
                .map_err(|e| SynthError::Backend(format!("openai body: {e}")))?;

            match classify_status(status, retry_after, &self.retry, attempt) {
                RetryDecision::Done => {
                    let parsed: Response = serde_json::from_str(&text)
                        .map_err(|e| SynthError::Backend(format!("openai parse: {e}")))?;
                    return parsed
                        .choices
                        .into_iter()
                        .find_map(|c| {
                            if c.message.content.is_empty() {
                                None
                            } else {
                                Some(c.message.content)
                            }
                        })
                        .ok_or_else(|| {
                            SynthError::Backend("openai returned no choice content".into())
                        });
                }
                RetryDecision::Retry(delay) => {
                    last_error = format!("openai {status}: {text}");
                    tokio::time::sleep(delay).await;
                    continue;
                }
                RetryDecision::Fatal => {
                    return Err(SynthError::Backend(format!("openai {status}: {text}")));
                }
            }
        }
        Err(SynthError::Backend(format!(
            "openai exhausted retries: {last_error}"
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

impl OpenAIAdapter {
    /// Issue a streaming `/v1/chat/completions` request and collect the
    /// SSE frames into an ordered vector of [`ChatEvent`]s. The vector
    /// is then re-streamed by [`stream_chat`]. We buffer the body
    /// before parsing because the workspace reqwest config does not
    /// enable the `stream` feature — once that's available the parser
    /// here can drive a `bytes_stream()` incrementally without
    /// changing the emitted event order.
    async fn run_stream_chat(
        &self,
        messages: &[ChatMessage],
        tools: &[Tool],
    ) -> Result<Vec<Result<ChatEvent, SynthError>>, SynthError> {
        let req_messages: Vec<ChatStreamMessage> =
            messages.iter().map(chat_message_to_openai).collect();
        let req_tools: Vec<ChatStreamTool> = tools.iter().map(tool_to_openai).collect();

        let body = StreamRequest {
            model: &self.model,
            max_tokens: self.max_tokens,
            stream: true,
            messages: req_messages,
            tools: if req_tools.is_empty() {
                None
            } else {
                Some(req_tools)
            },
        };
        let url = format!(
            "{}/v1/chat/completions",
            self.base_url.trim_end_matches('/')
        );
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| SynthError::Backend(format!("openai stream serialize: {e}")))?;

        let mut last_error = String::new();
        for attempt in 1..=self.retry.max_attempts {
            let resp = self
                .client
                .post(&url)
                .bearer_auth(&self.api_key)
                .header("content-type", "application/json")
                .header("accept", "text/event-stream")
                .body(body_bytes.clone())
                .send()
                .await
                .map_err(|e| SynthError::Backend(format!("openai stream request: {e}")))?;

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
                        .map_err(|e| SynthError::Backend(format!("openai stream body: {e}")))?;
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    return Ok(parse_openai_sse(&text));
                }
                RetryDecision::Retry(delay) => {
                    let text = resp.text().await.unwrap_or_default();
                    last_error = format!("openai stream {status}: {text}");
                    tokio::time::sleep(delay).await;
                    continue;
                }
                RetryDecision::Fatal => {
                    let text = resp.text().await.unwrap_or_default();
                    return Err(SynthError::Backend(format!(
                        "openai stream {status}: {text}"
                    )));
                }
            }
        }
        Err(SynthError::Backend(format!(
            "openai stream exhausted retries: {last_error}"
        )))
    }
}

// ---------------------------------------------------------------------------
// SSE / request wire types and parsing for /v1/chat/completions streaming.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StreamRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    stream: bool,
    messages: Vec<ChatStreamMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<ChatStreamTool>>,
}

#[derive(Serialize)]
struct ChatStreamMessage {
    role: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<ChatStreamToolCall>>,
}

#[derive(Serialize)]
struct ChatStreamToolCall {
    id: String,
    #[serde(rename = "type")]
    kind: &'static str,
    function: ChatStreamToolCallFn,
}

#[derive(Serialize)]
struct ChatStreamToolCallFn {
    name: String,
    arguments: String,
}

#[derive(Serialize)]
struct ChatStreamTool {
    #[serde(rename = "type")]
    kind: &'static str,
    function: ChatStreamToolFn,
}

#[derive(Serialize)]
struct ChatStreamToolFn {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

fn chat_message_to_openai(m: &ChatMessage) -> ChatStreamMessage {
    match m.role {
        ChatRole::System => ChatStreamMessage {
            role: "system",
            content: Some(m.content.clone()),
            tool_call_id: None,
            tool_calls: None,
        },
        ChatRole::User => ChatStreamMessage {
            role: "user",
            content: Some(m.content.clone()),
            tool_call_id: None,
            tool_calls: None,
        },
        ChatRole::Assistant => {
            let tool_calls = if m.tool_calls.is_empty() {
                None
            } else {
                Some(
                    m.tool_calls
                        .iter()
                        .map(|tc| ChatStreamToolCall {
                            id: tc.id.clone(),
                            kind: "function",
                            function: ChatStreamToolCallFn {
                                name: tc.name.clone(),
                                arguments: tc.arguments.to_string(),
                            },
                        })
                        .collect(),
                )
            };
            ChatStreamMessage {
                role: "assistant",
                content: if m.content.is_empty() {
                    None
                } else {
                    Some(m.content.clone())
                },
                tool_call_id: None,
                tool_calls,
            }
        }
        ChatRole::Tool => ChatStreamMessage {
            role: "tool",
            content: Some(m.content.clone()),
            tool_call_id: m.tool_call_id.clone(),
            tool_calls: None,
        },
    }
}

fn tool_to_openai(t: &Tool) -> ChatStreamTool {
    ChatStreamTool {
        kind: "function",
        function: ChatStreamToolFn {
            name: t.name.clone(),
            description: t.description.clone(),
            parameters: t.input_schema.clone(),
        },
    }
}

#[derive(Deserialize)]
struct StreamChunk {
    #[serde(default)]
    choices: Vec<StreamChoice>,
}

#[derive(Deserialize)]
struct StreamChoice {
    #[serde(default)]
    delta: StreamDelta,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Default, Deserialize)]
struct StreamDelta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<StreamToolCallDelta>>,
}

#[derive(Deserialize)]
struct StreamToolCallDelta {
    #[serde(default)]
    index: usize,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<StreamToolCallDeltaFn>,
}

#[derive(Deserialize)]
struct StreamToolCallDeltaFn {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

#[derive(Default)]
struct ToolCallBuffer {
    id: String,
    name: String,
    arguments: String,
}

/// Parse a buffered OpenAI SSE response into an ordered list of
/// `ChatEvent`s. Frames are split on the SSE `\n\n` boundary; each
/// `data:` line carrying JSON is decoded as a `StreamChunk`. The
/// terminator is `data: [DONE]`. Tool-call fragments are merged by
/// `index` and emitted once `finish_reason == "tool_calls"`.
fn parse_openai_sse(body: &str) -> Vec<Result<ChatEvent, SynthError>> {
    let mut events: Vec<Result<ChatEvent, SynthError>> = Vec::new();
    let mut tool_buffers: Vec<ToolCallBuffer> = Vec::new();
    let mut last_finish: Option<String> = None;
    let mut emitted_tool_calls = false;

    for frame in body.split("\n\n") {
        let frame = frame.trim_start_matches('\r').trim();
        if frame.is_empty() {
            continue;
        }
        // Collect `data:` lines (an SSE event may have multiple).
        let mut payload = String::new();
        for line in frame.lines() {
            let line = line.trim_end_matches('\r');
            if let Some(rest) = line.strip_prefix("data:") {
                if !payload.is_empty() {
                    payload.push('\n');
                }
                payload.push_str(rest.trim_start());
            }
        }
        if payload.is_empty() {
            continue;
        }
        if payload == "[DONE]" {
            // Flush any buffered tool calls that didn't get an
            // explicit finish_reason frame ahead of [DONE].
            if !emitted_tool_calls {
                flush_openai_tool_calls(&mut tool_buffers, &mut events);
            }
            events.push(Ok(ChatEvent::Done {
                stop_reason: last_finish.clone(),
            }));
            return events;
        }
        let chunk: StreamChunk = match serde_json::from_str(&payload) {
            Ok(c) => c,
            Err(e) => {
                events.push(Ok(ChatEvent::Warning {
                    message: format!("openai sse parse: {e}"),
                }));
                continue;
            }
        };
        for choice in chunk.choices {
            if let Some(text) = choice.delta.content {
                if !text.is_empty() {
                    events.push(Ok(ChatEvent::Text { delta: text }));
                }
            }
            if let Some(tcs) = choice.delta.tool_calls {
                for tc in tcs {
                    while tool_buffers.len() <= tc.index {
                        tool_buffers.push(ToolCallBuffer::default());
                    }
                    let buf = &mut tool_buffers[tc.index];
                    if let Some(id) = tc.id {
                        buf.id = id;
                    }
                    if let Some(f) = tc.function {
                        if let Some(name) = f.name {
                            if !name.is_empty() {
                                buf.name = name;
                            }
                        }
                        if let Some(args) = f.arguments {
                            buf.arguments.push_str(&args);
                        }
                    }
                }
            }
            if let Some(reason) = choice.finish_reason {
                last_finish = Some(reason.clone());
                if reason == "tool_calls" && !emitted_tool_calls {
                    flush_openai_tool_calls(&mut tool_buffers, &mut events);
                    emitted_tool_calls = true;
                }
            }
        }
    }

    // The server closed the stream without a `[DONE]` terminator.
    // Flush whatever we have and synthesize a Done event so callers
    // see a clean termination.
    if !emitted_tool_calls {
        flush_openai_tool_calls(&mut tool_buffers, &mut events);
    }
    events.push(Ok(ChatEvent::Done {
        stop_reason: last_finish,
    }));
    events
}

fn flush_openai_tool_calls(
    buffers: &mut Vec<ToolCallBuffer>,
    events: &mut Vec<Result<ChatEvent, SynthError>>,
) {
    for buf in buffers.drain(..) {
        if buf.id.is_empty() && buf.name.is_empty() && buf.arguments.is_empty() {
            continue;
        }
        let arguments = if buf.arguments.is_empty() {
            serde_json::Value::Object(Default::default())
        } else {
            match serde_json::from_str::<serde_json::Value>(&buf.arguments) {
                Ok(v) => v,
                Err(e) => {
                    events.push(Ok(ChatEvent::Warning {
                        message: format!("openai tool args parse ({}): {e}", buf.name),
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
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    content: String,
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
    async fn returns_first_choice_content() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(
            r#"{"choices":[{"message":{"content":"hi there"}}]}"#.into(),
            captured.clone(),
        )
        .await;
        let adapter = OpenAIAdapter::new("sk-test").with_base_url(base);
        let result = adapter.complete("ping").await.unwrap();
        assert_eq!(result, "hi there");
    }

    #[tokio::test]
    async fn sends_bearer_auth_and_chat_completions_path() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(
            r#"{"choices":[{"message":{"content":"ok"}}]}"#.into(),
            captured.clone(),
        )
        .await;
        let adapter = OpenAIAdapter::new("sk-AAA")
            .with_base_url(base)
            .with_model("gpt-4o");
        let _ = adapter.complete("hello").await.unwrap();

        let req = captured.lock().await.take().unwrap();
        assert!(req.headers_blob.contains("POST /v1/chat/completions"));
        assert!(req
            .headers_blob
            .to_lowercase()
            .contains("authorization: bearer sk-aaa"));
        assert!(req.body.contains("\"model\":\"gpt-4o\""));
        assert!(req.body.contains("\"role\":\"user\""));
        assert!(req.body.contains("\"content\":\"hello\""));
    }

    #[tokio::test]
    async fn http_error_surfaces_as_backend_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"error":{"message":"rate limited"}}"#;
            let resp = format!(
                "HTTP/1.1 429 Too Many Requests\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.shutdown().await;
        });

        let adapter = OpenAIAdapter::new("bad").with_base_url(format!("http://{addr}"));
        let err = adapter.complete("hi").await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("429") || msg.contains("openai"));
    }

    #[tokio::test]
    async fn empty_choices_array_is_error() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(r#"{"choices":[]}"#.into(), captured).await;
        let adapter = OpenAIAdapter::new("k").with_base_url(base);
        let err = adapter.complete("p").await.unwrap_err();
        assert!(format!("{err}").contains("no choice content"));
    }

    #[test]
    fn defaults_match_published_constants() {
        let a = OpenAIAdapter::new("k");
        assert_eq!(a.base_url, DEFAULT_BASE_URL);
        assert_eq!(a.model, DEFAULT_MODEL);
        assert_eq!(a.max_tokens, DEFAULT_MAX_TOKENS);
    }

    /// Spawn a one-shot HTTP server that replies with an SSE body
    /// (Content-Type: text/event-stream). The body is written all at
    /// once — adequate for tests that only assert the parser handles
    /// well-formed frames.
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
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\", \"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"world\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let base = mock_sse_server(sse.to_string()).await;
        let adapter = OpenAIAdapter::new("sk-test").with_base_url(base);
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
        let done = events.last().expect("at least one event");
        match done {
            Ok(ChatEvent::Done { stop_reason }) => {
                assert_eq!(stop_reason.as_deref(), Some("stop"));
            }
            other => panic!("expected Done last, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stream_chat_emits_tool_call() {
        use futures::StreamExt as _;
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_42\",\"function\":{\"name\":\"lookup\",\"arguments\":\"\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"q\\\":\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"mantis\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let base = mock_sse_server(sse.to_string()).await;
        let adapter = OpenAIAdapter::new("sk-test").with_base_url(base);
        let msgs = vec![crate::ChatMessage::user("call the tool")];
        let tools = vec![crate::Tool {
            name: "lookup".into(),
            description: "look up".into(),
            input_schema: serde_json::json!({"type": "object"}),
        }];
        let events: Vec<_> = adapter.stream_chat(&msgs, &tools).collect().await;

        let tool_call = events
            .iter()
            .find_map(|e| match e {
                Ok(ChatEvent::ToolCall(tc)) => Some(tc.clone()),
                _ => None,
            })
            .expect("expected a ToolCall event");
        assert_eq!(tool_call.id, "call_42");
        assert_eq!(tool_call.name, "lookup");
        assert_eq!(tool_call.arguments, serde_json::json!({"q": "mantis"}));
        assert!(matches!(
            events.last(),
            Some(Ok(ChatEvent::Done {
                stop_reason: Some(_)
            }))
        ));
    }
}
