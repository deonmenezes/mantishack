//! Ollama local-LLM adapter.
//!
//! Talks to a local Ollama daemon over HTTP (default
//! `http://localhost:11434`). Ollama is unauthenticated: there is no
//! API key, only a base URL. `complete` uses `/api/generate` in
//! one-shot mode; `stream_chat` uses `/api/chat` with NDJSON
//! streaming (newline-delimited JSON, NOT SSE).
//!
//! Tool call IDs: Ollama does not assign call IDs to function calls.
//! We emit `ToolCall { id: name.clone(), name, arguments }` — callers
//! treat id == name.

use async_trait::async_trait;
use futures::stream::{self, BoxStream, StreamExt};
use serde::Deserialize;

use crate::retry::{classify_status, parse_retry_after, RetryDecision, RetryPolicy};
use crate::{ChatEvent, ChatMessage, ChatRole, LlmAdapter, SynthError, Tool, ToolCall};

const DEFAULT_BASE_URL: &str = "http://localhost:11434";
const DEFAULT_MODEL: &str = "llama3.2";

#[derive(Debug, Clone)]
pub struct OllamaAdapter {
    client: reqwest::Client,
    base_url: String,
    model: String,
    retry: RetryPolicy,
}

impl Default for OllamaAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl OllamaAdapter {
    pub fn new() -> Self {
        Self {
            // Pooled HTTP client — TLS handshakes amortise across
            // every turn / every adapter instance in the process.
            // Localhost-only by default, but the pool still saves
            // socket setup overhead.
            client: crate::http::shared_client(),
            base_url: DEFAULT_BASE_URL.into(),
            model: DEFAULT_MODEL.into(),
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

    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Build the `/api/chat` request body. Ollama uses OpenAI-style
    /// role strings (`system`/`user`/`assistant`/`tool`).
    fn build_chat_body(&self, messages: &[ChatMessage], tools: &[Tool]) -> serde_json::Value {
        let msgs: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| match m.role {
                ChatRole::System => serde_json::json!({
                    "role": "system",
                    "content": m.content,
                }),
                ChatRole::User => serde_json::json!({
                    "role": "user",
                    "content": m.content,
                }),
                ChatRole::Assistant => {
                    let mut obj = serde_json::json!({
                        "role": "assistant",
                        "content": m.content,
                    });
                    if !m.tool_calls.is_empty() {
                        let calls: Vec<serde_json::Value> = m
                            .tool_calls
                            .iter()
                            .map(|tc| {
                                serde_json::json!({
                                    "function": {
                                        "name": tc.name,
                                        "arguments": tc.arguments,
                                    }
                                })
                            })
                            .collect();
                        obj["tool_calls"] = serde_json::Value::Array(calls);
                    }
                    obj
                }
                ChatRole::Tool => {
                    let mut obj = serde_json::json!({
                        "role": "tool",
                        "content": m.content,
                    });
                    if let Some(id) = m.tool_call_id.as_deref() {
                        obj["tool_call_id"] = serde_json::Value::String(id.into());
                    }
                    obj
                }
            })
            .collect();

        let mut body = serde_json::json!({
            "model": self.model,
            "messages": msgs,
            "stream": true,
        });

        if !tools.is_empty() {
            let decls: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.input_schema,
                        }
                    })
                })
                .collect();
            body["tools"] = serde_json::Value::Array(decls);
        }

        body
    }
}

#[async_trait]
impl LlmAdapter for OllamaAdapter {
    async fn complete(&self, prompt: &str) -> Result<String, SynthError> {
        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
        });
        let url = format!("{}/api/generate", self.base_url.trim_end_matches('/'));
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| SynthError::Backend(format!("ollama serialize: {e}")))?;

        let mut last_error = String::new();
        for attempt in 1..=self.retry.max_attempts {
            let resp = self
                .client
                .post(&url)
                .header("content-type", "application/json")
                .body(body_bytes.clone())
                .send()
                .await
                .map_err(|e| SynthError::Backend(format!("ollama request: {e}")))?;

            let status = resp.status().as_u16();
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_retry_after);
            let text = resp
                .text()
                .await
                .map_err(|e| SynthError::Backend(format!("ollama body: {e}")))?;

            match classify_status(status, retry_after, &self.retry, attempt) {
                RetryDecision::Done => {
                    let parsed: GenerateResponse = serde_json::from_str(&text)
                        .map_err(|e| SynthError::Backend(format!("ollama parse: {e}")))?;
                    if parsed.response.is_empty() {
                        return Err(SynthError::Backend(
                            "ollama returned empty response".into(),
                        ));
                    }
                    return Ok(parsed.response);
                }
                RetryDecision::Retry(delay) => {
                    last_error = format!("ollama {status}: {text}");
                    tokio::time::sleep(delay).await;
                    continue;
                }
                RetryDecision::Fatal => {
                    return Err(SynthError::Backend(format!("ollama {status}: {text}")));
                }
            }
        }
        Err(SynthError::Backend(format!(
            "ollama exhausted retries: {last_error}"
        )))
    }

    fn stream_chat<'a>(
        &'a self,
        messages: &'a [ChatMessage],
        tools: &'a [Tool],
    ) -> BoxStream<'a, Result<ChatEvent, SynthError>> {
        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));
        let body = self.build_chat_body(messages, tools);
        let client = self.client.clone();

        let fut = async move {
            let body_bytes = match serde_json::to_vec(&body) {
                Ok(b) => b,
                Err(e) => {
                    return vec![Err(SynthError::Backend(format!(
                        "ollama serialize: {e}"
                    )))];
                }
            };
            let resp = match client
                .post(&url)
                .header("content-type", "application/json")
                .body(body_bytes)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    return vec![Err(SynthError::Backend(format!(
                        "ollama request: {e}"
                    )))];
                }
            };
            let status = resp.status().as_u16();
            if !(200..300).contains(&status) {
                let text = resp.text().await.unwrap_or_default();
                return vec![Err(SynthError::Backend(format!(
                    "ollama {status}: {text}"
                )))];
            }
            let body = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    return vec![Err(SynthError::Backend(format!(
                        "ollama body: {e}"
                    )))];
                }
            };
            parse_ndjson_stream(&body)
        };

        stream::once(fut).flat_map(stream::iter).boxed()
    }
}

/// Parse an NDJSON-encoded `/api/chat` body into `ChatEvent` results.
/// Each non-empty line is a complete JSON record. We surface text
/// deltas and tool calls; the `done: true` record terminates with a
/// `Done` carrying `done_reason` if Ollama provided one.
fn parse_ndjson_stream(body: &[u8]) -> Vec<Result<ChatEvent, SynthError>> {
    let mut events = Vec::new();
    let mut stop_reason: Option<String> = None;
    let mut saw_done = false;
    let text = String::from_utf8_lossy(body);
    for line in text.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: ChatStreamRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                events.push(Err(SynthError::Backend(format!("ollama parse: {e}"))));
                continue;
            }
        };
        if let Some(msg) = record.message {
            if !msg.content.is_empty() {
                events.push(Ok(ChatEvent::Text { delta: msg.content }));
            }
            for tc in msg.tool_calls {
                let name = tc.function.name;
                events.push(Ok(ChatEvent::ToolCall(ToolCall {
                    id: name.clone(),
                    name,
                    arguments: tc.function.arguments,
                })));
            }
        }
        if record.done {
            saw_done = true;
            stop_reason = record.done_reason;
        }
    }
    if !saw_done {
        // Stream ended without an explicit done flag — still emit a
        // Done so callers know the stream is closed.
    }
    events.push(Ok(ChatEvent::Done { stop_reason }));
    events
}

#[derive(Deserialize)]
struct GenerateResponse {
    response: String,
}

#[derive(Deserialize)]
struct ChatStreamRecord {
    #[serde(default)]
    message: Option<StreamMessage>,
    #[serde(default)]
    done: bool,
    #[serde(default, rename = "done_reason")]
    done_reason: Option<String>,
}

#[derive(Deserialize)]
struct StreamMessage {
    #[serde(default)]
    content: String,
    #[serde(default)]
    tool_calls: Vec<StreamToolCall>,
}

#[derive(Deserialize)]
struct StreamToolCall {
    function: StreamFunctionCall,
}

#[derive(Deserialize)]
struct StreamFunctionCall {
    name: String,
    #[serde(default)]
    arguments: serde_json::Value,
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

    async fn mock_server_json(
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

    async fn mock_server_ndjson(
        ndjson_body: String,
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
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/x-ndjson\r\n\r\n{}",
                ndjson_body.len(),
                ndjson_body
            );
            socket.write_all(resp.as_bytes()).await.unwrap();
            socket.shutdown().await.ok();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn complete_returns_text() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server_json(
            r#"{"response":"local says hi","done":true}"#.into(),
            captured.clone(),
        )
        .await;
        let adapter = OllamaAdapter::new().with_base_url(base);
        let result = adapter.complete("hi").await.unwrap();
        assert_eq!(result, "local says hi");

        let req = captured.lock().await.take().unwrap();
        assert!(req.headers_blob.contains("POST /api/generate"));
        assert!(req.body.contains("\"model\":\"llama3.2\""));
        assert!(req.body.contains("\"prompt\":\"hi\""));
        assert!(req.body.contains("\"stream\":false"));
    }

    #[tokio::test]
    async fn stream_chat_yields_text_deltas() {
        use futures::StreamExt as _;
        let ndjson = concat!(
            "{\"message\":{\"role\":\"assistant\",\"content\":\"hello \"},\"done\":false}\n",
            "{\"message\":{\"role\":\"assistant\",\"content\":\"world\"},\"done\":false}\n",
            "{\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true,\"done_reason\":\"stop\"}\n",
        );
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server_ndjson(ndjson.to_string(), captured.clone()).await;
        let adapter = OllamaAdapter::new().with_base_url(base);
        let msgs = vec![ChatMessage::user("hi")];
        let events: Vec<_> = adapter.stream_chat(&msgs, &[]).collect().await;

        // Expect: Text("hello "), Text("world"), Done(stop)
        assert_eq!(events.len(), 3, "got events {events:?}");
        match &events[0] {
            Ok(ChatEvent::Text { delta }) => assert_eq!(delta, "hello "),
            other => panic!("expected Text, got {other:?}"),
        }
        match &events[1] {
            Ok(ChatEvent::Text { delta }) => assert_eq!(delta, "world"),
            other => panic!("expected Text, got {other:?}"),
        }
        match &events[2] {
            Ok(ChatEvent::Done { stop_reason }) => {
                assert_eq!(stop_reason.as_deref(), Some("stop"));
            }
            other => panic!("expected Done, got {other:?}"),
        }

        let req = captured.lock().await.take().unwrap();
        assert!(req.headers_blob.contains("POST /api/chat"));
        assert!(req.body.contains("\"stream\":true"));
    }

    #[tokio::test]
    async fn stream_chat_emits_tool_call() {
        use futures::StreamExt as _;
        let ndjson = concat!(
            "{\"message\":{\"role\":\"assistant\",\"content\":\"\",\"tool_calls\":[{\"function\":{\"name\":\"lookup\",\"arguments\":{\"q\":\"mantis\"}}}]},\"done\":false}\n",
            "{\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true,\"done_reason\":\"stop\"}\n",
        );
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server_ndjson(ndjson.to_string(), captured.clone()).await;
        let adapter = OllamaAdapter::new().with_base_url(base);
        let msgs = vec![ChatMessage::user("find mantis")];
        let tools = vec![Tool {
            name: "lookup".into(),
            description: "search".into(),
            input_schema: serde_json::json!({"type":"object"}),
        }];
        let events: Vec<_> = adapter.stream_chat(&msgs, &tools).collect().await;

        // Expect: ToolCall(lookup), Done(stop)
        assert_eq!(events.len(), 2, "got events {events:?}");
        match &events[0] {
            Ok(ChatEvent::ToolCall(tc)) => {
                assert_eq!(tc.name, "lookup");
                assert_eq!(tc.id, "lookup"); // id == name by design
                assert_eq!(tc.arguments["q"], "mantis");
            }
            other => panic!("expected ToolCall, got {other:?}"),
        }
        match &events[1] {
            Ok(ChatEvent::Done { stop_reason }) => {
                assert_eq!(stop_reason.as_deref(), Some("stop"));
            }
            other => panic!("expected Done, got {other:?}"),
        }

        let req = captured.lock().await.take().unwrap();
        assert!(req.body.contains("\"type\":\"function\""));
        assert!(req.body.contains("\"name\":\"lookup\""));
    }

    #[test]
    fn defaults_match_published_constants() {
        let a = OllamaAdapter::new();
        assert_eq!(a.base_url, DEFAULT_BASE_URL);
        assert_eq!(a.model, DEFAULT_MODEL);
    }

    #[test]
    fn build_chat_body_includes_tool_calls_on_assistant() {
        let adapter = OllamaAdapter::new();
        let mut assistant = ChatMessage::assistant("calling tool");
        assistant.tool_calls.push(ToolCall {
            id: "lookup".into(),
            name: "lookup".into(),
            arguments: serde_json::json!({"q": "x"}),
        });
        let msgs = vec![assistant];
        let body = adapter.build_chat_body(&msgs, &[]);
        let m = &body["messages"][0];
        assert_eq!(m["role"], "assistant");
        assert_eq!(m["tool_calls"][0]["function"]["name"], "lookup");
        assert_eq!(m["tool_calls"][0]["function"]["arguments"]["q"], "x");
    }

    #[test]
    fn build_chat_body_tool_message_includes_tool_call_id() {
        let adapter = OllamaAdapter::new();
        let msgs = vec![ChatMessage::tool_result("lookup", "{\"hits\":1}")];
        let body = adapter.build_chat_body(&msgs, &[]);
        let m = &body["messages"][0];
        assert_eq!(m["role"], "tool");
        assert_eq!(m["tool_call_id"], "lookup");
        assert_eq!(m["content"], "{\"hits\":1}");
    }
}
