//! Google Gemini (Generative Language API v1beta) adapter.
//!
//! Posts to `/v1beta/models/{model}:generateContent` for one-shot
//! completions and `/v1beta/models/{model}:streamGenerateContent?alt=sse`
//! for streaming chat. Default model is `gemini-2.0-flash-exp`; pass any
//! other model id via [`GeminiAdapter::with_model`].
//!
//! Tool call IDs: Gemini's API does not assign call IDs to function
//! calls. We emit `ToolCall { id: name.clone(), name, arguments }` —
//! callers treat id == name. Tool-result messages map their
//! `tool_call_id` (== tool name) back to a `functionResponse.name`.

use async_trait::async_trait;
use futures::stream::{self, BoxStream, StreamExt};
use serde::Deserialize;

use crate::retry::{classify_status, parse_retry_after, RetryDecision, RetryPolicy};
use crate::{ChatEvent, ChatMessage, ChatRole, LlmAdapter, SynthError, Tool, ToolCall};

const DEFAULT_BASE_URL: &str = "https://generativelanguage.googleapis.com";
const DEFAULT_MODEL: &str = "gemini-2.0-flash-exp";
const DEFAULT_MAX_TOKENS: u32 = 1024;

#[derive(Debug, Clone)]
pub struct GeminiAdapter {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    retry: RetryPolicy,
}

impl GeminiAdapter {
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

    /// Build the `contents` + optional `systemInstruction` payload from
    /// a chat transcript. Gemini calls the assistant role `model` and
    /// stuffs system messages into a separate top-level field.
    fn build_chat_body(&self, messages: &[ChatMessage], tools: &[Tool]) -> serde_json::Value {
        let mut system_chunks: Vec<String> = Vec::new();
        let mut contents: Vec<serde_json::Value> = Vec::new();

        for m in messages {
            match m.role {
                ChatRole::System => {
                    if !m.content.is_empty() {
                        system_chunks.push(m.content.clone());
                    }
                }
                ChatRole::User => {
                    contents.push(serde_json::json!({
                        "role": "user",
                        "parts": [{"text": m.content}],
                    }));
                }
                ChatRole::Assistant => {
                    contents.push(serde_json::json!({
                        "role": "model",
                        "parts": [{"text": m.content}],
                    }));
                }
                ChatRole::Tool => {
                    // Gemini doesn't track call ids; use the
                    // tool_call_id (which we treat as the function
                    // name) as the response binding.
                    let name = m.tool_call_id.as_deref().unwrap_or("tool");
                    contents.push(serde_json::json!({
                        "role": "user",
                        "parts": [{
                            "functionResponse": {
                                "name": name,
                                "response": {"result": m.content},
                            }
                        }],
                    }));
                }
            }
        }

        let mut body = serde_json::json!({
            "contents": contents,
            "generationConfig": {"maxOutputTokens": self.max_tokens},
        });

        if !system_chunks.is_empty() {
            body["systemInstruction"] = serde_json::json!({
                "parts": [{"text": system_chunks.join("\n\n")}],
            });
        }

        if !tools.is_empty() {
            let decls: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    })
                })
                .collect();
            body["tools"] = serde_json::json!([{ "functionDeclarations": decls }]);
        }

        body
    }
}

#[async_trait]
impl LlmAdapter for GeminiAdapter {
    async fn complete(&self, prompt: &str) -> Result<String, SynthError> {
        let body = serde_json::json!({
            "contents": [{
                "role": "user",
                "parts": [{"text": prompt}],
            }],
            "generationConfig": {"maxOutputTokens": self.max_tokens},
        });
        let url = format!(
            "{}/v1beta/models/{}:generateContent?key={}",
            self.base_url.trim_end_matches('/'),
            self.model,
            self.api_key,
        );
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| SynthError::Backend(format!("gemini serialize: {e}")))?;

        let mut last_error = String::new();
        for attempt in 1..=self.retry.max_attempts {
            let resp = self
                .client
                .post(&url)
                .header("content-type", "application/json")
                .body(body_bytes.clone())
                .send()
                .await
                .map_err(|e| SynthError::Backend(format!("gemini request: {e}")))?;

            let status = resp.status().as_u16();
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_retry_after);
            let text = resp
                .text()
                .await
                .map_err(|e| SynthError::Backend(format!("gemini body: {e}")))?;

            match classify_status(status, retry_after, &self.retry, attempt) {
                RetryDecision::Done => {
                    let parsed: GenerateContentResponse = serde_json::from_str(&text)
                        .map_err(|e| SynthError::Backend(format!("gemini parse: {e}")))?;
                    return parsed
                        .candidates
                        .into_iter()
                        .find_map(|c| {
                            c.content.parts.into_iter().find_map(|p| match p {
                                Part::Text { text } if !text.is_empty() => Some(text),
                                _ => None,
                            })
                        })
                        .ok_or_else(|| SynthError::Backend("gemini returned no text part".into()));
                }
                RetryDecision::Retry(delay) => {
                    last_error = format!("gemini {status}: {text}");
                    tokio::time::sleep(delay).await;
                    continue;
                }
                RetryDecision::Fatal => {
                    return Err(SynthError::Backend(format!("gemini {status}: {text}")));
                }
            }
        }
        Err(SynthError::Backend(format!(
            "gemini exhausted retries: {last_error}"
        )))
    }

    fn stream_chat<'a>(
        &'a self,
        messages: &'a [ChatMessage],
        tools: &'a [Tool],
    ) -> BoxStream<'a, Result<ChatEvent, SynthError>> {
        let url = format!(
            "{}/v1beta/models/{}:streamGenerateContent?alt=sse&key={}",
            self.base_url.trim_end_matches('/'),
            self.model,
            self.api_key,
        );
        let body = self.build_chat_body(messages, tools);
        let client = self.client.clone();

        let fut = async move {
            let body_bytes = match serde_json::to_vec(&body) {
                Ok(b) => b,
                Err(e) => {
                    return vec![Err(SynthError::Backend(format!("gemini serialize: {e}")))];
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
                    return vec![Err(SynthError::Backend(format!("gemini request: {e}")))];
                }
            };
            let status = resp.status().as_u16();
            if !(200..300).contains(&status) {
                let text = resp.text().await.unwrap_or_default();
                return vec![Err(SynthError::Backend(format!("gemini {status}: {text}")))];
            }
            let body = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    return vec![Err(SynthError::Backend(format!("gemini body: {e}")))];
                }
            };
            parse_sse_stream(&body)
        };

        stream::once(fut).flat_map(stream::iter).boxed()
    }
}

/// Parse an SSE-encoded `streamGenerateContent` body into a vector of
/// `ChatEvent` results. Each `data: {...}` line is a partial
/// `GenerateContentResponse`. We accumulate text deltas, emit tool
/// calls inline, and append a single `Done` once we see a non-empty
/// `finishReason` or the stream ends.
fn parse_sse_stream(body: &[u8]) -> Vec<Result<ChatEvent, SynthError>> {
    let mut events = Vec::new();
    let mut stop_reason: Option<String> = None;
    let text = String::from_utf8_lossy(body);
    for line in text.lines() {
        let line = line.trim_start();
        if !line.starts_with("data:") {
            continue;
        }
        let payload = line["data:".len()..].trim();
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        let parsed: GenerateContentResponse = match serde_json::from_str(payload) {
            Ok(p) => p,
            Err(e) => {
                events.push(Err(SynthError::Backend(format!("gemini parse: {e}"))));
                continue;
            }
        };
        for cand in parsed.candidates {
            for part in cand.content.parts {
                match part {
                    Part::Text { text } if !text.is_empty() => {
                        events.push(Ok(ChatEvent::Text { delta: text }));
                    }
                    Part::FunctionCall {
                        function_call: FunctionCall { name, args },
                    } => {
                        events.push(Ok(ChatEvent::ToolCall(ToolCall {
                            id: name.clone(),
                            name,
                            arguments: args,
                        })));
                    }
                    _ => {}
                }
            }
            if let Some(reason) = cand.finish_reason {
                if !reason.is_empty() {
                    stop_reason = Some(reason);
                }
            }
        }
    }
    events.push(Ok(ChatEvent::Done { stop_reason }));
    events
}

#[derive(Deserialize)]
struct GenerateContentResponse {
    #[serde(default)]
    candidates: Vec<Candidate>,
}

#[derive(Deserialize)]
struct Candidate {
    #[serde(default)]
    content: Content,
    #[serde(default, rename = "finishReason")]
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct Content {
    #[serde(default)]
    parts: Vec<Part>,
}

/// A single element of `candidates[i].content.parts`. Gemini uses an
/// implicit-tag form (each part is an object with exactly one of
/// `text` / `functionCall` / something-else); `#[serde(untagged)]`
/// dispatches on field presence. We materialise unknown variants as
/// a `serde_json::Value` rather than dropping them so the parser
/// never fails on a new part type.
#[derive(Deserialize)]
#[serde(untagged)]
enum Part {
    FunctionCall {
        #[serde(rename = "functionCall")]
        function_call: FunctionCall,
    },
    Text {
        text: String,
    },
    Unknown(#[allow(dead_code)] serde_json::Value),
}

#[derive(Deserialize)]
struct FunctionCall {
    name: String,
    #[serde(default)]
    args: serde_json::Value,
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

    async fn mock_server_sse(
        sse_body: String,
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
    async fn complete_returns_text() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server_json(
            r#"{"candidates":[{"content":{"parts":[{"text":"hello gemini"}]}}]}"#.into(),
            captured.clone(),
        )
        .await;
        let adapter = GeminiAdapter::new("test-key").with_base_url(base);
        let result = adapter.complete("hi").await.unwrap();
        assert_eq!(result, "hello gemini");

        let req = captured.lock().await.take().unwrap();
        assert!(req
            .headers_blob
            .contains("POST /v1beta/models/gemini-2.0-flash-exp:generateContent"));
        assert!(req.headers_blob.contains("key=test-key"));
        assert!(req.body.contains("\"text\":\"hi\""));
    }

    #[tokio::test]
    async fn stream_chat_yields_text_deltas() {
        use futures::StreamExt as _;
        let sse = concat!(
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hello \"}]}}]}\n\n",
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"world\"}]},\"finishReason\":\"STOP\"}]}\n\n",
        );
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server_sse(sse.to_string(), captured.clone()).await;
        let adapter = GeminiAdapter::new("k").with_base_url(base);
        let msgs = vec![ChatMessage::user("hi")];
        let events: Vec<_> = adapter.stream_chat(&msgs, &[]).collect().await;

        // Expect: Text("hello "), Text("world"), Done(STOP)
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
                assert_eq!(stop_reason.as_deref(), Some("STOP"));
            }
            other => panic!("expected Done, got {other:?}"),
        }

        let req = captured.lock().await.take().unwrap();
        assert!(req.headers_blob.contains(":streamGenerateContent?alt=sse"));
    }

    #[tokio::test]
    async fn stream_chat_emits_tool_call() {
        use futures::StreamExt as _;
        let sse =
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"lookup\",\"args\":{\"q\":\"mantis\"}}}]},\"finishReason\":\"STOP\"}]}\n\n";
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server_sse(sse.to_string(), captured.clone()).await;
        let adapter = GeminiAdapter::new("k").with_base_url(base);
        let msgs = vec![ChatMessage::user("find mantis")];
        let tools = vec![Tool {
            name: "lookup".into(),
            description: "search".into(),
            input_schema: serde_json::json!({"type":"object"}),
        }];
        let events: Vec<_> = adapter.stream_chat(&msgs, &tools).collect().await;

        // Expect: ToolCall(lookup), Done(STOP)
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
                assert_eq!(stop_reason.as_deref(), Some("STOP"));
            }
            other => panic!("expected Done, got {other:?}"),
        }

        let req = captured.lock().await.take().unwrap();
        assert!(req.body.contains("functionDeclarations"));
        assert!(req.body.contains("\"name\":\"lookup\""));
    }

    #[test]
    fn defaults_match_published_constants() {
        let a = GeminiAdapter::new("k");
        assert_eq!(a.base_url, DEFAULT_BASE_URL);
        assert_eq!(a.model, DEFAULT_MODEL);
        assert_eq!(a.max_tokens, DEFAULT_MAX_TOKENS);
    }

    #[test]
    fn build_chat_body_routes_system_into_system_instruction() {
        let adapter = GeminiAdapter::new("k");
        let msgs = vec![
            ChatMessage::system("you are a security agent"),
            ChatMessage::system("be terse"),
            ChatMessage::user("hi"),
            ChatMessage::assistant("hello"),
        ];
        let body = adapter.build_chat_body(&msgs, &[]);
        let sys = &body["systemInstruction"]["parts"][0]["text"];
        assert_eq!(sys, "you are a security agent\n\nbe terse");
        let contents = body["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 2);
        assert_eq!(contents[0]["role"], "user");
        assert_eq!(contents[1]["role"], "model");
    }

    #[test]
    fn build_chat_body_maps_tool_result_to_function_response() {
        let adapter = GeminiAdapter::new("k");
        let msgs = vec![ChatMessage::tool_result("lookup", "{\"hits\":1}")];
        let body = adapter.build_chat_body(&msgs, &[]);
        let contents = body["contents"].as_array().unwrap();
        let fr = &contents[0]["parts"][0]["functionResponse"];
        assert_eq!(fr["name"], "lookup");
        assert_eq!(fr["response"]["result"], "{\"hits\":1}");
    }
}
