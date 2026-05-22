//! `POST /v1/chat` — streaming chat over Server-Sent Events.
//!
//! Wire format:
//!
//! ```text
//! data: {"type":"text","delta":"hello"}
//!
//! data: {"type":"tool_call","id":"c1","name":"...","arguments":{...}}
//!
//! data: {"type":"done","stop_reason":"end_turn"}
//! ```
//!
//! Each `data:` line is a JSON-serialized [`mantis_chat::ChatEvent`].
//! The variant tag (`type`) is produced by serde's
//! `#[serde(tag = "type", rename_all = "snake_case")]` on the enum.
//!
//! Architecture: we spawn `Conversation::turn` on a Tokio task and
//! bridge its callback into an `mpsc::channel`. The SSE response is
//! built from `ReceiverStream<Event>` so the HTTP body completes only
//! when the conversation task drops its sender.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::Json;
use futures::Stream;
use mantis_chat::{ChatEvent, ChatMessage, ChatRole, Conversation, NoTools};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

use crate::error::ApiError;
use crate::handlers::AppState;
use crate::provider;

/// JSON request body for `POST /v1/chat`.
///
/// `tools` defaults to `true` (load `$MANTIS_HOME/tools/`). Set
/// `false` to disable user-tools for a single request — e.g. when the
/// caller plans to handle tool execution itself or wants a pure
/// completion.
#[derive(Debug, Deserialize)]
pub struct ChatRequest {
    pub messages: Vec<WireMessage>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub system: Option<String>,
    #[serde(default = "default_tools")]
    pub tools: bool,
    #[serde(default = "default_max_tool_rounds")]
    pub max_tool_rounds: usize,
}

fn default_tools() -> bool {
    true
}
fn default_max_tool_rounds() -> usize {
    6
}

/// Simplified wire shape that drops `tool_calls` / `tool_call_id` —
/// the chat handler only needs role + content from the caller.
#[derive(Debug, Deserialize, Serialize)]
pub struct WireMessage {
    pub role: String,
    pub content: String,
}

impl WireMessage {
    fn into_chat(self) -> Result<ChatMessage, ApiError> {
        let role = match self.role.as_str() {
            "system" => ChatRole::System,
            "user" => ChatRole::User,
            "assistant" => ChatRole::Assistant,
            "tool" => ChatRole::Tool,
            other => {
                return Err(ApiError::bad_request(format!(
                    "unknown role `{other}` (expected system|user|assistant|tool)"
                )))
            }
        };
        Ok(ChatMessage {
            role,
            content: self.content,
            tool_calls: Vec::new(),
            tool_call_id: None,
        })
    }
}

/// Axum handler. Builds a `Conversation`, spawns it on a task, and
/// returns an SSE stream of [`ChatEvent`]s.
pub async fn handle_chat(
    State(state): State<AppState>,
    Json(req): Json<ChatRequest>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    // Resolve adapter — either the injected stub (tests) or the
    // live provider picker.
    let (adapter, provider_label, model_label) = match state.provider_override.clone() {
        Some(a) => (a, "stub".to_string(), String::new()),
        None => provider::pick_chat_adapter(req.provider.as_deref(), req.model.as_deref())
            .map_err(|e| ApiError::upstream(e.to_string()))?,
    };

    // Build the conversation. The first user-supplied system message
    // (if any) is dropped in favour of `req.system` so the caller has
    // a single canonical place to set the prompt.
    let mut conv = Conversation::new(adapter, provider_label).with_model_label(model_label);
    if let Some(sys) = req.system.clone() {
        conv = conv.with_system(sys);
    } else if let Some(first) = req
        .messages
        .iter()
        .find(|m| m.role == "system")
        .map(|m| m.content.clone())
    {
        conv = conv.with_system(first);
    }

    // User-tools opt-out for tests / non-tool sessions. The live tool
    // registry lives under `$MANTIS_HOME/tools/`; loading it requires
    // disk + IO we don't want to perform when `tools: false`.
    if !req.tools {
        conv = conv.with_tools(Arc::new(NoTools));
    } else {
        use mantis_chat::UserToolRegistry;
        let tools_dir = state.mantis_home.join("tools");
        if tools_dir.exists() {
            match UserToolRegistry::from_dir(&tools_dir) {
                Ok(reg) => conv = conv.with_tools(Arc::new(reg)),
                Err(e) => tracing::warn!(
                    dir = %tools_dir.display(),
                    error = %e,
                    "user-tools dir skipped"
                ),
            }
        }
    }

    // Convert the wire messages into chat messages, skipping the
    // leading system message (already injected above) and rejecting
    // unknown roles.
    let mut seen_system = false;
    for m in req.messages {
        if m.role == "system" && !seen_system {
            seen_system = true;
            continue;
        }
        let chat_msg = m.into_chat()?;
        conv.extend_from_history(vec![chat_msg]);
    }

    let max_rounds = req.max_tool_rounds.max(1);

    // The last message in the transcript drives the turn. We pop it
    // and feed its content to `turn()` so the user-message append in
    // the chat engine doesn't double up.
    let last = conv
        .messages()
        .last()
        .filter(|m| m.role == ChatRole::User)
        .map(|m| m.content.clone())
        .ok_or_else(|| ApiError::bad_request("messages must end with a user message"))?;

    // Drop the trailing user message; turn() will re-append it.
    {
        let count = conv.messages().len();
        conv.clear_after(count - 1);
    }

    // Bridge the callback API to an mpsc channel feeding the SSE stream.
    let (tx, rx) = mpsc::channel::<ChatEvent>(64);

    tokio::spawn(async move {
        let tx2 = tx.clone();
        let result = conv
            .turn(last, max_rounds, move |ev| {
                let _ = tx2.try_send(ev.clone());
            })
            .await;
        if let Err(e) = result {
            // Surface the failure as a final warning event before the
            // stream closes. The caller is responsible for handling
            // `warning` followed by stream close as an error condition.
            let _ = tx
                .send(ChatEvent::Warning {
                    message: e.to_string(),
                })
                .await;
        }
        drop(tx);
    });

    let stream = ReceiverStream::new(rx).map(|ev| {
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            format!("{{\"type\":\"warning\",\"message\":\"serialize failed: {e}\"}}")
        });
        Ok::<_, Infallible>(Event::default().data(json))
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

/// Small extension on `Conversation` for slicing the message tail.
/// Implemented as a trait so we don't have to fork mantis-chat just
/// for the server's wire shape.
trait ConversationExt {
    fn clear_after(&mut self, len: usize);
}

impl ConversationExt for Conversation {
    fn clear_after(&mut self, len: usize) {
        // mantis-chat exposes `messages()` but not a mutable handle.
        // Rebuild the transcript by clearing system+ then re-extending
        // with the prefix we want to keep.
        let prefix: Vec<ChatMessage> = self.messages().iter().take(len).cloned().collect();
        self.clear();
        // `clear()` keeps the leading system messages — drop them
        // from the prefix so we don't duplicate.
        let sys_count = self.messages().len();
        self.extend_from_history(prefix.into_iter().skip(sys_count).collect());
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use futures::stream::{self, BoxStream};
    use futures::StreamExt as _;
    use mantis_synthesizer::{ChatEvent, ChatMessage, LlmAdapter, SynthError, Tool, ToolCall};
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Scripted adapter — yields a fixed list of events for any
    /// `stream_chat` call. Used to verify the SSE bridge without
    /// requiring a real provider.
    struct ScriptedAdapter {
        events: Vec<ChatEvent>,
    }

    #[async_trait]
    impl LlmAdapter for ScriptedAdapter {
        async fn complete(&self, _prompt: &str) -> Result<String, SynthError> {
            unreachable!("scripted adapter only supports stream_chat")
        }

        fn stream_chat<'a>(
            &'a self,
            _messages: &'a [ChatMessage],
            _tools: &'a [Tool],
        ) -> BoxStream<'a, Result<ChatEvent, SynthError>> {
            let evs: Vec<_> = self.events.iter().cloned().map(Ok).collect();
            stream::iter(evs).boxed()
        }
    }

    fn scripted_adapter() -> Arc<dyn LlmAdapter> {
        Arc::new(ScriptedAdapter {
            events: vec![
                ChatEvent::Text {
                    delta: "hello".into(),
                },
                ChatEvent::Text {
                    delta: " world".into(),
                },
                ChatEvent::Done {
                    stop_reason: Some("end_turn".into()),
                },
            ],
        })
    }

    fn _ignore(_call: &ToolCall) {}

    fn build_app(require_auth: bool) -> axum::Router {
        let config = crate::ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            require_auth,
            token_path: std::env::temp_dir().join("mantis-server-test.token"),
            mantis_home: std::env::temp_dir(),
            daemon_endpoint: "http://127.0.0.1:50451".into(),
            provider_override: Some(scripted_adapter()),
        };
        crate::routes::build_router(config).expect("build router")
    }

    #[tokio::test]
    async fn chat_sse_streams_text() {
        let app = build_app(false);

        let body = json!({
            "messages": [{"role":"user","content":"hi"}],
            "tools": false,
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);

        // SSE frames separate with blank lines; each frame starts with
        // `data: ` and carries a JSON-serialized ChatEvent.
        assert!(text.contains("data: "), "expected SSE frames, got: {text}");
        assert!(
            text.contains("\"type\":\"text\""),
            "expected text event, got: {text}"
        );
        assert!(
            text.contains("\"delta\":\"hello\""),
            "expected hello delta, got: {text}"
        );
        assert!(
            text.contains("\"type\":\"done\""),
            "expected done event, got: {text}"
        );
    }

    #[tokio::test]
    async fn chat_requires_auth_when_enabled() {
        // Use a known token path so the test is hermetic.
        let tmp = tempfile::TempDir::new().unwrap();
        let token_path = tmp.path().join("server.token");
        std::fs::write(&token_path, "test-token-value").unwrap();

        let config = crate::ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            require_auth: true,
            token_path,
            mantis_home: tmp.path().to_path_buf(),
            daemon_endpoint: "http://127.0.0.1:50451".into(),
            provider_override: Some(scripted_adapter()),
        };
        let app = crate::routes::build_router(config).expect("build router");

        let body = json!({
            "messages": [{"role":"user","content":"hi"}],
            "tools": false,
        });

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // With the right bearer, the same request must succeed.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token-value")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn chat_no_auth_when_disabled() {
        let app = build_app(false);

        let body = json!({
            "messages": [{"role":"user","content":"hi"}],
            "tools": false,
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn healthz_does_not_require_auth() {
        // Even with auth enabled, /healthz is anonymous.
        let tmp = tempfile::TempDir::new().unwrap();
        let token_path = tmp.path().join("server.token");
        std::fs::write(&token_path, "x").unwrap();

        let config = crate::ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            require_auth: true,
            token_path,
            mantis_home: tmp.path().to_path_buf(),
            daemon_endpoint: "http://127.0.0.1:50451".into(),
            provider_override: None,
        };
        let app = crate::routes::build_router(config).expect("build router");

        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
