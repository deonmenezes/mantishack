//! Multi-turn conversation state with streaming + tool-loop
//! resolution. Wraps an `LlmAdapter` and a `ChatToolRegistry`.
//!
//! The single entry point operators care about is [`Conversation::turn`]:
//! given a user input, it appends the message, calls the underlying
//! adapter's `stream_chat`, streams every event to a caller-supplied
//! callback, and — if the model emitted any tool calls — executes
//! them and re-enters the stream. The loop terminates either when
//! the model produces a turn with no tool calls or when the
//! `max_tool_rounds` budget is exhausted.
//!
//! State is owned by the `Conversation` itself; the REPL keeps one
//! instance per session and calls `turn` per user line.

use std::sync::Arc;

use futures::StreamExt;
use tracing::warn;

use mantis_synthesizer::{
    ChatEvent, ChatMessage, ChatRole, LlmAdapter, SynthError, ToolCall,
};

use crate::history::HistoryFile;
use crate::tools::{ChatToolRegistry, NoTools};

/// One chat session. Holds the message transcript, the LLM adapter,
/// an optional tool registry, and an optional history file.
pub struct Conversation {
    adapter: Arc<dyn LlmAdapter>,
    messages: Vec<ChatMessage>,
    tools: Arc<dyn ChatToolRegistry>,
    history: Option<HistoryFile>,
    provider_label: String,
    model_label: String,
}

impl Conversation {
    pub fn new(adapter: Arc<dyn LlmAdapter>, provider_label: impl Into<String>) -> Self {
        Self {
            adapter,
            messages: Vec::new(),
            tools: Arc::new(NoTools),
            history: None,
            provider_label: provider_label.into(),
            model_label: String::new(),
        }
    }

    pub fn with_system(mut self, prompt: impl Into<String>) -> Self {
        self.messages.push(ChatMessage::system(prompt));
        self
    }

    /// Append additional text to the first system message in the
    /// transcript (or push a new system message if none exists).
    /// Used to inject vuln-class playbooks mid-session without
    /// rebuilding the conversation.
    ///
    /// Idempotent on the byte content: if the existing system
    /// message already contains the addition verbatim, this is a
    /// no-op. Lets callers safely re-arm playbooks on every turn
    /// without bloating the prompt.
    pub fn augment_system_prompt(&mut self, addition: &str) {
        if addition.trim().is_empty() {
            return;
        }
        if let Some(sys) = self
            .messages
            .iter_mut()
            .find(|m| m.role == ChatRole::System)
        {
            if !sys.content.contains(addition) {
                sys.content.push_str(addition);
            }
        } else {
            self.messages
                .insert(0, ChatMessage::system(addition.to_string()));
        }
    }

    pub fn with_tools(mut self, tools: Arc<dyn ChatToolRegistry>) -> Self {
        self.tools = tools;
        self
    }

    pub fn with_history(mut self, history: HistoryFile) -> Self {
        self.history = Some(history);
        self
    }

    pub fn with_model_label(mut self, model: impl Into<String>) -> Self {
        self.model_label = model.into();
        self
    }

    pub fn provider(&self) -> &str {
        &self.provider_label
    }

    pub fn model(&self) -> &str {
        &self.model_label
    }

    pub fn messages(&self) -> &[ChatMessage] {
        &self.messages
    }

    /// Snapshot of the currently registered tools. Used by the
    /// REPL's `/tools` slash command. The registry is queried once
    /// per call — dynamic registries can return different sets
    /// across snapshots.
    pub fn tools_snapshot(&self) -> Vec<mantis_synthesizer::Tool> {
        self.tools.tools()
    }

    /// Drop the entire transcript except the leading system
    /// message(s). Used by `/clear`.
    pub fn clear(&mut self) {
        let sys_count = self
            .messages
            .iter()
            .take_while(|m| m.role == ChatRole::System)
            .count();
        self.messages.truncate(sys_count);
    }

    /// Append already-built messages to the transcript. Used to
    /// rehydrate a saved history at startup.
    pub fn extend_from_history(&mut self, msgs: Vec<ChatMessage>) {
        self.messages.extend(msgs);
    }

    /// Run one user-driven turn.
    ///
    /// 1. Appends `input` as a user message and persists to history.
    /// 2. Calls `adapter.stream_chat`, forwarding every event to
    ///    `on_event` (callback model: lets the REPL write to stdout
    ///    in real time without async-stream borrow gymnastics).
    /// 3. If the model emitted tool calls, executes them via the
    ///    registry, appends a `tool_result` message per call, and
    ///    loops back into step 2.
    /// 4. Loop exits when the model finishes a turn without
    ///    requesting tools, or `max_tool_rounds` is hit.
    ///
    /// `max_tool_rounds` should be ≥ 1; the user-message turn
    /// itself counts as round 1.
    pub async fn turn<F: FnMut(&ChatEvent)>(
        &mut self,
        input: String,
        max_tool_rounds: usize,
        mut on_event: F,
    ) -> Result<(), SynthError> {
        let user_msg = ChatMessage::user(input);
        self.persist(&user_msg);
        self.messages.push(user_msg);

        let rounds = max_tool_rounds.max(1);
        for round in 0..rounds {
            let tools = self.tools.tools();
            let mut stream = self.adapter.stream_chat(&self.messages, &tools);
            let mut accumulated_text = String::new();
            let mut pending_calls: Vec<ToolCall> = Vec::new();
            let mut stop_reason: Option<String> = None;

            while let Some(event) = stream.next().await {
                let event = event?;
                match &event {
                    ChatEvent::Text { delta } => accumulated_text.push_str(delta),
                    ChatEvent::ToolCall(call) => pending_calls.push(call.clone()),
                    ChatEvent::Done { stop_reason: r } => {
                        stop_reason = r.clone();
                    }
                    ChatEvent::Warning { .. } => {}
                }
                on_event(&event);
            }

            // Drop the stream's borrow before mutating self.messages.
            drop(stream);

            let mut assistant_msg = ChatMessage::assistant(accumulated_text);
            assistant_msg.tool_calls = pending_calls.clone();
            self.persist(&assistant_msg);
            self.messages.push(assistant_msg);

            if pending_calls.is_empty() {
                // Normal end-of-turn.
                let _ = stop_reason;
                return Ok(());
            }

            if round + 1 >= rounds {
                // Tool-loop budget exhausted. Surface as an error so
                // the REPL can warn the operator; the partial
                // transcript is preserved.
                warn!(
                    rounds,
                    "tool-call loop hit the max-rounds budget without converging"
                );
                return Err(SynthError::Backend(format!(
                    "tool loop exceeded {rounds} rounds without a final answer"
                )));
            }

            for call in &pending_calls {
                let content = match self.tools.execute(call).await {
                    Ok(s) => s,
                    Err(e) => format!("[tool error: {e}]"),
                };
                let result_msg = ChatMessage::tool_result(call.id.clone(), content);
                self.persist(&result_msg);
                self.messages.push(result_msg);
            }
        }
        Ok(())
    }

    fn persist(&mut self, msg: &ChatMessage) {
        if let Some(h) = self.history.as_mut() {
            if let Err(e) = h.append(msg) {
                warn!("failed to persist chat message to history: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use serde_json::json;

    use mantis_synthesizer::{ChatEvent, ChatRole, Tool, ToolCall};

    /// A scripted adapter: each call to `stream_chat` consumes one
    /// canned reply from the queue.
    struct ScriptedAdapter {
        replies: tokio::sync::Mutex<std::collections::VecDeque<Vec<ChatEvent>>>,
    }

    impl ScriptedAdapter {
        fn new(replies: Vec<Vec<ChatEvent>>) -> Self {
            Self {
                replies: tokio::sync::Mutex::new(replies.into()),
            }
        }
    }

    #[async_trait]
    impl LlmAdapter for ScriptedAdapter {
        async fn complete(&self, _prompt: &str) -> Result<String, SynthError> {
            unreachable!("scripted adapter only supports stream_chat in tests")
        }

        fn stream_chat<'a>(
            &'a self,
            _messages: &'a [ChatMessage],
            _tools: &'a [Tool],
        ) -> futures::stream::BoxStream<'a, Result<ChatEvent, SynthError>> {
            let fut = async move {
                let mut g = self.replies.lock().await;
                let reply = g.pop_front().unwrap_or_default();
                reply.into_iter().map(Ok).collect::<Vec<_>>()
            };
            futures::stream::once(fut)
                .flat_map(futures::stream::iter)
                .boxed()
        }
    }

    struct EchoTools;

    #[async_trait]
    impl ChatToolRegistry for EchoTools {
        fn tools(&self) -> Vec<Tool> {
            vec![Tool {
                name: "echo".into(),
                description: "echoes its input".into(),
                input_schema: json!({"type":"object","properties":{"msg":{"type":"string"}}}),
            }]
        }

        async fn execute(&self, call: &ToolCall) -> Result<String, anyhow::Error> {
            Ok(format!("ECHO({})", call.arguments))
        }
    }

    fn done() -> ChatEvent {
        ChatEvent::Done { stop_reason: None }
    }

    fn text(s: &str) -> ChatEvent {
        ChatEvent::Text { delta: s.into() }
    }

    fn tool(id: &str, name: &str, args: serde_json::Value) -> ChatEvent {
        ChatEvent::ToolCall(ToolCall {
            id: id.into(),
            name: name.into(),
            arguments: args,
        })
    }

    #[tokio::test]
    async fn turn_appends_user_and_assistant_messages() {
        let adapter = Arc::new(ScriptedAdapter::new(vec![vec![text("hi back!"), done()]]));
        let mut conv = Conversation::new(adapter, "scripted").with_system("be brief");
        let mut events = Vec::new();
        conv.turn("hello".to_string(), 4, |ev| events.push(ev.clone()))
            .await
            .unwrap();
        assert_eq!(conv.messages().len(), 3); // system + user + assistant
        assert_eq!(conv.messages()[0].role, ChatRole::System);
        assert_eq!(conv.messages()[1].role, ChatRole::User);
        assert_eq!(conv.messages()[1].content, "hello");
        assert_eq!(conv.messages()[2].role, ChatRole::Assistant);
        assert_eq!(conv.messages()[2].content, "hi back!");
        assert!(matches!(events[0], ChatEvent::Text { .. }));
        assert!(matches!(events[1], ChatEvent::Done { .. }));
    }

    #[tokio::test]
    async fn turn_executes_tool_call_and_resumes_stream() {
        // Round 1: assistant emits a tool call.
        // Round 2: assistant produces a final text answer.
        let adapter = Arc::new(ScriptedAdapter::new(vec![
            vec![tool("c1", "echo", json!({"msg": "yo"})), done()],
            vec![text("done with the echo"), done()],
        ]));
        let mut conv = Conversation::new(adapter, "scripted").with_tools(Arc::new(EchoTools));
        conv.turn("call the tool".to_string(), 4, |_| {})
            .await
            .unwrap();
        // Expected transcript:
        // [0] user("call the tool")
        // [1] assistant (with tool_calls)
        // [2] tool result for c1
        // [3] assistant final
        assert_eq!(conv.messages().len(), 4);
        assert_eq!(conv.messages()[0].role, ChatRole::User);
        assert_eq!(conv.messages()[1].role, ChatRole::Assistant);
        assert_eq!(conv.messages()[1].tool_calls.len(), 1);
        assert_eq!(conv.messages()[2].role, ChatRole::Tool);
        assert_eq!(conv.messages()[2].tool_call_id.as_deref(), Some("c1"));
        assert!(conv.messages()[2].content.contains("ECHO"));
        assert_eq!(conv.messages()[3].role, ChatRole::Assistant);
        assert_eq!(conv.messages()[3].content, "done with the echo");
    }

    #[tokio::test]
    async fn tool_loop_budget_is_enforced() {
        // Every round emits a tool call — should hit the budget.
        let adapter = Arc::new(ScriptedAdapter::new(vec![
            vec![tool("a", "echo", json!({})), done()],
            vec![tool("b", "echo", json!({})), done()],
            vec![tool("c", "echo", json!({})), done()],
        ]));
        let mut conv = Conversation::new(adapter, "scripted").with_tools(Arc::new(EchoTools));
        let result = conv.turn("loop".to_string(), 2, |_| {}).await;
        assert!(result.is_err(), "expected budget exhaustion");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("2 rounds") || err.contains("tool loop"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn clear_preserves_system_messages() {
        let adapter = Arc::new(ScriptedAdapter::new(vec![vec![text("ok"), done()]]));
        let mut conv = Conversation::new(adapter, "scripted").with_system("you are mantis");
        conv.turn("first".to_string(), 4, |_| {}).await.unwrap();
        assert_eq!(conv.messages().len(), 3);
        conv.clear();
        assert_eq!(conv.messages().len(), 1);
        assert_eq!(conv.messages()[0].role, ChatRole::System);
    }

    #[test]
    fn augment_system_prompt_appends_to_existing_system() {
        let adapter = Arc::new(ScriptedAdapter::new(vec![vec![text("x"), done()]]));
        let mut conv =
            Conversation::new(adapter, "scripted").with_system("you are mantis");
        conv.augment_system_prompt("\n\nadditional context");
        assert_eq!(conv.messages().len(), 1);
        assert_eq!(conv.messages()[0].role, ChatRole::System);
        assert!(conv.messages()[0].content.contains("you are mantis"));
        assert!(conv.messages()[0].content.contains("additional context"));
    }

    #[test]
    fn augment_system_prompt_is_idempotent_on_byte_content() {
        let adapter = Arc::new(ScriptedAdapter::new(vec![vec![text("x"), done()]]));
        let mut conv = Conversation::new(adapter, "scripted").with_system("base");
        conv.augment_system_prompt("\n\nextra");
        let after_first = conv.messages()[0].content.clone();
        // Second call with the same text should NOT duplicate.
        conv.augment_system_prompt("\n\nextra");
        assert_eq!(conv.messages()[0].content, after_first);
    }

    #[test]
    fn augment_system_prompt_creates_one_when_missing() {
        let adapter = Arc::new(ScriptedAdapter::new(vec![vec![text("x"), done()]]));
        let mut conv = Conversation::new(adapter, "scripted");
        assert!(conv.messages().is_empty());
        conv.augment_system_prompt("brand-new system text");
        assert_eq!(conv.messages().len(), 1);
        assert_eq!(conv.messages()[0].role, ChatRole::System);
        assert_eq!(conv.messages()[0].content, "brand-new system text");
    }

    #[test]
    fn augment_system_prompt_skips_empty_input() {
        let adapter = Arc::new(ScriptedAdapter::new(vec![vec![text("x"), done()]]));
        let mut conv = Conversation::new(adapter, "scripted").with_system("base");
        conv.augment_system_prompt("");
        conv.augment_system_prompt("   ");
        assert_eq!(conv.messages()[0].content, "base");
    }
}
