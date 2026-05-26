//! Append-only log of items the TUI's message pane renders.
//!
//! The log is intentionally simple — a `Vec` of [`LogEntry`] items —
//! and the renderer materialises styled lines on every frame. We
//! trade compute for clarity: the entry set is small (a few hundred
//! turns at most) and rendering on every event would be fine even
//! without diffing.

use mantis_synthesizer::{ChatMessage, ToolCall};

/// One renderable item in the message log.
#[derive(Debug, Clone)]
pub enum LogEntry {
    /// User-supplied prompt for the current turn.
    User(String),
    /// Assistant text content. Streams append into the trailing
    /// `Assistant` entry until a [`LogEntry::TurnEnd`] arrives.
    Assistant(String),
    /// A model-requested tool call. Rendered as a dim `▸` line
    /// inside the assistant turn.
    ToolInvocation(ToolCall),
    /// Result text returned by a tool. Rendered as a dim `◂` line.
    ToolResult { call_id: String, content: String },
    /// Out-of-band system note — slash command echo, errors,
    /// warnings. Rendered dim and italic.
    SystemNote(String),
    /// Marker between assistant turns. Useful for paragraph spacing
    /// during render.
    TurnEnd,
}

#[derive(Debug, Default)]
pub struct MessageLog {
    entries: Vec<LogEntry>,
}

impl MessageLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Append a new entry verbatim.
    pub fn push(&mut self, entry: LogEntry) {
        self.entries.push(entry);
    }

    /// Append assistant text. If the trailing entry is already an
    /// `Assistant` entry (active stream), concatenates instead of
    /// pushing a new one. This is how `ChatEvent::Text { delta }`
    /// events accumulate into a single rendered paragraph.
    pub fn append_assistant_text(&mut self, delta: &str) {
        match self.entries.last_mut() {
            Some(LogEntry::Assistant(buf)) => buf.push_str(delta),
            _ => self.entries.push(LogEntry::Assistant(delta.to_string())),
        }
    }

    /// Drop every entry — keeps the log struct alive, mirrors the
    /// `/clear` slash command's effect on the visible history.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Replay a saved transcript so the user sees their resumed
    /// session as if they had just lived through it.
    pub fn rehydrate_from(&mut self, messages: &[ChatMessage]) {
        use mantis_synthesizer::ChatRole;
        for m in messages {
            match m.role {
                ChatRole::System => {
                    // System messages are not user-visible by default.
                }
                ChatRole::User => self.push(LogEntry::User(m.content.clone())),
                ChatRole::Assistant => {
                    if !m.content.is_empty() {
                        self.push(LogEntry::Assistant(m.content.clone()));
                    }
                    for tc in &m.tool_calls {
                        self.push(LogEntry::ToolInvocation(tc.clone()));
                    }
                    self.push(LogEntry::TurnEnd);
                }
                ChatRole::Tool => self.push(LogEntry::ToolResult {
                    call_id: m.tool_call_id.clone().unwrap_or_default(),
                    content: m.content.clone(),
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantis_synthesizer::ChatMessage;

    #[test]
    fn assistant_text_accumulates_into_trailing_entry() {
        let mut log = MessageLog::new();
        log.append_assistant_text("hel");
        log.append_assistant_text("lo");
        assert_eq!(log.len(), 1);
        match &log.entries()[0] {
            LogEntry::Assistant(s) => assert_eq!(s, "hello"),
            other => panic!("expected Assistant, got {other:?}"),
        }
    }

    #[test]
    fn user_message_breaks_assistant_streak() {
        let mut log = MessageLog::new();
        log.append_assistant_text("a");
        log.push(LogEntry::User("hi".into()));
        log.append_assistant_text("b");
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn rehydrate_skips_system_and_preserves_tool_calls() {
        let mut log = MessageLog::new();
        let mut assistant_with_call = ChatMessage::assistant("on it");
        assistant_with_call
            .tool_calls
            .push(mantis_synthesizer::ToolCall {
                id: "c1".into(),
                name: "echo".into(),
                arguments: serde_json::json!({}),
            });
        let msgs = vec![
            ChatMessage::system("hidden"),
            ChatMessage::user("hello"),
            assistant_with_call,
            ChatMessage::tool_result("c1", "ECHO()"),
        ];
        log.rehydrate_from(&msgs);
        // user + assistant text + tool invocation + turn-end + tool result
        assert_eq!(log.len(), 5);
        assert!(matches!(log.entries()[0], LogEntry::User(_)));
        assert!(matches!(log.entries()[1], LogEntry::Assistant(_)));
        assert!(matches!(log.entries()[2], LogEntry::ToolInvocation(_)));
        assert!(matches!(log.entries()[3], LogEntry::TurnEnd));
        assert!(matches!(log.entries()[4], LogEntry::ToolResult { .. }));
    }
}
