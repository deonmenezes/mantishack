//! mantis-chat — conversational chat engine for the mantis CLI.
//!
//! Wraps the `mantis_synthesizer::LlmAdapter` streaming surface with:
//!   - [`Conversation`] — multi-turn state, system prompt, tool-loop
//!     resolution, optional history persistence
//!   - [`slash`] — `/clear` / `/model` / `/tools` / `/help` parsing for
//!     the REPL
//!   - [`tools::ChatToolRegistry`] — pluggable tool registry (MCP
//!     bridge or user-defined TOML tools land on top of this trait)
//!   - [`HistoryFile`] — JSONL append-only persistence at
//!     `$MANTIS_HOME/<engagement>/chat.jsonl`
//!
//! The chat surface is deliberately callback-driven (`turn(&mut self,
//! input, on_event)`) rather than `Stream`-returning. That keeps the
//! ownership story simple — the REPL writes events to stdout as they
//! arrive, and the HTTP server pushes them into an SSE channel, both
//! without forcing the conversation state behind an `Arc<Mutex<..>>`.

pub mod conversation;
pub mod history;
pub mod playbooks;
pub mod slash;
pub mod tools;

pub use conversation::Conversation;
pub use history::HistoryFile;
pub use playbooks::{
    compose_playbook_prompt, matching_playbooks, playbook_index, Playbook, PLAYBOOKS,
};
pub use slash::{parse_input, Input, SlashCommand};
pub use tools::user::UserToolRegistry;
pub use tools::{ChatToolRegistry, NoTools};

// Re-export foundation types so callers only depend on mantis-chat.
pub use mantis_synthesizer::{
    ChatEvent, ChatMessage, ChatRole, LlmAdapter, SynthError, Tool, ToolCall,
};
