//! mantis-chat-tui — Codex-CLI-style terminal UI for the mantis
//! conversational surface.
//!
//! Layout (top to bottom):
//!   ┌─────────────────────────────────────────────────────────┐
//!   │ status bar (provider, model, session, latency)          │  ← 1 row
//!   ├─────────────────────────────────────────────────────────┤
//!   │ message log                                             │  ← fills
//!   │   user > ...                                            │
//!   │   mantis > ... (streaming, markdown-rendered)           │
//!   ├─────────────────────────────────────────────────────────┤
//!   │ ▸ tool_call_box (only when active)                      │  ← inline
//!   ├─────────────────────────────────────────────────────────┤
//!   │ input box (multiline, slash-autocomplete dropdown)      │  ← 3+ rows
//!   └─────────────────────────────────────────────────────────┘
//!
//! Architecture:
//! - [`App`] owns the [`UiState`] and the underlying [`Conversation`].
//!   It runs the crossterm event loop on the calling thread, with
//!   streaming `ChatEvent`s arriving over an `mpsc::Receiver` from
//!   a background tokio task spawned per user turn.
//! - Subsequent tasks fill in the modules under [`widgets`]:
//!   markdown rendering, multiline input, status bar, slash
//!   autocomplete, session picker.
//! - The crate is intentionally library-only — `mantis tui` lives
//!   in the CLI binary and just calls [`App::run`].

pub mod app;
pub mod attachments;
pub mod input;
pub mod messages;
pub mod ui;
pub mod widgets;

pub use app::{run, Config};
pub use attachments::{expand as expand_attachments, Expansion};
pub use input::{InputAction, InputWidget};
pub use messages::{LogEntry, MessageLog};
pub use widgets::picker::{run_picker, PickerOutcome, SessionEntry};
