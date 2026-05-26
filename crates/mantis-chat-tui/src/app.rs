//! Top-level TUI app — terminal lifecycle, event loop, and the
//! `App` struct that owns the conversation + UI state.
//!
//! Streaming, multiline input, markdown rendering, session picking,
//! and attachments are layered on by tasks #12–#17. This module
//! provides the scaffolding those tasks plug into.

use std::io::{stdout, Stdout};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::{self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use mantis_chat::{ChatRole, ChatToolRegistry, Conversation, HistoryFile, LlmAdapter, NoTools};

use crate::input::{InputAction, InputWidget};
use crate::messages::{LogEntry, MessageLog};
use crate::ui::{render, ViewModel};

/// Construction-time configuration for the TUI app. Mirrors the
/// CLI's `mantis chat` flags so the binary's `Tui` subcommand can
/// pass these through without translation.
pub struct Config {
    pub adapter: Arc<dyn LlmAdapter>,
    pub provider: String,
    pub model: String,
    pub session: String,
    pub system_prompt: Option<String>,
    pub history_path: PathBuf,
    pub resume: bool,
    pub tools: Option<Arc<dyn ChatToolRegistry>>,
    pub max_tool_rounds: usize,
    /// When true, [`run`] opens the session picker before entering
    /// the chat UI. The picker scans the parent of `history_path` for
    /// `*.jsonl` sessions; selecting one overrides `session` +
    /// `history_path` and forces `resume = true`. Default `false`
    /// preserves existing callers.
    pub allow_picker: bool,
}

/// Mutable state owned by the running app. Renderer reads, event
/// handlers + streaming task write.
pub struct UiState {
    pub provider: String,
    pub model: String,
    pub session: String,
    pub last_turn_ms: Option<u64>,
    pub log: MessageLog,
    pub input: InputWidget,
    pub streaming: bool,
    pub footer_hint: String,
    pub should_quit: bool,
    /// Cached slash-command suggestions for the current buffer.
    /// Recomputed whenever the buffer changes via
    /// [`UiState::refresh_slash_suggestions`].
    pub slash_suggestions: Vec<(&'static str, &'static str)>,
}

impl UiState {
    fn view(&self) -> ViewModel<'_> {
        ViewModel {
            provider: &self.provider,
            model: &self.model,
            session: &self.session,
            last_turn_ms: self.last_turn_ms,
            log: &self.log,
            input_buffer: self.input.buffer(),
            input_cursor: self.input.cursor(),
            streaming: self.streaming,
            footer_hint: &self.footer_hint,
            slash_suggestions: &self.slash_suggestions,
        }
    }

    /// Recompute slash-command suggestions from the current input
    /// buffer. Empties the list when the buffer doesn't start with
    /// `/` or contains whitespace after the command (i.e. once an
    /// argument is being typed).
    fn refresh_slash_suggestions(&mut self) {
        let buf = self.input.buffer();
        self.slash_suggestions.clear();
        let Some(rest) = buf.strip_prefix('/') else {
            return;
        };
        // Once the user starts typing arguments after the command,
        // we no longer want to autocomplete the command name itself.
        if rest.contains(char::is_whitespace) {
            return;
        }
        for entry in crate::widgets::slash::suggest(rest) {
            self.slash_suggestions.push((entry.0, entry.1));
        }
    }
}

/// Entry point: launches the TUI, runs the event loop until the
/// user quits or stdin closes, then restores the terminal. Designed
/// to be called from `mantis tui` and from `mantis chat` when stdout
/// is a TTY.
pub async fn run(mut config: Config) -> Result<()> {
    // When the caller didn't pin a session, surface the session
    // picker first so the operator can resume a prior conversation
    // or start a fresh one. The picker lives in its own alternate-
    // screen and exits cleanly before the chat UI takes the screen.
    if config.allow_picker {
        let dir = config
            .history_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        match crate::widgets::picker::run_picker(&dir).await? {
            crate::widgets::picker::PickerOutcome::Resume(entry) => {
                config.session = entry.name.clone();
                config.history_path = entry.path.clone();
                config.resume = true;
            }
            crate::widgets::picker::PickerOutcome::FreshSession(name) => {
                if let Some(n) = name {
                    config.session = n;
                    if let Some(parent) = config.history_path.parent() {
                        config.history_path = parent.join(format!("{}.jsonl", config.session));
                    }
                }
                // Fresh session — do NOT auto-resume even if the file
                // already exists (it shouldn't, since the picker skips
                // showing for an empty dir).
            }
            crate::widgets::picker::PickerOutcome::Quit => {
                return Ok(());
            }
        }
    }

    // Build the conversation up front so we surface any provider
    // errors before entering the alternate screen (otherwise the
    // user sees a flash and a blank terminal).
    let history_file = HistoryFile::open(&config.history_path)
        .with_context(|| format!("opening chat history at {}", config.history_path.display()))?;

    let mut conv = Conversation::new(config.adapter, config.provider.clone())
        .with_model_label(config.model.clone())
        .with_history(history_file);
    if let Some(prompt) = &config.system_prompt {
        conv = conv.with_system(prompt.clone());
    }
    if let Some(tools) = config.tools.clone() {
        conv = conv.with_tools(tools);
    } else {
        conv = conv.with_tools(Arc::new(NoTools));
    }

    let mut state = UiState {
        provider: config.provider.clone(),
        model: config.model.clone(),
        session: config.session.clone(),
        last_turn_ms: None,
        log: MessageLog::new(),
        input: InputWidget::new(),
        streaming: false,
        footer_hint: "ctrl+c to exit · /help for commands".into(),
        should_quit: false,
        slash_suggestions: Vec::new(),
    };

    if config.resume {
        match HistoryFile::load(&config.history_path) {
            Ok(prior) => {
                let n = prior.len();
                // Seed the input-history with prior user messages so
                // ↑/↓ in the input box can recall them.
                let prior_user_msgs: Vec<String> = prior
                    .iter()
                    .filter(|m| m.role == ChatRole::User)
                    .map(|m| m.content.clone())
                    .collect();
                state.input = InputWidget::new().with_history(prior_user_msgs);
                state.log.rehydrate_from(&prior);
                conv.extend_from_history(prior);
                state.log.push(LogEntry::SystemNote(format!(
                    "resumed {n} prior message(s) from {}",
                    config.history_path.display()
                )));
                state.log.push(LogEntry::TurnEnd);
            }
            Err(e) => {
                state.log.push(LogEntry::SystemNote(format!(
                    "could not resume history: {e}"
                )));
            }
        }
    }

    let mut terminal = enter_terminal()?;
    let result = event_loop(&mut terminal, &mut state, &mut conv, config.max_tool_rounds).await;
    leave_terminal(&mut terminal)?;
    result
}

fn enter_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableBracketedPaste)?;
    let backend = CrosstermBackend::new(out);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn leave_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableBracketedPaste
    )?;
    terminal.show_cursor()?;
    Ok(())
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &mut UiState,
    conv: &mut Conversation,
    max_tool_rounds: usize,
) -> Result<()> {
    let tick = Duration::from_millis(100);

    loop {
        terminal.draw(|f| render(f, &state.view()))?;

        if state.should_quit {
            return Ok(());
        }

        if event::poll(tick)? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    if state.streaming {
                        // Only ctrl+c during streaming.
                        if let crossterm::event::KeyCode::Char('c') = key.code {
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL)
                            {
                                state.should_quit = true;
                            }
                        }
                        continue;
                    }
                    // Intercept Tab when slash suggestions are
                    // active: accept the first suggestion as
                    // `/<command> ` (with trailing space).
                    if matches!(key.code, crossterm::event::KeyCode::Tab)
                        && !state.slash_suggestions.is_empty()
                    {
                        let cmd = state.slash_suggestions[0].0;
                        state.input.replace(format!("/{cmd} "));
                        state.refresh_slash_suggestions();
                        continue;
                    }
                    match state.input.handle_key(key) {
                        InputAction::Continue => {
                            state.refresh_slash_suggestions();
                        }
                        InputAction::Quit => {
                            state.should_quit = true;
                        }
                        InputAction::Submit(msg) => {
                            state.slash_suggestions.clear();
                            submit_turn(state, conv, msg, max_tool_rounds, terminal).await?;
                        }
                    }
                }
                Event::Paste(data)
                    if !state.streaming => {
                        state.input.insert_str(&data);
                        state.refresh_slash_suggestions();
                    }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
}

/// Run one turn end-to-end. The streaming integration in task #12
/// will spawn this on a tokio task and feed events back into the UI
/// over an mpsc channel. The scaffold runs it inline (blocking the
/// event loop for now), which keeps the architecture simple while
/// the layered tasks land.
async fn submit_turn(
    state: &mut UiState,
    conv: &mut Conversation,
    input: String,
    max_tool_rounds: usize,
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
) -> Result<()> {
    use mantis_synthesizer::ChatEvent;

    // Echo the *original* user input to the log so the UI shows
    // what the operator typed, not the expanded prompt. Push to
    // history likewise — they want ↑ to recall their actual line,
    // not the file-dump-laden version.
    state.log.push(LogEntry::User(input.clone()));
    state.input.push_history(input.clone());

    // Expand `@<path>` tokens into inline file blocks before
    // forwarding to the model. Notes (paths + byte counts, or
    // attachment failures) are surfaced as a dim SystemNote so
    // the operator sees what got picked up.
    let expansion = crate::attachments::expand(&input, crate::attachments::DEFAULT_BUDGET_BYTES);
    if !expansion.notes.is_empty() {
        for note in &expansion.notes {
            state
                .log
                .push(LogEntry::SystemNote(format!("attachment: {note}")));
        }
    }
    let prompt_for_model = expansion.prompt;

    state.streaming = true;
    state.last_turn_ms = None;
    let started = Instant::now();

    terminal.draw(|f| render(f, &state.view()))?;

    // Capture-via-RefCell pattern: the callback needs &mut access to
    // both the log and the streaming flag while `conv.turn` borrows
    // conv mutably. We use a small closure capturing &mut state.log
    // directly — the closure is FnMut and conv.turn's signature
    // requires FnMut.
    let log_ref = &mut state.log;
    let mut last_was_tool = false;
    let result = conv
        .turn(prompt_for_model, max_tool_rounds, |event| match event {
            ChatEvent::Text { delta } => {
                if last_was_tool {
                    log_ref.push(LogEntry::TurnEnd);
                    last_was_tool = false;
                }
                log_ref.append_assistant_text(delta);
            }
            ChatEvent::ToolCall(call) => {
                log_ref.push(LogEntry::ToolInvocation(call.clone()));
                last_was_tool = true;
            }
            ChatEvent::Done { .. } => {
                log_ref.push(LogEntry::TurnEnd);
            }
            ChatEvent::Warning { message } => {
                log_ref.push(LogEntry::SystemNote(format!("warning: {message}")));
            }
        })
        .await;

    state.streaming = false;
    state.last_turn_ms = Some(started.elapsed().as_millis() as u64);

    if let Err(e) = result {
        state
            .log
            .push(LogEntry::SystemNote(format!("turn failed: {e}")));
    }
    Ok(())
}
