//! Session picker — full-screen list selector shown when the user
//! runs `mantis chat` without a `--session` flag.
//!
//! Scans the chat history directory for `*.jsonl` files, lists them
//! sorted newest-first with a one-line preview drawn from the first
//! user message in each session, and lets the operator either
//! resume one, start a fresh session, delete a stale one, or quit.
//!
//! Lifecycle: [`run_picker`] enters its own alternate-screen, draws
//! the UI in an event loop driven by [`step`], and leaves the
//! alternate-screen before returning. The caller (`app::run`) then
//! enters the chat alternate-screen for the main view.
//!
//! Tests drive [`step`] directly against a synthetic [`PickerState`]
//! without spinning up a real terminal.

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Stdout};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
use ratatui::{Frame, Terminal};
use serde_json::Value;

/// One entry shown in the picker. One entry per `*.jsonl` file found
/// in the scanned directory.
#[derive(Debug, Clone)]
pub struct SessionEntry {
    /// Filename stem, e.g. `"default"` or `"app-tenkara"`.
    pub name: String,
    /// Absolute path to the JSONL file.
    pub path: PathBuf,
    /// Last-modified timestamp from the filesystem.
    pub modified: SystemTime,
    /// Number of JSON lines in the file (one per chat message).
    pub message_count: usize,
    /// First user message in the session, truncated to ~80 chars.
    pub preview: Option<String>,
}

/// User's choice when the picker exits.
#[derive(Debug, Clone)]
pub enum PickerOutcome {
    /// User selected a session — caller resumes it.
    Resume(SessionEntry),
    /// User chose to start a fresh session with this name.
    /// `None` = caller-supplied default name.
    FreshSession(Option<String>),
    /// User quit the picker without choosing (Ctrl+C / Esc / q).
    Quit,
}

/// Scan `dir` for `*.jsonl` files, build the list (sorted by modified
/// time, newest first), and run the picker UI. Returns the outcome.
///
/// If `dir` doesn't exist OR contains no sessions, returns
/// `Ok(PickerOutcome::FreshSession(None))` without showing the UI —
/// the caller's default-session flow takes over.
pub async fn run_picker(dir: &Path) -> Result<PickerOutcome> {
    let entries = scan_sessions(dir)?;
    if entries.is_empty() {
        return Ok(PickerOutcome::FreshSession(None));
    }

    let mut terminal = enter_picker_terminal()?;
    let result = run_picker_loop(&mut terminal, entries, dir).await;
    leave_picker_terminal(&mut terminal)?;
    result
}

fn enter_picker_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut out = std::io::stdout();
    execute!(out, EnterAlternateScreen, EnableBracketedPaste)?;
    let backend = CrosstermBackend::new(out);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn leave_picker_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableBracketedPaste
    )?;
    terminal.show_cursor()?;
    Ok(())
}

async fn run_picker_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    initial_entries: Vec<SessionEntry>,
    dir: &Path,
) -> Result<PickerOutcome> {
    let mut state = PickerState::new(initial_entries);
    let tick = Duration::from_millis(100);

    loop {
        terminal.draw(|f| render_picker(f, &state))?;

        if event::poll(tick)? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    if let Some(outcome) = step(&mut state, key) {
                        // `Delete` is an intent — perform the side
                        // effect, refresh the list, and continue.
                        match outcome {
                            StepResult::Outcome(o) => return Ok(o),
                            StepResult::DeleteSelected => {
                                if let Some(entry) = state.selected_entry().cloned() {
                                    let _ = fs::remove_file(&entry.path);
                                    let refreshed = scan_sessions(dir)?;
                                    if refreshed.is_empty() {
                                        return Ok(PickerOutcome::FreshSession(None));
                                    }
                                    state = PickerState::new(refreshed);
                                }
                            }
                        }
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
}

/// Internal mutable state for the picker. Owned by `run_picker_loop`
/// and threaded through `step` for testability.
#[derive(Debug)]
pub(crate) struct PickerState {
    pub(crate) entries: Vec<SessionEntry>,
    pub(crate) selected: usize,
    pub(crate) confirm_delete: bool,
}

impl PickerState {
    pub(crate) fn new(entries: Vec<SessionEntry>) -> Self {
        Self {
            entries,
            selected: 0,
            confirm_delete: false,
        }
    }

    pub(crate) fn selected_entry(&self) -> Option<&SessionEntry> {
        self.entries.get(self.selected)
    }
}

/// Result of one step. `Outcome` exits the loop; `DeleteSelected`
/// asks the caller to delete the highlighted file and rebuild the
/// list.
#[derive(Debug, Clone)]
pub(crate) enum StepResult {
    Outcome(PickerOutcome),
    DeleteSelected,
}

/// Apply one key event to the picker state. Returns `Some(StepResult)`
/// when the outer loop needs to take action; `None` for purely
/// in-state changes (selection movement, etc.).
pub(crate) fn step(state: &mut PickerState, key: KeyEvent) -> Option<StepResult> {
    // Ctrl+C always quits regardless of mode.
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return Some(StepResult::Outcome(PickerOutcome::Quit));
    }

    if state.confirm_delete {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                state.confirm_delete = false;
                return Some(StepResult::DeleteSelected);
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                state.confirm_delete = false;
                return None;
            }
            _ => return None,
        }
    }

    match key.code {
        KeyCode::Up => {
            if state.selected > 0 {
                state.selected -= 1;
            }
            None
        }
        KeyCode::Down => {
            if state.selected + 1 < state.entries.len() {
                state.selected += 1;
            }
            None
        }
        KeyCode::Enter => state
            .selected_entry()
            .cloned()
            .map(|e| StepResult::Outcome(PickerOutcome::Resume(e))),
        KeyCode::Char('n') => Some(StepResult::Outcome(PickerOutcome::FreshSession(None))),
        KeyCode::Char('d') => {
            if !state.entries.is_empty() {
                state.confirm_delete = true;
            }
            None
        }
        KeyCode::Char('q') | KeyCode::Esc => Some(StepResult::Outcome(PickerOutcome::Quit)),
        _ => None,
    }
}

/// Scan `dir` for `*.jsonl` files. Returns entries sorted by
/// modified time, newest first. Missing directory yields an empty
/// vec (caller falls back to fresh-session).
pub(crate) fn scan_sessions(dir: &Path) -> Result<Vec<SessionEntry>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let read = fs::read_dir(dir)
        .with_context(|| format!("reading session directory {}", dir.display()))?;
    let mut entries: Vec<SessionEntry> = Vec::new();
    for dirent in read.flatten() {
        let path = dirent.path();
        if path.extension().map(|s| s != "jsonl").unwrap_or(true) {
            continue;
        }
        let name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let meta = match dirent.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let (message_count, preview) = scan_file_summary(&path);
        entries.push(SessionEntry {
            name,
            path,
            modified,
            message_count,
            preview,
        });
    }
    // Newest first; stable secondary sort by name keeps tests deterministic.
    entries.sort_by(|a, b| {
        b.modified
            .cmp(&a.modified)
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(entries)
}

/// Inspect a JSONL session file: count lines and extract the first
/// user message as a preview. Errors return `(0, None)` — a corrupt
/// or unreadable file still shows up in the list so the operator can
/// delete it.
fn scan_file_summary(path: &Path) -> (usize, Option<String>) {
    let Ok(file) = File::open(path) else {
        return (0, None);
    };
    let mut count = 0usize;
    let mut preview: Option<String> = None;
    for line in BufReader::new(file).lines().map_while(|l| l.ok()) {
        if line.trim().is_empty() {
            continue;
        }
        count += 1;
        if preview.is_some() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(&line) {
            let role = value.get("role").and_then(|v| v.as_str()).unwrap_or("");
            if role == "user" {
                if let Some(text) = value.get("content").and_then(|v| v.as_str()) {
                    preview = Some(truncate_preview(text));
                }
            }
        }
    }
    (count, preview)
}

fn truncate_preview(text: &str) -> String {
    // Collapse whitespace runs into single spaces so multiline
    // prompts render on one row.
    let collapsed: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    const MAX: usize = 80;
    if collapsed.chars().count() <= MAX {
        return collapsed;
    }
    let truncated: String = collapsed.chars().take(MAX - 1).collect();
    format!("{truncated}…")
}

/// Format a `SystemTime` as a short human-readable age string.
///
/// Buckets:
/// - `<N>s ago` if <60s
/// - `<N>m ago` if <60min
/// - `<N>h ago` if <24h
/// - `yesterday` if 24–48h
/// - `<N>d ago` if <7d (weekday-ish bucket; we use day-count for
///   determinism since we don't carry a calendar lib)
/// - `YYYY-MM-DD` otherwise
pub(crate) fn humanise(ts: SystemTime) -> String {
    humanise_relative(ts, SystemTime::now())
}

/// Same as [`humanise`] but with an explicit "now" — testable.
pub(crate) fn humanise_relative(ts: SystemTime, now: SystemTime) -> String {
    let elapsed = now.duration_since(ts).unwrap_or(Duration::ZERO);
    let secs = elapsed.as_secs();
    const MIN: u64 = 60;
    const HOUR: u64 = 60 * MIN;
    const DAY: u64 = 24 * HOUR;

    if secs < MIN {
        return format!("{secs}s ago");
    }
    if secs < HOUR {
        return format!("{}m ago", secs / MIN);
    }
    if secs < DAY {
        return format!("{}h ago", secs / HOUR);
    }
    if secs < 2 * DAY {
        return "yesterday".to_string();
    }
    if secs < 7 * DAY {
        return format!("{}d ago", secs / DAY);
    }
    // Fall back to a calendar-ish YYYY-MM-DD using the UNIX epoch
    // arithmetic. We don't pull chrono, so do an in-house civil-date
    // conversion (Howard Hinnant's algorithm).
    let epoch_secs = ts
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    civil_date_string(epoch_secs)
}

/// Civil date YYYY-MM-DD from a Unix timestamp in seconds. Based on
/// Howard Hinnant's `days_from_civil` inverse — works for any date in
/// [0000-03-01, 9999-12-31].
fn civil_date_string(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}")
}

fn render_picker(frame: &mut Frame<'_>, state: &PickerState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title
            Constraint::Min(3),    // table
            Constraint::Length(1), // hint
        ])
        .split(frame.area());

    render_title(frame, chunks[0]);
    render_table(frame, chunks[1], state);
    render_hint(frame, chunks[2], state);
}

fn render_title(frame: &mut Frame<'_>, area: Rect) {
    let line = Line::from(vec![
        Span::styled(
            " mantis ",
            Style::default().fg(Color::Black).bg(Color::Cyan),
        ),
        Span::raw(" · session picker — "),
        Span::styled(
            "↑↓ navigate, Enter resume, n new, d delete, q quit",
            Style::default().add_modifier(Modifier::DIM),
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_table(frame: &mut Frame<'_>, area: Rect, state: &PickerState) {
    let header = Row::new(vec![
        Cell::from("name"),
        Cell::from("modified"),
        Cell::from("msgs"),
        Cell::from("preview"),
    ])
    .style(
        Style::default()
            .add_modifier(Modifier::BOLD)
            .add_modifier(Modifier::DIM),
    );

    let rows: Vec<Row> = state
        .entries
        .iter()
        .map(|e| {
            Row::new(vec![
                Cell::from(e.name.clone()),
                Cell::from(humanise(e.modified)),
                Cell::from(e.message_count.to_string()),
                Cell::from(e.preview.clone().unwrap_or_default()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(20),
        Constraint::Length(14),
        Constraint::Length(6),
        Constraint::Min(20),
    ];

    let mut table_state = TableState::default();
    table_state.select(Some(state.selected));

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().add_modifier(Modifier::DIM))
                .title(" sessions "),
        )
        .row_highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_stateful_widget(table, area, &mut table_state);
}

fn render_hint(frame: &mut Frame<'_>, area: Rect, state: &PickerState) {
    let line = if state.confirm_delete {
        let name = state
            .selected_entry()
            .map(|e| e.name.as_str())
            .unwrap_or("?");
        Line::from(vec![
            Span::styled(
                format!("delete \"{name}\"? "),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled("y/n", Style::default().add_modifier(Modifier::BOLD)),
        ])
    } else {
        Line::from(Span::styled(
            "↑↓ navigate · Enter resume · n new · d delete · q quit",
            Style::default().add_modifier(Modifier::DIM),
        ))
    };
    frame.render_widget(Paragraph::new(line), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn write_session(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(format!("{name}.jsonl"));
        std::fs::write(&p, body).unwrap();
        p
    }

    fn set_mtime(path: &Path, ts: SystemTime) {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_modified(ts).unwrap();
    }

    #[test]
    fn scan_empty_dir_returns_no_entries() {
        let dir = tempfile::tempdir().unwrap();
        let entries = scan_sessions(dir.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn scan_missing_dir_returns_no_entries() {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("does-not-exist");
        let entries = scan_sessions(&nonexistent).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn scan_lists_jsonl_files_sorted_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let older = write_session(dir.path(), "older", "{\"role\":\"user\",\"content\":\"hi\"}\n");
        let newer = write_session(dir.path(), "newer", "{\"role\":\"user\",\"content\":\"hi\"}\n");
        // Force `older` to be older than `newer` regardless of filesystem
        // mtime resolution.
        let past = SystemTime::now() - Duration::from_secs(120);
        set_mtime(&older, past);
        let recent = SystemTime::now() - Duration::from_secs(1);
        set_mtime(&newer, recent);

        let entries = scan_sessions(dir.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "newer");
        assert_eq!(entries[1].name, "older");
    }

    #[test]
    fn scan_extracts_preview_from_first_user_message() {
        let dir = tempfile::tempdir().unwrap();
        let body = "{\"role\":\"system\",\"content\":\"you are mantis\"}\n\
                    {\"role\":\"user\",\"content\":\"find idor in /api/users\"}\n\
                    {\"role\":\"assistant\",\"content\":\"on it\"}\n";
        write_session(dir.path(), "s1", body);
        let entries = scan_sessions(dir.path()).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.message_count, 3);
        assert_eq!(e.preview.as_deref(), Some("find idor in /api/users"));
    }

    #[test]
    fn scan_skips_non_jsonl_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("notes.txt"), "hello").unwrap();
        write_session(dir.path(), "s1", "{\"role\":\"user\",\"content\":\"x\"}\n");
        let entries = scan_sessions(dir.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "s1");
    }

    #[test]
    fn humanise_seconds_minutes_hours_recent() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        assert_eq!(humanise_relative(now - Duration::from_secs(5), now), "5s ago");
        assert_eq!(humanise_relative(now - Duration::from_secs(120), now), "2m ago");
        assert_eq!(
            humanise_relative(now - Duration::from_secs(3 * 60 * 60), now),
            "3h ago"
        );
        assert_eq!(
            humanise_relative(now - Duration::from_secs(36 * 60 * 60), now),
            "yesterday"
        );
        assert_eq!(
            humanise_relative(now - Duration::from_secs(4 * 24 * 60 * 60), now),
            "4d ago"
        );
    }

    #[test]
    fn humanise_fallback_renders_calendar_date() {
        // 2020-01-15 00:00:00 UTC = 1_579_046_400
        let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(1_579_046_400);
        // "Now" is one year later — well past the 7-day cutoff.
        let now = ts + Duration::from_secs(365 * 24 * 60 * 60);
        assert_eq!(humanise_relative(ts, now), "2020-01-15");
    }

    #[test]
    fn picker_outcome_quit_on_esc() {
        let dir = tempfile::tempdir().unwrap();
        write_session(dir.path(), "s1", "{\"role\":\"user\",\"content\":\"x\"}\n");
        let entries = scan_sessions(dir.path()).unwrap();
        let mut state = PickerState::new(entries);
        let result = step(&mut state, key(KeyCode::Esc));
        assert!(matches!(
            result,
            Some(StepResult::Outcome(PickerOutcome::Quit))
        ));
    }

    #[test]
    fn picker_outcome_quit_on_q() {
        let dir = tempfile::tempdir().unwrap();
        write_session(dir.path(), "s1", "{\"role\":\"user\",\"content\":\"x\"}\n");
        let entries = scan_sessions(dir.path()).unwrap();
        let mut state = PickerState::new(entries);
        let result = step(&mut state, key(KeyCode::Char('q')));
        assert!(matches!(
            result,
            Some(StepResult::Outcome(PickerOutcome::Quit))
        ));
    }

    #[test]
    fn picker_outcome_quit_on_ctrl_c() {
        let dir = tempfile::tempdir().unwrap();
        write_session(dir.path(), "s1", "{\"role\":\"user\",\"content\":\"x\"}\n");
        let entries = scan_sessions(dir.path()).unwrap();
        let mut state = PickerState::new(entries);
        let result = step(
            &mut state,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        );
        assert!(matches!(
            result,
            Some(StepResult::Outcome(PickerOutcome::Quit))
        ));
    }

    #[test]
    fn picker_outcome_resume_on_enter() {
        let dir = tempfile::tempdir().unwrap();
        write_session(dir.path(), "alpha", "{\"role\":\"user\",\"content\":\"x\"}\n");
        write_session(dir.path(), "bravo", "{\"role\":\"user\",\"content\":\"y\"}\n");
        let entries = scan_sessions(dir.path()).unwrap();
        // The default selection is index 0 — whichever has the newer
        // mtime. We just assert the outcome carries one of them.
        let mut state = PickerState::new(entries);
        let result = step(&mut state, key(KeyCode::Enter));
        match result {
            Some(StepResult::Outcome(PickerOutcome::Resume(e))) => {
                assert!(e.name == "alpha" || e.name == "bravo");
            }
            other => panic!("expected Resume outcome, got {other:?}"),
        }
    }

    #[test]
    fn picker_arrows_move_selection() {
        let dir = tempfile::tempdir().unwrap();
        let a = write_session(dir.path(), "a", "{\"role\":\"user\",\"content\":\"x\"}\n");
        let b = write_session(dir.path(), "b", "{\"role\":\"user\",\"content\":\"y\"}\n");
        // Make `a` newer.
        let recent = SystemTime::now();
        let past = SystemTime::now() - Duration::from_secs(120);
        set_mtime(&a, recent);
        set_mtime(&b, past);

        let entries = scan_sessions(dir.path()).unwrap();
        let mut state = PickerState::new(entries);
        assert_eq!(state.selected, 0);
        assert_eq!(state.selected_entry().unwrap().name, "a");

        let result = step(&mut state, key(KeyCode::Down));
        assert!(result.is_none());
        assert_eq!(state.selected, 1);
        assert_eq!(state.selected_entry().unwrap().name, "b");

        // Down at the end is a no-op.
        let result = step(&mut state, key(KeyCode::Down));
        assert!(result.is_none());
        assert_eq!(state.selected, 1);

        let result = step(&mut state, key(KeyCode::Up));
        assert!(result.is_none());
        assert_eq!(state.selected, 0);
    }

    #[test]
    fn picker_n_returns_fresh_session() {
        let dir = tempfile::tempdir().unwrap();
        write_session(dir.path(), "s1", "{\"role\":\"user\",\"content\":\"x\"}\n");
        let entries = scan_sessions(dir.path()).unwrap();
        let mut state = PickerState::new(entries);
        let result = step(&mut state, key(KeyCode::Char('n')));
        assert!(matches!(
            result,
            Some(StepResult::Outcome(PickerOutcome::FreshSession(None)))
        ));
    }

    #[test]
    fn picker_d_prompts_then_y_deletes() {
        let dir = tempfile::tempdir().unwrap();
        write_session(dir.path(), "s1", "{\"role\":\"user\",\"content\":\"x\"}\n");
        let entries = scan_sessions(dir.path()).unwrap();
        let mut state = PickerState::new(entries);

        // First press toggles confirm prompt.
        let r1 = step(&mut state, key(KeyCode::Char('d')));
        assert!(r1.is_none());
        assert!(state.confirm_delete);

        // 'n' cancels.
        let r2 = step(&mut state, key(KeyCode::Char('n')));
        assert!(r2.is_none());
        assert!(!state.confirm_delete);

        // Re-arm and confirm with 'y'.
        let _ = step(&mut state, key(KeyCode::Char('d')));
        assert!(state.confirm_delete);
        let r3 = step(&mut state, key(KeyCode::Char('y')));
        assert!(matches!(r3, Some(StepResult::DeleteSelected)));
        assert!(!state.confirm_delete);
    }

    #[test]
    fn truncate_preview_handles_long_input() {
        let long: String = "a".repeat(200);
        let out = truncate_preview(&long);
        let count = out.chars().count();
        assert!(count <= 80);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn truncate_preview_collapses_whitespace() {
        let out = truncate_preview("hello\n\n  world\t\there");
        assert_eq!(out, "hello world here");
    }
}
