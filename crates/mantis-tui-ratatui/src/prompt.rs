//! Claude-Code-style prompt TUI for `mantis` (no-args default).
//!
//! Layout (matches the Claude Code screenshot the user referenced):
//!
//! ```text
//!   ▲▼   Mantis vX.Y.Z
//!   ⟨⟩   <provider label> · <model> · ethical hacking
//!        <cwd>
//!
//!  ┌────────────────────────────────────────────────────────────────┐
//!  │ <output stream from the spawned AI CLI>                        │
//!  │                                                                │
//!  └────────────────────────────────────────────────────────────────┘
//!  ›  <input prompt, blinking cursor>
//!
//!  <provider> | <cwd-basename> | <engagement?> | <target?>           xhigh ·
//!  ▶▶ ethical hacking only (shift+tab to cycle provider) · ← agents
//! ```
//!
//! Keybinds:
//! - Enter           → submit the current prompt buffer; spawn the
//!                     selected provider's CLI in `-p` mode and stream
//!                     stdout into the output pane.
//! - Tab / Shift+Tab → cycle the active provider through installed
//!                     CLIs (claude, codex, opencode, gemini).
//! - Backspace       → delete one char from the prompt buffer.
//! - Ctrl-C / Esc    → quit.
//!
//! The prompt is wrapped with a Mantis-context system message so the
//! spawned CLI knows it's being invoked from an offensive-security
//! tool with operator-confirmed authorization.

use std::io;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
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
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;

const MASCOT: &[&str] = &[
    "    /\\_/\\  ",
    "   ( ^.^ ) ",
    "    > ^ <  ",
];

const PROVIDERS: &[&str] = &["claude", "codex", "opencode", "gemini"];

const ETHICAL_DISCLAIMER: &str =
    "ethical hacking with authorization only · mantis enforces scope at the egress proxy";

/// Entry point. Initializes the terminal, runs the event loop, and
/// restores the terminal state on exit (even on panic).
pub async fn run() -> Result<()> {
    // Detect which providers are actually on PATH, so Tab only cycles
    // through installed ones.
    let providers = detected_providers();
    if providers.is_empty() {
        eprintln!(
            "mantis tui: no supported AI CLI on PATH. Install one of: \
             {} — then re-run `mantis`.",
            PROVIDERS.join(", ")
        );
        std::process::exit(1);
    }

    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).context("enter alt screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    let mut app = App::new(providers);
    let result = run_app(&mut terminal, &mut app).await;

    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .ok();
    terminal.show_cursor().ok();

    result
}

#[derive(Debug, Clone)]
struct App {
    prompt: String,
    output_lines: Arc<Mutex<Vec<String>>>,
    providers: Vec<String>,
    active_provider_idx: usize,
    busy: bool,
    quit: bool,
    cwd_label: String,
}

impl App {
    fn new(providers: Vec<String>) -> Self {
        let cwd_label = std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "?".into());
        Self {
            prompt: String::new(),
            output_lines: Arc::new(Mutex::new(welcome_lines())),
            providers,
            active_provider_idx: 0,
            busy: false,
            quit: false,
            cwd_label,
        }
    }

    fn active_provider(&self) -> &str {
        &self.providers[self.active_provider_idx]
    }

    fn cycle_provider(&mut self, forward: bool) {
        let len = self.providers.len();
        if forward {
            self.active_provider_idx = (self.active_provider_idx + 1) % len;
        } else {
            self.active_provider_idx = (self.active_provider_idx + len - 1) % len;
        }
    }
}

fn welcome_lines() -> Vec<String> {
    vec![
        String::new(),
        "  Mantis — offensive-security agent runner".into(),
        "  Type a request and press Enter.".into(),
        "  Examples:".into(),
        "    hack deonmenezes.com".into(),
        "    scan https://api.example.com for IDOR".into(),
        "    write a recon plan for app.example.com".into(),
        String::new(),
        "  Tab / Shift+Tab cycles AI providers. Ctrl-C exits.".into(),
        String::new(),
    ]
}

fn detected_providers() -> Vec<String> {
    PROVIDERS
        .iter()
        .filter(|&&name| which_bin(name).is_some())
        .map(|s| s.to_string())
        .collect()
}

fn which_bin(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    let tick = Duration::from_millis(50);
    loop {
        terminal.draw(|f| draw(f, app))?;
        if app.quit {
            return Ok(());
        }
        if event::poll(tick)? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    handle_key(k, app).await;
                }
            }
        }
    }
}

async fn handle_key(k: KeyEvent, app: &mut App) {
    // Ctrl-C / Esc → quit
    if (k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c'))
        || k.code == KeyCode::Esc
    {
        app.quit = true;
        return;
    }
    // Don't accept new prompts while a previous one is still streaming.
    if app.busy {
        return;
    }
    match k.code {
        KeyCode::Enter => {
            let prompt = app.prompt.trim().to_string();
            if prompt.is_empty() {
                return;
            }
            app.prompt.clear();
            let provider = app.active_provider().to_string();
            let sink = app.output_lines.clone();
            app.busy = true;
            // Append an echo of the user's prompt to the output buffer.
            {
                let mut lines = sink.lock().await;
                lines.push(String::new());
                lines.push(format!("› {prompt}"));
                lines.push(format!("  ↳ spawning `{provider} -p ...`"));
            }
            // Spawn the provider as a child process. The tokio task
            // hooks the stdout pipe and appends each line to the
            // shared output buffer; the UI tick (50ms) picks them up.
            // `App` itself is not Send across .await for the long
            // task, so we capture by value.
            let busy_flag = Arc::clone(&sink);
            tokio::spawn(async move {
                let res = stream_provider(&provider, &prompt, &sink).await;
                let mut lines = busy_flag.lock().await;
                match res {
                    Ok(code) => {
                        lines.push(format!("  ↳ done (exit {code})"));
                    }
                    Err(e) => {
                        lines.push(format!("  ↳ error: {e}"));
                    }
                }
                lines.push(String::new());
            });
            // Mark not-busy immediately so the UI accepts the next
            // prompt; the streaming task keeps appending to the
            // output buffer independently.
            app.busy = false;
        }
        KeyCode::Tab => app.cycle_provider(true),
        KeyCode::BackTab => app.cycle_provider(false),
        KeyCode::Backspace => {
            app.prompt.pop();
        }
        KeyCode::Char(c) => app.prompt.push(c),
        _ => {}
    }
}

/// Build the system-context preamble that gets prepended to every
/// user prompt. Tells the spawned AI CLI it's being invoked from
/// Mantis, the operator has confirmed ethical use, and Mantis-side
/// MCP tools / scope enforcement are available.
fn build_full_prompt(user_prompt: &str) -> String {
    format!(
        "You are being invoked from the Mantis TUI for AUTHORIZED \
         offensive-security work. The operator has confirmed ethical \
         use (testing only systems they own or have written \
         authorization to test). When the user asks you to hack / \
         scan / recon a target, drive the engagement through the \
         `mantis` MCP server's tools and Task spawns — do not shell \
         out to `mantis hack` (you ARE the AI that mantis hack \
         invokes; calling it would recurse). For non-target requests \
         (planning, explaining concepts), just answer normally.\n\n\
         User: {user_prompt}"
    )
}

/// Spawn `<provider> -p "<prompt>"` and stream its stdout lines into
/// the shared output buffer. Returns the child's exit status code.
async fn stream_provider(
    provider: &str,
    user_prompt: &str,
    sink: &Arc<Mutex<Vec<String>>>,
) -> Result<i32> {
    let full = build_full_prompt(user_prompt);
    // Per-provider invocation. All four CLIs honor `-p`/`--print` for
    // non-interactive mode, but their permission flags differ.
    let mut cmd = Command::new(provider);
    match provider {
        "claude" => {
            cmd.arg("--print")
                .arg("--dangerously-skip-permissions")
                .arg(&full);
        }
        "codex" | "opencode" | "gemini" => {
            cmd.arg("-p").arg(&full);
        }
        other => {
            anyhow::bail!("unknown provider `{other}`");
        }
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {provider}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("{provider} child has no stdout"))?;
    let mut lines = BufReader::new(stdout).lines();
    while let Some(line) = lines.next_line().await? {
        let mut buf = sink.lock().await;
        buf.push(line);
    }
    let status = child.wait().await?;
    Ok(status.code().unwrap_or(0))
}

// --- Rendering ---------------------------------------------------------

fn draw(f: &mut Frame<'_>, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // header (mascot + title)
            Constraint::Min(5),     // output pane
            Constraint::Length(3),  // input box
            Constraint::Length(2),  // status bar
        ])
        .split(f.area());

    draw_header(f, outer[0]);
    draw_output(f, outer[1], app);
    draw_input(f, outer[2], app);
    draw_status(f, outer[3], app);
}

fn draw_header(f: &mut Frame<'_>, area: Rect) {
    let mantis_green = Style::default()
        .fg(Color::Rgb(130, 240, 180))
        .add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(Color::Gray);
    let mut lines: Vec<Line<'_>> = MASCOT
        .iter()
        .map(|s| Line::from(Span::styled((*s).to_string(), mantis_green)))
        .collect();
    // Adjust: append title + tagline to the right of the art.
    let title = Line::from(vec![
        Span::styled(
            "  Mantis  ",
            Style::default()
                .fg(Color::Rgb(130, 240, 180))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(env!("CARGO_PKG_VERSION"), dim),
    ]);
    let tagline = Line::from(vec![
        Span::styled("  ", dim),
        Span::styled(
            ETHICAL_DISCLAIMER,
            Style::default().fg(Color::Rgb(160, 160, 180)),
        ),
    ]);
    lines.push(title);
    lines.push(tagline);
    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn draw_output(f: &mut Frame<'_>, area: Rect, app: &App) {
    // Snapshot the shared buffer once per frame (no .await — we use
    // blocking_lock since draw is sync).
    let snapshot: Vec<String> = match app.output_lines.try_lock() {
        Ok(g) => g.clone(),
        Err(_) => vec!["...".into()],
    };
    // Show only the tail that fits in the pane.
    let inner_h = area.height.saturating_sub(2) as usize;
    let start = snapshot.len().saturating_sub(inner_h);
    let visible: Vec<Line<'_>> = snapshot[start..]
        .iter()
        .map(|s| Line::from(s.clone()))
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " output ",
            Style::default().fg(Color::Rgb(130, 240, 180)),
        ));
    let p = Paragraph::new(visible).block(block).wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn draw_input(f: &mut Frame<'_>, area: Rect, app: &App) {
    let title = format!(" › {} ", app.active_provider());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(130, 240, 180)))
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::Rgb(130, 240, 180))
                .add_modifier(Modifier::BOLD),
        ));
    let cursor = if app.busy { " …" } else { "▌" };
    let body = Line::from(vec![
        Span::styled(app.prompt.clone(), Style::default().fg(Color::White)),
        Span::styled(
            cursor.to_string(),
            Style::default()
                .fg(Color::Rgb(130, 240, 180))
                .add_modifier(Modifier::SLOW_BLINK),
        ),
    ]);
    let p = Paragraph::new(body).block(block);
    f.render_widget(p, area);
}

fn draw_status(f: &mut Frame<'_>, area: Rect, app: &App) {
    let dim = Style::default().fg(Color::Rgb(140, 140, 160));
    let red = Style::default().fg(Color::Rgb(220, 90, 90));
    let line1 = Line::from(vec![
        Span::styled(app.active_provider().to_string(), Style::default().fg(Color::Rgb(130, 240, 180))),
        Span::styled("  ·  ", dim),
        Span::styled(app.cwd_label.clone(), dim),
        Span::styled("  ·  ", dim),
        Span::styled(
            format!("{} CLI{}", app.providers.len(), if app.providers.len() == 1 { "" } else { "s" }),
            dim,
        ),
    ]);
    let line2 = Line::from(vec![
        Span::styled("▶▶ ", red),
        Span::styled(ETHICAL_DISCLAIMER, dim),
        Span::styled("   (Tab cycles · Ctrl-C exits)", dim),
    ]);
    let p = Paragraph::new(vec![line1, line2]);
    f.render_widget(p, area);
}
