//! Interactive Claude-model picker for the `mantis` CLI.
//!
//! `mantis model` opens a Tab / Shift+Tab cycler that mirrors the
//! Claude Code picker UX:
//!
//!   ↑ / Shift+Tab   move selection up
//!   ↓ / Tab         move selection down
//!   Enter           confirm — persist to ~/.Mantis/model
//!   Esc / q         cancel — preference unchanged
//!
//! The chosen model is written as a single-line UTF-8 file at
//! `~/.Mantis/model`. `mantis hack` reads that file at startup and
//! prepends `--model <id>` to the `claude --print` invocation unless
//! the user explicitly passed `-- --model …` themselves.

use anyhow::{Context, Result};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{self, ClearType},
};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

/// One Claude model the picker can offer.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClaudeModel {
    /// The `--model` value passed to the `claude` CLI.
    pub id: &'static str,
    /// Short human label (e.g. "Opus 4.7").
    pub label: &'static str,
    /// Family hint (Opus / Sonnet / Haiku / Auto) shown beside the label.
    pub family: &'static str,
    /// One-line "when to use" hint.
    pub blurb: &'static str,
}

/// Models offered by the picker. Order is the cycle order: Tab moves
/// down, Shift+Tab moves up. "Auto" first so it's the default
/// selection on a fresh `mantis model` call.
pub(crate) const MODELS: &[ClaudeModel] = &[
    ClaudeModel {
        id: "",
        label: "Auto",
        family: "default",
        blurb: "Let Claude Code pick (uses its own default — usually the latest Sonnet).",
    },
    ClaudeModel {
        id: "claude-opus-4-7",
        label: "Opus 4.7",
        family: "Opus",
        blurb: "Strongest reasoning. Best for architecture, deep multi-step engagements.",
    },
    ClaudeModel {
        id: "claude-sonnet-4-6",
        label: "Sonnet 4.6",
        family: "Sonnet",
        blurb: "Balanced quality + speed. Good default for most hunts.",
    },
    ClaudeModel {
        id: "claude-haiku-4-5-20251001",
        label: "Haiku 4.5",
        family: "Haiku",
        blurb: "Fast + cheap. Good for quick scans and dry runs.",
    },
];

/// Return the path `~/.Mantis/model`.
fn model_file() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join(".Mantis").join("model"))
}

/// Read the currently-persisted model id, or `None` if no preference
/// is set / file unreadable / file empty.
pub(crate) fn load_saved() -> Option<String> {
    let path = model_file().ok()?;
    let raw = std::fs::read_to_string(path).ok()?;
    let id = raw.trim();
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

/// Persist a model id (writes `~/.Mantis/model`, creating
/// `~/.Mantis/` if needed). An empty `id` clears the preference by
/// removing the file.
pub(crate) fn save(id: &str) -> Result<()> {
    let path = model_file()?;
    if id.is_empty() {
        // Clear: silently no-op if file doesn't exist.
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("rm {}", path.display()))?;
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    std::fs::write(&path, format!("{}\n", id))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Find a model in `MODELS` by id (`""` matches "Auto"). Returns
/// `None` for unknown ids (e.g. a custom user-set string).
pub(crate) fn find_by_id(id: &str) -> Option<&'static ClaudeModel> {
    MODELS.iter().find(|m| m.id == id)
}

/// Index in `MODELS` of the currently-saved model. Defaults to 0
/// ("Auto") when no preference is set.
fn current_index() -> usize {
    match load_saved() {
        Some(id) => MODELS.iter().position(|m| m.id == id).unwrap_or(0),
        None => 0,
    }
}

/// Run the interactive Tab / Shift+Tab picker. Returns the selected
/// `ClaudeModel` on Enter, or `None` on Esc / Ctrl+C / `q`.
///
/// Falls back gracefully when stdout/stdin aren't a TTY: prints a
/// numbered list and reads one line. Useful in SSH-less / piped
/// environments where raw mode would otherwise garble the terminal.
pub(crate) fn pick_interactive() -> Result<Option<&'static ClaudeModel>> {
    if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        return pick_non_tty();
    }
    pick_tty()
}

fn pick_non_tty() -> Result<Option<&'static ClaudeModel>> {
    println!("Pick a Claude model for `mantis hack`:");
    println!();
    for (i, m) in MODELS.iter().enumerate() {
        let id = if m.id.is_empty() { "(auto)" } else { m.id };
        println!("  {})  {:<12} {:<8} {}", i + 1, m.label, m.family, id);
    }
    println!();
    print!("Number [1-{}], or blank to cancel: ", MODELS.len());
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line).context("read selection")?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let n: usize = trimmed.parse().context("parse selection")?;
    if n == 0 || n > MODELS.len() {
        anyhow::bail!("selection {n} is out of range (1-{})", MODELS.len());
    }
    Ok(Some(&MODELS[n - 1]))
}

fn pick_tty() -> Result<Option<&'static ClaudeModel>> {
    let mut selected = current_index();
    let mut stdout = io::stdout();

    terminal::enable_raw_mode().context("enable raw mode")?;
    execute!(stdout, cursor::Hide).ok();

    // Reserve vertical space: header + blank + one row per model +
    // blank + footer hint = MODELS.len() + 4 lines.
    let total_rows = MODELS.len() + 4;
    for _ in 0..total_rows {
        println!();
    }
    execute!(stdout, cursor::MoveUp(total_rows as u16)).ok();

    let result = run_picker_loop(&mut stdout, &mut selected, total_rows);

    execute!(stdout, cursor::Show).ok();
    terminal::disable_raw_mode().ok();
    // Move past the picker region so subsequent output doesn't
    // overwrite it.
    execute!(stdout, cursor::MoveDown(total_rows as u16)).ok();
    println!();

    result.map(|confirmed| {
        if confirmed {
            Some(&MODELS[selected])
        } else {
            None
        }
    })
}

/// The actual key loop. Returns `Ok(true)` if the user pressed Enter,
/// `Ok(false)` on Esc / Ctrl+C / `q`.
fn run_picker_loop<W: Write>(
    stdout: &mut W,
    selected: &mut usize,
    total_rows: usize,
) -> Result<bool> {
    loop {
        render(stdout, *selected, total_rows)?;

        let ev = event::read().context("read terminal event")?;
        let key = match ev {
            Event::Key(k) if matches!(k.kind, KeyEventKind::Press | KeyEventKind::Repeat) => k,
            _ => continue,
        };

        match classify(key) {
            PickerAction::Up => {
                if *selected == 0 {
                    *selected = MODELS.len() - 1;
                } else {
                    *selected -= 1;
                }
            }
            PickerAction::Down => {
                *selected = (*selected + 1) % MODELS.len();
            }
            PickerAction::Jump(i) if i < MODELS.len() => {
                *selected = i;
            }
            PickerAction::Jump(_) => {}
            PickerAction::Confirm => return Ok(true),
            PickerAction::Cancel => return Ok(false),
            PickerAction::Ignore => {}
        }
    }
}

enum PickerAction {
    Up,
    Down,
    Jump(usize),
    Confirm,
    Cancel,
    Ignore,
}

fn classify(key: KeyEvent) -> PickerAction {
    // Shift+Tab arrives as either `BackTab` or `Tab` with SHIFT.
    if matches!(key.code, KeyCode::BackTab) {
        return PickerAction::Up;
    }
    if matches!(key.code, KeyCode::Tab) && key.modifiers.contains(KeyModifiers::SHIFT) {
        return PickerAction::Up;
    }
    if matches!(key.code, KeyCode::Tab) {
        return PickerAction::Down;
    }
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => PickerAction::Up,
        KeyCode::Down | KeyCode::Char('j') => PickerAction::Down,
        KeyCode::Enter => PickerAction::Confirm,
        KeyCode::Esc => PickerAction::Cancel,
        KeyCode::Char('q') => PickerAction::Cancel,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => PickerAction::Cancel,
        KeyCode::Char(c) if c.is_ascii_digit() => {
            let n = (c as u8 - b'0') as usize;
            if n == 0 {
                PickerAction::Ignore
            } else {
                PickerAction::Jump(n - 1)
            }
        }
        _ => PickerAction::Ignore,
    }
}

fn render<W: Write>(stdout: &mut W, selected: usize, total_rows: usize) -> Result<()> {
    // Wipe the picker region, then redraw from the top of it.
    for _ in 0..total_rows {
        queue!(
            stdout,
            terminal::Clear(ClearType::CurrentLine),
            cursor::MoveDown(1)
        )?;
    }
    queue!(stdout, cursor::MoveUp(total_rows as u16))?;
    // Column 0, in case the previous line left the cursor mid-row.
    queue!(stdout, cursor::MoveToColumn(0))?;

    queue!(
        stdout,
        SetForegroundColor(Color::Cyan),
        Print("  pick a Claude model for `mantis hack`"),
        ResetColor,
        Print("  "),
        SetForegroundColor(Color::DarkGrey),
        Print("(Tab / Shift+Tab to cycle · Enter to confirm · Esc to cancel)"),
        ResetColor,
        Print("\r\n\r\n"),
    )?;

    for (i, m) in MODELS.iter().enumerate() {
        let active = i == selected;
        let marker = if active { "❯" } else { " " };
        let color = if active { Color::Green } else { Color::Reset };
        let dim = if active {
            Color::White
        } else {
            Color::DarkGrey
        };

        queue!(
            stdout,
            SetForegroundColor(color),
            Print(format!("  {marker} ")),
            Print(format!("{:<12}", m.label)),
            ResetColor,
            SetForegroundColor(dim),
            Print(format!(" {:<8}  ", m.family)),
            Print(m.blurb),
            ResetColor,
            Print("\r\n"),
        )?;
    }

    queue!(
        stdout,
        Print("\r\n"),
        SetForegroundColor(Color::DarkGrey),
        Print(format!("  current: {}", saved_label())),
        ResetColor,
        Print("\r\n"),
    )?;
    stdout.flush()?;

    // Park cursor back at the top of the picker so the next render
    // starts from the same anchor row.
    execute!(stdout, cursor::MoveUp(total_rows as u16))?;
    Ok(())
}

fn saved_label() -> String {
    match load_saved() {
        None => "(none — claude default applies)".to_string(),
        Some(id) => match find_by_id(&id) {
            Some(m) => format!(
                "{} ({})",
                m.label,
                if m.id.is_empty() { "auto" } else { m.id }
            ),
            None => format!("{} (custom)", id),
        },
    }
}

/// Print the current preference (used by `mantis model show`).
pub(crate) fn print_show() {
    println!("model preference: {}", saved_label());
    if let Ok(path) = model_file() {
        println!("file:             {}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_by_id_matches_each_model() {
        for m in MODELS {
            let found = find_by_id(m.id).expect("model present");
            assert_eq!(found.id, m.id);
        }
    }

    #[test]
    fn find_by_id_returns_none_for_unknown() {
        assert!(find_by_id("does-not-exist").is_none());
    }

    #[test]
    fn classify_shift_tab_via_backtab_is_up() {
        let k = KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE);
        assert!(matches!(classify(k), PickerAction::Up));
    }

    #[test]
    fn classify_shift_tab_via_modifier_is_up() {
        let k = KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT);
        assert!(matches!(classify(k), PickerAction::Up));
    }

    #[test]
    fn classify_tab_is_down() {
        let k = KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE);
        assert!(matches!(classify(k), PickerAction::Down));
    }

    #[test]
    fn classify_enter_confirms() {
        let k = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        assert!(matches!(classify(k), PickerAction::Confirm));
    }

    #[test]
    fn classify_esc_and_q_and_ctrl_c_cancel() {
        for k in [
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        ] {
            assert!(matches!(classify(k), PickerAction::Cancel));
        }
    }

    #[test]
    fn classify_digit_jumps_to_index() {
        let k = KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE);
        match classify(k) {
            PickerAction::Jump(1) => {}
            _ => panic!("expected Jump(1)"),
        }
    }
}
