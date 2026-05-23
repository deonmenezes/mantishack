//! Layout + render functions. Pure: given state, produce ratatui
//! frames. No I/O, no event handling — the event loop lives in
//! [`crate::app`].

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::messages::{LogEntry, MessageLog};

/// Visual configuration the renderer reads on every frame. Owned by
/// [`crate::app::App`] and updated as the chat state changes.
#[derive(Debug, Clone)]
pub struct ViewModel<'a> {
    pub provider: &'a str,
    pub model: &'a str,
    pub session: &'a str,
    pub last_turn_ms: Option<u64>,
    pub log: &'a MessageLog,
    pub input_buffer: &'a str,
    pub input_cursor: usize,
    pub streaming: bool,
    pub footer_hint: &'a str,
    /// Slash-command suggestions to render above the input box. Each
    /// entry is `(command_name, description)`. When empty, the
    /// dropdown is not drawn. The first entry is the row Tab will
    /// accept.
    pub slash_suggestions: &'a [(&'static str, &'static str)],
}

/// Three-pane vertical layout: status bar (1 row), message log
/// (fills), input box (3 rows). The input box gets at least 3 rows
/// so multiline editing has room without the bottom-most line being
/// cramped against the terminal edge.
fn compute_layout(area: Rect) -> [Rect; 3] {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(5),
        ])
        .split(area);
    [chunks[0], chunks[1], chunks[2]]
}

pub fn render(frame: &mut Frame<'_>, vm: &ViewModel<'_>) {
    let [status, log, input] = compute_layout(frame.area());
    render_status_bar(frame, status, vm);
    render_message_log(frame, log, vm);
    render_input_box(frame, input, vm);
}

fn render_status_bar(frame: &mut Frame<'_>, area: Rect, vm: &ViewModel<'_>) {
    let mut spans = vec![
        Span::styled(
            " mantis ",
            Style::default().fg(Color::Black).bg(Color::Cyan),
        ),
        Span::raw(" "),
        Span::styled(vm.provider, Style::default().fg(Color::Cyan)),
        Span::raw("/"),
        Span::raw(vm.model),
        Span::raw("  "),
        Span::styled("session=", Style::default().add_modifier(Modifier::DIM)),
        Span::raw(vm.session),
    ];
    if let Some(ms) = vm.last_turn_ms {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("⏱ {ms}ms"),
            Style::default().add_modifier(Modifier::DIM),
        ));
    }
    if vm.streaming {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            "● streaming",
            Style::default().fg(Color::Yellow),
        ));
    }
    let line = Line::from(spans);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_message_log(frame: &mut Frame<'_>, area: Rect, vm: &ViewModel<'_>) {
    // For the scaffold, we render entries as plain styled paragraphs.
    // The markdown renderer (task #13) will replace `LogEntry::Assistant`
    // formatting with a richer pulldown-cmark-based pass.
    let mut lines: Vec<Line> = Vec::new();
    for entry in vm.log.entries() {
        match entry {
            LogEntry::User(text) => {
                lines.push(Line::from(vec![
                    Span::styled(
                        "you ❯ ",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(text.clone()),
                ]));
            }
            LogEntry::Assistant(text) => {
                lines.push(Line::from(Span::styled(
                    "mantis ❯ ",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )));
                for md_line in crate::widgets::markdown::render(text) {
                    let mut spans: Vec<Span<'static>> = Vec::with_capacity(md_line.spans.len() + 1);
                    spans.push(Span::raw("  "));
                    spans.extend(md_line.spans);
                    lines.push(Line::from(spans));
                }
            }
            LogEntry::ToolInvocation(call) => {
                let args = serde_json::to_string(&call.arguments).unwrap_or_default();
                lines.push(Line::from(Span::styled(
                    format!("  ▸ {}({})", call.name, args),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::DIM),
                )));
            }
            LogEntry::ToolResult { content, .. } => {
                let preview = first_lines(content, 6);
                lines.push(Line::from(Span::styled(
                    format!("  ◂ {preview}"),
                    Style::default().add_modifier(Modifier::DIM),
                )));
            }
            LogEntry::SystemNote(text) => {
                lines.push(Line::from(Span::styled(
                    format!("· {text}"),
                    Style::default()
                        .add_modifier(Modifier::DIM)
                        .add_modifier(Modifier::ITALIC),
                )));
            }
            LogEntry::TurnEnd => {
                lines.push(Line::raw(""));
            }
        }
    }

    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().add_modifier(Modifier::DIM));

    // Auto-scroll: show the tail by computing how many lines fit and
    // skipping the prefix. Wraps complicate exact line accounting; we
    // approximate by area.height — 2 (top border + safety margin)
    // and trust ratatui's wrap to handle the rest.
    let visible = area.height.saturating_sub(2) as usize;
    let skip = lines.len().saturating_sub(visible);
    let visible_lines = lines.into_iter().skip(skip).collect::<Vec<_>>();

    let paragraph = Paragraph::new(visible_lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn render_input_box(frame: &mut Frame<'_>, area: Rect, vm: &ViewModel<'_>) {
    let title = if vm.streaming {
        " (waiting on response…) "
    } else {
        " message — Enter to send, Shift+Enter for newline, /help, /quit "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().add_modifier(Modifier::DIM))
        .title(title);
    let body = Paragraph::new(vm.input_buffer.to_string())
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(body, area);

    if !vm.slash_suggestions.is_empty() && !vm.streaming {
        render_slash_dropdown(frame, area, vm.slash_suggestions);
    }

    if !vm.streaming {
        // Position the terminal cursor inside the input box. Crude
        // single-line approximation — task #14 (multiline input) will
        // upgrade this with proper line-wrapping cursor math.
        let inner_x = area.x + 1 + (vm.input_cursor as u16).min(area.width.saturating_sub(2));
        let inner_y = area.y + 1;
        frame.set_cursor_position((inner_x, inner_y));
    }

    if !vm.footer_hint.is_empty() && area.height >= 5 {
        let hint_y = area.y + area.height.saturating_sub(1);
        let hint_rect = Rect {
            x: area.x + 1,
            y: hint_y,
            width: area.width.saturating_sub(2),
            height: 1,
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                vm.footer_hint,
                Style::default().add_modifier(Modifier::DIM),
            ))),
            hint_rect,
        );
    }
}

/// Draw the slash-command autocomplete dropdown above the input box.
///
/// Caps at 6 rows and at whatever fits between the top of the
/// terminal (row 0) and the top of the input box. The first row is
/// highlighted because that's the entry Tab will accept.
fn render_slash_dropdown(
    frame: &mut Frame<'_>,
    input_area: Rect,
    suggestions: &[(&'static str, &'static str)],
) {
    const MAX_ROWS: usize = 6;
    // Block has its own top + bottom border so 2 rows go to chrome,
    // plus one row per visible suggestion.
    let want_rows = suggestions.len().min(MAX_ROWS);
    if want_rows == 0 {
        return;
    }
    let available = input_area.y as usize;
    if available < 3 {
        // Need room for at least one row plus top + bottom borders.
        return;
    }
    let rows = want_rows.min(available.saturating_sub(2));
    if rows == 0 {
        return;
    }
    let height = (rows + 2) as u16;
    let dropdown_area = Rect {
        x: input_area.x,
        y: input_area.y.saturating_sub(height),
        width: input_area.width,
        height,
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().add_modifier(Modifier::DIM))
        .title(" /commands — Tab to accept ");

    let lines: Vec<Line> = suggestions
        .iter()
        .take(rows)
        .enumerate()
        .map(|(i, (name, desc))| {
            let name_style = if i == 0 {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Cyan)
            };
            let desc_style = Style::default().add_modifier(Modifier::DIM);
            Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("/{name}"), name_style),
                Span::raw("  "),
                Span::styled(desc.to_string(), desc_style),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, dropdown_area);
}

fn first_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().take(n).collect();
    let joined = lines.join(" ⏎ ");
    if joined.len() > 240 {
        format!("{}…", &joined[..240])
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn vm_for<'a>(log: &'a MessageLog, input: &'a str) -> ViewModel<'a> {
        ViewModel {
            provider: "anthropic",
            model: "claude-opus-4-7",
            session: "default",
            last_turn_ms: Some(312),
            log,
            input_buffer: input,
            input_cursor: input.len(),
            streaming: false,
            footer_hint: "",
            slash_suggestions: &[],
        }
    }

    #[test]
    fn renders_without_panicking_on_empty_log() {
        let log = MessageLog::new();
        let vm = vm_for(&log, "");
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &vm)).unwrap();
    }

    #[test]
    fn renders_user_and_assistant_entries() {
        let mut log = MessageLog::new();
        log.push(LogEntry::User("hello".into()));
        log.push(LogEntry::Assistant("hi there".into()));
        log.push(LogEntry::TurnEnd);
        let vm = vm_for(&log, "next msg");

        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &vm)).unwrap();

        // Snapshot the buffer and verify our key strings appear.
        let buf = terminal.backend().buffer();
        let dump: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            dump.contains("hello"),
            "rendered buffer missing user text: {dump}"
        );
        assert!(dump.contains("hi there"));
        assert!(dump.contains("anthropic"));
    }

    #[test]
    fn streaming_status_shown_in_status_bar() {
        let log = MessageLog::new();
        let mut vm = vm_for(&log, "");
        vm.streaming = true;
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &vm)).unwrap();
        let buf = terminal.backend().buffer();
        let dump: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(dump.contains("streaming"));
    }
}
