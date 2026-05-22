//! Render markdown to ratatui Lines with syntax-highlighted code
//! fences. Built on pulldown-cmark for parsing and syntect for
//! language detection + tokenization.

use std::sync::OnceLock;

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use syntect::easy::HighlightLines;
use syntect::highlighting::{Style as SyntStyle, ThemeSet};
use syntect::parsing::SyntaxSet;
use syntect::util::LinesWithEndings;

/// Render `markdown` into a sequence of styled lines suitable for
/// embedding in a `Paragraph`. The output is line-oriented — wrap
/// the resulting `Vec<Line<'static>>` in a ratatui `Paragraph` and
/// it will reflow naturally on terminal resize.
pub fn render(markdown: &str) -> Vec<Line<'static>> {
    let mut renderer = Renderer::default();
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    for event in Parser::new_ext(markdown, options) {
        renderer.handle(event);
    }
    renderer.finish();
    renderer.lines
}

fn assets() -> &'static (SyntaxSet, ThemeSet) {
    static ASSETS: OnceLock<(SyntaxSet, ThemeSet)> = OnceLock::new();
    ASSETS.get_or_init(|| {
        let syntax_set = SyntaxSet::load_defaults_newlines();
        let theme_set = ThemeSet::load_defaults();
        (syntax_set, theme_set)
    })
}

#[derive(Default)]
struct Renderer {
    lines: Vec<Line<'static>>,
    /// Spans accumulated for the current line being built.
    buffer: Vec<Span<'static>>,
    /// Stack of inline modifiers (bold / italic / inline code).
    /// We track them with a small set of bools because pulldown-cmark
    /// can nest e.g. `**_both_**` and the spans need to inherit both.
    bold: u32,
    italic: u32,
    strike: u32,
    /// Stack of list contexts. Each entry is `Some(n)` for an ordered
    /// list starting at `n`, or `None` for a bulleted list.
    list_stack: Vec<ListContext>,
    /// Pending list-item marker (e.g. `"  • "` or `"  1. "`) that will
    /// be flushed as the first span of the next textual content.
    pending_marker: Option<Span<'static>>,
    /// `Some(lang)` while inside a fenced code block. `lang` may be
    /// empty when no language was specified on the fence.
    code_block_lang: Option<String>,
    /// Source text accumulated for the in-progress code block.
    code_block_src: String,
    /// True when we're inside a blockquote — every line that is flushed
    /// gets prefixed with the cyan `│ ` marker and dimmed.
    in_block_quote: u32,
    /// Heading level if currently inside a heading.
    heading_level: Option<HeadingLevel>,
    /// True when the next emitted text should start a new logical line
    /// (paragraph start, list item, etc.).
    paragraph_just_ended: bool,
}

#[derive(Debug, Clone, Copy)]
enum ListContext {
    Bullet,
    Ordered(u64),
}

impl Renderer {
    fn handle(&mut self, event: Event<'_>) {
        match event {
            Event::Start(tag) => self.start(tag),
            Event::End(tag) => self.end(tag),
            Event::Text(text) => self.on_text(text.as_ref()),
            Event::Code(text) => self.on_inline_code(text.as_ref()),
            Event::Html(html) | Event::InlineHtml(html) => {
                // Render raw HTML literally — TUIs can't render it
                // anyway. Dim it so it's clearly inert.
                self.push_span(Span::styled(
                    html.into_string(),
                    Style::default().add_modifier(Modifier::DIM),
                ));
            }
            Event::SoftBreak => {
                self.push_span(Span::raw(" "));
            }
            Event::HardBreak => {
                self.flush_line();
            }
            Event::Rule => {
                self.flush_line();
                self.lines.push(Line::from(Span::styled(
                    "─".repeat(40),
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::DIM),
                )));
            }
            Event::TaskListMarker(checked) => {
                let marker = if checked { "[x] " } else { "[ ] " };
                self.push_span(Span::raw(marker.to_string()));
            }
            Event::FootnoteReference(_) | Event::InlineMath(_) | Event::DisplayMath(_) => {
                // Best-effort: drop silently for the TUI path.
            }
        }
    }

    fn start(&mut self, tag: Tag<'_>) {
        match tag {
            Tag::Paragraph => {
                self.flush_line();
            }
            Tag::Heading { level, .. } => {
                self.flush_line();
                self.heading_level = Some(level);
            }
            Tag::BlockQuote(_) => {
                self.flush_line();
                self.in_block_quote += 1;
            }
            Tag::CodeBlock(kind) => {
                self.flush_line();
                let lang = match kind {
                    CodeBlockKind::Fenced(lang) => lang.into_string(),
                    CodeBlockKind::Indented => String::new(),
                };
                self.code_block_lang = Some(lang);
                self.code_block_src.clear();
            }
            Tag::List(start) => {
                self.flush_line();
                self.list_stack.push(match start {
                    Some(n) => ListContext::Ordered(n),
                    None => ListContext::Bullet,
                });
            }
            Tag::Item => {
                self.flush_line();
                let indent_levels = self.list_stack.len().saturating_sub(1);
                let indent = "  ".repeat(indent_levels + 1);
                let marker = match self.list_stack.last_mut() {
                    Some(ListContext::Bullet) => format!("{indent}• "),
                    Some(ListContext::Ordered(n)) => {
                        let m = format!("{indent}{n}. ");
                        *n += 1;
                        m
                    }
                    None => indent,
                };
                self.pending_marker = Some(Span::raw(marker));
            }
            Tag::Emphasis => self.italic += 1,
            Tag::Strong => self.bold += 1,
            Tag::Strikethrough => self.strike += 1,
            Tag::Link {
                dest_url: _dest, ..
            } => {
                // Link text is emitted as normal `Event::Text`s; we
                // append the URL on End(Link).
            }
            Tag::Image { dest_url, .. } => {
                self.push_span(Span::styled(
                    format!("[image: {dest_url}]"),
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::DIM),
                ));
            }
            Tag::Table(_) | Tag::TableHead | Tag::TableRow | Tag::TableCell => {
                // Tables: separate cells with " | ", rows on their own
                // lines. Keeps the renderer line-oriented.
                if matches!(tag, Tag::TableRow | Tag::TableHead) {
                    self.flush_line();
                }
                if matches!(tag, Tag::TableCell) && !self.buffer.is_empty() {
                    self.push_span(Span::raw(" | "));
                }
            }
            Tag::FootnoteDefinition(_)
            | Tag::HtmlBlock
            | Tag::MetadataBlock(_)
            | Tag::DefinitionList
            | Tag::DefinitionListTitle
            | Tag::DefinitionListDefinition => {}
        }
    }

    fn end(&mut self, tag: TagEnd) {
        match tag {
            TagEnd::Paragraph => {
                self.flush_line();
                self.paragraph_just_ended = true;
                // Blank line between paragraphs.
                self.lines.push(Line::from(Vec::<Span<'static>>::new()));
            }
            TagEnd::Heading(_) => {
                self.flush_line();
                self.heading_level = None;
                self.lines.push(Line::from(Vec::<Span<'static>>::new()));
            }
            TagEnd::BlockQuote(_) => {
                self.flush_line();
                self.in_block_quote = self.in_block_quote.saturating_sub(1);
            }
            TagEnd::CodeBlock => {
                self.flush_code_block();
            }
            TagEnd::List(_) => {
                self.flush_line();
                self.list_stack.pop();
            }
            TagEnd::Item => {
                self.flush_line();
                self.pending_marker = None;
            }
            TagEnd::Emphasis => self.italic = self.italic.saturating_sub(1),
            TagEnd::Strong => self.bold = self.bold.saturating_sub(1),
            TagEnd::Strikethrough => self.strike = self.strike.saturating_sub(1),
            TagEnd::Link => {
                // We don't have the URL here in 0.12's TagEnd — the
                // url-on-close behaviour is encoded by appending the
                // URL while handling `Tag::Link` text events. Since
                // pulldown-cmark emits the link URL only on `Start`,
                // we instead remember it via a small Vec — but for
                // simplicity in this widget we drop the URL append.
                // Most chat-style markdown puts the URL inline anyway.
            }
            TagEnd::Image => {}
            TagEnd::Table | TagEnd::TableHead | TagEnd::TableRow | TagEnd::TableCell => {
                if matches!(tag, TagEnd::TableRow | TagEnd::TableHead) {
                    self.flush_line();
                }
            }
            TagEnd::FootnoteDefinition
            | TagEnd::HtmlBlock
            | TagEnd::MetadataBlock(_)
            | TagEnd::DefinitionList
            | TagEnd::DefinitionListTitle
            | TagEnd::DefinitionListDefinition => {}
        }
    }

    fn on_text(&mut self, text: &str) {
        if self.code_block_lang.is_some() {
            self.code_block_src.push_str(text);
            return;
        }
        let style = self.current_inline_style();
        let owned = text.to_string();
        self.push_span(Span::styled(owned, style));
    }

    fn on_inline_code(&mut self, text: &str) {
        let style = Style::default().add_modifier(Modifier::DIM | Modifier::REVERSED);
        self.push_span(Span::styled(text.to_string(), style));
    }

    fn current_inline_style(&self) -> Style {
        let mut style = Style::default();
        if let Some(level) = self.heading_level {
            let color = match level {
                HeadingLevel::H1 => Some(Color::Cyan),
                HeadingLevel::H2 => Some(Color::Blue),
                _ => None,
            };
            if let Some(c) = color {
                style = style.fg(c);
            }
            style = style.add_modifier(Modifier::BOLD);
        }
        if self.bold > 0 {
            style = style.add_modifier(Modifier::BOLD);
        }
        if self.italic > 0 {
            style = style.add_modifier(Modifier::ITALIC);
        }
        if self.strike > 0 {
            style = style.add_modifier(Modifier::CROSSED_OUT);
        }
        if self.in_block_quote > 0 {
            style = style.add_modifier(Modifier::DIM);
        }
        style
    }

    /// Emit a span into the in-progress line. If a pending list-item
    /// marker is set, emit it as the first span on the line.
    fn push_span(&mut self, span: Span<'static>) {
        if self.buffer.is_empty() {
            if let Some(marker) = self.pending_marker.take() {
                self.buffer.push(marker);
            } else if self.in_block_quote > 0 {
                self.buffer.push(Span::styled(
                    "│ ",
                    Style::default().fg(Color::Cyan),
                ));
            }
        }
        self.buffer.push(span);
    }

    /// Flush the current in-progress line into `lines`.
    fn flush_line(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let spans = std::mem::take(&mut self.buffer);
        self.lines.push(Line::from(spans));
    }

    fn flush_code_block(&mut self) {
        let Some(lang) = self.code_block_lang.take() else {
            return;
        };
        let src = std::mem::take(&mut self.code_block_src);
        let (syntax_set, theme_set) = assets();
        let theme = theme_set
            .themes
            .get("base16-ocean.dark")
            .or_else(|| theme_set.themes.values().next())
            .expect("at least one syntect theme");

        let syntax = if lang.is_empty() {
            syntax_set.find_syntax_plain_text()
        } else {
            syntax_set
                .find_syntax_by_token(lang.as_str())
                .or_else(|| syntax_set.find_syntax_by_extension(lang.as_str()))
                .or_else(|| syntax_set.find_syntax_by_name(lang.as_str()))
                .unwrap_or_else(|| syntax_set.find_syntax_plain_text())
        };

        let mut highlighter = HighlightLines::new(syntax, theme);
        for line in LinesWithEndings::from(&src) {
            let pieces = match highlighter.highlight_line(line, syntax_set) {
                Ok(p) => p,
                Err(_) => {
                    self.lines.push(Line::from(Span::raw(line.to_string())));
                    continue;
                }
            };
            let mut spans: Vec<Span<'static>> = Vec::with_capacity(pieces.len());
            for (style, piece) in pieces {
                let text = piece.trim_end_matches('\n');
                if text.is_empty() {
                    continue;
                }
                spans.push(Span::styled(text.to_string(), syntect_style_to_ratatui(style)));
            }
            self.lines.push(Line::from(spans));
        }
    }

    fn finish(&mut self) {
        self.flush_line();
        if self.code_block_lang.is_some() {
            self.flush_code_block();
        }
    }
}

fn syntect_style_to_ratatui(style: SyntStyle) -> Style {
    let fg = style.foreground;
    let mut out = Style::default().fg(Color::Rgb(fg.r, fg.g, fg.b));
    let flags = style.font_style;
    if flags.contains(syntect::highlighting::FontStyle::BOLD) {
        out = out.add_modifier(Modifier::BOLD);
    }
    if flags.contains(syntect::highlighting::FontStyle::ITALIC) {
        out = out.add_modifier(Modifier::ITALIC);
    }
    if flags.contains(syntect::highlighting::FontStyle::UNDERLINE) {
        out = out.add_modifier(Modifier::UNDERLINED);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Concatenate a Line's span text into a single String for matching.
    fn line_text(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn headings_render_with_color() {
        let lines = render("# Title");
        let title_line = lines
            .iter()
            .find(|l| line_text(l).contains("Title"))
            .expect("title line present");
        let title_span = title_line
            .spans
            .iter()
            .find(|s| s.content.contains("Title"))
            .expect("Title span present");
        assert_eq!(title_span.style.fg, Some(Color::Cyan));
        assert!(title_span
            .style
            .add_modifier
            .contains(Modifier::BOLD));
    }

    #[test]
    fn bullet_list_indented_with_bullet() {
        let lines = render("- one\n- two");
        let item_lines: Vec<String> = lines
            .iter()
            .map(line_text)
            .filter(|t| t.contains('•'))
            .collect();
        assert_eq!(item_lines.len(), 2, "expected two bullet lines: {item_lines:?}");
        for text in &item_lines {
            assert!(
                text.starts_with("  • "),
                "expected line to start with '  • ', got {text:?}"
            );
        }
    }

    #[test]
    fn numbered_list_preserves_numbers() {
        let lines = render("1. one\n2. two");
        let texts: Vec<String> = lines.iter().map(line_text).collect();
        assert!(
            texts.iter().any(|t| t.starts_with("  1. ")),
            "expected a '  1. ' line, got {texts:?}"
        );
        assert!(
            texts.iter().any(|t| t.starts_with("  2. ")),
            "expected a '  2. ' line, got {texts:?}"
        );
    }

    #[test]
    fn fenced_code_block_uses_lang_from_fence() {
        let lines = render("```rust\nfn x() {}\n```");
        let code_line = lines
            .iter()
            .find(|l| line_text(l).contains("fn x()"))
            .expect("code line present");
        let has_rgb_span = code_line
            .spans
            .iter()
            .any(|s| matches!(s.style.fg, Some(Color::Rgb(_, _, _))));
        assert!(
            has_rgb_span,
            "expected at least one syntect-highlighted Rgb span: {:?}",
            code_line.spans
        );
    }

    #[test]
    fn inline_code_styled_dim_reversed() {
        let lines = render("hi `code` there");
        let code_span = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .find(|s| s.content == "code")
            .expect("`code` span present");
        assert!(
            code_span.style.add_modifier.contains(Modifier::REVERSED),
            "expected REVERSED modifier on inline code, got {:?}",
            code_span.style
        );
    }

    #[test]
    fn bold_and_italic_modifiers() {
        let lines = render("**bold** _italic_");
        let bold_span = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .find(|s| s.content == "bold")
            .expect("bold span present");
        assert!(bold_span.style.add_modifier.contains(Modifier::BOLD));

        let italic_span = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .find(|s| s.content == "italic")
            .expect("italic span present");
        assert!(italic_span.style.add_modifier.contains(Modifier::ITALIC));
    }

    #[test]
    fn block_quote_prefixed() {
        let lines = render("> quoted");
        let quote_line = lines
            .iter()
            .find(|l| line_text(l).contains("quoted"))
            .expect("quoted line present");
        let first = quote_line.spans.first().expect("at least one span");
        assert!(
            first.content.starts_with("│ "),
            "expected block-quote prefix '│ ', got {:?}",
            first.content
        );
    }

    #[test]
    fn paragraphs_separated_by_blank_line() {
        let lines = render("p1\n\np2");
        // Find p1 and p2 lines, assert a blank Line exists between
        // them.
        let positions: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| {
                let t = line_text(l);
                t == "p1" || t == "p2"
            })
            .map(|(i, _)| i)
            .collect();
        assert_eq!(positions.len(), 2, "expected two paragraph lines: {lines:?}");
        let between = &lines[positions[0] + 1..positions[1]];
        assert!(
            between.iter().any(|l| l.spans.is_empty()),
            "expected a blank Line between paragraphs: {between:?}"
        );
    }
}
