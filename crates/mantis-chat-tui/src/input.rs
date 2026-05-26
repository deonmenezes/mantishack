//! Multiline input widget with sent-message history navigation.
//!
//! Owns the edit buffer, the cursor, and the up/down history
//! browser. The widget is keyboard-driven via [`InputWidget::handle_key`];
//! the caller maps the returned [`InputAction`] into UI state changes
//! and message submission.
//!
//! History navigation rules:
//! - **Up** when not browsing: snapshot the current buffer and load
//!   the most-recent prior message into the buffer.
//! - **Up** when browsing: walk further back, saturating at the
//!   oldest message.
//! - **Down** while browsing: walk newer, stopping one past the most
//!   recent (restores the snapshotted live buffer).
//! - Any character keystroke or Enter exits browse mode and commits
//!   the visible buffer as the live edit buffer.
//!
//! Keys handled:
//! - char input, Backspace, Delete
//! - Left/Right/Home/End/Ctrl+A/Ctrl+E
//! - Ctrl+U (delete to start of line), Ctrl+K (delete to end of line)
//! - Ctrl+W (delete word back)
//! - Ctrl+L (clear screen — surfaced as `InputAction::Redraw`)
//! - Up/Down (history navigation)
//! - Enter (submit), Shift+Enter (insert newline)
//! - Esc (clear input)
//! - Ctrl+C / Ctrl+D (caller decides — we just return `Quit`)
//!
//! Paste handling happens in the caller's bracketed-paste branch,
//! which calls [`InputWidget::insert_str`].

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Result of handling one key press. The caller renders, submits, or
/// quits based on the variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputAction {
    /// Buffer or cursor changed; caller should redraw.
    Continue,
    /// User hit Enter on a non-empty buffer. The string is the
    /// extracted buffer; the widget is reset to empty.
    Submit(String),
    /// User requested termination (Ctrl+C, or Ctrl+D on an empty
    /// buffer). Caller decides whether to exit.
    Quit,
}

#[derive(Debug)]
pub struct InputWidget {
    buffer: String,
    /// Cursor as a byte offset into `buffer`. Always sits on a char
    /// boundary; methods enforce this on every move.
    cursor: usize,
    /// Sent-message history, oldest first. Populated from the
    /// session JSONL when the TUI starts and grown via
    /// [`InputWidget::push_history`] after each submitted turn.
    history: Vec<String>,
    /// `None` when editing live; `Some(i)` when showing `history[i]`.
    history_pos: Option<usize>,
    /// Saved live buffer + cursor while browsing history. Restored
    /// when the user walks past the most-recent message.
    saved: Option<(String, usize)>,
}

impl Default for InputWidget {
    fn default() -> Self {
        Self::new()
    }
}

impl InputWidget {
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            cursor: 0,
            history: Vec::new(),
            history_pos: None,
            saved: None,
        }
    }

    pub fn with_history(mut self, history: Vec<String>) -> Self {
        self.history = history;
        self
    }

    pub fn buffer(&self) -> &str {
        &self.buffer
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Record a submitted message so up-arrow can recall it. Dedup
    /// adjacent duplicates so repeated `/help` invocations don't
    /// clutter the history.
    pub fn push_history(&mut self, msg: String) {
        if self.history.last().map(String::as_str) == Some(msg.as_str()) {
            return;
        }
        self.history.push(msg);
        self.history_pos = None;
        self.saved = None;
    }

    /// Insert literal text at the cursor (used for paste).
    pub fn insert_str(&mut self, s: &str) {
        self.exit_history_browse();
        self.buffer.insert_str(self.cursor, s);
        self.cursor += s.len();
    }

    /// Replace the entire buffer and position cursor at end. Exits
    /// history-browse mode. Used by slash-command autocomplete.
    pub fn replace(&mut self, content: String) {
        self.exit_history_browse();
        self.buffer = content;
        self.cursor = self.buffer.len();
    }

    /// Handle one key event. Returns the action the caller should
    /// take.
    pub fn handle_key(&mut self, key: KeyEvent) -> InputAction {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);

        // Global controls.
        if ctrl {
            match key.code {
                KeyCode::Char('c') => return InputAction::Quit,
                KeyCode::Char('d') if self.buffer.is_empty() => return InputAction::Quit,
                KeyCode::Char('u') => {
                    self.delete_to_line_start();
                    return InputAction::Continue;
                }
                KeyCode::Char('k') => {
                    self.delete_to_line_end();
                    return InputAction::Continue;
                }
                KeyCode::Char('w') => {
                    self.delete_word_back();
                    return InputAction::Continue;
                }
                KeyCode::Char('a') => {
                    self.cursor_to_line_start();
                    return InputAction::Continue;
                }
                KeyCode::Char('e') => {
                    self.cursor_to_line_end();
                    return InputAction::Continue;
                }
                KeyCode::Left => {
                    self.cursor_word_back();
                    return InputAction::Continue;
                }
                KeyCode::Right => {
                    self.cursor_word_forward();
                    return InputAction::Continue;
                }
                _ => {}
            }
        }

        match key.code {
            KeyCode::Enter => {
                if shift {
                    // Shift+Enter inserts a literal newline.
                    self.exit_history_browse();
                    self.buffer.insert(self.cursor, '\n');
                    self.cursor += 1;
                    InputAction::Continue
                } else if self.buffer.trim().is_empty() {
                    InputAction::Continue
                } else {
                    let msg = std::mem::take(&mut self.buffer);
                    self.cursor = 0;
                    self.history_pos = None;
                    self.saved = None;
                    InputAction::Submit(msg)
                }
            }
            KeyCode::Char(ch) => {
                // Anything-but-control char: insert.
                self.exit_history_browse();
                let mut buf = [0u8; 4];
                let s = ch.encode_utf8(&mut buf);
                self.buffer.insert_str(self.cursor, s);
                self.cursor += s.len();
                InputAction::Continue
            }
            KeyCode::Backspace => {
                self.exit_history_browse();
                if self.cursor > 0 {
                    let mut new_cursor = self.cursor - 1;
                    while !self.buffer.is_char_boundary(new_cursor) && new_cursor > 0 {
                        new_cursor -= 1;
                    }
                    self.buffer.replace_range(new_cursor..self.cursor, "");
                    self.cursor = new_cursor;
                }
                InputAction::Continue
            }
            KeyCode::Delete => {
                self.exit_history_browse();
                if self.cursor < self.buffer.len() {
                    let mut next = self.cursor + 1;
                    while next < self.buffer.len() && !self.buffer.is_char_boundary(next) {
                        next += 1;
                    }
                    self.buffer.replace_range(self.cursor..next, "");
                }
                InputAction::Continue
            }
            KeyCode::Left => {
                self.cursor_left();
                InputAction::Continue
            }
            KeyCode::Right => {
                self.cursor_right();
                InputAction::Continue
            }
            KeyCode::Home => {
                self.cursor = 0;
                InputAction::Continue
            }
            KeyCode::End => {
                self.cursor = self.buffer.len();
                InputAction::Continue
            }
            KeyCode::Up => {
                self.history_back();
                InputAction::Continue
            }
            KeyCode::Down => {
                self.history_forward();
                InputAction::Continue
            }
            KeyCode::Esc => {
                self.buffer.clear();
                self.cursor = 0;
                self.history_pos = None;
                self.saved = None;
                InputAction::Continue
            }
            _ => InputAction::Continue,
        }
    }

    // ----- cursor + buffer primitives -----

    fn cursor_left(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let mut new_cursor = self.cursor - 1;
        while !self.buffer.is_char_boundary(new_cursor) && new_cursor > 0 {
            new_cursor -= 1;
        }
        self.cursor = new_cursor;
    }

    fn cursor_right(&mut self) {
        if self.cursor >= self.buffer.len() {
            return;
        }
        let mut new_cursor = self.cursor + 1;
        while new_cursor < self.buffer.len() && !self.buffer.is_char_boundary(new_cursor) {
            new_cursor += 1;
        }
        self.cursor = new_cursor;
    }

    fn cursor_to_line_start(&mut self) {
        // Find the most recent newline before the cursor.
        let prefix = &self.buffer[..self.cursor];
        match prefix.rfind('\n') {
            Some(nl) => self.cursor = nl + 1,
            None => self.cursor = 0,
        }
    }

    fn cursor_to_line_end(&mut self) {
        let suffix = &self.buffer[self.cursor..];
        match suffix.find('\n') {
            Some(off) => self.cursor += off,
            None => self.cursor = self.buffer.len(),
        }
    }

    fn cursor_word_back(&mut self) {
        let bytes = self.buffer.as_bytes();
        let mut i = self.cursor;
        // Skip whitespace immediately left of the cursor.
        while i > 0 && bytes[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        // Then skip non-whitespace to reach the start of the word.
        while i > 0 && !bytes[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        // Snap to char boundary.
        while !self.buffer.is_char_boundary(i) && i > 0 {
            i -= 1;
        }
        self.cursor = i;
    }

    fn cursor_word_forward(&mut self) {
        let bytes = self.buffer.as_bytes();
        let mut i = self.cursor;
        // Skip current non-whitespace.
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        // Skip whitespace to next word start.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        while i < self.buffer.len() && !self.buffer.is_char_boundary(i) {
            i += 1;
        }
        self.cursor = i;
    }

    fn delete_to_line_start(&mut self) {
        self.exit_history_browse();
        let start = self.buffer[..self.cursor]
            .rfind('\n')
            .map(|n| n + 1)
            .unwrap_or(0);
        self.buffer.replace_range(start..self.cursor, "");
        self.cursor = start;
    }

    fn delete_to_line_end(&mut self) {
        self.exit_history_browse();
        let end = self.buffer[self.cursor..]
            .find('\n')
            .map(|off| self.cursor + off)
            .unwrap_or(self.buffer.len());
        self.buffer.replace_range(self.cursor..end, "");
    }

    fn delete_word_back(&mut self) {
        self.exit_history_browse();
        let target = {
            let bytes = self.buffer.as_bytes();
            let mut i = self.cursor;
            while i > 0 && bytes[i - 1].is_ascii_whitespace() {
                i -= 1;
            }
            while i > 0 && !bytes[i - 1].is_ascii_whitespace() {
                i -= 1;
            }
            while !self.buffer.is_char_boundary(i) && i > 0 {
                i -= 1;
            }
            i
        };
        self.buffer.replace_range(target..self.cursor, "");
        self.cursor = target;
    }

    // ----- history browse -----

    fn history_back(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let new_pos = match self.history_pos {
            None => {
                self.saved = Some((self.buffer.clone(), self.cursor));
                self.history.len() - 1
            }
            Some(0) => 0,
            Some(i) => i - 1,
        };
        self.history_pos = Some(new_pos);
        self.buffer = self.history[new_pos].clone();
        self.cursor = self.buffer.len();
    }

    fn history_forward(&mut self) {
        let Some(pos) = self.history_pos else {
            return;
        };
        if pos + 1 < self.history.len() {
            let new_pos = pos + 1;
            self.history_pos = Some(new_pos);
            self.buffer = self.history[new_pos].clone();
            self.cursor = self.buffer.len();
        } else {
            // Walked past the most recent — restore live buffer.
            if let Some((buf, cur)) = self.saved.take() {
                self.buffer = buf;
                self.cursor = cur;
            } else {
                self.buffer.clear();
                self.cursor = 0;
            }
            self.history_pos = None;
        }
    }

    fn exit_history_browse(&mut self) {
        // When the user edits while browsing, commit the visible
        // text as the new live buffer and drop the snapshot.
        self.history_pos = None;
        self.saved = None;
    }

    /// Translate a byte cursor into a (line, column) pair for
    /// terminal placement. Used by the renderer to position the
    /// terminal cursor inside the multiline input box.
    pub fn cursor_visual_position(&self) -> (u16, u16) {
        let prefix = &self.buffer[..self.cursor];
        let line = prefix.matches('\n').count() as u16;
        let col_str = prefix.rsplit('\n').next().unwrap_or("");
        let col = unicode_width::UnicodeWidthStr::width(col_str) as u16;
        (line, col)
    }

    /// Iterator over the logical lines of the buffer for rendering.
    pub fn lines(&self) -> std::str::Split<'_, char> {
        self.buffer.split('\n')
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        }
    }
    fn kc(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        }
    }

    #[test]
    fn char_input_appends_and_advances_cursor() {
        let mut w = InputWidget::new();
        for ch in "hello".chars() {
            assert_eq!(w.handle_key(k(KeyCode::Char(ch))), InputAction::Continue);
        }
        assert_eq!(w.buffer(), "hello");
        assert_eq!(w.cursor(), 5);
    }

    #[test]
    fn enter_submits_non_empty_buffer() {
        let mut w = InputWidget::new();
        for ch in "hi".chars() {
            w.handle_key(k(KeyCode::Char(ch)));
        }
        let action = w.handle_key(k(KeyCode::Enter));
        assert_eq!(action, InputAction::Submit("hi".into()));
        assert!(w.buffer().is_empty());
    }

    #[test]
    fn shift_enter_inserts_newline() {
        let mut w = InputWidget::new();
        w.handle_key(k(KeyCode::Char('a')));
        let action = w.handle_key(kc(KeyCode::Enter, KeyModifiers::SHIFT));
        assert_eq!(action, InputAction::Continue);
        w.handle_key(k(KeyCode::Char('b')));
        assert_eq!(w.buffer(), "a\nb");
    }

    #[test]
    fn ctrl_c_quits_regardless_of_buffer() {
        let mut w = InputWidget::new();
        assert_eq!(
            w.handle_key(kc(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            InputAction::Quit
        );
        w.handle_key(k(KeyCode::Char('x')));
        assert_eq!(
            w.handle_key(kc(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            InputAction::Quit
        );
    }

    #[test]
    fn ctrl_d_only_quits_when_buffer_empty() {
        let mut w = InputWidget::new();
        assert_eq!(
            w.handle_key(kc(KeyCode::Char('d'), KeyModifiers::CONTROL)),
            InputAction::Quit
        );
        w.handle_key(k(KeyCode::Char('x')));
        assert_eq!(
            w.handle_key(kc(KeyCode::Char('d'), KeyModifiers::CONTROL)),
            InputAction::Continue
        );
    }

    #[test]
    fn ctrl_u_deletes_to_line_start() {
        let mut w = InputWidget::new();
        for ch in "hello world".chars() {
            w.handle_key(k(KeyCode::Char(ch)));
        }
        w.handle_key(kc(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert_eq!(w.buffer(), "");
    }

    #[test]
    fn ctrl_w_deletes_word_back() {
        let mut w = InputWidget::new();
        for ch in "hello world".chars() {
            w.handle_key(k(KeyCode::Char(ch)));
        }
        w.handle_key(kc(KeyCode::Char('w'), KeyModifiers::CONTROL));
        assert_eq!(w.buffer(), "hello ");
    }

    #[test]
    fn ctrl_a_and_e_jump_to_line_bounds_in_multiline() {
        let mut w = InputWidget::new();
        w.insert_str("line1\nline2");
        // Cursor is at end of "line2".
        w.handle_key(kc(KeyCode::Char('a'), KeyModifiers::CONTROL));
        // Should be at start of "line2".
        assert_eq!(w.cursor(), "line1\n".len());
        w.handle_key(kc(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert_eq!(w.cursor(), "line1\nline2".len());
    }

    #[test]
    fn arrow_left_right_respect_char_boundaries() {
        let mut w = InputWidget::new();
        w.insert_str("héllo"); // é is 2 bytes
        let len = w.buffer().len();
        w.cursor = 0;
        for _ in 0..5 {
            w.handle_key(k(KeyCode::Right));
        }
        assert_eq!(w.cursor(), len);
        for _ in 0..5 {
            w.handle_key(k(KeyCode::Left));
        }
        assert_eq!(w.cursor(), 0);
    }

    #[test]
    fn up_arrow_loads_most_recent_history() {
        let mut w = InputWidget::new().with_history(vec!["older".into(), "newer".into()]);
        w.handle_key(k(KeyCode::Up));
        assert_eq!(w.buffer(), "newer");
        w.handle_key(k(KeyCode::Up));
        assert_eq!(w.buffer(), "older");
        // Up at the oldest stays put.
        w.handle_key(k(KeyCode::Up));
        assert_eq!(w.buffer(), "older");
    }

    #[test]
    fn down_arrow_walks_forward_and_restores_live_buffer() {
        let mut w = InputWidget::new().with_history(vec!["older".into(), "newer".into()]);
        w.insert_str("draft");
        w.handle_key(k(KeyCode::Up));
        assert_eq!(w.buffer(), "newer");
        w.handle_key(k(KeyCode::Up));
        assert_eq!(w.buffer(), "older");
        w.handle_key(k(KeyCode::Down));
        assert_eq!(w.buffer(), "newer");
        w.handle_key(k(KeyCode::Down));
        assert_eq!(w.buffer(), "draft");
    }

    #[test]
    fn editing_while_browsing_commits_visible_buffer_as_live() {
        let mut w = InputWidget::new().with_history(vec!["prior".into()]);
        w.handle_key(k(KeyCode::Up));
        assert_eq!(w.buffer(), "prior");
        // Append a char — should commit "prior" as the live buffer.
        w.handle_key(k(KeyCode::Char('!')));
        assert_eq!(w.buffer(), "prior!");
        // Down arrow now does nothing (not browsing anymore).
        w.handle_key(k(KeyCode::Down));
        assert_eq!(w.buffer(), "prior!");
    }

    #[test]
    fn push_history_dedupes_adjacent() {
        let mut w = InputWidget::new();
        w.push_history("a".into());
        w.push_history("a".into());
        w.push_history("b".into());
        assert_eq!(w.history.len(), 2);
    }

    #[test]
    fn cursor_visual_position_handles_multiline() {
        let mut w = InputWidget::new();
        w.insert_str("hello\nworld");
        // Cursor at end of "world", line 1, col 5.
        assert_eq!(w.cursor_visual_position(), (1, 5));
        // Move to start of buffer.
        w.cursor = 0;
        assert_eq!(w.cursor_visual_position(), (0, 0));
    }
}
