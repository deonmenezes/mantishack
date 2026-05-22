//! Slash-command autocomplete: known-command table + prefix matcher.
//!
//! The renderer in [`crate::ui`] consumes the suggestions returned by
//! [`suggest`] and draws a dropdown above the input box. The app
//! event loop intercepts `Tab` when suggestions are non-empty and
//! replaces the input buffer with `/<command> `.

/// Known slash commands. Keep this list in sync with the REPL
/// handler in `mantis-cli/src/main.rs::handle_chat`.
pub const COMMANDS: &[(&str, &str)] = &[
    ("clear", "drop history (keep system prompt)"),
    ("model", "show or switch the model"),
    ("provider", "show or switch the provider"),
    ("tools", "list available tools"),
    ("help", "list slash commands"),
    ("quit", "exit"),
    ("session", "show or switch the session label"),
    ("save", "save a snapshot of the current transcript"),
];

/// Maximum suggestions returned at once (and rendered in the dropdown).
pub const MAX_SUGGESTIONS: usize = 6;

/// Match `/prefix` against the known [`COMMANDS`] table.
///
/// The caller strips the leading `/` before invoking. Matching is
/// case-insensitive and preserves declaration order. At most
/// [`MAX_SUGGESTIONS`] entries are returned.
pub fn suggest(prefix: &str) -> Vec<&'static (&'static str, &'static str)> {
    let lower = prefix.to_ascii_lowercase();
    COMMANDS
        .iter()
        .filter(|(name, _)| name.to_ascii_lowercase().starts_with(&lower))
        .take(MAX_SUGGESTIONS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggest_returns_all_for_empty_prefix() {
        let got = suggest("");
        assert_eq!(got.len(), COMMANDS.len().min(MAX_SUGGESTIONS));
        for (i, entry) in got.iter().enumerate() {
            assert_eq!(entry.0, COMMANDS[i].0);
        }
    }

    #[test]
    fn suggest_filters_by_prefix() {
        let got = suggest("cl");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "clear");
    }

    #[test]
    fn suggest_is_case_insensitive() {
        let got = suggest("Q");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "quit");
    }

    #[test]
    fn suggest_returns_empty_on_no_match() {
        let got = suggest("xyz");
        assert!(got.is_empty());
    }

    #[test]
    fn suggest_caps_at_six_results() {
        // Empty prefix matches every command; verify the cap.
        assert!(COMMANDS.len() >= MAX_SUGGESTIONS);
        let got = suggest("");
        assert_eq!(got.len(), MAX_SUGGESTIONS);
    }
}
