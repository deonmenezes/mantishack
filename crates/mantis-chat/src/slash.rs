//! Slash-command parser for the chat REPL.
//!
//! Lines starting with `/` are treated as control commands rather
//! than messages to the model. Everything else is forwarded as a
//! user message.

/// A single parsed line of REPL input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    Slash(SlashCommand),
    Message(String),
}

/// Recognised slash commands. Unknown `/...` lines become
/// [`SlashCommand::Unknown`] so the REPL can surface a "type /help"
/// hint without swallowing typos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashCommand {
    /// `/clear` — drop the conversation history (keeps the system
    /// prompt).
    Clear,
    /// `/model` — show the current model. `/model gpt-4o-mini` —
    /// request a switch (REPL decides whether the underlying
    /// provider supports it).
    Model { name: Option<String> },
    /// `/provider` — show or switch the active provider.
    Provider { name: Option<String> },
    /// `/tools` — list tools the model can call this turn.
    Tools,
    /// `/help` — print the slash-command index.
    Help,
    /// `/quit` or `/exit` — end the REPL.
    Quit,
    /// Anything else starting with `/`.
    Unknown(String),
}

/// Parse one REPL line.
pub fn parse_input(line: &str) -> Input {
    let trimmed = line.trim();
    if !trimmed.starts_with('/') {
        return Input::Message(line.to_string());
    }
    // Strip the leading `/` and split on whitespace.
    let body = &trimmed[1..];
    let mut parts = body.split_whitespace();
    let cmd = match parts.next() {
        Some(c) => c,
        None => return Input::Slash(SlashCommand::Unknown(String::new())),
    };
    let rest: Vec<&str> = parts.collect();
    let joined_rest = if rest.is_empty() {
        None
    } else {
        Some(rest.join(" "))
    };
    let slash = match cmd {
        "clear" | "reset" => SlashCommand::Clear,
        "model" => SlashCommand::Model { name: joined_rest },
        "provider" => SlashCommand::Provider { name: joined_rest },
        "tools" => SlashCommand::Tools,
        "help" | "?" => SlashCommand::Help,
        "quit" | "exit" | "q" => SlashCommand::Quit,
        other => SlashCommand::Unknown(other.to_string()),
    };
    Input::Slash(slash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_message() {
        match parse_input("hello there") {
            Input::Message(s) => assert_eq!(s, "hello there"),
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[test]
    fn leading_slash_is_command() {
        assert_eq!(parse_input("/clear"), Input::Slash(SlashCommand::Clear));
        assert_eq!(parse_input("/reset"), Input::Slash(SlashCommand::Clear));
        assert_eq!(parse_input("/quit"), Input::Slash(SlashCommand::Quit));
        assert_eq!(parse_input("/exit"), Input::Slash(SlashCommand::Quit));
        assert_eq!(parse_input("/help"), Input::Slash(SlashCommand::Help));
        assert_eq!(parse_input("/?"), Input::Slash(SlashCommand::Help));
        assert_eq!(parse_input("/tools"), Input::Slash(SlashCommand::Tools));
    }

    #[test]
    fn model_with_and_without_arg() {
        assert_eq!(
            parse_input("/model"),
            Input::Slash(SlashCommand::Model { name: None })
        );
        assert_eq!(
            parse_input("/model gpt-4o-mini"),
            Input::Slash(SlashCommand::Model {
                name: Some("gpt-4o-mini".to_string())
            })
        );
    }

    #[test]
    fn unknown_command_is_preserved() {
        match parse_input("/banana") {
            Input::Slash(SlashCommand::Unknown(s)) => assert_eq!(s, "banana"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn whitespace_does_not_swallow_slash() {
        assert_eq!(parse_input("  /clear  "), Input::Slash(SlashCommand::Clear));
    }
}
