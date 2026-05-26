//! `@<path>` attachment expansion for chat input.
//!
//! Before submitting a user turn, scan the input for `@`-prefixed
//! tokens that look like file paths and inline the file contents as
//! tagged fenced code blocks. Operators paste paths in conversation
//! — `analyse @src/main.rs and @Cargo.toml` — and the model gets
//! the file contents alongside the prompt.
//!
//! Rules:
//! - A token is recognised as an attachment if it starts with `@`
//!   immediately after whitespace or at the start of the input.
//! - The path is everything after the `@` up to the next whitespace.
//! - The path is read with the calling process's CWD as the base —
//!   relative paths resolve to the user's working directory.
//! - The attachment block is appended to the END of the turn so the
//!   user's original prompt comes first and the model sees the
//!   contents as supporting context.
//! - Total attachment budget defaults to 256 KiB. Files past the
//!   budget are listed but truncated.
//! - Missing files produce an `[attachment failed: ...]` note in
//!   the inlined block. Submission continues regardless.
//!
//! Binary detection: if the file starts with a NUL byte in the
//! first 8 KiB, it's flagged as binary and rendered as
//! `[binary attachment: <path> — <N> bytes]` instead of dumping
//! garbage bytes that would blow the model's context.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Default cap on cumulative attachment byte size per turn. The
/// model sees at most this many bytes of inlined content; the rest
/// is reported as `[truncated, original was <N> bytes]`.
pub const DEFAULT_BUDGET_BYTES: usize = 256 * 1024;

/// One parsed attachment reference from the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// Path as written by the user (relative to CWD).
    pub path: PathBuf,
    /// Byte range in the original input where the `@<path>` token
    /// sits. The expander leaves the token in place — it's still
    /// visible to the model — and appends the inline block below.
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone)]
pub struct Expansion {
    /// Augmented prompt: original input + appended attachment blocks.
    pub prompt: String,
    /// One entry per attachment that was actually expanded (for the
    /// caller's SystemNote echo). Includes errors.
    pub notes: Vec<String>,
    /// Total bytes inlined (after truncation).
    pub bytes_inlined: usize,
}

/// Scan `input` for `@<path>` tokens, read the referenced files,
/// and return an augmented prompt with the files inlined as
/// fenced blocks. The original `@<path>` tokens stay in the prompt
/// — they help the model identify which block corresponds to which
/// mention.
pub fn expand(input: &str, budget_bytes: usize) -> Expansion {
    let attachments = parse(input);
    if attachments.is_empty() {
        return Expansion {
            prompt: input.to_string(),
            notes: Vec::new(),
            bytes_inlined: 0,
        };
    }

    let mut prompt = input.to_string();
    let mut notes = Vec::new();
    let mut bytes_used: usize = 0;
    let mut blocks: Vec<String> = Vec::new();

    for att in &attachments {
        let remaining = budget_bytes.saturating_sub(bytes_used);
        match inline_one(&att.path, remaining) {
            Ok(inlined) => {
                bytes_used += inlined.bytes_used;
                notes.push(format!(
                    "@ {} ({} bytes)",
                    att.path.display(),
                    inlined.bytes_used
                ));
                blocks.push(inlined.block);
            }
            Err(e) => {
                let msg = format!("[attachment failed: {} — {}]", att.path.display(), e);
                notes.push(format!("@ {}: {}", att.path.display(), e));
                blocks.push(msg);
            }
        }
    }

    if !blocks.is_empty() {
        prompt.push_str("\n\n--- attached files ---\n");
        for block in blocks {
            prompt.push('\n');
            prompt.push_str(&block);
            prompt.push('\n');
        }
    }

    Expansion {
        prompt,
        notes,
        bytes_inlined: bytes_used,
    }
}

/// Scan `input` for `@<path>` tokens. A token starts with `@`
/// preceded by whitespace or string start, and extends to the next
/// whitespace character.
pub fn parse(input: &str) -> Vec<Attachment> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let preceded_by_ws = i == 0 || bytes[i - 1].is_ascii_whitespace();
        if bytes[i] == b'@' && preceded_by_ws {
            let start = i;
            let path_start = i + 1;
            let mut end = path_start;
            while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            if end > path_start {
                // Strip trailing punctuation that's almost certainly
                // not part of the path: `,`, `;`, `.`, `:`, `)`, `]`.
                // (Only if the previous char isn't also part of a
                // sensible path.)
                let mut path_end = end;
                while path_end > path_start
                    && matches!(bytes[path_end - 1], b',' | b';' | b':' | b')' | b']')
                {
                    path_end -= 1;
                }
                // Strip a single trailing `.` when it's clearly a
                // sentence-ending period (preceded by alphanumeric,
                // not a path separator or another dot).
                if path_end > path_start
                    && bytes[path_end - 1] == b'.'
                    && path_end >= 2
                    && bytes[path_end - 2].is_ascii_alphanumeric()
                {
                    path_end -= 1;
                }
                let path_str = std::str::from_utf8(&bytes[path_start..path_end]).unwrap_or("");
                if !path_str.is_empty() {
                    out.push(Attachment {
                        path: PathBuf::from(path_str),
                        start,
                        end: path_end,
                    });
                }
            }
            i = end;
            continue;
        }
        i += 1;
    }
    out
}

struct InlinedBlock {
    block: String,
    bytes_used: usize,
}

fn inline_one(path: &Path, budget: usize) -> std::io::Result<InlinedBlock> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let file_size = metadata.len() as usize;

    // Binary detection: peek at the first 8 KiB.
    let to_read = file_size.min(8 * 1024);
    let mut buf = vec![0u8; to_read];
    let n = std::io::Read::read(&mut std::fs::File::open(path)?, &mut buf)?;
    buf.truncate(n);
    let is_binary = buf.iter().take(8 * 1024).any(|&b| b == 0);
    if is_binary {
        let block = format!(
            "[binary attachment: {} — {} bytes — skipped]",
            path.display(),
            file_size
        );
        let bytes_used = block.len();
        return Ok(InlinedBlock { block, bytes_used });
    }

    // Read the rest if not truncated yet.
    let full_bytes = if to_read < file_size {
        std::fs::read(path)?
    } else {
        buf
    };
    let original_len = full_bytes.len();
    let truncated = original_len > budget;
    let body_bytes = if truncated {
        &full_bytes[..budget]
    } else {
        &full_bytes[..]
    };
    let body = String::from_utf8_lossy(body_bytes).into_owned();

    let lang = detect_language(path);
    let mut block = format!("```{lang}\n# {}\n", path.display());
    block.push_str(&body);
    if !body.ends_with('\n') {
        block.push('\n');
    }
    if truncated {
        let _ = writeln!(
            block,
            "\n[truncated to {} bytes — original was {} bytes]",
            budget, original_len
        );
    }
    block.push_str("```");

    Ok(InlinedBlock {
        block,
        bytes_used: body.len(),
    })
}

/// Map common file extensions to fence-language tags so the model
/// (and any downstream markdown renderer) syntax-highlights the
/// inlined content. Unknown extensions get no tag.
fn detect_language(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("rs") => "rust",
        Some("py") => "python",
        Some("js" | "mjs") => "javascript",
        Some("ts") => "typescript",
        Some("tsx") => "tsx",
        Some("jsx") => "jsx",
        Some("go") => "go",
        Some("java") => "java",
        Some("kt") => "kotlin",
        Some("rb") => "ruby",
        Some("php") => "php",
        Some("c") => "c",
        Some("h") => "c",
        Some("cpp" | "cc" | "cxx") => "cpp",
        Some("hpp" | "hxx") => "cpp",
        Some("cs") => "csharp",
        Some("swift") => "swift",
        Some("sh" | "bash" | "zsh") => "bash",
        Some("toml") => "toml",
        Some("yaml" | "yml") => "yaml",
        Some("json") => "json",
        Some("xml") => "xml",
        Some("html") => "html",
        Some("css") => "css",
        Some("scss") => "scss",
        Some("md" | "markdown") => "markdown",
        Some("sql") => "sql",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_finds_single_attachment() {
        let atts = parse("look at @src/main.rs please");
        assert_eq!(atts.len(), 1);
        assert_eq!(atts[0].path, PathBuf::from("src/main.rs"));
    }

    #[test]
    fn parse_finds_multiple_attachments() {
        let atts = parse("compare @a.rs and @b.rs side by side");
        assert_eq!(atts.len(), 2);
        assert_eq!(atts[0].path, PathBuf::from("a.rs"));
        assert_eq!(atts[1].path, PathBuf::from("b.rs"));
    }

    #[test]
    fn parse_at_start_of_input() {
        let atts = parse("@README.md tell me about this");
        assert_eq!(atts.len(), 1);
        assert_eq!(atts[0].path, PathBuf::from("README.md"));
    }

    #[test]
    fn parse_strips_trailing_punctuation() {
        let atts = parse("look at @src/main.rs, then @lib.rs.");
        assert_eq!(atts.len(), 2);
        assert_eq!(atts[0].path, PathBuf::from("src/main.rs"));
        assert_eq!(atts[1].path, PathBuf::from("lib.rs"));
    }

    #[test]
    fn parse_skips_email_addresses() {
        // Email-like patterns are NOT preceded by whitespace at the @.
        let atts = parse("contact me at foo@bar.com please");
        assert!(atts.is_empty());
    }

    #[test]
    fn parse_lone_at_is_ignored() {
        let atts = parse("hello @ there");
        // The whitespace after the @ means path is empty — ignored.
        assert!(atts.is_empty());
    }

    #[test]
    fn expand_inlines_file_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        std::fs::write(&path, "hello world").unwrap();
        let input = format!("look at @{}", path.display());
        let exp = expand(&input, DEFAULT_BUDGET_BYTES);
        assert!(exp.prompt.contains("hello world"));
        assert_eq!(exp.bytes_inlined, "hello world".len());
        assert_eq!(exp.notes.len(), 1);
    }

    #[test]
    fn expand_truncates_at_budget() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.txt");
        let content = "a".repeat(1024);
        std::fs::write(&path, &content).unwrap();
        let input = format!("@{}", path.display());
        let exp = expand(&input, 128);
        assert!(exp.prompt.contains("truncated"));
        assert!(exp.bytes_inlined <= 128);
    }

    #[test]
    fn expand_reports_missing_file_as_note_not_panic() {
        let exp = expand("@/this/does/not/exist.rs", DEFAULT_BUDGET_BYTES);
        assert!(exp.prompt.contains("attachment failed"));
        assert_eq!(exp.notes.len(), 1);
        assert!(exp.notes[0].contains("/this/does/not/exist.rs"));
    }

    #[test]
    fn expand_no_attachments_returns_input_unchanged() {
        let exp = expand("plain text", DEFAULT_BUDGET_BYTES);
        assert_eq!(exp.prompt, "plain text");
        assert!(exp.notes.is_empty());
        assert_eq!(exp.bytes_inlined, 0);
    }

    #[test]
    fn expand_detects_binary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.bin");
        std::fs::write(&path, [0xFFu8, 0x00, 0xFF, 0xAA, 0x55]).unwrap();
        let input = format!("@{}", path.display());
        let exp = expand(&input, DEFAULT_BUDGET_BYTES);
        assert!(exp.prompt.contains("binary attachment"));
    }

    #[test]
    fn detect_language_known_extensions() {
        assert_eq!(detect_language(Path::new("a.rs")), "rust");
        assert_eq!(detect_language(Path::new("a.py")), "python");
        assert_eq!(detect_language(Path::new("a.unknown")), "");
        assert_eq!(detect_language(Path::new("Cargo.toml")), "toml");
    }
}
