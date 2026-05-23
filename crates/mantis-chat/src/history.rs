//! Append-only JSONL history for a chat conversation.
//!
//! One line per [`ChatMessage`]. The file is opened in append mode
//! on construction and flushed after every append so a crash mid-
//! session preserves prior turns. Loading is a streaming read of
//! all lines — turn-level granularity, no compaction.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use mantis_synthesizer::ChatMessage;

/// Append-only JSONL log of a conversation. Constructed via
/// [`HistoryFile::open`]; callers `append` after each message
/// they want persisted.
pub struct HistoryFile {
    path: PathBuf,
    writer: BufWriter<File>,
}

impl HistoryFile {
    /// Open (or create) the history file at `path`. Parent
    /// directories are created if missing.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            writer: BufWriter::new(file),
        })
    }

    /// Append one message as a single JSON line. Flushes to disk
    /// before returning so a crash on the next instruction still
    /// preserves the write.
    pub fn append(&mut self, message: &ChatMessage) -> std::io::Result<()> {
        let line = serde_json::to_string(message)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read every message from a history file. Lines that fail to
    /// parse are skipped with a warning to stderr — partial reads
    /// are preferred over hard failure on a corrupted suffix.
    pub fn load(path: &Path) -> std::io::Result<Vec<ChatMessage>> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(path)?;
        let mut out = Vec::new();
        for (i, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<ChatMessage>(&line) {
                Ok(m) => out.push(m),
                Err(e) => {
                    eprintln!(
                        "[mantis-chat] skipping corrupted history line {} in {}: {e}",
                        i + 1,
                        path.display()
                    );
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantis_synthesizer::ChatMessage;

    #[test]
    fn roundtrip_append_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.jsonl");
        {
            let mut h = HistoryFile::open(&path).unwrap();
            h.append(&ChatMessage::system("sys")).unwrap();
            h.append(&ChatMessage::user("hello")).unwrap();
            h.append(&ChatMessage::assistant("hi back")).unwrap();
        }
        let loaded = HistoryFile::load(&path).unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[1].content, "hello");
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.jsonl");
        let loaded = HistoryFile::load(&path).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn load_tolerates_corrupted_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.jsonl");
        std::fs::write(
            &path,
            "{\"role\":\"user\",\"content\":\"ok\"}\n{not json}\n{\"role\":\"assistant\",\"content\":\"still parses\"}\n",
        )
        .unwrap();
        let loaded = HistoryFile::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].content, "ok");
        assert_eq!(loaded[1].content, "still parses");
    }

    #[test]
    fn open_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/sub/chat.jsonl");
        let mut h = HistoryFile::open(&path).unwrap();
        h.append(&ChatMessage::user("x")).unwrap();
        assert!(path.exists());
    }
}
