//! Filesystem and `$PATH` probes used by every adapter.
//!
//! Kept private to the crate — no external crate should depend on these
//! details directly. The functions are intentionally narrow so they're
//! easy to override under test by an `EnvProbe` injection if needed
//! later.

use std::path::{Path, PathBuf};

/// Walk `$PATH` looking for an executable named `name`. Returns the first
/// hit or `None` if not found / `$PATH` is unset.
pub(crate) fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// `$HOME` resolved via the same env var the installer uses. Returns
/// `None` when running in a context that has no home directory.
pub(crate) fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Convenience: build a path under `$HOME` if `HOME` is set.
pub(crate) fn home_join(parts: &[&str]) -> Option<PathBuf> {
    let mut p = home_dir()?;
    for part in parts {
        p.push(part);
    }
    Some(p)
}

/// Returns the path if it exists, otherwise `None`. Bridges `Option` and
/// `Path::exists` for cleaner adapter code.
pub(crate) fn exists(p: PathBuf) -> Option<PathBuf> {
    if p.exists() {
        Some(p)
    } else {
        None
    }
}
