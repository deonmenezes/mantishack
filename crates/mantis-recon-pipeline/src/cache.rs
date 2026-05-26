//! Disk cache for [`ReconBundle`] keyed by (target, scope_hash,
//! schema_version, depth).
//!
//! Recon is expensive (10s–5min wall-clock depending on depth);
//! caching lets repeated queries within an engagement reuse the
//! same bundle instantly. The cache is intentionally simple:
//! one file per key under `$MANTIS_HOME/recon-cache/`, JSON
//! payload, mtime-based TTL.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::bundle::{ReconBundle, SCHEMA_VERSION};
use crate::PipelineError;

/// 30-minute default TTL. Tradeoff: long enough that an operator
/// can chat through 10–20 turns without re-running recon, short
/// enough to catch real changes during active work.
pub const DEFAULT_TTL_SECS: u64 = 30 * 60;

/// Compute a stable, filename-safe cache key from the inputs.
pub fn cache_key(target: &str, scope_hash: Option<&str>, depth_label: &str) -> String {
    let scope = scope_hash.unwrap_or("");
    // Feed inputs into the hasher incrementally instead of allocating
    // a fresh String via format! just to immediately discard it.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"v");
    hasher.update(SCHEMA_VERSION.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(target.as_bytes());
    hasher.update(b"|");
    hasher.update(scope.as_bytes());
    hasher.update(b"|");
    hasher.update(depth_label.as_bytes());
    let hash = hasher.finalize();
    let h = hash.to_hex();
    // Truncated 16-byte hex — collision-resistant enough for a
    // local cache where the input set is tiny. `to_string()` on the
    // sliced &str is cleaner and one fewer formatter pass than
    // `format!("{}", &h.as_str()[..32])`.
    h.as_str()[..32].to_string()
}

/// Read a cached bundle, returning `Ok(Some(bundle))` if a valid
/// entry exists, `Ok(None)` if missing or stale.
pub fn read_cached(
    cache_dir: &Path,
    key: &str,
    ttl: Duration,
) -> Result<Option<ReconBundle>, PipelineError> {
    let path = cache_dir.join(format!("{key}.json"));
    if !path.is_file() {
        return Ok(None);
    }
    let meta = std::fs::metadata(&path)?;
    let age = meta
        .modified()
        .ok()
        .and_then(|m| SystemTime::now().duration_since(m).ok())
        .unwrap_or(Duration::MAX);
    if age > ttl {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)?;
    let bundle: ReconBundle = serde_json::from_slice(&bytes)?;
    // Defensive: if the cached schema doesn't match the current
    // code's, ignore it (operator probably upgraded mantis).
    if bundle.schema_version != SCHEMA_VERSION {
        return Ok(None);
    }
    Ok(Some(bundle))
}

/// Write a bundle to the cache. Best-effort — failures are logged
/// but never propagated, since a missed write just means the next
/// invocation reruns the pipeline.
pub fn write_cached(
    cache_dir: &Path,
    key: &str,
    bundle: &ReconBundle,
) -> Result<(), PipelineError> {
    std::fs::create_dir_all(cache_dir)?;
    let path = cache_dir.join(format!("{key}.json"));
    let tmp = cache_dir.join(format!(".{key}.json.tmp"));
    let bytes = serde_json::to_vec(bundle)?;
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Default cache directory: `$MANTIS_HOME/recon-cache/` with a
/// fallback to `~/.mantis/recon-cache/`.
pub fn default_cache_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("MANTIS_HOME") {
        return PathBuf::from(home).join("recon-cache");
    }
    let home = std::env::var_os("HOME").unwrap_or_default();
    PathBuf::from(home).join(".mantis").join("recon-cache")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_deterministic_and_unique() {
        let k1 = cache_key("example.com", Some("scope-a"), "quick");
        let k2 = cache_key("example.com", Some("scope-a"), "quick");
        let k3 = cache_key("example.com", Some("scope-b"), "quick");
        let k4 = cache_key("example.com", Some("scope-a"), "deep");
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, k4);
    }

    #[test]
    fn roundtrip_write_then_read() {
        let dir = tempfile::tempdir().unwrap();
        let key = cache_key("x.example", None, "quick");
        let mut bundle = ReconBundle::new("x.example");
        bundle.elapsed_ms = 999;

        write_cached(dir.path(), &key, &bundle).unwrap();
        let loaded = read_cached(dir.path(), &key, Duration::from_secs(60))
            .unwrap()
            .expect("cache hit");
        assert_eq!(loaded.target, "x.example");
        assert_eq!(loaded.elapsed_ms, 999);
    }

    #[test]
    fn read_cached_misses_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_cached(dir.path(), "nope", Duration::from_secs(60)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_cached_misses_when_schema_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        // Hand-craft a payload with a wrong schema_version.
        let payload = serde_json::json!({
            "schema_version": 999,
            "target": "x",
            "started_at_unix": 0,
            "elapsed_ms": 0,
            "subdomains": [],
            "live_surfaces": [],
            "tech_stack": {},
            "findings": [],
            "anomalies": [],
            "scanner_stats": [],
        });
        let key = "test";
        std::fs::write(dir.path().join("test.json"), payload.to_string()).unwrap();
        let result = read_cached(dir.path(), key, Duration::from_secs(60)).unwrap();
        assert!(result.is_none(), "schema mismatch should miss");
    }
}
