//! Shannon-entropy-based detection for high-entropy tokens that
//! didn't match a named rule.
//!
//! Algorithm:
//! 1. Walk the input character-by-character.
//! 2. Whenever we hit a contiguous run of `[A-Za-z0-9+/=_\-]`
//!    (base64 / base64url charset) of length ≥ [`MIN_LEN`] and
//!    ≤ [`MAX_LEN`], compute its Shannon entropy.
//! 3. If entropy ≥ `threshold` and the candidate doesn't look like a
//!    well-known non-secret structure (uuid, sha hash, build id),
//!    emit a finding.

use crate::{SecretFinding, Severity};

/// Minimum token length for entropy detection. Anything shorter is
/// drowned out by false positives.
pub const MIN_LEN: usize = 24;

/// Maximum token length. Beyond this we cap to avoid catching
/// embedded blobs (sourcemaps, base64-ed images, JWT bodies).
pub const MAX_LEN: usize = 256;

/// Walk `text` and return one finding per high-entropy contiguous
/// run that doesn't look like a known non-secret structure.
pub fn scan(text: &str, threshold: f64) -> Vec<SecretFinding> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !is_secret_char(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_secret_char(bytes[i]) {
            i += 1;
        }
        let end = i;
        let len = end - start;
        if !(MIN_LEN..=MAX_LEN).contains(&len) {
            continue;
        }
        let token = &text[start..end];
        if looks_like_non_secret(token) {
            continue;
        }
        let h = shannon_entropy(token);
        if h < threshold {
            continue;
        }
        out.push(SecretFinding {
            rule_id: "entropy-high".into(),
            description: "High-entropy token (possible secret)".into(),
            severity: Severity::Medium,
            matched: token.to_string(),
            offset: start,
            source: None,
        });
    }
    out
}

fn is_secret_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=' || c == b'_' || c == b'-'
}

/// Precomputed `c * log2(c)` for c in [0, MAX_LEN]. Lets
/// [`shannon_entropy`] avoid all transcendental calls in the inner
/// loop on inputs ≤ MAX_LEN bytes — which is the entire callable
/// range of the entropy scanner.
///
/// Identity used:
///
/// ```text
/// H = -Σ p_i log2(p_i)
///   = log2(N) - (1/N) Σ c_i log2(c_i)
/// ```
///
/// where `c_i` is the count of byte `i` and `N` is the total length.
/// So we need one `log2(N)` per call plus a table lookup per
/// non-zero bucket — no other transcendentals.
static C_LOG2_C: std::sync::LazyLock<[f64; MAX_LEN + 1]> = std::sync::LazyLock::new(|| {
    let mut t = [0.0f64; MAX_LEN + 1];
    for c in 1..=MAX_LEN {
        t[c] = (c as f64) * (c as f64).log2();
    }
    t
});

/// Shannon entropy in bits/char.
///
/// Uses the [`C_LOG2_C`] lookup table to avoid per-byte log2 calls in
/// the hot path. For inputs longer than [`MAX_LEN`] (which the scanner
/// never produces, but `pub fn` callers might), falls back to the
/// direct computation.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len();
    let len = n as f64;
    if n <= MAX_LEN {
        // Hot path: c_i log2(c_i) via lookup. One log2 call total.
        let mut sum_c_log2_c = 0.0;
        for &c in counts.iter() {
            if c != 0 {
                sum_c_log2_c += C_LOG2_C[c as usize];
            }
        }
        return len.log2() - sum_c_log2_c / len;
    }
    // Cold fallback for over-long inputs.
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

/// Cheap structural disqualifiers — fast paths to skip strings that
/// match common high-entropy non-secrets.
fn looks_like_non_secret(s: &str) -> bool {
    // UUID v4: 8-4-4-4-12 hex with dashes. Without dashes, length
    // is exactly 32 and chars are all [0-9a-f]. We catch the dashed
    // form trivially (it can't reach is_secret_char because of `-`
    // being included, so we should explicitly check).
    if is_uuid(s) {
        return true;
    }
    // SHA-1 (40 lowercase hex) / SHA-256 (64 lowercase hex) — common
    // in source maps + git commit IDs.
    if is_lowercase_hex(s) && (s.len() == 40 || s.len() == 64 || s.len() == 32) {
        return true;
    }
    // CSS module hashes, Vite/Webpack chunk IDs often look like
    // alnum-with-dash and are mostly digits. If digit density > 60%,
    // probably a content-hash, not a secret.
    let digits = s.bytes().filter(|c| c.is_ascii_digit()).count();
    if s.len() >= 8 && digits * 100 / s.len() >= 60 {
        return true;
    }
    // All-uppercase + digits at exactly 32 chars — looks like an
    // MD5 in upper-case form.
    if s.len() == 32 && s.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return true;
    }
    // JWT payload segments — start with `eyJ` (`{"...`). Caught by
    // the JWT rule; suppress here to avoid duplicates.
    if s.starts_with("eyJ") {
        return true;
    }
    false
}

fn is_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                if !(b.is_ascii_hexdigit()) {
                    return false;
                }
            }
        }
    }
    true
}

fn is_lowercase_hex(s: &str) -> bool {
    s.bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_entropy_of_uniform_input_is_high() {
        // A 64-char run with all 64 distinct base64 chars
        // should reach log2(64) = 6.0 bits/char.
        let s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let h = shannon_entropy(s);
        assert!(h > 5.5, "expected high entropy, got {}", h);
    }

    #[test]
    fn shannon_entropy_of_repeated_char_is_zero() {
        assert_eq!(shannon_entropy("aaaaaaaaaa"), 0.0);
    }

    #[test]
    fn detects_a_high_entropy_token() {
        let body = "context=zX7Q2Lk9TmA8sR4VnJ6BcW1F3dEYpUgHkMrLqZvNxOiKj9";
        let f = scan(body, 4.5);
        assert!(!f.is_empty());
        assert_eq!(f[0].rule_id, "entropy-high");
    }

    #[test]
    fn ignores_uuid() {
        let body = "id=550e8400-e29b-41d4-a716-446655440000";
        let f = scan(body, 4.0);
        assert!(f.is_empty(), "got {:?}", f);
    }

    #[test]
    fn ignores_sha1_and_sha256() {
        let sha1 = "abf12f7c8d9e3a4b5c6d7e8f9012345678abcdef";
        let sha256 = "abc123def456abc123def456abc123def456abc123def456abc123def4567890";
        for s in [sha1, sha256] {
            assert!(scan(s, 4.0).is_empty(), "should ignore {}", s);
        }
    }

    #[test]
    fn ignores_jwt_payload_segments() {
        let s = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9aaaaaaaaaaaaaaaaaa";
        assert!(scan(s, 4.0).is_empty());
    }

    #[test]
    fn ignores_short_tokens_below_min_len() {
        let s = "abc123XYZ"; // 9 chars
        assert!(scan(s, 3.0).is_empty());
    }

    #[test]
    fn handles_empty_input() {
        assert!(scan("", 4.5).is_empty());
    }

    #[test]
    fn finds_multiple_distinct_tokens() {
        let s = "first=zXq7Lk9TmA8sR4VnJ6BcW1F3dEYpUgHkMrLqZvNxOiKj second=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789xY";
        let f = scan(s, 4.5);
        assert!(f.len() >= 2, "got {:?}", f);
    }

    #[test]
    fn skips_digit_heavy_chunk_hashes() {
        // 80% digits — likely a Vite/Webpack content hash, not a secret.
        let s = "12345678901234567890abc1234567890";
        assert!(scan(s, 3.0).is_empty());
    }
}
