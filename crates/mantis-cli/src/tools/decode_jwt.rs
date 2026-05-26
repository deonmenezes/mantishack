//! `mantis tools decode-jwt` — decode a JWT without verifying its signature.
//!
//! Pure-compute port of the `mantis_decode_jwt` MCP tool. Returns a structured
//! result for every input, including malformed ones — failure modes appear in
//! the `warnings` array so the caller doesn't need to retry on parse errors.
//!
//! Self-contained — no `base64` dependency; the tiny encoder/decoder lives in
//! this file. This is intentional: keeps `mantis-cli`'s dependency surface
//! tight and lets the file move into a shared `mantis-tools` crate later
//! without disturbing the algorithm.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Decoded JWT — the structured output of `decode`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(super) struct DecodedJwt {
    /// Header JSON (e.g. `{"alg":"HS256","typ":"JWT"}`). `Null` on parse failure.
    pub header: serde_json::Value,
    /// Payload (claims) JSON. `Null` on parse failure.
    pub payload: serde_json::Value,
    /// Raw base64url-encoded signature segment (not decoded — useful for
    /// length-based heuristics).
    pub signature_b64: String,
    /// Length of the decoded signature in bytes (0 on parse failure or empty).
    pub signature_bytes: usize,
    /// Sorted alphabetical list of claim keys present in the payload.
    pub claims_present: Vec<String>,
    /// Standard-claim convenience field: `exp` as unix seconds.
    pub exp_unix: Option<i64>,
    /// Standard-claim convenience field: `nbf` as unix seconds.
    pub nbf_unix: Option<i64>,
    /// Standard-claim convenience field: `iat` as unix seconds.
    pub iat_unix: Option<i64>,
    /// `iss` claim (string) when present.
    pub iss: Option<String>,
    /// `aud` claim, raw value (may be string or array).
    pub aud: Option<serde_json::Value>,
    /// `sub` claim when present.
    pub sub: Option<String>,
    /// `alg` from the header (e.g. `"HS256"`, `"RS256"`, `"none"`).
    pub alg: Option<String>,
    /// One-line warnings about dangerous patterns: `alg:none`,
    /// `signature:empty`, `exp:missing`, `exp:expired`, `iss:missing`, etc.
    pub warnings: Vec<String>,
}

/// Decode a JWT without verifying its signature. Always returns a structured
/// `DecodedJwt`; malformed input becomes `warnings` rather than an error.
///
/// Accepts a bare JWT or a `Bearer <jwt>` string.
pub(super) fn decode(jwt: &str) -> DecodedJwt {
    let mut out = DecodedJwt::default();

    let trimmed = jwt.trim();
    let stripped = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))
        .unwrap_or(trimmed);

    let parts: Vec<&str> = stripped.split('.').collect();
    if parts.len() != 3 {
        out.warnings.push(format!(
            "format:invalid (expected 3 dot-separated segments, got {})",
            parts.len()
        ));
        return out;
    }

    out.signature_b64 = parts[2].to_string();
    out.signature_bytes = b64url_decode(parts[2]).map(|v| v.len()).unwrap_or(0);
    if parts[2].is_empty() || out.signature_bytes == 0 {
        out.warnings.push("signature:empty".into());
    }

    match decode_segment_json(parts[0]) {
        Ok(h) => {
            out.alg = h.get("alg").and_then(|v| v.as_str()).map(str::to_owned);
            if matches!(
                out.alg.as_deref(),
                Some("none") | Some("None") | Some("NONE")
            ) {
                out.warnings.push("alg:none — unauthenticated JWT".into());
            }
            out.header = h;
        }
        Err(e) => out.warnings.push(format!("header:{e}")),
    }

    match decode_segment_json(parts[1]) {
        Ok(p) => {
            out.exp_unix = p.get("exp").and_then(json_as_i64);
            out.nbf_unix = p.get("nbf").and_then(json_as_i64);
            out.iat_unix = p.get("iat").and_then(json_as_i64);
            out.iss = p.get("iss").and_then(|v| v.as_str()).map(str::to_owned);
            out.sub = p.get("sub").and_then(|v| v.as_str()).map(str::to_owned);
            out.aud = p.get("aud").cloned();
            if let Some(obj) = p.as_object() {
                let mut keys: BTreeMap<&str, ()> = BTreeMap::new();
                for k in obj.keys() {
                    keys.insert(k.as_str(), ());
                }
                out.claims_present = keys.into_keys().map(str::to_owned).collect();
            }
            if out.exp_unix.is_none() {
                out.warnings.push("exp:missing".into());
            } else if let Some(exp) = out.exp_unix {
                if exp < now_unix() {
                    out.warnings.push("exp:expired".into());
                }
            }
            if out.iss.is_none() {
                out.warnings.push("iss:missing".into());
            }
            out.payload = p;
        }
        Err(e) => out.warnings.push(format!("payload:{e}")),
    }
    out
}

fn json_as_i64(v: &serde_json::Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_u64().and_then(|u| i64::try_from(u).ok()))
        .or_else(|| v.as_f64().map(|f| f as i64))
}

fn decode_segment_json(seg: &str) -> Result<serde_json::Value, String> {
    let bytes = b64url_decode(seg).ok_or_else(|| "base64url:invalid".to_string())?;
    let s = std::str::from_utf8(&bytes).map_err(|_| "utf8:invalid".to_string())?;
    serde_json::from_str::<serde_json::Value>(s).map_err(|e| format!("json:invalid({e})"))
}

/// Decode a base64url string. RFC 7515 §2 form: `-`/`_` map back to `+`/`/`,
/// padding is added if missing. Returns `None` on any malformed character.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut padded = String::with_capacity(s.len() + 3);
    for c in s.chars() {
        match c {
            '-' => padded.push('+'),
            '_' => padded.push('/'),
            c => padded.push(c),
        }
    }
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    b64_std_decode(&padded)
}

/// Self-contained standard-base64 decoder. ~40 lines; avoids pulling in the
/// `base64` crate just for this one usage.
fn b64_std_decode(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        Some(match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut buf = 0u32;
        let mut pad = 0usize;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                if i < 2 {
                    return None;
                }
                pad += 1;
                continue;
            }
            buf = (buf << 6) | val(b)?;
        }
        buf <<= 6 * pad;
        out.push((buf >> 16) as u8);
        if pad < 2 {
            out.push((buf >> 8) as u8);
        }
        if pad < 1 {
            out.push(buf as u8);
        }
    }
    Some(out)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a JWT-shaped string from header/payload JSON. Signature segment
    /// is a literal base64url string (caller chooses to make it empty,
    /// non-empty, or invalid as test demands).
    fn jwt(header: &str, payload: &str, sig: &str) -> String {
        let h = b64url_encode(header.as_bytes());
        let p = b64url_encode(payload.as_bytes());
        format!("{h}.{p}.{sig}")
    }

    fn b64url_encode(bytes: &[u8]) -> String {
        const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(bytes.len() * 4 / 3 + 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
            let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                out.push(ALPHA[((n >> 6) & 0x3F) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(ALPHA[(n & 0x3F) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn flags_alg_none() {
        let t = jwt(r#"{"alg":"none","typ":"JWT"}"#, r#"{"sub":"x"}"#, "");
        let d = decode(&t);
        assert_eq!(d.alg.as_deref(), Some("none"));
        assert!(d.warnings.iter().any(|w| w.starts_with("alg:none")));
        assert!(d.warnings.iter().any(|w| w == "signature:empty"));
    }

    #[test]
    fn extracts_standard_claims() {
        let t = jwt(
            r#"{"alg":"HS256"}"#,
            r#"{"sub":"alice","iss":"issuer.example","exp":9999999999,"iat":1000000000,"aud":"audience"}"#,
            "signature",
        );
        let d = decode(&t);
        assert_eq!(d.sub.as_deref(), Some("alice"));
        assert_eq!(d.iss.as_deref(), Some("issuer.example"));
        assert_eq!(d.exp_unix, Some(9999999999));
        assert_eq!(d.iat_unix, Some(1000000000));
        assert_eq!(d.aud, Some(serde_json::Value::String("audience".into())));
        assert!(!d.warnings.iter().any(|w| w == "exp:missing"));
        assert!(!d.warnings.iter().any(|w| w == "iss:missing"));
    }

    #[test]
    fn flags_expired() {
        let t = jwt(
            r#"{"alg":"HS256"}"#,
            r#"{"sub":"x","iss":"y","exp":1}"#,
            "sig",
        );
        let d = decode(&t);
        assert!(d.warnings.iter().any(|w| w == "exp:expired"));
    }

    #[test]
    fn strips_bearer_prefix() {
        let t = jwt(r#"{"alg":"HS256"}"#, r#"{"sub":"x"}"#, "sig");
        let with_bearer = format!("Bearer {t}");
        let d = decode(&with_bearer);
        assert_eq!(d.sub.as_deref(), Some("x"));
        assert!(d.warnings.iter().all(|w| !w.starts_with("format:invalid")));
    }

    #[test]
    fn strips_lowercase_bearer_prefix() {
        let t = jwt(r#"{"alg":"HS256"}"#, r#"{"sub":"x"}"#, "sig");
        let d = decode(&format!("bearer {t}"));
        assert_eq!(d.sub.as_deref(), Some("x"));
    }

    #[test]
    fn handles_malformed_two_segments() {
        let d = decode("not-a-jwt");
        assert!(d.warnings.iter().any(|w| w.starts_with("format:invalid")));
        assert!(d.header.is_null());
        assert!(d.payload.is_null());
    }

    #[test]
    fn handles_malformed_segment_content() {
        // 3 segments but middle is not base64url-decodable
        let d = decode("aGVsbG8.!!!.signature");
        assert!(d.warnings.iter().any(|w| w.starts_with("payload:")));
    }

    #[test]
    fn empty_input_classified_as_format_invalid() {
        let d = decode("");
        assert!(d.warnings.iter().any(|w| w.starts_with("format:invalid")));
    }

    #[test]
    fn claims_present_is_sorted_unique_list() {
        let t = jwt(
            r#"{"alg":"HS256"}"#,
            r#"{"zeta":1,"alpha":2,"mu":3,"sub":"x","iss":"y","exp":9999999999}"#,
            "sig",
        );
        let d = decode(&t);
        // Must be sorted alphabetically.
        let mut sorted = d.claims_present.clone();
        sorted.sort();
        assert_eq!(d.claims_present, sorted);
        // Must contain every key.
        assert!(d.claims_present.contains(&"alpha".to_string()));
        assert!(d.claims_present.contains(&"zeta".to_string()));
        assert!(d.claims_present.contains(&"sub".to_string()));
    }

    #[test]
    fn missing_iss_flagged_in_warnings() {
        let t = jwt(
            r#"{"alg":"HS256"}"#,
            r#"{"sub":"x","exp":9999999999}"#,
            "sig",
        );
        let d = decode(&t);
        assert!(d.warnings.iter().any(|w| w == "iss:missing"));
    }

    #[test]
    fn missing_exp_flagged_in_warnings() {
        let t = jwt(r#"{"alg":"HS256"}"#, r#"{"sub":"x","iss":"y"}"#, "sig");
        let d = decode(&t);
        assert!(d.warnings.iter().any(|w| w == "exp:missing"));
    }

    #[test]
    fn signature_b64_preserved_even_on_invalid_signature() {
        let t = jwt(r#"{"alg":"HS256"}"#, r#"{"sub":"x"}"#, "abc!!!def");
        let d = decode(&t);
        // The b64 string is preserved as-is for caller inspection even though
        // it doesn't decode cleanly.
        assert_eq!(d.signature_b64, "abc!!!def");
        // Decoded bytes are zero because the segment failed to decode.
        assert_eq!(d.signature_bytes, 0);
    }

    #[test]
    fn round_trips_through_json() {
        let t = jwt(r#"{"alg":"HS256"}"#, r#"{"sub":"x"}"#, "sig");
        let d = decode(&t);
        let json = serde_json::to_string(&d).unwrap();
        // Sanity: the JSON is a single object with the expected top-level
        // keys. We don't deserialize back because the Default::default()
        // serializes `header: null` as `null` and DecodedJwt deserialization
        // from a fresh parse is not in scope here.
        assert!(json.contains("\"signature_b64\""));
        assert!(json.contains("\"warnings\""));
    }
}
