//! Per-parameter fuzz seed generator.
//!
//! Given an [`ApiParameter`], emit a set of [`SeedInput`]s grounded
//! in the parameter's declared type. The output mixes:
//! - typed valid values (so positive control responses exist)
//! - typed boundary values (max int, min int, empty string, …)
//! - cross-type confusion (string where int is expected, etc.)
//! - vulnerability-class polyglots from [`mantis_payloads`] for the
//!   relevant class
//!
//! Keep the output small: 8–20 inputs per parameter typically
//! suffices, and the rest of the pipeline can chain `mantis-fuzzer`
//! for deeper coverage.

use crate::openapi::{ApiParameter, ParameterType};
use mantis_payloads::{for_category, PayloadCategory};
use serde::{Deserialize, Serialize};

/// `Deserialize` is intentionally omitted: `label` is a `&'static`
/// constant from the generator. Downstream code that needs to round-
/// trip a seed list should convert via [`SeedInput::to_owned`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeedInput {
    pub value: String,
    pub label: &'static str,
}

impl SeedInput {
    /// Convert to an owned representation suitable for serde
    /// round-trips.
    pub fn into_owned(self) -> OwnedSeedInput {
        OwnedSeedInput {
            value: self.value,
            label: self.label.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedSeedInput {
    pub value: String,
    pub label: String,
}

/// Generate seeds for one parameter. Returns at most ~20 inputs.
pub fn seeds_for(param: &ApiParameter) -> Vec<SeedInput> {
    let mut out = Vec::new();
    typed_seeds(param.typ, &mut out);
    cross_type_seeds(param.typ, &mut out);
    polyglot_seeds(param.typ, &mut out);

    // Dedupe by value, preserving first label.
    let mut seen = std::collections::BTreeSet::new();
    out.retain(|s| seen.insert(s.value.clone()));
    out.truncate(20);
    out
}

fn typed_seeds(t: ParameterType, out: &mut Vec<SeedInput>) {
    match t {
        ParameterType::Integer => {
            out.push(SeedInput {
                value: "0".into(),
                label: "int-zero",
            });
            out.push(SeedInput {
                value: "1".into(),
                label: "int-one",
            });
            out.push(SeedInput {
                value: "-1".into(),
                label: "int-neg-one",
            });
            out.push(SeedInput {
                value: i64::MAX.to_string(),
                label: "int-max-i64",
            });
            out.push(SeedInput {
                value: i64::MIN.to_string(),
                label: "int-min-i64",
            });
        }
        ParameterType::Number => {
            out.push(SeedInput {
                value: "0".into(),
                label: "num-zero",
            });
            out.push(SeedInput {
                value: "3.14".into(),
                label: "num-decimal",
            });
            out.push(SeedInput {
                value: "1e308".into(),
                label: "num-near-max-f64",
            });
            out.push(SeedInput {
                value: "NaN".into(),
                label: "num-nan",
            });
            out.push(SeedInput {
                value: "Infinity".into(),
                label: "num-inf",
            });
        }
        ParameterType::Boolean => {
            for (v, l) in [
                ("true", "bool-true"),
                ("false", "bool-false"),
                ("1", "bool-1"),
                ("0", "bool-0"),
            ] {
                out.push(SeedInput {
                    value: v.into(),
                    label: l,
                });
            }
        }
        ParameterType::Uuid => {
            out.push(SeedInput {
                value: "00000000-0000-0000-0000-000000000000".into(),
                label: "uuid-nil",
            });
            out.push(SeedInput {
                value: "ffffffff-ffff-ffff-ffff-ffffffffffff".into(),
                label: "uuid-max",
            });
            out.push(SeedInput {
                value: "550e8400-e29b-41d4-a716-446655440000".into(),
                label: "uuid-valid",
            });
        }
        ParameterType::DateTime => {
            out.push(SeedInput {
                value: "1970-01-01T00:00:00Z".into(),
                label: "datetime-epoch",
            });
            out.push(SeedInput {
                value: "9999-12-31T23:59:59Z".into(),
                label: "datetime-far-future",
            });
            out.push(SeedInput {
                value: "0000-00-00T00:00:00Z".into(),
                label: "datetime-invalid",
            });
        }
        ParameterType::Email => {
            out.push(SeedInput {
                value: "a@b.co".into(),
                label: "email-shortest",
            });
            out.push(SeedInput {
                value: "test+plus@example.com".into(),
                label: "email-with-plus",
            });
            out.push(SeedInput {
                value: "\"x\"@example.com".into(),
                label: "email-quoted-local",
            });
        }
        ParameterType::String => {
            out.push(SeedInput {
                value: "".into(),
                label: "str-empty",
            });
            out.push(SeedInput {
                value: "a".into(),
                label: "str-short",
            });
            out.push(SeedInput {
                value: "A".repeat(4096),
                label: "str-overlong",
            });
            out.push(SeedInput {
                value: "\u{0}\u{0}\u{0}".into(),
                label: "str-null-bytes",
            });
            out.push(SeedInput {
                value: "ünïcödë".into(),
                label: "str-unicode",
            });
        }
        ParameterType::Array | ParameterType::Object | ParameterType::Unknown => {
            // Cross-type seeds handle these.
        }
    }
}

fn cross_type_seeds(t: ParameterType, out: &mut Vec<SeedInput>) {
    // For every type, try the "wrong shape" inputs that most often
    // trigger parser bugs.
    match t {
        ParameterType::Integer | ParameterType::Number => {
            out.push(SeedInput {
                value: "not-a-number".into(),
                label: "cross-string-where-num",
            });
            out.push(SeedInput {
                value: "null".into(),
                label: "cross-null-where-num",
            });
        }
        ParameterType::Boolean => {
            out.push(SeedInput {
                value: "maybe".into(),
                label: "cross-string-where-bool",
            });
        }
        ParameterType::Uuid => {
            out.push(SeedInput {
                value: "1".into(),
                label: "cross-int-where-uuid",
            });
            out.push(SeedInput {
                value: "00000000-0000-0000-0000-00000000000".into(),
                label: "cross-uuid-short-one",
            });
        }
        _ => {
            out.push(SeedInput {
                value: "1".into(),
                label: "cross-int-default",
            });
            out.push(SeedInput {
                value: "true".into(),
                label: "cross-bool-default",
            });
        }
    }
}

fn polyglot_seeds(t: ParameterType, out: &mut Vec<SeedInput>) {
    // For string-shaped params, include one payload from each
    // relevant injection class. For non-strings we skip — those
    // checks happen at the verifier layer instead.
    if !matches!(
        t,
        ParameterType::String | ParameterType::Email | ParameterType::Unknown
    ) {
        return;
    }
    for cat in [
        PayloadCategory::Sqli,
        PayloadCategory::Xss,
        PayloadCategory::Ssti,
        PayloadCategory::Cmdi,
        PayloadCategory::OpenRedirect,
    ] {
        if let Some(p) = for_category(cat).first() {
            out.push(SeedInput {
                value: p.value.to_string(),
                label: leaked_label(cat),
            });
        }
    }
}

fn leaked_label(cat: PayloadCategory) -> &'static str {
    match cat {
        PayloadCategory::Sqli => "payload-sqli",
        PayloadCategory::Xss => "payload-xss",
        PayloadCategory::Ssti => "payload-ssti",
        PayloadCategory::Cmdi => "payload-cmdi",
        PayloadCategory::OpenRedirect => "payload-open-redirect",
        PayloadCategory::Ssrf => "payload-ssrf",
        PayloadCategory::Lfi => "payload-lfi",
        PayloadCategory::Xxe => "payload-xxe",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openapi::ParameterIn;

    fn p(typ: ParameterType) -> ApiParameter {
        ApiParameter {
            name: "x".into(),
            location: ParameterIn::Query,
            required: false,
            typ,
            example: None,
        }
    }

    #[test]
    fn integer_seeds_include_zero_one_and_extremes() {
        let s = seeds_for(&p(ParameterType::Integer));
        let values: Vec<&str> = s.iter().map(|x| x.value.as_str()).collect();
        assert!(values.contains(&"0"));
        assert!(values.contains(&"1"));
        assert!(values.iter().any(|v| v.contains(&i64::MAX.to_string())));
    }

    #[test]
    fn uuid_seeds_include_nil_and_valid() {
        let s = seeds_for(&p(ParameterType::Uuid));
        let values: Vec<&str> = s.iter().map(|x| x.value.as_str()).collect();
        assert!(values.contains(&"00000000-0000-0000-0000-000000000000"));
        assert!(values.contains(&"550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn string_seeds_include_empty_overlong_and_polyglots() {
        let s = seeds_for(&p(ParameterType::String));
        assert!(s.iter().any(|x| x.value.is_empty()));
        assert!(s.iter().any(|x| x.value.len() >= 4096));
        // Includes at least one payload polyglot.
        assert!(s.iter().any(|x| x.label.starts_with("payload-")));
    }

    #[test]
    fn boolean_seeds_include_zero_and_one() {
        let s = seeds_for(&p(ParameterType::Boolean));
        let values: Vec<&str> = s.iter().map(|x| x.value.as_str()).collect();
        assert!(values.contains(&"true"));
        assert!(values.contains(&"false"));
        assert!(values.contains(&"1"));
        assert!(values.contains(&"0"));
    }

    #[test]
    fn cross_type_seeds_for_int_include_string() {
        let s = seeds_for(&p(ParameterType::Integer));
        assert!(s.iter().any(|x| x.value == "not-a-number"));
    }

    #[test]
    fn seed_count_capped_at_twenty() {
        let s = seeds_for(&p(ParameterType::String));
        assert!(s.len() <= 20);
    }

    #[test]
    fn seeds_deduplicate_by_value() {
        // String + Email both include "a@b.co" implicitly through
        // payloads — verify no duplicates regardless.
        let s = seeds_for(&p(ParameterType::String));
        let mut values: Vec<&str> = s.iter().map(|x| x.value.as_str()).collect();
        values.sort_unstable();
        let pre = values.len();
        values.dedup();
        assert_eq!(pre, values.len());
    }

    #[test]
    fn unknown_type_still_returns_some_seeds() {
        let s = seeds_for(&p(ParameterType::Unknown));
        assert!(!s.is_empty());
    }

    #[test]
    fn array_type_returns_seeds_from_cross_and_polyglot() {
        let s = seeds_for(&p(ParameterType::Array));
        // Should at least include the cross-type defaults.
        assert!(s.iter().any(|x| x.value == "1" || x.value == "true"));
    }

    #[test]
    fn seed_input_serializes() {
        let v = SeedInput {
            value: "x".into(),
            label: "test",
        };
        let j = serde_json::to_string(&v).unwrap();
        assert!(j.contains("test"));
        assert!(j.contains("\"value\":\"x\""));
    }

    #[test]
    fn owned_seed_input_round_trips_through_serde() {
        let v = SeedInput {
            value: "x".into(),
            label: "test",
        }
        .into_owned();
        let j = serde_json::to_string(&v).unwrap();
        let back: OwnedSeedInput = serde_json::from_str(&j).unwrap();
        assert_eq!(v, back);
    }
}
