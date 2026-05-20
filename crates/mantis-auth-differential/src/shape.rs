//! Response-shape signature.
//!
//! We do NOT compare raw response bodies — server-side timestamps,
//! request IDs, cache pragmas, and trace IDs would constantly flag
//! "different" responses that mean the same thing. Instead we
//! compute a stable shape signature that captures:
//!
//! - HTTP status
//! - Whether the body is a JSON array, object, or scalar
//! - For arrays: row count + sorted set of field names from the
//!   first row
//! - For objects: sorted set of top-level field names
//! - Whether the body is empty or an explicit error envelope
//!
//! Two responses with the same shape but different row contents
//! (e.g. attacker sees [victim's row], victim sees [victim's row])
//! produce the same shape — that lets us classify "attacker can
//! read the same shape as victim" as the divergence.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// Sensitive-looking field substrings. Any field whose lowercased
/// name contains one of these is flagged in the shape; the
/// classifier uses this to escalate severity when sensitive fields
/// reach the wrong audience.
pub const SENSITIVE_FIELD_HINTS: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "credentials",
    "credit_card",
    "ssn",
    "email",
    "phone",
    "address",
    "stripe",
    "marketplace_credentials",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseShape {
    pub http_status: u16,
    pub body_kind: BodyKind,
    /// Top-level field set (object case) OR first-row field set (array case).
    pub field_names: Vec<String>,
    /// Row count for arrays; 1 for non-empty objects; 0 for empty/null.
    pub row_count: u32,
    /// True iff the body looks like an explicit error envelope:
    /// `{"message": ..., "code": ...}` or similar. PostgREST and
    /// most APIs use this shape.
    pub is_error_envelope: bool,
    /// Field-name substrings that matched [`SENSITIVE_FIELD_HINTS`].
    /// Surfaces in evidence strings.
    pub sensitive_fields_present: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyKind {
    EmptyOrNull,
    Scalar,
    Object,
    Array,
}

impl ResponseShape {
    pub fn from_response(status: u16, body: &Value) -> Self {
        let (body_kind, fields, row_count) = match body {
            Value::Null => (BodyKind::EmptyOrNull, BTreeSet::new(), 0),
            Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                (BodyKind::Scalar, BTreeSet::new(), 1)
            }
            Value::Array(arr) => {
                let fields = arr
                    .first()
                    .and_then(|v| v.as_object())
                    .map(|m| m.keys().cloned().collect::<BTreeSet<_>>())
                    .unwrap_or_default();
                let row_count = arr.len() as u32;
                let body_kind = if arr.is_empty() {
                    BodyKind::EmptyOrNull
                } else {
                    BodyKind::Array
                };
                (body_kind, fields, row_count)
            }
            Value::Object(obj) => {
                let fields = obj.keys().cloned().collect::<BTreeSet<_>>();
                let row_count = if obj.is_empty() { 0 } else { 1 };
                let body_kind = if obj.is_empty() {
                    BodyKind::EmptyOrNull
                } else {
                    BodyKind::Object
                };
                (body_kind, fields, row_count)
            }
        };
        let field_names: Vec<String> = fields.into_iter().collect();
        let is_error_envelope = body_kind == BodyKind::Object
            && (field_names.iter().any(|f| f == "message")
                || field_names.iter().any(|f| f == "error"))
            && row_count == 1;
        let sensitive_fields_present: Vec<String> = field_names
            .iter()
            .filter(|f| {
                let lf = f.to_ascii_lowercase();
                SENSITIVE_FIELD_HINTS.iter().any(|h| lf.contains(h))
            })
            .cloned()
            .collect();
        Self {
            http_status: status,
            body_kind,
            field_names,
            row_count,
            is_error_envelope,
            sensitive_fields_present,
        }
    }

    /// True iff this response represents a server-blocked outcome —
    /// nothing material returned.
    pub fn is_blocked(&self) -> bool {
        matches!(self.http_status, 401 | 403 | 407 | 511) || self.is_error_envelope
    }

    /// True iff this response represents a successful read — 2xx
    /// status with a non-empty body that isn't an error envelope.
    pub fn is_success_with_data(&self) -> bool {
        (200..300).contains(&self.http_status)
            && !self.is_error_envelope
            && self.row_count > 0
            && !matches!(self.body_kind, BodyKind::EmptyOrNull)
    }

    /// Stable hex fingerprint of the shape signature. Same shape →
    /// same hash. Used to detect "attacker sees the same shape as
    /// victim" cheaply.
    pub fn signature(&self) -> ShapeSignature {
        let mut h = blake3::Hasher::new();
        h.update(&self.http_status.to_le_bytes());
        h.update(format!("{:?}", self.body_kind).as_bytes());
        h.update(&self.row_count.to_le_bytes());
        h.update(&[u8::from(self.is_error_envelope)]);
        for f in &self.field_names {
            h.update(b"|");
            h.update(f.as_bytes());
        }
        ShapeSignature(hex::encode(h.finalize().as_bytes()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShapeSignature(pub String);

impl std::fmt::Display for ShapeSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0[..self.0.len().min(12)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_body_is_empty_or_null() {
        let s = ResponseShape::from_response(200, &json!(null));
        assert_eq!(s.body_kind, BodyKind::EmptyOrNull);
        assert_eq!(s.row_count, 0);
        assert!(!s.is_success_with_data());
    }

    #[test]
    fn array_captures_first_row_fields() {
        let s =
            ResponseShape::from_response(200, &json!([{"id":1, "email":"a@b.com", "org_id":"X"}]));
        assert_eq!(s.body_kind, BodyKind::Array);
        assert_eq!(s.row_count, 1);
        assert!(s.field_names.contains(&"id".to_string()));
        assert!(s.field_names.contains(&"email".to_string()));
        assert!(s.is_success_with_data());
        assert!(s.sensitive_fields_present.iter().any(|f| f == "email"));
    }

    #[test]
    fn error_envelope_detected() {
        let s = ResponseShape::from_response(401, &json!({"message":"JWT expired"}));
        assert!(s.is_error_envelope);
        assert!(s.is_blocked());
        assert!(!s.is_success_with_data());
    }

    #[test]
    fn same_shape_same_signature() {
        let s1 = ResponseShape::from_response(200, &json!([{"id":1,"email":"a"}]));
        let s2 = ResponseShape::from_response(200, &json!([{"id":2,"email":"b"}]));
        assert_eq!(
            s1.signature(),
            s2.signature(),
            "row contents differ but shape matches"
        );
    }

    #[test]
    fn different_field_set_different_signature() {
        let s1 = ResponseShape::from_response(200, &json!([{"id":1}]));
        let s2 = ResponseShape::from_response(200, &json!([{"id":1,"secret_token":"x"}]));
        assert_ne!(s1.signature(), s2.signature());
    }

    #[test]
    fn sensitive_field_picks_up_marketplace_credentials() {
        let s = ResponseShape::from_response(
            200,
            &json!([{"id":1, "marketplace_credentials":{"password":"p"}}]),
        );
        assert!(s
            .sensitive_fields_present
            .iter()
            .any(|f| f == "marketplace_credentials"));
    }

    #[test]
    fn forbidden_status_is_blocked_even_without_envelope() {
        let s = ResponseShape::from_response(403, &json!([]));
        assert!(s.is_blocked());
    }

    #[test]
    fn empty_array_is_empty_or_null_kind() {
        let s = ResponseShape::from_response(200, &json!([]));
        assert_eq!(s.body_kind, BodyKind::EmptyOrNull);
        assert!(!s.is_success_with_data());
    }
}
