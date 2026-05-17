//! Value redaction helpers used by [`Debug`] impls and
//! [`crate::store::RedactedProfile`] construction.

/// Returns `"<empty>"` for empty values; otherwise the first 4 hex chars
/// of `blake3(value)` prefixed with `"b3:"`.
///
/// This gives enough signal to detect whether a stored credential has
/// changed (fingerprint drift) without revealing the credential itself.
pub fn redact_value(value: &str) -> String {
    if value.is_empty() {
        return "<empty>".to_owned();
    }
    let hash = blake3::hash(value.as_bytes());
    let full = hex::encode(hash.as_bytes());
    format!("b3:{}", &full[..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_value_returns_placeholder() {
        assert_eq!(redact_value(""), "<empty>");
    }

    #[test]
    fn non_empty_value_returns_b3_prefix() {
        let r = redact_value("some-secret");
        assert!(r.starts_with("b3:"), "must start with b3: prefix");
        assert_eq!(r.len(), 7, "b3: + 4 hex chars");
    }

    #[test]
    fn same_value_same_redaction() {
        assert_eq!(redact_value("abc"), redact_value("abc"));
    }

    #[test]
    fn different_values_different_redactions() {
        assert_ne!(redact_value("abc"), redact_value("xyz"));
    }
}
