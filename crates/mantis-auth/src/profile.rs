//! Auth profile types: structured headers, cookies, and query params
//! for a named identity (e.g. "attacker", "victim", "admin").
//!
//! Secret material in [`AuthHeader::value`] and [`AuthCookie::value`]
//! is zeroized on drop. [`Debug`] impls emit only names, never values,
//! so secrets never leak into tracing output.

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::redact::redact_value;

/// A named identity that carries all auth material needed to replay
/// requests as that identity (headers, cookies, query params).
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthProfile {
    /// Human-readable identity label: `"attacker"`, `"victim"`, `"admin"`, `"tenant_b"`, …
    pub name: String,
    pub headers: Vec<AuthHeader>,
    pub cookies: Vec<AuthCookie>,
    /// Token-bearing URL query entries (rare; e.g. `?api_key=…`).
    pub query: Vec<(String, String)>,
    /// Optional hard expiry as a Unix timestamp.
    pub expires_at_unix: Option<u64>,
    pub created_at_unix: u64,
    /// Free-form tag describing how the profile was obtained:
    /// `"manual_paste"`, `"auto_signup"`, `"oauth_callback"`, etc.
    pub origin: String,
}

impl std::fmt::Debug for AuthProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthProfile")
            .field("name", &self.name)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|h| h.name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field(
                "cookies",
                &self
                    .cookies
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field(
                "query_keys",
                &self
                    .query
                    .iter()
                    .map(|(k, _)| k.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("expires_at_unix", &self.expires_at_unix)
            .field("created_at_unix", &self.created_at_unix)
            .field("origin", &self.origin)
            .finish()
    }
}

impl AuthProfile {
    /// Returns `true` when the profile's hard expiry is in the past.
    /// Profiles without an expiry are never considered expired.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        match self.expires_at_unix {
            Some(exp) => now_unix >= exp,
            None => false,
        }
    }

    /// Stable hex-encoded blake3 fingerprint of all secret material.
    ///
    /// The fingerprint is computed over a canonical byte sequence so
    /// that the same secrets always produce the same hash regardless
    /// of insertion order. Safe to log; the underlying values are
    /// never recoverable from the hash.
    pub fn secret_fingerprint(&self) -> String {
        let mut parts: Vec<String> = Vec::new();

        // Sort each category so insertion order doesn't affect the hash.
        let mut header_pairs: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|h| (h.name.as_str(), h.value.as_str()))
            .collect();
        header_pairs.sort_unstable_by_key(|(k, _)| *k);
        for (name, value) in &header_pairs {
            parts.push(format!("h:{name}={value}"));
        }

        let mut cookie_pairs: Vec<(&str, &str)> = self
            .cookies
            .iter()
            .map(|c| (c.name.as_str(), c.value.as_str()))
            .collect();
        cookie_pairs.sort_unstable_by_key(|(k, _)| *k);
        for (name, value) in &cookie_pairs {
            parts.push(format!("c:{name}={value}"));
        }

        let mut query_pairs: Vec<(&str, &str)> = self
            .query
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        query_pairs.sort_unstable_by_key(|(k, _)| *k);
        for (key, value) in &query_pairs {
            parts.push(format!("q:{key}={value}"));
        }

        let canonical = parts.join("\n");
        let hash = blake3::hash(canonical.as_bytes());
        hex::encode(hash.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// AuthHeader
// ---------------------------------------------------------------------------

/// A single HTTP request header. The `value` is zeroized on drop.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct AuthHeader {
    pub name: String,
    #[zeroize]
    pub value: String,
}

impl std::fmt::Debug for AuthHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthHeader")
            .field("name", &self.name)
            .field("value", &redact_value(&self.value))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// AuthCookie
// ---------------------------------------------------------------------------

/// A single HTTP cookie. The `value` is zeroized on drop.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct AuthCookie {
    pub name: String,
    #[zeroize]
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
}

impl std::fmt::Debug for AuthCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCookie")
            .field("name", &self.name)
            .field("value", &redact_value(&self.value))
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// AuthExpiry — thin wrapper around the optional expiry timestamp
// ---------------------------------------------------------------------------

/// Convenience wrapper returned by expiry-checking helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthExpiry {
    /// No expiry was set; treat the profile as perpetually valid.
    Never,
    /// Expiry timestamp (Unix seconds).
    At(u64),
}

impl AuthExpiry {
    /// Build from an [`AuthProfile`].
    pub fn from_profile(profile: &AuthProfile) -> Self {
        match profile.expires_at_unix {
            Some(ts) => Self::At(ts),
            None => Self::Never,
        }
    }

    /// `true` if the expiry is in the past relative to `now_unix`.
    pub fn is_expired(self, now_unix: u64) -> bool {
        match self {
            Self::Never => false,
            Self::At(exp) => now_unix >= exp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_profile(name: &str) -> AuthProfile {
        AuthProfile {
            name: name.to_owned(),
            headers: vec![AuthHeader {
                name: "Authorization".to_owned(),
                value: "Bearer secret-token".to_owned(),
            }],
            cookies: vec![AuthCookie {
                name: "session".to_owned(),
                value: "abc123".to_owned(),
                domain: Some("example.com".to_owned()),
                path: Some("/".to_owned()),
                secure: true,
                http_only: true,
            }],
            query: vec![("api_key".to_owned(), "key-value".to_owned())],
            expires_at_unix: None,
            created_at_unix: 1_700_000_000,
            origin: "manual_paste".to_owned(),
        }
    }

    #[test]
    fn debug_redacts_header_value() {
        let h = AuthHeader {
            name: "Authorization".to_owned(),
            value: "Bearer secret-token".to_owned(),
        };
        let debug = format!("{h:?}");
        assert!(debug.contains("Authorization"), "name must appear");
        assert!(
            !debug.contains("Bearer secret-token"),
            "raw value must not appear in Debug"
        );
    }

    #[test]
    fn debug_redacts_cookie_value() {
        let c = AuthCookie {
            name: "session".to_owned(),
            value: "abc123".to_owned(),
            domain: None,
            path: None,
            secure: false,
            http_only: false,
        };
        let debug = format!("{c:?}");
        assert!(debug.contains("session"), "name must appear");
        assert!(!debug.contains("abc123"), "raw value must not appear");
    }

    #[test]
    fn profile_debug_shows_names_only() {
        let p = make_profile("attacker");
        let debug = format!("{p:?}");
        assert!(debug.contains("Authorization"));
        assert!(debug.contains("session"));
        assert!(!debug.contains("Bearer secret-token"));
        assert!(!debug.contains("abc123"));
    }

    #[test]
    fn is_expired_with_past_expiry() {
        let mut p = make_profile("victim");
        p.expires_at_unix = Some(1_000);
        assert!(p.is_expired(2_000));
        assert!(!p.is_expired(999));
    }

    #[test]
    fn is_expired_no_expiry_never_expired() {
        let p = make_profile("admin");
        assert!(!p.is_expired(u64::MAX));
    }

    #[test]
    fn secret_fingerprint_is_deterministic() {
        let p = make_profile("attacker");
        assert_eq!(p.secret_fingerprint(), p.secret_fingerprint());
    }

    #[test]
    fn secret_fingerprint_differs_for_different_values() {
        let p1 = make_profile("attacker");
        let mut p2 = make_profile("attacker");
        p2.headers[0].value = "Bearer different-token".to_owned();
        assert_ne!(p1.secret_fingerprint(), p2.secret_fingerprint());
    }

    #[test]
    fn auth_expiry_wrapper() {
        let exp = AuthExpiry::At(500);
        assert!(exp.is_expired(500));
        assert!(!exp.is_expired(499));
        assert!(!AuthExpiry::Never.is_expired(u64::MAX));
    }
}
