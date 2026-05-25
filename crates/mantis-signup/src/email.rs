//! # Apache-2.0 §4(b) notice — derivative work
//!
//! Portions of this file are derived from or mirror algorithm
//! shape, named constants, threshold values, or workflow logic from
//! Hacker Bob (<https://github.com/vmihalis/hacker-bob>),
//! Copyright 2026 Michail Vasileiadis, licensed under the Apache
//! License, Version 2.0. The surrounding Rust implementation is
//! independent and was written from scratch.
//!
//! See the project NOTICE for the upstream attribution and the
//! compliance-history apology. This notice is provided per
//! Apache-2.0 §4(b) ("You must cause any modified files to carry
//! prominent notices stating that You changed the files").
//!
//! Disposable email generator.
//!
//! v1 generates `<ulid>@<reserved-domain>` addresses. The default
//! domain is `mantis-test.invalid` — the `.invalid` TLD is reserved
//! by RFC 2606 and guaranteed never to resolve, so we cannot
//! accidentally spam a real inbox.
//!
//! When the target requires a real verification mailbox (most apps
//! don't, but Tenkara's prior research found Supabase signup
//! accepts anything — F-7), the operator can pass
//! `EmailSpec::user_supplied`.
//!
//! Browser-driven temp-email integration (mailinator / 1secmail /
//! tempr.email) matches hacker-bob's `bounty_temp_email` and lands
//! in a follow-up.

use serde::{Deserialize, Serialize};

/// Reserved-by-RFC-2606 domain. Will never resolve, so even a
/// confused mailserver can't bounce to a real recipient.
pub const DEFAULT_DOMAIN: &str = "mantis-test.invalid";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSpec {
    pub local_part: String,
    pub domain: String,
}

impl EmailSpec {
    /// Generate `mantis-<ulid>@<DEFAULT_DOMAIN>`.
    pub fn random() -> Self {
        Self {
            local_part: format!("mantis-{}", ulid::Ulid::new()).to_ascii_lowercase(),
            domain: DEFAULT_DOMAIN.into(),
        }
    }

    /// Generate a random local part under a custom domain.
    pub fn random_with_domain(domain: impl Into<String>) -> Self {
        Self {
            local_part: format!("mantis-{}", ulid::Ulid::new()).to_ascii_lowercase(),
            domain: domain.into(),
        }
    }

    /// Operator-supplied address (use when the target needs a
    /// resolvable inbox for verification mail).
    pub fn user_supplied(local_part: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            local_part: local_part.into(),
            domain: domain.into(),
        }
    }

    pub fn as_address(&self) -> String {
        format!("{}@{}", self.local_part, self.domain)
    }
}

/// Convenience: just give me a random address.
pub fn disposable_email() -> String {
    EmailSpec::random().as_address()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_emails_have_invalid_domain_by_default() {
        let e = EmailSpec::random();
        assert!(e.domain.ends_with(".invalid"));
        let addr = e.as_address();
        assert!(addr.contains('@'));
        assert!(addr.ends_with(".invalid"));
    }

    #[test]
    fn random_emails_are_unique() {
        let a = disposable_email();
        let b = disposable_email();
        assert_ne!(a, b);
    }

    #[test]
    fn user_supplied_round_trips() {
        let e = EmailSpec::user_supplied("alice", "example.com");
        assert_eq!(e.as_address(), "alice@example.com");
    }

    #[test]
    fn custom_domain_works() {
        let e = EmailSpec::random_with_domain("evil.tld");
        assert!(e.as_address().ends_with("@evil.tld"));
    }
}
