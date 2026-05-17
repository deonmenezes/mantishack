//! Mantis per-engagement auth profile store.
//!
//! Ports hacker-bob's `auth_profile`/`auth_store` concept to Rust.
//!
//! # Modules
//! - [`profile`] — typed [`AuthProfile`], [`AuthHeader`], [`AuthCookie`], [`AuthExpiry`]
//! - [`store`]   — on-disk [`AuthStore`] with atomic JSON persistence
//! - [`redact`]  — [`redact_value`] helper: blake3-prefix redaction used by Debug impls

pub mod profile;
pub mod redact;
pub mod store;

pub use crate::profile::{AuthCookie, AuthExpiry, AuthHeader, AuthProfile};
pub use crate::redact::redact_value;
pub use crate::store::{AuthStore, AuthStoreError, RedactedProfile};
