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
