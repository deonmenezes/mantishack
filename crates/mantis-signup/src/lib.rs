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
//! Auto-signup: capture an [`mantis_auth::AuthProfile`] by driving a
//! target's signup endpoint and parsing the returned JWT / cookie /
//! session response.
//!
//! v1 ships two paths:
//!
//! - **Supabase** — `POST /auth/v1/signup` with the public `apikey`
//!   header and `{"email","password"}` JSON. Response carries an
//!   `access_token` we use as a `Bearer` header. This is the path
//!   that lights up Supabase / PostgREST stacks like Tenkara.
//! - **Generic JSON** — operator-supplied URL + form fields,
//!   response key. For Next.js NextAuth and similar.
//!
//! Browser-driven flows (Patchright + CAPTCHA solver) match
//! hacker-bob's `bounty_auto_signup` but require shipping a
//! headless browser and are out of scope for v1.

pub mod detect;
pub mod email;
pub mod supabase;

pub use crate::detect::{detect_signup, SignupKind};
pub use crate::email::{disposable_email, EmailSpec};
pub use crate::supabase::{signup_supabase, SupabaseSignupConfig};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum SignupError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("signup endpoint rejected payload: HTTP {status} body: {body}")]
    Rejected { status: u16, body: String },
    #[error("response was not JSON: {0}")]
    Decode(String),
    #[error("response missing expected token field `{field}` in body: {body}")]
    NoToken { field: String, body: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignupOutcome {
    pub email: String,
    pub access_token: String,
    /// Optional refresh token (Supabase returns one). Stored on the
    /// profile so the operator can drive refresh later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Token type returned by the auth endpoint (`bearer` for Supabase).
    pub token_type: String,
    /// Seconds until access_token expiry. `None` if unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
}
