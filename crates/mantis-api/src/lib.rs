//! mantis-api — API-aware testing.
//!
//! ## Why this exists
//!
//! Modern targets are API-first. Most pentest tooling treats APIs
//! like directories to brute-force, which both misses real endpoints
//! (REST verbs, query-string parameters, GraphQL fields) and wastes
//! request budget on impossible paths. mantis-api inverts that:
//! parse the schema when one is exposed, talk to the API on its
//! terms, and brute-force only as a fallback.
//!
//! ## Modules
//!
//! - [`openapi`] — Swagger 2.0 + OpenAPI 3.x JSON/YAML parser →
//!   typed [`openapi::ApiEndpoint`] list with method, path,
//!   parameters, request/response shapes.
//! - [`graphql`] — introspection probe + graphql-cop-style security
//!   checks (introspection enabled, depth bomb, batching, debug
//!   leaks).
//! - [`grpc`] — gRPC reflection-protocol method descriptors.
//! - [`fuzz_seeds`] — per-parameter fuzz seed generator that uses
//!   the parameter's declared type to choose realistic inputs
//!   (UUID for `uuid`, big-int for `integer`, polyglot for `string`).

pub mod fuzz_seeds;
pub mod graphql;
pub mod grpc;
pub mod openapi;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("network: {0}")]
    Network(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
}

impl From<reqwest::Error> for ApiError {
    fn from(value: reqwest::Error) -> Self {
        ApiError::Network(value.to_string())
    }
}

pub use crate::fuzz_seeds::{seeds_for, SeedInput};
pub use crate::graphql::{
    introspect, security_audit, GraphqlCheck, GraphqlFinding, GraphqlSeverity,
};
pub use crate::grpc::{GrpcMethodDescriptor, GrpcServiceDescriptor};
pub use crate::openapi::{parse, ApiEndpoint, ApiParameter, ParameterIn, ParameterType};
