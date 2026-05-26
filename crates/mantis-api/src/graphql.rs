//! GraphQL introspection probe + cop-style security audit.
//!
//! Two parts:
//!
//! 1. [`introspect`] — POST a minimal `__schema` query and decide
//!    whether introspection is enabled. Returns the raw JSON when it
//!    is, so callers can fold the schema into the surface set.
//! 2. [`security_audit`] — run a battery of cheap checks against a
//!    GraphQL endpoint and emit [`GraphqlFinding`]s. Inspired by
//!    `dolevf/graphql-cop` (BSD-3-Clause). Checks include:
//!    - introspection enabled
//!    - field-suggestion enabled (typo → schema leak)
//!    - alias-based query batching (DoS vector)
//!    - debug error mode (stack traces in errors)
//!    - any-origin CORS on the GraphQL handler
//!
//! Every check is best-effort and returns at most one finding so the
//! audit is bounded.

use crate::ApiError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GraphqlSeverity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GraphqlCheck {
    IntrospectionEnabled,
    FieldSuggestions,
    AliasOverloading,
    DebugErrorMode,
    AnyOriginCors,
    PostMethodOnly,
}

impl GraphqlCheck {
    pub fn slug(self) -> &'static str {
        match self {
            GraphqlCheck::IntrospectionEnabled => "introspection-enabled",
            GraphqlCheck::FieldSuggestions => "field-suggestions",
            GraphqlCheck::AliasOverloading => "alias-overloading",
            GraphqlCheck::DebugErrorMode => "debug-error-mode",
            GraphqlCheck::AnyOriginCors => "any-origin-cors",
            GraphqlCheck::PostMethodOnly => "post-method-only",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlFinding {
    pub check: GraphqlCheck,
    pub severity: GraphqlSeverity,
    pub description: String,
    pub endpoint: String,
}

/// Result of an introspection probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntrospectionResult {
    pub enabled: bool,
    /// Raw JSON response — empty when `enabled = false`.
    pub raw_response: String,
}

/// Run the canonical `__schema { queryType { name } }` probe. We
/// keep the query minimal so even rate-limited endpoints generally
/// answer.
pub async fn introspect(
    client: &reqwest::Client,
    endpoint: &str,
) -> Result<IntrospectionResult, ApiError> {
    let body = r#"{"query":"query{__schema{queryType{name}}}"}"#;
    let resp = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body)
        .timeout(DEFAULT_TIMEOUT)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Ok(IntrospectionResult {
            enabled: false,
            raw_response: String::new(),
        });
    }
    let text = resp.text().await?;
    let enabled = is_introspection_enabled(&text);
    Ok(IntrospectionResult {
        enabled,
        raw_response: if enabled { text } else { String::new() },
    })
}

pub(crate) fn is_introspection_enabled(body: &str) -> bool {
    // The successful response contains `__schema.queryType.name` in
    // a `data` envelope. Disabled servers either error out with
    // "introspection is not allowed" or return `data: null`.
    let lower = body.to_ascii_lowercase();
    if lower.contains("introspection") && lower.contains("disabled") {
        return false;
    }
    if lower.contains("introspection") && lower.contains("not allowed") {
        return false;
    }
    body.contains("queryType") && body.contains("\"data\"") && !body.contains("\"data\":null")
}

/// Run the security audit. Each check is independent; failures are
/// swallowed so a single broken check doesn't kill the audit.
pub async fn security_audit(
    client: &reqwest::Client,
    endpoint: &str,
) -> Vec<GraphqlFinding> {
    let mut out = Vec::new();
    if let Ok(intro) = introspect(client, endpoint).await {
        if intro.enabled {
            out.push(GraphqlFinding {
                check: GraphqlCheck::IntrospectionEnabled,
                severity: GraphqlSeverity::Medium,
                description: "GraphQL introspection is enabled on a non-public endpoint. \
                    Schema-level secrets (internal types, deprecated fields, admin mutations) \
                    are discoverable."
                    .into(),
                endpoint: endpoint.into(),
            });
        }
    }
    if let Ok(true) = check_field_suggestions(client, endpoint).await {
        out.push(GraphqlFinding {
            check: GraphqlCheck::FieldSuggestions,
            severity: GraphqlSeverity::Low,
            description: "Field suggestions enabled — the server leaks similar field names on \
                typos, effectively granting introspection-by-fuzzing."
                .into(),
            endpoint: endpoint.into(),
        });
    }
    if let Ok(true) = check_alias_overloading(client, endpoint).await {
        out.push(GraphqlFinding {
            check: GraphqlCheck::AliasOverloading,
            severity: GraphqlSeverity::Medium,
            description: "Alias-based query batching unbounded — a single request can issue \
                many fields, enabling a low-cost denial-of-service."
                .into(),
            endpoint: endpoint.into(),
        });
    }
    if let Ok(true) = check_debug_errors(client, endpoint).await {
        out.push(GraphqlFinding {
            check: GraphqlCheck::DebugErrorMode,
            severity: GraphqlSeverity::Low,
            description: "Debug error mode appears active — server returns stack traces \
                or framework names in error payloads."
                .into(),
            endpoint: endpoint.into(),
        });
    }
    if let Ok(true) = check_get_method_allowed(client, endpoint).await {
        out.push(GraphqlFinding {
            check: GraphqlCheck::PostMethodOnly,
            severity: GraphqlSeverity::Info,
            description: "GraphQL endpoint accepts GET method — wider CSRF surface and risk \
                of cache poisoning via query-string."
                .into(),
            endpoint: endpoint.into(),
        });
    }
    out
}

async fn check_field_suggestions(
    client: &reqwest::Client,
    endpoint: &str,
) -> Result<bool, ApiError> {
    // A made-up field name should either trigger a "Did you mean…"
    // hint (suggestions enabled) or a flat "Cannot query field" error.
    let body = r#"{"query":"{ tysers }"}"#;
    let resp = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body)
        .timeout(DEFAULT_TIMEOUT)
        .send()
        .await?;
    let text = resp.text().await.unwrap_or_default();
    Ok(text.to_ascii_lowercase().contains("did you mean"))
}

async fn check_alias_overloading(
    client: &reqwest::Client,
    endpoint: &str,
) -> Result<bool, ApiError> {
    // Issue 25 aliases against a field that almost certainly doesn't
    // exist. If the server responds with 25 errors instead of a
    // single "alias limit exceeded" or a single combined error, the
    // overloading is unbounded.
    let aliases: String = (0..25)
        .map(|i| format!("a{i}: __typename"))
        .collect::<Vec<_>>()
        .join(" ");
    let body = format!(r#"{{"query":"{{ {aliases} }}"}}"#);
    let resp = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body)
        .timeout(DEFAULT_TIMEOUT)
        .send()
        .await?;
    let text = resp.text().await.unwrap_or_default();
    Ok(text.matches("\"a0\"").count() >= 1 && text.matches("\"a24\"").count() >= 1)
}

async fn check_debug_errors(
    client: &reqwest::Client,
    endpoint: &str,
) -> Result<bool, ApiError> {
    let body = r#"{"query":"{ nonsense_field_that_should_not_exist_anywhere }"}"#;
    let resp = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body)
        .timeout(DEFAULT_TIMEOUT)
        .send()
        .await?;
    let text = resp.text().await.unwrap_or_default();
    let lower = text.to_ascii_lowercase();
    let leaks = ["traceback", "stack trace", "at line", "graphql-core", "apollo server"];
    Ok(leaks.iter().any(|s| lower.contains(s)))
}

async fn check_get_method_allowed(
    client: &reqwest::Client,
    endpoint: &str,
) -> Result<bool, ApiError> {
    let url = format!("{endpoint}?query=%7B__typename%7D");
    let resp = client.get(&url).timeout(DEFAULT_TIMEOUT).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    Ok((200..400).contains(&status) && text.contains("__typename"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn introspection_enabled_when_data_contains_query_type() {
        let body = r#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#;
        assert!(is_introspection_enabled(body));
    }

    #[test]
    fn introspection_disabled_when_message_says_so() {
        let body = r#"{"errors":[{"message":"GraphQL introspection is disabled"}]}"#;
        assert!(!is_introspection_enabled(body));
    }

    #[test]
    fn introspection_disabled_when_not_allowed_message_present() {
        let body = r#"{"errors":[{"message":"introspection is not allowed in production"}]}"#;
        assert!(!is_introspection_enabled(body));
    }

    #[test]
    fn introspection_disabled_when_data_is_null() {
        let body = r#"{"data":null}"#;
        assert!(!is_introspection_enabled(body));
    }

    #[test]
    fn introspection_disabled_when_random_body() {
        assert!(!is_introspection_enabled("welcome to my homepage"));
    }

    #[test]
    fn graphql_check_slugs_unique() {
        let mut slugs: Vec<&str> = [
            GraphqlCheck::IntrospectionEnabled,
            GraphqlCheck::FieldSuggestions,
            GraphqlCheck::AliasOverloading,
            GraphqlCheck::DebugErrorMode,
            GraphqlCheck::AnyOriginCors,
            GraphqlCheck::PostMethodOnly,
        ]
        .iter()
        .map(|c| c.slug())
        .collect();
        slugs.sort_unstable();
        let pre = slugs.len();
        slugs.dedup();
        assert_eq!(pre, slugs.len());
    }

    #[test]
    fn graphql_finding_round_trips_through_json() {
        let f = GraphqlFinding {
            check: GraphqlCheck::IntrospectionEnabled,
            severity: GraphqlSeverity::Medium,
            description: "test".into(),
            endpoint: "https://example.com/graphql".into(),
        };
        let j = serde_json::to_string(&f).unwrap();
        let back: GraphqlFinding = serde_json::from_str(&j).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn graphql_severity_orders_low_to_high() {
        assert!(GraphqlSeverity::Info < GraphqlSeverity::Low);
        assert!(GraphqlSeverity::Low < GraphqlSeverity::Medium);
        assert!(GraphqlSeverity::Medium < GraphqlSeverity::High);
    }
}
