//! Linear GraphQL `issueCreate` mutation payload formatter.
//!
//! Spec: <https://developers.linear.app/docs/graphql/working-with-the-graphql-api>.
//!
//! Linear's API is GraphQL; clients POST a `{ query, variables }` body to
//! `https://api.linear.app/graphql`. We emit that envelope with the
//! `issueCreate` mutation pre-substituted.

use serde_json::{json, Value};
use std::fmt::Write as _;

use crate::notification::Notification;

/// Configuration for materializing a Linear issue payload.
#[derive(Debug, Clone)]
pub struct LinearConfig<'a> {
    /// Linear team UUID — required.
    pub team_id: &'a str,
    /// Optional priority (0 = no priority, 1 = urgent, 2 = high, 3 = medium, 4 = low).
    /// When `None`, the field is mapped from notification severity by
    /// [`severity_to_priority`].
    pub priority: Option<u8>,
    /// Optional list of label UUIDs to attach.
    pub label_ids: &'a [&'a str],
}

impl<'a> LinearConfig<'a> {
    /// Create a config with auto-mapped priority and no extra labels.
    pub fn new(team_id: &'a str) -> Self {
        Self {
            team_id,
            priority: None,
            label_ids: &[],
        }
    }
}

/// Map Mantis severity to Linear's priority scale.
///
/// - `Critical` → 1 (Urgent)
/// - `High`     → 2 (High)
/// - `Medium`   → 3 (Medium)
/// - `Low`      → 4 (Low)
/// - `Info`     → 0 (No priority)
pub const fn severity_to_priority(severity: crate::Severity) -> u8 {
    use crate::Severity::*;
    match severity {
        Critical => 1,
        High => 2,
        Medium => 3,
        Low => 4,
        Info => 0,
    }
}

const MUTATION: &str = r#"mutation Mantis_IssueCreate($input: IssueCreateInput!) {
  issueCreate(input: $input) {
    success
    issue { id identifier title url }
  }
}"#;

/// Render a [`Notification`] as a Linear GraphQL request body.
pub fn format(n: &Notification, cfg: &LinearConfig<'_>) -> Value {
    let title = format!("[{}] {}", n.severity.label(), n.title);
    let description = description_markdown(n);
    let priority = cfg.priority.unwrap_or_else(|| severity_to_priority(n.severity));

    let mut input = serde_json::Map::new();
    input.insert("teamId".into(), Value::String(cfg.team_id.to_string()));
    input.insert("title".into(), Value::String(title));
    input.insert("description".into(), Value::String(description));
    input.insert("priority".into(), Value::Number(priority.into()));
    if !cfg.label_ids.is_empty() {
        input.insert(
            "labelIds".into(),
            Value::Array(
                cfg.label_ids
                    .iter()
                    .map(|id| Value::String((*id).to_string()))
                    .collect(),
            ),
        );
    }

    json!({
        "query": MUTATION,
        "variables": { "input": input },
    })
}

fn description_markdown(n: &Notification) -> String {
    let mut out = String::new();
    if let Some(detail) = &n.detail {
        out.push_str(detail);
        out.push_str("\n\n");
    }
    let _ = writeln!(out, "- **Severity:** {}", n.severity.label());
    if let Some(target) = &n.target {
        let _ = writeln!(out, "- **Target:** {target}");
    }
    if let Some(cwe) = &n.cwe {
        let _ = writeln!(out, "- **CWE:** {cwe}");
    }
    if let Some(eng) = &n.engagement_id {
        let _ = writeln!(out, "- **Engagement:** `{eng}`");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification::Severity;

    #[test]
    fn body_has_query_and_variables() {
        let n = Notification::new("t", Severity::Medium);
        let p = format(&n, &LinearConfig::new("team-uuid"));
        assert!(p["query"].as_str().unwrap().contains("issueCreate"));
        assert!(p["variables"].is_object());
    }

    #[test]
    fn title_prefixes_severity() {
        let n = Notification::new("SSRF found", Severity::Critical);
        let p = format(&n, &LinearConfig::new("team-uuid"));
        let title = p["variables"]["input"]["title"].as_str().unwrap();
        assert_eq!(title, "[Critical] SSRF found");
    }

    #[test]
    fn team_id_is_included() {
        let n = Notification::new("t", Severity::Low);
        let p = format(&n, &LinearConfig::new("abc-123"));
        assert_eq!(p["variables"]["input"]["teamId"], "abc-123");
    }

    #[test]
    fn description_is_markdown_with_detail_first() {
        let n = Notification::new("t", Severity::Low)
            .with_detail("Reproducer details here")
            .with_target("https://x/y")
            .with_cwe("CWE-918");
        let p = format(&n, &LinearConfig::new("team"));
        let desc = p["variables"]["input"]["description"].as_str().unwrap();
        assert!(desc.starts_with("Reproducer details here"));
        assert!(desc.contains("**Severity:** Low"));
        assert!(desc.contains("**Target:** https://x/y"));
        assert!(desc.contains("**CWE:** CWE-918"));
    }

    #[test]
    fn priority_auto_maps_from_severity() {
        for (sev, expected) in [
            (Severity::Critical, 1u8),
            (Severity::High, 2),
            (Severity::Medium, 3),
            (Severity::Low, 4),
            (Severity::Info, 0),
        ] {
            let n = Notification::new("t", sev);
            let p = format(&n, &LinearConfig::new("team"));
            assert_eq!(
                p["variables"]["input"]["priority"].as_u64().unwrap(),
                u64::from(expected),
                "severity {sev:?}"
            );
        }
    }

    #[test]
    fn explicit_priority_overrides_auto_mapping() {
        let n = Notification::new("t", Severity::Low);
        let mut cfg = LinearConfig::new("team");
        cfg.priority = Some(1);
        let p = format(&n, &cfg);
        assert_eq!(p["variables"]["input"]["priority"], 1);
    }

    #[test]
    fn label_ids_array_included_when_set() {
        let n = Notification::new("t", Severity::High);
        let labels = ["label-uuid-1", "label-uuid-2"];
        let mut cfg = LinearConfig::new("team");
        cfg.label_ids = &labels;
        let p = format(&n, &cfg);
        let arr = p["variables"]["input"]["labelIds"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], "label-uuid-1");
    }

    #[test]
    fn label_ids_omitted_when_empty() {
        let n = Notification::new("t", Severity::High);
        let p = format(&n, &LinearConfig::new("team"));
        assert!(p["variables"]["input"].get("labelIds").is_none());
    }

    #[test]
    fn description_omits_target_when_unset() {
        let n = Notification::new("t", Severity::Low);
        let p = format(&n, &LinearConfig::new("team"));
        let desc = p["variables"]["input"]["description"].as_str().unwrap();
        assert!(!desc.contains("Target"));
    }
}
