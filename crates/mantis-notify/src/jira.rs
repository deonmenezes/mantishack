//! Jira REST v3 create-issue payload formatter.
//!
//! Spec: <https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post>.
//!
//! Jira Cloud expects an Atlassian Document Format (ADF) body for `description`.
//! We emit a minimal ADF document with one paragraph per `detail` paragraph and
//! an additional bullet list summarizing severity, target, CWE, and engagement
//! identifier when set.

use serde_json::{json, Value};

use crate::notification::Notification;

/// Configuration knobs the dispatcher supplies when materializing the payload.
#[derive(Debug, Clone)]
pub struct JiraConfig<'a> {
    /// Project key, e.g. `"SEC"`.
    pub project_key: &'a str,
    /// Issue type name, e.g. `"Bug"`, `"Vulnerability"`, `"Task"`.
    pub issue_type: &'a str,
    /// Optional Jira priority name (`"Highest"`, `"High"`, etc). When `None`,
    /// the field is omitted and Jira falls back to the project default.
    pub priority: Option<&'a str>,
    /// Optional list of label strings to attach to the issue.
    pub labels: &'a [&'a str],
}

impl<'a> JiraConfig<'a> {
    /// Construct a config with sensible defaults: `Bug` issue type, no priority override.
    pub fn new(project_key: &'a str) -> Self {
        Self {
            project_key,
            issue_type: "Bug",
            priority: None,
            labels: &[],
        }
    }
}

/// Render a [`Notification`] as a Jira REST v3 create-issue request body.
pub fn format(n: &Notification, cfg: &JiraConfig<'_>) -> Value {
    let mut fields = serde_json::Map::new();

    fields.insert(
        "project".into(),
        json!({ "key": cfg.project_key }),
    );
    fields.insert(
        "issuetype".into(),
        json!({ "name": cfg.issue_type }),
    );
    fields.insert(
        "summary".into(),
        Value::String(format!("[{}] {}", n.severity.label(), n.title)),
    );
    fields.insert("description".into(), description_adf(n));

    if let Some(pri) = cfg.priority {
        fields.insert("priority".into(), json!({ "name": pri }));
    }
    if !cfg.labels.is_empty() {
        fields.insert(
            "labels".into(),
            Value::Array(cfg.labels.iter().map(|l| Value::String((*l).to_string())).collect()),
        );
    }

    json!({ "fields": fields })
}

fn description_adf(n: &Notification) -> Value {
    let mut content: Vec<Value> = Vec::new();

    if let Some(detail) = &n.detail {
        content.push(paragraph(detail));
    }

    let mut bullets: Vec<Value> = Vec::new();
    bullets.push(bullet(&format!("Severity: {}", n.severity.label())));
    if let Some(target) = &n.target {
        bullets.push(bullet(&format!("Target: {target}")));
    }
    if let Some(cwe) = &n.cwe {
        bullets.push(bullet(&format!("CWE: {cwe}")));
    }
    if let Some(eng) = &n.engagement_id {
        bullets.push(bullet(&format!("Engagement: {eng}")));
    }

    content.push(json!({ "type": "bulletList", "content": bullets }));

    json!({
        "type": "doc",
        "version": 1,
        "content": content,
    })
}

fn paragraph(text: &str) -> Value {
    json!({
        "type": "paragraph",
        "content": [{ "type": "text", "text": text }],
    })
}

fn bullet(text: &str) -> Value {
    json!({
        "type": "listItem",
        "content": [paragraph(text)],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification::Severity;

    #[test]
    fn includes_project_key_and_issue_type() {
        let n = Notification::new("t", Severity::High);
        let cfg = JiraConfig::new("SEC");
        let p = format(&n, &cfg);
        assert_eq!(p["fields"]["project"]["key"], "SEC");
        assert_eq!(p["fields"]["issuetype"]["name"], "Bug");
    }

    #[test]
    fn summary_prefixes_severity_label() {
        let n = Notification::new("SSRF at /api", Severity::Critical);
        let p = format(&n, &JiraConfig::new("SEC"));
        assert_eq!(p["fields"]["summary"], "[Critical] SSRF at /api");
    }

    #[test]
    fn description_is_adf_document() {
        let n = Notification::new("t", Severity::Low);
        let p = format(&n, &JiraConfig::new("SEC"));
        let desc = &p["fields"]["description"];
        assert_eq!(desc["type"], "doc");
        assert_eq!(desc["version"], 1);
        assert!(desc["content"].is_array());
    }

    #[test]
    fn detail_becomes_paragraph_in_adf() {
        let n = Notification::new("t", Severity::Low).with_detail("body text");
        let p = format(&n, &JiraConfig::new("SEC"));
        let content = p["fields"]["description"]["content"].as_array().unwrap();
        assert!(content
            .iter()
            .any(|n| n["type"] == "paragraph"
                && n["content"][0]["text"] == "body text"));
    }

    #[test]
    fn metadata_fields_appear_as_bullet_list_items() {
        let n = Notification::new("t", Severity::High)
            .with_target("https://x/y")
            .with_cwe("CWE-89")
            .with_engagement_id("eng-1");
        let p = format(&n, &JiraConfig::new("SEC"));
        let json_str = p.to_string();
        assert!(json_str.contains("Severity: High"));
        assert!(json_str.contains("Target: https://x/y"));
        assert!(json_str.contains("CWE: CWE-89"));
        assert!(json_str.contains("Engagement: eng-1"));
    }

    #[test]
    fn priority_omitted_when_not_set() {
        let n = Notification::new("t", Severity::Medium);
        let p = format(&n, &JiraConfig::new("SEC"));
        assert!(p["fields"].get("priority").is_none());
    }

    #[test]
    fn priority_included_when_set() {
        let n = Notification::new("t", Severity::Medium);
        let mut cfg = JiraConfig::new("SEC");
        cfg.priority = Some("Highest");
        let p = format(&n, &cfg);
        assert_eq!(p["fields"]["priority"]["name"], "Highest");
    }

    #[test]
    fn labels_array_included_when_set() {
        let n = Notification::new("t", Severity::Medium);
        let labels = ["mantis", "auto-filed"];
        let mut cfg = JiraConfig::new("SEC");
        cfg.labels = &labels;
        let p = format(&n, &cfg);
        let arr = p["fields"]["labels"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn labels_omitted_when_empty() {
        let n = Notification::new("t", Severity::Medium);
        let p = format(&n, &JiraConfig::new("SEC"));
        assert!(p["fields"].get("labels").is_none());
    }
}
