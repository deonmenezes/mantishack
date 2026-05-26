//! Microsoft Teams incoming-webhook payload formatter (MessageCard schema).
//!
//! Spec: <https://learn.microsoft.com/en-us/outlook/actionable-messages/message-card-reference>.
//!
//! Microsoft has moved Office 365 customers toward Adaptive Cards via
//! Workflows, but the legacy MessageCard schema is still what the basic
//! "Incoming Webhook" connector accepts and is the simplest format compatible
//! with the broadest set of Teams configurations.

use serde_json::{json, Value};

use crate::notification::Notification;

pub(crate) fn format(n: &Notification) -> Value {
    let mut facts: Vec<Value> = Vec::new();
    facts.push(json!({ "name": "Severity", "value": n.severity.label() }));
    if let Some(target) = &n.target {
        facts.push(json!({ "name": "Target", "value": target }));
    }
    if let Some(cwe) = &n.cwe {
        facts.push(json!({ "name": "CWE", "value": cwe }));
    }
    if let Some(eng) = &n.engagement_id {
        facts.push(json!({ "name": "Engagement", "value": eng }));
    }

    let summary = format!("{} {}", n.severity.emoji(), n.title);
    json!({
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        // `themeColor` accepts hex without the `#` prefix.
        "themeColor": n.severity.color_hex().trim_start_matches('#'),
        "summary": summary,
        "title": summary,
        "text": n.detail.as_deref().unwrap_or(""),
        "sections": [{
            "facts": facts,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification::Severity;

    #[test]
    fn declares_messagecard_type() {
        let n = Notification::new("t", Severity::High);
        let payload = format(&n);
        assert_eq!(payload["@type"], "MessageCard");
        assert_eq!(payload["@context"], "https://schema.org/extensions");
    }

    #[test]
    fn theme_color_strips_hash_prefix() {
        let n = Notification::new("t", Severity::Critical);
        let payload = format(&n);
        // Teams MessageCard expects "RRGGBB", not "#RRGGBB".
        assert_eq!(payload["themeColor"], "8E1538");
    }

    #[test]
    fn summary_and_title_include_emoji() {
        let n = Notification::new("Hi", Severity::High);
        let payload = format(&n);
        let summary = payload["summary"].as_str().unwrap();
        let title = payload["title"].as_str().unwrap();
        assert!(summary.contains("🔴"));
        assert!(title.contains("Hi"));
        assert_eq!(summary, title); // they're the same string in this schema
    }

    #[test]
    fn facts_include_target_and_cwe_when_set() {
        let n = Notification::new("t", Severity::Medium)
            .with_target("https://x/y")
            .with_cwe("CWE-79");
        let payload = format(&n);
        let facts = payload["sections"][0]["facts"].as_array().unwrap();
        let names: Vec<&str> = facts.iter().filter_map(|f| f["name"].as_str()).collect();
        assert!(names.contains(&"Severity"));
        assert!(names.contains(&"Target"));
        assert!(names.contains(&"CWE"));
    }

    #[test]
    fn detail_text_falls_back_to_empty_string() {
        let n = Notification::new("t", Severity::Low);
        let payload = format(&n);
        assert_eq!(payload["text"], "");
    }

    #[test]
    fn detail_text_passes_through_when_set() {
        let n = Notification::new("t", Severity::Low).with_detail("body");
        let payload = format(&n);
        assert_eq!(payload["text"], "body");
    }
}
