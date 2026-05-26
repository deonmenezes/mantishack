//! Slack incoming-webhook payload formatter (Block Kit).
//!
//! Spec: <https://api.slack.com/messaging/webhooks> and
//! <https://api.slack.com/block-kit>.

use serde_json::{json, Value};

use crate::notification::Notification;

pub(crate) fn format(n: &Notification) -> Value {
    let header_text = format!("{} {}", n.severity.emoji(), n.title);

    let mut fields: Vec<Value> = Vec::new();
    fields.push(json!({
        "type": "mrkdwn",
        "text": format!("*Severity:*\n{}", n.severity.label()),
    }));
    if let Some(target) = &n.target {
        fields.push(json!({
            "type": "mrkdwn",
            "text": format!("*Target:*\n<{target}>"),
        }));
    }
    if let Some(cwe) = &n.cwe {
        fields.push(json!({
            "type": "mrkdwn",
            "text": format!("*CWE:*\n{cwe}"),
        }));
    }
    if let Some(eng) = &n.engagement_id {
        fields.push(json!({
            "type": "mrkdwn",
            "text": format!("*Engagement:*\n`{eng}`"),
        }));
    }

    let mut blocks: Vec<Value> = vec![
        json!({
            "type": "header",
            "text": { "type": "plain_text", "text": header_text, "emoji": true },
        }),
        json!({ "type": "section", "fields": fields }),
    ];
    if let Some(detail) = &n.detail {
        blocks.push(json!({
            "type": "section",
            "text": { "type": "mrkdwn", "text": detail },
        }));
    }

    json!({
        // Plain-text fallback for clients that don't render blocks.
        "text": header_text,
        "attachments": [{
            "color": n.severity.color_hex(),
            "blocks": blocks,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification::Severity;

    #[test]
    fn minimal_notification_produces_valid_blocks() {
        let n = Notification::new("Test finding", Severity::High);
        let payload = format(&n);
        let attachments = payload["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 1);
        let blocks = attachments[0]["blocks"].as_array().unwrap();
        assert!(blocks.iter().any(|b| b["type"] == "header"));
    }

    #[test]
    fn severity_color_appears_on_attachment() {
        let n = Notification::new("t", Severity::Critical);
        let payload = format(&n);
        assert_eq!(payload["attachments"][0]["color"], "#8E1538");
    }

    #[test]
    fn target_renders_as_link_field() {
        let n = Notification::new("t", Severity::Medium).with_target("https://x.example/y");
        let payload = format(&n);
        let s = payload.to_string();
        assert!(s.contains("https://x.example/y"));
        assert!(s.contains("Target"));
    }

    #[test]
    fn detail_renders_as_extra_section() {
        let n = Notification::new("t", Severity::Low).with_detail("Full reproducer details");
        let payload = format(&n);
        let blocks = payload["attachments"][0]["blocks"].as_array().unwrap();
        let sections: Vec<&Value> = blocks.iter().filter(|b| b["type"] == "section").collect();
        // One section for fields, one for the detail text.
        assert_eq!(sections.len(), 2);
        assert!(payload.to_string().contains("Full reproducer details"));
    }

    #[test]
    fn no_detail_produces_one_section() {
        let n = Notification::new("t", Severity::Low);
        let payload = format(&n);
        let blocks = payload["attachments"][0]["blocks"].as_array().unwrap();
        let sections: Vec<&Value> = blocks.iter().filter(|b| b["type"] == "section").collect();
        assert_eq!(sections.len(), 1);
    }

    #[test]
    fn top_level_text_is_plain_text_fallback() {
        let n = Notification::new("Hello", Severity::Info);
        let payload = format(&n);
        // Slack uses top-level `text` as plain fallback for screen readers and
        // clients that don't support Block Kit.
        assert!(payload["text"].as_str().unwrap().contains("Hello"));
    }

    #[test]
    fn cwe_field_is_included_when_set() {
        let n = Notification::new("t", Severity::High).with_cwe("CWE-89");
        let payload = format(&n);
        assert!(payload.to_string().contains("CWE-89"));
    }
}
