//! Discord webhook payload formatter (embed-based).
//!
//! Spec: <https://discord.com/developers/docs/resources/webhook#execute-webhook>.

use serde_json::{json, Value};

use crate::notification::Notification;

pub(crate) fn format(n: &Notification) -> Value {
    let mut fields: Vec<Value> = Vec::new();
    fields.push(json!({
        "name": "Severity",
        "value": n.severity.label(),
        "inline": true,
    }));
    if let Some(cwe) = &n.cwe {
        fields.push(json!({ "name": "CWE", "value": cwe, "inline": true }));
    }
    if let Some(eng) = &n.engagement_id {
        fields.push(json!({ "name": "Engagement", "value": eng, "inline": true }));
    }
    if let Some(target) = &n.target {
        fields.push(json!({
            "name": "Target",
            "value": target,
            "inline": false,
        }));
    }

    let embed = json!({
        "title": format!("{} {}", n.severity.emoji(), n.title),
        "description": n.detail.as_deref().unwrap_or(""),
        // Discord wants the color as a decimal integer, not a hex string.
        "color": hex_to_decimal(n.severity.color_hex()),
        "fields": fields,
    });

    json!({
        "username": "Mantis",
        "embeds": [embed],
    })
}

fn hex_to_decimal(hex: &str) -> u32 {
    // hex is `"#RRGGBB"` from `Severity::color_hex`. Strip prefix and parse.
    let trimmed = hex.trim_start_matches('#');
    u32::from_str_radix(trimmed, 16).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification::Severity;

    #[test]
    fn produces_single_embed() {
        let n = Notification::new("t", Severity::High);
        let payload = format(&n);
        let embeds = payload["embeds"].as_array().unwrap();
        assert_eq!(embeds.len(), 1);
    }

    #[test]
    fn color_is_decimal_integer_not_hex_string() {
        let n = Notification::new("t", Severity::Critical);
        let payload = format(&n);
        let color = &payload["embeds"][0]["color"];
        assert!(color.is_number(), "Discord requires decimal color, not string");
    }

    #[test]
    fn hex_to_decimal_known_values() {
        assert_eq!(hex_to_decimal("#000000"), 0);
        assert_eq!(hex_to_decimal("#FFFFFF"), 0xFFFFFF);
        assert_eq!(hex_to_decimal("#8E1538"), 0x8E1538);
    }

    #[test]
    fn title_includes_severity_emoji() {
        let n = Notification::new("Hello", Severity::Critical);
        let payload = format(&n);
        let title = payload["embeds"][0]["title"].as_str().unwrap();
        assert!(title.contains("Hello"));
        assert!(title.contains("🚨"));
    }

    #[test]
    fn detail_appears_as_description() {
        let n = Notification::new("t", Severity::Low).with_detail("body");
        let payload = format(&n);
        assert_eq!(payload["embeds"][0]["description"], "body");
    }

    #[test]
    fn missing_detail_gives_empty_description() {
        let n = Notification::new("t", Severity::Low);
        let payload = format(&n);
        assert_eq!(payload["embeds"][0]["description"], "");
    }

    #[test]
    fn target_renders_as_non_inline_field() {
        let n = Notification::new("t", Severity::Medium).with_target("https://x/y");
        let payload = format(&n);
        let fields = payload["embeds"][0]["fields"].as_array().unwrap();
        let target_field = fields
            .iter()
            .find(|f| f["name"] == "Target")
            .expect("target field");
        assert_eq!(target_field["inline"], false);
        assert_eq!(target_field["value"], "https://x/y");
    }

    #[test]
    fn username_is_mantis() {
        let n = Notification::new("t", Severity::Info);
        let payload = format(&n);
        assert_eq!(payload["username"], "Mantis");
    }
}
