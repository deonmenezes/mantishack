//! HackerOne `reports` create payload formatter.
//!
//! Spec: <https://api.hackerone.com/customer-resources/#reports-create-report>.
//!
//! The endpoint `POST /v1/hackers/reports` (hacker-side) accepts a JSON:API
//! shaped body whose `data.attributes` carries the report. We render that
//! body from a Mantis [`Notification`] plus engagement context.

use serde_json::{json, Value};

use crate::notification::{Notification, Severity};

/// Required + optional fields for a HackerOne report submission.
#[derive(Debug, Clone)]
pub struct HackerOneConfig<'a> {
    /// Target program handle (e.g. `"acme"`).
    pub program_handle: &'a str,
    /// Optional severity rating override. When `None`, the rating is mapped
    /// from the notification severity by [`severity_to_rating`].
    pub severity_rating: Option<&'a str>,
    /// Optional list of weakness IDs the report cites (HackerOne weakness IDs,
    /// not raw CWE strings).
    pub weakness_id: Option<u64>,
    /// Optional asset identifier on HackerOne (structured-scope asset_identifier).
    pub asset_identifier: Option<&'a str>,
}

impl<'a> HackerOneConfig<'a> {
    /// Minimal config with only the program handle.
    pub fn new(program_handle: &'a str) -> Self {
        Self {
            program_handle,
            severity_rating: None,
            weakness_id: None,
            asset_identifier: None,
        }
    }
}

/// Map Mantis severity to HackerOne severity rating string.
pub const fn severity_to_rating(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "none",
    }
}

/// Render a [`Notification`] as a HackerOne `reports` create body.
pub fn format(n: &Notification, cfg: &HackerOneConfig<'_>) -> Value {
    let severity_rating = cfg
        .severity_rating
        .unwrap_or_else(|| severity_to_rating(n.severity));

    let mut attributes = serde_json::Map::new();
    attributes.insert("team_handle".into(), Value::String(cfg.program_handle.to_string()));
    attributes.insert("title".into(), Value::String(n.title.clone()));
    attributes.insert(
        "vulnerability_information".into(),
        Value::String(report_body(n)),
    );
    attributes.insert("severity_rating".into(), Value::String(severity_rating.to_string()));
    if let Some(wid) = cfg.weakness_id {
        attributes.insert("weakness_id".into(), Value::Number(wid.into()));
    }
    if let Some(asset) = cfg.asset_identifier {
        attributes.insert(
            "structured_scope_attributes".into(),
            json!({ "asset_identifier": asset }),
        );
    }

    json!({
        "data": {
            "type": "report",
            "attributes": attributes,
        }
    })
}

fn report_body(n: &Notification) -> String {
    let mut out = String::new();
    if let Some(target) = &n.target {
        out.push_str(&format!("**Target:** {target}\n\n"));
    }
    if let Some(cwe) = &n.cwe {
        out.push_str(&format!("**CWE:** {cwe}\n\n"));
    }
    if let Some(detail) = &n.detail {
        out.push_str("## Description\n\n");
        out.push_str(detail);
        out.push_str("\n\n");
    }
    out.push_str(&format!("**Severity:** {}\n", n.severity.label()));
    if let Some(eng) = &n.engagement_id {
        out.push_str(&format!("\nReported by Mantis engagement `{eng}`.\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_has_jsonapi_envelope() {
        let n = Notification::new("t", Severity::High);
        let p = format(&n, &HackerOneConfig::new("acme"));
        assert_eq!(p["data"]["type"], "report");
        assert!(p["data"]["attributes"].is_object());
    }

    #[test]
    fn program_handle_is_included() {
        let n = Notification::new("t", Severity::High);
        let p = format(&n, &HackerOneConfig::new("acme"));
        assert_eq!(p["data"]["attributes"]["team_handle"], "acme");
    }

    #[test]
    fn severity_auto_maps_to_rating_string() {
        for (sev, expected) in [
            (Severity::Critical, "critical"),
            (Severity::High, "high"),
            (Severity::Medium, "medium"),
            (Severity::Low, "low"),
            (Severity::Info, "none"),
        ] {
            let n = Notification::new("t", sev);
            let p = format(&n, &HackerOneConfig::new("acme"));
            assert_eq!(p["data"]["attributes"]["severity_rating"], expected);
        }
    }

    #[test]
    fn explicit_severity_rating_overrides_auto_mapping() {
        let n = Notification::new("t", Severity::Low);
        let mut cfg = HackerOneConfig::new("acme");
        cfg.severity_rating = Some("critical");
        let p = format(&n, &cfg);
        assert_eq!(p["data"]["attributes"]["severity_rating"], "critical");
    }

    #[test]
    fn vulnerability_information_includes_description_target_cwe() {
        let n = Notification::new("t", Severity::High)
            .with_target("https://x/y")
            .with_cwe("CWE-89")
            .with_detail("Body text");
        let p = format(&n, &HackerOneConfig::new("acme"));
        let body = p["data"]["attributes"]["vulnerability_information"]
            .as_str()
            .unwrap();
        assert!(body.contains("Body text"));
        assert!(body.contains("https://x/y"));
        assert!(body.contains("CWE-89"));
        assert!(body.contains("Severity"));
    }

    #[test]
    fn weakness_id_omitted_when_unset() {
        let n = Notification::new("t", Severity::High);
        let p = format(&n, &HackerOneConfig::new("acme"));
        assert!(p["data"]["attributes"].get("weakness_id").is_none());
    }

    #[test]
    fn weakness_id_included_when_set() {
        let n = Notification::new("t", Severity::High);
        let mut cfg = HackerOneConfig::new("acme");
        cfg.weakness_id = Some(31);
        let p = format(&n, &cfg);
        assert_eq!(p["data"]["attributes"]["weakness_id"], 31);
    }

    #[test]
    fn asset_identifier_nested_under_structured_scope() {
        let n = Notification::new("t", Severity::Medium);
        let mut cfg = HackerOneConfig::new("acme");
        cfg.asset_identifier = Some("example.com");
        let p = format(&n, &cfg);
        assert_eq!(
            p["data"]["attributes"]["structured_scope_attributes"]["asset_identifier"],
            "example.com"
        );
    }
}
