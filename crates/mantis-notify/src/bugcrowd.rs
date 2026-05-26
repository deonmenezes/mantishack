//! Bugcrowd `submissions` create payload formatter.
//!
//! Spec: <https://docs.bugcrowd.com/api/getting-started/> (Researcher API,
//! Submissions). Bugcrowd uses a JSON:API style envelope similar to
//! HackerOne's, with attributes plus a `relationships` block tying the
//! submission to a target.

use serde_json::{json, Value};

use crate::notification::{Notification, Severity};

/// Bugcrowd VRT (Vulnerability Rating Taxonomy) severity buckets, P1–P5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Vrt {
    /// P1 — Critical (RCE, full account takeover with no interaction).
    P1,
    /// P2 — High.
    P2,
    /// P3 — Medium.
    P3,
    /// P4 — Low.
    P4,
    /// P5 — Informational.
    P5,
}

impl Vrt {
    /// Canonical numeric identifier used by Bugcrowd's API.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P1 => "P1",
            Self::P2 => "P2",
            Self::P3 => "P3",
            Self::P4 => "P4",
            Self::P5 => "P5",
        }
    }
}

/// Map Mantis severity to Bugcrowd VRT priority.
pub const fn severity_to_vrt(severity: Severity) -> Vrt {
    match severity {
        Severity::Critical => Vrt::P1,
        Severity::High => Vrt::P2,
        Severity::Medium => Vrt::P3,
        Severity::Low => Vrt::P4,
        Severity::Info => Vrt::P5,
    }
}

/// Required + optional Bugcrowd submission config.
#[derive(Debug, Clone)]
pub struct BugcrowdConfig<'a> {
    /// Target/program identifier (Bugcrowd `target_id`).
    pub target_id: &'a str,
    /// Optional VRT override. When `None`, auto-mapped from severity.
    pub vrt: Option<Vrt>,
    /// Optional VRT taxonomy category id (e.g. `"server_security_misconfiguration"`).
    pub vrt_category: Option<&'a str>,
}

impl<'a> BugcrowdConfig<'a> {
    /// Minimal config.
    pub fn new(target_id: &'a str) -> Self {
        Self {
            target_id,
            vrt: None,
            vrt_category: None,
        }
    }
}

/// Render a [`Notification`] as a Bugcrowd submission create body.
pub fn format(n: &Notification, cfg: &BugcrowdConfig<'_>) -> Value {
    let vrt = cfg.vrt.unwrap_or_else(|| severity_to_vrt(n.severity));

    let mut attributes = serde_json::Map::new();
    attributes.insert("title".into(), Value::String(n.title.clone()));
    attributes.insert(
        "description".into(),
        Value::String(submission_body(n)),
    );
    attributes.insert("priority".into(), Value::String(vrt.as_str().to_string()));
    if let Some(category) = cfg.vrt_category {
        attributes.insert("vrt_id".into(), Value::String(category.to_string()));
    }
    if let Some(target) = &n.target {
        attributes.insert("bug_url".into(), Value::String(target.clone()));
    }

    let relationships = json!({
        "target": {
            "data": { "type": "target", "id": cfg.target_id }
        }
    });

    json!({
        "data": {
            "type": "submission",
            "attributes": attributes,
            "relationships": relationships,
        }
    })
}

fn submission_body(n: &Notification) -> String {
    let mut out = String::new();
    if let Some(detail) = &n.detail {
        out.push_str("## Description\n\n");
        out.push_str(detail);
        out.push_str("\n\n");
    }
    out.push_str(&format!("**Severity:** {}\n", n.severity.label()));
    if let Some(cwe) = &n.cwe {
        out.push_str(&format!("**CWE:** {cwe}\n"));
    }
    if let Some(target) = &n.target {
        out.push_str(&format!("**Target:** {target}\n"));
    }
    if let Some(eng) = &n.engagement_id {
        out.push_str(&format!("\nSubmitted by Mantis engagement `{eng}`.\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_has_jsonapi_envelope_with_submission_type() {
        let n = Notification::new("t", Severity::High);
        let p = format(&n, &BugcrowdConfig::new("target-uuid"));
        assert_eq!(p["data"]["type"], "submission");
    }

    #[test]
    fn relationships_link_to_target() {
        let n = Notification::new("t", Severity::High);
        let p = format(&n, &BugcrowdConfig::new("target-uuid"));
        assert_eq!(p["data"]["relationships"]["target"]["data"]["type"], "target");
        assert_eq!(p["data"]["relationships"]["target"]["data"]["id"], "target-uuid");
    }

    #[test]
    fn severity_maps_to_vrt_priority() {
        for (sev, expected) in [
            (Severity::Critical, "P1"),
            (Severity::High, "P2"),
            (Severity::Medium, "P3"),
            (Severity::Low, "P4"),
            (Severity::Info, "P5"),
        ] {
            let n = Notification::new("t", sev);
            let p = format(&n, &BugcrowdConfig::new("target-uuid"));
            assert_eq!(p["data"]["attributes"]["priority"], expected, "severity {sev:?}");
        }
    }

    #[test]
    fn explicit_vrt_overrides_auto_mapping() {
        let n = Notification::new("t", Severity::Low);
        let mut cfg = BugcrowdConfig::new("target-uuid");
        cfg.vrt = Some(Vrt::P1);
        let p = format(&n, &cfg);
        assert_eq!(p["data"]["attributes"]["priority"], "P1");
    }

    #[test]
    fn vrt_category_included_when_set() {
        let n = Notification::new("t", Severity::Medium);
        let mut cfg = BugcrowdConfig::new("target-uuid");
        cfg.vrt_category = Some("server_security_misconfiguration");
        let p = format(&n, &cfg);
        assert_eq!(
            p["data"]["attributes"]["vrt_id"],
            "server_security_misconfiguration"
        );
    }

    #[test]
    fn target_url_lifts_to_bug_url_attribute() {
        let n = Notification::new("t", Severity::High).with_target("https://x/y");
        let p = format(&n, &BugcrowdConfig::new("target-uuid"));
        assert_eq!(p["data"]["attributes"]["bug_url"], "https://x/y");
    }

    #[test]
    fn target_url_omitted_when_unset() {
        let n = Notification::new("t", Severity::High);
        let p = format(&n, &BugcrowdConfig::new("target-uuid"));
        assert!(p["data"]["attributes"].get("bug_url").is_none());
    }

    #[test]
    fn description_markdown_contains_detail() {
        let n = Notification::new("t", Severity::Medium).with_detail("Reproducer body");
        let p = format(&n, &BugcrowdConfig::new("target-uuid"));
        let desc = p["data"]["attributes"]["description"].as_str().unwrap();
        assert!(desc.contains("Reproducer body"));
        assert!(desc.contains("**Severity:** Medium"));
    }

    #[test]
    fn vrt_as_str_emits_canonical_priority_id() {
        assert_eq!(Vrt::P1.as_str(), "P1");
        assert_eq!(Vrt::P5.as_str(), "P5");
    }
}
