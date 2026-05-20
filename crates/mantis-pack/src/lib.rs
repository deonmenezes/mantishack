//! Capability-pack abstraction.
//!
//! A `Pack` describes how a surface should be exploited: which
//! hunter to dispatch, which verifier to use, what brief profile
//! the hunter receives, and which replay tool the verifier calls
//! during the cascade. This abstraction lets the orchestrator route
//! findings without `if surface.type == "web"` ladders.
//!
//! v1 ships only the `web` pack. Future packs (`api`, `mobile`,
//! `static-asset`, `smart-contract-evm`, …) plug in by registering
//! a new [`Pack`] in [`PackRegistry`] without touching the
//! orchestrator or any of the cascade tooling.
//!
//! Mirrors hacker-bob's `capability-packs.js` design: the verifier
//! prompts read the routed pack's `replay_tool` instead of branching
//! on chain family, so adding a new surface category never requires
//! editing every downstream prompt.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Stable pack identifier. Persists in event logs and routing tables
/// — must never be renamed once minted.
pub type PackId = String;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pack {
    pub id: PackId,
    pub version: u32,
    /// Hunter agent identifier the orchestrator dispatches.
    pub hunter_agent: String,
    /// Brief profile passed to the hunter. Web hunters see
    /// `web.full`; smart-contract hunters see chain-specific
    /// briefs in future packs.
    pub brief_profile: String,
    /// Verifier replay tool. The brutalist / balanced / final
    /// rounds invoke this tool to replay each finding's PoC against
    /// fresh state.
    pub replay_tool: String,
    /// Optional sample type label (`http_replay`, `evm_foundry_run`,
    /// …) used by evidence packs.
    pub sample_type: String,
    /// Free-form `reasons` carried through to operator-facing
    /// route tables for debuggability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_reasons: Vec<String>,
}

impl Pack {
    /// Web pack — Mantis v1 default. Mirrors hacker-bob's `web` pack
    /// (`capability-packs.js` ~L80).
    pub fn web_v1() -> Self {
        Self {
            id: "web".into(),
            version: 1,
            hunter_agent: "hunter-web".into(),
            brief_profile: "web.full".into(),
            replay_tool: "http_scan".into(),
            sample_type: "http_replay".into(),
            default_reasons: vec!["surface_type=web".into()],
        }
    }
}

/// Outcome of classifying a surface — what pack, why, and how confident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDecision {
    pub pack_id: PackId,
    pub pack_version: u32,
    pub hunter_agent: String,
    pub brief_profile: String,
    pub replay_tool: String,
    pub sample_type: String,
    pub confidence: RouteConfidence,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteConfidence {
    /// Direct surface_type match — full confidence.
    High,
    /// Heuristic match (e.g. hostname pattern) — operator should review.
    Medium,
    /// Default fallback (no signal) — operator must classify.
    Low,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PackError {
    #[error("pack not found: {0}")]
    NotFound(PackId),
    #[error("pack already registered: {0}")]
    Duplicate(PackId),
    #[error("unsupported surface_type: {0}")]
    Unsupported(String),
}

/// Surface descriptor consumed by the routing function. Compact and
/// serializable so the daemon, MCP layer, and report-writer can all
/// pass it without pulling the scanner crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceDescriptor {
    pub surface_id: String,
    /// `web` | `api` | `mobile` | `static-asset` | `smart_contract` | etc.
    /// Empty/unknown triggers fallback routing.
    pub surface_type: Option<String>,
    /// Optional hint: HTTP scheme/method/url for web-like surfaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Optional hint: smart-contract chain family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_family: Option<String>,
}

/// In-memory registry of known packs. The daemon populates this at
/// startup from a workspace config; tests build it directly.
#[derive(Debug, Clone, Default)]
pub struct PackRegistry {
    packs: BTreeMap<PackId, Pack>,
}

impl PackRegistry {
    pub fn new() -> Self {
        Self {
            packs: BTreeMap::new(),
        }
    }

    /// Build a registry containing every default pack Mantis v1
    /// ships. Currently just `web`. Future versions add api/mobile.
    pub fn default_v1() -> Self {
        let mut r = Self::new();
        r.register(Pack::web_v1())
            .expect("web pack uniquely registered");
        r
    }

    pub fn register(&mut self, pack: Pack) -> Result<(), PackError> {
        if self.packs.contains_key(&pack.id) {
            return Err(PackError::Duplicate(pack.id));
        }
        self.packs.insert(pack.id.clone(), pack);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<&Pack, PackError> {
        self.packs
            .get(id)
            .ok_or_else(|| PackError::NotFound(id.into()))
    }

    pub fn pack_ids(&self) -> Vec<&str> {
        self.packs.keys().map(|s| s.as_str()).collect()
    }

    /// Route a surface to its pack. Returns the routing decision plus
    /// the reasons string list — both surface to operators via the
    /// session-state JSON.
    ///
    /// Routing rules (matched in order):
    /// 1. `surface_type == "smart_contract"` → smart-contract pack
    ///    keyed by `chain_family` (unsupported for v1 → error).
    /// 2. `surface_type == "web" | "api" | None` and `url` starts
    ///    with `http://`/`https://` → `web` pack (High confidence).
    /// 3. Default → `web` pack (Low confidence; operator should
    ///    classify).
    pub fn route(&self, descriptor: &SurfaceDescriptor) -> Result<RouteDecision, PackError> {
        let st = descriptor
            .surface_type
            .as_deref()
            .map(|s| s.to_ascii_lowercase());
        let url = descriptor.url.as_deref().unwrap_or("");
        let is_http_url = url.starts_with("http://") || url.starts_with("https://");

        if st.as_deref() == Some("smart_contract") {
            // v1 has no SC packs. Return an explicit error rather
            // than silently routing to `web`.
            let fam = descriptor
                .chain_family
                .clone()
                .unwrap_or_else(|| "unknown".into());
            return Err(PackError::Unsupported(format!(
                "smart_contract surface (chain_family={fam}) — no pack registered"
            )));
        }

        let (pack, confidence, mut reasons) = match (st.as_deref(), is_http_url) {
            (Some("web"), _) | (Some("api"), _) => (
                self.get("web")?,
                RouteConfidence::High,
                vec![format!("surface_type={}", st.as_deref().unwrap_or("web"))],
            ),
            (None, true) => (
                self.get("web")?,
                RouteConfidence::High,
                vec!["url_scheme=http".into()],
            ),
            (None, false) | (Some(_), _) => (
                self.get("web")?,
                RouteConfidence::Low,
                vec![format!(
                    "fallback: unrecognised surface_type={:?}",
                    st.as_deref().unwrap_or("(none)")
                )],
            ),
        };
        reasons.extend(pack.default_reasons.iter().cloned());

        Ok(RouteDecision {
            pack_id: pack.id.clone(),
            pack_version: pack.version,
            hunter_agent: pack.hunter_agent.clone(),
            brief_profile: pack.brief_profile.clone(),
            replay_tool: pack.replay_tool.clone(),
            sample_type: pack.sample_type.clone(),
            confidence,
            reasons,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(surface_type: Option<&str>, url: Option<&str>) -> SurfaceDescriptor {
        SurfaceDescriptor {
            surface_id: "s-1".into(),
            surface_type: surface_type.map(str::to_string),
            url: url.map(str::to_string),
            chain_family: None,
        }
    }

    #[test]
    fn default_registry_has_web() {
        let r = PackRegistry::default_v1();
        assert_eq!(r.pack_ids(), vec!["web"]);
        let p = r.get("web").unwrap();
        assert_eq!(p.replay_tool, "http_scan");
        assert_eq!(p.brief_profile, "web.full");
    }

    #[test]
    fn duplicate_register_rejected() {
        let mut r = PackRegistry::new();
        r.register(Pack::web_v1()).unwrap();
        let err = r.register(Pack::web_v1()).unwrap_err();
        assert_eq!(err, PackError::Duplicate("web".into()));
    }

    #[test]
    fn missing_pack_is_not_found() {
        let r = PackRegistry::new();
        let err = r.get("web").unwrap_err();
        assert!(matches!(err, PackError::NotFound(_)));
    }

    #[test]
    fn web_surface_type_routes_to_web_high_confidence() {
        let r = PackRegistry::default_v1();
        let d = descriptor(Some("web"), Some("https://example.com/"));
        let decision = r.route(&d).unwrap();
        assert_eq!(decision.pack_id, "web");
        assert_eq!(decision.confidence, RouteConfidence::High);
        assert_eq!(decision.replay_tool, "http_scan");
    }

    #[test]
    fn api_surface_type_also_routes_to_web() {
        let r = PackRegistry::default_v1();
        let d = descriptor(Some("api"), Some("https://api.example.com/v1/users"));
        let decision = r.route(&d).unwrap();
        assert_eq!(decision.pack_id, "web");
        assert_eq!(decision.confidence, RouteConfidence::High);
    }

    #[test]
    fn http_url_with_no_type_routes_to_web_high_confidence() {
        let r = PackRegistry::default_v1();
        let d = descriptor(None, Some("http://example.com/login"));
        let decision = r.route(&d).unwrap();
        assert_eq!(decision.pack_id, "web");
        assert_eq!(decision.confidence, RouteConfidence::High);
        assert!(decision.reasons.iter().any(|r| r.contains("url_scheme")));
    }

    #[test]
    fn unknown_type_falls_back_to_web_low_confidence() {
        let r = PackRegistry::default_v1();
        let d = descriptor(Some("mobile"), Some("ipa://Vulnerable.app"));
        let decision = r.route(&d).unwrap();
        assert_eq!(decision.pack_id, "web");
        assert_eq!(decision.confidence, RouteConfidence::Low);
        assert!(decision.reasons.iter().any(|r| r.contains("fallback")));
    }

    #[test]
    fn smart_contract_surface_type_is_unsupported() {
        let r = PackRegistry::default_v1();
        let d = SurfaceDescriptor {
            surface_id: "s-1".into(),
            surface_type: Some("smart_contract".into()),
            url: None,
            chain_family: Some("evm".into()),
        };
        let err = r.route(&d).unwrap_err();
        assert!(matches!(err, PackError::Unsupported(_)));
    }

    #[test]
    fn reasons_include_pack_defaults() {
        let r = PackRegistry::default_v1();
        let d = descriptor(Some("web"), Some("https://example.com/"));
        let decision = r.route(&d).unwrap();
        assert!(decision.reasons.iter().any(|r| r == "surface_type=web"));
    }

    #[test]
    fn decision_json_round_trips() {
        let r = PackRegistry::default_v1();
        let d = descriptor(Some("web"), Some("https://example.com/"));
        let decision = r.route(&d).unwrap();
        let j = serde_json::to_string(&decision).unwrap();
        let back: RouteDecision = serde_json::from_str(&j).unwrap();
        assert_eq!(decision, back);
    }
}
