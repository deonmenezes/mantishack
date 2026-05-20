//! TieredRunner — drives light → medium → hard escalation.
//!
//! The runner owns the three tier objects + the LLM/sandbox adapters
//! and exposes `run_tiered(probe)`. Light tier first: cheap, fixed
//! Rust probes. On miss, escalate to medium (one-shot LLM exploit).
//! On miss, escalate to hard (verifier-loop LLM iteration).
//!
//! Light-tier failures DO NOT block escalation — a broken Rust
//! primitive shouldn't deny the operator the more-expensive tiers.

use crate::adapter::{LlmAttempt, LlmCodegen, SandboxRunner};
use crate::tier::{Tier, TierKind, TierResult};
use crate::verifier::{verify_finding, VerifierConfig};
use crate::{Probe, TieredFinding};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// One run-result. Aggregates per-tier verdicts so operators see
/// the full escalation chain even when an earlier tier produced
/// the finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TieredOutcome {
    pub finding: Option<TieredFinding>,
    pub light_result: Option<String>,
    pub medium_result: Option<String>,
    pub hard_result: Option<String>,
    pub notes: Vec<String>,
}

pub struct TieredRunner {
    pub light: Option<Arc<dyn Tier>>,
    pub llm: Arc<dyn LlmCodegen>,
    pub sandbox: Arc<dyn SandboxRunner>,
    pub verifier: VerifierConfig,
    pub hard_max_iterations: u32,
    pub per_tier_timeout_secs: u32,
}

impl TieredRunner {
    pub fn new(
        light: Option<Arc<dyn Tier>>,
        llm: Arc<dyn LlmCodegen>,
        sandbox: Arc<dyn SandboxRunner>,
    ) -> Self {
        Self {
            light,
            llm,
            sandbox,
            verifier: VerifierConfig::default(),
            hard_max_iterations: 3,
            per_tier_timeout_secs: 30,
        }
    }

    pub fn with_verifier(mut self, cfg: VerifierConfig) -> Self {
        self.verifier = cfg;
        self
    }

    pub fn with_hard_max_iterations(mut self, n: u32) -> Self {
        self.hard_max_iterations = n;
        self
    }

    pub async fn run(&self, probe: &Probe) -> TieredOutcome {
        let mut outcome = TieredOutcome {
            finding: None,
            light_result: None,
            medium_result: None,
            hard_result: None,
            notes: Vec::new(),
        };

        // Light tier.
        if let Some(light) = &self.light {
            match light.run(probe).await {
                TierResult::Found(f) => {
                    outcome.light_result = Some("found".into());
                    outcome.finding = Some(f);
                    return outcome;
                }
                TierResult::Miss => {
                    outcome.light_result = Some("miss".into());
                }
                TierResult::Error(e) => {
                    outcome.light_result = Some(format!("error: {e}"));
                    outcome.notes.push(format!("light tier error: {e}"));
                }
            }
        } else {
            outcome.notes.push("light tier not configured".into());
        }

        // Medium tier — one LLM round.
        match self.run_medium(probe).await {
            Ok(Some(f)) => {
                outcome.medium_result = Some("found".into());
                outcome.finding = Some(f);
                return outcome;
            }
            Ok(None) => {
                outcome.medium_result = Some("miss".into());
            }
            Err(e) => {
                outcome.medium_result = Some(format!("error: {e}"));
                outcome.notes.push(format!("medium tier error: {e}"));
            }
        }

        // Hard tier — verifier loop.
        match self.run_hard(probe).await {
            Ok(Some(f)) => {
                outcome.hard_result = Some(format!("found in {} iter(s)", f.hard_iterations));
                outcome.finding = Some(f);
            }
            Ok(None) => {
                outcome.hard_result =
                    Some(format!("miss after {} iter(s)", self.hard_max_iterations));
            }
            Err(e) => {
                outcome.hard_result = Some(format!("error: {e}"));
                outcome.notes.push(format!("hard tier error: {e}"));
            }
        }

        outcome
    }

    async fn run_medium(&self, probe: &Probe) -> Result<Option<TieredFinding>, String> {
        let script = self
            .llm
            .generate(probe, &[])
            .await
            .map_err(|e| e.to_string())?;
        let env = build_env(probe);
        let out = self
            .sandbox
            .run(&script, &env, self.per_tier_timeout_secs)
            .await
            .map_err(|e| e.to_string())?;
        let verdict = verify_finding(&out, &self.verifier);
        if verdict.accepted() {
            let evidence = match &verdict {
                crate::verifier::VerifierVerdict::Accepted {
                    evidence_excerpt, ..
                } => evidence_excerpt.clone(),
                _ => String::new(),
            };
            return Ok(Some(TieredFinding {
                tier: TierKind::Medium,
                vuln_class: classify_objective(&probe.objective),
                severity: "high".into(),
                url: probe.target_url.clone(),
                evidence,
                script: Some(script),
                verifier_verdict: Some(verdict.short_label().to_string()),
                hard_iterations: 0,
            }));
        }
        Ok(None)
    }

    async fn run_hard(&self, probe: &Probe) -> Result<Option<TieredFinding>, String> {
        let mut attempts: Vec<LlmAttempt> = Vec::new();
        for iter in 1..=self.hard_max_iterations {
            let script = self
                .llm
                .generate(probe, &attempts)
                .await
                .map_err(|e| e.to_string())?;
            let env = build_env(probe);
            let out = self
                .sandbox
                .run(&script, &env, self.per_tier_timeout_secs)
                .await
                .map_err(|e| e.to_string())?;
            let verdict = verify_finding(&out, &self.verifier);
            if verdict.accepted() {
                let evidence = match &verdict {
                    crate::verifier::VerifierVerdict::Accepted {
                        evidence_excerpt, ..
                    } => evidence_excerpt.clone(),
                    _ => String::new(),
                };
                return Ok(Some(TieredFinding {
                    tier: TierKind::Hard,
                    vuln_class: classify_objective(&probe.objective),
                    severity: "high".into(),
                    url: probe.target_url.clone(),
                    evidence,
                    script: Some(script),
                    verifier_verdict: Some(verdict.short_label().to_string()),
                    hard_iterations: iter,
                }));
            }
            attempts.push(LlmAttempt {
                script,
                output: out,
                verdict: verdict.short_label().to_string(),
            });
        }
        Ok(None)
    }
}

/// Free-function shortcut for callers who don't want to keep a runner around.
pub async fn run_tiered(runner: &TieredRunner, probe: &Probe) -> TieredOutcome {
    runner.run(probe).await
}

fn build_env(probe: &Probe) -> Vec<(String, String)> {
    let mut env = vec![
        ("MANTIS_TARGET_URL".into(), probe.target_url.clone()),
        ("MANTIS_OBJECTIVE".into(), probe.objective.clone()),
    ];
    if let Some(p) = &probe.attacker_profile {
        for h in &p.headers {
            env.push((
                format!(
                    "MANTIS_ATTACKER_{}",
                    h.name.to_ascii_uppercase().replace('-', "_")
                ),
                h.value.clone(),
            ));
        }
    }
    if let Some(p) = &probe.victim_profile {
        for h in &p.headers {
            env.push((
                format!(
                    "MANTIS_VICTIM_{}",
                    h.name.to_ascii_uppercase().replace('-', "_")
                ),
                h.value.clone(),
            ));
        }
    }
    env
}

fn classify_objective(objective: &str) -> String {
    let lower = objective.to_ascii_lowercase();
    if lower.contains("idor") {
        "broken-access-control.idor".into()
    } else if lower.contains("mass-assignment") || lower.contains("mass assignment") {
        "broken-access-control.mass-assignment".into()
    } else if lower.contains("cross-tenant") || lower.contains("tenant") {
        "broken-access-control.cross-tenant-read".into()
    } else if lower.contains("sqli") || lower.contains("sql injection") {
        "sqli".into()
    } else if lower.contains("xss") {
        "xss-reflected".into()
    } else if lower.contains("ssrf") {
        "ssrf".into()
    } else if lower.contains("rce") {
        "rce".into()
    } else {
        "unknown".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{MockLlm, NullLlm, SubprocessSandbox};
    use crate::tier::TierResult;
    use std::pin::Pin;

    struct AlwaysMissTier;
    impl Tier for AlwaysMissTier {
        fn kind(&self) -> TierKind {
            TierKind::Light
        }
        fn run<'a>(
            &'a self,
            _probe: &'a Probe,
        ) -> Pin<Box<dyn std::future::Future<Output = TierResult> + Send + 'a>> {
            Box::pin(async move { TierResult::Miss })
        }
    }

    struct AlwaysFoundTier;
    impl Tier for AlwaysFoundTier {
        fn kind(&self) -> TierKind {
            TierKind::Light
        }
        fn run<'a>(
            &'a self,
            probe: &'a Probe,
        ) -> Pin<Box<dyn std::future::Future<Output = TierResult> + Send + 'a>> {
            let url = probe.target_url.clone();
            Box::pin(async move {
                TierResult::Found(TieredFinding {
                    tier: TierKind::Light,
                    vuln_class: "auth-bypass".into(),
                    severity: "critical".into(),
                    url,
                    evidence: "light tier fixed pattern matched".into(),
                    script: None,
                    verifier_verdict: None,
                    hard_iterations: 0,
                })
            })
        }
    }

    fn probe() -> Probe {
        Probe {
            target_url: "https://x".into(),
            objective: "test cross-tenant read".into(),
            attacker_profile: None,
            victim_profile: None,
            budget_seconds: 5,
        }
    }

    #[tokio::test]
    async fn light_hit_short_circuits() {
        let runner = TieredRunner::new(
            Some(Arc::new(AlwaysFoundTier)),
            Arc::new(NullLlm),
            Arc::new(SubprocessSandbox),
        );
        let out = runner.run(&probe()).await;
        assert!(out.finding.is_some());
        assert_eq!(out.light_result.as_deref(), Some("found"));
        assert!(out.medium_result.is_none());
        assert!(out.hard_result.is_none());
    }

    #[tokio::test]
    async fn light_miss_escalates_to_medium_then_hard_on_null_llm() {
        let runner = TieredRunner::new(
            Some(Arc::new(AlwaysMissTier)),
            Arc::new(NullLlm),
            Arc::new(SubprocessSandbox),
        );
        let out = runner.run(&probe()).await;
        assert_eq!(out.light_result.as_deref(), Some("miss"));
        // NullLlm returns an error, so medium and hard report errors.
        assert!(out
            .medium_result
            .as_deref()
            .unwrap_or("")
            .starts_with("error"));
        assert!(out
            .hard_result
            .as_deref()
            .unwrap_or("")
            .starts_with("error"));
        assert!(out.finding.is_none());
    }

    #[tokio::test]
    async fn medium_tier_accepts_when_llm_script_emits_positive_marker() {
        let llm = MockLlm {
            script: "#!/bin/bash\necho \"victim-org found\"".into(),
        };
        let runner = TieredRunner::new(
            Some(Arc::new(AlwaysMissTier)),
            Arc::new(llm),
            Arc::new(SubprocessSandbox),
        )
        .with_verifier(VerifierConfig {
            positive_markers: vec!["victim-org".into()],
            negative_markers: vec![],
        });
        let out = runner.run(&probe()).await;
        let f = out.finding.expect("medium tier should accept");
        assert_eq!(f.tier, TierKind::Medium);
        assert!(f.evidence.contains("victim-org"));
        assert!(f.script.is_some());
    }

    #[tokio::test]
    async fn hard_tier_iterates_when_medium_misses_inconclusively() {
        // Mock LLM that never produces a hit. Hard tier should
        // exhaust its iteration budget cleanly.
        let llm = MockLlm {
            script: "#!/bin/bash\necho 'nothing interesting'".into(),
        };
        let runner = TieredRunner::new(
            Some(Arc::new(AlwaysMissTier)),
            Arc::new(llm),
            Arc::new(SubprocessSandbox),
        )
        .with_verifier(VerifierConfig {
            positive_markers: vec!["never-matches".into()],
            negative_markers: vec![],
        })
        .with_hard_max_iterations(2);
        let out = runner.run(&probe()).await;
        assert!(out.finding.is_none());
        assert!(out
            .hard_result
            .as_deref()
            .unwrap_or("")
            .contains("miss after 2"));
    }

    #[test]
    fn classify_objective_picks_idor() {
        assert_eq!(
            classify_objective("test IDOR on /api"),
            "broken-access-control.idor"
        );
        assert_eq!(
            classify_objective("mass assignment via PATCH"),
            "broken-access-control.mass-assignment"
        );
        assert_eq!(classify_objective("test SSRF"), "ssrf");
        assert_eq!(
            classify_objective("test cross-tenant access"),
            "broken-access-control.cross-tenant-read"
        );
        assert_eq!(classify_objective("random thing"), "unknown");
    }

    #[test]
    fn build_env_includes_target_and_auth_headers() {
        let mut p = probe();
        p.attacker_profile = Some(mantis_auth::AuthProfile {
            name: "attacker".into(),
            headers: vec![mantis_auth::AuthHeader {
                name: "Authorization".into(),
                value: "Bearer ATT".into(),
            }],
            cookies: vec![],
            query: vec![],
            expires_at_unix: None,
            created_at_unix: 0,
            origin: "test".into(),
        });
        let env = build_env(&p);
        assert!(env.iter().any(|(k, _)| k == "MANTIS_TARGET_URL"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "MANTIS_ATTACKER_AUTHORIZATION" && v == "Bearer ATT"));
    }
}
