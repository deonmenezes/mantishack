//! End-to-end engagement pipeline.
//!
//! Drives the loop that connects scanner → planner → primitive →
//! verifier → posterior update → event log. Phase 1 M1.7's central
//! integration. The pipeline runs synchronously per scan request;
//! Phase 2 will move it behind an `Engagement.Subscribe` streaming
//! RPC so the operator sees progress live.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::sync::Arc;

use mantis_claim::{verify_claim, Claim, ClaimState, SurfaceSnapshot};
use mantis_core::{EngagementId, Signer};
use mantis_event_store::{EventKind, EventStore};
use mantis_hypothesis::generate_for;
use mantis_planner::{Planner, SurfaceKey};
use mantis_posterior::Posteriors;
use mantis_primitive::{
    CachePoisoning, CommandInjection, CorsWildcard, CrlfInjection, FileUploadExtensionBypass,
    HostHeaderInjection, Idor, LdapInjection, MissingSecurityHeaders, NoSqlInjection, OpenRedirect,
    PathTraversal, Primitive, PrimitiveResult, SqliErrorBased, SsrfReflection, SstiBasic,
    SubdomainTakeoverDanglingCname, XssReflected, XxeBasic,
};
use mantis_scanner_http::Surface;
use mantis_tiered_exec::{
    build_codegen, llm_signal_present, Probe as TieredProbe, SubprocessSandbox, TieredRunner,
};
use reqwest::Client;
use tracing::{info, warn};

/// Build the static primitive catalog. Order doesn't matter — the
/// planner picks via UCB1.
pub(crate) fn build_catalog() -> Vec<Box<dyn Primitive>> {
    vec![
        // Original six.
        Box::new(MissingSecurityHeaders),
        Box::new(OpenRedirect),
        Box::new(CorsWildcard),
        Box::new(Idor),
        Box::new(XssReflected),
        Box::new(SqliErrorBased),
        // Extended catalog (twelve new vuln-class detectors).
        Box::new(SsrfReflection),
        Box::new(SstiBasic),
        Box::new(NoSqlInjection),
        Box::new(XxeBasic),
        Box::new(CrlfInjection),
        Box::new(HostHeaderInjection),
        Box::new(PathTraversal),
        Box::new(LdapInjection),
        Box::new(CommandInjection),
        Box::new(FileUploadExtensionBypass),
        Box::new(CachePoisoning),
        Box::new(SubdomainTakeoverDanglingCname),
    ]
}

/// Outcome counts returned to the RPC caller.
#[derive(Debug, Default)]
pub(crate) struct PipelineOutcome {
    pub hypotheses_recorded: u32,
    pub primitives_executed: u32,
    pub claims_verified: u32,
    pub claims_rejected: u32,
    pub claims_retained: u32,
    /// Surfaces escalated to the tiered (LLM-codegen) runner because
    /// the Rust primitives produced no confirmed claim. One entry per
    /// surface attempted.
    pub tiered_attempts: u32,
    /// Subset of `tiered_attempts` that produced an accepted finding.
    pub tiered_findings: u32,
}

/// Run the full pipeline over a list of discovered surfaces. Writes
/// events to the event store and updates the workspace posterior
/// store.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_pipeline(
    surfaces: &[Surface],
    catalog: &[Box<dyn Primitive>],
    event_store: &Arc<EventStore>,
    engagement_id: EngagementId,
    signer: &Arc<dyn Signer>,
    posteriors: &Posteriors,
    client: &Client,
    request_budget: u32,
) -> PipelineOutcome {
    let mut outcome = PipelineOutcome::default();
    let mut planner = Planner::new();
    // Track which surfaces produced at least one verified claim under
    // the cheap primitive layer; the tiered runner only escalates the
    // surfaces that didn't.
    let mut verified_surfaces: HashSet<String> = HashSet::new();
    // Track per-surface hypothesis summaries so the tiered runner can
    // build a clear objective string when it escalates.
    let mut surface_hypotheses: std::collections::HashMap<String, Vec<(String, String, u32)>> =
        std::collections::HashMap::new();

    // Hypothesis generation + planner registration.
    for surface in surfaces {
        for h in generate_for(surface) {
            let stack = surface
                .tech_hints
                .first()
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            let prior = posteriors.blended_prior(stack, &h.vuln_class, h.prior_pp10k);
            let surface_id = surface.target.url();
            let kind = EventKind::HypothesisGenerated {
                surface_id: surface_id.clone(),
                vuln_class: h.vuln_class.clone(),
                summary: h.summary.clone(),
                prior,
            };
            if let Err(e) = event_store.append(engagement_id, kind, signer.as_ref()) {
                warn!(error = %e, "failed to append HypothesisGenerated");
                continue;
            }
            outcome.hypotheses_recorded += 1;
            surface_hypotheses
                .entry(surface_id.clone())
                .or_default()
                .push((h.vuln_class.clone(), h.summary.clone(), prior));
            for primitive in catalog {
                if primitive.vuln_class() == h.vuln_class && primitive.matches_surface(surface) {
                    planner.register_action(
                        SurfaceKey(surface_id.clone()),
                        primitive.id().to_string(),
                        prior,
                    );
                }
            }
        }
    }

    // Drive the planner up to the budget.
    let surface_by_url: std::collections::HashMap<String, &Surface> =
        surfaces.iter().map(|s| (s.target.url(), s)).collect();

    for _ in 0..request_budget {
        let Some(action) = planner.next_action() else {
            break;
        };
        let action_id = action.id;
        let surface_url = action.surface_key.0.clone();
        let primitive_id = action.primitive_id.to_string();

        let Some(surface) = surface_by_url.get(surface_url.as_str()).copied() else {
            warn!(%surface_url, "planner returned action for unknown surface");
            planner.record_outcome(action_id, 0.0);
            continue;
        };
        let Some(primitive) = catalog.iter().find(|p| p.id() == primitive_id) else {
            warn!(%primitive_id, "planner returned action for unknown primitive");
            planner.record_outcome(action_id, 0.0);
            continue;
        };

        let result = match primitive.execute(surface, client).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, %primitive_id, "primitive execution error");
                planner.record_outcome(action_id, 0.0);
                continue;
            }
        };
        outcome.primitives_executed += 1;
        let verdict_kind = match &result {
            PrimitiveResult::Confirmed { .. } => "confirmed",
            PrimitiveResult::Denied { .. } => "denied",
            PrimitiveResult::Inconclusive { .. } => "inconclusive",
        };
        let _ = event_store.append(
            engagement_id,
            EventKind::PrimitiveExecuted {
                surface_id: surface_url.clone(),
                primitive_id: primitive_id.clone(),
                vuln_class: primitive.vuln_class().to_owned(),
                verdict: verdict_kind.to_owned(),
            },
            signer.as_ref(),
        );

        let stack = surface
            .tech_hints
            .first()
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        let (success, reward): (Option<bool>, f64) = match result {
            PrimitiveResult::Denied { .. } => (Some(false), 0.0),
            PrimitiveResult::Inconclusive { .. } => (None, 0.0),
            PrimitiveResult::Confirmed {
                evidence,
                reproducer,
            } => {
                // Build a Claim and run the verifier.
                let claim = Claim::pending(
                    primitive.id().to_string(),
                    primitive.vuln_class().to_string(),
                    SurfaceSnapshot::from(surface),
                    evidence,
                    reproducer,
                );
                match verify_claim(&claim, client).await {
                    Ok(ClaimState::Verified { verifier_id }) => {
                        outcome.claims_verified += 1;
                        verified_surfaces.insert(surface_url.clone());
                        let _ = event_store.append(
                            engagement_id,
                            EventKind::ClaimVerified {
                                surface_id: surface_url.clone(),
                                primitive_id: primitive_id.clone(),
                                verifier_id,
                            },
                            signer.as_ref(),
                        );
                        (Some(true), 1.0)
                    }
                    Ok(ClaimState::Rejected { reason }) => {
                        outcome.claims_rejected += 1;
                        let _ = event_store.append(
                            engagement_id,
                            EventKind::ClaimRejected {
                                surface_id: surface_url.clone(),
                                primitive_id: primitive_id.clone(),
                                reason,
                            },
                            signer.as_ref(),
                        );
                        (Some(false), 0.0)
                    }
                    Ok(ClaimState::Retained { reason }) => {
                        outcome.claims_retained += 1;
                        let _ = event_store.append(
                            engagement_id,
                            EventKind::ClaimRetained {
                                surface_id: surface_url.clone(),
                                primitive_id: primitive_id.clone(),
                                reason,
                            },
                            signer.as_ref(),
                        );
                        (None, 0.0)
                    }
                    Ok(ClaimState::Pending) | Err(_) => (None, 0.0),
                }
            }
        };

        if let Some(s) = success {
            posteriors.record_outcome(stack, primitive.vuln_class(), s);
        }
        planner.record_outcome(action_id, reward);
    }

    // ---------- Tiered LLM-codegen escalation ----------
    //
    // For every surface that produced hypotheses but no verified claim
    // under the cheap Rust primitives, escalate to the tiered runner
    // (medium tier: one-shot LLM codegen + sandbox; hard tier: verifier
    // loop). This is gated on (a) the operator having configured an
    // LLM provider (env var present) and (b) the per-surface cap.
    //
    // The runner produces structured `TieredFinding` events that the
    // grader phase picks up alongside primitive findings.
    if llm_signal_present() {
        let runner = TieredRunner::new(
            None, // light tier is the primitive layer; we already ran it
            build_codegen(None),
            Arc::new(SubprocessSandbox),
        );
        let tiered_cap = std::env::var("MANTIS_TIERED_CAP")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(5);
        let mut tiered_ran: usize = 0;
        for (surface_id, hypotheses) in surface_hypotheses.iter() {
            if tiered_ran >= tiered_cap {
                break;
            }
            if verified_surfaces.contains(surface_id) {
                continue;
            }
            // Build the objective: include every hypothesis the
            // surface had so the LLM can pick the most promising one.
            let mut objective = String::with_capacity(256);
            for (vc, summary, prior) in hypotheses {
                let _ = writeln!(objective, "[{vc} prior={prior}pp10k] {summary}");
            }
            let probe = TieredProbe {
                target_url: surface_id.clone(),
                objective,
                attacker_profile: None,
                victim_profile: None,
                budget_seconds: 30,
            };
            outcome.tiered_attempts += 1;
            tiered_ran += 1;
            let tiered = runner.run(&probe).await;
            if let Some(f) = tiered.finding {
                outcome.tiered_findings += 1;
                verified_surfaces.insert(surface_id.clone());
                let _ = event_store.append(
                    engagement_id,
                    EventKind::TieredFindingProduced {
                        surface_id: surface_id.clone(),
                        vuln_class: f.vuln_class,
                        tier: format!("{:?}", f.tier).to_ascii_lowercase(),
                        severity: f.severity,
                        verifier_verdict: f.verifier_verdict.unwrap_or_default(),
                        hard_iterations: f.hard_iterations,
                    },
                    signer.as_ref(),
                );
            } else {
                let _ = event_store.append(
                    engagement_id,
                    EventKind::TieredEscalationExhausted {
                        surface_id: surface_id.clone(),
                        light_result: tiered.light_result,
                        medium_result: tiered.medium_result,
                        hard_result: tiered.hard_result,
                        notes_joined: tiered.notes.join(" | "),
                    },
                    signer.as_ref(),
                );
            }
        }
    }

    info!(
        hypotheses = outcome.hypotheses_recorded,
        primitives = outcome.primitives_executed,
        verified = outcome.claims_verified,
        rejected = outcome.claims_rejected,
        retained = outcome.claims_retained,
        tiered_attempts = outcome.tiered_attempts,
        tiered_findings = outcome.tiered_findings,
        "pipeline complete"
    );
    outcome
}
