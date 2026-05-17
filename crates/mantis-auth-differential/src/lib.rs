//! Multi-account auth-differential runner.
//!
//! Ports hacker-bob's `mcp/lib/auth-differential.js` +
//! `auth-differential-runner.js`. The premise: most web vulns
//! visible to an external tester (cross-tenant read, IDOR,
//! mass-assignment, broken access control, open public endpoint)
//! become trivially classifiable when you replay the same request
//! under multiple auth profiles and compare the response *shapes*.
//!
//! Inputs: an URL + 1..N [`ProfileResponse`]s.
//! Outputs: zero or more [`DiffFinding`]s — each one carrying a
//! [`DivergenceClass`] and the evidence string for the report.
//!
//! Tunable: shape comparison ignores volatile fields (timestamps,
//! request-id headers, cache pragma) so divergence reflects
//! actual authorization decisions, not server-side jitter.

pub mod classify;
pub mod runner;
pub mod shape;

pub use crate::classify::{
    classify, DiffFinding, DivergenceClass, ProfileResponse, ProfileRole,
};
pub use crate::runner::{run_differential, ProfileBinding, RunnerConfig, RunnerError};
pub use crate::shape::{ResponseShape, ShapeSignature};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthDiffError {
    #[error("at least one profile response is required")]
    NoProfiles,
    #[error("duplicate profile role: {0:?}")]
    DuplicateRole(ProfileRole),
}

/// Convenience builder: run the classifier and translate every
/// `DiffFinding` into a [`mantis_fsm::FindingSummary`] suitable
/// for the goal evaluator and report renderer.
pub fn classify_to_findings(
    url: &str,
    responses: &[ProfileResponse],
) -> Result<Vec<mantis_fsm::FindingSummary>, AuthDiffError> {
    let findings = classify(url, responses)?;
    Ok(findings
        .into_iter()
        .map(|f| mantis_fsm::FindingSummary {
            finding_id: f.finding_id,
            vuln_class: f.class.vuln_class().to_string(),
            severity: f.class.default_severity().to_string(),
        })
        .collect())
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::classify::{ProfileResponse, ProfileRole};

    fn body(json: &str) -> serde_json::Value {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn cross_tenant_read_classifies_when_attacker_sees_victim_data() {
        // F-12-style: GET /rest/v1/orders.
        // Unauth → 401. Attacker → 200 with rows. Victim → 200 with same rows shape.
        // The attacker's response includes rows belonging to victim's org → cross-tenant read.
        let rs = vec![
            ProfileResponse::new(ProfileRole::Unauthenticated, 401, body(r#"{"message":"JWT expired"}"#)),
            ProfileResponse::new(ProfileRole::Attacker, 200, body(r#"[{"id":"o1","organization_id":"victim-org","total":500}]"#)),
            ProfileResponse::new(ProfileRole::Victim, 200, body(r#"[{"id":"o1","organization_id":"victim-org","total":500}]"#)),
        ];
        let findings = classify("https://x/rest/v1/orders", &rs).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.class, DivergenceClass::CrossTenantRead)),
            "expected CrossTenantRead, got {findings:?}"
        );
    }

    #[test]
    fn open_public_table_detected_when_unauth_sees_data() {
        // F-10-style: GET /rest/v1/users with anon JWT only.
        let rs = vec![
            ProfileResponse::new(
                ProfileRole::Unauthenticated,
                200,
                body(r#"[{"id":1,"email":"a@b.com"}]"#),
            ),
            ProfileResponse::new(
                ProfileRole::Attacker,
                200,
                body(r#"[{"id":1,"email":"a@b.com"}]"#),
            ),
        ];
        let findings = classify("https://x/rest/v1/users", &rs).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.class, DivergenceClass::UnauthSuccessWithAuthBlocked)
                    || matches!(f.class, DivergenceClass::PublicTableSensitiveFields)),
            "expected open-table classification, got {findings:?}"
        );
    }

    #[test]
    fn no_finding_when_only_blocked() {
        let rs = vec![
            ProfileResponse::new(ProfileRole::Unauthenticated, 401, body("{}")),
            ProfileResponse::new(ProfileRole::Attacker, 403, body(r#"{"message":"forbidden"}"#)),
        ];
        let findings = classify("https://x/admin", &rs).unwrap();
        assert!(findings.is_empty(), "no divergence to report: {findings:?}");
    }

    #[test]
    fn duplicate_role_rejected() {
        let rs = vec![
            ProfileResponse::new(ProfileRole::Attacker, 200, body("{}")),
            ProfileResponse::new(ProfileRole::Attacker, 200, body("{}")),
        ];
        let err = classify("https://x", &rs).unwrap_err();
        assert!(matches!(err, AuthDiffError::DuplicateRole(_)));
    }

    #[test]
    fn no_profiles_rejected() {
        let err = classify("https://x", &[]).unwrap_err();
        assert!(matches!(err, AuthDiffError::NoProfiles));
    }

    #[test]
    fn findings_promote_to_fsm_summaries() {
        let rs = vec![
            ProfileResponse::new(ProfileRole::Unauthenticated, 401, body("{}")),
            ProfileResponse::new(
                ProfileRole::Attacker,
                200,
                body(r#"[{"id":"o1","organization_id":"victim-org"}]"#),
            ),
            ProfileResponse::new(
                ProfileRole::Victim,
                200,
                body(r#"[{"id":"o1","organization_id":"victim-org"}]"#),
            ),
        ];
        let summaries = classify_to_findings("https://x/rest/v1/orders", &rs).unwrap();
        assert!(!summaries.is_empty());
        assert!(summaries
            .iter()
            .any(|s| s.severity == "critical" || s.severity == "high"));
    }
}
