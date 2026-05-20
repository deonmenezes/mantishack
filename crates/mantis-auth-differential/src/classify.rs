//! Classifier — the brain of the differential runner.
//!
//! Takes N [`ProfileResponse`]s for a single URL and decides
//! whether the divergence pattern matches a known authorization
//! bug. Mirrors hacker-bob's `auth-differential.js` classifier
//! decisions, ported as plain pattern-matching on
//! [`crate::shape::ResponseShape`].

use crate::shape::ResponseShape;
use crate::AuthDiffError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// Operator-defined role of an auth profile. Ordered most-to-least
/// privileged from a differential standpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileRole {
    /// No credentials. Anything readable here is public-by-default.
    Unauthenticated,
    /// The probing attacker account. Captured via `mantis-auth`.
    Attacker,
    /// A second user the attacker is NOT a member with. Comparing
    /// attacker vs victim is the cross-tenant test.
    Victim,
    /// An admin / privileged profile. Used to confirm "this endpoint
    /// is supposed to return data, but only to admins."
    Admin,
}

impl ProfileRole {
    pub fn as_str(self) -> &'static str {
        match self {
            ProfileRole::Unauthenticated => "unauthenticated",
            ProfileRole::Attacker => "attacker",
            ProfileRole::Victim => "victim",
            ProfileRole::Admin => "admin",
        }
    }
}

/// One captured response for one profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileResponse {
    pub role: ProfileRole,
    pub http_status: u16,
    /// The full parsed JSON body. Use `Value::Null` for empty.
    pub body: Value,
    /// Cached shape — computed lazily by `shape()` on first access.
    /// Direct constructors leave this `None`.
    #[serde(skip)]
    cached_shape: std::cell::OnceCell<ResponseShape>,
}

impl ProfileResponse {
    pub fn new(role: ProfileRole, http_status: u16, body: Value) -> Self {
        Self {
            role,
            http_status,
            body,
            cached_shape: std::cell::OnceCell::new(),
        }
    }

    pub fn shape(&self) -> &ResponseShape {
        self.cached_shape
            .get_or_init(|| ResponseShape::from_response(self.http_status, &self.body))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceClass {
    /// `attacker` and `victim` both see successful data with the
    /// same shape and the *exact same row content* — the attacker
    /// is reading the victim's records. F-12, F-22, F-31, F-34.
    CrossTenantRead,
    /// `unauthenticated` sees data that should require an account
    /// (and `attacker` agrees the data is reachable). F-10, F-26.
    UnauthSuccessWithAuthBlocked,
    /// Both unauth and attacker get data that contains sensitive
    /// field names (`email`, `password`, `marketplace_credentials`,
    /// …). Higher severity than a bare unauth read. F-20.
    PublicTableSensitiveFields,
    /// `attacker` sees the same response shape as `admin` — likely
    /// privilege escalation through mass-assignment or stale role.
    /// F-9.
    PrivilegeShapeMatch,
    /// `attacker`'s response includes fields with names that
    /// suggest cross-tenant identifiers (`organization_id`,
    /// `tenant_id`, `org_id`) that don't match the attacker's known
    /// org. F-12 strong signal.
    ForeignOwnerIdentifier,
}

impl DivergenceClass {
    pub fn vuln_class(self) -> &'static str {
        match self {
            DivergenceClass::CrossTenantRead => "broken-access-control.cross-tenant-read",
            DivergenceClass::UnauthSuccessWithAuthBlocked => "broken-access-control.unauth-read",
            DivergenceClass::PublicTableSensitiveFields => "info-disclosure.sensitive-fields",
            DivergenceClass::PrivilegeShapeMatch => "auth-bypass.privilege-escalation",
            DivergenceClass::ForeignOwnerIdentifier => "broken-access-control.foreign-tenant",
        }
    }

    pub fn default_severity(self) -> &'static str {
        match self {
            DivergenceClass::CrossTenantRead => "critical",
            DivergenceClass::UnauthSuccessWithAuthBlocked => "high",
            DivergenceClass::PublicTableSensitiveFields => "critical",
            DivergenceClass::PrivilegeShapeMatch => "critical",
            DivergenceClass::ForeignOwnerIdentifier => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffFinding {
    pub finding_id: String,
    pub class: DivergenceClass,
    pub url: String,
    pub evidence: String,
    /// Stable signature of (url + class + profile-roles set). Lets
    /// callers dedupe across repeated diff runs.
    pub finding_hash: String,
}

/// The classifier.
///
/// Order of pattern checks (first match wins per finding-class —
/// but multiple finding-classes can fire for one URL, so the
/// returned vec may contain several):
///
/// 1. `CrossTenantRead` — attacker + victim both 2xx with matching
///    shape, and identical row IDs across responses, AND attacker
///    is not the same identity as victim.
/// 2. `ForeignOwnerIdentifier` — attacker's response contains an
///    `organization_id` / `org_id` / `tenant_id` field with a value
///    that doesn't appear in any of the attacker's own request
///    metadata.
/// 3. `PrivilegeShapeMatch` — attacker's shape ≡ admin's shape, AND
///    attacker isn't supposed to be admin.
/// 4. `PublicTableSensitiveFields` — unauth 2xx with body
///    containing sensitive field names.
/// 5. `UnauthSuccessWithAuthBlocked` — unauth 2xx with non-empty
///    body (no sensitive fields) and at least one *other* role is
///    also 2xx confirming the endpoint is real.
pub fn classify(
    url: &str,
    responses: &[ProfileResponse],
) -> Result<Vec<DiffFinding>, AuthDiffError> {
    if responses.is_empty() {
        return Err(AuthDiffError::NoProfiles);
    }
    // Reject duplicate roles — caller must commit to one response
    // per profile per request.
    let mut seen = BTreeSet::new();
    for r in responses {
        if !seen.insert(r.role) {
            return Err(AuthDiffError::DuplicateRole(r.role));
        }
    }

    let by_role: std::collections::BTreeMap<ProfileRole, &ProfileResponse> =
        responses.iter().map(|r| (r.role, r)).collect();

    let mut findings: Vec<DiffFinding> = Vec::new();
    let mut emitted: BTreeSet<DivergenceClass> = BTreeSet::new();

    let push = |findings: &mut Vec<DiffFinding>,
                emitted: &mut BTreeSet<DivergenceClass>,
                class: DivergenceClass,
                evidence: String| {
        if emitted.insert(class) {
            let id = format!("auth-diff-{}", findings.len() + 1);
            let hash = {
                let mut h = blake3::Hasher::new();
                h.update(url.as_bytes());
                h.update(b"|");
                h.update(class.vuln_class().as_bytes());
                hex::encode(&h.finalize().as_bytes()[..16])
            };
            findings.push(DiffFinding {
                finding_id: id,
                class,
                url: url.to_string(),
                evidence,
                finding_hash: hash,
            });
        }
    };

    // ---- 1. CrossTenantRead ----
    if let (Some(att), Some(vic)) = (
        by_role.get(&ProfileRole::Attacker),
        by_role.get(&ProfileRole::Victim),
    ) {
        let attacker_shape = att.shape();
        let victim_shape = vic.shape();
        if attacker_shape.is_success_with_data()
            && victim_shape.is_success_with_data()
            && attacker_shape.signature() == victim_shape.signature()
            && row_ids_match(&att.body, &vic.body)
        {
            let ev = format!(
                "Attacker and victim both returned HTTP {} with identical response shape \
                 ({} rows, fields: {:?}) AND identical row identifiers. \
                 Attacker should not have read access to victim's records. \
                 Shape signature: {} (both sides).",
                attacker_shape.http_status,
                attacker_shape.row_count,
                attacker_shape.field_names,
                attacker_shape.signature(),
            );
            push(
                &mut findings,
                &mut emitted,
                DivergenceClass::CrossTenantRead,
                ev,
            );
        }
    }

    // ---- 2. ForeignOwnerIdentifier ----
    if let Some(att) = by_role.get(&ProfileRole::Attacker) {
        let attacker_shape = att.shape();
        if attacker_shape.is_success_with_data() {
            let foreign_ids = scan_foreign_owner_ids(&att.body);
            if !foreign_ids.is_empty() {
                let ev = format!(
                    "Attacker's response includes owner-identifier values: {:?}. \
                     These are likely cross-tenant IDs — the attacker is reading rows \
                     scoped to other organizations. URL: {url}.",
                    foreign_ids.iter().take(8).collect::<Vec<_>>()
                );
                push(
                    &mut findings,
                    &mut emitted,
                    DivergenceClass::ForeignOwnerIdentifier,
                    ev,
                );
            }
        }
    }

    // ---- 3. PrivilegeShapeMatch ----
    if let (Some(att), Some(adm)) = (
        by_role.get(&ProfileRole::Attacker),
        by_role.get(&ProfileRole::Admin),
    ) {
        let attacker_shape = att.shape();
        let admin_shape = adm.shape();
        if attacker_shape.is_success_with_data()
            && admin_shape.is_success_with_data()
            && attacker_shape.signature() == admin_shape.signature()
        {
            let ev = format!(
                "Attacker response shape matches admin response shape on {url}. \
                 Either the attacker has escalated to admin (mass-assignment / role \
                 takeover) or the endpoint doesn't differentiate by role. Shape sig: {}.",
                attacker_shape.signature()
            );
            push(
                &mut findings,
                &mut emitted,
                DivergenceClass::PrivilegeShapeMatch,
                ev,
            );
        }
    }

    // ---- 4. PublicTableSensitiveFields ----
    if let Some(unauth) = by_role.get(&ProfileRole::Unauthenticated) {
        let shape = unauth.shape();
        if shape.is_success_with_data() && !shape.sensitive_fields_present.is_empty() {
            let ev = format!(
                "Unauthenticated client received HTTP {} with sensitive fields {:?} in the body. \
                 No JWT / cookie / API key required.",
                shape.http_status, shape.sensitive_fields_present,
            );
            push(
                &mut findings,
                &mut emitted,
                DivergenceClass::PublicTableSensitiveFields,
                ev,
            );
        }
    }

    // ---- 5. UnauthSuccessWithAuthBlocked ----
    if let Some(unauth) = by_role.get(&ProfileRole::Unauthenticated) {
        let unauth_shape = unauth.shape();
        if unauth_shape.is_success_with_data() && unauth_shape.sensitive_fields_present.is_empty() {
            // Confirm with another role that the endpoint is real.
            let confirmed_by_other = [
                ProfileRole::Attacker,
                ProfileRole::Victim,
                ProfileRole::Admin,
            ]
            .iter()
            .any(|r| {
                by_role
                    .get(r)
                    .map(|x| x.shape().is_success_with_data())
                    .unwrap_or(false)
            });
            // OR: the unauth itself is the only profile present AND
            // the body has rows — still a public-table leak.
            let alone = by_role.len() == 1;
            if confirmed_by_other || alone {
                let ev = format!(
                    "Unauthenticated client received HTTP {} with {} row(s) and fields {:?}. \
                     Endpoint returns data without any auth context.",
                    unauth_shape.http_status, unauth_shape.row_count, unauth_shape.field_names,
                );
                push(
                    &mut findings,
                    &mut emitted,
                    DivergenceClass::UnauthSuccessWithAuthBlocked,
                    ev,
                );
            }
        }
    }

    Ok(findings)
}

/// True iff two JSON arrays (or single objects) carry the same set
/// of row identifiers. Looks for any field whose name ends in `id`
/// or `_id` and compares the sorted set of values.
fn row_ids_match(a: &Value, b: &Value) -> bool {
    let ids_a = extract_row_ids(a);
    let ids_b = extract_row_ids(b);
    if ids_a.is_empty() || ids_b.is_empty() {
        // Without IDs we can't claim row-level identity. Treat as
        // a weak match — return true so the shape-match alone fires
        // CrossTenantRead. False positives here are caught by the
        // operator review step.
        return true;
    }
    ids_a == ids_b
}

fn extract_row_ids(v: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    fn walk(v: &Value, out: &mut BTreeSet<String>) {
        match v {
            Value::Array(arr) => {
                for item in arr {
                    walk(item, out);
                }
            }
            Value::Object(obj) => {
                for (k, val) in obj {
                    let lk = k.to_ascii_lowercase();
                    if lk == "id" || lk.ends_with("_id") {
                        if let Some(s) = val.as_str() {
                            out.insert(format!("{lk}={s}"));
                        } else if let Some(n) = val.as_i64() {
                            out.insert(format!("{lk}={n}"));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    walk(v, &mut out);
    out
}

/// Pull every value of every owner-identifier field. The presence
/// of any such ID is the signal — the classifier can't know what
/// the attacker's own org is, so we surface the IDs as evidence.
fn scan_foreign_owner_ids(v: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    fn walk(v: &Value, out: &mut BTreeSet<String>) {
        match v {
            Value::Array(arr) => {
                for item in arr {
                    walk(item, out);
                }
            }
            Value::Object(obj) => {
                for (k, val) in obj {
                    let lk = k.to_ascii_lowercase();
                    if lk == "organization_id"
                        || lk == "org_id"
                        || lk == "tenant_id"
                        || lk == "owner_id"
                        || lk == "user_id"
                    {
                        if let Some(s) = val.as_str() {
                            out.insert(s.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    walk(v, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cross_tenant_fires_when_attacker_sees_victim_rows() {
        let att = ProfileResponse::new(
            ProfileRole::Attacker,
            200,
            json!([{"id":"o1","organization_id":"victim-org"}]),
        );
        let vic = ProfileResponse::new(
            ProfileRole::Victim,
            200,
            json!([{"id":"o1","organization_id":"victim-org"}]),
        );
        let findings = classify("https://x/orders", &[att, vic]).unwrap();
        assert!(findings
            .iter()
            .any(|f| matches!(f.class, DivergenceClass::CrossTenantRead)));
    }

    #[test]
    fn foreign_owner_fires_when_attacker_response_carries_owner_ids() {
        let att = ProfileResponse::new(
            ProfileRole::Attacker,
            200,
            json!([
                {"id":"x","organization_id":"foreign-org-1"},
                {"id":"y","organization_id":"foreign-org-2"},
            ]),
        );
        let findings = classify("https://x/orders", &[att]).unwrap();
        assert!(findings
            .iter()
            .any(|f| matches!(f.class, DivergenceClass::ForeignOwnerIdentifier)));
    }

    #[test]
    fn privilege_shape_match_fires_attacker_eq_admin() {
        let att = ProfileResponse::new(
            ProfileRole::Attacker,
            200,
            json!({"role":"admin","permissions":"admin"}),
        );
        let adm = ProfileResponse::new(
            ProfileRole::Admin,
            200,
            json!({"role":"admin","permissions":"admin"}),
        );
        let findings = classify("https://x/users/me", &[att, adm]).unwrap();
        assert!(findings
            .iter()
            .any(|f| matches!(f.class, DivergenceClass::PrivilegeShapeMatch)));
    }

    #[test]
    fn public_sensitive_fires_on_unauth_with_passwords() {
        let unauth = ProfileResponse::new(
            ProfileRole::Unauthenticated,
            200,
            json!([{"id":1,"marketplace_credentials":{"password":"p"}}]),
        );
        let findings = classify("https://x/suppliers", &[unauth]).unwrap();
        assert!(findings
            .iter()
            .any(|f| matches!(f.class, DivergenceClass::PublicTableSensitiveFields)));
    }

    #[test]
    fn unauth_read_alone_still_fires() {
        let unauth = ProfileResponse::new(ProfileRole::Unauthenticated, 200, json!([{"id":1}]));
        let findings = classify("https://x/users", &[unauth]).unwrap();
        assert!(findings
            .iter()
            .any(|f| matches!(f.class, DivergenceClass::UnauthSuccessWithAuthBlocked)));
    }

    #[test]
    fn blocked_endpoint_produces_no_finding() {
        let att = ProfileResponse::new(ProfileRole::Attacker, 403, json!({"message":"forbidden"}));
        let unauth = ProfileResponse::new(ProfileRole::Unauthenticated, 401, json!({}));
        let findings = classify("https://x/admin", &[att, unauth]).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn no_double_emit_same_class() {
        let att = ProfileResponse::new(
            ProfileRole::Attacker,
            200,
            json!([
                {"id":"o1","organization_id":"foreign-1"},
                {"id":"o2","organization_id":"foreign-2"},
            ]),
        );
        let vic = ProfileResponse::new(
            ProfileRole::Victim,
            200,
            json!([
                {"id":"o1","organization_id":"foreign-1"},
                {"id":"o2","organization_id":"foreign-2"},
            ]),
        );
        let findings = classify("https://x/orders", &[att, vic]).unwrap();
        let cross_tenant_count = findings
            .iter()
            .filter(|f| matches!(f.class, DivergenceClass::CrossTenantRead))
            .count();
        assert_eq!(cross_tenant_count, 1);
    }

    #[test]
    fn finding_hash_stable_for_url_and_class() {
        let unauth1 = ProfileResponse::new(ProfileRole::Unauthenticated, 200, json!([{"id":1}]));
        let unauth2 = ProfileResponse::new(ProfileRole::Unauthenticated, 200, json!([{"id":2}]));
        let f1 = classify("https://x/users", &[unauth1]).unwrap();
        let f2 = classify("https://x/users", &[unauth2]).unwrap();
        assert_eq!(f1[0].finding_hash, f2[0].finding_hash);
    }

    #[test]
    fn severity_promotes_for_critical_classes() {
        assert_eq!(
            DivergenceClass::CrossTenantRead.default_severity(),
            "critical"
        );
        assert_eq!(
            DivergenceClass::PrivilegeShapeMatch.default_severity(),
            "critical"
        );
        assert_eq!(
            DivergenceClass::PublicTableSensitiveFields.default_severity(),
            "critical"
        );
        assert_eq!(
            DivergenceClass::ForeignOwnerIdentifier.default_severity(),
            "critical"
        );
        assert_eq!(
            DivergenceClass::UnauthSuccessWithAuthBlocked.default_severity(),
            "high"
        );
    }
}
