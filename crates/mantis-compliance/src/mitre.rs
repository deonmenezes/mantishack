//! MITRE ATT&CK technique tagging for Mantis claims.
//!
//! Reference: <https://attack.mitre.org/> (Enterprise matrix, v15+).
//!
//! ATT&CK is sprawling — hundreds of techniques across many tactics. This
//! module exposes the subset that web/API/cloud pentest claims typically
//! reference, plus a coarse CWE → technique heuristic. Reports can attach an
//! ATT&CK ID to every confirmed claim without each claim site needing to
//! know the matrix.
//!
//! Where multiple techniques apply (e.g. SQLi maps to both T1190 "Exploit
//! Public-Facing Application" and T1213 "Data from Information Repositories"),
//! the mapping returns the *initial-access* tactic technique, since reports
//! typically anchor on the entry point. Operators can layer downstream
//! techniques manually.

use serde::{Deserialize, Serialize};

use crate::cwe::Cwe;

/// ATT&CK tactic groupings used by Enterprise matrix v15+.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tactic {
    /// TA0001 Initial Access.
    InitialAccess,
    /// TA0002 Execution.
    Execution,
    /// TA0003 Persistence.
    Persistence,
    /// TA0004 Privilege Escalation.
    PrivilegeEscalation,
    /// TA0005 Defense Evasion.
    DefenseEvasion,
    /// TA0006 Credential Access.
    CredentialAccess,
    /// TA0007 Discovery.
    Discovery,
    /// TA0008 Lateral Movement.
    LateralMovement,
    /// TA0009 Collection.
    Collection,
    /// TA0010 Exfiltration.
    Exfiltration,
    /// TA0011 Command and Control.
    CommandAndControl,
    /// TA0040 Impact.
    Impact,
}

impl Tactic {
    /// Canonical ATT&CK tactic ID, e.g. `"TA0001"`.
    pub const fn id(self) -> &'static str {
        match self {
            Self::InitialAccess => "TA0001",
            Self::Execution => "TA0002",
            Self::Persistence => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion => "TA0005",
            Self::CredentialAccess => "TA0006",
            Self::Discovery => "TA0007",
            Self::LateralMovement => "TA0008",
            Self::Collection => "TA0009",
            Self::Exfiltration => "TA0010",
            Self::CommandAndControl => "TA0011",
            Self::Impact => "TA0040",
        }
    }
}

/// A single ATT&CK technique with its canonical ID, name, and primary tactic.
///
/// Subtechniques use the dotted form (e.g. `T1059.007` for JavaScript).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Technique {
    /// Canonical ATT&CK technique ID, e.g. `"T1190"` or `"T1059.007"`.
    pub id: &'static str,
    /// Technique display name.
    pub name: &'static str,
    /// Primary tactic this technique falls under in the matrix.
    pub tactic: Tactic,
}

/// Curated catalog of ATT&CK techniques that commonly appear in web / API /
/// cloud pentest reports. Not exhaustive — sized for the claim layer's needs,
/// not for replacing the upstream ATT&CK STIX bundle.
pub mod techniques {
    use super::{Tactic, Technique};

    /// T1190 — Exploit Public-Facing Application.
    pub const EXPLOIT_PUBLIC_FACING_APP: Technique = Technique {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: Tactic::InitialAccess,
    };

    /// T1078 — Valid Accounts.
    pub const VALID_ACCOUNTS: Technique = Technique {
        id: "T1078",
        name: "Valid Accounts",
        tactic: Tactic::InitialAccess,
    };

    /// T1059.007 — Command and Scripting Interpreter: JavaScript.
    pub const JAVASCRIPT_EXECUTION: Technique = Technique {
        id: "T1059.007",
        name: "Command and Scripting Interpreter: JavaScript",
        tactic: Tactic::Execution,
    };

    /// T1059.006 — Command and Scripting Interpreter: Python.
    pub const PYTHON_EXECUTION: Technique = Technique {
        id: "T1059.006",
        name: "Command and Scripting Interpreter: Python",
        tactic: Tactic::Execution,
    };

    /// T1083 — File and Directory Discovery.
    pub const FILE_DIRECTORY_DISCOVERY: Technique = Technique {
        id: "T1083",
        name: "File and Directory Discovery",
        tactic: Tactic::Discovery,
    };

    /// T1213 — Data from Information Repositories.
    pub const DATA_FROM_INFO_REPOS: Technique = Technique {
        id: "T1213",
        name: "Data from Information Repositories",
        tactic: Tactic::Collection,
    };

    /// T1552 — Unsecured Credentials.
    pub const UNSECURED_CREDENTIALS: Technique = Technique {
        id: "T1552",
        name: "Unsecured Credentials",
        tactic: Tactic::CredentialAccess,
    };

    /// T1110 — Brute Force.
    pub const BRUTE_FORCE: Technique = Technique {
        id: "T1110",
        name: "Brute Force",
        tactic: Tactic::CredentialAccess,
    };

    /// T1539 — Steal Web Session Cookie.
    pub const STEAL_WEB_SESSION_COOKIE: Technique = Technique {
        id: "T1539",
        name: "Steal Web Session Cookie",
        tactic: Tactic::CredentialAccess,
    };

    /// T1071 — Application Layer Protocol.
    pub const APPLICATION_LAYER_PROTOCOL: Technique = Technique {
        id: "T1071",
        name: "Application Layer Protocol",
        tactic: Tactic::CommandAndControl,
    };

    /// T1556 — Modify Authentication Process.
    pub const MODIFY_AUTHENTICATION: Technique = Technique {
        id: "T1556",
        name: "Modify Authentication Process",
        tactic: Tactic::Persistence,
    };

    /// T1565 — Data Manipulation.
    pub const DATA_MANIPULATION: Technique = Technique {
        id: "T1565",
        name: "Data Manipulation",
        tactic: Tactic::Impact,
    };

    /// T1485 — Data Destruction.
    pub const DATA_DESTRUCTION: Technique = Technique {
        id: "T1485",
        name: "Data Destruction",
        tactic: Tactic::Impact,
    };
}

/// Best-effort CWE → primary ATT&CK technique mapping.
///
/// Returns the *initial-access* technique whenever a CWE represents a remote
/// exploitation primitive (most web/API CWEs do). Returns `None` for CWEs
/// outside the curated set rather than guessing.
pub const fn technique_for_cwe(cwe: Cwe) -> Option<Technique> {
    use techniques::*;
    Some(match cwe.0 {
        // Injection family — all map to T1190 (Exploit Public-Facing Application)
        // as the initial-access vector. Downstream impact varies but anchoring
        // on T1190 matches how pentest reports describe these.
        20 | 74 | 77 | 78 | 88 | 89 | 90 | 91 | 94 | 95 | 917 => EXPLOIT_PUBLIC_FACING_APP,

        // XSS subfamily — execution in browser.
        79 | 80 | 83 | 87 => JAVASCRIPT_EXECUTION,

        // Access-control / IDOR / path traversal — initial access through the public app.
        22 | 23 | 35 | 200 | 285 | 425 | 552 | 639 | 668 | 862 | 863 => EXPLOIT_PUBLIC_FACING_APP,

        // SSRF — initial access plus optional C2.
        918 => EXPLOIT_PUBLIC_FACING_APP,

        // Brute-force-ish — matched before VALID_ACCOUNTS because the auth
        // failure is specifically a missing lockout/throttle.
        307 | 1216 => BRUTE_FORCE,

        // Hardcoded / exposed credentials — matched before VALID_ACCOUNTS for
        // the same reason: the underlying weakness is the leaked secret, not
        // the attacker possessing valid creds.
        256 | 259 | 522 | 798 => UNSECURED_CREDENTIALS,

        // Cookie / session theft.
        539 | 614 => STEAL_WEB_SESSION_COOKIE,

        // Generic authentication failures — Valid Accounts (the attacker walks in).
        287 | 290 | 294 | 295 | 297 | 306 | 384 | 521 | 613 | 940 => VALID_ACCOUNTS,

        // Data exposure / information disclosure.
        209 | 213 | 532 | 538 | 540 => DATA_FROM_INFO_REPOS,

        // Deserialization / supply chain → app-layer execution.
        502 | 494 | 829 | 830 | 915 => APPLICATION_LAYER_PROTOCOL,

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqli_maps_to_t1190() {
        assert_eq!(technique_for_cwe(Cwe(89)).map(|t| t.id), Some("T1190"));
    }

    #[test]
    fn xss_maps_to_javascript_execution() {
        let t = technique_for_cwe(Cwe(79)).unwrap();
        assert_eq!(t.id, "T1059.007");
        assert_eq!(t.tactic, Tactic::Execution);
    }

    #[test]
    fn ssrf_maps_to_t1190() {
        assert_eq!(technique_for_cwe(Cwe(918)).map(|t| t.id), Some("T1190"));
    }

    #[test]
    fn hardcoded_creds_map_to_unsecured_credentials() {
        let t = technique_for_cwe(Cwe(798)).unwrap();
        assert_eq!(t.id, "T1552");
        assert_eq!(t.tactic, Tactic::CredentialAccess);
    }

    #[test]
    fn missing_auth_maps_to_valid_accounts() {
        let t = technique_for_cwe(Cwe(306)).unwrap();
        assert_eq!(t.id, "T1078");
    }

    #[test]
    fn deserialization_maps_to_app_layer_protocol() {
        let t = technique_for_cwe(Cwe(502)).unwrap();
        assert_eq!(t.id, "T1071");
    }

    #[test]
    fn unmapped_cwe_returns_none() {
        assert_eq!(technique_for_cwe(Cwe(1_234_567)), None);
    }

    #[test]
    fn technique_serializes_to_canonical_id() {
        let t = techniques::EXPLOIT_PUBLIC_FACING_APP;
        let json = serde_json::to_string(&t).unwrap();
        // The struct serializes as { id, name, tactic } — the canonical id is preserved.
        assert!(json.contains("\"id\":\"T1190\""));
        assert!(json.contains("\"name\":\"Exploit Public-Facing Application\""));
    }

    #[test]
    fn tactic_ids_are_canonical() {
        assert_eq!(Tactic::InitialAccess.id(), "TA0001");
        assert_eq!(Tactic::Impact.id(), "TA0040");
    }

    #[test]
    fn subtechnique_id_format_is_preserved() {
        // T1059.007 must remain dotted — pentest reports cite subtechniques.
        assert_eq!(techniques::JAVASCRIPT_EXECUTION.id, "T1059.007");
    }
}
