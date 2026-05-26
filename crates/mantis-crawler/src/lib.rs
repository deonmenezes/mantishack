//! Static HTML+JS analyzer for endpoint discovery (PRD §5.3.5).
//!
//! PRD §5.3.5: "The system shall crawl JavaScript-heavy
//! applications using an embedded headless browser pool, extracting
//! endpoints, parameters, and dynamic API surfaces."
//!
//! A real headless-browser pool (Chromium via `chromiumoxide`) is
//! a 50–100 MB dependency and adds platform-specific build pain.
//! This crate ships the *static* side of that requirement: a
//! purely-textual extractor that walks HTML + inline JS + script
//! src URLs and surfaces every callable endpoint it can prove
//! exists without executing JavaScript.
//!
//! Coverage:
//!   - `<a href>`, `<form action>`, `<img src>`, `<script src>`,
//!     `<link href>`, `<iframe src>` (HTML attributes)
//!   - `fetch("...")`, `fetch('...')` (literal fetch calls)
//!   - `XMLHttpRequest.open("METHOD","URL")`
//!   - `axios.get("...")` / `axios.post("...")`
//!   - ES module `import "..."`
//!   - URL literals matching `https://...` or `/api/...`
//!
//! What it deliberately misses (template-built URLs, dynamic
//! imports, fetch arguments resolved at runtime): the downstream
//! daemon falls back to the headless browser path when the static
//! analyzer's result set is too sparse for the target.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CrawlError {
    #[error("input too large: {0} bytes exceeds limit")]
    InputTooLarge(usize),
}

/// Soft cap on per-call input size. Matches the daemon's
/// per-experiment memory budget shape: anything above this gets
/// streamed through a different code path.
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrawlResult {
    pub endpoints: BTreeSet<String>,
    pub scripts: BTreeSet<String>,
    pub forms: Vec<DiscoveredForm>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredForm {
    pub action: String,
    pub method: String,
    pub field_names: Vec<String>,
}

/// Walk `body` looking for endpoint references. The `base_url` is
/// used to make relative URLs absolute when callers want
/// already-resolved targets; pass `None` to keep them raw.
pub fn extract(body: &str, base_url: Option<&str>) -> Result<CrawlResult, CrawlError> {
    if body.len() > MAX_INPUT_BYTES {
        return Err(CrawlError::InputTooLarge(body.len()));
    }
    let mut result = CrawlResult::default();

    // HTML attribute scanning. We don't pull in a full HTML parser
    // — a targeted scanner over (attr, value) pairs is faster and
    // the false-positive rate is fine for an offensive surface
    // sweep.
    for attr in &[
        "href=",
        "src=",
        "action=",
        "data-url=",
        "data-src=",
        "formaction=",
    ] {
        for value in find_attr_values(body, attr) {
            store_endpoint(&value, &mut result, base_url);
            if *attr == "src=" {
                result.scripts.insert(value);
            }
        }
    }

    // JS literal scanning: bare strings inside fetch / axios /
    // XHR.open / module-import calls.
    for pat in &[
        "fetch(\"",
        "fetch('",
        "axios.get(\"",
        "axios.get('",
        "axios.post(\"",
        "axios.post('",
        "axios.put(\"",
        "axios.put('",
        "axios.delete(\"",
        "axios.delete('",
        "$.ajax({url:\"",
        "$.ajax({url:'",
        "import(\"",
        "import('",
        "import \"",
        "import '",
        "from \"",
        "from '",
    ] {
        for value in find_pattern_string(body, pat) {
            store_endpoint(&value, &mut result, base_url);
        }
    }

    // XMLHttpRequest.open("METHOD","URL")
    for value in find_xhr_open(body) {
        store_endpoint(&value, &mut result, base_url);
    }

    // Standalone URL-literal scrape: anything that looks like a
    // path beginning with /api/ or an absolute URL appearing in JS
    // strings the regular patterns missed.
    for value in find_bare_url_literals(body) {
        store_endpoint(&value, &mut result, base_url);
    }

    // Forms — a simple per-<form> walk capturing action, method,
    // and the names of every input/select/textarea inside.
    for form in find_forms(body) {
        result.forms.push(form);
    }

    Ok(result)
}

fn store_endpoint(value: &str, result: &mut CrawlResult, base_url: Option<&str>) {
    if value.is_empty() {
        return;
    }
    if value.starts_with("javascript:") || value.starts_with("data:") || value.starts_with("#") {
        return;
    }
    if let Some(base) = base_url {
        if let Some(resolved) = resolve_against_base(value, base) {
            result.endpoints.insert(resolved);
            return;
        }
    }
    result.endpoints.insert(value.to_string());
}

fn find_attr_values(haystack: &str, attr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut search = haystack;
    while let Some(pos) = search.find(attr) {
        let after = &search[pos + attr.len()..];
        if let Some(value) = extract_quoted(after) {
            out.push(value);
        }
        search = &after[1..];
        if search.is_empty() {
            break;
        }
    }
    out
}

fn find_pattern_string(haystack: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut search = haystack;
    while let Some(pos) = search.find(prefix) {
        let after = &search[pos + prefix.len()..];
        let quote = prefix
            .chars()
            .last()
            .filter(|c| *c == '"' || *c == '\'')
            .unwrap_or('"');
        if let Some(end) = after.find(quote) {
            let value = &after[..end];
            if looks_like_url_ish(value) {
                out.push(value.to_string());
            }
            search = &after[end + 1..];
        } else {
            break;
        }
    }
    out
}

fn find_xhr_open(haystack: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut search = haystack;
    while let Some(pos) = search.find(".open(") {
        let after = &search[pos + ".open(".len()..];
        // first quoted = method, second quoted = URL
        if let Some(method_end) = after.find(['"', '\'']) {
            let after_method_quote = &after[method_end + 1..];
            if let Some(method_close) = after_method_quote.find(['"', '\'']) {
                let after_method = &after_method_quote[method_close + 1..];
                if let Some(url_start) = after_method.find(['"', '\'']) {
                    let after_url_quote = &after_method[url_start + 1..];
                    if let Some(url_end) = after_url_quote.find(['"', '\'']) {
                        let value = &after_url_quote[..url_end];
                        if !value.is_empty() {
                            out.push(value.to_string());
                        }
                    }
                }
            }
        }
        search = &after[1..];
        if search.is_empty() {
            break;
        }
    }
    out
}

fn find_bare_url_literals(haystack: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in haystack.split(|c: char| !is_url_char(c)) {
        if token.starts_with("/api/")
            || token.starts_with("http://")
            || token.starts_with("https://")
        {
            // Strip trailing punctuation common in JS string ends.
            let trimmed = token.trim_end_matches([',', ';', ':', '"', '\'', ')', '}']);
            if trimmed.len() >= 4 {
                out.push(trimmed.to_string());
            }
        }
    }
    out
}

fn is_url_char(c: char) -> bool {
    matches!(c,
        'A'..='Z' | 'a'..='z' | '0'..='9' |
        '/' | ':' | '?' | '&' | '=' | '%' | '.' | '-' | '_' | '~' | '#'
    )
}

fn looks_like_url_ish(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.starts_with('/') {
        return true;
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return true;
    }
    // Allow relative paths like "users/123" — must contain at
    // least one '/' to dampen common false positives ("hello").
    s.contains('/')
}

fn extract_quoted(after_eq: &str) -> Option<String> {
    let bytes = after_eq.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let q = bytes[i];
    if q != b'"' && q != b'\'' {
        // Unquoted attribute: stop at whitespace or `>`.
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
            i += 1;
        }
        if start == i {
            return None;
        }
        return Some(after_eq[start..i].to_string());
    }
    let start = i + 1;
    let mut j = start;
    while j < bytes.len() && bytes[j] != q {
        j += 1;
    }
    if j >= bytes.len() {
        return None;
    }
    Some(after_eq[start..j].to_string())
}

fn resolve_against_base(value: &str, base: &str) -> Option<String> {
    if value.starts_with("http://") || value.starts_with("https://") {
        return Some(value.into());
    }
    let base = base.trim_end_matches('/');
    if value.starts_with('/') {
        // Absolute path — find scheme://host portion of base.
        let scheme_end = base.find("://")?;
        let after_scheme = &base[scheme_end + 3..];
        let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
        let origin = &base[..scheme_end + 3 + host_end];
        return Some(format!("{origin}{value}"));
    }
    Some(format!("{base}/{value}"))
}

fn find_forms(haystack: &str) -> Vec<DiscoveredForm> {
    let mut out = Vec::new();
    let lower = haystack.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(open_idx) = lower[search_from..].find("<form") {
        let open_abs = search_from + open_idx;
        let after_open = &lower[open_abs..];
        let tag_end = after_open.find('>').unwrap_or(after_open.len());
        let tag_blob = &haystack[open_abs..open_abs + tag_end];
        let action = find_attr_values(tag_blob, "action=")
            .into_iter()
            .next()
            .unwrap_or_default();
        let method = find_attr_values(tag_blob, "method=")
            .into_iter()
            .next()
            .unwrap_or_else(|| "GET".into())
            .to_uppercase();
        let close_idx = lower[open_abs..].find("</form>");
        let body_end = match close_idx {
            Some(rel) => open_abs + rel,
            None => haystack.len(),
        };
        let form_body = &haystack[open_abs + tag_end..body_end];
        let mut field_names: Vec<String> = Vec::new();
        // Compute the lowercased form body ONCE — the prior version
        // recomputed it on every iteration of the input/select/textarea
        // loop, doing the same O(form_body) lowercase 3 times. Also
        // pre-build the search needles as &'static str so we don't
        // format!("<{tag}") on every find iteration.
        let lc_body = form_body.to_ascii_lowercase();
        for tag_pat in &["<input", "<select", "<textarea"] {
            let mut s = 0usize;
            while let Some(p) = lc_body[s..].find(tag_pat) {
                let abs = s + p;
                let after = &form_body[abs..];
                let tag_close = after.find('>').unwrap_or(after.len());
                let descriptor = &form_body[abs..abs + tag_close];
                if let Some(name) = find_attr_values(descriptor, "name=").into_iter().next() {
                    field_names.push(name);
                }
                s = abs + tag_close + 1;
                if s >= lc_body.len() {
                    break;
                }
            }
        }
        out.push(DiscoveredForm {
            action,
            method,
            field_names,
        });
        search_from = body_end + 1;
        if search_from >= haystack.len() {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_anchor_hrefs() {
        let html = r#"<html><a href="/api/users">u</a><a href="/api/posts">p</a></html>"#;
        let result = extract(html, None).unwrap();
        assert!(result.endpoints.contains("/api/users"));
        assert!(result.endpoints.contains("/api/posts"));
    }

    #[test]
    fn extracts_script_srcs() {
        let html =
            r#"<script src="/static/app.js"></script><script src="https://cdn/x.js"></script>"#;
        let result = extract(html, None).unwrap();
        assert!(result.scripts.contains("/static/app.js"));
        assert!(result.scripts.contains("https://cdn/x.js"));
    }

    #[test]
    fn extracts_fetch_calls() {
        let js = r#"
            fetch("/api/v1/items").then(r => r.json());
            fetch('/api/v2/users');
        "#;
        let result = extract(js, None).unwrap();
        assert!(result.endpoints.contains("/api/v1/items"));
        assert!(result.endpoints.contains("/api/v2/users"));
    }

    #[test]
    fn extracts_axios_get_post() {
        let js = r#"axios.get("/api/me"); axios.post('/api/login', payload);"#;
        let result = extract(js, None).unwrap();
        assert!(result.endpoints.contains("/api/me"));
        assert!(result.endpoints.contains("/api/login"));
    }

    #[test]
    fn extracts_xhr_open_urls() {
        let js = r#"
            var x = new XMLHttpRequest();
            x.open("POST", "/api/submit");
            x.open('GET','/api/list');
        "#;
        let result = extract(js, None).unwrap();
        assert!(result.endpoints.contains("/api/submit"));
        assert!(result.endpoints.contains("/api/list"));
    }

    #[test]
    fn extracts_es_module_imports() {
        let js = r#"
            import("/modules/admin.js").then(m => m.run());
            import 'https://cdn.example/dep.js';
        "#;
        let result = extract(js, None).unwrap();
        assert!(result.endpoints.contains("/modules/admin.js"));
        assert!(result.endpoints.contains("https://cdn.example/dep.js"));
    }

    #[test]
    fn extracts_forms_with_field_names() {
        let html = r#"
            <form action="/login" method="POST">
                <input name="username" type="text">
                <input name="password" type="password">
                <input type="submit" value="go">
            </form>
        "#;
        let result = extract(html, None).unwrap();
        assert_eq!(result.forms.len(), 1);
        assert_eq!(result.forms[0].action, "/login");
        assert_eq!(result.forms[0].method, "POST");
        assert!(result.forms[0].field_names.contains(&"username".into()));
        assert!(result.forms[0].field_names.contains(&"password".into()));
    }

    #[test]
    fn default_form_method_is_get() {
        let html = r#"<form action="/search"><input name="q"></form>"#;
        let result = extract(html, None).unwrap();
        assert_eq!(result.forms[0].method, "GET");
    }

    #[test]
    fn ignores_javascript_and_anchor_hrefs() {
        let html = r##"<a href="javascript:void(0)">x</a><a href="#section">y</a>"##;
        let result = extract(html, None).unwrap();
        assert!(result.endpoints.is_empty());
    }

    #[test]
    fn resolves_relative_paths_against_base_url() {
        let html = r#"<a href="/api/users">u</a><a href="https://other.example/x">o</a>"#;
        let result = extract(html, Some("https://api.example.com/foo/")).unwrap();
        assert!(result
            .endpoints
            .contains("https://api.example.com/api/users"));
        assert!(result.endpoints.contains("https://other.example/x"));
    }

    #[test]
    fn bare_url_literals_picked_up() {
        let js =
            r#"const URL = "https://api.example.com/v3/widgets"; const P = "/api/internal/log";"#;
        let result = extract(js, None).unwrap();
        assert!(result
            .endpoints
            .contains("https://api.example.com/v3/widgets"));
        assert!(result.endpoints.contains("/api/internal/log"));
    }

    #[test]
    fn rejects_input_above_max_bytes() {
        let big = "x".repeat(MAX_INPUT_BYTES + 1);
        let err = extract(&big, None).unwrap_err();
        assert!(matches!(err, CrawlError::InputTooLarge(_)));
    }

    #[test]
    fn endpoints_are_deduplicated() {
        let html = r#"<a href="/api/x">a</a><a href="/api/x">b</a>"#;
        let result = extract(html, None).unwrap();
        assert_eq!(result.endpoints.len(), 1);
    }

    #[test]
    fn multiple_forms_each_get_an_entry() {
        let html = r#"
            <form action="/a"><input name="x"></form>
            <form action="/b" method="post"><input name="y"></form>
        "#;
        let result = extract(html, None).unwrap();
        assert_eq!(result.forms.len(), 2);
        assert_eq!(result.forms[0].action, "/a");
        assert_eq!(result.forms[1].action, "/b");
        assert_eq!(result.forms[1].method, "POST");
    }
}
