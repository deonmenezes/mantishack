//! Provider-specific rule catalog.
//!
//! Each rule is a [`Rule`] with:
//! - a stable `id` (slug used in findings + reports)
//! - a short `description`
//! - a [`Matcher`] callback that returns the matched substrings and
//!   their byte offsets in the input
//! - a [`Severity`]
//!
//! Matchers are hand-rolled (no regex runtime dep) — almost every
//! credential format has a fixed prefix + a known length + a known
//! charset, which is straightforward to implement directly. This
//! keeps the dependency surface small and the scan fast.

use crate::{SecretFinding, Severity};

/// One match returned by a [`Matcher`]: the matched substring and its
/// byte offset in the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub matched: String,
    pub offset: usize,
}

/// Pluggable matcher callback. Receives the full input text and
/// returns every match found.
pub type Matcher = fn(&str) -> Vec<Match>;

/// One detection rule.
#[derive(Clone)]
pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub matcher: Matcher,
}

impl std::fmt::Debug for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rule")
            .field("id", &self.id)
            .field("description", &self.description)
            .field("severity", &self.severity)
            .finish()
    }
}

/// Collection of rules. Constructed via [`RuleSet::built_in`] for the
/// default catalog, or via [`RuleSet::new`] + [`RuleSet::push`] to
/// build a custom one.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// Empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// The default catalog — covers AWS, GCP, GitHub, GitLab, Slack,
    /// Stripe, OpenAI, Anthropic, Twilio, SendGrid, npm, PyPI,
    /// DigitalOcean, Square, Discord, Telegram, Notion, Linear,
    /// Postman, Mailgun, Heroku, JWT, generic PEM private keys.
    pub fn built_in() -> Self {
        Self {
            rules: vec![
                Rule {
                    id: "aws-access-key-id",
                    description: "AWS access key ID",
                    severity: Severity::High,
                    matcher: match_aws_access_key_id,
                },
                Rule {
                    id: "github-pat",
                    description: "GitHub personal access token (ghp_/ghs_/gho_/ghu_/ghr_)",
                    severity: Severity::High,
                    matcher: match_github_pat,
                },
                Rule {
                    id: "gitlab-pat",
                    description: "GitLab personal access token",
                    severity: Severity::High,
                    matcher: match_gitlab_pat,
                },
                Rule {
                    id: "slack-bot-token",
                    description: "Slack bot/user token (xoxb-/xoxp-/xoxa-/xoxr-)",
                    severity: Severity::High,
                    matcher: match_slack_token,
                },
                Rule {
                    id: "slack-webhook",
                    description: "Slack incoming webhook URL",
                    severity: Severity::Medium,
                    matcher: match_slack_webhook,
                },
                Rule {
                    id: "stripe-secret-key",
                    description: "Stripe live or test secret key",
                    severity: Severity::Critical,
                    matcher: match_stripe_key,
                },
                Rule {
                    id: "google-api-key",
                    description: "Google API key (AIza...)",
                    severity: Severity::High,
                    matcher: match_google_api_key,
                },
                Rule {
                    id: "openai-api-key",
                    description: "OpenAI API key (sk-...)",
                    severity: Severity::High,
                    matcher: match_openai_key,
                },
                Rule {
                    id: "anthropic-api-key",
                    description: "Anthropic API key (sk-ant-...)",
                    severity: Severity::High,
                    matcher: match_anthropic_key,
                },
                Rule {
                    id: "twilio-account-sid",
                    description: "Twilio Account SID (AC + 32 hex)",
                    severity: Severity::High,
                    matcher: match_twilio_sid,
                },
                Rule {
                    id: "sendgrid-api-key",
                    description: "SendGrid API key (SG....)",
                    severity: Severity::High,
                    matcher: match_sendgrid_key,
                },
                Rule {
                    id: "mailgun-api-key",
                    description: "Mailgun API key (key-...)",
                    severity: Severity::High,
                    matcher: match_mailgun_key,
                },
                Rule {
                    id: "npm-token",
                    description: "npm access token (npm_)",
                    severity: Severity::High,
                    matcher: match_npm_token,
                },
                Rule {
                    id: "pypi-token",
                    description: "PyPI API token (pypi-...)",
                    severity: Severity::High,
                    matcher: match_pypi_token,
                },
                Rule {
                    id: "digitalocean-pat",
                    description: "DigitalOcean personal access token (dop_v1_)",
                    severity: Severity::High,
                    matcher: match_do_pat,
                },
                Rule {
                    id: "discord-bot-token",
                    description: "Discord bot token",
                    severity: Severity::Medium,
                    matcher: match_discord_bot,
                },
                Rule {
                    id: "discord-webhook",
                    description: "Discord webhook URL",
                    severity: Severity::Medium,
                    matcher: match_discord_webhook,
                },
                Rule {
                    id: "telegram-bot-token",
                    description: "Telegram bot token",
                    severity: Severity::Medium,
                    matcher: match_telegram_bot,
                },
                Rule {
                    id: "notion-integration-token",
                    description: "Notion integration token (secret_)",
                    severity: Severity::Medium,
                    matcher: match_notion_token,
                },
                Rule {
                    id: "linear-api-key",
                    description: "Linear API key (lin_api_)",
                    severity: Severity::Medium,
                    matcher: match_linear_key,
                },
                Rule {
                    id: "postman-api-key",
                    description: "Postman API key (PMAK-)",
                    severity: Severity::Medium,
                    matcher: match_postman_key,
                },
                Rule {
                    id: "square-access-token",
                    description: "Square access token (sq0atp-)",
                    severity: Severity::High,
                    matcher: match_square_token,
                },
                Rule {
                    id: "jwt",
                    description: "JSON Web Token (eyJ...)",
                    severity: Severity::Low,
                    matcher: match_jwt,
                },
                Rule {
                    id: "private-key",
                    description: "PEM-encoded private key (RSA / EC / OpenSSH / DSA)",
                    severity: Severity::Critical,
                    matcher: match_private_key,
                },
                Rule {
                    id: "cloudflare-api-token",
                    description: "Cloudflare API token (40 alphanum)",
                    severity: Severity::High,
                    matcher: match_cloudflare_token,
                },
                Rule {
                    id: "datadog-api-key",
                    description: "Datadog API key (32 lowercase hex assigned to dd_*)",
                    severity: Severity::High,
                    matcher: match_datadog_api_key,
                },
                Rule {
                    id: "heroku-api-key",
                    description: "Heroku API key (UUID assigned to heroku_*)",
                    severity: Severity::High,
                    matcher: match_heroku_api_key,
                },
            ],
        }
    }

    pub fn push(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Rule> {
        self.rules.iter()
    }

    /// Apply every rule to `text` and return all findings.
    pub fn scan(&self, text: &str) -> Vec<SecretFinding> {
        let mut out = Vec::new();
        for rule in &self.rules {
            for m in (rule.matcher)(text) {
                out.push(SecretFinding {
                    rule_id: rule.id.to_string(),
                    description: rule.description.to_string(),
                    severity: rule.severity,
                    matched: m.matched,
                    offset: m.offset,
                    source: None,
                });
            }
        }
        out
    }
}

// ---------------- helpers ----------------

/// Find each occurrence of `prefix` and, if the following bytes pass
/// `body_ok`, emit a match of length `prefix.len() + body_len`.
fn find_prefixed_runs(
    text: &str,
    prefix: &str,
    body_len: usize,
    body_ok: impl Fn(u8) -> bool,
) -> Vec<Match> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let prefix_bytes = prefix.as_bytes();
    let plen = prefix_bytes.len();
    if bytes.len() < plen + body_len {
        return out;
    }
    // SIMD-accelerated prefix search via memmem — jumps directly to each
    // candidate position instead of stepping byte-by-byte. On a 1 MB JS
    // bundle this drops the prefix-scan cost from O(n) byte compares to
    // ~one vector instruction per chunk; the body verification still
    // runs per candidate, but candidates are rare relative to the input.
    let finder = memchr::memmem::Finder::new(prefix_bytes);
    let mut search_from = 0;
    while let Some(rel) = finder.find(&bytes[search_from..]) {
        let i = search_from + rel;
        let body_end = i + plen + body_len;
        if body_end > bytes.len() {
            // Not enough trailing bytes; no later occurrence can satisfy
            // the length requirement either, since the input only gets
            // shorter as we advance.
            break;
        }
        let body = &bytes[i + plen..body_end];
        if body.iter().all(|&c| body_ok(c)) {
            // Reject partial matches embedded in a longer accepted run
            // (e.g. an AKIA…run continuing past the expected 16 chars
            // would otherwise look like a valid 16-char token).
            let continues = bytes.get(body_end).copied().is_some_and(&body_ok);
            if !continues {
                // Input is &str, so the byte slice is valid UTF-8 by
                // construction — skip the from_utf8 round-trip.
                let matched = text[i..body_end].to_string();
                out.push(Match { matched, offset: i });
                search_from = body_end;
                continue;
            }
        }
        // Either the body charset failed or the run continues past
        // body_len. Advance past this prefix occurrence and keep
        // searching.
        search_from = i + 1;
    }
    out
}

fn alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

fn alnum_or_dash_underscore(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

fn lowercase_hex(c: u8) -> bool {
    c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
}

fn b64_charset(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
}

// ---------------- matchers ----------------

fn match_aws_access_key_id(text: &str) -> Vec<Match> {
    // AWS access keys: AKIA (long-term) / ASIA (STS) / AIDA (IAM
    // user) / AGPA (IAM group) / AROA (IAM role) followed by 16
    // uppercase alphanum.
    let mut out = Vec::new();
    for prefix in ["AKIA", "ASIA", "AIDA", "AGPA", "AROA"] {
        out.extend(find_prefixed_runs(text, prefix, 16, |c| {
            c.is_ascii_uppercase() || c.is_ascii_digit()
        }));
    }
    out
}

fn match_github_pat(text: &str) -> Vec<Match> {
    let mut out = Vec::new();
    for prefix in ["ghp_", "ghs_", "gho_", "ghu_", "ghr_"] {
        out.extend(find_prefixed_runs(text, prefix, 36, alnum));
    }
    out
}

fn match_gitlab_pat(text: &str) -> Vec<Match> {
    find_prefixed_runs(text, "glpat-", 20, alnum_or_dash_underscore)
}

fn match_slack_token(text: &str) -> Vec<Match> {
    let mut out = Vec::new();
    // Slack tokens: xoxb-/xoxp-/xoxa-/xoxr- followed by digits, then
    // alnum segments joined by `-`. We accept ≥ 20 chars of body.
    let bytes = text.as_bytes();
    for prefix in ["xoxb-", "xoxp-", "xoxa-", "xoxr-"] {
        let p = prefix.as_bytes();
        // SIMD-jump to each prefix occurrence.
        let finder = memchr::memmem::Finder::new(p);
        let mut from = 0;
        while let Some(rel) = finder.find(&bytes[from..]) {
            let start = from + rel;
            let mut j = start + p.len();
            while j < bytes.len() && alnum_or_dash_underscore(bytes[j]) {
                j += 1;
            }
            if j - (start + p.len()) >= 20 {
                out.push(Match {
                    matched: text[start..j].to_string(),
                    offset: start,
                });
                from = j;
            } else {
                from = start + 1;
            }
        }
    }
    out
}

fn match_slack_webhook(text: &str) -> Vec<Match> {
    // https://hooks.slack.com/services/T.../B.../...
    let anchor = "https://hooks.slack.com/services/";
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let p = anchor.as_bytes();
    let finder = memchr::memmem::Finder::new(p);
    let mut from = 0;
    while let Some(rel) = finder.find(&bytes[from..]) {
        let start = from + rel;
        let mut j = start + p.len();
        while j < bytes.len() && (alnum(bytes[j]) || bytes[j] == b'/') {
            j += 1;
        }
        if j - start > p.len() + 20 {
            out.push(Match {
                matched: text[start..j].to_string(),
                offset: start,
            });
            from = j;
        } else {
            from = start + 1;
        }
    }
    out
}

fn match_stripe_key(text: &str) -> Vec<Match> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    for prefix in ["sk_live_", "sk_test_", "rk_live_", "rk_test_"] {
        // Stripe keys are 24+ alphanum after the prefix. memmem prefix
        // search instead of byte-by-byte compare (same pattern as the
        // sibling matchers in this file).
        let p = prefix.as_bytes();
        let finder = memchr::memmem::Finder::new(p);
        let mut from = 0;
        while let Some(rel) = finder.find(&bytes[from..]) {
            let start = from + rel;
            let mut j = start + p.len();
            while j < bytes.len() && alnum(bytes[j]) {
                j += 1;
            }
            if j - (start + p.len()) >= 20 {
                out.push(Match {
                    matched: text[start..j].to_string(),
                    offset: start,
                });
                from = j;
            } else {
                from = start + 1;
            }
        }
    }
    out
}

fn match_google_api_key(text: &str) -> Vec<Match> {
    find_prefixed_runs(text, "AIza", 35, alnum_or_dash_underscore)
}

fn match_openai_key(text: &str) -> Vec<Match> {
    // sk-<48 base64-url chars>. Exclude sk-ant- which is Anthropic's
    // prefix — we don't want to double-match.
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let prefix = b"sk-";
    let mut i = 0;
    while i + 3 < bytes.len() {
        if &bytes[i..i + 3] == prefix {
            // Skip if this is actually `sk-ant-` (handled separately).
            if bytes.get(i + 3..i + 7) == Some(b"ant-") {
                i += 7;
                continue;
            }
            let start = i;
            let mut j = i + 3;
            while j < bytes.len() && alnum_or_dash_underscore(bytes[j]) {
                j += 1;
            }
            if j - (i + 3) >= 32 {
                let matched = text[start..j].to_string();
                out.push(Match {
                    matched,
                    offset: start,
                });
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn match_anthropic_key(text: &str) -> Vec<Match> {
    let bytes = text.as_bytes();
    let prefix = b"sk-ant-";
    let mut out = Vec::new();
    // memmem prefix search (same pattern as sibling matchers).
    let finder = memchr::memmem::Finder::new(prefix);
    let mut from = 0;
    while let Some(rel) = finder.find(&bytes[from..]) {
        let start = from + rel;
        let mut j = start + prefix.len();
        while j < bytes.len() && alnum_or_dash_underscore(bytes[j]) {
            j += 1;
        }
        if j - (start + prefix.len()) >= 40 {
            out.push(Match {
                matched: text[start..j].to_string(),
                offset: start,
            });
            from = j;
        } else {
            from = start + 1;
        }
    }
    out
}

fn match_twilio_sid(text: &str) -> Vec<Match> {
    find_prefixed_runs(text, "AC", 32, lowercase_hex)
}

fn match_sendgrid_key(text: &str) -> Vec<Match> {
    // SG.<22 b64url>.<43 b64url>
    let bytes = text.as_bytes();
    let prefix = b"SG.";
    let mut out = Vec::new();
    // SIMD prefix scan via memmem instead of byte-by-byte compare.
    let finder = memchr::memmem::Finder::new(prefix);
    let mut from = 0;
    while let Some(rel) = finder.find(&bytes[from..]) {
        let start = from + rel;
        let mut j = start + prefix.len();
        while j < bytes.len()
            && (alnum(bytes[j]) || bytes[j] == b'-' || bytes[j] == b'_' || bytes[j] == b'.')
        {
            j += 1;
        }
        let body = &bytes[start + prefix.len()..j];
        // Must contain exactly one `.` and be ≥ 60 chars. Early-exit
        // dot count via memchr — faster than iter().filter().count()
        // and short-circuits once we know we've exceeded 1 dot.
        let mut dot_iter = memchr::memchr_iter(b'.', body);
        let exactly_one_dot = dot_iter.next().is_some() && dot_iter.next().is_none();
        if exactly_one_dot && body.len() >= 60 {
            out.push(Match {
                matched: text[start..j].to_string(),
                offset: start,
            });
            from = j;
        } else {
            from = start + 1;
        }
    }
    out
}

fn match_mailgun_key(text: &str) -> Vec<Match> {
    find_prefixed_runs(text, "key-", 32, lowercase_hex)
}

fn match_npm_token(text: &str) -> Vec<Match> {
    find_prefixed_runs(text, "npm_", 36, alnum)
}

fn match_pypi_token(text: &str) -> Vec<Match> {
    // pypi-AgEIcHlwaS5vcmcCJDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    // body is base64-url, ≥ 60 chars.
    let bytes = text.as_bytes();
    let prefix = b"pypi-";
    let mut out = Vec::new();
    let finder = memchr::memmem::Finder::new(prefix);
    let mut from = 0;
    while let Some(rel) = finder.find(&bytes[from..]) {
        let start = from + rel;
        let mut j = start + prefix.len();
        while j < bytes.len() && alnum_or_dash_underscore(bytes[j]) {
            j += 1;
        }
        if j - (start + prefix.len()) >= 60 {
            out.push(Match {
                matched: text[start..j].to_string(),
                offset: start,
            });
            from = j;
        } else {
            from = start + 1;
        }
    }
    out
}

fn match_do_pat(text: &str) -> Vec<Match> {
    find_prefixed_runs(text, "dop_v1_", 64, lowercase_hex)
}

fn match_discord_bot(text: &str) -> Vec<Match> {
    // Discord bot tokens: <24-26 alphanum>.<6 alphanum>.<27+ alphanum>
    // The first segment is base64 of snowflake (24-26 chars), but
    // we accept generously and require the `.<6>.<27+>` shape.
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    'outer: while i < bytes.len() {
        if !alnum(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        let mut j = i;
        while j < bytes.len() && alnum(bytes[j]) {
            j += 1;
        }
        let seg1 = j - start;
        if !(24..=30).contains(&seg1) || bytes.get(j) != Some(&b'.') {
            i = j + 1;
            continue 'outer;
        }
        let mid_start = j + 1;
        let mut k = mid_start;
        while k < bytes.len() && (alnum(bytes[k]) || bytes[k] == b'_' || bytes[k] == b'-') {
            k += 1;
        }
        let seg2 = k - mid_start;
        if seg2 != 6 || bytes.get(k) != Some(&b'.') {
            i = j + 1;
            continue 'outer;
        }
        let last_start = k + 1;
        let mut m = last_start;
        while m < bytes.len() && (alnum(bytes[m]) || bytes[m] == b'_' || bytes[m] == b'-') {
            m += 1;
        }
        let seg3 = m - last_start;
        if seg3 < 27 {
            i = j + 1;
            continue;
        }
        let matched = text[start..m].to_string();
        out.push(Match {
            matched,
            offset: start,
        });
        i = m;
    }
    out
}

fn match_discord_webhook(text: &str) -> Vec<Match> {
    let anchor = "https://discord.com/api/webhooks/";
    let bytes = text.as_bytes();
    let p = anchor.as_bytes();
    let mut out = Vec::new();
    let finder = memchr::memmem::Finder::new(p);
    let mut from = 0;
    while let Some(rel) = finder.find(&bytes[from..]) {
        let start = from + rel;
        let mut j = start + p.len();
        while j < bytes.len()
            && (alnum(bytes[j]) || bytes[j] == b'/' || bytes[j] == b'-' || bytes[j] == b'_')
        {
            j += 1;
        }
        if j - start > p.len() + 20 {
            out.push(Match {
                matched: text[start..j].to_string(),
                offset: start,
            });
            from = j;
        } else {
            from = start + 1;
        }
    }
    out
}

fn match_telegram_bot(text: &str) -> Vec<Match> {
    // Telegram bot tokens: <8-10 digits>:<35 alphanum/dash/underscore>
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        let digits = j - start;
        if !(8..=10).contains(&digits) || bytes.get(j) != Some(&b':') {
            i = j;
            continue;
        }
        let body_start = j + 1;
        let mut k = body_start;
        while k < bytes.len() && alnum_or_dash_underscore(bytes[k]) {
            k += 1;
        }
        if k - body_start >= 35 {
            let matched = text[start..k].to_string();
            out.push(Match {
                matched,
                offset: start,
            });
        }
        i = k;
    }
    out
}

fn match_notion_token(text: &str) -> Vec<Match> {
    find_prefixed_runs(text, "secret_", 43, alnum_or_dash_underscore)
}

fn match_linear_key(text: &str) -> Vec<Match> {
    find_prefixed_runs(text, "lin_api_", 40, alnum_or_dash_underscore)
}

fn match_postman_key(text: &str) -> Vec<Match> {
    find_prefixed_runs(text, "PMAK-", 59, alnum)
}

fn match_square_token(text: &str) -> Vec<Match> {
    find_prefixed_runs(text, "sq0atp-", 22, alnum_or_dash_underscore)
}

fn match_jwt(text: &str) -> Vec<Match> {
    // JWT: 3 base64url segments separated by `.`; header always starts
    // with `eyJ` (base64 of `{"`).
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if &bytes[i..i + 3] != b"eyJ" {
            i += 1;
            continue;
        }
        let start = i;
        let mut j = i;
        while j < bytes.len() && (alnum_or_dash_underscore(bytes[j]) || bytes[j] == b'=') {
            j += 1;
        }
        if bytes.get(j) != Some(&b'.') {
            i = j + 1;
            continue;
        }
        // payload
        let mid_start = j + 1;
        let mut k = mid_start;
        while k < bytes.len() && (alnum_or_dash_underscore(bytes[k]) || bytes[k] == b'=') {
            k += 1;
        }
        if bytes.get(k) != Some(&b'.') {
            i = j + 1;
            continue;
        }
        // signature (may be empty for alg=none, but require at least 1)
        let sig_start = k + 1;
        let mut m = sig_start;
        while m < bytes.len() && (alnum_or_dash_underscore(bytes[m]) || bytes[m] == b'=') {
            m += 1;
        }
        if m - sig_start == 0 {
            i = j + 1;
            continue;
        }
        let matched = text[start..m].to_string();
        out.push(Match {
            matched,
            offset: start,
        });
        i = m;
    }
    out
}

fn match_private_key(text: &str) -> Vec<Match> {
    let anchors = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ];
    let mut out = Vec::new();
    for anchor in anchors {
        let mut start = 0;
        while let Some(pos) = text[start..].find(anchor) {
            let abs = start + pos;
            out.push(Match {
                matched: anchor.to_string(),
                offset: abs,
            });
            start = abs + anchor.len();
        }
    }
    out
}

fn match_cloudflare_token(text: &str) -> Vec<Match> {
    // Cloudflare API tokens look like 40 alphanum characters preceded
    // by an assignment to a known variable name. Pure structural
    // matching here is too noisy; require a `cloudflare`/`cf_` hint
    // within 32 chars before the token.
    contextual_alnum_token(text, &["cloudflare", "cf_", "cf-api", "cloudflare_api"], 40)
}

fn match_datadog_api_key(text: &str) -> Vec<Match> {
    contextual_lowercase_hex_token(text, &["datadog", "dd_api", "dd_app", "dd-api"], 32)
}

fn match_heroku_api_key(text: &str) -> Vec<Match> {
    // Heroku API keys are UUIDs. Require a `heroku` hint nearby.
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 36 <= bytes.len() {
        let slice = &bytes[i..i + 36];
        let looks = (0..36).all(|k| match k {
            8 | 13 | 18 | 23 => slice[k] == b'-',
            _ => slice[k].is_ascii_hexdigit(),
        });
        if !looks {
            i += 1;
            continue;
        }
        let look_back_start = i.saturating_sub(40);
        let prelude = &text[look_back_start..i];
        if prelude.to_ascii_lowercase().contains("heroku") {
            let matched = text[i..i + 36].to_string();
            out.push(Match { matched, offset: i });
            i += 36;
        } else {
            i += 1;
        }
    }
    out
}

fn contextual_alnum_token(text: &str, hints: &[&str], len: usize) -> Vec<Match> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + len <= bytes.len() {
        let slice = &bytes[i..i + len];
        let next = bytes.get(i + len).copied();
        let prev = if i == 0 { None } else { Some(bytes[i - 1]) };
        let ok = slice.iter().all(|&c| c.is_ascii_alphanumeric())
            && next.map(|c| !c.is_ascii_alphanumeric()).unwrap_or(true)
            && prev.map(|c| !c.is_ascii_alphanumeric()).unwrap_or(true);
        if !ok {
            i += 1;
            continue;
        }
        let look_back_start = i.saturating_sub(48);
        let prelude = &text[look_back_start..i].to_ascii_lowercase();
        if hints.iter().any(|h| prelude.contains(h)) {
            let matched = text[i..i + len].to_string();
            out.push(Match { matched, offset: i });
            i += len;
        } else {
            i += 1;
        }
    }
    out
}

fn contextual_lowercase_hex_token(text: &str, hints: &[&str], len: usize) -> Vec<Match> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + len <= bytes.len() {
        let slice = &bytes[i..i + len];
        let next = bytes.get(i + len).copied();
        let prev = if i == 0 { None } else { Some(bytes[i - 1]) };
        let ok = slice.iter().all(|&c| lowercase_hex(c))
            && next.map(|c| !c.is_ascii_alphanumeric()).unwrap_or(true)
            && prev.map(|c| !c.is_ascii_alphanumeric()).unwrap_or(true);
        if !ok {
            i += 1;
            continue;
        }
        let look_back_start = i.saturating_sub(48);
        let prelude = &text[look_back_start..i].to_ascii_lowercase();
        if hints.iter().any(|h| prelude.contains(h)) {
            let matched = text[i..i + len].to_string();
            out.push(Match { matched, offset: i });
            i += len;
        } else {
            i += 1;
        }
    }
    out
}

// Avoid an unused-fn warning for b64_charset — used by future rules
// (Slack legacy tokens, S3 secret access keys). Keep the symbol live.
#[allow(dead_code)]
fn _force_use_b64_charset() {
    let _ = b64_charset(b'A');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_rule_set_is_non_empty_and_unique() {
        let rs = RuleSet::built_in();
        assert!(rs.len() > 20);
        let mut ids: Vec<&str> = rs.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        let pre = ids.len();
        ids.dedup();
        assert_eq!(pre, ids.len(), "duplicate rule IDs");
    }

    #[test]
    fn aws_access_key_matches_all_prefixes() {
        for prefix in ["AKIA", "ASIA", "AIDA", "AGPA", "AROA"] {
            // Exactly 16 uppercase-alnum after the prefix, then a
            // non-alnum delimiter so the continuation guard passes.
            let key = format!("{prefix}0123456789ABCDEF");
            let body = format!("\"{key}\"");
            let r = match_aws_access_key_id(&body);
            assert_eq!(r.len(), 1, "prefix {} didn't match in {}", prefix, body);
            assert_eq!(r[0].matched, key);
        }
    }

    #[test]
    fn aws_access_key_rejects_lowercase_body() {
        let body = concat!("AKIA", "aaaaaaaaaaaaaaaa"); // lowercase body — invalid
        assert!(match_aws_access_key_id(body).is_empty());
    }

    #[test]
    fn github_pat_matches_all_variants() {
        for prefix in ["ghp_", "ghs_", "gho_", "ghu_", "ghr_"] {
            // 36 alnum after prefix, delimited.
            let key = format!("{prefix}ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
            let body = format!("token={key} ");
            assert_eq!(match_github_pat(&body).len(), 1, "{}", body);
        }
    }

    // Test fixtures below use concat!() to split secret-shape literals so the
    // source file does not contain contiguous matches for our own regexes (which
    // would trigger upstream secret-scanning push protection). The compiler joins
    // the parts; the resulting binary still exercises the real matchers.

    #[test]
    fn slack_bot_token_matches() {
        let body = concat!(
            "Authorization: Bearer ",
            "xoxb",
            "-1234567890-1234567890123-AaBbCcDdEeFfGg"
        );
        let r = match_slack_token(body);
        assert_eq!(r.len(), 1);
        assert!(r[0].matched.starts_with("xoxb-"));
    }

    #[test]
    fn slack_webhook_matches_full_url() {
        let body = concat!(
            "post to https://hooks.",
            "slack.com/services/",
            "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX please"
        );
        let r = match_slack_webhook(body);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn stripe_secret_key_matches_live_and_test() {
        let live = concat!("sk_", "live_aaaaaaaaaaaaaaaaaaaaaaaa");
        let test = concat!("sk_", "test_bbbbbbbbbbbbbbbbbbbbbbbb");
        assert_eq!(match_stripe_key(live).len(), 1);
        assert_eq!(match_stripe_key(test).len(), 1);
    }

    #[test]
    fn openai_and_anthropic_do_not_collide() {
        let body = concat!(
            "openai ",
            "sk-",
            "abcdefghijklmnopqrstuvwxyz0123456789AB",
            " and anthropic ",
            "sk-ant-",
            "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
        );
        let oai = match_openai_key(body);
        let ant = match_anthropic_key(body);
        assert_eq!(oai.len(), 1, "openai got {:?}", oai);
        assert_eq!(ant.len(), 1, "anthropic got {:?}", ant);
        assert!(!oai[0].matched.contains("ant-"));
        assert!(ant[0].matched.starts_with("sk-ant-"));
    }

    #[test]
    fn google_api_key_matches() {
        // 35 chars after AIza, then a delimiter. Split so source file doesn't
        // hold a contiguous `AIza…` literal.
        let body = concat!("key=", "AIza", "SyABCDEFGHIJKLMNOPQRSTUVWXYZ-abcdef ");
        let r = match_google_api_key(body);
        assert_eq!(r.len(), 1, "{}", body);
    }

    #[test]
    fn twilio_account_sid_matches_32_hex() {
        let body = concat!("AC", "00112233445566778899aabbccddeeff");
        let r = match_twilio_sid(body);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn sendgrid_key_requires_one_dot_in_body() {
        let body = concat!(
            "SG",
            ".aBcDeFgHiJkLmNoPqRsTuV.aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678901234567xyz"
        );
        let r = match_sendgrid_key(body);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn pem_private_key_matches_all_variants() {
        for anchor in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
        ] {
            let r = match_private_key(anchor);
            assert_eq!(r.len(), 1, "{} not matched", anchor);
        }
    }

    #[test]
    fn jwt_matches_three_segment_token() {
        let body =
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature";
        let r = match_jwt(body);
        assert_eq!(r.len(), 1);
        assert!(r[0].matched.starts_with("eyJ"));
    }

    #[test]
    fn telegram_bot_matches_format() {
        let body = "TG=123456789:AAAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let r = match_telegram_bot(body);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn discord_bot_matches_three_segment_token() {
        let body = "DISCORD_TOKEN=AbCdEfGhIjKlMnOpQrStUvWx.XyZ012.abcdefghijklmnopqrstuvwxyz0";
        let r = match_discord_bot(body);
        assert_eq!(r.len(), 1, "got {:?}", r);
    }

    #[test]
    fn discord_webhook_matches() {
        let body = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789";
        let r = match_discord_webhook(body);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn cloudflare_token_requires_context() {
        let without = "x".repeat(40);
        assert!(match_cloudflare_token(&without).is_empty());
        let with = format!(
            "cloudflare_api_token={}",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd"
        );
        assert_eq!(match_cloudflare_token(&with).len(), 1);
    }

    #[test]
    fn datadog_key_requires_context() {
        let with = "datadog_api_key=0123456789abcdef0123456789abcdef";
        let without = "raw=0123456789abcdef0123456789abcdef";
        assert_eq!(match_datadog_api_key(with).len(), 1);
        assert!(match_datadog_api_key(without).is_empty());
    }

    #[test]
    fn heroku_key_requires_context() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let with = format!("heroku_api_key={uuid}");
        let without = format!("user_id={uuid}");
        assert_eq!(match_heroku_api_key(&with).len(), 1);
        assert!(match_heroku_api_key(&without).is_empty());
    }

    #[test]
    fn rule_set_scan_aggregates_across_all_rules() {
        let rs = RuleSet::built_in();
        // AKIA + 16 uppercase-alnum, then space; ghp_ + 36 alnum, then space.
        // Split with concat!() so push protection doesn't trip on these test fixtures.
        let body = concat!(
            "aws ",
            "AKIA",
            "IOSFODNN7EXAMPL3 gh ",
            "ghp",
            "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 done"
        );
        let f = rs.scan(body);
        assert!(
            f.iter().any(|x| x.rule_id == "aws-access-key-id"),
            "no aws hit in {f:?}"
        );
        assert!(
            f.iter().any(|x| x.rule_id == "github-pat"),
            "no gh hit in {f:?}"
        );
    }

    #[test]
    fn find_prefixed_runs_does_not_match_partial() {
        // 14 trailing chars instead of 16 — should not match.
        let body = concat!("AKIA", "0123456789ABCD"); // 14 chars after AKIA
        assert!(match_aws_access_key_id(body).is_empty());
    }

    #[test]
    fn find_prefixed_runs_does_not_match_when_longer_than_expected() {
        // 16 chars exactly should match — verify the cutoff.
        let body = concat!("AKIA", "0123456789ABCDEF");
        let r = match_aws_access_key_id(body);
        assert_eq!(r.len(), 1);
        // Adding an alnum continuation should cause us to reject —
        // the body continues so we don't know where it ends.
        let longer = concat!("AKIA", "0123456789ABCDEFG");
        assert!(match_aws_access_key_id(longer).is_empty());
    }
}
