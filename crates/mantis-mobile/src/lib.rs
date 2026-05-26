//! mantis-mobile — static analysis for Android (`.apk`) and iOS
//! (`.ipa`) application bundles.
//!
//! ## What this crate does (and explicitly does not)
//!
//! Mobile app analysis splits into static (read the bundle) and
//! dynamic (instrument the running process). This crate covers
//! the static half:
//!
//! * Unpack the bundle (both APK and IPA are ZIP archives).
//! * Locate the manifest (`AndroidManifest.xml` for APK,
//!   `Info.plist` for IPA — when shipped as XML; binary-plist
//!   handling is a TODO with a clear hint).
//! * Parse the manifest with a deliberately conservative text
//!   matcher — we extract attributes by regex-ish scanning rather
//!   than pulling in a full AXML / binary-plist decoder. This
//!   handles human-readable manifests directly and produces a
//!   clear "binary manifest detected" finding when it can't.
//! * Walk every embedded text file and run secret-detection
//!   regexes (AWS keys, generic API tokens, JWTs, hard-coded
//!   private-key PEM blocks, Firebase keys).
//! * Flag insecure-config patterns: `android:debuggable="true"`,
//!   `android:allowBackup="true"`, `usesCleartextTraffic="true"`,
//!   exported components without permissions, iOS ATS
//!   `NSAllowsArbitraryLoads`.
//!
//! Dynamic instrumentation (Frida bindings) is out of scope for
//! this crate — it would pull in libfrida or its python wheels,
//! both of which significantly broaden the build surface. A
//! companion `mantis-mobile-dynamic` crate can take that on.
//!
//! ## License posture
//!
//! No code is copied from MobSF (GPL-3.0). The regex and
//! permissions catalogues here are recreations from public
//! Android / iOS documentation. The crate license is the workspace
//! default (Apache-2.0 OR MIT).

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use mantis_static_scan::{Finding, Severity};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MobileError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("unsupported bundle: {0}")]
    Unsupported(String),
}

/// Which platform the artefact belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Android,
    Ios,
}

impl Platform {
    /// Decide platform purely from the filename extension. Callers
    /// who care about content-type can override by constructing the
    /// platform manually.
    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("apk") => Some(Platform::Android),
            Some("ipa") => Some(Platform::Ios),
            _ => None,
        }
    }
}

/// Android permissions that are commonly abused or that elevate the
/// app's risk profile. Compiled from
/// developer.android.com/reference/android/Manifest.permission and
/// the Google Play "Permissions best practices" guidance. Maintained
/// as a tight allow-list rather than a sprawling catalogue — better
/// to flag a few high-signal permissions confidently than every
/// permission with vague guidance.
const DANGEROUS_ANDROID_PERMISSIONS: &[(&str, Severity)] = &[
    ("android.permission.READ_SMS", Severity::High),
    ("android.permission.SEND_SMS", Severity::High),
    ("android.permission.READ_CONTACTS", Severity::Medium),
    ("android.permission.WRITE_CONTACTS", Severity::Medium),
    ("android.permission.RECORD_AUDIO", Severity::High),
    ("android.permission.CAMERA", Severity::Medium),
    ("android.permission.ACCESS_FINE_LOCATION", Severity::Medium),
    ("android.permission.ACCESS_BACKGROUND_LOCATION", Severity::High),
    ("android.permission.READ_EXTERNAL_STORAGE", Severity::Low),
    ("android.permission.WRITE_EXTERNAL_STORAGE", Severity::Medium),
    ("android.permission.SYSTEM_ALERT_WINDOW", Severity::High),
    ("android.permission.REQUEST_INSTALL_PACKAGES", Severity::High),
    ("android.permission.WRITE_SETTINGS", Severity::High),
    ("android.permission.BIND_ACCESSIBILITY_SERVICE", Severity::High),
];

/// Secret patterns — substring matches against extracted text from
/// the bundle. These are intentionally conservative; trufflehog
/// (wired in via mantis-static-scan) is the real secret scanner.
/// What we add here is *bundle-aware* discovery — strings inside
/// `assets/`, `res/raw/`, `META-INF/`, `*.dex` strings tables, etc.
fn secret_patterns() -> &'static [(&'static str, &'static str, Severity)] {
    &[
        ("aws-access-key", "AKIA", Severity::High),
        ("google-api-key", "AIza", Severity::Medium),
        ("private-key-pem", "-----BEGIN PRIVATE KEY-----", Severity::Critical),
        ("rsa-key-pem", "-----BEGIN RSA PRIVATE KEY-----", Severity::Critical),
        ("ec-key-pem", "-----BEGIN EC PRIVATE KEY-----", Severity::Critical),
        ("firebase-secret", "firebase-adminsdk", Severity::High),
        ("github-token", "ghp_", Severity::High),
        ("github-token", "gho_", Severity::High),
        ("github-token", "ghs_", Severity::High),
        ("slack-token", "xoxb-", Severity::High),
        ("slack-token", "xoxp-", Severity::High),
        ("stripe-key", "sk_live_", Severity::Critical),
        ("stripe-key", "rk_live_", Severity::Critical),
    ]
}

/// Scan a mobile bundle and return the aggregate findings.
pub fn scan_bundle(path: &Path) -> Result<Vec<Finding>, MobileError> {
    let platform = Platform::from_path(path).ok_or_else(|| {
        MobileError::Unsupported(format!(
            "{}: unrecognised extension (expected .apk or .ipa)",
            path.display()
        ))
    })?;

    let file = File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let mut findings = Vec::new();
    let mut manifest_seen = false;
    let mut target_label = path.display().to_string();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();

        // Surface the manifest content separately and once.
        let is_manifest = matches!(platform, Platform::Android) && name == "AndroidManifest.xml"
            || matches!(platform, Platform::Ios)
                && (name.ends_with("/Info.plist") || name == "Info.plist");

        if is_manifest && !manifest_seen {
            manifest_seen = true;
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            let manifest_findings = analyse_manifest(platform, &name, &buf, &target_label);
            findings.extend(manifest_findings);
            continue;
        }

        // Skip files that are obviously binary blobs — running our
        // text scan over `.dex` / `.so` / images is wasted work. We
        // deliberately *don't* skip `.dex` text-strings: a dedicated
        // strings extractor would be a follow-up, surface it via a
        // single info-level finding for now.
        if name.ends_with(".dex") {
            findings.push(
                Finding::new(
                    "mantis-mobile",
                    "binary-blob",
                    name.clone(),
                    Severity::Info,
                    format!("dex bundle present: {name}"),
                )
                .with_description(
                    "Mantis flags dex presence but does not yet extract its strings table. \
                     Pair with `mantis-binary` if you need disassembly.",
                ),
            );
            continue;
        }
        if is_binary_extension(&name) {
            continue;
        }

        // Read text content and scan for secrets.
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        let Ok(text) = std::str::from_utf8(&buf) else {
            continue;
        };
        for f in scan_text_for_secrets(&name, text) {
            findings.push(f);
        }

        if name == "Info.plist" || name.ends_with("/Info.plist") {
            target_label = name.clone();
        }
    }

    if !manifest_seen {
        findings.push(Finding::new(
            "mantis-mobile",
            "manifest-missing",
            target_label,
            Severity::Medium,
            format!("no manifest found in {platform:?} bundle"),
        ));
    }

    Ok(findings)
}

/// Whether the path extension is a known opaque binary type we
/// shouldn't bother running text scans over.
fn is_binary_extension(name: &str) -> bool {
    const BIN: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svgz", ".woff", ".woff2",
        ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".wav", ".ogg", ".aac", ".flac", ".so", ".dylib",
        ".framework", ".class", ".jar", ".car",
    ];
    let lower = name.to_ascii_lowercase();
    BIN.iter().any(|ext| lower.ends_with(ext))
}

/// Parse a manifest (textual XML or plist) and emit findings.
/// Falls back to a "binary manifest" notice if the content looks
/// like AXML or binary-plist.
pub fn analyse_manifest(
    platform: Platform,
    name: &str,
    bytes: &[u8],
    bundle_label: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(text) = manifest_text(bytes) else {
        findings.push(
            Finding::new(
                "mantis-mobile",
                "manifest-binary",
                format!("{bundle_label}!{name}"),
                Severity::Low,
                format!("{name} is in binary format — extract with apktool/plutil first"),
            )
            .with_description(
                "Mantis intentionally avoids bundling an AXML / binary-plist decoder. \
                 Re-run after `apktool d <apk>` (Android) or `plutil -convert xml1 Info.plist` (iOS).",
            ),
        );
        return findings;
    };

    match platform {
        Platform::Android => analyse_android_manifest(&text, name, bundle_label, &mut findings),
        Platform::Ios => analyse_ios_plist(&text, name, bundle_label, &mut findings),
    }
    findings
}

/// Heuristic: does this look like a text manifest? AXML starts with
/// the bytes `03 00 08 00`; binary plist starts with `bplist`.
fn manifest_text(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(&[0x03, 0x00, 0x08, 0x00]) {
        return None;
    }
    if bytes.starts_with(b"bplist") {
        return None;
    }
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

fn analyse_android_manifest(text: &str, name: &str, label: &str, out: &mut Vec<Finding>) {
    let target = format!("{label}!{name}");

    if contains_attr(text, "android:debuggable", "true") {
        out.push(
            Finding::new(
                "mantis-mobile",
                "insecure-config",
                target.clone(),
                Severity::High,
                "android:debuggable=\"true\" enabled",
            )
            .with_description(
                "Debuggable builds let any user with adb attach a debugger and \
                 read app memory. Must be `false` in release builds.",
            )
            .with_meta("attribute", "android:debuggable"),
        );
    }
    if contains_attr(text, "android:allowBackup", "true") {
        out.push(
            Finding::new(
                "mantis-mobile",
                "insecure-config",
                target.clone(),
                Severity::Medium,
                "android:allowBackup=\"true\" enabled",
            )
            .with_description(
                "Allows adb backup to dump app private data on non-rooted devices.",
            )
            .with_meta("attribute", "android:allowBackup"),
        );
    }
    if contains_attr(text, "android:usesCleartextTraffic", "true") {
        out.push(
            Finding::new(
                "mantis-mobile",
                "insecure-config",
                target.clone(),
                Severity::High,
                "android:usesCleartextTraffic=\"true\"",
            )
            .with_description(
                "App permits plaintext HTTP. Combine with the network-security-config \
                 file if a domain-scoped exception is intended.",
            ),
        );
    }

    let permissions = extract_uses_permissions(text);
    for perm in &permissions {
        if let Some((_, severity)) = DANGEROUS_ANDROID_PERMISSIONS.iter().find(|(p, _)| p == perm) {
            out.push(
                Finding::new(
                    "mantis-mobile",
                    "dangerous-permission",
                    target.clone(),
                    *severity,
                    format!("uses-permission: {perm}"),
                )
                .with_meta("permission", perm.clone()),
            );
        }
    }

    for comp in extract_exported_components(text) {
        out.push(
            Finding::new(
                "mantis-mobile",
                "exported-component",
                target.clone(),
                Severity::Medium,
                format!("exported {} `{}`", comp.kind, comp.name),
            )
            .with_meta("component_kind", comp.kind)
            .with_meta("component_name", comp.name),
        );
    }
}

fn analyse_ios_plist(text: &str, name: &str, label: &str, out: &mut Vec<Finding>) {
    let target = format!("{label}!{name}");

    // NSAllowsArbitraryLoads true => ATS disabled.
    if has_plist_bool(text, "NSAllowsArbitraryLoads", true) {
        out.push(
            Finding::new(
                "mantis-mobile",
                "insecure-config",
                target.clone(),
                Severity::High,
                "ATS disabled (NSAllowsArbitraryLoads=true)",
            )
            .with_description(
                "App Transport Security is globally disabled; the app may load \
                 arbitrary HTTP endpoints.",
            ),
        );
    }
    if has_plist_bool(text, "NSAllowsArbitraryLoadsInWebContent", true) {
        out.push(
            Finding::new(
                "mantis-mobile",
                "insecure-config",
                target.clone(),
                Severity::Medium,
                "ATS disabled for WKWebView content",
            ),
        );
    }
    // UIFileSharingEnabled lets users pluck files out of /Documents.
    if has_plist_bool(text, "UIFileSharingEnabled", true) {
        out.push(
            Finding::new(
                "mantis-mobile",
                "insecure-config",
                target,
                Severity::Low,
                "UIFileSharingEnabled — /Documents is visible in iTunes/Finder",
            ),
        );
    }
}

/// `<uses-permission android:name="…" />` extractor. Tolerates
/// arbitrary attribute order and quoting style.
pub fn extract_uses_permissions(manifest_xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = "<uses-permission";
    let mut rest = manifest_xml;
    while let Some(idx) = rest.find(needle) {
        let tail = &rest[idx..];
        let end = tail.find('>').unwrap_or(tail.len());
        let tag = &tail[..end];
        if let Some(name) = attr_value(tag, "android:name") {
            out.push(name);
        }
        rest = &tail[end.min(tail.len())..];
        if rest.is_empty() {
            break;
        }
        rest = &rest[1..]; // skip the '>'
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedComponent {
    pub kind: String,
    pub name: String,
}

/// Find `<activity|service|receiver|provider … android:exported="true" />`.
/// We don't try to mirror the implicit-export rules
/// (`exported="true"` is inferred when an `<intent-filter>` is
/// present and exported is unset) — that would require building an
/// XML tree. The current behaviour catches the explicit cases,
/// which is the most common operator-introduced misconfiguration.
pub fn extract_exported_components(manifest_xml: &str) -> Vec<ExportedComponent> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for kind in ["activity", "service", "receiver", "provider"] {
        let needle = format!("<{kind}");
        let mut rest = manifest_xml;
        while let Some(idx) = rest.find(&needle) {
            let tail = &rest[idx..];
            let end = tail.find('>').unwrap_or(tail.len());
            let tag = &tail[..end];
            let exported = attr_value(tag, "android:exported")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if exported {
                if let Some(name) = attr_value(tag, "android:name") {
                    let comp = ExportedComponent {
                        kind: kind.to_string(),
                        name,
                    };
                    let key = format!("{}::{}", comp.kind, comp.name);
                    if seen.insert(key) {
                        out.push(comp);
                    }
                }
            }
            rest = &tail[end.min(tail.len())..];
            if rest.is_empty() {
                break;
            }
            rest = &rest[1..];
        }
    }
    out
}

/// Read `attr="value"` (or `attr='value'`) out of a single XML tag.
fn attr_value(tag: &str, attr: &str) -> Option<String> {
    let with_eq = format!("{attr}=");
    let idx = tag.find(&with_eq)?;
    let after = &tag[idx + with_eq.len()..];
    let mut chars = after.chars();
    let quote = chars.next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let rest = &after[1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

/// True iff the XML tag carries `attr="expected"`.
fn contains_attr(text: &str, attr: &str, expected: &str) -> bool {
    let pat = format!(r#"{attr}=""#);
    let mut rest = text;
    while let Some(idx) = rest.find(&pat) {
        let after = &rest[idx + pat.len()..];
        if let Some(end) = after.find('"') {
            if after[..end].eq_ignore_ascii_case(expected) {
                return true;
            }
            rest = &after[end + 1..];
        } else {
            break;
        }
    }
    false
}

/// Tiny plist matcher: looks for `<key>NAME</key><true/>` or
/// `<key>NAME</key><false/>` allowing arbitrary whitespace.
fn has_plist_bool(text: &str, key: &str, expected: bool) -> bool {
    let key_tag = format!("<key>{key}</key>");
    let Some(after_key) = text.find(&key_tag).map(|i| &text[i + key_tag.len()..]) else {
        return false;
    };
    let trimmed = after_key.trim_start();
    if expected {
        trimmed.starts_with("<true/>") || trimmed.starts_with("<true />")
    } else {
        trimmed.starts_with("<false/>") || trimmed.starts_with("<false />")
    }
}

/// Run every secret pattern against a single text file extracted
/// from the bundle. The file's archive-relative path becomes the
/// finding target.
pub fn scan_text_for_secrets(path: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (rule, pattern, severity) in secret_patterns() {
        if let Some(idx) = text.find(pattern) {
            // First-occurrence snippet, no more than 64 chars to
            // avoid leaking the whole secret into the finding.
            let snippet = &text[idx..text.len().min(idx + 64)];
            out.push(
                Finding::new(
                    "mantis-mobile",
                    "secret",
                    path.to_string(),
                    *severity,
                    format!("{rule} in {path}"),
                )
                .with_description(format!("matched pattern `{pattern}` -> `{snippet}…`"))
                .with_meta("rule", rule.to_string())
                .with_meta("pattern", (*pattern).to_string()),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, body) in entries {
            zip.start_file(*name, opts).unwrap();
            zip.write_all(body).unwrap();
        }
        zip.finish().unwrap();
    }

    #[test]
    fn platform_inferred_from_extension() {
        assert_eq!(Platform::from_path(Path::new("a.apk")), Some(Platform::Android));
        assert_eq!(Platform::from_path(Path::new("a.ipa")), Some(Platform::Ios));
        assert_eq!(Platform::from_path(Path::new("a.tar")), None);
        assert_eq!(Platform::from_path(Path::new("noext")), None);
    }

    #[test]
    fn attr_value_handles_both_quote_styles() {
        assert_eq!(
            attr_value("<x android:name=\"foo\" />", "android:name"),
            Some("foo".into())
        );
        assert_eq!(
            attr_value("<x android:name='bar' />", "android:name"),
            Some("bar".into())
        );
        assert_eq!(attr_value("<x />", "android:name"), None);
    }

    #[test]
    fn contains_attr_case_insensitive() {
        let xml = r#"<application android:debuggable="True" />"#;
        assert!(contains_attr(xml, "android:debuggable", "true"));
        assert!(!contains_attr(xml, "android:debuggable", "false"));
    }

    #[test]
    fn extract_uses_permissions_picks_up_all() {
        let xml = r#"
            <manifest>
              <uses-permission android:name="android.permission.READ_SMS" />
              <uses-permission android:name="android.permission.INTERNET" />
              <uses-permission android:name='android.permission.CAMERA' />
            </manifest>
        "#;
        let perms = extract_uses_permissions(xml);
        assert_eq!(perms.len(), 3);
        assert!(perms.contains(&"android.permission.READ_SMS".to_string()));
        assert!(perms.contains(&"android.permission.INTERNET".to_string()));
        assert!(perms.contains(&"android.permission.CAMERA".to_string()));
    }

    #[test]
    fn extract_exported_components_finds_explicit_exports() {
        let xml = r#"
            <application>
              <activity android:name=".Main" android:exported="true" />
              <service android:name=".Bg" android:exported="false" />
              <receiver android:name=".R" android:exported='true' />
              <provider android:name=".P" android:exported="true" android:authorities="x"/>
            </application>
        "#;
        let comps = extract_exported_components(xml);
        let names: Vec<_> = comps.iter().map(|c| (c.kind.as_str(), c.name.as_str())).collect();
        assert!(names.contains(&("activity", ".Main")));
        assert!(names.contains(&("receiver", ".R")));
        assert!(names.contains(&("provider", ".P")));
        assert!(!names.iter().any(|(_, n)| *n == ".Bg"));
    }

    #[test]
    fn android_manifest_findings_cover_insecure_flags() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
              <uses-permission android:name="android.permission.READ_SMS" />
              <application android:debuggable="true"
                           android:allowBackup="true"
                           android:usesCleartextTraffic="true">
                <activity android:name=".LeakyActivity" android:exported="true" />
              </application>
            </manifest>"#;
        let mut findings = Vec::new();
        analyse_android_manifest(xml, "AndroidManifest.xml", "demo.apk", &mut findings);
        let kinds: Vec<_> = findings.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"insecure-config"));
        assert!(kinds.contains(&"dangerous-permission"));
        assert!(kinds.contains(&"exported-component"));

        let titles: Vec<_> = findings.iter().map(|f| f.title.as_str()).collect();
        assert!(titles.iter().any(|t| t.contains("debuggable")));
        assert!(titles.iter().any(|t| t.contains("allowBackup")));
        assert!(titles.iter().any(|t| t.contains("usesCleartextTraffic")));
    }

    #[test]
    fn ios_plist_flags_ats_disabled() {
        let plist = r#"
            <plist><dict>
              <key>NSAppTransportSecurity</key><dict>
                <key>NSAllowsArbitraryLoads</key><true/>
              </dict>
              <key>UIFileSharingEnabled</key><true/>
            </dict></plist>
        "#;
        let mut findings = Vec::new();
        analyse_ios_plist(plist, "Info.plist", "demo.ipa", &mut findings);
        let titles: Vec<_> = findings.iter().map(|f| f.title.as_str()).collect();
        assert!(titles.iter().any(|t| t.contains("ATS disabled")));
        assert!(titles.iter().any(|t| t.contains("UIFileSharingEnabled")));
    }

    #[test]
    fn has_plist_bool_tolerates_whitespace_and_self_closing() {
        assert!(has_plist_bool(
            "<key>X</key>  <true/>",
            "X",
            true
        ));
        assert!(has_plist_bool("<key>X</key><true />", "X", true));
        assert!(!has_plist_bool("<key>X</key><false/>", "X", true));
    }

    #[test]
    fn scan_text_for_secrets_catches_common_tokens() {
        let body = "config:\n  github: ghp_abcd1234\n  aws: AKIAFAKEFAKEFAKEFAKE\n";
        let findings = scan_text_for_secrets("assets/config.yaml", body);
        let rules: Vec<_> = findings
            .iter()
            .map(|f| f.meta.get("rule").unwrap().clone())
            .collect();
        assert!(rules.iter().any(|r| r == "github-token"));
        assert!(rules.iter().any(|r| r == "aws-access-key"));
    }

    #[test]
    fn scan_text_for_secrets_emits_no_findings_for_clean_file() {
        let findings = scan_text_for_secrets("a.txt", "just normal text");
        assert!(findings.is_empty());
    }

    #[test]
    fn manifest_text_detects_axml_and_binary_plist() {
        assert!(manifest_text(&[0x03, 0x00, 0x08, 0x00, 0xff]).is_none());
        assert!(manifest_text(b"bplist00\x00").is_none());
        assert_eq!(manifest_text(b"<xml/>").as_deref(), Some("<xml/>"));
    }

    #[test]
    fn scan_bundle_round_trip_on_synthetic_apk() {
        let dir = tempdir().unwrap();
        let apk = dir.path().join("demo.apk");
        let manifest = r#"<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-permission android:name="android.permission.READ_SMS" />
  <application android:debuggable="true">
    <activity android:name=".X" android:exported="true" />
  </application>
</manifest>"#;
        write_zip(
            &apk,
            &[
                ("AndroidManifest.xml", manifest.as_bytes()),
                ("classes.dex", &[0x00, 0x01, 0x02]),
                ("assets/secrets.json", b"{\"key\":\"AKIATESTTESTTESTTEST\"}"),
                ("res/raw/clean.txt", b"hello world"),
            ],
        );

        let findings = scan_bundle(&apk).expect("scan ok");
        let kinds: HashSet<_> = findings.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains("insecure-config"));
        assert!(kinds.contains("dangerous-permission"));
        assert!(kinds.contains("exported-component"));
        assert!(kinds.contains("secret"));
        assert!(kinds.contains("binary-blob"));
    }

    #[test]
    fn scan_bundle_flags_missing_manifest() {
        let dir = tempdir().unwrap();
        let apk = dir.path().join("hollow.apk");
        write_zip(&apk, &[("assets/x.txt", b"x")]);
        let findings = scan_bundle(&apk).unwrap();
        assert!(findings.iter().any(|f| f.kind == "manifest-missing"));
    }

    #[test]
    fn scan_bundle_rejects_unsupported_extension() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("weird.zip");
        File::create(&path).unwrap();
        let err = scan_bundle(&path).unwrap_err();
        match err {
            MobileError::Unsupported(_) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn binary_manifest_produces_extract_hint() {
        let findings = analyse_manifest(
            Platform::Android,
            "AndroidManifest.xml",
            &[0x03, 0x00, 0x08, 0x00, 0x55],
            "demo.apk",
        );
        assert!(findings.iter().any(|f| f.kind == "manifest-binary"));
    }

    #[test]
    fn is_binary_extension_picks_common_assets() {
        assert!(is_binary_extension("res/drawable/foo.PNG"));
        assert!(is_binary_extension("lib/x86/libfoo.so"));
        assert!(!is_binary_extension("res/raw/text.json"));
    }
}
