//! Integration tests for mantis-auth.
//!
//! These tests exercise the full public API end-to-end using real
//! temporary directories, verifying persistence, isolation, and
//! redaction properties.

use camino::Utf8PathBuf;
use mantis_auth::{AuthCookie, AuthHeader, AuthProfile, AuthStore};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_store() -> (tempfile::TempDir, AuthStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
    let store = AuthStore::new(root);
    (dir, store)
}

fn profile(name: &str, token: &str) -> AuthProfile {
    AuthProfile {
        name: name.to_owned(),
        headers: vec![AuthHeader {
            name: "Authorization".to_owned(),
            value: format!("Bearer {token}"),
        }],
        cookies: vec![AuthCookie {
            name: "session".to_owned(),
            value: token.to_owned(),
            domain: Some("target.example.com".to_owned()),
            path: Some("/".to_owned()),
            secure: true,
            http_only: true,
        }],
        query: vec![("api_key".to_owned(), format!("key-{token}"))],
        expires_at_unix: None,
        created_at_unix: 1_700_000_000,
        origin: "manual_paste".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

#[test]
fn round_trip_put_get() {
    let (_dir, store) = make_store();
    store.put("eng-rt", profile("attacker", "tok-xyz")).unwrap();
    let got = store.get("eng-rt", "attacker").unwrap();
    assert_eq!(got.name, "attacker");
    assert_eq!(got.headers[0].value, "Bearer tok-xyz");
    assert_eq!(got.cookies[0].value, "tok-xyz");
    assert_eq!(got.query[0].1, "key-tok-xyz");
}

// ---------------------------------------------------------------------------
// list_redacted
// ---------------------------------------------------------------------------

#[test]
fn list_redacted_exposes_names_not_values() {
    let (_dir, store) = make_store();
    store
        .put("eng-rd", profile("attacker", "secret-password"))
        .unwrap();

    let redacted = store.list_redacted("eng-rd").unwrap();
    assert_eq!(redacted.len(), 1);

    let r = &redacted[0];
    assert_eq!(r.name, "attacker");
    assert!(
        r.header_names.contains(&"Authorization".to_owned()),
        "header name must appear"
    );
    assert!(
        r.cookie_names.contains(&"session".to_owned()),
        "cookie name must appear"
    );
    assert!(
        r.query_keys.contains(&"api_key".to_owned()),
        "query key must appear"
    );

    // Serialise the redacted profile — raw secret must never appear.
    let json = serde_json::to_string(r).unwrap();
    assert!(
        !json.contains("secret-password"),
        "raw secret must not appear in redacted JSON; got: {json}"
    );
    assert!(
        !json.contains("Bearer secret-password"),
        "raw Authorization value must not appear"
    );

    // Secret fingerprint must be exactly 16 hex chars.
    assert_eq!(r.secret_fingerprint.len(), 16);
    assert!(
        r.secret_fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
        "fingerprint must be hex"
    );
}

// ---------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------

#[test]
fn delete_true_on_existing_false_on_missing() {
    let (_dir, store) = make_store();
    store.put("eng-del", profile("victim", "tok")).unwrap();
    assert!(
        store.delete("eng-del", "victim").unwrap(),
        "should return true when deleting existing profile"
    );
    assert!(
        !store.delete("eng-del", "victim").unwrap(),
        "should return false when deleting already-deleted profile"
    );
    assert!(
        !store.delete("eng-del", "never-existed").unwrap(),
        "should return false for non-existent profile"
    );
}

// ---------------------------------------------------------------------------
// Engagement isolation
// ---------------------------------------------------------------------------

#[test]
fn two_engagements_isolated() {
    let (_dir, store) = make_store();

    store.put("eng-A", profile("attacker", "secret-A")).unwrap();
    store.put("eng-B", profile("attacker", "secret-B")).unwrap();

    let a = store.get("eng-A", "attacker").unwrap();
    let b = store.get("eng-B", "attacker").unwrap();

    assert_eq!(a.headers[0].value, "Bearer secret-A");
    assert_eq!(b.headers[0].value, "Bearer secret-B");

    // Deleting from A must not affect B.
    store.delete("eng-A", "attacker").unwrap();
    let still_b = store.get("eng-B", "attacker").unwrap();
    assert_eq!(still_b.headers[0].value, "Bearer secret-B");

    // Writing new profile to A must not appear in B.
    store.put("eng-A", profile("admin", "admin-tok")).unwrap();
    let b_list = store.list("eng-B").unwrap();
    assert!(
        b_list.iter().all(|p| p.name != "admin"),
        "eng-A profile must not leak into eng-B"
    );
}

// ---------------------------------------------------------------------------
// is_expired
// ---------------------------------------------------------------------------

#[test]
fn is_expired_compares_against_now() {
    let p_no_exp = profile("attacker", "tok");
    assert!(!p_no_exp.is_expired(u64::MAX), "no expiry → never expired");

    let mut p_with_exp = profile("attacker", "tok");
    p_with_exp.expires_at_unix = Some(1_000);
    assert!(p_with_exp.is_expired(1_000), "at boundary → expired");
    assert!(p_with_exp.is_expired(2_000), "past expiry → expired");
    assert!(!p_with_exp.is_expired(999), "before expiry → not expired");
}

// ---------------------------------------------------------------------------
// secret_fingerprint
// ---------------------------------------------------------------------------

#[test]
fn secret_fingerprint_is_deterministic() {
    let p = profile("attacker", "same-token");
    let fp1 = p.secret_fingerprint();
    let fp2 = p.secret_fingerprint();
    assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    assert!(!fp1.is_empty());
}

#[test]
fn secret_fingerprint_differs_for_different_secrets() {
    let p1 = profile("attacker", "token-one");
    let p2 = profile("attacker", "token-two");
    assert_ne!(
        p1.secret_fingerprint(),
        p2.secret_fingerprint(),
        "different secrets must produce different fingerprints"
    );
}

// ---------------------------------------------------------------------------
// On-disk JSON contains full secrets (for replay), not redacted values
// ---------------------------------------------------------------------------

#[test]
fn on_disk_json_contains_secrets_not_redacted() {
    let (dir, store) = make_store();
    store
        .put("eng-disk", profile("attacker", "plain-secret"))
        .unwrap();

    // Read the raw JSON from disk.
    let json_path = dir
        .path()
        .join("engagements")
        .join("eng-disk")
        .join("auth.json");
    let raw = std::fs::read_to_string(&json_path).expect("auth.json must exist");

    // The persisted JSON must contain the actual secret for replay.
    assert!(
        raw.contains("plain-secret"),
        "on-disk JSON must contain the raw secret for replay; got:\n{raw}"
    );
    // But it must NOT contain any "REDACTED" string (which would indicate
    // the Debug impl was accidentally used for serialisation).
    assert!(
        !raw.contains("REDACTED"),
        "on-disk JSON must not contain 'REDACTED' string"
    );
}

// ---------------------------------------------------------------------------
// AuthProfile Debug redacts values
// ---------------------------------------------------------------------------

#[test]
fn auth_profile_debug_redacts_values() {
    let p = profile("attacker", "my-super-secret");
    let debug = format!("{p:?}");

    // Names must appear in Debug output.
    assert!(
        debug.contains("Authorization"),
        "header name must appear in Debug"
    );
    assert!(
        debug.contains("session"),
        "cookie name must appear in Debug"
    );

    // Raw values must NOT appear.
    assert!(
        !debug.contains("my-super-secret"),
        "raw secret value must not appear in AuthProfile Debug; got:\n{debug}"
    );
    assert!(
        !debug.contains("Bearer my-super-secret"),
        "raw Authorization header value must not appear in Debug"
    );
}
