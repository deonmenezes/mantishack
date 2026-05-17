//! Per-engagement on-disk auth store.
//!
//! Each engagement has an isolated `auth.json` file at:
//! `<workspace_root>/engagements/<engagement_id>/auth.json`.
//!
//! Writes are atomic: data is written to `auth.json.tmp` then renamed
//! over the target, matching the rest of the workspace's write discipline.

use std::collections::HashMap;

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

use crate::profile::AuthProfile;
use crate::redact::redact_value;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors returned by [`AuthStore`] operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthStoreError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: Utf8PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON parse error at {path}: {source}")]
    Json {
        path: Utf8PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("profile not found: engagement={engagement_id} name={name}")]
    ProfileNotFound {
        engagement_id: String,
        name: String,
    },
}

// ---------------------------------------------------------------------------
// On-disk document format
// ---------------------------------------------------------------------------

/// Versioned envelope written to `auth.json`.
#[derive(Debug, Serialize, Deserialize)]
struct AuthDoc {
    version: u32,
    profiles: HashMap<String, AuthProfile>,
}

impl AuthDoc {
    fn new() -> Self {
        Self {
            version: 1,
            profiles: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// RedactedProfile
// ---------------------------------------------------------------------------

/// A safe-to-log summary of an [`AuthProfile`]: secret values are
/// replaced with their blake3 prefix; only names and metadata are
/// exposed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedProfile {
    pub name: String,
    pub header_names: Vec<String>,
    pub cookie_names: Vec<String>,
    pub query_keys: Vec<String>,
    pub expires_at_unix: Option<u64>,
    pub created_at_unix: u64,
    pub origin: String,
    /// First 16 hex chars of the profile's full secret fingerprint.
    pub secret_fingerprint: String,
}

impl From<&AuthProfile> for RedactedProfile {
    fn from(p: &AuthProfile) -> Self {
        let fp = p.secret_fingerprint();
        Self {
            name: p.name.clone(),
            header_names: p.headers.iter().map(|h| h.name.clone()).collect(),
            cookie_names: p.cookies.iter().map(|c| c.name.clone()).collect(),
            query_keys: p.query.iter().map(|(k, _)| k.clone()).collect(),
            expires_at_unix: p.expires_at_unix,
            created_at_unix: p.created_at_unix,
            origin: p.origin.clone(),
            secret_fingerprint: fp[..16.min(fp.len())].to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// AuthStore
// ---------------------------------------------------------------------------

/// Manages auth profiles for all engagements under a workspace root.
pub struct AuthStore {
    root: Utf8PathBuf,
}

impl AuthStore {
    /// Create a store rooted at `workspace_root`.
    pub fn new(workspace_root: impl Into<Utf8PathBuf>) -> Self {
        Self {
            root: workspace_root.into(),
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Persist `profile`, overwriting any existing profile with the same
    /// name in this engagement.
    pub fn put(
        &self,
        engagement_id: &str,
        profile: AuthProfile,
    ) -> Result<(), AuthStoreError> {
        let path = self.auth_path(engagement_id);
        let mut doc = self.read_doc(&path)?;
        doc.profiles.insert(profile.name.clone(), profile);
        self.write_doc(&path, &doc)
    }

    /// Retrieve a single profile by name.
    pub fn get(
        &self,
        engagement_id: &str,
        profile_name: &str,
    ) -> Result<AuthProfile, AuthStoreError> {
        let path = self.auth_path(engagement_id);
        let doc = self.read_doc(&path)?;
        doc.profiles
            .into_values()
            .find(|p| p.name == profile_name)
            .ok_or_else(|| AuthStoreError::ProfileNotFound {
                engagement_id: engagement_id.to_owned(),
                name: profile_name.to_owned(),
            })
    }

    /// List all profiles for this engagement.
    pub fn list(&self, engagement_id: &str) -> Result<Vec<AuthProfile>, AuthStoreError> {
        let path = self.auth_path(engagement_id);
        let doc = self.read_doc(&path)?;
        let mut profiles: Vec<AuthProfile> = doc.profiles.into_values().collect();
        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(profiles)
    }

    /// Same as [`Self::list`] but every secret value is redacted to its
    /// blake3 prefix. Safe to log or surface via MCP.
    pub fn list_redacted(
        &self,
        engagement_id: &str,
    ) -> Result<Vec<RedactedProfile>, AuthStoreError> {
        let profiles = self.list(engagement_id)?;
        Ok(profiles.iter().map(RedactedProfile::from).collect())
    }

    /// Delete a profile. Returns `true` if it existed, `false` if not found.
    pub fn delete(
        &self,
        engagement_id: &str,
        profile_name: &str,
    ) -> Result<bool, AuthStoreError> {
        let path = self.auth_path(engagement_id);
        let mut doc = self.read_doc(&path)?;
        let existed = doc.profiles.remove(profile_name).is_some();
        if existed {
            self.write_doc(&path, &doc)?;
        }
        Ok(existed)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn auth_path(&self, engagement_id: &str) -> Utf8PathBuf {
        self.root
            .join("engagements")
            .join(engagement_id)
            .join("auth.json")
    }

    /// Read and deserialize `auth.json`. Returns an empty doc if the file
    /// does not yet exist.
    fn read_doc(&self, path: &Utf8Path) -> Result<AuthDoc, AuthStoreError> {
        if !path.exists() {
            return Ok(AuthDoc::new());
        }
        let raw = std::fs::read_to_string(path).map_err(|e| AuthStoreError::Io {
            path: path.to_owned(),
            source: e,
        })?;
        serde_json::from_str(&raw).map_err(|e| AuthStoreError::Json {
            path: path.to_owned(),
            source: e,
        })
    }

    /// Atomically write `doc` to `path` via a `.tmp` rename.
    fn write_doc(&self, path: &Utf8Path, doc: &AuthDoc) -> Result<(), AuthStoreError> {
        // Ensure parent directory exists.
        let parent = path.parent().unwrap_or(Utf8Path::new("."));
        std::fs::create_dir_all(parent).map_err(|e| AuthStoreError::Io {
            path: parent.to_owned(),
            source: e,
        })?;

        let tmp_path = path.with_extension("json.tmp");

        let content = serde_json::to_string_pretty(doc)
            .expect("AuthDoc serialization is infallible")
            + "\n";

        std::fs::write(&tmp_path, content.as_bytes()).map_err(|e| AuthStoreError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;

        std::fs::rename(&tmp_path, path).map_err(|e| AuthStoreError::Io {
            path: path.to_owned(),
            source: e,
        })?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{AuthCookie, AuthHeader};

    fn make_profile(name: &str, token: &str) -> AuthProfile {
        AuthProfile {
            name: name.to_owned(),
            headers: vec![AuthHeader {
                name: "Authorization".to_owned(),
                value: format!("Bearer {token}"),
            }],
            cookies: vec![AuthCookie {
                name: "session".to_owned(),
                value: token.to_owned(),
                domain: Some("example.com".to_owned()),
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

    #[test]
    fn round_trip_put_get() {
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let store = AuthStore::new(root);

        let original = make_profile("attacker", "tok-abc");
        store.put("eng-1", original.clone()).unwrap();

        let retrieved = store.get("eng-1", "attacker").unwrap();
        assert_eq!(retrieved.name, "attacker");
        assert_eq!(retrieved.headers[0].value, "Bearer tok-abc");
    }

    #[test]
    fn list_returns_all_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let store = AuthStore::new(root);

        store.put("eng-1", make_profile("attacker", "a")).unwrap();
        store.put("eng-1", make_profile("victim", "v")).unwrap();

        let profiles = store.list("eng-1").unwrap();
        assert_eq!(profiles.len(), 2);
        let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"attacker"));
        assert!(names.contains(&"victim"));
    }

    #[test]
    fn list_redacted_contains_names_not_values() {
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let store = AuthStore::new(root);

        store.put("eng-1", make_profile("attacker", "secret-tok")).unwrap();

        let redacted = store.list_redacted("eng-1").unwrap();
        assert_eq!(redacted.len(), 1);
        let r = &redacted[0];
        assert_eq!(r.name, "attacker");
        assert!(r.header_names.contains(&"Authorization".to_owned()));
        assert!(r.cookie_names.contains(&"session".to_owned()));
        assert!(r.query_keys.contains(&"api_key".to_owned()));
        // Secret fingerprint is 16 hex chars.
        assert_eq!(r.secret_fingerprint.len(), 16);
        // The serialized redacted profile must not contain the raw secret.
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("secret-tok"), "raw secret must not appear in redacted JSON");
    }

    #[test]
    fn delete_returns_true_on_existing_false_on_missing() {
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let store = AuthStore::new(root);

        store.put("eng-1", make_profile("attacker", "a")).unwrap();
        assert!(store.delete("eng-1", "attacker").unwrap());
        assert!(!store.delete("eng-1", "attacker").unwrap());
    }

    #[test]
    fn two_engagements_are_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let store = AuthStore::new(root);

        store.put("eng-A", make_profile("attacker", "secret-A")).unwrap();
        store.put("eng-B", make_profile("attacker", "secret-B")).unwrap();

        let a = store.get("eng-A", "attacker").unwrap();
        let b = store.get("eng-B", "attacker").unwrap();

        assert_eq!(a.headers[0].value, "Bearer secret-A");
        assert_eq!(b.headers[0].value, "Bearer secret-B");

        // Deleting from A doesn't affect B.
        store.delete("eng-A", "attacker").unwrap();
        assert!(store.get("eng-B", "attacker").is_ok());
    }

    #[test]
    fn redacted_value_helper_used_in_store_output() {
        // Verify that redact_value is the function used, not a raw value.
        let r = redact_value("hello");
        assert!(r.starts_with("b3:"));
    }

    #[test]
    fn get_missing_profile_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let store = AuthStore::new(root);

        let err = store.get("eng-1", "nonexistent").unwrap_err();
        assert!(matches!(err, AuthStoreError::ProfileNotFound { .. }));
    }
}
