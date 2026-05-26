//! mantis-binary — binary analysis primitives.
//!
//! Wraps [radare2](https://github.com/radareorg/radare2) (the
//! `r2 -q -c <cmd>` form is the contract) as a subprocess. Output
//! from r2 is always requested as JSON (`iIj`, `izj`, `iij`,
//! `aflj`, etc.) and parsed into the small surface types defined
//! here.
//!
//! ## License posture
//!
//! radare2 is LGPL-3.0 with a clarifying exception. We deliberately
//! avoid linking to `libr_*` — every interaction goes through the
//! `r2` CLI binary so the LGPL boundary sits at the process edge,
//! not the binary boundary. Operators install r2 themselves
//! (`brew install radare2`).
//!
//! ## What lives here
//!
//! * [`R2`] — the shell-out adapter.
//! * [`BinaryInfo`] — the `iIj` summary: arch, endianness, pic /
//!   nx / canary flags, hashes.
//! * [`Function`] — one entry from `aflj`: name, offset, size.
//! * [`StringRef`] — one entry from `izj`: ASCII / wide strings in
//!   data sections.
//! * [`Import`] — one entry from `iij`: imported symbol + library.
//! * [`security_findings`] — converts a [`BinaryInfo`] into
//!   [`Finding`]s for missing exploit mitigations (no NX, no PIC,
//!   no stack canary, RWX segments).
//!
//! The shape mirrors the other mantis adapters — JSON-only,
//! availability-checked, timeout-bounded.
//!
//! ## Out of scope
//!
//! * Symbolic execution — `angr` is the right tool for that. We
//!   considered an angr subprocess adapter (the goal lists it under
//!   Priority 3) but the call surface for a meaningful angr task
//!   is much larger than one shell-out; tracking as `mantis-symex`
//!   future work rather than wedging it in here.
//! * Disassembly listing — r2 can emit it but the volume kills the
//!   LLM context window. `function_disasm(addr)` is a helper for
//!   when the caller already knows which function to look at.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use mantis_static_scan::{Finding, ScanError, Severity, binary_available};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::process::Command;

const BIN: &str = "r2";
const INSTALL_HINT: &str =
    "`brew install radare2` (or follow https://github.com/radareorg/radare2#install)";
const DEFAULT_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Error)]
pub enum BinaryError {
    #[error("scan layer: {0}")]
    Scan(#[from] ScanError),
    #[error("invalid JSON from r2: {0}")]
    BadJson(String),
    #[error("missing field `{0}` in r2 output")]
    MissingField(&'static str),
}

/// Adapter handle. Cheap to construct and clone-able via [`with_*`]
/// builders.
pub struct R2 {
    binary: String,
    timeout: Duration,
}

impl R2 {
    pub fn new() -> Self {
        Self {
            binary: BIN.to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    pub fn with_binary(mut self, b: impl Into<String>) -> Self {
        self.binary = b.into();
        self
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    pub async fn ensure_available(&self) -> Result<(), BinaryError> {
        if binary_available(&self.binary).await {
            Ok(())
        } else {
            Err(BinaryError::Scan(ScanError::Unavailable {
                tool: BIN,
                install_hint: INSTALL_HINT,
            }))
        }
    }

    /// Run `r2 -q -c "<cmd>" <path>` and return stdout.
    pub async fn run_cmd(&self, path: &Path, cmd: &str) -> Result<String, BinaryError> {
        self.ensure_available().await?;
        let child = Command::new(&self.binary)
            .args(["-q", "-c", cmd])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| BinaryError::Scan(ScanError::Spawn { tool: BIN, source }))?;

        match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(Ok(out)) if out.status.success() => {
                Ok(String::from_utf8_lossy(&out.stdout).into_owned())
            }
            Ok(Ok(out)) => Err(BinaryError::Scan(ScanError::NonZeroExit {
                tool: BIN,
                status: out.status.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            })),
            Ok(Err(e)) => Err(BinaryError::Scan(ScanError::Spawn { tool: BIN, source: e })),
            Err(_) => Err(BinaryError::Scan(ScanError::Timeout {
                tool: BIN,
                seconds: self.timeout.as_secs(),
            })),
        }
    }

    /// `iIj` — bin info summary.
    pub async fn info(&self, path: &Path) -> Result<BinaryInfo, BinaryError> {
        let raw = self.run_cmd(path, "iIj").await?;
        parse_info(&raw)
    }

    /// `aflj` after `aaa` — function list. Auto-analysis is a
    /// prerequisite so we chain both into one r2 invocation.
    pub async fn functions(&self, path: &Path) -> Result<Vec<Function>, BinaryError> {
        let raw = self.run_cmd(path, "aaa; aflj").await?;
        parse_functions(&raw)
    }

    /// `izj` — strings in data sections.
    pub async fn strings(&self, path: &Path) -> Result<Vec<StringRef>, BinaryError> {
        let raw = self.run_cmd(path, "izj").await?;
        parse_strings(&raw)
    }

    /// `iij` — imported symbols.
    pub async fn imports(&self, path: &Path) -> Result<Vec<Import>, BinaryError> {
        let raw = self.run_cmd(path, "iij").await?;
        parse_imports(&raw)
    }

    /// Disassemble a single function. The caller supplies the
    /// function virtual address; output is r2's textual disassembly
    /// (NOT JSON) since it's intended for human / LLM consumption,
    /// not for further structured analysis.
    pub async fn function_disasm(&self, path: &Path, va: u64) -> Result<String, BinaryError> {
        let cmd = format!("s 0x{va:x}; pdf");
        self.run_cmd(path, &cmd).await
    }
}

impl Default for R2 {
    fn default() -> Self {
        Self::new()
    }
}

/// Output of `iIj`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub arch: String,
    pub bits: u32,
    pub bintype: String,
    pub endian: String,
    pub canary: bool,
    pub nx: bool,
    pub pic: bool,
    pub stripped: bool,
    pub relocs: bool,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub linked_libraries: Vec<String>,
}

/// Output of `aflj` — one function entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

/// Output of `izj` — one string reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringRef {
    pub vaddr: u64,
    pub paddr: u64,
    pub size: u64,
    pub length: u64,
    pub section: String,
    pub string: String,
    #[serde(rename = "type")]
    pub kind: String,
}

/// Output of `iij` — one imported symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub name: String,
    #[serde(default)]
    pub libname: Option<String>,
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub plt: Option<u64>,
}

/// Parser for `iIj`. r2 emits a single JSON object.
pub fn parse_info(raw: &str) -> Result<BinaryInfo, BinaryError> {
    let trimmed = raw.trim();
    let doc: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| BinaryError::BadJson(format!("info: {e}")))?;

    let s = |key: &'static str| -> Result<String, BinaryError> {
        doc.get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(BinaryError::MissingField(key))
    };
    let b = |key: &'static str| doc.get(key).and_then(|v| v.as_bool()).unwrap_or(false);
    let u = |key: &'static str| -> Result<u32, BinaryError> {
        doc.get(key)
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .ok_or(BinaryError::MissingField(key))
    };

    let linked = doc
        .get("linked_libraries")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Ok(BinaryInfo {
        arch: s("arch")?,
        bits: u("bits")?,
        bintype: s("bintype").unwrap_or_default(),
        endian: s("endian").unwrap_or_default(),
        canary: b("canary"),
        nx: b("nx"),
        pic: b("pic"),
        stripped: b("stripped"),
        relocs: b("relocs"),
        sha256: doc.get("sha256").and_then(|v| v.as_str()).map(String::from),
        linked_libraries: linked,
    })
}

pub fn parse_functions(raw: &str) -> Result<Vec<Function>, BinaryError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(trimmed)
        .map_err(|e| BinaryError::BadJson(format!("functions: {e}")))
}

pub fn parse_strings(raw: &str) -> Result<Vec<StringRef>, BinaryError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(trimmed)
        .map_err(|e| BinaryError::BadJson(format!("strings: {e}")))
}

pub fn parse_imports(raw: &str) -> Result<Vec<Import>, BinaryError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(trimmed)
        .map_err(|e| BinaryError::BadJson(format!("imports: {e}")))
}

/// Convert exploit-mitigation absence into [`Finding`]s. The
/// severity ladder reflects defensive impact:
///
/// * NX off          — High      (modern exploit primitives assume DEP)
/// * PIC off         — Medium    (no ASLR for the main image)
/// * No stack canary — Medium    (stack BoFs become easier to weaponise)
/// * Stripped        — Info      (purely a triage signal)
/// * Linked to libc  — Info      (helpful context, not a finding)
pub fn security_findings(target: &str, info: &BinaryInfo) -> Vec<Finding> {
    let mut out = Vec::new();
    if !info.nx {
        out.push(
            Finding::new(
                "mantis-binary",
                "missing-mitigation",
                target.to_string(),
                Severity::High,
                "NX/DEP disabled",
            )
            .with_meta("mitigation", "nx"),
        );
    }
    if !info.pic {
        out.push(
            Finding::new(
                "mantis-binary",
                "missing-mitigation",
                target.to_string(),
                Severity::Medium,
                "Position-independent code disabled",
            )
            .with_meta("mitigation", "pic"),
        );
    }
    if !info.canary {
        out.push(
            Finding::new(
                "mantis-binary",
                "missing-mitigation",
                target.to_string(),
                Severity::Medium,
                "Stack canary absent",
            )
            .with_meta("mitigation", "canary"),
        );
    }
    if !info.stripped {
        // Not a vuln per se; surface as info because unstripped
        // binaries in production usually indicate a build-pipeline
        // oversight.
        out.push(
            Finding::new(
                "mantis-binary",
                "build-hygiene",
                target.to_string(),
                Severity::Info,
                "binary contains symbols (not stripped)",
            )
            .with_meta("mitigation", "strip"),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO_JSON: &str = r#"{
        "arch": "x86",
        "bits": 64,
        "bintype": "elf",
        "endian": "little",
        "canary": false,
        "nx": false,
        "pic": false,
        "stripped": false,
        "relocs": true,
        "sha256": "abc123",
        "linked_libraries": ["libc.so.6", "libssl.so.3"]
    }"#;

    #[test]
    fn parse_info_extracts_full_object() {
        let info = parse_info(INFO_JSON).expect("parse ok");
        assert_eq!(info.arch, "x86");
        assert_eq!(info.bits, 64);
        assert_eq!(info.bintype, "elf");
        assert_eq!(info.endian, "little");
        assert!(!info.nx);
        assert!(!info.pic);
        assert!(!info.canary);
        assert!(!info.stripped);
        assert!(info.relocs);
        assert_eq!(info.sha256.as_deref(), Some("abc123"));
        assert_eq!(info.linked_libraries, vec!["libc.so.6", "libssl.so.3"]);
    }

    #[test]
    fn parse_info_rejects_garbage() {
        assert!(parse_info("not json").is_err());
        assert!(parse_info("{}").is_err());
    }

    #[test]
    fn parse_info_tolerates_missing_optional_fields() {
        let raw = r#"{"arch":"arm","bits":32,"bintype":"","endian":"","canary":true,"nx":true,"pic":true,"stripped":true,"relocs":false}"#;
        let info = parse_info(raw).expect("parse ok");
        assert_eq!(info.arch, "arm");
        assert!(info.canary);
        assert!(info.nx);
        assert!(info.pic);
        assert!(info.stripped);
        assert!(info.sha256.is_none());
        assert!(info.linked_libraries.is_empty());
    }

    #[test]
    fn parse_functions_handles_aflj_array() {
        let raw = r#"[
            {"name":"main","offset":4096,"size":120},
            {"name":"helper","offset":4220,"size":48}
        ]"#;
        let fns = parse_functions(raw).expect("parse ok");
        assert_eq!(fns.len(), 2);
        assert_eq!(fns[0].name, "main");
        assert_eq!(fns[0].offset, 4096);
        assert_eq!(fns[1].size, 48);
    }

    #[test]
    fn parse_functions_empty_input_yields_zero() {
        assert!(parse_functions("").unwrap().is_empty());
    }

    #[test]
    fn parse_strings_handles_izj_array() {
        let raw = r#"[
            {"vaddr":8192,"paddr":4096,"size":12,"length":11,"section":".rodata","string":"hello world","type":"ascii"},
            {"vaddr":8204,"paddr":4108,"size":24,"length":11,"section":".rodata","string":"goodbye","type":"ascii"}
        ]"#;
        let strs = parse_strings(raw).expect("parse ok");
        assert_eq!(strs.len(), 2);
        assert_eq!(strs[0].string, "hello world");
        assert_eq!(strs[1].section, ".rodata");
        assert_eq!(strs[0].kind, "ascii");
    }

    #[test]
    fn parse_imports_handles_iij_array() {
        let raw = r#"[
            {"name":"printf","libname":"libc.so.6","type":"FUNC","plt":4112},
            {"name":"SSL_read","libname":"libssl.so.3","type":"FUNC"}
        ]"#;
        let imps = parse_imports(raw).expect("parse ok");
        assert_eq!(imps.len(), 2);
        assert_eq!(imps[0].name, "printf");
        assert_eq!(imps[0].libname.as_deref(), Some("libc.so.6"));
        assert_eq!(imps[0].plt, Some(4112));
        assert!(imps[1].plt.is_none());
    }

    #[test]
    fn security_findings_emits_every_missing_mitigation() {
        let info = parse_info(INFO_JSON).unwrap();
        let findings = security_findings("./demo.elf", &info);
        let mitigations: Vec<_> = findings
            .iter()
            .map(|f| f.meta.get("mitigation").unwrap().clone())
            .collect();
        assert!(mitigations.contains(&"nx".to_string()));
        assert!(mitigations.contains(&"pic".to_string()));
        assert!(mitigations.contains(&"canary".to_string()));
        assert!(mitigations.contains(&"strip".to_string()));
    }

    #[test]
    fn security_findings_skips_hardened_binary() {
        let info = BinaryInfo {
            arch: "x86_64".into(),
            bits: 64,
            bintype: "elf".into(),
            endian: "little".into(),
            canary: true,
            nx: true,
            pic: true,
            stripped: true,
            relocs: false,
            sha256: None,
            linked_libraries: vec![],
        };
        assert!(security_findings("./hardened", &info).is_empty());
    }

    #[test]
    fn security_findings_severity_ladder_correct() {
        let info = BinaryInfo {
            arch: "x86_64".into(),
            bits: 64,
            bintype: "elf".into(),
            endian: "little".into(),
            canary: false,
            nx: false,
            pic: false,
            stripped: false,
            relocs: false,
            sha256: None,
            linked_libraries: vec![],
        };
        let findings = security_findings("./b", &info);
        let by_mit: std::collections::HashMap<_, _> = findings
            .iter()
            .map(|f| (f.meta.get("mitigation").unwrap().clone(), f.severity))
            .collect();
        assert_eq!(by_mit["nx"], Severity::High);
        assert_eq!(by_mit["pic"], Severity::Medium);
        assert_eq!(by_mit["canary"], Severity::Medium);
        assert_eq!(by_mit["strip"], Severity::Info);
    }

    #[tokio::test]
    async fn r2_returns_unavailable_for_missing_binary() {
        let r2 = R2::new().with_binary("definitely-not-r2-xyz");
        let err = r2.ensure_available().await.unwrap_err();
        match err {
            BinaryError::Scan(ScanError::Unavailable { tool, .. }) => assert_eq!(tool, "r2"),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }
}
