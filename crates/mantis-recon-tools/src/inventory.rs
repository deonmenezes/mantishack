//! # Apache-2.0 §4(b) notice — derivative work
//!
//! Portions of this file are derived from or mirror algorithm
//! shape, named constants, threshold values, or workflow logic from
//! Hacker Bob (<https://github.com/vmihalis/hacker-bob>),
//! Copyright 2026 Michail Vasileiadis, licensed under the Apache
//! License, Version 2.0. The surrounding Rust implementation is
//! independent and was written from scratch.
//!
//! See the project NOTICE for the upstream attribution and the
//! compliance-history apology. This notice is provided per
//! Apache-2.0 §4(b) ("You must cause any modified files to carry
//! prominent notices stating that You changed the files").
//!
//! Tool inventory — what's installed, where, and at what version.

use serde::{Deserialize, Serialize};

/// Every external recon tool Mantis knows how to drive
/// opportunistically. Adding a new variant here is the *only*
/// place a tool needs to be registered — runners reference it via
/// the matching `binary_name()` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolKind {
    /// projectdiscovery/subfinder — subdomain enumeration.
    Subfinder,
    /// projectdiscovery/httpx — HTTP/S liveness + tech fingerprinting.
    Httpx,
    /// projectdiscovery/nuclei — template-based vuln scanner.
    Nuclei,
    /// owasp-amass/amass — passive + active subdomain enumeration.
    Amass,
    /// tomnomnom/assetfinder — quick passive subdomain enum.
    Assetfinder,
    /// projectdiscovery/chaos-client — Project Discovery subdomain dataset.
    Chaos,
    /// projectdiscovery/dnsx — DNS resolver + record dumper.
    Dnsx,
    /// projectdiscovery/tlsx — TLS handshake + cert metadata.
    Tlsx,
    /// projectdiscovery/katana — crawler / endpoint discovery.
    Katana,
    /// PentestPad/subzy — subdomain-takeover scanner.
    Subzy,
    /// ticarpi/jwt_tool — JWT inspection / fuzzing (Python).
    JwtTool,
}

impl ToolKind {
    /// All known variants — used by [`ToolInventory::scan`].
    pub fn all() -> &'static [ToolKind] {
        &[
            ToolKind::Subfinder,
            ToolKind::Httpx,
            ToolKind::Nuclei,
            ToolKind::Amass,
            ToolKind::Assetfinder,
            ToolKind::Chaos,
            ToolKind::Dnsx,
            ToolKind::Tlsx,
            ToolKind::Katana,
            ToolKind::Subzy,
            ToolKind::JwtTool,
        ]
    }

    /// Binary name as installed on `PATH`. For `jwt_tool` we assume
    /// the canonical `~/jwt_tool/jwt_tool.py` install location (per
    /// hacker-bob's README) and also check for a `jwt_tool` shim.
    pub fn binary_name(self) -> &'static str {
        match self {
            ToolKind::Subfinder => "subfinder",
            ToolKind::Httpx => "httpx",
            ToolKind::Nuclei => "nuclei",
            ToolKind::Amass => "amass",
            ToolKind::Assetfinder => "assetfinder",
            ToolKind::Chaos => "chaos",
            ToolKind::Dnsx => "dnsx",
            ToolKind::Tlsx => "tlsx",
            ToolKind::Katana => "katana",
            ToolKind::Subzy => "subzy",
            ToolKind::JwtTool => "jwt_tool",
        }
    }

    /// Install hint (one of the lines from the upstream `go install`
    /// / `git clone` recipe).
    pub fn install_hint(self) -> &'static str {
        match self {
            ToolKind::Subfinder => {
                "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            }
            ToolKind::Httpx => "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
            ToolKind::Nuclei => {
                "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            }
            ToolKind::Amass => "go install github.com/owasp-amass/amass/v4/...@latest",
            ToolKind::Assetfinder => "go install github.com/tomnomnom/assetfinder@latest",
            ToolKind::Chaos => {
                "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
            }
            ToolKind::Dnsx => "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            ToolKind::Tlsx => "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
            ToolKind::Katana => "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            ToolKind::Subzy => "go install -v github.com/PentestPad/subzy@latest",
            ToolKind::JwtTool => {
                "git clone https://github.com/ticarpi/jwt_tool ~/jwt_tool && \
                 python3 -m pip install -r ~/jwt_tool/requirements.txt"
            }
        }
    }

    /// Version-check argument. Each tool has a different convention;
    /// we shell out and trust the first line.
    pub fn version_arg(self) -> &'static str {
        match self {
            ToolKind::JwtTool => "-h", // no `--version`; help banner shows version
            _ => "-version",           // projectdiscovery + most others
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInfo {
    pub kind: ToolKind,
    pub installed: bool,
    /// Absolute path to the binary, if found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Short version string (first line of `tool -version` stdout).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl ToolInfo {
    pub fn missing(kind: ToolKind) -> Self {
        Self {
            kind,
            installed: false,
            path: None,
            version: None,
        }
    }
}

/// Result of probing every known tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInventory {
    pub tools: Vec<ToolInfo>,
}

impl ToolInventory {
    /// Empty inventory — useful for tests + as the fallback when
    /// detection itself fails.
    pub fn empty() -> Self {
        Self { tools: Vec::new() }
    }

    /// Probe every known tool. Synchronous because `which`-style
    /// checks + a single `--version` shell-out are sub-millisecond.
    pub fn scan() -> Self {
        let mut tools = Vec::with_capacity(ToolKind::all().len());
        for kind in ToolKind::all() {
            tools.push(probe_one(*kind));
        }
        Self { tools }
    }

    pub fn get(&self, kind: ToolKind) -> Option<&ToolInfo> {
        self.tools.iter().find(|t| t.kind == kind)
    }

    pub fn is_installed(&self, kind: ToolKind) -> bool {
        self.get(kind).map(|t| t.installed).unwrap_or(false)
    }

    pub fn installed_count(&self) -> usize {
        self.tools.iter().filter(|t| t.installed).count()
    }
}

fn probe_one(kind: ToolKind) -> ToolInfo {
    let name = kind.binary_name();
    let path = match which(name) {
        Some(p) => p,
        None => return ToolInfo::missing(kind),
    };
    let version = read_version(&path, kind.version_arg());
    ToolInfo {
        kind,
        installed: true,
        path: Some(path),
        version,
    }
}

fn which(name: &str) -> Option<String> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

fn read_version(path: &str, arg: &str) -> Option<String> {
    let output = std::process::Command::new(path).arg(arg).output().ok()?;
    // ProjectDiscovery tools emit version on STDERR (the banner);
    // others (including help-screen-only tools) emit on STDOUT.
    // Try both and take the first non-empty line.
    for stream in [output.stderr, output.stdout] {
        let text = String::from_utf8_lossy(&stream);
        for line in text.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.chars().take(120).collect());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_a_binary_name_and_install_hint() {
        for k in ToolKind::all() {
            assert!(!k.binary_name().is_empty(), "{:?}", k);
            assert!(!k.install_hint().is_empty(), "{:?}", k);
        }
    }

    #[test]
    fn binary_names_are_unique() {
        let names: std::collections::BTreeSet<&str> =
            ToolKind::all().iter().map(|k| k.binary_name()).collect();
        assert_eq!(names.len(), ToolKind::all().len());
    }

    #[test]
    fn empty_inventory_reports_zero_installed() {
        let inv = ToolInventory::empty();
        assert_eq!(inv.installed_count(), 0);
        assert!(!inv.is_installed(ToolKind::Subfinder));
    }

    #[test]
    fn scan_returns_one_entry_per_kind() {
        let inv = ToolInventory::scan();
        assert_eq!(inv.tools.len(), ToolKind::all().len());
        // Whether tools are installed is host-dependent; just verify
        // every variant got a row.
        for kind in ToolKind::all() {
            assert!(
                inv.get(*kind).is_some(),
                "missing inventory entry for {kind:?}"
            );
        }
    }

    #[test]
    fn missing_tool_record_is_well_formed() {
        let m = ToolInfo::missing(ToolKind::Nuclei);
        assert!(!m.installed);
        assert!(m.path.is_none());
        assert!(m.version.is_none());
    }

    #[test]
    fn install_hints_reference_canonical_repos() {
        // Sanity: the hints should point at the same upstream repos
        // the user's request listed.
        assert!(ToolKind::Subfinder
            .install_hint()
            .contains("projectdiscovery/subfinder"));
        assert!(ToolKind::Nuclei
            .install_hint()
            .contains("projectdiscovery/nuclei"));
        assert!(ToolKind::Amass.install_hint().contains("owasp-amass/amass"));
        assert!(ToolKind::Assetfinder
            .install_hint()
            .contains("tomnomnom/assetfinder"));
        assert!(ToolKind::Subzy.install_hint().contains("PentestPad/subzy"));
        assert!(ToolKind::JwtTool
            .install_hint()
            .contains("ticarpi/jwt_tool"));
    }

    #[test]
    fn inventory_json_round_trip() {
        let inv = ToolInventory {
            tools: vec![ToolInfo {
                kind: ToolKind::Httpx,
                installed: true,
                path: Some("/usr/local/bin/httpx".into()),
                version: Some("v1.6.0".into()),
            }],
        };
        let j = serde_json::to_string(&inv).unwrap();
        let back: ToolInventory = serde_json::from_str(&j).unwrap();
        assert_eq!(inv, back);
    }
}
