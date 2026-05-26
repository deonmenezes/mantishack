# Hash independence audit

## Why this exists

The independence transition (tracked in
[`TRANSITION_AUDIT.md`](./TRANSITION_AUDIT.md)) requires that no algorithm,
naming scheme, or execution-flow primitive in Mantis is derivative of
Hacker Bob. This document audits every 256-bit hash usage in the
codebase and either confirms its independence or proposes a Mantis-native
replacement.

## Audit summary

| Usage | Algorithm | Where | Status |
|---|---|---|---|
| Merkle event-log leaves | BLAKE3 | `mantis-chain` (extensive) | **Independent** — Mantis-native choice. Hacker Bob (Node.js) uses built-in `crypto` / SHA-256 for analogous purposes. |
| Engagement state hashing | BLAKE3 | `mantis-event-store`, `mantis-fsm` | **Independent** — same as above. |
| Request-shape stable hash (for `mantis_hash_request` tool) | BLAKE3 | `mantis-mcp/src/utility_tools.rs` | **Independent** — Mantis-native; algorithm computes a deterministic hash over `(method, path, sorted-headers, body-hash)`. |
| OCI manifest digest (registry compat) | SHA-256 | `mantis-registry/src/oci_client.rs` | **Compat-only** — SHA-256 is the OCI standard. Mantis accepts both `sha256:` and `blake3:` digest prefixes; BLAKE3 is the Mantis-native side. Not derivative — required by the OCI spec, not borrowed from Hacker Bob. |
| Binary release checksum field | SHA-256 | `mantis-binary/src/lib.rs` | **Compat-only** — SHA-256 is the de-facto release-artifact checksum standard. Field exposed for external integrations (Homebrew, distros, package managers). Not derivative. |
| Secret-shape recognizer (regex matching SHA-256-formatted strings in incoming data) | SHA-256 (recognition only) | `mantis-secrets/src/entropy.rs` | **Compat-only** — this is a regex for identifying 64-hex-character strings that *look like* SHA-256 hashes in scanned blobs (so the secrets-scanner can avoid false-positive-flagging them as credentials). Not Mantis's own hash. |
| Findings-index feature vector | (not implemented in Mantis Rust) | Referenced in `docs/capability-hypergraph.md` only | **Not implemented** — the 256-slot feature vector described in the capability-hypergraph log entry is a Hacker Bob design (`mcp/lib/findings-index.js`). The corresponding `mantis_index_finding` / `mantis_query_findings_index` MCP tools in `mantis-mcp/src/server.rs` delegate to the daemon; no Mantis Rust code currently implements the 256-slot feature-hash scheme. If/when this is implemented, it must use the Mantis-native scheme below — NOT a port of the Hacker Bob algorithm. |

**Conclusion of audit:** every 256-bit hash in Mantis is either:

1. BLAKE3 (Mantis-native, not Hacker Bob's hash), or
2. SHA-256 used only for compat with industry standards (OCI, distro
   checksums) or for recognizing incoming-data patterns.

No hash usage is derivative of Hacker Bob's hashing approach.

## Proposed: Mantis-native domain separation for BLAKE3

Even though BLAKE3 isn't Hacker Bob's algorithm, two projects that both
use BLAKE3 in similar contexts could produce identical hash outputs for
identical inputs. To eliminate even that incidental overlap, every
BLAKE3 hash in Mantis should pass through a Mantis-specific domain-
separation prefix:

```rust
//! crates/mantis-core/src/hash.rs
//!
//! Mantis-native hashing wrapper. Every BLAKE3 hash in the codebase goes
//! through this module so the output carries a Mantis-specific domain
//! prefix that no other project will accidentally collide with.

/// Mantis hash domain version. Bump when the prefix changes.
pub const MANTIS_HASH_DOMAIN: &str = "MANTIS-v1";

/// Compute a domain-separated BLAKE3 hash. The domain string is mixed
/// into the hash before the data, so identical data hashed under
/// different domains produces different outputs.
pub fn mantis_hash(domain: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANTIS_HASH_DOMAIN.as_bytes());
    hasher.update(b":");
    hasher.update(domain.as_bytes());
    hasher.update(b":");
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Convenience: BLAKE3 hex output of `mantis_hash`.
pub fn mantis_hash_hex(domain: &str, data: &[u8]) -> String {
    hex::encode(mantis_hash(domain, data))
}
```

Domain strings used across the codebase (to be added as `pub const`
values in the same module):

```rust
pub const DOMAIN_EVIDENCE: &str = "evidence";
pub const DOMAIN_MERKLE_LEAF: &str = "merkle.leaf";
pub const DOMAIN_REQUEST_SHAPE: &str = "request.shape";
pub const DOMAIN_REPRODUCER: &str = "reproducer";
pub const DOMAIN_CLAIM_BODY: &str = "claim.body";
pub const DOMAIN_SCOPE_MANIFEST: &str = "scope.manifest";
pub const DOMAIN_EVENT_PAYLOAD: &str = "event.payload";
```

This is a small wrapper change that:

1. Makes Mantis's hash outputs distinct from any other BLAKE3-using
   project's outputs for the same input.
2. Provides a single point to audit hash usage going forward.
3. Self-documents what each hash invocation is for (via the domain
   string).
4. Allows future hash-algorithm migration (e.g., to SHA3-256 or
   BLAKE3-keyed) with one module-level change instead of touching
   every call site.

## Migration plan

The migration to domain-separated hashing lands in three phases:

### Phase H1 — add the wrapper module (this proposal + a small PR)

Add `crates/mantis-core/src/hash.rs` (or a new `crates/mantis-hash`
crate, depending on dependency direction) with `mantis_hash`,
`mantis_hash_hex`, and the domain constants. Add unit tests confirming
the domain separator changes the output. No call sites updated.

### Phase H2 — migrate call sites one crate at a time

For each existing `blake3::hash(data)` call site:

1. Identify which domain it belongs to.
2. Replace with `mantis_hash(DOMAIN_X, data)`.
3. If the hash is persisted (in the event log, in a claim, in a
   reproducer), the change is observable downstream — coordinate with
   the merkle-log replay code so historical engagements still verify.
4. Update tests against the new domain-separated values.

This is breaking for any operator with historical engagement data.
Schedule for a major-version bump and document the migration in
`CHANGELOG.md`.

### Phase H3 — enforce via clippy lint

Add a workspace clippy `disallowed_methods` lint that forbids direct
`blake3::hash` / `blake3::Hasher::new` usage outside the wrapper
module. Every BLAKE3 call site in the codebase is forced to go
through `mantis_hash`. Lint failures block CI.

## What this does NOT change

- The OCI manifest digest is SHA-256 because the OCI spec requires it.
  No change here.
- The binary release checksum stays SHA-256 because distros and
  Homebrew expect it.
- The secrets-scanner regex recognizing SHA-256-formatted strings in
  incoming data is unchanged — that's pattern matching, not hashing.

## Faithful acknowledgement

Hash independence isn't a license obligation under Apache-2.0 §4 (the
license doesn't address algorithm choice). It's a hardening step
beyond the formal §4 requirements, motivated by the goal stated in
the [Transition audit](./TRANSITION_AUDIT.md): *make sure the faithful
transition doesn't copy any line of code, keeps everything original
even the architecture and names of execution.*

This audit confirms hash *algorithm* choice is already independent
(BLAKE3 vs Hacker Bob's SHA-256-via-Node-crypto). The domain-
separation proposal hardens that further by ensuring hash *outputs*
are distinct even when both projects hash equivalent data.

Hacker Bob is not affected by any change proposed here. The
acknowledgement in `NOTICE` remains as architectural-inspiration
credit; nothing about how Mantis hashes is borrowed from Hacker Bob,
and the domain-separation step makes that operationally observable.
