# Context Scaling Architecture

Mantis scales attack-surface coverage through MCP-owned routing and bounded context retrieval, not by loading every technique into every hunter prompt.

## Architecture

The core flow is:

```text
surface -> capability pack -> surface-family hunter -> on-demand technique packs -> structured finalization
```

Capability packs own surface-family routing. Each routed assignment carries the selected `capability_pack`, `hunter_agent`, `brief_profile`, `capability_pack_version`, and enforced `context_budget`. The orchestrator must spawn the returned `assignment.hunter_agent` instead of hard-coding hunter names.

Technique packs are Mantis registry records, not host-native skills by default. Hunters receive bounded summaries through `mantis_read_hunter_brief` and request full technique bodies only through `mantis_read_technique_pack`. This keeps context selection, read budgets, attempt history, and warning metadata in the MCP runtime, which preserves adapter portability across Claude, Codex, and generic MCP hosts.

## Context Budget

The current enforced assignment budget is:

```json
{
  "candidate_pack_limit": 5,
  "full_pack_read_limit": 2,
  "attempt_log_required": true
}
```

`candidate_pack_limit` caps selected technique summaries returned to a web hunter. `full_pack_read_limit` caps distinct full technique-pack reads per wave assignment. `attempt_log_required` makes hunter finalization require at least one matching `mantis_log_technique_attempt` record for that assignment.

Smart-contract hunters currently set `attempt_log_required: false` because their workflows are driven by chain-specific tools, `bob-spec.json`, and harness evidence rather than web technique packs. When smart-contract technique packs are added, the capability packs should opt into the same attempt-log contract.

## Technique Registry

The registry file is `knowledge/hunter-techniques.json` under Mantis resource roots. Registry entries should contain compact metadata, match hints, summary guidance, payload hints, capability-pack compatibility, and estimated token costs.

Registry reads are resilient. A malformed optional file or entry must not block hunter brief generation. The runtime skips invalid entries and returns bounded `registry_warnings` metadata without exposing raw technique bodies in warnings.

`technique_packs.selected` is the canonical web-hunter context. Top-level `techniques` and `payload_hints` are retained only as small legacy compatibility summaries derived from selected packs.

## Host Adapters

Host adapters install and render Mantis contracts, but they should not own routing, technique selection, budget enforcement, or session artifact mutation. Claude Code agent teams or additional workers may be useful for explicit escalation, but the default execution model remains one routed surface-family hunter per assignment.

Session artifacts for state, routes, handoffs, findings, coverage, technique reads, and technique attempts remain MCP-owned. Host hooks and guards should preserve that boundary instead of introducing adapter-specific artifact writers.

## Artifact Naming Conventions

Artifact filenames should communicate both storage shape and ownership boundary:

- `.jsonl` means append-only records. Use it for event streams, attempt logs, coverage traces, and other artifacts that accumulate entries over time.
- `.json` means a single document snapshot. Use it for the current state of a structure, a derived result bundle, or a manifest-style index.

The naming should also hint at the artifact category:

- `index` artifacts are lookup structures. They are usually single-document `.json` files when they represent the current index state, but they can be `.jsonl` when the index is emitted as a stream of records.
- `result` artifacts are derived outputs from a specific run, wave, or evaluation pass. They should read as snapshots rather than logs.
- `raw-evidence` artifacts preserve source material or minimally transformed evidence. They should stay append-only when multiple records are collected, and their names should make provenance obvious.

Current v1.3.0 examples already follow this split:

- Append-only `.jsonl`: `schema-contracts.jsonl`, `findings-index.jsonl`, `surface-graph.jsonl`, `chain-tree.jsonl`, `audit-reports.jsonl`, `invariant-runs.jsonl`
- Snapshot `.json`: `doc-delta-results.json`, `auth-differential-results.json`, `symbol-surface-index.json`

The rule of thumb is simple: if the artifact grows record by record, name it like a log. If the artifact should be replaced wholesale, name it like a snapshot.

## Evaluation Gates

Before adding a large technique registry, keep tests around:

- capability routing accuracy across mixed surfaces
- selected technique count and full-read limits
- duplicate or incompatible technique-attempt prevention
- finalization blocking when required attempt logs are missing
- prompt/rendered adapter parity
- registry warning behavior for malformed entries

The scaling goal is not more context. It is better ownership over which context each hunter is allowed to see and when.
