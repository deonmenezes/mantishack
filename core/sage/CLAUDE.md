# SAGE persistent memory usage

Loaded on demand by MANTISHACK's root `CLAUDE.md` when the `sage_inception`
MCP tool is present (i.e. when the user has run `libexec/mantishack-sage-setup`).
If this file is loaded, SAGE is available — use it.

## Boot sequence

1. Call `sage_inception` to initialize persistent memory.
2. Call `sage_turn` every turn with the current topic + observation.
3. Call `sage_reflect` after significant tasks with dos and don'ts.

## Domains

- `mantishack-findings` — Vulnerability findings and analysis results
- `mantishack-fuzzing` — Fuzzing strategies, crash patterns, exploit techniques
- `mantishack-crashes` — Crash analysis patterns and root causes
- `mantishack-forensics` — OSS forensics evidence and investigation patterns
- `mantishack-exploits` — Exploit development patterns and constraints
- `mantishack-methodology` — Analysis methodology and expert reasoning
- `mantishack-campaigns` — Campaign history and outcomes
- `mantishack-reports` — Report structures and templates
- `mantishack-agents` — Agent role definitions and capabilities
- `mantishack-primitives` — Exploitation primitives and dependency graphs
- `mantishack-prompts` — LLM system prompts and personas

## When to use

- **When scanning:** after analysis, store key findings via `sage_remember` in `mantishack-findings`.
- **When fuzzing:** record strategy outcomes and crash patterns in `mantishack-fuzzing`.
- **When developing exploits:** record technique success/failure in `mantishack-exploits`.
- **Before destructive actions:** call `sage_recall` with `mantishack-methodology` for known pitfalls.

## Graceful degradation

If a SAGE call errors mid-session (server restart, transient failure),
fall back silently and continue — SAGE is purely additive. Log the error
at debug level (matching `core/sage/hooks.py`'s existing pattern) rather
than surfacing it to the user. Never let a SAGE failure block MANTISHACK work.
