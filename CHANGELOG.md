# Changelog

All notable changes to Mantis are recorded here. Order is reverse-chronological. Each entry links to the commit on `main`.

## Unreleased — agent power + Claude-Code-style CLI parity

A multi-iteration push to make `mantis-cli` feel like `claude` / `claw` and to give spawned agents a richer pure-utility tool surface.

### New `mantis-cli` subcommands

- **`mantis prompt "<text>"`** — Claude-Code-style one-shot. Wires the `mantis` MCP server, applies the model-resolution chain, streams the response. Honors `--output-format text|json`. (`c8d3a40`)
- **`mantis status [--output-format text|json]`** — single-glance setup snapshot: daemon + claude + MCP + model + project config + `~/.Mantis/` paths. (`c8d3a40`, `4f07c03`, `74358e2`)
- **`mantis version [--output-format text|json]`** — version + rust_target for scripting. (`915d18e`)
- **`mantis model [pick|show|set|clear]`** — Tab / Shift+Tab interactive picker, persisted to `~/.Mantis/model`. (`7765786`)
- **`mantis init --project`** — scaffolds `.mantis.json` template + `MANTIS.md` guidance file in cwd. Idempotent. (`9f00134`)

### `mantis hack` improvements

- **Parallel pre-flight checks** (~2× faster startup) — daemon-up gRPC ping, `claude` PATH walk, and `mantis-mcp` lookup now run concurrently via `tokio::join!`. (`27a4e9c`)
- **`--turbo` preset** — equivalent to `--deep` + Opus model when no other preference is set. (`27a4e9c`)
- **`--print-prompt`** — dump the assembled system + user prompts and exit without spending tokens. (`27a4e9c`)
- **`--dry-run`** — run every pre-flight check and exit (CI smoke tests). (`27a4e9c`)
- **Auto-loads `MANTIS.md`** repo guidance into the orchestrator's system prompt so spawned hunters see the per-repo scope / posture. (`9d65452`)
- **Post-run summary panel** — findings-by-severity counts + grade verdict + report paths printed inline when the orchestrator returns. (`a13cc15`)

### Model-resolution chain

Closes the chain claude-code / claw-code style. Priority order:

1. CLI flag `-- --model …` / `-m …`
2. `MANTIS_MODEL` env var (`4f07c03`)
3. `.mantis.json` `"model"` key (`74358e2`)
4. `~/.Mantis/model` via `mantis model` (`7765786`)
5. Claude default

`mantis status` surfaces the effective slot and every raw value.

### `.mantis.json` per-project config

- Discovery walks up from cwd. (`74358e2`)
- Keys: `model`, `deep`, `no_auth`, `egress`, `daemon`. All optional. (`74358e2`, `7498793`)
- Drives defaults for `mantis hack` flags (CLI flags still win). (`7498793`)
- `MANTIS.md` sibling auto-loads into the orchestrator prompt. (`9d65452`)

### Interactive REPL slash commands

The bare-`mantis` REPL now dispatches slash commands to the running `mantis` binary via `std::env::current_exe()`:

- `/doctor`, `/status`, `/version`, `/init`, `/init-project`, `/model [id|clear|show]`, `/hack <target>`
- (`9300e23`, `cebd230`)

### New pure-utility MCP tools for agents

Eight new `mantis_*` tools — pure Rust, no daemon round-trip, all granted to the relevant hunter / verifier / chain-builder / evidence agents.

- **`mantis_decode_jwt`** — parse JWT header + payload, flag dangerous patterns (`alg:none`, missing/expired `exp`, empty signature). Accepts bare token or `Bearer …`. (`cff8584`)
- **`mantis_diff_responses`** — classify two HTTP responses (identical / status_changed / length_changed / headers_changed / body_changed / mixed) and surface `markers` (role flags, JWT shapes, leaked AWS / Stripe / GitHub keys) present in one side only. (`cff8584`)
- **`mantis_summarize_url`** — RFC-3986 parser + classifier. Flags `host_is_internal`, `host_is_cloud_metadata`, `host_is_ip_literal`, `has_userinfo`, `path_is_admin_like`, `path_is_secret_artifact`. (`cff8584`)
- **`mantis_extract_secrets`** — anchored-prefix + structural scanner for AWS / GitHub / Stripe / OpenAI / Anthropic / Slack / Google / SendGrid / Mailgun / Tailscale / Fly / Vercel / npm tokens, JWT shapes, PEM private keys, DB connection URLs. Per-match severity hint + redacted form. (`ded38ae`)
- **`mantis_score_finding`** — pre-grader using the same 5-axis rubric as the post-VERIFY `grader` sub-agent. Returns `SUBMIT` / `HOLD` / `SKIP` plus `elevate_hints`. Hunters self-filter before `mantis_record_finding`. (`cdf5ad3`)
- **`mantis_hash_request`** — BLAKE3 stable hash of (method, url, headers, body) with default-ignored noisy headers. Probe dedup. (`f45952d`)
- **`mantis_extract_html_forms`** — extract every `<form>` with method + action + inputs + `csrf_tokens` + `mass_assignment_candidates`. (`f45952d`)
- **`mantis_extract_links`** — find URLs in HTML / JS / JSON / traces. Classifies same_origin / external / relative + distinct host set. (`023c665`)

### Marketing / docs

- New `docs/site/index.html` landing page with title "Ethically hack and discover vulnerabilities in any software with the power of AI". (`8a6cde7`)
- Tagline synced across `README.md`, `docs/site/README.md`, the `/mantishack` slash-command banner, and the live CLI banner. (`8a6cde7`, `27a4e9c`)
- New docs pages: `docs/site/cli/model.md`, `docs/site/cli/prompt.md`, `docs/site/cli/status.md`. (`7765786`, `eb23056`)
- Updated `docs/site/cli/hack.md` with the new flags + per-repo config section. (`eb23056`)
