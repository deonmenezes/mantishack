# First Run

This guide walks through a clean install into one project directory and a short smoke test.

## Install

Choose the project directory where you will run your host CLI, then install Mantis into that directory. Claude is the default adapter:

```bash
npx -y mantishack@latest install /path/to/your/project
cd /path/to/your/project
```

Other adapters use the same target directory with an explicit adapter flag:

```bash
npx -y mantishack@latest install /path/to/your/project --adapter codex
npx -y mantishack@latest install /path/to/your/project --adapter generic-mcp
npx -y mantishack@latest install /path/to/your/project --adapter all
```

The installer writes shared runtime files into `mcp/` and `.mantishack/`, then writes the selected adapter surface. Claude uses `.claude/`, Codex uses direct `$bob-*` skills in `~/.codex/skills` plus `.codex/plugins/mantishack`, `.agents/plugins/marketplace.json`, and Codex cache/config activation for MCP wiring, and generic MCP uses root `.mcp.json` plus `.mantishack/generic-mcp/` prompt docs. Codex exposes Mantis as `$bob-hunt`, `$bob-status`, `$bob-debug`, `$bob-update`, `$bob-export`, and `$bob-egress` skills. A global npm install adds the `mantishack` command to your `PATH`, but it does not install Mantis into every project automatically.

## Doctor Check

Run the read-only doctor command:

```bash
mantishack doctor /path/to/your/project
mantishack doctor /path/to/your/project --adapter codex
```

A healthy install has this shape:

```text
Mantis doctor: /path/to/your/project

OK: node_version - Node.js ... satisfies >=20
OK: target_directory - /path/to/your/project is a directory
OK: required_tool_curl - curl is available
OK: required_tool_python3 - python3 is available
OK: install_version - Installed Mantis version is ...
OK: install_metadata_json - .mantishack/install.json is valid JSON
OK: install_metadata - Neutral install metadata matches this project
OK: claude_installed_version - Installed Mantis version is ...
OK: claude_install_metadata_json - .claude/bob/install.json is valid JSON
OK: claude_install_metadata - Install metadata matches this project
OK: claude_commands - Mantis slash commands are installed
OK: claude_hook_files - Mantis hook files are installed
OK: claude_hook_modes - Executable Mantis hooks have executable mode
OK: claude_mcp_json - .mcp.json is valid JSON
OK: claude_mcp_server_config - .mcp.json points mantis at this project's mcp/server.js
OK: claude_settings_json - .claude/settings.json is valid JSON
OK: claude_settings_hooks - .claude/settings.json contains Mantis hooks
OK: claude_settings_permissions - .claude/settings.json contains Mantis MCP permissions
OK: claude_settings_statusline - .claude/settings.json contains Mantis statusline
OK: mcp_server_file - mcp/server.js is installed
OK: mcp_server_loadable - mcp/server.js loads successfully
WARN: optional_tool_subfinder - subfinder is missing; related recon steps will be skipped
WARN: optional_tool_nuclei - nuclei is missing; related recon steps will be skipped
WARN: optional_tool_httpx - httpx is missing; related recon steps will be skipped
WARN: optional_tool_dnsx - dnsx is missing; related recon steps will be skipped
WARN: optional_tool_tlsx - tlsx is missing; related recon steps will be skipped
WARN: optional_tool_katana - katana is missing; related recon steps will be skipped
WARN: optional_tool_subzy - subzy is missing; related recon steps will be skipped
WARN: optional_tool_jwt_tool - jwt_tool is missing; JWT candidate review helpers will be skipped
WARN: optional_patchright - patchright is missing; Tier 2 auto-signup is disabled
WARN: optional_capsolver - CAPSOLVER_API_KEY is not set; CAPTCHA solving is disabled

No required problems found.
```

The exact list can grow as diagnostics improve. Treat any `ERROR` line as something to fix before starting a hunt. Optional tools can be missing without blocking first use.

If doctor reports `WARN: install_version` or `WARN: install_metadata_json` and mentions legacy `.claude/bob/` metadata, the runtime can still read the legacy fallback. Rerun the installer to write neutral `.mantishack/` metadata.

## Restart Claude Code

After a Claude install or update, fully restart Claude Code from the project directory:

```bash
cd /path/to/your/project
claude --dangerously-skip-permissions --effort max
```

Warning: `--dangerously-skip-permissions` disables Claude Code permission prompts. Use it only in a dedicated workspace for authorized security testing.

The restart is required because Claude Code reads slash commands, MCP config, settings, hooks, and statusline setup at startup.

For Codex, restart Codex in the target directory and confirm `$bob-hunt`, `$bob-status`, `$bob-debug`, `$bob-update`, `$bob-export`, and `$bob-egress` are available. The installer activates `mantishack@mantishack-local` in Codex's cache/config for MCP wiring; if skills are still missing, run `mantishack doctor /path/to/your/project --adapter codex --json`. For generic MCP hosts, reload the host's MCP server configuration and use `.mantishack/generic-mcp/mantishack.md` as the operator prompt guide.

## Smoke Check

For Claude, run:

```text
/mantis-status
```

For a fresh install, it is normal for Mantis to report that there is no completed session yet. The command should load without a missing-command error and should be able to read the local MCP/status files.

For Codex, invoke `$bob-status`. For generic MCP hosts, list the `mantis` tools or call a read-only status tool through the host's MCP UI.

## Pre-Run Checklist

Before running `/mantishack`, confirm that you have written authorization for the target and accounts, and that the authorization explicitly covers the testing methods Mantis may use. Check that automated scanning, authenticated testing, signup or account creation, third-party pivots, internal or private-network targets, rate limits, and data handling rules are all allowed for this engagement.

For a first smoke test, use a private lab target or an intentionally vulnerable training app you control:

```text
/mantishack lab.example.test
```

Do not use a real company, public service, customer environment, or bug bounty target until you have confirmed that the target is in scope and you understand the allowed testing methods.
