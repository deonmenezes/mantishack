# Troubleshooting

## Run Doctor First

Use the CLI doctor before changing files manually:

```bash
mantishack doctor /path/to/your/project
mantishack doctor /path/to/your/project --json
```

The command is read-only. It checks Node.js, installed Mantis files, neutral install metadata, selected adapter config, and whether `mcp/server.js` can load.

Use `--adapter claude`, `--adapter codex`, `--adapter generic-mcp`, or `--adapter all` when checking a non-default install:

```bash
mantishack doctor /path/to/your/project --adapter codex --json
```

## MCP Server Is Not Listed

Bob writes a `mantis` server entry into the selected host config. Claude and generic MCP use the project `.mcp.json`; Codex uses `.codex/plugins/mantishack/.mcp.json`. Make sure you installed into the same directory you run the host CLI from:

```bash
npx -y mantishack@latest install /path/to/your/project --adapter claude
cd /path/to/your/project
claude mcp list
```

If `mantishack doctor` reports a missing or mismatched `.mcp.json` entry, rerun the install command for that project directory.

For Codex installs, check that `.codex/plugins/mantishack/.codex-plugin/plugin.json`, `.codex/plugins/mantishack/.mcp.json`, `~/.codex/skills/bob-{hunt,status,debug,update,export,egress}/SKILL.md`, `.agents/plugins/marketplace.json`, and the doctor `codex_plugin_activation` and `codex_global_skills` checks are present. For generic MCP installs, check `.mantishack/generic-mcp/mantishack.md` and the root `.mcp.json`.

## Codex Skills Are Missing

Codex reads Mantis as direct skills from `~/.codex/skills` and reads MCP wiring from the enabled local plugin cache. Rerun the Codex adapter install in the exact project directory you start Codex from:

```bash
npx -y mantishack@latest install /path/to/your/project --adapter codex
cd /path/to/your/project
codex
```

The install should print `Codex plugin cache/config activated for MCP discovery`. Then look for `$bob-hunt`, `$bob-status`, `$bob-debug`, `$bob-update`, `$bob-export`, and `$bob-egress`. If they still do not appear, run:

```bash
mantishack doctor /path/to/your/project --adapter codex --json
```

## Claude Restart Required

Claude Code reads project MCP and settings during startup. After installing or updating Mantis, fully restart Claude Code in that project before running `/mantishack`.

## `/mantis-update` Is Missing

Legacy Claude installs may not have the update command. Update from outside Claude Code:

```bash
npx -y mantishack@latest install /path/to/your/project
```

Then restart Claude Code in that project.

For Codex installs, use `$bob-update`. For generic MCP installs, run `mantishack update /path/to/your/project --adapter generic-mcp` from a shell and reload the host config.

## Egress Command Is Missing

Claude installs expose `/mantis-egress`; Codex installs expose `$bob-egress`. After installing or updating, restart the selected host CLI in the target project. If the command is still missing in Codex, rerun:

```bash
npx -y mantishack@latest install /path/to/your/project --adapter codex
```

## Legacy Metadata Warning

Older Claude-only installs may have `.claude/bob/VERSION` and `.claude/bob/install.json` without neutral `.mantishack/` install metadata. Doctor reports this as a warning and uses the legacy version as a migration fallback. Rerun the installer to write `.mantishack/VERSION`, `.mantishack/install.json`, and the installed adapter list:

```bash
npx -y mantishack@latest install /path/to/your/project --adapter claude
```

## npm Cache Or Network Issues

If `npx` cannot fetch the package, retry with a clean npm cache directory:

```bash
npm_config_cache=/tmp/mantishack-npm-cache npx -y mantishack@latest install /path/to/your/project
```

If your network blocks npm, install the CLI on a network that can reach the npm registry or use a source checkout:

```bash
git clone https://github.com/vmihalis/mantishack.git
cd mantishack
./install.sh /path/to/your/project
```

## Optional Recon Tools Missing

Bob works without optional recon tools, but some recon steps are skipped. `mantishack doctor` reports these as warnings.

Install the optional recon tools when you want deeper recon:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/owasp-amass/amass/v4/...@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/PentestPad/subzy@latest
git clone https://github.com/ticarpi/jwt_tool ~/jwt_tool
python3 -m pip install -r ~/jwt_tool/requirements.txt
```

Optional browser automation for Tier 2 auto-signup requires `patchright` in the project and browser binaries:

```bash
cd /path/to/your/project
npm init -y
npm install patchright
npx patchright install chromium
```

CAPTCHA solving also requires `CAPSOLVER_API_KEY`.
