---
name: mantis-update
description: Check for Mantis package updates and guide project-local update installation from Codex.
---

# Mantis Update

Use this when the operator asks to check, plan, or apply Mantis updates from Codex.

## Read Cache
Read the passive local cache without network access:
```bash
node -e "const update=require('./mcp/lib/update-check.js'); console.log(JSON.stringify(update.readUpdateCache(process.cwd()) || null, null, 2));"
```

## Check Latest
Run this only when the operator explicitly asks to check for updates:
```bash
node -e "const update=require('./mcp/lib/update-check.js'); update.checkForUpdate(process.cwd(), { includeChangelog: true }).then((result) => console.log(update.renderUpdatePlan(result))).catch((error) => { console.error(error.message || String(error)); process.exit(1); });"
```

## Apply Update
Ask before updating. When confirmed, run from the project root:
```bash
npx -y mantis@latest install "$PWD"
```

After installation, tell the operator to restart Codex in this project before continuing.
