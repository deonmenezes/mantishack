---
name: mantis-export
description: Create a Mantis post-release improvement bundle for the currently installed Mantis version.
---

# Mantis Export

Use this when the operator asks to create a post-release improvement bundle from Codex.

Run from the project root. The command has no v1 flags:
```bash
node -e "const exporter=require('./mcp/lib/mantis-export.js'); const result=exporter.exportMantisReleaseBundle({ projectDir: process.cwd() }); process.stdout.write(exporter.renderExportResult(result));"
```

Report the helper output exactly. This workflow exports telemetry and session summaries for improving Mantis; it does not hunt, resume sessions, or interact with targets.
