---
description: List all available MANTISHACK commands
---

# MANTISHACK Command Reference

Output "Full list of MANTISHACK commands:" then list all available MANTISHACK slash commands as a bullet list. Format: `- /command <args> — Description`. Derive the list from the available skills — do not use a hardcoded list.

Omit commands flagged as "unavailable" in the most recent startup warnings. Commands flagged as "limited" should still be shown with a note (e.g., `(limited — rr not found)`).

Exclude non-MANTISHACK commands (e.g., /commands itself, /help) and internal/duplicate commands (e.g., mantishack-scan, mantishack-fuzz, mantishack-web).

End with: "Commands with missing dependencies are omitted. Check the startup warnings for details."
