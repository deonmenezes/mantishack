---
description: Software Composition Analysis — find vulnerable dependencies, gate CI, fix and pin
---

# /mantis-sca - MANTISHACK Software Composition Analysis

Find vulnerable third-party dependencies, gate CI on them, and fix + pin them.

## Your Task

1. **Identify the target**: ask which directory / repository to audit if not specified.

2. **Run the SCA scan** (auto-detects manifests/lockfiles for Python, Node, Maven, etc.):
   ```bash
   python3 mantishack.py sca --repo <path>
   ```

3. **Report**: list vulnerable packages with the advisory ID, severity, the installed
   vs. fixed version, and whether a safe upgrade exists. Lead with anything critical/high.

4. **Offer to fix and pin** the vulnerable dependencies:
   ```bash
   python3 mantishack.py sca --repo <path> fix --apply
   ```
   Review the proposed version bumps before applying them.
