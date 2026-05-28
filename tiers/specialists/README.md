# MANTISHACK Specialists (Sub-Agents)

## Purpose

Domain-specific sub-agents for specialized security testing tasks.

**Currently:** Python handles all sub-agent orchestration (packages/*)
**Future:** Space reserved for custom specialists

---

## Python Sub-Agents (Already Exist)

Python code already implements specialized agents:

| Sub-Agent | Location | Purpose |
|-----------|----------|---------|
| **Static Analysis** | packages/static-analysis/ | Semgrep orchestration |
| **CodeQL** | packages/codeql/ | Advanced dataflow analysis |
| **LLM Analysis** | packages/llm_analysis/ | Autonomous vulnerability analysis |
| **Fuzzing** | packages/fuzzing/ | AFL++ binary fuzzing |
| **Binary Analysis** | packages/binary_analysis/ | GDB crash analysis |
| **Web Scanner** | packages/web/ | OWASP Top 10 testing |
| **Recon** | packages/recon/ | Tech stack enumeration |
| **SCA** | packages/sca/ | Dependency vulnerability scanning |

**No duplication needed** - Python orchestrates these automatically.

---

## Future: Custom Specialists

This directory is reserved for future custom specialists that DON'T exist in Python:

**Potential additions:**
- API-specific testing approaches
- Mobile app security patterns
- Cloud infrastructure testing
- Custom domain expertise

**Add when needed, not preemptively.**

---

## Structure Check

The system can check what specialists exist:

```bash
# Check Python sub-agents
ls packages/*/agent.py 2>/dev/null

# Check custom specialists (future)
ls tiers/specialists/*.md 2>/dev/null
```

**If custom specialist exists:** Use it
**If only Python exists:** Defer to Python (default behavior)

---

## How This Differs from Personas

**Sub-Agents/Specialists (this directory):**
- Purpose: Execute specific tasks (scan, fuzz, analyze)
- Implementation: Python code (packages/)
- When: Task-specific execution

**Personas (tiers/personas/):**
- Purpose: Provide expert methodology for analysis
- Implementation: Markdown methodology files
- When: Manual guidance/review requested

**Both:** Available but not auto-loaded. Use when needed.
