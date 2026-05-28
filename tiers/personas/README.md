# MANTISHACK Expert Personas

## Purpose

Expert methodologies extracted from MANTISHACK's Python code, made available for explicit invocation.

**These personas already exist in Python code** - this makes them accessible to Claude Code users for manual guidance and review.

---

## Available Personas

| Persona | Named Expert | Source File | Tool/Context | Token Cost |
|---------|--------------|-------------|--------------|------------|
| **Exploit Developer** | Mark Dowd | agent.py | Exploit generation | ~650t |
| **Crash Analyst** | Charlie Miller / Halvar Flake | crash_agent.py | Binary crash analysis | ~700t |
| **Security Researcher** | Research methodology | agent.py | Vulnerability validation | ~620t |
| **Patch Engineer** | Senior security engineer | agent.py | Secure patch creation | ~400t |
| **Penetration Tester** | Senior pentester | web/fuzzer.py | Web payload generation | ~350t |
| **Fuzzing Strategist** | Expert strategist | autonomous/dialogue.py | Fuzzing decisions | ~300t |
| **Binary Exploitation Specialist** | Binary expert | crash_agent.py | Crash exploit generation | ~400t |
| **CodeQL Dataflow Analyst** | Dataflow expert | codeql/dataflow_validator.py | Dataflow validation | ~400t |
| **CodeQL Finding Analyst** | Mark Dowd methodology | codeql/autonomous_analyzer.py | CodeQL findings | ~350t |

---

## Usage

### Explicit Invocation Only

Personas are **NOT auto-loaded**. Load when you need expert methodology:

```
"Use exploit developer persona to create PoC for finding #42"
"Use crash analyst persona to analyze this crash"
"Use security researcher persona to validate if this is a false positive"
"Use patch engineer persona to create secure fix for this vulnerability"
```

### What Happens

1. Claude loads persona file (tiers/personas/[name].md)
2. Applies persona methodology framework
3. Analyzes using expert criteria
4. Returns structured verdict/code

### Token Cost

- **Not loaded:** 0 tokens (default)
- **When invoked:** 400-500 tokens per persona
- **Session impact:** Only when explicitly requested

---

## Integration with Python

**Python already uses these personas internally:**
- `packages/llm_analysis/agent.py`: Security Researcher + Exploit Developer
- `packages/llm_analysis/crash_agent.py`: Crash Analyst

**These files make Python's internal methodologies explicit and user-accessible.**

No Python code changes needed - personas are reference documentation only.

---

## When to Use

**Security Researcher:**
- Validate if finding is real or false positive
- Analyze sanitizer effectiveness
- Assess exploitability with 4-step framework

**Exploit Developer:**
- Generate working exploit code (not templates)
- Fix broken/placeholder exploits
- Create actual patches (not recommendations)

**Crash Analyst:**
- Analyze AFL++ crashes
- Assess binary exploitability
- Understand crash types and primitives

---

## Quick Reference

**Security Researcher Framework:**
1. Source Control (attacker-controlled?)
2. Sanitizer Analysis (effective or bypassable?)
3. Reachability (can attacker trigger?)
4. Impact Assessment (what's the damage?)

**Exploit Developer Principles:**
- Working code ONLY (no TODOs)
- Complete and compilable
- Safe for authorized testing
- Well documented

**Crash Analyst Framework:**
1. Signal interpretation
2. Register analysis
3. Exploit primitives
4. Mitigations check
5. Feasibility classification

---

## Future Expansion

**Reserved space for additional personas:**
- `code_auditor.md` (systematic code review)
- `penetration_tester.md` (attack simulation)
- `defensive_analyst.md` (blue team perspective)

**Add when needed, not preemptively.**
