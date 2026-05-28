# MANTISHACK + Claude Code Integration

This directory contains custom slash commands that let you use MANTISHACK with plain English via Claude Code.

## Available Slash Commands

### `/mantishack` - General MANTISHACK Assistant
The main command that helps you decide which MANTISHACK mode to use.

**Examples:**
- "Hey Claude, /mantishack - scan my code for vulnerabilities"
- "/mantishack - I need to fuzz a binary"
- "/mantishack - test my web application"

### `/mantishack-scan` - Code Scanning
Runs MANTISHACK's autonomous code scanning (Semgrep + CodeQL + LLM analysis).

**Examples:**
- "/mantishack-scan - scan the current directory"
- "/mantishack-scan - check this repository for security issues"
- "/mantishack-scan - find vulnerabilities in /path/to/my/app"

### `/mantishack-fuzz` - Binary Fuzzing
Fuzzes binaries with AFL++ and generates exploits from crashes.

**Examples:**
- "/mantishack-fuzz - fuzz ./my_binary for 10 minutes"
- "/mantishack-fuzz - test /usr/local/bin/myapp for crashes"
- "/mantishack-fuzz - find bugs in this binary"

### `/mantishack-web` - Web Application Testing
Scans web applications for OWASP Top 10 vulnerabilities.

**Examples:**
- "/mantishack-web - scan https://myapp.com"
- "/mantishack-web - test my website for XSS and SQLi"

## How to Use

1. **Type the slash command** in Claude Code
2. **Add your request in plain English** after the dash
3. **Claude will**:
   - Ask clarifying questions if needed
   - Run the appropriate MANTISHACK command
   - Analyze the results
   - Summarize vulnerabilities found
   - Show exploits and patches
   - Help you fix issues

## Example Workflow

```
You: /mantishack-scan - scan this directory for secrets and vulnerabilities

Claude: I'll run a comprehensive security scan on the current directory.
        Let me start by running MANTISHACK in agentic mode...

        [Runs: python3 mantishack.py agentic --repo /current/path]

        ✓ Scan complete! Found 5 vulnerabilities:
        1. Hardcoded AWS credentials (HIGH) - app/config.py:23
        2. SQL Injection (CRITICAL) - api/users.py:45
        3. XSS vulnerability (MEDIUM) - web/templates/index.html:67
        ...

        I've also generated:
        - 3 working exploit PoCs in out/exploits/
        - 5 secure patches in out/patches/

        Would you like me to:
        1. Apply the patches automatically?
        2. Explain each vulnerability in detail?
        3. Show the exploit code?
```

## Natural Language Examples

You can use very natural language:

- "Hey Claude, scan my code"
- "Fuzz this binary for me"
- "Check if my website has XSS"
- "Find security bugs in ./myapp"
- "Test /usr/bin/vulnerable_program for crashes"
- "Scan this repo for hardcoded secrets"

Claude will understand your intent and run the appropriate MANTISHACK command!

## What Happens Behind the Scenes

1. **Slash command loads** the context/instructions for that MANTISHACK mode
2. **Claude understands** what you want to test and which parameters to use
3. **MANTISHACK runs** via the Bash tool (python3 mantishack.py ...)
4. **Results are analyzed** by reading output files from the `out/` directory
5. **Claude summarizes** findings in plain English
6. **Next steps offered** - apply patches, explain vulnerabilities, etc.

## Benefits

✅ **No need to remember command syntax** - just use plain English
✅ **Intelligent defaults** - Claude picks good parameters
✅ **Results interpretation** - Claude explains what was found
✅ **Interactive** - Ask follow-up questions, drill into findings
✅ **Helpful** - Offers to apply patches, explain concepts, etc.

## Tips

- Be specific about what you want to test
- Claude will ask for paths if you don't provide them
- You can chain requests: "scan this, then fuzz that binary"
- Claude remembers context, so you can say "now explain finding #2"

## Requirements

- Claude Code CLI installed
- MANTISHACK installed (python3, dependencies)
- For fuzzing: AFL++ properly configured
- For full analysis: ANTHROPIC_API_KEY or OPENAI_API_KEY set

---

**Start using MANTISHACK with natural language now!** Just type `/mantishack` and tell Claude what you want to test.
