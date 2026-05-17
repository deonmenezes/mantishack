# /mantishack — one-shot pentest

End-to-end Mantis pentest in a single command. Drives every step
of the platform: recon → hypothesis → MCTS planner → verifier →
synthesizer (corpus + fuzzer + symbolic + LLM) → report.

**Before running:** confirm with the user that they have explicit
written authorization to test the named target. Refuse if not.

```sh
pgrep -x mantis-daemon >/dev/null || (mantis-daemon &)
sleep 1
mantis pentest "$TARGET" --i-have-authorization
```

Accepts:
- web URL:    `https://example.com`
- domain:     `example.com`  (HTTPS assumed)
- Android:    `path/to/app.apk`
- iOS:        `path/to/app.ipa`
- Windows:    `path/to/app.exe`
- macOS:      `path/to/app.dmg` or `.app`

For packaged apps the command extracts embedded URLs (via `strings`
or by scanning the binary) and pentests those URLs.

Stream `[mantishack]` progress lines to the user. When it
completes, offer report-format conversions and reproducer exports.
