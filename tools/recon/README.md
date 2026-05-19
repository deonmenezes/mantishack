# tools/recon/

Per-repo install of the external recon binaries the `recon-agent` shells out
to. Binaries live under `bin/` and are gitignored — re-run `install.sh` on a
fresh checkout instead of committing them.

## What gets installed

| Binary       | Source                                                      | Used for                                |
| ------------ | ----------------------------------------------------------- | --------------------------------------- |
| `subfinder`  | ProjectDiscovery (Go)                                       | Passive subdomain enumeration           |
| `httpx`      | ProjectDiscovery (Go)                                       | Live-host probe + tech / title / status |
| `katana`     | ProjectDiscovery (Go)                                       | Bounded JS-aware crawl                  |
| `nuclei`     | ProjectDiscovery (Go)                                       | Safe templated checks                   |
| `jwt_tool`   | ticarpi/jwt_tool (Python — cloned + wrapper shim)            | JWT structure / weak-secret triage      |

Nuclei templates land in `templates/` and are refreshed by `install.sh`.

## Layout

```
tools/recon/
├── install.sh        # idempotent installer (Go + Python deps + templates)
├── README.md
├── .gitignore        # ignores bin/ templates/ jwt_tool/ .venv/
├── bin/              # GOBIN target + jwt_tool shim (gitignored)
├── templates/        # nuclei templates (gitignored)
└── jwt_tool/         # ticarpi/jwt_tool clone (gitignored)
```

## Install

From the repo root:

```sh
tools/recon/install.sh
```

The script is idempotent — re-running upgrades any tool that has a newer
version upstream and refreshes the nuclei template set.

Prerequisites: a working `go` toolchain (the script will install Go via
Homebrew on macOS if missing) and `python3` (Apple-shipped is fine).

## How the recon-agent finds these

The `recon-agent.md` step-1 binary check prepends `<repo>/tools/recon/bin`
to `PATH` (via `git rev-parse --show-toplevel`). So once the install
finishes, the next `/mantis-hunt <target>` run uses these binaries
automatically instead of falling into degraded mode.

## Updating

- `tools/recon/install.sh` — re-runs all `go install ...@latest` lines.
- `bin/nuclei -update-templates` (or just re-run `install.sh`) refreshes the
  template set after a fresh release.
- `tools/recon/jwt_tool/` is a `git clone` — `git -C tools/recon/jwt_tool pull`
  to update.

## Removing

`rm -rf tools/recon/bin tools/recon/templates tools/recon/jwt_tool` resets the
install. Nothing escapes the `tools/recon/` directory.
