# tools/recon/ — third-party attributions

The `install.sh` here fetches the upstream binaries below at install time
into `tools/recon/bin/` (gitignored). No upstream source is vendored in
this repository — fresh checkouts re-run `install.sh` to materialize the
tools locally. Every project below is credited under the license shown.

The wrapper shims, installer, and PATH-injection lines in
`.claude/agents/recon-agent.md`, `.claude/agents/deep-recon-agent.md`,
`prompts/roles/recon.md`, and `prompts/roles/deep-recon.md` are original
Mantis code.

---

## ProjectDiscovery — `subfinder`, `httpx`, `katana`, `nuclei`

- Upstream organization: https://github.com/projectdiscovery
- License: **MIT** (each binary's `LICENSE.md` lives in its own repo)
- Copyright: ProjectDiscovery, Inc. and contributors

Specific repositories and what Mantis uses each for:

| Binary       | Upstream                                                                | License | Mantis usage                              |
| ------------ | ----------------------------------------------------------------------- | ------- | ----------------------------------------- |
| `subfinder`  | https://github.com/projectdiscovery/subfinder                            | MIT     | Passive subdomain enumeration             |
| `httpx`      | https://github.com/projectdiscovery/httpx                                | MIT     | Live-host probe + tech / title / status   |
| `katana`     | https://github.com/projectdiscovery/katana                               | MIT     | Bounded JS-aware crawl                    |
| `nuclei`     | https://github.com/projectdiscovery/nuclei                               | MIT     | Safe templated checks                     |

Nuclei community templates installed into `tools/recon/templates/`:

| Resource              | Upstream                                                          | License |
| --------------------- | ----------------------------------------------------------------- | ------- |
| Nuclei templates      | https://github.com/projectdiscovery/nuclei-templates               | MIT     |

`install.sh` fetches the latest tagged releases via `go install`, which
respects each upstream module's `LICENSE.md`. Templates are pulled via
`nuclei -update-templates` and remain under their MIT license.

## ticarpi — `jwt_tool`

- Upstream: https://github.com/ticarpi/jwt_tool
- License: **GNU GPL v3.0**
- Copyright: ticarpi and contributors

Mantis uses `jwt_tool` exclusively as a separate-process subprocess
invoked through a thin wrapper shim (`tools/recon/bin/jwt_tool`) that
`exec`s the upstream Python entrypoint. No Mantis Rust or Python code
links against or imports `jwt_tool` source. The GPL boundary is the
shim and the upstream clone under `tools/recon/jwt_tool/` (gitignored,
fetched at install time). Operators who run `tools/recon/install.sh`
materialize the upstream clone under its own GPL v3.0 license.

The wrapper shim text is short and original:

```
#!/usr/bin/env bash
exec "$JWT_DIR/.venv/bin/python" "$JWT_DIR/jwt_tool.py" "$@"
```

If you redistribute a fork of Mantis with `jwt_tool` already cloned in
the tree, you must comply with GPL v3.0 for that subtree. The default
Mantis tarball / git checkout does not include `jwt_tool` source.

---

## Why install-time fetch rather than vendoring

- Keeps the Mantis repository under `Apache-2.0 OR MIT` workspace
  license without the GPL boundary issue that would arise from
  vendoring `jwt_tool`.
- Lets operators always run the most recent release of each scanner
  by re-running `install.sh` (or `nuclei -update-templates`).
- Avoids shipping multi-MB binaries through the Mantis git history.

---

## License compatibility note

Mantis's own code remains dual-licensed `Apache-2.0 OR MIT`. The MIT
ProjectDiscovery tools are compatible with both. The GPL v3.0
`jwt_tool` is invoked as a separate process; per the FSF's
`mere-aggregation` reading, calling a GPL binary by `exec` does not
impose GPL on the calling program. Operators redistributing a Mantis
fork that *bundles* GPL binaries (rather than fetching them at install
time, as the default install does) must comply with GPL v3.0 for that
subtree.
