# Install via npm / bun / yarn / pnpm

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

<p align="center">
  <img src="../../assets/mascot/hero.png" alt="Mantis mascot" width="220" />
</p>

## TL;DR

```sh
npm  install -g mantishack
bun  add    -g mantishack
yarn global add mantishack
pnpm add    -g mantishack
```

After the install:

```sh
mantis init                      # wire daemon + MCP
mantis hack <target> --i-have-authorization
```

## How the package works

The `mantishack` package uses the **per-platform `optionalDependencies` pattern** — the same approach as `esbuild`, `swc`, `biome`, `rolldown`, and `sharp`. There is **no postinstall script**.

When you install `mantishack`:

1. Your package manager resolves the `optionalDependencies` and downloads exactly one platform-specific binary package matching your OS/arch:
   - `@mantishack/cli-darwin-arm64` (Apple Silicon Mac)
   - `@mantishack/cli-darwin-x64` (Intel Mac)
   - `@mantishack/cli-linux-x64`
   - `@mantishack/cli-linux-arm64`
2. The main `mantishack` package's `bin/mantis.js` shim (~50 lines, Node 14+) resolves the platform binary via `require.resolve` and `exec`s it with your argv.
3. The shim ad-hoc extends `PATH` with the platform package's `bin/` directory so the main CLI's lookups for sibling binaries (`mantis-daemon`, `mantis-mcp`) resolve from the same install.

This means:

- **Bun-safe.** Bun ignores postinstall scripts by default for security. The platform-package pattern doesn't need one.
- **pnpm-safe.** pnpm's strict mode rejects postinstall artifacts; this pattern works fine.
- **One platform binary per machine.** No wasted bandwidth.
- **No network at install time** beyond the package manager's normal registry fetch.

## What gets installed

Three executable shims, all symlinked into your prefix's `bin/`:

| Shim | Resolves to | What it does |
|---|---|---|
| `mantis` | platform-package `bin/mantis` | The main CLI |
| `mantis-daemon` | platform-package `bin/mantis-daemon` | The long-running gRPC daemon |
| `mantis-mcp` | platform-package `bin/mantis-mcp` | The MCP server (spawned by `claude` / `codex` etc.) |

## Verify the install

```sh
mantis --version       # mantis 0.0.1
mantis hack --help     # confirms `hack` subcommand surface
```

If `mantis --version` works but `mantis hack <target>` doesn't, run `mantis doctor` to diagnose.

## Supported platforms

| OS      | Arch   | Package                          | Status |
|---------|--------|----------------------------------|--------|
| macOS   | arm64  | `@mantishack/cli-darwin-arm64`   | ✅ |
| macOS   | x64    | `@mantishack/cli-darwin-x64`     | ✅ |
| Linux   | x64    | `@mantishack/cli-linux-x64`      | ✅ |
| Linux   | arm64  | `@mantishack/cli-linux-arm64`    | ✅ |
| Windows | x64    | `@mantishack/cli-win32-x64`      | 🚧 planned |

## Troubleshooting

### `mantis: no prebuilt binary for <os>-<arch>`

Your platform isn't on the supported list. Build from source — see [Install from source](./source.md).

### `@mantishack/cli-… is not installed`

Your package manager skipped the optional dependency. Most likely you ran with `--no-optional` or similar. Re-install:

```sh
npm install -g mantishack --include=optional
```

Or just install the platform package directly:

```sh
npm install -g @mantishack/cli-darwin-arm64
```

### macOS: `zsh: killed mantis`

macOS killed the binary because it isn't code-signed. Ad-hoc sign it:

```sh
codesign --force --sign - "$(which mantis)"
codesign --force --sign - "$(which mantis-daemon)"
codesign --force --sign - "$(which mantis-mcp)"
```

The `mantishack` build script ad-hoc-signs binaries before packing, so this should be rare with the published binaries — but if you built from source via raw `cp` it can happen.

### Bun-specific

Bun installs `optionalDependencies` by default. If you used `bun install --production` (which skips optional), re-install without that flag, or:

```sh
bun add -g @mantishack/cli-darwin-arm64    # add platform package directly
```
