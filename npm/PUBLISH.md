# Publishing `mantishack` to npm

The repo ships an npm distribution under `npm/`. It uses the **per-platform `optionalDependencies` pattern** (same approach as esbuild, swc, biome, rolldown). No postinstall script — works in Bun and pnpm strict mode by design.

## Layout

```
npm/
├── mantishack/                              # main package, what users install
│   ├── package.json                         # name: "mantishack", optionalDependencies
│   ├── bin/mantis.js                        # node shim → resolves platform binary
│   ├── bin/mantis-daemon.js
│   ├── bin/mantis-mcp.js
│   └── README.md
├── platforms/
│   ├── darwin-arm64/package.json            # @deonmenezes/mantis-cli-darwin-arm64
│   ├── darwin-x64/package.json              # @deonmenezes/mantis-cli-darwin-x64
│   ├── linux-x64/package.json               # @deonmenezes/mantis-cli-linux-x64
│   └── linux-arm64/package.json             # @deonmenezes/mantis-cli-linux-arm64
├── build.sh                                 # compile + pack tarballs
└── PUBLISH.md (you are here)
```

## Build

```sh
# Build for the host platform only (fast, no cross-compile setup):
./npm/build.sh

# Build all 4 platforms (requires `cross` or a CI matrix — see below):
./npm/build.sh --all

# Build one specific target:
./npm/build.sh --target aarch64-unknown-linux-gnu
```

Output: `npm/dist/*.tgz` ready for `npm publish`. Each tarball is also installable directly:

```sh
bun add ./npm/dist/mantishack-0.0.1.tgz
# Or:
npm i  ./npm/dist/mantishack-0.0.1.tgz
```

That's how you can smoke-test the package without publishing.

## Cross-compiling

The cleanest path is a **GitHub Actions matrix** that runs `./npm/build.sh` on each platform's native runner:

| Target                         | Runner                       |
|--------------------------------|------------------------------|
| `aarch64-apple-darwin`         | `macos-14`                   |
| `x86_64-apple-darwin`          | `macos-13`                   |
| `x86_64-unknown-linux-gnu`     | `ubuntu-22.04`               |
| `aarch64-unknown-linux-gnu`    | `ubuntu-22.04-arm` (or QEMU) |

Locally, [`cross`](https://github.com/cross-rs/cross) handles Linux cross-compile from macOS via Docker:

```sh
cargo install cross --git https://github.com/cross-rs/cross
cross build --release --target aarch64-unknown-linux-gnu -p mantis-cli -p mantis-daemon -p mantis-mcp
```

## Publish

> ⚠️  Publishing is irreversible. Once a version is on npm you can `npm unpublish` only within 72 hours.

```sh
# 1. Log in once (interactive)
npm login

# 2. Publish each platform package (must precede the main package so optionalDependencies resolve)
for plat in darwin-arm64 darwin-x64 linux-x64 linux-arm64; do
  (cd npm/platforms/$plat && npm publish --access public)
done

# 3. Publish the main package
cd npm/mantishack && npm publish --access public
```

After that, anyone can:

```sh
npm  install -g mantishack
bun  add    -g mantishack
yarn global add mantishack
pnpm add    -g mantishack
```

## Versioning

The npm package version mirrors the Cargo workspace version in the root `Cargo.toml`. When you bump Cargo, also bump:

- `npm/mantishack/package.json` → `version` AND each `optionalDependencies.@deonmenezes/mantis-cli-*` value
- Each `npm/platforms/*/package.json` → `version`

A future helper (`npm/bump.sh`) can automate this.

## Why this pattern

- **Postinstall scripts don't work in Bun.** Bun ignores them by default for security. A postinstall-based downloader would silently leave Bun users with no binary.
- **`optionalDependencies` filtered by `os`/`cpu`** is npm's native cross-platform mechanism. Every modern Rust-on-npm project uses it (esbuild, swc, biome, rolldown, sharp, parcel, …).
- **Install is fast** — only one platform binary is downloaded per machine.
- **The Node shim is ~50 lines** and only uses `node:child_process` + `node:path`. No runtime dependencies, works on Node 14+.
