# Install via one-line curl

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

```sh
curl -fsSL https://raw.githubusercontent.com/deonmenezes/mantishack/main/install.sh | bash
```

The installer builds `mantis-daemon`, `mantis`, and `mantis-mcp` from source into `~/.local/bin/` and runs `mantis init`. Requires the Rust toolchain. See [Install from source](./source.md) for what `install.sh` does step-by-step.

For most users, the [npm install](./npm.md) path is faster (no compilation required).
