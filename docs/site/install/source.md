# Install from source

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

```sh
git clone https://github.com/deonmenezes/mantishack
cd mantishack
cargo install --path crates/mantis-cli --force
cargo install --path crates/mantis-daemon --force
cargo install --path crates/mantis-mcp --force
mantis init
```

`cargo install` ad-hoc-signs binaries on macOS so you don't hit the `zsh: killed` SIGKILL trap.

Requires Rust 1.75+ (workspace MSRV is in `rust-toolchain.toml`).

Run the test suite once after install to confirm the workspace is healthy:

```sh
cargo test --workspace
```

The canonical gate is **652 tests passing**.
