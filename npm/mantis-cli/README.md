# mantis-cli

> **Alias package — installs [`mantishack`](https://www.npmjs.com/package/mantishack).**

Use whichever name you prefer:

```sh
npm  install -g mantis-cli       # this package — alias
npm  install -g mantishack       # the actual package
```

Both end up with the same `mantis`, `mantis-daemon`, and `mantis-mcp` binaries on your PATH. `mantis-cli` is a tiny shim package that just declares `"dependencies": { "mantishack": "0.0.4" }`; npm pulls down the real implementation transitively.

---

> ## ⚠️  Authorized Testing Only
>
> Mantis is offensive-security tooling. Use it **only** against systems you own or have **explicit written authorization** to test.

---

## Quick start

```sh
npm install -g mantis-cli
mantis init                                          # wire daemon + MCP
mantis hack app.example.com --i-have-authorization   # one-shot full FSM
```

## License

Apache-2.0 OR MIT
