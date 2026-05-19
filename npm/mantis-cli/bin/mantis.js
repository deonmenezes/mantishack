#!/usr/bin/env node
// Thin alias: re-runs mantishack's own shim. The mantishack
// package's shim already handles platform-binary resolution +
// auto-init + macOS quarantine stripping. We just chain to it.
require("mantishack/bin/mantis.js");
