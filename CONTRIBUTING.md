# Contributing to Mantis

Thanks for the interest. This file is the short list of rules that keep the
project's licensing, attribution, and review hygiene tight. It is not a style
guide — see [`AGENTS.md`](./AGENTS.md) for code conventions and
[`ROADMAP.md`](./ROADMAP.md) for what's planned.

---

## Licensing

Mantis is dual-licensed Apache-2.0 OR MIT. By submitting a contribution you
agree that your contribution is licensed under those same terms. See
[`LICENSE-APACHE`](./LICENSE-APACHE) and [`LICENSE-MIT`](./LICENSE-MIT).

If your contribution carries a different license, say so in the PR description
and we'll decide together whether it can be integrated (typically: only if
it's a permissive license already on the [`deny.toml`](./deny.toml) allowlist).

## Third-party code or prompts ported into this repo

This is the rule with the highest enforcement priority. Mantis has a documented
license compliance history (see [`NOTICE`](./NOTICE)) and we keep §4 mechanics
tight going forward.

**If your PR ports any non-trivial code, prompt, schema, or playbook from an
external source — even a single file — you must, in the same PR:**

1. **Add an Apache-2.0 §4(b) header** to each ported file. The header must
   name:
   - the upstream URL (canonical permalink, blob/`main` or pinned SHA),
   - the upstream copyright holder and year,
   - the upstream license (verbatim SPDX identifier),
   - the concrete renames / structural changes you applied at port time.

   See any file under [`plugin/claude-code/agents/`](./plugin/claude-code/agents)
   or [`prompts/roles/`](./prompts/roles) for the template — those are the
   canonical examples we maintain.

2. **Add a row to [`PORTING.md`](./PORTING.md)** under the appropriate section.
   Map every ported file to its upstream source URL.

3. **Add a row to [`CREDITS.md`](./CREDITS.md)** (and [`NOTICE`](./NOTICE) if
   the upstream project isn't already listed there).

4. **Confirm license compatibility against [`deny.toml`](./deny.toml).** The
   allowlist defines what's safe for direct integration. GPL / AGPL upstreams
   are inspiration-only and must not be ported — see the
   [License Compatibility Quick Reference](./ROADMAP.md#license-compatibility-quick-reference)
   in `ROADMAP.md`.

PRs that port external content without all four of these are not eligible for
merge. The review bar is "every ported file in this PR has the §4(b) header
on the upstream URL it claims to come from."

## Pull requests

- Keep PRs focused. One concern per PR.
- Run `cargo test` and `cargo clippy --workspace --all-targets -- -D warnings`
  before pushing (or accept that CI will).
- Pre-commit hook expectations live in the `.git/hooks/` set this repo
  installs; don't bypass them with `--no-verify`.
- Commit messages: present-tense, lowercase prefix (`feat:`, `fix:`, `perf:`,
  `chore:`, `docs:`), one-line summary under ~70 chars, body explaining *why*.
  See recent `git log` for the established style.

## Security issues

Do not file security issues as public GitHub issues. Open a private security
advisory or email the address listed in
[`SECURITY.md`](./SECURITY.md).

## Code of conduct

Behave like a respectful adult. We don't ship a CoC document because the
maintainer reserves the right to remove anyone whose conduct makes the project
worse for others, with or without a formal policy.

## Questions

Open a [Discussion](https://github.com/deonmenezes/mantishack/discussions) for
design questions; an [Issue](https://github.com/deonmenezes/mantishack/issues)
for bugs or concrete proposals.
