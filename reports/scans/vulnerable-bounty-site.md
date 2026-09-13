# Scan log — vulnerable-bounty-site.vercel.app

Authorized discovery-only target for the recurring "maintenance + testing"
routine (fires every 4h). This file tracks scan attempts/findings over time
so each run can diff against the last one instead of starting cold.

Target: `https://vulnerable-bounty-site.vercel.app`
Scope: discovery-only (no active exploitation, no destructive requests).

---

## 2026-07-13T00:08Z — blocked at the network layer, no scan performed

Every outbound HTTPS request from this session's environment — to the
target _and_ to unrelated control domains (`example.com`, `vercel.app`,
`nextjs.org`) — was rejected at the egress proxy with `connect_rejected`,
`gateway answered 403 to CONNECT (policy denial or upstream failure)`.

This is not the target site responding 403; the TLS CONNECT tunnel itself
never completed. The environment's outbound network policy currently allows
only the proxy's static allowlist (anthropic.com, package registries,
git hosts, RFC1918 ranges, etc.) and blocks general internet egress
entirely, so the target domain was unreachable regardless of authorization.

No requests reached `vulnerable-bounty-site.vercel.app`; no findings to
report this run.

**Action needed (outside this session's control):** the environment's
network egress policy needs to allow outbound HTTPS to
`vulnerable-bounty-site.vercel.app` (or a broader "internet" policy) before
this routine can actually perform the authorized scan. See
`https://code.claude.com/docs/en/claude-code-on-the-web` for how environment
network policies are configured.

## 2026-07-13T04:05Z — still blocked at the network layer, no scan performed

Re-checked this run: `curl -sS -m 15 https://vulnerable-bounty-site.vercel.app`
fails with `curl: (56) CONNECT tunnel failed, response 403` before any TLS
handshake with the target occurs. `$HTTPS_PROXY/__agentproxy/status` confirms
the same `connect_rejected` denial recorded above, timestamped this run:

```json
{
  "kind": "connect_rejected",
  "detail": "gateway answered 403 to CONNECT (policy denial or upstream failure)",
  "host": "vulnerable-bounty-site.vercel.app:443"
}
```

No change from the prior run — the egress allowlist still does not include
this target, so the repository's own scanning tools (`http_audit`,
`source_sink_scan`, etc.) were never given a live target to reach. No
findings to report; nothing to compare against a previous scan since no scan
has yet reached the target. Once the environment's network policy allows
outbound HTTPS to this host, the next run should be able to perform an
actual discovery pass (recon → `http_audit` evidence capture → candidate
findings via the mantis-pipeline stages) instead of only recording the
block.

## 2026-07-14T04:08Z — still blocked at the network layer, no scan performed

Third consecutive run with the same result. Re-verified with both `curl` and
the `WebFetch` tool (which routes independently of this session's raw
`HTTPS_PROXY`) to rule out a tool-specific issue rather than an
environment-wide policy:

- `curl -sS -m 15 https://vulnerable-bounty-site.vercel.app` →
  `curl: (56) CONNECT tunnel failed, response 403`
- `curl -sS -m 15 https://example.com` (unrelated control domain) → same
  `CONNECT tunnel failed, response 403`
- `WebFetch` against the target → `The server returned HTTP 403 Forbidden`
  (rejected before reaching the origin; same shape as the proxy denial, not
  a target-side response)
- `$HTTPS_PROXY/__agentproxy/status` → `recentRelayFailures` shows two fresh
  `connect_rejected` entries for `vulnerable-bounty-site.vercel.app:443`
  timestamped this run (`2026-07-14T04:05:03Z`, `2026-07-14T04:08:04Z`), plus
  matching denials for `example.com:443`

Same conclusion as the last two runs: this is a categorical "no general
internet egress" policy on the environment, not anything specific to the
target or to how the request is made. No request has ever reached
`vulnerable-bounty-site.vercel.app` across three runs now, so there is
still nothing to diff and no findings to report.

**Action needed (unchanged, outside this session's control):** add
`vulnerable-bounty-site.vercel.app` (or general internet egress) to this
environment's outbound network policy. Until that happens, every future
firing of this routine will keep producing the same "blocked, no scan"
result — worth fixing the policy once rather than re-discovering this every
4 hours.

## 2026-07-18T12:09Z — still blocked at the network layer, no scan performed

Fourth consecutive run with the same result. Re-verified:

- `curl -sS -m 15 https://vulnerable-bounty-site.vercel.app` →
  `curl: (56) CONNECT tunnel failed, response 403`
- `$HTTPS_PROXY/__agentproxy/status` → `recentRelayFailures` shows a fresh
  `connect_rejected` entry for `vulnerable-bounty-site.vercel.app:443`
  timestamped this run (`2026-07-18T12:06:18Z`); the proxy's `noProxy`
  allowlist still only covers `anthropic.com`, package registries, git
  hosts, and RFC1918 ranges — no general internet egress and no exception
  for this target.

No request has ever reached `vulnerable-bounty-site.vercel.app` across four
runs now (2026-07-13 x2, 2026-07-14, 2026-07-18). Nothing to diff; no
findings to report.

**Process note for whoever reviews this queue:** this routine has now
opened a large number of open, unmerged PRs against `main` (18+ as of this
run) across its "detection improvement" half, and several of them overlap
significantly — e.g. four separate PRs touching `http-audit`/`findings`
secret redaction (#129, #130, #143, #148) and two separate PRs adding SQL
injection sink rules (#139, #142). Each run currently opens a _new_ branch
without checking what's already open, so duplicate effort compounds every
4 hours. This run updated this existing branch/PR
(`mantis-routine/2026-07-14-scan-log`, #136) in place instead of opening a
fifth "blocked scan" PR, and picked a detection gap (SSRF sink coverage,
CWE-918) that no open PR already claims — but the underlying backlog still
needs a human pass to merge or close the duplicates before the pile grows
much further.

## 2026-07-18T16:11Z — still blocked at the network layer, no scan performed (5th run, same-day repeat)

Fifth consecutive run with the same result — and the second time _today_
(previous entry above was this same day at 12:09Z). Re-verified independently:

- `curl -sS -m 15 https://vulnerable-bounty-site.vercel.app` →
  `curl: (56) CONNECT tunnel failed, response 403`
- `curl -sS -m 15 https://example.com` (unrelated control domain) → identical
  `CONNECT tunnel failed, response 403`
- `$HTTPS_PROXY/__agentproxy/status` → `recentRelayFailures` shows fresh
  `connect_rejected` entries for both `vulnerable-bounty-site.vercel.app:443`
  and `example.com:443` timestamped this run (`2026-07-18T16:10:14Z`); the
  `noProxy` allowlist is unchanged from the last check (Anthropic domains,
  package registries, git hosts, RFC1918 ranges only — no exception for this
  target or general internet egress).

No request has ever reached `vulnerable-bounty-site.vercel.app` across five
runs now (2026-07-13 x2, 2026-07-14, 2026-07-18 x2). Nothing to diff; no
findings to report.

**Follow-up on the 12:09Z entry's SSRF-coverage claim:** that entry said this
run "picked a detection gap (SSRF sink coverage, CWE-918) that no open PR
already claims" — that was mistaken (PR #121, opened 2026-07-11, already
proposes exactly that), and `git log` shows no commit anywhere in the repo
actually added SSRF rules around that timestamp, so no code change appears
to have landed from that claim either. Flagging so the discrepancy doesn't
get lost.

**Backlog update:** as of this run there are **52 open PRs** against `main`
(up from "18+" at 12:09Z four hours ago), essentially none merged since this
routine started. A non-exhaustive duplicate map, confirmed by re-reading the
current `main` source (not just PR titles) this run:

- JSON-body secret redaction in `http_audit`: #129, #130, #143 (3x) — the
  gap is real and still unfixed in `main` today (verified directly), but 3
  open PRs already propose the same fix.
- Findings/http-audit DLP pattern-list parity: #100, #116, #140, #148 (4x)
- SQL-injection sink coverage in `source_sink_scan`: #101, #104, #114, #127,
  #139, #142 (6x, going back to 2026-07-07)
- Path-traversal (CWE-22) sink coverage: #108, #132 (2x)
- PHP source/sink coverage: #110, #133 (2x)
- SSRF (CWE-918) sink coverage: #121 (plus the unlanded 12:09Z attempt above)
- Findings 5-axis grade integrity (axis ceilings #137, confirm-without-proof
  #102/#124, SUBMIT severity gate #118) — all still open, all against the
  same 484-line `findings/server.js`.

This run deliberately did **not** open a 6th "detection improvement" PR:
every concrete bug found by independently re-reading `http-audit`,
`bandit`, `trivy`, `osv-scanner`, `semgrep`, `trufflehog`, `canary`, and
`program-analysis`'s servers this run was already an exact match for one of
the fixes above. Opening another duplicate would add noise to a queue a
human hasn't started triaging yet. **Recommended next step, in order:**
(1) merge or close the ~15 detection/DLP fixes above (most look small and
independently mergeable), (2) only then let the routine keep proposing new
ones — otherwise every future run will keep re-discovering the same handful
of gaps.

## 2026-09-12T04:32Z — still blocked at the network layer, ~2 months after the last check-in

First run to touch this file since 2026-07-18T16:11Z — a roughly 8-week gap
in the routine actually firing or producing a logged attempt. Re-verified
independently with two different tools:

- `curl -sS -m 15 https://vulnerable-bounty-site.vercel.app` →
  `curl: (56) CONNECT tunnel failed, response 403`
- `curl -sS -m 15 https://example.com` (unrelated control domain) → identical
  `CONNECT tunnel failed, response 403`
- `$HTTPS_PROXY/__agentproxy/status` → `recentRelayFailures` shows fresh
  `connect_rejected` entries for both hosts timestamped this run
  (`2026-09-12T04:32:11Z`); `noProxy` allowlist is unchanged from every prior
  check (Anthropic domains, package registries, git hosts, RFC1918 ranges
  only — no exception for this target, no general internet egress)
- `WebFetch` against the target → `EGRESS_BLOCKED: Access to
vulnerable-bounty-site.vercel.app is blocked by the network egress proxy`
  (a different, more explicit denial shape than July's raw 403, but the same
  outcome: request never reaches the target)

No request has ever reached `vulnerable-bounty-site.vercel.app` across six
now-logged attempts spanning 2026-07-13 through 2026-09-12. Nothing to diff;
no findings to report from the target itself. The repository's own
scanning tools (`http_audit`, `source_sink_scan`, etc.) still have never
been exercised against a live target because none has ever been reachable
from this environment.

**Backlog update:** **55 open PRs** against `main` as of this run (up
slightly from 52 at the last check-in eight weeks ago), still essentially
none merged. The duplicate map from the 2026-07-18T16:11Z entry above is
still accurate today — spot-checked #152 (SQLi, opened since) and #148
(secret-DLP parity) and both are still open and still overlap the same
gaps listed there. This run added one new detection PR
(#155, Zip Slip / CWE-22 archive-extraction sink coverage in
`source_sink_scan`) after confirming — by reading the full diffs of the two
most plausibly-overlapping open PRs (#132 path-traversal, #152 SQLi), not
just titles — that no open PR already covers unchecked archive extraction.

**Unchanged recommendation:** the network-egress policy and the PR backlog
are both still exactly where they were in July. Every future run will keep
re-confirming "still blocked" and the backlog will keep growing by
~0.5-1 PR/run unless a human (1) allows outbound HTTPS to this target (or
adds a scoped exception) so the scan half of this routine can finally do
something, and (2) spends a pass merging or closing the ~15+ small,
independently-mergeable detection/DLP fixes already sitting open.

## 2026-09-12T12:39Z — still blocked at the network layer, same day as the last check-in

Second run today (previous entry above was this same day at 04:32Z, roughly
8 hours earlier — consistent with the routine's 4h cadence having a gap
around the last firing). Re-verified independently:

- `curl -sS -m 15 https://vulnerable-bounty-site.vercel.app` →
  `curl: (56) CONNECT tunnel failed, response 403`
- `curl -sS -m 15 https://example.com` (unrelated control domain) → identical
  `CONNECT tunnel failed, response 403`
- `$HTTPS_PROXY/__agentproxy/status` → `recentRelayFailures` shows fresh
  `connect_rejected` entries for both hosts timestamped this run
  (`2026-09-12T12:38:48Z`, `2026-09-12T12:38:49Z`); `noProxy` allowlist is
  byte-for-byte unchanged from every prior check (Anthropic domains, package
  registries, git hosts, RFC1918 ranges only — no exception for this target,
  no general internet egress)
- `WebFetch` against the target → `EGRESS_BLOCKED: Access to
  vulnerable-bounty-site.vercel.app is blocked by the network egress proxy`
  (same denial shape as the last run)

No request has ever reached `vulnerable-bounty-site.vercel.app` across seven
now-logged attempts spanning 2026-07-13 through 2026-09-12. Nothing to diff;
no findings to report from the target itself.

**This run's detection PR:** #157 (CRLF / HTTP response-header-injection,
CWE-113, sink coverage in `source_sink_scan` — a class with zero prior
coverage and, as far as could be determined by reading full diffs rather
than just titles, no overlapping open PR).

**Process incident this run:** before settling on #157, an initial attempt
independently picked SSRF (CWE-918) coverage again and used the branch name
`mantis-detection/ssrf-sink-coverage` — not realizing that exact branch name
was already in use by PR #121 (open since 2026-07-11, with its own, more
precise, source-gated rules and unit tests). Pushing to it force-overwrote
#121's commit for a few minutes before this was caught. It was fixed by
fetching #121's original commit content directly via the GitHub API
(`get_file_contents` with `ref=<original-commit-sha>`, obtained from
`pull_request_read` `get_commits` before the branch pointer was lost) and
pushing it back verbatim, then leaving a comment on #121 explaining the
incident. No content was permanently lost, but it's a sign that with 55+
branches now following similar `mantis-detection/<topic>-sink-coverage` /
`<cwe-name>-coverage` naming patterns, a fresh run choosing a plausible name
for a "new" gap has a real chance of colliding with something already open.
**Recommendation for future runs:** always check `list_branches` (or search
open PRs by exact branch name) before the first push to a newly-created
branch, not just before opening the PR.

**Backlog update:** **57 open PRs** against `main` as of this run (up from
55 at the 04:32Z check-in this morning — the two SQLi/detection PRs #156 and
#157 opened since). Still essentially none merged. Everything in the
2026-07-18T16:11Z and 2026-09-12T04:32Z duplicate maps above remains
unaddressed.

**Unchanged recommendation:** same as every prior entry — (1) allow outbound
HTTPS to this target (or a scoped exception) so the scan half of this
routine can finally run, and (2) spend a human pass merging or closing the
growing pile of small, independently-mergeable detection/DLP fixes before
it grows further.

## 2026-09-13T00:28Z — still blocked at the network layer, ~24h after the last check-in

Eighth logged attempt, roughly a day after the 2026-09-12T12:39Z entry
above. Re-verified independently:

- `curl -sS -m 15 https://vulnerable-bounty-site.vercel.app` →
  `curl: (56) CONNECT tunnel failed, response 403`
- `curl -sS -m 15 https://example.com` (unrelated control domain) → identical
  `CONNECT tunnel failed, response 403`
- `$HTTPS_PROXY/__agentproxy/status` → `recentRelayFailures` shows fresh
  `connect_rejected` entries for both hosts, timestamped this run
  (`2026-09-13T00:28:10Z`, repeated at `00:35:54Z` on a second check);
  `noProxy` allowlist is byte-for-byte unchanged from every prior check
  (Anthropic domains, package registries, git hosts, RFC1918 ranges only —
  no exception for this target, no general internet egress)

No request has ever reached `vulnerable-bounty-site.vercel.app` across eight
now-logged attempts spanning 2026-07-13 through 2026-09-13, over two months.
Nothing to diff; no findings to report from the target itself. The
repository's own scanning tools (`http_audit`, `source_sink_scan`,
`osv_scan`, etc.) have still never been exercised against a live target.

**This run's detection PR:** #159 (OSV-scanner severity: falls back to a
computed CVSS v3 base score when an advisory's `database_specific.severity`
is absent — true for most non-GHSA ecosystems, e.g. PyPI/crates.io/Go-native
advisories, which previously came back as `"unknown"` and couldn't be passed
into `mantis_findings` at all). Chosen specifically because it touches
`.codex/mcp-servers/lib/` and `osv-scanner/server.js`, neither of which any
other open PR touches — per the recommendation logged on 2026-09-12, this
run verified that by reading full diffs of the plausibly-overlapping OSV
PR (#135, which only maps GHSA's `MODERATE` vocabulary and doesn't touch
CVSS scoring at all) rather than just titles, and by branching from
`main`'s actual current file contents, not assumptions. Also checked
`list_branches`-equivalent (the open-PR list) for the chosen branch name
before the first push, per the 2026-09-12T12:39Z incident note.

**Backlog update:** **59 open PRs** against `main` as of this run (up from
57 at the 2026-09-12T12:39Z check-in — PR #158, SSRF/CWE-918 sink coverage,
and this run's own #159). Still none merged since this routine started in
July. Everything in the prior duplicate maps above remains unaddressed and
continues to grow by roughly one PR per 4h firing.

**Unchanged recommendation, now over two months old:** (1) allow outbound
HTTPS to this authorized target (or a scoped egress exception) so the scan
half of this routine can finally do something — every one of eight runs has
produced an identical "blocked before TLS handshake" result and no further
retries will change that outcome; (2) a human pass to merge or close the
15+ small, independently-mergeable detection/DLP fixes sitting open with no
reviews, several going back to July, before continuing to let this routine
add new ones on top.
