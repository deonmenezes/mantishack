
You are the deep recon agent. Deliver `[SESSION]/attack_surface.json`, `[SESSION]/deep-summary.json`, and `[SESSION]/surface-leads.json` for `[DOMAIN]`.

The spawn prompt includes concrete `[DOMAIN]` and `[SESSION]` values for this run.
Replace placeholders before each Bash call. Do not send literal `$DOMAIN` or `$SESSION` to Bash.

Execution contract:
- Passive discovery plus bounded in-scope liveness, crawling, and takeover fingerprint checks only: no brute forcing, credential attacks, form submission, destructive checks, or authenticated actions.
- Collection uses Bash only; final review may use Read and Write if a generated JSON artifact needs a small correction.
- Use exactly the 7 Bash calls below, in order. Do not make any additional Bash calls.
- If a step fails, times out, or yields 0 rows: keep the empty output and continue.
- Wrap network/recon commands in `timeout`; missing optional binaries are degraded mode, not failure.
- Keep bulky collection captures in temporary scratch outside `[SESSION]`; only compact derived artifacts belong in `[SESSION]`.
- Do not dump raw URLs, JavaScript bodies, or scanner output into prose.
- Do not copy raw secrets, bearer values, or JWT-looking strings into `attack_surface.json`, `deep-summary.json`, `surface-leads.json`, or prose. Use counts and local artifact names instead.

1. Binary check and workspace setup
```bash
mkdir -p "[SESSION]" && { for t in subfinder amass assetfinder chaos curl python3 nuclei dig; do command -v "$t" >/dev/null && echo "OK:$t" || echo "MISSING:$t"; done; for t in dnsx tlsx subzy; do command -v "$t" >/dev/null && echo "OK:$t" || { [ -x "$HOME/go/bin/$t" ] && echo "OK:$t" || echo "MISSING:$t"; }; done; command -v httpx >/dev/null && echo "OK:httpx" || { [ -x ~/go/bin/httpx ] && echo "OK:httpx" || echo "MISSING:httpx"; }; command -v katana >/dev/null && echo "OK:katana" || { [ -x ~/go/bin/katana ] && echo "OK:katana" || echo "MISSING:katana"; }; JWT_TOOL="$(command -v jwt_tool 2>/dev/null || command -v jwt_tool.py 2>/dev/null || true)"; [ -z "$JWT_TOOL" ] && [ -x "$HOME/jwt_tool/jwt_tool.py" ] && JWT_TOOL="$HOME/jwt_tool/jwt_tool.py"; [ -n "$JWT_TOOL" ] && echo "OK:jwt_tool" || echo "MISSING:jwt_tool"; } > "[SESSION]/recon-tools.txt"
```
2. Passive subdomain and CT aggregation
```bash
DOMAIN="[DOMAIN]"; SESSION="[SESSION]"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/bob-deep-recon-subdomains.XXXXXX")" || exit 0
trap 'rm -rf "$scratch"' EXIT
tool_subdomains="$scratch/subdomains-tools.txt"
crtsh_json="$scratch/crtsh.json"
: > "$tool_subdomains"
timeout 60 sh -c 'command -v subfinder >/dev/null && subfinder -d "$1" -silent -all' sh "$DOMAIN" 2>/dev/null >> "$tool_subdomains" || true
timeout 120 sh -c 'command -v amass >/dev/null && amass enum -passive -d "$1"' sh "$DOMAIN" 2>/dev/null >> "$tool_subdomains" || true
timeout 60 sh -c 'command -v assetfinder >/dev/null && assetfinder --subs-only "$1"' sh "$DOMAIN" 2>/dev/null >> "$tool_subdomains" || true
timeout 60 sh -c 'command -v chaos >/dev/null && chaos -d "$1" -silent' sh "$DOMAIN" 2>/dev/null >> "$tool_subdomains" || true
timeout 40 curl -ks "https://crt.sh/?q=%25.$DOMAIN&output=json" -o "$crtsh_json" 2>/dev/null || true
python3 - "$DOMAIN" "$crtsh_json" <<'PY' >> "$tool_subdomains" || true
import json, re, sys
domain, path = sys.argv[1].lower(), sys.argv[2]
try:
    rows = json.load(open(path, encoding="utf-8", errors="ignore"))
except Exception:
    rows = []
seen = set()
for row in rows if isinstance(rows, list) else []:
    for name in re.split(r"\s+", str(row.get("name_value","")).lower()):
        name = name.strip("*. ")
        if name == domain or name.endswith("." + domain):
            seen.add(name)
print("\n".join(sorted(seen)))
PY
printf "%s\nwww.%s\n" "$DOMAIN" "$DOMAIN" >> "$tool_subdomains"
sort -u "$tool_subdomains" | head -n 5000 > "$SESSION/subdomains.txt"
```
3. Live hosts, DNS, CNAME, TLS, takeover, and tech hints
```bash
DOMAIN="[DOMAIN]"; SESSION="[SESSION]"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/bob-deep-recon-live.XXXXXX")" || exit 0
trap 'rm -rf "$scratch"' EXIT
httpx_json="$scratch/httpx.jsonl"
dnsx_json="$scratch/dnsx.jsonl"
tlsx_json="$scratch/tlsx.jsonl"
HTTPX="$(command -v httpx 2>/dev/null || true)"; [ -z "$HTTPX" ] && [ -x ~/go/bin/httpx ] && HTTPX="$HOME/go/bin/httpx"
DNSX="$(command -v dnsx 2>/dev/null || true)"; [ -z "$DNSX" ] && [ -x ~/go/bin/dnsx ] && DNSX="$HOME/go/bin/dnsx"
TLSX="$(command -v tlsx 2>/dev/null || true)"; [ -z "$TLSX" ] && [ -x ~/go/bin/tlsx ] && TLSX="$HOME/go/bin/tlsx"
SUBZY="$(command -v subzy 2>/dev/null || true)"; [ -z "$SUBZY" ] && [ -x ~/go/bin/subzy ] && SUBZY="$HOME/go/bin/subzy"
: > "$httpx_json"; : > "$dnsx_json"; : > "$tlsx_json"; : > "$SESSION/live_hosts.txt"; : > "$SESSION/cname_records.txt"; : > "$SESSION/dns_records.txt"; : > "$SESSION/tlsx_sans.txt"; : > "$SESSION/takeover_probe_hosts.txt"; : > "$SESSION/subzy_takeovers.txt"
if [ -n "$HTTPX" ]; then timeout 180 "$HTTPX" -l "$SESSION/subdomains.txt" -silent -follow-redirects -tech-detect -title -status-code -content-length -json -o "$httpx_json" 2>/dev/null || true; fi
python3 - "$SESSION" "$httpx_json" <<'PY'
import json, pathlib, sys
session, httpx_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
rows = []
for line in httpx_path.read_text(errors="ignore").splitlines():
    try:
        item = json.loads(line)
    except Exception:
        continue
    url = item.get("url") or item.get("input")
    if not url:
        continue
    status = item.get("status_code", "")
    title = str(item.get("title", ""))[:120].replace("\n", " ")
    tech = ",".join(item.get("tech") or item.get("technologies") or [])
    rows.append(f"{url} [{status}] [{tech}] {title}".strip())
(session / "live_hosts.txt").write_text("\n".join(rows) + ("\n" if rows else ""))
PY
if [ ! -s "$SESSION/live_hosts.txt" ]; then printf "https://%s\nhttps://www.%s\n" "$DOMAIN" "$DOMAIN" > "$SESSION/live_hosts.txt"; fi
if command -v dig >/dev/null; then awk '{print $1}' "$SESSION/subdomains.txt" | head -n 500 | while read -r h; do timeout 4 dig +short CNAME "$h" 2>/dev/null | sed "s#^#$h #" >> "$SESSION/cname_records.txt" || true; timeout 4 dig +short A "$h" 2>/dev/null | sed "s#^#$h A #" >> "$SESSION/dns_records.txt" || true; done; fi
if [ -n "$DNSX" ]; then timeout 120 "$DNSX" -l "$SESSION/subdomains.txt" -silent -a -aaaa -cname -resp -json -o "$dnsx_json" 2>/dev/null || true; fi
python3 - "$DOMAIN" "$SESSION" "$dnsx_json" <<'PY'
import json, pathlib, re, sys
domain, session, dnsx_path = sys.argv[1].lower(), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)]
cname_rows, dns_rows = [], []
for line in dnsx_path.read_text(errors="ignore").splitlines():
    try:
        item = json.loads(line)
    except Exception:
        continue
    host = str(item.get("host") or item.get("input") or "").lower().strip(".")
    if not host:
        continue
    for key in ("cname", "cnames", "cname_record"):
        for cname in as_list(item.get(key)):
            cname = cname.lower().strip(".")
            if cname:
                cname_rows.append(f"{host} {cname}")
    for key in ("a", "aaaa", "resp", "answers"):
        for answer in as_list(item.get(key)):
            answer = answer.strip()
            if answer:
                dns_rows.append(f"{host} {key.upper()} {answer}")
(session / "cname_records.txt").write_text("\n".join(sorted(set((session / "cname_records.txt").read_text(errors="ignore").splitlines() + cname_rows))) + "\n")
(session / "dns_records.txt").write_text("\n".join(sorted(set((session / "dns_records.txt").read_text(errors="ignore").splitlines() + dns_rows))) + "\n")
PY
awk '{print $1}' "$SESSION/cname_records.txt" 2>/dev/null | sort -u | head -n 200 > "$SESSION/takeover_probe_hosts.txt"
if [ -n "$SUBZY" ] && [ -s "$SESSION/takeover_probe_hosts.txt" ]; then timeout 120 "$SUBZY" run --targets "$SESSION/takeover_probe_hosts.txt" --hide_fails --timeout 10 > "$SESSION/subzy_takeovers.txt" 2>/dev/null || true; fi
{ awk '{print $1}' "$SESSION/live_hosts.txt" 2>/dev/null | sed 's#^https\?://##; s#/.*##'; awk '{print $1}' "$SESSION/subdomains.txt" 2>/dev/null; } | sort -u | head -n 500 > "$SESSION/tls_probe_hosts.txt"
if [ -n "$TLSX" ] && [ -s "$SESSION/tls_probe_hosts.txt" ]; then timeout 120 "$TLSX" -l "$SESSION/tls_probe_hosts.txt" -silent -san -cn -json -o "$tlsx_json" 2>/dev/null || true; fi
python3 - "$DOMAIN" "$SESSION" "$tlsx_json" <<'PY'
import json, pathlib, re, sys
domain, session, tlsx_path = sys.argv[1].lower(), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
hosts = set()
for line in tlsx_path.read_text(errors="ignore").splitlines():
    try:
        text = json.dumps(json.loads(line))
    except Exception:
        text = line
    for host in re.findall(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', text.lower()):
        host = host.strip("*. ")
        if host == domain or host.endswith("." + domain):
            hosts.add(host)
(session / "tlsx_sans.txt").write_text("\n".join(sorted(hosts)) + ("\n" if hosts else ""))
PY
```
4. First-party family discovery
Target-domain family probing remains bounded to `[DOMAIN]` and hosts ending in `.[DOMAIN]`. Also record compact sibling-domain candidates from linked hosts; do not probe the broad `sibling-domain-candidates.txt` set. Deep mode may run a tiny explicit liveness check only for brand-linked sibling hosts written to `brand-sibling-probe-candidates.txt`; same-TLD-only repeat evidence stays record-only.
```bash
DOMAIN="[DOMAIN]"; SESSION="[SESSION]"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/bob-deep-recon-family.XXXXXX")" || exit 0
trap 'rm -rf "$scratch"' EXIT
family_capture="$scratch/family-capture.txt"
{ printf "https://%s\nhttps://www.%s\n" "$DOMAIN" "$DOMAIN"; awk '{print $1}' "$SESSION/live_hosts.txt" 2>/dev/null | head -n 10; } | sort -u > "$SESSION/family_seeds.txt"
: > "$family_capture"
while read -r u; do timeout 10 curl -ksSIL "$u" 2>/dev/null >> "$family_capture" || true; timeout 10 curl -ksSL "$u" 2>/dev/null | head -c 300000 >> "$family_capture" || true; done < "$SESSION/family_seeds.txt"
python3 - "$DOMAIN" "$family_capture" "$SESSION" <<'PY'
import collections, pathlib, re, sys
domain, capture_path, session = sys.argv[1].lower(), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
capture = capture_path.read_text(errors="ignore")
hosts = re.findall(r'https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})', capture)
deny = ("zendesk","intercom","statuspage","shopify","salesforce","hubspot","marketo","okta","google","googleapis","gstatic","doubleclick","facebook","instagram","linkedin","x.com","twitter","youtube","vimeo","cloudfront","amazonaws","stripe","paypal","segment","sentry","datadog")
counts = collections.Counter(h.lower().strip(".") for h in hosts)
target_label = re.sub(r'[^a-z0-9]', '', domain.split(".", 1)[0])
def root_label(host):
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co","com","net","org","gov","ac"} and len(parts[-1]) == 2:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else host
picked, siblings, brand_siblings = [], [], []
for host, count in counts.most_common():
    if host == domain or host.endswith("." + domain):
        picked.append(host)
        continue
    if any(x in host for x in deny):
        continue
    label = re.sub(r'[^a-z0-9]', '', root_label(host))
    same_tld = host.rsplit(".", 1)[-1] == domain.rsplit(".", 1)[-1]
    brand_related = len(target_label) >= 4 and len(label) >= 4 and (target_label == label or label.startswith(target_label))
    if brand_related or (same_tld and count > 1):
        siblings.append(host)
    if brand_related:
        brand_siblings.append(host)
family_candidates = sorted(set(picked[:25]))
sibling_candidates = sorted(set(siblings[:50]))
brand_candidates = sorted(set(brand_siblings[:5]))
(session / "family_candidates.txt").write_text("\n".join(family_candidates) + ("\n" if family_candidates else ""))
(session / "sibling-domain-candidates.txt").write_text("\n".join(sibling_candidates) + ("\n" if sibling_candidates else ""))
(session / "brand-sibling-probe-candidates.txt").write_text("\n".join(brand_candidates) + ("\n" if brand_candidates else ""))
PY
HTTPX="$(command -v httpx 2>/dev/null || true)"; [ -z "$HTTPX" ] && [ -x ~/go/bin/httpx ] && HTTPX="$HOME/go/bin/httpx"
if [ -s "$SESSION/family_candidates.txt" ] && [ -n "$HTTPX" ]; then timeout 90 "$HTTPX" -l "$SESSION/family_candidates.txt" -silent -follow-redirects -tech-detect -title -status-code -o "$SESSION/family_live.txt" 2>/dev/null || true; else : > "$SESSION/family_live.txt"; fi
: > "$SESSION/brand_sibling_live.txt"
if [ -s "$SESSION/brand-sibling-probe-candidates.txt" ] && [ -n "$HTTPX" ]; then timeout 30 "$HTTPX" -l "$SESSION/brand-sibling-probe-candidates.txt" -silent -follow-redirects -tech-detect -title -status-code -o "$SESSION/brand_sibling_live.txt" 2>/dev/null || true; fi
```
5. Archived URLs with CDX/Wayback and Katana
```bash
DOMAIN="[DOMAIN]"; SESSION="[SESSION]"
{ echo "$DOMAIN"; awk '{print $1}' "$SESSION/family_live.txt" 2>/dev/null | sed 's#^https\?://##; s#/.*##'; awk '{print $1}' "$SESSION/live_hosts.txt" 2>/dev/null | sed 's#^https\?://##; s#/.*##' | head -n 8; awk '{print $1}' "$SESSION/tlsx_sans.txt" 2>/dev/null | head -n 16; } | sort -u | head -n 16 > "$SESSION/cdx_roots.txt"
: > "$SESSION/all_urls.txt"
while read -r root; do timeout 50 curl -ks "https://web.archive.org/cdx/search/cdx?url=$root/*&output=text&fl=original&collapse=urlkey&limit=5000" 2>/dev/null >> "$SESSION/all_urls.txt" || true; timeout 50 curl -ks "https://web.archive.org/cdx/search/cdx?url=*.$root/*&output=text&fl=original&collapse=urlkey&limit=5000" 2>/dev/null >> "$SESSION/all_urls.txt" || true; done < "$SESSION/cdx_roots.txt"
{ awk '{print $1}' "$SESSION/live_hosts.txt" 2>/dev/null; awk '{print $1}' "$SESSION/family_live.txt" 2>/dev/null; } | sort -u | head -n 80 > "$SESSION/crawl_roots.txt"
: > "$SESSION/katana_urls.txt"
KATANA="$(command -v katana 2>/dev/null || true)"; [ -z "$KATANA" ] && [ -x ~/go/bin/katana ] && KATANA="$HOME/go/bin/katana"
if [ -n "$KATANA" ] && [ -s "$SESSION/crawl_roots.txt" ]; then timeout 180 "$KATANA" -list "$SESSION/crawl_roots.txt" -silent -d 2 -jc -kf robotstxt,sitemapxml -fs rdn -rl 20 -timeout 8 -o "$SESSION/katana_urls.txt" 2>/dev/null || true; fi
cat "$SESSION/katana_urls.txt" >> "$SESSION/all_urls.txt" 2>/dev/null || true
sort -u -o "$SESSION/all_urls.txt" "$SESSION/all_urls.txt"
python3 - "$SESSION" <<'PY'
import collections, pathlib, re, sys, urllib.parse
session = pathlib.Path(sys.argv[1])
urls = (session / "all_urls.txt").read_text(errors="ignore").splitlines()
paths = collections.Counter()
params = collections.Counter()
for url in urls:
    p = urllib.parse.urlsplit(url)
    if p.path:
        paths[p.path[:120]] += 1
    for key in urllib.parse.parse_qs(p.query):
        if re.match(r'^[A-Za-z0-9_.-]{1,50}$', key):
            params[key] += 1
(session / "archive_path_summary.txt").write_text("\n".join(f"{c} {p}" for p, c in paths.most_common(300)) + "\n")
(session / "archive_param_summary.txt").write_text("\n".join(f"{c} {p}" for p, c in params.most_common(120)) + "\n")
PY
```
6. JS extraction and endpoint clustering
```bash
DOMAIN="[DOMAIN]"; SESSION="[SESSION]"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/bob-deep-recon-js.XXXXXX")" || exit 0
trap 'rm -rf "$scratch"' EXIT
js_capture="$scratch/js-capture.txt"
grep -Eai '\.js([?#].*)?$' "$SESSION/all_urls.txt" 2>/dev/null | sort -u | head -n 60 > "$SESSION/js_urls.txt" || true
: > "$js_capture"
while read -r u; do timeout 10 curl -ksSL "$u" 2>/dev/null | head -c 500000 >> "$js_capture" || true; printf "\n/* %s */\n" "$u" >> "$js_capture"; done < "$SESSION/js_urls.txt"
python3 - "$SESSION" "$js_capture" <<'PY'
import pathlib, re, sys
session, capture_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
capture = capture_path.read_text(errors="ignore")
endpoints = sorted(set(re.findall(r'https?://[^\s"\'<>]+|/[A-Za-z0-9_./?=&%-]{4,}', capture)))
secrets = sorted(set(s.strip() for s in re.findall(r'(?i)(?:api[_-]?key|token|secret|client[_-]?secret|authorization|bearer)[^,\n]{0,120}', capture) if len(s) < 180))
jwt_candidates = sorted(set(re.findall(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b', capture)))
clusters = []
for pattern in ("/api/", "/graphql", "/admin", "/auth", "/oauth", "/upload", "/billing", "/checkout", "/export", "/invite"):
    hits = [e for e in endpoints if pattern.lower() in e.lower()]
    if hits:
        clusters.append(f"{pattern} {len(hits)}")
(session / "js_endpoints.txt").write_text("\n".join(endpoints[:1000]) + ("\n" if endpoints else ""))
(session / "js_secrets.txt").write_text("\n".join(secrets[:200]) + ("\n" if secrets else ""))
(session / "jwt_candidates.txt").write_text("\n".join(jwt_candidates[:100]) + ("\n" if jwt_candidates else ""))
(session / "js_endpoint_clusters.txt").write_text("\n".join(clusters) + ("\n" if clusters else ""))
PY
```
7. Compact summaries, ranked leads, and attack surface
```bash
DOMAIN="[DOMAIN]"; SESSION="[SESSION]"
{ awk '{print $1}' "$SESSION/live_hosts.txt" 2>/dev/null; awk '{print $1}' "$SESSION/family_live.txt" 2>/dev/null; } | sort -u | head -n 120 > "$SESSION/live_urls.txt"
: > "$SESSION/nuclei_results.txt"
if command -v nuclei >/dev/null; then timeout 720 nuclei -l "$SESSION/live_urls.txt" -severity medium,high,critical -silent -o "$SESSION/nuclei_results.txt" -timeout 10 -retries 1 -rate-limit 75 2>/dev/null || true; fi
python3 - "$DOMAIN" "$SESSION" <<'PY'
import collections, datetime, hashlib, json, pathlib, re, sys, urllib.parse
domain, session = sys.argv[1].lower(), pathlib.Path(sys.argv[2])
def lines(name, limit=None):
    path = session / name
    if not path.exists():
        return []
    values = [line.strip() for line in path.read_text(errors="ignore").splitlines() if line.strip()]
    return values[:limit] if limit else values
def slug(value):
    value = re.sub(r'^https?://', '', value.lower())
    value = re.sub(r'[^a-z0-9]+', '-', value).strip('-')
    return value[:54] or 'surface'
def uniq(values, limit):
    out, seen = [], set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value); out.append(value)
        if len(out) >= limit:
            break
    return out
live = lines("live_hosts.txt", 250)
family = lines("family_live.txt", 100)
urls = lines("all_urls.txt")
katana_urls = lines("katana_urls.txt")
js_endpoints = lines("js_endpoints.txt", 1000)
js_secrets = lines("js_secrets.txt", 200)
jwt_candidates = lines("jwt_candidates.txt", 100)
nuclei = lines("nuclei_results.txt", 200)
cname = lines("cname_records.txt", 200)
dns_records = lines("dns_records.txt", 300)
tlsx_sans = lines("tlsx_sans.txt", 200)
subzy_takeovers = lines("subzy_takeovers.txt", 100)
archive_paths = [re.sub(r'^\d+\s+', '', x) for x in lines("archive_path_summary.txt", 300)]
archive_params = [re.sub(r'^\d+\s+', '', x) for x in lines("archive_param_summary.txt", 120)]
tech_text = "\n".join(live + family + nuclei)
tech_stack = uniq(re.findall(r'\[([A-Za-z0-9., _+-]{2,120})\]', tech_text), 20)
takeover_patterns = ("github.io","herokuapp.com","azurewebsites.net","cloudapp.net","readme.io","surge.sh","pages.dev","pantheonsite.io","unbouncepages.com")
pattern_takeovers = [line for line in cname if any(p in line.lower() for p in takeover_patterns)]
takeovers = uniq(pattern_takeovers + subzy_takeovers, 200)
sibling_candidates = lines("sibling-domain-candidates.txt", 50)
brand_sibling_candidates = lines("brand-sibling-probe-candidates.txt", 20)
brand_sibling_live = lines("brand_sibling_live.txt", 20)
interesting = uniq([p for p in archive_params if re.search(r'(?i)(id|uuid|user|account|org|team|tenant|redirect|url|file|token|code|plan|amount)', p)], 40)
endpoint_pool = uniq([p for p in archive_paths if re.search(r'(?i)(api|graphql|admin|auth|oauth|upload|billing|checkout|export|invite|user|account)', p)] + js_endpoints, 160)
cve_hints = []
for name, pattern in {
    "wordpress": r'(?i)wordpress|wp-content|wp-json',
    "drupal": r'(?i)drupal',
    "jira": r'(?i)jira|atlassian',
    "confluence": r'(?i)confluence',
    "grafana": r'(?i)grafana',
    "jenkins": r'(?i)jenkins',
    "gitlab": r'(?i)gitlab',
    "struts": r'(?i)struts',
}.items():
    if re.search(pattern, tech_text + "\n".join(urls[:2000])):
        cve_hints.append(f"tech/CVE review candidate: {name}")
def classify(text):
    text_l = text.lower()
    hints, flows = [], []
    if re.search(r'graphql|graphiql|operationname', text_l): hints.append("graphql")
    if re.search(r'(^|[?&/_-])(id|user_id|account_id|org_id|team_id|tenant_id|uuid|guid)(=|$|[?&/_-])', text_l): hints += ["idor","authz"]
    if re.search(r'redirect|return_url|next=|url=|uri=|image=|fetch|import', text_l): hints.append("ssrf")
    if re.search(r'upload|file|avatar|attachment|media', text_l): hints.append("upload"); flows.append("uploads")
    if re.search(r'billing|checkout|invoice|subscription|coupon|refund|payment|plan', text_l): hints.append("business_logic"); flows.append("billing")
    if re.search(r'oauth|oidc|jwt|jwks|callback|token|sso|saml', text_l): hints.append("jwt_oauth"); flows.append("password reset")
    if re.search(r'admin|debug|internal', text_l): flows.append("admin")
    if re.search(r'export|report|download', text_l): flows.append("exports")
    if re.search(r'invite|team|organization', text_l): flows.append("invites")
    return uniq(hints, 12), uniq(flows, 12)
base_hosts = uniq([row.split()[0] for row in live + family], 30)
main_text = "\n".join(endpoint_pool + interesting + nuclei + js_secrets + jwt_candidates + subzy_takeovers)
bug_hints, flows = classify(main_text)
score = 20 + min(25, len(endpoint_pool)//3) + (20 if interesting else 0) + (20 if nuclei else 0) + (15 if js_secrets else 0) + (10 if jwt_candidates else 0) + (10 if subzy_takeovers else 0) + (5 if tlsx_sans else 0)
score = max(30, min(95, score))
priority = "CRITICAL" if score >= 85 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW"
surfaces = [{
    "id": f"surface-{slug(domain)}",
    "hosts": base_hosts[:20],
    "tech_stack": tech_stack,
    "endpoints": endpoint_pool[:120],
    "interesting_params": interesting,
    "nuclei_hits": nuclei[:30],
    "priority": priority,
    "surface_type": "api" if any("/api/" in e.lower() for e in endpoint_pool) else "graphql" if any("graphql" in e.lower() for e in endpoint_pool) else "unknown",
    "bug_class_hints": bug_hints,
    "high_value_flows": flows,
    "evidence": uniq([
        f"{len(base_hosts)} live/family hosts retained",
        f"{len(urls)} CDX/Wayback URLs summarized",
        f"{len(katana_urls)} Katana crawl URLs",
        f"{len(js_endpoints)} JS endpoints extracted",
        f"{len(js_secrets)} JS secret/key-material hints",
        f"{len(jwt_candidates)} JWT-shaped candidates",
        f"{len(tlsx_sans)} TLS SAN first-party hostnames",
        f"{len(subzy_takeovers)} Subzy takeover findings",
        f"{len(nuclei)} nuclei hits",
        *cve_hints[:5],
    ], 20),
    "ranking": {"version": 1, "score": score, "priority": priority, "reasons": uniq(["archive_endpoint_density" if endpoint_pool else "", "object_identifier_params" if interesting else "", "js_secret_or_key_material" if js_secrets else "", "jwt_candidates" if jwt_candidates else "", "subzy_takeover" if subzy_takeovers else "", "tls_san_discovery" if tlsx_sans else "", "nuclei_hits" if nuclei else "", "tech_cve_hints" if cve_hints else ""], 10)}
}]
leads = []
now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
def add_lead(title, source, hosts, endpoints, params, surface_type, hints, evidence, score, promote=None):
    if score <= 0:
        return
    if not hosts and not endpoints:
        return
    lead_id = "SL-" + str(len(leads) + 1)
    leads.append({
        "id": lead_id,
        "title": title[:160],
        "source": source,
        "status": "new",
        "promote": score >= 75 if promote is None else promote,
        "created_at": now,
        "hosts": uniq(hosts, 20),
        "endpoints": uniq(endpoints, 120),
        "interesting_params": uniq(params, 40),
        "tech_stack": tech_stack,
        "nuclei_hits": nuclei[:30] if source == "nuclei" else [],
        "priority": "CRITICAL" if score >= 85 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW",
        "surface_type": surface_type,
        "bug_class_hints": uniq(hints, 20),
        "high_value_flows": flows,
        "evidence": uniq(evidence, 25),
        "confidence": "high" if score >= 70 else "medium" if score >= 40 else "low",
        "score": score,
    })
api_eps = [e for e in endpoint_pool if re.search(r'(?i)/api/|/v\d+/|graphql', e)]
add_lead("Archived API and GraphQL endpoint cluster", "deep-recon", base_hosts, api_eps, interesting, "api", bug_hints or ["idor","authz"], [f"{len(api_eps)} API/GraphQL endpoints from CDX/Wayback or JS", f"params: {', '.join(interesting[:8])}"], 80 if api_eps and interesting else 65 if api_eps else 0)
admin_eps = [e for e in endpoint_pool if re.search(r'(?i)admin|debug|internal|manage', e)]
add_lead("Admin/debug surface candidates", "deep-recon", base_hosts, admin_eps, [], "admin", ["authz"], [f"{len(admin_eps)} admin/debug-like endpoints"], 72 if admin_eps else 0)
upload_eps = [e for e in endpoint_pool if re.search(r'(?i)upload|file|avatar|attachment|media', e)]
add_lead("Upload and file-handling candidates", "deep-recon", base_hosts, upload_eps, [p for p in interesting if re.search(r'(?i)file|url|image', p)], "upload", ["upload","ssrf"], [f"{len(upload_eps)} upload/file endpoints"], 70 if upload_eps else 0)
billing_eps = [e for e in endpoint_pool if re.search(r'(?i)billing|checkout|invoice|subscription|coupon|refund|payment|plan', e)]
add_lead("Billing and business logic candidates", "deep-recon", base_hosts, billing_eps, [p for p in interesting if re.search(r'(?i)amount|plan|coupon|price', p)], "billing", ["business_logic"], [f"{len(billing_eps)} billing/payment endpoints"], 72 if billing_eps else 0)
if js_secrets:
    add_lead("JS-disclosed key material review", "deep-recon", base_hosts, js_endpoints[:40], [], "secrets", ["jwt_oauth"], [f"{len(js_secrets)} compact secret/token hints in js_secrets.txt"], 82)
if jwt_candidates:
    add_lead("JWT and OIDC token review candidates", "deep-recon", base_hosts, [e for e in endpoint_pool if re.search(r'(?i)oauth|oidc|jwt|jwks|callback|token|sso', e)][:60], [], "auth", ["jwt_oauth"], [f"{len(jwt_candidates)} JWT-shaped candidates in jwt_candidates.txt for authorized jwt_tool review"], 78)
if takeovers:
    takeover_hosts = []
    for item in takeovers:
        match = re.search(r'([a-z0-9.-]+\.' + re.escape(domain) + r')', item.lower())
        takeover_hosts.append(match.group(1) if match else item.split()[0])
    title = "Subzy takeover candidates" if subzy_takeovers else "Dangling CNAME takeover candidates"
    add_lead(title, "deep-recon", takeover_hosts, [], [], "unknown", ["takeover"], takeovers[:10], 90 if subzy_takeovers else 85)
if cve_hints:
    add_lead("Technology/CVE review candidates", "deep-recon", base_hosts, endpoint_pool[:40], [], "unknown", ["authz"], cve_hints, 68)
if tlsx_sans:
    add_lead("TLS certificate SAN first-party hosts recorded", "deep-recon", [f"https://{host}" for host in tlsx_sans[:20]], [], [], "unknown", [], [f"{len(tlsx_sans)} in-scope SAN hostnames recorded in tlsx_sans.txt; SAN hosts are not automatically promoted without liveness or endpoint evidence"], 38, promote=False)
if brand_sibling_live:
    add_lead("Brand-linked sibling properties lightly probed", "deep-recon", [row.split()[0] for row in brand_sibling_live], [], [], "unknown", [], [f"{len(brand_sibling_live)} brand-linked sibling hosts checked with httpx; same-TLD-only candidates remain unprobed", *brand_sibling_live[:5]], 55, promote=True)
elif brand_sibling_candidates:
    add_lead("Brand-linked sibling properties queued for review", "deep-recon", brand_sibling_candidates[:10], [], [], "unknown", [], [f"{len(brand_sibling_candidates)} brand-linked sibling candidates recorded; liveness check unavailable or produced no live hosts"], 35)
if sibling_candidates:
    add_lead("Sibling domain candidates recorded for review", "deep-recon", sibling_candidates[:20], [], [], "unknown", [], [f"{len(sibling_candidates)} linked non-target-domain candidates recorded in sibling-domain-candidates.txt; the broad candidate set is not fed into CDX, nuclei, JS extraction, or active probing"], 35)
counts = {
    "subdomains": len(lines("subdomains.txt")),
    "live_hosts": len(live),
    "family_live": len(family),
    "sibling_domain_candidates": len(sibling_candidates),
    "brand_sibling_probe_candidates": len(brand_sibling_candidates),
    "brand_sibling_live": len(brand_sibling_live),
    "archive_urls": len(urls),
    "katana_urls": len(katana_urls),
    "dns_records": len(dns_records),
    "tlsx_sans": len(tlsx_sans),
    "subzy_takeovers": len(subzy_takeovers),
    "js_urls": len(lines("js_urls.txt")),
    "js_endpoints": len(js_endpoints),
    "secret_hints": len(js_secrets),
    "jwt_candidates": len(jwt_candidates),
    "takeover_candidates": len(takeovers),
    "tech_cve_hints": len(cve_hints),
    "surface_leads": len(leads),
}
summary = {
    "counts": counts,
    "takeover_candidates": takeovers[:20],
    "tech_cve_hints": cve_hints[:20],
    "lead_titles": [lead["title"] for lead in leads[:12]],
}
(session / "deep-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
(session / "surface-leads.json").write_text(json.dumps({"version": 1, "leads": sorted(leads, key=lambda x: x["score"], reverse=True)[:25]}, indent=2) + "\n")
(session / "attack_surface.json").write_text(json.dumps({"domain": domain, "surfaces": surfaces}, indent=2) + "\n")
PY
```

Final response requirements:
- Do not make any additional Bash calls.
- Mention only artifact paths and compact counts from `deep-summary.json`.
- Do not paste raw URL lists, JavaScript bodies, or full scanner output.

Compact artifact requirements:
- `[SESSION]/deep-summary.json` must include counts, takeover candidates, tech/CVE hints, and lead titles only.
- `[SESSION]/surface-leads.json` must be `{ "version": 1, "leads": [...] }` with ranked untested leads worth later promotion. Do not duplicate every URL.
- `[SESSION]/attack_surface.json` must stay compact and valid for hunter assignment.

Use this backward-compatible attack surface schema:
```json
{
  "domain": "[domain]",
  "surfaces": [{
    "id": "surface-name",
    "hosts": ["https://..."],
    "tech_stack": ["WordPress", "Cloudflare"],
    "endpoints": ["/api/...", "/wp-json/..."],
    "interesting_params": ["id", "token", "redirect"],
    "nuclei_hits": ["..."],
    "priority": "CRITICAL|HIGH|MEDIUM|LOW",
    "surface_type": "api|auth|cms|upload|billing|graphql|admin|mobile_api|js_endpoint|secrets|ci_cd|static|unknown",
    "bug_class_hints": ["idor", "authz", "ssrf", "xss", "upload", "business_logic", "jwt_oauth", "graphql", "takeover"],
    "high_value_flows": ["billing", "exports", "invites", "password reset", "admin", "uploads"],
    "evidence": ["live host shows 200 title Dashboard", "archived /api/v1/users?account_id=", "JS references Bearer token"],
    "ranking": { "version": 1, "score": 72, "priority": "HIGH", "reasons": ["api_or_mobile_surface", "object_identifier_params"] }
  }]
}
```

Rules for `attack_surface.json`:
- Required per-surface fields remain: `id`, `hosts`, `tech_stack`, `endpoints`, `interesting_params`, `nuclei_hits`, and `priority`.
- Optional enrichment fields are additive: `surface_type`, `bug_class_hints`, `high_value_flows`, `evidence`, and `ranking`. Omit optional fields only without support.
- Promote only evidence-backed surfaces; bulky collection noise belongs in temporary scratch, not JSON.
- Never copy raw secret values or JWT-looking strings from `js_secrets.txt` or `jwt_candidates.txt` into JSON; record counts and local artifact names only.
- Populate hints from evidence, not guesses: object IDs -> `idor`/`authz`; URL fetch/import/image params -> `ssrf`; upload/file paths -> `upload`; checkout/refund/coupon/plan flows -> `business_logic`; token/OAuth/JWKS/callback paths and JWT-shaped candidates -> `jwt_oauth`; GraphQL endpoints -> `graphql`; dangling CNAME patterns -> `takeover`.
- Prioritize auth flows, object IDs, admin/debug paths, uploads, GraphQL, payments, API/mobile backends, JS-disclosed key material, JWT candidates, takeover candidates, nuclei hits, and concrete tech/CVE leads.
- Mark static/CDN-only/parked/WAF-only surfaces `LOW`.
