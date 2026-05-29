"""Discover a security/contact email address for a disclosure target.

Resolution order (first hit wins):

1. ``--to`` override supplied by the operator.
2. RFC 9116 ``/.well-known/security.txt`` (and legacy ``/security.txt``)
   ``Contact:`` field — the intended security-disclosure channel.
3. Scraping a small fixed set of pages on the target host (``/security``,
   ``/contact``, home, ``/about``) for ``mailto:`` links and bare addresses.
4. For a local-path target: repo metadata (``SECURITY.md``, an in-repo
   ``security.txt``, or a ``package.json`` author email).

Stdlib-only (``urllib``) so this works under the base interpreter as well as
the project venv. ``bs4`` is used opportunistically when importable but is not
required. The network layer is injectable (``fetcher=``) so discovery is unit
testable offline.

SSRF posture: only ``http``/``https`` is fetched, only on the
operator-specified (authorized) target host, only a fixed path set, with a
timeout and a response size cap. **Scraped URLs are never followed** — addresses
are extracted from returned HTML but no link in it is requested. That bounds the
fetch surface to the target the operator named.
"""
from __future__ import annotations

import json
import re
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from urllib import request as _urlrequest
from urllib.error import URLError
from urllib.parse import urlparse

# Email matcher. Conservative; candidates are post-filtered to drop asset
# filenames that look like addresses (e.g. ``logo@2x.png``).
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Strip a trailing ``mailto:`` query string and HTML entities.
_MAILTO_PREFIX = "mailto:"

# TLD-position tokens that mean "this is a filename, not an email".
_ASSET_TLDS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "tiff",
    "css", "js", "mjs", "json", "map", "woff", "woff2", "ttf", "eot",
    "mp4", "webm", "mp3", "pdf", "zip", "gz",
}

# Third-party vendor / CDN / analytics domains that frequently appear in page
# source but are never the site's own security contact. Dropped from candidates.
# (RFC 2606 example.* are intentionally NOT here — they never appear as real
# targets, and excluding them only breaks legitimate testing.)
_JUNK_DOMAINS = {
    "sentry.io", "sentry-next.wixpress.com", "wixpress.com", "schema.org",
    "w3.org", "googleapis.com", "gstatic.com", "cloudflare.com",
    "jsdelivr.net", "unpkg.com",
}

# Local-part ranking: lower number = preferred disclosure contact.
_PREFERRED_LOCALPARTS = [
    ("security", 0), ("psirt", 0), ("secure", 0), ("vuln", 0), ("disclosure", 0),
    ("abuse", 1), ("soc", 1), ("cert", 1),
    ("info", 3), ("contact", 3), ("hello", 4), ("support", 4),
    ("admin", 5), ("webmaster", 5),
]

_FETCH_TIMEOUT = 10
_MAX_BYTES = 512 * 1024  # cap each fetched body at 512 KiB
_USER_AGENT = (
    "Mantishack-disclosure/1.0 "
    "(+responsible-disclosure courtesy contact lookup)"
)

# Fixed page set scraped on the target host (never followed beyond these).
_SCRAPE_PATHS = ("/security", "/contact", "/contact-us", "/", "/about")
_SECURITY_TXT_PATHS = ("/.well-known/security.txt", "/security.txt")


@dataclass
class DiscoveryResult:
    """Outcome of recipient discovery."""

    email: str | None
    source: str  # override | security.txt | scrape:<page> | repo:<file> | none
    candidates: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "email": self.email,
            "source": self.source,
            "candidates": self.candidates,
            "notes": self.notes,
        }


# --------------------------------------------------------------------------- #
# Network layer (injectable, stdlib urllib)
# --------------------------------------------------------------------------- #
def default_fetcher(url: str, timeout: int = _FETCH_TIMEOUT) -> str | None:
    """Fetch ``url`` and return the size-capped body text, or ``None``.

    Only ``http``/``https`` is permitted. Any network/parse error is swallowed
    and reported as ``None`` so discovery degrades gracefully.
    """
    scheme = urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        return None
    req = _urlrequest.Request(url, headers={"User-Agent": _USER_AGENT})
    # Default TLS verification (certifi/system trust). We are only ever
    # contacting the operator-named target; no verification downgrade.
    ctx = ssl.create_default_context()
    try:
        with _urlrequest.urlopen(req, timeout=timeout, context=ctx) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            raw = resp.read(_MAX_BYTES) or b""
            charset = resp.headers.get_content_charset() or "utf-8"
            return raw.decode(charset, errors="replace")
    except (URLError, ValueError, OSError):
        return None
    except Exception:  # noqa: BLE001 - any unexpected error -> graceful miss
        return None


# --------------------------------------------------------------------------- #
# Parsing / ranking helpers
# --------------------------------------------------------------------------- #
def _clean_candidates(raw: list[str | None]) -> list[str]:
    """De-duplicate, lowercase, and drop false-positive addresses."""
    out: list[str] = []
    seen: set[str] = set()
    for addr in raw:
        if not addr:
            continue
        addr = addr.strip().strip(".,;:<>()[]{}\"'").lower()
        if not addr or "@" not in addr:
            continue
        domain = addr.split("@", 1)[1]
        tld = addr.rsplit(".", 1)[-1]
        if tld in _ASSET_TLDS:
            continue
        if domain in _JUNK_DOMAINS:
            continue
        local = addr.split("@", 1)[0]
        if local in ("", "2x", "3x"):
            continue
        if addr in seen:
            continue
        seen.add(addr)
        out.append(addr)
    return out


def rank_candidates(candidates: list[str | None]) -> list[str]:
    """Order cleaned candidates so the best disclosure contact comes first."""
    def score(addr: str) -> tuple[int, str]:
        local = addr.split("@", 1)[0]
        best = 9
        for token, rank in _PREFERRED_LOCALPARTS:
            if token in local:
                best = min(best, rank)
        return (best, addr)

    return sorted(_clean_candidates(candidates), key=score)


def parse_security_txt(text: str) -> list[str]:
    """Extract ranked email contacts from a ``security.txt`` body (RFC 9116)."""
    emails: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("contact:"):
            value = line.split(":", 1)[1].strip()
            if value.lower().startswith(_MAILTO_PREFIX):
                emails.append(value[len(_MAILTO_PREFIX):].split("?", 1)[0].strip())
            else:
                emails.extend(_EMAIL_RE.findall(value))
    return rank_candidates(emails)


def extract_emails_from_html(html: str) -> list[str]:
    """Pull ranked email addresses from ``mailto:`` links and visible text."""
    emails: list[str] = []
    text = html
    try:
        from bs4 import BeautifulSoup  # optional enhancement

        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.lower().startswith(_MAILTO_PREFIX):
                emails.append(href[len(_MAILTO_PREFIX):].split("?", 1)[0])
        text = soup.get_text(" ")
    except Exception:  # noqa: BLE001 - bs4 absent or parse error -> regex only
        # Recover mailto: targets without bs4.
        for m in re.finditer(r'mailto:([^"\'>?\s]+)', html, re.IGNORECASE):
            emails.append(m.group(1))
    emails.extend(_EMAIL_RE.findall(text))
    return rank_candidates(emails)


# --------------------------------------------------------------------------- #
# Target normalization
# --------------------------------------------------------------------------- #
def normalize_host(target: str) -> str | None:
    """Return ``scheme://host`` for a URL/domain target, else ``None``.

    Preserves an explicit ``http``/``https`` scheme; defaults to ``https`` for a
    bare domain. Rejects values that are not plausibly a host (embedded
    whitespace, no dot, empty netloc) so junk targets fall through to ``--to``.
    """
    target = (target or "").strip()
    if not target:
        return None
    if "//" in target:
        parsed = urlparse(target)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc
    else:
        scheme = "https"
        netloc = urlparse("https://" + target).netloc
    if scheme not in ("http", "https"):
        scheme = "https"
    if not netloc or " " in netloc or "." not in netloc:
        return None
    return f"{scheme}://{netloc}"


# --------------------------------------------------------------------------- #
# Repo (local target) discovery
# --------------------------------------------------------------------------- #
def _discover_from_repo(root: Path) -> DiscoveryResult:
    notes: list[str] = []
    for name in ("SECURITY.md", "security.md", ".github/SECURITY.md"):
        p = root / name
        if p.is_file():
            cands = extract_emails_from_html(p.read_text(errors="replace"))
            if cands:
                return DiscoveryResult(cands[0], f"repo:{name}", cands, notes)
            notes.append(f"{name} present but contained no email")
    for name in (".well-known/security.txt", "security.txt"):
        p = root / name
        if p.is_file():
            cands = parse_security_txt(p.read_text(errors="replace"))
            if cands:
                return DiscoveryResult(cands[0], f"repo:{name}", cands, notes)
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(errors="replace"))
            author = data.get("author")
            email = None
            if isinstance(author, dict):
                email = author.get("email")
            elif isinstance(author, str):
                m = _EMAIL_RE.search(author)
                email = m.group(0) if m else None
            cands = _clean_candidates([email]) if email else []
            if cands:
                return DiscoveryResult(cands[0], "repo:package.json", cands, notes)
        except (ValueError, OSError):
            pass
    notes.append(
        "no email found in repo metadata "
        "(SECURITY.md / security.txt / package.json)"
    )
    return DiscoveryResult(None, "none", [], notes)


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def discover_recipient(
    target: str,
    *,
    to_override: str | None = None,
    fetcher=default_fetcher,
    timeout: int = _FETCH_TIMEOUT,
) -> DiscoveryResult:
    """Find the best disclosure email for ``target``.

    ``to_override`` short-circuits discovery. A local filesystem path falls back
    to repo metadata; anything else is treated as a host/URL and probed over
    HTTP(S) via ``fetcher``.
    """
    if to_override:
        cleaned = _clean_candidates([to_override])
        if cleaned:
            return DiscoveryResult(cleaned[0], "override", cleaned, [])
        # Respect an explicit operator choice even if it's unusual.
        chosen = to_override.strip()
        return DiscoveryResult(chosen, "override", [chosen], [])

    # Local path target -> repo metadata.
    try:
        if target and Path(target).exists():
            return _discover_from_repo(Path(target))
    except OSError:
        pass

    base = normalize_host(target)
    if not base:
        return DiscoveryResult(
            None, "none", [],
            [f"could not derive a host from target {target!r}; pass --to <email>"],
        )

    notes: list[str] = []

    # 1. security.txt (https paths, then http fallback)
    for path in _SECURITY_TXT_PATHS:
        body = fetcher(base + path, timeout)
        if body:
            cands = parse_security_txt(body)
            if cands:
                return DiscoveryResult(cands[0], "security.txt", cands, notes)
            notes.append(f"{path} fetched but had no Contact email")
    if base.startswith("https://"):
        http_base = "http://" + base[len("https://"):]
        body = fetcher(http_base + _SECURITY_TXT_PATHS[0], timeout)
        if body:
            cands = parse_security_txt(body)
            if cands:
                return DiscoveryResult(cands[0], "security.txt", cands, notes)

    # 2. scrape a small fixed set of pages on the target host only
    for path in _SCRAPE_PATHS:
        body = fetcher(base + path, timeout)
        if body:
            cands = extract_emails_from_html(body)
            if cands:
                page = path if path != "/" else "/home"
                return DiscoveryResult(cands[0], f"scrape:{page}", cands, notes)

    notes.append(
        "no security.txt and no email scraped from target pages; "
        "pass --to <email>"
    )
    return DiscoveryResult(None, "none", [], notes)
