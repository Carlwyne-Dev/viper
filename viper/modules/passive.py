"""
modules/passive.py — Passive reconnaissance. Sends nothing to the target.

Two capabilities:
  * Certificate Transparency subdomain discovery (crt.sh) — pulls real,
    historically-issued subdomains instead of brute-forcing a wordlist.
  * Subdomain takeover detection — flags subdomains whose DNS still points
    at an unclaimed third-party service (S3, GitHub Pages, Heroku, …).

No rendering. Returns structured data only.
"""

import json
import re
import socket
import ssl
import urllib.request
import urllib.parse
import urllib.error
import concurrent.futures
from dataclasses import dataclass, field


# ── Data models ──────────────────────────────────────────────────────────────

@dataclass
class PassiveSub:
    subdomain: str
    source:    str = "crt.sh"


@dataclass
class TakeoverResult:
    subdomain:  str
    service:    str            # e.g. "GitHub Pages", "AWS/S3"
    cname:      str   = ""     # resolved CNAME target, if known
    vulnerable: bool  = False  # body matched an "unclaimed" fingerprint
    confidence: int   = 0      # 0–100
    detail:     str   = ""


# ── Takeover fingerprints ──────────────────────────────────────────────────────
# (service, cname_regex, body_regex)
# cname_regex identifies the hosting provider from the CNAME target.
# body_regex is the provider's "this resource is not claimed" response — the
# actual evidence that the name is dangling and takeover-able.
TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages", r"\.github\.io$",              r"There isn't a GitHub Pages site here"),
    ("AWS/S3",       r"s3[.-].*amazonaws\.com$",    r"NoSuchBucket|The specified bucket does not exist"),
    ("Heroku",       r"\.herokuapp\.com$",          r"No such app|herokucdn\.com/error-pages/no-such-app"),
    ("Azure",        r"\.(azurewebsites|cloudapp|trafficmanager)\.net$", r"404 Web Site not found|Error 404"),
    ("Shopify",      r"\.myshopify\.com$",          r"Sorry, this shop is currently unavailable"),
    ("Fastly",       r"\.fastly\.net$",             r"Fastly error: unknown domain"),
    ("Zendesk",      r"\.zendesk\.com$",            r"Help Center Closed|this help center no longer exists"),
    ("Tumblr",       r"\.domains\.tumblr\.com$",    r"There's nothing here\.|Whatever you were looking for doesn't currently exist"),
    ("ReadTheDocs",  r"\.readthedocs\.io$",         r"unknown to Read the Docs"),
    ("Pantheon",     r"\.pantheonsite\.io$",        r"The gods are wise, but do not know of the site"),
    ("Surge.sh",     r"\.surge\.sh$",               r"project not found"),
    ("Bitbucket",    r"\.bitbucket\.io$",           r"Repository not found"),
    ("Cargo",        r"\.cargocollective\.com$",    r"404 Not Found"),
    ("Webflow",      r"\.proxy-ssl\.webflow\.com$", r"The page you are looking for doesn't exist"),
]


# ── Pure cores (network-free, unit-testable) ─────────────────────────────────

def parse_crtsh(payload: str, domain: str) -> list[PassiveSub]:
    """
    Parse a crt.sh JSON response body into a deduped, sorted subdomain list.
    crt.sh returns one object per cert; `name_value` may hold several names
    (newline separated) and wildcard entries ("*.example.com").
    """
    try:
        rows = json.loads(payload)
    except Exception:
        return []

    names: set[str] = set()
    suffix = domain.lower().lstrip(".")
    for row in rows:
        raw = str(row.get("name_value", ""))
        for name in raw.splitlines():
            name = name.strip().lower().lstrip("*.")
            if not name or name == suffix:
                continue
            if name == suffix or name.endswith("." + suffix):
                # basic hostname sanity
                if re.fullmatch(r"[a-z0-9._-]+", name):
                    names.add(name)
    return [PassiveSub(subdomain=n, source="crt.sh") for n in sorted(names)]


def match_takeover(cname: str, body: str) -> TakeoverResult | None:
    """
    Given a resolved CNAME target and an HTTP response body, decide whether
    this looks like a dangling third-party resource (takeover candidate).

    Confidence model:
      * CNAME points at a known provider AND body matches its unclaimed
        signature  → 90 (strong).
      * body matches a provider signature but CNAME is unknown/empty → 60.
      * CNAME points at a provider but body doesn't match (site may be live
        or provider changed its page) → not reported here.
    """
    cname = (cname or "").strip().lower().rstrip(".")
    body = body or ""
    for service, cname_rx, body_rx in TAKEOVER_FINGERPRINTS:
        cname_hit = bool(cname) and re.search(cname_rx, cname) is not None
        body_hit = re.search(body_rx, body, re.IGNORECASE) is not None
        if body_hit:
            conf = 90 if cname_hit else 60
            return TakeoverResult(
                subdomain="", service=service, cname=cname,
                vulnerable=True, confidence=conf,
                detail=f"Unclaimed {service} resource — response matched takeover signature",
            )
    return None


# ── Network wrappers (thin, always graceful) ─────────────────────────────────

def crtsh_subdomains(domain: str, timeout: float = 15.0) -> list[PassiveSub]:
    """Query crt.sh certificate transparency logs. Never raises."""
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Viper-CLI/1.0 (passive recon)",
            "Accept":     "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = r.read().decode("utf-8", errors="ignore")
    except Exception:
        return []
    return parse_crtsh(payload, domain)


def _resolve_cname(host: str) -> str:
    """Best-effort CNAME resolution. Uses dnspython when available."""
    try:
        import dns.resolver
        try:
            ans = dns.resolver.resolve(host, "CNAME")
            return str(ans[0].target) if ans else ""
        except Exception:
            return ""
    except ImportError:
        return ""


def _fetch_body(host: str, timeout: float) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{scheme}://{host}/",
                headers={"User-Agent": "Viper-CLI/1.0 (takeover check)"},
            )
            with opener.open(req, timeout=timeout) as r:
                return r.read(8192).decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:   # 404 bodies are exactly what we want
            try:
                return e.read(8192).decode("utf-8", errors="ignore")
            except Exception:
                return ""
        except Exception:
            continue
    return ""


def check_takeover(subdomain: str, timeout: float = 6.0) -> TakeoverResult | None:
    """Check a single subdomain for a dangling-takeover condition."""
    cname = _resolve_cname(subdomain)
    body = _fetch_body(subdomain, timeout)
    if not body:
        return None
    hit = match_takeover(cname, body)
    if hit:
        hit.subdomain = subdomain
    return hit


def check_takeovers(subdomains: list[str], timeout: float = 6.0,
                    threads: int = 20) -> list[TakeoverResult]:
    """Check many subdomains concurrently. Returns only vulnerable ones."""
    found: list[TakeoverResult] = []
    if not subdomains:
        return found
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check_takeover, s, timeout): s for s in subdomains}
        for f in concurrent.futures.as_completed(futures):
            try:
                r = f.result()
            except Exception:
                r = None
            if r and r.vulnerable:
                found.append(r)
    return sorted(found, key=lambda r: r.subdomain)


# ── Convenience: passive enumeration combining sources ───────────────────────

def enumerate_subdomains(domain: str, extra: list[str] | None = None,
                         timeout: float = 15.0) -> list[PassiveSub]:
    """
    Passive subdomain set from crt.sh, merged with any `extra` names already
    discovered (e.g. from the brute-force resolver), deduped.
    """
    results = {s.subdomain: s for s in crtsh_subdomains(domain, timeout)}
    for name in (extra or []):
        name = name.strip().lower()
        if name and name not in results:
            results[name] = PassiveSub(subdomain=name, source="resolver")
    return [results[k] for k in sorted(results)]
