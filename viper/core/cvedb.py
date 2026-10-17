"""
core/cvedb.py — Live CVE database via NVD API.

Fetches, caches, and queries CVEs from the National Vulnerability Database.
Cache lives at ~/.viper/cvedb/ — refreshes every 24h per keyword.

NVD API: https://nvd.nist.gov/developers/vulnerabilities
No API key required for basic use (rate limited to 5 req/30s without key).
"""

import json
import time
import urllib.request
import urllib.parse
import datetime
import hashlib
from pathlib import Path
from dataclasses import dataclass, field

CACHE_DIR  = Path.home() / ".viper" / "cvedb"
CACHE_TTL  = 86400  # 24 hours
NVD_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_DELAY = 6.5    # seconds between NVD requests (no API key = 5 req/30s)


@dataclass
class CVE:
    id:          str
    description: str
    severity:    str       # CRITICAL, HIGH, MEDIUM, LOW, NONE
    cvss_score:  float     # 0.0 - 10.0
    published:   str
    modified:    str
    references:  list[str] = field(default_factory=list)
    cpe_matches: list[str] = field(default_factory=list)

    @property
    def viper_severity(self) -> str:
        """Map NVD severity to Viper severity."""
        return {
            "CRITICAL": "CRIT",
            "HIGH":     "HIGH",
            "MEDIUM":   "MED",
            "LOW":      "LOW",
            "NONE":     "INFO",
        }.get(self.severity.upper(), "INFO")

    def short_desc(self, max_len: int = 100) -> str:
        d = self.description
        return d[:max_len] + "…" if len(d) > max_len else d


# ── Cache ──────────────────────────────────────────────────────────────────────

def _cache_path(key: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe = hashlib.md5(key.encode()).hexdigest()[:12]
    return CACHE_DIR / f"{safe}.json"


def _cache_valid(path: Path) -> bool:
    if not path.exists():
        return False
    age = time.time() - path.stat().st_mtime
    return age < CACHE_TTL


def _cache_read(path: Path) -> list[CVE] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return [CVE(**c) for c in data]
    except Exception:
        return None


def _cache_write(path: Path, cves: list[CVE]):
    try:
        data = [c.__dict__ for c in cves]
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


# ── NVD fetcher ────────────────────────────────────────────────────────────────

def _fetch_nvd(keyword: str, results_per_page: int = 20) -> list[CVE]:
    """
    Query NVD API for CVEs matching a keyword.
    Returns list of CVE objects sorted by CVSS score descending.
    """
    params = urllib.parse.urlencode({
        "keywordSearch":   keyword,
        "resultsPerPage":  results_per_page,
        "sortBy":          "publishedDate",
        "sortOrder":       "dsc",
    })
    url = f"{NVD_BASE}?{params}"

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Viper-CLI/1.0 (security research tool)",
            "Accept":     "application/json",
        })
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id   = cve_data.get("id", "")

        # Description (English)
        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS score + severity
        score    = 0.0
        severity = "NONE"
        metrics  = cve_data.get("metrics", {})

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                score     = cvss_data.get("baseScore", 0.0)
                severity  = cvss_data.get("baseSeverity", "NONE")
                if not severity and score:
                    # Derive severity from score
                    if score >= 9.0:   severity = "CRITICAL"
                    elif score >= 7.0: severity = "HIGH"
                    elif score >= 4.0: severity = "MEDIUM"
                    else:              severity = "LOW"
                break

        # References
        refs = [
            r.get("url", "") for r in cve_data.get("references", [])
        ][:3]

        # CPE matches
        cpes = []
        for cfg in cve_data.get("configurations", []):
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    if cpe:
                        cpes.append(cpe)

        published = cve_data.get("published", "")[:10]
        modified  = cve_data.get("lastModified", "")[:10]

        cves.append(CVE(
            id=cve_id, description=desc, severity=severity,
            cvss_score=score, published=published, modified=modified,
            references=refs, cpe_matches=cpes[:5],
        ))

    # Sort by CVSS score descending
    return sorted(cves, key=lambda c: c.cvss_score, reverse=True)


# ── Public API ─────────────────────────────────────────────────────────────────

def search(keyword: str, max_results: int = 10, force_refresh: bool = False) -> list[CVE]:
    """
    Search for CVEs matching keyword.
    Uses cache — only hits NVD API if cache is stale or missing.
    """
    cache_key = f"{keyword.lower().strip()}:{max_results}"
    path      = _cache_path(cache_key)

    if not force_refresh and _cache_valid(path):
        cached = _cache_read(path)
        if cached is not None:
            return cached[:max_results]

    cves = _fetch_nvd(keyword, results_per_page=max_results)
    if cves:
        _cache_write(path, cves)

    return cves[:max_results]


def by_id(cve_id: str) -> CVE | None:
    """Fetch a specific CVE by ID."""
    url = f"{NVD_BASE}?cveId={cve_id.upper()}"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Viper-CLI/1.0",
            "Accept":     "application/json",
        })
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        # Re-use _fetch_nvd parsing by passing through a minimal search
        results = search(cve_id, max_results=1, force_refresh=True)
        return results[0] if results else None
    except Exception:
        return None


def for_banner(banner: str) -> list[CVE]:
    """
    Auto-search CVEs based on a service banner string.
    Extracts product + version from common banner patterns.
    """
    import re

    queries = []

    patterns = [
        (r"nginx/([\d.]+)",          lambda m: f"nginx {m.group(1)}"),
        (r"Apache/([\d.]+)",         lambda m: f"Apache httpd {m.group(1)}"),
        (r"OpenSSH[_ ]([\d.]+)",     lambda m: f"OpenSSH {m.group(1)}"),
        (r"OpenSSL/([\d.]+)",        lambda m: f"OpenSSL {m.group(1)}"),
        (r"PHP/([\d.]+)",            lambda m: f"PHP {m.group(1)}"),
        (r"MySQL\s+([\d.]+)",        lambda m: f"MySQL {m.group(1)}"),
        (r"Redis\s+([\d.]+)",        lambda m: f"Redis {m.group(1)}"),
        (r"Microsoft-IIS/([\d.]+)",  lambda m: f"IIS {m.group(1)}"),
        (r"vsftpd\s*([\d.]+)",       lambda m: f"vsftpd {m.group(1)}"),
        (r"Exim\s+([\d.]+)",         lambda m: f"Exim {m.group(1)}"),
        (r"ProFTPD\s*([\d.]+)",      lambda m: f"ProFTPD {m.group(1)}"),
        (r"PostgreSQL\s+([\d.]+)",   lambda m: f"PostgreSQL {m.group(1)}"),
        (r"MongoDB\s+([\d.]+)",      lambda m: f"MongoDB {m.group(1)}"),
    ]

    for pattern, query_fn in patterns:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            queries.append(query_fn(m))

    if not queries:
        return []

    # Search for first match (rate limit friendly)
    query = queries[0]
    return search(query, max_results=5)


def cache_stats() -> dict:
    """How many CVEs cached, how old."""
    if not CACHE_DIR.exists():
        return {"files": 0, "total_cves": 0}
    files  = list(CACHE_DIR.glob("*.json"))
    total  = 0
    oldest = None
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            total += len(data)
            age = time.time() - f.stat().st_mtime
            if oldest is None or age > oldest:
                oldest = age
        except Exception:
            pass
    return {
        "files":      len(files),
        "total_cves": total,
        "oldest_hrs": round(oldest / 3600, 1) if oldest else 0,
    }


def clear_cache():
    """Delete all cached CVE data."""
    if CACHE_DIR.exists():
        for f in CACHE_DIR.glob("*.json"):
            f.unlink()
