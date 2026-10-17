"""
modules/intel.py — Passive intelligence via third-party APIs.

Currently: Shodan host lookup. Returns ports, banners, hostnames, tags and
Shodan-known vulns for an IP — without sending a single packet to the target.

Disabled unless an API key is configured (config.integrations.shodan_key or
the VIPER_SHODAN_KEY environment variable). Never raises.

No rendering. Returns structured data only.
"""

import os
import json
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field


SHODAN_HOST = "https://api.shodan.io/shodan/host/"


@dataclass
class IntelService:
    port:      int
    transport: str = "tcp"
    product:   str = ""
    version:   str = ""
    banner:    str = ""


@dataclass
class IntelResult:
    ip:        str
    source:    str = "shodan"
    available: bool = False          # did we have a key + a response?
    hostnames: list[str] = field(default_factory=list)
    ports:     list[int] = field(default_factory=list)
    tags:      list[str] = field(default_factory=list)
    vulns:     list[str] = field(default_factory=list)   # CVE ids Shodan flags
    org:       str = ""
    os:        str = ""
    services:  list[IntelService] = field(default_factory=list)
    error:     str = ""


# ── Key resolution ───────────────────────────────────────────────────────────

def shodan_key(cfg=None) -> str:
    """Env var wins over config file. Returns '' when unset."""
    env = os.environ.get("VIPER_SHODAN_KEY", "").strip()
    if env:
        return env
    if cfg is not None:
        return (getattr(cfg.integrations, "shodan_key", "") or "").strip()
    return ""


# ── Pure core (network-free, unit-testable) ──────────────────────────────────

def parse_shodan_host(ip: str, payload: str) -> IntelResult:
    """Parse a Shodan /shodan/host/{ip} JSON response into an IntelResult."""
    result = IntelResult(ip=ip, source="shodan")
    try:
        data = json.loads(payload)
    except Exception:
        result.error = "invalid response"
        return result

    result.available = True
    result.hostnames = list(data.get("hostnames", []) or [])
    result.ports     = sorted(data.get("ports", []) or [])
    result.tags      = list(data.get("tags", []) or [])
    result.org       = str(data.get("org", "") or "")
    result.os        = str(data.get("os", "") or "")

    vulns = data.get("vulns", []) or []
    # Shodan may return vulns as a list or dict keyed by CVE.
    if isinstance(vulns, dict):
        result.vulns = sorted(vulns.keys())
    else:
        result.vulns = sorted(vulns)

    for entry in data.get("data", []) or []:
        result.services.append(IntelService(
            port=int(entry.get("port", 0) or 0),
            transport=str(entry.get("transport", "tcp") or "tcp"),
            product=str(entry.get("product", "") or ""),
            version=str(entry.get("version", "") or ""),
            banner=str(entry.get("data", "") or "")[:200],
        ))
    return result


# ── Network wrapper (thin, graceful) ─────────────────────────────────────────

def shodan_host(ip: str, cfg=None, timeout: float = 15.0) -> IntelResult:
    """Look up an IP on Shodan. Returns an unavailable result if no key."""
    key = shodan_key(cfg)
    if not key:
        return IntelResult(ip=ip, source="shodan", available=False,
                           error="no API key (set integrations.shodan_key or VIPER_SHODAN_KEY)")
    url = SHODAN_HOST + urllib.parse.quote(ip) + "?" + urllib.parse.urlencode({"key": key})
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = r.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        msg = {401: "invalid API key", 404: "no information available",
               429: "rate limited"}.get(e.code, f"HTTP {e.code}")
        return IntelResult(ip=ip, source="shodan", available=False, error=msg)
    except Exception as e:
        return IntelResult(ip=ip, source="shodan", available=False, error=str(e))
    return parse_shodan_host(ip, payload)
