"""
modules/recon.py — DNS, WHOIS, subdomain enum.
Concurrent subdomain probing for speed.
No rendering. Returns structured data only.
"""

import socket
import concurrent.futures
from dataclasses import dataclass, field

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
    "vpn", "remote", "portal", "app", "mobile", "beta", "cdn",
    "static", "assets", "blog", "shop", "help", "support", "docs",
    "dashboard", "auth", "login", "secure", "mx", "smtp", "ns1",
    "ns2", "git", "gitlab", "jenkins", "ci", "status", "internal",
    "intranet", "jira", "confluence", "vault", "api-dev", "api-v2",
    "m", "media", "img", "images", "video", "files", "download",
    "upload", "store", "pay", "billing", "account", "accounts",
    "monitor", "metrics", "grafana", "kibana", "elastic", "redis",
    "db", "database", "mysql", "postgres", "backup", "old", "new",
]


@dataclass
class DnsResult:
    A:     list[str] = field(default_factory=list)
    AAAA:  list[str] = field(default_factory=list)
    MX:    list[str] = field(default_factory=list)
    NS:    list[str] = field(default_factory=list)
    TXT:   list[str] = field(default_factory=list)
    CNAME: list[str] = field(default_factory=list)


@dataclass
class SubResult:
    subdomain: str
    ip:        str


def dns(domain: str) -> DnsResult:
    result = DnsResult()
    try:
        result.A = list({r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except Exception:
        pass
    try:
        result.AAAA = list({r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET6)})
    except Exception:
        pass
    try:
        import dns.resolver
        for rtype in ("MX", "NS", "TXT", "CNAME"):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                setattr(result, rtype, [str(r) for r in answers])
            except Exception:
                pass
    except ImportError:
        pass
    return result


def whois(domain: str) -> dict:
    try:
        import whois as _w
        w = _w.whois(domain)
        return {
            "registrar":    str(w.registrar or ""),
            "created":      str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date or ""),
            "expires":      str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date or ""),
            "name_servers": list(w.name_servers or []),
            "org":          str(w.org or ""),
            "country":      str(w.country or ""),
        }
    except Exception:
        return {}


def _probe_sub(domain: str, word: str) -> SubResult | None:
    fqdn = f"{word}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return SubResult(subdomain=fqdn, ip=ip)
    except socket.gaierror:
        return None


def subdomains(domain: str, wordlist: list[str] | None = None, threads: int = 50) -> list[SubResult]:
    """Concurrent subdomain enumeration — significantly faster than sequential."""
    words  = wordlist or SUBDOMAIN_WORDLIST
    found  = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_probe_sub, domain, word): word for word in words}
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                found.append(result)
    return sorted(found, key=lambda r: r.subdomain)
