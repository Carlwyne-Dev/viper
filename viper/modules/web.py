"""
modules/web.py — Web Fang capability.
Tech fingerprinting, sensitive path detection, SSL info, header analysis.
No rendering. Returns structured data only.
"""

import re
import socket
import ssl
import urllib.request
import urllib.error
import concurrent.futures
import datetime
from dataclasses import dataclass, field

# ── Signatures ─────────────────────────────────────────────────────────────────

TECH_SIGNATURES = [
    # (header_or_body_pattern, field, name)
    # Server headers
    (r"nginx/([\d.]+)",              "Server",           "nginx {0}"),
    (r"Apache/([\d.]+)",             "Server",           "Apache {0}"),
    (r"Microsoft-IIS/([\d.]+)",      "Server",           "IIS {0}"),
    (r"LiteSpeed",                   "Server",           "LiteSpeed"),
    (r"cloudflare",                  "Server",           "Cloudflare"),
    # Powered-by
    (r"PHP/([\d.]+)",                "X-Powered-By",     "PHP {0}"),
    (r"ASP\.NET",                    "X-Powered-By",     "ASP.NET"),
    (r"Express",                     "X-Powered-By",     "Express.js"),
    # Cookies
    (r"wordpress",                   "Set-Cookie",       "WordPress"),
    (r"PHPSESSID",                   "Set-Cookie",       "PHP Session"),
    (r"laravel_session",             "Set-Cookie",       "Laravel"),
    (r"django",                      "Set-Cookie",       "Django"),
    # Body patterns (HTML)
    (r"wp-content/",                 "body",             "WordPress"),
    (r"wp-includes/",                "body",             "WordPress"),
    (r"/sites/default/files",        "body",             "Drupal"),
    (r"Joomla!",                     "body",             "Joomla"),
    (r"content=\"Next\.js",          "body",             "Next.js"),
    (r"__nuxt",                      "body",             "Nuxt.js"),
    (r"ng-version=",                 "body",             "Angular"),
    (r"react-root|__REACT",         "body",             "React"),
    (r"shopify",                     "body",             "Shopify"),
    (r"woocommerce",                 "body",             "WooCommerce"),
]

SENSITIVE_PATHS = [
    ("/.env",                 "CRIT", "Environment file — may contain secrets"),
    ("/.git/config",          "CRIT", "Git config exposed"),
    ("/.git/HEAD",            "CRIT", "Git repo exposed"),
    ("/wp-login.php",         "HIGH", "WordPress login page"),
    ("/wp-admin/",            "HIGH", "WordPress admin panel"),
    ("/admin/",               "HIGH", "Admin panel"),
    ("/administrator/",       "HIGH", "Admin panel (Joomla)"),
    ("/phpmyadmin/",          "CRIT", "phpMyAdmin exposed"),
    ("/backup/",              "HIGH", "Backup directory"),
    ("/backup.zip",           "CRIT", "Backup archive exposed"),
    ("/backup.sql",           "CRIT", "Database backup exposed"),
    ("/config.php",           "CRIT", "Config file exposed"),
    ("/config.yml",           "CRIT", "Config file exposed"),
    ("/config.json",          "HIGH", "Config file exposed"),
    ("/docker-compose.yml",   "CRIT", "Docker config exposed"),
    ("/Dockerfile",           "HIGH", "Dockerfile exposed"),
    ("/robots.txt",           "INFO", "robots.txt found"),
    ("/sitemap.xml",          "INFO", "Sitemap found"),
    ("/.htaccess",            "HIGH", ".htaccess exposed"),
    ("/server-status",        "HIGH", "Apache server-status exposed"),
    ("/api/",                 "INFO", "API endpoint"),
    ("/api/v1/",              "INFO", "API v1 endpoint"),
    ("/api/v2/",              "INFO", "API v2 endpoint"),
    ("/swagger/",             "MED",  "Swagger UI exposed"),
    ("/swagger.json",         "MED",  "Swagger spec exposed"),
    ("/graphql",              "MED",  "GraphQL endpoint"),
    ("/.well-known/",         "INFO", "Well-known directory"),
    ("/crossdomain.xml",      "LOW",  "Flash crossdomain policy"),
    ("/elmah.axd",            "HIGH", "ELMAH error log (ASP.NET)"),
    ("/trace.axd",            "HIGH", "ASP.NET trace exposed"),
    ("/actuator",             "HIGH", "Spring Boot actuator exposed"),
    ("/actuator/env",         "CRIT", "Spring Boot env endpoint"),
    ("/.DS_Store",            "MED",  ".DS_Store file exposed"),
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HIGH", "HSTS not set — HTTPS downgrade possible"),
    "Content-Security-Policy":   ("MED",  "CSP missing — XSS risk"),
    "X-Frame-Options":           ("MED",  "Clickjacking protection missing"),
    "X-Content-Type-Options":    ("LOW",  "MIME sniffing protection missing"),
    "Referrer-Policy":           ("LOW",  "Referrer policy not set"),
    "Permissions-Policy":        ("LOW",  "Permissions policy not set"),
}


@dataclass
class TechResult:
    name: str
    source: str = ""


@dataclass
class PathResult:
    path:     str
    status:   int
    severity: str
    desc:     str
    size:     int = 0


@dataclass
class HeaderFinding:
    header:   str
    severity: str
    desc:     str
    value:    str = ""


@dataclass
class SslResult:
    valid:       bool = False
    issuer:      str  = ""
    subject:     str  = ""
    expires:     str  = ""
    days_left:   int  = 0
    tls_version: str  = ""
    expired:     bool = False
    expiring_soon: bool = False


@dataclass
class WebResult:
    url:          str
    status:       int              = 0
    tech:         list[TechResult] = field(default_factory=list)
    paths:        list[PathResult] = field(default_factory=list)
    headers:      list[HeaderFinding] = field(default_factory=list)
    ssl:          SslResult | None = None
    robots_txt:   str = ""
    title:        str = ""
    redirects_to: str = ""


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_opener():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    return urllib.request.build_opener(https_handler)


def _fetch(url: str, timeout: float = 6.0, follow: bool = True) -> tuple[int, dict, str, str]:
    """Returns (status, headers, body[:4096], final_url)"""
    opener = _make_opener()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Viper/0.2)"})
        with opener.open(req, timeout=timeout) as r:
            body = r.read(4096).decode(errors="ignore")
            return r.status, dict(r.headers), body, r.url
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers) if e.headers else {}, "", url
    except Exception:
        return 0, {}, "", url


def _probe_path(base: str, path: str, sev: str, desc: str, timeout: float) -> PathResult | None:
    url = base.rstrip("/") + path
    status, hdrs, body, _ = _fetch(url, timeout=timeout, follow=False)
    if status in (200, 301, 302, 403):
        size = len(body)
        # 403 on sensitive paths is still a finding
        real_sev = sev if status == 200 else ("LOW" if status == 403 else sev)
        return PathResult(path=path, status=status, severity=real_sev, desc=desc, size=size)
    return None


def _fingerprint_tech(headers: dict, body: str) -> list[TechResult]:
    found = set()
    results = []
    all_headers_lower = {k.lower(): v for k, v in headers.items()}

    for pattern, field_name, name_tpl in TECH_SIGNATURES:
        field_lower = field_name.lower()
        source = ""
        text = ""

        if field_name == "body":
            text = body
            source = "html"
        else:
            text = all_headers_lower.get(field_lower, "")
            source = "header"

        if not text:
            continue

        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            name = name_tpl.format(m.group(1) if m.lastindex else "")
            if name not in found:
                found.add(name)
                results.append(TechResult(name=name, source=source))

    return results


def _check_ssl(host: str, port: int = 443, timeout: float = 5.0) -> SslResult:
    result = SslResult()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert   = ssock.getpeercert()
                result.tls_version = ssock.version() or ""
                result.valid = True

                # Subject
                subj = dict(x[0] for x in cert.get("subject", []))
                result.subject = subj.get("commonName", host)

                # Issuer
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result.issuer = issuer.get("organizationName", "")

                # Expiry
                exp_str = cert.get("notAfter", "")
                if exp_str:
                    exp = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                    result.expires   = exp.strftime("%Y-%m-%d")
                    result.days_left = (exp - datetime.datetime.utcnow()).days
                    result.expired      = result.days_left < 0
                    result.expiring_soon = 0 <= result.days_left <= 30
    except ssl.SSLCertVerificationError:
        result.valid = False
    except Exception:
        pass
    return result


def _extract_title(body: str) -> str:
    m = re.search(r"<title[^>]*>([^<]{1,120})</title>", body, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _parse_robots(body: str) -> str:
    disallowed = re.findall(r"(?i)Disallow:\s*(.+)", body)
    return "  ".join(d.strip() for d in disallowed[:10])


# ── Main scan ──────────────────────────────────────────────────────────────────

def scan(
    target: str,
    timeout: float = 6.0,
    check_paths: bool = True,
    check_ssl: bool = True,
    max_paths: int = len(SENSITIVE_PATHS),
) -> WebResult:
    # Determine base URL
    scheme = "https"
    try:
        socket.create_connection((target, 443), timeout=2)
    except Exception:
        scheme = "http"

    base_url = f"{scheme}://{target}"
    result = WebResult(url=base_url)

    # Fetch home page
    status, headers, body, final_url = _fetch(base_url, timeout=timeout)
    result.status = status
    if final_url and final_url != base_url:
        result.redirects_to = final_url

    if status == 0:
        return result

    # Tech fingerprint
    result.tech = _fingerprint_tech(headers, body)

    # Page title
    result.title = _extract_title(body)

    # Security headers
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for hdr, (sev, desc) in SECURITY_HEADERS.items():
        val = headers_lower.get(hdr.lower(), "")
        if not val:
            result.headers.append(HeaderFinding(header=hdr, severity=sev, desc=desc))
        # else present — good

    # SSL
    if check_ssl and scheme == "https":
        result.ssl = _check_ssl(target, timeout=timeout)

    # Sensitive paths (concurrent)
    if check_paths:
        paths_to_check = SENSITIVE_PATHS[:max_paths]
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futures = {
                ex.submit(_probe_path, base_url, path, sev, desc, timeout): path
                for path, sev, desc in paths_to_check
            }
            for f in concurrent.futures.as_completed(futures):
                hit = f.result()
                if hit:
                    result.paths.append(hit)

        result.paths.sort(key=lambda x: {"CRIT": 0, "HIGH": 1, "MED": 2, "LOW": 3, "INFO": 4}.get(x.severity, 5))

        # Parse robots.txt if found
        robots = next((p for p in result.paths if p.path == "/robots.txt" and p.status == 200), None)
        if robots:
            _, _, rbody, _ = _fetch(base_url + "/robots.txt", timeout=timeout)
            result.robots_txt = _parse_robots(rbody)

    return result
