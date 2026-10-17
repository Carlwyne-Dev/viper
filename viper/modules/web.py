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

# (path, max_severity, description, content_fingerprint)
# content_fingerprint: regex that must match body to confirm finding.
# None = HTTP status alone is enough (lower confidence).
SENSITIVE_PATHS = [
    ("/.env",               "HIGH", "Env file present",           r"[A-Z_]+=.+"),
    ("/.git/HEAD",          "HIGH", "Git repo exposed",           r"ref: refs/heads/"),
    ("/.git/config",        "HIGH", "Git config exposed",         r"\[core\]"),
    ("/wp-login.php",       "MED",  "WordPress login",            r"wp-login|WordPress"),
    ("/wp-admin/",          "MED",  "WordPress admin",            r"wp-admin|WordPress"),
    ("/phpmyadmin/",        "MED",  "phpMyAdmin present",         r"phpMyAdmin|pma_"),
    ("/admin/",             "MED",  "Admin panel present",        None),
    ("/administrator/",     "MED",  "Admin panel present",        r"Joomla|Administrator"),
    ("/backup/",            "MED",  "Backup directory",           r"Index of|backup"),
    ("/backup.zip",         "HIGH", "Backup archive exposed",     None),
    ("/backup.sql",         "HIGH", "Database backup exposed",    r"INSERT INTO|CREATE TABLE|mysqldump"),
    ("/config.php",         "MED",  "Config file present",        r"\<\?php|define\("),
    ("/config.yml",         "MED",  "Config file present",        r"password:|secret:|key:"),
    ("/config.json",        "MED",  "Config file present",        r'"password"|"secret"|"key"'),
    ("/docker-compose.yml", "MED",  "Docker config present",      r"version:|services:"),
    ("/Dockerfile",         "LOW",  "Dockerfile present",         r"FROM |RUN |CMD "),
    ("/robots.txt",         "INFO", "robots.txt found",           None),
    ("/sitemap.xml",        "INFO", "Sitemap found",              None),
    ("/.htaccess",          "MED",  ".htaccess present",          r"RewriteRule|Deny from|Options"),
    ("/server-status",      "MED",  "Apache server-status",       r"Apache Server Status|requests currently"),
    ("/swagger.json",       "MED",  "Swagger spec exposed",       r'"swagger"|"openapi"'),
    ("/swagger/",           "LOW",  "Swagger UI present",         r"swagger-ui|Swagger UI"),
    ("/graphql",            "LOW",  "GraphQL endpoint",           r"graphql|__schema"),
    ("/actuator/env",       "HIGH", "Spring Boot env exposed",    r"activeProfiles|propertySources"),
    ("/actuator",           "MED",  "Spring Boot actuator",       r"_links|health|info"),
    ("/elmah.axd",          "MED",  "ELMAH error log",            r"Error Log|ELMAH"),
    ("/.DS_Store",          "LOW",  ".DS_Store present",          None),
    ("/api/v1/",            "INFO", "API v1 endpoint",            None),
    ("/api/v2/",            "INFO", "API v2 endpoint",            None),
    ("/.well-known/",       "INFO", "Well-known directory",       None),
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
    # Deeper TLS posture
    weak_protocols: list = field(default_factory=list)  # e.g. ["TLSv1", "TLSv1.1"]
    self_signed:    bool = False
    hostname_mismatch: bool = False


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


def _probe_path(base: str, path: str, max_sev: str, desc: str, timeout: float,
                fingerprint: str = None) -> PathResult | None:
    """
    Probe a path. Only flag if:
    - HTTP 200 AND content fingerprint matches (if fingerprint provided)
    - HTTP 200 AND no fingerprint (lower confidence — noted in desc)
    - HTTP 403 = path exists but blocked (LOW, informational only)
    Never report a finding based on HTTP 200 alone for high-severity paths.
    """
    import re as _re
    url = base.rstrip("/") + path
    status, hdrs, body, _ = _fetch(url, timeout=timeout, follow=False)

    if status == 200:
        size = len(body)
        if fingerprint:
            # Content verification — only flag if body matches
            if _re.search(fingerprint, body, _re.IGNORECASE):
                return PathResult(path=path, status=status,
                                  severity=max_sev, desc=desc + " (content verified)", size=size)
            else:
                # HTTP 200 but content doesn't match — could be WAF/redirect/fake
                # Downgrade to INFO
                return PathResult(path=path, status=status,
                                  severity="INFO",
                                  desc=desc + " (HTTP 200, content unverified — manual check recommended)",
                                  size=size)
        else:
            # No fingerprint — report but at reduced severity
            sev = max_sev if max_sev in ("INFO", "LOW") else "LOW"
            return PathResult(path=path, status=status,
                              severity=sev,
                              desc=desc + " (HTTP 200, manual verification recommended)",
                              size=size)

    elif status == 403:
        # Exists but access denied — always LOW, informational
        return PathResult(path=path, status=status, severity="LOW",
                          desc=desc + " (HTTP 403 — access denied, path exists)", size=0)

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


# Protocols considered weak/deprecated (RFC 8996 deprecates TLS 1.0/1.1).
_WEAK_TLS = {
    "TLSv1":   getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1,
    "TLSv1.1": getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_1,
}


def tls_weakness_severity(weak_protocols: list, self_signed: bool,
                          hostname_mismatch: bool) -> tuple | None:
    """
    Pure decision: given TLS posture, return (severity, description) or None.
    Separated from the network probe so it can be unit-tested.
    """
    if hostname_mismatch:
        return ("HIGH", "TLS certificate hostname mismatch")
    if weak_protocols:
        return ("MED", "Deprecated TLS protocol(s) accepted: " + ", ".join(weak_protocols))
    if self_signed:
        return ("MED", "TLS certificate is self-signed")
    return None


def _probe_weak_protocols(host: str, port: int, timeout: float) -> list:
    """Return the deprecated TLS versions the server still accepts."""
    accepted = []
    for name, version in _WEAK_TLS.items():
        if not version:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    accepted.append(name)
        except Exception:
            pass  # handshake refused = good, protocol not supported
    return accepted


def _check_ssl(host: str, port: int = 443, timeout: float = 5.0) -> SslResult:
    result = SslResult()
    # First, a strict handshake to detect self-signed / hostname issues.
    try:
        strict = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with strict.wrap_socket(sock, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as e:
        msg = str(e).lower()
        if "self-signed" in msg or "self signed" in msg:
            result.self_signed = True
        if "hostname mismatch" in msg or "doesn't match" in msg:
            result.hostname_mismatch = True
    except Exception:
        pass

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

    # Probe for deprecated TLS versions (independent of cert validity).
    try:
        result.weak_protocols = _probe_weak_protocols(host, port, timeout)
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
                ex.submit(_probe_path, base_url, path, sev, desc, timeout, fp): path
                for path, sev, desc, fp in paths_to_check
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
