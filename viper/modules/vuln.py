"""
modules/vuln.py — Banner grabbing + CVE signature matching.
No rendering. Returns structured data only.
"""

import socket
import ssl
import re
import urllib.request
import concurrent.futures
from dataclasses import dataclass

TLS_PORTS = {443, 8443}
HTTP_PORTS = {80, 8080}

SIGNATURES = [
    # (pattern, service, CVE, severity, description)
    (r"OpenSSH[_ ]([67]\.\d)",          "SSH",   "CVE-2016-6210",  "HIGH", "User enumeration via timing"),
    (r"OpenSSH[_ ](8\.[0-3])",          "SSH",   "CVE-2023-38408", "CRIT", "RCE via ssh-agent forwarding"),
    (r"Apache/2\.4\.(4[0-9]|50)",       "HTTP",  "CVE-2021-41773", "CRIT", "Path traversal / RCE"),
    (r"Apache/2\.4\.(2[0-9]|3[0-9])",  "HTTP",  "CVE-2017-7679",  "HIGH", "mod_mime buffer overread"),
    (r"nginx/1\.(1[0-7])\.",            "HTTP",  "CVE-2017-7529",  "MED",  "Range filter integer overflow"),
    (r"vsftpd 2\.3\.4",                 "FTP",   "CVE-2011-2523",  "CRIT", "Backdoor command execution"),
    (r"ProFTPD 1\.3\.[0-3]",            "FTP",   "CVE-2010-4221",  "HIGH", "Stack-based buffer overflow"),
    (r"Microsoft-IIS/6",                "HTTP",  "CVE-2017-7269",  "CRIT", "WebDAV buffer overflow"),
    (r"OpenSSL/1\.0\.[01]",             "TLS",   "CVE-2014-0160",  "CRIT", "Heartbleed — memory disclosure"),
    (r"OpenSSL/1\.0\.2[a-l]",           "TLS",   "CVE-2016-0800",  "HIGH", "DROWN attack"),
    (r"PHP/([45]\.\d)",                 "HTTP",  "CVE-2019-11043", "CRIT", "RCE via php-fpm + nginx"),
    (r"Exim\s+([0-4]\.|[0-9]\.[0-9][0-2])", "SMTP","CVE-2019-10149","CRIT","Remote command execution"),
    (r"MySQL\s+5\.[0-6]",              "DB",    "CVE-2016-6662",  "CRIT", "Arbitrary file write"),
    (r"Redis\s+([0-6]\.|7\.0\.[01])",  "DB",    "CVE-2022-0543",  "CRIT", "Lua sandbox escape / RCE"),
]

SECURITY_HEADERS = [
    "X-Frame-Options", "X-Content-Type-Options",
    "Content-Security-Policy", "Strict-Transport-Security",
]

DEFAULT_PORTS = [21, 22, 23, 25, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017]


@dataclass
class VulnResult:
    port:        int
    service:     str
    cve:         str
    severity:    str
    desc:        str
    banner:      str
    # Banner/version matches are inferred, not proven: the service may be
    # patched (distros backport fixes), the banner may be spoofed or stripped,
    # or the version may not be in the vulnerable range after all.
    presumptive: bool = True
    confidence:  int  = 60    # 0–100; how much to trust this match

    @property
    def display_desc(self) -> str:
        if self.presumptive:
            return f"{self.desc} — presumptive, verify manually"
        return self.desc


@dataclass
class HeaderResult:
    port:   int
    header: str


def _grab(host: str, port: int, timeout: float) -> str | None:
    req = b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
    try:
        if port in TLS_PORTS:
            # TLS ports speak TLS first — a plaintext HTTP send gets no reply.
            # Wrap the socket so the HEAD request actually reaches the server.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    s.settimeout(timeout)
                    s.send(req)
                    return s.recv(2048).decode(errors="ignore").strip()
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in HTTP_PORTS:
                s.send(req)
            return s.recv(2048).decode(errors="ignore").strip()
    except Exception:
        return None


def _http_headers(host: str, port: int, timeout: float) -> dict:
    scheme = "https" if port in (443, 8443) else "http"
    try:
        req = urllib.request.Request(
            f"{scheme}://{host}:{port}/",
            headers={"User-Agent": "Viper/0.2"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return dict(r.headers)
    except Exception:
        return {}


def scan(host: str, ports: list[int] | None = None, timeout: float = 3.0) -> tuple[dict, list[VulnResult], list[HeaderResult]]:
    """
    Returns (banners, vulns, missing_headers).
    banners = {port: banner_string}
    """
    port_list = ports or DEFAULT_PORTS
    banners: dict[int, str] = {}
    vulns: list[VulnResult] = []
    missing: list[HeaderResult] = []

    # Grab banners concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_grab, host, p, timeout): p for p in port_list}
        for f in concurrent.futures.as_completed(futures):
            port = futures[f]
            b = f.result()
            if b:
                banners[port] = b

    # Match hardcoded signatures
    for port, banner in banners.items():
        for pattern, service, cve, severity, desc in SIGNATURES:
            if re.search(pattern, banner, re.IGNORECASE):
                # Version-string match against the banner — presumptive by nature.
                vulns.append(VulnResult(port=port, service=service, cve=cve,
                                        severity=severity, desc=desc, banner=banner[:80],
                                        presumptive=True, confidence=60))

    # Live CVE lookup for banners not matched by signatures
    matched_ports = {v.port for v in vulns}
    for port, banner in banners.items():
        if port in matched_ports:
            continue  # already have findings for this port
        try:
            from viper.core.cvedb import for_banner
            live_cves = for_banner(banner)
            for cve in live_cves[:3]:  # max 3 per port
                vulns.append(VulnResult(
                    port=port, service="",
                    cve=cve.id,
                    severity=cve.viper_severity,
                    desc=cve.short_desc(80),
                    banner=banner[:80],
                    # Keyword/CPE match from NVD against the banner — weaker
                    # still than a version-range signature.
                    presumptive=True, confidence=50,
                ))
        except Exception:
            pass  # CVE DB never blocks the scan

    # Check HTTP security headers
    http_ports = [p for p in port_list if p in (80, 443, 8080, 8443) and p in banners]
    for port in http_ports:
        hdrs = _http_headers(host, port, timeout)
        for sh in SECURITY_HEADERS:
            if not any(k.lower() == sh.lower() for k in hdrs):
                missing.append(HeaderResult(port=port, header=sh))

    return banners, vulns, missing
