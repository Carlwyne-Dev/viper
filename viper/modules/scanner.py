"""
modules/scanner.py — Raw port scanning capability.
No rendering. Returns structured data only.
"""

import socket
import concurrent.futures
from dataclasses import dataclass

KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB", 9200: "Elasticsearch",
}

# Ports that are interesting to flag even if expected
FLAGGED_PORTS = {23, 445, 3389, 5900, 6379, 27017, 9200}


@dataclass
class PortResult:
    port:    int
    service: str
    flagged: bool = False


def parse_ports(port_str: str) -> list[int]:
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def _probe(host: str, port: int, timeout: float) -> PortResult | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            service = KNOWN_SERVICES.get(port, "")
            return PortResult(port=port, service=service, flagged=port in FLAGGED_PORTS)
    except Exception:
        return None


def scan(host: str, ports: str, timeout: float, threads: int, on_progress=None) -> list[PortResult]:
    """
    Scan ports on host. Calls on_progress() after each probe.
    Returns list of open PortResult, sorted by port number.
    """
    port_list = parse_ports(ports)
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_probe, host, p, timeout): p for p in port_list}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
            if on_progress:
                on_progress()

    return sorted(results, key=lambda r: r.port)
