"""
core/targets.py — Target specification expansion.

Turns what a user types (or lists in a file) into a concrete, deduped,
order-preserving list of hosts to scan:

  * single host / domain          example.com
  * comma list                    a.com,b.com,10.0.0.1
  * CIDR range                    10.0.0.0/30  → the usable hosts
  * explicit range                10.0.0.1-10.0.0.5
  * a file of any of the above    (one spec per line, # comments allowed)

Pure logic — no network, no DNS resolution. Invalid specs are kept verbatim
so the resolver downstream can report them.
"""

import ipaddress
from pathlib import Path


def _expand_cidr(spec: str) -> list[str] | None:
    try:
        net = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return None
    # /31 and /32 (and v6 equivalents): include the address(es) themselves.
    if net.num_addresses <= 2:
        return [str(h) for h in net]
    return [str(h) for h in net.hosts()]


def _expand_range(spec: str) -> list[str] | None:
    """Expand 'a.b.c.d-a.b.c.e' or 'a.b.c.d-e' dash ranges."""
    if "-" not in spec:
        return None
    left, right = spec.split("-", 1)
    left = left.strip()
    right = right.strip()
    try:
        start = ipaddress.ip_address(left)
    except ValueError:
        return None
    # Shorthand: last octet only on the right side.
    if "." not in right and ":" not in right and right.isdigit():
        prefix = left.rsplit(".", 1)[0]
        right = f"{prefix}.{right}"
    try:
        end = ipaddress.ip_address(right)
    except ValueError:
        return None
    if int(end) < int(start):
        return None
    if int(end) - int(start) > 65536:   # safety ceiling
        return None
    return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]


def expand_one(spec: str) -> list[str]:
    """Expand a single spec token into concrete hosts."""
    spec = spec.strip()
    if not spec:
        return []
    if "/" in spec:
        cidr = _expand_cidr(spec)
        if cidr is not None:
            return cidr
    rng = _expand_range(spec)
    if rng is not None:
        return rng
    return [spec]   # plain host/domain — leave as-is


def expand(spec: str) -> list[str]:
    """Expand a possibly comma-separated spec string, deduped & ordered."""
    out: list[str] = []
    seen: set[str] = set()
    for token in spec.split(","):
        for host in expand_one(token):
            if host not in seen:
                seen.add(host)
                out.append(host)
    return out


def from_file(path: str) -> list[str]:
    """Read a targets file: one spec per line, '#' comments and blanks ignored."""
    text = Path(path).read_text(encoding="utf-8")
    specs = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            specs.append(line)
    return collect(specs)


def collect(specs: list[str]) -> list[str]:
    """Expand and merge many specs, deduped & order-preserving."""
    out: list[str] = []
    seen: set[str] = set()
    for spec in specs:
        for host in expand(spec):
            if host not in seen:
                seen.add(host)
                out.append(host)
    return out
