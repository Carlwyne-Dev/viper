"""
core/scope.py — Authorization scope guard.

Active scanning should only ever hit systems you're allowed to test. If a scope
file exists (~/.viper/scope.txt), Viper refuses active scans against anything
not listed, unless explicitly overridden. No scope file = no restriction (the
guard is opt-in, but once set it is enforced).

A scope entry may be:
  * an exact host          example.com
  * a wildcard             *.example.com   (matches sub.example.com, not apex)
  * a CIDR block           10.0.0.0/8
  * an IP                  10.0.0.5

Pure matching logic — no network. Lines starting with '#' are comments.
"""

import ipaddress
from pathlib import Path

SCOPE_PATH = Path.home() / ".viper" / "scope.txt"


def _host_matches(target: str, pattern: str) -> bool:
    target = target.strip().lower().rstrip(".")
    pattern = pattern.strip().lower().rstrip(".")
    if not pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[1:]            # ".example.com"
        return target.endswith(suffix) and target != suffix.lstrip(".")
    return target == pattern


def _ip_matches(target: str, pattern: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False
    try:
        if "/" in pattern:
            return ip in ipaddress.ip_network(pattern, strict=False)
        return ip == ipaddress.ip_address(pattern)
    except ValueError:
        return False


def in_scope(target: str, patterns: list[str]) -> bool:
    """True if target matches any scope pattern. Empty patterns → True (no scope set)."""
    if not patterns:
        return True
    for pattern in patterns:
        pattern = pattern.strip()
        if not pattern or pattern.startswith("#"):
            continue
        if _host_matches(target, pattern) or _ip_matches(target, pattern):
            return True
    return False


def load_scope(path: Path | None = None) -> list[str]:
    """Read scope patterns from the scope file. Missing file → []."""
    p = path or SCOPE_PATH
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def check(target: str, path: Path | None = None) -> tuple[bool, bool]:
    """
    Returns (allowed, enforced):
      enforced = a non-empty scope file exists
      allowed  = target is in scope (or nothing is enforced)
    """
    patterns = load_scope(path)
    if not patterns:
        return True, False
    return in_scope(target, patterns), True
