"""
core/diff.py — Scan comparison engine.

Compares two ScanResults and produces a structured diff.
The key insight: findings are compared by their stable key().
  source:category:target  — e.g. "port:open-port:443"

New    = in current, not in previous
Closed = in previous, not in current
Changed = same key, different severity or description
"""

from __future__ import annotations
from dataclasses import dataclass, field
from viper.core.models import Finding, ScanResult, SEVERITY_RANK


@dataclass
class DiffResult:
    target:   str
    previous: str   # timestamp of previous scan
    current:  str   # timestamp of current scan

    new:     list[Finding] = field(default_factory=list)  # appeared
    closed:  list[Finding] = field(default_factory=list)  # gone
    changed: list[tuple[Finding, Finding]] = field(default_factory=list)  # (old, new)
    stable:  list[Finding] = field(default_factory=list)  # unchanged

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.closed or self.changed)

    @property
    def new_critical(self) -> list[Finding]:
        return [f for f in self.new if f.severity == "CRIT"]

    @property
    def new_high(self) -> list[Finding]:
        return [f for f in self.new if f.severity == "HIGH"]

    def risk_delta(self) -> int:
        """
        Positive = more exposed than before.
        Negative = less exposed.
        Weighted by severity.
        """
        weights = {"CRIT": 100, "HIGH": 40, "MED": 10, "LOW": 2, "INFO": 0}
        gained = sum(weights.get(f.severity, 0) for f in self.new)
        lost   = sum(weights.get(f.severity, 0) for f in self.closed)
        return gained - lost


def compare(previous: ScanResult, current: ScanResult) -> DiffResult:
    diff = DiffResult(
        target=current.target,
        previous=previous.timestamp,
        current=current.timestamp,
    )

    prev_map = {f.key(): f for f in previous.findings}
    curr_map = {f.key(): f for f in current.findings}

    prev_keys = set(prev_map.keys())
    curr_keys = set(curr_map.keys())

    # New findings
    for key in sorted(curr_keys - prev_keys):
        diff.new.append(curr_map[key])

    # Closed findings
    for key in sorted(prev_keys - curr_keys):
        diff.closed.append(prev_map[key])

    # Changed + stable
    for key in sorted(prev_keys & curr_keys):
        old = prev_map[key]
        new = curr_map[key]
        if old.severity != new.severity or old.description != new.description:
            diff.changed.append((old, new))
        else:
            diff.stable.append(new)

    # Sort by severity
    diff.new     = sorted(diff.new,    key=lambda f: SEVERITY_RANK.get(f.severity, 9))
    diff.closed  = sorted(diff.closed, key=lambda f: SEVERITY_RANK.get(f.severity, 9))

    return diff
