"""
core/history.py — Scan history storage.

Saves every ScanResult to ~/.viper/history/{target}/{timestamp}.json
Provides fast lookup: latest scan, all scans for target, index.
"""

import json
import os
from pathlib import Path
from viper.core.models import ScanResult

HISTORY_DIR = Path.home() / ".viper" / "history"


def _target_dir(target: str) -> Path:
    # Sanitize target for use as directory name
    safe = target.replace(".", "_").replace("/", "_").replace(":", "_")
    return HISTORY_DIR / safe


def save(result: ScanResult) -> Path:
    """Persist a ScanResult. Returns the path it was saved to."""
    d = _target_dir(result.target)
    d.mkdir(parents=True, exist_ok=True)

    # Filename: timestamp-based, sortable
    ts = result.timestamp.replace(":", "-").replace(".", "-")[:19]
    path = d / f"{ts}.json"
    path.write_text(json.dumps(result.to_dict(), indent=2, default=str), encoding="utf-8")
    return path


def load(path: Path) -> ScanResult:
    data = json.loads(path.read_text(encoding="utf-8"))
    return ScanResult.from_dict(data)


def scans_for(target: str) -> list[Path]:
    """Return all scan files for a target, newest first."""
    d = _target_dir(target)
    if not d.exists():
        return []
    return sorted(d.glob("*.json"), reverse=True)


def latest(target: str) -> ScanResult | None:
    """Load the most recent scan for a target, or None."""
    files = scans_for(target)
    if not files:
        return None
    return load(files[0])


def previous(target: str) -> ScanResult | None:
    """Load the second-most-recent scan (for comparison)."""
    files = scans_for(target)
    if len(files) < 2:
        return None
    return load(files[1])


def all_targets() -> list[str]:
    """List all targets that have scan history."""
    if not HISTORY_DIR.exists():
        return []
    return [d.name.replace("_", ".") for d in HISTORY_DIR.iterdir() if d.is_dir()]


def scan_count(target: str) -> int:
    return len(scans_for(target))


def delete_history(target: str) -> int:
    """Delete all scans for a target. Returns count deleted."""
    files = scans_for(target)
    for f in files:
        f.unlink()
    d = _target_dir(target)
    if d.exists() and not list(d.iterdir()):
        d.rmdir()
    return len(files)
