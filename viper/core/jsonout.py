"""
core/jsonout.py — JSON output mode.
When --json is passed, all results are collected and printed
as a single JSON object at the end instead of rendered terminal output.
Used for piping: viper bite target.com --json | jq .ports
"""

import json
import sys

_enabled = False
_buffer: dict = {}


def enable():
    global _enabled, _buffer
    _enabled = True
    _buffer = {}


def disable():
    global _enabled
    _enabled = False


def is_enabled() -> bool:
    return _enabled


def set(key: str, value):
    """Store a result section."""
    if _enabled:
        _buffer[key] = value


def merge(data: dict):
    """Merge a dict into the buffer."""
    if _enabled:
        _buffer.update(data)


def flush():
    """Print the full JSON buffer and exit cleanly."""
    if _enabled:
        print(json.dumps(_buffer, indent=2, default=str))
