"""
core/latency.py — Network latency probe.
Measures round-trip time to target and returns a tuned timeout.
Fast targets get tight timeouts. Slow targets get breathing room.
"""

import socket
import time


def probe(host: str, port: int = 80, samples: int = 3) -> float:
    """
    Ping host:port TCP samples times, return median RTT in seconds.
    Falls back to 1.0s on failure.
    """
    times = []
    for _ in range(samples):
        try:
            t0 = time.perf_counter()
            with socket.create_connection((host, port), timeout=3.0):
                times.append(time.perf_counter() - t0)
        except Exception:
            pass

    if not times:
        return 1.0

    times.sort()
    rtt = times[len(times) // 2]  # median
    return rtt


def tune_timeout(host: str) -> float:
    """
    Auto-tune scan timeout based on measured latency.
    Returns a per-port timeout value appropriate for this target.

    Tiers:
      < 20ms   (local/LAN)   → 0.15s
      < 80ms   (regional)    → 0.30s
      < 200ms  (continental) → 0.60s
      < 500ms  (global)      → 1.00s
      >= 500ms (slow/far)    → 2.00s
    """
    # Try common open ports for the probe
    rtt = None
    for port in (80, 443, 22, 21):
        try:
            r = probe(host, port, samples=2)
            if r < 3.0:
                rtt = r
                break
        except Exception:
            continue

    if rtt is None:
        return 1.0

    if rtt < 0.020:  return 0.15
    if rtt < 0.080:  return 0.30
    if rtt < 0.200:  return 0.60
    if rtt < 0.500:  return 1.00
    return 2.00
