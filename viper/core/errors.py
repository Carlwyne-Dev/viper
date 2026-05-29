"""
core/errors.py — Viper never crashes visibly.

Rules:
  - No raw tracebacks to the user. Ever.
  - Every failure has a human message.
  - Log internally if needed, show only what matters.
  - Exit codes are consistent.
"""

import sys
import logging
from viper.output import terminal as out

log = logging.getLogger("viper")


class ViperError(Exception):
    """Base exception. Always has a user-facing message."""
    def __init__(self, message: str, tip: str = ""):
        self.message = message
        self.tip_text = tip
        super().__init__(message)


class ResolveError(ViperError):
    pass

class TimeoutError(ViperError):
    pass

class WordlistError(ViperError):
    pass

class ConfigError(ViperError):
    pass


def handle(exc: Exception, exit: bool = True):
    """Show a clean error and optionally exit."""
    if isinstance(exc, ViperError):
        out.error(exc.message)
        if exc.tip_text:
            out.tip(exc.tip_text)
    else:
        out.error(str(exc))
        log.debug("Unhandled exception", exc_info=exc)

    if exit:
        sys.exit(1)


def resolve(host: str) -> str:
    """Resolve a hostname to IP, raise ResolveError cleanly."""
    import socket
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        raise ResolveError(
            f"Cannot resolve: {host}",
            tip="Check spelling or try an IP address directly."
        )


def safe(fn):
    """Decorator: catch all exceptions, show clean error, continue."""
    import functools
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ViperError as e:
            handle(e, exit=False)
        except KeyboardInterrupt:
            out.blank()
            out.warn("Interrupted.")
        except Exception as e:
            handle(e, exit=False)
    return wrapper
