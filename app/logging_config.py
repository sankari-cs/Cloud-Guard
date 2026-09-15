"""Logging configuration with a redaction filter.
Any log record whose message contains a known-sensitive key name or a
secret-shaped value is rewritten before it reaches the handler. The
original value is never written.
"""
from __future__ import annotations
import logging
import re
SECRET_KEYS = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|authorization)\b"
)
# Long, high-entropy strings. Best-effort filter, never perfect.
SECRET_SHAPES = re.compile(
    r"\b("
    r"AKIA[0-9A-Z]{16}"
    r"|ghp_[A-Za-z0-9]{36}"
    r"|gho_[A-Za-z0-9]{36}"
    r"|ghs_[A-Za-z0-9]{36}"
    r"|github_pat_[A-Za-z0-9_]{82}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|sk_live_[0-9a-zA-Z]{24,}"
    r"|eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"
    r")\b"
)
REDACTED = "********REDACTED********"
class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        msg = SECRET_SHAPES.sub(REDACTED, msg)
        # Mask values of the form key=value or key: value for known key names.
        def _mask(match: re.Match) -> str:
            return f"{match.group(1)}={REDACTED}"
        msg = re.sub(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|"
            r"access[_-]?key|private[_-]?key|authorization)\b"
            r"\s*[=:]\s*"
            r"[\"']?([^\s\"']+)[\"']?",
            _mask,
            msg,
        )
        record.msg = msg
        record.args = ()
        return True
def configure_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger()
    root.setLevel(level)
    # Remove existing handlers so repeated create_app calls do not stack.
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))
    handler.addFilter(RedactionFilter())
    root.addHandler(handler)
    logging.getLogger("werkzeug").setLevel(logging.INFO)