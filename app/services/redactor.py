"""Secret redaction.

Every user-visible surface (dashboard, finding detail, reports, logs)
must show a redacted value, never the plaintext.

Two levels:
  - redact_secret(): partial mask for short display, e.g. "AKIA****9XYZ"
  - REDACTED:        full mask used when partial would leak too much

Rules:
  - Values shorter than MIN_PARTIAL_LEN are fully masked.
  - Only the first and last FIXED_PREFIX / FIXED_SUFFIX characters are
    ever shown, and only when the total length is large enough that
    those characters cannot help an attacker guess the rest.
  - Never log or serialize the raw value.
"""
from __future__ import annotations

from dataclasses import dataclass

REDACTED = "********REDACTED********"

MIN_PARTIAL_LEN = 12
FIXED_PREFIX = 4
FIXED_SUFFIX = 4


@dataclass(frozen=True)
class RedactionResult:
    value: str
    is_partial: bool


def redact_secret(value: str, *, partial: bool = True) -> str:
    """Return a safe representation of a secret.

    For long values, show "PREFIX****SUFFIX". For short values, return
    the full REDACTED marker.
    """
    if value is None:
        return REDACTED
    stripped = value.strip()
    if not stripped:
        return REDACTED
    if not partial:
        return REDACTED
    if len(stripped) < MIN_PARTIAL_LEN:
        return REDACTED

    prefix = stripped[:FIXED_PREFIX]
    suffix = stripped[-FIXED_SUFFIX:]
    stars = "*" * max(8, len(stripped) - FIXED_PREFIX - FIXED_SUFFIX)
    return f"{prefix}{stars}{suffix}"


def redact_secret_result(value: str) -> RedactionResult:
    """Return redaction plus a flag indicating whether it was partial."""
    result = redact_secret(value)
    return RedactionResult(value=result, is_partial=result != REDACTED)


def redact_line(line: str, secrets: list[str]) -> str:
    """Replace each secret occurrence in a line with REDACTED.

    Useful for context snippets: the snippet still shows the assignment
    shape, but the value is masked.
    """
    if not line:
        return line
    out = line
    for secret in secrets:
        if not secret:
            continue
        out = out.replace(secret, REDACTED)
    return out


def redact_text(text: str, secrets: list[str]) -> str:
    """Redact every known secret value from an arbitrary blob."""
    if not text:
        return text
    return redact_line(text, secrets)


def safe_context_snippet(
    text: str,
    *,
    line_number: int,
    secrets: list[str],
    radius: int = 2,
) -> str:
    """Return a multi-line snippet around a line, with secrets redacted.

    line_number is 1-based. radius is the number of lines before and
    after to include.
    """
    if not text or line_number < 1:
        return ""
    lines = text.splitlines()
    idx = line_number - 1
    if idx < 0 or idx >= len(lines):
        return ""
    start = max(0, idx - radius)
    end = min(len(lines), idx + radius + 1)
    snippet = "\n".join(lines[start:end])
    return redact_text(snippet, secrets)


__all__ = [
    "REDACTED",
    "RedactionResult",
    "redact_secret",
    "redact_secret_result",
    "redact_line",
    "redact_text",
    "safe_context_snippet",
]