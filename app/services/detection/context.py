"""Context analysis to reduce false positives.

Classifies a candidate value as:
  - env reference (os.getenv, process.env.X, ${VAR}, ...)
  - placeholder (YOUR_KEY, changeme, xxxxx, <TOKEN>, ...)
  - test/example value (in test files, or value contains 'example', 'test')
  - empty/masked
Or as a real-looking value worth reporting.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


ENV_REF_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bos\.getenv\s*\("),
    re.compile(r"\bos\.environ(?:\.get)?\s*[\(\[]"),
    re.compile(r"\bprocess\.env(?:\.|\[)"),
    re.compile(r"\bgetenv\s*\("),
    re.compile(r"\bSystem\.getenv\s*\("),
    re.compile(r"\bENV\s*\["),
    re.compile(r"\$\{[A-Z_][A-Z0-9_]*\}"),
    re.compile(r"\$[A-Z_][A-Z0-9_]*\b"),
    re.compile(r"%[A-Z_][A-Z0-9_]*%"),
    re.compile(r"<[A-Z_][A-Z0-9_]*>"),
    re.compile(r"\{\{\s*[A-Za-z_][A-Za-z0-9_]*\s*\}\}"),
)

PLACEHOLDER_VALUES: frozenset[str] = frozenset({
    "", "changeme", "change_me", "changeme!", "replaceme", "replace_me",
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "your_password", "your-password", "yourpassword",
    "your_token", "your-token", "yourtoken",
    "your_api_key", "your-api-key", "yourapikey",
    "example", "sample", "dummy", "fake", "test", "demo",
    "xxx", "xxxx", "xxxxx", "xxxxxx", "yyyy", "zzz",
    "null", "none", "nil", "undefined", "empty",
    "todo", "fixme", "tbd",
    "redacted", "masked", "placeholder",
})

PLACEHOLDER_SUBSTRINGS: tuple[str, ...] = (
    "your_", "your-",
    "example", "sample", "dummy", "fake",
    "placeholder", "replace_me", "changeme",
    "<", ">",
)

TEST_MARKER_FILENAMES: tuple[str, ...] = (
    "test_", "_test.", ".test.", ".spec.", "conftest.py",
)

TEST_MARKER_SUBSTRINGS: tuple[str, ...] = (
    "example", "sample", "dummy", "fixture", "mock", "fake",
    "test_only", "not_a_real",
)


@dataclass(frozen=True)
class ContextInfo:
    is_env_reference: bool
    is_placeholder: bool
    is_test_value: bool
    reason: str


def looks_like_env_reference(text: str) -> bool:
    """True if text (typically the RHS of an assignment) reads a variable."""
    return any(p.search(text) for p in ENV_REF_PATTERNS)


def looks_like_placeholder(value: str) -> bool:
    if not value:
        return True
    stripped = value.strip().strip("'\"")
    if not stripped:
        return True
    lowered = stripped.lower()
    if lowered in PLACEHOLDER_VALUES:
        return True
    if len(set(stripped)) == 1:
        return True
    if all(c in "xX*.-_/\\|" for c in stripped):
        return True
    for sub in PLACEHOLDER_SUBSTRINGS:
        if sub in lowered:
            return True
    return False


def looks_like_test_value(value: str, filename: str, line: str) -> bool:
    name = filename.lower()
    if any(marker in name for marker in TEST_MARKER_FILENAMES):
        return True
    lowered_value = value.lower()
    lowered_line = line.lower()
    for marker in TEST_MARKER_SUBSTRINGS:
        if marker in lowered_value or marker in lowered_line:
            return True
    return False


def classify(value: str, filename: str, line: str) -> ContextInfo:
    if looks_like_env_reference(line):
        return ContextInfo(True, False, False, "environment variable reference")
    if looks_like_placeholder(value):
        return ContextInfo(False, True, False, "placeholder or dummy value")
    if looks_like_test_value(value, filename, line):
        return ContextInfo(False, False, True, "test/example value")
    return ContextInfo(False, False, False, "credential-shaped value")