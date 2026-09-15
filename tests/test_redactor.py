"""Tests for secret redaction."""
from app.services.redactor import (
    REDACTED,
    redact_line,
    redact_secret,
    redact_secret_result,
    redact_text,
    safe_context_snippet,
)


def test_short_value_fully_redacted():
    assert redact_secret("abc") == REDACTED
    assert redact_secret("short") == REDACTED


def test_empty_value_redacted():
    assert redact_secret("") == REDACTED
    assert redact_secret("    ") == REDACTED


def test_none_value_redacted():
    assert redact_secret(None) == REDACTED


def test_long_value_partial_mask():
    value = "AKIAIOSFODNN7EXAMPLE"
    masked = redact_secret(value)
    assert masked != REDACTED
    assert masked.startswith("AKIA")
    assert masked.endswith("MPLE")
    assert "IOSFODNN7EXA" not in masked


def test_long_value_hides_middle():
    value = "abcdefghijklmnopqrstuvwxyz"
    masked = redact_secret(value)
    assert "abcdef" not in masked
    assert "uvwxyz" not in masked
    assert "*" in masked


def test_partial_false_returns_full_marker():
    value = "AKIAIOSFODNN7EXAMPLE"
    assert redact_secret(value, partial=False) == REDACTED


def test_redact_secret_result_flag():
    r1 = redact_secret_result("AKIAIOSFODNN7EXAMPLE")
    assert r1.is_partial is True
    assert r1.value.startswith("AKIA")

    r2 = redact_secret_result("abc")
    assert r2.is_partial is False
    assert r2.value == REDACTED


def test_redact_line_replaces_secret():
    line = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
    masked = redact_line(line, ["AKIAIOSFODNN7EXAMPLE"])
    assert "AKIAIOSFODNN7EXAMPLE" not in masked
    assert REDACTED in masked


def test_redact_line_multiple_secrets():
    line = 'user=admin password="s3cr3t" token="abc123xyz"'
    masked = redact_line(line, ["s3cr3t", "abc123xyz"])
    assert "s3cr3t" not in masked
    assert "abc123xyz" not in masked
    assert masked.count(REDACTED) == 2


def test_redact_line_with_empty_secret_is_noop():
    line = "nothing to see"
    assert redact_line(line, ["", None]) == line


def test_redact_text_multiline():
    text = (
        'line1 password="s3cr3t"\n'
        'line2 api_key="abcdef1234567890"\n'
    )
    masked = redact_text(text, ["s3cr3t", "abcdef1234567890"])
    assert "s3cr3t" not in masked
    assert "abcdef1234567890" not in masked


def test_safe_context_snippet_shows_surrounding_lines():
    text = "\n".join([
        "before1",
        "before2",
        'password = "s3cr3t-value"',
        "after1",
        "after2",
        "after3",
    ])
    snippet = safe_context_snippet(
        text, line_number=3, secrets=["s3cr3t-value"], radius=1
    )
    assert "before2" in snippet
    assert "after1" in snippet
    assert "s3cr3t-value" not in snippet
    assert REDACTED in snippet


def test_safe_context_snippet_invalid_line():
    assert safe_context_snippet("a\nb", line_number=0, secrets=[]) == ""
    assert safe_context_snippet("a\nb", line_number=99, secrets=[]) == ""


def test_safe_context_snippet_clamps_edges():
    text = "one\ntwo\nthree"
    snippet = safe_context_snippet(text, line_number=1, secrets=[], radius=5)
    assert "one" in snippet
    assert "two" in snippet
    assert "three" in snippet